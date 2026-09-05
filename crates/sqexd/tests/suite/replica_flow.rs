//! SIP-35: what a replica refuses, which is the whole difference between a
//! witnessed copy and a mirror.
//!
//! **These test the half that exists.** An origin can be authorised to
//! replicate to a peer, can be asked, and answers; the verification and
//! storage half decides what may be written. What is missing is the pull loop
//! joining them, because `sqexd` has no runtime sQUIC client — see
//! `sqexd::replica`. So the origin is driven over the wire and the replica is
//! driven directly, which has one advantage a full loop would not: an
//! equivocating origin can be played without writing a dishonest sqexd.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{ByAccount, Role, TYPE_REPLICATE, TYPE_UNREPLICATE, Visibility};
use sqex_proto::entry_sig::Place;
use sqex_proto::peer::{Hello, Hi, PEER_VERSION, Pull, Pulled};
use sqex_proto::receipt::{self, ReceiptTerms};
use sqex_proto::refusal::{Code, Refusal};
use sqexd::channel::Channels;
use sqexd::config::FileConfig;
use sqexd::replica::{Refused, take};
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

/// A server whose peering whitelist holds `peers`.
async fn server_in(
    dir: &Path,
    peers: &[PubKey],
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nreplication_peers = [{list}]\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let config_path = dir.join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, Some(config_path), signing_key)
        .await
        .unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    let handle = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, handle)
}

/// A second exchange, bound but not serving: a replica's own stores are what
/// the pull writes into, and nothing needs to connect *to* it here.
async fn bind_replica(dir: &Path) -> std::sync::Arc<sqexd::Server> {
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n",
        dir.join("host_key").to_string_lossy(),
        dir.join("replica.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    sqexd::bind(config, None, signing_key).await.unwrap().server
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn a_room(c: &mut Client, s: &Signer, chain: &mut Chain, channel: [u8; 32]) {
    let req = s.create_chained(
        chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![],
    );
    let (code, body) = c.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn say(c: &mut Client, s: &Signer, chain: &mut Chain, channel: [u8; 32], text: &[u8]) {
    let info = s.info(c, channel).await;
    let req = s.post_chained(chain, channel, info.instance, 0, 0, text.to_vec());
    let (code, body) = c.post("/channel/post", req.encode()).await.unwrap();
    assert_eq!(code, 200, "saying {:?}: {}", String::from_utf8_lossy(text), common::said(&body));
}

/// **Every peering refusal is the same refusal**, whatever the reason.
///
/// An unknown peer, an absent channel, and a channel that exists and is not
/// replicated to this peer must be indistinguishable. These routes are
/// reachable by strangers, and a reply that varied by cause would make them an
/// existence oracle for private channels — SIP-24's rule for its admission
/// endpoint and SIP-4's for a withheld beacon.
#[tokio::test]
async fn a_stranger_and_an_absent_channel_get_the_same_answer() {
    let dir = tempfile::tempdir().unwrap();
    let (_, peer_key) = identity(91);
    let (stranger_seed, _) = identity(92);
    let (alice_seed, alice) = identity(93);
    let (addr, server_pub, _h) = server_in(dir.path(), &[peer_key]).await;
    let channel = [91u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = Signer::new(alice_seed, alice, server_pub);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    say(&mut a, &s, &mut chain, channel, b"not for you").await;

    // A stranger, on a channel that exists.
    let mut stranger = Client::connect_as(addr, &server_pub, &stranger_seed).await.unwrap();
    let existing = stranger
        .post("/peer/pull", Pull { channel, since: 0, max: 16 }.encode())
        .await
        .unwrap();
    // The same stranger, on a channel that does not.
    let absent = stranger
        .post("/peer/pull", Pull { channel: [0xAB; 32], since: 0, max: 16 }.encode())
        .await
        .unwrap();
    // And a whitelisted peer, on a channel nobody authorised it for.
    let (peer_seed, _) = identity(91);
    let mut peer = Client::connect_as(addr, &server_pub, &peer_seed).await.unwrap();
    let unauthorised = peer
        .post("/peer/pull", Pull { channel, since: 0, max: 16 }.encode())
        .await
        .unwrap();

    assert_eq!(existing.0, absent.0);
    assert_eq!(existing.0, unauthorised.0);
    assert_eq!(existing.1, absent.1, "the reply must not vary by cause");
    assert_eq!(existing.1, unauthorised.1, "the reply must not vary by cause");
    // And it carries no detail, because a detail string is a reply that varies.
    let r = Refusal::decode(&existing.1).unwrap();
    assert_eq!(r.code, Code::NoSuchChannel);
    assert!(r.detail.is_none(), "a peering refusal must say nothing");

    // The whitelist alone is not entitlement either: being allowed to speak the
    // routes gave this peer no channel.
    let hello = peer
        .post("/peer/hello", Hello { version: PEER_VERSION, since: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(hello.0, 200, "a whitelisted peer may still say hello");
    let hi = Hi::decode(&hello.1).unwrap();
    assert_eq!(hi.exchange, PubKey::new(server_pub));
    assert_eq!(hi.version, PEER_VERSION);

    // A stranger cannot even do that.
    let (code, _) = stranger
        .post("/peer/hello", Hello { version: PEER_VERSION, since: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 404, "the operational gate is on hello too");
}

/// A channel replicates only when a member says so, and the saying is an entry.
///
/// An out-of-band arrangement between two operators would have been simpler and
/// would have made a channel's copies invisible to the people in it. This lands
/// in the log they already read, signed by whoever did it.
#[tokio::test]
async fn a_peer_is_served_only_after_an_admin_authorises_it_in_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let (peer_seed, peer_key) = identity(101);
    let (alice_seed, alice) = identity(102);
    let (addr, server_pub, _h) = server_in(dir.path(), &[peer_key]).await;
    let channel = [101u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = Signer::new(alice_seed, alice, server_pub);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    say(&mut a, &s, &mut chain, channel, b"before").await;

    let mut peer = Client::connect_as(addr, &server_pub, &peer_seed).await.unwrap();
    let (code, _) = peer
        .post("/peer/pull", Pull { channel, since: 0, max: 16 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 404, "an unauthorised peer is served nothing");

    // Alice authorises it, signed like any other membership act.
    let info = s.info(&mut a, channel).await;
    let action = s.action_at(&info, channel, sqex_proto::channel::EVENT_REPLICATE, &peer_key, &[]);
    let (code, body) = a
        .post(
            "/channel/replicate",
            ByAccount { channel, account: peer_key, action }.encode(TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    let (code, body) = peer
        .post("/peer/pull", Pull { channel, since: 0, max: 16 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let pulled = Pulled::decode(&body).unwrap();
    assert_eq!(pulled.origin, PubKey::new(server_pub));
    assert_eq!(pulled.instance, instance_for(channel, 0));
    assert!(!pulled.entries.is_empty());
    // Every entry carries a receipt, not optionally: a replica storing one
    // without would be taking the origin's word for its own ordering.
    assert!(pulled.entries.iter().all(|e| e.stamp.is_some()));
    // And the authorisation itself is in the log the members read.
    assert!(
        pulled.entries.iter().any(|e| {
            sqex_proto::channel::System::decode(&e.body)
                .ok()
                .flatten()
                .is_some_and(|sys| sys.event == sqex_proto::channel::EVENT_REPLICATE
                    && sys.subject == peer_key)
        }),
        "the authorisation must be visible to the members"
    );

    // Withdrawal ends the subscription. It recalls nothing, and the test says
    // so by checking only that serving stops.
    let info = s.info(&mut a, channel).await;
    let action = s.action_at(&info, channel, sqex_proto::channel::EVENT_UNREPLICATE, &peer_key, &[]);
    let (code, body) = a
        .post(
            "/channel/unreplicate",
            ByAccount { channel, account: peer_key, action }.encode(TYPE_UNREPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let (code, _) = peer
        .post("/peer/pull", Pull { channel, since: 0, max: 16 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 404, "serving must stop on withdrawal");
}

/// **The verification is the whole difference between this and a mirror.**
///
/// A replica given a batch stores what verifies and refuses the rest, and each
/// refusal is a different statement about the origin. The negative control is
/// the first assertion: the same batch, unaltered, is stored in full — so the
/// refusals below are the checks firing and not the harness failing.
#[tokio::test]
async fn a_replica_stores_what_verifies_and_refuses_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let (peer_seed, peer_key) = identity(111);
    let (alice_seed, alice) = identity(112);
    let (addr, server_pub, _h) = server_in(dir.path(), &[peer_key]).await;
    let origin = PubKey::new(server_pub);
    let channel = [111u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = Signer::new(alice_seed, alice, server_pub);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    for text in [&b"one"[..], b"two"] {
        say(&mut a, &s, &mut chain, channel, text).await;
    }
    let info = s.info(&mut a, channel).await;
    let action = s.action_at(&info, channel, sqex_proto::channel::EVENT_REPLICATE, &peer_key, &[]);
    let (code, _) = a
        .post(
            "/channel/replicate",
            ByAccount { channel, account: peer_key, action }.encode(TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let mut peer = Client::connect_as(addr, &server_pub, &peer_seed).await.unwrap();
    let (_, body) = peer
        .post("/peer/pull", Pull { channel, since: 0, max: 64 }.encode())
        .await
        .unwrap();
    let pulled = Pulled::decode(&body).unwrap();
    let n = pulled.entries.len() as u64;
    assert!(n >= 3, "a create and two messages at least");

    // Every device here is its own account (SIP-22), so no credential is
    // needed and the lookup is never consulted — asserted rather than assumed.
    let never = |_: &PubKey| -> Option<PubKey> {
        panic!("a self-signed entry must not need a credential")
    };

    // The control: unaltered, all of it stores.
    let store = Channels::open(None, PubKey::new([0xEE; 32]), None).unwrap();
    let took = take(&store, &origin, &channel, &pulled, &never);
    assert_eq!(took.stored, n, "an honest batch must store whole: {took:?}");
    assert!(took.refused.is_empty(), "{took:?}");
    assert_eq!(store.origin_of(&channel), Some(origin));

    // A tampered body. SIP-31 step 1 fails and the entry is not written.
    let mut forged = pulled.clone();
    let victim = forged
        .entries
        .iter_mut()
        .find(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .unwrap();
    victim.body = b"something else entirely".to_vec();
    let seq = victim.seq;
    let store = Channels::open(None, PubKey::new([0xEE; 32]), None).unwrap();
    let took = take(&store, &origin, &channel, &forged, &never);
    assert!(
        took.refused.contains(&(seq, Refused::Repudiated))
            || took.refused.contains(&(seq, Refused::Forged)),
        "a tampered entry must be refused: {took:?}"
    );
    assert_eq!(took.stored, n - 1);

    // A receipt that does not verify under the key this replica pinned. Not
    // absence — an origin cannot switch the mechanism off by corrupting its
    // own signatures.
    let mut repudiated = pulled.clone();
    let last = repudiated.entries.last_mut().unwrap();
    last.stamp.as_mut().unwrap().receipt[0] ^= 1;
    let seq = last.seq;
    let store = Channels::open(None, PubKey::new([0xEE; 32]), None).unwrap();
    let took = take(&store, &origin, &channel, &repudiated, &never);
    assert!(took.refused.contains(&(seq, Refused::Repudiated)), "{took:?}");

    // And a batch checked under the wrong origin verifies nothing at all,
    // which is what pinning the key independently is for.
    let store = Channels::open(None, PubKey::new([0xEE; 32]), None).unwrap();
    let took = take(&store, &PubKey::new([7; 32]), &channel, &pulled, &never);
    assert_eq!(took.stored, 0, "{took:?}");
    assert!(took.refused.iter().all(|(_, r)| r == &Refused::Repudiated));
}

/// **An origin that says two things about one position leaves a proof, and the
/// replica does not choose between them.**
///
/// Picking a branch would silently convert evidence into a disagreement between
/// two honest-looking servers. This is also the case a full pull loop could not
/// produce on its own: making it happen needs a dishonest origin, and driving
/// the replica directly is what lets one be played.
#[tokio::test]
async fn an_origin_that_equivocates_is_caught_and_nothing_is_chosen() {
    let dir = tempfile::tempdir().unwrap();
    let (peer_seed, peer_key) = identity(121);
    let (alice_seed, alice) = identity(122);
    let (addr, server_pub, _h) = server_in(dir.path(), &[peer_key]).await;
    let origin = PubKey::new(server_pub);
    let channel = [121u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = Signer::new(alice_seed, alice, server_pub);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    say(&mut a, &s, &mut chain, channel, b"what one reader was shown").await;
    let info = s.info(&mut a, channel).await;
    let action = s.action_at(&info, channel, sqex_proto::channel::EVENT_REPLICATE, &peer_key, &[]);
    let (code, _) = a
        .post(
            "/channel/replicate",
            ByAccount { channel, account: peer_key, action }.encode(TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let mut peer = Client::connect_as(addr, &server_pub, &peer_seed).await.unwrap();
    let (_, body) = peer
        .post("/peer/pull", Pull { channel, since: 0, max: 64 }.encode())
        .await
        .unwrap();
    let pulled = Pulled::decode(&body).unwrap();
    let never = |_: &PubKey| -> Option<PubKey> { None };

    let store = Channels::open(None, PubKey::new([0xEE; 32]), None).unwrap();
    let took = take(&store, &origin, &channel, &pulled, &never);
    assert!(took.stored > 0);
    assert!(store.equivocation_for(&channel).is_none(), "nothing said twice yet");

    // The same position, told differently — and signed, because an unsigned
    // branch is something anybody could have written and proves nothing.
    let (origin_seed, _) = squic::load_keypair(
        &std::fs::read_to_string(dir.path().join("host_key")).unwrap(),
    )
    .unwrap();
    let mut second = pulled.clone();
    let e = second.entries.last_mut().unwrap();
    let stamp = e.stamp.as_mut().unwrap();
    stamp.head[0] ^= 1;
    let terms = ReceiptTerms {
        place: Place { exchange: origin, instance: second.instance, channel },
        seq: e.seq,
        posted: e.posted,
        entry_hash: stamp.entry_hash,
        head: stamp.head,
    };
    stamp.receipt = receipt::sign(&origin_seed.to_bytes(), &terms);

    let took = take(&store, &origin, &channel, &second, &never);
    assert!(took.equivocated, "the contradiction was not caught: {took:?}");
    let proof = store
        .equivocation_for(&channel)
        .expect("a replica holding a contradiction must keep the proof");

    // **And it presents neither branch.** A replica that went on serving one
    // would be choosing on the reader's behalf, which is the one thing it has
    // no basis to do. The proof is served instead, on its own route.
    assert!(
        matches!(
            store.fetch(&alice, &alice, &channel, 0, false),
            Err(sqexd::channel::ChannelError::Equivocated)
        ),
        "a replica served a branch of a history it knows is contradictory"
    );
    assert_eq!(proof.len(), sqex_proto::receipt::EQUIVOCATION_LEN);
    // It verifies for anybody holding only the origin's public key, which is
    // the property that makes it worth keeping.
    let decoded = sqex_proto::receipt::Equivocation::decode(&proof).unwrap();
    assert_eq!(decoded.place.exchange, origin);
    assert_ne!(decoded.a.head, decoded.b.head);
}

/// Writes go to the origin, always — and the refusal names it, which is the
/// difference between "no" and "not here".
#[test]
fn a_replica_refuses_a_write_and_says_where_it_belongs() {
    use sqexd::channel::ChannelError;
    let origin = PubKey::new([0x33; 32]);
    let store = Channels::open(None, PubKey::new([0xEE; 32]), None).unwrap();
    let channel = [0x44u8; 32];
    store.adopt(&channel, &[9; 32], &origin, 3600).unwrap();
    assert_eq!(store.origin_of(&channel), Some(origin));

    let caller = PubKey::new([1; 32]);
    let action = sqex_proto::channel::Action {
        chain_seq: 0,
        prev: [0; 32],
        sig: [0; 64],
    };
    let err = store.leave(&caller, &caller, &channel, &action).unwrap_err();
    match err {
        ChannelError::Replicated(named) => assert_eq!(named, origin),
        other => panic!("a replica accepted a write, or hid the origin: {other:?}"),
    }
}

/// **Two exchanges, and the second ends up holding the first's channel.**
///
/// The whole document, end to end: an admin authorises a replica in the log,
/// the replica dials the origin with its own identity, pulls, verifies every
/// entry under the key it pinned, and stores what survives. Nothing in it takes
/// the origin's word for anything except the bytes of a system entry's hash,
/// which SIP-34 says plainly it must.
#[tokio::test]
async fn a_second_exchange_pulls_a_channel_and_ends_up_holding_it() {
    use sqexd::replica::{Origin, pull_once};
    use sqex_proto::h3::H3Client;

    let origin_dir = tempfile::tempdir().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();

    // The replica's identity is its own host key, so it must exist before the
    // origin's whitelist can name it.
    let replica_key_path = replica_dir.path().join("host_key");
    let (replica_sk, replica_pub) = squic::generate_keypair();
    std::fs::write(&replica_key_path, hex::encode(replica_sk.to_bytes())).unwrap();
    let replica_key = PubKey::new(replica_pub);

    let (origin_addr, origin_pub, _oh) = server_in(origin_dir.path(), &[replica_key]).await;
    let origin = PubKey::new(origin_pub);

    // A conversation on the origin, with a membership change in it so the
    // replica has to carry a system entry as well as messages.
    let (alice_seed, alice) = identity(131);
    let (bob_seed, bob) = identity(132);
    let channel = [131u8; 32];
    let mut a = Client::connect_as(origin_addr, &origin_pub, &alice_seed).await.unwrap();
    let mut b = Client::connect_as(origin_addr, &origin_pub, &bob_seed).await.unwrap();
    let s = Signer::new(alice_seed, alice, origin_pub);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    say(&mut a, &s, &mut chain, channel, b"before the replica existed").await;

    let joining = Signer::new(bob_seed, bob, origin_pub).action_outside(
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_JOINED,
        &bob,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, _) = b
        .post(
            "/channel/join",
            sqex_proto::channel::ByChannelSigned { channel, action: joining }
                .encode(sqex_proto::channel::TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    say(&mut a, &s, &mut chain, channel, b"and one after").await;

    let info = s.info(&mut a, channel).await;
    let action = s.action_at(&info, channel, sqex_proto::channel::EVENT_REPLICATE, &replica_key, &[]);
    let (code, body) = a
        .post(
            "/channel/replicate",
            ByAccount { channel, account: replica_key, action }.encode(TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Authorising spent a position on Alice's own SIP-31 chain, like every
    // signed act. Resyncing from the exchange rather than guessing is what a
    // real client does, and skipping it is a broken chain on her next message.
    let info = s.info(&mut a, channel).await;
    chain = Chain { seq: info.my_chain_seq, head: info.my_chain_head };

    // A real second exchange, not a bare store: replication pulls profiles as
    // well as entries, and a replica is an exchange.
    let replica = bind_replica(replica_dir.path()).await;
    let store = replica.channels();
    let mut client = H3Client::connect(origin_addr, &origin_pub, &replica_sk.to_bytes())
        .await
        .expect("the replica could not reach the origin");
    let spec = Origin {
        key: origin,
        addr: origin_addr,
        channels: vec![channel],
        interval: std::time::Duration::from_secs(1),
    };

    let took = pull_once(&mut client, &replica, &spec).await.unwrap();
    let t = took.get(&channel).expect("the channel was not pulled");
    assert!(t.stored >= 4, "create, message, join, message: {t:?}");
    assert!(t.refused.is_empty(), "an honest origin was refused: {t:?}");
    assert!(!t.equivocated);

    // It holds the channel, knows whose it is, and will not be written to.
    assert_eq!(store.origin_of(&channel), Some(origin));
    assert_eq!(store.highest(&channel), t.stored);

    // A second pull asks only for what is new, and there is nothing.
    let again = pull_once(&mut client, &replica, &spec).await.unwrap();
    assert_eq!(again.get(&channel).unwrap().stored, 0, "a pull repeated itself");

    // And it keeps up: a message posted now reaches the replica on the next
    // pull, which is what "replicates" means rather than "copied once".
    say(&mut a, &s, &mut chain, channel, b"after the replica caught up").await;
    let third = pull_once(&mut client, &replica, &spec).await.unwrap();
    assert_eq!(third.get(&channel).unwrap().stored, 1);
    assert_eq!(store.highest(&channel), t.stored + 1);
}

/// **A member can read the conversation from the replica**, which is what the
/// whole arrangement is for: a conversation obtainable from a party that never
/// held the power to write it.
///
/// The roster the replica serves it against is *derived* — from the
/// constitution and the signed membership actions in the log it holds, never
/// from a summary the origin sent. The second half of the test is the other
/// side of that rule: a replica that began mid-channel cannot derive one, and
/// refuses rather than guessing.
#[tokio::test]
async fn a_replica_serves_a_derived_roster_and_refuses_one_it_cannot_derive() {
    use sqexd::channel::ChannelError;
    use sqex_proto::h3::H3Client;
    use sqexd::replica::{Origin, pull_once};

    let origin_dir = tempfile::tempdir().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();
    let (replica_sk, replica_pub) = squic::generate_keypair();
    std::fs::write(
        replica_dir.path().join("host_key"),
        hex::encode(replica_sk.to_bytes()),
    )
    .unwrap();
    let replica_key = PubKey::new(replica_pub);

    let (origin_addr, origin_pub, _oh) = server_in(origin_dir.path(), &[replica_key]).await;
    let origin = PubKey::new(origin_pub);
    let (alice_seed, alice) = identity(141);
    let (bob_seed, bob) = identity(142);
    let channel = [141u8; 32];

    let mut a = Client::connect_as(origin_addr, &origin_pub, &alice_seed).await.unwrap();
    let mut b = Client::connect_as(origin_addr, &origin_pub, &bob_seed).await.unwrap();
    let s = Signer::new(alice_seed, alice, origin_pub);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;

    let joining = Signer::new(bob_seed, bob, origin_pub).action_outside(
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_JOINED,
        &bob,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, _) = b
        .post(
            "/channel/join",
            sqex_proto::channel::ByChannelSigned { channel, action: joining }
                .encode(sqex_proto::channel::TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    say(&mut a, &s, &mut chain, channel, b"readable at the replica").await;

    let info = s.info(&mut a, channel).await;
    let action = s.action_at(&info, channel, sqex_proto::channel::EVENT_REPLICATE, &replica_key, &[]);
    let (code, _) = a
        .post(
            "/channel/replicate",
            ByAccount { channel, account: replica_key, action }.encode(TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let spec = Origin {
        key: origin,
        addr: origin_addr,
        channels: vec![channel],
        interval: std::time::Duration::from_secs(1),
    };

    // From the beginning: the constitution arrives, so the roster is derived.
    let replica = bind_replica(replica_dir.path()).await;
    let whole = replica.channels();
    let mut client = H3Client::connect(origin_addr, &origin_pub, &replica_sk.to_bytes())
        .await
        .unwrap();
    pull_once(&mut client, &replica, &spec).await.unwrap();

    // Alice and Bob are both members at the replica, and it never saw a roster.
    let read = whole
        .fetch(&alice, &alice, &channel, 0, false)
        .expect("a member could not read from the replica");
    assert!(
        read.entries.iter().any(|e| e.body == b"readable at the replica"),
        "the message did not survive the copy"
    );
    let seen = whole
        .info(&bob, &bob, &channel)
        .expect("the joiner was not derived as a member");
    assert_eq!(seen.members.len(), 2);
    assert!(
        seen.members.iter().any(|m| m.account == alice && m.role == Role::Admin),
        "the creator must be derived as the first admin"
    );

    // A stranger is refused by the derived roster, exactly as at the origin.
    let (_, stranger) = identity(143);
    assert!(matches!(
        whole.fetch(&stranger, &stranger, &channel, 0, false),
        Err(ChannelError::NotAMember)
    ));

    // And the other side of the rule: a replica that began after the
    // constitution cannot derive anything, and says so rather than serving a
    // roster it would have had to take on trust.
    let partial = Channels::open(None, replica_key, Some(replica_sk.to_bytes())).unwrap();
    let (_, body) = client
        .post(
            "/peer/pull",
            sqex_proto::peer::Pull { channel, since: 2, max: 64 }.encode(),
        )
        .await
        .unwrap();
    let pulled = Pulled::decode(&body).unwrap();
    assert!(!pulled.entries.is_empty(), "the origin served nothing to skip into");
    sqexd::replica::take(&partial, &origin, &channel, &pulled, &|_| None);
    match partial.fetch(&alice, &alice, &channel, 0, false) {
        Err(ChannelError::Underived(named)) => assert_eq!(named, origin),
        other => panic!("a replica served a roster it could not derive: {other:?}"),
    }
}

/// **The record half: what a member needs besides the entries.**
///
/// A copy of the log alone is not a copy of the conversation. Without the SIP-17
/// key envelopes a member reading at the replica has ciphertext and no key;
/// without the SIP-18 blobs the attachments are names of nothing; without the
/// profiles it is a wall of public keys. All three replicate, and each is
/// checked on the way in by the property its own SIP gave it — an envelope by
/// its publisher's signature, a blob by the hash that *is* its name, a profile
/// by its subject's signature and its serial.
#[tokio::test]
async fn envelopes_blobs_and_profiles_cross_and_are_checked_on_the_way_in() {
    use sqex_proto::blob_store::{Begin, ByChannelBlob, Commit, PutChunk, blob_id};
    use sqex_proto::channel_key::{ChannelKey, Put as KeyPut, seal_envelope, sign_envelope};
    use sqex_proto::peer::PulledBlob;
    use sqex_proto::profile::{Profile, Put as ProfilePut, Record};
    use sqex_proto::h3::H3Client;
    use sqexd::replica::{Origin, pull_once};

    let origin_dir = tempfile::tempdir().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();
    let (replica_sk, replica_pub) = squic::generate_keypair();
    std::fs::write(
        replica_dir.path().join("host_key"),
        hex::encode(replica_sk.to_bytes()),
    )
    .unwrap();
    let replica_key = PubKey::new(replica_pub);

    let (origin_addr, origin_pub, _oh) = server_in(origin_dir.path(), &[replica_key]).await;
    let origin = PubKey::new(origin_pub);
    let (alice_seed, alice) = identity(151);
    let channel = [151u8; 32];

    let mut a = Client::connect_as(origin_addr, &origin_pub, &alice_seed).await.unwrap();
    let s = Signer::new(alice_seed, alice, origin_pub);
    let mut chain = Chain::default();

    // A private channel, so there is a key envelope to carry at all.
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Private,
        3600,
        "",
        vec![],
    );
    let (code, body) = a.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Alice mints epoch 1 and seals it to herself. The prekey is generated
    // here rather than published: the exchange checks the envelope's signature
    // and never opens one, which is the property being relied on.
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let prekey_public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    let epoch1 = ChannelKey::generate();
    let envelope = sign_envelope(
        &alice_seed,
        &PubKey::new(origin_pub),
        &instance_for(channel, 0),
        &channel,
        1,
        seal_envelope(&alice, 7, &prekey_public, 1, &[epoch1]).unwrap(),
    );
    let rot = s.action_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_ROTATED,
        &alice,
        &1u32.to_be_bytes(),
    );
    let (code, body) = a
        .post(
            "/channel/key/put",
            KeyPut {
                channel,
                epoch: 1,
                envelopes: vec![envelope.clone()],
                action: Some(rot),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // A blob, uploaded and attached. Its bytes are opaque to both exchanges.
    let sealed = vec![b"sealed chunk of an attachment".to_vec()];
    let id = blob_id(&sealed);
    let (code, body) = a
        .post(
            "/blob/begin",
            Begin { channel, size: sealed[0].len() as u64, chunks: 1, expires_after: 0 }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let upload = sqex_proto::blob_store::Begun::decode(&body).unwrap().upload;
    let (code, _) = a
        .post(
            "/blob/put",
            PutChunk { upload, index: 0, sealed: sealed[0].clone() }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (code, body) = a
        .post("/blob/commit", Commit { upload, blob: id }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let (code, body) = a
        .post("/blob/attach", ByChannelBlob { channel, blob: id, expires_after: 0 }.encode(sqex_proto::blob_store::TYPE_ATTACH))
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // A prekey at the origin, so the assertion further down that the replica
    // holds none is about replication declining to copy it rather than about
    // there having been nothing there.
    let mut pool = sqex_proto::prekey::Pool::new(&alice_seed);
    let (code, _) = a
        .post(
            "/prekey/publish",
            sqex_proto::prekey::Publish { prekeys: pool.mint_one_time(2) }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // And a profile, signed by its subject.
    let record = Record::sign(&alice_seed, &alice, 1, 1_700_000_000, Profile {
            flags: 0,
            name: "Alice".into(),
            title: String::new(),
            avatar: Vec::new(),
        });
    let (code, body) = a
        .post("/profile/put", ProfilePut { record }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Authorise, then pull the lot.
    let info = s.info(&mut a, channel).await;
    let action = s.action_at(&info, channel, sqex_proto::channel::EVENT_REPLICATE, &replica_key, &[]);
    let (code, body) = a
        .post(
            "/channel/replicate",
            ByAccount { channel, account: replica_key, action }.encode(TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    let replica = bind_replica(replica_dir.path()).await;
    let mut client = H3Client::connect(origin_addr, &origin_pub, &replica_sk.to_bytes())
        .await
        .unwrap();
    let spec = Origin {
        key: origin,
        addr: origin_addr,
        channels: vec![channel],
        interval: std::time::Duration::from_secs(1),
    };
    let took = pull_once(&mut client, &replica, &spec).await.unwrap();
    assert!(took.get(&channel).unwrap().stored > 0);

    // The envelope crossed, and Alice can ask the replica for her key.
    let got = replica
        .channels()
        .get_keys(&alice, &alice, &channel, 0)
        .expect("the replica would not serve a key it holds");
    assert_eq!(got.envelopes.len(), 1, "the key envelope did not cross");
    assert_eq!(got.envelopes[0].ciphertext, envelope.ciphertext);
    assert_eq!(got.envelopes[0].publisher, alice, "the publisher must survive");

    // The blob crossed, whole, and hashes to its own name — which is the only
    // check a blob needs and the reason it carries no signature.
    assert!(replica.channels().holds_blob(&id), "the blob did not cross");
    let chunk = replica
        .channels()
        .pull_blob(&channel, &id, 0)
        .expect("the replica holds the blob but will not read it");
    assert_eq!(blob_id(std::slice::from_ref(&chunk.sealed)), id);
    assert_eq!(chunk.sealed, sealed[0]);

    // **Prekeys did not cross, and must not.** SIP-23's whole value is that a
    // prekey is served once and destroyed on use; two exchanges each holding
    // the pool each serve the same one to a different sender, and the
    // recipient's duplicate check — SIP-23's own defence — fires on a condition
    // that has become normal. Nothing here replicates them, and this is what
    // says so.
    //
    // The control is that the origin *does* hold one for Alice — published
    // below before this ran — so an empty pool here is replication declining to
    // copy it rather than there being nothing to copy.
    let at_origin = a
        .post("/prekey/take", sqex_proto::prekey::Take { device: alice }.encode())
        .await
        .unwrap();
    assert_eq!(at_origin.0, 200);
    assert!(
        sqex_proto::prekey::Taken::decode(&at_origin.1).unwrap().found,
        "the origin should hold a prekey for Alice, or this proves nothing"
    );
    assert!(
        !replica.prekeys().take(&alice).found,
        "a replica served a prekey for an account whose home is the origin"
    );

    // The profile crossed, signed by its subject.
    let profile = replica
        .profiles()
        .get(&alice, &alice, &|_, _| true)
        .expect("the replica would not serve the profile");
    assert!(profile.found, "the profile did not cross");
    assert_eq!(profile.record.unwrap().serial, 1);

    // The negative control for the blob, which is the only one of the three
    // whose check is a hash rather than a signature: bytes that do not hash to
    // the name are not the blob, and must not be stored under it.
    let lying = PulledBlob { blobs: Vec::new(), sealed: b"different bytes entirely".to_vec() };
    assert_ne!(
        blob_id(&[lying.sealed]),
        id,
        "bytes that hash to the same name would make the check meaningless"
    );

}
