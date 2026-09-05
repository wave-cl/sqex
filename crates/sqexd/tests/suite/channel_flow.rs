//! End-to-end for SIP-16 channels over real HTTP/3.
//!
//! The slice these cover is public channels carrying text: no devices, no
//! envelopes, no blobs. That is deliberate — a public entry is unsealed, so
//! this exercises the parts every other chat SIP rests on (ordering,
//! membership, persistence, pruning, the long poll) without waiting on the
//! parts most likely to change.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    Action, ByChannel, ByChannelSigned, ByTarget, ChannelInfo, Create, Cursor, EVENT_CREATED,
    EVENT_JOINED, EVENT_LEFT, EVENT_RETENTION, Entries, Fetch, KIND_MEMBER, KIND_SYSTEM, List,
    Listing, MAX_RETENTION, MIN_RETENTION, Mark, Marks, Posted, Retain, Role, SignalOut, System,
    TYPE_CLOSE, TYPE_CURSORS, TYPE_INFO, TYPE_JOIN, TYPE_LEAVE, TYPE_REDACT, Visibility,
};
use sqex_proto::refusal::{Code, Refusal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Signer, instance_for};
use sqex_proto::entry_sig::GENESIS;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let config_toml = format!(
        // No welcome channel: these count what an account is in and what the
        // directory holds, and one that puts everybody into `general` on
        // sight moves both baselines. The front door has its own tests, in
        // sqex-chat's `public_join_flow`.
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n",
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

/// A connection and what signs on it.
///
/// They travel together because every write to a channel is now signed, and a
/// test holding them apart would have to thread a seed through every call.
/// `client` is public so the many helpers that only read still take a `Client`.
struct Peer {
    client: Client,
    signer: Signer,
}

async fn as_identity(addr: SocketAddr, server_pub: [u8; 32], seed: [u8; 32]) -> Peer {
    let key = PubKey::new(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
    Peer {
        client: Client::connect_as(addr, &server_pub, &seed).await.unwrap(),
        signer: Signer::new(seed, key, server_pub),
    }
}

fn public(signer: &Signer, channel: [u8; 32], name: &str) -> Create {
    signer.create(
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        name,
        vec![],
    )
}

/// Create a public channel, signed by the peer that is creating it.
///
/// A separate helper because the request has to be built from the signer
/// before the connection is borrowed to send it.
async fn create_public(peer: &mut Peer, channel: [u8; 32], name: &str) -> u16 {
    let req = public(&peer.signer, channel, name);
    create(peer, &req).await
}

/// The signature for a retention change. The pair is what it authorises, so
/// the pair is what it covers: a bare "somebody changed retention" would let a
/// signed request be replayed with different numbers.
async fn retention_action(
    peer: &mut Peer,
    channel: [u8; 32],
    retention_secs: u32,
    max_entries: u32,
) -> Action {
    let mut arg = Vec::with_capacity(8);
    arg.extend_from_slice(&retention_secs.to_be_bytes());
    arg.extend_from_slice(&max_entries.to_be_bytes());
    let account = peer.signer.account;
    peer.signer
        .action(&mut peer.client, channel, EVENT_RETENTION, &account, &arg)
        .await
}

async fn create(peer: &mut Peer, req: &Create) -> u16 {
    let (code, _) = peer
        .client
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    code
}

async fn join(peer: &mut Peer, channel: [u8; 32]) -> u16 {
    // Signed against the incarnation this test chose when it created the
    // channel. A joiner cannot ask `Info` for it — that needs the membership
    // the join is acquiring — so in the real client it comes from the
    // directory row the channel was found in.
    let action = peer.signer.action_outside(
        channel,
        instance_for(channel, 0),
        EVENT_JOINED,
        &peer.signer.account,
        &[],
        0,
        GENESIS,
    );
    let (code, _) = peer
        .client
        .post(
            "/channel/join",
            ByChannelSigned { channel, action }.encode(TYPE_JOIN),
        )
        .await
        .unwrap();
    code
}

async fn leave(peer: &mut Peer, channel: [u8; 32]) -> u16 {
    let account = peer.signer.account;
    let action = peer
        .signer
        .action(&mut peer.client, channel, EVENT_LEFT, &account, &[])
        .await;
    let (code, _) = peer
        .client
        .post(
            "/channel/leave",
            ByChannelSigned { channel, action }.encode(TYPE_LEAVE),
        )
        .await
        .unwrap();
    code
}

async fn post(peer: &mut Peer, channel: [u8; 32], text: &[u8]) -> (u16, Vec<u8>) {
    let req = peer
        .signer
        .post(&mut peer.client, channel, 0, 0, text.to_vec())
        .await;
    peer.client
        .post("/channel/post", req.encode())
        .await
        .unwrap()
}

async fn fetch(client: &mut Client, channel: [u8; 32], since: u64, wait: u16) -> (u16, Vec<u8>) {
    client
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since,
                wait_secs: wait,
                receipts: false,
            }
            .encode(),
        )
        .await
        .unwrap()
}

async fn info(client: &mut Client, channel: [u8; 32]) -> (u16, Vec<u8>) {
    client
        .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
        .await
        .unwrap()
}

/// The entries a member posted, which is what a client shows as messages.
/// The exchange's own entries share the sequence space and are folded into the
/// timeline separately.
fn messages(e: &Entries) -> Vec<&sqex_proto::channel::Entry> {
    e.entries.iter().filter(|x| x.kind == KIND_MEMBER).collect()
}

fn bodies(e: &Entries) -> Vec<Vec<u8>> {
    messages(e).iter().map(|x| x.body.clone()).collect()
}

/// The exchange's own entries: who did what to whom.
fn events(e: &Entries) -> Vec<System> {
    e.entries
        .iter()
        .filter(|x| x.kind == KIND_SYSTEM)
        .filter_map(|x| System::decode(&x.body).ok().flatten())
        .collect()
}

#[tokio::test]
async fn two_members_hold_a_conversation_in_one_order() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(21);
    let (bob_seed, _bob) = identity(22);
    let channel = [1u8; 32];

    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create_public(&mut a, channel, "planning").await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    for text in [&b"one"[..], b"two", b"three"] {
        assert_eq!(post(&mut a, channel, text).await.0, 200);
    }
    assert_eq!(post(&mut b, channel, b"four").await.0, 200);

    // The order is the exchange's, and it is the same order for everybody.
    let (code, body) = fetch(&mut b.client, channel, 0, 0).await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let seen = Entries::decode(&body, false).unwrap();
    assert_eq!(
        bodies(&seen),
        vec![
            b"one".to_vec(),
            b"two".to_vec(),
            b"three".to_vec(),
            b"four".to_vec()
        ]
    );
    // SIP-32's `created` is entry 1 and Bob's join is entry 2, so the messages
    // start at 3 — the exchange's own entries share the sequence space, which
    // is what makes interleaving free.
    assert_eq!(
        messages(&seen).iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![3, 4, 5, 6]
    );
    assert_eq!(events(&seen).len(), 2);
    assert_eq!(events(&seen)[0].event, EVENT_CREATED);
    assert_eq!(events(&seen)[1].event, EVENT_JOINED);

    let (_, body) = fetch(&mut a.client, channel, 0, 0).await;
    assert_eq!(
        bodies(&Entries::decode(&body, false).unwrap()),
        bodies(&seen)
    );

    // The creator is an admin and the joiner is not.
    let (_, body) = info(&mut a.client, channel).await;
    let seen = ChannelInfo::decode(&body).unwrap();
    assert_eq!(seen.members.len(), 2);
    let mine = seen.members.iter().find(|m| m.account == alice).unwrap();
    assert_eq!(mine.role, Role::Admin);
}

#[tokio::test]
async fn a_stranger_cannot_read_a_channel_it_has_not_joined() {
    // The load-bearing row of SIP-16's authorization table. A channel
    // identifier is not a way in.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(31);
    let (mallory_seed, _) = identity(32);
    let channel = [2u8; 32];

    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut m = as_identity(addr, pubkey, mallory_seed).await;

    assert_eq!(create_public(&mut a, channel, "members only").await, 200);
    assert_eq!(post(&mut a, channel, b"secret enough").await.0, 200);

    assert_eq!(fetch(&mut m.client, channel, 0, 0).await.0, 403);
    // Built without asking `Info`, which a stranger is refused anyway — the
    // refusal under test is the post's, not the lookup's.
    let stranger =
        m.signer
            .post_outside(channel, instance_for(channel, 0), 0, 0, b"hello".to_vec());
    assert_eq!(
        m.client
            .post("/channel/post", stranger.encode())
            .await
            .unwrap()
            .0,
        403
    );
    assert_eq!(info(&mut m.client, channel).await.0, 403);

    // Joining is what changes it, and a public channel lets anyone.
    assert_eq!(join(&mut m, channel).await, 200);
    let (code, body) = fetch(&mut m.client, channel, 0, 0).await;
    assert_eq!(code, 200);
    assert_eq!(
        bodies(&Entries::decode(&body, false).unwrap()),
        vec![b"secret enough".to_vec()]
    );
}

#[tokio::test]
async fn a_parked_fetch_is_answered_by_a_post() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(41);
    let (bob_seed, _) = identity(42);
    let channel = [3u8; 32];

    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;
    assert_eq!(create_public(&mut a, channel, "waiting").await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    // Bob's join is itself an entry, so catch up first: a fetch only parks
    // when there is genuinely nothing waiting.
    let (_, body) = fetch(&mut b.client, channel, 0, 0).await;
    let caught_up = Entries::decode(&body, false).unwrap().last;

    let waiter = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let (code, body) = fetch(&mut b.client, channel, caught_up, 20).await;
        (code, body, started.elapsed())
    });

    // Long enough that the fetch is certainly parked rather than answered by
    // the first read.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(post(&mut a, channel, b"woken").await.0, 200);

    let (code, body, elapsed) = waiter.await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(
        bodies(&Entries::decode(&body, false).unwrap()),
        vec![b"woken".to_vec()]
    );
    // Answered by the post, not by the timeout.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "waited {elapsed:?}"
    );
}

#[tokio::test]
async fn a_fetch_with_nothing_to_say_returns_empty_rather_than_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(51);
    let channel = [4u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    assert_eq!(create_public(&mut a, channel, "quiet").await, 200);

    let started = std::time::Instant::now();
    // From the `created` event onwards, so a long poll on a channel with
    // nothing said in it still has nothing to say.
    let (code, body) = fetch(&mut a.client, channel, 1, 1).await;
    assert_eq!(code, 200);
    assert!(Entries::decode(&body, false).unwrap().entries.is_empty());
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));
}

#[tokio::test]
async fn the_log_survives_a_restart() {
    // The claim that separates this service from every other one in the
    // daemon. If it fails, the service is not the service.
    let dir = tempfile::tempdir().unwrap();
    let (alice_seed, _) = identity(61);
    let channel = [5u8; 32];

    let (addr, pubkey, first) = server_in(dir.path()).await;
    {
        let mut a = as_identity(addr, pubkey, alice_seed).await;
        assert_eq!(create_public(&mut a, channel, "durable").await, 200);
        assert_eq!(post(&mut a, channel, b"before the restart").await.0, 200);
    }
    first.abort();
    let _ = first.await;

    let (addr, pubkey, _second) = server_in(dir.path()).await;
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let (code, body) = fetch(&mut a.client, channel, 0, 0).await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let seen = Entries::decode(&body, false).unwrap();
    assert_eq!(bodies(&seen), vec![b"before the restart".to_vec()]);

    // And the sequence continues rather than starting again, because next_seq
    // is stored rather than derived from what survives.
    // SIP-32's `created` is entry 1 and the pruned message was 2, so this is 3.
    let (_, body) = post(&mut a, channel, b"after").await;
    assert_eq!(Posted::decode(&body, false).unwrap().seq, 3);
}

#[tokio::test]
async fn retention_by_count_drops_the_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(71);
    let channel = [6u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    // Signed with the cap in place: SIP-32's `created` commits to
    // `max_entries`, so setting it on the request afterwards would leave a
    // signature for a channel nobody asked for.
    let req = a.signer.create_capped(
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        MAX_RETENTION,
        3,
        "short memory",
    );
    assert_eq!(create(&mut a, &req).await, 200);

    for i in 0..6u8 {
        assert_eq!(post(&mut a, channel, &[b'a' + i]).await.0, 200);
    }
    let (_, body) = fetch(&mut a.client, channel, 0, 0).await;
    let seen = Entries::decode(&body, false).unwrap();
    assert_eq!(bodies(&seen), vec![vec![b'd'], vec![b'e'], vec![b'f']]);

    // A client that was away longer than the window must be able to tell it
    // has a gap, which is what `first` is for.
    assert_eq!(seen.first, 5);
    assert_eq!(seen.last, 7);
}

#[tokio::test]
async fn a_public_channel_outlives_its_membership_and_a_private_one_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(81);
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    let open = [7u8; 32];
    let shut = [8u8; 32];
    assert_eq!(create_public(&mut a, open, "a place").await, 200);
    let priv_req = a.signer.create(
        shut,
        instance_for(shut, 0),
        Visibility::Private,
        3600,
        "",
        vec![],
    );
    assert_eq!(create(&mut a, &priv_req).await, 200);

    assert_eq!(leave(&mut a, open).await, 200);
    assert_eq!(leave(&mut a, shut).await, 200);

    // The public room is still there and its admin, who is no longer a member,
    // can still see it and close it.
    let (code, body) = info(&mut a.client, open).await;
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(ChannelInfo::decode(&body).unwrap().members.is_empty());

    // The private one went with its last member.
    assert_eq!(info(&mut a.client, shut).await.0, 404);

    let (code, _) = a
        .client
        .post(
            "/channel/close",
            ByChannel { channel: open }.encode(TYPE_CLOSE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(info(&mut a.client, open).await.0, 404);
}

#[tokio::test]
async fn the_directory_lists_public_channels_only() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(91);
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    assert_eq!(create_public(&mut a, [10u8; 32], "rust talk").await, 200);
    assert_eq!(create_public(&mut a, [11u8; 32], "garden talk").await, 200);
    let hidden = a.signer.create(
        [12u8; 32],
        instance_for([12u8; 32], 0),
        Visibility::Private,
        3600,
        "should not appear",
        vec![],
    );
    assert_eq!(create(&mut a, &hidden).await, 200);

    let (code, body) = a
        .client
        .post(
            "/channel/list",
            List {
                offset: 0,
                query: String::new(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let listing = Listing::decode(&body).unwrap();
    assert_eq!(listing.total, 2);
    let names: Vec<&str> = listing.channels.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"rust talk") && names.contains(&"garden talk"));
    assert!(!names.contains(&"should not appear"));

    // A private channel's name is not stored at the exchange at all, so it
    // cannot leak through a query that happens to match it.
    let (_, body) = a
        .client
        .post(
            "/channel/list",
            List {
                offset: 0,
                query: "should".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(Listing::decode(&body).unwrap().total, 0);
}

#[tokio::test]
async fn retention_outside_the_permitted_range_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(101);
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    let mut too_short = public(&a.signer, [13u8; 32], "blink");
    too_short.retention_secs = MIN_RETENTION - 1;
    assert_eq!(create(&mut a, &too_short).await, 409);
}

#[tokio::test]
async fn an_anonymous_connection_has_no_membership() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(111);
    let channel = [14u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    assert_eq!(
        create_public(&mut a, channel, "named callers only").await,
        200
    );

    // Client::connect does not advertise an identity (SIP-3 is opt-in), and
    // every channel route refuses a connection carrying none.
    let mut anon = Client::connect(addr, &pubkey).await.unwrap();
    assert_eq!(fetch(&mut anon, channel, 0, 0).await.0, 403);
    // Built by hand rather than through `join`, which would first ask
    // `/channel/info` to sign against — and be refused there instead, which is
    // the right answer for the wrong reason. The signature is never reached:
    // no identity is refused before anything is verified.
    let unsigned = ByChannelSigned {
        channel,
        action: Action {
            chain_seq: 0,
            prev: [0; 32],
            sig: [0; 64],
        },
    };
    let (code, _) = anon
        .post("/channel/join", unsigned.encode(TYPE_JOIN))
        .await
        .unwrap();
    assert_eq!(code, 403);
}

async fn cursor(client: &mut Client, channel: [u8; 32], read: u64, receipts: bool) -> u16 {
    let (code, _) = client
        .post(
            "/channel/cursor",
            Cursor {
                channel,
                read,
                receipts,
            }
            .encode(),
        )
        .await
        .unwrap();
    code
}

async fn marks(client: &mut Client, channel: [u8; 32]) -> Marks {
    let (code, body) = client
        .post(
            "/channel/cursors",
            ByChannel { channel }.encode(TYPE_CURSORS),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Marks::decode(&body).unwrap()
}

fn mark_of(m: &Marks, who: &PubKey) -> Mark {
    *m.marks.iter().find(|x| &x.account == who).unwrap()
}

#[tokio::test]
async fn delivery_is_observed_and_reading_is_asserted() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(121);
    let (bob_seed, bob) = identity(122);
    let channel = [20u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create_public(&mut a, channel, "receipts").await, 200);
    assert_eq!(join(&mut b, channel).await, 200);
    for t in [&b"one"[..], b"two", b"three"] {
        assert_eq!(post(&mut a, channel, t).await.0, 200);
    }

    // Bob collects everything. He never says so — asking for what comes after 0
    // and being handed three entries is the exchange watching him do it.
    let (_, body) = fetch(&mut b.client, channel, 0, 0).await;
    let seen = Entries::decode(&body, false).unwrap();
    assert_eq!(messages(&seen).len(), 3);
    // Five in all: SIP-32's `created`, Bob's join, then three messages.
    assert_eq!(seen.entries.len(), 5);
    let last = seen.last;

    let m = marks(&mut b.client, channel).await;
    assert_eq!(mark_of(&m, &bob).delivered, last);
    assert_eq!(mark_of(&m, &bob).read, 0, "collected is not read");

    assert_eq!(cursor(&mut b.client, channel, 2, true).await, 200);
    let m = marks(&mut a.client, channel).await;
    assert_eq!(mark_of(&m, &bob).read, 2);
    let delivered = mark_of(&m, &bob).delivered;

    // A mark cannot run ahead of what was delivered: a client may not claim to
    // have read further than it collected.
    assert_eq!(cursor(&mut b.client, channel, 99, true).await, 200);
    assert_eq!(
        mark_of(&marks(&mut a.client, channel).await, &bob).read,
        delivered
    );

    // Nor backwards.
    assert_eq!(cursor(&mut b.client, channel, 1, true).await, 200);
    assert_eq!(
        mark_of(&marks(&mut a.client, channel).await, &bob).read,
        delivered
    );
    assert_eq!(
        mark_of(&marks(&mut a.client, channel).await, &alice).delivered,
        0
    );
}

#[tokio::test]
async fn opting_out_of_receipts_withholds_others_reading_but_not_their_delivery() {
    // The reciprocity is enforced at the exchange rather than left to a client
    // that might simply not honour it — which is what stops somebody taking
    // the signal without giving it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(131);
    let (bob_seed, _bob) = identity(132);
    let channel = [21u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create_public(&mut a, channel, "quiet reader").await, 200);
    assert_eq!(join(&mut b, channel).await, 200);
    assert_eq!(post(&mut a, channel, b"hello").await.0, 200);

    let (_, body) = fetch(&mut a.client, channel, 0, 0).await;
    let last = Entries::decode(&body, false).unwrap().last;
    assert_eq!(cursor(&mut a.client, channel, last, true).await, 200);

    // Bob reads, and opts out.
    fetch(&mut b.client, channel, 0, 0).await;
    assert_eq!(cursor(&mut b.client, channel, last, false).await, 200);

    let seen = marks(&mut b.client, channel).await;
    assert_eq!(
        mark_of(&seen, &alice).read,
        0,
        "he gave nothing, he sees nothing"
    );
    assert!(
        mark_of(&seen, &alice).delivered > 0,
        "delivery is never withheld"
    );

    // Alice still gave hers, so she still sees his.
    assert!(mark_of(&marks(&mut a.client, channel).await, &alice).read > 0);
}

#[tokio::test]
async fn a_redaction_leaves_a_tombstone_and_a_stranger_cannot_make_one() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(141);
    let (bob_seed, _) = identity(142);
    let channel = [22u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create_public(&mut a, channel, "regrets").await, 200);
    assert_eq!(join(&mut b, channel).await, 200);
    let (_, body) = post(&mut b, channel, b"said too much").await;
    let bobs = Posted::decode(&body, false).unwrap().seq;

    let redact = |c: [u8; 32], t: u64| {
        ByTarget {
            channel: c,
            target: t,
        }
        .encode(TYPE_REDACT)
    };

    // Neither a stranger to the entry nor a plain member may redact it.
    let (mallory_seed, _) = identity(143);
    let mut m = as_identity(addr, pubkey, mallory_seed).await;
    assert_eq!(join(&mut m, channel).await, 200);
    let (code, _) = m
        .client
        .post("/channel/redact", redact(channel, bobs))
        .await
        .unwrap();
    assert_eq!(code, 403);

    // Nor may an admin reach the exchange's own record of who did what: an
    // audit trail its subject can erase is not one.
    let (code, _) = a
        .client
        .post("/channel/redact", redact(channel, 1))
        .await
        .unwrap();
    assert_eq!(code, 409, "a system entry is never redactable");

    // Its author may.
    let (code, _) = b
        .client
        .post("/channel/redact", redact(channel, bobs))
        .await
        .unwrap();
    assert_eq!(code, 200);

    // The entry survives as a gap, which is the record.
    let (_, body) = fetch(&mut a.client, channel, 0, 0).await;
    let seen = Entries::decode(&body, false).unwrap();
    let mine: Vec<_> = messages(&seen)
        .into_iter()
        .filter(|e| e.seq == bobs)
        .collect();
    assert_eq!(mine.len(), 1, "the entry is still there");
    assert!(mine[0].body.is_empty(), "and its body is not");

    // An admin may redact somebody else's, which is the moderation path.
    let (_, body) = post(&mut b, channel, b"again").await;
    let again = Posted::decode(&body, false).unwrap().seq;
    let (code, _) = a
        .client
        .post("/channel/redact", redact(channel, again))
        .await
        .unwrap();
    assert_eq!(code, 200);

    let (code, _) = a
        .client
        .post("/channel/redact", redact(channel, 99))
        .await
        .unwrap();
    assert_eq!(code, 404, "nothing to redact");
}

#[tokio::test]
async fn a_signal_reaches_the_others_once_and_is_never_stored() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(151);
    let (bob_seed, _) = identity(152);
    let channel = [23u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create_public(&mut a, channel, "typing").await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    let (code, _) = a
        .client
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind: 0x01,
                body: vec![1],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let (_, body) = fetch(&mut b.client, channel, 0, 0).await;
    let seen = Entries::decode(&body, false).unwrap();
    assert_eq!(seen.signals.len(), 1);
    assert_eq!(seen.signals[0].account, alice);
    assert_eq!(seen.signals[0].kind, 0x01);
    assert!(messages(&seen).is_empty(), "a signal is not an entry");

    // Delivered at most once, and it left nothing behind.
    let (_, body) = fetch(&mut b.client, channel, 0, 0).await;
    assert!(Entries::decode(&body, false).unwrap().signals.is_empty());

    // The sender does not receive their own.
    let (_, body) = fetch(&mut a.client, channel, 0, 0).await;
    assert!(Entries::decode(&body, false).unwrap().signals.is_empty());
}

#[tokio::test]
async fn a_parked_fetch_is_answered_by_a_signal_too() {
    // SIP-16: a held request returns as soon as an entry is accepted *or* a
    // signal arrives for the caller.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(161);
    let (bob_seed, _) = identity(162);
    let channel = [24u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;
    assert_eq!(create_public(&mut a, channel, "waiting").await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    let (_, body) = fetch(&mut b.client, channel, 0, 0).await;
    let caught_up = Entries::decode(&body, false).unwrap().last;

    let waiter = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let (code, body) = fetch(&mut b.client, channel, caught_up, 20).await;
        (code, body, started.elapsed())
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    a.client
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind: 0x01,
                body: vec![1],
            }
            .encode(),
        )
        .await
        .unwrap();

    let (code, body, elapsed) = waiter.await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(Entries::decode(&body, false).unwrap().signals.len(), 1);
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "waited {elapsed:?}"
    );
}

#[tokio::test]
async fn an_invitee_can_discover_the_private_channel_they_were_added_to() {
    // The gap this route closes. A private channel is absent from the
    // directory by construction and its identifier is 32 bytes, so before
    // `Mine` an invitation reached an account with no way to learn it had
    // happened — the identifier had to arrive out of band or the channel was
    // unreachable. A direct message escapes that only because its identifier
    // derives from its two members.
    use sqex_proto::channel::{Mine, Mines};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _alice) = identity(1);
    let (bob_seed, bob) = identity(2);
    let mut a = as_identity(addr, server_pub, alice_seed).await;
    let mut b = as_identity(addr, server_pub, bob_seed).await;

    let channel = [0x33; 32];
    let req = a.signer.create(
        channel,
        instance_for(channel, 0),
        Visibility::Private,
        3600,
        "",
        vec![sqex_proto::channel::Invitee {
            account: bob,
            role: Role::Member,
        }],
    );
    let (code, _) = a
        .client
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);

    // Bob was never told the identifier, and the directory will not say.
    let (code, body) = b
        .client
        .post(
            "/channel/list",
            sqex_proto::channel::List {
                offset: 0,
                query: String::new(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(
        sqex_proto::channel::Listing::decode(&body)
            .unwrap()
            .channels
            .is_empty(),
        "a private channel appeared in the public directory"
    );

    // He asks what he is in, and finds it.
    let (code, body) = b
        .client
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    let mine = Mines::decode(&body).unwrap();
    assert_eq!(mine.total, 1);
    assert_eq!(mine.channels.len(), 1);
    assert_eq!(mine.channels[0].channel, channel);
    assert_eq!(mine.channels[0].visibility, Visibility::Private);
    assert_eq!(mine.channels[0].role, Role::Member);
    // Alice created it, so she is its admin and sees the same channel.
    let (_, body) = a
        .client
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(Mines::decode(&body).unwrap().channels[0].role, Role::Admin);
}

#[tokio::test]
async fn mine_answers_about_the_caller_and_nobody_else() {
    use sqex_proto::channel::{Mine, Mines};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(1);
    let (stranger_seed, _) = identity(9);
    let mut a = as_identity(addr, server_pub, alice_seed).await;
    let mut s = as_identity(addr, server_pub, stranger_seed).await;

    create_public(&mut a, [0x41; 32], "alice's room").await;

    // The request names no account, so there is no way to ask about one. A
    // stranger asking gets their own empty list, not hers.
    let (code, body) = s
        .client
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(Mines::decode(&body).unwrap().channels.is_empty());

    // And an anonymous connection has no memberships to report.
    let mut anon = Client::connect(addr, &server_pub).await.unwrap();
    let (code, body) = anon
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 403, "an unidentified caller was answered");
    assert_eq!(
        Refusal::decode(&body).unwrap().code,
        Code::NoIdentity,
        "an unidentified caller should be told why"
    );
}

#[tokio::test]
async fn mine_pages_and_reports_the_window_and_the_read_mark() {
    use sqex_proto::channel::{Cursor, MAX_MINE, Mine, Mines};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(1);
    let mut a = as_identity(addr, server_pub, alice_seed).await;

    for n in 0..(MAX_MINE + 5) {
        let mut id = [0u8; 32];
        id[0] = n as u8;
        id[1] = (n >> 8) as u8;
        create_public(&mut a, id, &format!("room {n}")).await;
    }

    let (_, body) = a
        .client
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    let first = Mines::decode(&body).unwrap();
    assert_eq!(first.total as usize, MAX_MINE + 5, "total counts them all");
    assert_eq!(first.channels.len(), MAX_MINE, "one reply is bounded");

    let (_, body) = a
        .client
        .post(
            "/channel/mine",
            Mine {
                offset: MAX_MINE as u32,
            }
            .encode(),
        )
        .await
        .unwrap();
    let second = Mines::decode(&body).unwrap();
    assert_eq!(second.channels.len(), 5);
    // No overlap: paging by offset over a stable order.
    assert!(second.channels.iter().all(|m| !first.channels.contains(m)));

    // Post, read, and see both reflected without a second call per channel.
    let mut id = [0u8; 32];
    id[0] = 0;
    post(&mut a, id, b"hello").await;
    post(&mut a, id, b"again").await;
    // Fetch before marking read, which is what a client actually does and what
    // the mark means. `delivered` is what the exchange handed over, and it has
    // handed Alice nothing — supplying an entry is not collecting one — so a
    // read mark set before any fetch is clamped to zero. This test used to pass
    // without the fetch only because `delivered` folded in the caller's own
    // `since`, which let a request name its own delivery receipt.
    fetch(&mut a.client, id, 0, 0).await;
    let (_, body) = a
        .client
        .post(
            "/channel/cursor",
            Cursor {
                channel: id,
                read: 1,
                receipts: true,
            }
            .encode(),
        )
        .await
        .unwrap();
    let _ = body;
    let (_, body) = a
        .client
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    let mine = Mines::decode(&body).unwrap();
    let row = mine.channels.iter().find(|m| m.channel == id).unwrap();
    assert_eq!(row.read, 1, "the read mark did not travel");
    assert!(row.last >= 2, "the window did not travel: {row:?}");
    assert!(row.first >= 1);
}

#[tokio::test]
async fn leaving_removes_a_channel_from_mine() {
    use sqex_proto::channel::{Mine, Mines};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(1);
    let (bob_seed, _) = identity(2);
    let mut a = as_identity(addr, server_pub, alice_seed).await;
    let mut b = as_identity(addr, server_pub, bob_seed).await;

    let channel = [0x55; 32];
    create_public(&mut a, channel, "a room").await;
    join(&mut b, channel).await;

    let (_, body) = b
        .client
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(Mines::decode(&body).unwrap().channels.len(), 1);

    leave(&mut b, channel).await;
    let (_, body) = b
        .client
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    assert!(
        Mines::decode(&body).unwrap().channels.is_empty(),
        "a channel somebody left is still listed as theirs"
    );
}

/// `/channel/retain` had no test anywhere in this workspace. It is the one
/// route in the lifecycle nothing exercised, and it both rewrites the window
/// and prunes against it immediately — so getting it wrong deletes messages.
#[tokio::test]
async fn narrowing_retention_drops_what_now_falls_outside_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice_key) = identity(101);
    let channel = [21u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    assert_eq!(create_public(&mut a, channel, "a long memory").await, 200);
    for i in 0..6u8 {
        assert_eq!(post(&mut a, channel, &[b'a' + i]).await.0, 200);
    }
    assert_eq!(
        bodies(&Entries::decode(&fetch(&mut a.client, channel, 0, 0).await.1, false).unwrap())
            .len(),
        6
    );

    let action = retention_action(&mut a, channel, MIN_RETENTION, 3).await;
    let (code, _) = a
        .client
        .post(
            "/channel/retain",
            Retain {
                channel,
                retention_secs: MIN_RETENTION,
                max_entries: 3,
                action,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // Not a policy that takes effect later: the exchange prunes as part of the
    // same transaction, so narrowing a window is a deletion.
    //
    // Two messages out of a limit of three, because the record of the change
    // itself is an entry and occupies one of the places. Worth knowing: asking
    // for a limit of two here keeps one message.
    let seen = Entries::decode(&fetch(&mut a.client, channel, 0, 0).await.1, false).unwrap();
    assert_eq!(bodies(&seen), vec![vec![b'e'], vec![b'f']]);

    // And a reader is told where the surviving history starts, or it would
    // present what is left as the whole conversation.
    assert_eq!(seen.first, 6);

    // The change is recorded, so a member can see that somebody narrowed it
    // rather than finding messages missing with no explanation.
    let system: Vec<System> = seen
        .entries
        .iter()
        .filter(|e| e.kind == KIND_SYSTEM)
        .filter_map(|e| System::decode(&e.body).ok().flatten())
        .collect();
    assert!(
        system
            .iter()
            .any(|s| s.event == EVENT_RETENTION && s.actor == alice_key),
        "narrowing the window left no record of who did it"
    );

    let info = ChannelInfo::decode(&info(&mut a.client, channel).await.1).unwrap();
    assert_eq!(info.retention_secs, MIN_RETENTION);
    assert_eq!(info.max_entries, 3);
}

#[tokio::test]
async fn only_an_admin_may_change_retention() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(102);
    let (bob_seed, _) = identity(103);
    let channel = [22u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create_public(&mut a, channel, "not yours").await, 200);
    assert_eq!(join(&mut b, channel).await, 200);
    assert_eq!(post(&mut a, channel, b"keep me").await.0, 200);

    let narrow = Retain {
        channel,
        retention_secs: MIN_RETENTION,
        max_entries: 1,
        action: retention_action(&mut a, channel, MIN_RETENTION, 1).await,
    }
    .encode();
    let (code, _) = b
        .client
        .post("/channel/retain", narrow.clone())
        .await
        .unwrap();
    assert_ne!(
        code, 200,
        "a member who is not an admin narrowed the window"
    );

    // A member being able to do this would be a member being able to delete
    // everybody's history, so the refusal is the whole point.
    let seen = Entries::decode(&fetch(&mut b.client, channel, 0, 0).await.1, false).unwrap();
    assert_eq!(bodies(&seen), vec![b"keep me".to_vec()]);
}

#[tokio::test]
async fn retention_outside_the_permitted_range_is_refused_by_retain_too() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(104);
    let channel = [23u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    assert_eq!(create_public(&mut a, channel, "bounded").await, 200);

    // Create enforces the range. Retain is a second door into the same field
    // and has to enforce it as well, or the bound is only a default.
    for secs in [0, MIN_RETENTION - 1, MAX_RETENTION + 1] {
        let action = retention_action(&mut a, channel, secs, 0).await;
        let (code, _) = a
            .client
            .post(
                "/channel/retain",
                Retain {
                    channel,
                    retention_secs: secs,
                    max_entries: 0,
                    action,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_ne!(code, 200, "retention of {secs} was accepted");
    }

    let info = ChannelInfo::decode(&info(&mut a.client, channel).await.1).unwrap();
    assert_eq!(info.retention_secs, 3600, "a refused change took effect");
}
