//! End-to-end for SIP-21 profiles and blocking over real HTTP/3.
//!
//! Blocking is the interesting half, and what it claims is narrow: nothing
//! *states* that a block happened. It is not undetectable, and these tests say
//! so in both directions.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByChannel, ChannelInfo, Create, Invitee, Role, TYPE_INFO, TYPE_INVITE, Visibility,
    direct_message_id,
};
use sqex_proto::profile::{
    Block, Blocks, ByAccount, FLAG_WITHHOLD, Record, Got, MAX_UPDATES_PER_HOUR, Profile, Put, TYPE_GET,
};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

mod common;
use common::{Chain, Signer, instance_for};
use sqex_proto::channel::{ByChannelSigned, EVENT_ADDED, EVENT_JOINED};
use sqex_proto::entry_sig::GENESIS;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n",
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

async fn peer(addr: SocketAddr, pubkey: [u8; 32], b: u8) -> (Client, PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    let seed = sk.to_bytes();
    (
        Client::connect_as(addr, &pubkey, &seed).await.unwrap(),
        PubKey::new(sk.verifying_key().to_bytes()),
    )
}

/// Where a creator's chain stands after SIP-32's `created` event.
fn created_head(s: &Signer, channel: [u8; 32], visibility: Visibility, name: &str) -> [u8; 32] {
    let mut chain = Chain::default();
    let _ = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        visibility,
        3600,
        name,
        vec![],
    );
    chain.head
}

/// What signs for identity `b` against this exchange (SIP-31).
fn signer(pubkey: [u8; 32], b: u8) -> Signer {
    let sk = SigningKey::from_bytes(&[b; 32]);
    Signer::new(sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()), pubkey)
}

fn profile(name: &str, title: &str, flags: u8) -> Profile {
    Profile {
        flags,
        name: name.into(),
        title: title.into(),
        avatar: vec![0xab; 64],
    }
}

/// A signed profile record, at a serial that climbs each time so it never
/// loses to what the exchange already holds.
async fn put_as(c: &mut Client, seed: &[u8; 32], account: &PubKey, serial: u64, p: Profile) -> u16 {
    let record = Record::sign(seed, account, serial, 1_000_000 + serial, p);
    c.post("/profile/put", Put { record }.encode())
        .await
        .unwrap()
        .0
}

async fn get(c: &mut Client, who: &PubKey) -> Got {
    let (code, body) = c
        .post("/profile/get", ByAccount { account: *who }.encode(TYPE_GET))
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Got::decode(&body).unwrap()
}

async fn block(c: &mut Client, who: &PubKey, add: bool) -> u16 {
    c.post("/block/set", Block { account: *who, add }.encode())
        .await
        .unwrap()
        .0
}

fn public(signer: &Signer, channel: [u8; 32]) -> Create {
    signer.create(channel, instance_for(channel, 0), Visibility::Public, 3600, "shared", vec![])
}

#[tokio::test]
async fn a_profile_is_published_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice) = peer(addr, pubkey, 21).await;
    let (mut b, _) = peer(addr, pubkey, 22).await;

    assert!(!get(&mut b, &alice).await.found, "nothing published yet");
    assert_eq!(put_as(&mut a, &[21; 32], &alice, 1, profile("Colin Lyons", "Infrastructure", 0)).await, 200);

    let got = get(&mut b, &alice).await;
    assert!(got.found);
    assert_eq!(got.profile().name, "Colin Lyons");
    assert_eq!(got.profile().title, "Infrastructure");
    assert!(got.updated > 0);

    // Replacement is whole: there is no partial update to get wrong.
    assert_eq!(put_as(&mut a, &[21; 32], &alice, 2, profile("C. Lyons", "", 0)).await, 200);
    let got = get(&mut b, &alice).await;
    assert_eq!(got.profile().name, "C. Lyons");
    assert!(got.profile().title.is_empty());
}

#[tokio::test]
async fn a_withheld_profile_looks_exactly_like_one_that_does_not_exist() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice) = peer(addr, pubkey, 31).await;
    let (mut b, bob) = peer(addr, pubkey, 32).await;
    let (_, never) = peer(addr, pubkey, 33).await;
    let channel = [1u8; 32];

    assert_eq!(put_as(&mut a, &[31; 32], &alice, 1, profile("Hidden", "", FLAG_WITHHOLD)).await, 200);

    // A stranger is told the same thing about a withheld profile as about one
    // that was never published. Answering "exists but hidden" would itself be
    // the disclosure.
    let withheld = get(&mut b, &alice).await;
    let absent = get(&mut b, &never).await;
    assert_eq!(withheld, Got { now: withheld.now, ..absent.clone() });
    assert!(!withheld.found);

    // Sharing a channel is the visibility rule, and it is a relationship the
    // exchange already knows.
    a.post("/channel/create", public(&signer(pubkey, 31), channel).encode())
        .await
        .unwrap();
    let joining = signer(pubkey, 32).action_outside(
        channel,
        instance_for(channel, 0),
        EVENT_JOINED,
        &bob,
        &[],
        0,
        GENESIS,
    );
    b.post(
        "/channel/join",
        ByChannelSigned { channel, action: joining }.encode(sqex_proto::channel::TYPE_JOIN),
    )
    .await
    .unwrap();
    assert!(get(&mut b, &alice).await.found, "now they share a room");

    // And she always sees her own, whatever the flag says.
    assert!(get(&mut a, &alice).await.found);
}

#[tokio::test]
async fn a_blocked_invitation_is_dropped_and_answered_as_though_it_landed() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, alice_key) = peer(addr, pubkey, 41).await;
    let (mut mallory, _) = peer(addr, pubkey, 42).await;
    let channel = [2u8; 32];

    assert_eq!(block(&mut alice, &{ let (_, m) = peer(addr, pubkey, 42).await; m }, true).await, 200);

    // Built private rather than built public and flipped: SIP-32's `created`
    // commits to the visibility and the name.
    let req = signer(pubkey, 42).create(
        channel,
        instance_for(channel, 0),
        Visibility::Private,
        3600,
        "",
        vec![],
    );
    let (code, body) = mallory.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    let mut invite = vec![TYPE_INVITE];
    invite.extend_from_slice(&channel);
    invite.extend_from_slice(alice_key.as_bytes());
    invite.push(Role::Member as u8);
    // Position 1: SIP-32's `created` took 0.
    signer(pubkey, 42)
        .action_outside(
            channel,
            instance_for(channel, 0),
            EVENT_ADDED,
            &alice_key,
            &[Role::Member as u8],
            1,
            created_head(&signer(pubkey, 42), channel, Visibility::Private, ""),
        )
        .write(&mut invite);
    let (code, _) = mallory.post("/channel/invite", invite).await.unwrap();
    assert_eq!(code, 200, "the request succeeds, as it must");

    // Nothing was delivered. This is the exchange answering untruthfully on
    // the blocker's behalf, which is what a block is.
    let (code, body) = mallory
        .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(code, 200);
    let info = ChannelInfo::decode(&body).unwrap();
    assert_eq!(info.members.len(), 1, "and inferable from exactly this");
    assert!(!info.members.iter().any(|m| m.account == alice_key));

    // Alice was never added, so the channel is not hers to read.
    let (code, _) = alice
        .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(code, 403);
}

#[tokio::test]
async fn a_blocked_direct_message_leaves_the_sender_alone_in_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, alice_key) = peer(addr, pubkey, 51).await;
    let (mut mallory, mallory_key) = peer(addr, pubkey, 52).await;

    assert_eq!(block(&mut alice, &mallory_key, true).await, 200);

    let dm = direct_message_id(&alice_key, &mallory_key);
    let (code, _) = mallory
        .post(
            "/channel/create",
            signer(pubkey, 52)
                .create(
                    dm,
                    instance_for(dm, 0),
                    Visibility::Private,
                    3600,
                    "",
                    vec![Invitee { account: alice_key, role: Role::Admin }],
                )
                .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "the create succeeds");

    let (_, body) = mallory
        .post("/channel/info", ByChannel { channel: dm }.encode(TYPE_INFO))
        .await
        .unwrap();
    let info = ChannelInfo::decode(&body).unwrap();
    assert_eq!(info.members.len(), 1, "alone in it, and may post indefinitely");

    // Unblocking and creating again lets Alice take her half of the
    // identifier, which is hers by arithmetic.
    assert_eq!(block(&mut alice, &mallory_key, false).await, 200);
    // A fresh incarnation: Mallory's is retired, and the exchange refuses a
    // repeat so the entries signed under it can never be replayed into the
    // channel Alice is taking over.
    let (code, body) = alice
        .post(
            "/channel/create",
            signer(pubkey, 51)
                .create(
                    dm,
                    instance_for(dm, 1),
                    Visibility::Private,
                    3600,
                    "",
                    vec![Invitee { account: mallory_key, role: Role::Admin }],
                )
                .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    // She is *returning*, not taking the identifier over: Mallory's create put
    // her in the channel and the block only kept her from being told. So the
    // first create is answered `created: 0` with the incarnation that stands
    // and changes nothing, and the second names it and signs the `joined` the
    // exchange will actually write. One extra round trip, only here.
    let standing = sqex_proto::channel::Created::decode(&body).unwrap().instance;
    let me = signer(pubkey, 51);
    let mut back = me.create(
        dm,
        standing,
        Visibility::Private,
        3600,
        "",
        vec![Invitee { account: mallory_key, role: Role::Admin }],
    );
    back.actions = vec![me.action_outside(
        dm,
        standing,
        EVENT_JOINED,
        &alice_key,
        &[],
        0,
        GENESIS,
    )];
    let (code, body) = alice.post("/channel/create", back.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let (code, body) = alice
        .post("/channel/info", ByChannel { channel: dm }.encode(TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(ChannelInfo::decode(&body).unwrap().members.len(), 2);
}

#[tokio::test]
async fn a_blocked_account_is_told_nothing_about_the_blocker() {
    // Including the avatar: a client should not be decoding an image for
    // somebody it has been asked to keep away.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, alice_key) = peer(addr, pubkey, 61).await;
    let (mut mallory, mallory_key) = peer(addr, pubkey, 62).await;

    assert_eq!(put_as(&mut alice, &[61; 32], &alice_key, 1, profile("Alice", "", 0)).await, 200);
    assert!(get(&mut mallory, &alice_key).await.found);

    assert_eq!(block(&mut alice, &mallory_key, true).await, 200);
    let got = get(&mut mallory, &alice_key).await;
    assert!(!got.found);
    assert!(got.profile().avatar.is_empty());

    // Everybody else still sees it.
    let (mut bob, _) = peer(addr, pubkey, 63).await;
    assert!(get(&mut bob, &alice_key).await.found);
}

#[tokio::test]
async fn a_block_list_is_returned_only_to_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = peer(addr, pubkey, 71).await;
    let (mut bob, bob_key) = peer(addr, pubkey, 72).await;

    assert_eq!(block(&mut alice, &bob_key, true).await, 200);

    let (code, body) = alice.post("/block/list", vec![]).await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(Blocks::decode(&body).unwrap().accounts, vec![bob_key]);

    // Bob asking gets his own list, which is empty. There is no argument to
    // pass, so he cannot ask about anybody else's.
    let (code, body) = bob.post("/block/list", vec![]).await.unwrap();
    assert_eq!(code, 200);
    assert!(Blocks::decode(&body).unwrap().accounts.is_empty());

    assert_eq!(block(&mut alice, &bob_key, false).await, 200);
    let (_, body) = alice.post("/block/list", vec![]).await.unwrap();
    assert!(Blocks::decode(&body).unwrap().accounts.is_empty());
}

/// **SIP-32: the highest serial wins, and a record at or below the one held is
/// refused.**
///
/// Untested until now, and untestable by accident: the `put_as` helper climbs
/// the serial every time it is called — it says so in its own doc comment —
/// so every existing test drives the accepting path and nothing ever drove the
/// refusal. That is the shape this repository has been caught by before: where
/// a rule distinguishes two cases, the tests need one of each.
///
/// A counter rather than a clock is the whole mechanism here, and what it buys
/// is that a stale record *loses* rather than merely looking old. An exchange
/// that accepted a replayed record would let anyone who kept a copy of an old
/// profile put it back.
#[tokio::test]
async fn a_profile_at_or_below_the_serial_held_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice) = peer(addr, pubkey, 91).await;

    assert_eq!(
        put_as(&mut a, &[91; 32], &alice, 5, profile("current", "", 0)).await,
        200,
        "the honest put must land, or the rest of this proves nothing"
    );

    // The same serial again: a replay of what is already held.
    assert_eq!(
        put_as(&mut a, &[91; 32], &alice, 5, profile("replayed", "", 0)).await,
        409,
        "a record at the serial held must be refused"
    );
    // And one below it.
    assert_eq!(
        put_as(&mut a, &[91; 32], &alice, 4, profile("older still", "", 0)).await,
        409,
        "a record below the serial held must be refused"
    );

    // What is served is still the record that won.
    let got = get(&mut a, &alice).await;
    assert!(got.found);
    assert_eq!(
        got.profile().name, "current",
        "a refused record must not have overwritten the one held"
    );
}

#[tokio::test]
async fn profile_updates_are_rate_limited() {
    // A profile is served to everyone who shares a channel with its subject,
    // so rewriting it repeatedly makes the exchange serve traffic on somebody
    // else's behalf.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice) = peer(addr, pubkey, 81).await;

    // A climbing serial each time: the rate limit is what should refuse the
    // last one, not a stale record losing to the one before it.
    for i in 0..MAX_UPDATES_PER_HOUR {
        let s = i as u64 + 1;
        assert_eq!(
            put_as(&mut a, &[81; 32], &alice, s, profile(&format!("n{i}"), "", 0)).await,
            200,
            "at {i}"
        );
    }
    let over = MAX_UPDATES_PER_HOUR as u64 + 1;
    assert_eq!(put_as(&mut a, &[81; 32], &alice, over, profile("one too many", "", 0)).await, 507);
}

#[tokio::test]
async fn the_profile_store_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (alice_b, mallory_b) = (91u8, 92u8);

    let (addr, pubkey, first) = server_in(dir.path()).await;
    let alice_key;
    let mallory_key;
    {
        let (mut a, ak) = peer(addr, pubkey, alice_b).await;
        let (_, mk) = peer(addr, pubkey, mallory_b).await;
        alice_key = ak;
        mallory_key = mk;
        assert_eq!(put_as(&mut a, &[alice_b; 32], &alice_key, 1, profile("Durable", "", 0)).await, 200);
        assert_eq!(block(&mut a, &mallory_key, true).await, 200);
    }
    first.abort();
    let _ = first.await;

    let (addr, pubkey, _second) = server_in(dir.path()).await;
    let (mut b, _) = peer(addr, pubkey, 93).await;
    assert_eq!(get(&mut b, &alice_key).await.profile().name, "Durable");

    // A block that evaporated on a restart would be worse than none.
    let (mut m, _) = peer(addr, pubkey, mallory_b).await;
    assert!(!get(&mut m, &alice_key).await.found);
}
