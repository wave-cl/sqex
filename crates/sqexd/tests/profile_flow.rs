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
    Block, Blocks, ByAccount, FLAG_WITHHOLD, Got, MAX_UPDATES_PER_HOUR, Profile, Put, TYPE_GET,
};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

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

fn profile(name: &str, title: &str, flags: u8) -> Profile {
    Profile {
        flags,
        name: name.into(),
        title: title.into(),
        avatar: vec![0xab; 64],
    }
}

async fn put(c: &mut Client, p: Profile) -> u16 {
    c.post("/profile/put", Put { profile: p }.encode())
        .await
        .unwrap()
        .0
}

async fn get(c: &mut Client, who: &PubKey) -> Got {
    let (code, body) = c
        .post("/profile/get", ByAccount { account: *who }.encode(TYPE_GET))
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    Got::decode(&body).unwrap()
}

async fn block(c: &mut Client, who: &PubKey, add: bool) -> u16 {
    c.post("/block/set", Block { account: *who, add }.encode())
        .await
        .unwrap()
        .0
}

fn public(channel: [u8; 32]) -> Create {
    Create {
        channel,
        visibility: Visibility::Public,
        retention_secs: 3600,
        max_entries: 0,
        name: "shared".into(),
        topic: String::new(),
        invites: vec![],
    }
}

#[tokio::test]
async fn a_profile_is_published_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice) = peer(addr, pubkey, 21).await;
    let (mut b, _) = peer(addr, pubkey, 22).await;

    assert!(!get(&mut b, &alice).await.found, "nothing published yet");
    assert_eq!(put(&mut a, profile("Colin Lyons", "Infrastructure", 0)).await, 200);

    let got = get(&mut b, &alice).await;
    assert!(got.found);
    assert_eq!(got.profile.name, "Colin Lyons");
    assert_eq!(got.profile.title, "Infrastructure");
    assert!(got.updated > 0);

    // Replacement is whole: there is no partial update to get wrong.
    assert_eq!(put(&mut a, profile("C. Lyons", "", 0)).await, 200);
    let got = get(&mut b, &alice).await;
    assert_eq!(got.profile.name, "C. Lyons");
    assert!(got.profile.title.is_empty());
}

#[tokio::test]
async fn a_withheld_profile_looks_exactly_like_one_that_does_not_exist() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice) = peer(addr, pubkey, 31).await;
    let (mut b, _) = peer(addr, pubkey, 32).await;
    let (_, never) = peer(addr, pubkey, 33).await;
    let channel = [1u8; 32];

    assert_eq!(put(&mut a, profile("Hidden", "", FLAG_WITHHOLD)).await, 200);

    // A stranger is told the same thing about a withheld profile as about one
    // that was never published. Answering "exists but hidden" would itself be
    // the disclosure.
    let withheld = get(&mut b, &alice).await;
    let absent = get(&mut b, &never).await;
    assert_eq!(withheld, Got { now: withheld.now, ..absent.clone() });
    assert!(!withheld.found);

    // Sharing a channel is the visibility rule, and it is a relationship the
    // exchange already knows.
    a.post("/channel/create", public(channel).encode()).await.unwrap();
    b.post("/channel/join", ByChannel { channel }.encode(sqex_proto::channel::TYPE_JOIN))
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

    let mut req = public(channel);
    req.visibility = Visibility::Private;
    req.name = String::new();
    mallory.post("/channel/create", req.encode()).await.unwrap();

    let mut invite = vec![TYPE_INVITE];
    invite.extend_from_slice(&channel);
    invite.extend_from_slice(alice_key.as_bytes());
    invite.push(Role::Member as u8);
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
            Create {
                channel: dm,
                visibility: Visibility::Private,
                retention_secs: 3600,
                max_entries: 0,
                name: String::new(),
                topic: String::new(),
                invites: vec![Invitee { account: alice_key, role: Role::Admin }],
            }
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
    let (code, _) = alice
        .post(
            "/channel/create",
            Create {
                channel: dm,
                visibility: Visibility::Private,
                retention_secs: 3600,
                max_entries: 0,
                name: String::new(),
                topic: String::new(),
                invites: vec![Invitee { account: mallory_key, role: Role::Admin }],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (_, body) = alice
        .post("/channel/info", ByChannel { channel: dm }.encode(TYPE_INFO))
        .await
        .unwrap();
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

    assert_eq!(put(&mut alice, profile("Alice", "", 0)).await, 200);
    assert!(get(&mut mallory, &alice_key).await.found);

    assert_eq!(block(&mut alice, &mallory_key, true).await, 200);
    let got = get(&mut mallory, &alice_key).await;
    assert!(!got.found);
    assert!(got.profile.avatar.is_empty());

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

#[tokio::test]
async fn profile_updates_are_rate_limited() {
    // A profile is served to everyone who shares a channel with its subject,
    // so rewriting it repeatedly makes the exchange serve traffic on somebody
    // else's behalf.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, _) = peer(addr, pubkey, 81).await;

    for i in 0..MAX_UPDATES_PER_HOUR {
        assert_eq!(put(&mut a, profile(&format!("n{i}"), "", 0)).await, 200, "at {i}");
    }
    assert_eq!(put(&mut a, profile("one too many", "", 0)).await, 507);
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
        assert_eq!(put(&mut a, profile("Durable", "", 0)).await, 200);
        assert_eq!(block(&mut a, &mallory_key, true).await, 200);
    }
    first.abort();
    let _ = first.await;

    let (addr, pubkey, _second) = server_in(dir.path()).await;
    let (mut b, _) = peer(addr, pubkey, 93).await;
    assert_eq!(get(&mut b, &alice_key).await.profile.name, "Durable");

    // A block that evaporated on a restart would be worse than none.
    let (mut m, _) = peer(addr, pubkey, mallory_b).await;
    assert!(!get(&mut m, &alice_key).await.found);
}
