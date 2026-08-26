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
    ByChannel, ChannelInfo, Create, Entries, Fetch, List, Listing, MIN_RETENTION, Post, Posted,
    Role, TYPE_CLOSE, TYPE_INFO, TYPE_JOIN, TYPE_LEAVE, Visibility,
};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn as_identity(addr: SocketAddr, server_pub: [u8; 32], seed: [u8; 32]) -> Client {
    Client::connect_as(addr, &server_pub, &seed).await.unwrap()
}

fn public(channel: [u8; 32], name: &str) -> Create {
    Create {
        channel,
        visibility: Visibility::Public,
        retention_secs: 3600,
        max_entries: 0,
        name: name.into(),
        topic: String::new(),
        invites: vec![],
    }
}

async fn create(client: &mut Client, req: &Create) -> u16 {
    let (code, _) = client.post("/channel/create", req.encode()).await.unwrap();
    code
}

async fn join(client: &mut Client, channel: [u8; 32]) -> u16 {
    let (code, _) = client
        .post("/channel/join", ByChannel { channel }.encode(TYPE_JOIN))
        .await
        .unwrap();
    code
}

async fn post(client: &mut Client, channel: [u8; 32], text: &[u8]) -> (u16, Vec<u8>) {
    client
        .post(
            "/channel/post",
            Post {
                channel,
                epoch: 0,
                msg_seq: 0,
                expires_after: 0,
                body: text.to_vec(),
            }
            .encode(),
        )
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

fn bodies(e: &Entries) -> Vec<Vec<u8>> {
    e.entries.iter().map(|x| x.body.clone()).collect()
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

    assert_eq!(create(&mut a, &public(channel, "planning")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    for text in [&b"one"[..], b"two", b"three"] {
        assert_eq!(post(&mut a, channel, text).await.0, 200);
    }
    assert_eq!(post(&mut b, channel, b"four").await.0, 200);

    // The order is the exchange's, and it is the same order for everybody.
    let (code, body) = fetch(&mut b, channel, 0, 0).await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let seen = Entries::decode(&body).unwrap();
    assert_eq!(
        bodies(&seen),
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec(), b"four".to_vec()]
    );
    assert_eq!(
        seen.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );

    let (_, body) = fetch(&mut a, channel, 0, 0).await;
    assert_eq!(bodies(&Entries::decode(&body).unwrap()), bodies(&seen));

    // The creator is an admin and the joiner is not.
    let (_, body) = info(&mut a, channel).await;
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

    assert_eq!(create(&mut a, &public(channel, "members only")).await, 200);
    assert_eq!(post(&mut a, channel, b"secret enough").await.0, 200);

    assert_eq!(fetch(&mut m, channel, 0, 0).await.0, 403);
    assert_eq!(post(&mut m, channel, b"hello").await.0, 403);
    assert_eq!(info(&mut m, channel).await.0, 403);

    // Joining is what changes it, and a public channel lets anyone.
    assert_eq!(join(&mut m, channel).await, 200);
    let (code, body) = fetch(&mut m, channel, 0, 0).await;
    assert_eq!(code, 200);
    assert_eq!(bodies(&Entries::decode(&body).unwrap()), vec![b"secret enough".to_vec()]);
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
    assert_eq!(create(&mut a, &public(channel, "waiting")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    let waiter = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let (code, body) = fetch(&mut b, channel, 0, 20).await;
        (code, body, started.elapsed())
    });

    // Long enough that the fetch is certainly parked rather than answered by
    // the first read.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(post(&mut a, channel, b"woken").await.0, 200);

    let (code, body, elapsed) = waiter.await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(bodies(&Entries::decode(&body).unwrap()), vec![b"woken".to_vec()]);
    // Answered by the post, not by the timeout.
    assert!(elapsed < std::time::Duration::from_secs(5), "waited {elapsed:?}");
}

#[tokio::test]
async fn a_fetch_with_nothing_to_say_returns_empty_rather_than_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(51);
    let channel = [4u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    assert_eq!(create(&mut a, &public(channel, "quiet")).await, 200);

    let started = std::time::Instant::now();
    let (code, body) = fetch(&mut a, channel, 0, 1).await;
    assert_eq!(code, 200);
    assert!(Entries::decode(&body).unwrap().entries.is_empty());
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
        assert_eq!(create(&mut a, &public(channel, "durable")).await, 200);
        assert_eq!(post(&mut a, channel, b"before the restart").await.0, 200);
    }
    first.abort();
    let _ = first.await;

    let (addr, pubkey, _second) = server_in(dir.path()).await;
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let (code, body) = fetch(&mut a, channel, 0, 0).await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let seen = Entries::decode(&body).unwrap();
    assert_eq!(bodies(&seen), vec![b"before the restart".to_vec()]);

    // And the sequence continues rather than starting again, because next_seq
    // is stored rather than derived from what survives.
    let (_, body) = post(&mut a, channel, b"after").await;
    assert_eq!(Posted::decode(&body).unwrap().seq, 2);
}

#[tokio::test]
async fn retention_by_count_drops_the_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(71);
    let channel = [6u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    let mut req = public(channel, "short memory");
    req.max_entries = 3;
    assert_eq!(create(&mut a, &req).await, 200);

    for i in 0..6u8 {
        assert_eq!(post(&mut a, channel, &[b'a' + i]).await.0, 200);
    }
    let (_, body) = fetch(&mut a, channel, 0, 0).await;
    let seen = Entries::decode(&body).unwrap();
    assert_eq!(bodies(&seen), vec![vec![b'd'], vec![b'e'], vec![b'f']]);

    // A client that was away longer than the window must be able to tell it
    // has a gap, which is what `first` is for.
    assert_eq!(seen.first, 4);
    assert_eq!(seen.last, 6);
}

#[tokio::test]
async fn a_public_channel_outlives_its_membership_and_a_private_one_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(81);
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    let open = [7u8; 32];
    let shut = [8u8; 32];
    assert_eq!(create(&mut a, &public(open, "a place")).await, 200);
    let mut priv_req = public(shut, "");
    priv_req.channel = shut;
    priv_req.visibility = Visibility::Private;
    assert_eq!(create(&mut a, &priv_req).await, 200);

    let leave = |c: [u8; 32]| ByChannel { channel: c }.encode(TYPE_LEAVE);
    assert_eq!(a.post("/channel/leave", leave(open)).await.unwrap().0, 200);
    assert_eq!(a.post("/channel/leave", leave(shut)).await.unwrap().0, 200);

    // The public room is still there and its admin, who is no longer a member,
    // can still see it and close it.
    let (code, body) = info(&mut a, open).await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    assert!(ChannelInfo::decode(&body).unwrap().members.is_empty());

    // The private one went with its last member.
    assert_eq!(info(&mut a, shut).await.0, 404);

    let (code, _) = a
        .post("/channel/close", ByChannel { channel: open }.encode(TYPE_CLOSE))
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(info(&mut a, open).await.0, 404);
}

#[tokio::test]
async fn the_directory_lists_public_channels_only() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(91);
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    assert_eq!(create(&mut a, &public([10u8; 32], "rust talk")).await, 200);
    assert_eq!(create(&mut a, &public([11u8; 32], "garden talk")).await, 200);
    let mut hidden = public([12u8; 32], "should not appear");
    hidden.visibility = Visibility::Private;
    assert_eq!(create(&mut a, &hidden).await, 200);

    let (code, body) = a
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

    let mut too_short = public([13u8; 32], "blink");
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
    assert_eq!(create(&mut a, &public(channel, "named callers only")).await, 200);

    // Client::connect does not advertise an identity (SIP-3 is opt-in), and
    // every channel route refuses a connection carrying none.
    let mut anon = Client::connect(addr, &pubkey).await.unwrap();
    assert_eq!(fetch(&mut anon, channel, 0, 0).await.0, 403);
    assert_eq!(join(&mut anon, channel).await, 403);
}
