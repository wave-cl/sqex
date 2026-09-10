//! `/channel/fetch` used as the long poll it was written to be.
//!
//! The exchange holds the request open and answers the moment an entry or a
//! signal arrives. Every caller in this repository passed `wait_secs = 0` and
//! asked again on a timer instead, for one reason: `Chat` is a single borrow,
//! and a request parked inside it for twenty-five seconds is twenty-five
//! seconds in which the client can do nothing else. So the parked half is now
//! separable — `Chat::watch` hands out a `Watch` that owns a handle on the same
//! connection, and `Chat::absorb` makes a conversation out of what it brings
//! back, exactly as `poll` would have.
//!
//! What these prove is the pair of claims that makes it worth having: a message
//! arrives in **one** trip rather than a hint followed by a fetch, and the
//! client stays usable while the fetch is parked.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
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

async fn chat_at(addr: SocketAddr, server_pub: [u8; 32], b: u8, store_path: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.top_up_prekeys().await.unwrap();
    chat
}

/// How long a parked fetch is allowed to sit. The exchange clamps to
/// `MAX_WAIT`; what matters here is that it is far longer than anything these
/// tests should take, so a pass cannot be the wait running out.
const WAIT: u16 = 25;

/// A message arrives in the answer to a request that was already parked.
///
/// One trip, not two. The event stream can only say "this conversation moved",
/// which costs a fetch to act on; this *is* the fetch, sent before there was
/// anything to fetch.
#[tokio::test]
async fn a_parked_fetch_answers_the_moment_something_is_said() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 21, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 22, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(21);
    let (_, bob_key) = identity(22);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    // Bob reads the empty conversation first, so his cursor is where a client
    // with the window open would have it.
    let mut timeline = Timeline::new();
    bob.poll(&channel, &mut timeline, 0).await.unwrap();

    let watch = bob.watch(&channel, WAIT).expect("a connection to park on");
    assert_eq!(watch.channel(), channel);
    let parked = tokio::spawn(async move { watch.arrived().await });

    // Long enough that the request is certainly parked at the exchange rather
    // than racing it: a fetch that had not arrived yet would find the entry
    // waiting and pass without ever having been a long poll.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let began = tokio::time::Instant::now();
    alice
        .send(&channel, "said to somebody already listening")
        .await
        .unwrap();

    let got = tokio::time::timeout(Duration::from_secs(10), parked)
        .await
        .expect("the parked fetch should return long before its wait")
        .expect("the task should not panic")
        .expect("the fetch should succeed");
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "the fetch waited {:?}, which is a timer and not a long poll",
        began.elapsed()
    );
    assert_eq!(got.channel(), channel);

    // And it is a real answer, not a nudge: the entry is in the bytes that came
    // back, and absorbing them is all it takes to read it.
    let conversation = bob.absorb(&mut timeline, got).await.unwrap();
    assert!(
        conversation
            .timeline
            .messages()
            .any(|m| m.post.body_text() == Some("said to somebody already listening")),
        "the parked fetch brought back a nudge rather than the message"
    );
}

/// The client is not held hostage by a request that is meant to sit there.
///
/// This is the whole reason `wait_secs` was zero everywhere. A parked fetch
/// borrows nothing from the `Chat`, so the `Chat` goes on sending — on the same
/// connection, each request its own HTTP/3 stream, no second handshake.
#[tokio::test]
async fn a_client_stays_usable_while_a_fetch_is_parked() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 23, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 24, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(23);
    let (_, bob_key) = identity(24);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    let mut timeline = Timeline::new();
    bob.poll(&channel, &mut timeline, 0).await.unwrap();

    let watch = bob.watch(&channel, WAIT).expect("a connection to park on");
    let parked = tokio::spawn(async move { watch.arrived().await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Bob's own client, in the middle of the wait. Sending is the sharpest
    // version of it: it signs, seals, posts and reads the answer.
    let began = tokio::time::Instant::now();
    bob.send(&channel, "typed while waiting").await.unwrap();
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "sending waited {:?} — it was queued behind the parked fetch",
        began.elapsed()
    );

    // And Bob's own message is what wakes his parked fetch, which is right: the
    // exchange tells a sender about their own entry by the same path as
    // everybody else, so there is one way a message reaches the screen.
    let got = tokio::time::timeout(Duration::from_secs(10), parked)
        .await
        .expect("the parked fetch should have returned")
        .expect("the task should not panic")
        .expect("the fetch should succeed");
    let conversation = bob.absorb(&mut timeline, got).await.unwrap();
    assert!(
        conversation
            .timeline
            .messages()
            .any(|m| m.post.body_text() == Some("typed while waiting")),
    );
}

/// Typing wakes it too, which is the other half of what the exchange offers.
///
/// `fetch_waiting` returns on an entry **or a signal**, so one parked request
/// carries both kinds of news. A client that had to ask separately about
/// somebody typing would be back to a timer for the one thing that has no
/// durable record at all.
#[tokio::test]
async fn a_parked_fetch_answers_when_somebody_starts_typing() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 25, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 26, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(25);
    let (_, bob_key) = identity(26);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    let mut timeline = Timeline::new();
    bob.poll(&channel, &mut timeline, 0).await.unwrap();

    let watch = bob.watch(&channel, WAIT).expect("a connection to park on");
    let parked = tokio::spawn(async move { watch.arrived().await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let began = tokio::time::Instant::now();
    alice.typing(&channel, true).await;

    let got = tokio::time::timeout(Duration::from_secs(10), parked)
        .await
        .expect("a signal should wake a parked fetch")
        .expect("the task should not panic")
        .expect("the fetch should succeed");
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "the fetch waited {:?} for a signal that had already been sent",
        began.elapsed()
    );
    let conversation = bob.absorb(&mut timeline, got).await.unwrap();
    assert!(
        conversation.typing,
        "the answer should say somebody is writing"
    );
}
