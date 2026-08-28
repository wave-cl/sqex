//! SIP-21 through the client: what a person publishes about themselves, and
//! who they can stop reaching them.
//!
//! The exchange side of this is tested in `sqexd/tests/profile_flow.rs`. What
//! is tested here is the half a person actually touches — that a name can be
//! published and read back, that blocking a stranger works from the client
//! that has been written to, and that the name never arrives anywhere without
//! the key that distinguishes it from an identical one.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::profile::Profile;
use sqex_proto::timeline::Timeline;
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn chat_at(addr: SocketAddr, server_pub: [u8; 32], b: u8, store_path: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, store);
    chat.top_up_prekeys().await.unwrap();
    chat
}

fn named(name: &str, title: &str) -> Profile {
    Profile {
        flags: 0,
        name: name.into(),
        title: title.into(),
        avatar: Vec::new(),
    }
}

#[tokio::test]
async fn a_name_is_published_and_read_back_by_somebody_sharing_a_channel() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    alice.set_profile(named("Alice", "shipping")).await.unwrap();

    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "hello").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let got = bob.profile_of(&alice_key).await.unwrap();
    assert!(got.found);
    assert_eq!(got.profile.name, "Alice");
    // Called `title` and not `role` on purpose: `role` is what the exchange
    // holds and vouches for, and this is what its subject says about itself.
    assert_eq!(got.profile.title, "shipping");
}

#[tokio::test]
async fn a_name_is_cached_and_not_asked_for_twice() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    alice.set_profile(named("Alice", "")).await.unwrap();
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "hello").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let now = 1_000_000;
    assert_eq!(bob.refresh_profiles(&[alice_key], now).await.unwrap(), 1);
    assert_eq!(bob.display_name(&alice_key).as_deref(), Some("Alice"));

    // Asked once. Asking the exchange who everybody is on every poll would
    // turn a display convenience into a stream of traffic about who this
    // client is reading.
    assert_eq!(bob.refresh_profiles(&[alice_key], now + 60).await.unwrap(), 0);
    // And an hour later it is asked again, because SIP-21 lets a profile
    // change 32 times an hour.
    assert_eq!(
        bob.refresh_profiles(&[alice_key], now + 3601).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn an_account_that_publishes_nothing_is_not_asked_about_forever() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "hello").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let now = 1_000_000;
    assert_eq!(bob.refresh_profiles(&[alice_key], now).await.unwrap(), 1);
    assert_eq!(bob.display_name(&alice_key), None, "a name was invented");
    // "Asked and told nothing" is remembered, or the client asks again on
    // every poll for the rest of the conversation.
    assert_eq!(bob.refresh_profiles(&[alice_key], now + 60).await.unwrap(), 0);
}

#[tokio::test]
async fn a_blocked_account_cannot_reach_us_and_is_not_told_so() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut mallory = chat_at(addr, server_pub, 3, &dir.path().join("mallory.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, mallory_key) = identity(3);

    // The client's own help says anybody who writes to you is added on
    // startup. Until now nothing could stop them.
    alice.set_block(&mallory_key, true).await.unwrap();

    let channel = mallory.open_dm(&alice_key).await.unwrap();
    mallory.send(&channel, "let me in").await.unwrap();

    // Alice is not merely missing the message — she is not in the channel.
    // The block drops the invitation, so the conversation never appears, which
    // is stronger than filtering it after the fact: there is nothing to filter.
    let mine = alice.mine().await.unwrap();
    assert!(
        !mine.iter().any(|m| m.channel == channel),
        "a blocked account got a conversation into our list"
    );
    assert!(
        alice.poll(&channel, &mut Timeline::new(), 0).await.is_err(),
        "a blocked account's channel was readable"
    );

    // And nothing told Mallory. The create succeeded, the message was
    // accepted, and the answer is the same one an unblocked sender gets — so a
    // block is not a signal the blocked party can read.
    let mut mallorys = Timeline::new();
    let seen = mallory.poll(&channel, &mut mallorys, 0).await.unwrap();
    assert_eq!(
        seen.timeline
            .messages()
            .filter_map(|m| m.post.body_text())
            .collect::<Vec<_>>(),
        vec!["let me in"],
        "the sender was told their message went nowhere"
    );

    // Unblocking is a decision and not a one-way door: invited again, Alice
    // now joins. The old invitation is gone for good, which is the honest
    // consequence of dropping it rather than holding it back.
    alice.set_block(&mallory_key, false).await.unwrap();
    mallory.invite(&channel, &alice_key).await.unwrap();
    mallory.send(&channel, "and now?").await.unwrap();

    let mut alices = Timeline::new();
    let got = alice.poll(&channel, &mut alices, 0).await.unwrap();
    assert!(
        got.timeline
            .messages()
            .filter_map(|m| m.post.body_text())
            .any(|t| t == "and now?"),
        "unblocking did not take effect"
    );
}

#[tokio::test]
async fn the_block_list_is_ours_and_nobody_elses() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut mallory = chat_at(addr, server_pub, 3, &dir.path().join("mallory.db")).await;
    let (_, mallory_key) = identity(3);

    assert!(alice.blocked().await.unwrap().is_empty());
    alice.set_block(&mallory_key, true).await.unwrap();
    assert_eq!(alice.blocked().await.unwrap(), vec![mallory_key]);

    // The route takes no argument, so there is no way to ask about somebody
    // else — a list of who somebody wants to avoid is more sensitive than the
    // membership it protects them from.
    assert!(
        mallory.blocked().await.unwrap().is_empty(),
        "a block list leaked to the account it names"
    );
}
