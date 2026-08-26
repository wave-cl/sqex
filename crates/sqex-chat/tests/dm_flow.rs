//! Two people hold a direct message through a real exchange, and one of them
//! restarts.
//!
//! The restart is the point. Every other test in this workspace keeps its
//! client state in memory and dies with the process, which is exactly the case
//! a chat client does not get to be: an epoch key arrives sealed against a
//! one-time prekey, opening it spends that prekey, and the exchange will hand
//! over the same envelope tomorrow to no effect. So a client that cannot
//! reload its own store has no conversation, and nothing before this crate
//! persisted anything at all.

use std::net::SocketAddr;
use std::path::Path;

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

/// Open a client, exactly as the binary does: connect as the identity, open the
/// store at a real path, publish prekeys if the pool is low.
async fn chat_at(
    addr: SocketAddr,
    server_pub: [u8; 32],
    b: u8,
    store_path: &Path,
) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, store);
    chat.top_up_prekeys().await.unwrap();
    chat
}

fn said(timeline: &Timeline) -> Vec<String> {
    timeline
        .messages()
        .filter(|m| m.is_visible())
        .filter_map(|m| m.post.body_text().map(|t| t.to_string()))
        .collect()
}

#[tokio::test]
async fn two_people_hold_a_direct_message_the_exchange_cannot_read() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let a_store = dir.path().join("alice.db");
    let b_store = dir.path().join("bob.db");

    let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
    let mut bob = chat_at(addr, server_pub, 2, &b_store).await;
    let (_, bob_key) = identity(2);
    let (_, alice_key) = identity(1);

    // Alice starts it. Nothing is asked of the exchange to find the channel —
    // its identifier is derived from the two accounts.
    let channel = alice.open_dm(&bob_key).await.unwrap();
    assert_eq!(channel, bob.dm_with(&alice_key), "both ends derive the same id");

    alice.send(&channel, &bob_key, "are you there?").await.unwrap();

    // Bob opens his side, collects the key Alice sealed to him, and reads.
    let same = bob.open_dm(&alice_key).await.unwrap();
    assert_eq!(same, channel);
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["are you there?"]);
    assert!(!got.gap);
    assert!(got.unreadable.is_empty(), "bob could not open something");

    bob.send(&channel, &alice_key, "i am").await.unwrap();
    let mut alices = Timeline::new();
    let got = alice.poll(&channel, &mut alices, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["are you there?", "i am"]);
}

#[tokio::test]
async fn the_exchange_stores_ciphertext_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, bob_key) = identity(2);
    let (_, alice_key) = identity(1);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    let secret = "the exchange must never see this";
    alice.send(&channel, &bob_key, secret).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    // Read the raw entry the exchange is holding, not our own copy of it.
    let mut raw = Timeline::new();
    bob.poll(&channel, &mut raw, 0).await.unwrap();
    let db = dir.path().join("channels.db");
    let bytes = std::fs::read(&db).unwrap();
    assert!(
        !bytes
            .windows(secret.len())
            .any(|w| w == secret.as_bytes()),
        "the plaintext reached the exchange's disk"
    );
}

#[tokio::test]
async fn a_client_that_restarts_can_still_read_and_still_write() {
    // The test this whole crate exists for. Alice's process ends; everything
    // she knows is on disk or it is gone.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let a_store = dir.path().join("alice.db");
    let b_store = dir.path().join("bob.db");
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    // Bob first: nothing can be sealed to a device that has published no
    // prekeys, so he has to have started at least once.
    let mut bob = chat_at(addr, server_pub, 2, &b_store).await;

    let channel;
    {
        let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
        channel = alice.open_dm(&bob_key).await.unwrap();
        alice.send(&channel, &bob_key, "before the restart").await.unwrap();
    } // Alice's client is dropped: connection, pool, keys, counters, all gone.

    bob.open_dm(&alice_key).await.unwrap();
    bob.send(&channel, &alice_key, "while she was away").await.unwrap();

    // A completely fresh client over the same store.
    let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
    let mut alices = Timeline::new();
    let got = alice.poll(&channel, &mut alices, 0).await.unwrap();
    assert_eq!(
        said(&got.timeline),
        vec!["before the restart", "while she was away"],
        "the reopened store lost the epoch key"
    );

    // And she can still send. The counter must not collide with the one she
    // used before the restart, or ChaCha20-Poly1305 leaks both messages.
    alice.send(&channel, &bob_key, "after the restart").await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(
        said(&got.timeline),
        vec![
            "before the restart",
            "while she was away",
            "after the restart"
        ]
    );
}

#[tokio::test]
async fn a_restart_does_not_reuse_a_message_counter() {
    // The failure this guards is silent and total: two entries under one key
    // and one counter leak the XOR of their plaintexts. Assert on the counters
    // the exchange recorded rather than on anything the client believes.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let a_store = dir.path().join("alice.db");
    let (_, bob_key) = identity(2);
    let (_, alice_key) = identity(1);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;

    let channel;
    {
        let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
        channel = alice.open_dm(&bob_key).await.unwrap();
        alice.send(&channel, &bob_key, "one").await.unwrap();
        alice.send(&channel, &bob_key, "two").await.unwrap();
    }
    for _ in 0..3 {
        let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
        alice.send(&channel, &bob_key, "again").await.unwrap();
    }

    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    bob.poll(&channel, &mut bobs, 0).await.unwrap();
    // Five messages from Alice, five distinct counters, none of them lost to a
    // collision the reader would have shown as a missing message.
    assert_eq!(said(&bobs).len(), 5, "a counter collided and an entry was lost");
}

#[tokio::test]
async fn a_replayed_entry_is_refused_by_the_reader() {
    // SIP-17's rule, exercised through the client rather than in a unit test:
    // the exchange cannot check a counter, so the recipient is the only party
    // who can. Polling twice re-offers nothing, so drive it by rewinding our
    // own cursor — which is exactly what a replaying exchange would achieve.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let a_store = dir.path().join("alice.db");
    let b_store = dir.path().join("bob.db");
    let (_, bob_key) = identity(2);
    let (_, alice_key) = identity(1);

    let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
    let mut bob = chat_at(addr, server_pub, 2, &b_store).await;
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, &bob_key, "said once").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["said once"]);

    // Rewind and fetch the same entries again.
    bob.store().set_since(&channel, 0).unwrap();
    let mut again = Timeline::new();
    let got = bob.poll(&channel, &mut again, 0).await.unwrap();
    assert!(
        said(&got.timeline).is_empty(),
        "a counter already seen was decrypted a second time"
    );
}

#[tokio::test]
async fn a_stranger_cannot_read_the_conversation() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let _bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, bob_key) = identity(2);
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, &bob_key, "private").await.unwrap();

    // Mallory knows the channel identifier — it is derivable from two public
    // keys, so this is not a secret — and is refused on membership alone.
    let mut mallory = chat_at(addr, server_pub, 9, &dir.path().join("mallory.db")).await;
    let mut t = Timeline::new();
    assert!(
        mallory.poll(&channel, &mut t, 0).await.is_err(),
        "a stranger read a direct message"
    );
}

#[tokio::test]
async fn a_conversation_with_somebody_who_has_never_run_a_client_waits_rather_than_fails() {
    // Opening the channel must work: Bob is a member the moment Alice creates
    // it. What cannot happen yet is minting a key, because SIP-23 forbids
    // sealing to a device that has published no prekeys and offers no
    // static-only path to fall back to. A person should be told they are
    // waiting, not told it broke.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let a_store = dir.path().join("alice.db");
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
    let channel = alice
        .open_dm(&bob_key)
        .await
        .expect("the channel opens even though Bob has never connected");
    assert!(matches!(
        alice.send(&channel, &bob_key, "hello?").await,
        Err(sqex_chat::ChatError::NotReady(_))
    ));

    // Bob starts up, and the same call now works with nothing else changed.
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    alice.send(&channel, &bob_key, "hello?").await.unwrap();

    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["hello?"]);
}

#[tokio::test]
async fn a_restarted_client_still_shows_the_conversation_it_already_read() {
    // The bug a live trial found and the earlier restart test missed: that one
    // never polled before restarting, so its cursor was still 0 and it fetched
    // everything again. Once a client has actually read a message, the cursor
    // has moved past it — and re-fetching cannot recover it, because SIP-17
    // forbids decrypting a counter twice. So what was read must be kept.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let a_store = dir.path().join("alice.db");
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;

    let channel;
    {
        let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
        channel = alice.open_dm(&bob_key).await.unwrap();
        alice.send(&channel, &bob_key, "first").await.unwrap();
        bob.open_dm(&alice_key).await.unwrap();
        bob.send(&channel, &alice_key, "second").await.unwrap();

        // Alice reads them, which moves her cursor past both.
        let mut t = Timeline::new();
        let got = alice.poll(&channel, &mut t, 0).await.unwrap();
        assert_eq!(said(&got.timeline), vec!["first", "second"]);
    }

    // A fresh client over the same store, before any polling.
    let alice = chat_at(addr, server_pub, 1, &a_store).await;
    let history = alice.history(&channel, &bob_key).unwrap();
    assert_eq!(
        said(&history),
        vec!["first", "second"],
        "the conversation vanished on restart"
    );

    // And polling on top of it adds to the history rather than replacing it.
    let mut alice = alice;
    let mut t = history;
    bob.send(&channel, &alice_key, "third").await.unwrap();
    let got = alice.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["first", "second", "third"]);
}

#[tokio::test]
async fn a_client_that_lost_its_store_can_still_publish_prekeys() {
    // Found by running the thing against a live exchange: delete the client's
    // store, keep the identity, and every publish comes back 409 reused_id —
    // the exchange remembers those ids forever, by SIP-23's rule, and the
    // client used to start again at 1 and refuse to launch. An identity that
    // survives its store must still be usable.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let (_, alice_key) = identity(1);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;

    let channel;
    {
        let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
        channel = alice.open_dm(&bob_key).await.unwrap();
        alice.send(&channel, &bob_key, "before the loss").await.unwrap();
    }

    // The store is gone. chat_at publishes prekeys on the way in, which is the
    // call that used to fail outright.
    let lost = dir.path().join("alice-again.db");
    let mut alice = chat_at(addr, server_pub, 1, &lost).await;

    // And she is not merely running — she can still hold a conversation. The
    // old messages are gone with the store, which is the forward secrecy
    // working; the identity is not.
    alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, &bob_key, "after the loss").await.unwrap();

    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["before the loss", "after the loss"]);
}

#[tokio::test]
async fn a_lost_store_does_not_leave_stale_prekeys_for_peers_to_seal_to() {
    // The failure a live trial produced, reduced. Before SIP-23's `Clear`, a
    // client that lost its store left its prekeys on the exchange, still
    // served; a peer sealed to one; the envelope would not open; the device
    // rotated; the peer sealed the new epoch to another stale prekey; and the
    // two rotated past each other until the stale pool drained.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    // Both publish, then both lose everything.
    {
        let _a = chat_at(addr, server_pub, 1, &dir.path().join("a1.db")).await;
        let _b = chat_at(addr, server_pub, 2, &dir.path().join("b1.db")).await;
    }
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a2.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b2.db")).await;

    // Whatever either of them is served now must be a prekey the holder can
    // actually open — the stale ones are gone rather than queued in front.
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, &bob_key, "after we both lost it").await.unwrap();

    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(
        said(&got.timeline),
        vec!["after we both lost it"],
        "the two clients rotated past each other"
    );

    // And it is a conversation, not one lucky message.
    bob.send(&channel, &alice_key, "so did i").await.unwrap();
    let mut alices = Timeline::new();
    let got = alice.poll(&channel, &mut alices, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["after we both lost it", "so did i"]);
}
