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

    alice.send(&channel, "are you there?").await.unwrap();

    // Bob opens his side, collects the key Alice sealed to him, and reads.
    let same = bob.open_dm(&alice_key).await.unwrap();
    assert_eq!(same, channel);
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["are you there?"]);
    assert!(!got.gap);
    assert!(got.unreadable.is_empty(), "bob could not open something");

    bob.send(&channel, "i am").await.unwrap();
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
    alice.send(&channel, secret).await.unwrap();
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
        alice.send(&channel, "before the restart").await.unwrap();
    } // Alice's client is dropped: connection, pool, keys, counters, all gone.

    bob.open_dm(&alice_key).await.unwrap();
    bob.send(&channel, "while she was away").await.unwrap();

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
    alice.send(&channel, "after the restart").await.unwrap();
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
        alice.send(&channel, "one").await.unwrap();
        alice.send(&channel, "two").await.unwrap();
    }
    for _ in 0..3 {
        let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
        alice.send(&channel, "again").await.unwrap();
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
    alice.send(&channel, "said once").await.unwrap();
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
    alice.send(&channel, "private").await.unwrap();

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
        alice.send(&channel, "hello?").await,
        Err(sqex_chat::ChatError::NotReady(_))
    ));

    // Bob starts up, and the same call now works with nothing else changed.
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    alice.send(&channel, "hello?").await.unwrap();

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
        alice.send(&channel, "first").await.unwrap();
        bob.open_dm(&alice_key).await.unwrap();
        bob.send(&channel, "second").await.unwrap();

        // Alice reads them, which moves her cursor past both.
        let mut t = Timeline::new();
        let got = alice.poll(&channel, &mut t, 0).await.unwrap();
        assert_eq!(said(&got.timeline), vec!["first", "second"]);
    }

    // A fresh client over the same store, before any polling.
    let alice = chat_at(addr, server_pub, 1, &a_store).await;
    let history = alice.history(&channel, &[alice_key, bob_key]).unwrap();
    assert_eq!(
        said(&history),
        vec!["first", "second"],
        "the conversation vanished on restart"
    );

    // And polling on top of it adds to the history rather than replacing it.
    let mut alice = alice;
    let mut t = history;
    bob.send(&channel, "third").await.unwrap();
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
        alice.send(&channel, "before the loss").await.unwrap();
    }

    // The store is gone. chat_at publishes prekeys on the way in, which is the
    // call that used to fail outright.
    let lost = dir.path().join("alice-again.db");
    let mut alice = chat_at(addr, server_pub, 1, &lost).await;

    // And she is not merely running — she can still hold a conversation. The
    // old messages are gone with the store, which is the forward secrecy
    // working; the identity is not.
    alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "after the loss").await.unwrap();

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
    alice.send(&channel, "after we both lost it").await.unwrap();

    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(
        said(&got.timeline),
        vec!["after we both lost it"],
        "the two clients rotated past each other"
    );

    // And it is a conversation, not one lucky message.
    bob.send(&channel, "so did i").await.unwrap();
    let mut alices = Timeline::new();
    let got = alice.poll(&channel, &mut alices, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["after we both lost it", "so did i"]);
}

#[tokio::test]
async fn a_file_travels_end_to_end_and_the_exchange_cannot_open_it() {
    use sqex_proto::blob_store::CHUNK;
    use sqex_proto::message::{Part, Post as SipPost};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    // Big enough to be several chunks, so the chunking is exercised rather
    // than assumed. Compressible content would hide a chunk-order bug, so the
    // bytes vary.
    let path = dir.path().join("notes.md");
    let secret: Vec<u8> = (0..(CHUNK * 2 + 1234)).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &secret).unwrap();

    let channel = alice.open_dm(&bob_key).await.unwrap();
    let limits = alice.blob_limits().await.unwrap();
    let prepared = alice.prepare_file(&path, limits.chunk as usize).unwrap();
    assert_eq!(prepared.chunks(), 3, "expected three chunks at this size");

    let attachment = alice.upload(&channel, &prepared).await.unwrap();
    let mut post = SipPost::text("the notes");
    post.parts.push(Part::Attachment(attachment));
    alice.send_post(&channel, post).await.unwrap();

    // Bob reads the message and pulls the file down.
    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    let msg = got.timeline.messages().next().unwrap();
    assert_eq!(msg.post.body_text(), Some("the notes"));
    let a = msg.post.attachments().next().expect("no attachment arrived");
    assert_eq!(a.size, secret.len() as u64);
    assert_eq!(sqex_chat::file_name(a).as_deref(), Some("notes.md"));

    let opened = bob.download(a).await.unwrap();
    assert_eq!(opened, secret, "the file did not survive the round trip");

    // And the exchange holds it without being able to read it.
    let stored = std::fs::read(dir.path().join("channels.db")).unwrap();
    assert!(
        !stored.windows(64).any(|w| w == &secret[0..64]),
        "the plaintext reached the exchange's disk"
    );
}

#[tokio::test]
async fn a_blob_served_wrong_is_refused_before_it_is_decrypted() {
    // The id is the hash of the ciphertext, which is what lets a client tell it
    // got the bytes it asked for without trusting the exchange to be honest.
    use sqex_proto::blob_store::CHUNK;

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let _bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let path = dir.path().join("small.txt");
    std::fs::write(&path, b"a short file").unwrap();
    let channel = alice.open_dm(&bob_key).await.unwrap();
    let prepared = alice.prepare_file(&path, CHUNK).unwrap();
    let mut attachment = alice.upload(&channel, &prepared).await.unwrap();

    // Name a blob the exchange does not have: the fetch fails rather than
    // handing back something that will not open.
    attachment.blob[0] ^= 1;
    assert!(alice.download(&attachment).await.is_err());
}

#[tokio::test]
async fn an_attachment_with_the_wrong_key_does_not_open() {
    use sqex_proto::blob_store::CHUNK;

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let _bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let path = dir.path().join("small.txt");
    std::fs::write(&path, b"a short file").unwrap();
    let channel = alice.open_dm(&bob_key).await.unwrap();
    let prepared = alice.prepare_file(&path, CHUNK).unwrap();
    let mut attachment = alice.upload(&channel, &prepared).await.unwrap();

    // The key rides inside the sealed message, so this is what a reader with
    // the wrong one sees — a refusal, not silent rubbish.
    attachment.key[0] ^= 1;
    assert!(alice.download(&attachment).await.is_err());
}

#[tokio::test]
async fn a_conversation_from_a_stranger_can_be_found() {
    // Before `Mine` this was impossible and the client said so in its --help:
    // a direct message from an account you had not added could not be seen,
    // because nothing would tell you it existed. The identifier derives from
    // the two accounts, so Alice can compute it and Bob cannot guess it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    // Alice writes to Bob. Bob has never heard of Alice.
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "you don't know me").await.unwrap();
    assert!(
        bob.store().contacts().unwrap().is_empty(),
        "bob should not know alice yet"
    );

    // Bob asks what he is in, and finds her.
    let mine = bob.mine().await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].channel, channel);

    // The identifier is a hash and cannot be run backwards, so the peer comes
    // from the member list — and is checked by re-deriving the identifier.
    let info = bob.info(&channel).await.unwrap();
    let other = info
        .members
        .iter()
        .map(|m| m.account)
        .find(|a| *a != bob.me)
        .expect("no other member");
    assert_eq!(other, alice_key);
    assert_eq!(bob.dm_with(&other), channel, "the identifier does not hash back");

    // Which is what the client does next: adding the contact and opening the
    // conversation is what collects the epoch key Alice sealed to him.
    bob.store().add_contact(&other, "alice", 0).unwrap();
    bob.open_dm(&other).await.unwrap();

    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["you don't know me"]);
}

#[tokio::test]
async fn mine_does_not_leak_channels_we_are_not_in() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let _bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    alice.open_dm(&bob_key).await.unwrap();

    // A third party is in nothing, and asking says so rather than saying who
    // else is talking.
    let mut mallory = chat_at(addr, server_pub, 9, &dir.path().join("m.db")).await;
    assert!(mallory.mine().await.unwrap().is_empty());
}

// ---- group channels -------------------------------------------------------

#[tokio::test]
async fn three_people_hold_a_group_conversation() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(3);

    // Everybody has to have published prekeys before a key can be sealed to
    // them, which for a group means everybody invited at creation.
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice
        .create_group("the thing", &[bob_key, carol_key])
        .await
        .unwrap();
    alice.send(&channel, "we are all here").await.unwrap();

    // Neither of them was told the identifier: a group's is random, not
    // derived, so `Mine` is the only way to find it.
    for (who, key) in [(&mut bob, bob_key), (&mut carol, carol_key)] {
        let mine = who.mine().await.unwrap();
        assert_eq!(mine.len(), 1, "{key} did not find the group");
        assert_eq!(mine[0].channel, channel);
        who.collect_keys(&channel).await.unwrap();
        let mut t = Timeline::new();
        let got = who.poll(&channel, &mut t, 0).await.unwrap();
        assert_eq!(said(&got.timeline), vec!["we are all here"]);
        // The name travels sealed, so it is known only to members.
        assert_eq!(got.timeline.name, "the thing");
    }

    // And everybody can speak, not just the one who made it.
    bob.send(&channel, "so we are").await.unwrap();
    carol.send(&channel, "hello both").await.unwrap();
    let mut t = Timeline::new();
    let got = alice.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(
        said(&got.timeline),
        vec!["we are all here", "so we are", "hello both"]
    );
    assert_eq!(alice_key, alice.me);
}

#[tokio::test]
async fn the_exchange_never_learns_what_a_group_is_called() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let _bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let name = "the very secret committee";
    let channel = alice.create_group(name, &[bob_key]).await.unwrap();

    // Not in the channel row, and not in any entry: a private channel's name is
    // stored empty at the exchange and travels as a sealed metadata entry,
    // because a membership graph plus a name says far more than the graph.
    let info = alice.info(&channel).await.unwrap();
    assert_eq!(info.name, "");
    let stored = std::fs::read(dir.path().join("channels.db")).unwrap();
    assert!(
        !stored.windows(name.len()).any(|w| w == name.as_bytes()),
        "the group's name reached the exchange"
    );
}

#[tokio::test]
async fn somebody_invited_later_can_read_what_came_before() {
    // Inviting does not rotate, and that is a decision rather than an omission:
    // SIP-17 leaves it to the inviter whether a new member gets the history,
    // and sealing them the current epoch grants it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(3);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice.create_group("early", &[bob_key]).await.unwrap();
    alice.send(&channel, "before carol").await.unwrap();

    alice.invite(&channel, &carol_key).await.unwrap();
    alice.send(&channel, "after carol").await.unwrap();

    carol.collect_keys(&channel).await.unwrap();
    let mut t = Timeline::new();
    let got = carol.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["before carol", "after carol"]);
    let _ = bob.mine().await.unwrap();
}

#[tokio::test]
async fn a_removed_member_cannot_read_what_follows() {
    // The rotation is the point and it is not optional. The exchange refuses
    // them further entries, but a removed member keeps every key it was ever
    // given — so without a new epoch they could still read what came after,
    // from the exchange's own copy or from anyone who forwards it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(3);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice
        .create_group("the thing", &[bob_key, carol_key])
        .await
        .unwrap();
    alice.send(&channel, "while bob was here").await.unwrap();
    bob.collect_keys(&channel).await.unwrap();
    let mut bobs = Timeline::new();
    assert_eq!(
        said(&bob.poll(&channel, &mut bobs, 0).await.unwrap().timeline),
        vec!["while bob was here"]
    );
    let bob_epoch = alice.info(&channel).await.unwrap().epoch;

    alice.remove(&channel, &bob_key).await.unwrap();
    assert!(
        alice.info(&channel).await.unwrap().epoch > bob_epoch,
        "removal did not rotate"
    );
    alice.send(&channel, "after bob left").await.unwrap();

    // Carol, who stayed, reads it.
    carol.collect_keys(&channel).await.unwrap();
    let mut ct = Timeline::new();
    assert!(
        said(&carol.poll(&channel, &mut ct, 0).await.unwrap().timeline)
            .contains(&"after bob left".to_string())
    );

    // Bob is refused outright, and would hold no key for the new epoch even if
    // he were not.
    assert!(bob.poll(&channel, &mut bobs, 0).await.is_err());
    assert!(bob.store().key(&channel, bob_epoch + 1).unwrap().is_none());
}

#[tokio::test]
async fn a_member_without_the_role_cannot_seize_an_epoch() {
    // A direct message's parties are both admins, so a client with no key
    // rotates to recover. In a group that would be a member taking an epoch
    // they were deliberately left out of, so they are told instead.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice.create_group("closed", &[bob_key]).await.unwrap();
    alice.send(&channel, "members only").await.unwrap();
    bob.collect_keys(&channel).await.unwrap();
    drop(bob);

    // Bob loses his store. In a direct message he would rotate and carry on;
    // here he is an ordinary member, so he is told he has no key rather than
    // taking an epoch the admin did not give him.
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob-again.db")).await;
    assert!(matches!(
        bob.ensure_epoch(&channel).await,
        Err(sqex_chat::ChatError::NoKey(_))
    ));

    // The channel is undisturbed: Alice can still post and the epoch has not
    // moved under her.
    let before = alice.info(&channel).await.unwrap().epoch;
    alice.send(&channel, "still here").await.unwrap();
    assert_eq!(alice.info(&channel).await.unwrap().epoch, before);
    let _ = before;

    // Re-inviting him cannot fix it: an envelope for him at this epoch already
    // exists — the one sealed to the prekey he lost — and the exchange refuses
    // a second, which is the rule that settles the creation race.
    assert!(matches!(
        alice.invite(&channel, &bob_key).await,
        Err(sqex_chat::ChatError::AlreadyKeyed(_))
    ));

    // The remedy is a rotation, and it is an admin's to apply. Bob cannot.
    assert!(matches!(
        bob.rotate(&channel).await,
        Err(sqex_chat::ChatError::NotAnAdmin)
    ));
    alice.rotate(&channel).await.unwrap();
    assert!(bob.ensure_epoch(&channel).await.is_ok());
    alice.send(&channel, "and now bob is back").await.unwrap();

    let mut t = Timeline::new();
    let got = bob.poll(&channel, &mut t, 0).await.unwrap();
    let read = said(&got.timeline);
    assert!(
        read.contains(&"and now bob is back".to_string()),
        "the rotation did not reach him: {read:?}"
    );
    // And what was said while he had no key stays shut. A rotation hands out
    // the next epoch, never the last one — that is the forward secrecy doing
    // its job rather than a gap in the recovery.
    assert!(!read.contains(&"still here".to_string()));
    // Reported as gone rather than as late: those epochs are superseded, and
    // a rotation hands out the next one and never an old one.
    assert!(got.lost > 0, "the gap should be reported");
    assert!(got.unreadable.is_empty(), "and not as something still coming");
}

#[tokio::test]
async fn a_client_republishes_when_the_exchange_has_lost_its_prekeys() {
    // The failure this closes was silent and total. Prekeys used to live only
    // in the exchange's memory, so bouncing it made every device unsealable-to
    // — and a client's own pool is untouched by that, so it saw a healthy
    // count and published nothing. Group creation stopped at epoch 0 with
    // nothing to say why, which is how it was found.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    // Bob's prekeys vanish from the exchange while his own store keeps its
    // secrets — an exchange restored from a backup taken before he published.
    let db = dir.path().join("prekeys.db");
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "DELETE FROM prekey WHERE device = ?1",
            [bob_key.as_bytes()],
        )
        .unwrap();
    }
    let channel = alice.open_dm(&bob_key).await.unwrap();
    assert!(
        matches!(
            alice.send(&channel, "anyone there?").await,
            Err(sqex_chat::ChatError::NotReady(_))
        ),
        "there should be nothing to seal to"
    );

    // Bob starts his client. It asks what the exchange holds rather than
    // trusting its own count, finds nothing, and republishes.
    let mut bob2 = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    alice
        .send(&channel, "back in business")
        .await
        .expect("bob is sealable again");

    bob2.open_dm(&alice.me).await.unwrap();
    let mut t = Timeline::new();
    let got = bob2.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["back in business"]);
    let _ = &mut bob;
}

#[tokio::test]
async fn history_lost_with_the_keys_is_told_apart_from_history_still_coming() {
    // Your situation, reduced. A client whose store went with its keys can
    // rotate and carry on, but the older entries stay shut — and reporting
    // that every session as "could not be opened", alongside live faults, is
    // how a status line stops being read.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let a_store = dir.path().join("alice.db");
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;

    let channel;
    {
        let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
        channel = alice.open_dm(&bob_key).await.unwrap();
        alice.send(&channel, "one").await.unwrap();
        alice.send(&channel, "two").await.unwrap();
        bob.open_dm(&alice_key).await.unwrap();
        bob.send(&channel, "three").await.unwrap();
    }

    // Alice loses everything and comes back. Both parties to a direct message
    // are admins, so her next send rotates and the conversation continues.
    std::fs::remove_file(&a_store).ok();
    let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
    alice.send(&channel, "still here").await.unwrap();
    bob.send(&channel, "so are we").await.unwrap();

    let mut t = Timeline::new();
    let got = alice.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(
        said(&got.timeline),
        vec!["still here", "so are we"],
        "the new epoch should read normally"
    );
    // The three from before are gone, and counted as gone.
    assert_eq!(got.lost, 3, "old entries should be counted as lost");
    assert!(
        got.unreadable.is_empty(),
        "nothing is merely late: {:?}",
        got.unreadable
    );

    // And it stays that way across a restart. The judgement is derived from
    // whether we hold the epoch in force, so it is re-made correctly each time
    // rather than remembered and going stale.
    let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
    let mut t = alice.history(&channel, &[alice_key, bob_key]).unwrap();
    let got = alice.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(got.lost, 3);
    assert!(got.unreadable.is_empty());
}

#[tokio::test]
async fn a_key_that_has_not_arrived_yet_is_not_called_lost() {
    // The distinction has to hold in both directions, or it is just a nicer
    // word for the same thing. Under the epoch in force an admin can still
    // send a key, so those entries are late rather than gone.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(3);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice.create_group("waiting room", &[bob_key]).await.unwrap();
    alice.send(&channel, "before carol").await.unwrap();

    // Carol is added to the channel but not given the key — the exchange lets
    // an admin do that, and SIP-17 says a client should say so plainly.
    alice
        .post_invite_without_key(&channel, &carol_key)
        .await
        .unwrap();
    let mut t = Timeline::new();
    let got = carol.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(got.lost, 0, "nothing is gone; the key simply has not come");
    assert!(!got.unreadable.is_empty(), "and it should say something is waiting");
    let _ = &mut bob;
}

// ---- public channels ------------------------------------------------------

#[tokio::test]
async fn a_stranger_finds_a_public_channel_and_joins_it() {
    // The whole point of a public channel: no invitation, no identifier passed
    // out of band, no key. The directory is how you find it and joining is how
    // you read it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut stranger = chat_at(addr, server_pub, 9, &dir.path().join("stranger.db")).await;

    let channel = alice.create_public("rustaceans", "").await.unwrap();
    alice.send(&channel, "anybody about?").await.unwrap();

    // The stranger was told nothing. They search, find it, and join.
    let listing = stranger.find("rusta", 0).await.unwrap();
    assert_eq!(listing.total, 1);
    assert_eq!(listing.channels[0].channel, channel);
    assert_eq!(listing.channels[0].name, "rustaceans");
    stranger.join(&channel).await.unwrap();

    let mut t = Timeline::new();
    let got = stranger.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["anybody about?"]);
    assert!(got.unreadable.is_empty(), "nothing to unseal");
    assert_eq!(got.lost, 0);

    // And they can speak, without anybody granting them anything.
    stranger.send(&channel, "just arrived").await.unwrap();
    let mut at = Timeline::new();
    let got = alice.poll(&channel, &mut at, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["anybody about?", "just arrived"]);
}

#[tokio::test]
async fn a_public_channel_is_stored_in_the_clear_and_that_is_the_point() {
    // SIP-16 is explicit: anybody may join, so anybody may hold any key it
    // used. Encrypting anyway would produce something that looks end-to-end
    // and is not. This test exists so that nobody later "fixes" it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice.create_public("town square", "").await.unwrap();
    let said_aloud = "this is not a secret";
    alice.send(&channel, said_aloud).await.unwrap();

    // Read it the way the exchange can: straight out of the entry it stored.
    let db = rusqlite::Connection::open(dir.path().join("channels.db")).unwrap();
    let body: Vec<u8> = db
        .query_row(
            "SELECT body FROM entry WHERE channel = ?1 AND kind = 1 ORDER BY seq DESC LIMIT 1",
            [&channel[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        body.windows(said_aloud.len())
            .any(|w| w == said_aloud.as_bytes()),
        "a public channel should be readable by the exchange"
    );
    // And it decodes as an ordinary SIP-19 body, with no key involved.
    let post = sqex_proto::message::Body::decode(&body).unwrap().unwrap();
    assert!(matches!(post, sqex_proto::message::Body::Post(_)));
    // No epoch, so no key was ever minted for it.
    assert_eq!(alice.info(&channel).await.unwrap().epoch, 0);
    assert!(alice.store().key(&channel, 0).unwrap().is_none());
}

#[tokio::test]
async fn a_private_channel_refuses_a_join() {
    // The rule that stops an identifier being a way in. A group's id is random
    // rather than derived, but 32 bytes is not a secret and must not be one.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let _bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut stranger = chat_at(addr, server_pub, 9, &dir.path().join("stranger.db")).await;

    let channel = alice.create_group("private club", &[bob_key]).await.unwrap();
    alice.send(&channel, "members only").await.unwrap();

    // Not in the directory under any query.
    assert!(stranger.find("", 0).await.unwrap().channels.is_empty());
    // And knowing the identifier does not help.
    assert!(stranger.join(&channel).await.is_err());
    let mut t = Timeline::new();
    assert!(stranger.poll(&channel, &mut t, 0).await.is_err());
}

#[tokio::test]
async fn a_public_channel_a_person_joined_comes_back_from_mine() {
    // It has to appear in the client's own list on the next start, or joining
    // is a thing you have to do again every time.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let joiner_store = dir.path().join("joiner.db");
    let mut joiner = chat_at(addr, server_pub, 9, &joiner_store).await;

    let channel = alice.create_public("the pub", "open to all").await.unwrap();
    joiner.join(&channel).await.unwrap();

    let mine = joiner.mine().await.unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].channel, channel);
    assert_eq!(mine[0].visibility, sqex_proto::channel::Visibility::Public);
    // Epoch 0: there is nothing to collect and nothing to wait for.
    assert_eq!(mine[0].epoch, 0);
}

// ---- multi-device (SIP-20, SIP-22, SIP-23) --------------------------------

/// A second client for an account that already has one.
///
/// Its own key, its own store, its own prekeys — everything a device holds
/// separately, which is the whole point.
async fn link_device(
    addr: SocketAddr,
    server_pub: [u8; 32],
    owner: &mut Chat,
    b: u8,
    store: &std::path::Path,
) -> Chat {
    let mut second = chat_at(addr, server_pub, b, store).await;
    // The owner registers itself first. An account with no registered devices
    // is its own device; once one is registered that fallback stops applying,
    // so the owner must be in the set or it seals itself out.
    if !owner
        .my_devices()
        .await
        .unwrap()
        .iter()
        .any(|d| d.device == owner.me)
    {
        let own = owner.issue_credential(&owner.me, 90 * 24 * 60 * 60).unwrap();
        owner.register_self(&own).await.unwrap();
    }
    let credential = owner
        .issue_credential(&second.device(), 90 * 24 * 60 * 60)
        .unwrap();
    second.register_self(&credential).await.unwrap();
    // The client learns whose it is; the exchange resolves device to account
    // internally and has no route that answers "who am I".
    second.store().set_account(&credential.account).unwrap();
    // A device that has published nothing cannot be sealed to.
    second.top_up_prekeys().await.unwrap();
    // Rebuilt so it picks the account up, as a real client would on next start.
    let client = Client::connect_as(addr, &server_pub, &identity(b).0).await.unwrap();
    let store = Store::open(&identity(b).0, Some(store)).unwrap();
    let mut second = Chat::new(client, identity(b).0, identity(b).1, store);
    second.top_up_prekeys().await.unwrap();
    second
}

#[tokio::test]
async fn two_devices_of_one_account_never_share_a_counter() {
    // The failure this whole stratum exists to prevent. SIP-17 derives the
    // sender subkey from the *device*, so two clients under one identity must
    // seal under different subkeys — otherwise both start at msg_seq 0 under
    // one key and ChaCha20-Poly1305 gives up the XOR of two plaintexts and its
    // authentication with it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut phone = chat_at(addr, server_pub, 1, &dir.path().join("phone.db")).await;

    let channel = phone.open_dm(&bob_key).await.unwrap();
    phone.send(&channel, "from the phone").await.unwrap();

    // Link a laptop to the same account, and give it the epoch in force.
    let mut laptop = link_device(addr, server_pub, &mut phone, 7, &dir.path().join("laptop.db")).await;
    phone.reseal_to_siblings(&channel).await.unwrap();
    assert!(laptop.collect_keys(&channel).await.unwrap() > 0, "the laptop got no key");
    laptop.send(&channel, "from the laptop").await.unwrap();

    // Both read the whole conversation.
    bob.open_dm(&alice_key).await.unwrap();
    let mut t = Timeline::new();
    let got = bob.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["from the phone", "from the laptop"]);

    // And the exchange recorded them under different devices. That is the
    // property; equal device keys here would mean a shared subkey.
    let db = rusqlite::Connection::open(dir.path().join("channels.db")).unwrap();
    let devices: Vec<Vec<u8>> = db
        .prepare("SELECT device FROM entry WHERE channel = ?1 AND kind = 1 ORDER BY seq")
        .unwrap()
        .query_map([&channel[..]], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(devices.len(), 2);
    assert_ne!(devices[0], devices[1], "both entries came from one device key");
    // And both are the *same account*, which is the other half of the property:
    // two devices, one person, as far as anybody reading is concerned.
    let accounts: Vec<Vec<u8>> = db
        .prepare("SELECT DISTINCT account FROM entry WHERE channel = ?1 AND kind = 1")
        .unwrap()
        .query_map([&channel[..]], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(accounts.len(), 1, "the two devices reported as two people");
    assert_eq!(accounts[0], alice_key.as_bytes().to_vec());
}

#[tokio::test]
async fn a_device_gets_its_key_from_a_sibling_with_no_admin_involved() {
    // SIP-17's same-account rule, which the exchange used not to implement: a
    // plain member could seal only to itself, and membership was checked
    // against the member table, which is keyed by account. So an envelope
    // aimed at a second device was refused as NotAMember.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, carol_key) = identity(3);
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;

    // Carol owns the group; Bob is an ordinary member with two devices.
    let (_, bob_key) = identity(2);
    let channel = carol.create_group("the thing", &[bob_key]).await.unwrap();
    carol.send(&channel, "before bob linked").await.unwrap();
    bob.collect_keys(&channel).await.unwrap();

    let mut bob2 = link_device(addr, server_pub, &mut bob, 8, &dir.path().join("bob2.db")).await;
    // Bob is not an admin here. He seals to his own other device anyway.
    bob.reseal_to_siblings(&channel).await.unwrap();
    assert!(bob2.collect_keys(&channel).await.unwrap() > 0);

    let mut t = Timeline::new();
    let got = bob2.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["before bob linked"]);
    // And the epoch did not move — nobody had to rotate to let him in.
    assert_eq!(carol.info(&channel).await.unwrap().epoch, 1);
    let _ = (alice_key, carol_key);
}

#[tokio::test]
async fn a_credential_is_bound_to_the_device_it_names() {
    // A credential somebody found is a credential they cannot use: the
    // delegate must equal the caller's transport identity.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut mine = chat_at(addr, server_pub, 7, &dir.path().join("mine.db")).await;
    let mut theirs = chat_at(addr, server_pub, 8, &dir.path().join("theirs.db")).await;

    let credential = alice.issue_credential(&mine.device(), 3600).unwrap();
    assert!(
        theirs.register_self(&credential).await.is_err(),
        "a forwarded credential registered somebody else's device"
    );
    assert!(mine.register_self(&credential).await.is_ok());
}

#[tokio::test]
async fn revoking_a_device_stops_it_being_sealed_to() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let _bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut phone = chat_at(addr, server_pub, 1, &dir.path().join("phone.db")).await;
    let mut laptop =
        link_device(addr, server_pub, &mut phone, 7, &dir.path().join("laptop.db")).await;

    // Both are registered: the phone by linking, the laptop by claiming.
    assert_eq!(phone.my_devices().await.unwrap().len(), 2);
    // `laptop.me` is the *account* now that it is linked — the thing to revoke
    // is its own key. Getting this wrong in a test is the same confusion the
    // account/device split exists to prevent.
    phone.revoke_device(&laptop.device()).await.unwrap();
    let left = phone.my_devices().await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].device, phone.device());

    // It can no longer act for the account: the exchange resolves it to
    // itself again, so it is a stranger to the channel.
    let channel = phone.open_dm(&bob_key).await.unwrap();
    phone.send(&channel, "after the revoke").await.unwrap();
    let mut t = Timeline::new();
    assert!(
        laptop.poll(&channel, &mut t, 0).await.is_err(),
        "a revoked device still read the conversation"
    );
}

#[tokio::test]
async fn a_late_key_opens_what_was_already_held() {
    // A device linked after a conversation started polls before its key
    // arrives, so it holds entries it cannot read. When the key comes, nothing
    // else would ever look at them again — and marking their counters seen on
    // a failed attempt would refuse them for good, which is not what SIP-17's
    // replay rule is for: it forbids decrypting a counter twice, and a failed
    // open decrypted nothing.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut phone = chat_at(addr, server_pub, 1, &dir.path().join("phone.db")).await;

    let channel = phone.open_dm(&bob_key).await.unwrap();
    phone.send(&channel, "said before you linked").await.unwrap();

    let mut laptop =
        link_device(addr, server_pub, &mut phone, 7, &dir.path().join("laptop.db")).await;

    // The laptop reads first, with no key. It keeps what it cannot open.
    let mut t = Timeline::new();
    let got = laptop.poll(&channel, &mut t, 0).await.unwrap();
    assert!(said(&got.timeline).is_empty(), "it should read nothing yet");

    // Then the key arrives.
    phone.reseal_to_siblings(&channel).await.unwrap();
    assert!(laptop.collect_keys(&channel).await.unwrap() > 0);

    // And what it was already holding opens.
    let mut t = laptop.history(&channel, &[]).unwrap();
    let got = laptop.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(
        said(&got.timeline),
        vec!["said before you linked"],
        "the entries held before the key arrived stayed shut"
    );
    let _ = &mut bob;
}

#[tokio::test]
async fn missing_names_devices_and_not_accounts() {
    // The one diagnostic the design has for a member who can fetch entries and
    // open none of them — and device-addressed envelopes inverted it. Asking
    // whether an *account* holds an envelope reports every correctly-sealed
    // member as stranded, and never reports the device that actually is.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut phone = chat_at(addr, server_pub, 1, &dir.path().join("phone.db")).await;

    let channel = phone.create_group("the thing", &[bob_key]).await.unwrap();
    // Everybody sealed: nothing is stranded.
    assert!(
        phone.stranded(&channel).await.unwrap().devices.is_empty(),
        "a correctly sealed channel reported somebody stranded"
    );

    // Link a device and do *not* reseal to it.
    let laptop =
        link_device(addr, server_pub, &mut phone, 7, &dir.path().join("laptop.db")).await;
    let absent = phone.stranded(&channel).await.unwrap();
    assert_eq!(absent.devices.len(), 1, "the new device should be reported");
    assert_eq!(absent.devices[0].device, laptop.device());
    assert_eq!(
        absent.devices[0].account, phone.me,
        "reported under the account it belongs to"
    );
    assert!(
        absent.devices[0].has_prekeys,
        "it published prekeys when it claimed, so it can be sealed to"
    );

    // Once sealed, it stops being reported.
    phone.reseal_to_siblings(&channel).await.unwrap();
    assert!(phone.stranded(&channel).await.unwrap().devices.is_empty());
    let _ = &mut bob;
}

#[tokio::test]
async fn a_member_may_rekey_after_revoking_one_of_its_own_devices() {
    // SIP-17 makes this a MUST, and without it the advice to rotate after a
    // revocation is advice nobody can follow: lose a phone in a group where
    // you are an ordinary member and you could revoke the device and not
    // change the key, so whoever holds it keeps reading every future message
    // until an admin — who may be unreachable — happens to act.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;

    // Carol owns the group. Bob is an ordinary member.
    let channel = carol.create_group("the thing", &[bob_key]).await.unwrap();
    bob.collect_keys(&channel).await.unwrap();
    let before = carol.info(&channel).await.unwrap().epoch;

    // Bob has revoked nothing, so he may not rotate.
    assert!(
        matches!(bob.rotate(&channel).await, Err(sqex_chat::ChatError::NotAnAdmin)),
        "an ordinary member rotated without cause"
    );

    // He links a device, loses it, and revokes it.
    let laptop = link_device(addr, server_pub, &mut bob, 8, &dir.path().join("laptop.db")).await;
    bob.revoke_device(&laptop.device()).await.unwrap();

    // Now he may rekey — exactly once per revocation, and the exchange checks
    // it because it holds both the revocation and when the epoch was minted.
    bob.rotate(&channel).await.unwrap();
    assert!(carol.info(&channel).await.unwrap().epoch > before);

    // And what follows is not the revoked device's.
    bob.send(&channel, "after the revoke").await.unwrap();
    let mut t = Timeline::new();
    let got = carol.poll(&channel, &mut t, 0).await.unwrap();
    assert!(said(&got.timeline).contains(&"after the revoke".to_string()));
}

#[tokio::test]
async fn a_revoked_client_is_told_so_rather_than_refused_everywhere() {
    // Otherwise it learns by being treated as a stranger by every route it
    // tries, which is true and explains nothing.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut phone = chat_at(addr, server_pub, 1, &dir.path().join("phone.db")).await;
    let mut laptop =
        link_device(addr, server_pub, &mut phone, 7, &dir.path().join("laptop.db")).await;

    assert_eq!(laptop.still_linked().await.unwrap(), Some(true));
    phone.revoke_device(&laptop.device()).await.unwrap();
    assert_eq!(laptop.still_linked().await.unwrap(), Some(false));

    // A client that was never linked has nothing to check and must not be
    // told it was revoked.
    assert_eq!(phone.still_linked().await.unwrap(), None);
}

/// SIP-16, "A reset sequence space". A cursor above the exchange's newest entry
/// is not being ahead of the conversation: it is the cursor of a channel that
/// was destroyed and recreated under the same identifier, numbering from 1
/// again. Only a direct message can do that, and it always does, because its
/// identifier is derived from the two accounts.
///
/// Left alone it never recovers — every entry the new channel accepts is at or
/// below the stale cursor, so a fetch returns nothing for good, including the
/// client's own posts. It presented as typing a message and watching nothing
/// appear, with no error at either end, and it cost an afternoon to find.
#[tokio::test]
async fn a_restarted_sequence_space_recovers_instead_of_going_silent() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let a_store = dir.path().join("alice.db");
    let b_store = dir.path().join("bob.db");
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let mut bob = chat_at(addr, server_pub, 2, &b_store).await;
    let mut alice = chat_at(addr, server_pub, 1, &a_store).await;
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "before").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let mut alices = Timeline::new();
    alice.poll(&channel, &mut alices, 0).await.unwrap();

    // Strand Alice's cursor far above anything the exchange holds. That is
    // exactly the state a destroyed-and-recreated channel leaves behind, without
    // needing to destroy one: the client is asking for entries that this
    // channel's numbering will not reach.
    alice.store().set_since(&channel, 9_999).unwrap();

    bob.send(&channel, "after the reset").await.unwrap();

    let mut fresh = Timeline::new();
    let got = alice.poll(&channel, &mut fresh, 0).await.unwrap();

    assert!(
        got.restarted,
        "a cursor above the exchange's newest entry was not recognised as a restart"
    );
    assert!(
        said(&got.timeline).contains(&"after the reset".to_string()),
        "the conversation stayed silent after its sequence space restarted: {:?}",
        said(&got.timeline)
    );

    // And it keeps working afterwards — the reset is a recovery, not a one-off
    // read that leaves the cursor wrong again.
    alice.send(&channel, "and onwards").await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert!(
        said(&got.timeline).contains(&"and onwards".to_string()),
        "sending after the recovery did not reach the other side: {:?}",
        said(&got.timeline)
    );
}

/// SIP-16 redaction has two halves and a client must issue both: the exchange
/// call removes the bytes and leaves a tombstone, the SIP-19 body is what other
/// clients render. Issuing only the second would leave the words at the
/// exchange for anyone who joined later with history access.
#[tokio::test]
async fn redacting_removes_the_words_from_the_exchange_and_tells_the_other_side() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "keep this").await.unwrap();
    let regret = alice.send(&channel, "delete this").await.unwrap().seq;

    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert!(said(&got.timeline).contains(&"delete this".to_string()));

    alice.redact(&channel, regret).await.unwrap();

    // Bob no longer shows it. The entry survives as a tombstone — the gap is
    // the record — but the words are gone. The same timeline is reused: it
    // accumulates, and the redaction arrives as a further entry against it.
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    let visible = said(&got.timeline);
    assert!(
        visible.contains(&"keep this".to_string()),
        "redaction took the wrong message: {visible:?}"
    );
    assert!(
        !visible.contains(&"delete this".to_string()),
        "the redacted message is still being shown: {visible:?}"
    );

    // The entry is kept, marked, and not dropped: SIP-16's tombstone is the
    // record, and a client that discarded it would show a conversation that
    // silently does not follow.
    let tomb = got.timeline.get(regret).expect("the tombstone was dropped");
    assert!(tomb.redacted, "the entry survived but was not marked redacted");
    assert!(
        tomb.post.body_text().is_none_or(|t| t.is_empty()),
        "the redacted body was kept in the timeline"
    );

    // And a reader arriving fresh, who never saw the original, cannot find it
    // either — which is the half that only the exchange call provides.
    let mut newcomer = chat_at(addr, server_pub, 2, &dir.path().join("bob2.db")).await;
    let mut fresh = Timeline::new();
    let got = newcomer.poll(&channel, &mut fresh, 0).await.unwrap();
    assert!(
        !said(&got.timeline).contains(&"delete this".to_string()),
        "the exchange still served the redacted body to a fresh reader"
    );

    // And they are told it was deleted, not that they are missing a key. A
    // reader who arrives after a redaction never held the words; reporting the
    // empty entry as unopenable sends them looking for a fault that is not
    // there.
    assert!(
        !got.timeline.unreadable().contains(&regret),
        "the tombstone (seq {regret}) was reported unopenable: {:?}",
        got.timeline.unreadable()
    );
    assert!(
        got.timeline.get(regret).is_some_and(|m| m.redacted),
        "a fresh reader did not see the tombstone at all"
    );
}

/// SIP-18: "deleting a message must delete what it carried". The exchange
/// cannot do this half — the reference lives inside a sealed body it cannot
/// read — so the client deleting the message has to detach the blob, and it is
/// the only party that can.
///
/// The fetch here is **by id**, not through the timeline, because the id is
/// exactly what a reader who already saw the message still holds. A reader who
/// wrote it down before the redaction is the whole threat: checking that the
/// message no longer shows the attachment proves nothing about whether the
/// bytes are still being served.
#[tokio::test]
async fn redacting_takes_the_file_with_it() {
    use sqex_proto::blob_store::CHUNK;
    use sqex_proto::message::{Part, Post as SipPost};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let path = dir.path().join("regret.txt");
    let secret: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &secret).unwrap();

    let channel = alice.open_dm(&bob_key).await.unwrap();
    let prepared = alice.prepare_file(&path, CHUNK).unwrap();
    let attachment = alice.upload(&channel, &prepared).await.unwrap();
    let mut post = SipPost::text("this was a mistake");
    post.parts.push(Part::Attachment(attachment.clone()));
    let regret = alice.send_post(&channel, post).await.unwrap().seq;

    // Bob reads it, and keeps the reference — as any client that rendered the
    // message necessarily has.
    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    let held = got
        .timeline
        .get(regret)
        .and_then(|m| m.post.attachments().next().cloned())
        .expect("bob never saw the attachment");
    assert_eq!(bob.download(&held).await.unwrap(), secret);

    let outcome = alice.redact(&channel, regret).await.unwrap();
    assert!(outcome.opened, "alice could not read her own message");
    assert_eq!(outcome.detached, 1, "the file was not detached");
    assert!(
        outcome.left_behind.is_empty(),
        "a file was left attached: {:?}",
        outcome.left_behind
    );

    // The reference Bob still holds no longer resolves.
    let after = bob.download(&held).await;
    assert!(
        after.is_err(),
        "the exchange still served the file of a deleted message to a reader \
         holding its id"
    );
}

/// Metadata is one record and a reader assigns all of it, so a client changing
/// one field must carry the others. `/name` sending an empty topic silently
/// destroyed it, with nothing in the client able to put it back.
#[tokio::test]
async fn renaming_a_channel_leaves_its_topic_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice.create_group("planning", &[]).await.unwrap();
    alice
        .set_topic(&channel, "what we ship in October")
        .await
        .unwrap();
    alice.set_name(&channel, "shipping").await.unwrap();

    let (_, me) = identity(1);
    let held = alice.history(&channel, &[me]).unwrap();
    assert_eq!(held.name, "shipping");
    assert_eq!(
        held.topic, "what we ship in October",
        "renaming destroyed the topic"
    );

    // And the other way round, since the same record carries both.
    alice.set_topic(&channel, "what we ship in November").await.unwrap();
    let held = alice.history(&channel, &[me]).unwrap();
    assert_eq!(held.name, "shipping", "setting the topic destroyed the name");
    assert_eq!(held.topic, "what we ship in November");
}

/// Deleting a message has to reach the copies on disk. The exchange drops the
/// bytes, but every reader that opened the message keeps the plaintext in its
/// own store — sealed at rest, and recoverable by anyone holding the identity.
/// "Delete" meaning hidden rather than gone is not what the word promises.
#[tokio::test]
async fn redacting_takes_the_words_off_both_disks() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice.open_dm(&bob_key).await.unwrap();
    let regret = alice.send(&channel, "the incriminating words").await.unwrap().seq;

    bob.open_dm(&alice_key).await.unwrap();
    let mut bobs = Timeline::new();
    bob.poll(&channel, &mut bobs, 0).await.unwrap();

    // Both hold the plaintext at this point, which is the whole point of the
    // store: an entry the exchange serves once is one a client cannot re-read.
    let held = |c: &Chat| {
        c.store()
            .messages(&channel)
            .unwrap()
            .into_iter()
            .find(|(seq, ..)| *seq == regret)
            .and_then(|(_, _, _, _, plain)| plain)
    };
    assert!(held(&alice).is_some_and(|p| !p.is_empty()));
    assert!(held(&bob).is_some_and(|p| !p.is_empty()));

    alice.redact(&channel, regret).await.unwrap();

    // The sender's copy goes at once, not on some later poll.
    assert_eq!(
        held(&alice),
        Some(Vec::new()),
        "the words stayed on the deleting client's disk"
    );

    // And the reader's, as soon as it learns of the redaction.
    bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(
        held(&bob),
        Some(Vec::new()),
        "the words stayed on the reader's disk"
    );

    // Empty and not absent: "deleted" and "held but could not be opened" are
    // different things and have to survive a restart as different things.
    let reopened = Store::open(&identity(2).0, Some(&dir.path().join("bob.db"))).unwrap();
    let row = reopened
        .messages(&channel)
        .unwrap()
        .into_iter()
        .find(|(seq, ..)| *seq == regret)
        .unwrap();
    assert_eq!(row.4, Some(Vec::new()), "a tombstone came back as unopenable");
}

/// Only the message's own account or an admin may delete it, and the store has
/// to obey the same rule as the fold. A client that cleared its disk on any
/// redaction it received would let anybody in a channel destroy anybody's
/// message — on everybody else's machine.
#[tokio::test]
async fn a_forged_redaction_does_not_reach_the_disk() {
    use sqex_proto::message::Body;

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(3);

    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;

    // A group, so there is a third party with no authority over the message.
    let channel = alice
        .create_group("planning", &[bob_key, carol_key])
        .await
        .unwrap();
    let said = alice.send(&channel, "alice's words").await.unwrap().seq;

    bob.collect_keys(&channel).await.unwrap();
    let mut bobs = Timeline::new();
    bob.poll(&channel, &mut bobs, 0).await.unwrap();

    // Carol is an ordinary member. The exchange would refuse her a redaction,
    // so she sends only the SIP-19 notice — which nothing at the exchange can
    // check, because it cannot read it.
    carol.collect_keys(&channel).await.unwrap();
    carol
        .send_body(&channel, Body::Redact { target: said })
        .await
        .unwrap();

    bob.poll(&channel, &mut bobs, 0).await.unwrap();
    let held = bob
        .store()
        .messages(&channel)
        .unwrap()
        .into_iter()
        .find(|(seq, ..)| *seq == said)
        .and_then(|(_, _, _, _, plain)| plain);
    assert!(
        held.is_some_and(|p| !p.is_empty()),
        "a member with no authority destroyed somebody else's message on \
         another member's disk"
    );
    assert!(
        bobs.get(said).is_some_and(|m| !m.redacted),
        "the fold honoured a forged redaction"
    );
}

/// A message deleted before this client knew to clear its disk kept the words
/// for good: the poll path only helps from the moment it runs. Folding a
/// history is where those are found, and it happens once per channel at start.
///
/// The old state is built directly, because the current code cannot produce it
/// — which is the point of the fix.
#[tokio::test]
async fn words_deleted_before_we_learned_to_forget_them_are_cleared_on_reload() {
    use sqex_chat::store::Kept;
    use sqex_proto::channel::KIND_MEMBER;
    use sqex_proto::message::{Body, Post as SipPost};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (seed, me) = identity(2);
    let (_, them) = identity(1);
    let path = dir.path().join("old.db");
    let channel = [9u8; 32];

    // What an older client's store looked like: the message with its words
    // still in it, and the notice that deleted it sitting right after.
    {
        let store = Store::open(&seed, Some(&path)).unwrap();
        let post = Body::Post(SipPost::text("the incriminating words")).encode();
        store
            .put_message(
                &channel,
                Kept { seq: 1, account: them, posted: 10, kind: KIND_MEMBER, plain: Some(&post) },
            )
            .unwrap();
        let notice = Body::Redact { target: 1 }.encode();
        store
            .put_message(
                &channel,
                Kept { seq: 2, account: them, posted: 20, kind: KIND_MEMBER, plain: Some(&notice) },
            )
            .unwrap();
        let words = store
            .messages(&channel)
            .unwrap()
            .into_iter()
            .find(|(s, ..)| *s == 1)
            .and_then(|(_, _, _, _, p)| p)
            .unwrap();
        assert!(!words.is_empty(), "the old state was not built");
    }

    // Opening it folds the history, which is where the deletion is noticed.
    let chat = Chat::new(
        Client::connect_as(addr, &server_pub, &seed).await.unwrap(),
        seed,
        me,
        Store::open(&seed, Some(&path)).unwrap(),
    );
    let folded = chat.history(&channel, &[them]).unwrap();
    assert!(folded.get(1).is_some_and(|m| m.redacted), "the fold missed it");

    assert_eq!(
        chat.store()
            .messages(&channel)
            .unwrap()
            .into_iter()
            .find(|(s, ..)| *s == 1)
            .and_then(|(_, _, _, _, p)| p),
        Some(Vec::new()),
        "the words of an already-deleted message survived the reload"
    );
}
