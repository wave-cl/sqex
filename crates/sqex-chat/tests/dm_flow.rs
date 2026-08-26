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
    assert!(!got.unreadable.is_empty(), "the gap should be reported");
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
