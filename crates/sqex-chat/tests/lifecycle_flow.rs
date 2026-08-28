//! A channel from its creation to its end, through the client.
//!
//! The exchange's own tests prove the rows go. What only a client test can
//! prove is what the client does afterwards — closing a conversation and then
//! sitting there waiting for messages from it would be a working server and a
//! broken client, and the exchange has no way to notice.
//!
//! Closing a direct message is also where SIP-16's reset sequence space comes
//! from: the identifier is derived from the two accounts, so the conversation
//! comes back under the same name with its numbering restarted. That went
//! wrong in a real conversation, and this is the arc that produces it.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::channel::MIN_RETENTION;
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

fn said(t: &Timeline) -> Vec<String> {
    t.messages()
        .filter(|m| m.is_visible())
        .filter_map(|m| m.post.body_text().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn narrowing_a_channels_memory_deletes_what_no_longer_fits() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.create_group("planning", &[bob_key]).await.unwrap();
    for text in ["one", "two", "three", "four"] {
        alice.send(&channel, text).await.unwrap();
    }

    // Four messages, and a limit of three places — one of which the record of
    // this change will occupy.
    alice
        .set_retention(&channel, MIN_RETENTION, 3)
        .await
        .unwrap();

    // A reader who was never here sees what is left, and is told it is not the
    // whole conversation.
    bob.collect_keys(&channel).await.unwrap();
    let mut bobs = Timeline::new();
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["three", "four"]);
    let _ = alice_key;

    // Out of range is refused before it is sent: a client that let somebody
    // ask for a second of retention would delete a conversation to find out
    // the exchange says no.
    assert!(alice.set_retention(&channel, 1, 0).await.is_err());
    assert!(alice.set_retention(&channel, u32::MAX, 0).await.is_err());
}

#[tokio::test]
async fn closing_a_channel_ends_it_for_everyone() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, bob_key) = identity(2);

    let channel = alice.create_group("planning", &[bob_key]).await.unwrap();
    alice.send(&channel, "we ship on friday").await.unwrap();
    bob.collect_keys(&channel).await.unwrap();
    let mut bobs = Timeline::new();
    assert_eq!(
        said(&bob.poll(&channel, &mut bobs, 0).await.unwrap().timeline),
        vec!["we ship on friday"]
    );

    alice.close(&channel).await.unwrap();

    // Gone for the other member too, and gone as a channel rather than as an
    // empty one: it is not in Bob's list and cannot be read.
    assert!(
        !bob.mine()
            .await
            .unwrap()
            .iter()
            .any(|m| m.channel == channel),
        "a closed channel is still listed"
    );
    assert!(
        bob.poll(&channel, &mut bobs, 0).await.is_err(),
        "a closed channel was still readable"
    );

    // And the client that closed it forgets it, or it polls a channel that no
    // longer exists for the rest of the session. This is the half only a
    // client test can see.
    alice.store().forget_channel(&channel).unwrap();
    assert!(
        !alice
            .store()
            .channels()
            .unwrap()
            .iter()
            .any(|(c, ..)| *c == channel),
        "the closing client kept the channel it destroyed"
    );
}

#[tokio::test]
async fn a_direct_message_closed_and_reopened_recovers_rather_than_going_silent() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    for text in ["one", "two", "three"] {
        alice.send(&channel, text).await.unwrap();
    }
    let mut bobs = Timeline::new();
    assert_eq!(
        said(&bob.poll(&channel, &mut bobs, 0).await.unwrap().timeline),
        vec!["one", "two", "three"]
    );

    // Bob ends it. A direct message's identifier is derived from the two
    // accounts, so what comes back has the same name and starts counting from
    // one again — which is exactly how a real conversation went silent.
    bob.close(&channel).await.unwrap();
    let reopened = alice.open_dm(&bob_key).await.unwrap();
    assert_eq!(reopened, channel, "the identifier is derived, so it returns");
    bob.open_dm(&alice_key).await.unwrap();
    // Alice polls before she writes, as a running client does every 700 ms.
    // She holds keys and a cursor for a channel that no longer exists, and the
    // reset is what clears them — sealing under the old epoch would produce a
    // message nobody in the new channel can open.
    let mut alices = Timeline::new();
    alice.poll(&channel, &mut alices, 0).await.unwrap();
    alice.send(&channel, "still here?").await.unwrap();

    // Bob's cursor is above the new channel's newest entry. Being ahead of the
    // conversation is not the same as having read it: SIP-16 says a `since`
    // above `last` means the space restarted, and the client starts again
    // rather than waiting forever for entries that will never come.
    let got = bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert!(got.restarted, "the reset sequence space was not noticed");
    assert!(
        said(&got.timeline).contains(&"still here?".to_string()),
        "the client went silent after the channel came back: {:?}",
        said(&got.timeline)
    );
}

#[tokio::test]
async fn reading_is_reported_back_and_declining_to_say_is_not_the_same_as_not_reading() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    let last = alice.send(&channel, "did you see this?").await.unwrap().seq;

    // Nobody has read it yet. This client has published its own cursor since
    // it was written and never once read anybody else's, so until now the
    // receipts went out and nothing came back.
    let before = alice.marks(&channel).await.unwrap();
    let bobs_mark = before.iter().find(|m| m.account == bob_key);
    assert!(
        bobs_mark.is_none_or(|m| m.read < last),
        "bob was reported as having read something he has not"
    );

    let mut bobs = Timeline::new();
    bob.poll(&channel, &mut bobs, 0).await.unwrap();
    bob.mark_read(&channel, last).await.unwrap();

    let after = alice.marks(&channel).await.unwrap();
    let mark = after
        .iter()
        .find(|m| m.account == bob_key)
        .expect("bob has no mark at all");
    assert_eq!(mark.read, last, "reading was not reported back");
    assert!(mark.delivered >= last);
}

/// SIP-18 forwarding: the reference moves, the bytes do not.
///
/// Which also means forwarding a file hands its recipients the key to it —
/// the key rides inside the message carrying the reference. That is what
/// forwarding is, and the test says so by opening the file at the far end.
#[tokio::test]
async fn a_file_is_forwarded_without_being_uploaded_again() {
    use sqex_proto::blob_store::CHUNK;
    use sqex_proto::message::{Part, Post as SipPost};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(3);

    let path = dir.path().join("plan.txt");
    let contents: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &contents).unwrap();

    // Alice sends Bob a file.
    let first = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    let prepared = alice.prepare_file(&path, CHUNK).unwrap();
    let attachment = alice.upload(&first, &prepared).await.unwrap();
    let mut post = SipPost::text("the plan");
    post.parts.push(Part::Attachment(attachment.clone()));
    alice.send_post(&first, post).await.unwrap();

    let mut bobs = Timeline::new();
    let got = bob.poll(&first, &mut bobs, 0).await.unwrap();
    let held = got
        .timeline
        .messages()
        .next()
        .unwrap()
        .post
        .attachments()
        .next()
        .unwrap()
        .clone();

    // Bob forwards it to Carol, uploading nothing.
    let second = bob.open_dm(&carol_key).await.unwrap();
    carol.open_dm(&bob_key).await.unwrap();
    bob.attach(&second, &held.blob).await.unwrap();
    let mut post = SipPost::text("look at this");
    post.parts.push(Part::Attachment(held.clone()));
    bob.send_post(&second, post).await.unwrap();

    let mut carols = Timeline::new();
    let got = carol.poll(&second, &mut carols, 0).await.unwrap();
    let arrived = got
        .timeline
        .messages()
        .next()
        .unwrap()
        .post
        .attachments()
        .next()
        .unwrap()
        .clone();
    assert_eq!(arrived.blob, attachment.blob, "the file was re-uploaded");
    assert_eq!(
        carol.download(&arrived).await.unwrap(),
        contents,
        "the forwarded file did not open"
    );

    // Alice ending her conversation with Bob does not take the file out of
    // Carol's: a blob dies with its last attachment, not with one channel.
    alice.close(&first).await.unwrap();
    assert_eq!(carol.download(&arrived).await.unwrap(), contents);
}

/// SIP-18 again, from the other side: a reference cannot be minted for a blob
/// the caller has no claim on, or forwarding would be a way to attach any file
/// on the exchange to a channel by guessing its name.
#[tokio::test]
async fn a_blob_we_cannot_fetch_cannot_be_attached() {
    use sqex_proto::blob_store::CHUNK;

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut mallory = chat_at(addr, server_pub, 3, &dir.path().join("mallory.db")).await;
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(4);

    let path = dir.path().join("private.txt");
    std::fs::write(&path, vec![7u8; 2000]).unwrap();
    let theirs = alice.open_dm(&bob_key).await.unwrap();
    let prepared = alice.prepare_file(&path, CHUNK).unwrap();
    let attachment = alice.upload(&theirs, &prepared).await.unwrap();

    // Mallory knows the name — it is the hash of the ciphertext, and a name is
    // not a secret. It buys nothing.
    let mine = mallory.open_dm(&carol_key).await.unwrap();
    assert!(
        mallory.attach(&mine, &attachment.blob).await.is_err(),
        "a blob was attached by somebody with no claim on it"
    );
}
