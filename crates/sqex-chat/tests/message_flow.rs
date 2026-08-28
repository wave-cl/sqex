//! The SIP-19 message types, through two real clients and a real exchange.
//!
//! `Timeline::apply` has folded reactions, edits, replies and mentions since it
//! was written, and every one of those paths is tested — against entries built
//! by hand. Nothing tested that a client could *produce* one, and until now
//! none could: `Chat` sent `Post` and `Redact` and nothing else. So somebody
//! could react to your message and you would never learn of it, and the fold
//! that handled it perfectly was never reached.
//!
//! These go through the seal, the exchange and the fold, which is the only way
//! to tell "the reader handles this shape" from "the two halves agree".

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::message::{Part, Post as SipPost};
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

/// Two clients in a direct message, and the timelines each ends up with.
struct Pair {
    alice: Chat,
    bob: Chat,
    channel: [u8; 32],
    /// Held so the temporary directory outlives the clients using it.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
}

async fn pair() -> Pair {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    Pair {
        alice,
        bob,
        channel,
        dir,
    }
}

#[tokio::test]
async fn a_reaction_reaches_the_other_side_and_counts_once() {
    let mut p = pair().await;
    let seq = p.alice.send(&p.channel, "we ship on friday").await.unwrap().seq;

    let mut bobs = Timeline::new();
    p.bob.poll(&p.channel, &mut bobs, 0).await.unwrap();
    p.bob.react(&p.channel, seq, "👍", true).await.unwrap();

    // Sent twice. The fold is keyed on (account, target, emoji), so this is
    // not two — which is what lets a client send one without first knowing
    // what it has already sent.
    p.bob.react(&p.channel, seq, "👍", true).await.unwrap();

    let mut alices = Timeline::new();
    let got = p.alice.poll(&p.channel, &mut alices, 0).await.unwrap();
    let m = got.timeline.get(seq).expect("the message went missing");
    let (_, who) = m.reactions.iter().next().expect("no reaction arrived");
    assert_eq!(who.len(), 1, "the same reaction was counted twice");
    assert_eq!(who[0], identity(2).1, "the reaction named the wrong account");

    // And taking it back empties it, rather than leaving a zero.
    p.bob.react(&p.channel, seq, "👍", false).await.unwrap();
    let got = p.alice.poll(&p.channel, &mut alices, 0).await.unwrap();
    assert!(
        got.timeline.get(seq).unwrap().reactions.is_empty(),
        "the reaction survived being taken back"
    );
}

#[tokio::test]
async fn a_reaction_the_exchange_could_read_would_be_a_leak() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let seq = alice.send(&channel, "a thing").await.unwrap().seq;
    let mut bobs = Timeline::new();
    bob.poll(&channel, &mut bobs, 0).await.unwrap();
    bob.react(&channel, seq, "🎉", true).await.unwrap();

    // A reaction is an ordinary sealed entry. The exchange counts nothing and
    // stores nothing it can read — including the emoji, which on its own would
    // say a great deal about a conversation it cannot otherwise see.
    let stored = std::fs::read(dir.path().join("channels.db")).unwrap();
    assert!(
        !stored.windows(4).any(|w| w == "🎉".as_bytes()),
        "the emoji reached the exchange in the clear"
    );
}

#[tokio::test]
async fn an_edit_replaces_the_words_and_says_that_it_did() {
    let mut p = pair().await;
    let seq = p.alice.send(&p.channel, "we ship on thursday").await.unwrap().seq;

    let mut bobs = Timeline::new();
    let got = p.bob.poll(&p.channel, &mut bobs, 0).await.unwrap();
    assert_eq!(
        got.timeline.get(seq).unwrap().post.body_text(),
        Some("we ship on thursday")
    );

    p.alice
        .edit(&p.channel, seq, SipPost::text("we ship on friday"))
        .await
        .unwrap();

    let got = p.bob.poll(&p.channel, &mut bobs, 0).await.unwrap();
    let m = got.timeline.get(seq).unwrap();
    assert_eq!(m.post.body_text(), Some("we ship on friday"));
    // Marked, and it has to be: presenting an edit as the original hides that
    // the words changed after somebody read them.
    assert!(m.edited.is_some(), "the edit was applied but not marked");
    // And it is not a second message.
    assert_eq!(
        got.timeline.messages().count(),
        1,
        "the edit was folded in as a message of its own"
    );
}

#[tokio::test]
async fn nobody_can_edit_somebody_elses_message() {
    let mut p = pair().await;
    let seq = p.alice.send(&p.channel, "what alice said").await.unwrap().seq;

    let mut bobs = Timeline::new();
    p.bob.poll(&p.channel, &mut bobs, 0).await.unwrap();
    // The exchange cannot check this — it cannot read either entry — so the
    // refusal is the reader's, and the wire carries the attempt.
    p.bob
        .edit(&p.channel, seq, SipPost::text("what bob wishes alice said"))
        .await
        .unwrap();

    let mut alices = Timeline::new();
    let got = p.alice.poll(&p.channel, &mut alices, 0).await.unwrap();
    assert_eq!(
        got.timeline.get(seq).unwrap().post.body_text(),
        Some("what alice said"),
        "a forged edit was applied"
    );
}

#[tokio::test]
async fn a_reply_carries_what_it_answers() {
    let mut p = pair().await;
    let asked = p.alice.send(&p.channel, "thursday or friday?").await.unwrap().seq;

    let mut bobs = Timeline::new();
    p.bob.poll(&p.channel, &mut bobs, 0).await.unwrap();
    p.bob.reply(&p.channel, asked, "friday").await.unwrap();

    let mut alices = Timeline::new();
    let got = p.alice.poll(&p.channel, &mut alices, 0).await.unwrap();
    let answer = got
        .timeline
        .messages()
        .find(|m| m.post.body_text() == Some("friday"))
        .expect("the reply never arrived");
    assert_eq!(
        answer.post.reply_to(),
        Some(asked),
        "the reply lost what it was answering"
    );
}

#[tokio::test]
async fn a_mention_survives_and_carries_no_name() {
    let mut p = pair().await;
    let (_, bob_key) = identity(2);
    let mut post = SipPost::text("ask them");
    post.parts.push(Part::Mention(bob_key));
    p.alice.send_post(&p.channel, post).await.unwrap();

    let mut bobs = Timeline::new();
    let got = p.bob.poll(&p.channel, &mut bobs, 0).await.unwrap();
    let m = got.timeline.messages().next().unwrap();
    let named: Vec<_> = m.post.mentions().collect();
    assert_eq!(named, vec![&bob_key], "the mention did not survive");
    // SIP-19 gives a mention no room for a display name, deliberately: a name
    // inside a message is one the sender controls, rendered exactly where a
    // reader looks to work out who is being talked about.
    assert_eq!(m.post.body_text(), Some("ask them"));
}

#[tokio::test]
async fn a_reaction_to_a_message_that_is_not_there_changes_nothing() {
    let mut p = pair().await;
    p.alice.send(&p.channel, "hello").await.unwrap();
    // Nothing holds sequence 99. The fold has no target to check the reaction
    // against, so it does nothing rather than inventing a message to hang it
    // on — which is what a client arriving mid-conversation always sees.
    p.bob.react(&p.channel, 99, "👍", true).await.unwrap();

    let mut alices = Timeline::new();
    let got = p.alice.poll(&p.channel, &mut alices, 0).await.unwrap();
    assert!(got.timeline.get(99).is_none());
    assert_eq!(got.timeline.messages().count(), 1);
}

#[tokio::test]
async fn an_oversized_reaction_is_refused_here_rather_than_at_the_reader() {
    let mut p = pair().await;
    let seq = p.alice.send(&p.channel, "hello").await.unwrap().seq;
    // The wire limit is in bytes and the decoder enforces it. Sending one the
    // reader will refuse costs a message counter and tells nobody anything, so
    // it is refused before it is sealed.
    let err = p
        .bob
        .react(&p.channel, seq, &"x".repeat(64), true)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("bytes"),
        "unhelpful refusal: {err}"
    );
    assert!(p.bob.react(&p.channel, seq, "", true).await.is_err());
}

/// The avatar is the third field of the metadata record, and the one most
/// easily lost: it is set rarely and the other two are changed often, so a
/// client that does not carry it over deletes it on the next rename.
#[tokio::test]
async fn a_channel_picture_survives_the_name_changing_under_it() {
    use sqex_proto::blob_store::CHUNK;

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, me) = identity(1);

    let path = dir.path().join("badge.png");
    let picture: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &picture).unwrap();

    let channel = alice.create_group("planning", &[]).await.unwrap();
    let prepared = alice.prepare_file(&path, CHUNK).unwrap();
    let attachment = alice.upload(&channel, &prepared).await.unwrap();
    alice
        .set_avatar(&channel, Some(attachment.clone()))
        .await
        .unwrap();

    alice.set_name(&channel, "shipping").await.unwrap();
    alice.set_topic(&channel, "october").await.unwrap();

    let held = alice.history(&channel, &[me]).unwrap();
    assert_eq!(held.name, "shipping");
    assert_eq!(held.topic, "october");
    let kept = held.avatar.as_ref().expect("the picture was lost on rename");
    assert_eq!(kept.blob, attachment.blob);

    // And it opens: the reference survived intact, not merely a field with
    // something in it.
    assert_eq!(alice.download(kept).await.unwrap(), picture);

    // Removing it is a thing that can be asked for, and is not the same as
    // changing the name.
    alice.set_avatar(&channel, None).await.unwrap();
    let held = alice.history(&channel, &[me]).unwrap();
    assert!(held.avatar.is_none(), "the picture could not be removed");
    assert_eq!(held.name, "shipping", "removing the picture took the name");
}
