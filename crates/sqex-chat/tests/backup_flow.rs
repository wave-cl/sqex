//! SIP-48: a store goes up to the exchange sealed, and comes back down into
//! a fresh one -- after the exchange has forgotten the conversation, so what
//! comes back can only have come from the backup. The controls: the wrong
//! words open nothing, a stranger reads nothing, and a second backup with
//! nothing new uploads nothing.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::backup::{from_words, words};
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32]) {
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
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
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

fn said(timeline: &Timeline) -> Vec<String> {
    timeline
        .messages()
        .filter(|m| m.is_visible())
        .filter_map(|m| m.post.body_text().map(|t| t.to_string()))
        .collect()
}

#[tokio::test]
async fn a_store_comes_back_from_the_exchange_after_the_exchange_forgot_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;

    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "one").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    bob.send(&channel, "two").await.unwrap();
    alice.send(&channel, "three").await.unwrap();
    let mut t = Timeline::new();
    let got = alice.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["one", "two", "three"]);
    alice.store().add_contact(&bob_key, "Bob", 1).unwrap();
    alice.store().verify(&bob_key, 2).unwrap();

    // A key, shown as words that read back to it.
    assert!(alice.backup_key().unwrap().is_none());
    let key = alice.new_backup_key().unwrap();
    assert_eq!(alice.backup_key().unwrap(), Some(key));
    let w = words(&key);
    assert_eq!(from_words(&w).unwrap(), key);

    let r = alice.backup(&key).await.unwrap();
    assert_eq!(r.generation, 1);
    assert_eq!((r.uploaded, r.kept, r.contacts), (1, 0, 1), "{r:?}");
    assert!(r.used > 0 && r.used <= r.quota);

    // Nothing new: the segment from last time still covers the channel.
    let r2 = alice.backup(&key).await.unwrap();
    assert_eq!(r2.generation, 2);
    assert_eq!((r2.uploaded, r2.kept), (0, 1), "{r2:?}");

    // The exchange forgets all but its newest entry. A fresh store for
    // alice reads that one from it and nothing below.
    alice
        .set_retention(&channel, sqex_proto::channel::MIN_RETENTION, 1)
        .await
        .unwrap();
    let mut t = Timeline::new();
    let _ = alice.poll(&channel, &mut t, 0).await;
    let mut fresh = chat_at(addr, server_pub, 1, &dir.path().join("alice-2.db")).await;
    let mut t = Timeline::new();
    let _ = fresh.poll(&channel, &mut t, 0).await;
    assert_eq!(fresh.store().entry_count(&channel).unwrap(), 1);
    assert!(fresh.store().contacts().unwrap().is_empty());

    // The wrong words open nothing.
    let mut wrong = key;
    wrong[0] ^= 1;
    assert!(
        fresh.restore(&wrong, None).await.is_err(),
        "a wrong key restored"
    );
    // A stranger reads nothing.
    assert!(
        bob.restore(&key, Some(alice_key)).await.is_err(),
        "bob read alice's backup"
    );

    // The right words: the history and the key it opens with, and the
    // contact, verified as she left it.
    let r = fresh.restore(&key, None).await.unwrap();
    assert_eq!(r.generation, 2);
    assert_eq!(r.channels, 1, "{r:?}");
    assert!(r.entries >= 2, "{r:?}");
    assert!(r.keys >= 1, "{r:?}");
    assert_eq!(r.contacts, 1);
    assert!(r.skipped.is_empty(), "{:?}", r.skipped);
    assert_eq!(
        fresh.store().entry_count(&channel).unwrap(),
        alice.store().entry_count(&channel).unwrap()
    );
    let history = fresh.history(&channel, &[alice_key, bob_key]).unwrap();
    assert_eq!(said(&history), vec!["one", "two", "three"]);
    let contacts = fresh.store().contacts().unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].label, "Bob");
    assert!(
        fresh
            .store()
            .verified()
            .unwrap()
            .iter()
            .any(|(k, _)| *k == bob_key)
    );

    // Dropped: nothing to restore from.
    alice.drop_backup().await.unwrap();
    let mut third = chat_at(addr, server_pub, 1, &dir.path().join("alice-3.db")).await;
    assert!(third.restore(&key, None).await.is_err());
}
