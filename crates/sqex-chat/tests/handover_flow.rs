//! SIP-62 at the client. Alice hands her account over to a new key from
//! inside the client: it goes on acting, now for the successor, on the
//! same device key and the same store; the sealed direct message with Bob
//! keeps its channel on both sides -- Bob's client follows the contact and
//! the conversation from the log -- and a restarted client of Alice's
//! signs a fresh Move with the new key it kept.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
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
    chat.set_domain(Some("x.test".into()));
    chat.top_up_prekeys().await.unwrap();
    chat.ensure_home().await.unwrap();
    chat
}

fn said(timeline: &Timeline) -> Vec<String> {
    timeline
        .messages()
        .filter(|m| m.is_visible())
        .filter_map(|m| m.post.body_text().map(|t| t.to_string()))
        .collect()
}

async fn until(chat: &mut Chat, channel: &[u8; 32], t: &mut Timeline, want: &[&str]) -> bool {
    let mut last = String::new();
    for _ in 0..40 {
        match chat.poll(channel, t, 0).await {
            Ok(got) if said(&got.timeline) == want => return true,
            Ok(got) => last = format!("{:?}", said(&got.timeline)),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    eprintln!("wanted {want:?}, last saw {last}");
    false
}

#[tokio::test]
async fn a_client_hands_its_account_over_and_the_conversation_keeps_its_channel() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (_, alice) = identity(1);
    let (_, bob) = identity(2);
    let alice_store = dir.path().join("alice.db");
    let bob_store = dir.path().join("bob.db");

    let mut alice_at = chat_at(addr, server_pub, 1, &alice_store).await;
    let mut bob_at = chat_at(addr, server_pub, 2, &bob_store).await;
    bob_at.store().add_contact(&alice, "alice", 1).unwrap();
    let dm = alice_at.open_dm(&bob).await.unwrap();
    alice_at.send(&dm, "before").await.unwrap();
    let mut tb = Timeline::new();
    assert!(until(&mut bob_at, &dm, &mut tb, &["before"]).await);
    bob_at.send(&dm, "hi alice").await.unwrap();
    let mut ta = Timeline::new();
    assert!(until(&mut alice_at, &dm, &mut ta, &["before", "hi alice"]).await);

    // The handover, from inside the client. It acts for the successor now,
    // on the same device key, and knows its conversation with Bob.
    let new = alice_at.handover(None).await.unwrap();
    assert_ne!(new, alice);
    assert_eq!(alice_at.me, new);
    assert_eq!(alice_at.device(), alice);
    assert_eq!(
        alice_at.dm_with(&bob),
        dm,
        "Alice's client derived a second conversation"
    );
    alice_at.send(&dm, "after, as the new key").await.unwrap();

    // Bob's client reads the succeeded entry: the contact follows, and the
    // conversation with the new key is the same channel.
    assert!(
        until(
            &mut bob_at,
            &dm,
            &mut tb,
            &["before", "hi alice", "after, as the new key"]
        )
        .await
    );
    let contacts = bob_at.store().contacts().unwrap();
    assert!(
        contacts
            .iter()
            .any(|c| c.account == new && c.label == "alice")
    );
    assert!(!contacts.iter().any(|c| c.account == alice));
    assert_eq!(
        bob_at.dm_with(&new),
        dm,
        "Bob's client derived a second conversation"
    );
    bob_at.send(&dm, "still you").await.unwrap();
    assert!(
        until(
            &mut alice_at,
            &dm,
            &mut ta,
            &["before", "hi alice", "after, as the new key", "still you"]
        )
        .await
    );
    assert!(ta.forged().is_empty(), "{:?}", ta.forged());
    assert!(tb.forged().is_empty(), "{:?}", tb.forged());

    // A restart: the store says which account this device is, the new
    // key it kept signs a fresh Move (the exchange's record was re-keyed
    // with its signature cleared), and the conversation is where it was.
    // And a hole: one message row taken out of the store, as a copy that
    // refused an entry and later took it leaves one below the cursor. The
    // restarted client asks for the gap, once, and the conversation is
    // whole again.
    let hole_seq = ta
        .messages()
        .find(|m| m.post.body_text() == Some("hi alice"))
        .map(|m| m.seq)
        .unwrap();
    drop(alice_at);
    {
        let db = rusqlite::Connection::open(&alice_store).unwrap();
        let n = db
            .execute("DELETE FROM message WHERE seq = ?1", [hole_seq as i64])
            .unwrap();
        assert_eq!(n, 1, "the hole was not made");
        // A real hole was never seen at all; the replay guard (SIP-17) must
        // not know it, or the refetch is a replay by definition.
        db.execute(
            "DELETE FROM seen WHERE channel = ?1 AND device = ?2",
            rusqlite::params![&dm[..], bob.as_bytes()],
        )
        .unwrap();
    }
    let (seed, _) = identity(1);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(&alice_store)).unwrap();
    let mut again = Chat::new(client, seed, alice, PubKey::new(server_pub), store);
    again.set_domain(Some("x.test".into()));
    assert_eq!(again.me, new);
    assert!(
        again.ensure_home().await.unwrap(),
        "no fresh Move was signed after the handover"
    );
    assert_ne!(again.account_home(&new).await.unwrap().since, 0);
    assert_eq!(again.dm_with(&bob), dm);
    let mut t = again.history(&dm, &[new, bob]).unwrap();
    assert_eq!(said(&t).len(), 3, "the hole is there before the fetch");
    assert!(
        until(
            &mut again,
            &dm,
            &mut t,
            &["before", "hi alice", "after, as the new key", "still you"]
        )
        .await
    );
}
