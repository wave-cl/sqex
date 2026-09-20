//! SIP-62 at the client. Alice hands her account over to a new key from
//! inside the client: it goes on acting, now for the successor, on the
//! same device key and the same store; the sealed direct message with Bob
//! keeps its channel on both sides -- Bob's client follows the contact and
//! the conversation from the log -- and a restarted client of Alice's
//! signs a fresh Move with the new key it kept.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::{Chat, HomeSaid};
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
    assert_eq!(
        again.ensure_home().await.unwrap(),
        HomeSaid::Presented,
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

/// SIP-62 §Which account a device is. Alice's phone (a linked device) holds a stale store after she
/// hands over from the laptop: on its next start it asks whose device it
/// is, follows the successor -- account, credential, the direct message
/// with Bob -- and reads and posts as the new account. It holds no key
/// until the laptop entrusts one over a sibling session; then it can sign
/// a Move. A key for another account ends the session; a sync that was
/// not asked to give the key gives none.
#[tokio::test]
async fn a_linked_device_follows_the_handover_and_is_entrusted_the_key() {
    use sqex_chat::sync::{Phase, Sync};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (_, alice) = identity(11);
    let (_, bob) = identity(12);
    let (phone_seed, phone_key) = identity(13);
    let laptop_store = dir.path().join("laptop.db");
    let bob_store = dir.path().join("bob.db");
    let phone_store = dir.path().join("phone.db");

    let mut laptop = chat_at(addr, server_pub, 11, &laptop_store).await;
    let mut bob_at = chat_at(addr, server_pub, 12, &bob_store).await;
    // The phone, linked by a credential the laptop signs; the laptop
    // registers itself first so it is not sealed out of its own account.
    let own = laptop.issue_credential(&alice, 90 * 24 * 60 * 60).unwrap();
    laptop.register_self(&own).await.unwrap();
    let mut phone = chat_at(addr, server_pub, 13, &phone_store).await;
    let credential = laptop
        .issue_credential(&phone_key, 90 * 24 * 60 * 60)
        .unwrap();
    phone.register_self(&credential).await.unwrap();
    drop(phone);
    let phone_client = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    let phone_st = Store::open(&phone_seed, Some(&phone_store)).unwrap();
    let mut phone = Chat::new(
        phone_client,
        phone_seed,
        phone_key,
        PubKey::new(server_pub),
        phone_st,
    );
    phone.set_domain(Some("x.test".into()));
    assert_eq!(phone.me, alice, "the phone is Alice's device");
    assert!(!phone.holds_account_key());

    bob_at.store().add_contact(&alice, "alice", 1).unwrap();
    let dm = laptop.open_dm(&bob).await.unwrap();
    laptop.send(&dm, "from the laptop").await.unwrap();
    let mut tb = Timeline::new();
    assert!(until(&mut bob_at, &dm, &mut tb, &["from the laptop"]).await);
    // The phone reads the conversation too, under the old derivation.
    assert_eq!(phone.dm_with(&bob), dm);
    let mut tp = Timeline::new();
    assert!(until(&mut phone, &dm, &mut tp, &["from the laptop"]).await);

    // The laptop hands over. The phone, restarted with its stale store,
    // asks whose device it is and follows.
    let new = laptop.handover(None).await.unwrap();
    assert_ne!(new, alice);
    drop(phone);
    let phone_client = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    let phone_st = Store::open(&phone_seed, Some(&phone_store)).unwrap();
    let mut phone = Chat::new(
        phone_client,
        phone_seed,
        phone_key,
        PubKey::new(server_pub),
        phone_st,
    );
    phone.set_domain(Some("x.test".into()));
    assert_eq!(phone.me, alice, "the store still names the old account");
    assert_eq!(phone.follow_account().await.unwrap(), Some(new));
    assert_eq!(phone.me, new);
    assert_eq!(
        phone.credential().map(|c| c.account),
        Some(new),
        "the credential did not follow"
    );
    assert_eq!(
        phone.dm_with(&bob),
        dm,
        "the phone derived a second conversation"
    );
    assert_eq!(
        phone.follow_account().await.unwrap(),
        None,
        "followed twice"
    );
    // It reads on, and posts as the new account's device.
    let mut tp = phone.history(&dm, &[new, bob]).unwrap();
    phone
        .send(&dm, "from the phone, as the new key")
        .await
        .unwrap();
    assert!(
        until(
            &mut bob_at,
            &dm,
            &mut tb,
            &["from the laptop", "from the phone, as the new key"]
        )
        .await
    );
    assert!(
        until(
            &mut phone,
            &dm,
            &mut tp,
            &["from the laptop", "from the phone, as the new key"]
        )
        .await
    );
    // Without the key it signs no Move.
    assert!(!phone.holds_account_key());
    assert_eq!(phone.ensure_home().await.unwrap(), HomeSaid::NotMine);

    // A plain sync gives no key.
    let ((mut ll, sl), (mut lp, sp)) = meet(&laptop, &phone).await;
    let mut xl = Sync::new(sl, phone.device());
    let mut xp = Sync::new(sp, laptop.device());
    run(&mut laptop, &mut phone, &mut xl, &mut ll, &mut xp, &mut lp).await;
    assert_eq!(xp.phase(), Phase::Finished, "{:?}", xp.why);
    assert!(!xp.entrusted);
    assert!(
        !phone.holds_account_key(),
        "a sync that was not asked gave the key"
    );

    // SIP-70: mail sent to the account is listed on the phone beside its
    // own; without the key the phone can read what was sealed to it and
    // only list what was sealed to the account -- and must not delete that.
    {
        let (carol_seed, _) = identity(14);
        let carol = Client::connect_as(addr, &server_pub, &carol_seed)
            .await
            .unwrap();
        let mut carol = carol;
        let send = |to: PubKey, text: &[u8]| {
            sqex_proto::mailbox::Send {
                recipient: to,
                sealed: sqex_proto::mailbox::seal(&to, text).unwrap(),
            }
            .encode()
        };
        let (code, body) = carol
            .post("/mailbox/send", send(new, b"for the account"))
            .await
            .unwrap();
        assert_eq!(code, 200);
        let to_account = sqex_proto::mailbox::SendAck::decode(&body).unwrap().id;
        let (code, body) = carol
            .post("/mailbox/send", send(phone_key, b"for the phone"))
            .await
            .unwrap();
        assert_eq!(code, 200);
        let to_phone = sqex_proto::mailbox::SendAck::decode(&body).unwrap().id;
        let listed = phone.mail_list().await.unwrap();
        assert_eq!(
            listed.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![to_account, to_phone]
        );
        assert_eq!(
            phone.mail_read(to_phone).await.unwrap().map(|(_, t)| t),
            Some(b"for the phone".to_vec())
        );
        assert!(matches!(
            phone.mail_read(to_account).await,
            Err(sqex_chat::ChatError::MailSealedElsewhere(_))
        ));
        assert!(
            matches!(
                phone.mail_delete(to_account).await,
                Err(sqex_chat::ChatError::MailSealedElsewhere(_))
            ),
            "the phone deleted what it could not read"
        );
        // The laptop, which holds the key, reads it.
        assert_eq!(
            laptop.mail_read(to_account).await.unwrap().map(|(_, t)| t),
            Some(b"for the account".to_vec())
        );
        assert!(laptop.mail_delete(to_account).await.unwrap());
        assert!(phone.mail_delete(to_phone).await.unwrap());
    }

    // The laptop entrusts the key; the phone holds it and signs a Move.
    let seed = laptop.account_seed().unwrap();
    let ((mut ll, sl), (mut lp, sp)) = meet(&laptop, &phone).await;
    let mut xl = Sync::new(sl, phone.device()).entrusting(seed);
    let mut xp = Sync::new(sp, laptop.device());
    run(&mut laptop, &mut phone, &mut xl, &mut ll, &mut xp, &mut lp).await;
    assert_eq!(xp.phase(), Phase::Finished, "{:?}", xp.why);
    assert!(xp.entrusted);
    assert!(phone.holds_account_key());
    assert_eq!(phone.account_seed(), Some(seed));
    assert_eq!(
        phone.ensure_home().await.unwrap(),
        HomeSaid::Presented,
        "the entrusted phone signed no Move"
    );
    // SIP-70: and, entrusted, it opens what is sealed to the account.
    {
        let (carol_seed, _) = identity(14);
        let mut carol = Client::connect_as(addr, &server_pub, &carol_seed)
            .await
            .unwrap();
        let (code, body) = carol
            .post(
                "/mailbox/send",
                sqex_proto::mailbox::Send {
                    recipient: new,
                    sealed: sqex_proto::mailbox::seal(&new, b"for the account, again").unwrap(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200);
        let id = sqex_proto::mailbox::SendAck::decode(&body).unwrap().id;
        assert_eq!(
            phone.mail_read(id).await.unwrap().map(|(_, t)| t),
            Some(b"for the account, again".to_vec()),
            "the entrusted phone could not open the account's mail"
        );
        assert!(phone.mail_delete(id).await.unwrap());
    }
    assert!(xl.gave_key);

    // The phone, holding the key, hands over; the laptop's stored seed is
    // the retired account's now, and it must not sign with it -- the
    // laptop follows on its next look and holds no key until entrusted.
    let newer = phone.handover(None).await.unwrap();
    assert_eq!(laptop.follow_account().await.unwrap(), Some(newer));
    assert_eq!(laptop.me, newer);
    assert!(
        !laptop.holds_account_key(),
        "a retired account's seed still counted"
    );
    assert_ne!(laptop.ensure_home().await.unwrap(), HomeSaid::Presented);
    assert!(phone.holds_account_key());

    // A key for another account ends the session on the phone's side.
    let (carol_seed, _) = identity(14);
    let ((mut ll, sl), (mut lp, sp)) = meet(&laptop, &phone).await;
    let mut xl = Sync::new(sl, phone.device()).entrusting(carol_seed);
    let mut xp = Sync::new(sp, laptop.device());
    run(&mut laptop, &mut phone, &mut xl, &mut ll, &mut xp, &mut lp).await;
    assert_eq!(xp.phase(), Phase::Failed);
    assert!(
        xp.why.as_deref().unwrap_or("").contains("not this account"),
        "{:?}",
        xp.why
    );
    assert_ne!(
        phone.account_seed(),
        Some(carol_seed),
        "a stranger's key was kept"
    );
    assert!(phone.holds_account_key());
}

async fn meet(
    a: &Chat,
    b: &Chat,
) -> (
    (sqex_chat::sync::Relayed, sqex_proto::session::Session),
    (sqex_chat::sync::Relayed, sqex_proto::session::Session),
) {
    let ea = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let eb = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    for _ in 0..100 {
        let ra = a.meet_sibling(&ea, &b.device()).await.unwrap();
        let rb = b.meet_sibling(&eb, &a.device()).await.unwrap();
        if let (Some(x), Some(y)) = (ra, rb) {
            return (x, y);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the two devices never met");
}

async fn run(
    a: &mut Chat,
    b: &mut Chat,
    xa: &mut sqex_chat::sync::Sync,
    la: &mut sqex_chat::sync::Relayed,
    xb: &mut sqex_chat::sync::Sync,
    lb: &mut sqex_chat::sync::Relayed,
) {
    use sqex_chat::sync::Phase;
    let over = |p: Phase| matches!(p, Phase::Finished | Phase::Failed);
    for _ in 0..2000 {
        if !over(xa.phase()) && !xa.step(a, la).await.unwrap_or(false) {
            la.close().await;
        }
        if !over(xb.phase()) && !xb.step(b, lb).await.unwrap_or(false) {
            lb.close().await;
        }
        if over(xa.phase()) && over(xb.phase()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!(
        "the sync did not finish: {:?} / {:?}",
        xa.phase(),
        xb.phase()
    );
}
