//! SIP-68: mail follows the account home. What was queued for Alice at X
//! before she moved to H is collected by H -- as the account would
//! collect it, over the peering link, once -- and listed, fetched and
//! opened at H with the sender and time X observed; X's queue is empty
//! and tells the sender it was collected. A stranger and a configured
//! acts-for peer are refused the queue.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::home::{Move, Moving};
use sqex_proto::mailbox::{self, ById, Fetched, Listing, Send as MailSend, SendAck, State, Status};
use sqex_proto::peer::{Mail, PullMail};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;

/// An exchange peering openly, finding `found` without DNS, with `peers`
/// listed (as acts-for peers where `acts_for` names accounts).
async fn exchange_in(
    dir: &Path,
    listen: SocketAddr,
    domain: &str,
    peers: &str,
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        key_in(dir);
    }
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
         replication_peers = [{peers}]\nhome_secs = 1\n",
        listen.to_string(),
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let map = found
        .iter()
        .map(|(d, k, a)| ((*d).to_string(), (*k, *a)))
        .collect();
    let bound = sqexd::bind_with(config, None, signing_key, sqexd::relay::Find::Fixed(map))
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

fn key_in(dir: &Path) -> (PubKey, [u8; 32]) {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let seed = server_sk.to_bytes();
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    (PubKey::new(vk.to_bytes()), seed)
}

fn free_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn send(c: &mut Client, to: &PubKey, text: &[u8]) -> u64 {
    let sealed = mailbox::seal(to, text).unwrap();
    let (code, body) = c
        .post(
            "/mailbox/send",
            MailSend {
                recipient: *to,
                sealed,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    SendAck::decode(&body).unwrap().id
}

async fn listing(c: &mut Client) -> Listing {
    let (code, body) = c.post("/mailbox/list", Vec::new()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Listing::decode(&body).unwrap()
}

#[tokio::test]
async fn mail_queued_before_a_move_is_collected_by_the_new_home() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (h_key, _) = key_in(h_dir.path());
    let (x_at, h_at) = (free_port(), free_port());
    let (alice_seed, alice) = identity(41);
    let (bob_seed, bob) = identity(42);
    let (stranger_seed, stranger) = identity(43);
    // X lists the stranger as acting for Alice: an operator's word, which
    // confers no mailbox.
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        &format!("{{ key = \"{stranger}\", for = [\"{alice}\"] }}"),
        &[("h.test", h_key, h_at)],
    )
    .await;
    let (h_addr, h_pub) = exchange_in(
        h_dir.path(),
        h_at,
        "h.test",
        "",
        &[("x.test", x_key, x_addr)],
    )
    .await;
    assert_eq!((PubKey::new(x_pub), PubKey::new(h_pub)), (x_key, h_key));

    // Alice lives at X; Bob leaves her two messages there.
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let (code, _) = alice_at_x
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &x_key, now()),
                domain: "x.test".into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let mut bob_at_x = Client::connect_as(x_addr, &x_pub, &bob_seed).await.unwrap();
    let first = send(&mut bob_at_x, &alice, b"first, before the move").await;
    let second = send(&mut bob_at_x, &alice, b"second, before the move").await;
    let queued = listing(&mut alice_at_x).await;
    assert_eq!(queued.entries.len(), 2);
    let received_at_x = queued.entries[0].received;

    // A stranger X lists as acting for Alice, and a stranger it does not,
    // are both refused her queue: only her home collects it.
    for seed in [stranger_seed, identity(44).0] {
        let mut s = Client::connect_as(x_addr, &x_pub, &seed).await.unwrap();
        let (code, _) = s
            .post("/peer/mailbox", PullMail { account: alice }.encode())
            .await
            .unwrap();
        assert_eq!(
            code, 404,
            "somebody other than the home was given the queue"
        );
    }

    // Alice moves to H, naming X as an origin. H carries the Move, and
    // collects her mail.
    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = alice_at_h
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &h_key, now() + 1),
                domain: "h.test".into(),
                origins: vec![(x_key, "x.test".into())],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let mut at_h = Listing {
        entries: vec![],
        now: 0,
    };
    for _ in 0..80 {
        at_h = listing(&mut alice_at_h).await;
        if at_h.entries.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    assert_eq!(at_h.entries.len(), 2, "the mail did not follow Alice home");
    assert_eq!(at_h.entries[0].sender, bob, "the sender X observed");
    assert_eq!(
        at_h.entries[0].received, received_at_x,
        "the time X observed, not the time H stored"
    );
    // Fetched at H and opened by Alice, in order.
    let mut texts = Vec::new();
    for e in &at_h.entries {
        let (code, body) = alice_at_h
            .post("/mailbox/fetch", ById::fetch(e.id).encode())
            .await
            .unwrap();
        assert_eq!(code, 200);
        let fetched = Fetched::decode(&body).unwrap();
        assert!(fetched.found);
        texts.push(mailbox::open(&alice_seed, &fetched.sealed).unwrap());
    }
    assert_eq!(
        texts,
        vec![
            b"first, before the move".to_vec(),
            b"second, before the move".to_vec()
        ]
    );

    // X's queue is empty, and Bob is told his messages were collected.
    assert!(listing(&mut alice_at_x).await.entries.is_empty());
    for id in [first, second] {
        let (code, body) = bob_at_x
            .post("/mailbox/status", ById::status(id).encode())
            .await
            .unwrap();
        assert_eq!(code, 200);
        let st = Status::decode(&body).unwrap();
        assert_eq!(
            st.state,
            State::Collected,
            "the sender was not told of the collection"
        );
        assert_ne!(st.collected, 0);
    }
    // Another cycle stores nothing twice, and the home's own pull -- as
    // the home, by hand -- answers the rest: nothing.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert_eq!(listing(&mut alice_at_h).await.entries.len(), 2);
    let (_, h_seed) = {
        let bytes = std::fs::read_to_string(h_dir.path().join("host_key")).unwrap();
        let (sk, _) = squic::load_keypair(&bytes).unwrap();
        (h_key, sk.to_bytes())
    };
    let mut as_h = Client::connect_as(x_addr, &x_pub, &h_seed).await.unwrap();
    let (code, body) = as_h
        .post("/peer/mailbox", PullMail { account: alice }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(Mail::decode(&body).unwrap().items.is_empty());
    // And a message sent to Alice at X now is refused with `moved`, as
    // SIP-59 says: there is nothing left to collect.
    let sealed = mailbox::seal(&alice, b"late").unwrap();
    let (code, _) = bob_at_x
        .post(
            "/mailbox/send",
            MailSend {
                recipient: alice,
                sealed,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403);
}
