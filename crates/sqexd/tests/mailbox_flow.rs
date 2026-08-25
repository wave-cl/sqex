//! End-to-end for the SIP-5 store-and-forward mailbox over real HTTP/3.
//!
//! Two identities that have never been registered with the exchange, and are
//! never online at the same moment, exchange a message through it — and the
//! exchange cannot read what passed through.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::mailbox::{
    self, ById, Fetched, Listing, Send as MailSend, SendAck, State, Status, TYPE_DELETE,
    TYPE_FETCH, TYPE_STATUS,
};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn bare_server(
    dir: &std::path::Path,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
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

/// Connect as an identity — every mailbox operation is bound to who you are.
async fn as_identity(addr: SocketAddr, server_pub: &[u8; 32], seed: &[u8; 32]) -> Client {
    Client::connect_as(addr, server_pub, seed).await.unwrap()
}

#[tokio::test]
async fn two_identities_exchange_a_message_without_meeting() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    // Neither is an admin, neither is whitelisted, and they are never connected
    // at the same time — the sender's connection closes before the recipient's
    // is opened.
    let (alice_seed, alice) = identity(11);
    let (bob_seed, bob) = identity(12);
    let secret = b"the exchange must not be able to read this";

    // Alice leaves a message and goes away.
    let id = {
        let mut c = as_identity(addr, &server_pub, &alice_seed).await;
        let sealed = mailbox::seal(&bob, secret).unwrap();
        let (code, body) = c
            .post(
                "/mailbox/send",
                MailSend {
                    recipient: bob,
                    sealed,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "an unregistered identity may send (open set)");
        SendAck::decode(&body).unwrap().id
    };

    // Bob arrives later, lists, fetches, opens, and collects.
    let mut c = as_identity(addr, &server_pub, &bob_seed).await;

    let (code, body) = c.post("/mailbox/list", Vec::new()).await.unwrap();
    assert_eq!(code, 200);
    let listing = Listing::decode(&body).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].id, id);
    assert_eq!(
        listing.entries[0].sender, alice,
        "the exchange reports who it saw connect"
    );

    let (code, body) = c
        .post("/mailbox/fetch", ById::fetch(id).encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    let fetched = Fetched::decode(&body).unwrap();
    assert!(fetched.found);
    assert_eq!(
        mailbox::open(&bob_seed, &fetched.sealed).unwrap(),
        secret,
        "and only Bob can read it"
    );

    // Fetching alone does not collect — at-least-once.
    let listing = Listing::decode(&c.post("/mailbox/list", Vec::new()).await.unwrap().1).unwrap();
    assert_eq!(listing.entries.len(), 1, "still waiting until deleted");

    let (_, body) = c
        .post("/mailbox/delete", ById::delete(id).encode())
        .await
        .unwrap();
    assert_eq!(body, vec![1], "collected");
    let listing = Listing::decode(&c.post("/mailbox/list", Vec::new()).await.unwrap().1).unwrap();
    assert!(listing.entries.is_empty());

    handle.abort();
}

#[tokio::test]
async fn the_sender_learns_it_was_collected() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;
    let (alice_seed, _alice) = identity(21);
    let (bob_seed, bob) = identity(22);

    let mut a = as_identity(addr, &server_pub, &alice_seed).await;
    let sealed = mailbox::seal(&bob, b"did you get it?").unwrap();
    let (_, body) = a
        .post(
            "/mailbox/send",
            MailSend {
                recipient: bob,
                sealed,
            }
            .encode(),
        )
        .await
        .unwrap();
    let id = SendAck::decode(&body).unwrap().id;

    let status = |body: Vec<u8>| Status::decode(&body).unwrap();
    let (_, body) = a
        .post("/mailbox/status", ById::status(id).encode())
        .await
        .unwrap();
    assert_eq!(status(body).state, State::Waiting);

    // Bob collects.
    let mut b = as_identity(addr, &server_pub, &bob_seed).await;
    b.post("/mailbox/fetch", ById::fetch(id).encode())
        .await
        .unwrap();
    b.post("/mailbox/delete", ById::delete(id).encode())
        .await
        .unwrap();

    let (_, body) = a
        .post("/mailbox/status", ById::status(id).encode())
        .await
        .unwrap();
    let s = status(body);
    assert_eq!(s.state, State::Collected, "the sender can see it was taken");
    assert!(s.collected > 0);

    handle.abort();
}

#[tokio::test]
async fn a_mailbox_belongs_to_the_identity_that_can_connect_as_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;
    let (alice_seed, _alice) = identity(31);
    let (bob_seed, bob) = identity(32);
    let (eve_seed, _eve) = identity(33);

    let mut a = as_identity(addr, &server_pub, &alice_seed).await;
    let sealed = mailbox::seal(&bob, b"for bob").unwrap();
    let (_, body) = a
        .post(
            "/mailbox/send",
            MailSend {
                recipient: bob,
                sealed,
            }
            .encode(),
        )
        .await
        .unwrap();
    let id = SendAck::decode(&body).unwrap().id;

    // Eve knows the id but is not the recipient.
    let mut e = as_identity(addr, &server_pub, &eve_seed).await;
    let listing = Listing::decode(&e.post("/mailbox/list", Vec::new()).await.unwrap().1).unwrap();
    assert!(listing.entries.is_empty(), "Eve's mailbox is her own");

    let (_, body) = e
        .post("/mailbox/fetch", ById::fetch(id).encode())
        .await
        .unwrap();
    assert!(
        !Fetched::decode(&body).unwrap().found,
        "not addressed to Eve: reported exactly as absent"
    );

    let (_, body) = e
        .post("/mailbox/delete", ById::delete(id).encode())
        .await
        .unwrap();
    assert_eq!(body, vec![0], "Eve cannot destroy Bob's mail");

    // And Eve cannot use status to learn about someone else's message.
    let (_, body) = e
        .post("/mailbox/status", ById::status(id).encode())
        .await
        .unwrap();
    assert_eq!(Status::decode(&body).unwrap().state, State::Unknown);

    // Bob's message is untouched.
    let mut b = as_identity(addr, &server_pub, &bob_seed).await;
    let listing = Listing::decode(&b.post("/mailbox/list", Vec::new()).await.unwrap().1).unwrap();
    assert_eq!(listing.entries.len(), 1);

    handle.abort();
}

#[tokio::test]
async fn an_anonymous_connection_has_no_mailbox() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;
    let (_bob_seed, bob) = identity(41);

    // The default admin-style dial: no advertised identity.
    let mut c = Client::connect(addr, &server_pub).await.unwrap();

    let sealed = mailbox::seal(&bob, b"from nobody").unwrap();
    let (code, _) = c
        .post(
            "/mailbox/send",
            MailSend {
                recipient: bob,
                sealed,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403, "there is no identity to send as");

    let (code, _) = c.post("/mailbox/list", Vec::new()).await.unwrap();
    assert_eq!(code, 403, "and no mailbox to list");

    handle.abort();
}

#[tokio::test]
async fn a_malformed_or_oversized_send_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;
    let (alice_seed, _alice) = identity(51);
    let mut a = as_identity(addr, &server_pub, &alice_seed).await;

    let (code, _) = a.post("/mailbox/send", vec![0x01, 0x02]).await.unwrap();
    assert_eq!(code, 400, "too short to be a send");

    // A request of the wrong type on a by-id endpoint.
    let (code, _) = a
        .post("/mailbox/fetch", ById::delete(1).encode())
        .await
        .unwrap();
    assert_eq!(code, 400, "a delete is not a fetch");

    // Oversized ciphertext: the exchange bounds what it cannot read.
    let mut raw = vec![0x01u8];
    raw.extend_from_slice(&[9u8; 32]); // recipient
    raw.extend_from_slice(&[8u8; 32]); // ephemeral
    raw.extend(std::iter::repeat_n(0u8, mailbox::MAX_PLAINTEXT + 17));
    let (code, _) = a.post("/mailbox/send", raw).await.unwrap();
    assert_eq!(code, 400);

    let _ = (TYPE_FETCH, TYPE_DELETE, TYPE_STATUS);
    handle.abort();
}
