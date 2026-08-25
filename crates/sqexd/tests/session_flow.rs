//! End-to-end for SIP-12 relayed sessions over real HTTP/3.
//!
//! Two identities that neither can reach directly exchange data *through* the
//! exchange — and the exchange, which is carrying every byte, can read none of
//! it and cannot stand in the middle of the key agreement.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::session::{
    BySession, Frames, Open, OpenAck, OpenState, SendFrame, Session,
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

fn ephemeral() -> (x25519_dalek::StaticSecret, [u8; 32]) {
    let s = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let p = x25519_dalek::PublicKey::from(&s).to_bytes();
    (s, p)
}

async fn open_session(client: &mut Client, peer: PubKey, eph_pub: [u8; 32]) -> OpenAck {
    let (code, body) = client
        .post(
            "/session/open",
            Open {
                peer,
                ephemeral: eph_pub,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    OpenAck::decode(&body).unwrap()
}

async fn recv(client: &mut Client, id: u64) -> Frames {
    let (code, body) = client
        .post("/session/recv", BySession::recv(id).encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    Frames::decode(&body).unwrap()
}

#[tokio::test]
async fn two_peers_exchange_data_through_the_exchange() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    // Neither is registered with the exchange, and neither is reachable by the
    // other — both only ever make outbound connections.
    let (a_seed, a_id) = identity(11);
    let (b_seed, b_id) = identity(12);
    let (a_eph, a_eph_pub) = ephemeral();
    let (b_eph, b_eph_pub) = ephemeral();

    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    // A asks first and learns nothing: consent is mutual.
    let ack = open_session(&mut a, b_id, a_eph_pub).await;
    assert_eq!(ack.state, OpenState::Waiting);
    assert_eq!(ack.peer_ephemeral, [0u8; 32]);

    // B asks, and the session comes into being for both.
    let b_ack = open_session(&mut b, a_id, b_eph_pub).await;
    assert_eq!(b_ack.state, OpenState::Established);
    let a_ack = open_session(&mut a, b_id, a_eph_pub).await;
    assert_eq!(a_ack.state, OpenState::Established);
    assert_eq!(a_ack.session_id, b_ack.session_id);

    let id = a_ack.session_id;
    let a_sess = Session::derive(&a_seed, &a_eph, &b_id, &a_ack.peer_ephemeral).unwrap();
    let b_sess = Session::derive(&b_seed, &b_eph, &a_id, &b_ack.peer_ephemeral).unwrap();

    // A speaks; B hears.
    let ct = a_sess.seal(0, b"the exchange carries this but cannot read it").unwrap();
    let (code, _) = a
        .post(
            "/session/send",
            SendFrame {
                session_id: id,
                seq: 0,
                ciphertext: ct,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let got = recv(&mut b, id).await;
    assert!(got.open);
    assert_eq!(got.frames.len(), 1);
    assert_eq!(
        b_sess.open(got.frames[0].0, &got.frames[0].1).unwrap(),
        b"the exchange carries this but cannot read it"
    );

    // And back the other way.
    let ct = b_sess.seal(0, b"heard you").unwrap();
    b.post(
        "/session/send",
        SendFrame {
            session_id: id,
            seq: 0,
            ciphertext: ct,
        }
        .encode(),
    )
    .await
    .unwrap();
    let got = recv(&mut a, id).await;
    assert_eq!(a_sess.open(got.frames[0].0, &got.frames[0].1).unwrap(), b"heard you");

    handle.abort();
}

#[tokio::test]
async fn the_exchange_cannot_read_what_it_carries() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(21);
    let (b_seed, b_id) = identity(22);
    let (a_eph, a_eph_pub) = ephemeral();
    let (b_eph, b_eph_pub) = ephemeral();
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    open_session(&mut a, b_id, a_eph_pub).await;
    let b_ack = open_session(&mut b, a_id, b_eph_pub).await;
    let a_ack = open_session(&mut a, b_id, a_eph_pub).await;
    let id = a_ack.session_id;

    let a_sess = Session::derive(&a_seed, &a_eph, &b_id, &a_ack.peer_ephemeral).unwrap();
    let secret = b"plaintext that must never appear on the wire";
    let ct = a_sess.seal(0, secret).unwrap();
    assert!(
        !ct.windows(secret.len()).any(|w| w == secret),
        "the frame the exchange relays is ciphertext"
    );

    a.post(
        "/session/send",
        SendFrame {
            session_id: id,
            seq: 0,
            ciphertext: ct,
        }
        .encode(),
    )
    .await
    .unwrap();

    // What the exchange holds and hands over is opaque to anyone without a
    // static private key — including a third identity that saw both ephemerals.
    let (evil_seed, _evil_id) = identity(23);
    let (evil_eph, _evil_pub) = ephemeral();
    let forged = Session::derive(&evil_seed, &evil_eph, &a_id, &a_ack.peer_ephemeral).unwrap();
    let got = recv(&mut b, id).await;
    assert!(
        forged.open(got.frames[0].0, &got.frames[0].1).is_err(),
        "an impostor in the middle cannot open the frame"
    );
    let b_sess = Session::derive(&b_seed, &b_eph, &a_id, &b_ack.peer_ephemeral).unwrap();
    assert_eq!(b_sess.open(got.frames[0].0, &got.frames[0].1).unwrap(), secret);

    handle.abort();
}

#[tokio::test]
async fn an_identity_cannot_be_probed_for_by_asking() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (a_seed, _a_id) = identity(31);
    let (_b_seed, b_id) = identity(32);
    let (_eph, eph_pub) = ephemeral();
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();

    // B has never connected at all. Asking repeatedly must reveal nothing.
    for _ in 0..3 {
        let ack = open_session(&mut a, b_id, eph_pub).await;
        assert_eq!(ack.state, OpenState::Waiting);
        assert_eq!(ack.session_id, 0);
        assert_eq!(ack.peer_ephemeral, [0u8; 32]);
    }

    handle.abort();
}

#[tokio::test]
async fn a_third_identity_cannot_join_or_read_a_session() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(41);
    let (b_seed, b_id) = identity(42);
    let (eve_seed, _eve_id) = identity(43);
    let (_a_eph, a_eph_pub) = ephemeral();
    let (_b_eph, b_eph_pub) = ephemeral();

    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();
    let mut eve = Client::connect_as(addr, &server_pub, &eve_seed).await.unwrap();

    open_session(&mut a, b_id, a_eph_pub).await;
    let id = open_session(&mut b, a_id, b_eph_pub).await.session_id;

    // Eve knows the session id but is not a member.
    let (code, body) = eve
        .post(
            "/session/send",
            SendFrame {
                session_id: id,
                seq: 0,
                ciphertext: vec![1, 2, 3],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 409, "Eve cannot inject frames");
    assert!(String::from_utf8_lossy(&body).contains("no_session"));

    let got = recv(&mut eve, id).await;
    assert!(!got.open, "reported exactly as no session");
    assert!(got.frames.is_empty());

    let (_, body) = eve
        .post("/session/close", BySession::close(id).encode())
        .await
        .unwrap();
    assert_eq!(body, vec![0], "and cannot end someone else's session");

    handle.abort();
}

#[tokio::test]
async fn either_peer_may_close_and_the_other_learns() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(51);
    let (b_seed, b_id) = identity(52);
    let (_a_eph, a_eph_pub) = ephemeral();
    let (_b_eph, b_eph_pub) = ephemeral();
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    open_session(&mut a, b_id, a_eph_pub).await;
    let id = open_session(&mut b, a_id, b_eph_pub).await.session_id;

    let (_, body) = b
        .post("/session/close", BySession::close(id).encode())
        .await
        .unwrap();
    assert_eq!(body, vec![1]);

    assert!(!recv(&mut a, id).await.open, "A sees the session has ended");

    handle.abort();
}

#[tokio::test]
async fn an_anonymous_connection_has_no_session() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;
    let (_b_seed, b_id) = identity(61);
    let (_eph, eph_pub) = ephemeral();

    let mut c = Client::connect(addr, &server_pub).await.unwrap();
    let (code, _) = c
        .post(
            "/session/open",
            Open {
                peer: b_id,
                ephemeral: eph_pub,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403, "there is no identity to be a party to a session");

    handle.abort();
}
