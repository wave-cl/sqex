//! End-to-end for SIP-39 cross-exchange calls, over two real exchanges.
//!
//! Alice is connected only to exchange X, Bob only to exchange Y. Alice calls
//! Bob; the two exchanges relay the call between themselves over an
//! authenticated, allowlisted link — and neither exchange can read a byte of
//! it, exactly as a single SIP-12 relay cannot, because the key agreement still
//! needs a static private key from each of the two parties.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::relay;
use sqex_proto::session::{CallAck, CallOpen, CallState, DatagramFrame, Open, OpenAck, Session};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

/// Bring up an exchange whose config names the given relay peers (a TOML
/// fragment of `[[relay_peers]]` tables). Returns its address and public key.
async fn relay_server(
    dir: &std::path::Path,
    host_key: &SigningKey,
    relay_peers: &str,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    std::fs::write(&key_path, hex::encode(host_key.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n{relay_peers}",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, None, signing_key).await.unwrap();
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

async fn call(client: &mut Client, target: &str, eph: [u8; 32]) -> CallAck {
    let (code, body) = client
        .post(
            "/session/call",
            CallOpen {
                ephemeral: eph,
                target: target.to_string(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    CallAck::decode(&body).unwrap()
}

async fn open(client: &mut Client, peer: PubKey, eph: [u8; 32]) -> OpenAck {
    let (code, body) = client
        .post(
            "/session/open",
            Open {
                peer,
                ephemeral: eph,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    OpenAck::decode(&body).unwrap()
}

/// The whole point: two people on two exchanges hold a call, the media crosses
/// both exchanges, and each end decrypts what the other sealed.
#[tokio::test]
async fn a_call_bridges_two_exchanges_and_neither_can_read_it() {
    let dir_x = tempfile::tempdir().unwrap();
    let dir_y = tempfile::tempdir().unwrap();
    let (x_key, x_pub) = {
        let (sk, pk) = identity(90);
        (SigningKey::from_bytes(&sk), pk)
    };
    let (y_key, y_pub) = {
        let (sk, pk) = identity(91);
        (SigningKey::from_bytes(&sk), pk)
    };

    // Y must be up first so X can be told its address; X dials Y. Each names the
    // other's key on its allowlist — Y to accept X's link, X to dial Y's.
    let y_peers = format!(
        "[[relay_peers]]\ndomain = \"x.test\"\nkey = \"{}\"\naddr = \"127.0.0.1:1\"\n",
        x_pub,
    );
    let (y_addr, y_server_pub, y_h) = relay_server(dir_y.path(), &y_key, &y_peers).await;

    let x_peers = format!(
        "[[relay_peers]]\ndomain = \"y.test\"\nkey = \"{}\"\naddr = \"{}\"\n",
        y_pub, y_addr,
    );
    let (x_addr, x_server_pub, x_h) = relay_server(dir_x.path(), &x_key, &x_peers).await;

    let (a_seed, a_id) = identity(1);
    let (b_seed, b_id) = identity(2);
    let (a_eph, a_eph_pub) = ephemeral();
    let (b_eph, b_eph_pub) = ephemeral();

    // Alice is on X only, Bob on Y only.
    let mut alice = Client::connect_as(x_addr, &x_server_pub, &a_seed)
        .await
        .unwrap();
    let mut bob = Client::connect_as(y_addr, &y_server_pub, &b_seed)
        .await
        .unwrap();

    // Alice calls Bob by key@domain (no name lookup needed for the test).
    let target = format!("{}@y.test", b_id);
    let first = call(&mut alice, &target, a_eph_pub).await;
    assert_eq!(first.state, CallState::Ringing, "the first poll is ringing");

    // Bob, rung, answers by opening toward Alice. His exchange bridges it.
    let b_ack = open(&mut bob, a_id, b_eph_pub).await;
    assert_eq!(
        b_ack.peer_ephemeral, a_eph_pub,
        "Bob learns Alice's ephemeral"
    );

    // Alice re-polls until her exchange has heard the accept.
    let mut a_ack = call(&mut alice, &target, a_eph_pub).await;
    for _ in 0..50 {
        if a_ack.state == CallState::Established {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        a_ack = call(&mut alice, &target, a_eph_pub).await;
    }
    assert_eq!(a_ack.state, CallState::Established, "the call connects");
    assert_eq!(a_ack.peer, b_id, "Alice learns which device answered");
    assert_eq!(a_ack.peer_ephemeral, b_eph_pub, "and its ephemeral");

    // Both derive the same session key — over the two identities and the two
    // ephemerals, which is all the far exchange never had.
    let a_sess = Session::derive(&a_seed, &a_eph, &b_id, &a_ack.peer_ephemeral).unwrap();
    let b_sess = Session::derive(&b_seed, &b_eph, &a_id, &b_ack.peer_ephemeral).unwrap();

    // Alice -> Bob, across X and Y, sealed end to end.
    let audio = b"\x01\x02 a 20ms opus frame, bridged";
    let ct = a_sess.seal_datagram(0, audio).unwrap();
    alice
        .send_datagram(
            DatagramFrame {
                session_id: a_ack.session_id,
                seq: 0,
                ciphertext: ct,
            }
            .encode(),
        )
        .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), bob.read_datagram())
        .await
        .expect("a datagram should cross both exchanges")
        .unwrap();
    let frame = DatagramFrame::decode(&got).unwrap();
    assert_eq!(
        b_sess.open(frame.seq, &frame.ciphertext).unwrap(),
        audio,
        "Bob decrypts what Alice sealed, though two exchanges relayed it"
    );

    // Bob -> Alice, the other way.
    let ct = b_sess.seal_datagram(0, b"reply, also bridged").unwrap();
    bob.send_datagram(
        DatagramFrame {
            session_id: b_ack.session_id,
            seq: 0,
            ciphertext: ct,
        }
        .encode(),
    )
    .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), alice.read_datagram())
        .await
        .expect("the reply should cross back")
        .unwrap();
    let frame = DatagramFrame::decode(&got).unwrap();
    assert_eq!(
        a_sess.open(frame.seq, &frame.ciphertext).unwrap(),
        b"reply, also bridged"
    );

    // Alice hangs up; the bridge tears down.
    let (code, _) = alice
        .post(
            "/session/close",
            sqex_proto::session::BySession::close(a_ack.session_id).encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    x_h.abort();
    y_h.abort();
}

/// The allowlist is the federation boundary: a call to a domain this exchange
/// has no relay peer for is refused, and refused the same coarse way as
/// everything else — no oracle for who it will and will not bridge to.
#[tokio::test]
async fn a_call_to_an_unfederated_domain_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (x_key, _) = {
        let (sk, pk) = identity(93);
        (SigningKey::from_bytes(&sk), pk)
    };
    // No relay peers at all: this exchange federates with nobody.
    let (addr, server_pub, h) = relay_server(dir.path(), &x_key, "").await;

    let (a_seed, _) = identity(3);
    let (_, target_id) = identity(4);
    let (_, eph) = ephemeral();
    let mut alice = Client::connect_as(addr, &server_pub, &a_seed)
        .await
        .unwrap();

    let target = format!("{}@nowhere.test", target_id);
    let ack = call(&mut alice, &target, eph).await;
    assert_eq!(
        ack.state,
        CallState::Rejected,
        "an unfederated call is refused"
    );
    assert_eq!(ack.reason, relay::REASON_REFUSED);

    h.abort();
}
