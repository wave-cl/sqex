//! End-to-end for SIP-12 relayed sessions over real HTTP/3.
//!
//! Two identities that neither can reach directly exchange data *through* the
//! exchange — and the exchange, which is carrying every byte, can read none of
//! it and cannot stand in the middle of the key agreement.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::session::{
    BySession, DatagramFrame, Frames, Open, OpenAck, OpenState, SendFrame, Session,
};
use sqex_proto::refusal::{Code, Refusal};
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
    assert_eq!(
        Refusal::decode(&body).unwrap().code,
        Code::NoSession,
        "a send with no session should say so"
    );

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

/// The unreliable path: frames ride QUIC datagrams instead of request-response,
/// which is what makes real-time media viable (SIP-12).
#[tokio::test]
async fn frames_ride_datagrams_with_the_same_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(71);
    let (b_seed, b_id) = identity(72);
    let (a_eph, a_eph_pub) = ephemeral();
    let (b_eph, b_eph_pub) = ephemeral();
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    // Datagrams have to be available on both ends, or there is no fast path.
    assert!(
        a.max_datagram_size().is_some(),
        "the path must carry datagrams"
    );

    open_session(&mut a, b_id, a_eph_pub).await;
    let b_ack = open_session(&mut b, a_id, b_eph_pub).await;
    let a_ack = open_session(&mut a, b_id, a_eph_pub).await;
    let id = a_ack.session_id;
    let a_sess = Session::derive(&a_seed, &a_eph, &b_id, &a_ack.peer_ephemeral).unwrap();
    let b_sess = Session::derive(&b_seed, &b_eph, &a_id, &b_ack.peer_ephemeral).unwrap();

    // The session was negotiated over HTTP/3; the media rides datagrams on the
    // very same connection, with the very same keys.
    let audio = b"\x01\x02 pretend this is a 20ms opus frame";
    let ct = a_sess.seal_datagram(0, audio).unwrap();
    a.send_datagram(
        DatagramFrame {
            session_id: id,
            seq: 0,
            ciphertext: ct,
        }
        .encode(),
    )
    .unwrap();

    let got = tokio::time::timeout(std::time::Duration::from_secs(5), b.read_datagram())
        .await
        .expect("a datagram should arrive")
        .unwrap();
    let frame = DatagramFrame::decode(&got).unwrap();
    assert_eq!(frame.session_id, id);
    assert_eq!(b_sess.open(frame.seq, &frame.ciphertext).unwrap(), audio);

    // And back the other way.
    let ct = b_sess.seal_datagram(0, b"reply").unwrap();
    b.send_datagram(
        DatagramFrame {
            session_id: id,
            seq: 0,
            ciphertext: ct,
        }
        .encode(),
    )
    .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), a.read_datagram())
        .await
        .expect("a datagram should come back")
        .unwrap();
    let frame = DatagramFrame::decode(&got).unwrap();
    assert_eq!(a_sess.open(frame.seq, &frame.ciphertext).unwrap(), b"reply");

    handle.abort();
}

/// A stream of frames arrives without the polling delay the reliable path has,
/// and losing one does not disturb the rest.
#[tokio::test]
async fn a_datagram_stream_flows_and_tolerates_gaps() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(81);
    let (b_seed, b_id) = identity(82);
    let (a_eph, a_eph_pub) = ephemeral();
    let (b_eph, b_eph_pub) = ephemeral();
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    open_session(&mut a, b_id, a_eph_pub).await;
    let b_ack = open_session(&mut b, a_id, b_eph_pub).await;
    let a_ack = open_session(&mut a, b_id, a_eph_pub).await;
    let id = a_ack.session_id;
    let a_sess = Session::derive(&a_seed, &a_eph, &b_id, &a_ack.peer_ephemeral).unwrap();
    let b_sess = Session::derive(&b_seed, &b_eph, &a_id, &b_ack.peer_ephemeral).unwrap();

    // Send a run of frames, deliberately skipping one sequence number as a lost
    // packet would.
    let sent: Vec<u64> = vec![0, 1, 3, 4];
    for seq in &sent {
        let ct = a_sess.seal_datagram(*seq, format!("frame {seq}").as_bytes()).unwrap();
        a.send_datagram(
            DatagramFrame {
                session_id: id,
                seq: *seq,
                ciphertext: ct,
            }
            .encode(),
        )
        .unwrap();
    }

    let mut seen = Vec::new();
    for _ in 0..sent.len() {
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), b.read_datagram())
            .await
            .expect("frames should arrive")
            .unwrap();
        let f = DatagramFrame::decode(&got).unwrap();
        // Each frame opens on its own: seq 2 never existing costs nothing.
        let plain = b_sess.open(f.seq, &f.ciphertext).unwrap();
        assert_eq!(plain, format!("frame {}", f.seq).as_bytes());
        seen.push(f.seq);
    }
    seen.sort_unstable();
    assert_eq!(seen, sent, "every sent frame arrived; the gap was never needed");

    handle.abort();
}

/// A datagram naming a session the sender is not party to is dropped, not
/// forwarded — the same rule the reliable path enforces, and the reason the
/// forwarder checks membership rather than trusting the header.
#[tokio::test]
async fn a_stranger_cannot_inject_datagrams() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(91);
    let (b_seed, b_id) = identity(92);
    let (eve_seed, _eve_id) = identity(93);
    let (_a_eph, a_eph_pub) = ephemeral();
    let (_b_eph, b_eph_pub) = ephemeral();

    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();
    let eve = Client::connect_as(addr, &server_pub, &eve_seed).await.unwrap();

    open_session(&mut a, b_id, a_eph_pub).await;
    let id = open_session(&mut b, a_id, b_eph_pub).await.session_id;

    eve.send_datagram(
        DatagramFrame {
            session_id: id,
            seq: 0,
            ciphertext: vec![0u8; 32],
        }
        .encode(),
    )
    .unwrap();

    // Nothing should reach B. Give the forwarder a generous window to be wrong.
    let nothing = tokio::time::timeout(std::time::Duration::from_millis(700), b.read_datagram()).await;
    assert!(nothing.is_err(), "an outsider's datagram must not be relayed");

    handle.abort();
}

/// A measurement rather than an assertion: how long a frame takes to reach the
/// peer on each path. Timing is machine- and load-dependent, so this is
/// `#[ignore]`d and never gates CI — run it with
/// `cargo test --test session_flow -- --ignored --nocapture` to see the numbers.
#[tokio::test]
#[ignore]
async fn measure_carriage_latency() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(101);
    let (b_seed, b_id) = identity(102);
    let (a_eph, a_eph_pub) = ephemeral();
    let (b_eph, b_eph_pub) = ephemeral();
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    open_session(&mut a, b_id, a_eph_pub).await;
    let b_ack = open_session(&mut b, a_id, b_eph_pub).await;
    let a_ack = open_session(&mut a, b_id, a_eph_pub).await;
    let id = a_ack.session_id;
    let a_sess = Session::derive(&a_seed, &a_eph, &b_id, &a_ack.peer_ephemeral).unwrap();
    let b_sess = Session::derive(&b_seed, &b_eph, &a_id, &b_ack.peer_ephemeral).unwrap();

    const N: u32 = 20;
    const POLL: u64 = 200; // what the reliable-path client uses

    // Datagram: send, then await arrival. No polling, no response to wait for.
    let mut dg_total = std::time::Duration::ZERO;
    for seq in 0..N as u64 {
        let ct = a_sess.seal_datagram(seq, b"20ms of audio").unwrap();
        let t0 = std::time::Instant::now();
        a.send_datagram(
            DatagramFrame { session_id: id, seq, ciphertext: ct }.encode(),
        )
        .unwrap();
        let got = b.read_datagram().await.unwrap();
        dg_total += t0.elapsed();
        let f = DatagramFrame::decode(&got).unwrap();
        assert_eq!(b_sess.open(f.seq, &f.ciphertext).unwrap(), b"20ms of audio");
    }

    // Reliable: POST the frame, then poll until it shows up. Model the client's
    // real behaviour — a poll lands on average half an interval after arrival.
    let mut rel_total = std::time::Duration::ZERO;
    for seq in 0..N as u64 {
        let ct = a_sess.seal(seq, b"20ms of audio").unwrap();
        let t0 = std::time::Instant::now();
        a.post("/session/send", SendFrame { session_id: id, seq, ciphertext: ct }.encode())
            .await
            .unwrap();
        loop {
            let f = recv(&mut b, id).await;
            if !f.frames.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        rel_total += t0.elapsed();
    }

    let dg = dg_total / N;
    let rel = rel_total / N;
    println!("\n─── carriage latency over loopback, {N} frames ───");
    println!("  datagram (push)          : {dg:?} per frame");
    println!("  reliable (POST + drain)  : {rel:?} per frame");
    println!("  reliable + {POLL}ms polling : ~{:?} per frame (as the CLI polls)", rel + std::time::Duration::from_millis(POLL / 2));
    println!("\n  A voice budget is ~150ms mouth-to-ear. Loopback removes the");
    println!("  network, so these show protocol overhead only: the datagram path");
    println!("  adds ~nothing, while polling alone spends most of the budget.\n");

    handle.abort();
}

/// Two people who called each other before, and are calling again.
///
/// A session outlives a call by an hour, so the second call finds the first
/// one still there. Answering that idempotently — which is what a *retry*
/// deserves — would hand each side the ephemeral from last time, and their new
/// secrets cannot pair with it: both would derive a key the other does not
/// have, and the call would come up looking perfectly healthy and be completely
/// deaf. A fresh ephemeral therefore replaces the session rather than resuming
/// it.
#[tokio::test]
async fn calling_someone_again_does_not_resume_the_last_call_with_new_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(141);
    let (b_seed, b_id) = identity(142);
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    // The first call. Nobody closes it — they crashed, or the lid shut.
    let (a_eph1, a_pub1) = ephemeral();
    let (b_eph1, b_pub1) = ephemeral();
    open_session(&mut a, b_id, a_pub1).await;
    let b_ack1 = open_session(&mut b, a_id, b_pub1).await;
    let a_ack1 = open_session(&mut a, b_id, a_pub1).await;
    assert_eq!(a_ack1.state, OpenState::Established);
    let old = a_ack1.session_id;
    // Sanity: those keys did agree with each other.
    let a1 = Session::derive(&a_seed, &a_eph1, &b_id, &a_ack1.peer_ephemeral).unwrap();
    let b1 = Session::derive(&b_seed, &b_eph1, &a_id, &b_ack1.peer_ephemeral).unwrap();
    assert!(b1.open(0, &a1.seal(0, b"first call").unwrap()).is_ok());

    // The second call: both sides restarted, so both offer fresh ephemerals.
    let (a_eph2, a_pub2) = ephemeral();
    let (b_eph2, b_pub2) = ephemeral();
    open_session(&mut a, b_id, a_pub2).await;
    let b_ack2 = open_session(&mut b, a_id, b_pub2).await;
    let a_ack2 = open_session(&mut a, b_id, a_pub2).await;

    assert_eq!(a_ack2.state, OpenState::Established);
    assert_ne!(a_ack2.session_id, old, "the stale session was not reused");
    assert_eq!(
        a_ack2.peer_ephemeral, b_pub2,
        "and the ephemeral is this call's, not last call's"
    );

    // The point of all of it: they can hear each other.
    let a2 = Session::derive(&a_seed, &a_eph2, &b_id, &a_ack2.peer_ephemeral).unwrap();
    let b2 = Session::derive(&b_seed, &b_eph2, &a_id, &b_ack2.peer_ephemeral).unwrap();
    let sealed = a2.seal(0, b"second call").unwrap();
    assert_eq!(
        b2.open(0, &sealed).unwrap(),
        b"second call",
        "the second call must not be silently deaf"
    );
}

/// The idempotency SIP-12 does require: the *same* ephemeral, offered again,
/// resumes rather than restarting. This is what a retry or a lost ack looks
/// like, and it must not tear a live call down.
#[tokio::test]
async fn re_offering_the_same_ephemeral_still_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(151);
    let (b_seed, b_id) = identity(152);
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    let (_a_eph, a_pub) = ephemeral();
    let (_b_eph, b_pub) = ephemeral();
    open_session(&mut a, b_id, a_pub).await;
    let _ = open_session(&mut b, a_id, b_pub).await;
    let first = open_session(&mut a, b_id, a_pub).await;
    assert_eq!(first.state, OpenState::Established);

    for _ in 0..3 {
        let again = open_session(&mut a, b_id, a_pub).await;
        assert_eq!(again.session_id, first.session_id, "same session");
        assert_eq!(again.peer_ephemeral, first.peer_ephemeral);
        assert_eq!(again.state, OpenState::Established);
    }
}
