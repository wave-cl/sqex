//! End-to-end for SIP-39 cross-exchange calls, over two real exchanges.
//!
//! Alice is connected only to exchange X, Bob only to exchange Y. Alice calls
//! Bob; the two exchanges relay the call between themselves over an
//! authenticated, allowlisted link — and neither exchange can read a byte of
//! it, exactly as a single SIP-12 relay cannot, because the key agreement still
//! needs a static private key from each of the two parties.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::events::{Event as WireEvent, Framer, Subscribe};
use sqex_proto::relay;
use sqex_proto::session::{
    CallAck, CallDecline, CallOpen, CallState, DatagramFrame, Open, OpenAck, Session,
};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

/// Bring up an exchange that federates with `peers` (base58 keys) and finds
/// them through `found` rather than DNS.
///
/// There is no DNS here: two exchanges on loopback with invented domains cannot
/// discover each other, which is exactly why `bind_with` takes a finder.
async fn relay_server(
    dir: &std::path::Path,
    host_key: &SigningKey,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    std::fs::write(&key_path, hex::encode(host_key.to_bytes())).unwrap();
    let listed = peers
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         relay_peers = [{listed}]\n",
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

/// Open a SIP-30 event stream, which is what makes an account *reachable* for a
/// cross-exchange ring: the ring is an event, so an account with no open stream
/// cannot hear one and its exchange says so rather than ringing into the void.
async fn subscribe(client: &Client) -> sqnr::Stream {
    let stream = client
        .stream(
            "POST",
            "/events",
            Subscribe {
                version: sqex_proto::events::VERSION,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(stream.status(), 200, "the event stream should open");
    stream
}

/// Read the stream until a cross-exchange call rings, and say which bridge and
/// who is calling.
async fn next_crosscall(stream: &mut sqnr::Stream) -> ([u8; 16], PubKey) {
    let mut framer = Framer::new();
    let read = async {
        loop {
            let chunk = stream
                .next()
                .await
                .unwrap()
                .expect("the event stream ended before the call rang");
            for e in framer.feed(&chunk).unwrap() {
                if let WireEvent::CrossCall { bridge, caller } = e {
                    return (bridge, caller);
                }
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), read)
        .await
        .expect("a ring should arrive")
}

/// Poll the call until it stops ringing, and say how it ended.
async fn settle(client: &mut Client, target: &str, eph: [u8; 32]) -> CallAck {
    for _ in 0..100 {
        let ack = call(client, target, eph).await;
        if ack.state != CallState::Ringing {
            return ack;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the call never stopped ringing");
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

    // Y must be up first so X can be told where it is; X dials Y. Each names
    // the other's key — Y to accept X's link, X to dial Y's — and X is told how
    // to find "y.test", which no DNS here could tell it.
    let (y_addr, y_server_pub, y_h) = relay_server(dir_y.path(), &y_key, &[x_pub], &[]).await;
    let (x_addr, x_server_pub, x_h) =
        relay_server(dir_x.path(), &x_key, &[y_pub], &[("y.test", y_pub, y_addr)]).await;

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

    // Bob has to be listening for a ring to reach him — the ring is a SIP-30
    // event, and his exchange refuses an invite for an account with no open
    // stream rather than ringing into the void.
    let _bob_events = subscribe(&bob).await;

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
    let (addr, server_pub, h) = relay_server(dir.path(), &x_key, &[], &[]).await;

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

/// Bringing up the two federated exchanges, with Alice on X and Bob on Y, for
/// the refusal tests below.
struct Pair {
    alice: Client,
    bob: Client,
    b_id: PubKey,
    y_addr: SocketAddr,
    y_server_pub: [u8; 32],
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    handles: (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>),
}

async fn federated_pair(seed_base: u8) -> Pair {
    let dir_x = tempfile::tempdir().unwrap();
    let dir_y = tempfile::tempdir().unwrap();
    let (xk, x_pub) = identity(seed_base);
    let (yk, y_pub) = identity(seed_base + 1);
    let (x_key, y_key) = (SigningKey::from_bytes(&xk), SigningKey::from_bytes(&yk));

    let (y_addr, y_server_pub, y_h) = relay_server(dir_y.path(), &y_key, &[x_pub], &[]).await;
    let (x_addr, x_server_pub, x_h) =
        relay_server(dir_x.path(), &x_key, &[y_pub], &[("y.test", y_pub, y_addr)]).await;

    let (a_seed, _) = identity(seed_base + 2);
    let (b_seed, b_id) = identity(seed_base + 3);
    let alice = Client::connect_as(x_addr, &x_server_pub, &a_seed)
        .await
        .unwrap();
    let bob = Client::connect_as(y_addr, &y_server_pub, &b_seed)
        .await
        .unwrap();
    Pair {
        alice,
        bob,
        b_id,
        y_addr,
        y_server_pub,
        _dirs: (dir_x, dir_y),
        handles: (x_h, y_h),
    }
}

/// A refused call says so, rather than leaving the caller to poll until it
/// gives up — and the reason the callee gave travels back across the link.
#[tokio::test]
async fn a_declined_call_tells_the_caller_why() {
    let mut p = federated_pair(100).await;
    let mut events = subscribe(&p.bob).await;
    let (_, eph) = ephemeral();
    let target = format!("{}@y.test", p.b_id);

    let first = call(&mut p.alice, &target, eph).await;
    assert_eq!(first.state, CallState::Ringing);

    // Bob's phone rings; he refuses it.
    let (bridge, _caller) = next_crosscall(&mut events).await;
    let (code, _) = p
        .bob
        .post(
            "/session/decline",
            CallDecline {
                bridge,
                reason: relay::REASON_DECLINED,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let ack = settle(&mut p.alice, &target, eph).await;
    assert_eq!(ack.state, CallState::Rejected, "the caller is told");
    assert_eq!(ack.reason, relay::REASON_DECLINED, "and told why");

    // And the refusal is reported once, not forever: Alice can call again.
    let again = call(&mut p.alice, &target, eph).await;
    assert_eq!(
        again.state,
        CallState::Ringing,
        "a declined call must not make the peer permanently uncallable"
    );

    p.handles.0.abort();
    p.handles.1.abort();
}

/// The reason is carried verbatim rather than flattened to one refusal.
#[tokio::test]
async fn a_busy_callee_is_reported_as_busy() {
    let mut p = federated_pair(110).await;
    let mut events = subscribe(&p.bob).await;
    let (_, eph) = ephemeral();
    let target = format!("{}@y.test", p.b_id);

    assert_eq!(
        call(&mut p.alice, &target, eph).await.state,
        CallState::Ringing
    );
    let (bridge, _) = next_crosscall(&mut events).await;
    p.bob
        .post(
            "/session/decline",
            CallDecline {
                bridge,
                reason: relay::REASON_BUSY,
            }
            .encode(),
        )
        .await
        .unwrap();

    let ack = settle(&mut p.alice, &target, eph).await;
    assert_eq!(ack.state, CallState::Rejected);
    assert_eq!(ack.reason, relay::REASON_BUSY, "busy is not declined");

    p.handles.0.abort();
    p.handles.1.abort();
}

/// A ring is a SIP-30 event, so an account with nothing listening cannot hear
/// one. Its exchange says so at once instead of ringing into the void and
/// leaving the caller to time out.
#[tokio::test]
async fn an_unreachable_callee_is_refused_rather_than_left_ringing() {
    let mut p = federated_pair(120).await;
    // Deliberately no `subscribe`: Bob is connected but not listening.
    let (_, eph) = ephemeral();
    let target = format!("{}@y.test", p.b_id);

    let started = std::time::Instant::now();
    let ack = settle(&mut p.alice, &target, eph).await;
    assert_eq!(ack.state, CallState::Rejected);
    assert_eq!(ack.reason, relay::REASON_UNREACHABLE);
    // Promptly, or this passes for the wrong reason — a timeout would also
    // eventually stop ringing.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the refusal should be immediate, not a timeout"
    );

    p.handles.0.abort();
    p.handles.1.abort();
}

/// Only a device of the addressed account may refuse a call. A stranger holding
/// the bridge id cannot hang up somebody else's call, and learns nothing from
/// trying — the reply is the same one a real decline gets.
#[tokio::test]
async fn only_the_addressed_account_may_decline() {
    let mut p = federated_pair(130).await;
    let mut events = subscribe(&p.bob).await;
    let (a_eph, a_eph_pub) = ephemeral();
    let (b_eph, b_eph_pub) = ephemeral();
    let target = format!("{}@y.test", p.b_id);

    assert_eq!(
        call(&mut p.alice, &target, a_eph_pub).await.state,
        CallState::Ringing
    );
    let (bridge, caller) = next_crosscall(&mut events).await;

    // Eve is on Bob's exchange but is nobody in this call.
    let (e_seed, _) = identity(139);
    let mut eve = Client::connect_as(p.y_addr, &p.y_server_pub, &e_seed)
        .await
        .unwrap();
    let (eve_code, eve_body) = eve
        .post(
            "/session/decline",
            CallDecline {
                bridge,
                reason: relay::REASON_DECLINED,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(eve_code, 200, "answered like any other decline");

    // The bridge survived: Bob can still answer, and the call connects.
    let b_ack = open(&mut p.bob, caller, b_eph_pub).await;
    let a_ack = settle(&mut p.alice, &target, a_eph_pub).await;
    assert_eq!(
        a_ack.state,
        CallState::Established,
        "a stranger's decline must not kill the call"
    );

    // And the two ends still agree on a key, so nothing was disturbed.
    let a_sess =
        Session::derive(&identity(132).0, &a_eph, &a_ack.peer, &a_ack.peer_ephemeral).unwrap();
    let b_sess = Session::derive(&identity(133).0, &b_eph, &caller, &b_ack.peer_ephemeral).unwrap();
    let ct = a_sess.seal_datagram(0, b"still connected").unwrap();
    assert_eq!(b_sess.open(0, &ct).unwrap(), b"still connected");

    // Eve's refusal was answered exactly as a genuine one is.
    let (bob_code, bob_body) = p
        .bob
        .post(
            "/session/decline",
            CallDecline {
                bridge: [0u8; 16],
                reason: relay::REASON_DECLINED,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!((eve_code, eve_body), (bob_code, bob_body), "no oracle");

    p.handles.0.abort();
    p.handles.1.abort();
}

/// Discovery finds a peer; the allowlist decides whether to federate with it.
/// Those are two steps and the second is the gate — so a peer this exchange can
/// *find* but has not been told to federate with must still be refused.
///
/// This is the case the discover-then-check ordering could quietly drop: the
/// domain resolves, a link would dial, and nothing else stands in the way.
#[tokio::test]
async fn a_findable_peer_that_is_not_allowlisted_is_still_refused() {
    let dir_x = tempfile::tempdir().unwrap();
    let dir_y = tempfile::tempdir().unwrap();
    let (xk, x_pub) = identity(150);
    let (yk, y_pub) = identity(151);
    let (x_key, y_key) = (SigningKey::from_bytes(&xk), SigningKey::from_bytes(&yk));

    let (y_addr, _y_pub_bytes, y_h) = relay_server(dir_y.path(), &y_key, &[x_pub], &[]).await;
    // X federates with *somebody* — a third exchange it will never call — so
    // the route's "federates with nobody" short circuit does not fire and the
    // allowlist check itself is what has to refuse this. Without a peer here
    // the call never reaches `place_call` at all, and this test would pass
    // while proving nothing.
    let (_, stranger) = identity(159);
    let (x_addr, x_server_pub, x_h) = relay_server(
        dir_x.path(),
        &x_key,
        &[stranger],
        &[("y.test", y_pub, y_addr)],
    )
    .await;

    let (a_seed, _) = identity(152);
    let (_, b_id) = identity(153);
    let (_, eph) = ephemeral();
    let mut alice = Client::connect_as(x_addr, &x_server_pub, &a_seed)
        .await
        .unwrap();

    let ack = call(&mut alice, &format!("{b_id}@y.test"), eph).await;
    assert_eq!(
        ack.state,
        CallState::Rejected,
        "a peer that is found but not allowlisted must be refused"
    );
    assert_eq!(
        ack.reason,
        relay::REASON_REFUSED,
        "refused for not being federated with, not for being unreachable"
    );

    x_h.abort();
    y_h.abort();
}
