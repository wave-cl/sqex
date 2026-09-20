//! SIP-85: a connection carried by the home. A member of exchange A asks A
//! to carry a connection to exchange B; the member's own sQUIC dial to B
//! runs through A's socket, B serves it, and what B sees arrive is A's
//! address. A stranger is refused before A resolves anything; a name whose
//! key is not the one named is refused; a home that does not carry does
//! not offer the ALPN. And the control: with B's address pointed at a dead
//! port, the tunnel opens and the dial through it goes nowhere.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sqex_proto::home::{Move, Moving};
use sqex_proto::tunnel::Carrier;
use sqexd::config::FileConfig;
use sqexd::server::Server;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::open_calls_flow::{identity, now};

struct Exchange {
    addr: SocketAddr,
    key: [u8; 32],
    server: Arc<Server>,
    _dir: tempfile::TempDir,
}

/// An exchange on loopback, carrying connections or not, finding `found`
/// without DNS.
async fn exchange(
    tunnel: bool,
    per_member: u32,
    domain: &str,
    found: &[(&str, PubKey, SocketAddr)],
) -> Exchange {
    for _ in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let listen = free_port();
        let config_toml = format!(
            "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
             welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
             tunnel = {tunnel}\ntunnels_per_member = {per_member}\nhome_secs = 1\n",
            listen.to_string(),
            dir.path().join("host_key").to_string_lossy(),
            dir.path().join("sqex.state").to_string_lossy(),
        );
        let own = key_in(dir.path());
        let file: FileConfig = toml::from_str(&config_toml).unwrap();
        let config = file.resolve().unwrap();
        let (signing_key, _pub) =
            squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
        // The exchange finds itself by its own name too, as a deployment
        // with a published record does.
        let map = found
            .iter()
            .map(|(d, k, a)| ((*d).to_string(), (*k, *a)))
            .chain(std::iter::once((domain.to_string(), (own, listen))))
            .collect();
        let Ok(bound) =
            sqexd::bind_with(config, None, signing_key, sqexd::relay::Find::Fixed(map)).await
        else {
            continue;
        };
        let ex = Exchange {
            addr: bound.local_addr,
            key: bound.public_key.to_bytes(),
            server: Arc::clone(&bound.server),
            _dir: dir,
        };
        tokio::spawn(async move {
            let _ = sqexd::serve(bound).await;
        });
        return ex;
    }
    panic!("no free port in five tries");
}

fn key_in(dir: &Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = ed25519_dalek::SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    PubKey::new(vk.to_bytes())
}

fn free_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

/// A home A that carries, and a target B; A finds B by name. `b_at` is
/// where A believes B is -- B's real address unless a test says otherwise.
async fn pair(a_carries: bool, per_member: u32, b_at: Option<SocketAddr>) -> (Exchange, Exchange) {
    let b = exchange(false, 4, "b.test", &[]).await;
    let a = exchange(
        a_carries,
        per_member,
        "a.test",
        &[("b.test", PubKey::new(b.key), b_at.unwrap_or(b.addr))],
    )
    .await;
    (a, b)
}

/// Make `seed`'s account live at `a`: a SIP-59 Move naming it, presented
/// there. That is what makes the identity a member A carries for.
async fn home_at(a: &Exchange, seed: &[u8; 32]) {
    let mut c = Client::connect_as(a.addr, &a.key, seed).await.unwrap();
    let (code, body) = c
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(seed, &PubKey::new(a.key), now()),
                domain: "a.test".into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

#[tokio::test]
async fn a_member_reaches_the_target_through_its_home() {
    let (a, b) = pair(true, 4, None).await;
    let (seed, me) = identity(0x51);
    home_at(&a, &seed).await;

    let carrier = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect("a member's tunnel opens");
    assert_eq!(carrier.family(), 4);
    assert_eq!(a.server.tunnels_open(), 1, "A carries one tunnel");

    // The member's own dial, pinned to B's key, sent to the carrier's
    // loopback socket -- and answered by B.
    let mut through = Client::connect_as(carrier.local_addr(), &b.key, &seed)
        .await
        .expect("B answers the handshake through the tunnel");
    let (code, body) = through.get("/status").await.unwrap();
    assert_eq!(code, 200);
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["tunnels"], 0, "B carries nothing; A does");
    // One connection at B: the tunnelled one. A dial that reached B some
    // other way as well would count twice.
    assert_eq!(status["connections"], 1, "B accepted more than the tunnelled connection");
    let (up, down) = carrier.bytes();
    assert!(
        up > 0 && down > 0,
        "bytes crossed both ways: {up} up, {down} down"
    );

    // **What B saw.** The connection arrived from the socket A opened for
    // this tunnel, not from the member's dialler -- the whole point.
    let seen = b.server.last_peer_addr().expect("B accepted a connection");
    let a_sockets = a.server.tunnel_sockets();
    assert_eq!(a_sockets.len(), 1);
    assert!(seen.ip().is_loopback());
    assert_eq!(
        seen.port(),
        a_sockets[0].port(),
        "B saw {seen}; A's tunnel socket is {}",
        a_sockets[0]
    );
    assert_ne!(seen, carrier.local_addr(), "B never saw the member's side");

    // **And whose connection it was.** The home only carried it: B's
    // transport key for this connection is the member's own (SIP-2, the
    // X25519 derivation of the identity) and the identity carried is the
    // member's (SIP-3) -- not the home's, which never handshook with B.
    assert_eq!(
        b.server.last_peer_identity(),
        Some(me),
        "B authenticated somebody other than the member"
    );
    let x_of = |k: &[u8; 32]| {
        squic::crypto::ed25519_public_to_x25519(k)
            .unwrap()
            .to_bytes()
    };
    assert_eq!(
        b.server.last_peer_key(),
        Some(x_of(me.as_bytes())),
        "B's transport key for the connection is not the member's"
    );
    assert_ne!(
        b.server.last_peer_key(),
        Some(x_of(&a.key)),
        "B saw the home's key"
    );
    assert_ne!(b.server.last_peer_identity(), Some(PubKey::new(a.key)));
    let (code, body) = through.get("/exchange/ping").await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // A's own status counts it, and stops counting when the member goes.
    let mut at_a = Client::connect_as(a.addr, &a.key, &seed).await.unwrap();
    let (_, body) = at_a.get("/status").await.unwrap();
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["tunnels"], 1);
    drop(through);
    drop(carrier);
    for _ in 0..50 {
        if a.server.tunnels_open() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        a.server.tunnels_open(),
        0,
        "the tunnel closed with its carrier"
    );
}

#[tokio::test]
async fn a_stranger_is_refused_whatever_it_names() {
    let (a, b) = pair(true, 4, None).await;
    let (stranger, _) = identity(0x52);
    // Not homed here, not on a list: refused, and refused the same way for
    // a name A could resolve and one it could not -- the answer must not
    // say which.
    let e = Carrier::open(a.addr, &a.key, &stranger, &b.key, "b.test")
        .await
        .expect_err("a stranger has no tunnel");
    assert!(e.contains("refused"), "{e}");
    let e2 = Carrier::open(a.addr, &a.key, &stranger, &b.key, "nowhere.test")
        .await
        .expect_err("a stranger has no tunnel to an unknown name either");
    assert!(e2.contains("refused"), "{e2}");
    assert_eq!(
        e.replace("b.test", "X"),
        e2.replace("nowhere.test", "X"),
        "the refusal must not depend on the name"
    );
    assert_eq!(a.server.tunnels_open(), 0);
}

#[tokio::test]
async fn the_name_must_vouch_for_the_key() {
    let (a, b) = pair(true, 4, None).await;
    let (seed, _) = identity(0x53);
    home_at(&a, &seed).await;

    // B's name with A's key: the name does not vouch for it.
    let e = Carrier::open(a.addr, &a.key, &seed, &a.key, "b.test")
        .await
        .expect_err("a key the name does not vouch for");
    assert!(e.contains("different key"), "{e}");
    // A name A cannot resolve.
    let e = Carrier::open(a.addr, &a.key, &seed, &b.key, "nowhere.test")
        .await
        .expect_err("a name with no exchange");
    assert!(e.contains("no exchange"), "{e}");
    // A itself: nothing a direct connection would not carry, and a loop.
    let e = Carrier::open(a.addr, &a.key, &seed, &a.key, "a.test")
        .await
        .expect_err("a tunnel to the home itself");
    assert!(e.contains("refused"), "{e}");
    assert_eq!(
        a.server.tunnels_open(),
        0,
        "every refusal gave its slot back"
    );
}

#[tokio::test]
async fn a_home_that_does_not_carry_refuses_at_the_handshake() {
    let (a, b) = pair(false, 4, None).await;
    let (seed, _) = identity(0x54);
    home_at(&a, &seed).await;
    let e = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect_err("no ALPN, no tunnel");
    assert!(e.contains("does not carry connections"), "{e}");
}

#[tokio::test]
async fn a_member_holds_no_more_than_its_share() {
    let (a, b) = pair(true, 1, None).await;
    let (seed, _) = identity(0x55);
    home_at(&a, &seed).await;
    let first = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect("the first opens");
    let e = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect_err("the second is over the member's share");
    assert!(e.contains("limit"), "{e}");
    drop(first);
    for _ in 0..50 {
        if a.server.tunnels_open() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _again = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect("the slot came back with the first tunnel's end");
}

/// **The control.** A believes B is at a port nothing listens on. The
/// tunnel opens -- A resolved a name to a key and an address and bound a
/// socket -- and the member's dial through it reaches nothing, because the
/// packets go through the tunnel and nowhere else. Were the dial reaching
/// B some other way, this would connect.
#[tokio::test]
async fn packets_go_through_the_tunnel_and_nowhere_else() {
    let dead = free_port();
    let (a, b) = pair(true, 4, Some(dead)).await;
    let (seed, _) = identity(0x56);
    home_at(&a, &seed).await;
    let carrier = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect("the tunnel opens; nothing has been sent yet");
    let dial = Client::connect_as(carrier.local_addr(), &b.key, &seed);
    let outcome = tokio::time::timeout(Duration::from_secs(8), dial).await;
    assert!(
        !matches!(outcome, Ok(Ok(_))),
        "a dial through a tunnel to a dead port connected -- the packets went somewhere else"
    );
    let (up, _) = carrier.bytes();
    assert!(up > 0, "the dial's Initials went up the tunnel");

    // And the positive half, for the same B, the same member, a live
    // address: so the instrument tells the two apart.
    let live = exchange(
        true,
        4,
        "a2.test",
        &[("b.test", PubKey::new(b.key), b.addr)],
    )
    .await;
    home_at(&live, &seed).await;
    let carrier = Carrier::open(live.addr, &live.key, &seed, &b.key, "b.test")
        .await
        .unwrap();
    let dial = Client::connect_as(carrier.local_addr(), &b.key, &seed);
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(8), dial).await,
            Ok(Ok(_))
        ),
        "the same dial through a live tunnel connects"
    );
}
