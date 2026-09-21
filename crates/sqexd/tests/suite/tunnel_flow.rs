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

use sqex_proto::Op;
use sqex_proto::home::{Move, Moving};
use sqex_proto::tunnel::Carrier;
use sqexd::config::FileConfig;
use sqexd::server::Server;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::carried_device_flow::admin;
use crate::common;
use crate::open_calls_flow::{identity, now};

struct Exchange {
    addr: SocketAddr,
    key: [u8; 32],
    server: Arc<Server>,
    _dir: tempfile::TempDir,
}

/// What an exchange is started with, beyond carrying or not.
#[derive(Default)]
struct Opts {
    per_member: u32,
    /// SIP-85 §Limits: `tunnel_idle_secs`; the default (60) when None.
    idle_secs: Option<u64>,
    /// SIP-85 §Limits: `tunnel_bytes_per_sec`; the default (2 MiB) when None.
    bytes_per_sec: Option<u64>,
    admins: Vec<PubKey>,
}

/// An exchange on loopback, carrying connections or not, finding `found`
/// without DNS.
async fn exchange(
    tunnel: bool,
    per_member: u32,
    domain: &str,
    found: &[(&str, PubKey, SocketAddr)],
) -> Exchange {
    exchange_with(
        tunnel,
        Opts {
            per_member,
            ..Default::default()
        },
        domain,
        found,
    )
    .await
}

async fn exchange_with(
    tunnel: bool,
    opts: Opts,
    domain: &str,
    found: &[(&str, PubKey, SocketAddr)],
) -> Exchange {
    let per_member = opts.per_member;
    let admins = opts
        .admins
        .iter()
        .map(|k| format!("{:?}", k.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let idle = opts
        .idle_secs
        .map(|s| format!("tunnel_idle_secs = {s}\n"))
        .unwrap_or_default();
    let bytes = opts
        .bytes_per_sec
        .map(|b| format!("tunnel_bytes_per_sec = {b}\n"))
        .unwrap_or_default();
    for _ in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let listen = free_port();
        let config_toml = format!(
            "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = [{admins}]\n\
             welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
             tunnel = {tunnel}\ntunnels_per_member = {per_member}\nhome_secs = 1\n{idle}{bytes}",
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
    assert_eq!(
        status["connections"], 1,
        "B accepted more than the tunnelled connection"
    );
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

/// A carrier carries one connection. A second dial of the same carrier's
/// socket is a second endpoint on one pump -- the replies have one port to
/// go to -- so the pump pins the first dialler and drops the second: the
/// first connection keeps working, the second never connects, and the
/// carrier counts what it dropped.
#[tokio::test]
async fn a_second_dial_through_one_carrier_is_dropped_not_multiplexed() {
    let (a, b) = pair(true, 4, None).await;
    let (seed, _) = identity(0x57);
    home_at(&a, &seed).await;
    let carrier = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .unwrap();
    let mut first = Client::connect_as(carrier.local_addr(), &b.key, &seed)
        .await
        .expect("the first connection through the carrier");
    assert_eq!(carrier.stray(), 0);

    let (other, _) = identity(0x58);
    let second = Client::connect_as(carrier.local_addr(), &b.key, &other);
    let outcome = tokio::time::timeout(Duration::from_secs(8), second).await;
    assert!(
        !matches!(outcome, Ok(Ok(_))),
        "a second endpoint through one carrier must not connect"
    );
    assert!(
        carrier.stray() > 0,
        "the second dialler's packets were dropped and counted"
    );
    // And the first is untouched by the attempt.
    let (code, _) = first.get("/status").await.expect("the first still answers");
    assert_eq!(code, 200);
}

/// A whitelisted exchange. `member` is on the list; nobody has presented a
/// Move. Returns A (carrying, with `admin` as its administrator) and B.
async fn listed_pair(admin_key: PubKey) -> (Exchange, Exchange) {
    let b = exchange(false, 4, "b.test", &[]).await;
    let a = exchange_with(
        true,
        Opts {
            per_member: 4,
            admins: vec![admin_key],
            ..Default::default()
        },
        "a.test",
        &[("b.test", PubKey::new(b.key), b.addr)],
    )
    .await;
    (a, b)
}

async fn settle(a: &Exchange, open: usize) -> bool {
    for _ in 0..60 {
        if a.server.tunnels_open() == open {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// SIP-85 §Opening a tunnel, the whitelist branch: with the list on, a
/// listed key is a member A carries for -- no Move presented, no account
/// homed here -- and it stops being one the moment it is removed: the
/// door closes its connections, the tunnel among them, and the next open
/// is dropped at the handshake.
#[tokio::test]
async fn a_listed_key_is_carried_for_without_a_move() {
    let (admin_seed, admin_key) = identity(0x61);
    let (a, b) = listed_pair(admin_key).await;
    let (seed, me) = identity(0x62);
    let v = admin(
        a.addr,
        a.key,
        admin_seed,
        vec![
            Op::WhitelistEnable,
            Op::WhitelistAdd {
                key: me,
                label: Some("member".into()),
            },
        ],
    )
    .await;
    assert_eq!(v["results"][1]["ok"], true);
    // No Move: A has no home on record for the member, so the list is
    // what admits it. (Asked as the member would ask.)
    let mut at_a = Client::connect_as(a.addr, &a.key, &seed).await.unwrap();
    let (_, homed) = at_a
        .post("/account/home", me.as_bytes().to_vec())
        .await
        .unwrap();
    assert_eq!(
        sqex_proto::home::Homed::decode(&homed).unwrap().since,
        0,
        "the member is homed here; the list is not what admits it"
    );
    drop(at_a);

    let carrier = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect("a listed key's tunnel opens");
    let mut through = Client::connect_as(carrier.local_addr(), &b.key, &seed)
        .await
        .expect("B answers through the tunnel");
    let (code, _) = through.get("/status").await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(b.server.last_peer_identity(), Some(me));
    assert_eq!(a.server.tunnels_open(), 1);

    // Removed from the list: no longer admitted, no longer carried for.
    let v = admin(a.addr, a.key, admin_seed, vec![Op::WhitelistRemove(me)]).await;
    assert_eq!(v["results"][0]["changed"], true);
    assert!(
        settle(&a, 0).await,
        "the tunnel outlived the member's admission: {:?}",
        a.server.tunnel_closes()
    );
    assert!(carrier.closed(), "the member did not see its tunnel end");
    assert_eq!(
        a.server.tunnel_closes().last(),
        Some(&"member gone"),
        "closed with the member's connection, which the door closed"
    );
    // The next open is dropped at the door -- the transport's silence, not
    // a refusal: a timeout, and nothing at A to show for it.
    let again = tokio::time::timeout(
        Duration::from_secs(4),
        Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test"),
    )
    .await;
    assert!(!matches!(again, Ok(Ok(_))), "a removed key opened a tunnel");
    assert_eq!(a.server.tunnels_open(), 0);
}

/// A list that is off admits nobody to a tunnel on its account: the keys on
/// it are inert, the door is open, and only an account homed here is
/// carried for. The stranger's refusal, then the homed branch on the same
/// exchange.
#[tokio::test]
async fn a_list_that_is_off_admits_nobody_to_a_tunnel() {
    let (admin_seed, admin_key) = identity(0x63);
    let (a, b) = listed_pair(admin_key).await;
    let (seed, me) = identity(0x64);
    let v = admin(
        a.addr,
        a.key,
        admin_seed,
        vec![
            Op::WhitelistAdd {
                key: me,
                label: Some("listed but the list is off".into()),
            },
            Op::WhitelistDisable,
        ],
    )
    .await;
    assert_eq!(v["results"][0]["ok"], true);
    // The door is open: the member connects and is served.
    let mut at_a = Client::connect_as(a.addr, &a.key, &seed).await.unwrap();
    let (code, _) = at_a.get("/status").await.unwrap();
    assert_eq!(code, 200);
    // And is not carried for.
    let e = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect_err("a key on a list that is off is a stranger to the tunnel");
    assert!(e.contains("refused"), "{e}");
    assert_eq!(a.server.tunnels_open(), 0);
    // Homed here, it is a member whatever the list says.
    home_at(&a, &seed).await;
    let carrier = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .expect("the homed branch admits with the list off");
    let mut through = Client::connect_as(carrier.local_addr(), &b.key, &seed)
        .await
        .unwrap();
    let (code, _) = through.get("/status").await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(b.server.last_peer_identity(), Some(me));
}

/// SIP-85 §Closing: a tunnel that carries nothing either way for
/// `tunnel_idle_secs` is closed by the home, and the member sees its stream
/// end; one that carries something is not. Three readings side by side:
/// idle at 2 s closes, busy at 2 s stays, idle at the default stays.
#[tokio::test]
async fn an_idle_tunnel_closes_and_a_busy_one_does_not() {
    let b = exchange(false, 4, "b.test", &[]).await;
    let quick = exchange_with(
        true,
        Opts {
            per_member: 4,
            idle_secs: Some(2),
            ..Default::default()
        },
        "a.test",
        &[("b.test", PubKey::new(b.key), b.addr)],
    )
    .await;
    let (seed, _) = identity(0x65);
    home_at(&quick, &seed).await;

    // Idle: opened, and nothing sent through it.
    let idle = Carrier::open(quick.addr, &quick.key, &seed, &b.key, "b.test")
        .await
        .unwrap();
    assert!(
        settle(&quick, 0).await,
        "an idle tunnel stayed open past 6 s: {:?}",
        quick.server.tunnel_closes()
    );
    assert_eq!(quick.server.tunnel_closes(), vec!["idle"]);
    assert!(idle.closed(), "the member did not see the idle close");

    // Busy: a dial through it, asked something every half second for 5 s,
    // which is two and a half idle spans.
    let busy = Carrier::open(quick.addr, &quick.key, &seed, &b.key, "b.test")
        .await
        .unwrap();
    let mut through = Client::connect_as(busy.local_addr(), &b.key, &seed)
        .await
        .unwrap();
    for _ in 0..10 {
        let (code, _) = through
            .get("/status")
            .await
            .expect("the busy tunnel carries");
        assert_eq!(code, 200);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(quick.server.tunnels_open(), 1, "the busy tunnel was closed");
    assert_eq!(
        quick.server.tunnel_closes(),
        vec!["idle"],
        "a second close happened while the tunnel was busy"
    );
    assert!(!busy.closed());

    // The control: the same idle tunnel under the default span is still
    // open when the 2 s one had long closed.
    let slow = exchange(
        true,
        4,
        "a2.test",
        &[("b.test", PubKey::new(b.key), b.addr)],
    )
    .await;
    home_at(&slow, &seed).await;
    let idle = Carrier::open(slow.addr, &slow.key, &seed, &b.key, "b.test")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        slow.server.tunnels_open(),
        1,
        "closed under the 60 s default"
    );
    assert!(slow.server.tunnel_closes().is_empty());
    assert!(!idle.closed());
}

/// SIP-85 §Limits: over its byte budget a tunnel drops packets, as UDP
/// drops -- it does not queue them -- and the member's connection, which is
/// QUIC, recovers. Ten 60 KB posts through a 64 KB/s tunnel: every one
/// completes, packets were dropped, and what went up is bounded by the
/// budget plus one second's burst. The control, the same posts through an
/// unbudgeted home: nothing dropped.
#[tokio::test]
async fn a_tunnel_over_its_byte_budget_drops_and_the_connection_survives() {
    const RATE: u64 = 64 * 1024;
    let b = exchange(false, 4, "b.test", &[]).await;
    let tight = exchange_with(
        true,
        Opts {
            per_member: 4,
            bytes_per_sec: Some(RATE),
            ..Default::default()
        },
        "a.test",
        &[("b.test", PubKey::new(b.key), b.addr)],
    )
    .await;
    let (seed, _) = identity(0x66);
    home_at(&tight, &seed).await;
    let body = vec![0x5au8; 60 * 1024];

    let carrier = Carrier::open(tight.addr, &tight.key, &seed, &b.key, "b.test")
        .await
        .unwrap();
    let mut through = Client::connect_as(carrier.local_addr(), &b.key, &seed)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    for i in 0..10 {
        let posted = tokio::time::timeout(
            Duration::from_secs(60),
            through.post("/exchange/ping", body.clone()),
        )
        .await;
        assert!(
            matches!(posted, Ok(Ok(_))),
            "post {i} did not complete through the budgeted tunnel: {posted:?}"
        );
    }
    let elapsed = started.elapsed().as_secs_f64();
    let (sent, _) = carrier.bytes();
    let (forwarded, _) = tight.server.tunnel_forwarded();
    let (dropped_up, _) = tight.server.tunnel_dropped();
    assert!(
        dropped_up > 0,
        "nothing was dropped: the bucket never engaged"
    );
    // What A carried on is bounded by the budget plus one second's burst,
    // whatever the machine's speed; what the member sent is more, by the
    // drops and QUIC's retransmissions of them.
    let bound = (RATE as f64) * (elapsed + 1.0);
    assert!(
        (forwarded as f64) <= bound,
        "{forwarded} bytes carried on in {elapsed:.1} s, over the budget's {bound:.0}"
    );
    assert!(
        forwarded >= 10 * 60 * 1024,
        "less was carried on than was posted: {forwarded}"
    );
    assert!(
        sent > forwarded,
        "the member sent {sent}, A carried {forwarded}: nothing dropped?"
    );

    // The control.
    let loose = exchange(
        true,
        4,
        "a2.test",
        &[("b.test", PubKey::new(b.key), b.addr)],
    )
    .await;
    home_at(&loose, &seed).await;
    let carrier = Carrier::open(loose.addr, &loose.key, &seed, &b.key, "b.test")
        .await
        .unwrap();
    let mut through = Client::connect_as(carrier.local_addr(), &b.key, &seed)
        .await
        .unwrap();
    for _ in 0..10 {
        through.post("/exchange/ping", body.clone()).await.unwrap();
    }
    assert_eq!(
        loose.server.tunnel_dropped(),
        (0, 0),
        "the unbudgeted home dropped packets"
    );
}
