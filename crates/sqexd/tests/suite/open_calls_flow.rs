//! SIP-65: calls on a member's word. Two exchanges that list nobody carry
//! a call between two people who already share a conversation, on the
//! caller's own signature: the caller's exchange dials on it, the
//! callee's verifies it and rings. Without the signature, or without the
//! shared conversation, or into an exchange that keeps to its list, the
//! call is refused as SIP-39 refuses everything a stranger may not have.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{Invitee, Role, Visibility};
use sqex_proto::events::{Event as WireEvent, Framer, Subscribe};
use sqex_proto::home::{Move, Moving};
use sqex_proto::relay;
use sqex_proto::session::{CallAck, CallOpen, CallState};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

/// An exchange listing nobody, peering openly, and taking calls openly or
/// not; finding `found` without DNS.
async fn exchange_in(
    dir: &Path,
    listen: SocketAddr,
    domain: &str,
    open_calls: bool,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
) -> Option<(SocketAddr, [u8; 32])> {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        key_in(dir);
    }
    let listed = peers
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
         open_calls = {open_calls}\nseed_relay_peers = [{listed}]\nhome_secs = 1\n",
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
    // A pre-picked port can be taken by another test between the pick and
    // the bind; the caller picks again.
    let bound = sqexd::bind_with(config, None, signing_key, sqexd::relay::Find::Fixed(map))
        .await
        .ok()?;
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    Some((addr, server_pub))
}

pub(crate) fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn key_in(dir: &Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    PubKey::new(vk.to_bytes())
}

fn free_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn ephemeral() -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    x25519_dalek::PublicKey::from(&s).to_bytes()
}

async fn place(client: &mut Client, open: &CallOpen) -> CallAck {
    let (code, body) = client.post("/session/call", open.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    CallAck::decode(&body).unwrap()
}

/// Poll until the call stops ringing.
async fn settle(client: &mut Client, open: &CallOpen, what: &str) -> CallAck {
    for _ in 0..150 {
        let ack = place(client, open).await;
        if ack.state != CallState::Ringing {
            return ack;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("{what}: the call never stopped ringing");
}

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
    assert_eq!(stream.status(), 200);
    stream
}

/// The next ring on the stream, or `None` within `secs`.
async fn ring_within(stream: &mut sqnr::Stream, secs: u64) -> Option<PubKey> {
    let mut framer = Framer::new();
    let read = async {
        loop {
            let chunk = stream.next().await.unwrap()?;
            for e in framer.feed(&chunk).unwrap() {
                if let WireEvent::CrossCall { caller, .. } = e {
                    return Some(caller);
                }
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(secs), read)
        .await
        .ok()
        .flatten()
}

/// Two exchanges listing nobody. Bob lives at Y; Alice at X puts him in a
/// group, which Y pulls for him (SIP-60/63). Returns the clients and Bob's
/// ring stream at Y.
pub(crate) struct Pair {
    pub(crate) x_addr: SocketAddr,
    pub(crate) x_pub: [u8; 32],
    pub(crate) y_addr: SocketAddr,
    pub(crate) y_pub: [u8; 32],
    pub(crate) alice_seed: [u8; 32],
    pub(crate) alice: PubKey,
    pub(crate) bob_seed: [u8; 32],
    pub(crate) bob: PubKey,
    pub(crate) _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// `x_lists_y`: X keeps Y on SIP-39's list, so X dials it as before and
/// sends the plain invite first; Y lists nobody either way.
pub(crate) async fn pair(y_open_calls: bool, x_lists_y: bool, a: u8, b: u8) -> Pair {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let x_key = key_in(x_dir.path());
    let y_key = key_in(y_dir.path());
    let x_peers: Vec<PubKey> = if x_lists_y { vec![y_key] } else { vec![] };
    let mut up = None;
    for _ in 0..5 {
        let (x_at, y_at) = (free_port(), free_port());
        let Some(x) = exchange_in(
            x_dir.path(),
            x_at,
            "x.test",
            true,
            &x_peers,
            &[("y.test", y_key, y_at)],
        )
        .await
        else {
            continue;
        };
        let Some(y) = exchange_in(
            y_dir.path(),
            y_at,
            "y.test",
            y_open_calls,
            &[],
            &[("x.test", x_key, x_at)],
        )
        .await
        else {
            continue;
        };
        up = Some((x, y));
        break;
    }
    let ((x_addr, x_pub), (y_addr, y_pub)) = up.expect("no free port pair in five tries");
    assert_eq!((PubKey::new(x_pub), PubKey::new(y_pub)), (x_key, y_key));

    let (alice_seed, alice) = identity(a);
    let (bob_seed, bob) = identity(b);
    let mut bob_at_y = Client::connect_as(y_addr, &y_pub, &bob_seed).await.unwrap();
    let (code, body) = bob_at_y
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&bob_seed, &y_key, now()),
                domain: "y.test".into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Alice locates Bob (SIP-60), so X knows where he lives; then her
    // group at X with Bob in it, which Y is told of and pulls.
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = alice_at_x
        .post(
            "/account/locate",
            sqex_proto::locate::Locate {
                target: format!("{bob}@y.test"),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    // A private group: the consent a call rests on. And a public one with
    // Carol in it, which is no consent -- anyone joins a public channel.
    let sa = Signer::new(alice_seed, alice, x_pub);
    let mut ca = Chain::default();
    let channel = [a; 32];
    let req = sa.create_chained(
        &mut ca,
        channel,
        instance_for(channel, 0),
        Visibility::Private,
        3600,
        "we talk",
        vec![Invitee {
            account: bob,
            role: Role::Member,
        }],
    );
    let (code, body) = alice_at_x
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let (carol_seed, carol) = identity(a + 2);
    let mut carol_at_x = Client::connect_as(x_addr, &x_pub, &carol_seed)
        .await
        .unwrap();
    let sc = Signer::new(carol_seed, carol, x_pub);
    let mut cc = Chain::default();
    let public = [a + 1; 32];
    let req = sc.create_chained(
        &mut cc,
        public,
        instance_for(public, 0),
        Visibility::Public,
        3600,
        "everyone",
        vec![Invitee {
            account: bob,
            role: Role::Member,
        }],
    );
    let (code, body) = carol_at_x
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    // Y holds both memberships once it has pulled the groups.
    for ch in [channel, public] {
        let mut held = false;
        for _ in 0..80 {
            let (code, _) = bob_at_y
                .post(
                    "/channel/info",
                    sqex_proto::channel::ByChannel { channel: ch }
                        .encode(sqex_proto::channel::TYPE_INFO),
                )
                .await
                .unwrap();
            if code == 200 {
                held = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        assert!(held, "Y never pulled a group for Bob");
    }
    Pair {
        x_addr,
        x_pub,
        y_addr,
        y_pub,
        alice_seed,
        alice,
        bob_seed,
        bob,
        _dirs: (x_dir, y_dir),
    }
}

/// Alice's signed call to Bob rings at Y over a link nobody listed; her
/// unsigned one is refused at X; Carol, who shares nothing with Bob, is
/// refused signed.
#[tokio::test]
async fn a_signed_call_rings_across_two_exchanges_that_list_nobody() {
    let p = pair(true, false, 211, 212).await;
    let bob_at_y = Client::connect_as(p.y_addr, &p.y_pub, &p.bob_seed)
        .await
        .unwrap();
    let mut ring = subscribe(&bob_at_y).await;
    let mut alice = Client::connect_as(p.x_addr, &p.x_pub, &p.alice_seed)
        .await
        .unwrap();
    let target = format!("{}@y.test", p.bob);

    // Unsigned: X will not carry it to an exchange it does not list.
    let plain = CallOpen {
        ephemeral: ephemeral(),
        target: target.clone(),
        word: None,
    };
    let ack = settle(&mut alice, &plain, "unsigned").await;
    assert_eq!(ack.state, CallState::Rejected);
    assert_eq!(ack.reason, relay::REASON_REFUSED);

    // A word signed by somebody else is no word of Alice's: X treats the
    // open as unsigned and refuses it.
    let (carol_seed, _) = identity(213);
    let forged = CallOpen::signed(&carol_seed, ephemeral(), &target, now(), None);
    let ack = settle(&mut alice, &forged, "forged").await;
    assert_eq!(ack.state, CallState::Rejected);
    assert_eq!(
        ring_within(&mut ring, 1).await,
        None,
        "Bob rang on a forged word"
    );

    // Signed: carried, verified at Y, and Bob's device rings.
    let signed = CallOpen::signed(&p.alice_seed, ephemeral(), &target, now(), None);
    let ack = place(&mut alice, &signed).await;
    assert_eq!(ack.state, CallState::Ringing, "reason {}", ack.reason);
    assert_eq!(ring_within(&mut ring, 10).await, Some(p.alice));

    // Carol shares only a public channel with Bob, which is no
    // conversation: refused at X, signed or not, and Bob's phone stays
    // quiet.
    let mut carol = Client::connect_as(p.x_addr, &p.x_pub, &carol_seed)
        .await
        .unwrap();
    let signed = CallOpen::signed(&carol_seed, ephemeral(), &target, now(), None);
    let ack = settle(&mut carol, &signed, "carol").await;
    assert_eq!(ack.state, CallState::Rejected);
    assert_eq!(ack.reason, relay::REASON_REFUSED);
    assert_eq!(
        ring_within(&mut ring, 2).await,
        None,
        "Bob rang for a stranger"
    );
}

/// Y keeps to its list: X, open and satisfied, dials, and Y closes the
/// link -- the call does not connect and Bob does not ring.
#[tokio::test]
async fn an_exchange_that_keeps_to_its_list_closes_the_link() {
    let p = pair(false, false, 221, 222).await;
    let bob_at_y = Client::connect_as(p.y_addr, &p.y_pub, &p.bob_seed)
        .await
        .unwrap();
    let mut ring = subscribe(&bob_at_y).await;
    let mut alice = Client::connect_as(p.x_addr, &p.x_pub, &p.alice_seed)
        .await
        .unwrap();
    let target = format!("{}@y.test", p.bob);
    let signed = CallOpen::signed(&p.alice_seed, ephemeral(), &target, now(), None);
    let ack = place(&mut alice, &signed).await;
    assert_ne!(ack.state, CallState::Established);
    assert_eq!(
        ring_within(&mut ring, 3).await,
        None,
        "a listed Y rang for a stranger"
    );
    let ack = place(&mut alice, &signed).await;
    assert_ne!(ack.state, CallState::Established);
}

/// X lists Y and Y lists nobody. X dials as SIP-39 has it and sends the
/// plain invite; Y, open, wants the caller's word from an exchange it did
/// not list and refuses; X sends the invite again signed, once, and Bob
/// rings. Carol, sharing nothing with Bob, gets through X's list and is
/// refused by Y's own check.
#[tokio::test]
async fn the_callees_exchange_checks_the_word_itself() {
    let p = pair(true, true, 241, 242).await;
    let bob_at_y = Client::connect_as(p.y_addr, &p.y_pub, &p.bob_seed)
        .await
        .unwrap();
    let mut ring = subscribe(&bob_at_y).await;
    let target = format!("{}@y.test", p.bob);

    let (carol_seed, _) = identity(243);
    let mut carol = Client::connect_as(p.x_addr, &p.x_pub, &carol_seed)
        .await
        .unwrap();
    let signed = CallOpen::signed(&carol_seed, ephemeral(), &target, now(), None);
    let ack = settle(&mut carol, &signed, "carol").await;
    assert_eq!(
        ack.state,
        CallState::Rejected,
        "Y rang for a stranger X listed"
    );
    assert_eq!(ack.reason, relay::REASON_REFUSED);
    assert_eq!(ring_within(&mut ring, 1).await, None);

    let mut alice = Client::connect_as(p.x_addr, &p.x_pub, &p.alice_seed)
        .await
        .unwrap();
    let signed = CallOpen::signed(&p.alice_seed, ephemeral(), &target, now(), None);
    let ack = place(&mut alice, &signed).await;
    assert_eq!(ack.state, CallState::Ringing, "reason {}", ack.reason);
    assert_eq!(ring_within(&mut ring, 10).await, Some(p.alice));
}
