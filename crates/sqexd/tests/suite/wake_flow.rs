//! SIP-45: a device that cannot hold a stream leaves an endpoint and is
//! woken with four fixed bytes when something happens -- once per interval
//! while it stays away, not at all while it is listening, at once for a
//! ring -- and the endpoint is forgotten when its distributor is.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{SignalOut, Visibility};
use sqex_proto::message::{RING_RINGING, SIGNAL_CALL_STATE, Signal};
use sqex_proto::wake::{Register, WAKE_BODY, forget};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nwake_loopback = true\n",
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

/// A push distributor, as far as an exchange can tell: something that takes
/// a POST on loopback and remembers what arrived. Answers `status`.
pub(crate) struct Distributor {
    pub(crate) url: String,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

pub(crate) async fn distributor(status: u16) -> Distributor {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let seen = Arc::clone(&bodies);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // Read headers, then as many body bytes as they promise.
                let body = loop {
                    let n = match sock.read(&mut tmp).await {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        while buf.len() < end + 4 + len {
                            let n = match sock.read(&mut tmp).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            buf.extend_from_slice(&tmp[..n]);
                        }
                        break Some((head, buf[end + 4..].to_vec()));
                    }
                };
                if let Some((head, body)) = body {
                    assert!(head.starts_with("POST "), "not a POST: {head}");
                    seen.lock().unwrap().push(body);
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(reply.as_bytes()).await;
                }
            });
        }
    });
    Distributor {
        url: format!("http://127.0.0.1:{port}/up/token"),
        bodies,
    }
}

pub(crate) async fn wakes_within(d: &Distributor, n: usize, secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if d.bodies.lock().unwrap().len() >= n {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    false
}

/// SIP-36: the ring state is in the clear, and is what the exchange rings on.
async fn ring(c: &mut Client, channel: [u8; 32], device: PubKey, target: u64) {
    let body = Signal::CallState {
        target,
        state: RING_RINGING,
        device,
    }
    .encode();
    let (code, said) = c
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind: SIGNAL_CALL_STATE,
                body,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&said));
}

async fn say(c: &mut Client, s: &Signer, chain: &mut Chain, channel: [u8; 32], text: &[u8]) {
    let info = s.info(c, channel).await;
    let req = s.post_chained(chain, channel, info.instance, 0, 0, text.to_vec());
    let (code, body) = c.post("/channel/post", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

#[tokio::test]
async fn an_absent_device_is_woken_once_and_a_listening_one_not_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(191);
    let (bob_seed, bob) = identity(192);
    let channel = [191u8; 32];

    // Alice makes a room Bob joins; Bob then leaves an endpoint and goes away.
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed)
        .await
        .unwrap();
    let s = Signer::new(alice_seed, alice, server_pub);
    let mut chain = Chain::default();
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![],
    );
    let (code, _) = a.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200);
    let mut b = Client::connect_as(addr, &server_pub, &bob_seed)
        .await
        .unwrap();
    let joining = Signer::new(bob_seed, bob, server_pub).action_outside(
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_JOINED,
        &bob,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, _) = b
        .post(
            "/channel/join",
            sqex_proto::channel::ByChannelSigned {
                channel,
                action: joining,
            }
            .encode(sqex_proto::channel::TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let pushes = distributor(200).await;
    // Not just anything: a public https address, or loopback here.
    let (code, _) = b
        .post(
            "/wake/register",
            Register {
                ttl: 3600,
                endpoint: "http://10.0.0.9/up".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_ne!(code, 200, "a private address was accepted");
    let (code, body) = b
        .post(
            "/wake/register",
            Register {
                ttl: 3600,
                endpoint: pushes.url.clone(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Alice speaks twice. Bob holds no stream: one wake, four fixed bytes,
    // and not a second within the interval.
    say(&mut a, &s, &mut chain, channel, b"one").await;
    assert!(wakes_within(&pushes, 1, 5).await, "no wake arrived");
    say(&mut a, &s, &mut chain, channel, b"two").await;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let bodies = pushes.bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1, "woken twice within the interval");
    assert_eq!(bodies[0], WAKE_BODY, "the wake said something");

    // A ring goes at once, interval or no.
    ring(&mut a, channel, alice, 7).await;
    assert!(
        wakes_within(&pushes, 2, 5).await,
        "a ring did not wake at once"
    );

    // Bob comes back and holds a stream: nothing is posted for him.
    let stream = b
        .stream(
            "POST",
            "/events",
            sqex_proto::events::Subscribe {
                version: sqex_proto::events::VERSION,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let before = pushes.bodies.lock().unwrap().len();
    // Past the interval, so a wake would be due if he were away.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    ring(&mut a, channel, alice, 8).await;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert_eq!(
        pushes.bodies.lock().unwrap().len(),
        before,
        "a listening device was woken"
    );
    drop(stream);

    // SIP-47: the stream held and let go answered the wake. The next event
    // -- an ordinary post, seconds after the last wake -- wakes him afresh
    // rather than waiting out the interval.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let before = pushes.bodies.lock().unwrap().len();
    say(&mut a, &s, &mut chain, channel, b"three").await;
    assert!(
        wakes_within(&pushes, before + 1, 5).await,
        "a device that came and went was held to a wake it had answered"
    );

    // Forgotten: nothing arrives after.
    let (code, _) = b.post("/wake/forget", forget()).await.unwrap();
    assert_eq!(code, 200);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let before = pushes.bodies.lock().unwrap().len();
    ring(&mut a, channel, alice, 9).await;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert_eq!(
        pushes.bodies.lock().unwrap().len(),
        before,
        "a forgotten device was woken"
    );
}

/// A distributor that answers 410 has forgotten the endpoint, and so does
/// the exchange: the next event posts nothing.
#[tokio::test]
async fn a_gone_endpoint_is_forgotten() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(193);
    let (bob_seed, bob) = identity(194);
    let channel = [193u8; 32];
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed)
        .await
        .unwrap();
    let s = Signer::new(alice_seed, alice, server_pub);
    let mut chain = Chain::default();
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![],
    );
    a.post("/channel/create", req.encode()).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &bob_seed)
        .await
        .unwrap();
    let joining = Signer::new(bob_seed, bob, server_pub).action_outside(
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_JOINED,
        &bob,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    b.post(
        "/channel/join",
        sqex_proto::channel::ByChannelSigned {
            channel,
            action: joining,
        }
        .encode(sqex_proto::channel::TYPE_JOIN),
    )
    .await
    .unwrap();
    let gone = distributor(410).await;
    b.post(
        "/wake/register",
        Register {
            ttl: 3600,
            endpoint: gone.url.clone(),
        }
        .encode(),
    )
    .await
    .unwrap();
    // Two rings: the first is posted and answered 410; the second finds no
    // endpoint to post to.
    for target in [1, 2] {
        ring(&mut a, channel, alice, target).await;
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    }
    assert_eq!(
        gone.bodies.lock().unwrap().len(),
        1,
        "the exchange kept knocking"
    );
}
