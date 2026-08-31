//! Losing the exchange, and getting it back.
//!
//! Until now this client dialled once, in `run`, and never again. A dropped
//! QUIC connection — a laptop lid, a changed network, an exchange restarted
//! for a release — left every request afterwards failing, one per conversation
//! every 700 ms, for as long as the client stayed open. Nothing said so, and
//! nothing recovered.
//!
//! The interruption is done with a **relay**: the client dials a UDP socket
//! that forwards to the exchange, and closing the gate stops the packets. That
//! is what a network going away actually looks like, and it is the only way to
//! do it in one process — aborting the exchange's accept loop does not close
//! the connections it has already handed to tasks of their own, so the client
//! carries on talking to a server that is supposedly dead.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use sqex_chat::client::{Chat, Link};
use sqex_chat::store::Store;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
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

/// A UDP forwarder with a gate on it.
///
/// Nothing about sQUIC minds being relayed: the server key is pinned and the
/// caller's identity is advertised in the Initial, both end to end, so the
/// relay is exactly a piece of network and not a party to anything.
async fn gated_relay(to: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    back.connect(to).await.unwrap();
    let open = Arc::new(AtomicBool::new(true));
    let gate = Arc::clone(&open);
    tokio::spawn(async move {
        let mut up = vec![0u8; 4096];
        let mut down = vec![0u8; 4096];
        let mut client: Option<SocketAddr> = None;
        loop {
            tokio::select! {
                got = front.recv_from(&mut up) => {
                    if let Ok((n, src)) = got {
                        client = Some(src);
                        if gate.load(Ordering::Relaxed) {
                            let _ = back.send(&up[..n]).await;
                        }
                    }
                }
                got = back.recv(&mut down) => {
                    if let Ok(n) = got
                        && gate.load(Ordering::Relaxed)
                        && let Some(c) = client
                    {
                        let _ = front.send_to(&down[..n], c).await;
                    }
                }
            }
        }
    });
    (front_addr, open)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

#[tokio::test]
async fn the_client_comes_back_after_the_exchange_goes_away() {
    let dir = tempfile::tempdir().unwrap();
    let (real, server_pub, server) = server_in(dir.path()).await;
    let (addr, gate) = gated_relay(real).await;

    let (seed, me) = identity(70);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(&dir.path().join("chat.db"))).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.dials(addr, server_pub);

    chat.top_up_prekeys().await.unwrap();
    assert!(chat.mine().await.is_ok(), "the exchange should be answering");
    assert_eq!(chat.link(), Link::Up);

    // The network goes away.
    gate.store(false, Ordering::Relaxed);

    let began = Instant::now();
    assert!(
        chat.mine().await.is_err(),
        "a request into a hole should fail"
    );
    let waited = began.elapsed();
    // The deadline is what makes this fail at all. QUIC's idle timer is 30 s,
    // and without a ceiling of our own the call — and the interface behind it
    // — would sit here for every second of that.
    assert!(
        waited < Duration::from_secs(15),
        "waited {waited:?} for a request that was never going to be answered"
    );
    assert_ne!(chat.link(), Link::Up, "the link still claims to be up");

    // And nothing is attempted while it is down: the poll loop asks about
    // every conversation every 700 ms, and each of those must cost nothing.
    let began = Instant::now();
    assert!(chat.mine().await.is_err());
    assert!(
        began.elapsed() < Duration::from_millis(100),
        "a call while offline waited {:?} — it should refuse without dialling",
        began.elapsed()
    );

    // The network comes back.
    gate.store(true, Ordering::Relaxed);

    let deadline = Instant::now() + Duration::from_secs(60);
    while chat.link() != Link::Up && Instant::now() < deadline {
        chat.keep_alive().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        chat.link(),
        Link::Up,
        "the client never reconnected to an exchange that came back"
    );
    assert!(
        chat.mine().await.is_ok(),
        "reconnected, and nothing works through the new connection"
    );
    server.abort();
}

/// A `Chat` nobody gave an endpoint to must not short-circuit its own
/// requests. It has no way to reconnect, so a state it can never leave would
/// be a client that stops working for good over one lost packet — and every
/// one of the four test files here builds a `Chat` that way.
#[tokio::test]
async fn a_chat_that_cannot_redial_keeps_trying() {
    let dir = tempfile::tempdir().unwrap();
    let (real, server_pub, server) = server_in(dir.path()).await;
    let (addr, gate) = gated_relay(real).await;

    let (seed, me) = identity(71);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(&dir.path().join("chat.db"))).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    // Deliberately no `dials`.

    chat.top_up_prekeys().await.unwrap();
    gate.store(false, Ordering::Relaxed);
    assert!(chat.mine().await.is_err());

    // Harmless with nowhere to dial, rather than a panic or a wait.
    let began = Instant::now();
    chat.keep_alive().await;
    assert!(began.elapsed() < Duration::from_millis(50));

    // Assert that the request was actually made, not that it took a while.
    //
    // This used to require the call to last more than a millisecond, using
    // elapsed time as a proxy for "it went to the wire". A successful round
    // trip through a loopback relay takes about 0.7ms, so the proxy failed
    // roughly a third of the time — and more often as the transport got
    // faster, which is the wrong direction for a test to move. A short-circuit
    // is what this guards against, and a short-circuit returns an error
    // without leaving the process, so succeeding is the property.
    gate.store(true, Ordering::Relaxed);
    let outcome = chat.mine().await;
    assert!(
        outcome.is_ok(),
        "it refused without trying, and it has no way back: {:?}",
        outcome.err()
    );
    server.abort();
}
