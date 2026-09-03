//! End-to-end for the SIP-4 liveness beacon over real HTTP/3.
//!
//! The property under test is that this is an **open set**: an identity the
//! server has never registered — not an admin, not whitelisted — can beat and
//! be named, purely because SIP-3 carried its Ed25519 key on the Initial. That
//! is what the transport flag-day bought.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::beacon::{Beat, BeatAck, Read, Reply};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn spawn_server(
    config_toml: &str,
    config_path: std::path::PathBuf,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let file: FileConfig = toml::from_str(config_toml).unwrap();
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

/// A server with no admins and an empty whitelist — nothing is pre-registered.
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
    spawn_server(&config_toml, config_path).await
}

fn identity(b: u8) -> (SigningKey, [u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    let seed = sk.to_bytes();
    let pk = PubKey::new(sk.verifying_key().to_bytes());
    (sk, seed, pk)
}

async fn beat(
    addr: SocketAddr,
    server_pub: &[u8; 32],
    seed: &[u8; 32],
    interval: u32,
    withhold: bool,
) -> (u16, Vec<u8>) {
    let mut c = Client::connect_as(addr, server_pub, seed).await.unwrap();
    c.post(
        "/beacon/beat",
        Beat {
            interval_secs: interval,
            withhold,
        }
        .encode(),
    )
    .await
    .unwrap()
}

/// Read as a given identity (or anonymously when `seed` is None).
async fn read(
    addr: SocketAddr,
    server_pub: &[u8; 32],
    seed: Option<&[u8; 32]>,
    target: PubKey,
) -> Reply {
    let mut c = match seed {
        Some(s) => Client::connect_as(addr, server_pub, s).await.unwrap(),
        None => Client::connect(addr, server_pub).await.unwrap(),
    };
    let (code, body) = c
        .post("/beacon/read", Read { key: target }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "read is open to any caller");
    Reply::decode(&body).unwrap()
}

#[tokio::test]
async fn an_unregistered_identity_can_beat_and_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    // This identity is in no admin list and no whitelist. The server has never
    // heard of it.
    let (_sk, seed, pk) = identity(21);

    let (code, body) = beat(addr, &server_pub, &seed, 60, false).await;
    assert_eq!(code, 200, "an unregistered identity may beat (open set)");
    let ack = BeatAck::decode(&body).unwrap();
    assert!(ack.now > 0, "the ack carries the exchange's clock");

    // Anyone may ask, including an anonymous caller.
    let r = read(addr, &server_pub, None, pk).await;
    assert!(r.found, "the beat was recorded against the Ed25519 identity");
    assert_eq!(r.interval_secs, 60);
    assert!(r.now >= r.last_seen);
    assert!(r.staleness() < 5, "just beaten, so barely stale");

    handle.abort();
}

#[tokio::test]
async fn an_anonymous_connection_cannot_beat() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    // Connect without advertising an identity — the default admin-style dial.
    let mut c = Client::connect(addr, &server_pub).await.unwrap();
    let (code, _) = c
        .post(
            "/beacon/beat",
            Beat {
                interval_secs: 60,
                withhold: false,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(
        code, 403,
        "a beat needs an identity the transport bound; there is nothing to record against"
    );

    handle.abort();
}

#[tokio::test]
async fn a_withheld_record_is_hidden_from_others_but_not_its_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (_sk, seed, pk) = identity(31);
    let (_osk, other_seed, _opk) = identity(32);

    let (code, _) = beat(addr, &server_pub, &seed, 30, true).await;
    assert_eq!(code, 200);

    assert!(
        !read(addr, &server_pub, None, pk).await.found,
        "withheld: hidden from an anonymous caller"
    );
    assert!(
        !read(addr, &server_pub, Some(&other_seed), pk).await.found,
        "withheld: hidden from a different identity"
    );
    assert!(
        read(addr, &server_pub, Some(&seed), pk).await.found,
        "withheld: its owner may still read it"
    );

    handle.abort();
}

#[tokio::test]
async fn an_unseen_identity_reports_not_found_with_a_clock() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (_sk, _seed, never) = identity(41);
    let r = read(addr, &server_pub, None, never).await;
    assert!(!r.found);
    assert!(
        r.now > 0,
        "now is reported even for an identity never seen, so staleness is always interpretable"
    );

    handle.abort();
}

#[tokio::test]
async fn a_later_beat_updates_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (_sk, seed, pk) = identity(51);
    beat(addr, &server_pub, &seed, 60, false).await;
    beat(addr, &server_pub, &seed, 120, false).await;

    let r = read(addr, &server_pub, None, pk).await;
    assert_eq!(r.interval_secs, 120, "the latest declared interval wins");

    handle.abort();
}

#[tokio::test]
async fn a_malformed_beat_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;

    let (_sk, seed, _pk) = identity(61);
    let mut c = Client::connect_as(addr, &server_pub, &seed).await.unwrap();

    // A reserved flag bit set — SIP-4 says these MUST be zero.
    let (code, _) = c.post("/beacon/beat", vec![0x01, 0, 0, 0, 60, 0b10]).await.unwrap();
    assert_eq!(code, 400);

    // Wrong length.
    let (code, _) = c.post("/beacon/beat", vec![0x01, 0, 0]).await.unwrap();
    assert_eq!(code, 400);

    handle.abort();
}
