//! SIP-85: the chat client reaches an exchange through its home. The
//! connection goes to the carrier's loopback socket with the target's key
//! pinned; the home carries it; and when the client starts over, the next
//! dial opens a fresh tunnel first, because a dial to the old carrier's
//! socket would reach nothing.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use sqex_chat::client::{Chat, Link};
use sqex_chat::store::Store;
use sqex_proto::home::{Move, Moving};
use sqex_proto::tunnel::Carrier;
use sqexd::config::FileConfig;
use sqexd::server::Server;
use sqnr::Client;
use sqnr_core::PubKey;

struct Exchange {
    addr: SocketAddr,
    key: [u8; 32],
    server: Arc<Server>,
    _dir: tempfile::TempDir,
}

async fn exchange(tunnel: bool, domain: &str, found: &[(&str, PubKey, SocketAddr)]) -> Exchange {
    for _ in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let listen = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let config_toml = format!(
            "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
             welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
             tunnel = {tunnel}\nhome_secs = 1\n",
            listen.to_string(),
            dir.path().join("host_key").to_string_lossy(),
            dir.path().join("sqex.state").to_string_lossy(),
        );
        key_in(dir.path());
        let file: FileConfig = toml::from_str(&config_toml).unwrap();
        let config = file.resolve().unwrap();
        let (signing_key, _pub) =
            squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
        let map = found
            .iter()
            .map(|(d, k, a)| ((*d).to_string(), (*k, *a)))
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

fn key_in(dir: &Path) {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn settle(chat: &mut Chat) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while chat.link() != Link::Up && Instant::now() < deadline {
        chat.keep_alive().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_client_through_its_home_comes_back_with_a_fresh_tunnel() {
    let b = exchange(false, "b.test", &[]).await;
    let a = exchange(true, "a.test", &[("b.test", PubKey::new(b.key), b.addr)]).await;
    let (seed, me) = identity(85);

    // Homed at A: a Move naming it, presented there.
    let mut at_a = Client::connect_as(a.addr, &a.key, &seed).await.unwrap();
    let (code, _) = at_a
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&seed, &PubKey::new(a.key), now()),
                domain: "a.test".into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let carrier = Carrier::open(a.addr, &a.key, &seed, &b.key, "b.test")
        .await
        .unwrap();
    let local = carrier.local_addr();
    let client = Client::connect_as(local, &b.key, &seed).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&seed, Some(&dir.path().join("chat.db"))).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(b.key), store);
    chat.dials(local, b.key);
    chat.via((a.addr, a.key), b.key, "b.test".into(), carrier);
    assert_eq!(chat.via_home(), Some(a.addr));

    chat.top_up_prekeys().await.unwrap();
    assert!(chat.mine().await.is_ok(), "B answers through the tunnel");
    assert_eq!(a.server.tunnels_open(), 1);
    let first = a.server.tunnel_sockets()[0];
    assert_eq!(
        b.server.last_peer_addr().map(|p| p.port()),
        Some(first.port())
    );
    // Transparent: B authenticated the member's own identity, carried
    // through the home, not anything of the home's.
    assert_eq!(b.server.last_peer_identity(), Some(me));

    // Starting over closes the tunnel held, and the next dial opens
    // another before it dials: a new socket at A, and B answers again.
    chat.reconnect_now();
    assert_ne!(chat.link(), Link::Up);
    for _ in 0..50 {
        if a.server.tunnels_open() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(a.server.tunnels_open(), 0, "the old tunnel closed");
    settle(&mut chat).await;
    assert_eq!(
        chat.link(),
        Link::Up,
        "never came back through a fresh tunnel"
    );
    assert!(chat.mine().await.is_ok(), "reconnected, and nothing works");
    assert_eq!(a.server.tunnels_open(), 1, "a fresh tunnel at A");
    let second = a.server.tunnel_sockets()[0];
    assert_ne!(first, second, "the second tunnel has its own socket");
    assert_eq!(
        b.server.last_peer_addr().map(|p| p.port()),
        Some(second.port()),
        "B saw the fresh tunnel's socket"
    );
}
