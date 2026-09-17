//! SIP-60: a client reaches somebody whose home is another exchange. Alice
//! at A locates Bob at B and opens a sealed direct message with him; it
//! lives at the lower key's home, each of them reads and writes it where
//! they are, and the epoch key crosses through the proxied prekey. Both
//! orderings of the two keys are run, since they take different paths.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn exchange_in(
    dir: &Path,
    listen: SocketAddr,
    domain: &str,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32]) {
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let key_path = dir.join("host_key");
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\nreplication_peers = [{list}]\n\
         seed_relay_peers = [{list}]\nhome_secs = 1\n",
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
    let bound = sqexd::bind_with(config, None, signing_key, sqexd::relay::Find::Fixed(map))
        .await
        .unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
}

fn key_in(dir: &Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    PubKey::new(vk.to_bytes())
}

fn free_port() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn chat_at(
    addr: SocketAddr,
    server_pub: [u8; 32],
    domain: &str,
    b: u8,
    store_path: &Path,
) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.set_domain(Some(domain.to_string()));
    chat.top_up_prekeys().await.unwrap();
    assert!(chat.ensure_home().await.unwrap(), "no move was presented");
    assert!(
        !chat.ensure_home().await.unwrap(),
        "a second move was presented"
    );
    chat
}

fn said(timeline: &Timeline) -> Vec<String> {
    timeline
        .messages()
        .filter(|m| m.is_visible())
        .filter_map(|m| m.post.body_text().map(|t| t.to_string()))
        .collect()
}

async fn until(chat: &mut Chat, channel: &[u8; 32], t: &mut Timeline, want: &[&str]) -> bool {
    let mut last = String::new();
    for _ in 0..60 {
        match chat.poll(channel, t, 0).await {
            Ok(got) => {
                if said(&got.timeline) == want {
                    return true;
                }
                last = format!("{:?} forged {:?}", said(&got.timeline), t.forged());
            }
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    eprintln!("wanted {want:?}, last saw {last}");
    false
}

/// Alice (identity `a`) at A and Bob (identity `b`) at B talk. Says which
/// exchange the message ended up living at.
async fn conversation(a: u8, b: u8) -> (PubKey, PubKey, PubKey) {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_key = key_in(a_dir.path());
    let b_key = key_in(b_dir.path());
    let (a_at, b_at) = (free_port(), free_port());
    let (a_addr, a_pub) = exchange_in(
        a_dir.path(),
        a_at,
        "a.test",
        &[b_key],
        &[("b.test", b_key, b_at)],
    )
    .await;
    let (b_addr, b_pub) = exchange_in(
        b_dir.path(),
        b_at,
        "b.test",
        &[a_key],
        &[("a.test", a_key, a_at)],
    )
    .await;
    let (_, bob) = identity(b);

    let mut bob_at_b = chat_at(b_addr, b_pub, "b.test", b, &b_dir.path().join("bob.db")).await;
    let mut alice_at_a = chat_at(a_addr, a_pub, "a.test", a, &a_dir.path().join("alice.db")).await;

    // Alice finds Bob through her exchange and opens the message; it is
    // sealed, so the epoch key is minted to a prekey of Bob's that came
    // through A from B's pool.
    let found = alice_at_a.locate(&format!("{bob}@b.test")).await.unwrap();
    assert_eq!((found.account, found.home), (bob, b_key));
    let dm = alice_at_a.open_dm(&bob).await.unwrap();
    alice_at_a.send(&dm, "hello from a").await.unwrap();

    let mut tb = Timeline::new();
    assert!(until(&mut bob_at_b, &dm, &mut tb, &["hello from a"]).await);
    assert!(tb.forged().is_empty(), "{:?}", tb.forged());
    bob_at_b.send(&dm, "hello from b").await.unwrap();
    let mut ta = Timeline::new();
    assert!(
        until(
            &mut alice_at_a,
            &dm,
            &mut ta,
            &["hello from a", "hello from b"]
        )
        .await
    );
    assert!(ta.forged().is_empty(), "{:?}", ta.forged());

    let home = alice_at_a.home(&dm).await.unwrap();
    let bobs = bob_at_b.home(&dm).await.unwrap();
    assert_eq!(
        home.origin, bobs.origin,
        "the two clients disagree where it lives"
    );
    (home.origin, a_key, b_key)
}

#[tokio::test]
async fn a_direct_message_with_a_lower_key_elsewhere_lives_there() {
    let (mut a, mut b) = (71u8, 72u8);
    if identity(a).1.as_bytes() < identity(b).1.as_bytes() {
        std::mem::swap(&mut a, &mut b);
    }
    // Bob holds the lower key: the message lives at B, created from A.
    let (origin, _a_key, b_key) = conversation(a, b).await;
    assert_eq!(origin, b_key);
}

#[tokio::test]
async fn a_direct_message_with_a_lower_key_here_lives_here() {
    let (mut a, mut b) = (73u8, 74u8);
    if identity(a).1.as_bytes() > identity(b).1.as_bytes() {
        std::mem::swap(&mut a, &mut b);
    }
    // Alice holds the lower key: the message lives at A, and B is told.
    let (origin, a_key, _b_key) = conversation(a, b).await;
    assert_eq!(origin, a_key);
}
