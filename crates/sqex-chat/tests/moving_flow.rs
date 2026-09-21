//! SIP-59: a client moves its account's home. Alice and Bob share a sealed
//! group at X; Alice moves to B with `Chat::move_home`, and at B her store
//! reads the group's history decrypted -- the keys moved with the rows --
//! and what she says there reaches Bob at X. A fresh store at B is the
//! control: the copy is there, and nothing in it can be read.

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
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32]) {
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nreplication_peers = [{list}]\nhome_secs = 1\n",
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

/// `exchange_in`, listening where told, so another exchange can be told
/// where to find it before it is up.
async fn exchange_at(
    dir: &Path,
    listen: SocketAddr,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32]) {
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nreplication_peers = [{list}]\nhome_secs = 1\n",
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

/// A client at an exchange it knows by `domain` -- which is what a move
/// hands the new home as the hint to find the old one by.
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
    chat
}

fn said(timeline: &Timeline) -> Vec<String> {
    timeline
        .messages()
        .filter(|m| m.is_visible())
        .filter_map(|m| m.post.body_text().map(|t| t.to_string()))
        .collect()
}

/// Poll until the timeline says all of `want`, in order.
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

#[tokio::test]
async fn a_moved_client_reads_its_sealed_history_at_the_new_home_and_is_heard_from_there() {
    let x_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let b_key = key_in(b_dir.path());
    let (x_addr, x_pub) = exchange_in(x_dir.path(), &[b_key], &[]).await;
    let x_key = PubKey::new(x_pub);
    let (b_addr, b_pub) = exchange_in(b_dir.path(), &[x_key], &[("x.test", x_key, x_addr)]).await;
    assert_eq!(PubKey::new(b_pub), b_key);
    let (_, alice) = identity(1);
    let (_, bob) = identity(2);
    let alice_store = x_dir.path().join("alice.db");
    let bob_store = x_dir.path().join("bob.db");

    // A sealed group at X with three messages in it, read by both.
    let mut bob_at_x = chat_at(x_addr, x_pub, "x.test", 2, &bob_store).await;
    let channel;
    {
        let mut alice_at_x = chat_at(x_addr, x_pub, "x.test", 1, &alice_store).await;
        channel = alice_at_x.create_group("us", &[bob]).await.unwrap();
        alice_at_x.send(&channel, "one").await.unwrap();
        let mut tb = Timeline::new();
        assert!(until(&mut bob_at_x, &channel, &mut tb, &["one"]).await);
        bob_at_x.send(&channel, "two").await.unwrap();
        let mut ta = Timeline::new();
        assert!(until(&mut alice_at_x, &channel, &mut ta, &["one", "two"]).await);
        alice_at_x.send(&channel, "three").await.unwrap();
        assert!(until(&mut alice_at_x, &channel, &mut ta, &["one", "two", "three"]).await);
        assert!(until(&mut bob_at_x, &channel, &mut tb, &["one", "two", "three"]).await);

        // Alice moves to B. X lists B, so the home's pulls will be served.
        let done = alice_at_x
            .move_home(b_addr, &b_key, "b.test", None)
            .await
            .unwrap();
        assert!(done.peered_here, "X did not say it lists B");
        assert!(done.refiled > 0, "nothing was re-filed under the new home");
        assert_eq!(done.left, 0);
    }

    // At B, the same store: the group is there and reads decrypted, and
    // nothing in it is judged forged -- it verifies under X, where it lives.
    let mut alice_at_b = chat_at(b_addr, b_pub, "b.test", 1, &alice_store).await;
    // As a restarted client does: the history from the store first -- which
    // is under the new home now, or this reads nothing -- then the exchange
    // from where the store left off.
    let mut ta = alice_at_b.history(&channel, &[alice]).unwrap();
    assert_eq!(
        said(&ta),
        ["one", "two", "three"],
        "the moved store did not hold its history under the new home"
    );
    assert!(
        until(&mut alice_at_b, &channel, &mut ta, &["one", "two", "three"]).await,
        "the copy at the new home did not serve the channel"
    );
    assert!(ta.forged().is_empty(), "{:?}", ta.forged());
    let home = alice_at_b.home(&channel).await.unwrap();
    assert_eq!((home.origin, home.domain.as_str()), (x_key, "x.test"));

    // The control: a store that did not move sees the copy and cannot read
    // a word of it.
    {
        let fresh = b_dir.path().join("alice-fresh.db");
        let mut stranger = chat_at(b_addr, b_pub, "b.test", 1, &fresh).await;
        let mut tf = Timeline::new();
        let mut readable = Vec::new();
        for _ in 0..10 {
            if let Ok(got) = stranger.poll(&channel, &mut tf, 0).await {
                readable = said(&got.timeline);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            readable.is_empty(),
            "a store without the keys read the sealed history: {readable:?}"
        );
    }

    // What Alice says at B is ordered at X and reaches Bob there; both
    // exchanges say where she lives.
    alice_at_b.send(&channel, "four").await.unwrap();
    let mut tb = bob_at_x.history(&channel, &[alice]).unwrap();
    assert!(
        until(
            &mut bob_at_x,
            &channel,
            &mut tb,
            &["one", "two", "three", "four"]
        )
        .await
    );
    assert!(tb.forged().is_empty(), "{:?}", tb.forged());
    assert!(
        until(
            &mut alice_at_b,
            &channel,
            &mut ta,
            &["one", "two", "three", "four"]
        )
        .await
    );

    let at_x = bob_at_x.account_home(&alice).await.unwrap();
    assert_eq!((at_x.home, at_x.domain.as_str()), (b_key, "b.test"));
    let at_b = alice_at_b.account_home(&alice).await.unwrap();
    assert_eq!(at_b.home, b_key);
    let bob_home = bob_at_x.account_home(&bob).await.unwrap();
    assert_eq!(bob_home.home, x_key);
}

/// SIP-60 §At a former home has a former home refuse a device's registration with `moved`;
/// a client moving *back* to a former home presents the Move first, so
/// the registration that follows lands at a home again.
#[tokio::test]
async fn a_client_can_move_back_to_a_former_home() {
    let x_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let x_key = key_in(x_dir.path());
    let b_key = key_in(b_dir.path());
    let (x_at, b_at): (SocketAddr, SocketAddr) = (
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap(),
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap(),
    );
    let (x_addr, x_pub) =
        exchange_at(x_dir.path(), x_at, &[b_key], &[("b.test", b_key, b_at)]).await;
    let (b_addr, b_pub) =
        exchange_at(b_dir.path(), b_at, &[x_key], &[("x.test", x_key, x_addr)]).await;
    let (seed, _) = identity(77);
    let store_path = x_dir.path().join("dana.db");
    let mut dana = chat_at(x_addr, x_pub, "x.test", 77, &store_path).await;
    dana.claim_home().await.unwrap();
    // She registers herself as her own device, as a client does.
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let me = dana.me;
    let cred = sqex_proto::credential::Credential::issue(
        &seed,
        &me,
        sqex_proto::credential::SCOPE_CHAT,
        n - 1,
        n + 3600,
    )
    .unwrap();
    dana.register_self(&cred).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    dana.move_home(b_addr, &b_key, "b.test", None)
        .await
        .unwrap();

    // And back. X is her former home until the Move lands there.
    let client = Client::connect_as(b_addr, &b_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(&store_path)).unwrap();
    let mut dana_at_b = Chat::new(client, seed, dana.me, PubKey::new(b_pub), store);
    dana_at_b.set_domain(Some("b.test".into()));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let back = dana_at_b.move_home(x_addr, &x_key, "x.test", None).await;
    assert!(
        back.is_ok(),
        "could not move back to a former home: {back:?}"
    );
}
