//! SIP-81 §Saying whose list it is: a client sealing a key to a member's devices waits when the
//! list its exchange has is stale -- the member lives at another exchange
//! this one could not ask -- and seals to the home's list when it can be.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::{Chat, ChatError};
use sqex_chat::store::Store;
use sqex_proto::home::{Move, Moving};
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Alice and Bob in a sealed group at X -- Bob's group, so Bob rotates --
/// with a message each way.
async fn alice_and_bob_at(
    x_addr: SocketAddr,
    x_pub: [u8; 32],
    dir: &Path,
    a: u8,
    b: u8,
) -> (Chat, Chat, [u8; 32]) {
    let (_, alice) = identity(a);
    let mut alicec = chat_at(x_addr, x_pub, "x.test", a, &dir.join("alice.db")).await;
    let mut bobc = chat_at(x_addr, x_pub, "x.test", b, &dir.join("bob.db")).await;
    let channel = bobc.create_group("us", &[alice]).await.unwrap();
    bobc.send(&channel, "one").await.unwrap();
    let mut ta = Timeline::new();
    assert!(until(&mut alicec, &channel, &mut ta, &["one"]).await);
    alicec.send(&channel, "two").await.unwrap();
    let mut tb = Timeline::new();
    assert!(until(&mut bobc, &channel, &mut tb, &["one", "two"]).await);
    (alicec, bobc, channel)
}

#[tokio::test]
async fn a_rotation_waits_while_a_members_home_cannot_be_asked() {
    let x_dir = tempfile::tempdir().unwrap();
    let g_dir = tempfile::tempdir().unwrap();
    let g_key = key_in(g_dir.path());
    // X knows where G would be; nothing listens there.
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        &[],
        &[("g.test", g_key, "127.0.0.1:1".parse().unwrap())],
    )
    .await;
    let (alice_seed, alice) = identity(61);
    let (_, bob) = identity(62);
    let x_key = PubKey::new(x_pub);
    let (mut alice_at_x, mut bob_at_x, channel) =
        alice_and_bob_at(x_addr, x_pub, x_dir.path(), 61, 62).await;
    // Both live at X, said so.
    for (c, who) in [(&mut alice_at_x, alice), (&mut bob_at_x, bob)] {
        c.present_move(&Moving {
            mv: Move::sign(c.account_seed().as_ref().unwrap(), &x_key, now()),
            domain: "x.test".into(),
            origins: vec![],
        })
        .await
        .unwrap();
        let _ = who;
    }
    let before = bob_at_x.rotate(&channel).await.unwrap();

    // Alice tells X she lives at G now. X cannot ask G, so the devices it
    // holds for her are the ones she had when she left.
    let mut raw = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let (code, _) = raw
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &g_key, now() + 1),
                domain: "g.test".into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // Bob's rotation waits rather than seal to that list...
    match bob_at_x.rotate(&channel).await {
        Err(ChatError::DevicesStale(who)) => assert_eq!(who, alice),
        other => panic!("the rotation did not wait on a stale list: {other:?}"),
    }
    // ...and the epoch stayed where it was; sending and reading go on.
    bob_at_x.send(&channel, "three").await.unwrap();
    // Fresh timelines: a poll answers from the cursor, so only the new one.
    let mut tb = Timeline::new();
    assert!(until(&mut bob_at_x, &channel, &mut tb, &["three"]).await);
    let mut ta = Timeline::new();
    let mut read = false;
    for _ in 0..60 {
        if let Ok(got) = alice_at_x.poll(&channel, &mut ta, 0).await
            && said(&got.timeline).last().map(String::as_str) == Some("three")
        {
            read = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(read, "Alice could not read on the epoch that stayed");
    let info_epoch = bob_at_x.rotate(&channel).await.err().is_some();
    assert!(
        info_epoch,
        "a second attempt went through with the home still away"
    );
    let _ = before;
}

#[tokio::test]
async fn a_rotation_seals_to_the_homes_list_when_it_answers() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let x_key = key_in(x_dir.path());
    let h_key = key_in(h_dir.path());
    let h_at: SocketAddr = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    };
    let (x_addr, x_pub) = exchange_in(x_dir.path(), &[], &[("h.test", h_key, h_at)]).await;
    // H listens where X expects it.
    let h_dir_path = h_dir.path().to_path_buf();
    let (h_addr, h_pub) = {
        let key_path = h_dir_path.join("host_key");
        let config_toml = format!(
            "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
             welcome_channel = \"\"\nreplication_peers = []\nhome_secs = 1\nopen_peering = true\n",
            h_at.to_string(),
            key_path.to_string_lossy(),
            h_dir_path.join("sqex.state").to_string_lossy(),
        );
        let file: FileConfig = toml::from_str(&config_toml).unwrap();
        let config = file.resolve().unwrap();
        let (signing_key, _pub) =
            squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
        let map = [("x.test".to_string(), (x_key, x_addr))]
            .into_iter()
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
    };
    assert_eq!(h_addr, h_at);
    let (mut alice_at_x, mut bob_at_x, channel) =
        alice_and_bob_at(x_addr, x_pub, x_dir.path(), 63, 64).await;
    alice_at_x
        .present_move(&Moving {
            mv: Move::sign(
                alice_at_x.account_seed().as_ref().unwrap(),
                &PubKey::new(x_pub),
                now(),
            ),
            domain: "x.test".into(),
            origins: vec![],
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    // Alice moves to H for real; X can ask H.
    let moved = alice_at_x
        .move_home(h_addr, &h_key, "h.test", None)
        .await
        .unwrap();
    assert!(moved.peered_at_home);
    // Her client starts at H, where her prekeys now live (SIP-23: a key is
    // sealed to a device through its pool, and X takes from the home).
    let mut alice_at_h = chat_at(h_addr, h_pub, "h.test", 63, &x_dir.path().join("alice.db")).await;
    let _ = alice_at_h.ensure_home().await.unwrap();
    // Bob's rotation seals to what H lists, and goes through.
    let epoch = bob_at_x.rotate(&channel).await.unwrap();
    assert!(epoch >= 1, "the rotation did not go through: {epoch}");
}
