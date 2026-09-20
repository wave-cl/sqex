//! SIP-16 §Searching the federation: a search at one exchange lists its own rooms and its peers',
//! each row saying where the room lives and whether it is joinable here.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{Found, Search, Visibility};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::{PubKey, SignedTransaction, SoftwareSigner, Transaction};

use crate::common;
use crate::common::{Chain, Signer, instance_for};

async fn exchange_in(
    dir: &std::path::Path,
    found: &[(&str, PubKey, SocketAddr)],
    admin: PubKey,
) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = [\"{admin}\"]\n\
         welcome_channel = \"\"\ndirectory_secs = 1\n",
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn key_in(dir: &std::path::Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    PubKey::new(
        ed25519_dalek::SigningKey::from_bytes(&server_sk.to_bytes())
            .verifying_key()
            .to_bytes(),
    )
}

async fn label_peer(
    addr: SocketAddr,
    server_pub: [u8; 32],
    admin_seed: [u8; 32],
    key: PubKey,
    label: &str,
) {
    let mut c = Client::connect_as(addr, &server_pub, &admin_seed)
        .await
        .unwrap();
    let (cs, nonce_bytes) = c.get("/admin/challenge").await.unwrap();
    assert_eq!(cs, 200);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let txn = Transaction {
        server: PubKey::new(server_pub),
        nonce,
        ops: vec![
            sqex_proto::Op::PeerAdd {
                key,
                label: Some(label.into()),
            }
            .to_operation(),
        ],
    };
    let signer = SoftwareSigner::new(SigningKey::from_bytes(&admin_seed));
    let (code, body) = c
        .post(
            "/admin/command",
            SignedTransaction::create(txn, &signer).encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
}

async fn room(c: &mut Client, s: &Signer, channel: [u8; 32], name: &str) {
    let mut chain = Chain::default();
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        name,
        vec![],
    );
    let (code, body) = c.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn search(c: &mut Client, query: &str) -> Found {
    let (code, body) = c
        .post(
            "/channel/search",
            Search {
                offset: 0,
                query: query.into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Found::decode(&body).unwrap()
}

#[tokio::test]
async fn a_search_finds_rooms_at_peers_and_says_where_they_live() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let y_key = key_in(y_dir.path());
    let (admin_seed, admin) = identity(251);
    let (y_addr, y_pub) = exchange_in(y_dir.path(), &[], admin).await;
    let (x_addr, x_pub) = exchange_in(x_dir.path(), &[("y.test", y_key, y_addr)], admin).await;
    let x_key = PubKey::new(x_pub);
    // X federates with Y, by label; Y knows nobody.
    label_peer(x_addr, x_pub, admin_seed, y_key, "y.test").await;

    let (alice_seed, alice) = identity(252);
    let mut at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let mut at_y = Client::connect_as(y_addr, &y_pub, &alice_seed)
        .await
        .unwrap();
    room(
        &mut at_x,
        &Signer::new(alice_seed, alice, x_pub),
        [251u8; 32],
        "gardening",
    )
    .await;
    room(
        &mut at_y,
        &Signer::new(alice_seed, alice, y_pub),
        [252u8; 32],
        "garden birds",
    )
    .await;
    room(
        &mut at_y,
        &Signer::new(alice_seed, alice, y_pub),
        [253u8; 32],
        "trains",
    )
    .await;

    // At X: its own room, at home; Y's rooms, at Y, not joinable here.
    let mut found = None;
    for _ in 0..60 {
        let f = search(&mut at_x, "garden").await;
        if f.rows.len() == 2 {
            found = Some(f);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let f = found.expect("X never read Y's directory");
    assert_eq!(f.total, 2);
    let mine = f.rows.iter().find(|r| r.name == "gardening").unwrap();
    assert_eq!(
        (mine.home, mine.domain.as_str(), mine.here),
        (x_key, "", true)
    );
    let theirs = f.rows.iter().find(|r| r.name == "garden birds").unwrap();
    assert_eq!(
        (theirs.home, theirs.domain.as_str(), theirs.here),
        (y_key, "y.test", false)
    );
    assert_eq!(theirs.channel, [252u8; 32]);
    assert_eq!(f.rows[0].name, "gardening", "local rows come first");
    // The query is a filter across both.
    let all = search(&mut at_x, "").await;
    assert_eq!(all.total, 3);
    assert!(
        search(&mut at_x, "trains")
            .await
            .rows
            .iter()
            .all(|r| r.home == y_key)
    );

    // At Y, which federates with nobody: its own two, and nothing of X's.
    let f = search(&mut at_y, "").await;
    assert_eq!(f.total, 2);
    assert!(f.rows.iter().all(|r| r.here && r.home == y_key));
}
