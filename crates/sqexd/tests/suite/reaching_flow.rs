//! SIP-60: reaching someone at another exchange. Alice's home A locates
//! Bob at his home B, takes one of his prekeys through B, and -- when she
//! puts him in a channel at A -- tells B, which carries Bob's own Move to
//! A and pulls the channel for him. A direct message between them lives
//! at the lower key's home, created there from the other side.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByChannel, CreateAt, Entries, Fetch, Invitee, Role, TYPE_INFO, Visibility, direct_message_id,
};
use sqex_proto::home::{Move, Moving};
use sqex_proto::locate::{Locate, Located};
use sqex_proto::prekey::{Pool, Publish, Take, Taken};
use sqex_proto::refusal::{Code, Refusal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

/// An exchange that knows its own domain, federates with `peers` for
/// calls and replication both, and finds `found` without DNS.
pub(crate) async fn exchange_in(
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
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
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

pub(crate) fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

pub(crate) fn key_in(dir: &Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    PubKey::new(vk.to_bytes())
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(crate) async fn texts(c: &mut Client, channel: [u8; 32]) -> Vec<String> {
    let (code, body) = c
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since: 0,
                wait_secs: 0,
                receipts: true,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Entries::decode(&body, true)
        .unwrap()
        .entries
        .iter()
        .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .map(|e| String::from_utf8_lossy(&e.body).into_owned())
        .collect()
}

pub(crate) async fn until<F: Fn(&[String]) -> bool>(
    c: &mut Client,
    channel: [u8; 32],
    ok: F,
) -> Vec<String> {
    for _ in 0..80 {
        let (code, _) = c
            .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
            .await
            .unwrap();
        if code == 200 {
            let t = texts(c, channel).await;
            if ok(&t) {
                return t;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    panic!("the channel never showed what was expected");
}

/// A client says where it lives: a Move naming the exchange it is at.
pub(crate) async fn i_live_here(c: &mut Client, seed: &[u8; 32], here: PubKey, domain: &str) {
    let (code, body) = c
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(seed, &here, now()),
                domain: domain.into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

/// A loopback address nobody is listening on right now, so two exchanges
/// can each be told where the other will be before either is bound: a
/// finder is fixed at bind, and each needs the other's address in it.
pub(crate) fn free_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

/// Two federated exchanges, each knowing its own domain and finding the
/// other by its domain.
pub(crate) struct Pair {
    pub(crate) a_addr: SocketAddr,
    pub(crate) a_pub: [u8; 32],
    pub(crate) b_addr: SocketAddr,
    pub(crate) b_pub: [u8; 32],
    pub(crate) _dirs: (tempfile::TempDir, tempfile::TempDir),
}

pub(crate) async fn pair() -> Pair {
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
    assert_eq!((PubKey::new(a_pub), PubKey::new(b_pub)), (a_key, b_key));
    Pair {
        a_addr,
        a_pub,
        b_addr,
        b_pub,
        _dirs: (a_dir, b_dir),
    }
}

/// Alice at A locates Bob at B, takes one of his prekeys through A, and
/// invites him to a group at A; B is told, carries Bob's Move, pulls, and
/// Bob reads and answers from B.
#[tokio::test]
async fn an_invitation_reaches_the_invitees_home() {
    let p = pair().await;
    let (a_addr, a_pub, b_addr, b_pub) = (p.a_addr, p.a_pub, p.b_addr, p.b_pub);
    let b_key = PubKey::new(b_pub);

    let (alice_seed, alice) = identity(61);
    let (bob_seed, bob) = identity(62);
    let mut bob_at_b = Client::connect_as(b_addr, &b_pub, &bob_seed).await.unwrap();
    i_live_here(&mut bob_at_b, &bob_seed, b_key, "b.test").await;
    let mut pool = Pool::new(&bob_seed);
    let prekeys = pool.mint_one_time(2);
    let (code, _) = bob_at_b
        .post("/prekey/publish", Publish { prekeys }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);

    let mut alice_at_a = Client::connect_as(a_addr, &a_pub, &alice_seed)
        .await
        .unwrap();
    // Before locating, A knows nothing of Bob: no prekey, no home.
    let (code, body) = alice_at_a
        .post("/prekey/take", Take { device: bob }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(
        !Taken::decode(&body).unwrap().found,
        "A had a prekey of Bob's before locating him"
    );

    // Locate: by key at his domain.
    let (code, body) = alice_at_a
        .post(
            "/account/locate",
            Locate {
                target: format!("{bob}@b.test"),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let found = Located::decode(&body).unwrap();
    assert_eq!(
        (found.account, found.home, found.domain.as_str()),
        (bob, b_key, "b.test")
    );
    // A domain A does not federate with is refused, and one it cannot
    // find is not found.
    let (code, body) = alice_at_a
        .post(
            "/account/locate",
            Locate {
                target: format!("{bob}@nowhere.test"),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 404, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::NotFound);

    // Now a prekey of Bob's comes through A, from B's pool, once each.
    let (code, body) = alice_at_a
        .post("/prekey/take", Take { device: bob }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let taken = Taken::decode(&body).unwrap();
    assert!(taken.found, "no prekey came through");
    let first = taken.prekey.unwrap();
    let (_, body) = alice_at_a
        .post("/prekey/take", Take { device: bob }.encode())
        .await
        .unwrap();
    let second = Taken::decode(&body).unwrap().prekey.unwrap();
    assert_ne!(first.id, second.id, "the same prekey was served twice");
    let (_, body) = alice_at_a
        .post("/prekey/take", Take { device: bob }.encode())
        .await
        .unwrap();
    assert!(
        !Taken::decode(&body).unwrap().found,
        "B's pool of two served a third"
    );

    // Alice makes a group at A with Bob in it. A tells B; B carries Bob's
    // Move to A and pulls the group; Bob reads it at B.
    let sa = Signer::new(alice_seed, alice, a_pub);
    let mut ca = Chain::default();
    let channel = [61u8; 32];
    let req = sa.create_chained(
        &mut ca,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "reaching",
        vec![Invitee {
            account: bob,
            role: Role::Member,
        }],
    );
    let (code, body) = alice_at_a
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let info = sa.info(&mut alice_at_a, channel).await;
    let post = sa.post_chained(&mut ca, channel, info.instance, 0, 0, b"hello bob".to_vec());
    assert_eq!(
        alice_at_a
            .post("/channel/post", post.encode())
            .await
            .unwrap()
            .0,
        200
    );

    assert_eq!(
        until(&mut bob_at_b, channel, |t| t == ["hello bob"]).await,
        ["hello bob"]
    );
    // A holds Bob's Move now, carried by B; and Bob answers from B.
    let (code, body) = alice_at_a
        .post("/account/home", bob.as_bytes().to_vec())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(sqex_proto::home::Homed::decode(&body).unwrap().home, b_key);
    let sb = Signer::new(bob_seed, bob, a_pub);
    let mut cb = Chain::default();
    let info = sb.info(&mut bob_at_b, channel).await;
    let post = sb.post_chained(
        &mut cb,
        channel,
        info.instance,
        0,
        0,
        b"hello alice".to_vec(),
    );
    let (code, body) = bob_at_b.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        until(&mut alice_at_a, channel, |t| t.len() == 2).await,
        ["hello bob", "hello alice"]
    );
}

/// A direct message lives at the lower key's home. The party at the higher
/// key creates it there from their own exchange; their home is told and
/// pulls it; both read and write it where they are.
#[tokio::test]
async fn a_direct_message_lives_at_the_lower_keys_home() {
    let p = pair().await;
    let (a_addr, a_pub, b_addr, b_pub) = (p.a_addr, p.a_pub, p.b_addr, p.b_pub);
    let (a_key, b_key) = (PubKey::new(a_pub), PubKey::new(b_pub));

    // Pick the pair so that Bob (at B) holds the lower key.
    let (mut alice_seed, mut alice) = identity(63);
    let (mut bob_seed, mut bob) = identity(64);
    if alice.as_bytes() < bob.as_bytes() {
        std::mem::swap(&mut alice_seed, &mut bob_seed);
        std::mem::swap(&mut alice, &mut bob);
    }
    assert!(bob.as_bytes() < alice.as_bytes());
    let dm = direct_message_id(&alice, &bob);

    let mut bob_at_b = Client::connect_as(b_addr, &b_pub, &bob_seed).await.unwrap();
    i_live_here(&mut bob_at_b, &bob_seed, b_key, "b.test").await;
    let mut alice_at_a = Client::connect_as(a_addr, &a_pub, &alice_seed)
        .await
        .unwrap();
    i_live_here(&mut alice_at_a, &alice_seed, a_key, "a.test").await;
    // Alice locates Bob, learns his home is B, and creates the message
    // there -- signed under B, carried by A.
    let (code, body) = alice_at_a
        .post(
            "/account/locate",
            Locate {
                target: format!("{bob}@b.test"),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(Located::decode(&body).unwrap().home, b_key);

    let sa = Signer::new(alice_seed, alice, b_pub);
    let mut ca = Chain::default();
    let req = sa.create_chained(
        &mut ca,
        dm,
        instance_for(dm, 0),
        Visibility::Public,
        3600,
        "",
        vec![Invitee {
            account: bob,
            role: Role::Member,
        }],
    );
    let (code, body) = alice_at_a
        .post(
            "/channel/create_at",
            CreateAt {
                origin: b_key,
                create: req.encode(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // It lives at B: Bob reads it there at once, and A holds a copy for
    // Alice once B has told A.
    let (code, _) = bob_at_b
        .post("/channel/info", ByChannel { channel: dm }.encode(TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(code, 200, "the message was not created at Bob's home");
    let sb = Signer::new(bob_seed, bob, b_pub);
    let mut cb = Chain::default();
    let info = sb.info(&mut bob_at_b, dm).await;
    let post = sb.post_chained(&mut cb, dm, info.instance, 0, 0, b"hi from b".to_vec());
    assert_eq!(
        bob_at_b
            .post("/channel/post", post.encode())
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        until(&mut alice_at_a, dm, |t| t == ["hi from b"]).await,
        ["hi from b"]
    );
    let (_, body) = alice_at_a
        .post(
            "/channel/home",
            ByChannel { channel: dm }.encode(sqex_proto::channel::TYPE_HOME),
        )
        .await
        .unwrap();
    let home = sqex_proto::channel::Home::decode(&body).unwrap();
    assert_eq!((home.origin, home.domain.as_str()), (b_key, "b.test"));

    // Alice writes from A; it is ordered at B and Bob reads it there.
    let info = sa.info(&mut alice_at_a, dm).await;
    let post = sa.post_chained(&mut ca, dm, info.instance, 0, 0, b"hi from a".to_vec());
    let (code, body) = alice_at_a
        .post("/channel/post", post.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        until(&mut bob_at_b, dm, |t| t.len() == 2).await,
        ["hi from b", "hi from a"]
    );
}
