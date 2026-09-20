//! SIP-64 §Following: a home follows an origin's rotation, and an origin follows a
//! home's. Each holds the other's key for a domain; when the domain is
//! found naming another key, the successor is taken on the retiring key's
//! own signed word -- here its lineage (SIP-64), the window long closed --
//! and every holding of the old key becomes one of the new: the copies a
//! home pulls, and the account's signed Move at the origin, with its
//! signature cleared.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use ed25519_dalek::{Signer as _, SigningKey};
use sqex_discovery::Handover;
use sqex_proto::channel::{ByChannel, Entries, Fetch, Invitee, Role, TYPE_INFO, Visibility};
use sqex_proto::home::{Homed, Move, Moving};
use sqexd::config::FileConfig;
use sqexd::relay::Find;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

type Map = Arc<RwLock<HashMap<String, (PubKey, SocketAddr)>>>;

/// An exchange under whatever `host_key` is in `dir`, open to any peer,
/// finding domains through the shared `map` -- which the test changes
/// when an exchange rotates.
async fn exchange_in(
    dir: &Path,
    domain: &str,
    map: &Map,
) -> (SocketAddr, PubKey, tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        key_in(dir);
    }
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
         home_secs = 1\nlineage_retry_secs = 1\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind_with(config, None, signing_key, Find::Live(Arc::clone(map)))
        .await
        .unwrap();
    let addr = bound.local_addr;
    let key = bound.public_key;
    let task = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, key, task)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn key_in(dir: &Path) -> (PubKey, [u8; 32]) {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let seed = server_sk.to_bytes();
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    (PubKey::new(vk.to_bytes()), seed)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn handover(from_seed: &[u8; 32], to: &PubKey, domain: &str) -> Handover {
    let sk = SigningKey::from_bytes(from_seed);
    let from = PubKey::new(sk.verifying_key().to_bytes());
    let until = now() + 86_400;
    let sig = sk
        .sign(&Handover::signing_input(domain, &from, to, until))
        .to_bytes();
    Handover {
        from,
        to: *to,
        until,
        sig,
    }
}

/// Stop the exchange, give it a new key with a lineage from the old one,
/// bring it up on a fresh port, and point the shared map at it.
async fn rotate(
    dir: &Path,
    task: tokio::task::JoinHandle<()>,
    old_seed: &[u8; 32],
    domain: &str,
    map: &Map,
) -> (SocketAddr, PubKey, tokio::task::JoinHandle<()>) {
    task.abort();
    let _ = task.await;
    let (new_key, _) = key_in(dir);
    let mut text = std::fs::read_to_string(dir.join("lineage")).unwrap_or_default();
    text.push_str(&format!(
        "{domain} {}\n",
        handover(old_seed, &new_key, domain).render()
    ));
    std::fs::write(dir.join("lineage"), text).unwrap();
    let (addr, key, task) = exchange_in(dir, domain, map).await;
    assert_eq!(key, new_key);
    map.write().unwrap().insert(domain.to_string(), (key, addr));
    (addr, key, task)
}

async fn texts(c: &mut Client, channel: [u8; 32]) -> Vec<String> {
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

async fn watch<F: Fn(&[String]) -> bool>(
    c: &mut Client,
    channel: [u8; 32],
    rounds: usize,
    ok: F,
) -> Vec<String> {
    let mut last = Vec::new();
    for _ in 0..rounds {
        let (code, _) = c
            .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
            .await
            .unwrap();
        if code == 200 {
            last = texts(c, channel).await;
            if ok(&last) {
                return last;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    last
}

async fn home_of(c: &mut Client, account: &PubKey) -> Option<Homed> {
    let (code, body) = c
        .post("/account/home", account.as_bytes().to_vec())
        .await
        .unwrap();
    (code == 200).then(|| Homed::decode(&body).unwrap())
}

/// Alice's group at X, Bob in it, one post each.
async fn group_at(
    x_addr: SocketAddr,
    x_key: &PubKey,
    alice: ([u8; 32], PubKey),
    bob: ([u8; 32], PubKey),
    channel: [u8; 32],
) -> (Client, Chain) {
    let mut a = Client::connect_as(x_addr, x_key.as_bytes(), &alice.0)
        .await
        .unwrap();
    let sa = Signer::new(alice.0, alice.1, *x_key.as_bytes());
    let mut ca = Chain::default();
    let req = sa.create_chained(
        &mut ca,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "rotation",
        vec![Invitee {
            account: bob.1,
            role: Role::Member,
        }],
    );
    let (code, body) = a.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let info = sa.info(&mut a, channel).await;
    let post = sa.post_chained(&mut ca, channel, info.instance, 0, 0, b"one".to_vec());
    assert_eq!(a.post("/channel/post", post.encode()).await.unwrap().0, 200);
    let mut b = Client::connect_as(x_addr, x_key.as_bytes(), &bob.0)
        .await
        .unwrap();
    let sb = Signer::new(bob.0, bob.1, *x_key.as_bytes());
    let mut cb = Chain::default();
    let info = sb.info(&mut b, channel).await;
    let post = sb.post_chained(&mut cb, channel, info.instance, 0, 0, b"two".to_vec());
    assert_eq!(b.post("/channel/post", post.encode()).await.unwrap().0, 200);
    (b, cb)
}

/// A home that met the origin before it rotated goes on pulling after,
/// on the origin's lineage: Bob's post under the new key reaches Alice
/// at her home, beside the two receipted under the old one.
#[tokio::test]
async fn a_home_follows_the_origin_it_pulls_from() {
    let map: Map = Arc::new(RwLock::new(HashMap::new()));
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, x_seed) = key_in(x_dir.path());
    let (x_addr, up, x_task) = exchange_in(x_dir.path(), "x.test", &map).await;
    assert_eq!(up, x_key);
    map.write()
        .unwrap()
        .insert("x.test".into(), (x_key, x_addr));
    let (h_addr, h_key, _h_task) = exchange_in(h_dir.path(), "h.test", &map).await;
    map.write()
        .unwrap()
        .insert("h.test".into(), (h_key, h_addr));

    let (alice_seed, alice) = identity(251);
    let (bob_seed, bob) = identity(252);
    let channel = [251u8; 32];
    let (bob_at_x, mut cb) = group_at(
        x_addr,
        &x_key,
        (alice_seed, alice),
        (bob_seed, bob),
        channel,
    )
    .await;

    // Alice lives at H, which pulls her group from X under X's first key.
    let mut at_h = Client::connect_as(h_addr, h_key.as_bytes(), &alice_seed)
        .await
        .unwrap();
    let (code, body) = at_h
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &h_key, now()),
                domain: "h.test".into(),
                origins: vec![(x_key, "x.test".into())],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        watch(&mut at_h, channel, 60, |t| t.len() == 2).await,
        ["one", "two"]
    );

    // X rotates: a new key, the handover in its lineage, a fresh port,
    // and the domain now naming the new key. Bob posts under it.
    let (x_addr, x_new, _x_task) = rotate(x_dir.path(), x_task, &x_seed, "x.test", &map).await;
    assert_ne!(x_new, x_key);
    drop(bob_at_x);
    let mut bob_at_x = Client::connect_as(x_addr, x_new.as_bytes(), &bob_seed)
        .await
        .unwrap();
    let sb = Signer::new(bob_seed, bob, *x_new.as_bytes());
    let info = sb.info(&mut bob_at_x, channel).await;
    let post = sb.post_chained(&mut cb, channel, info.instance, 0, 1, b"three".to_vec());
    let (code, body) = bob_at_x.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // H's next reach finds x.test naming another key, asks its lineage,
    // finds the key it held among the earlier ones, and follows: the
    // third post arrives, and the first two still read.
    assert_eq!(
        watch(&mut at_h, channel, 150, |t| t.len() == 3).await,
        ["one", "two", "three"],
        "the home did not follow the origin's rotation"
    );
}

/// An origin holding an account's signed Move follows the home's
/// rotation: the Move is re-keyed with its signature cleared, the
/// acts-for gate opens to the new key, and the new key pulls what the
/// account is put in next.
#[tokio::test]
async fn an_origin_follows_the_home_an_account_named() {
    let map: Map = Arc::new(RwLock::new(HashMap::new()));
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_addr, x_key, _x_task) = exchange_in(x_dir.path(), "x.test", &map).await;
    map.write()
        .unwrap()
        .insert("x.test".into(), (x_key, x_addr));
    let (h_key, h_seed) = key_in(h_dir.path());
    let (h_addr, up, h_task) = exchange_in(h_dir.path(), "h.test", &map).await;
    assert_eq!(up, h_key);
    map.write()
        .unwrap()
        .insert("h.test".into(), (h_key, h_addr));

    let (alice_seed, alice) = identity(201);
    let (bob_seed, bob) = identity(202);
    let channel = [201u8; 32];
    let (mut bob_at_x, _cb) = group_at(
        x_addr,
        &x_key,
        (alice_seed, alice),
        (bob_seed, bob),
        channel,
    )
    .await;
    let mut at_h = Client::connect_as(h_addr, h_key.as_bytes(), &alice_seed)
        .await
        .unwrap();
    let (code, body) = at_h
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &h_key, now()),
                domain: "h.test".into(),
                origins: vec![(x_key, "x.test".into())],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        watch(&mut at_h, channel, 60, |t| t.len() == 2).await,
        ["one", "two"]
    );
    // X holds Alice's Move, carried by H, naming H's first key.
    let homed = home_of(&mut bob_at_x, &alice).await.unwrap();
    assert_eq!(homed.home, h_key);
    assert_ne!(homed.since, 0);

    // H rotates. On its own start it re-keys what it held for its earlier
    // key: Alice is homed at the new key there, signature cleared.
    let (h_addr, h_new, _h_task) = rotate(h_dir.path(), h_task, &h_seed, "h.test", &map).await;
    let mut at_h = Client::connect_as(h_addr, h_new.as_bytes(), &alice_seed)
        .await
        .unwrap();
    let homed = home_of(&mut at_h, &alice).await.unwrap();
    assert_eq!((homed.home, homed.since), (h_new, 0));

    // Bob puts Alice in a second group at X. X tells her home, finds h.test
    // naming another key, follows on H's lineage, and tells the new key;
    // which pulls the group -- X's gate opened to it -- and Alice reads.
    let sb = Signer::new(bob_seed, bob, *x_key.as_bytes());
    let second = [202u8; 32];
    let mut cb = Chain::default();
    let req = sb.create_chained(
        &mut cb,
        second,
        instance_for(second, 0),
        Visibility::Public,
        3600,
        "after",
        vec![Invitee {
            account: alice,
            role: Role::Member,
        }],
    );
    let (code, body) = bob_at_x
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let info = sb.info(&mut bob_at_x, second).await;
    let post = sb.post_chained(&mut cb, second, info.instance, 0, 0, b"after".to_vec());
    assert_eq!(
        bob_at_x
            .post("/channel/post", post.encode())
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        watch(&mut at_h, second, 150, |t| t.len() == 1).await,
        ["after"],
        "the origin did not follow the home's rotation"
    );
    let homed = home_of(&mut bob_at_x, &alice).await.unwrap();
    assert_eq!(
        (homed.home, homed.since),
        (h_new, 0),
        "the Move at the origin was not re-keyed with its signature cleared"
    );
}

/// A domain that names another key with no word from the key held is a
/// different exchange, and nothing follows.
#[tokio::test]
async fn a_domain_that_changed_hands_is_not_followed() {
    let map: Map = Arc::new(RwLock::new(HashMap::new()));
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (x_addr, _, x_task) = exchange_in(x_dir.path(), "x.test", &map).await;
    map.write()
        .unwrap()
        .insert("x.test".into(), (x_key, x_addr));
    let (h_addr, h_key, _h_task) = exchange_in(h_dir.path(), "h.test", &map).await;
    map.write()
        .unwrap()
        .insert("h.test".into(), (h_key, h_addr));
    let (alice_seed, alice) = identity(211);
    let (bob_seed, bob) = identity(212);
    let channel = [211u8; 32];
    let (bob_at_x, mut cb) = group_at(
        x_addr,
        &x_key,
        (alice_seed, alice),
        (bob_seed, bob),
        channel,
    )
    .await;
    let mut at_h = Client::connect_as(h_addr, h_key.as_bytes(), &alice_seed)
        .await
        .unwrap();
    let (code, _) = at_h
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &h_key, now()),
                domain: "h.test".into(),
                origins: vec![(x_key, "x.test".into())],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(
        watch(&mut at_h, channel, 60, |t| t.len() == 2).await,
        ["one", "two"]
    );

    // x.test changes hands: a new key, no handover, no lineage.
    x_task.abort();
    let _ = x_task.await;
    let (other, _) = key_in(x_dir.path());
    let _ = std::fs::remove_file(x_dir.path().join("lineage"));
    let (x_addr, up, _x_task) = exchange_in(x_dir.path(), "x.test", &map).await;
    assert_eq!(up, other);
    map.write()
        .unwrap()
        .insert("x.test".into(), (other, x_addr));
    drop(bob_at_x);
    let mut bob_at_x = Client::connect_as(x_addr, other.as_bytes(), &bob_seed)
        .await
        .unwrap();
    let sb = Signer::new(bob_seed, bob, *other.as_bytes());
    let info = sb.info(&mut bob_at_x, channel).await;
    let post = sb.post_chained(&mut cb, channel, info.instance, 0, 1, b"three".to_vec());
    assert_eq!(
        bob_at_x
            .post("/channel/post", post.encode())
            .await
            .unwrap()
            .0,
        200
    );
    let got = watch(&mut at_h, channel, 60, |t| t.len() == 3).await;
    assert_eq!(
        got,
        ["one", "two"],
        "a home followed a domain that merely changed hands"
    );
}

/// A configured origin is the operator's: its rotation is logged and not
/// followed, and the pull goes on being refused until `[[replicate]]`
/// says otherwise (SIP-40's `predecessors`).
#[tokio::test]
async fn a_configured_origin_is_left_to_the_operator() {
    let map: Map = Arc::new(RwLock::new(HashMap::new()));
    let x_dir = tempfile::tempdir().unwrap();
    let r_dir = tempfile::tempdir().unwrap();
    let (x_key, x_seed) = key_in(x_dir.path());
    let (x_addr, _, x_task) = exchange_in(x_dir.path(), "x.test", &map).await;
    map.write()
        .unwrap()
        .insert("x.test".into(), (x_key, x_addr));
    let (alice_seed, alice) = identity(221);
    let (bob_seed, bob) = identity(222);
    let channel = [221u8; 32];
    let (bob_at_x, _cb) = group_at(
        x_addr,
        &x_key,
        (alice_seed, alice),
        (bob_seed, bob),
        channel,
    )
    .await;
    drop(bob_at_x);

    // R replicates the channel from X by configuration, and Alice also
    // names X as an origin of hers by a Move -- so R reaches X both ways.
    // X authorises R for the channel (SIP-35 0x0b) so the configured pull
    // is served.
    let r_key = key_in(r_dir.path()).0;
    {
        let mut a = Client::connect_as(x_addr, x_key.as_bytes(), &alice_seed)
            .await
            .unwrap();
        let sa = Signer::new(alice_seed, alice, *x_key.as_bytes());
        let info = sa.info(&mut a, channel).await;
        let mut ca = Chain {
            seq: info.my_chain_seq,
            head: info.my_chain_head,
        };
        let action = sa.action_chained(
            &mut ca,
            channel,
            info.instance,
            sqex_proto::channel::EVENT_REPLICATE,
            &r_key,
            &[],
        );
        let (code, body) = a
            .post(
                "/channel/replicate",
                sqex_proto::channel::ByAccount {
                    channel,
                    account: r_key,
                    action,
                }
                .encode(sqex_proto::channel::TYPE_REPLICATE),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
    }
    let key_path = r_dir.path().join("host_key");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = \"r.test\"\nopen_peering = true\nhome_secs = 1\n\
         lineage_retry_secs = 1\n\n[[replicate]]\norigin = {:?}\naddr = {:?}\nchannels = [{:?}]\n\
         interval_secs = 1\ndomain = \"x.test\"\n",
        key_path.to_string_lossy(),
        r_dir.path().join("sqex.state").to_string_lossy(),
        x_key.to_string(),
        x_addr.to_string(),
        bs58::encode(channel).into_string(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind_with(config, None, signing_key, Find::Live(Arc::clone(&map)))
        .await
        .unwrap();
    let r_addr = bound.local_addr;
    assert_eq!(bound.public_key, r_key);
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    let mut at_r = Client::connect_as(r_addr, r_key.as_bytes(), &alice_seed)
        .await
        .unwrap();
    assert_eq!(
        watch(&mut at_r, channel, 60, |t| t.len() == 2).await,
        ["one", "two"]
    );
    // Alice also lives at R and names X as an origin, so R's home task
    // reaches X by the domain too -- the path that would follow.
    let (code, body) = at_r
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &r_key, now()),
                domain: "r.test".into(),
                origins: vec![(x_key, "x.test".into())],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // X rotates with a lineage. R, whose origin is configured, does not
    // follow: Bob's post under the new key never arrives.
    let (x_addr, x_new, _x_task) = rotate(x_dir.path(), x_task, &x_seed, "x.test", &map).await;
    let mut bob_at_x = Client::connect_as(x_addr, x_new.as_bytes(), &bob_seed)
        .await
        .unwrap();
    let sb = Signer::new(bob_seed, bob, *x_new.as_bytes());
    let info = sb.info(&mut bob_at_x, channel).await;
    let mut cb = Chain {
        seq: info.my_chain_seq,
        head: info.my_chain_head,
    };
    let post = sb.post_chained(&mut cb, channel, info.instance, 0, 1, b"three".to_vec());
    assert_eq!(
        bob_at_x
            .post("/channel/post", post.encode())
            .await
            .unwrap()
            .0,
        200
    );
    let got = watch(&mut at_r, channel, 100, |t| t.len() == 3).await;
    assert_eq!(
        got,
        ["one", "two"],
        "a configured origin's rotation was followed"
    );
}
