//! SIP-53: a channel's origin moves to a replica. Planned, from the origin:
//! the origin closes to writes, the replica orders from there, and a third
//! exchange follows. Unplanned, the origin gone: the admin posts the move at
//! the replica once the origin has been away long enough, and an origin
//! that comes back is told and follows, stranding what only it ordered.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByAccount, ByChannel, EVENT_REHOMED, EVENT_REPLICATE, Entries, Fetch, Home, Rehome, Rehomed,
    Stranded, TYPE_HOME, TYPE_REPLICATE, TYPE_STRANDED, Visibility,
};
use sqex_proto::refusal::{Code, Refusal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

/// An origin whose peering whitelist holds `peers`, with a finder that
/// knows `found`, closable to simulate its going.
async fn origin_in(
    dir: &Path,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32], std::sync::Arc<squic::ServerListener>) {
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
         welcome_channel = \"\"\nreplication_peers = [{list}]\n",
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
    let listener = std::sync::Arc::clone(&bound.listener);
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, listener)
}

/// A replica of `channel` at `origin`, itself peering with `peers`, with a
/// finder that knows `found`, and taking a rehome after `away_secs`.
#[allow(clippy::too_many_arguments)]
async fn replica_in(
    dir: &Path,
    origin: PubKey,
    origin_addr: SocketAddr,
    channel: [u8; 32],
    domain: &str,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
    away_secs: u64,
) -> (SocketAddr, [u8; 32], std::sync::Arc<squic::ServerListener>) {
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
         welcome_channel = \"\"\nreplication_peers = [{list}]\nrehome_away_secs = {away_secs}\n\n\
         [[replicate]]\norigin = {:?}\naddr = {:?}\nchannels = [{:?}]\ninterval_secs = 1\n\
         domain = {:?}\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
        origin.to_string(),
        origin_addr.to_string(),
        bs58::encode(channel).into_string(),
        domain,
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
    let listener = std::sync::Arc::clone(&bound.listener);
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, listener)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn key_in(dir: &Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = ed25519_dalek::SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    PubKey::new(vk.to_bytes())
}

async fn home_of(c: &mut Client, channel: [u8; 32]) -> Home {
    let (code, body) = c
        .post("/channel/home", ByChannel { channel }.encode(TYPE_HOME))
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Home::decode(&body).unwrap()
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

async fn until<F: Fn(&[String]) -> bool>(c: &mut Client, channel: [u8; 32], ok: F) -> Vec<String> {
    for _ in 0..80 {
        let (code, _) = c
            .post(
                "/channel/info",
                ByChannel { channel }.encode(sqex_proto::channel::TYPE_INFO),
            )
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

async fn rehome(
    c: &mut Client,
    s: &Signer,
    chain: &mut Chain,
    channel: [u8; 32],
    subject: PubKey,
    domain: &str,
) -> (u16, Vec<u8>) {
    let action = s.action_chained(
        chain,
        channel,
        instance_for(channel, 0),
        EVENT_REHOMED,
        &subject,
        &[],
    );
    c.post(
        "/channel/rehome",
        Rehome {
            channel,
            subject,
            domain: domain.into(),
            action,
        }
        .encode(),
    )
    .await
    .unwrap()
}

/// A planned move: the origin closes, the named replica orders from there,
/// and a second replica that pulled from the origin follows to the new one.
#[tokio::test]
async fn a_planned_move_closes_the_origin_and_the_replica_orders_from_there() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let z_dir = tempfile::tempdir().unwrap();
    let y_key = key_in(y_dir.path());
    let z_key = key_in(z_dir.path());
    let (x_addr, x_pub, _x_l) = origin_in(x_dir.path(), &[y_key, z_key], &[]).await;
    let x_key = PubKey::new(x_pub);
    let (alice_seed, alice) = identity(221);
    let channel = [221u8; 32];

    let mut a = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let s = Signer::new(alice_seed, alice, x_pub);
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
    for who in [y_key, z_key] {
        let action = s.action_chained(
            &mut chain,
            channel,
            instance_for(channel, 0),
            EVENT_REPLICATE,
            &who,
            &[],
        );
        let (code, body) = a
            .post(
                "/channel/replicate",
                ByAccount {
                    channel,
                    account: who,
                    action,
                }
                .encode(TYPE_REPLICATE),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
    }
    let info = s.info(&mut a, channel).await;
    let post = s.post_chained(&mut chain, channel, info.instance, 0, 0, b"at x".to_vec());
    assert_eq!(a.post("/channel/post", post.encode()).await.unwrap().0, 200);

    // Y and Z replicate from X. Y is where the channel will go: X and Z
    // know Y's domain, so they can find it after the move.
    let (y_addr, y_pub, _y_l) = replica_in(
        y_dir.path(),
        x_key,
        x_addr,
        channel,
        "x.test",
        &[x_key, z_key],
        &[],
        300,
    )
    .await;
    assert_eq!(PubKey::new(y_pub), y_key);
    let (z_addr, z_pub, _z_l) = replica_in(
        z_dir.path(),
        x_key,
        x_addr,
        channel,
        "x.test",
        &[x_key, y_key],
        &[("y.test", y_key, y_addr)],
        300,
    )
    .await;
    let mut at_y = Client::connect_as(y_addr, &y_pub, &alice_seed)
        .await
        .unwrap();
    let mut at_z = Client::connect_as(z_addr, &z_pub, &alice_seed)
        .await
        .unwrap();
    until(&mut at_y, channel, |t| t == ["at x"]).await;
    until(&mut at_z, channel, |t| t == ["at x"]).await;

    // Not to a stranger, and not while a replica is asked to rehome
    // elsewhere; then the move, from the origin, to Y.
    let (_, stranger) = identity(229);
    let before = Chain { ..chain };
    let (code, body) = rehome(&mut a, &s, &mut chain, channel, stranger, "").await;
    assert_eq!(code, 409, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::NotAReplica);
    // A refused action spent no chain step at the exchange.
    chain = before;
    let (code, body) = rehome(&mut a, &s, &mut chain, channel, y_key, "y.test").await;
    assert_eq!(code, 200, "{}", common::said(&body));

    // X is closed to writes and says where the channel went.
    let info = s.info(&mut a, channel).await;
    let before = Chain { ..chain };
    let post = s.post_chained(
        &mut chain,
        channel,
        info.instance,
        0,
        0,
        b"too late".to_vec(),
    );
    let (code, body) = a.post("/channel/post", post.encode()).await.unwrap();
    assert_ne!(code, 200, "the old origin still took a post");
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::Replicated);
    chain = before;
    let home = home_of(&mut a, channel).await;
    assert_eq!((home.origin, home.domain.as_str()), (y_key, "y.test"));

    // Y pulls the rehome and is the origin: it orders a post signed under
    // it, and says so of itself.
    let sy = Signer::new(alice_seed, alice, y_pub);
    let mut posted = false;
    for _ in 0..80 {
        let home = home_of(&mut at_y, channel).await;
        if home.origin == y_key {
            posted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    assert!(posted, "Y never became the origin");
    let info = sy.info(&mut at_y, channel).await;
    let post = sy.post_chained(&mut chain, channel, info.instance, 0, 0, b"at y".to_vec());
    let (code, body) = at_y.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(texts(&mut at_y, channel).await, ["at x", "at y"]);

    // Z pulled the rehome from X, followed it to Y by the domain, and holds
    // what Y ordered.
    let got = until(&mut at_z, channel, |t| t.len() == 2).await;
    assert_eq!(got, ["at x", "at y"]);
    let home = home_of(&mut at_z, channel).await;
    assert_eq!(home.origin, y_key);
}

/// The origin is gone: the admin moves the channel to the replica they
/// are at, once it has been away long enough -- and not before. The old
/// origin, back and told, follows and strands what only it ordered.
#[tokio::test]
async fn a_replica_takes_a_channel_whose_origin_is_gone_and_the_origin_follows_when_told() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let y_key = key_in(y_dir.path());
    let (x_addr, x_pub, x_listener) = origin_in(x_dir.path(), &[y_key], &[]).await;
    let x_key = PubKey::new(x_pub);
    let (alice_seed, alice) = identity(231);
    let channel = [231u8; 32];

    let mut a = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let s = Signer::new(alice_seed, alice, x_pub);
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
    assert_eq!(
        a.post("/channel/create", req.encode()).await.unwrap().0,
        200
    );
    let action = s.action_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        EVENT_REPLICATE,
        &y_key,
        &[],
    );
    let (code, _) = a
        .post(
            "/channel/replicate",
            ByAccount {
                channel,
                account: y_key,
                action,
            }
            .encode(TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let info = s.info(&mut a, channel).await;
    let post = s.post_chained(&mut chain, channel, info.instance, 0, 0, b"before".to_vec());
    assert_eq!(a.post("/channel/post", post.encode()).await.unwrap().0, 200);

    // Y replicates, and would take a rehome after two seconds away.
    let (y_addr, y_pub, _y_l) = replica_in(
        y_dir.path(),
        x_key,
        x_addr,
        channel,
        "x.test",
        &[x_key],
        &[],
        2,
    )
    .await;
    let mut at_y = Client::connect_as(y_addr, &y_pub, &alice_seed)
        .await
        .unwrap();
    until(&mut at_y, channel, |t| t == ["before"]).await;

    // Too soon: X is reachable.
    let before = Chain { ..chain };
    let (code, body) = rehome(&mut at_y, &s, &mut chain, channel, y_key, "y.test").await;
    assert_eq!(code, 409, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::OriginReachable);
    chain = before;

    // X orders one more entry Y never sees, then goes.
    let info = s.info(&mut a, channel).await;
    let post = s.post_chained(&mut chain, channel, info.instance, 0, 0, b"only x".to_vec());
    assert_eq!(a.post("/channel/post", post.encode()).await.unwrap().0, 200);
    drop(a);
    x_listener.close(quinn::VarInt::from_u32(0), b"gone");
    // Y's copy stays at "before": it stopped pulling when X went.
    tokio::time::sleep(std::time::Duration::from_millis(3200)).await;

    // The admin's chain as Y knows it ends at "before": their own record
    // ran one step ahead at X, and that step is what will be stranded. It
    // is rebuilt from Y's entries, which is what a client with a fresh
    // store does (SIP-43).
    let mut chain_y = Chain::default();
    // Replay the admin's chain up to what Y holds, from Y's entries.
    let (code, body) = at_y
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
    assert_eq!(code, 200);
    let held = Entries::decode(&body, true).unwrap();
    for e in &held.entries {
        if e.device == alice {
            chain_y.seq = e.chain_seq + 1;
            chain_y.head = sqexd::replica::entry_hash_of(
                &sqex_proto::entry_sig::Place {
                    exchange: x_key,
                    instance: instance_for(channel, 0),
                    channel,
                },
                e,
            );
        }
    }
    // Now Y takes it: signed under X, receipted by Y, and Y is the origin.
    let (code, body) = rehome(&mut at_y, &s, &mut chain_y, channel, y_key, "y.test").await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let home = home_of(&mut at_y, channel).await;
    assert_eq!(home.origin, y_key);
    let sy = Signer::new(alice_seed, alice, y_pub);
    let info = sy.info(&mut at_y, channel).await;
    let post = sy.post_chained(&mut chain_y, channel, info.instance, 0, 0, b"at y".to_vec());
    let (code, body) = at_y.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(texts(&mut at_y, channel).await, ["before", "at y"]);

    // X comes back on the same store, holding "only x". A client carries
    // the rehome to it: X strands "only x", follows Y, and shows the
    // conversation as Y orders it.
    let (x_addr2, x_pub2, _x_l2) =
        origin_in(x_dir.path(), &[y_key], &[("y.test", y_key, y_addr)]).await;
    assert_eq!(x_pub2, x_pub);
    let mut a2 = Client::connect_as(x_addr2, &x_pub, &alice_seed)
        .await
        .unwrap();
    assert_eq!(texts(&mut a2, channel).await, ["before", "only x"]);
    let (code, body) = at_y
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
    assert_eq!(code, 200);
    let entry = Entries::decode(&body, true)
        .unwrap()
        .entries
        .into_iter()
        .find(|e| {
            e.kind == sqex_proto::channel::KIND_SYSTEM
                && sqex_proto::channel::System::decode(&e.body)
                    .ok()
                    .flatten()
                    .is_some_and(|s| s.event == EVENT_REHOMED)
        })
        .expect("Y holds the rehome entry");
    let (code, body) = a2
        .post(
            "/channel/rehomed",
            Rehomed {
                channel,
                domain: "y.test".into(),
                entry,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let home = home_of(&mut a2, channel).await;
    assert_eq!((home.origin, home.domain.as_str()), (y_key, "y.test"));
    // Truncated at the fork, closed to writes; nothing pulled from Y, since
    // no `0x0b` in the log names X.
    assert_eq!(texts(&mut a2, channel).await, ["before"]);
    let info = s.info(&mut a2, channel).await;
    let post = s.post_chained(
        &mut chain,
        channel,
        info.instance,
        0,
        0,
        b"still at x".to_vec(),
    );
    let (code, body) = a2.post("/channel/post", post.encode()).await.unwrap();
    assert_ne!(code, 200);
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::Replicated);
    let (code, body) = a2
        .post(
            "/channel/stranded",
            ByChannel { channel }.encode(TYPE_STRANDED),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let stranded = Stranded::decode(&body).unwrap();
    assert_eq!(stranded.entries.len(), 1);
    assert_eq!(stranded.entries[0].2, b"only x");
}
