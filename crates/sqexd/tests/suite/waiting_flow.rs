//! SIP-35 §Waiting: a replica waits on the origin instead of polling. On the wire,
//! `/peer/wait` answers at once for a channel with an entry past `since`,
//! within a second for one that gains an entry or a signal, with nothing
//! when the wait runs out, and never about a channel the peer may not
//! pull. End to end, a replica pulling on a twenty-second interval shows a
//! post made at the origin within a couple of seconds.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByChannel, EVENT_REPLICATE, Entries, Fetch, SignalOut, TYPE_INFO, TYPE_REPLICATE, Visibility,
};
use sqex_proto::message::SIGNAL_TYPING;
use sqex_proto::peer::{Changed, PeerWait};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

async fn origin_in(dir: &Path, peers: &[PubKey]) -> (SocketAddr, [u8; 32]) {
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nreplication_peers = [{list}]\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    serve(dir, &config_toml).await
}

/// A replica of `channel` pulling every `interval_secs` -- long, so that
/// anything that arrives sooner arrived by waiting.
async fn replica_in(
    dir: &Path,
    origin: PubKey,
    origin_addr: SocketAddr,
    channel: [u8; 32],
    interval_secs: u64,
) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n\n[[replicate]]\norigin = {:?}\naddr = {:?}\n\
         channels = [{:?}]\ninterval_secs = {interval_secs}\ndomain = \"x.test\"\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
        origin.to_string(),
        origin_addr.to_string(),
        bs58::encode(channel).into_string(),
    );
    serve(dir, &config_toml).await
}

async fn serve(dir: &Path, config_toml: &str) -> (SocketAddr, [u8; 32]) {
    let config_path = dir.join("sqexd.toml");
    std::fs::write(&config_path, config_toml).unwrap();
    let file: FileConfig = toml::from_str(config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, Some(config_path), signing_key)
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

fn key_in(dir: &Path) -> (PubKey, [u8; 32]) {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    (PubKey::new(vk.to_bytes()), server_sk.to_bytes())
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

/// Poll a channel at a replica until it says `want`; how long that took.
async fn until(c: &mut Client, channel: [u8; 32], want: &[&str]) -> Duration {
    let started = Instant::now();
    for _ in 0..200 {
        let (code, _) = c
            .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
            .await
            .unwrap();
        if code == 200 && texts(c, channel).await == want {
            return started.elapsed();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the replica never showed {want:?}");
}

async fn wait(c: &mut Client, channels: Vec<([u8; 32], u64)>, secs: u16) -> (Duration, Changed) {
    let started = Instant::now();
    let (code, body) = c
        .post(
            "/peer/wait",
            PeerWait {
                wait_secs: secs,
                channels,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    (started.elapsed(), Changed::decode(&body).unwrap())
}

/// A public channel at X, authorised to `replica`, with `n` posts in it.
async fn channel_at(
    x: &mut Client,
    s: &Signer,
    chain: &mut Chain,
    channel: [u8; 32],
    replica: PubKey,
    posts: &[&str],
) {
    let req = s.create_chained(
        chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "waiting",
        vec![],
    );
    assert_eq!(
        x.post("/channel/create", req.encode()).await.unwrap().0,
        200
    );
    let action = s.action_chained(
        chain,
        channel,
        instance_for(channel, 0),
        EVENT_REPLICATE,
        &replica,
        &[],
    );
    let (code, body) = x
        .post(
            "/channel/replicate",
            sqex_proto::channel::ByAccount {
                channel,
                account: replica,
                action,
            }
            .encode(TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    for (i, text) in posts.iter().enumerate() {
        let info = s.info(x, channel).await;
        let post = s.post_chained(
            chain,
            channel,
            info.instance,
            0,
            i as u64,
            text.as_bytes().to_vec(),
        );
        assert_eq!(x.post("/channel/post", post.encode()).await.unwrap().0, 200);
    }
}

#[tokio::test]
async fn a_wait_answers_when_a_channel_changes_and_says_nothing_of_the_rest() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let (y_key, y_seed) = key_in(y_dir.path());
    let (x_addr, x_pub) = origin_in(x_dir.path(), &[y_key]).await;
    let (alice_seed, alice) = identity(81);
    let mut a = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let s = Signer::new(alice_seed, alice, x_pub);
    let mut chain = Chain::default();
    let open = [81u8; 32];
    channel_at(&mut a, &s, &mut chain, open, y_key, &["one"]).await;
    // A second channel Y is not authorised for.
    let mut chain2 = Chain::default();
    let closed = [82u8; 32];
    let req = s.create_chained(
        &mut chain2,
        closed,
        instance_for(closed, 0),
        Visibility::Public,
        3600,
        "closed",
        vec![],
    );
    assert_eq!(
        a.post("/channel/create", req.encode()).await.unwrap().0,
        200
    );
    let last = s.info(&mut a, open).await.last;

    let mut as_y = Client::connect_as(x_addr, &x_pub, &y_seed).await.unwrap();
    // Behind: answered at once, naming the channel.
    let (took, changed) = wait(&mut as_y, vec![(open, 0)], 5).await;
    assert_eq!(changed.channels, vec![open]);
    assert!(
        took < Duration::from_secs(1),
        "a wait with something to say slept: {took:?}"
    );
    // Up to date, nothing happens: the wait runs out empty.
    let (took, changed) = wait(&mut as_y, vec![(open, last)], 1).await;
    assert!(changed.channels.is_empty());
    assert!(
        took >= Duration::from_millis(900),
        "the wait answered early: {took:?}"
    );
    // A channel the peer may not pull is never named, even when behind.
    let (_, changed) = wait(&mut as_y, vec![(closed, 0)], 1).await;
    assert!(
        changed.channels.is_empty(),
        "a wait named a channel the peer may not pull"
    );

    // Up to date, and a post lands during the wait: answered within the
    // second, well before the five it was allowed.
    let poster = {
        let mut a2 = Client::connect_as(x_addr, &x_pub, &alice_seed)
            .await
            .unwrap();
        let s2 = s;
        let mut chain = Chain { ..chain };
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let info = s2.info(&mut a2, open).await;
            let post = s2.post_chained(&mut chain, open, info.instance, 0, 1, b"two".to_vec());
            assert_eq!(
                a2.post("/channel/post", post.encode()).await.unwrap().0,
                200
            );
        })
    };
    let (took, changed) = wait(&mut as_y, vec![(open, last), (closed, 0)], 5).await;
    poster.await.unwrap();
    assert_eq!(changed.channels, vec![open]);
    assert!(
        took < Duration::from_secs(2),
        "the wait did not wake on the post: {took:?}"
    );
    let last = s.info(&mut a, open).await.last;

    // A signal wakes it too, with nothing new to pull but the signal.
    let signaller = {
        let mut a3 = Client::connect_as(x_addr, &x_pub, &alice_seed)
            .await
            .unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let (code, _) = a3
                .post(
                    "/channel/signal",
                    SignalOut {
                        channel: open,
                        kind: SIGNAL_TYPING,
                        body: vec![1],
                    }
                    .encode(),
                )
                .await
                .unwrap();
            assert_eq!(code, 200);
        })
    };
    let (took, changed) = wait(&mut as_y, vec![(open, last)], 5).await;
    signaller.await.unwrap();
    assert_eq!(changed.channels, vec![open]);
    assert!(
        took < Duration::from_secs(2),
        "the wait did not wake on the signal: {took:?}"
    );
}

/// The point of it: a replica on a twenty-second interval shows a post
/// made at the origin within a couple of seconds.
#[tokio::test]
async fn a_replica_on_a_long_interval_is_live_anyway() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let (y_key, _) = key_in(y_dir.path());
    let (x_addr, x_pub) = origin_in(x_dir.path(), &[y_key]).await;
    let (alice_seed, alice) = identity(83);
    let mut a = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let s = Signer::new(alice_seed, alice, x_pub);
    let mut chain = Chain::default();
    let channel = [83u8; 32];
    channel_at(&mut a, &s, &mut chain, channel, y_key, &["first"]).await;

    let (y_addr, y_pub) = replica_in(y_dir.path(), PubKey::new(x_pub), x_addr, channel, 20).await;
    let mut at_y = Client::connect_as(y_addr, &y_pub, &alice_seed)
        .await
        .unwrap();
    until(&mut at_y, channel, &["first"]).await;

    // Now a post at the origin, with the replica's next interval pull
    // nineteen seconds away.
    let info = s.info(&mut a, channel).await;
    let post = s.post_chained(&mut chain, channel, info.instance, 0, 1, b"second".to_vec());
    assert_eq!(a.post("/channel/post", post.encode()).await.unwrap().0, 200);
    let took = until(&mut at_y, channel, &["first", "second"]).await;
    assert!(
        took < Duration::from_secs(5),
        "the replica took {took:?} to show a post -- it polled instead of waiting"
    );
}
