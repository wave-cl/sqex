//! SIP-43 §Read marks at a replica: a read mark set at a copy reaches the origin and every copy; a
//! signal sent at either end reaches members at the other; a ring at the
//! origin rings a member at the copy.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByAccount, ByChannel, ByChannelSigned, Cursor, EVENT_JOINED, EVENT_REPLICATE, Entries, Fetch,
    Marks, SignalOut, Signalled, TYPE_CURSORS, TYPE_JOIN, TYPE_REPLICATE, Visibility,
};
use sqex_proto::entry_sig::GENESIS;
use sqex_proto::events::{Event as WireEvent, Framer, Subscribe};
use sqex_proto::message::{RING_RINGING, SIGNAL_CALL_STATE, SIGNAL_TYPING, Signal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

async fn serve(config_toml: &str) -> (SocketAddr, [u8; 32]) {
    let file: FileConfig = toml::from_str(config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, None, signing_key).await.unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
}

async fn origin_in(dir: &Path, peers: &[PubKey]) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nreplication_peers = [{list}]\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    serve(&toml).await
}

async fn replica_in(
    dir: &Path,
    origin: PubKey,
    origin_addr: SocketAddr,
    channel: [u8; 32],
) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n\n[[replicate]]\norigin = {:?}\naddr = {:?}\n\
         channels = [{:?}]\ninterval_secs = 1\ndomain = \"x.test\"\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
        origin.to_string(),
        origin_addr.to_string(),
        bs58::encode(channel).into_string(),
    );
    serve(&toml).await
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn key_in(dir: &Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    PubKey::new(
        ed25519_dalek::SigningKey::from_bytes(&server_sk.to_bytes())
            .verifying_key()
            .to_bytes(),
    )
}

async fn fetch(c: &mut Client, channel: [u8; 32], since: u64) -> Entries {
    let (code, body) = c
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since,
                wait_secs: 0,
                receipts: false,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Entries::decode(&body, false).unwrap()
}

async fn signals(c: &mut Client, channel: [u8; 32]) -> Vec<Signalled> {
    fetch(c, channel, u64::MAX - 1).await.signals
}

async fn marks(c: &mut Client, channel: [u8; 32]) -> Marks {
    let (code, body) = c
        .post(
            "/channel/cursors",
            ByChannel { channel }.encode(TYPE_CURSORS),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Marks::decode(&body).unwrap()
}

async fn mark_read(c: &mut Client, channel: [u8; 32], read: u64) {
    let (code, body) = c
        .post(
            "/channel/cursor",
            Cursor {
                channel,
                read,
                receipts: true,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn signal(c: &mut Client, channel: [u8; 32], kind: u8, body: Vec<u8>) {
    let (code, said) = c
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind,
                body,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&said));
}

/// Wait for a condition, polling; the replica pulls every second.
async fn soon<F, Fut>(mut f: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..40 {
        if f().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    false
}

#[tokio::test]
async fn marks_and_signals_cross_between_a_copy_and_its_origin() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let y_key = key_in(y_dir.path());
    let (x_addr, x_pub) = origin_in(x_dir.path(), &[y_key]).await;
    let x_key = PubKey::new(x_pub);
    let (alice_seed, alice) = identity(241);
    let (bob_seed, bob) = identity(242);
    let channel = [241u8; 32];

    // Alice's room at X, authorised to Y, with two entries.
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
    assert_eq!(
        a.post(
            "/channel/replicate",
            ByAccount {
                channel,
                account: y_key,
                action
            }
            .encode(TYPE_REPLICATE)
        )
        .await
        .unwrap()
        .0,
        200
    );
    for t in [b"one".as_slice(), b"two"] {
        let info = s.info(&mut a, channel).await;
        let post = s.post_chained(&mut chain, channel, info.instance, 0, 0, t.to_vec());
        assert_eq!(a.post("/channel/post", post.encode()).await.unwrap().0, 200);
    }
    let top = s.info(&mut a, channel).await.last;

    // Y replicates; Bob joins at Y and reads there.
    let (y_addr, y_pub) = replica_in(y_dir.path(), x_key, x_addr, channel).await;
    let mut b = Client::connect_as(y_addr, &y_pub, &bob_seed).await.unwrap();
    assert!(
        soon(|| async {
            let (code, _) = Client::connect_as(y_addr, &y_pub, &bob_seed)
                .await
                .unwrap()
                .post(
                    "/channel/info",
                    ByChannel { channel }.encode(sqex_proto::channel::TYPE_INFO),
                )
                .await
                .unwrap();
            code == 200
        })
        .await,
        "Y never pulled the room"
    );
    let joining = Signer::new(bob_seed, bob, x_pub).action_outside(
        channel,
        instance_for(channel, 0),
        EVENT_JOINED,
        &bob,
        &[],
        0,
        GENESIS,
    );
    let (code, body) = b
        .post(
            "/channel/join",
            ByChannelSigned {
                channel,
                action: joining,
            }
            .encode(TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(
        soon(|| async {
            let mut c = Client::connect_as(y_addr, &y_pub, &bob_seed).await.unwrap();
            fetch(&mut c, channel, 0).await.entries.len() >= 4
        })
        .await,
        "Bob's join never came back to Y"
    );
    let _ = fetch(&mut b, channel, 0).await;

    // Bob's mark, set at Y, is Alice's to see at X within a pull -- and
    // delivery there is what Y served him, not what X did (nothing).
    mark_read(&mut b, channel, top).await;
    assert!(
        soon(|| async {
            let mut c = Client::connect_as(x_addr, &x_pub, &alice_seed)
                .await
                .unwrap();
            marks(&mut c, channel)
                .await
                .marks
                .iter()
                .any(|m| m.account == bob && m.read == top)
        })
        .await,
        "Bob's mark never reached the origin"
    );

    // Alice's mark, set at X, is Bob's to see at Y within a pull.
    let _ = fetch(&mut a, channel, 0).await;
    mark_read(&mut a, channel, top).await;
    assert!(
        soon(|| async {
            let mut c = Client::connect_as(y_addr, &y_pub, &bob_seed).await.unwrap();
            marks(&mut c, channel)
                .await
                .marks
                .iter()
                .any(|m| m.account == alice && m.read == top)
        })
        .await,
        "Alice's mark never reached the copy"
    );

    // Alice types at X: Bob at Y sees it. Bob types at Y: Alice at X sees
    // it, and Bob does not get his own back.
    signal(&mut a, channel, SIGNAL_TYPING, vec![]).await;
    assert!(
        soon(|| async {
            let mut c = Client::connect_as(y_addr, &y_pub, &bob_seed).await.unwrap();
            signals(&mut c, channel)
                .await
                .iter()
                .any(|s| s.account == alice && s.kind == SIGNAL_TYPING)
        })
        .await,
        "Alice's typing never reached the copy"
    );
    signal(&mut b, channel, SIGNAL_TYPING, vec![]).await;
    assert!(
        soon(|| async {
            let mut c = Client::connect_as(x_addr, &x_pub, &alice_seed)
                .await
                .unwrap();
            signals(&mut c, channel)
                .await
                .iter()
                .any(|s| s.account == bob && s.kind == SIGNAL_TYPING)
        })
        .await,
        "Bob's typing never reached the origin"
    );
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(
        signals(&mut b, channel)
            .await
            .iter()
            .all(|s| s.account != bob),
        "Bob got his own typing back from the origin"
    );

    // A call rung at X rings Bob at Y: SIP-36's event, from the pulled
    // signal.
    let stream = b
        .stream(
            "POST",
            "/events",
            Subscribe {
                version: sqex_proto::events::VERSION,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);
    let mut stream = stream;
    signal(
        &mut a,
        channel,
        SIGNAL_CALL_STATE,
        Signal::CallState {
            target: top,
            state: RING_RINGING,
            device: alice,
        }
        .encode(),
    )
    .await;
    let mut framer = Framer::new();
    let rang = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            let chunk = stream.next().await.unwrap().expect("stream ended");
            for e in framer.feed(&chunk).unwrap() {
                if let WireEvent::Ringing { channel: c, seq } = e
                    && c == channel
                {
                    return seq;
                }
            }
        }
    })
    .await;
    assert_eq!(rang.ok(), Some(top), "Bob at the copy was not rung");
}
