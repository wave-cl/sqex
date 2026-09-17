//! SIP-57: a redaction made at a copy reaches the origin, and one made at
//! the origin reaches the copy as a tombstone. (That a copy keeps no
//! longer than the origin's window is a unit test on the store: the
//! shortest window is an hour.)

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByAccount, ByChannel, ByChannelSigned, ByTarget, EVENT_JOINED, EVENT_REPLICATE, Entries, Fetch,
    KIND_MEMBER, TYPE_JOIN, TYPE_REDACT, TYPE_REPLICATE, Visibility,
};
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

/// Member entries: (seq, body), a tombstone as an empty body.
async fn bodies(c: &mut Client, channel: [u8; 32]) -> Vec<(u64, Vec<u8>)> {
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
        .filter(|e| e.kind == KIND_MEMBER)
        .map(|e| (e.seq, e.body.clone()))
        .collect()
}

async fn until<F: Fn(&[(u64, Vec<u8>)]) -> bool>(c: &mut Client, channel: [u8; 32], ok: F) -> bool {
    for _ in 0..60 {
        let (code, _) = c
            .post(
                "/channel/info",
                ByChannel { channel }.encode(sqex_proto::channel::TYPE_INFO),
            )
            .await
            .unwrap();
        if code == 200 && ok(&bodies(c, channel).await) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    false
}

#[tokio::test]
async fn a_redaction_reaches_every_copy() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let y_key = key_in(y_dir.path());
    let (x_addr, x_pub) = origin_in(x_dir.path(), &[y_key]).await;
    let x_key = PubKey::new(x_pub);
    let (alice_seed, alice) = identity(1);
    let (bob_seed, bob) = identity(2);
    let channel = [7u8; 32];

    // Alice's room at X, kept for the minimum window; Bob joins at Y later.
    let mut a = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let sa = Signer::new(alice_seed, alice, x_pub);
    let mut ca = Chain::default();
    let req = sa.create_chained(
        &mut ca,
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
    let action = sa.action_chained(
        &mut ca,
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
    for t in [b"one".as_slice(), b"two", b"three"] {
        let info = sa.info(&mut a, channel).await;
        let req = sa.post_chained(&mut ca, channel, info.instance, 0, 0, t.to_vec());
        assert_eq!(a.post("/channel/post", req.encode()).await.unwrap().0, 200);
    }
    let (y_addr, y_pub) = replica_in(y_dir.path(), x_key, x_addr, channel).await;
    let mut at_y = Client::connect_as(y_addr, &y_pub, &bob_seed).await.unwrap();
    assert!(
        until(&mut at_y, channel, |b| b.len() == 3).await,
        "Y never caught up"
    );
    let sb = Signer::new(bob_seed, bob, x_pub);
    let joining = sb.action_outside(
        channel,
        instance_for(channel, 0),
        EVENT_JOINED,
        &bob,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, body) = at_y
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

    // Alice redacts "two" at the origin: Y shows the tombstone within a pull.
    let two = bodies(&mut a, channel)
        .await
        .iter()
        .find(|(_, b)| b == b"two")
        .unwrap()
        .0;
    let (code, body) = a
        .post(
            "/channel/redact",
            ByTarget {
                channel,
                target: two,
            }
            .encode(TYPE_REDACT),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(
        until(&mut at_y, channel, |b| b
            .iter()
            .any(|(s, body)| *s == two && body.is_empty()))
        .await,
        "the redaction never reached the copy"
    );
    // The rest is intact, and the chain of receipts still reads: the copy
    // still serves every entry.
    let got = bodies(&mut at_y, channel).await;
    assert_eq!(got.len(), 3);
    assert!(got.iter().any(|(_, b)| b == b"three"));

    // Alice, reading through the copy, redacts "three" there: carried to
    // the origin, then tombstoned back at the copy.
    let mut a_at_y = Client::connect_as(y_addr, &y_pub, &alice_seed)
        .await
        .unwrap();
    let three = got.iter().find(|(_, b)| b == b"three").unwrap().0;
    let (code, body) = a_at_y
        .post(
            "/channel/redact",
            ByTarget {
                channel,
                target: three,
            }
            .encode(TYPE_REDACT),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(
        bodies(&mut a, channel)
            .await
            .iter()
            .any(|(s, b)| *s == three && b.is_empty()),
        "the origin did not honour a redaction from a copy"
    );
    assert!(
        until(&mut at_y, channel, |b| b
            .iter()
            .any(|(s, body)| *s == three && body.is_empty()))
        .await,
        "the copy never tombstoned what it carried"
    );
    // Bob, not the author and not an admin, cannot redact "one" from the copy.
    let one = got.iter().find(|(_, b)| b == b"one").unwrap().0;
    let (code, _) = at_y
        .post(
            "/channel/redact",
            ByTarget {
                channel,
                target: one,
            }
            .encode(TYPE_REDACT),
        )
        .await
        .unwrap();
    assert_ne!(
        code, 200,
        "a member redacted somebody else's entry through a copy"
    );
}
