//! SIP-53 §Posting again: a post stranded by a move is posted again. Alice's channel at X
//! is replicated to Y; she posts "only x" at X, X goes away before Y sees
//! it, and she rehomes the channel at Y -- which strands "only x". Her
//! client keeps it aside, chains on from what Y holds, and posts it again
//! on her say, saying when it was first said. When X comes back it is
//! told, and nothing of the losing side is shown as the conversation.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

fn key_in(dir: &Path) -> PubKey {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let hex = std::fs::read_to_string(&key_path).unwrap();
    let (sk, _) = squic::load_keypair(&hex).unwrap();
    PubKey::new(
        SigningKey::from_bytes(&sk.to_bytes())
            .verifying_key()
            .to_bytes(),
    )
}

async fn serve(
    dir: &Path,
    config_toml: &str,
) -> (SocketAddr, [u8; 32], std::sync::Arc<squic::ServerListener>) {
    let file: FileConfig = toml::from_str(config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind_with(
        config,
        None,
        signing_key,
        sqexd::relay::Find::Fixed(std::collections::HashMap::new()),
    )
    .await
    .unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    let listener = std::sync::Arc::clone(&bound.listener);
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    let _ = dir;
    (addr, server_pub, listener)
}

/// The origin, serving `peers` as replicas; closable, and startable again
/// on the same store.
async fn origin_in(
    dir: &Path,
    peers: &[PubKey],
) -> (SocketAddr, [u8; 32], std::sync::Arc<squic::ServerListener>) {
    key_in(dir);
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nreplication_peers = [{list}]\n",
        dir.join("host_key").to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    serve(dir, &config_toml).await
}

/// A replica of `channel` at `origin`, taking a rehome after two seconds
/// without the origin.
async fn replica_in(
    dir: &Path,
    origin: PubKey,
    origin_addr: SocketAddr,
    channel: [u8; 32],
) -> (SocketAddr, [u8; 32], std::sync::Arc<squic::ServerListener>) {
    key_in(dir);
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nrehome_away_secs = 2\n\n[[replicate]]\norigin = {:?}\n\
         addr = {:?}\nchannels = [{:?}]\ninterval_secs = 1\ndomain = \"x.test\"\n",
        dir.join("host_key").to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
        origin.to_string(),
        origin_addr.to_string(),
        bs58::encode(channel).into_string(),
    );
    serve(dir, &config_toml).await
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn chat_at(addr: SocketAddr, server_pub: [u8; 32], b: u8, store_path: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
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

#[tokio::test]
async fn a_stranded_post_is_kept_aside_and_posted_again() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let y_key = key_in(y_dir.path());
    let (x_addr, x_pub, x_listener) = origin_in(x_dir.path(), &[y_key]).await;
    let x_key = PubKey::new(x_pub);
    let store = x_dir.path().join("alice.db");
    let (_, alice) = identity(3);

    // The channel at X, replicated to Y.
    let channel;
    {
        let mut at_x = chat_at(x_addr, x_pub, 3, &store).await;
        channel = at_x.create_public("forked", "").await.unwrap();
        at_x.send(&channel, "one").await.unwrap();
        at_x.replicate(&channel, &y_key, true).await.unwrap();
    }
    let (y_addr, y_pub, _y_l) = replica_in(y_dir.path(), x_key, x_addr, channel).await;
    let mut at_y = chat_at(y_addr, y_pub, 3, &store).await;
    let mut ty = Timeline::new();
    let mut caught_up = false;
    for _ in 0..50 {
        if let Ok(got) = at_y.poll(&channel, &mut ty, 0).await
            && said(&got.timeline) == ["one"]
        {
            caught_up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(caught_up, "Y never caught up");

    // X goes, and comes back where Y cannot find it -- a partition. One
    // more entry is ordered there that Y never sees.
    x_listener.close(quinn::VarInt::from_u32(0), b"gone");
    let (x_addr2, x_pub2, _x_l2) = origin_in(x_dir.path(), &[y_key]).await;
    assert_eq!(x_pub2, x_pub);
    let mut at_x = chat_at(x_addr2, x_pub, 3, &store).await;
    let sent = at_x.send(&channel, "only x").await.unwrap();
    let mut tx = Timeline::new();
    let got = at_x.poll(&channel, &mut tx, 0).await.unwrap();
    assert_eq!(said(&got.timeline), ["one", "only x"]);
    let first_said = got
        .timeline
        .messages()
        .find(|m| m.seq == sent.seq)
        .map(|m| m.posted)
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(3200)).await;

    // Alice rehomes at Y. The store files what it read at X under X, so
    // nothing at Y is stranded yet; the rehome chains on from what Y holds
    // and is accepted, and she can go on posting at Y.
    at_y.rehome(&channel, &y_key, "y.test").await.unwrap();
    assert_eq!(at_y.exchange_of(&channel), y_key);
    assert!(at_y.stranded_posts(&channel).unwrap().is_empty());
    at_y.send(&channel, "at y").await.unwrap();
    let mut ty = Timeline::new();
    let _ = at_y.poll(&channel, &mut ty, 0).await.unwrap();
    assert!(ty.forged().is_empty(), "{:?}", ty.forged());
    let held = at_y.history(&channel, &[alice]).unwrap();
    assert_eq!(said(&held), ["one", "at y"]);

    // The partition heals: Alice carries the rehome to X, which strands
    // "only x" and follows Y. Her client at X meets the fork in X's
    // answer, keeps "only x" aside, and shows nothing of the losing side
    // as the conversation.
    assert!(
        at_x.carry_rehome(&channel).await.unwrap(),
        "X did not take the rehome"
    );
    let mut tx = Timeline::new();
    let got = at_x.poll(&channel, &mut tx, 0).await.unwrap();
    assert!(
        !said(&got.timeline).iter().any(|m| m == "only x"),
        "the losing side is shown as the conversation: {:?}",
        said(&got.timeline)
    );
    let stranded = at_x.stranded_posts(&channel).unwrap();
    assert_eq!(stranded.len(), 1, "{stranded:?}");
    assert_eq!(stranded[0].2.body_text(), Some("only x"));
    assert_eq!(stranded[0].1, first_said);
    let held = at_x.history(&channel, &[alice]).unwrap();
    assert!(
        !said(&held).iter().any(|m| m == "only x"),
        "{:?}",
        said(&held)
    );

    // She posts it again -- at Y, where the channel lives -- and it says
    // when it was first said. The stranded post is a fact about her words,
    // not about an exchange: known at Y as at X.
    let stranded = at_y.stranded_posts(&channel).unwrap();
    assert_eq!(stranded.len(), 1);
    let seq = stranded[0].0;
    at_y.post_again(&channel, seq).await.unwrap();
    assert!(at_y.stranded_posts(&channel).unwrap().is_empty());
    assert!(at_x.stranded_posts(&channel).unwrap().is_empty());
    let _ = at_y.poll(&channel, &mut ty, 0).await.unwrap();
    assert!(ty.forged().is_empty(), "{:?}", ty.forged());
    let held = at_y.history(&channel, &[alice]).unwrap();
    assert_eq!(said(&held), ["one", "at y", "only x"]);
    let again = held
        .messages()
        .find(|m| m.post.body_text() == Some("only x"))
        .unwrap();
    assert_eq!(again.post.said(), Some(first_said));
    assert!(again.posted >= first_said);
}
