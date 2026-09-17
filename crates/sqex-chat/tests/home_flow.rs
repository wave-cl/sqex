//! SIP-43: a client posts to a channel at the exchange it is connected to,
//! and the exchange that orders the channel is another one.
//!
//! Two real exchanges: the origin, where the channel was made, and a replica
//! that pulls it and serves it. The client connected to the replica learns
//! where the channel lives, signs under the origin, posts where it is, and
//! reads its own message back from the replica -- with the origin's receipt
//! verifying under the origin's key, which is the check that used to fail at
//! a replica because a client verified under the key it had connected to.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

/// An exchange, with `peers` as the replicas it will serve.
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

/// An exchange that replicates `channel` from the origin every second and
/// serves it.
async fn replica_in(
    dir: &Path,
    origin: PubKey,
    origin_addr: SocketAddr,
    channel: [u8; 32],
) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n\n[[replicate]]\norigin = {:?}\naddr = {:?}\n\
         channels = [{:?}]\ninterval_secs = 1\ndomain = \"origin.example\"\n",
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

/// One device, one store, two exchanges. What it signs is filed under the
/// origin whichever way it reaches the channel, so a post made at the
/// replica continues the chain it started at the origin, and one made back
/// at the origin continues that.
#[tokio::test]
async fn a_client_posts_where_it_is_and_the_origin_orders_it() {
    let origin_dir = tempfile::tempdir().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();
    let (replica_sk, replica_pub) = squic::generate_keypair();
    std::fs::write(
        replica_dir.path().join("host_key"),
        hex::encode(replica_sk.to_bytes()),
    )
    .unwrap();
    let replica_key = PubKey::new(replica_pub);
    let (origin_addr, origin_pub) = origin_in(origin_dir.path(), &[replica_key]).await;
    let origin = PubKey::new(origin_pub);
    let store = origin_dir.path().join("alice.db");

    // Alice makes a public channel at the origin and authorises the replica.
    let channel;
    let before;
    {
        let mut alice = chat_at(origin_addr, origin_pub, 1, &store).await;
        channel = alice.create_public("town square", "").await.unwrap();
        alice.send(&channel, "from the origin").await.unwrap();
        alice.replicate(&channel, &replica_key, true).await.unwrap();
        let home = alice.home(&channel).await.unwrap();
        assert_eq!(home.origin, origin, "the origin should say it lives here");
        assert!(alice.homed_elsewhere(&channel).is_none());
        before = alice.info(&channel).await.unwrap().last;
    }

    // The replica comes up; the same device, same store, connects to it.
    let (replica_addr, _) = replica_in(replica_dir.path(), origin, origin_addr, channel).await;
    let posted_seq;
    {
        let mut here = chat_at(replica_addr, replica_pub, 1, &store).await;
        let mut t = Timeline::new();
        let mut caught_up = false;
        for _ in 0..50 {
            if let Ok(got) = here.poll(&channel, &mut t, 0).await
                && said(&got.timeline).contains(&"from the origin".to_string())
                && here.info(&channel).await.unwrap().last >= before
            {
                caught_up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert!(caught_up, "the replica never served the channel");

        // The client knows where it lives, and by which name; and what it
        // read verified under the origin's key -- SIP-31 binds the exchange
        // into the signature, and a client that checked under the key it
        // connected to called every entry at a replica forged.
        let home = here.home(&channel).await.unwrap();
        assert_eq!(home.origin, origin);
        assert_eq!(home.domain, "origin.example");
        assert!(here.homed_elsewhere(&channel).is_some());
        assert!(
            t.forged().is_empty(),
            "judged forged at the replica: {:?}",
            t.forged()
        );

        // Posting at the replica: ordered by the origin, with the next position.
        let posted = here.send(&channel, "posted at the replica").await.unwrap();
        assert_eq!(posted.seq, before + 1, "the origin did not order it next");
        posted_seq = posted.seq;

        // And pulled back within the second, so it reads where it was written.
        let mut seen = false;
        for _ in 0..30 {
            let got = here.poll(&channel, &mut t, 0).await.unwrap();
            if said(&got.timeline).contains(&"posted at the replica".to_string()) {
                seen = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(seen, "the replica did not pull the post back");
        assert!(t.forged().is_empty(), "{:?}", t.forged());
    }

    // A store that remembers nothing, at the replica: the replica's `info`
    // says where this device stands at the origin, so the client resumes
    // from there rather than signing from zero. And a file sent from here
    // is carried to the origin chunk by chunk -- the replica keeps nothing
    // on the way -- and comes back to the copy by the ordinary pull, so a
    // reader at either end opens it.
    let secret: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    let blob;
    {
        use sqex_proto::message::{Part, Post as SipPost};
        let mut fresh = chat_at(
            replica_addr,
            replica_pub,
            1,
            &replica_dir.path().join("fresh.db"),
        )
        .await;
        let posted = fresh
            .send(&channel, "from a store that remembered nothing")
            .await
            .unwrap();
        assert_eq!(posted.seq, posted_seq + 1);

        let path = replica_dir.path().join("notes.md");
        std::fs::write(&path, &secret).unwrap();
        let limits = fresh.blob_limits().await.unwrap();
        let prepared = fresh.prepare_file(&path, limits.chunk as usize).unwrap();
        let attachment = fresh.upload(&channel, &prepared).await.unwrap();
        blob = attachment.blob;
        let mut post = SipPost::text("the notes, from the copy");
        post.parts.push(Part::Attachment(attachment));
        fresh.send_post(&channel, post).await.unwrap();
    }
    // Somebody else at the replica, with no local copy, fetches it there.
    {
        let mut other = chat_at(
            replica_addr,
            replica_pub,
            1,
            &replica_dir.path().join("other.db"),
        )
        .await;
        let mut t = Timeline::new();
        let mut attachment = None;
        for _ in 0..50 {
            let got = other.poll(&channel, &mut t, 0).await.unwrap();
            if let Some(a) = got
                .timeline
                .messages()
                .find(|m| m.post.body_text() == Some("the notes, from the copy"))
                .and_then(|m| m.post.attachments().next().cloned())
            {
                attachment = Some(a);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let attachment = attachment.expect("the file's message never reached the copy");
        assert_eq!(attachment.blob, blob);
        let mut opened = None;
        for _ in 0..50 {
            if let Ok(bytes) = other.download(&attachment).await {
                opened = Some(bytes);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        assert_eq!(
            opened.as_deref(),
            Some(&secret[..]),
            "the blob never came back to the copy"
        );
    }

    // Back at the origin: it holds the posts, and the chain is one chain --
    // a post here follows the ones made through the replica.
    let mut alice = chat_at(origin_addr, origin_pub, 1, &store).await;
    let mut at_origin = Timeline::new();
    let got = alice.poll(&channel, &mut at_origin, 0).await.unwrap();
    assert!(
        got.timeline
            .messages()
            .any(|m| m.seq == posted_seq && m.post.body_text() == Some("posted at the replica"))
    );
    // The origin holds the file a member sent from the copy.
    let a = at_origin
        .messages()
        .find(|m| m.post.body_text() == Some("the notes, from the copy"))
        .and_then(|m| m.post.attachments().next().cloned())
        .expect("the file's message is not at the origin");
    assert_eq!(alice.download(&a).await.unwrap(), secret);
    alice
        .send(&channel, "and back at the origin")
        .await
        .unwrap();
    let got = alice.poll(&channel, &mut at_origin, 0).await.unwrap();
    assert_eq!(
        said(&got.timeline),
        vec![
            "from the origin",
            "posted at the replica",
            "from a store that remembered nothing",
            "the notes, from the copy",
            "and back at the origin"
        ]
    );
    assert!(at_origin.forged().is_empty());
}
