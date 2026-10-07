//! A person publishes, and another follows and reads — SIP-88 and SIP-89
//! from the client's side, against a real exchange.
//!
//! What is worth proving here and not at the exchange: that the follow list
//! never leaves this client except as the question `/feed/since` asks, that
//! the batched poll reports movement once and not twice, that a citation
//! resolves to the post it names and says why when it cannot, and that the
//! whole lot survives a lost device through SIP-48's backup.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::feed::Cited;
use sqex_chat::store::Store;
use sqex_proto::message::{Body, Part, Post as SipPost};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let config_path = dir.join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
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
    Chat::new(client, seed, me, PubKey::new(server_pub), store)
}

fn text(s: &str) -> Body {
    Body::Post(SipPost::text(s))
}

fn said(page: &sqex_proto::feed::Page) -> Vec<String> {
    page.posts
        .iter()
        .filter_map(|s| match Body::decode(&s.post.body).ok().flatten() {
            Some(Body::Post(p)) => p.body_text().map(str::to_string),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_feed_is_published_and_followed() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(1);

    for t in ["morning", "afternoon", "evening"] {
        alice.publish(&text(t)).await.unwrap();
    }

    // Bob follows. Nothing is told to the exchange by doing so.
    bob.follow(&alice_key).unwrap();
    assert_eq!(bob.following().unwrap(), vec![(alice_key, 0)]);

    let page = bob.read_feed_after(&alice_key, 0, 10).await.unwrap();
    assert!(page.found);
    assert_eq!(said(&page), vec!["morning", "afternoon", "evening"]);
    assert_eq!(page.newest, 3);

    // Backward is the default read, and it is the other end.
    let latest = bob.read_feed(&alice_key, 0, 1).await.unwrap();
    assert_eq!(said(&latest), vec!["evening"]);
}

#[tokio::test]
async fn the_batched_poll_reports_movement_once() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 3, &dir.path().join("a.db")).await;
    let mut carol = chat_at(addr, server_pub, 4, &dir.path().join("c.db")).await;
    let mut bob = chat_at(addr, server_pub, 5, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(3);
    let (_, carol_key) = identity(4);
    let nobody = PubKey::new([0x7e; 32]);

    alice.publish(&text("a1")).await.unwrap();
    carol.publish(&text("c1")).await.unwrap();
    bob.follow(&alice_key).unwrap();
    bob.follow(&carol_key).unwrap();
    bob.follow(&nobody).unwrap();

    let caught = bob.feeds_since().await.unwrap();
    assert_eq!(caught.moved.len(), 2, "both should have moved");
    assert_eq!(caught.gone, vec![nobody], "an absent feed was not reported");
    assert!(caught.unasked.is_empty());
    assert_eq!(caught.moved[0].behind(), 1);

    // Read them, mark them, and ask again: nothing has moved.
    for s in &caught.moved {
        bob.read_to(&s.account, s.newest).unwrap();
    }
    let caught = bob.feeds_since().await.unwrap();
    assert!(
        caught.moved.is_empty(),
        "a feed reported twice: {:?}",
        caught.moved
    );

    // The control: it reports again the moment something is said.
    alice.publish(&text("a2")).await.unwrap();
    let caught = bob.feeds_since().await.unwrap();
    assert_eq!(caught.moved.len(), 1);
    assert_eq!(caught.moved[0].account, alice_key);
    assert_eq!(caught.moved[0].behind(), 1);
}

#[tokio::test]
async fn a_cursor_never_walks_backwards() {
    // A serial belongs to its author and never restarts, so a lower one is a
    // fault and not a feed to re-read.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let bob = chat_at(addr, server_pub, 6, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(7);
    bob.follow(&alice_key).unwrap();
    bob.read_to(&alice_key, 5).unwrap();
    bob.read_to(&alice_key, 2).unwrap();
    assert_eq!(bob.following().unwrap(), vec![(alice_key, 5)]);
}

#[tokio::test]
async fn a_quote_resolves_to_the_post_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 8, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 9, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(8);

    alice.publish(&text("worth repeating")).await.unwrap();
    let at = alice.publish(&text("and this")).await.unwrap();

    // Bob quotes it in his own feed: his words, plus a pointer.
    let mut quoting = SipPost::text("she is right");
    quoting.parts.push(Part::Quote(alice_key, at.serial));
    bob.publish(&Body::Post(quoting)).await.unwrap();

    // A third party reads bob's feed, finds the citation, and resolves it.
    let (_, bob_key) = identity(9);
    let mut carol = chat_at(addr, server_pub, 10, &dir.path().join("c.db")).await;
    let page = carol.read_feed(&bob_key, 0, 1).await.unwrap();
    let Some(Body::Post(p)) = Body::decode(&page.posts[0].post.body).unwrap() else {
        panic!("not a post")
    };
    let (who, serial) = p.quoted().expect("the citation did not survive the wire");
    assert_eq!((who, serial), (alice_key, at.serial));

    match carol.resolve_quote(&who, serial).await {
        Cited::Got(stored) => {
            let Some(Body::Post(orig)) = Body::decode(&stored.post.body).unwrap() else {
                panic!("not a post")
            };
            assert_eq!(orig.body_text(), Some("and this"));
            // Checked under a key carol already held. No exchange is in the
            // trust path: the account key is both the locator and the
            // verifying key.
            assert!(stored.post.verify());
            assert_eq!(stored.post.account, alice_key);
        }
        other => panic!("the citation did not resolve: {other:?}"),
    }
}

#[tokio::test]
async fn a_withdrawn_post_resolves_as_withdrawn_and_not_as_missing() {
    // The whole reason SIP-89 carries a pointer and not a copy: the author's
    // withdrawal reaches every quote that resolves afterwards.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 11, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 12, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(11);

    let at = alice.publish(&text("said in haste")).await.unwrap();

    // The control: it resolves before the withdrawal.
    assert!(
        matches!(
            bob.resolve_quote(&alice_key, at.serial).await,
            Cited::Got(_)
        ),
        "the control failed: there was nothing to withdraw"
    );

    alice.withdraw(at.serial).await.unwrap();
    assert_eq!(
        bob.resolve_quote(&alice_key, at.serial).await,
        Cited::Withdrawn
    );
}

#[tokio::test]
async fn a_citation_of_a_feed_that_is_not_there_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 13, &dir.path().join("b.db")).await;
    let nobody = PubKey::new([0x3c; 32]);
    assert_eq!(bob.resolve_quote(&nobody, 1).await, Cited::NoFeed);

    // And a serial past the end of a feed that does exist is unresolved
    // rather than forged -- the feed may simply not have reached it.
    let mut alice = chat_at(addr, server_pub, 14, &dir.path().join("a.db")).await;
    let (_, alice_key) = identity(14);
    alice.publish(&text("one")).await.unwrap();
    assert_eq!(
        bob.resolve_quote(&alice_key, 99).await,
        Cited::Unresolved,
        "a serial not yet reached was called something worse"
    );
}

/// SIP-88 §One chain, from the client: a device that signs against a head
/// another device has already moved past is refused, and the refusal costs
/// nothing.
///
/// **Deterministic on purpose.** `publish` re-reads the head every time, so
/// two sequential `publish` calls never race and a test built on them proves
/// nothing about the retry. `publish_at` is the primitive underneath, and
/// driving it with a head that is deliberately stale is what makes the
/// losing case happen on every run rather than on an unlucky one.
#[tokio::test]
async fn a_device_signing_against_a_moved_head_is_refused_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let mut one = chat_at(addr, server_pub, 15, &dir.path().join("one.db")).await;
    let mut two = chat_at(addr, server_pub, 15, &dir.path().join("two.db")).await;
    let (_, me) = identity(15);

    // Both read the same head. This is the moment a race begins.
    let stale_head = two.feed_head().await.unwrap();
    assert_eq!(
        one.feed_head().await.unwrap().newest,
        stale_head.newest,
        "the control failed: they did not start level"
    );

    // One wins.
    one.publish(&text("from one")).await.unwrap();

    // Two signs against the head it read, which has moved. Refused, and
    // said as the serial losing rather than as anything darker.
    let lost = two.publish_at(&stale_head, &text("from two")).await;
    match lost {
        Err(sqex_chat::client::ChatError::Refused(_, r)) => assert_eq!(
            r.code,
            sqex_proto::refusal::Code::StaleSerial,
            "the wrong refusal: {r}"
        ),
        other => panic!("a stale head was accepted: {other:?}"),
    }

    // And the recovery `publish` relies on, driven from the same stale head:
    // the first attempt is refused, it re-reads, and the post lands. Nothing
    // was numbered by the refusal, so nothing was spent.
    two.publish_from(stale_head, &text("from two"))
        .await
        .expect("publish did not recover from a head that had moved");

    let page = one.read_feed_after(&me, 0, 10).await.unwrap();
    assert_eq!(page.posts.len(), 2, "the refusal left a gap");
    assert_eq!(said(&page), vec!["from one", "from two"]);
    // And the chain runs through both, so a reader sees no hole.
    assert_eq!(page.posts[1].post.prev, page.posts[0].post.link());
}

#[tokio::test]
async fn the_follow_list_survives_a_lost_device() {
    // The exchange never holds it, so SIP-48's sealed backup is the only
    // thing that can bring it back -- which is why it has a segment kind of
    // its own rather than riding in opaque client state.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 16, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(17);
    let (_, carol_key) = identity(18);

    bob.follow(&alice_key).unwrap();
    bob.follow(&carol_key).unwrap();
    bob.read_to(&alice_key, 4).unwrap();
    let key = bob.new_backup_key().unwrap();
    let wrote = bob.backup(&key).await.unwrap();
    assert_eq!(wrote.follows, 2, "the follows were not backed up");

    // A fresh store for the same identity: the device is gone.
    let mut fresh = chat_at(addr, server_pub, 16, &dir.path().join("b2.db")).await;
    assert!(
        fresh.following().unwrap().is_empty(),
        "the control failed: the new store already knew"
    );
    let back = fresh.restore(&key, None).await.unwrap();
    assert_eq!(back.follows, 2);
    let mut got = fresh.following().unwrap();
    got.sort();
    let mut want = vec![(alice_key, 4), (carol_key, 0)];
    want.sort();
    assert_eq!(got, want, "the cursors did not come back with the list");
}
