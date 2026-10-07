//! End-to-end for SIP-88 feeds over real HTTP/3.
//!
//! The properties worth proving here are the ones the shape buys and a
//! channel cannot: that the author numbers the log so the exchange cannot
//! fork it, that a refused append costs nothing, that the serial space stays
//! dense through a withdrawal, and that a feed with no members still refuses
//! everybody but its owner the right to write to it.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::entry_sig::GENESIS;
use sqex_proto::feed::{
    Append, Appended, DIR_BACKWARD, DIR_FORWARD, Head, Headed, Moved, Page, Post, Read, STATE_GONE,
    STATE_MOVED, Set, Since, Withdraw,
};
use sqex_proto::refusal::Code;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n",
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
    let handle = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, handle)
}

async fn peer(addr: SocketAddr, pubkey: [u8; 32], b: u8) -> (Client, PubKey, [u8; 32]) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    let seed = sk.to_bytes();
    (
        Client::connect_as(addr, &pubkey, &seed).await.unwrap(),
        PubKey::new(sk.verifying_key().to_bytes()),
        seed,
    )
}

/// An author's own view of where their feed has got to, so the next post can
/// be signed at the right serial with the right link.
struct Pen {
    me: PubKey,
    seed: [u8; 32],
    serial: u64,
    prev: [u8; 32],
}

impl Pen {
    fn new(me: PubKey, seed: [u8; 32]) -> Pen {
        Pen {
            me,
            seed,
            serial: 0,
            prev: GENESIS,
        }
    }

    fn post(&self, body: &[u8]) -> Post {
        Post::sign(
            &self.seed,
            &self.me,
            self.serial + 1,
            &self.prev,
            1_700_000_000 + self.serial,
            0,
            body.to_vec(),
        )
    }

    /// Append, and advance only on acceptance.
    ///
    /// **A chain position is spent when something is in the log at it**, and
    /// a feed forbids holes outright, so advancing over a refusal would leave
    /// a gap the exchange then reports as the thing it promises never to do.
    async fn append(&mut self, c: &mut Client, body: &[u8]) -> (u16, Vec<u8>) {
        let p = self.post(body);
        let (code, b) = c
            .post("/feed/append", Append { post: p.clone() }.encode())
            .await
            .unwrap();
        if code == 200 {
            let a = Appended::decode(&b).unwrap();
            self.serial = a.serial;
            self.prev = a.head_input;
        }
        (code, b)
    }
}

async fn read(c: &mut Client, who: &PubKey, since: u64, limit: u16, dir: u8) -> Page {
    let (code, body) = c
        .post(
            "/feed/read",
            Read {
                account: *who,
                since,
                limit,
                dir,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Page::decode(&body).unwrap()
}

async fn head(c: &mut Client, who: &PubKey) -> Headed {
    let (code, body) = c
        .post("/feed/head", Head { account: *who }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Headed::decode(&body).unwrap()
}

async fn since(c: &mut Client, feeds: &[(PubKey, u64)]) -> Moved {
    let (code, body) = c
        .post(
            "/feed/since",
            Since {
                feeds: feeds.to_vec(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Moved::decode(&body).unwrap()
}

fn code_of(body: &[u8]) -> Code {
    sqex_proto::refusal::Refusal::decode(body)
        .map(|r| r.code)
        .unwrap_or(Code::Unknown(0))
}

#[tokio::test]
async fn a_feed_is_published_and_read_by_a_stranger() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice, aseed) = peer(addr, pubkey, 81).await;
    let (mut b, _bob, _) = peer(addr, pubkey, 82).await;
    let mut pen = Pen::new(alice, aseed);

    // Nothing published: absent, and found is false rather than an error.
    assert!(!head(&mut b, &alice).await.found);

    for text in ["one", "two", "three"] {
        let (code, body) = pen.append(&mut a, text.as_bytes()).await;
        assert_eq!(code, 200, "{}", common::said(&body));
    }

    // **Read by a stranger who joined nothing.** There is no membership to
    // acquire and bob acquired none.
    let page = read(&mut b, &alice, 0, 10, DIR_FORWARD).await;
    assert!(page.found);
    assert_eq!(page.oldest, 1);
    assert_eq!(page.newest, 3);
    assert_eq!(page.posts.len(), 3);
    assert!(
        page.posts.iter().all(|s| s.post.verify()),
        "a post did not verify at the reader"
    );
    assert_eq!(
        page.posts
            .iter()
            .map(|s| String::from_utf8_lossy(&s.post.body).into_owned())
            .collect::<Vec<_>>(),
        vec!["one", "two", "three"]
    );

    // The chain holds across the whole log, which is what makes a hole mean
    // something later.
    for pair in page.posts.windows(2) {
        assert_eq!(
            pair[1].post.prev,
            pair[0].post.link(),
            "the chain broke between {} and {}",
            pair[0].post.serial,
            pair[1].post.serial
        );
    }
}

#[tokio::test]
async fn a_stranger_cannot_append_to_somebody_elses_feed() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice, aseed) = peer(addr, pubkey, 83).await;
    let (mut b, _bob, bseed) = peer(addr, pubkey, 84).await;

    // The control: alice can write to her own.
    let mut pen = Pen::new(alice, aseed);
    assert_eq!(pen.append(&mut a, b"mine").await.0, 200);

    // Bob signs a post naming alice's account. It is his device's signature
    // over her account, which is the shape an impersonation would take.
    let forged = Post::sign(
        &bseed,
        &alice,
        2,
        &pen.prev,
        1_700_000_100,
        0,
        b"not hers".to_vec(),
    );
    let (code, body) = b
        .post("/feed/append", Append { post: forged }.encode())
        .await
        .unwrap();
    assert_eq!(code, 401, "{}", common::said(&body));
    assert_eq!(code_of(&body), Code::NotYours);

    // And nothing landed.
    assert_eq!(
        read(&mut a, &alice, 0, 10, DIR_FORWARD).await.posts.len(),
        1
    );
}

#[tokio::test]
async fn a_refused_append_costs_the_author_nothing() {
    // Two devices of one account racing. SIP-88 §One chain: the loser is
    // refused, the exchange numbered nothing, and the same body re-signs at
    // the higher serial.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice, aseed) = peer(addr, pubkey, 85).await;
    let mut pen = Pen::new(alice, aseed);
    assert_eq!(pen.append(&mut a, b"first").await.0, 200);

    // A second post at the same serial, as a second device would sign it
    // having read the same head.
    let stale = Post::sign(
        &aseed,
        &alice,
        1,
        &GENESIS,
        1_700_000_200,
        0,
        b"loser".to_vec(),
    );
    let (code, body) = a
        .post("/feed/append", Append { post: stale }.encode())
        .await
        .unwrap();
    assert_eq!(code, 409, "{}", common::said(&body));
    assert_eq!(code_of(&body), Code::StaleSerial);

    // Re-signed at the serial the exchange actually holds, it lands.
    assert_eq!(pen.append(&mut a, b"loser").await.0, 200);
    let page = read(&mut a, &alice, 0, 10, DIR_FORWARD).await;
    assert_eq!(page.posts.len(), 2, "the refusal left a gap in the log");
    assert_eq!(page.posts[1].post.serial, 2);
}

#[tokio::test]
async fn a_withdrawal_leaves_a_tombstone_that_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice, aseed) = peer(addr, pubkey, 86).await;
    let (mut b, _bob, _) = peer(addr, pubkey, 87).await;
    let mut pen = Pen::new(alice, aseed);
    for text in ["keep", "regret", "keep too"] {
        assert_eq!(pen.append(&mut a, text.as_bytes()).await.0, 200);
    }

    // The control: it is there, with its body, before the withdrawal.
    let before = read(&mut b, &alice, 0, 10, DIR_FORWARD).await;
    assert_eq!(
        before.posts[1].post.body, b"regret",
        "the control failed: there was nothing to withdraw"
    );

    let (code, body) = a
        .post(
            "/feed/withdraw",
            Withdraw {
                account: alice,
                serial: 2,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    let after = read(&mut b, &alice, 0, 10, DIR_FORWARD).await;
    assert_eq!(after.posts.len(), 3, "the serial space grew a hole");
    let stone = &after.posts[1].post;
    assert!(stone.withdrawn());
    assert!(
        stone.verify(),
        "a withdrawn post read as forged -- the hash and signature were cleared"
    );
    assert_eq!(stone.link(), before.posts[1].post.link(), "the chain moved");
    // And the posts either side still chain through it.
    assert_eq!(after.posts[2].post.prev, stone.link());
}

#[tokio::test]
async fn nobody_withdraws_somebody_elses_post() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice, aseed) = peer(addr, pubkey, 88).await;
    let (mut b, _bob, _) = peer(addr, pubkey, 89).await;
    let mut pen = Pen::new(alice, aseed);
    assert_eq!(pen.append(&mut a, b"hers").await.0, 200);

    let (code, body) = b
        .post(
            "/feed/withdraw",
            Withdraw {
                account: alice,
                serial: 1,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 401, "{}", common::said(&body));
    assert_eq!(code_of(&body), Code::NotYours);
    assert!(
        !read(&mut a, &alice, 0, 10, DIR_FORWARD).await.posts[0]
            .post
            .withdrawn(),
        "somebody else withdrew it"
    );
}

#[tokio::test]
async fn since_reports_movement_once_and_not_twice() {
    // The route the design exists for: one request over many feeds, and only
    // the rows that are not unchanged carried.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice, aseed) = peer(addr, pubkey, 90).await;
    let (mut c, carol, cseed) = peer(addr, pubkey, 91).await;
    let (mut b, _bob, _) = peer(addr, pubkey, 92).await;
    let nobody = PubKey::new([0x5a; 32]);

    let mut apen = Pen::new(alice, aseed);
    let mut cpen = Pen::new(carol, cseed);
    assert_eq!(apen.append(&mut a, b"a1").await.0, 200);
    assert_eq!(cpen.append(&mut c, b"c1").await.0, 200);

    // Holding nothing of either, both have moved, and an account with no feed
    // is reported gone rather than silently omitted.
    let m = since(&mut b, &[(alice, 0), (carol, 0), (nobody, 0)]).await;
    assert_eq!(m.asked, 3);
    assert_eq!(m.rows.len(), 3);
    assert_eq!(m.rows[0].index, 0);
    assert_eq!(m.rows[0].state, STATE_MOVED);
    assert_eq!(m.rows[0].newest, 1);
    assert_eq!(
        m.rows[2].state, STATE_GONE,
        "an absent feed was not reported"
    );

    // Caught up on both: nothing is carried for either, which is the twelve
    // bytes the design is for.
    let m = since(&mut b, &[(alice, 1), (carol, 1)]).await;
    assert!(
        m.rows.is_empty(),
        "an unchanged feed was transmitted: {:?}",
        m.rows
    );
    assert_eq!(m.asked, 2, "the reply forgot how many were asked about");

    // One moves. Exactly one row, naming which.
    assert_eq!(apen.append(&mut a, b"a2").await.0, 200);
    let m = since(&mut b, &[(alice, 1), (carol, 1)]).await;
    assert_eq!(m.rows.len(), 1);
    assert_eq!(m.rows[0].index, 0, "the wrong row moved");
    assert_eq!(m.rows[0].newest, 2);
}

#[tokio::test]
async fn a_feed_pages_backwards_which_is_how_it_is_browsed() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice, aseed) = peer(addr, pubkey, 93).await;
    let (mut b, _bob, _) = peer(addr, pubkey, 94).await;
    let mut pen = Pen::new(alice, aseed);
    for i in 1..=5 {
        assert_eq!(pen.append(&mut a, format!("{i}").as_bytes()).await.0, 200);
    }

    let last_two = read(&mut b, &alice, 0, 2, DIR_BACKWARD).await;
    assert_eq!(last_two.posts.len(), 2);
    assert_eq!(last_two.posts[0].post.serial, 5, "backward is newest first");
    assert_eq!(last_two.posts[1].post.serial, 4);

    // The control: forward from the start is the other end.
    let first_two = read(&mut b, &alice, 0, 2, DIR_FORWARD).await;
    assert_eq!(first_two.posts[0].post.serial, 1);
}

#[tokio::test]
async fn a_feeds_policy_is_set_whole_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut a, alice, _) = peer(addr, pubkey, 95).await;

    let (code, body) = a
        .post(
            "/feed/set",
            Set {
                retention_secs: 86_400,
                max_posts: 50,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let h = head(&mut a, &alice).await;
    assert_eq!(h.retention_secs, 86_400);
    assert_eq!(h.max_posts, 50);

    // Outside the bounds, refused and said why.
    let (code, body) = a
        .post(
            "/feed/set",
            Set {
                retention_secs: 1,
                max_posts: 50,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 400, "{}", common::said(&body));
    assert_eq!(code_of(&body), Code::BadRetention);
    assert_eq!(
        head(&mut a, &alice).await.retention_secs,
        86_400,
        "a refused set changed the policy anyway"
    );
}

#[tokio::test]
async fn a_feed_with_no_identity_is_refused() {
    // Not access control -- an identity is free to mint -- but the handle the
    // exchange needs to apply a limit and a block against.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut anon = Client::connect(addr, &pubkey).await.unwrap();
    let (code, body) = anon
        .post(
            "/feed/read",
            Read {
                account: PubKey::new([1; 32]),
                since: 0,
                limit: 10,
                dir: DIR_FORWARD,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403, "{}", common::said(&body));
    assert_eq!(code_of(&body), Code::NoIdentity);
}
