//! SIP-35 §Open peering: peering on a member's word. An exchange that peers openly
//! serves the peering routes to anyone and grants nothing by it: a home
//! nobody listed pulls on the account's Move, an origin nobody listed
//! tells a home of a channel, a name is located at an unlisted domain --
//! and a stranger is refused what no statement entitles it to, exactly
//! as an unlisted key is refused at a listed exchange. A stranger pays
//! for the writes it causes and the waits it holds; a closed origin
//! admits the home its whitelisted member named.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::Op;
use sqex_proto::channel::{ByChannel, Entries, Fetch, Invitee, Role, TYPE_INFO, Visibility};
use sqex_proto::home::{Move, Moved, Moving};
use sqex_proto::locate::{Locate, Located};
use sqex_proto::peer::{
    Changed, Hello, Hi, Mine, PEER_VERSION, PeerInvited, PeerWait, Pull, PullMine,
};
use sqex_proto::refusal::{Code, Refusal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::{PubKey, SignedTransaction, SoftwareSigner, Transaction};

use crate::common;
use crate::common::{Chain, Signer, instance_for};

/// How an exchange under test is set up.
struct Setup<'a> {
    open: bool,
    domain: &'a str,
    peers: &'a [PubKey],
    found: &'a [(&'a str, PubKey, SocketAddr)],
    admin: Option<PubKey>,
    /// A `[limits]` line, e.g. `peering = [3, 3600]`.
    limits: &'a str,
}

impl Default for Setup<'_> {
    fn default() -> Self {
        Setup {
            open: false,
            domain: "x.test",
            peers: &[],
            found: &[],
            admin: None,
            limits: "",
        }
    }
}

async fn exchange_in(dir: &Path, listen: SocketAddr, s: Setup<'_>) -> (SocketAddr, [u8; 32]) {
    let list = s
        .peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let admins = s
        .admin
        .map(|a| format!("{:?}", a.to_string()))
        .unwrap_or_default();
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = [{admins}]\n\
         welcome_channel = \"\"\ndomain = {:?}\nreplication_peers = [{list}]\n\
         seed_relay_peers = [{list}]\nopen_peering = {}\nhome_secs = 1\n\
         [limits]\n{}\n",
        listen.to_string(),
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
        s.domain,
        s.open,
        s.limits,
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let map = s
        .found
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

/// An exchange key written where `exchange_in` will read it, so the key is
/// known before the exchange is up.
fn key_in(dir: &Path) -> (PubKey, [u8; 32]) {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let seed = server_sk.to_bytes();
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    (PubKey::new(vk.to_bytes()), seed)
}

fn any_port() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A loopback address nobody is listening on right now.
fn free_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

/// A public group at `x` created by `creator` with `member` in it and one
/// post from each; public so the bodies read without SIP-17, which the
/// gate under test does not touch.
async fn group_at(
    x_addr: SocketAddr,
    x_pub: [u8; 32],
    creator: ([u8; 32], PubKey),
    member: ([u8; 32], PubKey),
    channel: [u8; 32],
) -> (Client, Chain, Client) {
    let mut a = Client::connect_as(x_addr, &x_pub, &creator.0)
        .await
        .unwrap();
    let sa = Signer::new(creator.0, creator.1, x_pub);
    let mut ca = Chain::default();
    let req = sa.create_chained(
        &mut ca,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![Invitee {
            account: member.1,
            role: Role::Member,
        }],
    );
    let (code, body) = a.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let info = sa.info(&mut a, channel).await;
    let post = sa.post_chained(&mut ca, channel, info.instance, 0, 0, b"hello".to_vec());
    assert_eq!(a.post("/channel/post", post.encode()).await.unwrap().0, 200);

    let mut b = Client::connect_as(x_addr, &x_pub, &member.0).await.unwrap();
    let sb = Signer::new(member.0, member.1, x_pub);
    let mut cb = Chain::default();
    let info = sb.info(&mut b, channel).await;
    let post = sb.post_chained(&mut cb, channel, info.instance, 0, 0, b"hi".to_vec());
    assert_eq!(b.post("/channel/post", post.encode()).await.unwrap().0, 200);
    (a, ca, b)
}

async fn hello(c: &mut Client) -> (u16, Option<Hi>) {
    let (code, body) = c
        .post(
            "/peer/hello",
            Hello {
                version: PEER_VERSION,
                since: 0,
            }
            .encode(),
        )
        .await
        .unwrap();
    (code, (code == 200).then(|| Hi::decode(&body).unwrap()))
}

async fn pull(c: &mut Client, channel: [u8; 32]) -> u16 {
    c.post(
        "/peer/pull",
        Pull {
            channel,
            since: 0,
            max: 10,
        }
        .encode(),
    )
    .await
    .unwrap()
    .0
}

async fn mine(c: &mut Client, account: PubKey) -> (u16, Vec<[u8; 32]>) {
    let (code, body) = c
        .post("/peer/mine", PullMine { account }.encode())
        .await
        .unwrap();
    let channels = if code == 200 {
        Mine::decode(&body).unwrap().channels
    } else {
        Vec::new()
    };
    (code, channels)
}

async fn present(
    c: &mut Client,
    mv: Move,
    domain: &str,
    origins: Vec<(PubKey, String)>,
) -> (u16, Vec<u8>) {
    c.post(
        "/account/move",
        Moving {
            mv,
            domain: domain.into(),
            origins,
        }
        .encode(),
    )
    .await
    .unwrap()
}

/// A home nobody listed. X peers openly and lists no one; B lists no one
/// and finds X by its domain. A stranger at X is answered `/peer/hello`
/// and refused everything else; on Alice's Move, B pulls her group from
/// X and carries her post back; a channel she is not in stays refused.
/// A listed X with the same empty list refuses the stranger `hello` too,
/// and says a home it does not list is not peered.
#[tokio::test]
async fn a_home_nobody_listed_pulls_on_the_accounts_word() {
    let (alice_seed, alice) = identity(211);
    let (bob_seed, bob) = identity(212);
    let (carol_seed, carol) = identity(213);
    let group = [211u8; 32];
    let other = [212u8; 32];
    let b_dir = tempfile::tempdir().unwrap();
    let (b_key, b_seed) = key_in(b_dir.path());

    // Control: a listed exchange with an empty list -- SIP-35 as written.
    let closed_dir = tempfile::tempdir().unwrap();
    let (closed_addr, closed_pub) =
        exchange_in(closed_dir.path(), any_port(), Setup::default()).await;
    let mut as_b = Client::connect_as(closed_addr, &closed_pub, &b_seed)
        .await
        .unwrap();
    assert_eq!(
        hello(&mut as_b).await.0,
        404,
        "a listed exchange greeted a stranger"
    );
    let mut alice_closed = Client::connect_as(closed_addr, &closed_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = present(
        &mut alice_closed,
        Move::sign(&alice_seed, &b_key, now()),
        "b.test",
        vec![],
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(
        !Moved::decode(&body).unwrap().peered,
        "a listed exchange said an unlisted home was peered"
    );

    // The exchange under test.
    let x_dir = tempfile::tempdir().unwrap();
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        any_port(),
        Setup {
            open: true,
            ..Setup::default()
        },
    )
    .await;
    let x_key = PubKey::new(x_pub);
    let (mut a, mut ca, mut b) =
        group_at(x_addr, x_pub, (alice_seed, alice), (bob_seed, bob), group).await;
    // A second group Alice is not in.
    let (_c, _, _) = group_at(x_addr, x_pub, (carol_seed, carol), (bob_seed, bob), other).await;
    assert_eq!(texts(&mut a, group).await, ["hello", "hi"]);

    // A stranger is greeted and refused everything else, uniformly.
    let mut as_b = Client::connect_as(x_addr, &x_pub, &b_seed).await.unwrap();
    let (code, hi) = hello(&mut as_b).await;
    assert_eq!(code, 200, "an open exchange refused a stranger's hello");
    assert_eq!(hi.unwrap().exchange, x_key);
    assert_eq!(mine(&mut as_b, alice).await.0, 404);
    assert_eq!(
        pull(&mut as_b, group).await,
        404,
        "a stranger pulled a group"
    );
    assert_eq!(pull(&mut as_b, other).await, 404);
    assert_eq!(pull(&mut as_b, [99u8; 32]).await, 404);

    // Alice's Move, presented at B only. B lists nobody; X lists nobody.
    let (b_addr, b_pub) = exchange_in(
        b_dir.path(),
        any_port(),
        Setup {
            domain: "b.test",
            found: &[("x.test", x_key, x_addr)],
            ..Setup::default()
        },
    )
    .await;
    assert_eq!(PubKey::new(b_pub), b_key);
    let mut at_b = Client::connect_as(b_addr, &b_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = present(
        &mut at_b,
        Move::sign(&alice_seed, &b_key, now()),
        "b.test",
        vec![(x_key, "x.test".into())],
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));

    // B carried the Move to X over a link X never configured, and pulled.
    assert_eq!(
        until(&mut at_b, group, |t| t.len() == 2).await,
        ["hello", "hi"]
    );
    let (code, channels) = mine(&mut as_b, alice).await;
    assert_eq!(code, 200);
    assert_eq!(channels, vec![group]);
    assert_eq!(pull(&mut as_b, group).await, 200);
    // Entitled to hers and to nothing else: the same refusal as before.
    assert_eq!(
        pull(&mut as_b, other).await,
        404,
        "the home pulled a group its member is not in"
    );
    assert_eq!(pull(&mut as_b, [99u8; 32]).await, 404);

    // Alice posts through B; Bob reads it at X.
    let sa = Signer::new(alice_seed, alice, x_pub);
    let info = sa.info(&mut at_b, group).await;
    let post = sa.post_chained(&mut ca, group, info.instance, 0, 1, b"from b".to_vec());
    let (code, body) = at_b.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        until(&mut b, group, |t| t.len() == 3).await,
        ["hello", "hi", "from b"]
    );

    // And X, open, says a home it never listed is peered.
    let (code, body) = present(
        &mut a,
        Move::sign(&alice_seed, &b_key, now() + 1),
        "b.test",
        vec![],
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(Moved::decode(&body).unwrap().peered);
}

/// An origin nobody listed. Alice's exchange A and Bob's home B each list
/// no one and peer openly. A locates Bob at b.test, puts him in a group,
/// and tells B; B pulls the group from A and Bob reads it there. A listed
/// exchange with an empty list refuses the telling and the locating.
#[tokio::test]
async fn an_invitation_reaches_a_home_that_never_heard_of_the_origin() {
    let (alice_seed, alice) = identity(221);
    let (bob_seed, bob) = identity(222);
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let (a_key, a_seed) = key_in(a_dir.path());
    let (b_key, _) = key_in(b_dir.path());
    let (a_at, b_at) = (free_port(), free_port());
    let (a_addr, a_pub) = exchange_in(
        a_dir.path(),
        a_at,
        Setup {
            open: true,
            domain: "a.test",
            found: &[("b.test", b_key, b_at)],
            ..Setup::default()
        },
    )
    .await;
    let (b_addr, b_pub) = exchange_in(
        b_dir.path(),
        b_at,
        Setup {
            open: true,
            domain: "b.test",
            found: &[("a.test", a_key, a_at)],
            ..Setup::default()
        },
    )
    .await;
    assert_eq!((PubKey::new(a_pub), PubKey::new(b_pub)), (a_key, b_key));

    // Controls, at a listed exchange that finds b.test but lists nobody:
    // a stranger's telling is refused, and a lookup there is not made.
    let l_dir = tempfile::tempdir().unwrap();
    let (l_addr, l_pub) = exchange_in(
        l_dir.path(),
        any_port(),
        Setup {
            domain: "l.test",
            found: &[("b.test", b_key, b_at)],
            ..Setup::default()
        },
    )
    .await;
    let mut a_at_l = Client::connect_as(l_addr, &l_pub, &a_seed).await.unwrap();
    let (code, _) = a_at_l
        .post(
            "/peer/invited",
            PeerInvited {
                account: bob,
                channel: [221u8; 32],
                domain: "a.test".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 404, "a listed exchange took a stranger's hint");
    let mut alice_at_l = Client::connect_as(l_addr, &l_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = alice_at_l
        .post(
            "/account/locate",
            Locate {
                target: format!("{bob}@b.test"),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::NotAuthorised);

    // Bob lives at B.
    let mut bob_at_b = Client::connect_as(b_addr, &b_pub, &bob_seed).await.unwrap();
    let (code, body) = present(
        &mut bob_at_b,
        Move::sign(&bob_seed, &b_key, now()),
        "b.test",
        vec![],
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));

    // Alice at A locates him at a domain A does not list.
    let mut alice_at_a = Client::connect_as(a_addr, &a_pub, &alice_seed)
        .await
        .unwrap();
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
    assert_eq!((found.account, found.home), (bob, b_key));

    // A group at A with Bob in it. A tells B, which never heard of A; B
    // carries Bob's Move to A, pulls, and Bob reads at B.
    let sa = Signer::new(alice_seed, alice, a_pub);
    let mut ca = Chain::default();
    let channel = [222u8; 32];
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
    // A holds Bob's Move now, carried by a home it never listed.
    let (code, body) = alice_at_a
        .post("/account/home", bob.as_bytes().to_vec())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(sqex_proto::home::Homed::decode(&body).unwrap().home, b_key);
}

/// What a stranger can cost. X peers openly with a `peering` limit of
/// three an hour: the fourth hint from one key is `rate_limited` with
/// the seconds to wait, and a listed peer's is too. And an entitled
/// caller holds at most `MAX_WAITS_PER_PEER` waits: the ninth is refused
/// uniformly, and one is held again once the first eight let go.
#[tokio::test]
async fn a_stranger_pays_for_its_writes_and_its_waits() {
    let (alice_seed, alice) = identity(231);
    let (bob_seed, bob) = identity(232);
    let (s_seed, s_key) = identity(233);
    let (t_seed, t_key) = identity(234);
    let group = [231u8; 32];
    let x_dir = tempfile::tempdir().unwrap();
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        any_port(),
        Setup {
            open: true,
            peers: &[t_key],
            limits: "peering = [3, 3600]",
            ..Setup::default()
        },
    )
    .await;
    let (mut a, _, _) = group_at(x_addr, x_pub, (alice_seed, alice), (bob_seed, bob), group).await;

    // Hints from a stranger and from a listed peer, three each, then no.
    for (seed, name) in [(s_seed, "stranger"), (t_seed, "listed peer")] {
        let mut c = Client::connect_as(x_addr, &x_pub, &seed).await.unwrap();
        for i in 0..3 {
            let (code, body) = c
                .post(
                    "/peer/invited",
                    PeerInvited {
                        account: alice,
                        channel: [i; 32],
                        domain: "elsewhere.test".into(),
                    }
                    .encode(),
                )
                .await
                .unwrap();
            assert_eq!(code, 200, "{name}: {}", common::said(&body));
        }
        let (code, body) = c
            .post(
                "/peer/invited",
                PeerInvited {
                    account: alice,
                    channel: [9; 32],
                    domain: "elsewhere.test".into(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 429, "{name}: {}", common::said(&body));
        let r = Refusal::decode(&body).unwrap();
        assert_eq!(r.code, Code::RateLimited);
        assert!(
            r.detail
                .as_deref()
                .unwrap_or("")
                .parse::<u64>()
                .unwrap_or(0)
                >= 1,
            "no wait time in {:?}",
            r.detail
        );
        // A Move carried is counted in the same bucket.
        let (code, _) = c
            .post(
                "/peer/moved",
                sqex_proto::peer::PeerMoved {
                    mv: Move::sign(&alice_seed, &s_key, now()),
                    domain: "s.test".into(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 429, "{name}: a Move went past the limit");
    }

    // Waits. Alice names S her home so S is entitled to wait on her group.
    let (code, body) = present(
        &mut a,
        Move::sign(&alice_seed, &s_key, now() + 1),
        "s.test",
        vec![],
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let seq = {
        let mut c = Client::connect_as(x_addr, &x_pub, &s_seed).await.unwrap();
        let (code, body) = c
            .post(
                "/peer/wait",
                PeerWait {
                    wait_secs: 0,
                    channels: vec![(group, 0)],
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
        assert_eq!(Changed::decode(&body).unwrap().channels, vec![group]);
        // Past what the group holds, a wait holds.
        1_000u64
    };
    let mut held = tokio::task::JoinSet::new();
    for _ in 0..8 {
        held.spawn(async move {
            let mut c = Client::connect_as(x_addr, &x_pub, &s_seed).await.unwrap();
            let started = std::time::Instant::now();
            let (code, _) = c
                .post(
                    "/peer/wait",
                    PeerWait {
                        wait_secs: 3,
                        channels: vec![(group, seq)],
                    }
                    .encode(),
                )
                .await
                .unwrap();
            (code, started.elapsed())
        });
    }
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let mut ninth = Client::connect_as(x_addr, &x_pub, &s_seed).await.unwrap();
    let started = std::time::Instant::now();
    let (code, _) = ninth
        .post(
            "/peer/wait",
            PeerWait {
                wait_secs: 3,
                channels: vec![(group, seq)],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 404, "the ninth wait was held");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the ninth wait was held before being refused"
    );
    let mut codes = Vec::new();
    while let Some(r) = held.join_next().await {
        let (code, took) = r.unwrap();
        assert!(
            took >= std::time::Duration::from_secs(2),
            "a held wait let go early: {took:?}"
        );
        codes.push(code);
    }
    assert_eq!(
        codes,
        vec![200; 8],
        "the eight held waits were not all served"
    );
    // Let go, one is held again.
    let (code, _) = ninth
        .post(
            "/peer/wait",
            PeerWait {
                wait_secs: 1,
                channels: vec![(group, seq)],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "a wait was refused after the held ones let go");
}

async fn admin(addr: SocketAddr, server_pub: [u8; 32], admin_seed: [u8; 32], ops: Vec<Op>) {
    let mut c = Client::connect_as(addr, &server_pub, &admin_seed)
        .await
        .unwrap();
    let (cs, nonce_bytes) = c.get("/admin/challenge").await.unwrap();
    assert_eq!(cs, 200);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let txn = Transaction {
        server: PubKey::new(server_pub),
        nonce,
        ops: ops.into_iter().map(|o| o.to_operation()).collect(),
    };
    let signer = SoftwareSigner::new(SigningKey::from_bytes(&admin_seed));
    let (code, body) = c
        .post(
            "/admin/command",
            SignedTransaction::create(txn, &signer).encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
}

/// A dial that may be dropped at the door.
async fn try_connect(addr: SocketAddr, server_pub: [u8; 32], seed: [u8; 32]) -> Option<Client> {
    tokio::time::timeout(
        std::time::Duration::from_secs(4),
        Client::connect_as(addr, &server_pub, &seed),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
}

/// A closed origin admits the home its whitelisted member named, for as
/// long as her Move names it, and not the key she did not.
#[tokio::test]
async fn a_closed_origin_admits_the_home_its_member_named() {
    let (admin_seed, admin_key) = identity(241);
    let (alice_seed, alice) = identity(242);
    let (b_seed, b_key) = identity(243);
    let (c_seed, _) = identity(244);
    let x_dir = tempfile::tempdir().unwrap();
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        any_port(),
        Setup {
            open: true,
            admin: Some(admin_key),
            ..Setup::default()
        },
    )
    .await;
    let x_key = PubKey::new(x_pub);
    admin(
        x_addr,
        x_pub,
        admin_seed,
        vec![
            Op::WhitelistEnable,
            Op::WhitelistAdd {
                key: alice,
                label: Some("alice".into()),
            },
        ],
    )
    .await;
    assert!(
        try_connect(x_addr, x_pub, b_seed).await.is_none(),
        "an unlisted key got into a closed exchange"
    );

    // Alice names B her home: B is admitted, C is not.
    let mut a = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = present(
        &mut a,
        Move::sign(&alice_seed, &b_key, now()),
        "b.test",
        vec![],
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let mut as_b = try_connect(x_addr, x_pub, b_seed)
        .await
        .expect("the home Alice named was not admitted");
    assert_eq!(hello(&mut as_b).await.0, 200);
    assert!(try_connect(x_addr, x_pub, c_seed).await.is_none());

    // She moves back: B is admitted no longer.
    let (code, body) = present(
        &mut a,
        Move::sign(&alice_seed, &x_key, now() + 1),
        "x.test",
        vec![],
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        try_connect(x_addr, x_pub, b_seed).await.is_none(),
        "a former home stayed admitted"
    );
}
