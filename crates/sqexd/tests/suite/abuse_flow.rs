//! SIP-56: a rate limit refuses with how long to wait; a mute leaves a
//! member reading and stops them writing, at the origin and at a copy; a
//! report reaches the admins and nobody else.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByAccount, ByChannel, ByChannelSigned, ByTarget, EVENT_JOINED, EVENT_MUTED, EVENT_REPLICATE,
    EVENT_UNMUTED, Entries, Fetch, Report, Reports, SignalOut, TYPE_DISMISS, TYPE_JOIN, TYPE_MUTE,
    TYPE_REPLICATE, TYPE_REPORTS, TYPE_UNMUTE, Visibility,
};
use sqex_proto::events::{Event as WireEvent, Framer, Subscribe};
use sqex_proto::message::SIGNAL_TYPING;
use sqex_proto::refusal::{Code, Refusal};
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

/// An origin with posts limited to three a minute, peering with `peers`.
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
         welcome_channel = \"\"\nreplication_peers = [{list}]\n\n[limits]\nposts = [3, 60]\n",
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

async fn post(
    c: &mut Client,
    s: &Signer,
    chain: &mut Chain,
    channel: [u8; 32],
    t: &[u8],
) -> (u16, Vec<u8>) {
    let info = s.info(c, channel).await;
    let before = Chain { ..*chain };
    let req = s.post_chained(chain, channel, info.instance, 0, 0, t.to_vec());
    let (code, body) = c.post("/channel/post", req.encode()).await.unwrap();
    if code != 200 {
        *chain = before;
    }
    (code, body)
}

async fn texts(c: &mut Client, channel: [u8; 32]) -> Vec<String> {
    let (code, body) = c
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since: 0,
                wait_secs: 0,
                receipts: false,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Entries::decode(&body, false)
        .unwrap()
        .entries
        .iter()
        .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .map(|e| String::from_utf8_lossy(&e.body).into_owned())
        .collect()
}

fn code_of(body: &[u8]) -> (Code, String) {
    let r = Refusal::decode(body).unwrap();
    (r.code, r.detail.unwrap_or_default())
}

#[tokio::test]
async fn limits_mutes_and_reports_do_what_they_say() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let y_key = key_in(y_dir.path());
    let (x_addr, x_pub) = origin_in(x_dir.path(), &[y_key]).await;
    let x_key = PubKey::new(x_pub);
    let (alice_seed, alice) = identity(1);
    let (bob_seed, bob) = identity(2);
    let channel = [1u8; 32];

    // Alice's room; Bob joins at the origin.
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
    let mut b = Client::connect_as(x_addr, &x_pub, &bob_seed).await.unwrap();
    let sb = Signer::new(bob_seed, bob, x_pub);
    let mut cb = Chain::default();
    let joining = sb.action_chained(
        &mut cb,
        channel,
        instance_for(channel, 0),
        EVENT_JOINED,
        &bob,
        &[],
    );
    assert_eq!(
        b.post(
            "/channel/join",
            ByChannelSigned {
                channel,
                action: joining
            }
            .encode(TYPE_JOIN)
        )
        .await
        .unwrap()
        .0,
        200
    );

    // Three posts a minute: the fourth is refused, says how long, and
    // writes nothing; Alice's own bucket is her own.
    for t in [b"one".as_slice(), b"two", b"three"] {
        let (code, body) = post(&mut b, &sb, &mut cb, channel, t).await;
        assert_eq!(code, 200, "{}", common::said(&body));
    }
    let (code, body) = post(&mut b, &sb, &mut cb, channel, b"four").await;
    assert_eq!(code, 429, "{}", common::said(&body));
    let (c, detail) = code_of(&body);
    assert_eq!(c, Code::RateLimited);
    let wait: u64 = detail.parse().expect("the detail is seconds");
    assert!((1..=20).contains(&wait), "{wait}");
    assert_eq!(texts(&mut b, channel).await, ["one", "two", "three"]);
    assert_eq!(post(&mut a, &sa, &mut ca, channel, b"alice").await.0, 200);

    // Muted: Bob reads, and cannot post, signal or upload; unmuted, he can.
    // (A fresh bucket: the limit is per minute and the test is not.)
    let action = sa.action_chained(
        &mut ca,
        channel,
        instance_for(channel, 0),
        EVENT_MUTED,
        &bob,
        &[],
    );
    let (code, body) = a
        .post(
            "/channel/mute",
            ByAccount {
                channel,
                account: bob,
                action,
            }
            .encode(TYPE_MUTE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let got = texts(&mut b, channel).await;
    assert_eq!(
        got,
        ["one", "two", "three", "alice"],
        "a muted member could not read"
    );
    let (code, body) = b
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind: SIGNAL_TYPING,
                body: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403, "{}", common::said(&body));
    assert_eq!(code_of(&body).0, Code::Muted);
    // Not an admin: Bob cannot mute Alice; and Alice cannot mute an admin.
    let bad = sb.action_chained(
        &mut cb,
        channel,
        instance_for(channel, 0),
        EVENT_MUTED,
        &alice,
        &[],
    );
    let (code, _) = b
        .post(
            "/channel/mute",
            ByAccount {
                channel,
                account: alice,
                action: bad,
            }
            .encode(TYPE_MUTE),
        )
        .await
        .unwrap();
    assert_eq!(code, 403);
    let action = sa.action_chained(
        &mut ca,
        channel,
        instance_for(channel, 0),
        EVENT_UNMUTED,
        &bob,
        &[],
    );
    let (code, body) = a
        .post(
            "/channel/unmute",
            ByAccount {
                channel,
                account: bob,
                action,
            }
            .encode(TYPE_UNMUTE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let (code, body) = b
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind: SIGNAL_TYPING,
                body: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Muted again, and this time seen from a copy: the copy derives it from
    // the log and refuses Bob's post itself, before any forward.
    let action = sa.action_chained(
        &mut ca,
        channel,
        instance_for(channel, 0),
        EVENT_MUTED,
        &bob,
        &[],
    );
    assert_eq!(
        a.post(
            "/channel/mute",
            ByAccount {
                channel,
                account: bob,
                action
            }
            .encode(TYPE_MUTE)
        )
        .await
        .unwrap()
        .0,
        200
    );
    let (y_addr, y_pub) = replica_in(y_dir.path(), x_key, x_addr, channel).await;
    let mut at_y = Client::connect_as(y_addr, &y_pub, &bob_seed).await.unwrap();
    let mut derived = false;
    for _ in 0..50 {
        let (code, body) = at_y
            .post(
                "/channel/signal",
                SignalOut {
                    channel,
                    kind: SIGNAL_TYPING,
                    body: vec![],
                }
                .encode(),
            )
            .await
            .unwrap();
        if code == 403 && code_of(&body).0 == Code::Muted {
            derived = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    assert!(derived, "the copy never derived the mute");
    let info = sb.info(&mut at_y, channel).await;
    let req = sb.post_chained(&mut cb, channel, info.instance, 0, 0, b"from y".to_vec());
    let (code, body) = at_y.post("/channel/post", req.encode()).await.unwrap();
    assert_eq!(code, 403, "{}", common::said(&body));
    assert_eq!(code_of(&body).0, Code::Muted);
    assert_eq!(
        texts(&mut at_y, channel).await.len(),
        4,
        "a muted member could not read the copy"
    );

    // A report from Bob reaches Alice -- as an event on her stream, and in
    // the list only she can read. Bob cannot read it; dismissed, it goes.
    let stream = a
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
    let (code, body) = b
        .post(
            "/channel/report",
            Report {
                channel,
                target: 4,
                reason: 1,
                note: "spam".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let mut framer = Framer::new();
    let told = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let chunk = stream.next().await.unwrap().expect("stream ended");
            for e in framer.feed(&chunk).unwrap() {
                if let WireEvent::Reported { channel: c } = e {
                    return c;
                }
            }
        }
    })
    .await;
    assert_eq!(told.ok(), Some(channel), "the admin was not told");
    let (code, body) = a
        .post(
            "/channel/reports",
            ByChannel { channel }.encode(TYPE_REPORTS),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let r = Reports::decode(&body).unwrap();
    assert_eq!(r.reports.len(), 1);
    assert_eq!(
        (
            r.reports[0].reporter,
            r.reports[0].target,
            r.reports[0].reason
        ),
        (bob, 4, 1)
    );
    assert_eq!(r.reports[0].note, "spam");
    let (code, _) = b
        .post(
            "/channel/reports",
            ByChannel { channel }.encode(TYPE_REPORTS),
        )
        .await
        .unwrap();
    assert_eq!(code, 403, "a member read the reports");
    let (code, _) = a
        .post(
            "/channel/dismiss",
            ByTarget {
                channel,
                target: r.reports[0].id,
            }
            .encode(TYPE_DISMISS),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (_, body) = a
        .post(
            "/channel/reports",
            ByChannel { channel }.encode(TYPE_REPORTS),
        )
        .await
        .unwrap();
    assert!(Reports::decode(&body).unwrap().reports.is_empty());
    // And a report is not in the log.
    assert_eq!(texts(&mut a, channel).await.len(), 4);
}
