//! `POST /admin/tail`, over real HTTP/3: who may open one, how many at once,
//! and that opening one is recorded.
//!
//! The controls matter more than the happy path here. A tail is a live view of
//! everything an exchange does, and with no config gate on the capability the
//! audit entry is the only thing standing between "an administrator opened
//! one" and nobody knowing. So the tests that earn their place are the ones
//! that fail if the door is wider than it should be.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Buf;
use ed25519_dalek::SigningKey;
use sqex_proto::Op;
use sqex_proto::tail::{self, Framer, Line, Record};
use sqexd::config::FileConfig;
use sqnr_core::{Operation, PubKey, SignedTransaction, SoftwareSigner, Transaction};
use squic::Config as SquicConfig;

struct Harness {
    addr: SocketAddr,
    server_pub_bytes: [u8; 32],
    server_pub: PubKey,
    admin: SoftwareSigner,
    outsider: SoftwareSigner,
    _dir: tempfile::TempDir,
    _handle: tokio::task::JoinHandle<()>,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("host_key");
    let state_path = dir.path().join("sqex.state");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();

    let admin_sk = SigningKey::from_bytes(&[7u8; 32]);
    let admin_pub = PubKey::new(admin_sk.verifying_key().to_bytes());
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = [{:?}]\n\
         welcome_channel = \"\"\n",
        key_path.to_string_lossy(),
        state_path.to_string_lossy(),
        admin_pub.to_base58(),
    );
    let config_path = dir.path().join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, Some(config_path), signing_key)
        .await
        .unwrap();
    let addr = bound.local_addr;
    let server_pub_bytes = bound.public_key.to_bytes();
    let handle = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    Harness {
        addr,
        server_pub_bytes,
        server_pub: PubKey::new(server_pub_bytes),
        admin: SoftwareSigner::new(admin_sk),
        outsider: SoftwareSigner::new(SigningKey::from_bytes(&[8u8; 32])),
        _dir: dir,
        _handle: handle,
    }
}

/// One HTTP/3 connection. Unlike `admin_flow`'s client this one can leave a
/// response open, which is the whole point of the route under test.
struct Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _drive: tokio::task::JoinHandle<()>,
}

impl Client {
    async fn connect(addr: SocketAddr, server_pub: &[u8; 32], seed: &[u8; 32]) -> Client {
        let conn = squic::dial(
            addr,
            server_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                client_key: Some(hex::encode(seed)),
                advertise_identity: true,
                ..Default::default()
            },
        )
        .await
        .expect("the exchange answers");
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Client {
            send,
            _drive: drive,
        }
    }

    async fn get(&mut self, path: &str) -> (u16, Vec<u8>) {
        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://sqex{path}"))
            .body(())
            .unwrap();
        let mut stream = self.send.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        let mut out = Vec::new();
        while let Some(mut c) = stream.recv_data().await.unwrap() {
            while c.remaining() > 0 {
                let n = c.chunk().len();
                out.extend_from_slice(c.chunk());
                c.advance(n);
            }
        }
        (resp.status().as_u16(), out)
    }

    async fn post(&mut self, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
        let req = http::Request::builder()
            .method("POST")
            .uri(format!("https://sqex{path}"))
            .body(())
            .unwrap();
        let mut stream = self.send.send_request(req).await.unwrap();
        stream.send_data(bytes::Bytes::from(body)).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        let mut out = Vec::new();
        while let Some(mut c) = stream.recv_data().await.unwrap() {
            while c.remaining() > 0 {
                let n = c.chunk().len();
                out.extend_from_slice(c.chunk());
                c.advance(n);
            }
        }
        (resp.status().as_u16(), out)
    }

    /// Sign a batch and send it somewhere. `nonce` is taken fresh unless one is
    /// supplied, which is how the replay control reuses a spent one.
    async fn signed(
        &mut self,
        path: &str,
        ops: Vec<Operation>,
        server_pub: &PubKey,
        signer: &SoftwareSigner,
        nonce: Option<[u8; 32]>,
    ) -> (u16, Vec<u8>, [u8; 32]) {
        let nonce = match nonce {
            Some(n) => n,
            None => {
                let (cs, bytes) = self.get("/admin/challenge").await;
                assert_eq!(cs, 200);
                let mut n = [0u8; 32];
                n.copy_from_slice(&bytes);
                n
            }
        };
        let txn = Transaction {
            server: *server_pub,
            nonce,
            ops,
        };
        let signed = SignedTransaction::create(txn, signer);
        let (s, b) = self.post(path, signed.encode()).await;
        (s, b, nonce)
    }

    /// Open a tail and hand back the live stream, without draining it.
    async fn open_tail(
        &mut self,
        server_pub: &PubKey,
        signer: &SoftwareSigner,
    ) -> (
        u16,
        h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    ) {
        let (cs, bytes) = self.get("/admin/challenge").await;
        assert_eq!(cs, 200);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes);
        let txn = Transaction {
            server: *server_pub,
            nonce,
            ops: vec![
                Op::TailOpen {
                    version: tail::VERSION,
                    kinds: tail::WANT_ALL,
                }
                .to_operation(),
            ],
        };
        let signed = SignedTransaction::create(txn, signer);
        let req = http::Request::builder()
            .method("POST")
            .uri("https://sqex/admin/tail")
            .body(())
            .unwrap();
        let mut stream = self.send.send_request(req).await.unwrap();
        stream
            .send_data(bytes::Bytes::from(signed.encode()))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        (resp.status().as_u16(), stream)
    }
}

/// Read until a line satisfies `want`, or give up. Returns what it saw, so a
/// failure can say what arrived instead of only that nothing did.
async fn wait_for(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    within: Duration,
    want: impl Fn(&Line) -> bool,
) -> (bool, Vec<Line>) {
    let mut framer = Framer::new();
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return (false, seen);
        }
        let got = tokio::time::timeout(left, stream.recv_data()).await;
        let Ok(Ok(Some(mut chunk))) = got else {
            return (false, seen);
        };
        let mut buf = Vec::new();
        while chunk.remaining() > 0 {
            let n = chunk.chunk().len();
            buf.extend_from_slice(chunk.chunk());
            chunk.advance(n);
        }
        for line in framer.feed(&buf).expect("well-formed lines") {
            let hit = want(&line);
            seen.push(line);
            if hit {
                return (true, seen);
            }
        }
    }
}

/// **The door.** A correctly signed transaction from a key that is not an
/// administrator opens nothing — and it must be refused before any stream
/// exists, not after.
#[tokio::test]
async fn a_non_admin_cannot_open_a_tail() {
    let h = harness().await;
    let mut c = Client::connect(h.addr, &h.server_pub_bytes, &[9u8; 32]).await;
    let (status, stream) = c.open_tail(&h.server_pub, &h.outsider).await;
    assert_eq!(status, 403, "a stranger's signature opened a tail");
    drop(stream);

    // And the control on the control: the same call by the admin works, so the
    // 403 above is about who signed and not about the request being malformed.
    let (status, _s) = c.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!(status, 200, "the administrator could not open one either");
}

/// A nonce is single-use for a tail exactly as it is for a command. Without
/// this, a captured open could be replayed for as long as the admin key lived.
#[tokio::test]
async fn a_spent_nonce_cannot_open_a_tail() {
    let h = harness().await;
    let mut c = Client::connect(h.addr, &h.server_pub_bytes, &[9u8; 32]).await;
    let op = Op::TailOpen {
        version: tail::VERSION,
        kinds: tail::WANT_ALL,
    }
    .to_operation();

    // Spend one on a command, then try to reuse it on the tail.
    let (status, _b, nonce) = c
        .signed(
            "/admin/command",
            vec![Op::WhitelistList.to_operation()],
            &h.server_pub,
            &h.admin,
            None,
        )
        .await;
    assert_eq!(status, 200);
    let (status, _b, _n) = c
        .signed(
            "/admin/tail",
            vec![op],
            &h.server_pub,
            &h.admin,
            Some(nonce),
        )
        .await;
    assert_eq!(status, 401, "a spent nonce opened a tail");
}

/// A tail is a fan-out the request path pays for, so the count is bounded and
/// the refusal is a refusal rather than a queue.
#[tokio::test]
async fn only_two_tails_at_once() {
    let h = harness().await;
    let mut c = Client::connect(h.addr, &h.server_pub_bytes, &[9u8; 32]).await;
    let (s1, _a) = c.open_tail(&h.server_pub, &h.admin).await;
    let (s2, _b) = c.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!((s1, s2), (200, 200), "the first two should open");
    let (s3, _c) = c.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!(s3, 429, "a third tail was allowed");
}

/// **The only control there is.** With no config gate, an audit entry is what
/// stops a tail being something an operator can do unobserved — so it is
/// written before the first line, it survives in the state file, and a second
/// tail sees the first one being opened.
#[tokio::test]
async fn opening_a_tail_is_recorded_and_visible_to_another_tail() {
    let h = harness().await;
    let mut watcher = Client::connect(h.addr, &h.server_pub_bytes, &[9u8; 32]).await;
    let (status, mut first) = watcher.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!(status, 200);

    // A second administrator opening a tail is an event the first one sees.
    let mut other = Client::connect(h.addr, &h.server_pub_bytes, &[10u8; 32]).await;
    let (status, _second) = other.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!(status, 200);

    let (saw, seen) = wait_for(
        &mut first,
        Duration::from_secs(5),
        |l| matches!(&l.record, Record::Admin { action, .. } if action == "tail-open"),
    )
    .await;
    assert!(
        saw,
        "a tail did not see another tail being opened: {seen:?}"
    );

    // And it is in the audit log, which outlives every stream.
    let mut c = Client::connect(h.addr, &h.server_pub_bytes, &[11u8; 32]).await;
    let (status, body, _n) = c
        .signed(
            "/admin/command",
            vec![Op::AuditTail(50).to_operation()],
            &h.server_pub,
            &h.admin,
            None,
        )
        .await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries = v["results"][0]["entries"].as_array().cloned().unwrap();
    let opens = entries
        .iter()
        .filter(|e| e["action"] == "tail-open")
        .count();
    assert!(
        opens >= 2,
        "opening a tail was not audited; entries: {entries:?}"
    );
}

/// What it is for: a tail shows activity that is nobody else's. The request
/// below is made by a different connection, to a route the watcher never
/// called.
#[tokio::test]
async fn a_tail_sees_another_connections_request() {
    let h = harness().await;
    let mut watcher = Client::connect(h.addr, &h.server_pub_bytes, &[9u8; 32]).await;
    let (status, mut stream) = watcher.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!(status, 200);

    let mut other = Client::connect(h.addr, &h.server_pub_bytes, &[12u8; 32]).await;
    let (s, _b) = other.get("/health").await;
    assert_eq!(s, 200);

    let (saw, seen) = wait_for(
        &mut stream,
        Duration::from_secs(5),
        |l| matches!(&l.record, Record::Request { route, .. } if route == "/health"),
    )
    .await;
    assert!(
        saw,
        "the tail missed another connection's request: {seen:?}"
    );
}

/// `/status` says how many tails are open, so the capability is visible to
/// anybody reading the exchange rather than only to whoever holds the audit
/// log.
#[tokio::test]
async fn status_reports_open_tails() {
    let h = harness().await;
    let mut c = Client::connect(h.addr, &h.server_pub_bytes, &[9u8; 32]).await;
    let (_s, body) = c.get("/status").await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tails"], 0);
    assert_eq!(v["tails_opened"], 0);

    let (status, _stream) = c.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!(status, 200);

    let (_s, body) = c.get("/status").await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["tails"], 1, "an open tail is not reported");
    assert_eq!(v["tails_opened"], 1);
}

/// **A line says which connection it arrived on.**
///
/// Without it the tail could say a connection had ended, and say what had been
/// served, and nothing could join the two. Reading "why is this peer
/// redialling" meant pairing a close with whatever line happened to precede it
/// — which is not a pairing at all when several connections interleave, as they
/// always do. Tried against this estate on 2026-10-01 and the answer had to be
/// thrown away: it attributed a close to `/device/list` and `/prekey/count`,
/// which are not even routes the far exchange calls.
///
/// The property is the whole of it: requests over one connection carry one id,
/// and two connections carry two.
#[tokio::test]
async fn a_request_names_the_connection_it_arrived_on() {
    let h = harness().await;
    let mut watcher = Client::connect(h.addr, &h.server_pub_bytes, &[9u8; 32]).await;
    let (status, mut stream) = watcher.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!(status, 200);

    // Two connections, two requests each, interleaved so that neither
    // ordering nor adjacency could stand in for the identifier.
    let mut one = Client::connect(h.addr, &h.server_pub_bytes, &[21u8; 32]).await;
    let mut two = Client::connect(h.addr, &h.server_pub_bytes, &[22u8; 32]).await;
    for _ in 0..2 {
        assert_eq!(one.get("/health").await.0, 200);
        assert_eq!(two.get("/health").await.0, 200);
    }

    let got = std::sync::atomic::AtomicUsize::new(0);
    let (saw, seen) = wait_for(&mut stream, Duration::from_secs(8), |l| {
        matches!(&l.record, Record::Request { route, .. } if route == "/health")
            && got.fetch_add(1, std::sync::atomic::Ordering::Relaxed) >= 3
    })
    .await;
    assert!(saw, "the tail did not report four requests: {seen:?}");

    let mut by_conn: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for l in &seen {
        if let Record::Request { route, conn, .. } = &l.record
            && route == "/health"
        {
            *by_conn.entry(*conn).or_default() += 1;
        }
    }
    let mut counts: Vec<usize> = by_conn.values().copied().collect();
    counts.sort_unstable();
    assert_eq!(
        counts,
        vec![2, 2],
        "four requests over two connections should group two and two, got {by_conn:?}"
    );
}

/// **One line per event, with how far it reached.**
///
/// The tail wrote a line per *recipient*, so a read mark in a 32-member channel
/// drew 32 lines saying an event had gone to somebody -- while one stream was
/// open and one frame went out. An operator reading that over-counted by 32, and
/// the tail's volume scaled with membership rather than activity: at SIP-16's
/// `MAX_MEMBERS` one read mark is 256 lines, and two of those overrun `QUEUE`
/// and cost the watcher a `Dropped` -- the instrument losing records because
/// somebody marked a message read.
///
/// `live` is asserted separately from `to`, because that is the distinction a
/// line per recipient could not express: entitled to hear it is not told.
#[tokio::test]
async fn an_event_is_one_line_saying_how_far_it_reached() {
    let h = harness().await;
    let mut watcher = Client::connect(h.addr, &h.server_pub_bytes, &[9u8; 32]).await;
    let (status, mut stream) = watcher.open_tail(&h.server_pub, &h.admin).await;
    assert_eq!(status, 200);

    // One member, holding no stream: `to` is 1 and `live` 0, which is the pair a
    // line per recipient could not tell apart.
    let alice_sk = SigningKey::from_bytes(&[41u8; 32]);
    let alice_seed = alice_sk.to_bytes();
    let alice = sqnr_core::PubKey::new(alice_sk.verifying_key().to_bytes());
    let mut a = Client::connect(h.addr, &h.server_pub_bytes, &alice_seed).await;
    let channel = [41u8; 32];
    let s = crate::common::Signer::new(alice_seed, alice, h.server_pub_bytes);
    let mut chain = crate::common::Chain::default();
    let create = s.create_chained(
        &mut chain,
        channel,
        crate::common::instance_for(channel, 0),
        sqex_proto::channel::Visibility::Public,
        3600,
        "tailing",
        vec![],
    );
    let (code, body) = a.post("/channel/create", create.encode()).await;
    assert_eq!(code, 200, "{}", crate::common::said(&body));

    // **A second member, because one cannot tell the two shapes apart.** With a
    // single member "a line per recipient" *is* one line, so a one-member test
    // passes against the behaviour it exists to refuse -- which this one did,
    // until the sabotage showed it.
    let bob_sk = SigningKey::from_bytes(&[42u8; 32]);
    let bob_seed = bob_sk.to_bytes();
    let bob = sqnr_core::PubKey::new(bob_sk.verifying_key().to_bytes());
    let mut b = Client::connect(h.addr, &h.server_pub_bytes, &bob_seed).await;
    let bs = crate::common::Signer::new(bob_seed, bob, h.server_pub_bytes);
    let action = bs.action_outside(
        channel,
        crate::common::instance_for(channel, 0),
        sqex_proto::channel::EVENT_JOINED,
        &bob,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, body) = b
        .post(
            "/channel/join",
            sqex_proto::channel::ByChannelSigned { channel, action }
                .encode(sqex_proto::channel::TYPE_JOIN),
        )
        .await;
    assert_eq!(code, 200, "{}", crate::common::said(&body));

    // Bob's join is told to the members, which is now two of them.
    // **Waited past the events, not stopped at one.** A request made after them
    // is the marker: stopping at the first matching event line meant a second,
    // duplicate line was never read, and the test passed against the behaviour
    // it exists to refuse. The sabotage showed that too.
    let (code, _) = a.get("/health").await;
    assert_eq!(code, 200);
    let (saw, seen) = wait_for(
        &mut stream,
        Duration::from_secs(8),
        |l| matches!(&l.record, Record::Request { route, .. } if route == "/health"),
    )
    .await;
    assert!(saw, "the tail never reported the marker request: {seen:?}");

    let events: Vec<(u32, u32)> = seen
        .iter()
        .filter_map(|l| match &l.record {
            Record::Event {
                event, to, live, ..
            } if *event == 0x04 => Some((*to, *live)),
            _ => None,
        })
        .collect();
    // Two membership changes, two lines: the create (one member entitled) and
    // Bob's join (two). A line per recipient would make the join two lines and
    // this three -- which is the whole distinction, and why one member could not
    // test it.
    assert_eq!(
        events,
        vec![(1, 0), (2, 0)],
        "two membership changes should draw two lines, with the count entitled \
         and nought written to a stream nobody held: {events:?}"
    );
}
