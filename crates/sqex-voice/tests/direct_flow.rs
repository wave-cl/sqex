//! A call that goes straight between two peers after the exchange introduces
//! them (SIP-25), and the two ways it does not.
//!
//! On loopback there is no NAT, so what this proves is the flow -- the
//! introduction over a throwaway connection from a chosen port, the punch,
//! the dial and the listen, the ephemerals over the direct connection, and
//! the media loop over its datagrams -- and not the hole. The hole is what
//! the two-homes field test in `docs/sip25-field-test.md` is for.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use sqex_voice::audio::{Sink, Source, TONE_HZ, dominant_hz, rms};
use sqex_voice::direct::{self, Budget, DIRECT_SESSION};
use sqex_voice::engine::{self, CallOpts, Carrier, Endpoint, Event, Report, Silent};
use sqexd::config::FileConfig;
use sqnr_core::{PubKey, SoftwareSigner};

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

fn signer(b: u8) -> (SoftwareSigner, PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    let public = PubKey::new(sk.verifying_key().to_bytes());
    (SoftwareSigner::new(sk), public)
}

#[derive(Default, Clone)]
struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<Event>>>);

impl Recorder {
    fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }
}

impl Report for Recorder {
    fn event(&mut self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}

fn tone_call(sink: &Path, seconds: u64) -> CallOpts {
    CallOpts {
        source: Source::Tone,
        sink: Sink::Wav(sink.to_path_buf()),
        seconds: Some(seconds),
        dtx: false,
        ..CallOpts::default()
    }
}

/// A budget that does not make a failing test wait out a ring.
fn quick() -> Budget {
    Budget {
        introduce_wait: 2,
        handshake: Duration::from_secs(2),
        accept: Duration::from_secs(3),
    }
}

/// Both ask, both are introduced, one dials the other, they agree a key
/// nobody else was party to, and a tone crosses the direct connection in
/// both directions through the ordinary media loop.
#[tokio::test]
async fn two_peers_introduced_by_an_exchange_call_each_other_directly() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };
    let (a_signer, a_id) = signer(1);
    let (b_signer, b_id) = signer(2);
    let a_wav = dir.path().join("a-heard.wav");
    let b_wav = dir.path().join("b-heard.wav");
    let (mut a_report, mut b_report) = (Recorder::default(), Recorder::default());

    let a = async {
        let got = direct::connect(endpoint, &a_signer.seed(), b_id, quick(), &mut a_report)
            .await?
            .ok_or("A was not introduced")?;
        let (conn, session, id) = got;
        assert_eq!(id, DIRECT_SESSION);
        assert!(
            conn.max_datagram_size().is_some(),
            "the direct connection carries datagrams"
        );
        engine::call(conn, session, id, tone_call(&a_wav, 1), &mut a_report).await
    };
    let b = async {
        let got = direct::connect(endpoint, &b_signer.seed(), a_id, quick(), &mut b_report)
            .await?
            .ok_or("B was not introduced")?;
        let (conn, session, id) = got;
        engine::call(conn, session, id, tone_call(&b_wav, 1), &mut b_report).await
    };
    let (a_result, b_result) = tokio::join!(a, b);
    a_result.expect("A's call");
    b_result.expect("B's call");

    for (who, path) in [("A", &a_wav), ("B", &b_wav)] {
        let mut reader = hound::WavReader::open(path).unwrap_or_else(|e| panic!("{who}: {e}"));
        let samples: Vec<f32> = reader
            .samples::<i16>()
            .map(|s| s.unwrap() as f32 / i16::MAX as f32)
            .collect();
        assert!(
            samples.len() > 4_000,
            "{who} played back only {} samples",
            samples.len()
        );
        assert!(rms(&samples) > 0.01, "{who} heard silence");
        let hz = dominant_hz(&samples);
        assert!(
            (hz - TONE_HZ).abs() < 30.0,
            "{who} heard {hz:.0} Hz, wanted about {TONE_HZ:.0} Hz"
        );
    }
    // Both said they went direct, and to a loopback address -- the exchange
    // is not in the path.
    for (who, r) in [("A", &a_report), ("B", &b_report)] {
        let events = r.events();
        let direct = events.iter().find_map(|e| match e {
            Event::Direct { peer } => Some(*peer),
            _ => None,
        });
        let peer = direct.unwrap_or_else(|| panic!("{who} did not say it went direct: {events:?}"));
        assert!(peer.ip().is_loopback());
        assert_ne!(peer, addr, "{who} is talking to the exchange, not the peer");
        assert!(
            !events.iter().any(|e| matches!(e, Event::Relayed { .. })),
            "{who} said it was relayed: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::SessionUp { id, .. } if *id == DIRECT_SESSION))
        );
    }
}

/// One side asks and the other never does: the wait ends with nothing --
/// not an error, and not a word about the other side -- and inside the
/// budget, so the caller can relay in time.
#[tokio::test]
async fn an_introduction_nobody_returns_is_nothing_and_is_quick() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };
    let (a_signer, _) = signer(1);
    let (_, b_id) = signer(2);
    let started = Instant::now();
    let got = direct::connect(endpoint, &a_signer.seed(), b_id, quick(), &mut Silent)
        .await
        .expect("asking is not an error");
    assert!(got.is_none(), "nobody was there to be introduced to");
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(5),
        "the wait is the budget, no more: {took:?}"
    );
}

/// The listener admits only the peer it was introduced to. B is told to
/// expect C while A dials: A's handshake is refused and B hears nobody, so
/// both come back with an error rather than a connection to the wrong
/// person -- and the error names what the two-homes test will see when a
/// NAT is in the way, which is the same symptom.
#[tokio::test]
async fn the_listener_admits_only_the_peer_it_was_introduced_to() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    // Whichever of the two dials is A here; the other listens.
    let (one, two) = (signer(1), signer(2));
    let ((a_signer, a_id), (b_signer, b_id)) = if direct::dials(&one.1, &two.1) {
        (one, two)
    } else {
        (two, one)
    };
    let (_, c_id) = signer(3);
    assert!(direct::dials(&a_id, &b_id));

    let a = async {
        let intro = direct::introduce(addr, &server_pub, &a_signer.seed(), b_id, 5)
            .await?
            .ok_or("A was not introduced")?;
        direct::link(intro, &a_signer.seed(), b_id, quick()).await
    };
    let b = async {
        let intro = direct::introduce(addr, &server_pub, &b_signer.seed(), a_id, 5)
            .await?
            .ok_or("B was not introduced")?;
        // Introduced to A, but told to admit C.
        direct::listen_for(intro, &b_signer.seed(), c_id, quick()).await
    };
    let (a_result, b_result) = tokio::join!(a, b);
    let a_err = a_result.expect_err("A must not get a connection");
    let b_err = b_result.expect_err("B must not admit A");
    assert!(a_err.contains("no direct connection"), "{a_err}");
    assert!(b_err.contains("no direct connection"), "{b_err}");
}

/// The carrier over a direct connection round-trips a datagram, which is
/// the one thing the media loop needs of it.
#[tokio::test]
async fn a_direct_connection_carries_a_datagram_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };
    let (a_signer, a_id) = signer(1);
    let (b_signer, b_id) = signer(2);
    let a = async {
        direct::connect(endpoint, &a_signer.seed(), b_id, quick(), &mut Silent)
            .await?
            .ok_or_else(|| "A was not introduced".to_string())
    };
    let b = async {
        direct::connect(endpoint, &b_signer.seed(), a_id, quick(), &mut Silent)
            .await?
            .ok_or_else(|| "B was not introduced".to_string())
    };
    let (a, b) = tokio::join!(a, b);
    let (mut a_conn, a_session, _) = a.unwrap();
    let (mut b_conn, b_session, _) = b.unwrap();

    let sealed = a_session.seal_datagram(7, b"hello").unwrap();
    Carrier::send_datagram(&mut a_conn, sealed).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), Carrier::read_datagram(&mut b_conn))
        .await
        .expect("B hears A")
        .unwrap();
    assert_eq!(b_session.open(7, &got).unwrap(), b"hello");

    let sealed = b_session.seal_datagram(9, b"back").unwrap();
    Carrier::send_datagram(&mut b_conn, sealed).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), Carrier::read_datagram(&mut a_conn))
        .await
        .expect("A hears B")
        .unwrap();
    assert_eq!(a_session.open(9, &got).unwrap(), b"back");

    // And a frame sealed under a key that is not this session's does not
    // open: the key came from the ephemerals, not from anything the
    // exchange or a bystander could know.
    let session_c = sqex_proto::session::Session::derive(
        &signer(3).0.seed(),
        &x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng),
        &a_id,
        &[9u8; 32],
    )
    .unwrap();
    let stray = session_c.seal_datagram(1, b"stray").unwrap();
    assert!(a_session.open(1, &stray).is_err());
}
