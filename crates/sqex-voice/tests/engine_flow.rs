//! A whole call, driven through the engine's own API.
//!
//! `voice_flow.rs` proves the pieces — codec, jitter buffer, silence
//! descriptor — by wiring them together itself. This proves the **loop**: the
//! `tokio::select!` that actually holds a call, with its gate, its trim, its
//! playout tick and its teardown.
//!
//! That loop lived in `main.rs` until the engine lift and so was reachable
//! from nothing but a terminal, which is to say it was never tested at all.
//! Moving it into the library is what makes this file possible, and this file
//! is most of the argument for having moved it.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqex_voice::audio::{Sink, Source, TONE_HZ, dominant_hz, rms};
use sqex_voice::engine::{self, CallOpts, Endpoint, Event, Report, Silent};
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

/// Collects what the engine said, so a test can assert on the *diagnosis* and
/// not merely on the audio.
#[derive(Default)]
struct Collected(std::sync::Arc<std::sync::Mutex<Vec<Event>>>);

impl Collected {
    fn handle(&self) -> Recorder {
        Recorder(self.0.clone())
    }
    fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }
}

struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<Event>>>);

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
        // Discontinuous transmission off: a pure tone is speech to the gate,
        // but leaving it on would make the test depend on the gate's judgement
        // as well as the loop's, and this is about the loop.
        dtx: false,
        ..CallOpts::default()
    }
}

/// **A muted peer is silent, not gone.**
///
/// The tempting mute is to stop sending. It is wrong: `jitter::COAST_LIMIT` is
/// two seconds, so a sender that goes quiet empties the far end's buffer, is
/// counted as an underrun, and has to refill before it plays again -- and in a
/// room `room::Membership::STALE` tears the session down entirely. Muting
/// yourself for a minute would arrive at the other end as leaving.
///
/// So this mutes A for well past the coast limit and asks B's own counters
/// whether anything was *missing*. Concealment and underruns are what loss
/// looks like; deliberate silence shows up as neither.
#[tokio::test]
async fn a_muted_peer_is_silent_and_not_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };
    let (a_signer, a_id) = signer(11);
    let (b_signer, b_id) = signer(12);

    // B is the one listening to a muted peer, so B is the one recorded.
    let events = Collected::default();
    let mut b_report = events.handle();

    // A's mute, held here so the test can throw it mid-call.
    let (muting, muted_rx) = tokio::sync::watch::channel(engine::Controls::default());

    let a_dir = dir.path().to_path_buf();
    let a_task = tokio::spawn(async move {
        let mut report = Silent;
        let (client, session, id) =
            engine::establish(endpoint, &a_signer, b_id, 20, &mut report).await?;
        let opts = CallOpts {
            controls: Some(muted_rx),
            ..tone_call(&a_dir.join("a.wav"), 6)
        };
        engine::call(client, session, id, opts, &mut report).await
    });

    // Long enough to be talking, then muted for three times the coast limit.
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let _ = muting.send(engine::Controls {
            muted: true,
            ..Default::default()
        });
        // Held until the call ends: dropping the sender must not unmute, and
        // `control_changed` treats a dropped sender as "wait", never as an
        // instruction.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        drop(muting);
    });

    let b = async {
        let (client, session, id) =
            engine::establish(endpoint, &b_signer, a_id, 20, &mut b_report).await?;
        engine::call(
            client,
            session,
            id,
            tone_call(&dir.path().join("b.wav"), 6),
            &mut b_report,
        )
        .await
    };
    let done = tokio::time::timeout(std::time::Duration::from_secs(30), b).await;
    a_task.abort();
    assert!(done.is_ok(), "B never finished its six-second call");
    done.unwrap().expect("B's call");

    let seen = events.events();
    let stats = seen
        .iter()
        .find_map(|e| match e {
            Event::FinalStats(s) => Some(s.clone()),
            _ => None,
        })
        .expect("B reported no final stats, so this says nothing about them");

    // `sent 300 · recv 280 · loss 0.0% · … · concealed 0 · … · underruns 0 · …`
    let field = |name: &str| -> u64 {
        stats
            .split('·')
            .find_map(|part| part.trim().strip_prefix(name))
            .unwrap_or_else(|| panic!("no {name:?} in {stats:?}"))
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("{name:?} in {stats:?}: {e}"))
    };

    // The control: B heard A at all. Without this the two assertions below
    // pass for a call that never carried anything.
    assert!(
        field("recv ") > 0,
        "B received nothing at all, muted or not: {stats}"
    );
    assert_eq!(
        field("concealed "),
        0,
        "B concealed frames while A was muted, so a mute is arriving as packet \
         loss: {stats}"
    );
    assert_eq!(
        field("underruns "),
        0,
        "B's buffer ran dry while A was muted, which is what a sender that \
         stops sending does: {stats}"
    );
}

/// The whole point: two engines, a real exchange, and a tone that survives it.
#[tokio::test]
async fn a_call_driven_through_the_engine_carries_audio_both_ways() {
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

    let a_events = Collected::default();
    let (mut a_report, mut b_report) = (a_events.handle(), Silent);

    // Both sides must be establishing at once: consent is mutual, so neither
    // completes until the other has asked too.
    let a = async {
        let (client, session, id) =
            engine::establish(endpoint, &a_signer, b_id, 20, &mut a_report).await?;
        engine::call(client, session, id, tone_call(&a_wav, 1), &mut a_report).await
    };
    let b = async {
        let (client, session, id) =
            engine::establish(endpoint, &b_signer, a_id, 20, &mut b_report).await?;
        engine::call(client, session, id, tone_call(&b_wav, 1), &mut b_report).await
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
            "{who} played back only {} samples; the loop stopped early",
            samples.len()
        );
        assert!(rms(&samples) > 0.01, "{who} heard silence");
        let hz = dominant_hz(&samples);
        assert!(
            (hz - TONE_HZ).abs() < 30.0,
            "{who} heard {hz:.0} Hz, wanted about {TONE_HZ:.0} Hz"
        );
    }

    // The engine reported what it did, rather than printing it somewhere no
    // caller could reach -- which is the other half of the lift.
    let events = a_events.events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Identity(id) if *id == a_id)),
        "the engine says who you are: {events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(e, Event::SessionUp { .. })),
        "the engine says the session came up: {events:?}"
    );
    assert!(
        events.iter().any(|e| matches!(e, Event::Stats(_))),
        "the engine reports statistics: {events:?}"
    );

    // The closing summary is its own event, and deliberately so: the CLI has
    // always printed it even under `--quiet`, and routing it through the
    // periodic `Stats` would have dropped it for anyone who asked for a quiet
    // call. That is a regression a move like this loses in silence.
    let finals: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(e, Event::FinalStats(_)))
        .collect();
    assert_eq!(
        finals.len(),
        1,
        "exactly one closing summary, at the end: {events:?}"
    );
    assert!(
        matches!(events.last(), Some(Event::FinalStats(_))),
        "the closing summary is the last thing said: {:?}",
        events.last()
    );
}

/// A `Report` that drops the periodic statistics, as `--quiet` does, must still
/// be told how the call went.
#[tokio::test]
async fn quiet_still_hears_the_closing_summary() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };

    let (a_signer, a_id) = signer(1);
    let (b_signer, b_id) = signer(2);
    let a_wav = dir.path().join("a.wav");
    let b_wav = dir.path().join("b.wav");

    let events = Collected::default();
    let mut a_report = events.handle();
    let mut b_report = Silent;

    let a = async {
        let (c, s, id) = engine::establish(endpoint, &a_signer, b_id, 20, &mut a_report).await?;
        engine::call(c, s, id, tone_call(&a_wav, 1), &mut a_report).await
    };
    let b = async {
        let (c, s, id) = engine::establish(endpoint, &b_signer, a_id, 20, &mut b_report).await?;
        engine::call(c, s, id, tone_call(&b_wav, 1), &mut b_report).await
    };
    let (ra, rb) = tokio::join!(a, b);
    ra.unwrap();
    rb.unwrap();

    // What a quiet CLI would actually print.
    let printed: Vec<String> = events
        .events()
        .into_iter()
        .filter(|e| !matches!(e, Event::Stats(_)))
        .map(|e| e.describe())
        .collect();
    assert!(
        printed.iter().any(|line| line.starts_with("sent ")),
        "a quiet call still says how it went: {printed:?}"
    );
}

/// A call with nobody on the other end must give up rather than hang, and say
/// which of the two invisible causes it might be.
#[tokio::test]
async fn waiting_alone_times_out_and_names_the_causes() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };

    let (a_signer, _) = signer(1);
    let (_, b_id) = signer(2);
    let events = Collected::default();
    let mut report = events.handle();

    let err = tokio::time::timeout(
        Duration::from_secs(10),
        engine::establish(endpoint, &a_signer, b_id, 1, &mut report),
    )
    .await
    .expect("it must give up on its own, not hang");
    // `Client` and `Session` are not Debug, so unwrap the error by hand rather
    // than through `expect_err`.
    let err = match err {
        Ok(_) => panic!("nobody answered, yet a session was established"),
        Err(e) => e,
    };
    assert!(err.contains("did not join in time"), "unexpected: {err}");

    let got = events.events();
    assert!(
        got.iter()
            .any(|e| matches!(e, Event::Waiting { peer } if *peer == b_id)),
        "it says who it is waiting for: {got:?}"
    );
}

/// Calling yourself is a mistake worth catching before the network sees it:
/// a session needs two identities, and the exchange would only ever answer
/// `Waiting`.
#[tokio::test]
async fn calling_yourself_is_refused_locally() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };
    let (a_signer, a_id) = signer(1);

    let err = match engine::dial(endpoint, &a_signer, a_id, &mut Silent).await {
        Ok(_) => panic!("a session with yourself has no second end to consent"),
        Err(e) => e,
    };
    assert!(err.contains("two identities"), "unexpected: {err}");
}

/// A room reports its roster as data, not only as a printed line.
///
/// This is what a window needs and a terminal never did: who is here, who is
/// speaking, and how their path is holding up, as numbers it can draw rather
/// than a sentence it would have to parse back.
#[tokio::test]
async fn a_room_reports_who_is_present_and_who_is_speaking() {
    use sqex_proto::room::RoomId;
    use sqex_voice::engine::{Event as E, PeerStatus};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };
    let room = RoomId::generate();

    let (a_signer, a_id) = signer(1);
    let (b_signer, b_id) = signer(2);

    let a_events = Collected::default();
    let mut a_report = a_events.handle();
    let mut b_report = Silent;

    // Long enough for several heartbeats. Peers pair up on the two-second
    // roster tick, and the two sides' ticks are not in phase: if A offers at
    // t=2.0 and B has not yet, A's open returns `Waiting` and A does not try
    // again until t=4.0. At four seconds that race lost about one run in
    // three. Eight gives it three more chances, and the test still takes
    // longer than anything else here -- which is the price of driving two real
    // clients through a real exchange rather than asserting against a mock.
    const SECONDS: u64 = 8;

    // A listens on a tone, B talks. Both must be in the room at once for
    // either to hear anything, so they run together.
    let a = async {
        let client = engine::connect(endpoint, &a_signer, &mut a_report).await?;
        engine::room_call(
            client,
            &a_signer,
            room,
            tone_call(&dir.path().join("a.wav"), SECONDS),
            &mut a_report,
        )
        .await
    };
    let b = async {
        let client = engine::connect(endpoint, &b_signer, &mut b_report).await?;
        engine::room_call(
            client,
            &b_signer,
            room,
            tone_call(&dir.path().join("b.wav"), SECONDS),
            &mut b_report,
        )
        .await
    };
    let (ra, rb) = tokio::join!(a, b);
    ra.expect("A's room");
    rb.expect("B's room");

    let events = a_events.events();
    let rosters: Vec<(Vec<PeerStatus>, usize)> = events
        .iter()
        .filter_map(|e| match e {
            E::Present { peers, connecting } => Some((peers.clone(), *connecting)),
            _ => None,
        })
        .collect();
    assert!(
        !rosters.is_empty(),
        "a room describes its roster: {events:?}"
    );

    // B is in the room and eventually present, having joined via the heartbeat.
    let saw_b = rosters
        .iter()
        .any(|(peers, _)| peers.iter().any(|p| p.identity == b_id));
    assert!(saw_b, "B should appear in A's roster");

    // And with a tone playing, B is heard as speaking.
    let heard_b_speak = rosters
        .iter()
        .any(|(peers, _)| peers.iter().any(|p| p.identity == b_id && p.speaking));
    assert!(
        heard_b_speak,
        "B is playing a tone, so B should read as speaking: {rosters:?}"
    );

    // A never appears in A's own roster: you are not a peer of yourself, and a
    // room showing you back to yourself would double every count.
    assert!(
        !rosters
            .iter()
            .any(|(peers, _)| peers.iter().any(|p| p.identity == a_id)),
        "you are not one of your own peers"
    );

    // The roster is sorted, so a list drawn from it does not reshuffle.
    for (peers, _) in &rosters {
        let mut sorted = peers.clone();
        sorted.sort_unstable_by_key(|p| *p.identity.as_bytes());
        assert_eq!(
            peers.iter().map(|p| p.identity).collect::<Vec<_>>(),
            sorted.iter().map(|p| p.identity).collect::<Vec<_>>(),
            "the roster arrives in a stable order"
        );
    }
}

/// **An end frame ends the call, and ends it properly.**
///
/// A call in a channel records its ending in the log, which both sides
/// read. A bridged call (SIP-39) has no channel, so when one party hangs
/// up the far exchange had no way to pass that on: the audio stopped
/// because nothing was being relayed any more, and the call stayed on the
/// screen with nothing to say why. Reported from the field.
///
/// The exchange now says it on the path the call is already reading — a
/// frame with a header and no body, which media never is. This drives that
/// frame in directly and asserts the call **drains** rather than merely
/// stopping: draining is what reaches the `/session/close` at the end of
/// the loop, so this side tells its own exchange too.
#[tokio::test]
async fn a_frame_with_no_body_ends_the_call() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let endpoint = Endpoint {
        address: addr,
        server: PubKey::new(server_pub),
    };
    let (a_signer, a_id) = signer(1);
    let (b_signer, b_id) = signer(2);

    // B is the one being told, so B is the one recorded.
    let events = Collected::default();
    let (mut a_report, mut b_report) = (Silent, events.handle());

    // Sixty-second sources, so neither can end on its own inside the test:
    // what ends B has to be the frame.
    let a_dir = dir.path().to_path_buf();
    let a_task = tokio::spawn(async move {
        let mut report = Silent;
        let (client, session, id) =
            engine::establish(endpoint, &a_signer, b_id, 20, &mut report).await?;
        // What the exchange sends when a bridge drops. Sent from here
        // because a party to the session is the only thing a test can be,
        // and the exchange forwards it to the counterpart either way —
        // which is the path being tested.
        let poke = client.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            let _ = poke.send_datagram(sqex_proto::session::DatagramFrame::ended(id).encode());
        });
        engine::call(
            client,
            session,
            id,
            tone_call(&a_dir.join("a.wav"), 60),
            &mut report,
        )
        .await
    });
    let _ = &mut a_report;

    let b = async {
        let (client, session, id) =
            engine::establish(endpoint, &b_signer, a_id, 20, &mut b_report).await?;
        engine::call(
            client,
            session,
            id,
            tone_call(&dir.path().join("b.wav"), 60),
            &mut b_report,
        )
        .await
    };
    let done = tokio::time::timeout(std::time::Duration::from_secs(20), b).await;
    a_task.abort();
    assert!(
        done.is_ok(),
        "B never ended: a 60-second call outlived a 20-second wait, so the frame did nothing"
    );
    done.unwrap().expect("B's call");

    // **Drained, not merely stopped.** Draining is what reaches the
    // `/session/close` at the end of the loop, so this side tells its own
    // exchange too rather than leaving a session for the TTL to reap.
    let seen = events.events();
    assert!(
        seen.iter().any(|e| matches!(e, Event::Draining)),
        "B stopped without draining, so it never closed its session: {seen:?}"
    );
}
