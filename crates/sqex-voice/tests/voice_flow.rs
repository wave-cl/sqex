//! A call's worth of real audio through a real exchange.
//!
//! `session_flow.rs` in sqexd proves that bytes cross the datagram path. This
//! proves that *audio* does: a 440 Hz tone is encoded by Opus, sealed, relayed
//! by a `sqexd` holding neither key, opened, buffered, decoded, and comes out
//! the far side still recognisably a 440 Hz tone.
//!
//! No microphone, no speaker, no person — which is the whole reason the demo
//! has a synthetic source and sink.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqex_proto::session::{DatagramFrame, MAX_DATAGRAM_FRAME, Open, OpenAck, OpenState, Session};
use sqex_voice::audio::{TONE_HZ, dominant_hz, rms, tone};
use sqex_voice::jitter::{FRAME_SAMPLES, Jitter, Playback, SAMPLE_RATE};
use sqex_voice::media;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

/// One second of audio: fifty 20 ms frames.
const FRAMES: usize = 50;

// ---- harness (mirrors sqexd/tests/session_flow.rs) --------------------------

async fn bare_server(dir: &std::path::Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn ephemeral() -> (x25519_dalek::StaticSecret, [u8; 32]) {
    let s = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let p = x25519_dalek::PublicKey::from(&s).to_bytes();
    (s, p)
}

async fn open_session(client: &mut Client, peer: PubKey, eph_pub: [u8; 32]) -> OpenAck {
    let (code, body) = client
        .post(
            "/session/open",
            Open {
                peer,
                ephemeral: eph_pub,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    OpenAck::decode(&body).unwrap()
}

/// Two identities with a session established both ways.
struct Call {
    a: Client,
    b: Client,
    a_sess: Session,
    b_sess: Session,
    id: u64,
    _server: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

async fn call() -> Call {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, server) = bare_server(dir.path()).await;

    let (a_seed, a_id) = identity(91);
    let (b_seed, b_id) = identity(92);
    let (a_eph, a_eph_pub) = ephemeral();
    let (b_eph, b_eph_pub) = ephemeral();
    let mut a = Client::connect_as(addr, &server_pub, &a_seed)
        .await
        .unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed)
        .await
        .unwrap();
    assert!(
        a.max_datagram_size().is_some() && b.max_datagram_size().is_some(),
        "no datagrams means no call"
    );

    open_session(&mut a, b_id, a_eph_pub).await;
    let b_ack = open_session(&mut b, a_id, b_eph_pub).await;
    let a_ack = open_session(&mut a, b_id, a_eph_pub).await;
    assert_eq!(a_ack.state, OpenState::Established);

    Call {
        a_sess: Session::derive(&a_seed, &a_eph, &b_id, &a_ack.peer_ephemeral).unwrap(),
        b_sess: Session::derive(&b_seed, &b_eph, &a_id, &b_ack.peer_ephemeral).unwrap(),
        id: a_ack.session_id,
        a,
        b,
        _server: server,
        _dir: dir,
    }
}

// ---- the call itself --------------------------------------------------------

fn encoder() -> opus::Encoder {
    let mut e =
        opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
    e.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
    e.set_inband_fec(true).unwrap();
    e.set_packet_loss_perc(10).unwrap();
    e
}

/// Encode a tone, send every frame whose sequence number `send` accepts, and
/// return what the other end managed to receive.
async fn relay(c: &mut Call, send: impl Fn(u64) -> bool) -> (Vec<Vec<f32>>, BTreeSet<u64>) {
    let mut enc = encoder();
    let frames = tone(FRAMES);
    let mut expected = BTreeSet::new();

    for (i, samples) in frames.iter().enumerate() {
        let seq = i as u64;
        if !send(seq) {
            continue;
        }
        let packet = enc.encode_vec_float(samples, MAX_DATAGRAM_FRAME).unwrap();
        assert!(
            packet.len() <= MAX_DATAGRAM_FRAME,
            "a 20 ms frame at 24 kbit/s is {} bytes, which does not fit a datagram",
            packet.len()
        );
        let body = media::Frame::audio(seq as u32, packet).encode();
        let sealed = c.a_sess.seal_datagram(seq, &body).unwrap();
        c.a.send_datagram(
            DatagramFrame {
                session_id: c.id,
                seq,
                ciphertext: sealed,
            }
            .encode(),
        )
        .unwrap();
        expected.insert(seq);
        // Pace them roughly as a call would rather than bursting a second of
        // audio into the socket at once.
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Collect until the far end has everything, or until it is clear the rest
    // is not coming.
    let mut buffer = Jitter::new(3);
    let mut arrived = BTreeSet::new();
    while arrived.len() < expected.len() {
        let Ok(Ok(bytes)) = tokio::time::timeout(Duration::from_secs(2), c.b.read_datagram()).await
        else {
            break;
        };
        let frame = DatagramFrame::decode(&bytes).unwrap();
        assert_eq!(frame.session_id, c.id);
        let plaintext = c
            .b_sess
            .open(frame.seq, &frame.ciphertext)
            .expect("the peer's key opens it");
        let m = media::Frame::decode(&plaintext)
            .expect("a media frame")
            .expect("a known type");
        arrived.insert(frame.seq);
        buffer.push(frame.seq, m.timestamp, m.body);
    }

    // Drain the buffer the way the playout tick does, but without waiting out
    // a real second to do it.
    let mut playback = Playback::new(SAMPLE_RATE).unwrap();
    let mut pcm = vec![0f32; FRAME_SAMPLES];
    let mut played = Vec::new();
    loop {
        let slot = buffer.pop();
        if !playback.render(&slot, &mut pcm) {
            break;
        }
        played.push(pcm.clone());
    }
    assert_eq!(
        buffer.stats.received as usize,
        arrived.len(),
        "every arrival should be counted once"
    );
    (played, arrived)
}

#[tokio::test]
async fn a_tone_survives_the_codec_and_the_relay() {
    let mut c = call().await;
    let (played, arrived) = relay(&mut c, |_| true).await;

    assert_eq!(arrived.len(), FRAMES, "every frame should cross loopback");
    assert_eq!(played.len(), FRAMES, "and every one should be played");

    // Opus needs a frame or two to settle, so judge the tone on the steady
    // part rather than on the encoder warming up.
    let audio: Vec<f32> = played[2..].concat();
    let measured = dominant_hz(&audio);
    assert!(
        (measured - TONE_HZ).abs() < 5.0,
        "expected {TONE_HZ} Hz out the far side, measured {measured}"
    );

    let source: Vec<f32> = tone(FRAMES)[2..].concat();
    let (want, got) = (rms(&source), rms(&audio));
    assert!(
        (got - want).abs() < want * 0.25,
        "loudness changed too much: {want} in, {got} out"
    );
}

#[tokio::test]
async fn lost_frames_are_concealed_rather_than_leaving_holes() {
    let dropped = [10u64, 11, 30];
    let mut c = call().await;
    let (played, arrived) = relay(&mut c, |seq| !dropped.contains(&seq)).await;

    for seq in dropped {
        assert!(!arrived.contains(&seq), "frame {seq} was never sent");
    }
    // The stream keeps its length: three slots came from Opus's imagination
    // rather than from a packet, and the call does not shorten by 60 ms.
    assert_eq!(
        played.len(),
        FRAMES,
        "concealment should fill the gaps, not skip them"
    );

    let audio: Vec<f32> = played[2..].concat();
    let measured = dominant_hz(&audio);
    assert!(
        (measured - TONE_HZ).abs() < 15.0,
        "concealed audio should still be the tone, measured {measured}"
    );
    // Concealment is not silence: an actual continuation was invented.
    for (i, seq) in dropped.iter().enumerate() {
        let slot = &played[*seq as usize];
        assert!(
            rms(slot) > 0.05,
            "concealed slot {i} (seq {seq}) is silence, not concealment"
        );
    }
}

#[tokio::test]
async fn the_exchange_carrying_the_call_cannot_listen_to_it() {
    let c = call().await;

    // Everything the exchange sees of a frame: the session it belongs to, its
    // sequence number, and its length.
    let packet = encoder()
        .encode_vec_float(&tone(1)[0], MAX_DATAGRAM_FRAME)
        .unwrap();
    let sealed = c.a_sess.seal_datagram(0, &packet).unwrap();
    let on_the_wire = DatagramFrame {
        session_id: c.id,
        seq: 0,
        ciphertext: sealed,
    }
    .encode();

    let relayed = DatagramFrame::decode(&on_the_wire).unwrap();
    assert_ne!(
        relayed.ciphertext, packet,
        "the Opus packet must not appear on the wire"
    );
    // The exchange derives no session key — it has no static private key to
    // derive one with — so this is all it could ever try.
    assert!(
        c.b_sess.open(1, &relayed.ciphertext).is_err(),
        "a frame is bound to its sequence number"
    );
    assert!(
        c.b_sess.open(0, &relayed.ciphertext).is_ok(),
        "and opens under the right one"
    );
}

/// A call between two ends running at different rates.
///
/// One peer is on a Bluetooth headset at 16 kHz and the other on a 48 kHz
/// device — the pairing that used to be impossible, since the demo refused
/// anything but 48. Nothing negotiates: the sender encodes at its rate, the
/// receiver decodes at its own, and Opus reconciles them.
#[tokio::test]
async fn a_16k_caller_is_heard_by_a_48k_listener() {
    let c = call().await;

    let low = 16_000u32;
    let mut enc = opus::Encoder::new(low, opus::Channels::Mono, opus::Application::Voip).unwrap();
    enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
    let low_frame = (low as usize * 20) / 1000;

    // A 440 Hz tone as a 16 kHz microphone would deliver it.
    let mut phase = 0.0f32;
    let step = std::f32::consts::TAU * TONE_HZ / low as f32;
    for seq in 0..FRAMES as u64 {
        let frame: Vec<f32> = (0..low_frame)
            .map(|_| {
                let s = phase.sin() * 0.5;
                phase = (phase + step) % std::f32::consts::TAU;
                s
            })
            .collect();
        let packet = enc.encode_vec_float(&frame, MAX_DATAGRAM_FRAME).unwrap();
        assert!(packet.len() <= MAX_DATAGRAM_FRAME);
        let body = media::Frame::audio(seq as u32, packet).encode();
        let sealed = c.a_sess.seal_datagram(seq, &body).unwrap();
        c.a.send_datagram(
            DatagramFrame {
                session_id: c.id,
                seq,
                ciphertext: sealed,
            }
            .encode(),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // The far end knows nothing of 16 kHz and decodes at its own rate.
    let mut buffer = Jitter::new(3);
    let mut arrived = 0;
    while arrived < FRAMES {
        let Ok(Ok(bytes)) = tokio::time::timeout(Duration::from_secs(2), c.b.read_datagram()).await
        else {
            break;
        };
        let frame = DatagramFrame::decode(&bytes).unwrap();
        let m = media::Frame::decode(&c.b_sess.open(frame.seq, &frame.ciphertext).unwrap())
            .unwrap()
            .expect("a known type");
        buffer.push(frame.seq, m.timestamp, m.body);
        arrived += 1;
    }
    assert_eq!(arrived, FRAMES);

    let mut playback = Playback::new(SAMPLE_RATE).unwrap();
    let mut pcm = vec![0f32; FRAME_SAMPLES];
    let mut played: Vec<f32> = Vec::new();
    loop {
        let slot = buffer.pop();
        if !playback.render(&slot, &mut pcm) {
            break;
        }
        played.extend_from_slice(&pcm);
    }

    // A second in at 16 kHz is a second out at 48 kHz, and still a 440 Hz tone.
    assert_eq!(played.len(), FRAME_SAMPLES * FRAMES);
    let steady = &played[FRAME_SAMPLES * 3..];
    let measured = dominant_hz(steady);
    assert!(
        (measured - TONE_HZ).abs() < 5.0,
        "a narrowband caller should still sound like themselves, measured {measured}"
    );
    assert!(rms(steady) > 0.2, "and be audible");
}

/// SIP-15 end to end: somebody stops talking, and the far end hears their
/// room — not a hole, not a guess, and not a pulse.
///
/// This is three failures' worth of test. Rendering a pause as zeros chops the
/// noise floor in and out; concealing it invents speech; and replaying
/// concealment from an isolated noise frame overshoots and decays, which is the
/// pulse that killed the first noise gate. Describing the silence and
/// synthesising it is the only version of this that both saves the bandwidth
/// and sounds right.
#[tokio::test]
async fn a_pause_is_heard_as_the_room_and_costs_almost_nothing() {
    let c = call().await;

    let mut enc =
        opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
    enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
    enc.set_dtx(false).unwrap(); // SIP-15: we decide, not the codec
    let mut sender = media::Sender::new(50, true);

    // A room, then talking, then the room again. Never digital silence — that
    // is the case a synthetic test gets wrong and a microphone never produces.
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut phase = 0.0f32;
    let step = std::f32::consts::TAU * TONE_HZ / SAMPLE_RATE as f32;
    let mut seq = 0u64;
    let mut sent_slots: Vec<usize> = Vec::new();
    const SLOTS: usize = 500;

    for i in 0..SLOTS {
        let samples: Vec<f32> = (0..FRAME_SAMPLES)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let noise = ((seed >> 33) as f32 / (1u64 << 30) as f32 - 1.0) * 0.006;
                let s = if (150..250).contains(&i) {
                    phase.sin() * 0.5 + noise
                } else {
                    noise
                };
                phase = (phase + step) % std::f32::consts::TAU;
                s
            })
            .collect();
        let framed = sender
            .offer(&samples, |pcm| {
                enc.encode_vec_float(pcm, MAX_DATAGRAM_FRAME - media::HEADER)
                    .map_err(|e| sqnr_core::Error::Malformed(format!("{e}")))
            })
            .unwrap();
        if let Some(m) = framed {
            let sealed = c.a_sess.seal_datagram(seq, &m.encode()).unwrap();
            c.a.send_datagram(
                DatagramFrame {
                    session_id: c.id,
                    seq,
                    ciphertext: sealed,
                }
                .encode(),
            )
            .unwrap();
            sent_slots.push(i);
            seq += 1;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let on_the_wire = sent_slots.len();
    // The settled part of the pause, well clear of the gate's warm-up window
    // and the hangover after speech.
    let settled = 320..SLOTS;
    let in_settled = sent_slots.iter().filter(|i| settled.contains(i)).count();
    println!(
        "  SIP-15: {SLOTS} slots -> {on_the_wire} packets; \
         {in_settled}/{} during the settled pause",
        settled.len()
    );
    assert!(
        in_settled * 10 < settled.len(),
        "a settled pause should cost about a packet a second, sent {in_settled}"
    );

    let mut buffer = Jitter::new(3);
    let mut got = 0;
    while got < on_the_wire {
        let Ok(Ok(b)) = tokio::time::timeout(Duration::from_secs(2), c.b.read_datagram()).await
        else {
            break;
        };
        let frame = DatagramFrame::decode(&b).unwrap();
        let m = media::Frame::decode(&c.b_sess.open(frame.seq, &frame.ciphertext).unwrap())
            .unwrap()
            .expect("a known type");
        buffer.push(frame.seq, m.timestamp, m.body);
        got += 1;
    }
    assert_eq!(got, on_the_wire, "everything sent arrived");

    let mut playback = Playback::new(SAMPLE_RATE).unwrap();
    let mut pcm = vec![0f32; FRAME_SAMPLES];
    let mut played: Vec<Vec<f32>> = Vec::new();
    loop {
        let slot = buffer.pop();
        if !playback.render(&slot, &mut pcm) {
            break;
        }
        played.push(pcm.clone());
    }

    // The timeline did not shorten by the frames nobody sent.
    assert!(
        played.len() >= SLOTS - 10,
        "the call should still be ~{SLOTS} slots long, got {}",
        played.len()
    );
    assert_eq!(buffer.stats.concealed, 0, "nothing was invented");

    let levels: Vec<f32> = played.iter().map(|f| rms(f)).collect();
    let pause = &levels[330..levels.len() - 5];

    // Not dead: the room is still there.
    assert_eq!(
        pause.iter().filter(|x| **x < 0.0005).count(),
        0,
        "a pause must not contain digitally dead frames"
    );
    // Not pulsing: this is what killed the gate that replayed concealment.
    let (lo, hi) = pause
        .iter()
        .fold((f32::MAX, 0.0f32), |(l, h), x| (l.min(*x), h.max(*x)));
    assert!(
        hi / lo < 4.0,
        "a synthesised pause must be steady, swung {lo:.5} to {hi:.5}"
    );
    // And about as loud as the room actually was.
    let want = 0.006 / 3f32.sqrt();
    let mean = pause.iter().sum::<f32>() / pause.len() as f32;
    assert!(
        (mean / want).log2().abs() < 1.5,
        "the room came back at {mean:.5}, was {want:.5}"
    );

    // Speech either side survived.
    let speech: Vec<f32> = played[170..240].concat();
    assert!(
        (dominant_hz(&speech) - TONE_HZ).abs() < 10.0,
        "speech should be intact, measured {}",
        dominant_hz(&speech)
    );
}
