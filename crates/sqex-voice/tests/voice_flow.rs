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
use sqexd::config::FileConfig;
use sqex_voice::audio::{TONE_HZ, dominant_hz, rms, tone};
use sqex_voice::jitter::{FRAME_SAMPLES, Jitter, Playout, SAMPLE_RATE};
use sqnr::Client;
use sqnr_core::PubKey;

/// One second of audio: fifty 20 ms frames.
const FRAMES: usize = 50;

// ---- harness (mirrors sqexd/tests/session_flow.rs) --------------------------

async fn bare_server(
    dir: &std::path::Path,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
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
        .post("/session/open", Open { peer, ephemeral: eph_pub }.encode())
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
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();
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
    let mut e = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
        .unwrap();
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
        let sealed = c.a_sess.seal_datagram(seq, &packet).unwrap();
        c.a.send_datagram(
            DatagramFrame { session_id: c.id, seq, ciphertext: sealed }.encode(),
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
        let Ok(Ok(bytes)) =
            tokio::time::timeout(Duration::from_secs(2), c.b.read_datagram()).await
        else {
            break;
        };
        let frame = DatagramFrame::decode(&bytes).unwrap();
        assert_eq!(frame.session_id, c.id);
        let packet = c
            .b_sess
            .open(frame.seq, &frame.ciphertext)
            .expect("the peer's key opens it");
        arrived.insert(frame.seq);
        buffer.push(frame.seq, packet);
    }

    // Drain the buffer the way the playout tick does, but without waiting out
    // a real second to do it.
    let mut dec = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).unwrap();
    let mut pcm = vec![0f32; FRAME_SAMPLES];
    let mut played = Vec::new();
    loop {
        match buffer.pop() {
            Playout::Frame(packet) => {
                dec.decode_float(&packet, &mut pcm, false).unwrap();
                played.push(pcm.clone());
            }
            Playout::Conceal => {
                dec.decode_float(&[], &mut pcm, false).unwrap();
                played.push(pcm.clone());
            }
            Playout::Idle => break,
        }
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
    let on_the_wire = DatagramFrame { session_id: c.id, seq: 0, ciphertext: sealed }.encode();

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
