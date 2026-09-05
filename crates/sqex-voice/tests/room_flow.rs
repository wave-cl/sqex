//! Three people in a room, through a real exchange.
//!
//! `voice_flow.rs` proved a tone survives the codec and one relay hop.
//! `sqexd/tests/room_flow.rs` proved the roster works. This is the join:
//! three identities find each other by room secret, mesh themselves together
//! with ordinary SIP-12 sessions, and each hears the other two — mixed, and
//! not itself.
//!
//! Everyone is a different note, so the mix can be read note by note.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqex_proto::room::RoomId;
use sqex_proto::session::{DatagramFrame, MAX_DATAGRAM_FRAME};
use sqex_voice::audio::{Rate, amplitude_at, tone_at};
use sqex_voice::jitter::{FRAME_SAMPLES, SAMPLE_RATE};
use sqex_voice::media;
use sqex_voice::mix::Mixer;
use sqex_voice::room::{Event, Membership};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

/// Each participant's note, and a second of audio each.
const NOTES: [f32; 3] = [440.0, 660.0, 887.0];
const FRAMES: usize = 50;

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

/// One participant: a connection, a membership, and a note to play.
struct Member {
    client: Client,
    room: Membership,
    identity: PubKey,
    note: f32,
    seq: u64,
}

impl Member {
    async fn new(addr: SocketAddr, server_pub: [u8; 32], room: RoomId, b: u8, note: f32) -> Member {
        let sk = SigningKey::from_bytes(&[b; 32]);
        let seed = sk.to_bytes();
        let identity = PubKey::new(sk.verifying_key().to_bytes());
        let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
        Member {
            client,
            room: Membership::new(room, identity, seed, 3, Rate::DEFAULT),
            identity,
            note,
            seq: 0,
        }
    }
}

/// Poll everyone's roster until the mesh is complete, or give up.
///
/// SIP-12 needs both ends to have asked, so a pair takes at least two rounds:
/// the first offers, the second finds the offer waiting.
async fn mesh(members: &mut [Member]) -> Vec<Event> {
    let want = members.len() - 1;
    let mut all_events = Vec::new();
    for _ in 0..12 {
        for m in members.iter_mut() {
            let events = m.room.poll(&mut m.client).await.unwrap();
            all_events.extend(events);
        }
        if members.iter().all(|m| m.room.peers.len() == want) {
            return all_events;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "mesh never completed: {:?}",
        members
            .iter()
            .map(|m| m.room.peers.len())
            .collect::<Vec<_>>()
    );
}

/// Everyone speaks their note; everyone listens. Returns what each identity
/// heard, mixed.
async fn converse(members: &mut [Member]) -> HashMap<PubKey, Vec<f32>> {
    let mut encoders: Vec<opus::Encoder> = members
        .iter()
        .map(|_| {
            let mut e =
                opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
                    .unwrap();
            e.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
            e
        })
        .collect();

    // Everyone talks over everyone, which is the case that matters.
    for f in 0..FRAMES {
        for (i, m) in members.iter_mut().enumerate() {
            let frame = tone_at(m.note, FRAMES)[f].clone();
            let packet = encoders[i]
                .encode_vec_float(&frame, MAX_DATAGRAM_FRAME)
                .unwrap();
            assert!(packet.len() <= MAX_DATAGRAM_FRAME);
            let seq = m.seq;
            for peer in m.room.peers.values() {
                let body = media::Frame::audio(seq as u32, packet.clone()).encode();
                let sealed = peer.session.seal_datagram(seq, &body).unwrap();
                m.client
                    .send_datagram(
                        DatagramFrame {
                            session_id: peer.session_id,
                            seq,
                            ciphertext: sealed,
                        }
                        .encode(),
                    )
                    .unwrap();
            }
            m.seq += 1;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Collect. Each member should receive FRAMES from each peer.
    let want = FRAMES * (members.len() - 1);
    for m in members.iter_mut() {
        let mut got = 0;
        while got < want {
            let Ok(Ok(bytes)) =
                tokio::time::timeout(Duration::from_secs(2), m.client.read_datagram()).await
            else {
                break;
            };
            let frame = DatagramFrame::decode(&bytes).unwrap();
            let Some(peer) = m.room.peers.get_mut(&frame.session_id) else {
                continue;
            };
            let plaintext = peer
                .session
                .open(frame.seq, &frame.ciphertext)
                .expect("a room peer's frames open");
            let m = media::Frame::decode(&plaintext)
                .expect("a media frame")
                .expect("a known type");
            peer.jitter.push(frame.seq, m.timestamp, m.body);
            got += 1;
        }
        assert_eq!(got, want, "{} did not hear everyone", m.identity);
    }

    // Play out and mix, the way the call loop does but without waiting a real
    // second to do it.
    let mut heard = HashMap::new();
    for m in members.iter_mut() {
        let mut mixer = Mixer::new(FRAME_SAMPLES);
        let mut pcm = vec![0f32; FRAME_SAMPLES];
        let mut audio: Vec<f32> = Vec::new();
        loop {
            mixer.start();
            for peer in m.room.peers.values_mut() {
                let slot = peer.jitter.pop();
                let decoded = peer.playback.render(&slot, &mut pcm);
                if decoded {
                    mixer.add(&pcm);
                }
            }
            if mixer.active() == 0 {
                break;
            }
            audio.extend_from_slice(mixer.finish());
        }
        heard.insert(m.identity, audio);
    }
    heard
}

async fn room_of(
    n: u8,
) -> (
    Vec<Member>,
    RoomId,
    tempfile::TempDir,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, handle) = bare_server(dir.path()).await;
    let room = RoomId::generate();
    let mut members = Vec::new();
    for i in 0..n {
        members.push(Member::new(addr, server_pub, room, 101 + i, NOTES[i as usize]).await);
    }
    (members, room, dir, handle)
}

#[tokio::test]
async fn three_people_in_a_room_each_hear_the_other_two() {
    let (mut members, _room, _dir, _h) = room_of(3).await;
    let events = mesh(&mut members).await;

    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::Joined(_)))
            .count(),
        6,
        "three people is six one-way arrivals"
    );
    assert!(
        !events.iter().any(|e| matches!(e, Event::Rejected(_))),
        "everyone holds the secret"
    );

    let heard = converse(&mut members).await;

    for m in &members {
        let audio = &heard[&m.identity];
        assert!(
            audio.len() >= FRAMES * FRAME_SAMPLES,
            "{} heard only {} samples",
            m.identity,
            audio.len()
        );
        // Skip the encoder settling in.
        let steady = &audio[FRAME_SAMPLES * 3..];

        for other in &members {
            let level = amplitude_at(steady, other.note);
            if other.identity == m.identity {
                assert!(
                    level < 0.03,
                    "you should not hear yourself: {} Hz at {level}",
                    other.note
                );
            } else {
                assert!(
                    level > 0.15,
                    "{} should hear {} Hz, got {level}",
                    m.identity,
                    other.note
                );
            }
        }
    }
}

/// The mesh is pairwise, so every pair has its own key. A frame addressed to
/// one peer must be meaningless to the other — otherwise "the exchange cannot
/// read a room" would be the only thing the design got right.
#[tokio::test]
async fn each_pair_in_a_room_has_its_own_key() {
    let (mut members, _room, _dir, _h) = room_of(3).await;
    mesh(&mut members).await;

    let a = &members[0];
    let sessions: Vec<u64> = a.room.peers.keys().copied().collect();
    assert_eq!(sessions.len(), 2);

    let packet = b"a twenty millisecond frame, notionally";
    let to_first = a.room.peers[&sessions[0]]
        .session
        .seal_datagram(0, packet)
        .unwrap();

    // The other session in the same room, held by the same person, cannot open
    // it: three people in a room share a room, not a key.
    assert!(
        a.room.peers[&sessions[1]]
            .session
            .open(0, &to_first)
            .is_err(),
        "one member's two sessions must not share a key"
    );
}

#[tokio::test]
async fn someone_who_leaves_stops_being_heard() {
    let (mut members, _room, _dir, _h) = room_of(3).await;
    mesh(&mut members).await;

    let leaver = members[2].identity;
    {
        let m = &mut members[2];
        m.room.leave(&mut m.client).await;
    }

    // The remaining two notice on their next roster, and drop the peer.
    let mut events = Vec::new();
    for _ in 0..3 {
        for m in members[..2].iter_mut() {
            events.extend(m.room.poll(&mut m.client).await.unwrap());
        }
    }
    assert!(
        events.contains(&Event::Left(leaver)),
        "the others should be told, {events:?}"
    );
    for m in &members[..2] {
        assert_eq!(m.room.peers.len(), 1, "one peer left in the room");
        assert!(!m.room.peers.values().any(|p| p.identity == leaver));
    }
}

/// The exchange can put an identity in a roster — it holds the roster. It
/// cannot make one that a member will talk to, because talking requires
/// passing a check that needs the room secret.
#[tokio::test]
async fn a_member_who_cannot_prove_the_secret_is_never_connected_to() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;
    let room = RoomId::generate();
    let wrong_room = RoomId::generate();

    let mut a = Member::new(addr, server_pub, room, 121, NOTES[0]).await;
    // Eve is in the same room as far as the exchange is concerned — same
    // handle — but her membership is built from a different secret, so her
    // proof is for a room nobody else is in.
    let mut eve = Member::new(addr, server_pub, room, 122, NOTES[1]).await;
    eve.room = Membership::new(wrong_room, eve.identity, [122u8; 32], 3, Rate::DEFAULT);

    // She cannot even join under her own secret, because that is a different
    // handle. So she joins under the right handle with a bogus proof.
    let (code, _) = eve
        .client
        .post(
            "/room/join",
            sqex_proto::room::Join {
                handle: room.handle(),
                proof: [0x11; 32],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "the exchange has no way to tell");

    let events = a.room.poll(&mut a.client).await.unwrap();
    assert!(
        events.contains(&Event::Rejected(eve.identity)),
        "A should refuse her, {events:?}"
    );
    assert!(a.room.peers.is_empty(), "and open no session with her");
    assert_eq!(a.room.connecting(), 0, "not even an attempt");

    // Complaining once is enough; a forged member should not fill the log.
    let again = a.room.poll(&mut a.client).await.unwrap();
    assert!(!again.contains(&Event::Rejected(eve.identity)));
}
