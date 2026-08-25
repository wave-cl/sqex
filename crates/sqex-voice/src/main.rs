//! A voice call over a SIP-12 relayed session.
//!
//! SIP-12 gives two identities a way to exchange bytes through an exchange that
//! can read none of them, and SIP-12's datagram carriage costs about half a
//! millisecond a frame instead of the hundred that polling costs. That is the
//! whole argument for the unreliable path, and until now nothing had put real
//! media through it. This does: 20 ms of Opus, twenty times a second, relayed
//! by a `sqexd` that is holding neither key.
//!
//! The exchange forwards packets and does not manage a call — SIP-12 is
//! explicit that a jitter buffer, loss concealment, echo cancellation, a codec
//! and rate control belong to the application. Three of those live here. Echo
//! cancellation does not: **wear headphones**.
//!
//! This is a demo. It is not built or shipped with `sqex` and `sqexd`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use sqex_proto::room::{HEARTBEAT_SECS, RoomId};
use sqex_proto::session::{BySession, DatagramFrame, MAX_DATAGRAM_FRAME, Open, OpenAck, OpenState, Session};
use sqnr::{Client, config::Config, identity};
use sqnr_core::{PubKey, Signer};

use sqex_voice::audio::{self, Sink, Source};
use sqex_voice::jitter::{FRAME_MS, FRAME_SAMPLES, Jitter, Playout, Rtt, SAMPLE_RATE};
use sqex_voice::mix::Mixer;
use sqex_voice::room::{self, Event as RoomEvent, Membership};

#[derive(Parser)]
#[command(
    name = "sqex-voice",
    version,
    about = "Demo: Opus voice over a SIP-12 relayed session",
    long_about = "Two identities hold a voice call through a sqex exchange that can read none \
                  of it. Frames ride QUIC datagrams: unreliable, unordered, and never \
                  retransmitted, which is the right trade for speech.\n\n\
                  There is no echo cancellation. On speakers this will howl. Wear headphones."
)]
struct Cli {
    /// Server address, host:port (overrides SQEX_SERVER and ~/.sqnr/config).
    #[arg(long, global = true)]
    server: Option<String>,

    /// Server's pinned Ed25519 public key, base58 (overrides SQEX_SERVER_KEY).
    #[arg(long = "server-key", global = true)]
    server_key: Option<String>,

    /// Software identity file (default ~/.sqnr/identity).
    #[arg(short = 'i', long, global = true)]
    identity: Option<PathBuf>,

    /// Give up if the peer has not opened a session in return within N seconds.
    #[arg(long, global = true, default_value_t = 120)]
    wait: u64,

    /// Do not print the once-a-second statistics line.
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Call a peer: capture, encode, relay, decode, play.
    Call {
        /// The peer's Ed25519 identity, base58.
        peer: String,

        /// Where the audio comes from: `mic`, `tone`, or a path to a 48 kHz WAV.
        #[arg(long, default_value = "mic")]
        source: Source,

        /// Where the audio goes: `speaker`, `null`, or a path to write a WAV.
        #[arg(long, default_value = "speaker")]
        sink: Sink,

        /// Frames to hold before playing. Each is 20 ms of delay bought against
        /// reordering and jitter.
        #[arg(long, default_value_t = 3)]
        jitter: u64,

        /// Opus bitrate in bits per second.
        #[arg(long, default_value_t = 24_000)]
        bitrate: i32,

        /// Hang up after N seconds. Without it the call runs until the source
        /// ends or you interrupt it.
        #[arg(long)]
        seconds: Option<u64>,

        /// Measure round-trip time by matching returning frames to sent ones.
        /// Only meaningful against a peer running `sqex-voice echo`, which
        /// reflects each frame under the sequence number it arrived with.
        #[arg(long)]
        rtt: bool,
    },

    /// Reflect a peer's frames straight back, so one person can measure a real
    /// round trip through both relay hops without a second speaker.
    Echo {
        /// The peer's Ed25519 identity, base58.
        peer: String,
    },

    /// Join a room and talk to everyone in it (SIP-13).
    ///
    /// A room is named by a secret, and holding the secret is what being in the
    /// room consists of — there is no owner and no way to remove someone.
    /// Anyone you give it to can join, and can pass it on. Media is a mesh of
    /// ordinary two-party sessions, so the exchange can read no more of a room
    /// than it can of a call.
    Room {
        /// The room secret, base58. Omit with --new to mint one.
        room: Option<String>,

        /// Print a fresh room secret and exit. Give it to the people you want
        /// in the room, and to nobody else.
        #[arg(long)]
        new: bool,

        /// Where the audio comes from: `mic`, `tone`, or a 48 kHz WAV.
        #[arg(long, default_value = "mic")]
        source: Source,

        /// Where the audio goes: `speaker`, `null`, or a path to write a WAV.
        #[arg(long, default_value = "speaker")]
        sink: Sink,

        /// Frames to hold before playing, per peer.
        #[arg(long, default_value_t = 3)]
        jitter: u64,

        /// Opus bitrate in bits per second, to each peer.
        #[arg(long, default_value_t = 24_000)]
        bitrate: i32,

        /// Leave after N seconds.
        #[arg(long)]
        seconds: Option<u64>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let cfg = Config::load();

    // A room has no peer to name and may not need a connection at all.
    if let Cmd::Room {
        room,
        new,
        source,
        sink,
        jitter,
        bitrate,
        seconds,
    } = &cli.cmd
    {
        if *new {
            println!("{}", RoomId::generate().to_base58());
            eprintln!(
                "Give this to the people you want in the room. Anyone who has it can \
                 join, and it cannot be taken back."
            );
            return Ok(());
        }
        let text = room
            .as_deref()
            .ok_or("no room — pass a room secret, or --new to mint one")?;
        let id: RoomId = text.trim().parse().map_err(|e| format!("bad room: {e}"))?;
        return room_call(
            &cli,
            &cfg,
            id,
            CallOpts {
                source: source.clone(),
                sink: sink.clone(),
                depth: *jitter,
                bitrate: *bitrate,
                seconds: *seconds,
                rtt: false,
                quiet: cli.quiet,
            },
        )
        .await;
    }

    let peer = parse_key(match &cli.cmd {
        Cmd::Call { peer, .. } | Cmd::Echo { peer } => peer,
        Cmd::Room { .. } => unreachable!("handled above"),
    })?;
    let (client, session, id) = establish(&cli, &cfg, peer).await?;

    match &cli.cmd {
        Cmd::Call {
            source,
            sink,
            jitter,
            bitrate,
            seconds,
            rtt,
            ..
        } => {
            call(
                client,
                session,
                id,
                CallOpts {
                    source: source.clone(),
                    sink: sink.clone(),
                    depth: *jitter,
                    bitrate: *bitrate,
                    seconds: *seconds,
                    rtt: *rtt,
                    quiet: cli.quiet,
                },
            )
            .await
        }
        Cmd::Echo { .. } => echo(client, session, id, cli.quiet).await,
        Cmd::Room { .. } => unreachable!("handled above"),
    }
}

// ---- getting the two of us connected ----------------------------------------

/// Dial the exchange as this identity and open a relayed session with `peer`.
///
/// This mirrors `sqex session talk` in
/// `crates/sqex-cli/src/main.rs`. It is copied rather than shared: factoring it
/// out would mean either a new crate or giving `sqex-proto` the dependency on
/// the `sqnr` client it deliberately does not have, which is a lot of structure
/// to buy for thirty lines in a demo.
async fn establish(cli: &Cli, cfg: &Config, peer: PubKey) -> Result<(Client, Session, u64), String> {
    let signer = load_identity(cli, cfg)?;
    let me = PubKey::new(signer.public());
    if me == peer {
        return Err("a session needs two identities".into());
    }
    let (addr, server) = endpoint(cli, cfg)?;
    let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;

    if client.max_datagram_size().is_none() {
        return Err("this path does not carry datagrams, so it cannot carry a call".into());
    }

    // Our contribution to the key agreement. The exchange relays it but cannot
    // use it: completing the agreement needs a static private key from each of
    // us, and it holds neither.
    let eph = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let open = Open {
        peer,
        ephemeral: x25519_dalek::PublicKey::from(&eph).to_bytes(),
    };

    eprintln!("you are {me}");
    eprintln!("waiting for {peer} to open a session with you…");
    let deadline = Instant::now() + Duration::from_secs(cli.wait);
    let ack = loop {
        let (code, body) = client.post("/session/open", open.encode()).await?;
        if code != 200 {
            return Err(format!(
                "open failed ({code}): {}",
                String::from_utf8_lossy(&body)
            ));
        }
        let ack = OpenAck::decode(&body).map_err(|e| e.to_string())?;
        if ack.state == OpenState::Established {
            break ack;
        }
        if Instant::now() >= deadline {
            return Err("the peer did not join in time".into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    let session = Session::derive(&signer.seed(), &eph, &peer, &ack.peer_ephemeral)
        .map_err(|e| e.to_string())?;
    Ok((client, session, ack.session_id))
}

// ---- the call ---------------------------------------------------------------

/// One encoder, configured the same way whether it is feeding one peer or
/// seven — a frame is encoded once and sealed per peer, never encoded per peer.
fn encoder(bitrate: i32) -> Result<opus::Encoder, String> {
    let mut e = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
        .map_err(|e| format!("opus encoder: {e}"))?;
    e.set_bitrate(opus::Bitrate::Bits(bitrate))
        .map_err(|e| format!("opus bitrate: {e}"))?;
    // Forward error correction lets the decoder rebuild a lost frame from the
    // next one, which on an unreliable path is worth the few bits it costs.
    e.set_inband_fec(true).map_err(|e| e.to_string())?;
    e.set_packet_loss_perc(10).map_err(|e| e.to_string())?;
    Ok(e)
}

struct CallOpts {
    source: Source,
    sink: Sink,
    depth: u64,
    bitrate: i32,
    seconds: Option<u64>,
    rtt: bool,
    quiet: bool,
}

async fn call(
    mut client: Client,
    session: Session,
    id: u64,
    opts: CallOpts,
) -> Result<(), String> {
    let mut encoder = encoder(opts.bitrate)?;
    let mut decoder = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono)
        .map_err(|e| format!("opus decoder: {e}"))?;

    let mut source = audio::open_source(&opts.source, opts.seconds)?;
    let out = audio::open_sink(&opts.sink)?;
    let mut buffer = Jitter::new(opts.depth);
    let mut rtt = Rtt::default();
    let mut pcm = vec![0f32; FRAME_SAMPLES];

    let mut playout = tokio::time::interval(Duration::from_millis(FRAME_MS));
    let mut report = tokio::time::interval(Duration::from_secs(1));
    report.tick().await; // the first tick is immediate; skip it

    eprintln!(
        "session {id} up on datagrams — {} kbit/s, {} ms of jitter buffer. Ctrl-C to hang up.",
        opts.bitrate / 1000,
        opts.depth * FRAME_MS
    );

    let mut seq = 0u64;
    let mut hangup: Option<Instant> = None;

    loop {
        tokio::select! {
            // Captured audio goes out the moment it exists: no request, no
            // response, no waiting for an acknowledgement that would arrive too
            // late to matter.
            frame = source.recv(), if hangup.is_none() => match frame {
                Some(samples) => {
                    let packet = encoder
                        .encode_vec_float(&samples, MAX_DATAGRAM_FRAME)
                        .map_err(|e| format!("encode: {e}"))?;
                    let sealed = session.seal_datagram(seq, &packet).map_err(|e| e.to_string())?;
                    client.send_datagram(DatagramFrame { session_id: id, seq, ciphertext: sealed }.encode())?;
                    if opts.rtt {
                        rtt.sent(seq);
                    }
                    buffer.stats.sent += 1;
                    seq += 1;
                }
                None => {
                    // Let what is already in flight arrive before hanging up.
                    eprintln!("(source ended; draining)");
                    hangup = Some(Instant::now() + Duration::from_millis(500 + opts.depth * FRAME_MS));
                }
            },

            got = client.read_datagram() => {
                let bytes = got?;
                let frame = DatagramFrame::decode(&bytes).map_err(|e| e.to_string())?;
                if frame.session_id != id {
                    continue; // some other session on this connection
                }
                match session.open(frame.seq, &frame.ciphertext) {
                    Ok(packet) => {
                        if opts.rtt {
                            rtt.returned(frame.seq);
                        }
                        buffer.push(frame.seq, packet);
                    }
                    // Not fatal: on this path anything may arrive, and a frame
                    // we cannot open is one we simply do not play.
                    Err(e) => eprintln!("(undecryptable frame {}: {e})", frame.seq),
                }
            }

            _ = playout.tick() => {
                // Delay the buffer has accumulated is delay it will keep, since
                // frames arrive no faster than they are played. Shed it: decode
                // the stale frame so the decoder's state stays continuous, but
                // do not play it. The call catches up rather than staying half
                // a second behind the conversation.
                if let Some(stale) = buffer.trim() {
                    decoder.decode_float(&stale, &mut pcm, false).map_err(|e| format!("decode: {e}"))?;
                }
                match buffer.pop() {
                    Playout::Frame(packet) => {
                        decoder.decode_float(&packet, &mut pcm, false).map_err(|e| format!("decode: {e}"))?;
                        out.play(&pcm);
                    }
                    // Opus invents a plausible continuation of what it last
                    // heard. Better than a hole, and much better than a click.
                    Playout::Conceal => {
                        decoder.decode_float(&[], &mut pcm, false).map_err(|e| format!("conceal: {e}"))?;
                        out.play(&pcm);
                    }
                    // Nothing to play. Write nothing: the device fills silence
                    // on its own, and a file should not be padded with it.
                    Playout::Idle => {}
                }
                if hangup.is_some_and(|at| Instant::now() >= at) {
                    break;
                }
            }

            _ = report.tick(), if !opts.quiet => eprintln!("{}", summary(&buffer, &rtt)),

            _ = tokio::signal::ctrl_c() => {
                eprintln!();
                break;
            }
        }
    }

    eprintln!("{}", summary(&buffer, &rtt));
    out.finish()?;
    let _ = client
        .post("/session/close", BySession::close(id).encode())
        .await;
    Ok(())
}

fn summary(buffer: &Jitter, rtt: &Rtt) -> String {
    let s = &buffer.stats;
    let mut line = format!(
        "sent {} · recv {} · loss {:.1}% · late {} · dup {} · concealed {} · trimmed {} \
         · underruns {} · buffered {}",
        s.sent,
        s.received,
        s.loss_pct(buffer.span()),
        s.late,
        s.duplicate,
        s.concealed,
        s.trimmed,
        s.underruns,
        buffer.depth_now(),
    );
    if !rtt.is_empty() {
        let (p50, p95) = rtt.percentiles();
        line.push_str(&format!(
            " · rtt p50 {:.1} ms p95 {:.1} ms",
            p50.as_secs_f64() * 1000.0,
            p95.as_secs_f64() * 1000.0
        ));
    }
    line
}

// ---- the room ---------------------------------------------------------------

/// Talk to everyone in a room (SIP-13).
///
/// The shape is the two-party loop above with the singular made plural: one
/// encoder still, because a frame is encoded once and only *sealed* per peer,
/// but a jitter buffer, a decoder and a sequence counter each. The two loops
/// are kept apart rather than unified — `call` carries the round-trip
/// measurement and a fixed peer, this carries a roster that changes underneath
/// it, and folding them together made both harder to follow than either.
async fn room_call(
    cli: &Cli,
    cfg: &Config,
    room: RoomId,
    opts: CallOpts,
) -> Result<(), String> {
    let signer = load_identity(cli, cfg)?;
    let me = PubKey::new(signer.public());
    let (addr, server) = endpoint(cli, cfg)?;
    let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
    if client.max_datagram_size().is_none() {
        return Err("this path does not carry datagrams, so it cannot carry a room".into());
    }

    let mut encoder = encoder(opts.bitrate)?;
    let mut source = audio::open_source(&opts.source, opts.seconds)?;
    let out = audio::open_sink(&opts.sink)?;
    let mut mixer = Mixer::new(FRAME_SAMPLES);
    let mut pcm = vec![0f32; FRAME_SAMPLES];
    let mut members = Membership::new(room, me, signer.seed(), opts.depth);

    let mut playout = tokio::time::interval(Duration::from_millis(FRAME_MS));
    let mut roster = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
    let mut report = tokio::time::interval(Duration::from_secs(1));
    report.tick().await;

    eprintln!("you are {me}");
    eprintln!(
        "in the room — {} kbit/s to each peer, {} ms of jitter buffer. Ctrl-C to leave.",
        opts.bitrate / 1000,
        opts.depth * FRAME_MS
    );

    let mut hangup: Option<Instant> = None;
    let result = loop {
        tokio::select! {
            // Roster, heartbeat and session establishment are the same tick.
            // Everything here is a request-response on the one connection, so
            // it is sequential by construction; media does not wait for it.
            _ = roster.tick() => {
                match members.poll(&mut client).await {
                    Ok(events) => for e in events {
                        match e {
                            RoomEvent::Joined(id) => eprintln!("+ {} joined", room::short(&id)),
                            RoomEvent::Left(id) => eprintln!("- {} left", room::short(&id)),
                            RoomEvent::Rejected(id) => eprintln!(
                                "! {} is listed in the room but cannot prove they hold the \
                                 secret — ignoring them",
                                room::short(&id)
                            ),
                            RoomEvent::Restarted(id) => eprintln!(
                                "~ {} went quiet — rebuilding the session",
                                room::short(&id)
                            ),
                        }
                    },
                    Err(e) => break Err(e),
                }
            }

            // One encode, then a seal per peer: the ciphertext differs because
            // every session has its own key, but the Opus packet does not.
            frame = source.recv(), if hangup.is_none() => match frame {
                Some(samples) => {
                    let packet = match encoder.encode_vec_float(&samples, MAX_DATAGRAM_FRAME) {
                        Ok(p) => p,
                        Err(e) => break Err(format!("encode: {e}")),
                    };
                    for peer in members.peers.values_mut() {
                        let Ok(sealed) = peer.session.seal_datagram(peer.out_seq, &packet) else {
                            continue;
                        };
                        let _ = client.send_datagram(
                            DatagramFrame {
                                session_id: peer.session_id,
                                seq: peer.out_seq,
                                ciphertext: sealed,
                            }
                            .encode(),
                        );
                        peer.out_seq += 1;
                    }
                }
                None => {
                    eprintln!("(source ended; leaving)");
                    hangup = Some(Instant::now() + Duration::from_millis(500 + opts.depth * FRAME_MS));
                }
            },

            got = client.read_datagram() => {
                let bytes = match got {
                    Ok(b) => b,
                    Err(e) => break Err(e),
                };
                let Ok(frame) = DatagramFrame::decode(&bytes) else {
                    continue; // malformed: not ours to fix
                };
                // The session id says who this is. A frame for a session we do
                // not hold is one from a peer who has since left.
                if let Some(peer) = members.peers.get_mut(&frame.session_id) {
                    // A frame we cannot open is one we do not play. On this
                    // path anything may arrive, and in a room saying so once
                    // per frame would drown the roster.
                    if let Ok(packet) = peer.session.open(frame.seq, &frame.ciphertext) {
                        peer.heard();
                        peer.jitter.push(frame.seq, packet);
                    }
                }
            }

            _ = playout.tick() => {
                mixer.start();
                for peer in members.peers.values_mut() {
                    // Each peer's delay is its own: one bad path should not
                    // add latency to everybody else in the room.
                    if let Some(stale) = peer.jitter.trim() {
                        let _ = peer.decoder.decode_float(&stale, &mut pcm, false);
                    }
                    let decoded = match peer.jitter.pop() {
                        Playout::Frame(packet) => {
                            peer.decoder.decode_float(&packet, &mut pcm, false).is_ok()
                        }
                        Playout::Conceal => {
                            peer.decoder.decode_float(&[], &mut pcm, false).is_ok()
                        }
                        Playout::Idle => false,
                    };
                    if decoded {
                        peer.note_level(audio::rms(&pcm));
                        mixer.add(&pcm);
                    } else {
                        peer.note_level(0.0);
                    }
                }
                if mixer.active() > 0 {
                    out.play(mixer.finish());
                }
                if hangup.is_some_and(|at| Instant::now() >= at) {
                    break Ok(());
                }
            }

            _ = report.tick(), if !opts.quiet => eprintln!("{}", room_summary(&members)),

            _ = tokio::signal::ctrl_c() => {
                eprintln!();
                break Ok(());
            }
        }
    };

    eprintln!("{}", room_summary(&members));
    out.finish()?;
    members.leave(&mut client).await;
    result
}

/// Who is here, who is talking, and how the paths to them are holding up.
fn room_summary(members: &Membership) -> String {
    let present = members.present();
    if present.is_empty() {
        return match members.connecting() {
            0 => "nobody else here yet".to_string(),
            n => format!("connecting to {n}…"),
        };
    }
    let who: Vec<String> = present
        .iter()
        .map(|p| {
            let mark = if p.is_speaking() { "*" } else { " " };
            let s = &p.jitter.stats;
            format!(
                "{mark}{} loss {:.0}% conceal {} buf {}",
                room::short(&p.identity),
                s.loss_pct(p.jitter.span()),
                s.concealed,
                p.jitter.depth_now()
            )
        })
        .collect();
    let mut line = format!("{} here · {}", present.len(), who.join(" | "));
    if members.connecting() > 0 {
        line.push_str(&format!(" · {} connecting", members.connecting()));
    }
    line
}

// ---- the echo responder -----------------------------------------------------

/// Reflect every frame's plaintext back under the sequence number it arrived
/// with, so the caller can match a return to a departure and get a true round
/// trip through both relay hops.
///
/// Re-sealing is unavoidable — each direction has its own nonce space — but the
/// audio is never decoded, so nothing here needs a codec.
async fn echo(mut client: Client, session: Session, id: u64, quiet: bool) -> Result<(), String> {
    eprintln!("session {id} up on datagrams — reflecting. Ctrl-C to stop.");
    let mut reflected = 0u64;
    let mut report = tokio::time::interval(Duration::from_secs(1));
    report.tick().await;

    loop {
        tokio::select! {
            got = client.read_datagram() => {
                let bytes = got?;
                let frame = DatagramFrame::decode(&bytes).map_err(|e| e.to_string())?;
                if frame.session_id != id {
                    continue;
                }
                let Ok(packet) = session.open(frame.seq, &frame.ciphertext) else {
                    eprintln!("(undecryptable frame {})", frame.seq);
                    continue;
                };
                let sealed = session.seal_datagram(frame.seq, &packet).map_err(|e| e.to_string())?;
                client.send_datagram(
                    DatagramFrame { session_id: id, seq: frame.seq, ciphertext: sealed }.encode(),
                )?;
                reflected += 1;
            }
            _ = report.tick(), if !quiet => eprintln!("reflected {reflected}"),
            _ = tokio::signal::ctrl_c() => {
                eprintln!();
                break;
            }
        }
    }

    eprintln!("reflected {reflected}");
    let _ = client
        .post("/session/close", BySession::close(id).encode())
        .await;
    Ok(())
}

// ---- identity and endpoint --------------------------------------------------

/// A YubiKey is not an option here: the mailbox and session services act *as* an
/// identity on the transport, and a YubiKey signs but cannot be a transport key.
fn load_identity(cli: &Cli, cfg: &Config) -> Result<sqnr_core::SoftwareSigner, String> {
    let path = match (&cli.identity, &cfg.identity) {
        (Some(p), _) => p.clone(),
        (None, Some(p)) => p.clone(),
        (None, None) => identity::default_identity_path()?,
    };
    if !path.exists() {
        return Err(format!(
            "no identity at {} — run `sqnr keygen` first",
            path.display()
        ));
    }
    if identity::is_encrypted(&path)? {
        let pass = rpassword::prompt_password(format!("Passphrase for {}: ", path.display()))
            .map_err(|e| e.to_string())?;
        identity::load(&path, Some(&pass))
    } else {
        identity::load(&path, None)
    }
}

fn endpoint(cli: &Cli, cfg: &Config) -> Result<(SocketAddr, PubKey), String> {
    let addr = cli
        .server
        .clone()
        .or_else(|| env_nonempty("SQEX_SERVER"))
        .or_else(|| cfg.server.clone())
        .ok_or("no server address (pass --server, set SQEX_SERVER, or put it in ~/.sqnr/config)")?;
    let key = cli
        .server_key
        .clone()
        .or_else(|| env_nonempty("SQEX_SERVER_KEY"))
        .or_else(|| cfg.server_key.clone())
        .ok_or("no server key (pass --server-key, set SQEX_SERVER_KEY, or put it in ~/.sqnr/config)")?;
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| format!("bad server address {addr:?} (use host:port)"))?;
    let server: PubKey = key
        .trim()
        .parse()
        .map_err(|e| format!("bad server key: {e}"))?;
    Ok((socket, server))
}

fn parse_key(s: &str) -> Result<PubKey, String> {
    s.trim().parse().map_err(|e| format!("bad key {s:?}: {e}"))
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}
