//! The call itself: rendezvous, the media loops, and leaving cleanly.
//!
//! This used to live in `main.rs`, which meant the only way to hold a call was
//! to be a terminal. Everything here is now frontend-agnostic, so the CLI and a
//! desktop client run the *same* loop rather than two that drift apart.
//!
//! # What moved, and what had to change to move
//!
//! Three things were welded to a terminal and are now the caller's:
//!
//! - **Saying things.** Every `eprintln!` is an [`Event`] handed to a
//!   [`Report`]. The CLI prints them; a GUI draws them. The text is not lost —
//!   [`Event::describe`] carries the same words, because those words are years
//!   of accumulated answers to real confusion.
//! - **The identity.** Loading it may need a passphrase, and asking for one is
//!   not something a library can do — a CLI prompts on the terminal, a GUI
//!   opens a dialog. So the engine takes an already-unlocked signer.
//! - **Interruption.** Nothing here installs a signal handler or exits the
//!   process. A caller that wants to stop drops the future or trips
//!   `seconds`.
//!
//! What deliberately did *not* change is the shape of the loops. They are the
//! subtlest code in the project — the gate, the trim, the coast through a
//! described pause — and this is a move, not a rewrite.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sqex_proto::room::{HEARTBEAT_SECS, RoomId};
use sqex_proto::session::{
    BySession, DatagramFrame, MAX_DATAGRAM_FRAME, Open, OpenAck, OpenState, Session,
};
use sqnr::Client;
use sqnr_core::{PubKey, Signer};

use crate::audio::{self, Rate, Sink, Source};
use crate::jitter::{FRAME_MS, Jitter, Playback, Rtt};
use crate::media;
use crate::mix::Mixer;
use crate::room::{self, Event as RoomEvent, Membership};

/// One keepalive a second while nobody is speaking (SIP-15).
pub const KEEPALIVE_FRAMES: u32 = (1000 / FRAME_MS) as u32;

/// How long an echo responder waits before deciding its caller has gone and
/// going back to waiting for the next one.
pub const CALLER_GONE: Duration = Duration::from_secs(15);

/// How long to wait before saying that waiting has become suspicious.
const PATIENCE: Duration = Duration::from_secs(10);

/// How many frames may be sent into total silence before concluding that
/// nothing is coming back. Three seconds at fifty frames a second.
const DEAF_AFTER: u64 = 150;

/// How often a room may re-describe who is speaking.
///
/// A speaking indicator at one hertz reads as broken — it lags a conversation
/// badly enough that people stop trusting it. Fifty hertz, the playout rate, is
/// far more than an eye needs and would have the interface repainting
/// constantly through an hour-long meeting. Ten is the compromise, and it only
/// fires when the set of people speaking has actually *changed*, so a room
/// listening to one person costs one update a second like everything else.
const ROSTER_MS: u64 = 100;

// ---- what the engine has to say ---------------------------------------------

/// One peer in a room, as of the last look.
///
/// The roster used to leave the engine only as a formatted line. That is enough
/// for a terminal and no use at all to something that wants to draw a ring
/// around whoever is talking, so the numbers come out as numbers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeerStatus {
    pub identity: PubKey,
    /// Whether they are speaking now — smoothed, so it follows a conversation
    /// rather than flickering between syllables.
    pub speaking: bool,
    /// Smoothed loudness, for a level meter. Roughly 0..1.
    pub level: f32,
    pub loss_pct: f64,
    pub concealed: u64,
    /// Frames held for this peer. Each is 20 ms of delay bought against jitter.
    pub buffered: usize,
}

/// Something worth telling the person holding the call.
///
/// A GUI can render these as it likes; [`describe`](Event::describe) gives the
/// wording the CLI has always used, so nothing has to be reinvented and the
/// hard-won diagnostics survive the move.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Connected, and this is who the exchange thinks you are.
    Identity(PubKey),
    /// A domain was discovered over DNSSEC and pinned on first contact.
    Pinned { domain: String, key: PubKey },
    /// Waiting for `peer` to name us in return. Consent is mutual, so nothing
    /// happens until they ask too.
    Waiting { peer: PubKey },
    /// Still waiting after [`PATIENCE`]. Both causes are invisible from here,
    /// which is exactly why they get said out loud.
    StillWaiting { me: PubKey },
    /// A session is up and carrying media.
    SessionUp { id: u64, bitrate: i32, buffer_ms: u64 },
    /// A session is up and being reflected back. An echo responder neither
    /// encodes nor buffers, so it has no bitrate or jitter depth to report --
    /// which is why this is its own event rather than a `SessionUp` full of
    /// zeroes claiming otherwise.
    Reflecting { id: u64 },
    /// In a room, with a session to each peer as they appear.
    RoomJoined { me: PubKey, bitrate: i32, buffer_ms: u64 },
    /// Somebody joined, left, was rejected, or had their session rebuilt.
    Roster(RoomEvent),
    /// Who is in the room right now, and who is talking.
    ///
    /// Sent when the set of people speaking changes, and once a second
    /// regardless. `connecting` counts members whose session is not up yet —
    /// they are in the room and cannot be heard.
    Present { peers: Vec<PeerStatus>, connecting: usize },
    /// The once-a-second line: what the buffer has seen. A caller that wants
    /// less noise suppresses these.
    Stats(String),
    /// The same line, said once as the call ends.
    ///
    /// Separate from [`Stats`](Event::Stats) because the CLI has always
    /// printed this one **even under `--quiet`**: somebody who asked for a
    /// quiet call still wants to know how it went. Folding the two together
    /// silently dropped it, which is exactly the sort of thing a move like this
    /// loses if nobody looks.
    FinalStats(String),
    /// Sending steadily and hearing nothing at all. Said once.
    Deaf,
    /// The source ran out; the call is draining what is still in flight.
    Draining,
    /// A frame arrived that could not be opened or made sense of. Not fatal:
    /// on this path anything may arrive.
    BadFrame { seq: u64, why: String },
    /// An echo responder reflected this many frames.
    Reflected(u64),
    /// The caller went quiet; back to waiting for the next one.
    CallerGone { after: Duration },
    /// Something the audio layer wants said — a device substitution, a
    /// Bluetooth profile warning. These used to be `eprintln!` inside the
    /// library, where no frontend could reach them.
    Device(String),
}

impl Event {
    /// The wording the CLI prints. A GUI may ignore this entirely and render
    /// the variant, but for most of these the sentence *is* the value: they
    /// name causes that cannot be observed from inside the process.
    pub fn describe(&self) -> String {
        match self {
            Event::Identity(me) => format!("you are {me}"),
            Event::Pinned { domain, key } => format!(
                "{domain}: discovered {key} over DNSSEC and pinned it. \
                 Forget it with `sqex discover --forget {domain}`."
            ),
            Event::Waiting { peer } => {
                format!("waiting for {peer} to open a session with you…")
            }
            Event::StillWaiting { me } => format!(
                "  still waiting. Two things do this:\n    \
                 - the other end is not running, or names someone else. It needs \
                 to name you: {me}\n    \
                 - two processes are sharing one identity. Only one client may \
                 use an identity at a time; a second one keeps discarding the \
                 first one's session, and neither ever connects."
            ),
            Event::SessionUp { id, bitrate, buffer_ms } => format!(
                "session {id} up on datagrams — {} kbit/s, {buffer_ms} ms of jitter buffer.",
                bitrate / 1000
            ),
            Event::Reflecting { id } => {
                format!("session {id} up on datagrams — reflecting.")
            }
            Event::RoomJoined { me, bitrate, buffer_ms } => format!(
                "you are {me}\nin the room — {} kbit/s to each peer, {buffer_ms} ms of \
                 jitter buffer.",
                bitrate / 1000
            ),
            Event::Roster(RoomEvent::Joined(id)) => format!("+ {} joined", room::short(id)),
            Event::Roster(RoomEvent::Left(id)) => format!("- {} left", room::short(id)),
            Event::Roster(RoomEvent::Rejected(id)) => format!(
                "! {} is listed in the room but cannot prove they hold the \
                 secret — ignoring them",
                room::short(id)
            ),
            Event::Roster(RoomEvent::Restarted(id)) => {
                format!("~ {} went quiet — rebuilding the session", room::short(id))
            }
            // Deliberately terse: this arrives ten times a second at worst, and
            // the once-a-second `Stats` line already says it properly. A
            // terminal should print that one and ignore this.
            Event::Present { peers, connecting } => {
                format!("{} present, {connecting} connecting", peers.len())
            }
            Event::Stats(line) | Event::FinalStats(line) => line.clone(),
            Event::Deaf => String::from(
                "  nothing has arrived from the peer at all. Usually one of:\n    \
                 - they are not sending (check their end)\n    \
                 - two processes are sharing one identity, so the session \
                 you hold is not the one they hold. Only one client may use \
                 an identity at a time: `pgrep -fl sqex-voice`",
            ),
            Event::Draining => String::from("(source ended; draining)"),
            Event::BadFrame { seq, why } => format!("(frame {seq}: {why})"),
            Event::Reflected(n) => format!("reflected {n}"),
            Event::CallerGone { after } => format!(
                "(quiet for {}s — waiting for the next caller)",
                after.as_secs()
            ),
            Event::Device(msg) => msg.clone(),
        }
    }
}

/// Where the engine's events go.
///
/// Implemented for any `FnMut(Event)`, so a caller that only wants to print
/// can pass a closure and be done.
///
/// `Send` is required, and it is not incidental: the call loops are futures,
/// and anything that wants to hold a call *while doing something else* — a
/// desktop client, say — has to spawn one onto an executor. A reporter that
/// could not cross a thread would make `&mut dyn Report` un-`Send`, and with it
/// the whole future, so the loop could only ever be awaited by whoever built
/// it. That is the shape this module exists to get away from.
pub trait Report: Send {
    fn event(&mut self, event: Event);
}

impl<F: FnMut(Event) + Send> Report for F {
    fn event(&mut self, event: Event) {
        self(event)
    }
}

/// A [`Report`] that throws everything away — for tests, and for a caller that
/// genuinely has nowhere to put it.
pub struct Silent;

impl Report for Silent {
    fn event(&mut self, _event: Event) {}
}

/// Decode a refusal into something worth reading. A refusal has been a typed
/// binary value since v0.21.0, not JSON, and branching on a substring of the
/// body is how three call sites used to get this wrong.
pub(crate) fn said(body: &[u8]) -> String {
    match sqex_proto::refusal::Refusal::decode(body) {
        Ok(r) => r.to_string(),
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    }
}

// ---- getting the two of us connected ----------------------------------------

/// Where the exchange is, and which key it must prove it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub server: PubKey,
}

/// Resolve an exchange from the layers a caller can speak through, most
/// specific first.
///
/// Resolution is shared with the other clients in `sqex_discovery::target`,
/// because three copies of it is what produced two bugs in a day.
pub async fn resolve(
    layers: &[sqex_discovery::Layer; 3],
    report: &mut dyn Report,
) -> Result<Endpoint, String> {
    match sqex_discovery::target::resolve(layers).map_err(|e| e.to_string())? {
        sqex_discovery::Target::Direct { address, key } => {
            Ok(Endpoint { address: resolve_addr(&address)?, server: key })
        }
        sqex_discovery::Target::Discover(domain) => {
            let found = sqex_discovery::discover(&domain)
                .await
                .map_err(|e| e.to_string())?;
            if found.newly_pinned {
                report.event(Event::Pinned { domain, key: found.key });
            }
            Ok(Endpoint { address: resolve_addr(&found.address)?, server: found.key })
        }
    }
}

/// `host:port`, `host`, or an IP literal. This used to parse straight to a
/// `SocketAddr`, which accepts only an IP.
pub fn resolve_addr(address: &str) -> Result<SocketAddr, String> {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return Ok(socket);
    }
    let has_port = !address.starts_with('[')
        && address.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok());
    let with_port = if has_port {
        address.to_string()
    } else {
        format!("{address}:{}", sqex_discovery::DEFAULT_PORT)
    };
    std::net::ToSocketAddrs::to_socket_addrs(&with_port)
        .map_err(|e| format!("cannot resolve {address:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("{address:?} resolved to no addresses"))
}

/// Connect to the exchange as this identity. No peer, no session.
///
/// Takes an already-unlocked signer: a locked identity needs a passphrase, and
/// asking for one belongs to whatever has a person's attention — a terminal
/// prompt, or a dialog — not to a library.
///
/// A room uses this directly: it has nobody to name, only a secret to hold.
pub async fn connect(
    endpoint: Endpoint,
    signer: &sqnr_core::SoftwareSigner,
    report: &mut dyn Report,
) -> Result<Client, String> {
    let me = PubKey::new(signer.public());
    let client =
        Client::connect_as(endpoint.address, endpoint.server.as_bytes(), &signer.seed()).await?;
    if client.max_datagram_size().is_none() {
        return Err("this path does not carry datagrams, so it cannot carry a call".into());
    }
    report.event(Event::Identity(me));
    Ok(client)
}

/// Connect, having first checked there is somebody else to connect *to*.
pub async fn dial(
    endpoint: Endpoint,
    signer: &sqnr_core::SoftwareSigner,
    peer: PubKey,
    report: &mut dyn Report,
) -> Result<Client, String> {
    if PubKey::new(signer.public()) == peer {
        return Err("a session needs two identities".into());
    }
    connect(endpoint, signer, report).await
}

/// Open a relayed session with `peer` on a connection we already hold.
///
/// Separate from [`dial`] because it may need doing more than once: a session
/// does not survive the peer restarting, and whoever is left holding the old one
/// has to ask again.
pub async fn rendezvous(
    client: &mut Client,
    signer: &sqnr_core::SoftwareSigner,
    peer: PubKey,
    wait: u64,
    report: &mut dyn Report,
) -> Result<(Session, u64), String> {
    let me = PubKey::new(signer.public());

    // Our contribution to the key agreement. The exchange relays it but cannot
    // use it: completing the agreement needs a static private key from each of
    // us, and it holds neither.
    let eph = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let open = Open { peer, ephemeral: x25519_dalek::PublicKey::from(&eph).to_bytes() };

    report.event(Event::Waiting { peer });
    let started = Instant::now();
    let deadline = started + Duration::from_secs(wait);

    let mut hinted = false;
    let ack = loop {
        let (code, body) = client.post("/session/open", open.encode()).await?;
        if code != 200 {
            return Err(format!("open failed ({code}): {}", said(&body)));
        }
        let ack = OpenAck::decode(&body).map_err(|e| e.to_string())?;
        if ack.state == OpenState::Established {
            break ack;
        }
        // Waiting is normal for a few seconds and suspicious after ten. The
        // two causes are both invisible from here, so say them out loud
        // rather than let someone watch a silent line forever.
        if !hinted && started.elapsed() > PATIENCE {
            report.event(Event::StillWaiting { me });
            hinted = true;
        }
        if Instant::now() >= deadline {
            return Err("the peer did not join in time".into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    let session = Session::derive(&signer.seed(), &eph, &peer, &ack.peer_ephemeral)
        .map_err(|e| e.to_string())?;
    Ok((session, ack.session_id))
}

/// Dial and rendezvous in one go, for a caller that only wants a call.
pub async fn establish(
    endpoint: Endpoint,
    signer: &sqnr_core::SoftwareSigner,
    peer: PubKey,
    wait: u64,
    report: &mut dyn Report,
) -> Result<(Client, Session, u64), String> {
    let mut client = dial(endpoint, signer, peer, report).await?;
    let (session, id) = rendezvous(&mut client, signer, peer, wait, report).await?;
    Ok((client, session, id))
}

// ---- the call ---------------------------------------------------------------

/// One encoder, configured the same way whether it is feeding one peer or
/// seven — a frame is encoded once and sealed per peer, never encoded per peer.
pub fn encoder(bitrate: i32, rate: Rate) -> Result<opus::Encoder, String> {
    let mut e = opus::Encoder::new(rate.hz(), opus::Channels::Mono, opus::Application::Voip)
        .map_err(|e| format!("opus encoder: {e}"))?;
    // Deliberately off. SIP-15 takes the transmit decision back from the
    // codec: its detector judges whether *encoding* is worthwhile, not whether
    // *transmitting* is, and against a room it keeps deciding yes.
    e.set_dtx(false).map_err(|e| format!("opus dtx: {e}"))?;
    e.set_bitrate(opus::Bitrate::Bits(bitrate))
        .map_err(|e| format!("opus bitrate: {e}"))?;
    // Forward error correction lets the decoder rebuild a lost frame from the
    // next one, which on an unreliable path is worth the few bits it costs.
    e.set_inband_fec(true).map_err(|e| e.to_string())?;
    e.set_packet_loss_perc(10).map_err(|e| e.to_string())?;
    Ok(e)
}

/// Everything a call needs that is not the connection.
#[derive(Debug, Clone)]
pub struct CallOpts {
    pub source: Source,
    pub sink: Sink,
    pub input: Option<String>,
    pub output: Option<String>,
    pub depth: u64,
    pub bitrate: i32,
    pub seconds: Option<u64>,
    pub rtt: bool,
    pub dtx: bool,
}

impl Default for CallOpts {
    /// The same defaults the CLI documents: a microphone, a speaker, three
    /// frames of buffer, 24 kbit/s, and discontinuous transmission on.
    fn default() -> Self {
        Self {
            source: Source::Mic,
            sink: Sink::Speaker,
            input: None,
            output: None,
            depth: 3,
            bitrate: 24_000,
            seconds: None,
            rtt: false,
            dtx: true,
        }
    }
}

/// Hold a two-party call until the source ends, the deadline passes, or the
/// future is dropped.
pub async fn call(
    mut client: Client,
    session: Session,
    id: u64,
    opts: CallOpts,
    report: &mut dyn Report,
) -> Result<(), String> {
    // Capture and playback pick their own rates, and Opus converts between them
    // and whatever the far end chose. Nothing is negotiated.
    let (mut source, capture) =
        audio::open_source(&opts.source, opts.seconds, opts.input.as_deref())?;
    let (out, play_rate) = audio::open_sink(&opts.sink, opts.output.as_deref())?;
    let mut encoder = encoder(opts.bitrate, capture)?;
    let mut playback = Playback::new(play_rate.hz())?;
    let mut buffer = Jitter::new(opts.depth);
    let mut rtt = Rtt::default();
    let mut pcm = vec![0f32; play_rate.frame()];

    let mut playout = tokio::time::interval(Duration::from_millis(FRAME_MS));
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await; // the first tick is immediate; skip it

    report.event(Event::SessionUp {
        id,
        bitrate: opts.bitrate,
        buffer_ms: opts.depth * FRAME_MS,
    });

    let mut seq = 0u64;
    let mut hangup: Option<Instant> = None;
    let mut deaf = false;
    let mut outgoing = media::Sender::new(KEEPALIVE_FRAMES, opts.dtx);

    loop {
        tokio::select! {
            // Captured audio goes out the moment it exists: no request, no
            // response, no waiting for an acknowledgement that would arrive too
            // late to matter.
            frame = source.recv(), if hangup.is_none() => match frame {
                Some(samples) => {
                    // The gate decides; the encoder only runs when it says yes.
                    // The timestamp advances whether or not anything goes out;
                    // the sequence number only counts what does (SIP-15).
                    let framed = outgoing
                        .offer(&samples, |pcm| {
                            encoder.encode_vec_float(pcm, MAX_DATAGRAM_FRAME - media::HEADER)
                                .map_err(|e| sqnr_core::Error::Malformed(format!("encode: {e}")))
                        })
                        .map_err(|e| e.to_string())?;
                    if let Some(media) = framed {
                        let sealed = session
                            .seal_datagram(seq, &media.encode())
                            .map_err(|e| e.to_string())?;
                        client.send_datagram(
                            DatagramFrame { session_id: id, seq, ciphertext: sealed }.encode(),
                        )?;
                        if opts.rtt {
                            rtt.sent(seq);
                        }
                        buffer.stats.sent += 1;
                        seq += 1;
                    }
                }
                None => {
                    // Let what is already in flight arrive before hanging up.
                    report.event(Event::Draining);
                    hangup = Some(
                        Instant::now() + Duration::from_millis(500 + opts.depth * FRAME_MS),
                    );
                }
            },

            got = client.read_datagram() => {
                let bytes = got?;
                let frame = DatagramFrame::decode(&bytes).map_err(|e| e.to_string())?;
                if frame.session_id != id {
                    continue; // some other session on this connection
                }
                match session.open(frame.seq, &frame.ciphertext) {
                    Ok(plaintext) => {
                        if opts.rtt {
                            rtt.returned(frame.seq);
                        }
                        match media::Frame::decode(&plaintext) {
                            // A frame type we do not know is ignored, not an
                            // error: SIP-15 reserves the space deliberately.
                            Ok(Some(m)) => buffer.push(frame.seq, m.timestamp, m.body),
                            Ok(None) => {}
                            Err(e) => report.event(Event::BadFrame {
                                seq: frame.seq,
                                why: format!("malformed media frame: {e}"),
                            }),
                        }
                    }
                    // Not fatal: on this path anything may arrive, and a frame
                    // we cannot open is one we simply do not play.
                    Err(e) => report.event(Event::BadFrame {
                        seq: frame.seq,
                        why: format!("undecryptable: {e}"),
                    }),
                }
            }

            _ = playout.tick() => {
                // Delay the buffer has accumulated is delay it will keep, since
                // frames arrive no faster than they are played. Shed it: decode
                // the stale frame so the decoder's state stays continuous, but
                // do not play it. The call catches up rather than staying half
                // a second behind the conversation.
                if let Some(stale) = buffer.trim() {
                    playback.render(&crate::jitter::Playout::Frame(stale), &mut pcm);
                }
                // Decoding, concealing and making comfort noise all happen in
                // one place — see `Playback::render`. Idle alone plays nothing:
                // the device fills its own silence, and a file should not be
                // padded with it.
                let slot = buffer.pop();
                if playback.render(&slot, &mut pcm) {
                    out.play(&pcm);
                }
                if hangup.is_some_and(|at| Instant::now() >= at) {
                    break;
                }
            }

            _ = tick.tick() => {
                report.event(Event::Stats(summary(&buffer, &rtt)));
                // Sending steadily and hearing nothing at all is not a quiet
                // peer: with no discontinuous transmission a peer in a call
                // sends fifty frames a second. Say so once — the causes are
                // invisible from here, and the symptom points at none of them.
                if !deaf && buffer.stats.sent > DEAF_AFTER && buffer.stats.received == 0 {
                    report.event(Event::Deaf);
                    deaf = true;
                }
            }
        }
    }

    report.event(Event::FinalStats(summary(&buffer, &rtt)));
    out.finish()?;
    let _ = client
        .post("/session/close", BySession::close(id).encode())
        .await;
    Ok(())
}

/// What the buffer has seen, in one line.
pub fn summary(buffer: &Jitter, rtt: &Rtt) -> String {
    let s = &buffer.stats;
    let mut line = format!(
        "sent {} · recv {} · loss {:.1}% · late {} · dup {} · concealed {} · \
         trimmed {} · underruns {} · buffered {}",
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
pub async fn room_call(
    mut client: Client,
    signer: &sqnr_core::SoftwareSigner,
    room: RoomId,
    opts: CallOpts,
    report: &mut dyn Report,
) -> Result<(), String> {
    let me = PubKey::new(signer.public());
    if client.max_datagram_size().is_none() {
        return Err("this path does not carry datagrams, so it cannot carry a room".into());
    }

    let (mut source, capture) =
        audio::open_source(&opts.source, opts.seconds, opts.input.as_deref())?;
    let (out, play_rate) = audio::open_sink(&opts.sink, opts.output.as_deref())?;
    let mut encoder = encoder(opts.bitrate, capture)?;
    let mut mixer = Mixer::new(play_rate.frame());
    let mut pcm = vec![0f32; play_rate.frame()];
    // Every peer decodes at our playback rate, whatever rate they encoded at.
    let mut members = Membership::new(room, me, signer.seed(), opts.depth, play_rate);

    let mut playout = tokio::time::interval(Duration::from_millis(FRAME_MS));
    let mut roster = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
    let mut speaking_watch = tokio::time::interval(Duration::from_millis(ROSTER_MS));
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await;
    // Who was speaking when the roster was last described, so it is only
    // re-described when that changes.
    let mut spoke: Vec<PubKey> = Vec::new();

    report.event(Event::RoomJoined {
        me,
        bitrate: opts.bitrate,
        buffer_ms: opts.depth * FRAME_MS,
    });

    let mut hangup: Option<Instant> = None;
    let mut outgoing = media::Sender::new(KEEPALIVE_FRAMES, opts.dtx);
    let result = loop {
        tokio::select! {
            // Roster, heartbeat and session establishment are the same tick.
            // Everything here is a request-response on the one connection, so
            // it is sequential by construction; media does not wait for it.
            _ = roster.tick() => {
                match members.poll(&mut client).await {
                    Ok(events) => for e in events {
                        report.event(Event::Roster(e));
                    },
                    Err(e) => break Err(e),
                }
            }

            // One encode, then a seal per peer: the ciphertext differs because
            // every session has its own key, but the Opus packet does not.
            frame = source.recv(), if hangup.is_none() => match frame {
                Some(samples) => {
                    // One gate and one timestamp for the room: everyone is
                    // hearing the same person say the same thing at the same
                    // moment, so it is described once and sealed per peer.
                    let framed = outgoing.offer(&samples, |pcm| {
                        encoder
                            .encode_vec_float(pcm, MAX_DATAGRAM_FRAME - media::HEADER)
                            .map_err(|e| sqnr_core::Error::Malformed(format!("encode: {e}")))
                    });
                    let frame = match framed {
                        Ok(Some(f)) => f,
                        Ok(None) => continue,
                        Err(e) => break Err(e.to_string()),
                    };
                    let body = frame.encode();
                    for peer in members.peers.values_mut() {
                        let Ok(sealed) = peer.session.seal_datagram(peer.out_seq, &body) else {
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
                    report.event(Event::Draining);
                    hangup = Some(
                        Instant::now() + Duration::from_millis(500 + opts.depth * FRAME_MS),
                    );
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
                    if let Ok(plaintext) = peer.session.open(frame.seq, &frame.ciphertext)
                        && let Ok(Some(m)) = media::Frame::decode(&plaintext)
                    {
                        peer.heard();
                        peer.jitter.push(frame.seq, m.timestamp, m.body);
                    }
                }
            }

            _ = playout.tick() => {
                mixer.start();
                for peer in members.peers.values_mut() {
                    // Each peer's delay is its own: one bad path should not
                    // add latency to everybody else in the room.
                    if let Some(stale) = peer.jitter.trim() {
                        peer.playback
                            .render(&crate::jitter::Playout::Frame(stale), &mut pcm);
                    }
                    // A described pause counts as an active stream: their room
                    // keeps sounding like a room, and the mix gain does not
                    // lurch every time somebody pauses for breath.
                    let slot = peer.jitter.pop();
                    let decoded = peer.playback.render(&slot, &mut pcm);
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

            // A speaking indicator has to keep up with a conversation, but a
            // room where one person is talking must not repaint ten times a
            // second to say so. Only a *change* in who is speaking is worth an
            // update; the tick below carries the rest.
            _ = speaking_watch.tick() => {
                let mut now: Vec<PubKey> = members
                    .present()
                    .iter()
                    .filter(|p| p.is_speaking())
                    .map(|p| p.identity)
                    .collect();
                now.sort_unstable_by_key(|k| *k.as_bytes());
                if now != spoke {
                    spoke = now;
                    report.event(present_of(&members));
                }
            }

            _ = tick.tick() => {
                report.event(present_of(&members));
                report.event(Event::Stats(room_summary(&members)));
            }
        }
    };

    report.event(Event::FinalStats(room_summary(&members)));
    out.finish()?;
    members.leave(&mut client).await;
    result
}

/// The roster as structured data, for something that draws rather than prints.
///
/// Sorted by identity, and that is not cosmetic: `Membership::peers` is a
/// `HashMap`, so its order changes between looks. A list that reshuffles itself
/// ten times a second is unusable, and anything keyed on position in it — a
/// selection, a hover — would land on whoever happened to be there.
fn present_of(members: &Membership) -> Event {
    let mut peers: Vec<PeerStatus> = members
        .present()
        .iter()
        .map(|p| PeerStatus {
            identity: p.identity,
            speaking: p.is_speaking(),
            level: p.level,
            loss_pct: p.jitter.stats.loss_pct(p.jitter.span()),
            concealed: p.jitter.stats.concealed,
            buffered: p.jitter.depth_now(),
        })
        .collect();
    peers.sort_unstable_by_key(|p| *p.identity.as_bytes());
    Event::Present { peers, connecting: members.connecting() }
}

/// Who is here, who is talking, and how the paths to them are holding up.
///
/// The leading mark is a space rather than nothing when a peer is silent, so
/// the names stay in one column and the eye can find the speaker.
pub fn room_summary(members: &Membership) -> String {
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

// ---- reflecting -------------------------------------------------------------

/// Reflect a peer's frames straight back, so one person can measure a real
/// round trip through both relay hops without a second speaker.
///
/// Loops rather than returning: a session does not survive its caller
/// restarting, so when one goes quiet this waits for the next.
pub async fn echo(
    mut client: Client,
    signer: &sqnr_core::SoftwareSigner,
    peer: PubKey,
    wait: u64,
    report: &mut dyn Report,
) -> Result<(), String> {
    loop {
        let (session, id) = rendezvous(&mut client, signer, peer, wait, report).await?;
        report.event(Event::Reflecting { id });

        let mut reflected = 0u64;
        let mut last_heard = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.tick().await;

        loop {
            let mut gone = false;
            tokio::select! {
                got = client.read_datagram() => {
                    let bytes = got?;
                    let frame = DatagramFrame::decode(&bytes).map_err(|e| e.to_string())?;
                    if frame.session_id != id {
                        continue;
                    }
                    let Ok(packet) = session.open(frame.seq, &frame.ciphertext) else {
                        report.event(Event::BadFrame {
                            seq: frame.seq,
                            why: String::from("undecryptable"),
                        });
                        continue;
                    };
                    let sealed = session
                        .seal_datagram(frame.seq, &packet)
                        .map_err(|e| e.to_string())?;
                    client.send_datagram(
                        DatagramFrame { session_id: id, seq: frame.seq, ciphertext: sealed }
                            .encode(),
                    )?;
                    reflected += 1;
                    last_heard = Instant::now();
                }
                _ = tick.tick() => {
                    report.event(Event::Reflected(reflected));
                    if last_heard.elapsed() > CALLER_GONE {
                        gone = true;
                    }
                }
            }
            if gone {
                break;
            }
        }

        report.event(Event::FinalStats(Event::Reflected(reflected).describe()));
        let _ = client
            .post("/session/close", BySession::close(id).encode())
            .await;
        report.event(Event::CallerGone { after: CALLER_GONE });
    }
}
