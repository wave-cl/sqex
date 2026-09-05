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
//!
//! The call itself lives in [`sqex_voice::engine`]. This file is the terminal
//! around it: parsing arguments, unlocking an identity, printing what the
//! engine has to say, and handling SIGINT.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sqex_proto::room::RoomId;
use sqnr::{config::Config, identity};
use sqnr_core::PubKey;

use sqex_voice::audio::{self, Sink, Source};
use sqex_voice::engine::{self, CallOpts, Event, Report};

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
    /// A domain that publishes an exchange (SIP-33). Its key is discovered over
    /// DNSSEC, pinned on first contact, and refused if it later changes.
    #[arg(long)]
    server: Option<String>,
    /// A literal address, host:port, to dial. Requires --server-key.
    #[arg(long)]
    server_host: Option<String>,
    /// The server's base58 public key. Goes with --server-host; a --server
    /// domain supplies its own.
    #[arg(long)]
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

    /// Capture device, by any part of its name. Defaults to the system input.
    ///
    /// Worth setting on macOS: capturing from a Bluetooth headset drops it into
    /// narrowband in both directions, while capturing from the built-in
    /// microphone leaves the headset in high quality.
    #[arg(long = "in", global = true)]
    input_device: Option<String>,

    /// Playback device, by any part of its name. Defaults to the system output.
    #[arg(long = "out", global = true)]
    output_device: Option<String>,

    /// Transmit continuously, even while nobody is speaking.
    ///
    /// By default a silent speaker stops sending (SIP-14), which is most of the
    /// bandwidth in a room. Turn that off where the *pattern* of who speaks when
    /// is sensitive: the exchange cannot read a call either way, but it can see
    /// when packets flow.
    #[arg(long, global = true)]
    no_dtx: bool,

    /// List the audio devices and the rates each offers, then exit.
    #[arg(long)]
    list_devices: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
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

/// 130 is the shell's convention for "terminated by SIGINT".
extern "C" fn handle_sigint(_sig: libc::c_int) {
    // Nothing else. Anything that allocates or takes a lock may deadlock here,
    // because this runs on top of whatever the interrupted thread was doing.
    unsafe { libc::_exit(130) }
}

#[tokio::main]
async fn main() {
    // SIGINT is handled by the kernel, not by the runtime.
    //
    // Three async attempts at this failed intermittently and I could not
    // isolate why: a `select!` arm is starved by any blocking call in the other
    // arm, and a spawned task still depends on the executor being able to run
    // it. What is certain is the trap underneath them all — the first
    // `tokio::signal::ctrl_c()` anywhere in a process replaces SIGINT's default
    // disposition, so any moment nobody is awaiting it swallows the signal
    // instead of dying on it, leaving this harder to kill than if nothing had
    // handled it at all.
    //
    // A plain handler cannot be starved: the kernel runs it on whatever thread
    // takes the signal, whatever the runtime is doing. `_exit` is one of the
    // few things async-signal-safe enough to call from one.
    //
    // The cost is real and worth stating: an abandoned session is not closed on
    // the way out, so the exchange carries it until it times it out. That is a
    // better trade than a program you cannot stop.
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        );
    }

    let outcome = run(Cli::parse()).await;
    if let Err(e) = outcome {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ---- saying things ----------------------------------------------------------

/// Print what the engine reports, which is what this binary is for.
///
/// `--quiet` suppresses only the once-a-second statistics. Everything else —
/// the roster, the diagnoses, a device substitution — is said regardless: a
/// person who asked for less noise did not ask to be left guessing.
///
/// In particular it does **not** suppress `FinalStats`. The CLI has always
/// printed the closing summary under `--quiet`, because how the call went is
/// the one number worth having after it has ended.
struct Printer {
    quiet: bool,
}

impl Report for Printer {
    fn event(&mut self, event: Event) {
        if self.quiet && matches!(event, Event::Stats(_)) {
            return;
        }
        eprintln!("{}", event.describe());
    }
}

// ---- dispatch ---------------------------------------------------------------

async fn run(cli: Cli) -> Result<(), String> {
    if cli.list_devices {
        return audio::list_devices();
    }
    let cfg = Config::load();
    let Some(cmd) = &cli.cmd else {
        return Err("nothing to do — give a command, or --list-devices".into());
    };
    let mut report = Printer { quiet: cli.quiet };

    // A room has no peer to name, and `--new` needs no connection at all.
    if let Cmd::Room {
        room,
        new,
        source,
        sink,
        jitter,
        bitrate,
        seconds,
    } = cmd
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
        let signer = load_identity(&cli, &cfg)?;
        let endpoint = engine::resolve(&layers(&cli, &cfg), &mut report).await?;
        // A room has nobody to name, only a secret to hold, so it connects
        // rather than dials.
        let client = engine::connect(endpoint, &signer, &mut report).await?;
        return engine::room_call(
            client,
            &signer,
            id,
            opts(&cli, source, sink, *jitter, *bitrate, *seconds, false),
            &mut report,
        )
        .await;
    }

    let peer = parse_key(match cmd {
        Cmd::Call { peer, .. } | Cmd::Echo { peer } => peer,
        Cmd::Room { .. } => unreachable!("handled above"),
    })?;
    let signer = load_identity(&cli, &cfg)?;
    let endpoint = engine::resolve(&layers(&cli, &cfg), &mut report).await?;

    // Echo rendezvouses inside its own loop, so that it can do so again when a
    // caller goes away; a call does it once.
    if let Cmd::Echo { .. } = cmd {
        let client = engine::dial(endpoint, &signer, peer, &mut report).await?;
        return engine::echo(client, &signer, peer, cli.wait, &mut report).await;
    }

    let (client, session, id) =
        engine::establish(endpoint, &signer, peer, cli.wait, &mut report).await?;
    match cmd {
        Cmd::Call {
            source,
            sink,
            jitter,
            bitrate,
            seconds,
            rtt,
            ..
        } => {
            engine::call(
                client,
                session,
                id,
                opts(&cli, source, sink, *jitter, *bitrate, *seconds, *rtt),
                &mut report,
            )
            .await
        }
        Cmd::Echo { .. } => unreachable!("handled above"),
        Cmd::Room { .. } => unreachable!("handled above"),
    }
}

/// Fold the global flags and the subcommand's own into one set of options.
#[allow(clippy::too_many_arguments)]
fn opts(
    cli: &Cli,
    source: &Source,
    sink: &Sink,
    depth: u64,
    bitrate: i32,
    seconds: Option<u64>,
    rtt: bool,
) -> CallOpts {
    CallOpts {
        source: source.clone(),
        sink: sink.clone(),
        input: cli.input_device.clone(),
        output: cli.output_device.clone(),
        depth,
        bitrate,
        seconds,
        rtt,
        dtx: !cli.no_dtx,
    }
}

// ---- identity and endpoint --------------------------------------------------

/// A YubiKey is not an option here: the mailbox and session services act *as* an
/// identity on the transport, and a YubiKey signs but cannot be a transport key.
///
/// Asking for a passphrase is why this stayed in the binary. A terminal prompts
/// on stdin; something with a window opens a dialog; a library can do neither,
/// so the engine takes an already-unlocked signer.
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

/// The layers a caller can speak through, most specific first. Resolution is
/// shared with the other clients in `sqex_discovery::target`, because three
/// copies of it is what produced two bugs in a day.
fn layers(cli: &Cli, cfg: &Config) -> [sqex_discovery::Layer; 3] {
    [
        sqex_discovery::Layer {
            server: cli.server.clone(),
            host: cli.server_host.clone(),
            key: cli.server_key.clone(),
        },
        sqex_discovery::Layer {
            server: env_nonempty("SQEX_SERVER"),
            host: env_nonempty("SQEX_SERVER_HOST"),
            key: env_nonempty("SQEX_SERVER_KEY"),
        },
        // The config is `sqnr`'s type and has no `server_host`, so the pairing
        // rule is read off the two fields it does have.
        match (&cfg.server, &cfg.server_key) {
            (Some(s), Some(k)) => sqex_discovery::Layer {
                host: Some(s.clone()),
                key: Some(k.clone()),
                ..Default::default()
            },
            (Some(s), None) => sqex_discovery::Layer {
                server: Some(s.clone()),
                ..Default::default()
            },
            _ => sqex_discovery::Layer::default(),
        },
    ]
}

fn parse_key(s: &str) -> Result<PubKey, String> {
    s.trim().parse().map_err(|e| format!("bad key {s:?}: {e}"))
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}
