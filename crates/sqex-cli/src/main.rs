//! sqex — the command-line admin tool for sqex.
//!
//! It builds signed transactions from the [`sqex_proto::Op`] vocabulary and
//! submits them over HTTP/3 using sqnr's generic signer. Authority is the
//! Ed25519 signature on the transaction, produced by a software identity or a
//! YubiKey; the connection's transport key is irrelevant. The passphrase / PIN /
//! touch are entered by the operator — never stored here.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sqex_proto::Op;
use sqex_proto::refusal::Refusal;
use sqex_proto::beacon::{Beat, BeatAck, Read, Reply};
use sqex_proto::resolve::{
    Endpoint, KIND_DNS, KIND_IPV4, KIND_IPV6, MAX_HOST, Publish as ResolvePublish,
    Resolve as ResolveGet, Resolved, Successor as ResolveSuccessor,
};
use sqex_proto::mailbox::{self, ById, Fetched, Listing, Send as MailSend, SendAck, State, Status};
use sqex_proto::session::{
    BySession, DatagramFrame, Frames, Open, OpenAck, OpenState, SendFrame, Session,
};
use sqnr::{Backend, Card, Client, config::Config, flow, identity};
use sqnr_core::{Operation, PubKey, Signer, Transaction};

#[derive(Parser)]
#[command(name = "sqex", version, about = "Administer a sqex server with signed transactions")]
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

    /// Sign with a YubiKey instead of a file identity.
    #[arg(long, global = true)]
    yubikey: bool,

    /// Software identity file (default ~/.sqnr/identity).
    #[arg(short = 'i', long, global = true)]
    identity: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show server status (public; no signing).
    Status,
    /// Signed administration (whitelist, audit, admin list).
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Liveness beacon: assert this identity is alive, or ask about another.
    Beacon {
        #[command(subcommand)]
        cmd: BeaconCmd,
    },
    /// Public key resolution: say where this identity can be reached, or ask
    /// where another one is.
    Resolve {
        #[command(subcommand)]
        cmd: ResolveCmd,
    },
    /// Store-and-forward mailbox: leave sealed messages, collect your own.
    Mail {
        #[command(subcommand)]
        cmd: MailCmd,
    },
    /// Relayed session: exchange data with a peer through the exchange, when
    /// neither of you is reachable by the other.
    Session {
        #[command(subcommand)]
        cmd: SessionCmd,
    },
    /// Find the exchange a domain publishes (SIP-33), and inspect what is
    /// pinned. Talks to DNS only — no exchange is contacted.
    Discover {
        /// The domain to look up. Omit to list what is already pinned.
        domain: Option<String>,
        /// Forget the key pinned for a domain, so the next connection is
        /// treated as a first contact.
        #[arg(long, value_name = "DOMAIN")]
        forget: Option<String>,
    },
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Open a session with a peer and talk: stdin goes to them, their frames
    /// come to stdout. Waits until they open a session with you too.
    Talk {
        /// The peer's Ed25519 identity, base58.
        peer: String,
        /// Give up if the peer has not joined within this many seconds.
        #[arg(long, default_value_t = 120)]
        wait: u64,
        /// Carry frames on QUIC datagrams instead of request-response.
        ///
        /// Unreliable and unordered — a lost frame is not retransmitted — which
        /// is the right trade for real-time media, and the wrong one for
        /// anything that cannot lose a packet. Removes the polling delay.
        #[arg(long)]
        datagram: bool,
    },
}

#[derive(Subcommand)]
enum MailCmd {
    /// Seal a message to a recipient and leave it at the exchange.
    Send {
        /// Recipient's Ed25519 identity, base58.
        recipient: String,
        /// The message. Omit to read it from stdin.
        message: Option<String>,
    },
    /// List the messages waiting for you.
    List,
    /// Fetch and open one message. Leaves it on the exchange until `delete`.
    Fetch { id: u64 },
    /// Complete collection: drop the message from the exchange.
    Delete { id: u64 },
    /// Ask what became of a message you sent.
    Status { id: u64 },
    /// Fetch, open, delete — every message waiting for you, in order.
    Collect,
}

#[derive(Subcommand)]
enum BeaconCmd {
    /// Beat: tell the exchange this identity is alive. Connects *as* the
    /// identity, so no signature is needed — the connection is the proof.
    Beat {
        /// How often this identity intends to beat, in seconds. Consumers read
        /// it to judge staleness; the exchange does not enforce it.
        #[arg(short = 'n', long, default_value_t = 60)]
        interval: u32,
        /// Withhold this record from queries by other identities.
        #[arg(long)]
        withhold: bool,
    },
    /// Ask when the exchange last saw an identity.
    Read {
        /// The identity to ask about, base58. Defaults to your own.
        key: Option<String>,
    },
}

#[derive(Subcommand)]
enum ResolveCmd {
    /// Publish where this identity can be reached. Replaces the whole set:
    /// SIP-28 has no partial update, because reconciling one against a
    /// trusting store is where stale addresses live forever.
    Publish {
        /// `host:port` to advertise, repeatable. A bare IP or a DNS name.
        #[arg(required = true)]
        endpoint: Vec<String>,
        /// What this identity speaks — an ALPN, a service name, a version.
        /// Repeatable. Published alongside the addresses and expiring with
        /// them, because it has the same provenance they do.
        ///
        /// **Advertising capability advertises attack surface.** A version
        /// string tells an attacker which vulnerabilities apply, and an
        /// exchange makes that queryable for every identity at once.
        #[arg(short = 'c', long = "capability")]
        capability: Vec<String>,
        /// How long the exchange should believe it, in seconds.
        #[arg(short = 't', long, default_value_t = 300)]
        ttl: u32,
    },
    /// Ask where a key can be reached.
    ///
    /// **The answer is the exchange's word.** Connecting to it pins the key you
    /// asked for, so a wrong address is a failed handshake rather than somebody
    /// else answering — the exchange is trusted for availability, not for
    /// authenticity.
    Get {
        /// The identity to ask about, base58. Defaults to your own.
        key: Option<String>,
    },
    /// Say this identity has moved.
    ///
    /// **Not a retirement.** It is authenticated by the connection, so whoever
    /// holds the key can set it — after a theft, that is the attacker. It says
    /// "I am moving", and only while the mover is still in control.
    Moved {
        /// The identity that takes over, base58.
        successor: String,
        /// A line for a human, at most 128 bytes.
        #[arg(default_value = "")]
        reason: String,
    },
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Manage the connection whitelist.
    Whitelist {
        #[command(subcommand)]
        action: WhitelistCmd,
    },
    /// Read recent audit entries.
    Audit {
        #[arg(short = 'n', long, default_value_t = 50)]
        count: u32,
    },
    /// Re-read the server's admin list from its config file.
    ReloadAdmins,
}

#[derive(Subcommand)]
enum WhitelistCmd {
    /// List the whitelist (enabled flag + keys).
    List,
    /// Enforce the whitelist on protected endpoints.
    Enable,
    /// Stop enforcing the whitelist.
    Disable,
    /// Add one or more peer keys (signed as a single batch).
    Add {
        keys: Vec<String>,
        /// Optional human label recorded as provenance for each key.
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove one or more peer keys (signed as a single batch).
    Remove { keys: Vec<String> },
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
    match &cli.cmd {
        Cmd::Status => status(&cli, &cfg).await,
        Cmd::Admin { cmd } => admin(&cli, &cfg, cmd).await,
        Cmd::Beacon { cmd } => beacon(&cli, &cfg, cmd).await,
        Cmd::Resolve { cmd } => resolution(&cli, &cfg, cmd).await,
        Cmd::Mail { cmd } => mail(&cli, &cfg, cmd).await,
        Cmd::Session { cmd } => session(&cli, &cfg, cmd).await,
        Cmd::Discover { domain, forget } => discover(domain.as_deref(), forget.as_deref()).await,
    }
}

// ---- discovery (SIP-33) -----------------------------------------------------

/// Look a domain up, or show and edit what is pinned.
///
/// **Read-only on the pin store unless `--forget` is given.** A diagnostic that
/// pinned a key as a side effect would make a trust decision every time somebody
/// ran it to see what was there; connecting is what pins.
async fn discover(domain: Option<&str>, forget: Option<&str>) -> Result<(), String> {
    let path = sqex_discovery::known::path();

    if let Some(d) = forget {
        let mut store = sqex_discovery::Known::load(&path)?;
        if store.remove(d) {
            store.save(&path)?;
            println!("forgot {d}. The next connection to it is a first contact again.");
        } else {
            println!("nothing was pinned for {d}");
        }
        return Ok(());
    }

    let store = sqex_discovery::Known::load(&path)?;

    let Some(domain) = domain else {
        if store.entries().is_empty() {
            println!("nothing pinned yet — {}", path.display());
            return Ok(());
        }
        println!("pinned in {}:", path.display());
        for e in store.entries() {
            if e.comment.is_empty() {
                println!("  {}  {}", e.domain, e.key);
            } else {
                println!("  {}  {}  ({})", e.domain, e.key, e.comment);
            }
        }
        return Ok(());
    };

    let records = sqex_discovery::dns::lookup(domain)
        .await
        .map_err(|e| e.to_string())?;

    println!(
        "{domain} publishes {} record(s) at _sqex.{domain}, DNSSEC-validated:",
        records.len()
    );
    for r in &records {
        let host = r.host.as_deref().unwrap_or(domain);
        println!("  {}  at {host}:{}", r.key, r.port);
    }

    // What would happen next, said plainly, without doing it.
    let offered: Vec<_> = records.iter().map(|r| r.key).collect();
    match sqex_discovery::known::decide(&offered, store.lookup(domain)) {
        Some(sqex_discovery::Decision::Pinned(k)) => {
            println!("\npinned already: {k}");
            if offered.len() > 1 {
                println!(
                    "A rotation is in progress. The pin stays put until the key it names \n\
                     stops being published — a key seen beside it earns nothing."
                );
            }
        }
        Some(sqex_discovery::Decision::FirstContact(k)) => {
            println!("\nnothing pinned for {domain} yet.");
            println!("Connecting would pin {k} and refuse any later change.");
        }
        Some(sqex_discovery::Decision::Changed { pinned, offered }) => {
            println!();
            println!("{}", sqex_discovery::known::changed_message(domain, &pinned, &offered));
            return Err("the published key is not the pinned one".into());
        }
        None => {}
    }
    Ok(())
}

// ---- relayed session --------------------------------------------------------

async fn session(cli: &Cli, cfg: &Config, cmd: &SessionCmd) -> Result<(), String> {
    let SessionCmd::Talk {
        peer,
        wait,
        datagram,
    } = cmd;
    let peer = parse_key(peer)?;
    let (mut client, signer) = mail_client(cli, cfg).await?;
    let me = PubKey::new(signer.public());
    if me == peer {
        return Err("a session needs two identities".into());
    }

    // Our contribution to the key agreement. The exchange relays it but cannot
    // use it: completing the agreement needs a static private key from each of
    // us, and it holds neither.
    let eph = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes();
    let open = Open {
        peer,
        ephemeral: eph_pub,
    };

    eprintln!("waiting for {peer} to open a session with you…");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(*wait);
    let ack = loop {
        let (code, body) = client.post("/session/open", open.encode()).await?;
        if code != 200 {
            return Err(format!(
                "open failed ({code}): {}",
                said(&body)
            ));
        }
        let ack = OpenAck::decode(&body).map_err(|e| e.to_string())?;
        if ack.state == OpenState::Established {
            break ack;
        }
        if std::time::Instant::now() >= deadline {
            return Err("the peer did not join in time".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };

    let session = Session::derive(&signer.seed(), &eph, &peer, &ack.peer_ephemeral)
        .map_err(|e| e.to_string())?;
    if *datagram {
        match client.max_datagram_size() {
            Some(max) => eprintln!(
                "session {} established on datagrams (up to {max} bytes) — type to send, Ctrl-D to end",
                ack.session_id
            ),
            None => return Err("this path does not carry datagrams".into()),
        }
        return talk_datagram(client, session, ack.session_id).await;
    }

    eprintln!("session {} established — type to send, Ctrl-D to end", ack.session_id);
    talk(client, session, ack.session_id).await
}

/// Read stdin on its own thread; blocking reads cannot live on the runtime.
fn stdin_lines() -> tokio::sync::mpsc::UnboundedReceiver<String> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::stdin().lock().lines() {
            let Ok(l) = line else { break };
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    rx
}

/// The unreliable path: frames ride datagrams, so nothing polls and nothing
/// waits on a response. This is the shape real-time media needs.
async fn talk_datagram(mut client: Client, session: Session, id: u64) -> Result<(), String> {
    let mut lines = stdin_lines();
    let mut out_seq = 0u64;
    let mut last_seen: Option<u64> = None;

    loop {
        tokio::select! {
            // Anything to send goes out immediately — no request, no response.
            line = lines.recv() => match line {
                Some(l) => {
                    let ct = session.seal_datagram(out_seq, l.as_bytes()).map_err(|e| e.to_string())?;
                    client.send_datagram(
                        DatagramFrame { session_id: id, seq: out_seq, ciphertext: ct }.encode(),
                    )?;
                    out_seq += 1;
                }
                None => {
                    let _ = client.post("/session/close", BySession::close(id).encode()).await;
                    eprintln!("(input ended; closing)");
                    return Ok(());
                }
            },
            // Anything inbound arrives the moment the exchange forwards it.
            got = client.read_datagram() => {
                let bytes = got?;
                let frame = DatagramFrame::decode(&bytes).map_err(|e| e.to_string())?;
                if frame.session_id != id {
                    continue; // some other session on this connection
                }
                // A gap means a lost frame. Say so rather than hide it: with
                // media you would conceal it, and either way it is not an error.
                if let Some(prev) = last_seen
                    && frame.seq > prev + 1
                {
                    eprintln!("(lost {} frame(s))", frame.seq - prev - 1);
                }
                last_seen = Some(frame.seq);
                match session.open(frame.seq, &frame.ciphertext) {
                    Ok(plain) => println!("{}", String::from_utf8_lossy(&plain)),
                    Err(e) => eprintln!("(undecryptable frame {}: {e})", frame.seq),
                }
            }
        }
    }
}

/// Pump stdin to the peer and their frames to stdout until either end stops.
async fn talk(mut client: Client, session: Session, id: u64) -> Result<(), String> {
    let mut lines_rx = stdin_lines();
    let mut out_seq = 0u64;
    let mut stdin_open = true;
    loop {
        // Anything to send?
        if stdin_open {
            match lines_rx.try_recv() {
                Ok(line) => {
                    let ct = session.seal(out_seq, line.as_bytes()).map_err(|e| e.to_string())?;
                    let frame = SendFrame {
                        session_id: id,
                        seq: out_seq,
                        ciphertext: ct,
                    };
                    let (code, body) = client.post("/session/send", frame.encode()).await?;
                    if code != 200 {
                        return Err(format!(
                            "send failed ({code}): {}",
                            said(&body)
                        ));
                    }
                    out_seq += 1;
                    continue; // drain stdin eagerly before polling
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    stdin_open = false;
                    let _ = client
                        .post("/session/close", BySession::close(id).encode())
                        .await;
                    eprintln!("(input ended; closing)");
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            }
        }

        // Anything waiting for us?
        let (code, body) = client
            .post("/session/recv", BySession::recv(id).encode())
            .await?;
        if code != 200 {
            return Err(format!("recv failed ({code})"));
        }
        let frames = Frames::decode(&body).map_err(|e| e.to_string())?;
        for (seq, ct) in &frames.frames {
            match session.open(*seq, ct) {
                Ok(plain) => println!("{}", String::from_utf8_lossy(&plain)),
                Err(e) => eprintln!("(undecryptable frame {seq}: {e})"),
            }
        }
        if !frames.open {
            eprintln!("(the session has ended)");
            return Ok(());
        }
        if !stdin_open && frames.frames.is_empty() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

// ---- mailbox ----------------------------------------------------------------

/// Every mailbox operation acts *as* an identity, so all of them dial with
/// `connect_as`. A YubiKey cannot: it signs, but cannot be a transport key.
async fn mail_client(
    cli: &Cli,
    cfg: &Config,
) -> Result<(Client, sqnr_core::SoftwareSigner), String> {
    if cli.yubikey {
        return Err(
            "a YubiKey cannot use the mailbox: it signs, but cannot be a transport identity. \
             Use a software identity (see SIP-11 on delegation)."
                .into(),
        );
    }
    let signer = load_software_identity(cli, cfg)?;
    let (addr, server) = endpoint(cli, cfg).await?;
    let client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
    Ok((client, signer))
}

async fn mail(cli: &Cli, cfg: &Config, cmd: &MailCmd) -> Result<(), String> {
    match cmd {
        MailCmd::Send { recipient, message } => {
            let to = parse_key(recipient)?;
            let plaintext = match message {
                Some(m) => m.clone().into_bytes(),
                None => {
                    use std::io::Read as _;
                    let mut buf = Vec::new();
                    std::io::stdin()
                        .read_to_end(&mut buf)
                        .map_err(|e| format!("read stdin: {e}"))?;
                    buf
                }
            };
            // Sealed here, on this machine. The exchange only ever sees
            // ciphertext and cannot do otherwise.
            let sealed = mailbox::seal(&to, &plaintext).map_err(|e| e.to_string())?;
            let (mut client, _signer) = mail_client(cli, cfg).await?;
            let (code, body) = client
                .post("/mailbox/send", MailSend { recipient: to, sealed }.encode())
                .await?;
            if code != 200 {
                return Err(format!(
                    "send refused ({code}): {}",
                    said(&body)
                ));
            }
            let ack = SendAck::decode(&body).map_err(|e| e.to_string())?;
            println!("sent to {to} as message {}", ack.id);
            Ok(())
        }

        MailCmd::List => {
            let (mut client, signer) = mail_client(cli, cfg).await?;
            let listing = list_mail(&mut client).await?;
            if listing.entries.is_empty() {
                println!("no messages waiting for {}", PubKey::new(signer.public()));
                return Ok(());
            }
            println!("{} message(s) waiting:", listing.entries.len());
            for e in &listing.entries {
                println!(
                    "  [{}] from {}  {} bytes  {}s ago",
                    e.id,
                    e.sender,
                    e.len,
                    listing.now.saturating_sub(e.received)
                );
            }
            Ok(())
        }

        MailCmd::Fetch { id } => {
            let (mut client, signer) = mail_client(cli, cfg).await?;
            match fetch_one(&mut client, &signer, *id).await? {
                Some((sender, text)) => {
                    println!("from {sender}:");
                    println!("{text}");
                    println!("\n(still on the exchange — `sqex mail delete {id}` to complete collection)");
                    Ok(())
                }
                None => Err(format!("no message {id} for you")),
            }
        }

        MailCmd::Delete { id } => {
            let (mut client, _) = mail_client(cli, cfg).await?;
            let deleted = delete_one(&mut client, *id).await?;
            if deleted {
                println!("collected message {id}");
            } else {
                println!("nothing to collect for message {id}");
            }
            Ok(())
        }

        MailCmd::Status { id } => {
            let (mut client, _) = mail_client(cli, cfg).await?;
            let (code, body) = client
                .post("/mailbox/status", ById::status(*id).encode())
                .await?;
            if code != 200 {
                return Err(format!("status failed ({code})"));
            }
            let s = Status::decode(&body).map_err(|e| e.to_string())?;
            match s.state {
                State::Unknown => println!("message {id}: unknown (never sent by you, or expired)"),
                State::Waiting => println!(
                    "message {id}: waiting, left {}s ago",
                    s.now.saturating_sub(s.received)
                ),
                State::Collected => println!(
                    "message {id}: collected {}s ago",
                    s.now.saturating_sub(s.collected)
                ),
            }
            Ok(())
        }

        MailCmd::Collect => {
            let (mut client, signer) = mail_client(cli, cfg).await?;
            let listing = list_mail(&mut client).await?;
            if listing.entries.is_empty() {
                println!("nothing waiting");
                return Ok(());
            }
            for e in &listing.entries {
                match fetch_one(&mut client, &signer, e.id).await? {
                    Some((sender, text)) => {
                        println!("── [{}] from {sender} ──", e.id);
                        println!("{text}");
                        // Only delete once it is in hand: at-least-once means a
                        // failure here costs a retry, never the message.
                        delete_one(&mut client, e.id).await?;
                    }
                    None => println!("── [{}] vanished before collection", e.id),
                }
            }
            Ok(())
        }
    }
}

async fn list_mail(client: &mut Client) -> Result<Listing, String> {
    let (code, body) = client.post("/mailbox/list", Vec::new()).await?;
    if code != 200 {
        return Err(format!(
            "list failed ({code}): {}",
            said(&body)
        ));
    }
    Listing::decode(&body).map_err(|e| e.to_string())
}

/// Fetch and open one message, returning (sender, plaintext).
async fn fetch_one(
    client: &mut Client,
    signer: &sqnr_core::SoftwareSigner,
    id: u64,
) -> Result<Option<(PubKey, String)>, String> {
    let (code, body) = client.post("/mailbox/fetch", ById::fetch(id).encode()).await?;
    if code != 200 {
        return Err(format!("fetch failed ({code})"));
    }
    let f = Fetched::decode(&body).map_err(|e| e.to_string())?;
    if !f.found {
        return Ok(None);
    }
    let plain = mailbox::open(&signer.seed(), &f.sealed).map_err(|e| e.to_string())?;
    Ok(Some((f.sender, String::from_utf8_lossy(&plain).into_owned())))
}

async fn delete_one(client: &mut Client, id: u64) -> Result<bool, String> {
    let (code, body) = client
        .post("/mailbox/delete", ById::delete(id).encode())
        .await?;
    if code != 200 {
        return Err(format!("delete failed ({code})"));
    }
    Ok(body.first().copied().unwrap_or(0) != 0)
}

// ---- resolve ----------------------------------------------------------------

/// Parse a `host:port` an operator typed into the shape SIP-28 publishes.
///
/// A bare IPv4 or IPv6 literal becomes an address endpoint; anything else is
/// taken as a DNS name, which is what an operator behind a changing address
/// wants and is the only kind an exchange cannot check.
fn parse_endpoint(text: &str) -> Result<Endpoint, String> {
    let (host, port) = match text.rsplit_once(':') {
        // A bracketed IPv6 literal, `[::1]:443`.
        Some((h, p)) if h.starts_with('[') && h.ends_with(']') => (&h[1..h.len() - 1], p),
        Some((h, p)) if !h.contains(':') => (h, p),
        // No port, or an unbracketed IPv6 address, which is ambiguous either
        // way and is refused rather than guessed at.
        _ => return Err(format!("{text}: want host:port, and [addr]:port for IPv6")),
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("{text}: {port} is not a port"))?;
    let (kind, host) = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => (KIND_IPV4, a.octets().to_vec()),
        Ok(std::net::IpAddr::V6(a)) => (KIND_IPV6, a.octets().to_vec()),
        Err(_) => {
            if host.is_empty() || host.len() > MAX_HOST {
                return Err(format!("{text}: a name must be 1..={MAX_HOST} bytes"));
            }
            (KIND_DNS, host.as_bytes().to_vec())
        }
    };
    Ok(Endpoint {
        kind,
        host,
        port,
        priority: 0,
        weight: 0,
    })
}

/// Render an endpoint the way it was typed.
fn show_endpoint(e: &Endpoint) -> String {
    match e.kind {
        KIND_IPV4 if e.host.len() == 4 => {
            let o: [u8; 4] = e.host[..].try_into().unwrap();
            format!("{}:{}", std::net::Ipv4Addr::from(o), e.port)
        }
        KIND_IPV6 if e.host.len() == 16 => {
            let o: [u8; 16] = e.host[..].try_into().unwrap();
            format!("[{}]:{}", std::net::Ipv6Addr::from(o), e.port)
        }
        _ => format!("{}:{}", String::from_utf8_lossy(&e.host), e.port),
    }
}

async fn resolution(cli: &Cli, cfg: &Config, cmd: &ResolveCmd) -> Result<(), String> {
    match cmd {
        ResolveCmd::Publish { endpoint: addrs, capability, ttl } => {
            // Publishing means connecting *as* the identity: the handshake is
            // what establishes which key is speaking, which is why nothing here
            // is signed and why a YubiKey cannot do it.
            if cli.yubikey {
                return Err(
                    "a YubiKey cannot publish endpoints: it signs, but cannot be a transport \
                     identity. Publish with a software identity (see SIP-11 on delegation)."
                        .into(),
                );
            }
            let signer = load_software_identity(cli, cfg)?;
            let endpoints: Vec<Endpoint> = addrs
                .iter()
                .map(|e| parse_endpoint(e))
                .collect::<Result<_, _>>()?;
            let (addr, server) = endpoint(cli, cfg).await?;
            let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
            let req = ResolvePublish {
                ttl_secs: *ttl,
                endpoints,
                capabilities: capability.clone(),
            };
            let (code, body) = client.post("/resolve/publish", req.encode()).await?;
            if code != 200 {
                return Err(format!("publish refused ({code}): {}", said(&body)));
            }
            println!(
                "published {} endpoint(s) for {}, good for {}s",
                req.endpoints.len(),
                PubKey::new(signer.public()),
                ttl
            );
            Ok(())
        }
        ResolveCmd::Get { key } => {
            let target = match key {
                Some(k) => parse_key(k)?,
                None => own_identity(cli, cfg)?,
            };
            let (addr, server) = endpoint(cli, cfg).await?;
            // As ourselves where we can: an identity's own withheld liveness is
            // disclosed to it and to nobody else.
            let mut client = match load_software_identity(cli, cfg) {
                Ok(signer) => Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?,
                Err(_) => Client::connect(addr, server.as_bytes()).await?,
            };
            let (code, body) = client
                .post("/resolve/get", ResolveGet { key: target }.encode())
                .await?;
            if code != 200 {
                return Err(format!("resolve failed ({code}): {}", said(&body)));
            }
            let r = Resolved::decode(&body).map_err(|e| e.to_string())?;
            if !r.found {
                println!("{target}: no endpoints published");
                return Ok(());
            }
            for e in &r.endpoints {
                println!("{}", show_endpoint(e));
            }
            if !r.capabilities.is_empty() {
                println!("  speaks {}", r.capabilities.join(", "));
            }
            // The provenance, because an answer without it cannot be judged.
            // Ages against the exchange's clock, not this machine's, for the
            // reason SIP-4 gives.
            println!(
                "  published {}s ago, expires in {}s",
                r.now.saturating_sub(r.published_at),
                r.expires_at.saturating_sub(r.now)
            );
            match r.last_seen {
                0 => println!("  never seen beating — this exchange has no evidence it is up"),
                seen => println!("  last seen {}s ago", r.now.saturating_sub(seen)),
            }
            Ok(())
        }
        ResolveCmd::Moved { successor, reason } => {
            if cli.yubikey {
                return Err("a YubiKey cannot be a transport identity".into());
            }
            let signer = load_software_identity(cli, cfg)?;
            let to = parse_key(successor)?;
            let (addr, server) = endpoint(cli, cfg).await?;
            let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
            let req = ResolveSuccessor {
                successor: to,
                reason: reason.clone(),
            };
            let (code, body) = client.post("/resolve/successor", req.encode()).await?;
            if code != 200 {
                return Err(format!("successor refused ({code}): {}", said(&body)));
            }
            println!(
                "{} now points at {to}. This says you are moving; it does not say \
                 the old key was stolen, and cannot — whoever holds a key can set this",
                PubKey::new(signer.public())
            );
            Ok(())
        }
    }
}

// ---- beacon -----------------------------------------------------------------

async fn beacon(cli: &Cli, cfg: &Config, cmd: &BeaconCmd) -> Result<(), String> {
    match cmd {
        BeaconCmd::Beat { interval, withhold } => {
            // Beating means connecting *as* the identity, so the transport
            // carries it (SIP-3). That needs the identity's seed, which only a
            // software identity has — a YubiKey cannot be a transport key.
            if cli.yubikey {
                return Err(
                    "a YubiKey cannot beat: it signs, but cannot be a transport identity. \
                     Beat with a software identity (see SIP-11 on delegation)."
                        .into(),
                );
            }
            let signer = load_software_identity(cli, cfg)?;
            let seed = signer.seed();
            let (addr, server) = endpoint(cli, cfg).await?;
            let mut client = Client::connect_as(addr, server.as_bytes(), &seed).await?;

            let beat = Beat {
                interval_secs: *interval,
                withhold: *withhold,
            };
            let (code, body) = client.post("/beacon/beat", beat.encode()).await?;
            if code != 200 {
                return Err(format!(
                    "beat refused ({code}): {}",
                    said(&body)
                ));
            }
            let ack = BeatAck::decode(&body).map_err(|e| e.to_string())?;
            println!(
                "beat recorded for {} at {} (interval {}s{})",
                PubKey::new(signer.public()),
                ack.now,
                interval,
                if *withhold { ", withheld" } else { "" }
            );
            Ok(())
        }
        BeaconCmd::Read { key } => {
            // Reading is open, but connecting as ourselves is what lets the
            // exchange disclose our own withheld record.
            let target = match key {
                Some(k) => parse_key(k)?,
                None => own_identity(cli, cfg)?,
            };
            let (addr, server) = endpoint(cli, cfg).await?;
            let mut client = match load_software_identity(cli, cfg) {
                Ok(signer) => Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?,
                // No usable identity: ask anonymously. Withheld records stay hidden.
                Err(_) => Client::connect(addr, server.as_bytes()).await?,
            };

            let (code, body) = client.post("/beacon/read", Read { key: target }.encode()).await?;
            if code != 200 {
                return Err(format!(
                    "read failed ({code}): {}",
                    said(&body)
                ));
            }
            let r = Reply::decode(&body).map_err(|e| e.to_string())?;
            if !r.found {
                println!("{target}: not seen");
                return Ok(());
            }
            // Report the facts; the threshold is the caller's to choose, so
            // print how many declared intervals have elapsed rather than a
            // verdict (SIP-4 forbids the exchange deciding this, and a CLI
            // deciding it silently would be the same mistake one layer up).
            let missed = if r.interval_secs > 0 {
                format!(" ({} intervals)", r.staleness() / u64::from(r.interval_secs))
            } else {
                String::new()
            };
            println!(
                "{target}: last seen {}s ago{missed}, declared interval {}s",
                r.staleness(),
                r.interval_secs
            );
            Ok(())
        }
    }
}

/// The software identity, for connecting *as* it. Prompts only if encrypted.
fn load_software_identity(cli: &Cli, cfg: &Config) -> Result<sqnr_core::SoftwareSigner, String> {
    let path = identity_path(cli, cfg)?;
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

/// This caller's own Ed25519 identity, without needing to decrypt it.
fn own_identity(cli: &Cli, cfg: &Config) -> Result<PubKey, String> {
    identity::read_public(&identity_path(cli, cfg)?)
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

/// Resolve the server address and pinned key without connecting.
async fn endpoint(cli: &Cli, cfg: &Config) -> Result<(SocketAddr, PubKey), String> {
    match sqex_discovery::target::resolve(&layers(cli, cfg)).map_err(|e| e.to_string())? {
        sqex_discovery::Target::Direct { address, key } => Ok((resolve(&address)?, key)),
        sqex_discovery::Target::Discover(domain) => {
            let found = sqex_discovery::discover(&domain)
                .await
                .map_err(|e| e.to_string())?;
            if found.newly_pinned {
                eprintln!(
                    "{domain}: discovered {} over DNSSEC and pinned it. \
                     Forget it with `sqex discover --forget {domain}`.",
                    found.key
                );
            }
            Ok((resolve(&found.address)?, found.key))
        }
    }
}

/// `host:port`, `host`, or an IP literal.
///
/// A bare host is not an error — an exchange has a well-known port — and a name
/// is not one either: this used to parse straight to a `SocketAddr`, which
/// accepts only an IP, so `sqex --server ex.example.com` failed with a message
/// about the address being bad when it was perfectly good.
fn resolve(address: &str) -> Result<SocketAddr, String> {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return Ok(socket);
    }
    let with_port = if address.starts_with('[') || !has_port(address) {
        format!("{address}:{}", sqex_discovery::DEFAULT_PORT)
    } else {
        address.to_string()
    };
    std::net::ToSocketAddrs::to_socket_addrs(&with_port)
        .map_err(|e| format!("cannot resolve {address:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("{address:?} resolved to no addresses"))
}

/// Whether a trailing `:port` is present, leaving IPv6 literals alone.
fn has_port(address: &str) -> bool {
    !address.starts_with('[')
        && address
            .rsplit_once(':')
            .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
}

async fn admin(cli: &Cli, cfg: &Config, cmd: &AdminCmd) -> Result<(), String> {
    match cmd {
        AdminCmd::Whitelist { action } => whitelist(cli, cfg, action).await,
        AdminCmd::Audit { count } => {
            let v = submit(cli, cfg, vec![Op::AuditTail(*count).to_operation()]).await?;
            print_audit(&result(&v, 0));
            Ok(())
        }
        AdminCmd::ReloadAdmins => {
            let v = submit(cli, cfg, vec![Op::ReloadAdmins.to_operation()]).await?;
            println!("{}", result(&v, 0));
            Ok(())
        }
    }
}

async fn status(cli: &Cli, cfg: &Config) -> Result<(), String> {
    let (mut client, _server) = connect(cli, cfg).await?;
    let (code, body) = client.get("/status").await?;
    if code != 200 {
        return Err(format!("status failed ({code})"));
    }
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    println!(
        "server {} · up {}s · whitelist {} ({} keys)",
        v["version"].as_str().unwrap_or("?"),
        v["uptime_secs"].as_u64().unwrap_or(0),
        if v["whitelist_enabled"].as_bool().unwrap_or(false) {
            "on"
        } else {
            "off"
        },
        v["whitelist_count"].as_u64().unwrap_or(0),
    );
    // How much this exchange is being asked, and how many clients it is
    // pushing to. The pair is the point: under SIP-30 the second should grow
    // and the first should stop growing, and an operator who could only see
    // uptime had no way to tell whether that was happening.
    println!(
        "  {} requests · {} event stream(s) open",
        v["requests"].as_u64().unwrap_or(0),
        v["event_streams"].as_u64().unwrap_or(0),
    );
    // The SIP-29 retirement question, in the only form that can answer it:
    // which envelope versions this exchange accepts, and which ones callers
    // are actually still sending. Retiring a version with traffic on it locks
    // those callers out silently — a refused envelope is dropped without a
    // reply, so neither end reports anything. This is the arithmetic that
    // replaces the nerve.
    let t = &v["transport"];
    if let Some(arriving) = t["initials_by_envelope_version"].as_object() {
        let accepted: Vec<String> = t["accepted_envelope_versions"]
            .as_array()
            .map(|a| a.iter().map(|x| x.to_string()).collect())
            .unwrap_or_default();
        // Sorted: the map comes back keyed by a string, so "10" would
        // otherwise sort before "2" the day a tenth version exists.
        let mut counts: Vec<(u64, u64)> = arriving
            .iter()
            .filter_map(|(k, n)| Some((k.parse().ok()?, n.as_u64()?)))
            .collect();
        counts.sort_unstable();
        let seen: Vec<String> = counts
            .iter()
            .map(|(version, n)| format!("v{version} {n}"))
            .collect();
        println!(
            "  envelope: accepts [{}] · initials seen {}",
            accepted.join(", "),
            seen.join(" · "),
        );
    }
    if t["under_load"].as_bool().unwrap_or(false) {
        println!(
            "  UNDER LOAD: {} cookie challenge(s) issued, {} answered",
            t["cookie_replies_sent"].as_u64().unwrap_or(0),
            t["mac2_verified"].as_u64().unwrap_or(0),
        );
    }
    Ok(())
}

async fn whitelist(cli: &Cli, cfg: &Config, action: &WhitelistCmd) -> Result<(), String> {
    let ops: Vec<Operation> = match action {
        WhitelistCmd::List => vec![Op::WhitelistList.to_operation()],
        WhitelistCmd::Enable => vec![Op::WhitelistEnable.to_operation()],
        WhitelistCmd::Disable => vec![Op::WhitelistDisable.to_operation()],
        WhitelistCmd::Add { keys, label } => add_ops(keys, label)?,
        WhitelistCmd::Remove { keys } => remove_ops(keys)?,
    };
    let v = submit(cli, cfg, ops).await?;
    match action {
        WhitelistCmd::List => print_list(&result(&v, 0)),
        _ => println!("ok: {}", v["results"]),
    }
    Ok(())
}

fn add_ops(keys: &[String], label: &Option<String>) -> Result<Vec<Operation>, String> {
    if keys.is_empty() {
        return Err("give at least one key".into());
    }
    keys.iter()
        .map(|k| {
            let key = parse_key(k)?;
            Ok(Op::WhitelistAdd {
                key,
                label: label.clone(),
            }
            .to_operation())
        })
        .collect()
}

fn remove_ops(keys: &[String]) -> Result<Vec<Operation>, String> {
    if keys.is_empty() {
        return Err("give at least one key".into());
    }
    keys.iter()
        .map(|k| Ok(Op::WhitelistRemove(parse_key(k)?).to_operation()))
        .collect()
}

/// Connect, resolve the signer, and run the signed transaction.
async fn submit(cli: &Cli, cfg: &Config, ops: Vec<Operation>) -> Result<serde_json::Value, String> {
    let (mut client, server) = connect(cli, cfg).await?;
    let backend = signing_backend(cli, cfg).await?;
    let review = |txn: &Transaction| {
        eprintln!("About to sign {} operation(s):", txn.ops.len());
        for op in &txn.ops {
            eprintln!("  • {}", op.summary);
            for d in &op.detail {
                eprintln!("      {d}");
            }
        }
    };
    let touch = || eprintln!("👆  Touch your YubiKey to sign…");
    flow::sign_and_submit(&mut client, &backend, server, ops, &review, &touch).await
}

/// What the exchange said about a refusal, for an operator to read.
///
/// Refusals on sqex-proto routes are a `Refusal`; `/admin/command` still
/// answers JSON, and an exchange older than sqex 0.21 answered JSON everywhere.
/// Anything that is not a refusal is shown as it came rather than guessed at.
fn said(body: &[u8]) -> String {
    match Refusal::decode(body) {
        Ok(r) => r.to_string(),
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    }
}

// ---- output helpers ----------------------------------------------------------

/// The nth entry of the server's `results` array.
fn result(v: &serde_json::Value, i: usize) -> serde_json::Value {
    v["results"].get(i).cloned().unwrap_or(serde_json::Value::Null)
}

fn print_list(v: &serde_json::Value) {
    let enabled = v["enabled"].as_bool().unwrap_or(false);
    let keys = v["keys"].as_array().cloned().unwrap_or_default();
    println!(
        "whitelist {} ({} keys)",
        if enabled { "enabled" } else { "disabled" },
        keys.len()
    );
    for e in keys {
        let key = e["key"].as_str().unwrap_or("?");
        let mut line = format!("  {key}");
        if let Some(label) = e["label"].as_str() {
            line.push_str(&format!("  [{label}]"));
        }
        if let Some(by) = e["added_by"].as_str() {
            let short: String = by.chars().take(8).collect();
            line.push_str(&format!("  (by {short}…)"));
        }
        println!("{line}");
    }
}

fn print_audit(v: &serde_json::Value) {
    let entries = v["entries"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() {
        println!("(no audit entries)");
    }
    for e in entries {
        let time = e["time"].as_u64().unwrap_or(0);
        let admin = e["admin"].as_str().unwrap_or("?");
        let action = e["action"].as_str().unwrap_or("?");
        let target = e["target"].as_str().map(|t| format!(" {t}")).unwrap_or_default();
        let short: String = admin.chars().take(8).collect();
        println!("[{time}] {short}… {action}{target}");
    }
}

// ---- resolution helpers ------------------------------------------------------

async fn connect(cli: &Cli, cfg: &Config) -> Result<(Client, PubKey), String> {
    // Precedence for both address and key: CLI flag > env var > config file.
    let (socket, server) = endpoint(cli, cfg).await?;
    let client = Client::connect(socket, server.as_bytes()).await?;
    Ok((client, server))
}

/// Build a signing backend, prompting the operator for a passphrase (encrypted
/// software identity) or PIN (YubiKey). A plaintext identity signs with no
/// prompt — the unattended path.
async fn signing_backend(cli: &Cli, cfg: &Config) -> Result<Backend, String> {
    if cli.yubikey {
        let card = Card::spawn();
        let public = PubKey::new(card.pubkey().await?);
        let pin = rpassword::prompt_password("YubiKey user PIN: ").map_err(|e| e.to_string())?;
        card.unlock(pin).await?;
        Ok(Backend::yubikey(card, public))
    } else {
        let path = identity_path(cli, cfg)?;
        if !path.exists() {
            return Err(format!(
                "no identity at {} — run `sqnr keygen` first",
                path.display()
            ));
        }
        if identity::is_encrypted(&path)? {
            let pass = rpassword::prompt_password(format!("Passphrase for {}: ", path.display()))
                .map_err(|e| e.to_string())?;
            Ok(Backend::software(identity::load(&path, Some(&pass))?))
        } else {
            Ok(Backend::software(identity::load(&path, None)?))
        }
    }
}

fn identity_path(cli: &Cli, cfg: &Config) -> Result<PathBuf, String> {
    if let Some(p) = &cli.identity {
        return Ok(p.clone());
    }
    if let Some(p) = &cfg.identity {
        return Ok(p.clone());
    }
    identity::default_identity_path()
}

fn parse_key(s: &str) -> Result<PubKey, String> {
    s.trim().parse().map_err(|e| format!("bad key {s:?}: {e}"))
}

/// An environment variable's value, or None if unset or empty.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}
