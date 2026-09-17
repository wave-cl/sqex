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
use sqex_proto::attest::{
    Attestation, CLAIM_KNOWN_AS, CLAIM_OPERATES, CLAIM_REVIEWED, CLAIM_REVOKES,
    CLAIM_VERIFIED_IN_PERSON, Held, Query as AttestQuery,
};
use sqex_proto::beacon::{Beat, BeatAck, Read, Reply};
use sqex_proto::direct;
use sqex_proto::mailbox::{self, ById, Fetched, Listing, Send as MailSend, SendAck, State, Status};
use sqex_proto::name::{self, ClaimAck};
use sqex_proto::refusal::Refusal;
use sqex_proto::resolve::{
    Endpoint, KIND_DNS, KIND_IPV4, KIND_IPV6, MAX_HOST, Publish as ResolvePublish,
    Resolve as ResolveGet, Resolved, Successor as ResolveSuccessor,
};
use sqex_proto::session::{
    BySession, DatagramFrame, Frames, Open, OpenAck, OpenState, SendFrame, Session,
};
use sqnr::{Backend, Card, Client, config::Config, flow, identity};
use sqnr_core::{Operation, PubKey, Signer, Transaction};

use sqex_proto::handles;

#[derive(Parser)]
#[command(
    name = "sqex",
    version,
    about = "Administer a sqex server with signed transactions"
)]
struct Cli {
    /// A domain that publishes an exchange (SIP-33). Its key is discovered over
    /// DNSSEC, pinned on first contact, and refused if it later changes.
    #[arg(long, global = true)]
    server: Option<String>,
    /// A literal address, host:port, to dial. Requires --server-key.
    #[arg(long, global = true)]
    server_host: Option<String>,
    /// The server's base58 public key. Goes with --server-host; a --server
    /// domain supplies its own.
    #[arg(long, global = true)]
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
    /// Names (SIP-38): claim a name for your account, or resolve one.
    ///
    /// A name binds to your account, so once resolved the account's devices
    /// (SIP-22) and endpoints (SIP-28) follow. Resolve accepts `name@domain` or
    /// a bare `name` against the configured exchange. Whether you may claim a
    /// name depends on the exchange's policy (open, closed, or off).
    Name {
        #[command(subcommand)]
        cmd: NameCmd,
    },
    /// Show this identity's key and the names (SIP-38 handles) it holds, and
    /// verify each still resolves to you.
    ///
    /// Handles are recorded locally beside the identity — a hint, not authority;
    /// the exchange's directory is the source of truth. The primary handle's
    /// domain is the default exchange, so a claimed name replaces a `server=`
    /// line. `sqex name claim` records a handle; `--add`/`--forget` edit them by
    /// hand (for a name claimed elsewhere, or held on another exchange).
    Whoami {
        /// Record a `name@domain` handle for this identity.
        #[arg(long, value_name = "NAME@DOMAIN")]
        add: Option<String>,
        /// Forget a handle: a bare name (every domain), or a full name@domain.
        #[arg(long, value_name = "NAME")]
        forget: Option<String>,
    },
    /// Rendezvous: ask to be introduced to a peer, so the two of you can
    /// connect directly.
    ///
    /// Both sides must ask — an introduction discloses an address, so either
    /// both consent or neither learns anything. Once introduced, both punch
    /// their NATs open and one dials the other on the ports the exchange
    /// observed.
    ///
    /// **Endpoint-independent mapping is what this needs.** Symmetric NAT
    /// allocates a fresh external port per destination, so the port the
    /// exchange saw is not the port the peer will see, and nothing here works
    /// around that. SIP-12 relays instead, and works behind it.
    Meet {
        /// The peer's identity, base58.
        peer: String,
        /// How long to wait for them, in seconds.
        #[arg(short = 'w', long, default_value_t = 30)]
        wait: u16,
        /// Ask, print what both sides were told, and stop there.
        #[arg(long)]
        dry_run: bool,
    },
    /// Attestation: sign a statement about another identity, or read what has
    /// been said about one.
    Attest {
        #[command(subcommand)]
        cmd: AttestCmd,
    },
    /// The exchanges this one federates with (SIP-46): each by key, and by
    /// the domain it is reached at where the operator recorded one. A hint:
    /// reach one by discovering its domain, and refuse it if the key differs.
    Peers,
    /// A device that acts for this account (SIP-20/58): sign a credential
    /// for it, or a revocation, with no exchange in reach -- with a YubiKey
    /// too, which is the point. Give what this prints to an administrator
    /// (`sqex admin device register`), or to the device (`sqex-chat device
    /// claim`).
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Account succession (SIP-44): name who takes your account when your
    /// key is gone -- a successor key you sign for now, or guardians a
    /// quorum of whom may name one later -- and, as the successor, claim it.
    Succession {
        #[command(subcommand)]
        cmd: SuccessionCmd,
    },
    /// Wake-up for a device that cannot hold a stream (SIP-45): leave a
    /// push endpoint with the exchange, which posts the word `wake` to it
    /// when something happens while this device is away. Nothing else goes
    /// to the endpoint.
    Wake {
        #[command(subcommand)]
        cmd: WakeCmd,
    },
    /// Where an account lives (SIP-59): sign the statement that an exchange
    /// is this account's home -- with whatever signs for the account, a
    /// YubiKey included -- and ask an exchange where an account is.
    Home {
        #[command(subcommand)]
        cmd: HomeCmd,
    },
    /// The safety words for you and another identity (SIP-41): six words to
    /// compare with them in person or over a call. Nothing is sent unless
    /// you say the words matched.
    Verify {
        /// Their identity: base58, or name@domain.
        peer: String,
        /// Lodge a SIP-27 statement that you compared the words with them.
        /// Tells the exchange, and anyone who reads it, that the two of you
        /// are acquainted.
        #[arg(long)]
        attest: bool,
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
        /// treated as a first contact — **as if it were a different exchange**.
        /// Anything a client holds under the old key (every conversation on
        /// it) stays filed there and is not shown. For the same exchange
        /// under a new key, use --replace.
        #[arg(long, value_name = "DOMAIN", conflicts_with = "replace")]
        forget: Option<String>,
        /// Move the pin for a domain to the key it publishes now, by hand,
        /// recording the old key as the one it replaced — so the chat store
        /// follows exactly as it does after a signed handover (SIP-40).
        ///
        /// This is the deliberate act SIP-33 asks for when a key changed and
        /// no valid handover explains it: **you** are asserting that the key
        /// DNS names today is the same exchange. Nothing here checks that,
        /// which is why it is a flag you type and not a prompt you answer.
        #[arg(long, value_name = "DOMAIN")]
        replace: Option<String>,
        /// With --replace, when the domain publishes more than one key: which
        /// of them to pin. Must be one the zone publishes.
        #[arg(long, value_name = "KEY", requires = "replace")]
        key: Option<String>,
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
        /// Say that nobody is at the keyboard: connected, and away.
        #[arg(long)]
        away: bool,
    },
    /// Ask when the exchange last saw an identity.
    Read {
        /// The identity to ask about, base58. Defaults to your own.
        key: Option<String>,
    },
}

#[derive(Subcommand)]
enum NameCmd {
    /// Claim a name for your account (open registration only). Connects *as*
    /// your identity — the connection is the proof, so nothing is signed.
    Claim {
        /// The name to claim. Canonicalised to lowercase; `[a-z0-9-]` only.
        name: String,
    },
    /// Give up a name your account holds.
    Release {
        /// The name to release.
        name: String,
    },
    /// Resolve a name to the account behind it.
    Resolve {
        /// `name` or `name@domain`. A bare name is looked up on the configured
        /// exchange.
        name: String,
    },
    /// List the names an account holds.
    Reverse {
        /// The account to ask about, base58. Defaults to your own.
        key: Option<String>,
    },
}

#[derive(Subcommand)]
enum AttestCmd {
    /// Sign a statement about another identity and lodge it.
    ///
    /// **This is not retractable in practice.** A revocation is a signed
    /// statement a reader may never see, and anything once read can be kept and
    /// replayed by anybody. Expiry is the only guarantee, so `--days` is the
    /// setting that matters.
    Say {
        /// What is being claimed: `operates`, `known-as`, or `reviewed`.
        claim: String,
        /// The identity the claim is about, base58.
        subject: String,
        /// The claim's own text — a service name, a nickname, what was
        /// examined.
        #[arg(default_value = "")]
        detail: String,
        /// How long the statement stands, in days.
        #[arg(short = 'd', long, default_value_t = 30)]
        days: u64,
    },
    /// Withdraw a statement you made, by its digest.
    ///
    /// A reader that never sees this keeps trusting the claim until it expires,
    /// which is why it is a courtesy rather than a mechanism.
    Withdraw {
        /// The identity the withdrawn statement was about, base58.
        subject: String,
        /// The statement's digest, base58, as `attest read` prints it.
        digest: String,
    },
    /// Read what has been said about an identity.
    Read {
        /// The identity to ask about, base58. Defaults to your own.
        subject: Option<String>,
        /// Only statements by this issuer. **The ordinary case**: a count of
        /// attestations measures how many keys somebody made, and only issuers
        /// you already trust carry weight.
        #[arg(short = 'i', long)]
        issuer: Option<String>,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Sign a credential naming `key` as a device of this account, for
    /// `--days`. Printed base58; nothing is sent anywhere.
    Link {
        /// The device's identity, base58 -- its own `whoami`.
        key: String,
        #[arg(long, default_value_t = 90)]
        days: u64,
    },
    /// Sign a revocation of `key`. Printed base58; nothing is sent.
    Revoke { key: String },
}

#[derive(Subcommand)]
enum HomeCmd {
    /// Sign a Move naming `home` as this account's exchange from now.
    /// Printed base58; nothing is sent. Give it to `sqex-chat move
    /// --signed`, or present it yourself with `sqex home present`.
    Sign {
        /// The new home's exchange key, base58.
        home: String,
    },
    /// Present a signed Move at the exchange this command connects to,
    /// optionally saying where the account's channels live.
    Present {
        /// The Move, base58, as `home sign` printed it.
        signed: String,
        /// The home's domain, a hint for whoever reads the record.
        #[arg(long, default_value = "")]
        domain: String,
        /// An origin the account's channels live at, as `key` or
        /// `key=domain`; repeat for each. Meaningful at the home only.
        #[arg(long = "origin")]
        origins: Vec<String>,
    },
    /// Where an account lives, as the exchange has it. Yours if omitted.
    Show {
        /// The account, base58 or name@domain.
        account: Option<String>,
    },
}

#[derive(Subcommand)]
enum WakeCmd {
    /// Leave an endpoint: an https:// address your push distributor gave
    /// this device. Replaces any it held. Registered for `--days` (at most
    /// 30); re-run when you connect.
    Register {
        /// The endpoint, an absolute https:// URL.
        url: String,
        /// How long to keep it, in days.
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
    /// Drop this device's endpoint. Nothing further is posted to it.
    Forget,
}

#[derive(Subcommand)]
enum SuccessionCmd {
    /// Sign a will: the key that succeeds this identity, presented by that
    /// key when this one is gone. Printed base58; keep it where the
    /// successor's secret is not.
    Will {
        /// The successor's identity, base58.
        successor: String,
    },
    /// Sign a policy naming guardians, a quorum of whom may name your
    /// successor later, and lodge it at the exchange so they can find it.
    Policy {
        /// How many guardians it takes.
        #[arg(long)]
        threshold: u8,
        /// A guardian's identity, base58; repeat for each.
        #[arg(long = "guardian")]
        guardians: Vec<String>,
        /// Print the policy and lodge nothing.
        #[arg(long)]
        no_lodge: bool,
    },
    /// As a guardian: sign that `successor` succeeds `account`. Printed
    /// base58, for the successor to collect.
    Vouch {
        /// The account being succeeded, base58.
        account: String,
        /// The key that succeeds it, base58.
        successor: String,
    },
    /// As the successor: present a will, or a policy with the vouches that
    /// meet it, and take the account.
    Claim {
        /// The will, base58, as `succession will` printed it.
        #[arg(long)]
        will: Option<String>,
        /// The policy, base58 -- or omit it to fetch the lodged one.
        #[arg(long)]
        policy: Option<String>,
        /// The account, base58, when fetching its lodged policy.
        #[arg(long)]
        account: Option<String>,
        /// A guardian's vouch, base58; repeat for each.
        #[arg(long = "vouch")]
        vouches: Vec<String>,
    },
    /// What the exchange recorded of an account's succession, and the
    /// policy it lodged.
    Show {
        /// The account, base58 or name@domain.
        account: String,
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
    /// Administer names (SIP-38): assign, release, or list them. The
    /// administrator's authority over the name directory.
    Name {
        #[command(subcommand)]
        cmd: AdminNameCmd,
    },
    /// Manage the relay peers (SIP-39): which other exchanges this one will
    /// bridge calls to and from. Takes effect immediately — no restart.
    Peer {
        #[command(subcommand)]
        action: PeerCmd,
    },
    /// SIP-58: register or revoke a device by the account's own signed
    /// credential or revocation (`sqex device link` / `revoke`), carried by
    /// you -- for an account whose key cannot connect.
    Device {
        #[command(subcommand)]
        action: AdminDeviceCmd,
    },
}

#[derive(Subcommand)]
enum AdminDeviceCmd {
    /// Register a device: the credential, base58, as `sqex device link` printed it.
    Register { credential: String },
    /// Revoke a device: the revocation, base58, as `sqex device revoke` printed it.
    Revoke { revocation: String },
}

#[derive(Subcommand)]
enum PeerCmd {
    /// List the relay peers and their provenance.
    List,
    /// Add one or more peer exchange keys (signed as a single batch).
    ///
    /// The key is the exchange's SIP-9 host key, not an address: where a peer
    /// is comes from SIP-33 discovery of the domain a call names, so a peer
    /// that moves is followed rather than reconfigured.
    Add {
        keys: Vec<String>,
        /// Optional human label recorded as provenance for each key.
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove one or more peer exchange keys (signed as a single batch).
    ///
    /// Stops the next call. Bridges already open are not torn down.
    Remove { keys: Vec<String> },
}

#[derive(Subcommand)]
enum AdminNameCmd {
    /// Bind a name to an account, in any registration mode. Reassigns an
    /// existing binding; not subject to the per-account cap.
    Assign {
        /// The name to assign.
        name: String,
        /// The account (base58) to bind it to.
        account: String,
    },
    /// Free a name, whoever holds it.
    Release {
        /// The name to release.
        name: String,
    },
    /// Read the whole directory of bound names.
    List,
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
        Cmd::Name { cmd } => names(&cli, &cfg, cmd).await,
        Cmd::Whoami { add, forget } => whoami(&cli, &cfg, add.as_deref(), forget.as_deref()).await,
        Cmd::Resolve { cmd } => resolution(&cli, &cfg, cmd).await,
        Cmd::Attest { cmd } => attest(&cli, &cfg, cmd).await,
        Cmd::Verify { peer, attest } => verify(&cli, &cfg, peer, *attest).await,
        Cmd::Peers => peers(&cli, &cfg).await,
        Cmd::Succession { cmd } => succession(&cli, &cfg, cmd).await,
        Cmd::Home { cmd } => home(&cli, &cfg, cmd).await,
        Cmd::Device { cmd } => device(&cli, &cfg, cmd).await,
        Cmd::Wake { cmd } => wake(&cli, &cfg, cmd).await,
        Cmd::Meet {
            peer,
            wait,
            dry_run,
        } => meet(&cli, &cfg, peer, *wait, *dry_run).await,
        Cmd::Mail { cmd } => mail(&cli, &cfg, cmd).await,
        Cmd::Session { cmd } => session(&cli, &cfg, cmd).await,
        Cmd::Discover {
            domain,
            forget,
            replace,
            key,
        } => {
            discover(
                domain.as_deref(),
                forget.as_deref(),
                replace.as_deref(),
                key.as_deref(),
            )
            .await
        }
    }
}

// ---- discovery (SIP-33) -----------------------------------------------------

/// Look a domain up, or show and edit what is pinned.
///
/// **Read-only on the pin store unless `--forget` is given.** A diagnostic that
/// pinned a key as a side effect would make a trust decision every time somebody
/// ran it to see what was there; connecting is what pins.
async fn discover(
    domain: Option<&str>,
    forget: Option<&str>,
    replace: Option<&str>,
    key: Option<&str>,
) -> Result<(), String> {
    let path = sqex_discovery::known::path();

    if let Some(d) = forget {
        let mut store = sqex_discovery::Known::load(&path)?;
        if let Some(old) = store.lookup(d) {
            store.remove(d);
            store.save(&path)?;
            println!("forgot {d} ({old}). The next connection to it is a first contact again.");
            println!(
                "Conversations held under that key stay filed under it and will not be shown. \
                 If {d} is the same exchange under a new key, `sqex discover --replace {d}` \
                 instead: the pin moves and the chat store follows it."
            );
        } else {
            println!("nothing was pinned for {d}");
        }
        return Ok(());
    }

    if let Some(d) = replace {
        let mut store = sqex_discovery::Known::load(&path)?;
        let Some(old) = store.lookup(d) else {
            return Err(format!(
                "nothing is pinned for {d}, so there is nothing to replace — connecting will pin it"
            ));
        };
        let published = sqex_discovery::dns::lookup(d)
            .await
            .map_err(|e| e.to_string())?;
        let offered = published.offered();
        let chosen = choose_replacement(&offered, key)?;
        if chosen == old {
            println!("{d} still publishes the pinned key {old}; nothing to replace.");
            return Ok(());
        }
        store.add_moved(d, old, chosen, &format!("replaced by hand {}", today()));
        store.save(&path)?;
        println!("{d}: pin moved from {old} to {chosen}, by hand.");
        println!(
            "The chat store will re-file everything held under {old} on its next open. \
             This was your assertion that the two are one exchange; nothing checked it."
        );
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

    let published = sqex_discovery::dns::lookup(domain)
        .await
        .map_err(|e| e.to_string())?;

    println!(
        "{domain} publishes {} record(s) at _sqex.{domain}, DNSSEC-validated:",
        published.records.len()
    );
    for r in &published.records {
        let host = r.host.as_deref().unwrap_or(domain);
        println!("  {}  at {host}:{}", r.key, r.port);
    }
    // Only the handovers that verified are here; a bad one was dropped in
    // silence, as SIP-40 requires. Shown before the decision so a reader can
    // see what the decision was made from.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for h in &published.handovers {
        let state = if now < h.until {
            format!("{}s left", h.until - now)
        } else {
            "expired".to_string()
        };
        println!("  handover (SIP-40): {} → {}  ({state})", h.from, h.to);
    }

    // What would happen next, said plainly, without doing it.
    let offered = published.offered();
    match sqex_discovery::known::decide(&offered, store.lookup(domain), &published.handovers, now) {
        Some(sqex_discovery::Decision::Pinned(k)) => {
            println!("\npinned already: {k}");
            if offered.len() > 1 {
                println!(
                    "A rotation is in progress. The pin stays put until the key it names \n\
                     stops being published — a key seen beside it earns nothing, and a \n\
                     handover is acted on only once it has gone."
                );
            }
        }
        Some(sqex_discovery::Decision::FirstContact(k)) => {
            println!("\nnothing pinned for {domain} yet.");
            println!("Connecting would pin {k} and refuse any later change.");
        }
        Some(sqex_discovery::Decision::Moved { from, to }) => {
            println!("\npinned: {from}, which has been withdrawn and signed a handover to {to}.");
            println!(
                "Connecting would move the pin to {to} (SIP-40): the zone publishes it and \n\
                 the pinned key vouched for it. Nothing has been changed by this command."
            );
        }
        Some(sqex_discovery::Decision::Changed { pinned, offered }) => {
            println!();
            println!(
                "{}",
                sqex_discovery::known::changed_message(domain, &pinned, &offered)
            );
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
    let peer = resolve_target(cli, cfg, peer).await?;
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
            return Err(format!("open failed ({code}): {}", said(&body)));
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

    eprintln!(
        "session {} established — type to send, Ctrl-D to end",
        ack.session_id
    );
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
                    let ct = session
                        .seal(out_seq, line.as_bytes())
                        .map_err(|e| e.to_string())?;
                    let frame = SendFrame {
                        session_id: id,
                        seq: out_seq,
                        ciphertext: ct,
                    };
                    let (code, body) = client.post("/session/send", frame.encode()).await?;
                    if code != 200 {
                        return Err(format!("send failed ({code}): {}", said(&body)));
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
            let to = resolve_target(cli, cfg, recipient).await?;
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
                .post(
                    "/mailbox/send",
                    MailSend {
                        recipient: to,
                        sealed,
                    }
                    .encode(),
                )
                .await?;
            if code != 200 {
                return Err(format!("send refused ({code}): {}", said(&body)));
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
                    println!(
                        "\n(still on the exchange — `sqex mail delete {id}` to complete collection)"
                    );
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
        return Err(format!("list failed ({code}): {}", said(&body)));
    }
    Listing::decode(&body).map_err(|e| e.to_string())
}

/// Fetch and open one message, returning (sender, plaintext).
async fn fetch_one(
    client: &mut Client,
    signer: &sqnr_core::SoftwareSigner,
    id: u64,
) -> Result<Option<(PubKey, String)>, String> {
    let (code, body) = client
        .post("/mailbox/fetch", ById::fetch(id).encode())
        .await?;
    if code != 200 {
        return Err(format!("fetch failed ({code})"));
    }
    let f = Fetched::decode(&body).map_err(|e| e.to_string())?;
    if !f.found {
        return Ok(None);
    }
    let plain = mailbox::open(&signer.seed(), &f.sealed).map_err(|e| e.to_string())?;
    Ok(Some((
        f.sender,
        String::from_utf8_lossy(&plain).into_owned(),
    )))
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

// ---- rendezvous -------------------------------------------------------------

/// The flow is `sqex_proto::direct`, which is also what a voice client
/// runs: this is the field test for it, so it must be the same code.
async fn meet(cli: &Cli, cfg: &Config, peer: &str, wait: u16, dry_run: bool) -> Result<(), String> {
    let signer = load_software_identity(cli, cfg)?;
    let them = resolve_target(cli, cfg, peer).await?;
    let (addr, server) = endpoint(cli, cfg).await?;
    let me = PubKey::new(signer.public());

    // The request is a long poll and may sit for `wait` seconds by design.
    let Some(intro) =
        direct::introduce(addr, server.as_bytes(), &signer.seed(), them, wait).await?
    else {
        // Deliberately says nothing about whether they asked. That would be a
        // signal about somebody who has not consented.
        println!("no introduction: both sides must ask, and this one has not completed");
        return Ok(());
    };
    println!("{them} was seen at {}", intro.theirs);
    println!(
        "  both sides were told to begin in {}s",
        intro.lead.as_secs()
    );
    if dry_run {
        return Ok(());
    }

    let budget = direct::Budget {
        introduce_wait: wait,
        handshake: std::time::Duration::from_secs(10),
        accept: std::time::Duration::from_secs(15),
    };
    if direct::dials(&me, &them) {
        println!("  dialling {} from {}", intro.theirs, intro.ours);
    } else {
        println!("  listening on {} for {them}", intro.ours);
    }
    let conn = direct::link(intro, &signer.seed(), them, budget).await?;
    println!("  connected directly to {}", conn.remote_address());
    // And the key, so the field test proves the whole of what a call needs
    // and not only the hole.
    let (_session, id) =
        direct::agree(&conn, &signer.seed(), them, direct::dials(&me, &them)).await?;
    println!("  agreed a session key (session {id}); the exchange was not party to it");
    conn.close(0u32.into(), b"done");
    Ok(())
}

// ---- attest -----------------------------------------------------------------

fn claim_code(name: &str) -> Result<u8, String> {
    match name {
        "operates" => Ok(CLAIM_OPERATES),
        "known-as" => Ok(CLAIM_KNOWN_AS),
        "reviewed" => Ok(CLAIM_REVIEWED),
        // SIP-41's claim is made by `sqex verify --attest`, after the
        // words were compared; it is not something to say by name.
        // Deliberately not a list with a gap in it: there is no negative claim
        // to name, and SIP-27 settles that in the conservative direction
        // because an unaccountable assertion that somebody misbehaved has no
        // adjudicator.
        other => Err(format!(
            "unknown claim {other}: want operates, known-as or reviewed"
        )),
    }
}

fn claim_name(code: u8) -> &'static str {
    match code {
        CLAIM_OPERATES => "operates",
        CLAIM_KNOWN_AS => "known as",
        CLAIM_REVIEWED => "reviewed",
        CLAIM_REVOKES => "withdrew a statement",
        CLAIM_VERIFIED_IN_PERSON => "compared safety words with",
        _ => "unreadable",
    }
}

async fn attest(cli: &Cli, cfg: &Config, cmd: &AttestCmd) -> Result<(), String> {
    match cmd {
        AttestCmd::Say {
            claim,
            subject,
            detail,
            days,
        } => {
            let signer = load_software_identity(cli, cfg)?;
            let about = resolve_target(cli, cfg, subject).await?;
            let code = claim_code(claim)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let a = Attestation::sign(
                &signer.seed(),
                &about,
                code,
                detail.as_bytes().to_vec(),
                now,
                now + days * 86_400,
            );
            let (addr, server) = endpoint(cli, cfg).await?;
            // Lodging as ourselves is not required — an attestation carries its
            // own proof — but connecting anonymously would be an odd way to
            // publish something with your name on it.
            let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
            let (code_out, body) = client.post("/attest/lodge", a.encode()).await?;
            if code_out != 200 {
                return Err(format!("lodge refused ({code_out}): {}", said(&body)));
            }
            println!(
                "lodged: {} {} {about}, until {}",
                PubKey::new(signer.public()),
                claim_name(code),
                a.expires_at
            );
            println!("  digest {}", bs58::encode(a.digest()).into_string());
            println!(
                "  this cannot be taken back — a withdrawal is a statement a reader \
                 may never see, and anything once read can be kept"
            );
            Ok(())
        }
        AttestCmd::Withdraw { subject, digest } => {
            let signer = load_software_identity(cli, cfg)?;
            let about = resolve_target(cli, cfg, subject).await?;
            let named = bs58::decode(digest)
                .into_vec()
                .map_err(|e| format!("bad digest: {e}"))?;
            if named.len() != 32 {
                return Err("a digest is 32 bytes".into());
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let a = Attestation::sign(
                &signer.seed(),
                &about,
                CLAIM_REVOKES,
                named,
                now,
                now + 30 * 86_400,
            );
            let (addr, server) = endpoint(cli, cfg).await?;
            let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
            let (code, body) = client.post("/attest/lodge", a.encode()).await?;
            if code != 200 {
                return Err(format!("withdrawal refused ({code}): {}", said(&body)));
            }
            println!("withdrawn at this exchange. Readers who already have it still have it");
            Ok(())
        }
        AttestCmd::Read { subject, issuer } => {
            let about = match subject {
                Some(k) => resolve_target(cli, cfg, k).await?,
                None => own_identity(cli, cfg)?,
            };
            let from = match issuer {
                Some(k) => Some(resolve_target(cli, cfg, k).await?),
                None => None,
            };
            let (addr, server) = endpoint(cli, cfg).await?;
            let mut client = match load_software_identity(cli, cfg) {
                Ok(signer) => Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?,
                Err(_) => Client::connect(addr, server.as_bytes()).await?,
            };
            let (code, body) = client
                .post(
                    "/attest/read",
                    AttestQuery {
                        subject: about,
                        issuer: from,
                    }
                    .encode(),
                )
                .await?;
            if code != 200 {
                return Err(format!("read failed ({code}): {}", said(&body)));
            }
            let held = Held::decode(&body).map_err(|e| e.to_string())?;
            if held.attestations.is_empty() {
                println!("{about}: nothing said, by anyone this exchange holds");
                return Ok(());
            }
            for a in &held.attestations {
                // Each is verified here rather than taken from the exchange:
                // the whole point of a signature is that the holder checks it.
                if a.verify(held.now).is_err() {
                    println!("{}: a statement that does not verify — ignored", a.issuer);
                    continue;
                }
                // **An unreadable claim is not printed as text about a person.**
                // The escape hatch lets anybody encode anything, and rendering
                // it would be carrying it.
                if !a.readable() {
                    println!(
                        "{}: a claim of type {:#x} this build does not know",
                        a.issuer, a.claim
                    );
                    continue;
                }
                println!(
                    "{} says {} {}",
                    a.issuer,
                    claim_name(a.claim),
                    String::from_utf8_lossy(&a.body)
                );
                println!("  digest {}", bs58::encode(a.digest()).into_string());
            }
            println!(
                "  {} statement(s). This is not a score: anyone can make identities \
                 and have them vouch for each other, so only issuers you already \
                 trust mean anything",
                held.attestations.len()
            );
            Ok(())
        }
    }
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

// ---- names (SIP-38) ---------------------------------------------------------

/// Split `name@domain` into its parts. A bare `name` has no domain.
fn split_name(input: &str) -> Result<(String, Option<String>), String> {
    match input.split_once('@') {
        None => Ok((input.to_string(), None)),
        Some((local, domain)) => {
            if domain.contains('@') || domain.is_empty() || local.is_empty() {
                return Err(format!("{input:?} is not a valid name@domain"));
            }
            Ok((local.to_string(), Some(domain.to_string())))
        }
    }
}

/// Discover a domain's exchange over DNSSEC (SIP-33), pinning on first contact.
async fn resolve_domain(domain: &str) -> Result<(SocketAddr, PubKey), String> {
    let found = sqex_discovery::discover(domain)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(notice) = found.notice(domain) {
        eprintln!("{notice}");
    }
    Ok((resolve(&found.address)?, found.key))
}

/// Resolve a peer/target argument to a key. A key passes straight through; a
/// name is resolved through the SIP-38 directory — `name@domain` against that
/// domain's exchange (SIP-33), a bare name against the configured one.
///
/// Resolution is global (name → key), but the command that called this still
/// runs against *its own* exchange, so a store-and-forward command handed
/// `name@other.org` reaches the resolved key only if that exchange is also the
/// one it uses. Same-domain use (`alice@squic.org` with `squic.org` configured)
/// is seamless; cross-exchange is resolve-only.
async fn resolve_target(cli: &Cli, cfg: &Config, input: &str) -> Result<PubKey, String> {
    match name::classify(input).map_err(|e| e.to_string())? {
        name::Target::Key(k) => Ok(k),
        name::Target::Named { name, domain } => {
            let (addr, server) = match &domain {
                Some(d) => resolve_domain(d).await?,
                None => endpoint(cli, cfg).await?,
            };
            let label = match &domain {
                Some(d) => format!("{name}@{d}"),
                None => name.clone(),
            };
            let mut client = connect_preferring_identity(cli, cfg, addr, &server).await?;
            let (code, body) = client
                .post(
                    "/name/resolve",
                    name::Resolve { name: name.clone() }.encode(),
                )
                .await?;
            if code != 200 {
                return Err(format!(
                    "resolving {label}: exchange said {code}: {}",
                    said(&body)
                ));
            }
            let r = name::Resolved::decode(&body).map_err(|e| e.to_string())?;
            if !r.found {
                return Err(format!("no account is named {label}"));
            }
            if r.stale {
                eprintln!(
                    "warning: {label} is on notice — its lease has lapsed and it may be reclaimed"
                );
            }
            Ok(r.account)
        }
    }
}

async fn names(cli: &Cli, cfg: &Config, cmd: &NameCmd) -> Result<(), String> {
    match cmd {
        NameCmd::Claim { name } => {
            // Claiming means connecting *as* the account, so the transport
            // carries the identity (SIP-3) — a YubiKey cannot be a transport key.
            if cli.yubikey {
                return Err("a YubiKey cannot claim a name: it signs, but cannot be a \
                            transport identity. Claim with a software identity."
                    .into());
            }
            let name = name::canonical(name).map_err(|e| e.to_string())?;
            let signer = load_software_identity(cli, cfg)?;
            let (addr, server, domain) = resolve_endpoint(cli, cfg).await?;
            let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
            let (code, body) = client
                .post("/name/claim", name::Claim { name: name.clone() }.encode())
                .await?;
            if code != 200 {
                return Err(format!("claim refused ({code}): {}", said(&body)));
            }
            let ack = ClaimAck::decode(&body).map_err(|e| e.to_string())?;
            match ack.outcome {
                name::CLAIM_GRANTED => {
                    println!("{name} is yours ({})", PubKey::new(signer.public()));
                    // Record it as a handle for this identity, so it becomes the
                    // default exchange and shows in `sqex whoami`.
                    match &domain {
                        Some(d) => match identity_path(cli, cfg)
                            .and_then(|id| handles::add(&id, &format!("{name}@{d}")))
                        {
                            Ok((h, true)) => println!("  recorded {h} as one of your handles"),
                            Ok((_, false)) => {}
                            Err(e) => eprintln!("  (could not record handle: {e})"),
                        },
                        None => println!(
                            "  (reached by host+key, so no domain to record; add it with \
                             `sqex whoami --add {name}@<domain>`)"
                        ),
                    }
                }
                name::CLAIM_TAKEN => println!("{name} is held by another account"),
                name::CLAIM_AT_CAPACITY => {
                    println!("refused: you already hold the maximum number of names")
                }
                name::CLAIM_CLOSED => println!(
                    "this exchange does not allow self-claimed names \
                     (registration is closed or off)"
                ),
                name::CLAIM_RATE_LIMITED => {
                    println!("refused: too many claims this hour — try again later")
                }
                name::CLAIM_FULL => {
                    println!("refused: this exchange's name directory is full")
                }
                other => println!("unexpected claim outcome: {other}"),
            }
            Ok(())
        }
        NameCmd::Release { name } => {
            if cli.yubikey {
                return Err("a YubiKey cannot be a transport identity".into());
            }
            let name = name::canonical(name).map_err(|e| e.to_string())?;
            let signer = load_software_identity(cli, cfg)?;
            let (addr, server, domain) = resolve_endpoint(cli, cfg).await?;
            let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
            let (code, body) = client
                .post(
                    "/name/release",
                    name::Release { name: name.clone() }.encode(),
                )
                .await?;
            if code != 200 {
                return Err(format!("release refused ({code}): {}", said(&body)));
            }
            println!("released {name} (a no-op if your account did not hold it)");
            // Drop the matching local handle too, so `whoami` stays honest.
            if let Some(d) = &domain
                && let Ok(id) = identity_path(cli, cfg)
                && handles::remove(&id, &format!("{name}@{d}")).unwrap_or(false)
            {
                println!("  and forgot the {name}@{d} handle");
            }
            Ok(())
        }
        NameCmd::Resolve { name } => {
            let (local, domain) = split_name(name)?;
            let local = name::canonical(&local).map_err(|e| e.to_string())?;
            // A `name@domain` selects that domain's exchange (SIP-33); a bare
            // name uses the configured one.
            let (addr, server) = match &domain {
                Some(d) => resolve_domain(d).await?,
                None => endpoint(cli, cfg).await?,
            };
            let mut client = connect_preferring_identity(cli, cfg, addr, &server).await?;
            let (code, body) = client
                .post(
                    "/name/resolve",
                    name::Resolve {
                        name: local.clone(),
                    }
                    .encode(),
                )
                .await?;
            if code != 200 {
                return Err(format!("resolve failed ({code}): {}", said(&body)));
            }
            let r = name::Resolved::decode(&body).map_err(|e| e.to_string())?;
            if !r.found {
                println!("{local}: no such name");
                return Ok(());
            }
            println!("{local} → {}", r.account);
            // The provenance, so a consumer can judge the answer. Ages against
            // the exchange's clock, per SIP-4.
            if r.stale {
                println!(
                    "  STALE: the lease lapsed; this name may be reclaimed by another account"
                );
            } else if r.expires_at == 0 {
                println!("  assigned by an administrator (no lease)");
            } else {
                println!(
                    "  lease renews on activity; expires in {}s if idle",
                    r.expires_at.saturating_sub(r.now)
                );
            }
            println!(
                "  Resolve the account's devices with `sqex` (SIP-22) and its address with \
                 `sqex resolve get {}`.",
                r.account
            );
            Ok(())
        }
        NameCmd::Reverse { key } => {
            let target = match key {
                Some(k) => resolve_target(cli, cfg, k).await?,
                None => own_identity(cli, cfg)?,
            };
            let (addr, server) = endpoint(cli, cfg).await?;
            let mut client = connect_preferring_identity(cli, cfg, addr, &server).await?;
            let (code, body) = client
                .post("/name/reverse", name::Reverse { account: target }.encode())
                .await?;
            if code != 200 {
                return Err(format!("reverse failed ({code}): {}", said(&body)));
            }
            let n = name::Names::decode(&body).map_err(|e| e.to_string())?;
            if n.names.is_empty() {
                println!("{target}: holds no names");
                return Ok(());
            }
            for name in n.names {
                println!("{name}");
            }
            Ok(())
        }
    }
}

// ---- whoami (SIP-38 handles) ------------------------------------------------

async fn whoami(
    cli: &Cli,
    cfg: &Config,
    add: Option<&str>,
    forget: Option<&str>,
) -> Result<(), String> {
    let id = identity_path(cli, cfg)?;
    if let Some(h) = add {
        let (h, added) = handles::add(&id, h)?;
        println!(
            "{}",
            if added {
                format!("added {h}")
            } else {
                format!("{h} was already recorded")
            }
        );
    }
    if let Some(h) = forget {
        println!(
            "{}",
            if handles::remove(&id, h)? {
                format!("forgot {h}")
            } else {
                format!("no handle matched {h:?}")
            }
        );
    }

    // Reads the public-key line only — no passphrase, even for an encrypted key.
    let me = own_identity(cli, cfg)?;
    println!("identity {me}");
    let hs = handles::load(&id);
    if hs.is_empty() {
        println!("  no handles recorded — claim one, or `sqex whoami --add name@domain`");
        return Ok(());
    }
    // The checks connect as us when that costs no prompt — a plaintext
    // identity — because a whitelisted exchange (SIP-8) drops an anonymous
    // caller at the door, and this command promises not to ask for a
    // passphrase. An encrypted identity is checked anonymously, and a
    // whitelisted exchange then reads as unreachable; the line says so.
    let signer = quiet_signer(cli, cfg);
    for (i, h) in hs.iter().enumerate() {
        let role = if i == 0 { "primary" } else { "alias  " };
        println!(
            "  {role}  {h}  {}",
            verify_handle(h, &me, signer.as_ref()).await
        );
    }
    let encrypted = identity_path(cli, cfg)
        .ok()
        .filter(|p| p.exists())
        .and_then(|p| identity::is_encrypted(&p).ok())
        .unwrap_or(false);
    if signer.is_none() && encrypted {
        eprintln!(
            "(checked anonymously: this identity is encrypted and whoami does not prompt. \
             An exchange with its whitelist on refuses anonymous callers, so a handle there \
             shows as unreachable even when it is yours — `sqex name resolve <handle>` asks \
             as you.)"
        );
    }
    Ok(())
}

/// Best-effort check that a `name@domain` handle still resolves to `me` on its
/// domain's exchange. Returns a short status marker and never fails — a handle
/// is a hint, and the exchange is the authority (SIP-38).
async fn verify_handle(
    handle: &str,
    me: &PubKey,
    signer: Option<&sqnr_core::SoftwareSigner>,
) -> String {
    let Some((local, domain)) = handle.split_once('@') else {
        return "(malformed handle)".into();
    };
    let name = match name::canonical(local) {
        Ok(n) => n,
        Err(e) => return format!("(bad name: {e})"),
    };
    let (addr, server) = match resolve_domain(domain).await {
        Ok(v) => v,
        Err(e) => return format!("(unreachable: {e})"),
    };
    let connected = match signer {
        Some(s) => Client::connect_as(addr, server.as_bytes(), &s.seed()).await,
        None => Client::connect(addr, server.as_bytes()).await,
    };
    let mut client = match connected {
        Ok(c) => c,
        Err(e) => return format!("(unreachable: {e})"),
    };
    let body = match client
        .post("/name/resolve", name::Resolve { name }.encode())
        .await
    {
        Ok((200, body)) => body,
        Ok((code, body)) => return format!("(exchange said {code}: {})", said(&body)),
        Err(e) => return format!("(unreachable: {e})"),
    };
    match name::Resolved::decode(&body) {
        Ok(r) if !r.found => "✗ no longer registered".into(),
        Ok(r) if &r.account != me => format!("✗ resolves to {} — NOT this identity", r.account),
        Ok(r) if r.stale => "✓ STALE (lease lapsed, may be reclaimed)".into(),
        Ok(_) => "✓".into(),
        Err(e) => format!("(bad reply: {e})"),
    }
}

async fn resolution(cli: &Cli, cfg: &Config, cmd: &ResolveCmd) -> Result<(), String> {
    match cmd {
        ResolveCmd::Publish {
            endpoint: addrs,
            capability,
            ttl,
        } => {
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
                Some(k) => resolve_target(cli, cfg, k).await?,
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
            let to = resolve_target(cli, cfg, successor).await?;
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
        BeaconCmd::Beat {
            interval,
            withhold,
            away,
        } => {
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
                away: *away,
            };
            let (code, body) = client.post("/beacon/beat", beat.encode()).await?;
            if code != 200 {
                return Err(format!("beat refused ({code}): {}", said(&body)));
            }
            let ack = BeatAck::decode(&body).map_err(|e| e.to_string())?;
            println!(
                "beat recorded for {} at {} (interval {}s{}{})",
                PubKey::new(signer.public()),
                ack.now,
                interval,
                if *withhold { ", withheld" } else { "" },
                if *away { ", away" } else { "" }
            );
            Ok(())
        }
        BeaconCmd::Read { key } => {
            // Reading is open, but connecting as ourselves is what lets the
            // exchange disclose our own withheld record.
            let target = match key {
                Some(k) => resolve_target(cli, cfg, k).await?,
                None => own_identity(cli, cfg)?,
            };
            let (addr, server) = endpoint(cli, cfg).await?;
            let mut client = match load_software_identity(cli, cfg) {
                Ok(signer) => Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?,
                // No usable identity: ask anonymously. Withheld records stay hidden.
                Err(_) => Client::connect(addr, server.as_bytes()).await?,
            };

            let (code, body) = client
                .post("/beacon/read", Read { key: target }.encode())
                .await?;
            if code != 200 {
                return Err(format!("read failed ({code}): {}", said(&body)));
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
                format!(
                    " ({} intervals)",
                    r.staleness() / u64::from(r.interval_secs)
                )
            } else {
                String::new()
            };
            println!(
                "{target}: last seen {}s ago{missed}, declared interval {}s{}",
                r.staleness(),
                r.interval_secs,
                if r.away { ", away" } else { "" }
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

// ---- verify (SIP-41) ----------------------------------------------------

/// The six words for us and `peer`, and the code a camera reads; with
/// `--attest`, a SIP-27 statement that the words were compared.
async fn verify(cli: &Cli, cfg: &Config, peer: &str, attest: bool) -> Result<(), String> {
    let me = own_identity(cli, cfg)?;
    let them = resolve_target(cli, cfg, peer).await?;
    if me == them {
        return Err("the words are for two people".into());
    }
    let words = sqex_proto::safety::words_for(&me, &them);
    println!("you   {me}");
    println!("them  {them}");
    println!();
    println!("    {}", words.join("  "));
    println!();
    println!("  code {}", sqex_proto::safety::code(&me, &them));
    println!(
        "Read these to each other, or scan the code. They match on both sides or \
         they do not; nothing here can tell you which."
    );
    if !attest {
        return Ok(());
    }
    let signer = load_software_identity(cli, cfg)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let a = Attestation::sign(
        &signer.seed(),
        &them,
        CLAIM_VERIFIED_IN_PERSON,
        Vec::new(),
        now,
        now + 365 * 86_400,
    );
    let (addr, server) = endpoint(cli, cfg).await?;
    let mut client = Client::connect_as(addr, server.as_bytes(), &signer.seed()).await?;
    let (code_out, body) = client.post("/attest/lodge", a.encode()).await?;
    if code_out != 200 {
        return Err(format!("lodge refused ({code_out}): {}", said(&body)));
    }
    println!("lodged: you compared safety words with {them}");
    println!("  digest {}", bs58::encode(a.digest()).into_string());
    Ok(())
}

/// This caller's own Ed25519 identity, without needing to decrypt it.
fn own_identity(cli: &Cli, cfg: &Config) -> Result<PubKey, String> {
    identity::read_public(&identity_path(cli, cfg)?)
}

/// Connect **as** our identity where we can, anonymously where we cannot.
///
/// The SIP-38 name routes are public — anyone authenticated may resolve — and
/// used to be asked anonymously, which worked until an exchange turned its
/// transport whitelist on (SIP-8): an anonymous key is not on any list, so
/// the handshake is dropped in silence and `c@squic.org` reads as
/// "unreachable" to the very identity that holds it. Asking as ourselves costs
/// nothing when the identity is plaintext, and a passphrase when it is not —
/// the same passphrase every signed command already asks for.
async fn connect_preferring_identity(
    cli: &Cli,
    cfg: &Config,
    addr: SocketAddr,
    server: &PubKey,
) -> Result<Client, String> {
    match load_software_identity(cli, cfg) {
        Ok(signer) => Client::connect_as(addr, server.as_bytes(), &signer.seed())
            .await
            .map_err(|e| e.to_string()),
        Err(_) => Client::connect(addr, server.as_bytes())
            .await
            .map_err(|e| e.to_string()),
    }
}

/// Our identity if it can be used without asking anything: present and
/// unencrypted. For the read-only paths that promise not to prompt.
fn quiet_signer(cli: &Cli, cfg: &Config) -> Option<sqnr_core::SoftwareSigner> {
    let path = identity_path(cli, cfg).ok()?;
    if !path.exists() || identity::is_encrypted(&path).ok()? {
        return None;
    }
    identity::load(&path, None).ok()
}

/// The layers a caller can speak through, most specific first. Resolution is
/// shared with the other clients in `sqex_discovery::target`, because three
/// copies of it is what produced two bugs in a day.
fn layers(cli: &Cli, cfg: &Config) -> Vec<sqex_discovery::Layer> {
    let mut layers = vec![
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
    ];
    // Lowest priority: the active identity's primary handle domain (SIP-38), so
    // a claimed name *is* the default exchange and no `server =` pointer is
    // needed. Reading the sidecar is a cleartext file read — no passphrase.
    if let Ok(id) = identity_path(cli, cfg)
        && let Some(domain) = handles::primary_domain(&id)
    {
        layers.push(sqex_discovery::Layer {
            server: Some(domain),
            ..Default::default()
        });
    }
    layers
}

/// Resolve the server address and pinned key without connecting.
async fn endpoint(cli: &Cli, cfg: &Config) -> Result<(SocketAddr, PubKey), String> {
    let (addr, key, _domain) = resolve_endpoint(cli, cfg).await?;
    Ok((addr, key))
}

/// Like [`endpoint`], but also returns the domain when the exchange was reached
/// by SIP-33 discovery (`None` for a literal host+key). The domain is what a
/// SIP-38 handle needs — the caller can record `name@domain` only when it is
/// known.
async fn resolve_endpoint(
    cli: &Cli,
    cfg: &Config,
) -> Result<(SocketAddr, PubKey, Option<String>), String> {
    match sqex_discovery::target::resolve(&layers(cli, cfg)).map_err(|e| e.to_string())? {
        sqex_discovery::Target::Direct { address, key } => Ok((resolve(&address)?, key, None)),
        sqex_discovery::Target::Discover(domain) => {
            let found = sqex_discovery::discover(&domain)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(notice) = found.notice(&domain) {
                eprintln!("{notice}");
            }
            Ok((resolve(&found.address)?, found.key, Some(domain)))
        }
    }
}

/// `host:port`, `host`, or an IP literal.
///
/// A bare host is not an error — an exchange has a well-known port — and a name
/// is not one either: this used to parse straight to a `SocketAddr`, which
/// accepts only an IP, so `sqex --server ex.example.com` failed with a message
/// about the address being bad when it was perfectly good.
/// Turn a `host:port` into something dialable. One copy of this lives in
/// `sqex-discovery`, which owns addresses and the default port.
fn resolve(address: &str) -> Result<SocketAddr, String> {
    sqex_discovery::resolve_addr(address)
}

async fn admin(cli: &Cli, cfg: &Config, cmd: &AdminCmd) -> Result<(), String> {
    match cmd {
        AdminCmd::Whitelist { action } => whitelist(cli, cfg, action).await,
        AdminCmd::Peer { action } => peer(cli, cfg, action).await,
        AdminCmd::Device { action } => {
            let op = match action {
                AdminDeviceCmd::Register { credential } => {
                    let raw = bs58::decode(credential.trim())
                        .into_vec()
                        .map_err(|e| format!("not base58: {e}"))?;
                    Op::DeviceRegister(
                        sqex_proto::credential::Credential::decode(&raw)
                            .map_err(|e| e.to_string())?,
                    )
                }
                AdminDeviceCmd::Revoke { revocation } => {
                    let raw = bs58::decode(revocation.trim())
                        .into_vec()
                        .map_err(|e| format!("not base58: {e}"))?;
                    Op::DeviceRevoke(
                        sqex_proto::credential::Revocation::decode(&raw)
                            .map_err(|e| e.to_string())?,
                    )
                }
            };
            let v = submit(cli, cfg, vec![op.to_operation()]).await?;
            println!("{}", result(&v, 0));
            Ok(())
        }
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
        AdminCmd::Name { cmd } => admin_name(cli, cfg, cmd).await,
    }
}

async fn admin_name(cli: &Cli, cfg: &Config, cmd: &AdminNameCmd) -> Result<(), String> {
    let op = match cmd {
        AdminNameCmd::Assign { name, account } => {
            // Canonicalise before signing, so the summary the operator sees and
            // signs is the name that will be stored.
            let name = name::canonical(name).map_err(|e| e.to_string())?;
            Op::NameAssign {
                name,
                account: parse_key(account)?,
            }
        }
        AdminNameCmd::Release { name } => {
            Op::NameRelease(name::canonical(name).map_err(|e| e.to_string())?)
        }
        AdminNameCmd::List => Op::NameList,
    };
    let v = submit(cli, cfg, vec![op.to_operation()]).await?;
    match cmd {
        AdminNameCmd::List => {
            let r = result(&v, 0);
            let names = r["names"].as_array().cloned().unwrap_or_default();
            if names.is_empty() {
                println!("no names bound");
            }
            for n in names {
                let expires = n["expires_at"].as_u64().unwrap_or(0);
                println!(
                    "{}\t{}\t{}{}",
                    n["name"].as_str().unwrap_or("?"),
                    n["account"].as_str().unwrap_or("?"),
                    if n["admin_set"].as_bool().unwrap_or(false) {
                        "assigned"
                    } else {
                        "claimed"
                    },
                    if expires == 0 {
                        String::new()
                    } else {
                        format!(" (expires_at {expires})")
                    },
                );
            }
        }
        _ => println!("ok: {}", v["results"]),
    }
    Ok(())
}

// ---- succession (SIP-44) -------------------------------------------------

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

fn from_b58(what: &str, text: &str) -> Result<Vec<u8>, String> {
    bs58::decode(text.trim())
        .into_vec()
        .map_err(|e| format!("{what} is not base58: {e}"))
}

async fn succession(cli: &Cli, cfg: &Config, cmd: &SuccessionCmd) -> Result<(), String> {
    use sqex_proto::succession::{Claim, Policy, Proof, Succeeded, Vouch, Will, ask};
    match cmd {
        SuccessionCmd::Will { successor } => {
            let signer = load_software_identity(cli, cfg)?;
            let successor: PubKey = successor.parse().map_err(|e| format!("bad key: {e}"))?;
            let me = PubKey::new(signer.public());
            if successor == me {
                return Err("an account cannot succeed itself".into());
            }
            let will = Will::sign(&signer.seed(), &successor, now_secs());
            println!("{}", b58(&will.encode()));
            eprintln!();
            eprintln!("A will: {successor} may take this account by presenting it.");
            eprintln!("Keep it apart from that key's secret; together they are the account.");
            Ok(())
        }
        SuccessionCmd::Policy {
            threshold,
            guardians,
            no_lodge,
        } => {
            let signer = load_software_identity(cli, cfg)?;
            let guardians = guardians
                .iter()
                .map(|g| {
                    g.parse::<PubKey>()
                        .map_err(|e| format!("bad guardian {g}: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let policy = Policy::sign(&signer.seed(), *threshold, &guardians, now_secs())
                .map_err(|e| e.to_string())?;
            println!("{}", b58(&policy.encode()));
            if *no_lodge {
                return Ok(());
            }
            let (mut client, _server) = connect(cli, cfg).await?;
            let (code, body) = client.post("/account/lodge", policy.encode()).await?;
            if code != 200 {
                return Err(format!("lodge failed ({code}): {}", said(&body)));
            }
            eprintln!(
                "Lodged: any {} of {} guardians may name your successor. Tell them.",
                threshold,
                guardians.len()
            );
            Ok(())
        }
        SuccessionCmd::Vouch { account, successor } => {
            let signer = load_software_identity(cli, cfg)?;
            let account: PubKey = account.parse().map_err(|e| format!("bad account: {e}"))?;
            let successor: PubKey = successor.parse().map_err(|e| format!("bad key: {e}"))?;
            let vouch = Vouch::sign(&signer.seed(), &account, &successor, now_secs());
            println!("{}", b58(&vouch.encode()));
            eprintln!();
            eprintln!("Your word that {successor} succeeds {account}. Give it to them.");
            Ok(())
        }
        SuccessionCmd::Claim {
            will,
            policy,
            account,
            vouches,
        } => {
            let (mut client, _server) = connect(cli, cfg).await?;
            let proof = if let Some(will) = will {
                Proof::Will(Will::decode(&from_b58("the will", will)?).map_err(|e| e.to_string())?)
            } else {
                let policy_bytes = match (policy, account) {
                    (Some(p), _) => from_b58("the policy", p)?,
                    (None, Some(account)) => {
                        let account: PubKey =
                            account.parse().map_err(|e| format!("bad account: {e}"))?;
                        let (code, body) = client.post("/account/lodged", ask(&account)).await?;
                        if code != 200 {
                            return Err(format!(
                                "no policy lodged for {account} ({code}): {}",
                                said(&body)
                            ));
                        }
                        body
                    }
                    (None, None) => {
                        return Err(
                            "a claim needs --will, or --policy / --account with --vouch".into()
                        );
                    }
                };
                let policy = Policy::decode(&policy_bytes).map_err(|e| e.to_string())?;
                let vouches = vouches
                    .iter()
                    .map(|v| Vouch::decode(&from_b58("a vouch", v)?).map_err(|e| e.to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
                Proof::Guardians { policy, vouches }
            };
            let me = own_identity(cli, cfg)?;
            if proof.successor() != Some(me) {
                return Err("this proof names somebody else as successor".into());
            }
            if !proof.proves(&me) {
                return Err(
                    "this proof does not prove it: a signature is wrong, or the quorum is short"
                        .into(),
                );
            }
            let (code, body) = client
                .post(
                    "/account/succeed",
                    Claim {
                        proof: proof.clone(),
                    }
                    .encode(),
                )
                .await?;
            if code != 200 {
                return Err(format!(
                    "the exchange refused the claim ({code}): {}",
                    said(&body)
                ));
            }
            println!(
                "{} is yours: its names, its conversations, its place in each. Its old devices \
                 are nobody's now; link yours.",
                proof.account()
            );
            Ok(())
        }
        SuccessionCmd::Show { account } => {
            let account = resolve_target(cli, cfg, account).await?;
            let (mut client, _server) = connect(cli, cfg).await?;
            let (code, body) = client.post("/account/succession", ask(&account)).await?;
            match code {
                200 => {
                    let s = Succeeded::decode(&body).map_err(|e| e.to_string())?;
                    println!("{account}");
                    println!("  succeeded by {}", s.successor);
                    println!("  at {}", s.now);
                    match &s.proof {
                        Proof::Will(w) => println!(
                            "  by its will, signed {}: {}",
                            w.issued,
                            if w.verify() {
                                "verifies"
                            } else {
                                "DOES NOT VERIFY"
                            }
                        ),
                        Proof::Guardians { policy, vouches } => println!(
                            "  by {} of {} guardians ({} vouched): {}",
                            policy.threshold,
                            policy.guardians.len(),
                            vouches.len(),
                            if s.proof.proves(&s.successor) {
                                "verifies"
                            } else {
                                "DOES NOT VERIFY"
                            }
                        ),
                    }
                }
                404 => println!("{account}: not succeeded"),
                _ => return Err(format!("show failed ({code}): {}", said(&body))),
            }
            let (code, body) = client.post("/account/lodged", ask(&account)).await?;
            if code == 200
                && let Ok(p) = Policy::decode(&body)
            {
                println!(
                    "  policy lodged: any {} of {} guardians",
                    p.threshold,
                    p.guardians.len()
                );
                for g in &p.guardians {
                    println!("    {g}");
                }
            }
            Ok(())
        }
    }
}

/// SIP-58: a credential or a revocation, signed here and sent nowhere --
/// with whatever signs for this account, a YubiKey included.
async fn device(cli: &Cli, cfg: &Config, cmd: &DeviceCmd) -> Result<(), String> {
    use sqex_proto::credential::{Credential, Revocation, SCOPE_CHAT};
    let backend = signing_backend(cli, cfg).await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match cmd {
        DeviceCmd::Link { key, days } => {
            let device: PubKey = key.parse().map_err(|e| format!("bad key: {e}"))?;
            let account = backend.public();
            let (issued, not_after) = (now.saturating_sub(60), now + days * 86_400);
            if backend.is_yubikey() {
                eprintln!("touch the YubiKey to sign the credential");
            }
            let signature = backend
                .sign(&Credential::to_sign(
                    &account, &device, SCOPE_CHAT, issued, not_after,
                ))
                .await?;
            let credential = Credential::from_signature(
                account, device, SCOPE_CHAT, issued, not_after, signature,
            );
            credential
                .verify(&account, SCOPE_CHAT, now)
                .map_err(|e| format!("the credential does not verify: {e:?}"))?;
            println!("{}", bs58::encode(credential.encode()).into_string());
            eprintln!(
                "a credential for {device} to act as {} for {days} day(s). Give it to an \
                 administrator (`sqex admin device register`) or to the device itself \
                 (`sqex-chat device claim`).",
                credential.account
            );
            Ok(())
        }
        DeviceCmd::Revoke { key } => {
            let device: PubKey = key.parse().map_err(|e| format!("bad key: {e}"))?;
            let account = backend.public();
            if backend.is_yubikey() {
                eprintln!("touch the YubiKey to sign the revocation");
            }
            let signature = backend
                .sign(&Revocation::to_sign(&account, &device, now))
                .await?;
            let revocation = Revocation::from_signature(account, device, now, signature);
            println!("{}", bs58::encode(revocation.encode()).into_string());
            eprintln!(
                "a revocation of {device} as a device of {}. Give it to an administrator \
                 (`sqex admin device revoke`), or to any device of the account.",
                revocation.account
            );
            Ok(())
        }
    }
}

/// SIP-59: an account's home -- signed here with whatever signs for the
/// account, presented anywhere, asked of any exchange.
async fn home(cli: &Cli, cfg: &Config, cmd: &HomeCmd) -> Result<(), String> {
    use sqex_proto::home::{Homed, Move, Moved, Moving};
    match cmd {
        HomeCmd::Sign { home } => {
            let home: PubKey = home.parse().map_err(|e| format!("bad key: {e}"))?;
            let backend = signing_backend(cli, cfg).await?;
            let account = backend.public();
            let issued = now_secs();
            if backend.is_yubikey() {
                eprintln!("touch the YubiKey to sign the move");
            }
            let signature = backend
                .sign(&Move::to_sign(&account, &home, issued))
                .await?;
            let mv = Move::from_signature(account, home, issued, signature);
            if !mv.verify() {
                return Err("the move does not verify".into());
            }
            println!("{}", b58(&mv.encode()));
            eprintln!("a move: {account} lives at {home} from {issued}. Present it with");
            eprintln!("`sqex-chat move <domain> --signed <this>` or `sqex home present <this>`.");
            Ok(())
        }
        HomeCmd::Present {
            signed,
            domain,
            origins,
        } => {
            let raw = bs58::decode(signed.trim())
                .into_vec()
                .map_err(|e| format!("bad move: {e}"))?;
            let mv = Move::decode(&raw).map_err(|e| e.to_string())?;
            if !mv.verify() {
                return Err("the move does not verify".into());
            }
            let mut hints = Vec::new();
            for o in origins {
                let (key, dom) = o.split_once('=').unwrap_or((o.as_str(), ""));
                let key: PubKey = key.parse().map_err(|e| format!("bad origin {o}: {e}"))?;
                hints.push((key, dom.to_string()));
            }
            let (mut client, server) = connect(cli, cfg).await?;
            let (code, body) = client
                .post(
                    "/account/move",
                    Moving {
                        mv,
                        domain: domain.clone(),
                        origins: hints,
                    }
                    .encode(),
                )
                .await?;
            if code != 200 {
                return Err(format!("present failed ({code}): {}", said(&body)));
            }
            let moved = Moved::decode(&body).map_err(|e| e.to_string())?;
            let role = if mv.home == server {
                "the home"
            } else {
                "a former home or origin"
            };
            println!("recorded at {server} ({role})");
            if !moved.peered && mv.home != server {
                println!(
                    "note: this exchange does not list {} as a replication peer, so the \
                     home's pulls from it will be refused until its operator adds it",
                    mv.home
                );
            }
            Ok(())
        }
        HomeCmd::Show { account } => {
            let account = match account {
                Some(a) => resolve_target(cli, cfg, a).await?,
                None => PubKey::new(load_software_identity(cli, cfg)?.public()),
            };
            let (mut client, server) = connect(cli, cfg).await?;
            let (code, body) = client
                .post("/account/home", account.as_bytes().to_vec())
                .await?;
            match code {
                200 => {
                    let h = Homed::decode(&body).map_err(|e| e.to_string())?;
                    let at = if !h.domain.is_empty() {
                        format!("{} ({})", h.domain, h.home)
                    } else if h.home == server {
                        format!("here ({})", h.home)
                    } else {
                        h.home.to_string()
                    };
                    if h.since == 0 {
                        println!("{account} lives at {at}, as far as this exchange knows");
                    } else {
                        println!("{account} lives at {at} since {}", h.since);
                    }
                }
                404 => println!("{account}: not known here"),
                _ => return Err(format!("show failed ({code}): {}", said(&body))),
            }
            Ok(())
        }
    }
}

/// SIP-45: an endpoint the exchange posts `wake` to while this device is
/// away. The exchange never serves it back, so there is nothing to show.
async fn wake(cli: &Cli, cfg: &Config, cmd: &WakeCmd) -> Result<(), String> {
    use sqex_proto::wake::{MAX_TTL, Register, acceptable, forget};
    let (mut client, _server) = connect(cli, cfg).await?;
    match cmd {
        WakeCmd::Register { url, days } => {
            if !acceptable(url, false) {
                return Err(
                    "the endpoint must be an absolute https:// URL of at most 512 bytes".into(),
                );
            }
            let ttl = u32::try_from(u64::from(*days) * 86_400)
                .ok()
                .filter(|t| *t <= MAX_TTL)
                .ok_or("at most 30 days")?;
            let req = Register {
                ttl,
                endpoint: url.clone(),
            };
            let (code, body) = client.post("/wake/register", req.encode()).await?;
            match code {
                200 => {
                    println!("registered for {days} day(s)");
                    Ok(())
                }
                404 => Err("this exchange does not wake devices (SIP-45)".into()),
                _ => Err(format!("register failed ({code}): {}", said(&body))),
            }
        }
        WakeCmd::Forget => {
            let (code, body) = client.post("/wake/forget", forget()).await?;
            match code {
                200 => {
                    println!("forgotten");
                    Ok(())
                }
                404 => Err("this exchange does not wake devices (SIP-45)".into()),
                _ => Err(format!("forget failed ({code}): {}", said(&body))),
            }
        }
    }
}

/// SIP-46: what this exchange federates with.
async fn peers(cli: &Cli, cfg: &Config) -> Result<(), String> {
    let (mut client, _server) = connect(cli, cfg).await?;
    let (code, body) = client.get("/exchange/peers").await?;
    if code == 404 {
        return Err("this exchange has no peer directory (before sqex 0.62.0)".into());
    }
    if code != 200 {
        return Err(format!("peers failed ({code}): {}", said(&body)));
    }
    let listed = sqex_proto::exchange::Peers::decode(&body).map_err(|e| e.to_string())?;
    if listed.peers.is_empty() {
        println!("federates with nobody");
        return Ok(());
    }
    for p in &listed.peers {
        if p.domain.is_empty() {
            println!("{}  (no domain recorded)", p.key);
        } else {
            println!("{}  {}", p.key, p.domain);
        }
    }
    println!(
        "A hint, not an introduction: discover a domain (sqex discover) and refuse it if \
         the key differs."
    );
    Ok(())
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

async fn peer(cli: &Cli, cfg: &Config, action: &PeerCmd) -> Result<(), String> {
    let ops: Vec<Operation> = match action {
        PeerCmd::List => vec![Op::PeerList.to_operation()],
        PeerCmd::Add { keys, label } => keyed_ops(keys, |key| Op::PeerAdd {
            key,
            label: label.clone(),
        })?,
        PeerCmd::Remove { keys } => keyed_ops(keys, Op::PeerRemove)?,
    };
    let v = submit(cli, cfg, ops).await?;
    match action {
        PeerCmd::List => print_peers(&result(&v, 0)),
        _ => println!("ok: {}", v["results"]),
    }
    Ok(())
}

fn print_peers(v: &serde_json::Value) {
    let peers = v["peers"].as_array().cloned().unwrap_or_default();
    if peers.is_empty() {
        // Said rather than shown as an empty list: an exchange with no peers
        // refuses every cross-exchange call, and that is worth stating.
        println!("no relay peers — this exchange federates with nobody");
        return;
    }
    println!("{} relay peer(s):", peers.len());
    for p in &peers {
        let key = p["key"].as_str().unwrap_or("?");
        let label = p["label"].as_str().unwrap_or("");
        println!("  {key}  {}", provenance(p["added_by"].as_str(), label));
    }
}

/// Which of a domain's published keys `--replace` should pin: the only one,
/// or the one named — which must be among them, because a key the zone does
/// not publish is not "this exchange's key now", whatever the person meant.
fn choose_replacement(offered: &[PubKey], key: Option<&str>) -> Result<PubKey, String> {
    match (offered, key) {
        ([], _) => Err("the domain publishes no key".into()),
        ([only], None) => Ok(*only),
        (many, None) => Err(format!(
            "the domain publishes {} keys; say which with --key:\n{}",
            many.len(),
            many.iter()
                .map(|k| format!("  {k}"))
                .collect::<Vec<_>>()
                .join("\n")
        )),
        (many, Some(k)) => {
            let k: PubKey = k.parse().map_err(|_| format!("--key {k:?} is not a key"))?;
            if many.contains(&k) {
                Ok(k)
            } else {
                Err(format!(
                    "{k} is not a key the domain publishes; the zone has to agree"
                ))
            }
        }
    }
}

fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// How a peer came to be on the list, as one readable clause.
///
/// A seeded entry has no admin and carries "seed" as its label, so the obvious
/// rendering said the same word twice — `seed  (added by seed)`. The two are
/// different facts and deserve different sentences: nobody signed for a seeded
/// peer, and saying so is the point. It also happens to be the operationally
/// interesting half — a seeded peer is not in the state file yet, so a restart
/// re-seeds it from config.
fn provenance(added_by: Option<&str>, label: &str) -> String {
    match added_by {
        Some(admin) if label.is_empty() => format!("(added by {admin})"),
        Some(admin) => format!("({label}, added by {admin})"),
        None => "(seeded from config, not signed for)".to_string(),
    }
}

/// Build one op per key, for the batches that are just a list of keys.
fn keyed_ops(keys: &[String], make: impl Fn(PubKey) -> Op) -> Result<Vec<Operation>, String> {
    if keys.is_empty() {
        return Err("give at least one key".into());
    }
    keys.iter()
        .map(|k| Ok(make(parse_key(k)?).to_operation()))
        .collect()
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
    v["results"]
        .get(i)
        .cloned()
        .unwrap_or(serde_json::Value::Null)
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
        let target = e["target"]
            .as_str()
            .map(|t| format!(" {t}"))
            .unwrap_or_default();
        let short: String = admin.chars().take(8).collect();
        println!("[{time}] {short}… {action}{target}");
    }
}

// ---- resolution helpers ------------------------------------------------------

async fn connect(cli: &Cli, cfg: &Config) -> Result<(Client, PubKey), String> {
    // Precedence for both address and key: CLI flag > env var > config file.
    let (socket, server) = endpoint(cli, cfg).await?;
    // **As the identity, when there is one.** The managed whitelist is on
    // the transport: with it enabled the exchange keeps only the connections
    // whose key it allows -- the list, the administrators, its peers -- and
    // an anonymous connection is none of those, so an administrator signing
    // over one would be answered once and then closed. A YubiKey cannot be
    // a transport key and connects anonymously, which is the documented
    // cost of the transport gate.
    let client = match load_software_identity(cli, cfg) {
        Ok(signer) if !cli.yubikey => {
            Client::connect_as(socket, server.as_bytes(), &signer.seed()).await?
        }
        _ => Client::connect(socket, server.as_bytes()).await?,
    };
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

// `name@domain` classification lives in `sqex_proto::name::classify`, shared by
// the CLI, chat, and voice clients; its tests are there.

#[cfg(test)]
mod tests {
    use super::*;

    /// The first run of `admin peer list` against a real exchange printed
    /// `seed  (added by seed)` — the label and the fallback saying the same
    /// word. A seeded peer and an administered one are different facts.
    #[test]
    fn a_seeded_peer_reads_differently_from_an_administered_one() {
        assert_eq!(
            provenance(None, "seed"),
            "(seeded from config, not signed for)",
            "a seeded peer must not claim an administrator added it"
        );
        assert_eq!(
            provenance(Some("HR2vxdPD"), "indra.org"),
            "(indra.org, added by HR2vxdPD)"
        );
        // A SIP-40 follow: the outgoing exchange key is who authorised it.
        // Rendered as "added by" that key, not as a seed -- the first live
        // rotation printed "seeded from config, not signed for" for an entry
        // the retiring key had signed for and the state file held.
        assert_eq!(
            provenance(Some("7tbBEPxK"), "trunk.exchange, SIP-40 handover"),
            "(trunk.exchange, SIP-40 handover, added by 7tbBEPxK)"
        );
        // An administrator who gave no label still gets named, without a
        // stray comma where the label would have been.
        assert_eq!(provenance(Some("HR2vxdPD"), ""), "(added by HR2vxdPD)");
    }

    /// `--replace` pins the sole published key, needs `--key` when there are
    /// several, and refuses a key the zone does not publish — the same "the
    /// zone must agree" rule a signed handover has, kept for the manual path.
    #[test]
    fn a_replacement_must_be_a_key_the_zone_publishes() {
        let (a, b) = (PubKey::new([1; 32]), PubKey::new([2; 32]));
        assert_eq!(choose_replacement(&[a], None).unwrap(), a);
        assert!(
            choose_replacement(&[a, b], None)
                .unwrap_err()
                .contains("--key")
        );
        assert_eq!(
            choose_replacement(&[a, b], Some(&b.to_string())).unwrap(),
            b
        );
        let c = PubKey::new([3; 32]);
        assert!(
            choose_replacement(&[a, b], Some(&c.to_string()))
                .unwrap_err()
                .contains("zone has to agree")
        );
        assert!(choose_replacement(&[], None).is_err());
    }
}
