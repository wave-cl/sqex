//! `sqex-chat` — end-to-end encrypted direct messages, in a terminal.
//!
//! The connection's Ed25519 identity is the caller (SIP-3), so there is nothing
//! to log in to. What there is instead is a store: the keys this client has
//! opened cannot be recovered from the exchange, because opening an envelope
//! spends the prekey it was sealed against.

use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use sqex_chat::attach::describe;
use sqex_chat::client::{Chat, ChatError, Link};
use sqex_chat::store::{self, Store, store_path};
use std::collections::{HashMap, HashSet};

/// How long the answer to a command stays on screen. Long enough to read a
/// sentence, short enough not to sit over the next thing that goes wrong.
const NOTE_LINGER: Duration = Duration::from_secs(8);

use sqex_proto::events::Event as ChatEvent;
use sqex_proto::message::Post as SipPost;
use sqex_proto::timeline::{Deletion, Timeline};
use sqnr::{Client, config::Config, identity};
use sqnr_core::Signer;
use sqex_proto::channel::{Role, Visibility};
use sqex_proto::credential::Credential;
use sqex_proto::refusal::Code as RefusalCode;
use sqnr_core::PubKey;

mod ui;

use ui::{App, Found, Row, Said, Trouble, short};

#[derive(Parser)]
#[command(
    name = "sqex-chat",
    version,
    about = "End-to-end encrypted direct messages over sQUIC",
    long_about = "End-to-end encrypted direct messages over sQUIC.

A conversation's identifier is derived from the two identities in it, so there \
is nothing to look up and nothing to join. Somebody who writes to you first is \
found on startup by asking the exchange which channels you are in, and added \
to your list — you do not have to know them in advance.

Your keys live in ~/.sqex/chat, sealed under your identity. Lose that directory \
and the conversations in it cannot be read again by anyone, including you — \
that is the forward secrecy working, not a fault.

Private groups work the same way: /new makes one, /invite and /kick change who \
is in it, and removing somebody rotates the key so what follows is not theirs. \
A group's name is a sealed entry, so the exchange never learns it."
)]
struct Cli {
    /// A domain that publishes an exchange (SIP-33). Its key is discovered over
    /// DNSSEC, pinned on first contact, and refused if it later changes.
    ///
    /// Overrides SQEX_SERVER and ~/.sqnr/config. Use --server-host instead to
    /// dial an address with a key you already hold.
    #[arg(long)]
    server: Option<String>,
    /// A literal address, host:port, to dial. Requires --server-key.
    ///
    /// Overrides SQEX_SERVER_HOST. The port defaults to 443.
    #[arg(long)]
    server_host: Option<String>,
    /// The server's base58 public key. Goes with --server-host; a --server
    /// domain supplies its own.
    #[arg(long)]
    server_key: Option<String>,
    /// Identity file (default ~/.sqnr/identity).
    #[arg(short = 'i', long, global = true)]
    identity: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Add somebody you want to write to first. Anyone who writes to you is
    /// found on startup without this.
    Add {
        /// Their Ed25519 identity, base58.
        key: String,
        /// What to call them on screen.
        #[arg(long)]
        name: Option<String>,
    },
    /// Forget somebody. Keeps the conversation's keys; only stops listening.
    Forget { key: String },
    /// List who you have added.
    List,
    /// Print your own identity, to give to somebody who wants to write to you.
    Whoami,
    /// Link, list and withdraw the clients that act for you.
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Ask an exchange that does not know you to let you in (SIP-24).
    ///
    /// It answers every request identically — the same body, the same delay —
    /// so this can report that the request was sent and nothing more. Whether
    /// an administrator ever sees it, and what they decide, is not something
    /// the answer contains.
    Admit {
        /// A line for whoever reads the request. It is text you chose, shown at
        /// the moment of a security decision, so the exchange shows your key
        /// with it and an administrator should go by that.
        #[arg(long, default_value = "")]
        label: String,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// What this account has registered, and when each expires.
    List,
    /// Sign a credential naming another client, so it may act for you.
    ///
    /// Run this on the client you already use, then take the printed line to
    /// the new one and give it to `device claim`.
    Link {
        /// The new client's identity, base58 — its own `whoami`.
        key: String,
        /// How long the grant lasts, in days.
        #[arg(long, default_value_t = 90)]
        days: u64,
    },
    /// Register *this* client using a credential from `device link`.
    Claim {
        /// The credential, base58, as `device link` printed it.
        credential: String,
    },
    /// Withdraw a client. It keeps every key it already holds — rotate the
    /// channels that matter if that is the point.
    Revoke { key: String },
    /// Push this client's channel keys to your other devices.
    ///
    /// Runs on its own at startup; this is the same thing, said out loud, for
    /// when you want to know whether it worked.
    Reseal,
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

    // Before anything is unlocked: printing your own identity does not need the
    // seed, and asking for a passphrase to read a public key would be a poor
    // trade for the one command somebody runs to tell a friend where to write.
    if matches!(cli.cmd, Some(Cmd::Whoami)) {
        println!("{}", identity::read_public(&identity_path(&cli, &cfg)?)?);
        return Ok(());
    }

    let (seed, me) = load_identity(&cli, &cfg)?;
    let path = store_path(&me).map_err(|e| e.to_string())?;
    let store = Store::open(&seed, Some(&path)).map_err(|e| e.to_string())?;

    // The three commands that never touch the network. Doing them without
    // connecting means `add` works while the exchange is down, which is when
    // somebody is most likely to be fiddling with their contact list.
    match &cli.cmd {
        // Whoami is handled above, before the identity is unlocked.
        Some(Cmd::Whoami) => return Ok(()),
        Some(Cmd::List) => {
            let contacts = store.contacts().map_err(|e| e.to_string())?;
            if contacts.is_empty() {
                println!("nobody yet — sqex-chat add <key>");
            }
            for c in contacts {
                println!("{:<20} {}", c.label, c.account);
            }
            return Ok(());
        }
        Some(Cmd::Add { key, name }) => {
            let account: PubKey = key.trim().parse().map_err(|e| format!("bad key: {e}"))?;
            if account == me {
                return Err("that is your own key".into());
            }
            let label = name.clone().unwrap_or_else(|| short(&account));
            store
                .add_contact(&account, &label, now())
                .map_err(|e| e.to_string())?;
            println!("added {label} ({account})");
            return Ok(());
        }
        Some(Cmd::Forget { key }) => {
            let account: PubKey = key.trim().parse().map_err(|e| format!("bad key: {e}"))?;
            store.remove_contact(&account).map_err(|e| e.to_string())?;
            println!("forgotten — their keys are kept, this only stops listening");
            return Ok(());
        }
        None => {}
        _ => {}
    }

    let (client, addr, server, pinned_notice) = connect(&cli, &cfg, &seed).await?;
    // The exchange we are talking to is bound into every SIP-31 signature, so
    // an entry signed here cannot be lifted into another exchange's copy of the
    // same conversation — which for a direct message is byte-identical.
    let mut chat = Chat::new(client, seed, me, server, store);
    // Where to dial when this connection is lost — which, until now, was
    // nowhere: the client connected once here and a dropped connection meant
    // every request afterwards failed for as long as it stayed open.
    chat.dials(addr, *server.as_bytes());
    chat.top_up_prekeys()
        .await
        .map_err(|e| format!("publishing prekeys: {e}"))?;

    // The rest of `device` needs the exchange.
    if let Some(Cmd::Device { cmd }) = &cli.cmd {
        return device_command(&mut chat, cmd).await;
    }

    if let Some(Cmd::Admit { label }) = &cli.cmd {
        chat.request_admission(label)
            .await
            .map_err(|e| e.to_string())?;
        // Exactly what happened, and no more. SIP-24 has the exchange answer
        // every request the same way; a client that said "pending" or "sent to
        // an administrator" would be inventing a result out of an answer that
        // contains none.
        println!("request sent. The exchange answers every request identically,");
        println!("so there is nothing here to tell you what it decided.");
        println!("Your key is {}.", chat.me);
        return Ok(());
    }

    // A revoked client is otherwise refused as a stranger by every route it
    // tries, which is true and tells nobody what happened.
    if matches!(chat.still_linked().await, Ok(Some(false))) {
        return Err(format!(
            "this client has been revoked from {} — it is no longer one of that \
             account's devices, and the keys it already holds are all it will \
             ever have. Link it again to carry on.",
            chat.me
        ));
    }

    // One interactive client per account, and this is the only thing that can
    // enforce it: two of them share a device key and a prekey pool and cannot
    // see each other. Taken here rather than in `Store::open` so that the
    // one-shot commands — `list`, `add`, `whoami` — go on working while a
    // client is up, which is when somebody is most likely to want them.
    //
    // Held for the length of the session: dropping the guard, or the process
    // ending however it ends, hands it on.
    let _lock = store::lock(&path).map_err(|e| e.to_string())?;
    interface(chat, pinned_notice).await
}

/// Whether a credential was written for this client.
///
/// Compared against the client's **device** key and never the account it acts
/// for. A credential's `delegate` is a device; a client that has already been
/// linked acts for an account that is somebody else's key. Comparing against
/// the account passes exactly once — on a fresh client, where `me` falls back
/// to `device` — and then refuses the renewal SIP-22 expects a device to make
/// before its credential expires, with a message naming the wrong key as the
/// reason.
fn credential_is_for(credential: &Credential, device: &PubKey) -> bool {
    &credential.delegate == device
}

/// The device operations that talk to the exchange.
async fn device_command(chat: &mut Chat, cmd: &DeviceCmd) -> Result<(), String> {
    match cmd {
        DeviceCmd::Link { key, days } => {
            let device: PubKey = key.trim().parse().map_err(|e| format!("bad key: {e}"))?;
            if device == chat.me {
                return Err("that is this client's own key".into());
            }
            // This client registers itself first, and it has to. An account
            // with no registered devices is its own device; the moment one is
            // registered, that fallback stops applying and everything seals to
            // the registered set only — so linking without doing this would cut
            // *this* client out of every epoch minted afterwards.
            let already = chat.my_devices().await.map_err(|e| e.to_string())?;
            if !already.iter().any(|d| d.device == chat.me) {
                let own = chat
                    .issue_credential(&chat.me, days * 24 * 60 * 60)
                    .map_err(|e| e.to_string())?;
                chat.register_self(&own).await.map_err(|e| e.to_string())?;
                eprintln!("registered this client as a device first");
            }
            let credential = chat
                .issue_credential(&device, days * 24 * 60 * 60)
                .map_err(|e| e.to_string())?;
            println!("{}", bs58::encode(credential.encode()).into_string());
            eprintln!();
            eprintln!("Give that line to the new client:");
            eprintln!("  sqex-chat -i <its identity> device claim <the line>");
            eprintln!();
            eprintln!("Then run `sqex-chat` here once, so it can seal the new client");
            eprintln!("into the conversations it should be able to read.");
            eprintln!("It expires in {days} days; `device revoke` withdraws it sooner.");
            Ok(())
        }
        DeviceCmd::List => {
            let devices = chat.my_devices().await.map_err(|e| e.to_string())?;
            if devices.is_empty() {
                println!("no registered devices — this client is its own device");
                println!("(that is the ordinary single-client case, not a fault)");
            }
            for d in devices {
                let left = d.not_after.saturating_sub(now());
                println!("{}  expires in {} days", d.device, left / (24 * 60 * 60));
            }
            Ok(())
        }
        DeviceCmd::Claim { credential } => {
            let raw = bs58::decode(credential.trim())
                .into_vec()
                .map_err(|e| format!("that is not base58: {e}"))?;
            let credential = Credential::decode(&raw)
                .map_err(|e| format!("bad credential: {e}"))?;
            if !credential_is_for(&credential, &chat.device()) {
                return Err(format!(
                    "that credential names {}, not this client ({}) — \
                     a credential is bound to the device it was written for",
                    credential.delegate,
                    chat.device()
                ));
            }
            chat.register_self(&credential)
                .await
                .map_err(|e| e.to_string())?;
            // Remember whose client this now is. Everything account-shaped
            // depends on it — a direct message's identifier, whether we are an
            // admin, whose name goes beside a message — and the exchange will
            // not tell us: it resolves device to account internally and has no
            // route that answers "who am I".
            chat.store()
                .set_account(&credential.account)
                .map_err(|e| e.to_string())?;
            println!("registered as a device of {}", credential.account);
            // Prekeys under the new device key, or nothing can be sealed to it
            // — and then whatever its siblings have already sealed.
            chat.top_up_prekeys().await.map_err(|e| e.to_string())?;
            let mut collected = 0;
            for m in chat.mine().await.map_err(|e| e.to_string())? {
                collected += chat.collect_keys(&m.channel).await.unwrap_or(0);
            }
            println!("collected {collected} channel key(s)");
            // SIP-17 says to check after any device registers.
            let mut waiting = 0;
            for m in chat.mine().await.map_err(|e| e.to_string())? {
                waiting += chat.stranded(&m.channel).await.map(|a| a.devices.len()).unwrap_or(0);
            }
            if waiting > 0 {
                println!("{waiting} device(s) across your channels still hold no key");
            }
            println!("run `sqex-chat` on your other client once, so it can seal you the rest");
            Ok(())
        }
        DeviceCmd::Reseal => {
            let mut total = 0;
            for m in chat.mine().await.map_err(|e| e.to_string())? {
                match chat.reseal_to_siblings(&m.channel).await {
                    Ok(n) => {
                        total += n;
                        println!("{}  sealed {n}", hex8(&m.channel));
                    }
                    Err(e) => println!("{}  {e}", hex8(&m.channel)),
                }
            }
            println!("{total} key(s) sent to your other devices");
            Ok(())
        }
        DeviceCmd::Revoke { key } => {
            let device: PubKey = key.trim().parse().map_err(|e| format!("bad key: {e}"))?;
            chat.revoke_device(&device).await.map_err(|e| e.to_string())?;
            println!("revoked {device}");
            println!("it keeps every key it already holds — rotate what matters");
            Ok(())
        }
    }
}

/// One open conversation's live state.
///
/// Keyed by channel, not by contact. A direct message has a peer and a group
/// does not, which is the whole of the difference at this level — everything
/// below is the same log, the same epoch key and the same timeline.
struct Open {
    /// The other party, for a direct message. `None` for a group or a public
    /// channel.
    peer: Option<PubKey>,
    /// Anybody may join and read this one.
    public: bool,
    label: String,
    channel: [u8; 32],
    /// Who may redact and rename here. From the exchange, remembered so that a
    /// client starting offline folds its own history correctly.
    admins: Vec<PubKey>,
    timeline: Timeline,
    /// How many messages we had last time, so a new one can be counted unread
    /// without diffing two timelines.
    timeline_len: usize,
    trouble: Trouble,
    /// The answer to something we just did, and when it was said.
    ///
    /// Separate from `trouble.message`, which is about the *state* of the
    /// conversation and is rebuilt by every poll. A note is about an action,
    /// and the poll runs every 700 ms — so keeping the two in one field meant
    /// every confirmation this client has ever printed was on screen for less
    /// than a second, which is to say it was never read.
    note: Option<(String, std::time::Instant)>,
    typing: bool,
    /// Where everybody's cursor is, as of the last time we asked. Fetched
    /// only for the conversation on screen, and not on every poll: it is one
    /// more round trip and nobody is reading a receipt in a channel they are
    /// not looking at.
    marks: Vec<sqex_proto::channel::Mark>,
    marks_at: Option<std::time::Instant>,
    /// How far we have told the exchange we have read, so the same mark is not
    /// posted on every pass. Seeded from the exchange's own record at startup,
    /// which is what makes "where was I" survive closing the client.
    read_to: u64,
    /// Where the unread divider sits, frozen when the conversation was opened.
    ///
    /// Frozen on purpose. Reading a conversation immediately advances the read
    /// mark, so a divider computed from it would vanish the moment it appeared
    /// — exactly when somebody wants it. It is set once on arriving here and
    /// cleared on leaving.
    divider: Option<u64>,
    /// When something last happened here, for ordering the list. The newest
    /// message's time, or when we joined if nothing has been said.
    last_at: u64,
    /// How many people are in it. Nought means *not asked yet* rather than
    /// empty — a channel with no members is not a thing — so the header says
    /// nothing rather than claiming a number.
    members: usize,
    /// Messages arrived while this conversation was not the one on screen.
    unread: usize,
    /// They have published no prekeys, so nothing can be sealed to them yet.
    waiting: bool,
}

/// Find conversations nobody told us about, and add whoever started them.
///
/// This is what `Mine` bought. A direct message's identifier is a hash of the
/// two accounts, so it cannot be run backwards to say who the other party is —
/// but the exchange enforces membership and will therefore name them. Each
/// candidate is checked by re-deriving the identifier from the account it
/// found: a channel that does not hash back is not a direct message with that
/// person, whatever the exchange said.
///
/// A channel that is not a direct message is left alone. This client has no
/// interface for group channels yet, and inventing a contact for one would put
/// a row on screen that nothing can open.
async fn discover(chat: &mut Chat) -> std::result::Result<usize, ChatError> {
    let known: Vec<PubKey> = chat
        .store()
        .contacts()
        .map_err(ChatError::Store)?
        .into_iter()
        .map(|c| c.account)
        .collect();
    let mut found = 0;
    for m in chat.mine().await? {
        if known.iter().any(|k| chat.dm_with(k) == m.channel) {
            continue;
        }
        let info = match chat.info(&m.channel).await {
            Ok(i) => i,
            Err(_) => continue,
        };
        let Some(other) = info
            .members
            .iter()
            .map(|mem| mem.account)
            .find(|a| *a != chat.me)
        else {
            continue;
        };
        if chat.dm_with(&other) != m.channel {
            continue;
        }
        chat.store()
            .add_contact(&other, &short(&other), now())
            .map_err(ChatError::Store)?;
        found += 1;
    }
    Ok(found)
}

/// Reconcile what the exchange says we are in with what we have on screen.
///
/// Groups come from here and only from here: a group's identifier is random
/// rather than derived, so there is nothing to compute and nothing to guess.
/// Direct messages are matched against the contact list so that a conversation
/// keeps the name its contact was given.
async fn sync_channels(chat: &mut Chat) -> std::result::Result<Vec<Open>, ChatError> {
    let contacts = chat.store().contacts().map_err(ChatError::Store)?;
    let known = chat.store().channels().map_err(ChatError::Store)?;
    let mut open = Vec::new();

    for m in chat.mine().await? {
        let peer = contacts
            .iter()
            .find(|c| chat.dm_with(&c.account) == m.channel)
            .map(|c| (c.account, c.label.clone()));
        let remembered = known.iter().find(|k| k.0 == m.channel);

        // The exchange is authoritative about who administers a channel; the
        // store is what makes that survive being offline.
        let public = m.visibility == Visibility::Public;
        let (admins, given_name, members) = match chat.info(&m.channel).await {
            Ok(info) => (
                info.members
                    .iter()
                    .filter(|mem| mem.role == Role::Admin)
                    .map(|mem| mem.account)
                    .collect(),
                info.name,
                info.members.len(),
            ),
            Err(_) => (
                remembered.map(|k| k.3.clone()).unwrap_or_default(),
                String::new(),
                0,
            ),
        };

        let label = match &peer {
            Some((_, l)) => l.clone(),
            // A public channel's name is held by the exchange in the clear —
            // that is what the directory searches — so it is known before a
            // single entry is read. A group's is a sealed entry and is not, so
            // until the log is read it goes by its identifier.
            None if public && !given_name.is_empty() => given_name,
            None => remembered
                .map(|k| k.2.clone())
                .filter(|l| !l.is_empty())
                .unwrap_or_else(|| format!("group {}", hex8(&m.channel))),
        };

        chat.store()
            .put_channel(&m.channel, peer.is_none(), &label, &admins)
            .map_err(ChatError::Store)?;

        let timeline = chat.history(&m.channel, &admins).unwrap_or_default();
        let timeline_len = timeline.messages().count();
        let last_at = timeline
            .messages()
            .map(|msg| msg.posted)
            .max()
            .unwrap_or(m.joined);
        // The exchange's record of our own read mark. Seeding from it is what
        // lets the client be closed and reopened and still say where you were.
        let read_to = m.read;
        open.push(Open {
            members,
            peer: peer.map(|(a, _)| a),
            public,
            label,
            channel: m.channel,
            admins,
            timeline,
            timeline_len,
            trouble: Trouble::default(),
            note: None,
            typing: false,
            marks: Vec::new(),
            marks_at: None,
            read_to,
            divider: None,
            last_at,
            unread: 0,
            waiting: false,
        });
    }

    // A contact we have never exchanged anything with is not a membership yet,
    // so it will not come back from `mine` — but somebody who typed `add`
    // expects to see a row they can write into.
    for c in &contacts {
        let channel = chat.dm_with(&c.account);
        if open.iter().any(|o| o.channel == channel) {
            continue;
        }
        open.push(Open {
            peer: Some(c.account),
            public: false,
            label: c.label.clone(),
            channel,
            admins: vec![chat.me, c.account],
            timeline: Timeline::default(),
            timeline_len: 0,
            trouble: Trouble::default(),
            note: None,
            typing: false,
            marks: Vec::new(),
            marks_at: None,
            read_to: 0,
            divider: None,
            // Nothing has happened here yet, so it sorts below anything that
            // has rather than claiming a time it does not have.
            last_at: 0,
            members: 0,
            unread: 0,
            waiting: false,
        });
    }
    Ok(open)
}

/// Move what a rebuild would throw away from the old list onto the new one.
///
/// `sync_channels` asks the exchange what we are in and builds the answer from
/// scratch, which is right — it is the authority — but everything a *reader*
/// has accumulated lives here and not there: how many messages arrived while
/// they were looking elsewhere, where they had read up to, the answer to the
/// command they just typed. Rebuilding without this would clear all of it
/// every time somebody started a conversation with them, which is a rude
/// answer to a message arriving.
fn carry_over(old: &[Open], fresh: &mut [Open]) {
    for o in fresh.iter_mut() {
        let Some(was) = old.iter().find(|p| p.channel == o.channel) else {
            continue;
        };
        o.unread = was.unread;
        o.divider = was.divider;
        o.note = was.note.clone();
        o.marks = was.marks.clone();
        o.marks_at = was.marks_at;
        o.typing = was.typing;
        o.waiting = was.waiting;
        o.members = o.members.max(was.members);
        // The read mark only ever moves forward, and the exchange's copy can
        // be behind ours between publishing it and it being acknowledged.
        o.read_to = o.read_to.max(was.read_to);
        // Counted, not recomputed: this is what tells the next poll how many
        // messages are new, and resetting it would count the whole
        // conversation as having just arrived.
        o.timeline_len = was.timeline_len.max(o.timeline_len);
    }
}

/// Eight hex characters of a channel identifier, to call it something.
fn hex8(channel: &[u8; 32]) -> String {
    channel[..4].iter().map(|b| format!("{b:02x}")).collect()
}

async fn interface(mut chat: Chat, pinned_notice: Option<String>) -> Result<(), String> {
    // Before anything is drawn: somebody may have written to us while this
    // client had never heard of them.
    if let Err(e) = discover(&mut chat).await {
        eprintln!("could not list your channels ({e}); showing known contacts only");
    }
    let mut open = sync_channels(&mut chat).await.map_err(|e| e.to_string())?;

    let mut app = App {
        me: format!("{}", chat.me),
        ..Default::default()
    };

    // A trust decision was made on this user's behalf during startup, so it is
    // said where they will actually read it rather than into the scrollback the
    // interface is about to paint over.
    // On every conversation, not just the first: which one the interface opens
    // on is its decision, and a notice the user never sees because they happened
    // to land elsewhere is no notice at all. It expires in NOTE_LINGER either
    // way, so this shows once and leaves nothing behind.
    if let Some(notice) = pinned_notice {
        let at = std::time::Instant::now();
        for conv in open.iter_mut() {
            conv.note = Some((notice.clone(), at));
        }
    }

    let mut terminal = start_terminal().map_err(|e| e.to_string())?;
    let result = event_loop(&mut terminal, &mut chat, &mut open, &mut app).await;
    stop_terminal(&mut terminal).map_err(|e| e.to_string())?;
    result
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    chat: &mut Chat,
    open: &mut Vec<Open>,
    app: &mut App,
) -> Result<(), String> {
    // Every conversation is opened once at startup, so a message that arrived
    // while this client was off is collected rather than waited for.
    // Hand the epoch in force to our own other devices before anything else.
    // A client linked after a conversation started has no key for it, and this
    // is the only thing that gives it one without an admin rotating — which
    // would deny it everything said before, and disturb everybody else to do
    // it. Cheap when there are no siblings: one request that lists none.
    for conv in open.iter_mut() {
        match chat.reseal_to_siblings(&conv.channel).await {
            Ok(0) => {}
            Ok(n) => {
                conv.trouble.message =
                    Some(format!("sent the key to {n} of your other device(s)"))
            }
            // Discarded, this used to be, which meant the one operation that
            // makes a linked device work failed in silence.
            Err(e) => conv.trouble.message = Some(format!("sealing to your devices: {e}")),
        }
    }

    for conv in open.iter_mut() {
        let opened = match conv.peer {
            // `Create` on a direct message is idempotent and is how a party
            // returns to one, so this is also the ordinary way to reopen.
            Some(peer) => chat.open_dm(&peer).await.map(|_| ()),
            // A group already exists; what it needs is whatever key was sealed
            // to us while this client was off.
            None => chat.collect_keys(&conv.channel).await.map(|_| ()),
        };
        match opened {
            Ok(()) => {}
            Err(ChatError::NotReady(_)) => conv.waiting = true,
            Err(e) => conv.trouble.message = Some(e.to_string()),
        }
    }

    // The floor, not the cadence. Everything below is normally driven by SIP-30
    // events; this is what repairs a client that missed one — a dropped stream,
    // a resync, an exchange too old to push at all. It is deliberately slow
    // enough that an idle client is silent and fast enough that "missed
    // something" is a hiccup rather than a bug report.
    const IDLE_SWEEP: Duration = Duration::from_secs(30);
    let mut sweep_at = tokio::time::Instant::now();
    let mut dirty = Dirty::default();
    let mut was_selected: Option<usize> = None;
    let mut hover = ui::Drawn::default();
    loop {
        let names = name_map(chat, open, selected_index(open, app).map(|i| &open[i]));
        refresh(app, open, &chat.me, &names);
        app.link = chat.link();
        // Ours arrives with everybody else's, on the profile poll: it is not
        // known at startup, so the header shows the key stub until the first
        // one comes back and the name after.
        app.name = chat.display_name(&chat.me).unwrap_or_default();
        // Where each message ended up, kept from the frame that drew it: a
        // second copy of the layout could disagree with the first, and a
        // pointer that names the message above the one under it is worse than
        // no pointer at all.
        let was = (hover.total, app.scroll);
        terminal
            .draw(|f| hover = ui::draw(f, app))
            .map_err(|e| e.to_string())?;
        // What the wish came to. Storing it back is what keeps a held PgUp
        // from winding the number past the top of a short conversation, and
        // what makes `Home` — which asks for `usize::MAX` — land exactly at
        // the oldest line rather than somewhere unrepresentable.
        app.scroll = hover.scroll;
        app.page = hover.room.saturating_sub(2).max(1);
        // Somebody reading history stays where they are when a message
        // arrives. The lines all sit below them, so without this the text
        // would creep upward under their eyes at every poll.
        if was.1 > 0 && hover.total > was.0 {
            app.scroll += hover.total - was.0;
        }
        if app.should_quit {
            return Ok(());
        }

        // Keys first, so typing never waits on the network.
        if event::poll(Duration::from_millis(50)).map_err(|e| e.to_string())? {
            match event::read().map_err(|e| e.to_string())? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    handle_key(chat, open, app, k.code, k.modifiers).await;
                }
                // Motion is reported a cell at a time, so a sweep across the
                // pane is dozens of these. Only a change of *message* is worth
                // a redraw; the rest are dropped here rather than costing a
                // frame each and starving the poll below.
                // Guarded on our own state as well as on the terminal's.
                // A terminal that was never asked does not send these, but
                // saying so here is what makes the flag mean something rather
                // than describe something: a multiplexer with its own mouse
                // settings is not a thing to be surprised by.
                Event::Mouse(m) if app.mouse && m.kind == MouseEventKind::Moved => {
                    let over = hover.at(m.column, m.row);
                    if over == app.hovered {
                        continue;
                    }
                    app.hovered = over;
                }
                // The wheel, when the client has the mouse. Three lines a
                // notch is what a terminal pager does and what a hand
                // expects; one is treacle and a page is a jump.
                Event::Mouse(m)
                    if app.mouse
                        && matches!(
                            m.kind,
                            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                        ) =>
                {
                    let back = m.kind == MouseEventKind::ScrollUp;
                    app.scroll = if back {
                        app.scroll + 3
                    } else {
                        app.scroll.saturating_sub(3)
                    };
                }
                // Click a message to take its author's key. The transcript
                // stopped showing keys, so this is one of the three ways back
                // to one — and the only one that is a single gesture.
                Event::Mouse(m)
                    if app.mouse && m.kind == MouseEventKind::Down(MouseButton::Left) =>
                {
                    if let Some(s) = hover.at(m.column, m.row).and_then(|i| app.said.get(i)) {
                        let note = copied(&s.key.clone(), s.mine);
                        match selected_index(open, app) {
                            Some(i) => open[i].note = Some((note, std::time::Instant::now())),
                            None => app.trouble.message = Some(note),
                        }
                    }
                }
                _ => {}
            }
            continue;
        }

        // If the link is down this is what brings it back, and if it is up it
        // costs nothing. It never blocks for long — a handshake is advanced a
        // slice at a time, so the keyboard stays served while it happens.
        chat.keep_alive().await;

        // Subscribe, then reconcile — in that order, always. The exchange has
        // the subscription registered by the time `subscribe` returns, so
        // anything that changes while we are catching up is queued behind us
        // rather than lost in the gap. Reconciling first would drop exactly the
        // window in between and say nothing about it.
        if chat.link() == Link::Up && !chat.subscribed() {
            // A refusal is survivable and needs no branch of its own: the
            // sweep below still runs, so the client degrades to polling rather
            // than to silence — which is also what it does against an exchange
            // too old to push at all.
            if let Ok(true) = chat.subscribe().await {
                dirty.everything(open);
            }
        }

        for event in chat.take_events() {
            dirty.note(event, &chat.me, open);
        }

        // The floor. Everything, on a slow tick, whatever the stream did or
        // did not say.
        if tokio::time::Instant::now() >= sweep_at {
            sweep_at = tokio::time::Instant::now() + IDLE_SWEEP;
            dirty.everything(open);
        }

        // Moving to a conversation is a reason to look at it: the read mark we
        // owe is published from `receipts`, and without this it would wait for
        // somebody else to do something.
        let here = selected_index(open, app);
        if here != was_selected {
            was_selected = here;
            if let Some(i) = here {
                dirty.channels.insert(open[i].channel);
                dirty.receipts.insert(open[i].channel);
            }
        }

        if dirty.is_empty() {
            continue;
        }

        for channel in std::mem::take(&mut dirty.channels) {
            match open.iter().position(|c| c.channel == channel) {
                Some(i) => poll_one(chat, &mut open[i], app).await,
                // A channel we were told about and do not hold. That is a
                // conversation somebody else started, and the rebuild below is
                // what makes it appear.
                None => dirty.arrivals = true,
            }
        }

        if !dirty.profiles.is_empty() {
            let who: Vec<PubKey> = std::mem::take(&mut dirty.profiles).into_iter().collect();
            // `refetch`, not `refresh`: the exchange has just said this changed,
            // and honouring an hour-long cache against a fact we were handed
            // would be caching the answer to a question nobody asked.
            let _ = chat.refetch_profiles(&who, now()).await;
        }

        // Where the unread divider goes, decided once on arriving at a
        // conversation and left alone after — reading advances the mark
        // immediately, so a divider recomputed from it would disappear the
        // instant it was wanted.
        let me = chat.me;
        for (i, conv) in open.iter_mut().enumerate() {
            place_divider(conv, &me, Some(i) == here);
        }

        // Has anybody started talking to us since we last looked?
        //
        // A direct message needs no invitation and no acceptance, which makes
        // it exactly the thing that arrives without warning. This used to run
        // on a five-second timer; now it runs when the exchange says a
        // membership changed, and on the sweep.
        if std::mem::take(&mut dirty.arrivals)
            && let Ok(mine) = chat.mine().await
            && mine
                .iter()
                .any(|m| !open.iter().any(|o| o.channel == m.channel))
        {
            let _ = discover(chat).await;
            if let Ok(mut rebuilt) = sync_channels(chat).await {
                carry_over(open, &mut rebuilt);
                *open = rebuilt;
            }
        }

        // Receipts, for the conversation on screen only.
        //
        // Reading is what somebody does to the channel they are looking at, so
        // that is the only one to say so about — and telling the exchange you
        // have read a conversation you are not looking at would be publishing
        // something untrue about yourself.
        let wanted = std::mem::take(&mut dirty.receipts);
        if let Some(at) = selected_index(open, app)
            && wanted.contains(&open[at].channel)
        {
            receipts(chat, &mut open[at]).await;
        }
    }
}

/// What the exchange has said needs doing, and nothing about how.
///
/// A SIP-30 event carries no news, only the name of something that moved, so
/// the client's whole reaction is to remember what to go and ask about. Keeping
/// that as a set rather than acting per event is what makes a burst of twenty
/// messages in one channel cost one fetch instead of twenty.
#[derive(Default)]
struct Dirty {
    /// Fetch these conversations.
    channels: HashSet<[u8; 32]>,
    /// Refetch these profiles, ignoring the cache.
    profiles: HashSet<PubKey>,
    /// Read marks moved here; refresh them if this is the one on screen.
    receipts: HashSet<[u8; 32]>,
    /// The conversation list itself may have changed.
    arrivals: bool,
}

impl Dirty {
    fn is_empty(&self) -> bool {
        self.channels.is_empty()
            && self.profiles.is_empty()
            && self.receipts.is_empty()
            && !self.arrivals
    }

    /// Everything this client holds, as if it had just connected.
    ///
    /// Used on the slow sweep and after every subscribe. It is the repair for
    /// anything the stream did not deliver, and it must stay cheap enough to
    /// run unconditionally — which is why it is a set of names and not a set of
    /// requests.
    fn everything(&mut self, open: &[Open]) {
        for conv in open {
            self.channels.insert(conv.channel);
            self.receipts.insert(conv.channel);
        }
        self.arrivals = true;
    }

    /// File one event.
    fn note(&mut self, event: ChatEvent, me: &PubKey, open: &[Open]) {
        match event {
            // A signal is typing, which lives in the fetch alongside entries.
            ChatEvent::Channel { channel, .. } | ChatEvent::Signal { channel } => {
                self.channels.insert(channel);
            }
            ChatEvent::Cursor { channel } => {
                self.receipts.insert(channel);
            }
            ChatEvent::Membership {
                channel, account, ..
            } => {
                // Somebody else coming or going changes a member count, which
                // the fetch carries. Us coming or going changes which
                // conversations exist, which only a rebuild can find.
                if account == *me {
                    self.arrivals = true;
                } else {
                    self.channels.insert(channel);
                }
            }
            ChatEvent::Profile { account } => {
                self.profiles.insert(account);
            }
            // Nothing here can act on either. The heartbeat has already done
            // its job by arriving — it is what tells a live stream from a
            // silent exchange, and that is read where the stream is drained.
            // An admission request needs an admin tool this client is not.
            ChatEvent::Admission | ChatEvent::Heartbeat => {}
            // Everything, because we do not know what we missed.
            ChatEvent::Resync => self.everything(open),
            // SIP-19's rule, and the reason a later kind of event needs no flag
            // day: a client that refused what it did not recognise would make
            // every addition a breaking change.
            ChatEvent::Unknown(_) => {}
        }
    }
}

async fn poll_one(chat: &mut Chat, conv: &mut Open, app: &App) {
    let mut timeline = std::mem::take(&mut conv.timeline);
    match chat.poll(&conv.channel, &mut timeline, 0).await {
        Ok(got) => {
            let before = conv.timeline_len;
            conv.timeline = got.timeline;
            conv.trouble.unreadable = got.unreadable.len();
            conv.trouble.lost = got.lost;
            conv.trouble.gap = got.gap;
            conv.trouble.restarted = got.restarted;
            conv.trouble.message = None;
            conv.typing = got.typing;
            let after = conv.timeline.messages().count();
            let selected = app
                .selected_row()
                .map(|r| r.channel == conv.channel)
                .unwrap_or(false);
            if after > before && !selected {
                conv.unread += after - before;
            }
            conv.timeline_len = after;
            conv.waiting = false;
            if let Some(newest) = conv.timeline.messages().map(|m| m.posted).max() {
                conv.last_at = conv.last_at.max(newest);
            }
            // A group's name lives in a sealed entry, so it is only known once
            // the log has been read — and it changes when an admin renames it.
            let named = conv.timeline.name.clone();
            if conv.peer.is_none() && !named.is_empty() && named != conv.label {
                conv.label = named.clone();
                let _ = chat.store().set_label(&conv.channel, &named);
            }
            if got.admins != conv.admins {
                conv.admins = got.admins.clone();
                let _ = chat.store().put_channel(
                    &conv.channel,
                    conv.peer.is_none(),
                    &conv.label,
                    &conv.admins,
                );
            }
        }
        Err(ChatError::NoKey(epoch)) => {
            conv.timeline = timeline;
            conv.trouble.no_key = Some(epoch);
        }
        Err(ChatError::NotReady(_)) => {
            conv.timeline = timeline;
            conv.waiting = true;
        }
        Err(e) => {
            conv.timeline = timeline;
            // Said once, by the light in the corner, rather than by every
            // conversation. The loop asks about all of them every 700 ms, so
            // while the exchange is unreachable this line would be rewritten
            // roughly twice a second per conversation with the same words —
            // which is not a status line, it is a flicker.
            conv.trouble.message = (chat.link() == Link::Up).then(|| e.to_string());
        }
    }
}

/// The commands that are about this account rather than about a conversation.
///
/// Split out because they must work with nothing open: somebody being written
/// to by a stranger should not have to open the conversation in order to stop
/// it.
async fn account_command(
    chat: &mut Chat,
    cmd: Command,
) -> std::result::Result<String, ChatError> {
    let note = match cmd {
            Command::Profile(None) => {
                let me = chat.me;
                match chat.profile_of(&me).await {
                    Ok(got) if got.found => Ok(Some(format!(
                        "you are {:?}{} — /profile <name> | <title> changes it",
                        got.profile().name,
                        if got.profile().title.is_empty() {
                            String::new()
                        } else {
                            format!(", {:?}", got.profile().title)
                        }
                    ))),
                    Ok(_) => Ok(Some(
                        "you have published no profile — /profile <name> | <title>".into(),
                    )),
                    Err(e) => Err(e),
                }
            }
            Command::Profile(Some((name, title))) => {
                let profile = sqex_proto::profile::Profile {
                    flags: 0,
                    name: name.clone(),
                    title: title.clone(),
                    avatar: Vec::new(),
                };
                chat.set_profile(profile).await.map(|()| {
                    Some(if name.is_empty() {
                        "your profile is empty again — readers see your key".to_string()
                    } else {
                        // Said back with a reminder of what it is. A display
                        // name is a claim, not a credential, and a client that
                        // reported "you are now X" would be agreeing with it.
                        format!(
                            "published {name:?} — a name is a claim, and readers see \
                             your key beside it"
                        )
                    })
                })
            }
            Command::Block(key) => match key.parse::<PubKey>() {
                Ok(who) if who == chat.me => Err(ChatError::Protocol(
                    "that is your own key".into(),
                )),
                Ok(who) => chat.set_block(&who, true).await.map(|()| {
                    Some(format!(
                        "blocked {} — what they send is dropped, and they are \
                         answered as though it landed",
                        short(&who)
                    ))
                }),
                Err(e) => Err(ChatError::Protocol(format!("bad key: {e}"))),
            },
            Command::Unblock(key) => match key.parse::<PubKey>() {
                Ok(who) => chat
                    .set_block(&who, false)
                    .await
                    .map(|()| Some(format!("unblocked {}", short(&who)))),
                Err(e) => Err(ChatError::Protocol(format!("bad key: {e}"))),
            },
            Command::Whoami => Ok(Some(format!(
                "{} — your key in full. The header shows the first six, which \
                 is for recognising yourself and not for comparing against \
                 anybody",
                chat.me
            ))),
            Command::Reconnect => {
                chat.reconnect_now();
                Ok(Some("trying the exchange again now".to_string()))
            }
            Command::Blocked => chat.blocked().await.map(|who| {
                Some(if who.is_empty() {
                    "you have blocked nobody".to_string()
                } else {
                    who.iter().map(short).collect::<Vec<_>>().join(" ")
                })
            }),
        _ => Ok(None),
    }?;
    Ok(note.unwrap_or_default())
}

/// Decide where the unread divider sits in `conv`.
///
/// Set once on arriving and left alone after. Reading a conversation advances
/// the read mark within the second, so a divider recomputed from it would
/// disappear the instant it appeared — which is exactly when somebody wants to
/// see it. Leaving the conversation clears it, so coming back later marks the
/// new place.
fn place_divider(conv: &mut Open, me: &PubKey, selected: bool) {
    if !selected {
        conv.divider = None;
        return;
    }
    if conv.divider.is_some() {
        return;
    }
    conv.divider = conv
        .timeline
        .messages()
        // Somebody else's. A message you wrote is not one you have not seen,
        // and the read mark only catches up to your own on the next poll —
        // so quitting straight after sending would otherwise greet you with
        // your own words under a line saying they were unread.
        .filter(|m| m.account != *me)
        .map(|m| m.seq)
        .find(|seq| *seq > conv.read_to);
}

/// Publish how far we have read here, and collect how far everybody else has.
///
/// Both halves, because they are reciprocal: the exchange withholds everyone
/// else's reading from an account that withholds its own, and this client
/// published no read mark at all until now — which is why `/read` had only
/// ever reported "delivered", for everybody, forever.
///
/// The fetch is throttled. It is one more round trip and a receipt is not
/// something anybody watches change second by second.
async fn receipts(chat: &mut Chat, conv: &mut Open) {
    const EVERY: Duration = Duration::from_secs(3);

    if let Some(newest) = conv.timeline.messages().map(|m| m.seq).max()
        && newest > conv.read_to
    {
        // Best effort. A receipt nobody could publish is a cosmetic loss, and
        // it must not be able to stop the conversation working.
        if chat.mark_read(&conv.channel, newest).await.is_ok() {
            conv.read_to = newest;
        }
    }

    if conv.marks_at.is_some_and(|at| at.elapsed() < EVERY) {
        return;
    }
    conv.marks_at = Some(std::time::Instant::now());
    if let Ok(marks) = chat.marks(&conv.channel).await {
        conv.marks = marks;
    }
    // And who is here, on the same cadence and for the same reason: the poll
    // carries no membership, so without this the header's count would be
    // whatever it was when the client started.
    if let Ok(info) = chat.info(&conv.channel).await {
        conv.members = info.members.len();
        conv.admins = info
            .members
            .iter()
            .filter(|m| m.role == Role::Admin)
            .map(|m| m.account)
            .collect();
    }
}

/// Poll the conversation just acted on and redraw from it.
///
/// Every action in pick mode changes what the transcript should say, and the
/// change only exists at the exchange until something fetches it.
async fn settle_here(chat: &mut Chat, open: &mut [Open], app: &mut App, at: usize) {
    let me = chat.me;
    poll_one(chat, &mut open[at], app).await;
    let names = name_map(chat, open, open.get(at));
    refresh(app, open, &me, &names);
}

/// Keys while a message is picked.
///
/// Everything here acts on one message, so it is all guarded by there being
/// one. The actions that produce text — reply and edit — leave the mode,
/// because the next thing wanted is the input line.
async fn pick_mode(chat: &mut Chat, open: &mut [Open], app: &mut App, code: KeyCode) {
    let Some(i) = app.picked else { return };
    let Some(said) = app.said.get(i) else {
        app.picked = None;
        return;
    };
    let (seq, mine, redacted, text) = (said.seq, said.mine, said.redacted, said.text.clone());
    let key = said.key.clone();

    if app.reacting {
        match code {
            KeyCode::Esc => app.reacting = false,
            KeyCode::Char(c) if c.is_ascii_digit() => {
                let Some(n) = c.to_digit(10).map(|d| d as usize) else {
                    return;
                };
                let Some(emoji) = n.checked_sub(1).and_then(|n| ui::REACTIONS.get(n)) else {
                    return;
                };
                // Pressing the same one again takes it back. The fold is keyed
                // on (account, target, emoji), so this is a toggle at the
                // reader too and needs no agreement about order.
                let already = app
                    .said
                    .get(i)
                    .is_some_and(|s| s.reactions.iter().any(|(e, _, m)| e == *emoji && *m));
                app.reacting = false;
                let Some(at) = selected_index(open, app) else {
                    return;
                };
                let channel = open[at].channel;
                if let Err(e) = chat.react(&channel, seq, emoji, !already).await {
                    app.trouble.message = Some(e.to_string());
                }
                settle_here(chat, open, app, at).await;
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Esc => app.picked = None,
        KeyCode::Up | KeyCode::Char('k') => {
            app.picked = Some(i.saturating_sub(1));
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.picked = Some((i + 1).min(app.said.len().saturating_sub(1)));
        }
        // The keyboard's copy, so the one gesture that reaches a key is not a
        // click. Mouse capture is off until asked for, and somebody who never
        // turns it on must still be able to get at the thing the name stopped
        // saying.
        KeyCode::Char('c') => {
            let note = copied(&key, mine);
            match selected_index(open, app) {
                Some(at) => open[at].note = Some((note, std::time::Instant::now())),
                None => app.trouble.message = Some(note),
            }
        }
        KeyCode::Char('a') if !redacted => app.reacting = true,
        KeyCode::Char('r') if !redacted => {
            app.replying = Some((seq, text));
            app.picked = None;
        }
        KeyCode::Char('e') if mine && !redacted => {
            // Only our own, and the reader would ignore anybody else's anyway
            // — refusing here is what tells somebody that, rather than letting
            // them type an edit that quietly goes nowhere.
            app.editing = Some(seq);
            app.input = text;
            app.picked = None;
        }
        KeyCode::Char('e') if !mine => {
            app.trouble.message =
                Some("only the person who wrote a message can rewrite it".into());
        }
        KeyCode::Char('d') if !redacted => {
            let Some(at) = selected_index(open, app) else {
                return;
            };
            let channel = open[at].channel;
            app.picked = None;
            match chat.redact(&channel, seq).await {
                Ok(r) if !r.left_behind.is_empty() => {
                    app.trouble.message = Some(format!(
                        "deleted, but {} file(s) could not be detached and may still \
                         be fetchable by anyone who read it",
                        r.left_behind.len()
                    ));
                }
                Ok(_) => {}
                Err(e) => app.trouble.message = Some(e.to_string()),
            }
            settle_here(chat, open, app, at).await;
        }
        _ => {}
    }
}

async fn handle_key(
    chat: &mut Chat,
    open: &mut Vec<Open>,
    app: &mut App,
    code: KeyCode,
    mods: KeyModifiers,
) {
    if mods.contains(KeyModifiers::CONTROL) {
        match code {
            KeyCode::Char('c') => app.should_quit = true,
            // Adding somebody is Ctrl-N and not a bare letter. A bare binding
            // that only applies while the input is empty means a message
            // cannot begin with that letter, and nothing tells you why —
            // the keystroke is simply swallowed.
            KeyCode::Char('n') => app.adding = Some(String::new()),
            _ => {}
        }
        return;
    }

    if let Some(buf) = &mut app.adding {
        match code {
            KeyCode::Esc => app.adding = None,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Enter => {
                let typed = buf.trim().to_string();
                app.adding = None;
                add_contact(chat, open, app, &typed).await;
            }
            _ => {}
        }
        return;
    }

    // The directory and the command list are views over the transcript, so Esc
    // puts them away rather than leaving the reader stuck looking at one.
    if code == KeyCode::Esc && app.helping {
        app.helping = false;
        return;
    }
    if code == KeyCode::Esc && app.searching {
        app.searching = false;
        app.hits.clear();
        app.query.clear();
        return;
    }
    if code == KeyCode::Esc && !app.found.is_empty() {
        app.found.clear();
        return;
    }

    // Picking a message is a mode, and it has to be: reacting, replying and
    // rewriting all act on one message, and there is no way to say which
    // without either a mode or a sequence number typed by hand. Bare letters
    // are safe here and not outside it — the transcript shows the cursor and
    // the key line changes — which is the difference from a binding that
    // silently eats the first letter of a message.
    if app.picked.is_some() {
        pick_mode(chat, open, app, code).await;
        return;
    }

    // Esc with nothing else to dismiss enters it, on the newest message, which
    // is the one somebody almost always means.
    if code == KeyCode::Esc {
        if app.editing.take().is_some() || app.replying.take().is_some() {
            // Abandon what the input line was about to do first. Leaving an
            // edit half-typed and then entering pick mode would send it to the
            // wrong place on the next Enter.
            app.input.clear();
            return;
        }
        if !app.said.is_empty() {
            app.picked = Some(app.said.len() - 1);
        }
        return;
    }

    match code {
        // Changing conversation lands at the newest of the new one. Carrying
        // a line offset across would put somebody at an arbitrary depth in a
        // conversation they have just arrived in.
        KeyCode::Tab | KeyCode::Down => {
            app.select_next();
            app.scroll = 0;
            clear_unread(open, app);
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.select_previous();
            app.scroll = 0;
            clear_unread(open, app);
        }
        // Scrolling from the keyboard, because the wheel needs `/mouse on`
        // and the mouse stays the terminal's until it is asked for. A feature
        // that only exists in a mode nobody has turned on is not one.
        KeyCode::PageUp => app.scroll += app.page,
        KeyCode::PageDown => app.scroll = app.scroll.saturating_sub(app.page),
        KeyCode::End => app.scroll = 0,
        KeyCode::Home => app.scroll = usize::MAX,
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Char(c) => app.input.push(c),
        KeyCode::Enter => {
            let text = std::mem::take(&mut app.input);
            if text.trim().is_empty() {
                // An edit emptied to nothing is a deletion asked for the wrong
                // way. Say so rather than posting an empty message: /redact
                // removes the words at the exchange, and an empty edit would
                // leave them there.
                if app.editing.take().is_some() {
                    app.trouble.message =
                        Some("an edit cannot be empty — pick it and press d to delete it".into());
                }
                app.replying = None;
                return;
            }

            // A rewrite or a reply, before the line is read as a command:
            // "/save" typed into an edit is text somebody meant to keep, not
            // an instruction.
            if let Some(target) = app.editing.take() {
                let Some(at) = selected_index(open, app) else { return };
                let channel = open[at].channel;
                if let Err(e) = chat.edit(&channel, target, SipPost::text(&text)).await {
                    app.trouble.message = Some(e.to_string());
                }
                settle_here(chat, open, app, at).await;
                return;
            }
            if let Some((target, _)) = app.replying.take() {
                let Some(at) = selected_index(open, app) else { return };
                let channel = open[at].channel;
                if let Err(e) = chat.reply(&channel, target, &text).await {
                    app.trouble.message = Some(e.to_string());
                }
                settle_here(chat, open, app, at).await;
                return;
            }

            let cmd = Command::parse(&text);
            // `/new` is the one command that needs no conversation, and it has
            // to be: with none open there is nothing selected, and requiring a
            // selection would mean the first group could never be made.
            // Commands that need no conversation, and cannot require one:
            // with none open there is nothing selected, so demanding a
            // selection would mean the first channel could never be made or
            // found.
            match &cmd {
                Command::New(name) => {
                    let made = chat.create_group(name, &[]).await;
                    let note = match &made {
                        Ok(_) => format!("made {name} — /invite <key> to add somebody"),
                        Err(e) => e.to_string(),
                    };
                    settle(chat, open, app, made.ok(), note).await;
                    return;
                }
                Command::Public(name) => {
                    let made = chat.create_public(name, "").await;
                    let note = match &made {
                        Ok(_) => format!("made #{name} — anybody can find and join it"),
                        Err(e) => e.to_string(),
                    };
                    settle(chat, open, app, made.ok(), note).await;
                    return;
                }
                Command::Find(query) => {
                    match chat.find(query, 0).await {
                        Ok(listing) => {
                            app.found_total = listing.total;
                            app.found = listing
                                .channels
                                .into_iter()
                                .map(|c| Found {
                                    channel: c.channel,
                                    instance: c.instance,
                                    name: c.name,
                                    topic: c.topic,
                                    members: c.members,
                                })
                                .collect();
                            if app.found.is_empty() {
                                app.trouble.message =
                                    Some("no public channels match".into());
                            }
                        }
                        Err(e) => app.trouble.message = Some(e.to_string()),
                    }
                    return;
                }
                Command::Join(n) => {
                    let Some(found) = app.found.get(*n) else {
                        app.trouble.message =
                            Some("no such number — /find first".into());
                        return;
                    };
                    // The incarnation comes from the directory row we found it
                    // in — a joiner has to sign against it and cannot ask
                    // `Info`, which wants the membership this is acquiring.
                    let (channel, name) = (found.channel, found.name.clone());
                    let instance = found.instance;
                    let note = match chat.join(&channel, instance).await {
                        Ok(()) => format!("joined #{name}"),
                        Err(e) => e.to_string(),
                    };
                    app.found.clear();
                    settle(chat, open, app, Some(channel), note).await;
                    return;
                }
                _ => {}
            }

            // The profile and block commands are about this account rather
            // than about a conversation, and blocking in particular must work
            // when there is nothing open: somebody being written to by a
            // stranger should not have to open the conversation to stop it.
            if matches!(cmd, Command::Help) {
                app.helping = true;
                return;
            }
            // The terminal, not the exchange, so it is settled here rather
            // than in `account_command`.
            if let Command::Mouse(want) = cmd {
                let on = want.unwrap_or(!app.mouse);
                let note = match set_mouse(on) {
                    Ok(()) => {
                        app.mouse = on;
                        if on {
                            "the mouse is the client's — hover a message for its full \
                             time. Selecting text now needs Shift (Option on macOS), \
                             and /mouse off gives it back"
                                .to_string()
                        } else {
                            "the mouse is the terminal's again — selection and copy work \
                             as usual, and hovering says nothing"
                                .to_string()
                        }
                    }
                    Err(e) => format!("could not change the mouse: {e}"),
                };
                // Nothing is under the pointer once it has stopped being
                // watched, and a stale timestamp would sit in the status line
                // for good.
                if !app.mouse {
                    app.hovered = None;
                }
                match selected_index(open, app) {
                    Some(i) => open[i].note = Some((note, std::time::Instant::now())),
                    None => app.trouble.message = Some(note),
                }
                return;
            }
            if matches!(
                cmd,
                Command::Profile(_)
                    | Command::Block(_)
                    | Command::Unblock(_)
                    | Command::Blocked
                    | Command::Whoami
                    | Command::Reconnect
            ) {
                let note = match account_command(chat, cmd).await {
                    Ok(note) => note,
                    Err(e) => e.to_string(),
                };
                // On the conversation when there is one: the next redraw
                // rebuilds `app.trouble` from the selected conversation, so a
                // note left only on `app` is gone before anybody reads it.
                match selected_index(open, app) {
                    Some(i) => open[i].note = Some((note, std::time::Instant::now())),
                    None => app.trouble.message = Some(note),
                }
                return;
            }

            let Some(i) = selected_index(open, app) else {
                app.trouble.message =
                    Some("no conversation selected — ^N adds somebody, /new makes a group".into());
                return;
            };
            let channel = open[i].channel;
            // These change which conversations exist, so the list is rebuilt
            // rather than patched — the exchange is the authority on what we
            // are in, and guessing at it here is how the two drift apart.
            let restructured = matches!(cmd, Command::Leave | Command::CloseConfirmed);
            // What was typed, kept back in case sending it fails. `text` was
            // taken out of the input line before any of this, so a refusal or
            // a dropped connection destroyed it — the one loss in this client
            // that trying again cannot undo.
            let typed = matches!(cmd, Command::Send(_)).then(|| text.clone());
            let outcome = match cmd {
                Command::Send(text) => chat.send(&channel, &text).await.map(|_| None),
                Command::File(path) => send_file(chat, &channel, &path).await.map(Some),
                Command::Save(seq, path) => save_file(chat, &open[i], seq, &path).await.map(Some),
                // Handled above: these need no conversation.
                Command::New(_)
                | Command::Public(_)
                | Command::Find(_)
                | Command::Join(_)
                | Command::Profile(_)
                | Command::Block(_)
                | Command::Unblock(_)
                | Command::Blocked
                | Command::Whoami
                | Command::Reconnect
                | Command::Mouse(_)
                | Command::Help => Ok(None),
                Command::Name(name) => match chat.set_name(&channel, &name).await {
                    Ok(_) => Ok(Some(format!("renamed to {name}"))),
                    Err(e) => Err(e),
                },
                Command::Topic(topic) => match chat.set_topic(&channel, &topic).await {
                    Ok(_) => Ok(Some(format!("topic set to {topic}"))),
                    Err(e) => Err(e),
                },
                Command::Avatar(path) => set_avatar(chat, &channel, path.as_deref())
                    .await
                    .map(Some),
                Command::SaveAvatar(path) => {
                    save_avatar(chat, &open[i], &path).await.map(Some)
                }
                Command::Invite(key) => match key.parse::<PubKey>() {
                    Ok(who) => match chat.invite(&channel, &who).await {
                        // SIP-17 says to check after inviting: this is the one
                        // report of a member who can fetch entries and open
                        // none of them, and nothing else would say so.
                        Ok(()) => {
                            let waiting = chat
                                .stranded(&channel)
                                .await
                                .map(|a| a.devices.len())
                                .unwrap_or(0);
                            Ok(Some(if waiting > 0 {
                                format!(
                                    "invited {} — {waiting} device(s) still hold no key",
                                    short(&who)
                                )
                            } else {
                                format!("invited {}", short(&who))
                            }))
                        }
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(ChatError::Protocol(format!("bad key: {e}"))),
                },
                Command::Kick(key) => match key.parse::<PubKey>() {
                    Ok(who) => chat.remove(&channel, &who).await.map(|()| {
                        Some(format!(
                            "removed {} and rotated — what follows is not theirs",
                            short(&who)
                        ))
                    }),
                    Err(e) => Err(ChatError::Protocol(format!("bad key: {e}"))),
                },
                Command::Rotate => chat.rotate(&channel).await.map(|epoch| {
                    Some(format!(
                        "rotated to epoch {epoch} — everyone here has the new key, \
                         and what came before is unchanged"
                    ))
                }),
                Command::Redact(target) => {
                    chat.redact(&channel, target).await.map(|r| {
                        // Say which of the two halves happened. "Deleted" when
                        // a file was left behind would be a claim about
                        // somebody else's copy that we cannot make.
                        let mut said = format!("redacted {target} — the exchange no longer holds it");
                        match r.detached {
                            0 => {}
                            1 => said += ", and the file it carried",
                            n => said += &format!(", and the {n} files it carried"),
                        }
                        if !r.left_behind.is_empty() {
                            let n = r.left_behind.len();
                            let files = if n == 1 { "file" } else { "files" };
                            said += &format!(
                                "; {n} {files} could not be detached and may still be \
                                 fetchable by anyone who read the message"
                            );
                        } else if !r.opened {
                            said += "; this client could not read it, so any file it carried is still attached";
                        }
                        Some(said)
                    })
                }
                Command::Leave => chat.leave(&channel).await.map(|()| {
                    Some("left — it will be gone from the list next time".to_string())
                }),
                Command::Op(ref key) | Command::Deop(ref key) => {
                    let admin = matches!(cmd, Command::Op(_));
                    match key.parse::<PubKey>() {
                        Ok(who) => {
                            let role = if admin { Role::Admin } else { Role::Member };
                            match chat.grant(&channel, &who, role).await {
                                Ok(()) if admin => Ok(Some(format!(
                                    "{} is an admin here — they can rename it, invite, \
                                     remove and set retention",
                                    short(&who)
                                ))),
                                Ok(()) => Ok(Some(format!("{} is an ordinary member again", short(&who)))),
                                // The exchange refuses this in a direct
                                // message, where both parties are admins from
                                // the start; say that rather than pass on a
                                // bare refusal.
                                Err(ChatError::Refused(_, r))
                                    if r.code == RefusalCode::DirectMessage =>
                                {
                                    Err(ChatError::Protocol(
                                        "a direct message has no roles to give — both of \
                                         you are admins of it already"
                                            .into(),
                                    ))
                                }
                                Err(e) => Err(e),
                            }
                        }
                        Err(e) => Err(ChatError::Protocol(format!("bad key: {e}"))),
                    }
                }
                Command::Retain(secs, max) => {
                    chat.set_retention(&channel, secs, max).await.map(|()| {
                        Some(format!(
                            "keeping {secs} seconds{} — anything older is already gone",
                            match max {
                                0 => String::new(),
                                n => format!(" and at most {n} messages"),
                            }
                        ))
                    })
                }
                // Asked rather than done. There is no tombstone and no undo:
                // the entries, the envelopes and the attachments all go, and
                // the identifier becomes free for an unrelated channel.
                Command::Close => Ok(Some(
                    "/close yes — this destroys every message here for everyone, \
                     permanently, and cannot be undone"
                        .to_string(),
                )),
                Command::CloseConfirmed => match chat.close(&channel).await {
                    Ok(()) => {
                        // Only after the exchange has confirmed. Dropping our
                        // own keys first would destroy the conversation twice
                        // over if the call turned out to have failed.
                        let _ = chat.store().forget_channel(&channel);
                        Ok(Some("closed — it is gone for everyone".to_string()))
                    }
                    Err(e) => Err(e),
                },
                Command::Read => match chat.marks(&channel).await {
                    Ok(marks) => Ok(Some(read_marks(&marks, &chat.me, &open[i]))),
                    Err(e) => Err(e),
                },
                Command::Forward(seq, to) => {
                    match open.get(to).map(|o| (o.channel, o.label.clone())) {
                        Some((target, label)) if target != channel => {
                            forward_file(chat, &open[i], seq, &target).await.map(|n| {
                                Some(format!("forwarded {n} to {label} — the file was not \
                                              uploaded again"))
                            })
                        }
                        Some(_) => Err(ChatError::Protocol(
                            "that is this conversation".into(),
                        )),
                        None => Err(ChatError::Protocol(format!(
                            "there is no conversation {}",
                            to + 1
                        ))),
                    }
                }
                Command::Search(query) => {
                    // Here, against what this client holds, because that is
                    // the only place it can happen: the exchange cannot read a
                    // sealed entry, so it could not search one if it wanted
                    // to. The side effect is that it never learns what
                    // somebody looked for.
                    let needle = query.to_lowercase();
                    let names = name_map(chat, open, open.get(i));
                    app.hits = open[i]
                        .timeline
                        .messages()
                        .filter(|m| !m.redacted)
                        .filter_map(|m| {
                            let text = m.post.body_text()?;
                            let at_byte = text.to_lowercase().find(&needle)?;
                            Some(ui::Hit {
                                seq: m.seq,
                                who: ui::author(
                                    &names.get(&m.account).cloned().unwrap_or_default(),
                                    &m.account.to_string(),
                                    m.account == chat.me,
                                ),
                                at: m.posted,
                                text: text.to_string(),
                                at_byte,
                                len: needle.len(),
                            })
                        })
                        .collect();
                    // Newest first: the thing somebody is looking for is more
                    // often recent than ancient.
                    app.hits.reverse();
                    app.query = query.clone();
                    app.searching = true;
                    return;
                }
                Command::Who => match chat.info(&channel).await {
                    Ok(info) => {
                        // Ask about anybody we have no name for. `/who` is the
                        // one place a member who has never spoken is listed,
                        // and they are exactly who somebody runs it to
                        // identify.
                        let members: Vec<PubKey> =
                            info.members.iter().map(|m| m.account).collect();
                        // Asked for, not cached: somebody typing /who is
                        // putting the question, and answering it out of an
                        // hour-old note is refusing to answer it.
                        let _ = chat.refetch_profiles(&members, now()).await;
                        Ok(Some(
                            info.members
                                .iter()
                                .map(|m| {
                                    let name = chat
                                        .display_name(&m.account)
                                        .unwrap_or_default();
                                    // The whole key, not a stub of it. Since
                                    // the transcript stopped showing keys this
                                    // is the list somebody runs to find one,
                                    // and half a key answers nothing.
                                    format!(
                                        "{}{} {}",
                                        ui::author(&name, &m.account.to_string(), false),
                                        if m.role == Role::Admin { "*" } else { "" },
                                        m.account
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join("   "),
                        ))
                    }
                    Err(e) => Err(e),
                },
                Command::Unknown(word) => Err(ChatError::Protocol(format!(
                    "no such command {word:?} — /file <path> sends one, \
                     /save <n> <path> keeps one"
                ))),
            };
            // Poll first, then say what happened. The other order loses both
            // the confirmation and the error: a successful poll clears stale
            // trouble, and anything set beforehand is exactly what it clears.
            poll_one(chat, &mut open[i], app).await;
            let note = match outcome {
                Ok(note) => {
                    open[i].note = note.clone().map(|n| (n, std::time::Instant::now()));
                    note
                }
                Err(ChatError::NotReady(_)) => {
                    open[i].waiting = true;
                    None
                }
                Err(e) => {
                    open[i].note = Some((e.to_string(), std::time::Instant::now()));
                    // Back into the composer, where somebody can press Enter
                    // again once the light is green.
                    if let Some(text) = typed {
                        app.input = text;
                    }
                    None
                }
            };
            if restructured
                && let Ok(fresh) = sync_channels(chat).await
            {
                *open = fresh;
                if let Some(n) = note
                    && let Some(last) = open.last_mut()
                {
                    last.note = Some((n, std::time::Instant::now()));
                }
                app.selected = open.last().map(|o| o.channel);
            }
        }
        _ => {}
    }
}

/// What a line typed into the message box means.
///
/// A leading slash is a command and everything else is a message. There is no
/// escape for a message that begins with a slash, which is a real limitation
/// and a smaller one than a file-sending client without a way to send files.
enum Command {
    Send(String),
    File(std::path::PathBuf),
    Save(u64, std::path::PathBuf),
    /// `/new <name>` — a private group, which you can then invite people into.
    New(String),
    /// `/public <name>` — a channel anybody may find and join.
    Public(String),
    /// `/find [query]` — search the public directory.
    Find(String),
    /// `/join <n>` — join a channel from the last search.
    Join(usize),
    /// `/invite <key>` — add somebody, and give them the key.
    Invite(String),
    /// `/kick <key>` — remove somebody, and rotate so what follows is not theirs.
    Kick(String),
    /// `/name <name>` — rename, as a sealed entry the exchange cannot read.
    Name(String),
    /// `/topic <text>` — set what this channel is for, likewise sealed.
    Topic(String),
    /// `/avatar <path>` — set the channel's picture, or `/avatar off`.
    Avatar(Option<std::path::PathBuf>),
    /// `/avatar save <path>` — write the current picture out. A terminal
    /// cannot draw one, so saving it is how it is looked at.
    SaveAvatar(std::path::PathBuf),
    /// `/rotate` — mint a new key for everyone currently here.
    Rotate,
    /// `/leave` — leave this channel.
    Leave,
    /// `/redact <n>` — delete a message you posted, by its number.
    Redact(u64),
    /// `/who` — who is in here.
    Who,
    /// `/profile [name] [| title]` — what to say about ourselves, or nothing
    /// to see what we currently say.
    Profile(Option<(String, String)>),
    /// `/block <key>` — stop an account reaching us.
    Block(String),
    /// `/unblock <key>` — let it again.
    Unblock(String),
    /// `/blocked` — who we have blocked. Answered to nobody else.
    Blocked,
    /// `/help` — everything the client can do, over the transcript.
    Help,
    /// `/whoami` — this account's key, in full.
    ///
    /// The header carries six characters of it, which is enough to recognise
    /// yourself by and not enough to be compared against anything. This is
    /// where the whole key lives now.
    Whoami,
    /// `/reconnect` — try the exchange again now, whatever the backoff had
    /// planned. So that a red light has an answer that is not "restart it".
    Reconnect,
    /// `/mouse [on|off]` — whether the client takes the mouse.
    Mouse(Option<bool>),
    /// `/search <text>` — find it in this conversation.
    Search(String),
    /// `/op <key>` — make somebody an admin here, so they can rename it,
    /// invite, remove and set retention.
    Op(String),
    /// `/deop <key>` — take that back.
    Deop(String),
    /// `/retain <secs> [max]` — how long this channel keeps what is said here.
    Retain(u32, u32),
    /// `/close` — end this channel. Irreversible, so it asks first.
    Close,
    /// `/close yes` — the answer to that question.
    CloseConfirmed,
    /// `/read` — how far everybody else has read.
    Read,
    /// `/forward <n> <m>` — send message `n`'s file into conversation `m` from
    /// the sidebar, without uploading it again.
    Forward(u64, usize),
    Unknown(String),
}

impl Command {
    fn parse(line: &str) -> Command {
        let trimmed = line.trim();
        if !trimmed.starts_with('/') {
            return Command::Send(line.to_string());
        }
        // Verb, then the whole of the rest. Splitting into fixed words is what
        // made `/new release check` a group called "release" — a name, a path
        // and a topic are all free text, and quoting them would be a rule to
        // remember for no gain.
        let (verb, rest) = match trimmed.find(char::is_whitespace) {
            Some(i) => (&trimmed[..i], trimmed[i..].trim()),
            None => (trimmed, ""),
        };
        let first = rest.split_whitespace().next().unwrap_or("");
        match verb {
            "/file" if !rest.is_empty() => Command::File(expand(rest)),
            "/file" => Command::Unknown("/file needs a path".into()),
            "/save" => {
                let path = rest[first.len()..].trim();
                match (first.parse::<u64>(), path.is_empty()) {
                    (Ok(seq), false) => Command::Save(seq, expand(path)),
                    (Err(_), _) if !first.is_empty() => {
                        Command::Unknown(format!("{first} is not a message number"))
                    }
                    _ => Command::Unknown("/save needs a message number and a path".into()),
                }
            }
            "/new" if !rest.is_empty() => Command::New(rest.to_string()),
            "/new" => Command::Unknown("/new needs a name".into()),
            "/public" if !rest.is_empty() => Command::Public(rest.to_string()),
            "/public" => Command::Unknown("/public needs a name".into()),
            // An empty query lists everything, which is the useful default on
            // a small exchange and what SIP-16 specifies.
            "/find" => Command::Find(rest.to_string()),
            "/join" => match first.parse::<usize>() {
                Ok(n) if n >= 1 => Command::Join(n - 1),
                _ => Command::Unknown(
                    "/join takes a number from the last /find".into(),
                ),
            },
            "/name" if !rest.is_empty() => Command::Name(rest.to_string()),
            "/name" => Command::Unknown("/name needs a name".into()),
            "/topic" if !rest.is_empty() => Command::Topic(rest.to_string()),
            "/topic" => Command::Unknown("/topic needs some text".into()),
            "/avatar" if first == "off" => Command::Avatar(None),
            "/avatar" if first == "save" => {
                let path = rest[first.len()..].trim();
                if path.is_empty() {
                    Command::Unknown("/avatar save needs a path".into())
                } else {
                    Command::SaveAvatar(expand(path))
                }
            }
            "/avatar" if !rest.is_empty() => Command::Avatar(Some(expand(rest))),
            "/avatar" => Command::Unknown(
                "/avatar <path> sets the picture, /avatar save <path> writes it out, \
                 /avatar off removes it"
                    .into(),
            ),
            "/invite" if !first.is_empty() => Command::Invite(first.to_string()),
            "/invite" => Command::Unknown("/invite needs a public key".into()),
            "/kick" if !first.is_empty() => Command::Kick(first.to_string()),
            "/kick" => Command::Unknown("/kick needs a public key".into()),
            "/rotate" => Command::Rotate,
            "/leave" => Command::Leave,
            "/redact" => match first.parse::<u64>() {
                Ok(n) if n > 0 => Command::Redact(n),
                _ => Command::Unknown(
                    "/redact takes the number of a message you posted".into(),
                ),
            },
            "/who" => Command::Who,
            // The name and the title are both free text, so they are separated
            // by a character neither would contain rather than by a space —
            // `/profile Ada Lovelace` is a name, not a name and a title.
            "/profile" if rest.is_empty() => Command::Profile(None),
            // Publishing an empty record, which is how a name is taken back.
            // Without this a name could be set and never unset.
            "/profile" if first == "off" => {
                Command::Profile(Some((String::new(), String::new())))
            }
            "/profile" => {
                let (name, title) = match rest.split_once('|') {
                    Some((n, t)) => (n.trim().to_string(), t.trim().to_string()),
                    None => (rest.to_string(), String::new()),
                };
                Command::Profile(Some((name, title)))
            }
            "/block" if !first.is_empty() => Command::Block(first.to_string()),
            "/block" => Command::Unknown("/block needs a public key".into()),
            "/unblock" if !first.is_empty() => Command::Unblock(first.to_string()),
            "/unblock" => Command::Unknown("/unblock needs a public key".into()),
            "/blocked" => Command::Blocked,
            "/help" | "/?" => Command::Help,
            "/whoami" => Command::Whoami,
            "/reconnect" => Command::Reconnect,
            "/mouse" => match rest.trim() {
                "" => Command::Mouse(None),
                "on" => Command::Mouse(Some(true)),
                "off" => Command::Mouse(Some(false)),
                other => Command::Unknown(format!("/mouse takes on or off, not {other:?}")),
            },
            "/search" if !rest.is_empty() => Command::Search(rest.to_string()),
            "/search" => Command::Unknown("/search needs something to look for".into()),
            "/op" if !first.is_empty() => Command::Op(first.to_string()),
            "/op" => Command::Unknown("/op needs a public key".into()),
            "/deop" if !first.is_empty() => Command::Deop(first.to_string()),
            "/deop" => Command::Unknown("/deop needs a public key".into()),
            "/retain" => {
                let mut words = rest.split_whitespace();
                match (
                    words.next().map(str::parse::<u32>),
                    words.next().map(str::parse::<u32>),
                ) {
                    (Some(Ok(secs)), None) => Command::Retain(secs, 0),
                    (Some(Ok(secs)), Some(Ok(max))) => Command::Retain(secs, max),
                    _ => Command::Unknown(
                        "/retain <seconds> [max messages] — narrowing it deletes what \
                         falls outside straight away"
                            .into(),
                    ),
                }
            }
            "/close" if first == "yes" => Command::CloseConfirmed,
            "/close" => Command::Close,
            "/read" => Command::Read,
            "/forward" => {
                let mut words = rest.split_whitespace();
                match (
                    words.next().map(str::parse::<u64>),
                    words.next().map(str::parse::<usize>),
                ) {
                    (Some(Ok(seq)), Some(Ok(to))) if seq > 0 && to > 0 => {
                        // Numbered from one on screen, indexed from zero here.
                        Command::Forward(seq, to - 1)
                    }
                    _ => Command::Unknown(
                        "/forward <message number> <conversation number, counting down \
                         the list from 1>"
                            .into(),
                    ),
                }
            }
            other => Command::Unknown(other.to_string()),
        }
    }
}

/// `~` on the front of a path, because typing it is reflex.
fn expand(path: &str) -> std::path::PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => dirs::home_dir()
            .map(|h| h.join(rest))
            .unwrap_or_else(|| std::path::PathBuf::from(path)),
        None => std::path::PathBuf::from(path),
    }
}

/// Seal a file, upload it, and send a message referencing it.
async fn send_file(
    chat: &mut Chat,
    channel: &[u8; 32],
    path: &std::path::Path,
) -> std::result::Result<String, ChatError> {
    use sqex_chat::attach::describe;
    use sqex_proto::message::{Part, Post as SipPost};

    // Asked, not assumed: an exchange that has not raised its request cap
    // conforms by choosing a smaller chunk, and guessing fails on the first
    // Put with nothing to say why.
    let limits = chat.blob_limits().await?;
    let prepared = chat.prepare_file(path, limits.chunk as usize)?;
    let chunks = prepared.chunks();
    let attachment = chat.upload(channel, &prepared).await?;
    let note = format!("sent {} in {chunks} chunk(s)", describe(&attachment));

    let mut post = SipPost::default();
    post.parts.push(Part::Attachment(attachment));
    chat.send_post(channel, post).await?;
    Ok(note)
}

/// How far everybody else has read, in words.
///
/// A direct message has one other person, so "read to here" is the whole of
/// what there is to say. A group has several, and naming them is the point —
/// but a name is a claim, so each is shown with its key beside it (SIP-21).
///
/// An account that opted out of receipts reports `read: 0` and a real
/// `delivered`: the exchange withholds their reading, not their existence, and
/// saying "has not read any of it" of somebody who simply declined to say
/// would be inventing a fact.
fn read_marks(marks: &[sqex_proto::channel::Mark], me: &PubKey, conv: &Open) -> String {
    let others: Vec<&sqex_proto::channel::Mark> =
        marks.iter().filter(|m| m.account != *me).collect();
    if others.is_empty() {
        return "nobody else here yet".into();
    }
    others
        .iter()
        .map(|m| {
            let who = if conv.peer.is_some() {
                conv.label.clone()
            } else {
                short(&m.account)
            };
            match (m.read, m.delivered) {
                (0, 0) => format!("{who}: nothing delivered"),
                // Zero is ambiguous and has to be reported as ambiguous: it is
                // somebody who has read nothing, somebody who has opted out of
                // saying, and somebody whose client does not publish a mark,
                // all rendered identically by the exchange — on purpose, since
                // a refusal you can detect is not a refusal.
                (0, d) => format!("{who}: delivered to {d}, no read mark"),
                (r, _) => format!("{who}: read to {r}"),
            }
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Set or remove the channel's picture.
///
/// The upload is the same path a file takes, because it is one: an avatar is
/// an ordinary attachment, sealed under its own key and named by the hash of
/// its ciphertext, so the exchange stores a picture it cannot look at.
async fn set_avatar(
    chat: &mut Chat,
    channel: &[u8; 32],
    path: Option<&std::path::Path>,
) -> std::result::Result<String, ChatError> {
    let Some(path) = path else {
        chat.set_avatar(channel, None).await?;
        return Ok("the picture was removed".into());
    };
    let limits = chat.blob_limits().await?;
    let prepared = chat.prepare_file(path, limits.chunk as usize)?;
    let attachment = chat.upload(channel, &prepared).await?;
    chat.set_avatar(channel, Some(attachment)).await?;
    Ok(format!(
        "picture set from {} — /avatar save <path> writes it out",
        path.display()
    ))
}

/// Send a message's file into another conversation without uploading it again.
///
/// Two halves, as SIP-18 has it: the exchange is told the second channel now
/// references the blob, and the second channel is sent a message carrying the
/// reference. The bytes never move — one copy, named by the hash of its
/// ciphertext, and the key travels inside the sealed message.
///
/// Which means forwarding a file hands the recipient the key to it. That is
/// what forwarding is, and there is nothing to soften about it.
async fn forward_file(
    chat: &mut Chat,
    from: &Open,
    seq: u64,
    to: &[u8; 32],
) -> std::result::Result<String, ChatError> {
    use sqex_chat::attach::describe;
    use sqex_proto::message::{Part, Post as SipPost};

    let attachment = from
        .timeline
        .get(seq)
        .ok_or_else(|| ChatError::Protocol(format!("no message {seq} here")))?
        .post
        .attachments()
        .next()
        .ok_or_else(|| ChatError::Protocol(format!("message {seq} has no file")))?
        .clone();

    // The reference first. A message naming a blob the destination has no
    // claim on would be a message its readers cannot fetch, which looks
    // exactly like a file that has expired.
    chat.attach(to, &attachment.blob).await?;
    let note = describe(&attachment);
    let mut post = SipPost::default();
    post.parts.push(Part::Attachment(attachment));
    chat.send_post(to, post).await?;
    Ok(note)
}

/// Write the channel's picture out.
///
/// There is nothing to draw it on, and pretending otherwise — a coloured block
/// approximation — would be showing somebody a thing that is not the picture
/// at the moment they are trying to see what it is.
async fn save_avatar(
    chat: &mut Chat,
    conv: &Open,
    path: &std::path::Path,
) -> std::result::Result<String, ChatError> {
    let attachment = conv
        .timeline
        .avatar
        .clone()
        .ok_or_else(|| ChatError::Protocol("this channel has no picture".into()))?;
    let bytes = chat.download(&attachment).await?;
    let target = if path.is_dir() {
        let name = sqex_chat::file_name(&attachment).unwrap_or_else(|| "avatar".into());
        let leaf = std::path::Path::new(&name)
            .file_name()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("avatar"));
        path.join(leaf)
    } else {
        path.to_path_buf()
    };
    if target.exists() {
        return Err(ChatError::Protocol(format!(
            "{} already exists — nothing was overwritten",
            target.display()
        )));
    }
    std::fs::write(&target, &bytes)
        .map_err(|e| ChatError::Protocol(format!("{}: {e}", target.display())))?;
    Ok(format!("saved {} bytes to {}", bytes.len(), target.display()))
}

/// Fetch the attachment on message `seq` and write it out.
async fn save_file(
    chat: &mut Chat,
    conv: &Open,
    seq: u64,
    path: &std::path::Path,
) -> std::result::Result<String, ChatError> {
    let message = conv
        .timeline
        .get(seq)
        .ok_or_else(|| ChatError::Protocol(format!("no message {seq} here")))?;
    let attachment = message
        .post
        .attachments()
        .next()
        .ok_or_else(|| ChatError::Protocol(format!("message {seq} has no attachment")))?
        .clone();

    let bytes = chat.download(&attachment).await?;
    // A directory means "in here, under the name it came with" — the common
    // case, and the one where the sender's name is least dangerous, since it
    // is only ever a leaf.
    let target = if path.is_dir() {
        let name = sqex_chat::file_name(&attachment).unwrap_or_else(|| format!("blob-{seq}"));
        let leaf = std::path::Path::new(&name)
            .file_name()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(format!("blob-{seq}")));
        path.join(leaf)
    } else {
        path.to_path_buf()
    };
    if target.exists() {
        return Err(ChatError::Protocol(format!(
            "{} already exists — nothing was overwritten",
            target.display()
        )));
    }
    std::fs::write(&target, &bytes)
        .map_err(|e| ChatError::Protocol(format!("{}: {e}", target.display())))?;
    Ok(format!("saved {} bytes to {}", bytes.len(), target.display()))
}

/// Rebuild the conversation list and land on `channel`, carrying a note.
///
/// The list is rebuilt rather than patched because the exchange is the
/// authority on what we are in, and guessing at it here is how the two drift
/// apart. On failure the list is unchanged and the note must still survive —
/// an earlier version put it on the last row, which did not exist when the
/// first channel was the one that failed, so the only thing that went wrong
/// went nowhere.
async fn settle(
    chat: &mut Chat,
    open: &mut Vec<Open>,
    app: &mut App,
    channel: Option<[u8; 32]>,
    note: String,
) {
    match (channel, sync_channels(chat).await) {
        (Some(channel), Ok(fresh)) => {
            *open = fresh;
            app.selected = Some(channel);
            match open.iter_mut().find(|o| o.channel == channel) {
                Some(o) => o.note = Some((note, std::time::Instant::now())),
                // The channel we were told to land on is not in the list —
                // left, or closed under us. The note still has to be said.
                None => app.trouble.message = Some(note),
            }
        }
        _ => app.trouble.message = Some(note),
    }
}

async fn add_contact(chat: &mut Chat, open: &mut Vec<Open>, app: &mut App, typed: &str) {
    let Ok(account) = typed.parse::<PubKey>() else {
        app.trouble.message = Some(format!("{typed:?} is not a base58 identity"));
        return;
    };
    if account == chat.me {
        app.trouble.message = Some("that is your own key".into());
        return;
    }
    if open.iter().any(|o| o.peer == Some(account)) {
        return;
    }
    let label = short(&account);
    if let Err(e) = chat.store().add_contact(&account, &label, now()) {
        app.trouble.message = Some(e.to_string());
        return;
    }
    let channel = chat.dm_with(&account);
    let mut conv = Open {
        peer: Some(account),
        public: false,
        label,
        channel,
        last_at: now(),
        members: 0,
        marks: Vec::new(),
        marks_at: None,
        read_to: 0,
        divider: None,
        admins: vec![chat.me, account],
        timeline: Timeline::new(),
        timeline_len: 0,
        trouble: Trouble::default(),
        note: None,
        typing: false,
        unread: 0,
        waiting: false,
    };
    match chat.open_dm(&account).await {
        Ok(_) => {}
        Err(ChatError::NotReady(_)) => conv.waiting = true,
        Err(e) => conv.trouble.message = Some(e.to_string()),
    }
    let landed = conv.channel;
    open.push(conv);
    app.selected = Some(landed);
}

fn selected_index(open: &[Open], app: &App) -> Option<usize> {
    let row = app.selected_row()?;
    open.iter().position(|o| o.channel == row.channel)
}

fn clear_unread(open: &mut [Open], app: &App) {
    if let Some(row) = app.selected_row()
        && let Some(o) = open.iter_mut().find(|o| o.channel == row.channel)
    {
        o.unread = 0;
    }
}

/// Rebuild what is on screen from what the client knows.
/// Every display name we hold for the people in `conv`.
///
/// Built here rather than looked up in the renderer, which has no store — and
/// deliberately a map of *names only*: `ui::author` pairs each with a key, and
/// cannot be handed a name with no key to pair it with.
fn name_map(chat: &Chat, open: &[Open], conv: Option<&Open>) -> HashMap<PubKey, String> {
    let mut out = HashMap::new();
    let want = |account: PubKey, out: &mut HashMap<PubKey, String>| {
        if let std::collections::hash_map::Entry::Vacant(e) = out.entry(account)
            && let Some(name) = chat.display_name(&account)
        {
            e.insert(name);
        }
    };
    // Every direct message's peer, because the conversation list names all of
    // them at once and a row is where somebody chooses who to write to.
    for o in open {
        if let Some(peer) = o.peer {
            want(peer, &mut out);
        }
        // And whoever spoke last in a group, because the row previews them by
        // name. Without this the name resolved only for the conversation on
        // screen, so the same row read "Tim: Hey" while you were in it and
        // "9kSYePuJ: Hey" while you were anywhere else.
        if o.peer.is_none()
            && let Some(last) = o.timeline.messages().last()
        {
            want(last.account, &mut out);
        }
    }
    // And whoever spoke in the conversation on screen.
    if let Some(conv) = conv {
        for m in conv.timeline.messages() {
            want(m.account, &mut out);
        }
    }
    out
}

fn refresh(app: &mut App, open: &[Open], me: &PubKey, names: &HashMap<PubKey, String>) {
    // Most recent first, the way every chat client orders a conversation
    // list. `mine()` hands them back in join order, which says nothing about
    // where anything is happening.
    //
    // The cursor is a channel and not a position (see `App::selected`), so
    // reordering under somebody's cursor moves the row and not the reader.
    let mut order: Vec<&Open> = open.iter().collect();
    order.sort_by(|a, b| {
        b.last_at
            .cmp(&a.last_at)
            // A stable tie-break, or two conversations with the same time
            // would swap places on every redraw.
            .then_with(|| a.channel.cmp(&b.channel))
    });
    app.rows = order
        .into_iter()
        .map(|o| Row {
            channel: o.channel,
            // For a direct message the row names a *person*, so a published
            // name wins over the local label — and the label is dropped when
            // it is only the key repeated, which is what an unnamed contact
            // gets. For a group the label is the channel's own name.
            label: match o.peer {
                Some(peer) => names
                    .get(&peer)
                    .cloned()
                    .unwrap_or_else(|| o.label.clone())
                    .to_string(),
                None => o.label.clone(),
            },
            // In full. What is drawn is a stub of it, and only for a peer
            // with no name; the whole of it is what hover, click and `/who`
            // hand over.
            key: o.peer.map(|p| p.to_string()),
            // The newest thing said here, whoever said it. A redaction shows
            // as the gap it is rather than being skipped, or the list would
            // claim the conversation ended at an older message.
            preview: o
                .timeline
                .messages()
                .last()
                .map(|m| {
                    let said = if m.redacted {
                        // SIP-32: a tombstone with a signed request behind it
                        // is somebody deleting their message; one without is
                        // the exchange having removed it on its own authority,
                        // which it can do and which a reader should see.
                        match m.deletion {
                            Deletion::Unasked => "message removed by the exchange".to_string(),
                            _ => "message deleted".to_string(),
                        }
                    } else {
                        m.post
                            .body_text()
                            .map(str::to_string)
                            .unwrap_or_else(|| "a file".to_string())
                    };
                    // In a group, half of what the line is worth is *who*: the
                    // row already names the channel, so "lol" on its own says
                    // nothing about whether it is worth opening. A direct
                    // message needs no prefix — the row is the person.
                    if o.peer.is_some() {
                        return said;
                    }
                    let who = if m.account == *me {
                        "you".to_string()
                    } else {
                        names
                            .get(&m.account)
                            .cloned()
                            .unwrap_or_else(|| short(&m.account))
                    };
                    format!("{who}: {said}")
                })
                .unwrap_or_default(),
            at: o.last_at,
            group: o.peer.is_none(),
            public: o.public,
            unread: o.unread,
            waiting: o.waiting,
        })
        .collect();
    // A conversation that has gone — left, or closed — leaves the cursor
    // naming nothing, so it falls to the top of the list rather than nowhere.
    if app.selected_row().is_none() {
        app.selected = app.rows.first().map(|r| r.channel);
    }
    let Some(conv) = selected_index(open, app).map(|i| &open[i]) else {
        app.said.clear();
        app.picked = None;
        app.peer_typing = false;
        app.topic.clear();
        app.members = 0;
        app.has_avatar = false;
        return;
    };
    app.said = conv
        .timeline
        .messages()
        // Deliberately not filtered on `is_visible`. A redacted message is a
        // tombstone, and SIP-16 keeps the entry so that a reader can see
        // something was removed rather than find a conversation that silently
        // does not follow. Dropping it here is what made /redact look like it
        // deleted messages without trace.
        .map(|m| {
            // An attachment is described on the line rather than fetched: a
            // transcript should not pull megabytes to draw itself, and the
            // sender's `mime` is a claim this client must not act on beyond
            // choosing words. `/save` is what actually fetches.
            let files: Vec<String> = m.post.attachments().map(describe).collect();
            let has_file = !files.is_empty();
            let text = match (m.post.body_text(), files.is_empty()) {
                (Some(t), true) => t.to_string(),
                (Some(t), false) => format!("{t}  {}", files.join(" ")),
                (None, false) => files.join(" "),
                (None, true) => "(nothing to show)".to_string(),
            };
            Said {
                // A name and a key, never a name alone: `ui::author` composes
                // them, and refuses to drop the key to make room. What goes
                // here is only the name half — the display name its author
                // published, or the label we chose for a direct message, both
                // of which are claims about who somebody is.
                who: names
                    .get(&m.account)
                    .cloned()
                    .or_else(|| conv.peer.map(|_| conv.label.clone()))
                    .unwrap_or_default(),
                key: m.account.to_string(),
                mine: m.account == *me,
                text,
                seq: m.seq,
                has_file,
                at: m.posted,
                edited: m.edited.is_some(),
                redacted: m.redacted,
                // Only on ours: a receipt says what became of something you
                // sent. `Read` requires everybody, because a member who has
                // opted out reports having read nothing and cannot be told
                // apart from one who has — so a message that stops at
                // delivered may well have been read by somebody who declined
                // to say, and claiming otherwise would be inventing a fact.
                receipt: (m.account == *me).then(|| {
                    let others: Vec<_> =
                        conv.marks.iter().filter(|k| k.account != *me).collect();
                    if others.is_empty() {
                        ui::Receipt::Sent
                    } else if others.iter().all(|k| k.read >= m.seq) {
                        ui::Receipt::Read
                    } else if others.iter().all(|k| k.delivered >= m.seq) {
                        ui::Receipt::Delivered
                    } else {
                        ui::Receipt::Sent
                    }
                }),
                // The stub is resolved here rather than in the renderer, which
                // has no timeline to look the target up in. A target we do not
                // hold — pruned, or from before we joined — still shows the
                // number: "answering something we cannot see" is the truth,
                // and dropping the marker would hide that a reply is a reply.
                reply_to: m.post.reply_to().map(|t| {
                    let target = conv.timeline.get(t);
                    // Named the same way the author column names anybody, so a
                    // reply carries the key with the name (SIP-21) rather than
                    // a sequence number nobody has memorised.
                    let who = match target {
                        Some(t) => ui::author(
                            &names.get(&t.account).cloned().unwrap_or_default(),
                            &t.account.to_string(),
                            t.account == *me,
                        ),
                        // Pruned, or from before we joined. Still marked as a
                        // reply: hiding that would make the answer a
                        // non-sequitur with nothing to explain it.
                        None => "a message we no longer hold".to_string(),
                    };
                    let stub = target
                        .map(|t| match (t.redacted, t.post.body_text()) {
                            (true, _) => "message deleted".to_string(),
                            (_, Some(text)) => text.to_string(),
                            (_, None) => "(nothing to show)".to_string(),
                        })
                        // Nothing to quote, and the author line above already
                        // says why.
                        .unwrap_or_default();
                    (who, stub)
                }),
                reactions: m
                    .reactions
                    .iter()
                    .map(|(emoji, who)| {
                        (emoji.clone(), who.len(), who.contains(me))
                    })
                    .collect(),
                mentions: m.post.mentions().map(short).collect(),
            }
        })
        .collect();
    app.peer_typing = conv.typing;
    app.members = conv.members;
    app.topic = conv.timeline.topic.clone();
    app.divider = conv.divider;
    app.now = now();
    app.has_avatar = conv.timeline.avatar.is_some();
    // The cursor holds a position in a list that has just been rebuilt. A
    // message can arrive or be deleted between one frame and the next, and a
    // cursor left past the end would act on nothing or on the wrong line.
    app.picked = app
        .picked
        .filter(|_| !app.said.is_empty())
        .map(|i| i.min(app.said.len() - 1));
    if app.picked.is_none() {
        app.reacting = false;
    }
    // A note about what we just did wins over the conversation's state while
    // it is fresh: somebody who has typed a command is waiting for its answer,
    // not for a description of the channel.
    let note = conv
        .note
        .as_ref()
        .filter(|(_, at)| at.elapsed() < NOTE_LINGER)
        .map(|(n, _)| n.clone());
    app.trouble = Trouble {
        unreadable: conv.trouble.unreadable,
        lost: conv.trouble.lost,
        no_key: conv.trouble.no_key,
        gap: conv.trouble.gap,
        restarted: conv.trouble.restarted,
        message: note.or_else(|| conv.trouble.message.clone()).or_else(|| {
            conv.waiting.then(|| match conv.peer {
                Some(_) => format!(
                    "{} has not started their client yet — nothing can be sent until they do",
                    conv.label
                ),
                // A group is not a person, and saying it "has not started its
                // client" is nonsense the reader has to decode.
                None => "somebody here has published no keys yet, so nothing can be sealed \
                         to them — /who lists everyone"
                    .to_string(),
            })
        }),
    };
}

// ---- terminal, and the identity/endpoint glue -------------------------

fn start_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    // The mouse stays the terminal's until somebody asks for it. Capture
    // stops native text selection, and copying what somebody said is a more
    // ordinary thing to want than the seconds a message was sent at — so the
    // client does not take that away by default. `/mouse on` trades it.
    crossterm::execute!(out, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(out))
}

fn stop_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()
}

/// Copy a key, and say what happened in the words a reader needs.
///
/// Never claims success it cannot see. OSC 52 is fire-and-forget and
/// Terminal.app ignores it silently, so on a machine with no `pbcopy` this
/// prints the key instead of asserting it is on the clipboard — a false
/// "copied" is worse than no copy, because it is only discovered at the paste.
fn copied(key: &str, mine: bool) -> String {
    let whose = if mine { "your key" } else { "their key" };
    if copy(key) {
        format!("{whose} is on the clipboard — {key}")
    } else {
        format!("could not reach the clipboard. {whose}: {key}")
    }
}

/// Put `text` on the system clipboard, and say whether anything took it.
///
/// Two routes, because neither is enough on its own.
///
/// **OSC 52** asks the terminal to do it. It is the only thing that works when
/// the client is run over ssh — the clipboard that matters is then the one in
/// front of the person, not the one on the far machine — and iTerm2, kitty,
/// WezTerm and tmux (with `set-clipboard on`) honour it. Terminal.app does
/// not, and says nothing about ignoring it, which is the trouble with relying
/// on it alone.
///
/// **`pbcopy`** is certain and local. It writes the clipboard of the machine
/// this process is on, which is the right one exactly when the client is not
/// being run remotely.
///
/// Both are attempted, because which is right depends on where this is
/// running and the client cannot tell.
fn copy(text: &str) -> bool {
    let mut done = false;
    // OSC 52: ESC ] 52 ; c ; <base64> BEL
    let mut out = io::stdout();
    if write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes())).is_ok() && out.flush().is_ok() {
        done = true;
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(mut child) = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            && let Some(mut pipe) = child.stdin.take()
        {
            let wrote = pipe.write_all(text.as_bytes()).is_ok();
            drop(pipe);
            let _ = child.wait();
            done |= wrote;
        }
    }
    done
}

/// Base64, for OSC 52 and nothing else.
///
/// Hand-rolled rather than a dependency for one short function whose output is
/// checked against the RFC's own vectors.
fn base64(bytes: &[u8]) -> String {
    const SET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(SET[(n >> (18 - i * 6) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Take the mouse from the terminal, or hand it back.
///
/// Capture costs something real: with it on, the terminal's own selection stops
/// working and copying a message means holding Shift — or Option, on macOS.
/// That is a poor trade to make on somebody's behalf, so it is off until asked
/// for. `/mouse` is the whole of the interface to it.
fn set_mouse(on: bool) -> io::Result<()> {
    let mut out = io::stdout();
    if on {
        crossterm::execute!(out, EnableMouseCapture)
    } else {
        crossterm::execute!(out, DisableMouseCapture)
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// This mirrors the same glue in `sqex-cli` and `sqex-voice`. It is copied
// rather than shared for the reason `sqex-voice` gives: factoring it out would
// mean either a new crate or giving `sqex-proto` the dependency on the `sqnr`
// client it deliberately does not have, which is a lot of structure to buy for
// thirty lines.

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// How long a remembered or host-derived address gets before we move on.
///
/// `connect_as` allows five seconds, which is right for the address we believe
/// in and wrong for one we are merely guessing at: two stale guesses would
/// otherwise cost ten seconds before discovery is even tried, every start, for
/// as long as the cache is wrong.
const CACHED_ATTEMPT: Duration = Duration::from_millis(1500);

/// Connect, climbing SIP-33's ladder: a remembered address, then the host we
/// know, then a fresh DNSSEC lookup.
///
/// Whichever rung answers is written back, so the next start begins there.
async fn connect(
    cli: &Cli,
    cfg: &Config,
    seed: &[u8; 32],
) -> Result<(Client, std::net::SocketAddr, PubKey, Option<String>), String> {
    let target = sqex_discovery::target::resolve(&layers(cli, cfg)).map_err(|e| e.to_string())?;

    let addr = match target {
        sqex_discovery::Target::Direct { address, key } => {
            let socket = resolve_one_sync(&address)?;
            let client = Client::connect_as(socket, key.as_bytes(), seed)
                .await
                .map_err(|e| format!("could not reach {socket}: {e}"))?;
            return Ok((client, socket, key, None));
        }
        sqex_discovery::Target::Discover(d) => d,
    };

    let (domain, _) = split_port(&addr);
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "--server {domain} is an address, not a domain, and an address cannot \
             be discovered. Use --server-host {addr} --server-key <key>"
        ));
    }

    let (server, candidates, newly_pinned) = sqex_discovery::candidates(domain)
        .await
        .map_err(|e| e.to_string())?;
    // Not printed here. This runs before the interface takes the terminal, so
    // an `eprintln!` lands underneath the status line ratatui is about to draw
    // over it — the first thing a new user sees, and it looks broken. It is
    // carried out and shown as a note once there is somewhere to put it.
    let pinned_notice = newly_pinned.then(|| {
        format!(
            "discovered {server} for {domain} over DNSSEC and pinned it — it will not \
             change without telling you. Forget it with `sqex discover --forget {domain}`."
        )
    });

    let mut last = String::new();
    for c in &candidates {
        let budget = match c.source {
            sqex_discovery::Source::Discovered => None,
            _ => Some(CACHED_ATTEMPT),
        };
        let attempt = Client::connect_as(c.addr, server.as_bytes(), seed);
        let outcome = match budget {
            Some(d) => match tokio::time::timeout(d, attempt).await {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => Err(format!("no answer within {}ms", d.as_millis())),
            },
            None => attempt.await.map_err(|e| e.to_string()),
        };
        match outcome {
            Ok(client) => {
                // Note where it answered. A failure to write is not a failure to
                // connect — the worst it costs is rediscovery next time.
                if let Err(e) = sqex_discovery::remember(domain, c.host.as_deref(), c.addr) {
                    // Not a failure to connect. The cost is rediscovery next
                    // time, so it is said once and not treated as fatal.
                    eprintln!("note: could not remember where {domain} answered: {e}");
                }
                return Ok((client, c.addr, server, pinned_notice));
            }
            Err(e) => {
                // Quiet per candidate: a stale cached address is ordinary and
                // self-healing, and a line about it on every start would be
                // noise. The final error names the last thing tried.
                last = format!("{}: {e}", c.addr);
            }
        }
    }
    Err(format!(
        "could not reach {domain} at any of its {} address(es) — last was {last}",
        candidates.len()
    ))
}

/// The layers a caller can speak through, most specific first.
///
/// The resolution itself lives in `sqex_discovery::target`, shared with `sqex`
/// and `sqex-voice` — three copies of it is what produced two bugs in a day.
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
        // The config has no `server_host`: it is `sqnr`'s type, in another repo.
        // A `server` there with a key beside it is a literal address, and
        // without one it is a domain — the same pairing rule, read off the two
        // fields that exist.
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

/// `host:port` for the configured path, which may name a host.
fn resolve_one_sync(address: &str) -> Result<std::net::SocketAddr, String> {
    if let Ok(socket) = address.parse::<std::net::SocketAddr>() {
        return Ok(socket);
    }
    let (_, port) = split_port(address);
    let with_port = match port {
        Some(_) => address.to_string(),
        None => format!("{address}:{}", sqex_discovery::DEFAULT_PORT),
    };
    std::net::ToSocketAddrs::to_socket_addrs(&with_port)
        .map_err(|e| format!("cannot resolve {address:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("{address:?} resolved to no addresses"))
}



/// Split a trailing `:port`, leaving an IPv6 literal alone.
fn split_port(addr: &str) -> (&str, Option<u16>) {
    if addr.starts_with('[') {
        return (addr, None);
    }
    match addr.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(p) => (host, Some(p)),
            Err(_) => (addr, None),
        },
        None => (addr, None),
    }
}

/// Load the identity, and its seed.
///
/// The seed is needed twice — once to pin the transport key and once to derive
/// the store key — which is why a YubiKey cannot be used here at all: it signs
/// without ever releasing the seed, so there is nothing to bind either to.
/// `sqex mail` and `sqex session` refuse one for the first reason alone.
fn identity_path(cli: &Cli, cfg: &Config) -> Result<PathBuf, String> {
    let path = match (&cli.identity, &cfg.identity) {
        (Some(p), _) => p.clone(),
        (None, Some(p)) => PathBuf::from(p),
        (None, None) => identity::default_identity_path()?,
    };
    if !path.exists() {
        return Err(format!(
            "no identity at {} — run `sqnr keygen` first",
            path.display()
        ));
    }
    Ok(path)
}

fn load_identity(cli: &Cli, cfg: &Config) -> Result<([u8; 32], PubKey), String> {
    let path = identity_path(cli, cfg)?;
    let signer = if identity::is_encrypted(&path)? {
        let pass = rpassword::prompt_password(format!("Passphrase for {}: ", path.display()))
            .map_err(|e| {
                format!(
                    "{} is passphrase-protected and there is no terminal to ask on ({e}) — \
                     run this from a terminal, or point --identity at an unencrypted one",
                    path.display()
                )
            })?;
        identity::load(&path, Some(&pass))?
    } else {
        identity::load(&path, None)?
    };
    let seed = signer.seed();
    Ok((seed, PubKey::new(signer.public())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqex_proto::message::{Body, Post as SipPost};
    use sqex_proto::timeline::{Received, Verdict};

    /// A credential is addressed to a device, so a client that has been linked
    /// — where the account is somebody else's key — must still recognise one
    /// written for it. This is the case the check got wrong: it compared
    /// against the account, which equals the device only on a client that has
    /// never been linked, so the first claim passed and every renewal after it
    /// was refused with a message naming the wrong key.
    #[test]
    fn a_credential_is_recognised_by_device_and_not_by_account() {
        let account = PubKey::new([1; 32]);
        let device = PubKey::new([2; 32]);
        let cred = |delegate: PubKey| Credential {
            account,
            delegate,
            scope: "chat".to_string(),
            issued: 0,
            not_after: 0,
            signature: [0; 64],
        };

        assert!(credential_is_for(&cred(device), &device));
        // Written for the account key rather than this client: not ours, even
        // though it is our account that signed it.
        assert!(!credential_is_for(&cred(account), &device));
    }

    fn conv(peer: u8, label: &str) -> Open {
        Open {
            peer: Some(PubKey::new([peer; 32])),
            public: false,
            label: label.to_string(),
            channel: [7; 32],
            members: 2,
            admins: vec![PubKey::new([1; 32]), PubKey::new([peer; 32])],
            timeline: Timeline::new(),
            timeline_len: 0,
            marks: Vec::new(),
            marks_at: None,
            read_to: 0,
            divider: None,
            last_at: 0,
            trouble: Trouble::default(),
            note: None,
            typing: false,
            unread: 0,
            waiting: false,
        }
    }

    fn say(conv: &mut Open, from: u8, seq: u64, text: &str) {
        conv.timeline.apply(
            &Received {
                seq,
                account: PubKey::new([from; 32]),
                posted: 0,
                kind: sqex_proto::channel::KIND_MEMBER,
                tombstone: false,
                body: Some(Body::Post(SipPost::text(text))),
                verdict: Verdict::Valid,
            },
            &[],
        );
    }

    #[test]
    fn a_transcript_says_who_said_what() {
        let mut bob = conv(2, "bob");
        say(&mut bob, 2, 1, "from bob");
        say(&mut bob, 1, 2, "from me");
        let open = vec![bob];
        let mut app = App {
            rows: vec![Row {
                channel: [7; 32],
                label: "bob".into(),
                key: Some("8qbHbw2B".into()),
                group: false,
                public: false,
                unread: 0,
                preview: String::new(),
                at: 0,
                waiting: false,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert_eq!(app.said.len(), 2);
        assert_eq!(app.said[0].who, "bob");
        assert!(!app.said[0].mine);
        // Anything not from the peer is ours: a direct message has two members,
        // so there is no third case to get wrong.
        assert!(app.said[1].mine);

        // The line a reader sees is the name alone. The key is not gone —
        // it is carried whole on the message, which is what hover, click, the
        // pick cursor and `/who` hand over.
        let line = ui::author(&app.said[0].who, &app.said[0].key, app.said[0].mine);
        assert_eq!(line, "bob");
        assert_eq!(
            app.said[0].key,
            PubKey::new([2; 32]).to_string(),
            "the message does not carry the whole key, so nothing can hand it over"
        );
        // Whole, and not a stub of one: this is the path that used to
        // truncate, and a test with an eight-character fixture would not
        // notice if it started again.
        assert!(app.said[0].key.chars().count() > 40, "{}", app.said[0].key);
        assert_eq!(
            ui::author(&app.said[1].who, &app.said[1].key, app.said[1].mine),
            "you"
        );
    }

    /// A contact with no chosen label is labelled with its own short key, and
    /// pairing that with itself rendered "E4LUkjrZ (E4LUkjrZ)". A name that is
    /// the key is not a name.
    #[test]
    fn a_label_that_is_only_the_key_is_not_treated_as_a_name() {
        let bob = PubKey::new([2; 32]);
        let mut c = conv(2, &ui::short(&bob));
        c.timeline = Timeline::fold(
            &[Received {
                seq: 1,
                account: bob,
                posted: 10,
                kind: sqex_proto::channel::KIND_MEMBER,
                tombstone: false,
                body: Some(Body::Post(SipPost::text("hello"))),
                verdict: Verdict::Valid,
            }],
            &[],
        );
        let open = vec![c];
        let mut app = App {
            rows: vec![Row {
                channel: [7; 32],
                label: ui::short(&bob),
                key: Some(ui::short(&bob)),
                group: false,
                public: false,
                unread: 0,
                preview: String::new(),
                at: 0,
                waiting: false,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert_eq!(app.said.len(), 1);
        assert_eq!(
            ui::author(&app.said[0].who, &app.said[0].key, false),
            ui::short(&bob),
            "the key was rendered twice"
        );
    }

    /// The poll runs every 700 ms and clears the conversation's trouble, so a
    /// confirmation kept in that field was on screen for less than a second —
    /// which is to say it was never read. A note outlives the poll.
    /// Checked against RFC 4648's own vectors, including every padding case,
    /// because this is hand-rolled and a wrong clipboard is a silent one.
    #[test]
    fn base64_is_base64() {
        for (plain, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), want, "{plain:?}");
        }
        // And a key, which is the only thing this is ever asked to encode.
        let key = PubKey::new([7; 32]).to_string();
        assert_eq!(
            base64(key.as_bytes()).len(),
            key.len().div_ceil(3) * 4,
            "a key came out the wrong length"
        );
    }

    /// A copy that failed must not report success: it is discovered at the
    /// paste, by which time the key is gone from the screen too.
    #[test]
    fn a_copy_says_the_key_either_way() {
        let key = PubKey::new([9; 32]).to_string();
        let note = copied(&key, false);
        assert!(note.contains(&key), "the note does not carry the key: {note}");
        assert!(note.contains("their key"), "{note}");
        assert!(copied(&key, true).contains("your key"));
    }

    /// A rebuild asks the exchange what we are in and builds it from scratch.
    /// Everything a *reader* has accumulated lives on this side and not that
    /// one, so without carrying it the client would clear somebody's unread
    /// counts and their place in a conversation every time anybody started
    /// talking to them.
    #[test]
    fn a_rebuild_keeps_what_the_exchange_does_not_know() {
        let mut was = conv(2, "bob");
        was.unread = 4;
        was.divider = Some(7);
        was.read_to = 9;
        was.timeline_len = 12;
        was.marks_at = Some(std::time::Instant::now());
        was.note = Some(("renamed".into(), std::time::Instant::now()));

        // What a fresh `sync_channels` would produce: the exchange's facts,
        // and defaults for everything else.
        let mut fresh = vec![conv(2, "bob"), conv(3, "carol")];
        // `conv` gives every conversation the same identifier, and this is
        // keyed on it — without a distinct one the new arrival matches the old
        // row and inherits its counts, which is the bug this guards against
        // wearing a disguise.
        fresh[1].channel = [3; 32];
        fresh[0].read_to = 8;
        carry_over(&[was], &mut fresh);

        assert_eq!(fresh[0].unread, 4, "the unread count was cleared");
        assert_eq!(fresh[0].divider, Some(7), "the reader lost their place");
        assert_eq!(fresh[0].timeline_len, 12, "everything would count as new");
        assert!(fresh[0].note.is_some(), "the answer to a command was lost");
        // The read mark only moves forward: the exchange's copy can be behind
        // ours between publishing it and it being acknowledged.
        assert_eq!(fresh[0].read_to, 9);

        // And a conversation that has just arrived keeps its own defaults.
        assert_eq!(fresh[1].unread, 0);
        assert_eq!(fresh[1].divider, None);
    }

    #[test]
    fn the_answer_to_a_command_outlives_the_next_poll() {
        let mut c = conv(2, "bob");
        c.note = Some(("renamed to shipping".into(), std::time::Instant::now()));
        // What a poll does to the conversation's own state.
        c.trouble.message = None;
        let open = vec![c];
        let mut app = App {
            rows: vec![Row {
                channel: [7; 32],
                label: "bob".into(),
                key: Some("8qbHbw2B".into()),
                group: false,
                public: false,
                unread: 0,
                preview: String::new(),
                at: 0,
                waiting: false,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert_eq!(
            app.trouble.message.as_deref(),
            Some("renamed to shipping"),
            "the answer to a command was cleared by a poll"
        );

        // And it does not sit there for the rest of the session over the next
        // thing that goes wrong.
        let mut c = conv(2, "bob");
        c.note = Some((
            "renamed to shipping".into(),
            std::time::Instant::now() - NOTE_LINGER - Duration::from_secs(1),
        ));
        c.trouble.message = Some("the exchange refused (403)".into());
        let open = vec![c];
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert_eq!(
            app.trouble.message.as_deref(),
            Some("the exchange refused (403)")
        );
    }

    #[test]
    fn waiting_on_somebody_reads_as_waiting_and_not_as_a_fault() {
        let mut c = conv(2, "bob");
        c.waiting = true;
        let open = vec![c];
        let mut app = App {
            rows: vec![Row {
                channel: [7; 32],
                label: "bob".into(),
                key: Some("8qbHbw2B".into()),
                group: false,
                public: false,
                unread: 0,
                preview: String::new(),
                at: 0,
                waiting: true,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        let line = app.trouble.line();
        assert!(line.contains("bob has not started their client"), "{line}");
    }

    #[test]
    fn a_real_refusal_wins_over_the_waiting_note() {
        // Both can be true at once; the specific failure is the useful one.
        let mut c = conv(2, "bob");
        c.waiting = true;
        c.trouble.message = Some("the exchange refused (403): not_a_member".into());
        let open = vec![c];
        let mut app = App {
            rows: vec![Row {
                channel: [7; 32],
                label: "bob".into(),
                key: Some("8qbHbw2B".into()),
                group: false,
                public: false,
                unread: 0,
                preview: String::new(),
                at: 0,
                waiting: true,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert!(app.trouble.line().contains("403"));
    }

    /// `Read` means everybody, and it has to. A member who has opted out of
    /// receipts reports having read nothing and is indistinguishable from one
    /// who has read nothing — so a tick that needed only one reader would show
    /// "read" for a group where one person has looked and the rest have not.
    #[test]
    fn a_read_receipt_waits_for_everybody() {
        use sqex_proto::channel::Mark;

        let me = PubKey::new([1; 32]);
        let (bob, carol) = (PubKey::new([2; 32]), PubKey::new([3; 32]));
        let mut c = conv(2, "group");
        c.peer = None;
        c.timeline = Timeline::fold(
            &[Received {
                seq: 5,
                account: me,
                posted: 10,
                kind: sqex_proto::channel::KIND_MEMBER,
                tombstone: false,
                body: Some(Body::Post(SipPost::text("did you see this?"))),
                verdict: Verdict::Valid,
            }],
            &[me],
        );

        let receipt = |marks: Vec<Mark>| {
            let mut conv = conv(2, "group");
            conv.peer = None;
            conv.timeline = c.timeline.clone();
            conv.marks = marks;
            let open = vec![conv];
            let mut app = App {
                selected: Some([7; 32]),
                ..Default::default()
            };
            refresh(&mut app, &open, &me, &HashMap::new());
            app.said[0].receipt
        };

        let mark = |a, d, r| Mark { account: a, delivered: d, read: r };

        // Nobody has fetched it.
        assert_eq!(
            receipt(vec![mark(bob, 0, 0), mark(carol, 0, 0)]),
            Some(ui::Receipt::Sent)
        );
        // Both hold it, neither has said they read it.
        assert_eq!(
            receipt(vec![mark(bob, 5, 0), mark(carol, 5, 0)]),
            Some(ui::Receipt::Delivered)
        );
        // One has read it. That is not "read".
        assert_eq!(
            receipt(vec![mark(bob, 5, 5), mark(carol, 5, 0)]),
            Some(ui::Receipt::Delivered),
            "one reader was reported as everybody"
        );
        // Both have.
        assert_eq!(
            receipt(vec![mark(bob, 5, 5), mark(carol, 5, 5)]),
            Some(ui::Receipt::Read)
        );
        // Our own mark is not part of the question. The case that shows it is
        // ours lagging behind theirs: everybody else has read it, and whether
        // we have is beside the point.
        assert_eq!(
            receipt(vec![mark(me, 5, 0), mark(bob, 5, 5), mark(carol, 5, 5)]),
            Some(ui::Receipt::Read),
            "our own unread mark held back a receipt about other people"
        );
    }

    /// A receipt belongs on what you sent. Somebody else's message carries
    /// none — you are not waiting to hear what became of it.
    #[test]
    fn somebody_elses_message_carries_no_receipt() {
        use sqex_proto::channel::Mark;

        let me = PubKey::new([1; 32]);
        let bob = PubKey::new([2; 32]);
        let mut c = conv(2, "bob");
        c.marks = vec![
            Mark { account: me, delivered: 9, read: 9 },
            Mark { account: bob, delivered: 9, read: 9 },
        ];
        c.timeline = Timeline::fold(
            &[
                Received {
                    seq: 1,
                    account: bob,
                    posted: 10,
                    kind: sqex_proto::channel::KIND_MEMBER,
                    tombstone: false,
                    body: Some(Body::Post(SipPost::text("theirs"))),
                    verdict: Verdict::Valid,
                },
                Received {
                    seq: 2,
                    account: me,
                    posted: 11,
                    kind: sqex_proto::channel::KIND_MEMBER,
                    tombstone: false,
                    body: Some(Body::Post(SipPost::text("mine"))),
                    verdict: Verdict::Valid,
                },
            ],
            &[me, bob],
        );
        let open = vec![c];
        let mut app = App {
            selected: Some([7; 32]),
            ..Default::default()
        };
        refresh(&mut app, &open, &me, &HashMap::new());
        assert_eq!(app.said.len(), 2);
        assert_eq!(app.said[0].receipt, None, "a receipt on somebody else's message");
        assert_eq!(app.said[1].receipt, Some(ui::Receipt::Read));
    }

    /// The divider is frozen on arriving, not recomputed. Reading advances the
    /// mark within the second, so recomputing would take the line away at the
    /// moment it became useful.
    #[test]
    fn the_unread_divider_stays_where_it_was_put() {
        let me = PubKey::new([1; 32]);
        let bob = PubKey::new([2; 32]);
        let entry = |seq| Received {
            seq,
            account: bob,
            posted: 10 + seq,
            kind: sqex_proto::channel::KIND_MEMBER,
            tombstone: false,
            body: Some(Body::Post(SipPost::text("hello"))),
            verdict: Verdict::Valid,
        };
        let mut c = conv(2, "bob");
        c.timeline = Timeline::fold(&[entry(1), entry(2), entry(3)], &[me]);
        c.read_to = 1;

        // Arriving: the line goes above the first one not yet read.
        place_divider(&mut c, &me, true);
        assert_eq!(c.divider, Some(2));

        // Reading them advances the mark. The line does not move.
        c.read_to = 3;
        place_divider(&mut c, &me, true);
        assert_eq!(c.divider, Some(2), "the divider moved as it was read past");

        // Leaving clears it, so coming back marks the new place.
        place_divider(&mut c, &me, false);
        assert_eq!(c.divider, None);
        place_divider(&mut c, &me, true);
        assert_eq!(c.divider, None, "a divider appeared with nothing unread");

        // And something new arriving later gets its own line.
        c.timeline.apply(&entry(4), &[me]);
        place_divider(&mut c, &me, false);
        place_divider(&mut c, &me, true);
        assert_eq!(c.divider, Some(4));
    }

    /// A message you wrote is not one you have not seen. The read mark only
    /// catches up to your own on the next poll, so quitting straight after
    /// sending would otherwise greet you with your own words under a line
    /// saying they were unread.
    #[test]
    fn your_own_message_is_never_unread() {
        let me = PubKey::new([1; 32]);
        let bob = PubKey::new([2; 32]);
        let entry = |seq, who| Received {
            seq,
            account: who,
            posted: 10 + seq,
            kind: sqex_proto::channel::KIND_MEMBER,
            tombstone: false,
            body: Some(Body::Post(SipPost::text("hello"))),
            verdict: Verdict::Valid,
        };

        // Only our own is newer than the mark: nothing to come back to.
        let mut c = conv(2, "bob");
        c.timeline = Timeline::fold(&[entry(1, bob), entry(2, me)], &[me]);
        c.read_to = 1;
        place_divider(&mut c, &me, true);
        assert_eq!(c.divider, None, "our own message was called unread");

        // Somebody else's after it, and the line goes above theirs.
        let mut c = conv(2, "bob");
        c.timeline = Timeline::fold(&[entry(1, bob), entry(2, me), entry(3, bob)], &[me]);
        c.read_to = 1;
        place_divider(&mut c, &me, true);
        assert_eq!(c.divider, Some(3));
    }

    /// Signal's ordering: whatever happened last is at the top. The exchange
    /// hands conversations back in join order, which says nothing about where
    /// anything is happening.
    #[test]
    fn the_list_is_ordered_by_what_happened_last() {
        let mut a = conv(2, "alice");
        a.channel = [1; 32];
        a.last_at = 100;
        let mut b = conv(3, "bob");
        b.channel = [2; 32];
        b.last_at = 300;
        let mut c = conv(4, "carol");
        c.channel = [3; 32];
        c.last_at = 200;

        let open = vec![a, b, c];
        let mut app = App::default();
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert_eq!(
            app.rows.iter().map(|r| r.label.as_str()).collect::<Vec<_>>(),
            vec!["bob", "carol", "alice"]
        );
    }

    /// And the cursor stays on the conversation being read while the list
    /// moves around it. An index would put somebody in a channel they did not
    /// choose the moment a message arrived somewhere else.
    #[test]
    fn a_message_elsewhere_reorders_the_list_and_not_the_reader() {
        let mut a = conv(2, "alice");
        a.channel = [1; 32];
        a.last_at = 300;
        let mut b = conv(3, "bob");
        b.channel = [2; 32];
        b.last_at = 100;

        let mut open = vec![a, b];
        let mut app = App::default();
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert_eq!(app.rows[0].label, "alice");

        // Reading alice, at the top.
        app.selected = Some([1; 32]);
        // Bob says something, which puts bob first.
        open[1].last_at = 400;
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());

        assert_eq!(app.rows[0].label, "bob", "the list did not reorder");
        assert_eq!(
            app.selected,
            Some([1; 32]),
            "the reader was moved into a conversation they did not choose"
        );
        assert_eq!(app.selected_row().map(|r| r.label.as_str()), Some("alice"));
        assert_eq!(app.selected_at(), Some(1), "the cursor followed the row");
    }

    #[test]
    fn a_selection_naming_a_channel_that_has_gone_falls_to_the_top() {
        // A conversation can be left or closed underneath the cursor.
        let open = vec![conv(2, "bob")];
        let mut app = App {
            selected: Some([99; 32]),
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert_eq!(app.selected, Some([7; 32]), "the cursor named nothing");
        assert_eq!(app.said.len(), 0);
    }

    #[test]
    fn no_contacts_leaves_an_empty_transcript_rather_than_a_panic() {
        let mut app = App {
            selected: Some([7; 32]),
            ..Default::default()
        };
        refresh(&mut app, &[], &PubKey::new([1; 32]), &HashMap::new());
        assert!(app.rows.is_empty());
        assert!(app.said.is_empty());
    }

    #[test]
    fn a_leading_slash_is_a_command_and_nothing_else_is() {
        assert!(matches!(Command::parse("hello"), Command::Send(_)));
        // Including a message that merely contains one.
        assert!(matches!(Command::parse("and/or"), Command::Send(_)));
        assert!(matches!(Command::parse("/file x"), Command::File(_)));
        assert!(matches!(Command::parse("/nonsense"), Command::Unknown(_)));
    }

    /// Closing destroys every message for everyone, with no tombstone and no
    /// undo, so the bare word is a question and only the answer acts.
    #[test]
    fn closing_asks_before_it_acts() {
        assert!(matches!(Command::parse("/close"), Command::Close));
        assert!(matches!(
            Command::parse("/close yes"),
            Command::CloseConfirmed
        ));
        // Anything else is still the question, not the answer.
        assert!(matches!(Command::parse("/close please"), Command::Close));
    }

    #[test]
    fn retention_takes_a_window_and_optionally_a_count() {
        assert!(matches!(Command::parse("/retain 3600"), Command::Retain(3600, 0)));
        assert!(matches!(
            Command::parse("/retain 3600 50"),
            Command::Retain(3600, 50)
        ));
        // Not a number is a mistake to report rather than a value to guess at:
        // narrowing a window deletes messages straight away.
        assert!(matches!(Command::parse("/retain soon"), Command::Unknown(_)));
        assert!(matches!(Command::parse("/retain"), Command::Unknown(_)));
    }

    #[test]
    fn a_name_keeps_its_spaces() {
        // `/new release check` used to make a group called "release".
        match Command::parse("/new release check") {
            Command::New(n) => assert_eq!(n, "release check"),
            _ => panic!("not parsed as new"),
        }
        match Command::parse("/name the tuesday club") {
            Command::Name(n) => assert_eq!(n, "the tuesday club"),
            _ => panic!("not parsed as name"),
        }
        match Command::parse("/topic what we ship in October") {
            Command::Topic(t) => assert_eq!(t, "what we ship in October"),
            _ => panic!("not parsed as topic"),
        }
        // Neither is a way of clearing the other: an empty argument is a
        // mistake to report, not a blank record to publish.
        assert!(matches!(Command::parse("/topic"), Command::Unknown(_)));
        // A key is one word, so trailing rubbish is ignored rather than folded
        // into it.
        match Command::parse("/invite ZfS2aD5B  ") {
            Command::Invite(k) => assert_eq!(k, "ZfS2aD5B"),
            _ => panic!("not parsed as invite"),
        }
    }

    #[test]
    fn a_path_with_spaces_does_not_need_quoting() {
        match Command::parse("/file /tmp/my holiday photo.png") {
            Command::File(p) => assert_eq!(p, std::path::PathBuf::from("/tmp/my holiday photo.png")),
            _ => panic!("not parsed as a file"),
        }
    }

    #[test]
    fn save_needs_a_number_and_says_so_when_it_does_not_get_one() {
        match Command::parse("/save 12 /tmp/out.bin") {
            Command::Save(seq, p) => {
                assert_eq!(seq, 12);
                assert_eq!(p, std::path::PathBuf::from("/tmp/out.bin"));
            }
            _ => panic!("not parsed as a save"),
        }
        assert!(matches!(Command::parse("/save notanumber /tmp/x"), Command::Unknown(_)));
        assert!(matches!(Command::parse("/save 12"), Command::Unknown(_)));
        assert!(matches!(Command::parse("/file"), Command::Unknown(_)));
    }

    #[test]
    fn a_tilde_is_expanded_because_typing_it_is_reflex() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand("~/notes.md"), home.join("notes.md"));
        // Only at the front, and only as a path component.
        assert_eq!(expand("/tmp/~x"), std::path::PathBuf::from("/tmp/~x"));
        assert_eq!(expand("~notuser/x"), std::path::PathBuf::from("~notuser/x"));
    }

    // ---- SIP-30: what the client does with what it is told ----

    /// A conversation on a named channel.
    ///
    /// `conv` above gives every conversation the same channel, which is fine
    /// for the layout tests it was written for and useless here — half of what
    /// `Dirty` does is tell one channel from another.
    fn on_channel(c: u8) -> Open {
        let mut o = conv(2, "somebody");
        o.channel = [c; 32];
        o
    }

    fn me() -> PubKey {
        PubKey::new([1; 32])
    }

    /// The reason events are filed into a set instead of acted on one by one:
    /// twenty messages landing in a burst are one thing to go and fetch.
    #[test]
    fn a_burst_in_one_channel_is_one_fetch() {
        let open = vec![on_channel(9)];
        let mut dirty = Dirty::default();
        for seq in 1..=20 {
            dirty.note(
                ChatEvent::Channel {
                    channel: [9; 32],
                    last_seq: seq,
                },
                &me(),
                &open,
            );
        }
        assert_eq!(dirty.channels.len(), 1);
        assert!(dirty.channels.contains(&[9; 32]));
    }

    /// Somebody else joining changes a member count, which the fetch carries.
    /// *Us* joining changes which conversations exist, which only a rebuild
    /// finds — and a client that treated the two alike would never notice a
    /// conversation it had just been added to.
    #[test]
    fn our_own_membership_rebuilds_and_somebody_elses_does_not() {
        let open = vec![on_channel(9)];

        let mut ours = Dirty::default();
        ours.note(
            ChatEvent::Membership {
                channel: [9; 32],
                account: me(),
                what: sqex_proto::events::MEMBER_JOINED,
            },
            &me(),
            &open,
        );
        assert!(ours.arrivals, "being added to something rebuilt nothing");

        let mut theirs = Dirty::default();
        theirs.note(
            ChatEvent::Membership {
                channel: [9; 32],
                account: PubKey::new([5; 32]),
                what: sqex_proto::events::MEMBER_JOINED,
            },
            &me(),
            &open,
        );
        assert!(!theirs.arrivals, "somebody else joining rebuilt the world");
        assert!(theirs.channels.contains(&[9; 32]));
    }

    /// A resync means "you missed things and we are not saying which".
    #[test]
    fn a_resync_marks_everything_that_is_open() {
        let open = vec![on_channel(1), on_channel(2), on_channel(3)];
        let mut dirty = Dirty::default();
        dirty.note(ChatEvent::Resync, &me(), &open);

        assert!(dirty.arrivals);
        for c in [1u8, 2, 3] {
            assert!(dirty.channels.contains(&[c; 32]), "channel {c} was left stale");
            assert!(dirty.receipts.contains(&[c; 32]));
        }
    }

    /// SIP-19's rule, at the receiving end. A client that treated an unknown
    /// kind as a reason to do anything — including to resync — would make every
    /// new kind of event a stampede.
    #[test]
    fn an_unknown_event_asks_for_nothing() {
        let open = vec![on_channel(9)];
        let mut dirty = Dirty::default();
        dirty.note(ChatEvent::Unknown(0x7f), &me(), &open);
        assert!(dirty.is_empty(), "an unrecognised event caused work");
    }

    /// A heartbeat has already done its job by arriving; it is read where the
    /// stream is drained, not here.
    #[test]
    fn a_heartbeat_asks_for_nothing() {
        let open = vec![on_channel(9)];
        let mut dirty = Dirty::default();
        dirty.note(ChatEvent::Heartbeat, &me(), &open);
        assert!(dirty.is_empty());
    }

    /// The two facts are not the same request, and filing a read mark as a
    /// fetch would put the exchange back to a round trip per receipt.
    #[test]
    fn a_read_mark_is_not_a_reason_to_refetch_the_conversation() {
        let open = vec![on_channel(9)];
        let mut dirty = Dirty::default();
        dirty.note(ChatEvent::Cursor { channel: [9; 32] }, &me(), &open);
        assert!(dirty.receipts.contains(&[9; 32]));
        assert!(
            dirty.channels.is_empty(),
            "a moved read mark refetched the whole conversation"
        );
    }

    /// Typing arrives with entries on the same fetch, so a signal is a fetch.
    #[test]
    fn typing_is_fetched_with_the_conversation() {
        let open = vec![on_channel(9)];
        let mut dirty = Dirty::default();
        dirty.note(ChatEvent::Signal { channel: [9; 32] }, &me(), &open);
        assert!(dirty.channels.contains(&[9; 32]));
    }

    /// Nothing to do means nothing is done: the loop skips its whole network
    /// section on an empty set, which is what makes an idle client silent.
    #[test]
    fn an_idle_client_has_nothing_to_ask_for() {
        assert!(Dirty::default().is_empty());
        let mut dirty = Dirty::default();
        dirty.note(ChatEvent::Profile { account: me() }, &me(), &[]);
        assert!(!dirty.is_empty());
    }
}
