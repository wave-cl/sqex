//! `sqex-chat` — end-to-end encrypted direct messages, in a terminal.
//!
//! The connection's Ed25519 identity is the caller (SIP-3), so there is nothing
//! to log in to. What there is instead is a store: the keys this client has
//! opened cannot be recovered from the exchange, because opening an envelope
//! spends the prekey it was sealed against.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use sqex_chat::attach::describe;
use sqex_chat::client::{Chat, ChatError};
use sqex_chat::store::{Store, store_path};
use std::collections::HashMap;

/// How long the answer to a command stays on screen. Long enough to read a
/// sentence, short enough not to sit over the next thing that goes wrong.
const NOTE_LINGER: Duration = Duration::from_secs(8);

use sqex_proto::message::Post as SipPost;
use sqex_proto::timeline::Timeline;
use sqnr::{Client, config::Config, identity};
use sqnr_core::Signer;
use sqex_proto::channel::{Role, Visibility};
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
    /// Server address, host:port (overrides SQEX_SERVER and ~/.sqnr/config).
    #[arg(long, global = true)]
    server: Option<String>,
    /// Server's base58 public key (overrides SQEX_SERVER_KEY and the config).
    #[arg(long = "server-key", global = true)]
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
    let store = Store::open(&seed, Some(&store_path(&me).map_err(|e| e.to_string())?))
        .map_err(|e| e.to_string())?;

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

    let (addr, server) = endpoint(&cli, &cfg)?;
    let client = Client::connect_as(addr, server.as_bytes(), &seed)
        .await
        .map_err(|e| format!("could not reach {addr}: {e}"))?;
    let mut chat = Chat::new(client, seed, me, store);
    chat.top_up_prekeys()
        .await
        .map_err(|e| format!("publishing prekeys: {e}"))?;

    // The rest of `device` needs the exchange.
    if let Some(Cmd::Device { cmd }) = &cli.cmd {
        return device_command(&mut chat, cmd).await;
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

    interface(chat).await
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
            let credential = sqex_proto::credential::Credential::decode(&raw)
                .map_err(|e| format!("bad credential: {e}"))?;
            if credential.delegate != chat.me {
                return Err(format!(
                    "that credential names {}, not this client ({}) — \
                     a credential is bound to the device it was written for",
                    credential.delegate, chat.me
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
        let (admins, given_name) = match chat.info(&m.channel).await {
            Ok(info) => (
                info.members
                    .iter()
                    .filter(|mem| mem.role == Role::Admin)
                    .map(|mem| mem.account)
                    .collect(),
                info.name,
            ),
            Err(_) => (remembered.map(|k| k.3.clone()).unwrap_or_default(), String::new()),
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
        open.push(Open {
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
            unread: 0,
            waiting: false,
        });
    }
    Ok(open)
}

/// Eight hex characters of a channel identifier, to call it something.
fn hex8(channel: &[u8; 32]) -> String {
    channel[..4].iter().map(|b| format!("{b:02x}")).collect()
}

async fn interface(mut chat: Chat) -> Result<(), String> {
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

    let mut poll_at = tokio::time::Instant::now();
    loop {
        let names = name_map(chat, selected_index(open, app).map(|i| &open[i]));
        refresh(app, open, &chat.me, &names);
        terminal
            .draw(|f| ui::draw(f, app))
            .map_err(|e| e.to_string())?;
        if app.should_quit {
            return Ok(());
        }

        // Keys first, so typing never waits on the network.
        if event::poll(Duration::from_millis(50)).map_err(|e| e.to_string())? {
            if let Event::Key(k) = event::read().map_err(|e| e.to_string())?
                && k.kind == KeyEventKind::Press
            {
                handle_key(chat, open, app, k.code, k.modifiers).await;
            }
            continue;
        }

        if tokio::time::Instant::now() >= poll_at {
            // A short wait rather than the full long poll: the loop also has a
            // keyboard to serve, and parking 20 s here would make the interface
            // feel broken. The long poll is the right tool for a client with
            // nothing else to do, which this is not.
            for conv in open.iter_mut() {
                poll_one(chat, conv, app).await;
            }
            poll_at = tokio::time::Instant::now() + Duration::from_millis(700);
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
            // Whoever spoke here, asked for once and then read from the store.
            // Silent on failure: a name is decoration, and a conversation that
            // stopped working because one could not be fetched would be the
            // tail wagging the dog.
            let mut who: Vec<PubKey> = Vec::new();
            for m in conv.timeline.messages() {
                if !who.contains(&m.account) {
                    who.push(m.account);
                }
            }
            let _ = chat.refresh_profiles(&who, now()).await;
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
            conv.trouble.message = Some(e.to_string());
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
                        got.profile.name,
                        if got.profile.title.is_empty() {
                            String::new()
                        } else {
                            format!(", {:?}", got.profile.title)
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
                    // Said back with a reminder of what it is. A display
                    // name is a claim, not a credential, and a client that
                    // reported "you are now X" would be agreeing with it.
                    Some(format!(
                        "published {name:?} — a name is a claim, and readers see \
                         your key beside it"
                    ))
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

/// Poll the conversation just acted on and redraw from it.
///
/// Every action in pick mode changes what the transcript should say, and the
/// change only exists at the exchange until something fetches it.
async fn settle_here(chat: &mut Chat, open: &mut [Open], app: &mut App, at: usize) {
    let me = chat.me;
    poll_one(chat, &mut open[at], app).await;
    let names = name_map(chat, open.get(at));
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

    // The directory is a view over the transcript, so Esc puts it away rather
    // than leaving the reader stuck looking at a search.
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
        KeyCode::Tab | KeyCode::Down => {
            app.select_next();
            clear_unread(open, app);
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.select_previous();
            clear_unread(open, app);
        }
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
                    let (channel, name) = (found.channel, found.name.clone());
                    let note = match chat.join(&channel).await {
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
            if matches!(
                cmd,
                Command::Profile(_) | Command::Block(_) | Command::Unblock(_) | Command::Blocked
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
                | Command::Blocked => Ok(None),
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
                Command::Who => match chat.info(&channel).await {
                    Ok(info) => Ok(Some(
                        info.members
                            .iter()
                            .map(|m| {
                                format!(
                                    "{}{}",
                                    short(&m.account),
                                    if m.role == Role::Admin { "*" } else { "" }
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(" "),
                    )),
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
                app.selected = open.len().saturating_sub(1);
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
    /// `/retain <secs> [max]` — how long this channel keeps what is said here.
    Retain(u32, u32),
    /// `/close` — end this channel. Irreversible, so it asks first.
    Close,
    /// `/close yes` — the answer to that question.
    CloseConfirmed,
    /// `/read` — how far everybody else has read.
    Read,
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
                (0, d) => format!("{who}: delivered to {d}, reading not shared"),
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
            app.selected = open
                .iter()
                .position(|o| o.channel == channel)
                .unwrap_or(open.len().saturating_sub(1));
            if let Some(o) = open.get_mut(app.selected) {
                o.note = Some((note, std::time::Instant::now()));
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
    open.push(conv);
    app.selected = open.len() - 1;
}

fn selected_index(open: &[Open], app: &App) -> Option<usize> {
    let row = app.selected_row()?;
    open.iter().position(|o| o.channel == row.channel)
}

fn clear_unread(open: &mut [Open], app: &App) {
    if let Some(row) = app.rows.get(app.selected)
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
fn name_map(chat: &Chat, conv: Option<&Open>) -> HashMap<PubKey, String> {
    let mut out = HashMap::new();
    let Some(conv) = conv else { return out };
    for m in conv.timeline.messages() {
        if let std::collections::hash_map::Entry::Vacant(e) = out.entry(m.account)
            && let Some(name) = chat.display_name(&m.account)
        {
            e.insert(name);
        }
    }
    out
}

fn refresh(app: &mut App, open: &[Open], me: &PubKey, names: &HashMap<PubKey, String>) {
    app.rows = open
        .iter()
        .map(|o| Row {
            channel: o.channel,
            label: o.label.clone(),
            group: o.peer.is_none(),
            public: o.public,
            unread: o.unread,
            waiting: o.waiting,
        })
        .collect();
    if app.selected >= app.rows.len() {
        app.selected = app.rows.len().saturating_sub(1);
    }
    let Some(conv) = selected_index(open, app).map(|i| &open[i]) else {
        app.said.clear();
        app.picked = None;
        app.peer_typing = false;
        app.topic.clear();
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
                    // A contact with no chosen label is labelled with its own
                    // short key, and pairing that with itself renders
                    // "E4LUkjrZ (E4LUkjrZ)". A name that *is* the key is not a
                    // name.
                    .filter(|name| *name != short(&m.account))
                    .unwrap_or_default(),
                key: short(&m.account),
                mine: m.account == *me,
                text,
                seq: m.seq,
                has_file,
                at: m.posted,
                edited: m.edited.is_some(),
                redacted: m.redacted,
                // The stub is resolved here rather than in the renderer, which
                // has no timeline to look the target up in. A target we do not
                // hold — pruned, or from before we joined — still shows the
                // number: "answering something we cannot see" is the truth,
                // and dropping the marker would hide that a reply is a reply.
                reply_to: m.post.reply_to().map(|t| {
                    let stub = conv
                        .timeline
                        .get(t)
                        .map(|target| match (target.redacted, target.post.body_text()) {
                            (true, _) => "message deleted".to_string(),
                            (_, Some(text)) => text.to_string(),
                            (_, None) => "(nothing to show)".to_string(),
                        })
                        .unwrap_or_else(|| "(not held)".to_string());
                    (t, stub)
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
    app.topic = conv.timeline.topic.clone();
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
    crossterm::execute!(out, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(out))
}

fn stop_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
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

fn endpoint(cli: &Cli, cfg: &Config) -> Result<(std::net::SocketAddr, PubKey), String> {
    let addr = cli
        .server
        .clone()
        .or_else(|| env_nonempty("SQEX_SERVER"))
        .or_else(|| cfg.server.clone())
        .ok_or_else(|| {
            "no server address (pass --server, set SQEX_SERVER, or put it in ~/.sqnr/config)"
                .to_string()
        })?;
    let key = cli
        .server_key
        .clone()
        .or_else(|| env_nonempty("SQEX_SERVER_KEY"))
        .or_else(|| cfg.server_key.clone())
        .ok_or_else(|| {
            "no server key (pass --server-key, set SQEX_SERVER_KEY, or put it in ~/.sqnr/config)"
                .to_string()
        })?;
    let socket = addr
        .parse()
        .map_err(|_| format!("bad server address {addr:?} (use host:port)"))?;
    let server = key.trim().parse().map_err(|e| format!("bad server key: {e}"))?;
    Ok((socket, server))
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
    use sqex_proto::timeline::Received;

    fn conv(peer: u8, label: &str) -> Open {
        Open {
            peer: Some(PubKey::new([peer; 32])),
            public: false,
            label: label.to_string(),
            channel: [7; 32],
            admins: vec![PubKey::new([1; 32]), PubKey::new([peer; 32])],
            timeline: Timeline::new(),
            timeline_len: 0,
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
                group: false,
                public: false,
                unread: 0,
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

        // The line a reader actually sees pairs the name with the key, and
        // never shows one without the other (SIP-21).
        let line = ui::author(&app.said[0].who, &app.said[0].key, app.said[0].mine);
        assert!(line.contains("bob"), "{line}");
        assert!(
            line.contains(&app.said[0].key),
            "the name appeared without the key: {line}"
        );
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
            }],
            &[],
        );
        let open = vec![c];
        let mut app = App {
            rows: vec![Row {
                channel: [7; 32],
                label: ui::short(&bob),
                group: false,
                public: false,
                unread: 0,
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
                group: false,
                public: false,
                unread: 0,
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
                group: false,
                public: false,
                unread: 0,
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
                group: false,
                public: false,
                unread: 0,
                waiting: true,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert!(app.trouble.line().contains("403"));
    }

    #[test]
    fn a_selection_past_the_end_is_pulled_back() {
        // Contacts can go away underneath the cursor.
        let open = vec![conv(2, "bob")];
        let mut app = App {
            selected: 7,
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]), &HashMap::new());
        assert_eq!(app.selected, 0);
        assert_eq!(app.said.len(), 0);
    }

    #[test]
    fn no_contacts_leaves_an_empty_transcript_rather_than_a_panic() {
        let mut app = App {
            selected: 0,
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
}
