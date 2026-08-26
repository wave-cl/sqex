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
use sqex_proto::timeline::Timeline;
use sqnr::{Client, config::Config, identity};
use sqnr_core::Signer;
use sqex_proto::channel::Role;
use sqnr_core::PubKey;

mod ui;

use ui::{App, Row, Said, Trouble, short};

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

Group channels exist in the exchange and this client has no interface for them \
yet; it shows direct messages only."
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
    }

    let (addr, server) = endpoint(&cli, &cfg)?;
    let client = Client::connect_as(addr, server.as_bytes(), &seed)
        .await
        .map_err(|e| format!("could not reach {addr}: {e}"))?;
    let mut chat = Chat::new(client, seed, me, store);
    chat.top_up_prekeys()
        .await
        .map_err(|e| format!("publishing prekeys: {e}"))?;

    interface(chat).await
}

/// One open conversation's live state.
///
/// Keyed by channel, not by contact. A direct message has a peer and a group
/// does not, which is the whole of the difference at this level — everything
/// below is the same log, the same epoch key and the same timeline.
struct Open {
    /// The other party, for a direct message. `None` for a group.
    peer: Option<PubKey>,
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
        let admins = match chat.info(&m.channel).await {
            Ok(info) => info
                .members
                .iter()
                .filter(|mem| mem.role == Role::Admin)
                .map(|mem| mem.account)
                .collect(),
            Err(_) => remembered.map(|k| k.3.clone()).unwrap_or_default(),
        };

        let label = match &peer {
            Some((_, l)) => l.clone(),
            // A group's name is a sealed entry, so it is not known until the
            // log is read. Until then it is called by its identifier, which is
            // at least unambiguous.
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
            label,
            channel: m.channel,
            admins,
            timeline,
            timeline_len,
            trouble: Trouble::default(),
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
            label: c.label.clone(),
            channel,
            admins: vec![chat.me, c.account],
            timeline: Timeline::default(),
            timeline_len: 0,
            trouble: Trouble::default(),
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
        refresh(app, open, &chat.me);
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
            conv.trouble.gap = got.gap;
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
                return;
            }
            let cmd = Command::parse(&text);
            // `/new` is the one command that needs no conversation, and it has
            // to be: with none open there is nothing selected, and requiring a
            // selection would mean the first group could never be made.
            if let Command::New(name) = &cmd {
                let note = match chat.create_group(name, &[]).await {
                    Ok(_) => format!("made {name} — /invite <key> to add somebody"),
                    Err(e) => e.to_string(),
                };
                if let Ok(fresh) = sync_channels(chat).await {
                    *open = fresh;
                    app.selected = open.len().saturating_sub(1);
                    if let Some(last) = open.last_mut() {
                        last.trouble.message = Some(note);
                    }
                } else {
                    app.trouble.message = Some(note);
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
            let restructured = matches!(cmd, Command::Leave);
            let outcome = match cmd {
                Command::Send(text) => chat.send(&channel, &text).await.map(|_| None),
                Command::File(path) => send_file(chat, &channel, &path).await.map(Some),
                Command::Save(seq, path) => save_file(chat, &open[i], seq, &path).await.map(Some),
                // Handled above: it needs no conversation.
                Command::New(_) => Ok(None),
                Command::Name(name) => match chat.set_name(&channel, &name).await {
                    Ok(_) => Ok(Some(format!("renamed to {name}"))),
                    Err(e) => Err(e),
                },
                Command::Invite(key) => match key.parse::<PubKey>() {
                    Ok(who) => chat
                        .invite(&channel, &who)
                        .await
                        .map(|()| Some(format!("invited {}", short(&who)))),
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
                Command::Leave => chat.leave(&channel).await.map(|()| {
                    Some("left — it will be gone from the list next time".to_string())
                }),
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
                    open[i].trouble.message = note.clone();
                    note
                }
                Err(ChatError::NotReady(_)) => {
                    open[i].waiting = true;
                    None
                }
                Err(e) => {
                    open[i].trouble.message = Some(e.to_string());
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
                    last.trouble.message = Some(n);
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
    /// `/invite <key>` — add somebody, and give them the key.
    Invite(String),
    /// `/kick <key>` — remove somebody, and rotate so what follows is not theirs.
    Kick(String),
    /// `/name <name>` — rename, as a sealed entry the exchange cannot read.
    Name(String),
    /// `/rotate` — mint a new key for everyone currently here.
    Rotate,
    /// `/leave` — leave this channel.
    Leave,
    /// `/who` — who is in here.
    Who,
    Unknown(String),
}

impl Command {
    fn parse(line: &str) -> Command {
        let trimmed = line.trim();
        if !trimmed.starts_with('/') {
            return Command::Send(line.to_string());
        }
        let mut words = trimmed.splitn(3, char::is_whitespace);
        let verb = words.next().unwrap_or("");
        match verb {
            "/file" => match words.next() {
                Some(rest) => {
                    // The rest of the line, so a path with spaces in it works
                    // without anybody having to think about quoting.
                    let mut path = rest.to_string();
                    if let Some(more) = words.next() {
                        path.push(' ');
                        path.push_str(more);
                    }
                    Command::File(expand(path.trim()))
                }
                None => Command::Unknown("/file needs a path".into()),
            },
            "/save" => match (words.next(), words.next()) {
                (Some(n), Some(path)) => match n.parse::<u64>() {
                    Ok(seq) => Command::Save(seq, expand(path.trim())),
                    Err(_) => Command::Unknown(format!("{n} is not a message number")),
                },
                _ => Command::Unknown("/save needs a message number and a path".into()),
            },
            "/new" => match words.next() {
                Some(name) => Command::New(name.trim().to_string()),
                None => Command::Unknown("/new needs a name".into()),
            },
            "/name" => match words.next() {
                Some(name) => Command::Name(name.trim().to_string()),
                None => Command::Unknown("/name needs a name".into()),
            },
            "/invite" => match words.next() {
                Some(key) => Command::Invite(key.trim().to_string()),
                None => Command::Unknown("/invite needs a public key".into()),
            },
            "/kick" => match words.next() {
                Some(key) => Command::Kick(key.trim().to_string()),
                None => Command::Unknown("/kick needs a public key".into()),
            },
            "/rotate" => Command::Rotate,
            "/leave" => Command::Leave,
            "/who" => Command::Who,
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
        label,
        channel,
        admins: vec![chat.me, account],
        timeline: Timeline::new(),
        timeline_len: 0,
        trouble: Trouble::default(),
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
fn refresh(app: &mut App, open: &[Open], me: &PubKey) {
    app.rows = open
        .iter()
        .map(|o| Row {
            channel: o.channel,
            label: o.label.clone(),
            group: o.peer.is_none(),
            unread: o.unread,
            waiting: o.waiting,
        })
        .collect();
    if app.selected >= app.rows.len() {
        app.selected = app.rows.len().saturating_sub(1);
    }
    let Some(conv) = selected_index(open, app).map(|i| &open[i]) else {
        app.said.clear();
        return;
    };
    app.said = conv
        .timeline
        .messages()
        .filter(|m| m.is_visible())
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
                // In a direct message the other party is the conversation, so
                // its name serves. In a group there are several, and only the
                // key distinguishes them — a display name is a claim its
                // subject makes (SIP-21), so it is not what goes here.
                who: if m.account == *me {
                    "you".to_string()
                } else if conv.peer.is_some() {
                    conv.label.clone()
                } else {
                    short(&m.account)
                },
                mine: m.account == *me,
                text,
                seq: m.seq,
                has_file,
                at: m.posted,
                edited: m.edited.is_some(),
            }
        })
        .collect();
    app.peer_typing = conv.typing;
    app.trouble = Trouble {
        unreadable: conv.trouble.unreadable,
        no_key: conv.trouble.no_key,
        gap: conv.trouble.gap,
        message: conv
            .trouble
            .message
            .clone()
            .or_else(|| conv.waiting.then(|| {
                format!("{} has not started their client yet — nothing can be sent until they do", conv.label)
            })),
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
            label: label.to_string(),
            channel: [7; 32],
            admins: vec![PubKey::new([1; 32]), PubKey::new([peer; 32])],
            timeline: Timeline::new(),
            timeline_len: 0,
            trouble: Trouble::default(),
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
                unread: 0,
                waiting: false,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]));
        assert_eq!(app.said.len(), 2);
        assert_eq!(app.said[0].who, "bob");
        assert!(!app.said[0].mine);
        // Anything not from the peer is ours: a direct message has two members,
        // so there is no third case to get wrong.
        assert_eq!(app.said[1].who, "you");
        assert!(app.said[1].mine);
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
                unread: 0,
                waiting: true,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]));
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
                unread: 0,
                waiting: true,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open, &PubKey::new([1; 32]));
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
        refresh(&mut app, &open, &PubKey::new([1; 32]));
        assert_eq!(app.selected, 0);
        assert_eq!(app.said.len(), 0);
    }

    #[test]
    fn no_contacts_leaves_an_empty_transcript_rather_than_a_panic() {
        let mut app = App {
            selected: 0,
            ..Default::default()
        };
        refresh(&mut app, &[], &PubKey::new([1; 32]));
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
