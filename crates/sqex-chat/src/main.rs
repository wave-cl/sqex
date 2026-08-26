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
use sqex_chat::client::{Chat, ChatError};
use sqex_chat::store::{Store, store_path};
use sqex_proto::timeline::Timeline;
use sqnr::{Client, config::Config, identity};
use sqnr_core::Signer;
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
is nothing to look up and nothing to join. The consequence is worth knowing \
before you rely on it: the exchange has no way to tell you who has written to \
you, so this client can only show conversations with people you have added. A \
message from an account you have not added cannot be seen.

Your keys live in ~/.sqex/chat, sealed under your identity. Lose that directory \
and the conversations in it cannot be read again by anyone, including you — \
that is the forward secrecy working, not a fault."
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
    /// Add somebody, so their messages can be seen. Discovery is this list.
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
struct Open {
    peer: PubKey,
    label: String,
    channel: [u8; 32],
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

async fn interface(mut chat: Chat) -> Result<(), String> {
    let contacts = chat.store().contacts().map_err(|e| e.to_string())?;
    let mut open: Vec<Open> = Vec::new();
    for c in &contacts {
        let channel = chat.dm_with(&c.account);
        // What this client kept last time. Not a cache: the entries are still
        // on the exchange and will not open again, so this is the conversation.
        let timeline = chat.history(&channel, &c.account).unwrap_or_default();
        let timeline_len = timeline.messages().count();
        open.push(Open {
            peer: c.account,
            label: c.label.clone(),
            channel,
            timeline,
            timeline_len,
            trouble: Trouble::default(),
            typing: false,
            unread: 0,
            waiting: false,
        });
    }

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
        match chat.open_dm(&conv.peer).await {
            Ok(_) => {}
            Err(ChatError::NotReady(_)) => conv.waiting = true,
            Err(e) => conv.trouble.message = Some(e.to_string()),
        }
    }

    let mut poll_at = tokio::time::Instant::now();
    loop {
        refresh(app, open);
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
                .map(|r| r.account == conv.peer)
                .unwrap_or(false);
            if after > before && !selected {
                conv.unread += after - before;
            }
            conv.timeline_len = after;
            conv.waiting = false;
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
            let Some(i) = selected_index(open, app) else {
                return;
            };
            let (channel, peer) = (open[i].channel, open[i].peer);
            match chat.send(&channel, &peer, &text).await {
                Ok(_) => open[i].trouble.message = None,
                Err(ChatError::NotReady(_)) => open[i].waiting = true,
                Err(e) => open[i].trouble.message = Some(e.to_string()),
            }
            poll_one(chat, &mut open[i], app).await;
        }
        _ => {}
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
    if open.iter().any(|o| o.peer == account) {
        return;
    }
    let label = short(&account);
    if let Err(e) = chat.store().add_contact(&account, &label, now()) {
        app.trouble.message = Some(e.to_string());
        return;
    }
    let channel = chat.dm_with(&account);
    let mut conv = Open {
        peer: account,
        label,
        channel,
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
    open.iter().position(|o| o.peer == row.account)
}

fn clear_unread(open: &mut [Open], app: &App) {
    if let Some(row) = app.rows.get(app.selected)
        && let Some(o) = open.iter_mut().find(|o| o.peer == row.account)
    {
        o.unread = 0;
    }
}

/// Rebuild what is on screen from what the client knows.
fn refresh(app: &mut App, open: &[Open]) {
    app.rows = open
        .iter()
        .map(|o| Row {
            account: o.peer,
            label: o.label.clone(),
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
        .map(|m| Said {
            who: if m.account == conv.peer {
                conv.label.clone()
            } else {
                "you".to_string()
            },
            mine: m.account != conv.peer,
            text: m.post.body_text().unwrap_or("(nothing to show)").to_string(),
            at: m.posted,
            edited: m.edited.is_some(),
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
            peer: PubKey::new([peer; 32]),
            label: label.to_string(),
            channel: [7; 32],
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
                account: PubKey::new([2; 32]),
                label: "bob".into(),
                unread: 0,
                waiting: false,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open);
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
                account: PubKey::new([2; 32]),
                label: "bob".into(),
                unread: 0,
                waiting: true,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open);
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
                account: PubKey::new([2; 32]),
                label: "bob".into(),
                unread: 0,
                waiting: true,
            }],
            ..Default::default()
        };
        refresh(&mut app, &open);
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
        refresh(&mut app, &open);
        assert_eq!(app.selected, 0);
        assert_eq!(app.said.len(), 0);
    }

    #[test]
    fn no_contacts_leaves_an_empty_transcript_rather_than_a_panic() {
        let mut app = App {
            selected: 0,
            ..Default::default()
        };
        refresh(&mut app, &[]);
        assert!(app.rows.is_empty());
        assert!(app.said.is_empty());
    }
}
