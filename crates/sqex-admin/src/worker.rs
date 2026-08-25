//! Background worker: owns the tokio runtime, the HTTP/3 connection, and card
//! access, so the egui UI thread never blocks. The UI sends [`Cmd`]s and
//! receives [`Msg`]s over channels.

use std::net::SocketAddr;
use std::sync::mpsc::Sender as StdSender;

use sqex_core::PubKey;
use sqex_core::protocol::{Action, Command, SignedCommand};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::card::Card;
use crate::client::Client;

/// A request from the UI.
pub enum Cmd {
    Connect {
        addr: String,
        server_pub: String,
    },
    /// Run a signed admin command; `pin` unlocks the card for this action.
    Admin {
        action: Action,
        pin: String,
    },
}

/// A result pushed back to the UI.
pub enum Msg {
    Status(String),
    Connected {
        admin_key: String,
    },
    Whitelist {
        enabled: bool,
        keys: Vec<String>,
    },
    Audit(Vec<String>),
    /// The card is blinking, waiting for a physical touch to sign.
    AwaitingTouch,
    Error(String),
}

struct Session {
    client: Client,
    addr: SocketAddr,
    server: PubKey,
    admin: PubKey,
}

impl Session {
    /// Rebuild the HTTP/3 connection (after an idle timeout or a server
    /// restart), reusing the same address and pinned server key.
    async fn reconnect(&mut self) -> Result<(), String> {
        self.client = Client::connect(self.addr, self.server.as_bytes()).await?;
        Ok(())
    }
}

/// Whether an error looks like a dead/stale connection worth one reconnect.
fn is_connection_error(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    [
        "timeout",
        "closed",
        "connection",
        "reset",
        "h3",
        "not connected",
    ]
    .iter()
    .any(|needle| e.contains(needle))
}

/// Whether a signing error means the card lost its PW1 verification (so we
/// should re-unlock), rather than a genuine refusal.
fn is_pin_lost(e: &str) -> bool {
    let e = e.to_ascii_lowercase();
    e.contains("security status")
}

/// Spawn the worker thread. Returns the sender the UI uses to issue commands.
pub fn spawn(
    msg_tx: StdSender<Msg>,
    ctx: eframe::egui::Context,
) -> tokio::sync::mpsc::UnboundedSender<Cmd> {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = msg_tx.send(Msg::Error(format!("runtime: {e}")));
                return;
            }
        };
        rt.block_on(run(cmd_rx, msg_tx, ctx));
    });
    cmd_tx
}

async fn run(
    mut cmd_rx: UnboundedReceiver<Cmd>,
    msg_tx: StdSender<Msg>,
    ctx: eframe::egui::Context,
) {
    let mut session: Option<Session> = None;
    let card = Card::spawn();
    // Whether the card's PW1 has been verified this session. Set on the first
    // successful unlock; cleared only if a signature later reports the PIN was
    // lost (e.g. the card was removed and reinserted).
    let mut unlocked = false;
    let send = |m: Msg| {
        let _ = msg_tx.send(m);
        ctx.request_repaint();
    };

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Cmd::Connect { addr, server_pub } => match connect(&card, &addr, &server_pub).await {
                Ok(mut sess) => {
                    send(Msg::Connected {
                        admin_key: sess.admin.to_base58(),
                    });
                    // Public status needs no signature — show it immediately.
                    if let Some(s) = fetch_status(&mut sess.client).await {
                        send(Msg::Status(s));
                    }
                    session = Some(sess);
                }
                Err(e) => send(Msg::Error(e)),
            },
            Cmd::Admin { action, pin } => {
                let Some(sess) = session.as_mut() else {
                    send(Msg::Error("not connected".into()));
                    continue;
                };
                match run_admin(sess, &card, &mut unlocked, action.clone(), pin, &send).await {
                    Ok(value) => dispatch_result(&action, value, &send),
                    Err(e) => send(Msg::Error(e)),
                }
            }
        }
    }
}

async fn connect(card: &Card, addr: &str, server_pub: &str) -> Result<Session, String> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| format!("bad server address {addr:?} (use host:port)"))?;
    let server: PubKey = server_pub
        .trim()
        .parse()
        .map_err(|e| format!("bad server key: {e}"))?;
    let admin = PubKey::new(card.pubkey().await?);
    let client = Client::connect(socket, server.as_bytes()).await?;
    Ok(Session {
        client,
        addr: socket,
        server,
        admin,
    })
}

async fn fetch_status(client: &mut Client) -> Option<String> {
    let (_s, body) = client.get("/status").await.ok()?;
    let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
    Some(format!(
        "server {} up {}s · whitelist {} ({} keys)",
        v["version"].as_str().unwrap_or("?"),
        v["uptime_secs"].as_u64().unwrap_or(0),
        if v["whitelist_enabled"].as_bool().unwrap_or(false) {
            "on"
        } else {
            "off"
        },
        v["whitelist_count"].as_u64().unwrap_or(0),
    ))
}

/// Run an admin command, reconnecting once if the connection has gone stale
/// (idle timeout, server restart). The card only signs after a live challenge,
/// so a reconnect re-fetches a fresh nonce and re-signs — no double-apply.
async fn run_admin(
    sess: &mut Session,
    card: &Card,
    unlocked: &mut bool,
    action: Action,
    pin: String,
    notify: &impl Fn(Msg),
) -> Result<serde_json::Value, String> {
    ensure_unlocked(card, unlocked, &pin).await?;
    match run_admin_once(sess, card, action.clone(), notify).await {
        Err(e) if is_connection_error(&e) => {
            sess.reconnect().await?;
            run_admin_once(sess, card, action, notify).await
        }
        Err(e) if is_pin_lost(&e) => {
            // The card session dropped its PIN (removed/reinserted). Re-verify
            // once and retry — this re-prompts nothing new; the PIN is still in
            // hand from this action.
            *unlocked = false;
            ensure_unlocked(card, unlocked, &pin).await?;
            run_admin_once(sess, card, action, notify).await
        }
        other => other,
    }
}

/// Verify the card PIN once for the session.
async fn ensure_unlocked(card: &Card, unlocked: &mut bool, pin: &str) -> Result<(), String> {
    if !*unlocked {
        card.unlock(pin.to_string()).await?;
        *unlocked = true;
    }
    Ok(())
}

/// Fetch a challenge, sign the command on the card (touch), POST it, return JSON.
async fn run_admin_once(
    sess: &mut Session,
    card: &Card,
    action: Action,
    notify: &impl Fn(Msg),
) -> Result<serde_json::Value, String> {
    let (cs, nonce_bytes) = sess.client.get("/admin/challenge").await?;
    if cs != 200 || nonce_bytes.len() != 32 {
        return Err(format!("challenge failed (status {cs})"));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let command = Command {
        action,
        nonce,
        server: sess.server,
    };

    // With touch enabled the card blocks until tapped — prompt for it.
    notify(Msg::AwaitingTouch);
    let sig = card.sign(command.signing_bytes()).await?;

    let signed = SignedCommand {
        command,
        admin: sess.admin,
        signature: sig,
    };
    let (status, body) = sess.client.post("/admin/command", signed.encode()).await?;
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    if status != 200 {
        let detail = value["detail"].as_str().unwrap_or("").to_string();
        let kind = value["error"].as_str().unwrap_or("error");
        return Err(format!("{kind} ({status}) {detail}"));
    }
    Ok(value)
}

fn dispatch_result(action: &Action, value: serde_json::Value, send: &impl Fn(Msg)) {
    match action {
        Action::WhitelistList => {
            let enabled = value["enabled"].as_bool().unwrap_or(false);
            let keys = value["keys"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            send(Msg::Whitelist { enabled, keys });
        }
        Action::AuditTail(_) => {
            let rows = value["entries"]
                .as_array()
                .map(|a| a.iter().map(format_audit).collect())
                .unwrap_or_default();
            send(Msg::Audit(rows));
        }
        other => send(Msg::Status(format!("{}: {}", other.name(), value))),
    }
}

fn format_audit(e: &serde_json::Value) -> String {
    let time = e["time"].as_u64().unwrap_or(0);
    let admin = e["admin"].as_str().unwrap_or("?");
    let action = e["action"].as_str().unwrap_or("?");
    let target = e["target"]
        .as_str()
        .map(|t| format!(" {t}"))
        .unwrap_or_default();
    let short: String = admin.chars().take(8).collect();
    format!("[{time}] {short}… {action}{target}")
}
