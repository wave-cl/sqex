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
use sqnr::{Backend, Card, Client, config::Config, flow, identity};
use sqnr_core::{Operation, PubKey, Transaction};

#[derive(Parser)]
#[command(name = "sqex", version, about = "Administer a sqex server with signed transactions")]
struct Cli {
    /// Server address, host:port (overrides ~/.sqnr/config).
    #[arg(long, global = true)]
    server: Option<String>,

    /// Server's pinned Ed25519 public key, base58 (overrides ~/.sqnr/config).
    #[arg(long = "server-key", global = true)]
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
        Cmd::Whitelist { action } => whitelist(&cli, &cfg, action).await,
        Cmd::Audit { count } => {
            let v = submit(&cli, &cfg, vec![Op::AuditTail(*count).to_operation()]).await?;
            print_audit(&result(&v, 0));
            Ok(())
        }
        Cmd::ReloadAdmins => {
            let v = submit(&cli, &cfg, vec![Op::ReloadAdmins.to_operation()]).await?;
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
    let addr = cli
        .server
        .clone()
        .or_else(|| cfg.server.clone())
        .ok_or_else(|| "no server address (pass --server or set it in ~/.sqnr/config)".to_string())?;
    let key = cli
        .server_key
        .clone()
        .or_else(|| cfg.server_key.clone())
        .ok_or_else(|| "no server key (pass --server-key or set it in ~/.sqnr/config)".to_string())?;
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| format!("bad server address {addr:?} (use host:port)"))?;
    let server: PubKey = key.trim().parse().map_err(|e| format!("bad server key: {e}"))?;
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
