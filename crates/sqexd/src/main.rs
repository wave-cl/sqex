//! `sqexd` — the sqex exchange server.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use sqexd::config::{Config, DEFAULT_PORT};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "sqexd",
    version,
    about = "The sqex exchange server (HTTP/3 over sQUIC)"
)]
struct Cli {
    /// Config file (TOML). Defaults to /etc/sqex/sqexd.toml when it exists.
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,
    /// Override the listen address (host:port, IP, or port).
    #[arg(short = 'l', long)]
    listen: Option<String>,
    /// Override the identity key file (hex Ed25519 seed).
    #[arg(short = 'k', long)]
    key_file: Option<PathBuf>,
    /// Print this server's public key and exit.
    #[arg(long)]
    show_pubkey: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new identity key at the given path (or the default).
    Keygen {
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,
    },
    /// Sign a SIP-40 handover from this exchange's key to its successor, and
    /// print the TXT record to publish at `_sqex.<domain>` beside the
    /// successor's own `k=` record.
    ///
    /// Nothing is changed by this command. The record is inert until it is
    /// in the zone next to a `k=<to>` record; a client moves its pin only when
    /// both agree. Once published it cannot be withdrawn, only outlived —
    /// which is why the expiry is capped and why this prints exactly what it
    /// signed before it signs.
    Handover {
        /// The successor's public key, base58 — `sqexd -k <new> --show-pubkey`.
        #[arg(long)]
        to: String,
        /// The domain the record will be published under. Bound into the
        /// signature, so a handover for one zone cannot be replayed under
        /// another this key happens to serve.
        #[arg(long)]
        domain: String,
        /// How long the handover stands, in days. At most 30 (SIP-40).
        #[arg(long, default_value_t = 14)]
        days: u64,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("SQEXD_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr) // keep stdout clean for --show-pubkey
        .init();

    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sqexd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    if let Some(Command::Keygen { file }) = &cli.command {
        let path = file.clone().unwrap_or(default_key_path());
        keygen(&path)?;
        return Ok(ExitCode::SUCCESS);
    }

    let config = build_config(&cli)?;

    if let Some(Command::Handover { to, domain, days }) = &cli.command {
        let lineage_file = config.lineage_file.clone();
        // Never `load_or_create`: a handover from a key that did not exist
        // until this moment is a handover from nobody, and the created key
        // would look like the exchange's identity to whoever read the file
        // next.
        if !config.key_file.exists() {
            return Err(format!(
                "key file {} does not exist; a handover is signed by the key being retired",
                config.key_file.display()
            )
            .into());
        }
        let signing_key = load_or_create_key(&config.key_file, true)?;
        handover(&signing_key, to, domain, *days, &lineage_file)?;
        return Ok(ExitCode::SUCCESS);
    }

    let signing_key = load_or_create_key(&config.key_file, cli.key_file.is_some())?;

    if cli.show_pubkey {
        let pub_bytes = signing_key.verifying_key().to_bytes();
        println!("{}", bs58::encode(pub_bytes).into_string());
        return Ok(ExitCode::SUCCESS);
    }

    let config_path = resolved_config_path(&cli);
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let bound = sqexd::bind(config, config_path, signing_key).await?;
        sqexd::serve(bound).await
    })?;
    Ok(ExitCode::SUCCESS)
}

/// Merge the config file (or defaults) with CLI overrides.
fn build_config(cli: &Cli) -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = match resolved_config_path(cli) {
        Some(path) => Config::from_file(&path)?,
        None => {
            // No file: synthesize defaults with a default key path.
            let file: sqexd::config::FileConfig = toml::from_str(&format!(
                "key_file = {:?}",
                default_key_path().to_string_lossy()
            ))?;
            file.resolve()?
        }
    };
    if let Some(listen) = &cli.listen {
        config.listen = parse_listen_flag(listen)?;
    }
    if let Some(key_file) = &cli.key_file {
        config.key_file = key_file.clone();
    }
    Ok(config)
}

/// The config path actually in effect: the explicit flag, else the system path
/// when it exists, else none (built-in defaults).
fn resolved_config_path(cli: &Cli) -> Option<PathBuf> {
    if let Some(p) = &cli.config {
        return Some(p.clone());
    }
    let system = PathBuf::from("/etc/sqex/sqexd.toml");
    system.exists().then_some(system)
}

fn parse_listen_flag(s: &str) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    if let Ok(a) = s.parse() {
        return Ok(a);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, DEFAULT_PORT));
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            port,
        ));
    }
    Err(format!("cannot parse listen address {s:?}").into())
}

fn running_as_root() -> bool {
    // Safe: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn default_key_path() -> PathBuf {
    if running_as_root() {
        PathBuf::from("/etc/sqex/host_key")
    } else {
        dirs::home_dir()
            .map(|h| h.join(".sqex/host_key"))
            .unwrap_or_else(|| PathBuf::from("sqex_host_key"))
    }
}

/// Load a hex seed, or create one on first run. A key path given *explicitly*
/// must already exist — fail loud on a typo rather than minting a new identity.
fn load_or_create_key(
    path: &Path,
    explicit: bool,
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if path.exists() {
        let (sk, _pub) = squic::load_keypair(std::fs::read_to_string(path)?.trim())?;
        return Ok(sk);
    }
    if explicit {
        return Err(format!("key file {} does not exist", path.display()).into());
    }
    keygen(path)?;
    let (sk, _pub) = squic::load_keypair(std::fs::read_to_string(path)?.trim())?;
    Ok(sk)
}

/// Sign a SIP-40 handover and print the record. See `Command::Handover`.
fn handover(
    signing_key: &SigningKey,
    to: &str,
    domain: &str,
    days: u64,
    lineage_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use ed25519_dalek::Signer;
    use sqex_discovery::{HANDOVER_MAX_SECS, Handover};
    use sqnr_core::PubKey;

    let from = PubKey::new(signing_key.verifying_key().to_bytes());
    let to: PubKey = to
        .parse()
        .map_err(|_| format!("--to {to:?} is not a 32-byte base58 key"))?;
    if to == from {
        return Err("--to is this exchange's own key; a handover names a successor".into());
    }
    let domain = sqex_discovery::record::canonical_domain(domain);
    if domain.is_empty() || domain.len() > 255 || domain.contains(char::is_whitespace) {
        return Err(format!("--domain {domain:?} is not a domain").into());
    }
    let secs = days
        .checked_mul(86_400)
        .filter(|s| *s <= HANDOVER_MAX_SECS)
        .ok_or_else(|| {
            format!(
                "--days {days} is beyond the SIP-40 cap of {} days",
                HANDOVER_MAX_SECS / 86_400
            )
        })?;
    if secs == 0 {
        return Err("--days must be at least 1".into());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let until = now + secs;

    let input = Handover::signing_input(&domain, &from, &to, until);
    let sig = signing_key.sign(&input).to_bytes();
    let h = Handover {
        from,
        to,
        until,
        sig,
    };
    debug_assert!(h.verify(&domain));

    eprintln!("sqexd: signing a SIP-40 handover");
    eprintln!("  domain: {domain}");
    eprintln!("  from:   {from}  (this exchange's key)");
    eprintln!("  to:     {to}");
    eprintln!("  until:  {until}  ({days} days from now)");
    eprintln!();
    eprintln!("Publish this TXT record at _sqex.{domain}, beside a `v=sqex1; k={to}` record:");
    eprintln!();
    println!("{}", h.render());
    eprintln!();
    eprintln!(
        "It grants nothing until `k={to}` is published too, and cannot be withdrawn once \
         published — only outlived, at {until}."
    );
    // SIP-40 §Lineage: kept, so the successor serves it as its lineage for as long
    // as the history it covers -- the zone keeps it thirty days at most.
    sqexd::lineage::append(lineage_file, &domain, &h).map_err(|e| {
        format!(
            "cannot keep the handover in {}: {e}",
            lineage_file.display()
        )
    })?;
    eprintln!(
        "Kept in {} (SIP-40): the daemon running as `{to}` serves it as its lineage.",
        lineage_file.display()
    );
    Ok(())
}

/// Write a fresh hex Ed25519 seed to `path`, mode 0600.
fn keygen(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let (signing_key, pub_bytes) = squic::generate_keypair();
    let hex_seed = hex::encode(signing_key.to_bytes());
    std::fs::write(path, &hex_seed)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    eprintln!(
        "sqexd: wrote new identity to {} (public key {})",
        path.display(),
        bs58::encode(pub_bytes).into_string()
    );
    Ok(())
}
