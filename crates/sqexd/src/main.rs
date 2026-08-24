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
