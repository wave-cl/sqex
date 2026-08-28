//! Server configuration: a TOML file, command-line flags, or both.
//!
//! Two structs, following the sqns pattern: `FileConfig` is the raw TOML shape
//! (every field defaulted, unknown fields rejected), and `Config` is the parsed
//! and resolved form the server actually runs on.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use sqnr_core::key::PubKey;
use sqnr_core::{Error, Result};

/// Default UDP port for sqex.
pub const DEFAULT_PORT: u16 = 5400;

fn default_listen() -> String {
    format!("[::]:{DEFAULT_PORT}")
}

fn default_challenge_ttl() -> u64 {
    30
}

/// The TOML file's shape. Every field except `key_file` has a default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Address to listen on. Default `[::]:5400`.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Hex Ed25519 seed for this server's identity.
    pub key_file: PathBuf,
    /// Where the managed whitelist and audit log are snapshotted. Omit to keep
    /// them in memory only (lost on restart).
    #[serde(default)]
    pub state_file: Option<PathBuf>,
    /// Base58 Ed25519 public keys permitted to issue admin commands.
    #[serde(default)]
    pub admins: Vec<String>,
    /// Base58 Ed25519 keys the managed whitelist starts with on first run.
    /// Ignored once a `state_file` exists (runtime state wins).
    #[serde(default)]
    pub seed_whitelist: Vec<String>,
    /// How long an issued challenge nonce stays valid, in seconds.
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl_secs: u64,

    /// The sQUIC envelope versions this server parses (SIP-29). Omitted means
    /// squic's own default, which is both. Narrowing it to `[2]` retires
    /// version 1, after which clients older than sqex v0.11.0 cannot reach
    /// this exchange at all.
    ///
    /// Deliberately `Option`: resolving an omitted key to a hard-coded list
    /// would silently override squic's default and pin whatever this file
    /// happened to say when it was written.
    #[serde(default)]
    pub accepted_envelope_versions: Option<Vec<u8>>,
}

/// Configuration with everything parsed and resolved.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub key_file: PathBuf,
    pub state_file: Option<PathBuf>,
    pub admins: Vec<PubKey>,
    pub seed_whitelist: Vec<PubKey>,
    pub challenge_ttl: std::time::Duration,
    pub accepted_envelope_versions: Option<Vec<u8>>,
}

impl FileConfig {
    /// Parse the string forms into their resolved types.
    pub fn resolve(self) -> Result<Config> {
        let listen = parse_listen(&self.listen)?;
        let admins = parse_keys(&self.admins, "admins")?;
        let seed_whitelist = parse_keys(&self.seed_whitelist, "seed_whitelist")?;

        // SIP-29 reserves version 0 and forbids emitting it, and an empty list
        // would refuse every caller in silence — both are configuration
        // mistakes worth catching at load rather than at the first dropped
        // Initial.
        if let Some(versions) = &self.accepted_envelope_versions
            && (versions.is_empty() || versions.contains(&0))
        {
            return Err(Error::Malformed(
                "accepted_envelope_versions must be a non-empty list without 0".into(),
            ));
        }

        Ok(Config {
            listen,
            key_file: self.key_file,
            state_file: self.state_file,
            admins,
            seed_whitelist,
            challenge_ttl: std::time::Duration::from_secs(self.challenge_ttl_secs.max(1)),
            accepted_envelope_versions: self.accepted_envelope_versions,
        })
    }
}

impl Config {
    pub fn from_file(path: &std::path::Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Malformed(format!("cannot read {}: {e}", path.display())))?;
        let file: FileConfig = toml::from_str(&text)
            .map_err(|e| Error::Malformed(format!("cannot parse {}: {e}", path.display())))?;
        file.resolve()
    }
}

fn parse_keys(raw: &[String], field: &str) -> Result<Vec<PubKey>> {
    raw.iter()
        .map(|s| {
            s.parse::<PubKey>()
                .map_err(|e| Error::Key(format!("{field}: {s} is not a valid key: {e}")))
        })
        .collect()
}

/// Accepts `host:port`, a bare IP (default port), or a bare port.
fn parse_listen(s: &str) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            port,
        ));
    }
    Err(Error::Malformed(format!(
        "cannot parse listen address {s:?}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_config() {
        let admin = PubKey::new([1u8; 32]).to_base58();
        let seed = PubKey::new([2u8; 32]).to_base58();
        let toml_text = format!(
            r#"
            listen = "127.0.0.1:5400"
            key_file = "/tmp/sqex.key"
            state_file = "/tmp/sqex.state"
            admins = ["{admin}"]
            seed_whitelist = ["{seed}"]
            challenge_ttl_secs = 15
            "#
        );
        let cfg: FileConfig = toml::from_str(&toml_text).unwrap();
        let cfg = cfg.resolve().unwrap();
        assert_eq!(cfg.admins, vec![PubKey::new([1u8; 32])]);
        assert_eq!(cfg.seed_whitelist, vec![PubKey::new([2u8; 32])]);
        assert_eq!(cfg.challenge_ttl.as_secs(), 15);
        assert_eq!(cfg.listen.port(), 5400);
    }

    #[test]
    fn rejects_unknown_fields() {
        let toml_text = r#"key_file = "/x"
            bogus = 1
        "#;
        assert!(toml::from_str::<FileConfig>(toml_text).is_err());
    }

    #[test]
    fn defaults_apply() {
        let cfg: FileConfig = toml::from_str(r#"key_file = "/x""#).unwrap();
        let cfg = cfg.resolve().unwrap();
        assert!(cfg.admins.is_empty());
        assert_eq!(cfg.challenge_ttl.as_secs(), 30);
        assert_eq!(cfg.listen.port(), DEFAULT_PORT);
    }

    /// SIP-29. An omitted key must stay omitted so squic's own default applies:
    /// resolving it to a hard-coded list here would pin whatever this file said
    /// when it was written, which is how sqssh v0.4.0 kept emitting envelope
    /// version 1 after squic moved its default and locked its clients out of a
    /// server that had retired it.
    #[test]
    fn accepted_envelope_versions_is_unset_unless_named() {
        let base = "key_file = \"/tmp/k\"\n";

        let unset: FileConfig = toml::from_str(base).unwrap();
        assert_eq!(unset.resolve().unwrap().accepted_envelope_versions, None);

        let retired: FileConfig =
            toml::from_str(&format!("{base}accepted_envelope_versions = [2]\n")).unwrap();
        assert_eq!(
            retired.resolve().unwrap().accepted_envelope_versions,
            Some(vec![2])
        );

        // Version 0 is reserved, and an empty list would refuse everyone in
        // silence. Both are caught at load.
        for bad in ["[0]", "[]", "[1, 0]"] {
            let cfg: FileConfig =
                toml::from_str(&format!("{base}accepted_envelope_versions = {bad}\n")).unwrap();
            assert!(cfg.resolve().is_err(), "{bad} should be refused");
        }
    }
}
