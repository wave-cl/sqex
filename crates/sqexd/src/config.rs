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
/// 443/udp — HTTP/3's own port. See `sqex_discovery::DEFAULT_PORT`.
pub const DEFAULT_PORT: u16 = 443;

fn default_listen() -> String {
    format!("[::]:{DEFAULT_PORT}")
}

fn default_challenge_ttl() -> u64 {
    30
}

fn default_welcome_channel() -> String {
    "general".to_string()
}

/// The TOML file's shape. Every field except `key_file` has a default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Address to listen on. Default `[::]:443`.
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

    /// A public channel every account is put into the first time it appears,
    /// created on first boot if it is not there. Empty turns it off.
    ///
    /// An exchange with nothing in it is a room with no doors: a new account
    /// can find nobody and be found by nobody until somebody hands it a
    /// sixty-four character key out of band. This is the front door.
    #[serde(default = "default_welcome_channel")]
    pub welcome_channel: String,

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

    /// SIP-35: base58 Ed25519 identities of exchanges this one will serve
    /// replication to.
    ///
    /// The **operational** half of the gate, and only that half. Being on this
    /// list lets a peer speak the peering routes at all; it does not give it a
    /// single channel, which takes a signed authorisation by one of that
    /// channel's admins. Empty — the default — means this exchange serves
    /// replication to nobody and its peering routes refuse everyone
    /// identically.
    #[serde(default)]
    pub replication_peers: Vec<String>,

    /// SIP-35: origins this exchange replicates *from*.
    ///
    /// The other direction from `replication_peers`, and both ends of a link
    /// need their own entry: an origin lists the peer it will serve, and the
    /// replica lists the origin it pulls from. Neither implies the other, and
    /// neither is enough on its own — the origin's members must also have
    /// signed a `0x0b` for each channel.
    #[serde(default)]
    pub replicate: Vec<FileOrigin>,
}

/// One origin to replicate from.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOrigin {
    /// The origin's base58 Ed25519 identity — its SIP-9 key.
    ///
    /// **Pinned from here and never taken from the wire.** SIP-35 calls this
    /// the trap in the whole document: a replica that accepted the signing key
    /// from the party supplying the entries has been handed the forgery power
    /// the design spends its length removing.
    pub origin: String,
    /// `host:port` to dial.
    pub addr: String,
    /// Base58 channel identifiers to pull. A channel the origin has not
    /// authorised us for is refused, in the same words as everything else.
    #[serde(default)]
    pub channels: Vec<String>,
    /// Seconds between pulls. Clamped up to SIP-35's `PEER_MIN_INTERVAL`.
    #[serde(default = "default_pull_interval")]
    pub interval_secs: u64,
}

fn default_pull_interval() -> u64 {
    30
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
    /// The channel every account joins on first sight. Empty is off.
    pub welcome_channel: String,
    pub accepted_envelope_versions: Option<Vec<u8>>,
    pub replication_peers: Vec<PubKey>,
    pub replicate: Vec<OriginConfig>,
}

/// One resolved origin to replicate from.
#[derive(Debug, Clone)]
pub struct OriginConfig {
    pub origin: PubKey,
    pub addr: SocketAddr,
    pub channels: Vec<[u8; 32]>,
    pub interval: std::time::Duration,
}

impl FileConfig {
    /// Parse the string forms into their resolved types.
    pub fn resolve(self) -> Result<Config> {
        let listen = parse_listen(&self.listen)?;
        let admins = parse_keys(&self.admins, "admins")?;
        let seed_whitelist = parse_keys(&self.seed_whitelist, "seed_whitelist")?;
        let replication_peers = parse_keys(&self.replication_peers, "replication_peers")?;
        // SIP-35 caps the peers an origin will serve, and an operator who set
        // more should hear so at load rather than discover that some of them
        // are silently ignored.
        if replication_peers.len() > sqex_proto::peer::MAX_PEERS {
            return Err(Error::Malformed(format!(
                "replication_peers holds {}, limit is {}",
                replication_peers.len(),
                sqex_proto::peer::MAX_PEERS
            )));
        }

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

        let mut replicate = Vec::new();
        for r in self.replicate {
            let origin = r
                .origin
                .parse::<PubKey>()
                .map_err(|e| Error::Key(format!("replicate.origin {}: {e}", r.origin)))?;
            let addr = parse_listen(&r.addr)?;
            let mut channels = Vec::new();
            for c in &r.channels {
                let key = c
                    .parse::<PubKey>()
                    .map_err(|e| Error::Key(format!("replicate.channels {c}: {e}")))?;
                channels.push(*key.as_bytes());
            }
            replicate.push(OriginConfig {
                origin,
                addr,
                channels,
                // Clamped rather than refused: an operator asking to pull more
                // often than SIP-35 permits is not making an error, and a
                // replica that hammered an origin would be one.
                interval: std::time::Duration::from_secs(
                    r.interval_secs.max(sqex_proto::peer::PEER_MIN_INTERVAL),
                ),
            });
        }

        Ok(Config {
            listen,
            key_file: self.key_file,
            state_file: self.state_file,
            admins,
            seed_whitelist,
            challenge_ttl: std::time::Duration::from_secs(self.challenge_ttl_secs.max(1)),
            welcome_channel: self.welcome_channel.trim().to_string(),
            accepted_envelope_versions: self.accepted_envelope_versions,
            replication_peers,
            replicate,
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

#[cfg(test)]
mod replication_tests {
    use super::*;

    /// SIP-35's two directions are two settings, and neither implies the other:
    /// `replication_peers` is who this exchange will *serve*, `[[replicate]]`
    /// is who it will *pull from*. An operator who set one and expected both
    /// would get silence, so both are parsed and both are tested.
    #[test]
    fn both_directions_of_a_peering_link_are_parsed() {
        let peer = PubKey::new([1u8; 32]).to_base58();
        let origin = PubKey::new([2u8; 32]).to_base58();
        let channel = PubKey::new([3u8; 32]).to_base58();
        let text = format!(
            r#"
listen = "127.0.0.1:443"
key_file = "/etc/sqex/host_key"
replication_peers = ["{peer}"]

[[replicate]]
origin = "{origin}"
addr = "198.51.100.7:443"
channels = ["{channel}"]
interval_secs = 120
"#
        );
        let config: Config = toml::from_str::<FileConfig>(&text)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(config.replication_peers, vec![PubKey::new([1u8; 32])]);
        assert_eq!(config.replicate.len(), 1);
        assert_eq!(config.replicate[0].origin, PubKey::new([2u8; 32]));
        assert_eq!(config.replicate[0].channels, vec![[3u8; 32]]);
        assert_eq!(
            config.replicate[0].interval,
            std::time::Duration::from_secs(120)
        );
    }

    /// Neither is on by default, and that is the SIP's own default: no
    /// replication without a deliberate act, because every replica is another
    /// operator holding the shape of a conversation.
    #[test]
    fn an_exchange_replicates_nothing_unless_told_to() {
        let text = "listen = \"127.0.0.1:443\"\nkey_file = \"/etc/sqex/host_key\"\n";
        let config: Config = toml::from_str::<FileConfig>(text)
            .unwrap()
            .resolve()
            .unwrap();
        assert!(config.replication_peers.is_empty());
        assert!(config.replicate.is_empty());
    }

    /// A pull interval below SIP-35's floor is clamped rather than refused: an
    /// operator asking for it is not making an error, and a replica that
    /// hammered an origin would be.
    #[test]
    fn a_pull_interval_is_floored_rather_than_refused() {
        let origin = PubKey::new([2u8; 32]).to_base58();
        let text = format!(
            "listen = \"127.0.0.1:443\"\nkey_file = \"/k\"\n\n\
             [[replicate]]\norigin = \"{origin}\"\naddr = \"198.51.100.7:443\"\n\
             interval_secs = 0\n"
        );
        let config: Config = toml::from_str::<FileConfig>(&text)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(
            config.replicate[0].interval,
            std::time::Duration::from_secs(sqex_proto::peer::PEER_MIN_INTERVAL)
        );
    }

    /// More peers than SIP-35 permits is caught at load, not by silently
    /// ignoring some of them — an operator who set seventeen should hear so
    /// rather than discover which one stopped working.
    #[test]
    fn too_many_peers_is_refused_at_load() {
        let peers: Vec<String> = (0..=sqex_proto::peer::MAX_PEERS)
            .map(|i| format!("\"{}\"", PubKey::new([i as u8; 32]).to_base58()))
            .collect();
        let text = format!(
            "listen = \"127.0.0.1:443\"\nkey_file = \"/k\"\nreplication_peers = [{}]\n",
            peers.join(", ")
        );
        let err = toml::from_str::<FileConfig>(&text)
            .unwrap()
            .resolve()
            .unwrap_err();
        assert!(
            err.to_string().contains("replication_peers"),
            "the refusal must name the field: {err}"
        );
    }

    /// A key that is not a key is a configuration mistake, and it is named.
    #[test]
    fn an_unreadable_origin_key_names_itself() {
        let text = "listen = \"127.0.0.1:443\"\nkey_file = \"/k\"\n\n\
                    [[replicate]]\norigin = \"not-a-key\"\naddr = \"198.51.100.7:443\"\n";
        let err = toml::from_str::<FileConfig>(text)
            .unwrap()
            .resolve()
            .unwrap_err();
        assert!(err.to_string().contains("not-a-key"), "{err}");
    }
}
