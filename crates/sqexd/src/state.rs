//! The managed whitelist and the audit log — the server's mutable state.
//!
//! The whitelist is sqex's own connection ACL, but it is enforced at the HTTP/3
//! layer (via the SIP-2 `peer_key`), not as sQUIC's transport whitelist: if it
//! gated the transport, enabling it would drop the admin surface too, since
//! YubiKey admins have no stable transport key. See the plan's design note.
//!
//! Each whitelisted key carries provenance — who added it, an optional human
//! label, and when — so a delegated device key can be traced to the admin who
//! authorised it and revoked by that relationship later. Provenance is
//! informational; gating is on the key itself.
//!
//! State persists as JSON, written atomically (temp file then rename) so a
//! crash mid-write cannot corrupt it. Keys are stored base58 so the file is
//! legible.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sqnr_core::key::PubKey;
use sqnr_core::{Error, Result};

/// One recorded administrative action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix seconds when the action was applied.
    pub time: u64,
    /// The admin who issued it, base58.
    pub admin: String,
    /// The action name (e.g. `whitelist-add`).
    pub action: String,
    /// The affected key, base58, if the action named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Human-readable outcome.
    pub outcome: String,
}

/// Provenance for one whitelisted key.
#[derive(Debug, Clone, Default)]
pub struct WhitelistEntry {
    /// The admin who authorised the add, base58 (None for seeded keys).
    pub added_by: Option<String>,
    /// Optional human label recorded at add time.
    pub label: Option<String>,
    /// Unix seconds when the key was added.
    pub added_at: u64,
}

/// On-disk form of a whitelist entry. Accepts a bare base58 string (the older
/// format) or a full object, so existing state files still load.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum PersistedKey {
    Bare(String),
    Full {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        added_by: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default)]
        added_at: u64,
    },
}

/// The JSON shape on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    enabled: bool,
    keys: Vec<PersistedKey>,
    #[serde(default)]
    audit: Vec<AuditEntry>,
}

/// The live server state.
pub struct State {
    path: Option<PathBuf>,
    enabled: bool,
    keys: BTreeMap<PubKey, WhitelistEntry>,
    /// Forward Ed25519 -> X25519 of `keys`, rebuilt on every change so the
    /// per-request enforcement check is a plain set lookup.
    x25519: HashSet<[u8; 32]>,
    audit: Vec<AuditEntry>,
}

/// Keep at most this many audit entries in memory and on disk. Oldest drop
/// first; this is an operational trail, not an archive.
const MAX_AUDIT: usize = 1000;

impl State {
    /// Load from `path` if it exists; otherwise start from `seed` (config's
    /// `seed_whitelist`, disabled). A present state file always wins over the
    /// seed, so config only bootstraps the very first run.
    pub fn load(path: Option<PathBuf>, seed: &[PubKey]) -> Result<State> {
        if let Some(p) = &path
            && p.exists()
        {
            let text = std::fs::read_to_string(p)
                .map_err(|e| Error::Malformed(format!("cannot read {}: {e}", p.display())))?;
            let persisted: Persisted = serde_json::from_str(&text)
                .map_err(|e| Error::Malformed(format!("cannot parse {}: {e}", p.display())))?;
            let mut keys = BTreeMap::new();
            for pk in persisted.keys {
                let (k, entry) = match pk {
                    PersistedKey::Bare(s) => (PubKey::from_base58(&s)?, WhitelistEntry::default()),
                    PersistedKey::Full {
                        key,
                        added_by,
                        label,
                        added_at,
                    } => (
                        PubKey::from_base58(&key)?,
                        WhitelistEntry {
                            added_by,
                            label,
                            added_at,
                        },
                    ),
                };
                keys.insert(k, entry);
            }
            let mut state = State {
                path,
                enabled: persisted.enabled,
                keys,
                x25519: HashSet::new(),
                audit: persisted.audit,
            };
            state.rebuild_x25519();
            return Ok(state);
        }
        let now = now_unix();
        let keys = seed
            .iter()
            .map(|k| {
                (
                    *k,
                    WhitelistEntry {
                        added_by: None,
                        label: Some("seed".into()),
                        added_at: now,
                    },
                )
            })
            .collect();
        let mut state = State {
            path,
            enabled: false,
            keys,
            x25519: HashSet::new(),
            audit: Vec::new(),
        };
        state.rebuild_x25519();
        Ok(state)
    }

    fn rebuild_x25519(&mut self) {
        self.x25519 = self
            .keys
            .keys()
            .filter_map(|k| {
                squic::crypto::ed25519_public_to_x25519(k.as_bytes())
                    .ok()
                    .map(|x| x.to_bytes())
            })
            .collect();
    }

    /// Whether a peer with this MAC1-verified X25519 key may use protected
    /// endpoints. When the whitelist is disabled, everyone who reached the
    /// server is allowed.
    pub fn peer_allowed(&self, peer_x25519: Option<[u8; 32]>) -> bool {
        if !self.enabled {
            return true;
        }
        match peer_x25519 {
            Some(k) => self.x25519.contains(&k),
            None => false,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn keys(&self) -> Vec<PubKey> {
        self.keys.keys().copied().collect()
    }

    /// The whitelist as (key, provenance) pairs, for listing.
    pub fn list(&self) -> Vec<(PubKey, WhitelistEntry)> {
        self.keys.iter().map(|(k, e)| (*k, e.clone())).collect()
    }

    pub fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    /// Add a key with its provenance. Returns whether the set changed; an
    /// already-present key keeps its original provenance.
    pub fn add(&mut self, key: PubKey, entry: WhitelistEntry) -> bool {
        if self.keys.contains_key(&key) {
            return false;
        }
        self.keys.insert(key, entry);
        self.rebuild_x25519();
        true
    }

    /// Returns whether the set changed.
    pub fn remove(&mut self, key: &PubKey) -> bool {
        let changed = self.keys.remove(key).is_some();
        if changed {
            self.rebuild_x25519();
        }
        changed
    }

    pub fn record(&mut self, entry: AuditEntry) {
        self.audit.push(entry);
        if self.audit.len() > MAX_AUDIT {
            let overflow = self.audit.len() - MAX_AUDIT;
            self.audit.drain(0..overflow);
        }
    }

    /// The most recent `n` audit entries, newest last.
    pub fn audit_tail(&self, n: usize) -> Vec<AuditEntry> {
        let start = self.audit.len().saturating_sub(n);
        self.audit[start..].to_vec()
    }

    /// Persist atomically. A no-op when running memory-only.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let persisted = Persisted {
            enabled: self.enabled,
            keys: self
                .keys
                .iter()
                .map(|(k, e)| PersistedKey::Full {
                    key: k.to_base58(),
                    added_by: e.added_by.clone(),
                    label: e.label.clone(),
                    added_at: e.added_at,
                })
                .collect(),
            audit: self.audit.clone(),
        };
        let json = serde_json::to_vec_pretty(&persisted)
            .map_err(|e| Error::Malformed(format!("cannot encode state: {e}")))?;
        let tmp = path.with_extension("state.tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| Error::Malformed(format!("cannot write {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| Error::Malformed(format!("cannot rename into {}: {e}", path.display())))?;
        Ok(())
    }
}

/// Current Unix time in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn entry(admin: &str, label: &str) -> WhitelistEntry {
        WhitelistEntry {
            added_by: Some(admin.into()),
            label: Some(label.into()),
            added_at: 100,
        }
    }

    #[test]
    fn peer_allowed_respects_enabled() {
        let k = PubKey::new([1u8; 32]);
        let x = squic::crypto::ed25519_public_to_x25519(k.as_bytes())
            .unwrap()
            .to_bytes();
        let mut s = State::load(None, &[k]).unwrap();
        assert!(s.peer_allowed(None));
        assert!(s.peer_allowed(Some([9u8; 32])));
        s.set_enabled(true);
        assert!(s.peer_allowed(Some(x)));
        assert!(!s.peer_allowed(Some([9u8; 32])));
        assert!(!s.peer_allowed(None));
    }

    #[test]
    fn persist_and_reload_with_provenance() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sqex.state");
        let k = PubKey::new([2u8; 32]);
        {
            let mut s = State::load(Some(path.clone()), &[]).unwrap();
            s.set_enabled(true);
            assert!(s.add(k, entry("adminA", "colin-laptop")));
            s.save().unwrap();
        }
        let s = State::load(Some(path), &[PubKey::new([9u8; 32])]).unwrap();
        assert!(s.enabled());
        let list = s.list();
        assert_eq!(list.len(), 1);
        let (key, prov) = &list[0];
        assert_eq!(*key, k);
        assert_eq!(prov.added_by.as_deref(), Some("adminA"));
        assert_eq!(prov.label.as_deref(), Some("colin-laptop"));
    }

    #[test]
    fn reads_old_bare_key_format() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sqex.state");
        let k = PubKey::new([3u8; 32]);
        // An older state file: keys as bare base58 strings.
        let legacy = format!(
            "{{\"enabled\":true,\"keys\":[\"{}\"],\"audit\":[]}}",
            k.to_base58()
        );
        std::fs::write(&path, legacy).unwrap();
        let s = State::load(Some(path), &[]).unwrap();
        assert_eq!(s.keys(), vec![k]);
        assert!(s.enabled());
        // Bare entries have no provenance.
        assert!(s.list()[0].1.added_by.is_none());
    }

    #[test]
    fn add_remove_changed_flag() {
        let mut s = State::load(None, &[]).unwrap();
        let k = PubKey::new([3u8; 32]);
        assert!(s.add(k, WhitelistEntry::default()));
        assert!(!s.add(k, WhitelistEntry::default())); // already present
        assert!(s.remove(&k));
        assert!(!s.remove(&k)); // already gone
    }
}
