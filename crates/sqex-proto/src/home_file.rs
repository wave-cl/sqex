//! Where an identity's account lives (SIP-59), as the person said it: a
//! cleartext sidecar beside the identity file.
//!
//! One file per identity at `<identity>.home`, keyed by the identity *path*
//! like [`crate::handles`], so it is readable without unlocking an encrypted
//! key. Written by the client on every Move the person makes or claims, and
//! read for two things: the default exchange (above the handle domain, below
//! anything said on the command line), and whether a fresh store may present
//! the account's first Move to the exchange it is connected to (SIP-60 §When
//! a client presents a Move unasked). The exchange's record is the authority;
//! this is the person's word, and a store pointed anywhere else is a visitor.
//!
//! Line format: `home = <domain>` and, for a home with no name to discover (a
//! laptop exchange dialled by host and key), `key = <base58>`; either alone
//! is enough. `#` comments and blank lines are ignored.

use std::path::{Path, PathBuf};

use sqnr_core::PubKey;

/// The sidecar path for an identity file: `<identity>.home`, appended like
/// the handles sidecar so `identity-7` keeps its whole stem.
pub fn path_for(identity: &Path) -> PathBuf {
    PathBuf::from(format!("{}.home", identity.display()))
}

/// The home as recorded: a domain (SIP-33), a key, or both.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Home {
    pub domain: Option<String>,
    pub key: Option<PubKey>,
}

impl Home {
    /// Whether `exchange`, reached as `domain` (if by name), is the home
    /// recorded here. A key decides where one is recorded; a domain alone
    /// is compared as a domain, case-insensitively and ignoring a trailing
    /// dot.
    pub fn names(&self, exchange: &PubKey, domain: Option<&str>) -> bool {
        if let Some(k) = &self.key {
            return k == exchange;
        }
        match (&self.domain, domain) {
            (Some(mine), Some(theirs)) => same_domain(mine, theirs),
            _ => false,
        }
    }

    /// One line for the screen.
    pub fn describe(&self) -> String {
        match (&self.domain, &self.key) {
            (Some(d), Some(k)) => format!("{d} ({k})"),
            (Some(d), None) => d.clone(),
            (None, Some(k)) => k.to_string(),
            (None, None) => "(nothing recorded)".into(),
        }
    }
}

fn same_domain(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// The recorded home, or `None` when the sidecar is absent, unreadable or
/// says nothing usable -- a missing record is not an error, it is a store
/// that has not been told.
pub fn load(identity: &Path) -> Option<Home> {
    let text = std::fs::read_to_string(path_for(identity)).ok()?;
    let mut home = Home::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "home" if !v.is_empty() && !v.contains('@') => {
                home.domain = Some(v.trim_end_matches('.').to_ascii_lowercase());
            }
            "key" => home.key = v.parse().ok(),
            _ => {}
        }
    }
    (home.domain.is_some() || home.key.is_some()).then_some(home)
}

/// Record the home. A domain, a key, or both; nothing at all is refused,
/// since [`clear`] is how a record is withdrawn.
pub fn set(identity: &Path, home: &Home) -> Result<(), String> {
    if home.domain.is_none() && home.key.is_none() {
        return Err("a home is a domain or a key".into());
    }
    let path = path_for(identity);
    let mut body = String::from(
        "# Where this identity's account lives (SIP-59): the home the person\n\
         # named or moved to. The exchange's record is the authority; this is\n\
         # the person's word, and a client pointed anywhere else is a visitor.\n",
    );
    if let Some(d) = &home.domain {
        body.push_str(&format!("home = {d}\n"));
    }
    if let Some(k) = &home.key {
        body.push_str(&format!("key = {k}\n"));
    }
    std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Withdraw the record. True if there was one.
pub fn clear(identity: &Path) -> Result<bool, String> {
    let path = path_for(identity);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sqex-home-{}-{}", std::process::id(), tag))
    }

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    #[test]
    fn path_appends_rather_than_replacing() {
        assert_eq!(
            path_for(Path::new("/home/c/.sqnr/identity-7")),
            PathBuf::from("/home/c/.sqnr/identity-7.home")
        );
    }

    #[test]
    fn missing_is_none_not_an_error() {
        assert_eq!(load(&temp("missing")), None);
    }

    #[test]
    fn round_trip_domain_and_key() {
        let id = temp("round");
        let home = Home {
            domain: Some("squic.org".into()),
            key: Some(key(7)),
        };
        set(&id, &home).unwrap();
        assert_eq!(load(&id), Some(home.clone()));
        // A domain alone; the key line is not written.
        let only = Home {
            domain: Some("Trunk.Exchange.".into()),
            ..Default::default()
        };
        set(&id, &only).unwrap();
        let text = std::fs::read_to_string(path_for(&id)).unwrap();
        assert!(!text.contains("key ="), "{text}");
        // Read back canonical: lowercased, no trailing dot.
        assert_eq!(load(&id).unwrap().domain.as_deref(), Some("trunk.exchange"));
        assert!(clear(&id).unwrap());
        assert!(!clear(&id).unwrap());
        assert_eq!(load(&id), None);
    }

    #[test]
    fn nothing_is_refused_and_junk_is_ignored() {
        let id = temp("junk");
        assert!(set(&id, &Home::default()).is_err());
        std::fs::write(path_for(&id), "# only a comment\nhome = \nkey = notakey\n").unwrap();
        assert_eq!(load(&id), None, "an empty domain and a bad key say nothing");
        let _ = clear(&id);
    }

    #[test]
    fn the_key_decides_where_recorded_else_the_domain() {
        let both = Home {
            domain: Some("squic.org".into()),
            key: Some(key(1)),
        };
        assert!(both.names(&key(1), None));
        assert!(
            !both.names(&key(2), Some("squic.org")),
            "the key outranks the domain"
        );
        let by_name = Home {
            domain: Some("squic.org".into()),
            ..Default::default()
        };
        assert!(by_name.names(&key(9), Some("SQUIC.ORG.")));
        assert!(
            !by_name.names(&key(9), None),
            "reached by address, a domain cannot say"
        );
    }
}
