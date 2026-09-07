//! Per-identity SIP-38 handles: a cleartext sidecar recording which
//! `name@domain` handles an identity holds.
//!
//! **Hints, not authority.** The exchange's SIP-38 `resolve` is the source of
//! truth — names are leased and exchange-asserted, so a handle recorded here is
//! only true while the exchange still agrees. These drive two conveniences: the
//! default exchange (the primary handle's domain, so no `server =` pointer is
//! needed) and showing you your own handle. `sqex whoami` verifies them against
//! the exchange and flags drift.
//!
//! One file per identity at `<identity>.handles`, cleartext and keyed by the
//! identity *path* — so it is readable without unlocking an encrypted key (the
//! identity file's own public-key line already is; see `identity::read_public`).
//! Line format: one `name@domain` per line, `#` comments and blank lines
//! ignored; order is preserved and the first line is the primary.

use std::path::{Path, PathBuf};

use sqex_proto::name;

/// The sidecar path for an identity file: `<identity>.handles`.
///
/// Appended, not `with_extension`, so `~/.sqnr/identity` becomes
/// `~/.sqnr/identity.handles` and a stem like `identity-7` is kept intact.
pub fn path_for(identity: &Path) -> PathBuf {
    PathBuf::from(format!("{}.handles", identity.display()))
}

/// The handles recorded for an identity, in order (first = primary). Empty if
/// the sidecar is absent or unreadable — a missing hint is not an error.
pub fn load(identity: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path_for(identity)) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// The primary handle (the first recorded), if any.
pub fn primary(identity: &Path) -> Option<String> {
    load(identity).into_iter().next()
}

/// The domain of the primary handle, for defaulting the exchange.
pub fn primary_domain(identity: &Path) -> Option<String> {
    primary(identity).and_then(|h| h.split_once('@').map(|(_, d)| d.to_string()))
}

/// Validate and normalise a `name@domain`: the local part must be a canonical
/// SIP-38 name (ASCII, lowercased), the domain non-empty and `@`-free.
pub fn normalise(handle: &str) -> Result<String, String> {
    match handle.split_once('@') {
        Some((local, domain)) if !domain.is_empty() && !domain.contains('@') => {
            let name = name::canonical(local).map_err(|e| e.to_string())?;
            Ok(format!("{name}@{domain}"))
        }
        _ => Err(format!("{handle:?} is not a valid name@domain")),
    }
}

fn write(identity: &Path, handles: &[String]) -> Result<(), String> {
    let path = path_for(identity);
    let body = format!(
        "# SIP-38 handles for this identity. Hints, not authority — the \
         exchange's\n# resolve is the source of truth (names are leased). First \
         = primary.\n{}\n",
        handles.join("\n")
    );
    std::fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Add a handle (normalised), keeping order and dropping duplicates. A no-op if
/// already present. Returns the normalised handle and whether it was new.
pub fn add(identity: &Path, handle: &str) -> Result<(String, bool), String> {
    let handle = normalise(handle)?;
    let mut handles = load(identity);
    if handles.iter().any(|h| h == &handle) {
        return Ok((handle, false));
    }
    handles.push(handle.clone());
    write(identity, &handles)?;
    Ok((handle, true))
}

/// Remove a handle. With an `@`, matches the full `name@domain` exactly; a bare
/// name matches by local part (forgetting every domain it is held at). Returns
/// whether anything was removed.
pub fn remove(identity: &Path, needle: &str) -> Result<bool, String> {
    let mut handles = load(identity);
    let before = handles.len();
    if needle.contains('@') {
        handles.retain(|h| h != needle);
    } else {
        let local = name::canonical(needle).unwrap_or_else(|_| needle.to_ascii_lowercase());
        handles.retain(|h| h.split('@').next().unwrap_or(h) != local);
    }
    if handles.len() == before {
        return Ok(false);
    }
    write(identity, &handles)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        // A unique identity path under the temp dir; the sidecar lands beside it.
        std::env::temp_dir().join(format!("sqex-handles-{}-{}", std::process::id(), tag))
    }

    fn cleanup(id: &Path) {
        let _ = std::fs::remove_file(path_for(id));
    }

    #[test]
    fn path_appends_rather_than_replacing() {
        assert_eq!(
            path_for(Path::new("/home/c/.sqnr/identity")),
            PathBuf::from("/home/c/.sqnr/identity.handles")
        );
        // A hyphenated stem keeps its whole name.
        assert_eq!(
            path_for(Path::new("/home/c/.sqnr/identity-7")),
            PathBuf::from("/home/c/.sqnr/identity-7.handles")
        );
    }

    #[test]
    fn normalise_folds_and_validates() {
        assert_eq!(normalise("Colin@squic.org").unwrap(), "colin@squic.org");
        assert!(normalise("colin").is_err()); // no domain
        assert!(normalise("colin@").is_err()); // empty domain
        assert!(normalise("a.b@squic.org").is_err()); // bad local part
        assert!(normalise("a@b@c").is_err()); // two @
    }

    #[test]
    fn add_dedupes_keeps_order_and_primary_first() {
        let id = temp("add");
        cleanup(&id);
        assert!(load(&id).is_empty());
        // First add is the primary; folds case on the way in.
        assert_eq!(
            add(&id, "Colin@squic.org").unwrap(),
            ("colin@squic.org".into(), true)
        );
        assert_eq!(primary(&id).as_deref(), Some("colin@squic.org"));
        assert_eq!(primary_domain(&id).as_deref(), Some("squic.org"));
        // A second is an alias, appended.
        assert!(add(&id, "c@squic.org").unwrap().1);
        assert_eq!(load(&id), vec!["colin@squic.org", "c@squic.org"]);
        // Re-adding is a no-op and does not reorder.
        assert!(!add(&id, "colin@squic.org").unwrap().1);
        assert_eq!(load(&id), vec!["colin@squic.org", "c@squic.org"]);
        cleanup(&id);
    }

    #[test]
    fn remove_by_full_handle_and_by_bare_name() {
        let id = temp("remove");
        cleanup(&id);
        add(&id, "colin@squic.org").unwrap();
        add(&id, "colin@other.org").unwrap();
        add(&id, "carl@squic.org").unwrap();
        // Exact handle removes only that one.
        assert!(remove(&id, "colin@squic.org").unwrap());
        assert_eq!(load(&id), vec!["colin@other.org", "carl@squic.org"]);
        // A bare name forgets it at every domain (and folds case).
        assert!(remove(&id, "Colin").unwrap());
        assert_eq!(load(&id), vec!["carl@squic.org"]);
        // Removing what is not there is a no-op.
        assert!(!remove(&id, "nobody").unwrap());
        cleanup(&id);
    }
}
