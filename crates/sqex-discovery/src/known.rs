//! The pin store: what this client has already decided a domain's key is.
//!
//! One line per domain, in the shape `sqssh-core`'s `known_hosts` uses, because
//! a person may well have to read and edit it:
//!
//! ```text
//! # sqex known servers — see SIP-33
//! example.com  2YQYQCzPocTTdjMoU5KmimvyEkVLzS9mkE4C6QeM2F7u  # discovered 2026-08-31
//! ```
//!
//! # Why a withdrawn pin is refused rather than followed
//!
//! SIP-33 lets a domain publish several records at once so a key can be rotated
//! without an outage. It is tempting to let the pin *follow* that rotation: note
//! the keys seen beside the pinned one, and when the pinned one stops being
//! published, move to a key that was witnessed next to it.
//!
//! That is not done, and the reason is the whole value of pinning. An adversary
//! who can write the zone could then publish their key beside the real one, wait
//! for clients to witness the pair, withdraw the real one, and carry every
//! existing client across — turning "a zone compromise cannot move a client that
//! has already connected" into "a zone compromise can move a client in two
//! publishes". The pin exists precisely to deny that.
//!
//! So the overlap window buys what it can honestly buy: while both keys are
//! published, existing clients keep working on the pinned one and clients with
//! no pin take the new one, so the population migrates as it turns over. When
//! the old key is finally withdrawn, remaining pinned clients stop and a person
//! decides. A key change is an event, and it is meant to feel like one.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sqnr_core::PubKey;

/// What to do with a domain, given what DNS offered and what is pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing pinned. Take this key, and say so — a trust decision is being
    /// made on the user's behalf and they should know it happened.
    FirstContact(PubKey),
    /// The pinned key is still published. Use it, and say nothing.
    Pinned(PubKey),
    /// The pinned key is not among those offered. Refuse.
    Changed {
        pinned: PubKey,
        offered: Vec<PubKey>,
    },
}

/// Decide, given the keys a domain published and the key pinned for it.
///
/// `offered` is every key from every conforming record in the RRset. Order does
/// not matter and duplicates are harmless.
pub fn decide(offered: &[PubKey], pinned: Option<PubKey>) -> Option<Decision> {
    if offered.is_empty() {
        return None;
    }
    match pinned {
        None => Some(Decision::FirstContact(offered[0])),
        Some(p) if offered.contains(&p) => Some(Decision::Pinned(p)),
        Some(p) => Some(Decision::Changed {
            pinned: p,
            offered: offered.to_vec(),
        }),
    }
}

/// What to tell somebody whose pin no longer matches.
///
/// Deliberately not a prompt. A question asked at the moment of connecting is
/// answered "yes" by almost everybody almost always, which converts the control
/// into a formality; the fix is a separate deliberate act.
pub fn changed_message(domain: &str, pinned: &PubKey, offered: &[PubKey]) -> String {
    let mut s = format!(
        "the key published for {domain} is not the one pinned for it.\n\
         \n  pinned:  {pinned}\n"
    );
    for k in offered {
        s.push_str(&format!("  offered: {k}\n"));
    }
    s.push_str(&format!(
        "\nThis is either a key rotation you were not told about, or somebody \
         else answering for {domain}. Nothing will connect until you decide \
         which.\n\
         \nIf you know the new key is genuine, remove the line for {domain} \
         from {} and connect again.",
        path().display()
    ));
    s
}

/// Where the store lives. `~/.sqnr/known_servers`, beside the config that
/// already holds a server and key.
pub fn path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sqnr")
        .join("known_servers")
}

/// One line of the store.
///
/// `domain  key  [host]  [addr…]  # comment`
///
/// The host and addresses are a **cache of where it was**, not part of the
/// trust decision — the key is that. A stale or hostile address costs a failed
/// handshake and nothing else, because SIP-9 has the client refuse a server
/// that cannot prove the pinned key. That is what makes it safe to try a
/// remembered address before asking DNS anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub domain: String,
    pub key: PubKey,
    /// The `h=` from the record it was discovered by, so a changed address can
    /// be found without a full re-discovery.
    pub host: Option<String>,
    /// Where it answered last, newest first.
    pub addrs: Vec<SocketAddr>,
    pub comment: String,
}

/// How many addresses to keep per domain. Two families plus a little history;
/// beyond that the list is stale guesses that each cost a connection attempt.
pub const MAX_REMEMBERED: usize = 4;

/// The store, whole.
#[derive(Debug, Default, Clone)]
pub struct Known {
    entries: Vec<Entry>,
}

impl Known {
    /// Load, treating a missing file as an empty store — a first run is not an
    /// error.
    pub fn load(path: &Path) -> Result<Known, String> {
        if !path.exists() {
            return Ok(Known::default());
        }
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let mut entries = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // A line this parser cannot read is skipped rather than fatal: one
            // bad line must not lock somebody out of every domain they know.
            let (body, comment) = match line.split_once('#') {
                Some((b, c)) => (b.trim(), c.trim().to_string()),
                None => (line, String::new()),
            };
            let mut parts = body.split_whitespace();
            let (Some(domain), Some(key)) = (parts.next(), parts.next()) else {
                tracing::warn!(line = n + 1, "known_servers: skipping a line with too few fields");
                continue;
            };
            let Ok(key) = key.parse::<PubKey>() else {
                tracing::warn!(line = n + 1, "known_servers: skipping a line whose key is not base58");
                continue;
            };
            // Everything after the key is cache: a host, then addresses. They
            // are told apart by parsing — an address parses as one, a host does
            // not — rather than by position, so a line written by an older
            // build with neither still loads.
            let mut host = None;
            let mut addrs = Vec::new();
            for field in parts {
                match field.parse::<SocketAddr>() {
                    Ok(a) => addrs.push(a),
                    Err(_) if host.is_none() && addrs.is_empty() => {
                        host = Some(field.to_string());
                    }
                    Err(_) => tracing::warn!(
                        line = n + 1,
                        field,
                        "known_servers: ignoring a field that is neither host nor address"
                    ),
                }
            }
            entries.push(Entry {
                domain: domain.to_string(),
                key,
                host,
                addrs,
                comment,
            });
        }
        Ok(Known { entries })
    }

    pub fn lookup(&self, domain: &str) -> Option<PubKey> {
        self.get(domain).map(|e| e.key)
    }

    /// The whole entry, including the cached host and addresses.
    pub fn get(&self, domain: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.domain.eq_ignore_ascii_case(domain))
    }

    /// Record a key for a domain, replacing any entry already there.
    pub fn add(&mut self, domain: &str, key: PubKey, comment: &str) {
        self.entries.retain(|e| !e.domain.eq_ignore_ascii_case(domain));
        self.entries.push(Entry {
            domain: domain.to_string(),
            key,
            host: None,
            addrs: Vec::new(),
            comment: comment.to_string(),
        });
    }

    /// Remember where a domain answered, so the next start can go straight
    /// there. The key is untouched: this is the cache, not the pin.
    ///
    /// `addr` moves to the front, because the one that just worked is the one
    /// to try first next time. Older addresses are kept — a server that moves
    /// back, or answers on two families, should not have to be rediscovered.
    pub fn remember(&mut self, domain: &str, host: Option<&str>, addr: SocketAddr) {
        let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.domain.eq_ignore_ascii_case(domain))
        else {
            return;
        };
        if let Some(h) = host {
            e.host = Some(h.to_string());
        }
        e.addrs.retain(|a| a != &addr);
        e.addrs.insert(0, addr);
        e.addrs.truncate(MAX_REMEMBERED);
    }

    /// Forget a domain. `true` if there was one.
    pub fn remove(&mut self, domain: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| !e.domain.eq_ignore_ascii_case(domain));
        self.entries.len() != before
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Write the store, creating the directory if it is not there.
    ///
    /// Written to a temporary file and renamed, so an interrupted save leaves
    /// the old store rather than half of a new one — losing this file means
    /// every pin is gone and every domain looks like a first contact.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        let tmp = path.with_extension("tmp");
        let mut f = fs::File::create(&tmp).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        writeln!(f, "# sqex known servers — see SIP-33").map_err(|e| e.to_string())?;
        writeln!(
            f,
            "# One domain per line. Removing a line forgets its key and the next\n\
             # connection is treated as a first contact."
        )
        .map_err(|e| e.to_string())?;
        for e in &self.entries {
            let mut line = format!("{}  {}", e.domain, e.key);
            if let Some(h) = &e.host {
                line += &format!("  {h}");
            }
            for a in &e.addrs {
                line += &format!("  {a}");
            }
            if !e.comment.is_empty() {
                line += &format!("  # {}", e.comment);
            }
            writeln!(f, "{line}").map_err(|e| e.to_string())?;
        }
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        fs::rename(&tmp, path).map_err(|e| format!("rename onto {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PubKey {
        PubKey::new([n; 32])
    }

    /// The point of the whole design. A domain that starts publishing a
    /// different key does not get followed.
    #[test]
    fn a_changed_key_is_refused_not_followed() {
        let d = decide(&[key(2)], Some(key(1))).unwrap();
        match d {
            Decision::Changed { pinned, offered } => {
                assert_eq!(pinned, key(1));
                assert_eq!(offered, vec![key(2)]);
            }
            other => panic!("a changed key was accepted as {other:?}"),
        }
    }

    #[test]
    fn a_first_contact_takes_the_key() {
        assert_eq!(
            decide(&[key(1)], None),
            Some(Decision::FirstContact(key(1)))
        );
    }

    #[test]
    fn a_matching_pin_is_used() {
        assert_eq!(decide(&[key(1)], Some(key(1))), Some(Decision::Pinned(key(1))));
    }

    /// A rotation in progress: both keys published, the pinned one still there.
    /// The client keeps working and keeps its pin — it does **not** move to the
    /// new key merely because the new key appeared beside it.
    #[test]
    fn an_overlap_keeps_the_pin_rather_than_following_the_new_key() {
        assert_eq!(
            decide(&[key(2), key(1), key(3)], Some(key(1))),
            Some(Decision::Pinned(key(1))),
            "the pin should win while it is still published"
        );
    }

    /// And once the pinned key is withdrawn, having been seen beside the new one
    /// changes nothing. This is the case a witnessed-rotation design would let
    /// through, and letting it through is what would let a zone-writing
    /// adversary carry existing clients across in two publishes.
    #[test]
    fn having_been_seen_beside_the_new_key_does_not_earn_it_the_pin() {
        // Overlap: both published, pin holds.
        assert_eq!(decide(&[key(1), key(2)], Some(key(1))), Some(Decision::Pinned(key(1))));
        // Old withdrawn: refused, despite key(2) having been published beside it.
        assert!(matches!(
            decide(&[key(2)], Some(key(1))),
            Some(Decision::Changed { .. })
        ));
    }

    #[test]
    fn nothing_offered_is_no_decision() {
        assert_eq!(decide(&[], None), None);
        assert_eq!(decide(&[], Some(key(1))), None);
    }

    #[test]
    fn the_store_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("known_servers");

        let mut k = Known::load(&p).unwrap();
        assert!(k.entries().is_empty(), "a missing file is an empty store");
        k.add("example.com", key(7), "discovered 2026-08-31");
        k.add("other.example", key(8), "");
        k.save(&p).unwrap();

        let back = Known::load(&p).unwrap();
        assert_eq!(back.lookup("example.com"), Some(key(7)));
        assert_eq!(back.lookup("other.example"), Some(key(8)));
        assert_eq!(back.lookup("EXAMPLE.COM"), Some(key(7)), "domains are caseless");
        assert_eq!(back.lookup("nobody.example"), None);
    }

    #[test]
    fn adding_replaces_rather_than_duplicates() {
        let mut k = Known::default();
        k.add("example.com", key(1), "");
        k.add("example.com", key(2), "");
        assert_eq!(k.entries().len(), 1);
        assert_eq!(k.lookup("example.com"), Some(key(2)));
    }

    #[test]
    fn removing_forgets_it() {
        let mut k = Known::default();
        k.add("example.com", key(1), "");
        assert!(k.remove("example.com"));
        assert!(!k.remove("example.com"));
        assert_eq!(k.lookup("example.com"), None);
    }

    /// One unreadable line must not lock somebody out of every other domain.
    #[test]
    fn a_bad_line_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("known_servers");
        fs::write(
            &p,
            format!(
                "# a comment\n\
                 \n\
                 nonsense-with-no-key\n\
                 bad.example  not-base58-!!\n\
                 good.example  {}  # fine\n",
                key(9)
            ),
        )
        .unwrap();
        let k = Known::load(&p).unwrap();
        assert_eq!(k.lookup("good.example"), Some(key(9)));
        assert_eq!(k.entries().len(), 1);
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_host_and_addresses_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("known_servers");
        let mut k = Known::default();
        k.add("squic.org", key(1), "discovered 2026-08-31");
        k.remember("squic.org", Some("ex.squic.org"), addr("95.216.183.51:5400"));
        k.remember("squic.org", None, addr("[2a01:4f9:c01f:e09d::]:5400"));
        k.save(&p).unwrap();

        let back = Known::load(&p).unwrap();
        let e = back.get("squic.org").expect("entry");
        assert_eq!(e.key, key(1));
        assert_eq!(e.host.as_deref(), Some("ex.squic.org"));
        assert_eq!(
            e.addrs,
            vec![addr("[2a01:4f9:c01f:e09d::]:5400"), addr("95.216.183.51:5400")],
            "the one that answered most recently comes first"
        );
        assert_eq!(e.comment, "discovered 2026-08-31");
    }

    /// The address that just worked goes to the front, and does not accumulate
    /// duplicates — otherwise a stable server would fill the list with copies
    /// of itself and push out the alternatives.
    #[test]
    fn remembering_the_same_address_twice_moves_it_rather_than_repeats_it() {
        let mut k = Known::default();
        k.add("example.com", key(1), "");
        k.remember("example.com", None, addr("10.0.0.1:5400"));
        k.remember("example.com", None, addr("10.0.0.2:5400"));
        k.remember("example.com", None, addr("10.0.0.1:5400"));
        let e = k.get("example.com").unwrap();
        assert_eq!(e.addrs, vec![addr("10.0.0.1:5400"), addr("10.0.0.2:5400")]);
    }

    #[test]
    fn the_remembered_list_is_capped() {
        let mut k = Known::default();
        k.add("example.com", key(1), "");
        for n in 1..=MAX_REMEMBERED + 3 {
            k.remember("example.com", None, addr(&format!("10.0.0.{n}:5400")));
        }
        assert_eq!(k.get("example.com").unwrap().addrs.len(), MAX_REMEMBERED);
    }

    /// A line written before addresses were stored must still load: the fields
    /// after the key are told apart by parsing, not by position.
    #[test]
    fn a_line_with_no_host_or_addresses_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("known_servers");
        fs::write(&p, format!("example.com  {}  # old\n", key(3))).unwrap();
        let e = Known::load(&p).unwrap().get("example.com").cloned().unwrap();
        assert_eq!(e.key, key(3));
        assert_eq!(e.host, None);
        assert!(e.addrs.is_empty());
    }

    /// Remembering is a cache, not a pin: it must never touch the key.
    #[test]
    fn remembering_does_not_change_the_key() {
        let mut k = Known::default();
        k.add("example.com", key(1), "");
        k.remember("example.com", Some("elsewhere.example"), addr("10.0.0.9:5400"));
        assert_eq!(k.lookup("example.com"), Some(key(1)));
    }

    /// And it must not invent an entry for a domain with no pin — that would
    /// be a key-less line, and the store is a record of trust decisions.
    #[test]
    fn remembering_an_unpinned_domain_does_nothing() {
        let mut k = Known::default();
        k.remember("nobody.example", Some("h"), addr("10.0.0.1:5400"));
        assert!(k.entries().is_empty());
    }

    #[test]
    fn the_refusal_names_both_keys_and_the_file() {
        let m = changed_message("example.com", &key(1), &[key(2)]);
        assert!(m.contains(&key(1).to_string()), "the pinned key is not named");
        assert!(m.contains(&key(2).to_string()), "the offered key is not named");
        assert!(m.contains("known_servers"), "nothing says where to fix it");
    }
}
