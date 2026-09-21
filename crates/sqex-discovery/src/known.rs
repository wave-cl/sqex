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
//!
//! # Except when the pinned key itself says where to go (SIP-40)
//!
//! What a zone cannot forge is a signature by the pinned key. SIP-40 lets the
//! outgoing key publish a handover naming its successor, and the pin follows
//! **only** when the zone publishes that successor *and* the pinned key signed
//! for it — two secrets, held by different parties, both required. A witnessed
//! key still earns nothing; a signed-for one, also published, is the operator's
//! deliberate act made checkable. The moved-from key is kept in the entry's
//! comment as history, not as a pin: it authenticates nothing afterwards.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sqnr_core::PubKey;

use crate::record::Handover;

/// What to do with a domain, given what DNS offered and what is pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing pinned. Take this key, and say so — a trust decision is being
    /// made on the user's behalf and they should know it happened.
    FirstContact(PubKey),
    /// The pinned key is still published. Use it, and say nothing.
    Pinned(PubKey),
    /// The pinned key was withdrawn and signed a handover to `to`, which the
    /// zone also publishes. Move the pin, and say so — the user should know
    /// the thing they trusted has changed hands, even legitimately.
    Moved { from: PubKey, to: PubKey },
    /// The pinned key is not among those offered. Refuse.
    Changed {
        pinned: PubKey,
        offered: Vec<PubKey>,
    },
}

/// Decide, given the keys a domain published, the key pinned for it, and any
/// handovers that verified for the domain.
///
/// `offered` is every key from every conforming record in the RRset. Order does
/// not matter and duplicates are harmless. `handovers` are already
/// signature-checked ([`Handover::verify`]); this applies SIP-40's remaining
/// rules — `from` is the pin, `to` is published, not expired at `now`, and
/// exactly one successor — and a handover is consulted only once the pinned key
/// is gone from `offered`. While it is still there, a handover changes nothing.
pub fn decide(
    offered: &[PubKey],
    pinned: Option<PubKey>,
    handovers: &[Handover],
    now: u64,
) -> Option<Decision> {
    if offered.is_empty() {
        return None;
    }
    let Some(p) = pinned else {
        return Some(Decision::FirstContact(offered[0]));
    };
    if offered.contains(&p) {
        return Some(Decision::Pinned(p));
    }
    // Withdrawn. The one case a handover speaks to.
    let mut successors: Vec<PubKey> = handovers
        .iter()
        .filter(|h| h.carries(&p, offered, now))
        .map(|h| h.to)
        .collect();
    successors.dedup();
    match successors.as_slice() {
        [to] => Some(Decision::Moved { from: p, to: *to }),
        // None, or several naming different keys. Two valid handovers from one
        // key to different successors cannot both be the operator's intent,
        // and "confused" and "one of these is a thief's" look the same from
        // here. SIP-33's refusal, naming everything.
        _ => Some(Decision::Changed {
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
         \nIf you know this is the same exchange under a new key, \
         `sqex discover --replace {domain}` moves the pin and lets the chat \
         store follow it. If it is a different exchange, or you want to start \
         over, remove the line for {domain} from {} and connect again — \
         conversations held under the old key will not be shown.",
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
    /// SIP-40: the key this pin was moved from by a signed handover, if it
    /// ever was. **History, not a pin** — it authenticates nothing — kept so
    /// a store scoped by the old key can find its rows again, and so the
    /// change can be named to a person. Written as `moved-from=<key>` on the
    /// line; an older build warns about the field and ignores it.
    pub moved_from: Option<PubKey>,
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
                tracing::warn!(
                    line = n + 1,
                    "known_servers: skipping a line with too few fields"
                );
                continue;
            };
            let Ok(key) = key.parse::<PubKey>() else {
                tracing::warn!(
                    line = n + 1,
                    "known_servers: skipping a line whose key is not base58"
                );
                continue;
            };
            // Everything after the key is cache: a host, then addresses. They
            // are told apart by parsing — an address parses as one, a host does
            // not — rather than by position, so a line written by an older
            // build with neither still loads.
            let mut host = None;
            let mut addrs = Vec::new();
            let mut moved_from = None;
            for field in parts {
                if let Some(k) = field.strip_prefix("moved-from=") {
                    match k.parse::<PubKey>() {
                        Ok(k) => moved_from = Some(k),
                        Err(_) => tracing::warn!(
                            line = n + 1,
                            "known_servers: ignoring a moved-from= that is not a key"
                        ),
                    }
                    continue;
                }
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
                moved_from,
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
        self.entries
            .retain(|e| !e.domain.eq_ignore_ascii_case(domain));
        self.entries.push(Entry {
            domain: domain.to_string(),
            key,
            host: None,
            addrs: Vec::new(),
            moved_from: None,
            comment: comment.to_string(),
        });
    }

    /// Move a domain's pin to `to` on a SIP-40 handover from `from`, keeping
    /// the cached host and addresses (the exchange is where it was) and
    /// recording where the pin came from.
    pub fn add_moved(&mut self, domain: &str, from: PubKey, to: PubKey, comment: &str) {
        let (host, addrs) = self
            .get(domain)
            .map(|e| (e.host.clone(), e.addrs.clone()))
            .unwrap_or_default();
        self.entries
            .retain(|e| !e.domain.eq_ignore_ascii_case(domain));
        self.entries.push(Entry {
            domain: domain.to_string(),
            key: to,
            host,
            addrs,
            moved_from: Some(from),
            comment: comment.to_string(),
        });
    }

    /// The key a pin for `key` was moved from, if any entry says so. By key
    /// rather than domain because the callers that need it — a store scoped
    /// by exchange key — hold the key and not the name.
    pub fn predecessor_of(&self, key: &PubKey) -> Option<PubKey> {
        self.entries
            .iter()
            .find(|e| &e.key == key)
            .and_then(|e| e.moved_from)
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
        self.entries
            .retain(|e| !e.domain.eq_ignore_ascii_case(domain));
        self.entries.len() != before
    }

    /// The address a key was last reached at, whichever domain pinned it --
    /// for a home recorded by key alone (`sqex_proto::home_file`), which has
    /// no name to discover.
    pub fn address_of(&self, key: &PubKey) -> Option<SocketAddr> {
        self.entries
            .iter()
            .find(|e| &e.key == key)
            .and_then(|e| e.addrs.first().copied())
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
            if let Some(from) = &e.moved_from {
                line += &format!("  moved-from={from}");
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
        let d = decide(&[key(2)], Some(key(1)), &[], 0).unwrap();
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
            decide(&[key(1)], None, &[], 0),
            Some(Decision::FirstContact(key(1)))
        );
    }

    #[test]
    fn a_matching_pin_is_used() {
        assert_eq!(
            decide(&[key(1)], Some(key(1)), &[], 0),
            Some(Decision::Pinned(key(1)))
        );
    }

    /// A rotation in progress: both keys published, the pinned one still there.
    /// The client keeps working and keeps its pin — it does **not** move to the
    /// new key merely because the new key appeared beside it.
    #[test]
    fn an_overlap_keeps_the_pin_rather_than_following_the_new_key() {
        assert_eq!(
            decide(&[key(2), key(1), key(3)], Some(key(1)), &[], 0),
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
        assert_eq!(
            decide(&[key(1), key(2)], Some(key(1)), &[], 0),
            Some(Decision::Pinned(key(1)))
        );
        // Old withdrawn: refused, despite key(2) having been published beside it.
        assert!(matches!(
            decide(&[key(2)], Some(key(1)), &[], 0),
            Some(Decision::Changed { .. })
        ));
    }

    #[test]
    fn nothing_offered_is_no_decision() {
        assert_eq!(decide(&[], None, &[], 0), None);
        assert_eq!(decide(&[], Some(key(1)), &[], 0), None);
    }

    // ---- SIP-40 handovers ---------------------------------------------------

    /// A key whose secret is `[n; 32]`, so tests can sign as it.
    fn signer(n: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
    }
    fn pk(sk: &ed25519_dalek::SigningKey) -> PubKey {
        PubKey::new(sk.verifying_key().to_bytes())
    }
    fn signed(domain: &str, from: &ed25519_dalek::SigningKey, to: PubKey, until: u64) -> Handover {
        use ed25519_dalek::Signer;
        let f = pk(from);
        let input = Handover::signing_input(domain, &f, &to, until);
        Handover {
            from: f,
            to,
            until,
            sig: from.sign(&input).to_bytes(),
        }
    }
    const NOW: u64 = 1_800_000_000;

    /// The positive case: withdrawn, signed for, published, in date — moved.
    #[test]
    fn a_signed_handover_moves_a_withdrawn_pin() {
        let (old, new) = (signer(1), signer(2));
        let h = signed("example.com", &old, pk(&new), NOW + 100);
        assert!(h.verify("example.com"));
        assert_eq!(
            decide(&[pk(&new)], Some(pk(&old)), &[h], NOW),
            Some(Decision::Moved {
                from: pk(&old),
                to: pk(&new)
            })
        );
    }

    /// Negative control 1: the handover is from some other key. A pin only
    /// follows its own key's word.
    #[test]
    fn a_handover_from_a_different_key_moves_nothing() {
        let (old, new, other) = (signer(1), signer(2), signer(3));
        let h = signed("example.com", &other, pk(&new), NOW + 100);
        assert!(
            h.verify("example.com"),
            "the control must be a *valid* handover"
        );
        assert!(matches!(
            decide(&[pk(&new)], Some(pk(&old)), &[h], NOW),
            Some(Decision::Changed { .. })
        ));
    }

    /// Negative control 2: signed for, but the zone does not publish the
    /// successor. The signature proves intent; only the zone proves the key
    /// is live, and both are required.
    #[test]
    fn a_successor_the_zone_does_not_publish_is_not_followed() {
        let (old, new, zone) = (signer(1), signer(2), signer(3));
        let h = signed("example.com", &old, pk(&new), NOW + 100);
        assert!(matches!(
            decide(&[pk(&zone)], Some(pk(&old)), &[h], NOW),
            Some(Decision::Changed { .. })
        ));
    }

    /// Negative control 3: expired.
    #[test]
    fn an_expired_handover_moves_nothing() {
        let (old, new) = (signer(1), signer(2));
        let h = signed("example.com", &old, pk(&new), NOW - 1);
        assert!(matches!(
            decide(&[pk(&new)], Some(pk(&old)), &[h], NOW),
            Some(Decision::Changed { .. })
        ));
        // And the boundary: `until` itself is already expired (now < until).
        let h = signed("example.com", &old, pk(&new), NOW);
        assert!(matches!(
            decide(&[pk(&new)], Some(pk(&old)), &[h], NOW),
            Some(Decision::Changed { .. })
        ));
    }

    /// Negative control 4: a signature over another domain's input. `verify`
    /// is where this is caught, and the lookup drops it before `decide` ever
    /// sees it — but the property belongs to the type, so it is asserted here.
    #[test]
    fn a_handover_signed_for_another_domain_does_not_verify() {
        let (old, new) = (signer(1), signer(2));
        let h = signed("example.com", &old, pk(&new), NOW + 100);
        assert!(h.verify("example.com"));
        assert!(
            h.verify("EXAMPLE.COM."),
            "case and the trailing dot are canonicalised"
        );
        assert!(!h.verify("example.org"));
        // A flipped bit anywhere in the signature is a foreign record.
        let mut bad = h.clone();
        bad.sig[0] ^= 1;
        assert!(!bad.verify("example.com"));
    }

    /// While the pinned key is still published, a handover is not acted on.
    /// An operator who withdraws it before withdrawing the old key has changed
    /// nothing for anyone.
    #[test]
    fn a_handover_is_not_acted_on_while_the_pin_is_still_published() {
        let (old, new) = (signer(1), signer(2));
        let h = signed("example.com", &old, pk(&new), NOW + 100);
        assert_eq!(
            decide(&[pk(&old), pk(&new)], Some(pk(&old)), &[h], NOW),
            Some(Decision::Pinned(pk(&old)))
        );
    }

    /// Two valid handovers naming different successors is a fault, not a
    /// choice. Two naming the same one is one handover said twice.
    #[test]
    fn two_successors_is_a_refusal_and_a_duplicate_is_not() {
        let (old, a, b) = (signer(1), signer(2), signer(3));
        let ha = signed("example.com", &old, pk(&a), NOW + 100);
        let hb = signed("example.com", &old, pk(&b), NOW + 100);
        assert!(matches!(
            decide(&[pk(&a), pk(&b)], Some(pk(&old)), &[ha.clone(), hb], NOW),
            Some(Decision::Changed { .. })
        ));
        assert!(matches!(
            decide(&[pk(&a)], Some(pk(&old)), &[ha.clone(), ha], NOW),
            Some(Decision::Moved { .. })
        ));
    }

    /// Chains are not walked: a client pinned to A with A→B and B→C published
    /// moves to B, and only to B.
    #[test]
    fn a_chain_is_followed_one_link_at_a_time() {
        let (a, b, c) = (signer(1), signer(2), signer(3));
        let ab = signed("example.com", &a, pk(&b), NOW + 100);
        let bc = signed("example.com", &b, pk(&c), NOW + 100);
        assert_eq!(
            decide(&[pk(&b), pk(&c)], Some(pk(&a)), &[ab, bc], NOW),
            Some(Decision::Moved {
                from: pk(&a),
                to: pk(&b)
            })
        );
    }

    /// A moved pin keeps where it came from, through a save and a load, and
    /// answers `predecessor_of` by the new key. The cached host and addresses
    /// survive the move: the exchange is where it was.
    #[test]
    fn a_moved_pin_remembers_its_predecessor_across_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_servers");
        let mut k = Known::default();
        k.add("example.com", key(1), "discovered");
        k.remember("example.com", Some("ex.example.com"), addr("192.0.2.1:443"));
        k.add_moved("example.com", key(1), key(2), "moved");
        k.save(&path).unwrap();
        let k = Known::load(&path).unwrap();
        let e = k.get("example.com").unwrap();
        assert_eq!(e.key, key(2));
        assert_eq!(e.moved_from, Some(key(1)));
        assert_eq!(e.host.as_deref(), Some("ex.example.com"));
        assert_eq!(e.addrs, vec![addr("192.0.2.1:443")]);
        assert_eq!(k.predecessor_of(&key(2)), Some(key(1)));
        assert_eq!(k.predecessor_of(&key(1)), None);
        // And the line says so, in a form an older build merely warns about.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&format!("moved-from={}", key(1))), "{text}");
    }

    /// The record round-trips through its own text, and the parser rejects
    /// the shapes SIP-40 calls foreign.
    #[test]
    fn a_handover_renders_and_parses() {
        use crate::record::{Parsed, parse};
        let (old, new) = (signer(1), signer(2));
        let h = signed("example.com", &old, pk(&new), NOW + 100);
        assert_eq!(parse(&h.render()), Parsed::Handover(h.clone()));
        // from == to
        let same = format!(
            "v=sqex1h; from={}; to={}; until=1; sig={}",
            pk(&old),
            pk(&old),
            bs58::encode(h.sig).into_string()
        );
        assert_eq!(parse(&same), Parsed::Foreign);
        // a short signature
        let short = format!(
            "v=sqex1h; from={}; to={}; until=1; sig=abc",
            pk(&old),
            pk(&new)
        );
        assert_eq!(parse(&short), Parsed::Foreign);
        // a missing tag
        let missing = format!(
            "v=sqex1h; from={}; to={}; sig={}",
            pk(&old),
            pk(&new),
            bs58::encode(h.sig).into_string()
        );
        assert_eq!(parse(&missing), Parsed::Foreign);
        // a duplicate tag
        let dup = format!("{}; until=5", h.render());
        assert_eq!(parse(&dup), Parsed::Foreign);
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
        assert_eq!(
            back.lookup("EXAMPLE.COM"),
            Some(key(7)),
            "domains are caseless"
        );
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
        k.remember(
            "squic.org",
            Some("ex.squic.org"),
            addr("95.216.183.51:5400"),
        );
        k.remember("squic.org", None, addr("[2a01:4f9:c01f:e09d::]:5400"));
        k.save(&p).unwrap();

        let back = Known::load(&p).unwrap();
        let e = back.get("squic.org").expect("entry");
        assert_eq!(e.key, key(1));
        assert_eq!(e.host.as_deref(), Some("ex.squic.org"));
        assert_eq!(
            e.addrs,
            vec![
                addr("[2a01:4f9:c01f:e09d::]:5400"),
                addr("95.216.183.51:5400")
            ],
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
        let e = Known::load(&p)
            .unwrap()
            .get("example.com")
            .cloned()
            .unwrap();
        assert_eq!(e.key, key(3));
        assert_eq!(e.host, None);
        assert!(e.addrs.is_empty());
    }

    /// Remembering is a cache, not a pin: it must never touch the key.
    #[test]
    fn remembering_does_not_change_the_key() {
        let mut k = Known::default();
        k.add("example.com", key(1), "");
        k.remember(
            "example.com",
            Some("elsewhere.example"),
            addr("10.0.0.9:5400"),
        );
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
        assert!(
            m.contains(&key(1).to_string()),
            "the pinned key is not named"
        );
        assert!(
            m.contains(&key(2).to_string()),
            "the offered key is not named"
        );
        assert!(m.contains("known_servers"), "nothing says where to fix it");
    }
}
