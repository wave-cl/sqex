//! The SIP-33 discovery record: what a domain publishes so a stranger can find
//! its exchange.
//!
//! ```text
//! _sqex.example.com. IN TXT "v=sqex1; k=<base58>; h=exchange.example.com; p=443"
//! ```
//!
//! Tag-value in DKIM's grammar (RFC 6376 §3.2), because it is the one operators
//! already know from SPF and DKIM and it survives being retyped by hand.
//!
//! # Two kinds of "no"
//!
//! A `TXT` record at `_sqex` that does not begin `v=sqex1` is **not ours** and
//! is skipped in silence — somebody else's record is not a malformed one. A
//! record that does begin `v=sqex1` and is then wrong is **broken**, and says
//! so. Collapsing the two would mean a domain publishing anything else at that
//! name produced errors instead of being ignored.
//!
//! # The handover, SIP-40
//!
//! A second record kind at the same name, `v=sqex1h`, is a statement signed by
//! an exchange's outgoing key naming its successor. It is what lets a pinned
//! client follow a rotation without the zone gaining any say over the pin: the
//! pin moves only when the zone publishes the successor *and* the pinned key
//! has signed for it. A SIP-33 parser that predates it sees a foreign version
//! tag and skips it, which is what makes it additive.
//!
//! A handover that is structurally wrong — a key of the wrong length, a
//! signature that does not verify — is **foreign**, not broken: the SIP says
//! so, because the RRset is shared and a bad handover is not a fault in the
//! client's own configuration. The signature needs the domain, which the
//! parser does not have, so verification is [`Handover::verify`], run by the
//! lookup that does.

use sqnr_core::PubKey;

/// The default port, when a record does not name one.
///
/// 443/udp, which is HTTP/3's own port and the one that survives networks
/// filtering everything else — the same reasoning that put sqssh on 22 rather
/// than a number of its own. A record may still name any port with `p=`, so
/// this only decides for a domain that does not bother.
pub const DEFAULT_PORT: u16 = 443;

/// The version tag every record must open with.
pub const VERSION: &str = "sqex1";

/// The label a record is published beneath, per RFC 8552.
pub const LABEL: &str = "_sqex";

/// The version tag a SIP-40 handover opens with.
pub const HANDOVER_VERSION: &str = "sqex1h";

/// The furthest ahead a handover's `until` may lie. Thirty days: long enough
/// for the slowest realistic client population, short enough that a
/// pre-signed handover in a thief's pocket is worth little. A constant rather
/// than a tag because a signer that could choose it would choose it.
pub const HANDOVER_MAX_SECS: u64 = 30 * 24 * 60 * 60;

/// The domain-separation prefix of the handover signing input.
const HANDOVER_PREFIX: &[u8; 16] = b"sqex-handover-v1";

/// A SIP-40 handover: `from` says its successor is `to`, until `until`.
///
/// Structurally valid on construction — the right lengths, `from != to` — and
/// **cryptographically valid only once [`verify`](Self::verify) has said so**
/// for the domain it was published under. The two are separate because the
/// parser does not know the domain, and a handover for one zone must not
/// verify under another the same key happens to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handover {
    pub from: PubKey,
    pub to: PubKey,
    /// Seconds since the Unix epoch.
    pub until: u64,
    pub sig: [u8; 64],
}

impl Handover {
    /// The bytes `from` signs: prefix, the lowercased domain with its length,
    /// both keys, the expiry. Byte-exact per SIP-40 §The handover record.
    pub fn signing_input(domain: &str, from: &PubKey, to: &PubKey, until: u64) -> Vec<u8> {
        let domain = canonical_domain(domain);
        let mut out = Vec::with_capacity(16 + 1 + domain.len() + 64 + 8);
        out.extend_from_slice(HANDOVER_PREFIX);
        out.push(domain.len() as u8);
        out.extend_from_slice(domain.as_bytes());
        out.extend_from_slice(from.as_bytes());
        out.extend_from_slice(to.as_bytes());
        out.extend_from_slice(&until.to_be_bytes());
        out
    }

    /// Whether `from` really signed this, for `domain`.
    pub fn verify(&self, domain: &str) -> bool {
        let Ok(vk) = self.from.verifying_key() else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig);
        let input = Self::signing_input(domain, &self.from, &self.to, self.until);
        ed25519_dalek::Verifier::verify(&vk, &input, &sig).is_ok()
    }

    /// Whether this handover carries `pinned` to a key that `offered` also
    /// publishes, and has not expired at `now`. The whole of SIP-40's rule
    /// for one record; the caller decides what to do with several.
    pub fn carries(&self, pinned: &PubKey, offered: &[PubKey], now: u64) -> bool {
        &self.from == pinned && offered.contains(&self.to) && now < self.until
    }

    /// The record, as published.
    pub fn render(&self) -> String {
        format!(
            "v={HANDOVER_VERSION}; from={}; to={}; until={}; sig={}",
            self.from,
            self.to,
            self.until,
            bs58::encode(self.sig).into_string()
        )
    }
}

/// The domain as it is signed: lowercased, no trailing dot. A record is looked
/// up by whatever the user typed, and two spellings of one zone must produce
/// one signing input.
pub fn canonical_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A parsed discovery record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The exchange's key, to be pinned per SIP-9.
    pub key: PubKey,
    /// The host whose A/AAAA give the address. `None` means the queried domain.
    pub host: Option<String>,
    pub port: u16,
}

/// Why a record that claimed to be ours could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalid {
    /// No `k` tag. Without a key the record says nothing.
    NoKey,
    /// `k` is not base58, or does not decode to 32 bytes.
    BadKey(String),
    /// `p` is not a port.
    BadPort(String),
    /// The same tag twice. Which one was meant is unknowable, so neither is used.
    Duplicate(String),
    /// An empty `h`, which would resolve to nothing.
    EmptyHost,
}

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Invalid::NoKey => write!(f, "no k= tag, so the record names no key"),
            Invalid::BadKey(k) => write!(f, "k={k} is not a 32-byte base58 key"),
            Invalid::BadPort(p) => write!(f, "p={p} is not a port"),
            Invalid::Duplicate(t) => write!(f, "{t}= appears twice"),
            Invalid::EmptyHost => write!(f, "h= is empty"),
        }
    }
}

/// What one `TXT` record turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Ours, and usable.
    Ours(Record),
    /// A SIP-40 handover, structurally sound. Not yet verified: that needs the
    /// domain, and is the lookup's job.
    Handover(Handover),
    /// Not ours. Skipped without comment.
    Foreign,
    /// Ours, and broken.
    Broken(Invalid),
}

/// Join the character-strings of **one** `TXT` record.
///
/// `TXT` RDATA is one or more strings of at most 255 bytes, and the strings
/// within a single record concatenate with no separator. Strings belonging to
/// *different* records never do — that is a different record, saying a different
/// thing. A record here is around 100 bytes so a split will not normally happen,
/// which is exactly why an implementation that gets it wrong will not find out.
pub fn join(strings: &[impl AsRef<[u8]>]) -> String {
    let mut out = String::new();
    for s in strings {
        out.push_str(&String::from_utf8_lossy(s.as_ref()));
    }
    out
}

/// Parse one record's joined text.
pub fn parse(text: &str) -> Parsed {
    let text = text.trim();

    // The version tag must be first and must be ours. Checked before anything
    // else is looked at, so a foreign record costs nothing and reports nothing.
    let Some(first) = text.split(';').next() else {
        return Parsed::Foreign;
    };
    match first.trim().split_once('=') {
        Some((n, v)) if n.trim() == "v" && v.trim() == VERSION => {}
        Some((n, v)) if n.trim() == "v" && v.trim() == HANDOVER_VERSION => {
            return parse_handover(text);
        }
        _ => return Parsed::Foreign,
    }

    let mut key: Option<PubKey> = None;
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut seen_k = false;
    let mut seen_h = false;
    let mut seen_p = false;

    for field in text.split(';').skip(1) {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }
        let Some((name, value)) = field.split_once('=') else {
            // A tag with no value is not a tag. Unknown shapes are ignored for
            // the same reason unknown names are: this is how the record grows.
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        match name {
            "k" => {
                if seen_k {
                    return Parsed::Broken(Invalid::Duplicate("k".into()));
                }
                seen_k = true;
                match value.parse::<PubKey>() {
                    Ok(k) => key = Some(k),
                    Err(_) => return Parsed::Broken(Invalid::BadKey(value.to_string())),
                }
            }
            "h" => {
                if seen_h {
                    return Parsed::Broken(Invalid::Duplicate("h".into()));
                }
                seen_h = true;
                if value.is_empty() {
                    return Parsed::Broken(Invalid::EmptyHost);
                }
                host = Some(value.to_string());
            }
            "p" => {
                if seen_p {
                    return Parsed::Broken(Invalid::Duplicate("p".into()));
                }
                seen_p = true;
                match value.parse::<u16>() {
                    Ok(0) | Err(_) => {
                        return Parsed::Broken(Invalid::BadPort(value.to_string()));
                    }
                    Ok(p) => port = Some(p),
                }
            }
            // Unknown tags are ignored. This is the extension mechanism, and it
            // is why SPF has added modifiers for twenty years without breaking a
            // parser that predates them.
            _ => {}
        }
    }

    match key {
        None => Parsed::Broken(Invalid::NoKey),
        Some(key) => Parsed::Ours(Record {
            key,
            host,
            port: port.unwrap_or(DEFAULT_PORT),
        }),
    }
}

/// Parse a `v=sqex1h` record's joined text.
///
/// Anything wrong is [`Parsed::Foreign`], never [`Parsed::Broken`]: SIP-40 says
/// a bad handover MUST NOT be reported as an error, because the RRset is shared
/// and a malformed record there is not a fault in the client's configuration.
/// Duplicate tags are still fatal to the record, as in SIP-33.
fn parse_handover(text: &str) -> Parsed {
    let mut from: Option<PubKey> = None;
    let mut to: Option<PubKey> = None;
    let mut until: Option<u64> = None;
    let mut sig: Option<[u8; 64]> = None;

    for field in text.split(';').skip(1) {
        let field = field.trim();
        let Some((name, value)) = field.split_once('=') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        match name {
            "from" => {
                if from.is_some() {
                    return Parsed::Foreign;
                }
                match value.parse::<PubKey>() {
                    Ok(k) => from = Some(k),
                    Err(_) => return Parsed::Foreign,
                }
            }
            "to" => {
                if to.is_some() {
                    return Parsed::Foreign;
                }
                match value.parse::<PubKey>() {
                    Ok(k) => to = Some(k),
                    Err(_) => return Parsed::Foreign,
                }
            }
            "until" => {
                if until.is_some() {
                    return Parsed::Foreign;
                }
                match value.parse::<u64>() {
                    Ok(u) => until = Some(u),
                    Err(_) => return Parsed::Foreign,
                }
            }
            "sig" => {
                if sig.is_some() {
                    return Parsed::Foreign;
                }
                let Ok(bytes) = bs58::decode(value).into_vec() else {
                    return Parsed::Foreign;
                };
                let Ok(arr) = <[u8; 64]>::try_from(bytes) else {
                    return Parsed::Foreign;
                };
                sig = Some(arr);
            }
            _ => {}
        }
    }

    match (from, to, until, sig) {
        (Some(from), Some(to), Some(until), Some(sig)) if from != to => {
            Parsed::Handover(Handover {
                from,
                to,
                until,
                sig,
            })
        }
        _ => Parsed::Foreign,
    }
}

/// The name to query for a domain.
pub fn query_name(domain: &str) -> String {
    format!("{LABEL}.{}", domain.trim_end_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "2YQYQCzPocTTdjMoU5KmimvyEkVLzS9mkE4C6QeM2F7u";

    fn ours(text: &str) -> Record {
        match parse(text) {
            Parsed::Ours(r) => r,
            other => panic!("wanted a record, got {other:?}"),
        }
    }

    #[test]
    fn a_full_record_parses() {
        let r = ours(&format!("v=sqex1; k={K}; h=exchange.example.com; p=5400"));
        assert_eq!(r.key.to_string(), K);
        assert_eq!(r.host.as_deref(), Some("exchange.example.com"));
        assert_eq!(r.port, 5400);
    }

    /// The smallest useful record. `h` and `p` fall back, so a domain that runs
    /// its exchange at its own name on the default port publishes one tag.
    #[test]
    fn defaults_apply_when_only_the_key_is_given() {
        let r = ours(&format!("v=sqex1; k={K}"));
        assert_eq!(r.host, None);
        assert_eq!(r.port, DEFAULT_PORT);
    }

    /// The extension mechanism. A record written by something newer than this
    /// parser must still be usable, or the version would have to rise every
    /// time a field is added.
    #[test]
    fn unknown_tags_are_ignored() {
        let r = ours(&format!(
            "v=sqex1; zz=whatever; k={K}; future=1; p=47311; another=x"
        ));
        assert_eq!(r.port, 47311);
        assert_eq!(r.key.to_string(), K);
    }

    /// Somebody else's TXT at the same name is not our problem and must not be
    /// reported as a fault.
    #[test]
    fn a_foreign_record_is_skipped_not_diagnosed() {
        for text in [
            "v=spf1 include:_spf.example.com ~all",
            "google-site-verification=abc123",
            "v=sqex2; k=whatever",
            "k=2YQYQCz; v=sqex1",
            "",
        ] {
            assert_eq!(parse(text), Parsed::Foreign, "{text:?} should be foreign");
        }
    }

    /// Ours and wrong is a different answer from not ours.
    #[test]
    fn a_broken_record_says_so() {
        assert_eq!(parse("v=sqex1; p=5400"), Parsed::Broken(Invalid::NoKey));
        assert!(matches!(
            parse("v=sqex1; k=not-base58-!!"),
            Parsed::Broken(Invalid::BadKey(_))
        ));
        assert!(matches!(
            parse("v=sqex1; k=2YQYQCz"),
            Parsed::Broken(Invalid::BadKey(_))
        ));
        assert!(matches!(
            parse(&format!("v=sqex1; k={K}; p=0")),
            Parsed::Broken(Invalid::BadPort(_))
        ));
        assert!(matches!(
            parse(&format!("v=sqex1; k={K}; p=99999")),
            Parsed::Broken(Invalid::BadPort(_))
        ));
        assert!(matches!(
            parse(&format!("v=sqex1; k={K}; h=")),
            Parsed::Broken(Invalid::EmptyHost)
        ));
    }

    /// Which of two was meant is unknowable, so neither is used.
    #[test]
    fn a_duplicate_tag_is_broken() {
        assert_eq!(
            parse(&format!("v=sqex1; k={K}; k={K}")),
            Parsed::Broken(Invalid::Duplicate("k".into()))
        );
    }

    #[test]
    fn whitespace_and_trailing_semicolons_do_not_matter() {
        let r = ours(&format!("  v=sqex1 ;  k = {K} ;  p = 5400 ;  "));
        assert_eq!(r.port, 5400);
    }

    /// The strings of one record join; the records themselves do not.
    #[test]
    fn character_strings_join_within_a_record_only() {
        let split = ["v=sqex1; k=", K, "; p=5400"];
        assert_eq!(ours(&join(&split)).port, 5400);

        // Two separate records, each parsed on its own. Joining them would make
        // one nonsense record out of two good ones.
        let first = format!("v=sqex1; k={K}");
        let second = format!("v=sqex1; k={K}; p=47311");
        assert_eq!(ours(&first).port, DEFAULT_PORT);
        assert_eq!(ours(&second).port, 47311);
    }

    #[test]
    fn the_query_name_is_underscore_prefixed() {
        assert_eq!(query_name("example.com"), "_sqex.example.com");
        assert_eq!(query_name("example.com."), "_sqex.example.com");
    }
}
