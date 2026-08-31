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
