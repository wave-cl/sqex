//! SIP-38 names for a domain: the per-domain directory that maps a
//! human-memorable label to an account.
//!
//! A name binds to an **account** (SIP-22's person key), never to a device, so
//! everything downstream — the account's devices (SIP-22), its endpoints
//! (SIP-28) — already works once a name resolves. This module is only the one
//! hop in the middle: name → account.
//!
//! **The binding is exchange-asserted, not signed**, and that is a stronger
//! trust than SIP-28 asks: there a consumer pins the key it looked up, so a
//! lying exchange can only deny; here the exchange asserts *which key* a name
//! means and a consumer has no independent check. The concession is the same
//! one SIP-33 already makes for the domain — someone must be authoritative for
//! a name — and a future account-signed claim is the upgrade that would remove
//! it.
//!
//! Four messages on `POST /name`: [`Claim`], [`Release`], [`Resolve`],
//! [`Reverse`]. Administration (assigning and releasing names, and reading the
//! directory) is carried in a SIP-10 transaction instead — see the `Op` variants
//! `NameAssign`/`NameRelease`/`NameList` in the crate root.

use sqnr_core::{Error, PubKey, Result};

pub const TYPE_CLAIM: u8 = 0x01;
pub const TYPE_RELEASE: u8 = 0x02;
pub const TYPE_RESOLVE: u8 = 0x03;
pub const TYPE_REVERSE: u8 = 0x04;

/// Longest a name may be, in its canonical form. DNS-label-shaped.
pub const MAX_NAME: usize = 63;

/// What a [`Claim`] resulted in. The namespace is public by construction, so
/// unlike admission (SIP-24) this reports its outcome rather than answering
/// identically — a directory that would not say whether a name is free is not a
/// directory.
pub const CLAIM_GRANTED: u8 = 0;
pub const CLAIM_TAKEN: u8 = 1;
pub const CLAIM_AT_CAPACITY: u8 = 2;
pub const CLAIM_CLOSED: u8 = 3;
pub const CLAIM_RATE_LIMITED: u8 = 4;

/// `flags` bit 0 in a [`Resolved`]: the lease has lapsed but no one has
/// reclaimed the name. It still resolves; the flag says it is on notice.
pub const FLAG_STALE: u8 = 0x01;

/// Validate and canonicalise a name.
///
/// The canonical form is ASCII-lowercased and must match
/// `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, 1–63 bytes: DNS-label-shaped, so
/// `name@domain` parses without ambiguity and there is no confusable or
/// homograph surface. Uppercase is folded (so `C` and `c` are one name);
/// anything else — `@`, `.`, whitespace, a non-ASCII byte, a leading or
/// trailing hyphen — is refused.
pub fn canonical(name: &str) -> Result<String> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(Error::Malformed("name is empty".into()));
    }
    if bytes.len() > MAX_NAME {
        return Err(Error::Malformed(format!(
            "name is {} bytes, limit is {MAX_NAME}",
            bytes.len()
        )));
    }
    let mut out = String::with_capacity(bytes.len());
    for (i, &b) in bytes.iter().enumerate() {
        let c = match b {
            b'A'..=b'Z' => b + 32, // ASCII lowercase
            b'a'..=b'z' | b'0'..=b'9' => b,
            b'-' => {
                if i == 0 || i == bytes.len() - 1 {
                    return Err(Error::Malformed(
                        "a name may not begin or end with '-'".into(),
                    ));
                }
                b'-'
            }
            _ => {
                return Err(Error::Malformed(format!(
                    "name contains a byte that is not [a-z0-9-]: {b:#x}"
                )));
            }
        };
        out.push(c as char);
    }
    Ok(out)
}

/// A peer/target argument a client was given: a key typed directly, or a name
/// to resolve through the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Key(PubKey),
    /// A `name@domain`, or a bare `name` (domain `None`) meaning "the exchange
    /// this client is already talking to".
    Named {
        name: String,
        domain: Option<String>,
    },
}

/// Classify a peer/target string **without touching the network**, shared by
/// every client (CLI, chat, voice). A base58 Ed25519 key is taken as itself;
/// anything else is a name — `name@domain`, or a bare `name` — canonicalised
/// per [`canonical`]. The key parse is tried first, so an explicit key is never
/// reinterpreted as a name.
pub fn classify(input: &str) -> Result<Target> {
    let trimmed = input.trim();
    if let Ok(key) = trimmed.parse::<PubKey>() {
        return Ok(Target::Key(key));
    }
    match trimmed.split_once('@') {
        Some((local, domain)) => {
            if domain.is_empty() || domain.contains('@') || local.is_empty() {
                return Err(Error::Malformed(format!(
                    "{input:?} is not a valid name@domain"
                )));
            }
            Ok(Target::Named {
                name: canonical(local)?,
                domain: Some(domain.to_string()),
            })
        }
        None => Ok(Target::Named {
            name: canonical(trimmed)?,
            domain: None,
        }),
    }
}

fn read_name(b: &[u8]) -> Result<String> {
    // type byte, length byte, then the label.
    if b.len() < 2 {
        return Err(Error::Malformed("name request is truncated".into()));
    }
    let len = b[1] as usize;
    if b.len() != 2 + len {
        return Err(Error::Malformed("name length disagrees".into()));
    }
    let raw =
        std::str::from_utf8(&b[2..]).map_err(|_| Error::Malformed("name is not UTF-8".into()))?;
    // Canonicalise on decode, so a caller that did not fold cannot smuggle a
    // second spelling of a taken name past the store's primary key.
    canonical(raw)
}

fn write_name(type_byte: u8, name: &str, out: &mut Vec<u8>) {
    out.push(type_byte);
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
}

/// Claim a free (or one's own, or a lapsed) name for the caller's account.
///
/// Self-asserted: the connection has already proved the account (SIP-3 +
/// SIP-22), exactly as SIP-28 publication is unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub name: String,
}

impl Claim {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.name.len());
        write_name(TYPE_CLAIM, &self.name, &mut out);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Claim> {
        if b.first() != Some(&TYPE_CLAIM) {
            return Err(Error::Malformed("not a claim".into()));
        }
        Ok(Claim {
            name: read_name(b)?,
        })
    }
}

/// Give up a name the caller's account holds. A no-op otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub name: String,
}

impl Release {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.name.len());
        write_name(TYPE_RELEASE, &self.name, &mut out);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Release> {
        if b.first() != Some(&TYPE_RELEASE) {
            return Err(Error::Malformed("not a release".into()));
        }
        Ok(Release {
            name: read_name(b)?,
        })
    }
}

/// Ask which account a name is bound to. Answerable to anyone: the namespace is
/// public by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolve {
    pub name: String,
}

impl Resolve {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.name.len());
        write_name(TYPE_RESOLVE, &self.name, &mut out);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Resolve> {
        if b.first() != Some(&TYPE_RESOLVE) {
            return Err(Error::Malformed("not a resolve".into()));
        }
        Ok(Resolve {
            name: read_name(b)?,
        })
    }
}

/// Ask what names an account holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reverse {
    pub account: PubKey,
}

pub const REVERSE_LEN: usize = 1 + 32;

impl Reverse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REVERSE_LEN);
        out.push(TYPE_REVERSE);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Reverse> {
        if b.len() != REVERSE_LEN {
            return Err(Error::Malformed(format!(
                "reverse is {} bytes, want {REVERSE_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_REVERSE {
            return Err(Error::Malformed("not a reverse".into()));
        }
        Ok(Reverse {
            account: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// The reply to a [`Claim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimAck {
    pub outcome: u8,
    pub now: u64,
}

impl ClaimAck {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.push(self.outcome);
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<ClaimAck> {
        if b.len() != 9 {
            return Err(Error::Malformed("claim ack is not 9 bytes".into()));
        }
        Ok(ClaimAck {
            outcome: b[0],
            now: u64::from_be_bytes(b[1..9].try_into().unwrap()),
        })
    }
}

/// The answer to a [`Resolve`], with the provenance a consumer needs to judge
/// it — when it was registered, when the account was last active, and when the
/// lease lapses (zero for an administrator's assignment, which does not expire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    pub found: bool,
    pub now: u64,
    pub account: PubKey,
    pub registered_at: u64,
    pub last_active: u64,
    pub expires_at: u64,
    /// Past `expires_at` but not yet reclaimed. Still resolves; on notice.
    pub stale: bool,
}

impl Resolved {
    /// Nothing bound, in the same shape as an answer.
    pub fn none(now: u64) -> Resolved {
        Resolved {
            found: false,
            now,
            account: PubKey::new([0; 32]),
            registered_at: 0,
            last_active: 0,
            expires_at: 0,
            stale: false,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 32 + 24 + 1);
        out.push(u8::from(self.found));
        out.extend_from_slice(&self.now.to_be_bytes());
        if self.found {
            out.extend_from_slice(self.account.as_bytes());
            out.extend_from_slice(&self.registered_at.to_be_bytes());
            out.extend_from_slice(&self.last_active.to_be_bytes());
            out.extend_from_slice(&self.expires_at.to_be_bytes());
            out.push(if self.stale { FLAG_STALE } else { 0 });
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Resolved> {
        if b.len() < 9 {
            return Err(Error::Malformed("resolved is truncated".into()));
        }
        let found = b[0] != 0;
        let now = u64::from_be_bytes(b[1..9].try_into().unwrap());
        if !found {
            if b.len() != 9 {
                return Err(Error::Malformed(
                    "absent resolved has trailing bytes".into(),
                ));
            }
            return Ok(Resolved::none(now));
        }
        if b.len() != 9 + 32 + 24 + 1 {
            return Err(Error::Malformed(
                "present resolved is the wrong length".into(),
            ));
        }
        let account = PubKey::new(b[9..41].try_into().unwrap());
        let at = |i: usize| u64::from_be_bytes(b[41 + i..41 + i + 8].try_into().unwrap());
        let flags = b[65];
        Ok(Resolved {
            found,
            now,
            account,
            registered_at: at(0),
            last_active: at(8),
            expires_at: at(16),
            stale: flags & FLAG_STALE != 0,
        })
    }
}

/// The reply to a [`Reverse`]: the names an account holds, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    pub now: u64,
    pub names: Vec<String>,
}

impl Names {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.names.len() as u16).to_be_bytes());
        for n in &self.names {
            out.push(n.len() as u8);
            out.extend_from_slice(n.as_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Names> {
        if b.len() < 10 {
            return Err(Error::Malformed("names reply is truncated".into()));
        }
        let now = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap()) as usize;
        let mut o = 10;
        let mut names = Vec::with_capacity(count);
        for _ in 0..count {
            if b.len() < o + 1 {
                return Err(Error::Malformed("name is truncated".into()));
            }
            let len = b[o] as usize;
            o += 1;
            if b.len() < o + len {
                return Err(Error::Malformed("name is truncated".into()));
            }
            names.push(
                std::str::from_utf8(&b[o..o + len])
                    .map_err(|_| Error::Malformed("name is not UTF-8".into()))?
                    .to_string(),
            );
            o += len;
        }
        if o != b.len() {
            return Err(Error::Malformed("names reply has trailing bytes".into()));
        }
        Ok(Names { now, names })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalises_and_validates() {
        assert_eq!(canonical("Colin").unwrap(), "colin");
        assert_eq!(canonical("c").unwrap(), "c");
        assert_eq!(canonical("a-b-c").unwrap(), "a-b-c");
        assert_eq!(canonical("web3").unwrap(), "web3");
        // Rejected: empty, over-long, out-of-set, edge hyphens.
        assert!(canonical("").is_err());
        assert!(canonical(&"a".repeat(MAX_NAME + 1)).is_err());
        assert!(canonical("c@squic.org").is_err());
        assert!(canonical("a.b").is_err());
        assert!(canonical("a b").is_err());
        assert!(canonical("-lead").is_err());
        assert!(canonical("trail-").is_err());
        assert!(canonical("café").is_err());
    }

    #[test]
    fn the_four_requests_round_trip() {
        let c = Claim {
            name: "colin".into(),
        };
        assert_eq!(Claim::decode(&c.encode()).unwrap(), c);
        let r = Release {
            name: "colin".into(),
        };
        assert_eq!(Release::decode(&r.encode()).unwrap(), r);
        let g = Resolve {
            name: "colin".into(),
        };
        assert_eq!(Resolve::decode(&g.encode()).unwrap(), g);
        let rev = Reverse {
            account: PubKey::new([7; 32]),
        };
        assert_eq!(Reverse::decode(&rev.encode()).unwrap(), rev);
    }

    #[test]
    fn a_request_canonicalises_on_decode() {
        // A caller that sent uppercase gets folded — the store never sees two
        // spellings of one name.
        let mut raw = Vec::new();
        write_name(TYPE_CLAIM, "COLIN", &mut raw);
        assert_eq!(Claim::decode(&raw).unwrap().name, "colin");
        // And a request whose body is not a valid name is refused here.
        let mut bad = Vec::new();
        write_name(TYPE_CLAIM, "a.b", &mut bad);
        assert!(Claim::decode(&bad).is_err());
    }

    #[test]
    fn each_request_refuses_the_others_type_byte() {
        let c = Claim { name: "x".into() }.encode();
        assert!(Release::decode(&c).is_err());
        assert!(Resolve::decode(&c).is_err());
    }

    #[test]
    fn a_claim_ack_round_trips() {
        for outcome in [
            CLAIM_GRANTED,
            CLAIM_TAKEN,
            CLAIM_AT_CAPACITY,
            CLAIM_CLOSED,
            CLAIM_RATE_LIMITED,
        ] {
            let a = ClaimAck {
                outcome,
                now: 1_700_000_000,
            };
            assert_eq!(ClaimAck::decode(&a.encode()).unwrap(), a);
        }
    }

    #[test]
    fn a_resolved_round_trips_present_and_absent() {
        let r = Resolved {
            found: true,
            now: 1_700_000_100,
            account: PubKey::new([3; 32]),
            registered_at: 1_700_000_000,
            last_active: 1_700_000_050,
            expires_at: 1_700_002_000,
            stale: true,
        };
        assert_eq!(Resolved::decode(&r.encode()).unwrap(), r);
        let none = Resolved::none(1_700_000_000);
        assert_eq!(Resolved::decode(&none.encode()).unwrap(), none);
        assert!(!none.found);
    }

    #[test]
    fn classify_key_vs_name() {
        // A real published key (ex's identity) classifies as a key — and it is
        // also a valid *name* by grammar, so this proves key-parse wins first.
        const KEY: &str = "2j68p8rZKXE6W1f6LerRGB2SPTH8JkbfMmZRFTzcLKyW";
        assert!(matches!(classify(KEY).unwrap(), Target::Key(_)));
        assert_eq!(
            classify("colin").unwrap(),
            Target::Named {
                name: "colin".into(),
                domain: None
            }
        );
        assert_eq!(
            classify("Colin@squic.org").unwrap(),
            Target::Named {
                name: "colin".into(),
                domain: Some("squic.org".into())
            }
        );
        for bad in ["a.b", "", "x@", "@squic.org", "a@b@c", "café"] {
            assert!(classify(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn a_names_reply_round_trips() {
        let n = Names {
            now: 1_700_000_000,
            names: vec!["colin".into(), "c".into(), "carl".into()],
        };
        assert_eq!(Names::decode(&n.encode()).unwrap(), n);
        let empty = Names {
            now: 1,
            names: vec![],
        };
        assert_eq!(Names::decode(&empty.encode()).unwrap(), empty);
    }
}
