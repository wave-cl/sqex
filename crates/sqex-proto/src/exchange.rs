//! Exchange-level answers that belong to no service.
//!
//! Two routes. `/exchange/peers` (SIP-39 §The peer directory) lists the exchanges this one
//! federates with -- a hint a client pins by SIP-33 before trusting.
//! `/exchange/ping` exists to demonstrate SIP-9
//! whitelist enforcement, and used to answer `{"pong": true}` — a constant that
//! said nothing a 200 had not already said. The clock is worth more: a caller
//! checking whether it is allowed in generally wants to know the exchange is
//! awake and roughly when it thinks it is, and every other acknowledgement here
//! (`BeatAck`, `ChannelAck`) carries the same field for the same reason.

use sqnr_core::{Error, Result};

pub const TYPE_PONG: u8 = 0x01;

/// The answer to a ping: you are allowed, and this is my clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub now: u64,
}

impl Pong {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.push(TYPE_PONG);
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Pong> {
        if b.len() != 9 {
            return Err(Error::Malformed(format!(
                "pong is {} bytes, want 9",
                b.len()
            )));
        }
        if b[0] != TYPE_PONG {
            return Err(Error::Malformed(format!("not a pong (type {:#x})", b[0])));
        }
        Ok(Pong {
            now: u64::from_be_bytes(b[1..9].try_into().unwrap()),
        })
    }
}

/// Message type of a peer directory.
pub const TYPE_PEERS: u8 = 0x02;

/// The longest domain an entry may carry: a DNS name.
pub const MAX_DOMAIN: usize = 253;

/// One exchange this one federates with: its key, and the domain it is
/// reached by when the operator recorded one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    pub key: sqnr_core::PubKey,
    /// Lowercase DNS name, or empty: a peer may be known by key alone.
    pub domain: String,
}

/// The directory (SIP-39 §The peer directory).
///
/// `| type: u8 = 0x02 | count: u16 | (key[32] | domain_len: u8 | domain) * |`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Peers {
    pub peers: Vec<PeerEntry>,
}

impl Peers {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.peers.len() * 40);
        out.push(TYPE_PEERS);
        out.extend_from_slice(&(self.peers.len() as u16).to_be_bytes());
        for p in &self.peers {
            out.extend_from_slice(p.key.as_bytes());
            let domain = p.domain.as_bytes();
            out.push(domain.len().min(MAX_DOMAIN) as u8);
            out.extend_from_slice(&domain[..domain.len().min(MAX_DOMAIN)]);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Peers> {
        if b.len() < 3 {
            return Err(Error::Malformed("peers too short".into()));
        }
        if b[0] != TYPE_PEERS {
            return Err(Error::Malformed(format!(
                "not a peer list (type {:#x})",
                b[0]
            )));
        }
        let count = u16::from_be_bytes([b[1], b[2]]) as usize;
        let mut at = 3;
        let mut peers = Vec::with_capacity(count);
        for _ in 0..count {
            let key = b
                .get(at..at + 32)
                .ok_or_else(|| Error::Malformed("peer entry cut short".into()))?;
            at += 32;
            let len = *b
                .get(at)
                .ok_or_else(|| Error::Malformed("peer entry cut short".into()))?
                as usize;
            at += 1;
            let domain = b
                .get(at..at + len)
                .ok_or_else(|| Error::Malformed("peer domain cut short".into()))?;
            at += len;
            let domain = std::str::from_utf8(domain)
                .map_err(|_| Error::Malformed("peer domain is not UTF-8".into()))?;
            if !domain.is_empty() && !is_domain(domain) {
                return Err(Error::Malformed(format!(
                    "peer domain {domain:?} is not a DNS name"
                )));
            }
            peers.push(PeerEntry {
                key: sqnr_core::PubKey::new(key.try_into().unwrap()),
                domain: domain.to_string(),
            });
        }
        if at != b.len() {
            return Err(Error::Malformed(format!(
                "peer list has {} trailing bytes",
                b.len() - at
            )));
        }
        Ok(Peers { peers })
    }
}

/// Whether `s` is a lowercase DNS name of the shape SIP-33 discovers: labels
/// of letters, digits and hyphens, joined by dots, at least two of them.
pub fn is_domain(s: &str) -> bool {
    if s.len() > MAX_DOMAIN || !s.contains('.') {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A list round-trips, with and without domains, and the shape is
    /// refused where it is not the shape.
    #[test]
    fn a_peer_list_round_trips_and_a_bad_domain_is_refused() {
        let peers = Peers {
            peers: vec![
                PeerEntry {
                    key: sqnr_core::PubKey::new([1; 32]),
                    domain: "trunk.exchange".into(),
                },
                PeerEntry {
                    key: sqnr_core::PubKey::new([2; 32]),
                    domain: String::new(),
                },
            ],
        };
        assert_eq!(Peers::decode(&peers.encode()).unwrap(), peers);
        assert_eq!(
            Peers::decode(&Peers::default().encode()).unwrap(),
            Peers::default()
        );
        let mut raw = peers.encode();
        raw.push(0);
        assert!(
            Peers::decode(&raw).is_err(),
            "trailing bytes are corruption"
        );
        let cut = &peers.encode()[..40];
        assert!(Peers::decode(cut).is_err());
        let bad = Peers {
            peers: vec![PeerEntry {
                key: sqnr_core::PubKey::new([3; 32]),
                domain: "Not A Domain".into(),
            }],
        };
        assert!(
            Peers::decode(&bad.encode()).is_err(),
            "a label is not a domain"
        );
    }

    #[test]
    fn what_counts_as_a_domain() {
        assert!(is_domain("squic.org"));
        assert!(is_domain("ex.trunk.exchange"));
        assert!(is_domain("a-b.c1"));
        assert!(!is_domain("squic"), "one label is not a name to discover");
        assert!(!is_domain("Squic.org"), "lowercase, as SIP-33 discovers");
        assert!(!is_domain("-a.b"));
        assert!(!is_domain("a..b"));
        assert!(!is_domain("a b.c"));
        assert!(!is_domain(""));
    }

    #[test]
    fn a_pong_round_trips() {
        let p = Pong { now: 1_788_000_000 };
        assert_eq!(Pong::decode(&p.encode()).unwrap(), p);
        assert_eq!(p.encode().len(), 9);
    }

    #[test]
    fn a_wrong_shape_is_refused() {
        assert!(Pong::decode(&[TYPE_PONG, 0, 0]).is_err());
        assert!(Pong::decode(&[0x02, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
