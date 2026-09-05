//! SIP-25: two identities behind NAT ask an exchange to introduce them.
//!
//! **Address disclosure is the entire mechanism, so consent is not a detail.**
//! An introduction is served only when *both* parties have asked for it, and
//! until then no address is disclosed and neither learns that the other asked.
//! Without that rule an identity that could request an introduction to anyone
//! could locate anyone bound to the exchange.
//!
//! The address disclosed is the one the **exchange observed**, never one a
//! caller supplied. That is what stops the route being a reflection: a
//! coordinated pair of simultaneous connections to an address a third party
//! chose is exactly the shape an amplification abuse takes, and requiring both
//! sides to have asked, independently, is what addresses it.
//!
//! # Introduction presupposes prior knowledge
//!
//! A sQUIC server refuses anyone who does not already hold its public key, so
//! an introduced peer must already know the other's identity. The exchange
//! therefore reveals an **address and never a key**, and cannot introduce
//! strangers. That is a limitation of the design and also its safety property.
//!
//! # What this half does not do
//!
//! It coordinates. It does not punch: `squic::dial` binds a fresh ephemeral
//! port, so a peer cannot dial from the port the exchange observed, and the
//! reuse of that mapping is the whole mechanism. See SIP-25 on what remains.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use sqnr_core::{Error, PubKey, Result};

pub const TYPE_INTRODUCE: u8 = 0x01;

/// Longest a caller may hold an introduction request open.
///
/// A request is a long poll: the first party to ask waits for the second, and
/// both are answered at once, which is what makes a coordinated start possible
/// at all. Bounded because a request holds a connection.
pub const MAX_WAIT: u16 = 30;

/// How long after the answer both sides are told to begin.
///
/// **The exchange states its own clock alongside**, so each side computes its
/// own offset rather than trusting that the three clocks agree — the rule SIP-4
/// gives for staleness, applied to a start time.
pub const START_LEAD_SECS: u64 = 2;

/// Ask to be introduced to `peer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Introduce {
    pub peer: PubKey,
    /// How long to hold the request open waiting for the other side.
    pub wait_secs: u16,
}

/// Bytes an `Introduce` occupies.
pub const INTRODUCE_LEN: usize = 1 + 32 + 2;

impl Introduce {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INTRODUCE_LEN);
        out.push(TYPE_INTRODUCE);
        out.extend_from_slice(self.peer.as_bytes());
        out.extend_from_slice(&self.wait_secs.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Introduce> {
        if b.len() != INTRODUCE_LEN {
            return Err(Error::Malformed(format!(
                "introduce is {} bytes, want {INTRODUCE_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_INTRODUCE {
            return Err(Error::Malformed(format!(
                "not an introduce (type {:#x})",
                b[0]
            )));
        }
        Ok(Introduce {
            peer: PubKey::new(b[1..33].try_into().unwrap()),
            // Clamped rather than refused, as SIP-16 clamps a fetch's wait.
            wait_secs: u16::from_be_bytes(b[33..35].try_into().unwrap()).min(MAX_WAIT),
        })
    }
}

/// What the exchange tells each side.
///
/// `ready` is false when the other party has not asked. **Nothing else is
/// disclosed in that case** — not the address, and not that anybody asked at
/// all, which would itself be a signal about somebody who has not consented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Introduced {
    pub ready: bool,
    /// The peer's address **as the exchange observed it**. Zeroes when not
    /// ready.
    pub addr: Option<SocketAddr>,
    /// When both sides should begin, on the exchange's clock.
    pub start_at: u64,
    /// The exchange's clock, so each side can compute its own offset rather
    /// than assume the three agree.
    pub now: u64,
}

/// Bytes an `Introduced` occupies: a fixed shape whether or not it is ready, so
/// the length of the answer discloses nothing.
pub const INTRODUCED_LEN: usize = 1 + 1 + 16 + 2 + 8 + 8;

impl Introduced {
    /// Not ready, said in the same bytes as ready — see [`INTRODUCED_LEN`].
    pub fn waiting(now: u64) -> Introduced {
        Introduced {
            ready: false,
            addr: None,
            start_at: 0,
            now,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INTRODUCED_LEN);
        out.push(u8::from(self.ready));
        match self.addr {
            Some(SocketAddr::V4(a)) => {
                out.push(4);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&[0u8; 12]);
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            Some(SocketAddr::V6(a)) => {
                out.push(6);
                out.extend_from_slice(&a.ip().octets());
                out.extend_from_slice(&a.port().to_be_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 18]);
            }
        }
        out.extend_from_slice(&self.start_at.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Introduced> {
        if b.len() != INTRODUCED_LEN {
            return Err(Error::Malformed(format!(
                "introduced is {} bytes, want {INTRODUCED_LEN}",
                b.len()
            )));
        }
        let port = u16::from_be_bytes(b[18..20].try_into().unwrap());
        let addr = match b[1] {
            4 => {
                let o: [u8; 4] = b[2..6].try_into().unwrap();
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port))
            }
            6 => {
                let o: [u8; 16] = b[2..18].try_into().unwrap();
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
            }
            0 => None,
            other => {
                return Err(Error::Malformed(format!("unknown address kind {other}")));
            }
        };
        Ok(Introduced {
            ready: b[0] != 0,
            addr,
            start_at: u64::from_be_bytes(b[20..28].try_into().unwrap()),
            now: u64::from_be_bytes(b[28..36].try_into().unwrap()),
        })
    }
}
