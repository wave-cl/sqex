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

/// SIP-69: the same request from a caller that understands
/// [`Answer::NoSharedFamily`]. A SIP-25 caller sends [`TYPE_INTRODUCE`] and
/// is never told it -- where the families do not meet it is answered with the
/// same waiting it would have received had the peer not asked at all.
pub const TYPE_INTRODUCE_FAMILIES: u8 = 0x02;

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
    /// SIP-69: whether this caller can be told the two share no address
    /// family. Sent as the type byte, so an exchange that does not implement
    /// SIP-69 refuses it as malformed and the caller falls back.
    pub family_aware: bool,
}

/// Bytes an `Introduce` occupies.
pub const INTRODUCE_LEN: usize = 1 + 32 + 2;

impl Introduce {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INTRODUCE_LEN);
        out.push(if self.family_aware {
            TYPE_INTRODUCE_FAMILIES
        } else {
            TYPE_INTRODUCE
        });
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
        let family_aware = match b[0] {
            TYPE_INTRODUCE => false,
            TYPE_INTRODUCE_FAMILIES => true,
            other => {
                return Err(Error::Malformed(format!(
                    "not an introduce (type {other:#x})"
                )));
            }
        };
        Ok(Introduce {
            family_aware,
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
/// What the exchange has to say, as the first byte of an [`Introduced`].
///
/// Three values where SIP-25 had two. The reply is the same length whichever
/// it is, so its size discloses nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The other party has not asked. Nothing else is disclosed -- not the
    /// address, and not that anybody asked at all.
    Waiting = 0,
    /// Both asked, on a family they share. The address is the peer's.
    Ready = 1,
    /// SIP-69: both asked, and they share no address family, so neither could
    /// dial the other. Served **only when both have asked**, which is what
    /// makes it safe: it tells a party who has consented by asking something
    /// about a party who has consented by asking.
    NoSharedFamily = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Introduced {
    pub answer: Answer,
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
            answer: Answer::Waiting,
            addr: None,
            start_at: 0,
            now,
        }
    }

    /// SIP-69: both asked, and no family is common to them.
    pub fn no_shared_family(now: u64) -> Introduced {
        Introduced {
            answer: Answer::NoSharedFamily,
            addr: None,
            start_at: 0,
            now,
        }
    }

    /// Whether an address was disclosed and the pair should begin.
    pub fn is_ready(&self) -> bool {
        self.answer == Answer::Ready
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INTRODUCED_LEN);
        out.push(self.answer as u8);
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
        let answer = match b[0] {
            0 => Answer::Waiting,
            1 => Answer::Ready,
            2 => Answer::NoSharedFamily,
            other => {
                return Err(Error::Malformed(format!(
                    "unknown introduced answer {other}"
                )));
            }
        };
        Ok(Introduced {
            answer,
            addr,
            start_at: u64::from_be_bytes(b[20..28].try_into().unwrap()),
            now: u64::from_be_bytes(b[28..36].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    /// SIP-69 rides on the type byte, so an exchange that predates it refuses
    /// the request as malformed -- which is how a caller discovers it and
    /// falls back rather than being silently misunderstood.
    #[test]
    fn the_type_byte_says_whether_the_caller_understands_families() {
        let plain = Introduce {
            peer: key(2),
            wait_secs: 8,
            family_aware: false,
        };
        let aware = Introduce {
            family_aware: true,
            ..plain
        };
        assert_eq!(plain.encode()[0], TYPE_INTRODUCE);
        assert_eq!(aware.encode()[0], TYPE_INTRODUCE_FAMILIES);
        assert_eq!(Introduce::decode(&plain.encode()).unwrap(), plain);
        assert_eq!(Introduce::decode(&aware.encode()).unwrap(), aware);
        assert_eq!(
            plain.encode().len(),
            aware.encode().len(),
            "the request is the same shape either way"
        );

        let mut odd = aware.encode();
        odd[0] = 0x03;
        assert!(
            Introduce::decode(&odd).is_err(),
            "an unknown type is refused"
        );
    }

    /// All three answers round-trip, and **all three are the same length**:
    /// the size of the reply must disclose nothing, which is SIP-25's rule and
    /// the reason the third value is a byte rather than a longer message.
    #[test]
    fn every_answer_is_the_same_shape() {
        let ready = Introduced {
            answer: Answer::Ready,
            addr: Some("203.0.113.7:5400".parse().unwrap()),
            start_at: 99,
            now: 97,
        };
        let waiting = Introduced::waiting(97);
        let neither = Introduced::no_shared_family(97);

        for one in [ready, waiting, neither] {
            assert_eq!(one.encode().len(), INTRODUCED_LEN);
            assert_eq!(Introduced::decode(&one.encode()).unwrap(), one);
        }
        assert!(ready.is_ready());
        assert!(!waiting.is_ready());
        assert!(!neither.is_ready(), "no address was disclosed");
        assert_eq!(neither.addr, None);

        let mut odd = neither.encode();
        odd[0] = 0x09;
        assert!(
            Introduced::decode(&odd).is_err(),
            "an unknown answer is refused rather than read as ready"
        );
    }

    /// An IPv6 address survives the 16 bytes it is given, and an IPv4 one is
    /// not mistaken for an IPv6 address made of its zero padding.
    #[test]
    fn an_address_of_either_family_round_trips() {
        for text in ["203.0.113.7:5400", "[2a02:8084:d05:2a80::1]:52555"] {
            let addr: std::net::SocketAddr = text.parse().unwrap();
            let one = Introduced {
                answer: Answer::Ready,
                addr: Some(addr),
                start_at: 5,
                now: 3,
            };
            assert_eq!(Introduced::decode(&one.encode()).unwrap().addr, Some(addr));
        }
    }
}
