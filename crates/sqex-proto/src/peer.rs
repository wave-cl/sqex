//! SIP-35 exchange-to-exchange replication: what one exchange asks another for.
//!
//! A **replica** serves a channel it did not originate. It pulls entries from
//! the **origin**, verifies every one under SIP-31's signatures, SIP-20's
//! credentials and SIP-34's receipts, and stores nothing that fails — so what
//! it holds is a witnessed copy rather than a cache, and a party reading from
//! it checks the origin's signatures rather than the replica's word.
//!
//! **A replica that skips the verification has built a cache of somebody else's
//! assertions, which is worth less than nothing**: it launders one exchange's
//! word into two. The checking is the whole difference between this and a
//! mirror.
//!
//! # One origin per channel
//!
//! Stated here so no implementation invents otherwise: a channel originated
//! jointly, membership spanning exchanges, an origin that moves, and any merge
//! of two histories are all out of scope. A channel that must change origin is
//! a new channel, and the members create one.
//!
//! # Both ends gate the link
//!
//! An origin holds a list of the peer keys it will serve replication to, and
//! **answers every peering route identically to a caller not on it** — the same
//! refusal whether the peer is unknown, the channel does not exist, or the
//! channel exists and is not replicated. That is SIP-24's rule for its
//! admission endpoint and SIP-4's for a withheld beacon, applied here for the
//! same reason: these routes are reachable by strangers, and a reply that
//! varied would make them an existence oracle for private channels.

use sqnr_core::{Error, PubKey, Result};

use crate::channel::{Entry, Receipted, Tip};

/// Maximum entries one `Pull` may ask for.
pub const MAX_PULL: u16 = 256;
/// Peers one origin will serve replication to.
pub const MAX_PEERS: usize = 16;
/// Replicas one channel may have a surviving authorisation for.
///
/// A policy choice bounding fan-out and, more to the point, bounding the
/// metadata disclosure: each authorisation is another operator who learns the
/// channel's shape. An origin MAY lower it; raising it is not free.
pub const MAX_REPLICAS: usize = 4;
/// Shortest interval between one peer's pulls.
pub const PEER_MIN_INTERVAL: u64 = 1;
/// Bytes one pull response may carry.
pub const MAX_PULL_BYTES: usize = 1024 * 1024;

/// The peering protocol version this build speaks.
pub const PEER_VERSION: u8 = 1;

pub const TYPE_HELLO: u8 = 0x01;
pub const TYPE_PULL: u8 = 0x02;

/// Agree on a version, and say who is asking.
///
/// Establishes nothing else. **It is not authentication** — the sQUIC
/// connection already did that, carrying the caller's SIP-3 identity, which for
/// a peer is the SIP-9 key its own clients pin and its receipts verify under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    /// The lowest sequence number this peer still wants, across the channels it
    /// replicates. Advisory.
    pub since: u64,
}

/// Bytes a `Hello` occupies.
pub const HELLO_LEN: usize = 1 + 1 + 8;

impl Hello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HELLO_LEN);
        out.push(TYPE_HELLO);
        out.push(self.version);
        out.extend_from_slice(&self.since.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Hello> {
        if b.len() != HELLO_LEN {
            return Err(Error::Malformed(format!(
                "hello is {} bytes, want {HELLO_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_HELLO {
            return Err(Error::Malformed(format!("not a hello (type {:#x})", b[0])));
        }
        Ok(Hello {
            version: b[1],
            since: u64::from_be_bytes(b[2..10].try_into().unwrap()),
        })
    }
}

/// The responder's own identity and retention window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hi {
    pub now: u64,
    pub version: u8,
    /// This exchange's SIP-9 identity — the key its receipts verify under.
    pub exchange: PubKey,
    /// How long it keeps entries. A replica reports **its own** window to its
    /// own clients and never presents it as the origin's.
    pub window_secs: u32,
}

/// Bytes a `Hi` occupies.
pub const HI_LEN: usize = 8 + 1 + 32 + 4;

impl Hi {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HI_LEN);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.push(self.version);
        out.extend_from_slice(self.exchange.as_bytes());
        out.extend_from_slice(&self.window_secs.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Hi> {
        if b.len() != HI_LEN {
            return Err(Error::Malformed(format!(
                "hi is {} bytes, want {HI_LEN}",
                b.len()
            )));
        }
        Ok(Hi {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            version: b[8],
            exchange: PubKey::new(b[9..41].try_into().unwrap()),
            window_secs: u32::from_be_bytes(b[41..45].try_into().unwrap()),
        })
    }
}

/// `/channel/fetch` for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pull {
    pub channel: [u8; 32],
    pub since: u64,
    pub max: u16,
}

/// Bytes a `Pull` occupies.
pub const PULL_LEN: usize = 1 + 32 + 8 + 2;

impl Pull {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PULL_LEN);
        out.push(TYPE_PULL);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.since.to_be_bytes());
        out.extend_from_slice(&self.max.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Pull> {
        if b.len() != PULL_LEN {
            return Err(Error::Malformed(format!(
                "pull is {} bytes, want {PULL_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_PULL {
            return Err(Error::Malformed(format!("not a pull (type {:#x})", b[0])));
        }
        Ok(Pull {
            channel: b[1..33].try_into().unwrap(),
            since: u64::from_be_bytes(b[33..41].try_into().unwrap()),
            // Clamped rather than refused, as `Fetch` clamps `wait_secs`: a
            // peer asking for more than the limit is not making an error.
            max: u16::from_be_bytes(b[41..43].try_into().unwrap()).min(MAX_PULL),
        })
    }
}

/// What an origin serves a peer.
///
/// The same `Entry` layout a member's fetch returns — including SIP-31's
/// signature block and SIP-34's stamp, which are always present here — plus the
/// three things a member already knows and a peer does not: the channel's
/// incarnation, the origin's key, and the origin's window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    pub now: u64,
    /// **Served unaltered, and a replica MUST NOT mint one.** SIP-31 binds it
    /// into every signature, so a replica that generated its own would hold a
    /// channel whose entries all fail to verify.
    pub instance: [u8; 32],
    pub origin: PubKey,
    pub first: u64,
    pub last: u64,
    pub window_secs: u32,
    pub entries: Vec<Entry>,
    pub tip: Tip,
}

impl Pulled {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&self.instance);
        out.extend_from_slice(self.origin.as_bytes());
        out.extend_from_slice(&self.first.to_be_bytes());
        out.extend_from_slice(&self.last.to_be_bytes());
        out.extend_from_slice(&self.window_secs.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for e in &self.entries {
            e.write_receipted(&mut out);
        }
        out.extend_from_slice(&self.tip.seq.to_be_bytes());
        out.extend_from_slice(&self.tip.posted.to_be_bytes());
        self.tip.stamp.write_into(&mut out);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Pulled> {
        let head = 8 + 32 + 32 + 8 + 8 + 4 + 2; // now, instance, origin, first, last, window, count
        if b.len() < head {
            return Err(Error::Malformed("pulled is truncated".into()));
        }
        let count = u16::from_be_bytes(b[92..94].try_into().unwrap()) as usize;
        if count > MAX_PULL as usize {
            return Err(Error::Malformed(format!(
                "pulled holds {count}, limit is {MAX_PULL}"
            )));
        }
        let mut o = head;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(Entry::read_receipted(b, &mut o)?);
        }
        if b.len() < o + 16 + crate::channel::RECEIPTED_LEN {
            return Err(Error::Malformed("pulled tip is truncated".into()));
        }
        let tip = Tip {
            seq: u64::from_be_bytes(b[o..o + 8].try_into().unwrap()),
            posted: u64::from_be_bytes(b[o + 8..o + 16].try_into().unwrap()),
            stamp: Receipted::read_from(b, o + 16),
        };
        o += 16 + crate::channel::RECEIPTED_LEN;
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "pulled has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Pulled {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            instance: b[8..40].try_into().unwrap(),
            origin: PubKey::new(b[40..72].try_into().unwrap()),
            first: u64::from_be_bytes(b[72..80].try_into().unwrap()),
            last: u64::from_be_bytes(b[80..88].try_into().unwrap()),
            window_secs: u32::from_be_bytes(b[88..92].try_into().unwrap()),
            entries,
            tip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{KIND_MEMBER, Receipted, Tip};

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn stamp(b: u8) -> Receipted {
        Receipted {
            entry_hash: [b; 32],
            head: [b.wrapping_add(1); 32],
            receipt: [b; 64],
        }
    }

    fn entry(seq: u64, body: &[u8]) -> Entry {
        Entry {
            seq,
            kind: KIND_MEMBER,
            account: key(1),
            device: key(1),
            posted: 1000 + seq,
            expires_after: 0,
            epoch: 0,
            msg_seq: seq,
            chain_seq: seq,
            prev: [0; 32],
            body_hash: [0; 32],
            sig: [0; 64],
            // Never `None` here: an entry pulled without a receipt would be the
            // origin's word about its own ordering, which is what SIP-35 exists
            // to stop a replica repeating.
            stamp: Some(stamp(seq as u8)),
            body: body.to_vec(),
        }
    }

    #[test]
    fn a_hello_and_a_hi_round_trip() {
        let h = Hello {
            version: 1,
            since: 42,
        };
        assert_eq!(Hello::decode(&h.encode()).unwrap(), h);
        assert!(Hello::decode(&h.encode()[..5]).is_err());
        // A pull is not a hello, and the type byte is what says so.
        assert!(Hello::decode(&[TYPE_PULL, 1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());

        let hi = Hi {
            now: 1_700_000_000,
            version: 1,
            exchange: key(9),
            window_secs: 3600,
        };
        assert_eq!(Hi::decode(&hi.encode()).unwrap(), hi);
    }

    #[test]
    fn a_pull_round_trips_and_clamps_what_it_asks_for() {
        let p = Pull {
            channel: [3; 32],
            since: 9,
            max: 64,
        };
        assert_eq!(Pull::decode(&p.encode()).unwrap(), p);
        let greedy = Pull {
            max: u16::MAX,
            ..p
        };
        assert_eq!(Pull::decode(&greedy.encode()).unwrap().max, MAX_PULL);
    }

    #[test]
    fn a_pulled_round_trips_with_entries_and_a_tip() {
        let got = Pulled {
            now: 2000,
            instance: [4; 32],
            origin: key(9),
            first: 1,
            last: 3,
            window_secs: 86_400,
            entries: vec![entry(1, b"one"), entry(2, b""), entry(3, b"three")],
            tip: Tip {
                seq: 3,
                posted: 1003,
                stamp: stamp(3),
            },
        };
        assert_eq!(Pulled::decode(&got.encode()).unwrap(), got);

        // Trailing bytes are refused, as everywhere else here: a structure with
        // slack in it is malleable.
        let mut extra = got.encode();
        extra.push(0);
        assert!(Pulled::decode(&extra).is_err());
        assert!(Pulled::decode(&got.encode()[..40]).is_err());
    }
}
