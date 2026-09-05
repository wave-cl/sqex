//! The SIP-4 liveness beacon messages.
//!
//! A bound identity connects and **beats**; the exchange records when it last
//! did so and answers questions about it. Nothing is signed — the connection is
//! the proof, and the identity comes from the transport (SIP-3
//! `peer_identity()`), not from anything in these bytes.
//!
//! The layouts are SIP-4's, byte for byte. The one addition is the beat
//! acknowledgement, which SIP-4 left undefined: it carries the exchange's
//! current time, so a caller learns the clock its `last_seen` will be measured
//! against without a second request.

use sqnr_core::{Error, PubKey, Result};

/// Message type of a beat.
pub const TYPE_BEAT: u8 = 0x01;
/// Message type of a read.
pub const TYPE_READ: u8 = 0x02;

/// `flags` bit 0 — withhold this record from queries by other identities.
pub const FLAG_WITHHOLD: u8 = 0b0000_0001;

/// An identity asserting it is alive.
///
/// `| type: u8 = 0x01 | interval_secs: u32 | flags: u8 |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beat {
    /// How often the identity intends to beat. Read by consumers to judge
    /// staleness; the exchange does not enforce it.
    pub interval_secs: u32,
    /// Withhold the record from other identities' queries.
    pub withhold: bool,
}

impl Beat {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6);
        out.push(TYPE_BEAT);
        out.extend_from_slice(&self.interval_secs.to_be_bytes());
        out.push(if self.withhold { FLAG_WITHHOLD } else { 0 });
        out
    }

    pub fn decode(b: &[u8]) -> Result<Beat> {
        if b.len() != 6 {
            return Err(Error::Malformed(format!(
                "beat is {} bytes, want 6",
                b.len()
            )));
        }
        if b[0] != TYPE_BEAT {
            return Err(Error::Malformed(format!("not a beat (type {:#x})", b[0])));
        }
        let interval_secs = u32::from_be_bytes(b[1..5].try_into().unwrap());
        let flags = b[5];
        // SIP-4: bits other than 0 are reserved and MUST be zero.
        if flags & !FLAG_WITHHOLD != 0 {
            return Err(Error::Malformed(format!(
                "reserved beat flags set: {flags:#010b}"
            )));
        }
        Ok(Beat {
            interval_secs,
            withhold: flags & FLAG_WITHHOLD != 0,
        })
    }
}

/// The exchange's answer to a beat: the time it recorded, so the caller knows
/// the clock its record is kept against.
///
/// `| now: u64 |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeatAck {
    pub now: u64,
}

impl BeatAck {
    pub fn encode(&self) -> Vec<u8> {
        self.now.to_be_bytes().to_vec()
    }

    pub fn decode(b: &[u8]) -> Result<BeatAck> {
        if b.len() != 8 {
            return Err(Error::Malformed(format!(
                "ack is {} bytes, want 8",
                b.len()
            )));
        }
        Ok(BeatAck {
            now: u64::from_be_bytes(b.try_into().unwrap()),
        })
    }
}

/// A question about an identity. Open to any caller — reading is not privileged.
///
/// `| type: u8 = 0x02 | ed25519_pubkey: [32] |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Read {
    pub key: PubKey,
}

impl Read {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_READ);
        out.extend_from_slice(self.key.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Read> {
        if b.len() != 33 {
            return Err(Error::Malformed(format!(
                "read is {} bytes, want 33",
                b.len()
            )));
        }
        if b[0] != TYPE_READ {
            return Err(Error::Malformed(format!("not a read (type {:#x})", b[0])));
        }
        Ok(Read {
            key: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// What the exchange saw.
///
/// `| found: u8 | last_seen: u64 | interval_secs: u32 | now: u64 |`
///
/// `now` is not redundant: a consumer's clock may be wrong, so staleness is
/// `now - last_seen`, measured entirely in the exchange's own time. The
/// exchange never reports up/down — that threshold belongs to the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub found: bool,
    pub last_seen: u64,
    pub interval_secs: u32,
    pub now: u64,
}

impl Reply {
    /// The answer for an identity with no disclosable record. `now` is still
    /// reported, so "not found" and "found" are the same shape.
    pub fn not_found(now: u64) -> Reply {
        Reply {
            found: false,
            last_seen: 0,
            interval_secs: 0,
            now,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(21);
        out.push(u8::from(self.found));
        out.extend_from_slice(&self.last_seen.to_be_bytes());
        out.extend_from_slice(&self.interval_secs.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Reply> {
        if b.len() != 21 {
            return Err(Error::Malformed(format!(
                "reply is {} bytes, want 21",
                b.len()
            )));
        }
        Ok(Reply {
            found: b[0] != 0,
            last_seen: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            interval_secs: u32::from_be_bytes(b[9..13].try_into().unwrap()),
            now: u64::from_be_bytes(b[13..21].try_into().unwrap()),
        })
    }

    /// Seconds since the identity was last seen, in the exchange's own clock.
    pub fn staleness(&self) -> u64 {
        self.now.saturating_sub(self.last_seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beat_round_trip() {
        for withhold in [false, true] {
            let b = Beat {
                interval_secs: 60,
                withhold,
            };
            assert_eq!(Beat::decode(&b.encode()).unwrap(), b);
        }
    }

    #[test]
    fn beat_rejects_reserved_flags() {
        let mut raw = Beat {
            interval_secs: 60,
            withhold: false,
        }
        .encode();
        raw[5] = 0b0000_0010; // a reserved bit
        assert!(Beat::decode(&raw).is_err());
    }

    #[test]
    fn beat_rejects_wrong_length_and_type() {
        assert!(Beat::decode(&[]).is_err());
        assert!(Beat::decode(&[TYPE_BEAT, 0, 0, 0, 60, 0, 0]).is_err());
        assert!(Beat::decode(&[0xFF, 0, 0, 0, 60, 0]).is_err());
    }

    #[test]
    fn ack_round_trip() {
        let a = BeatAck { now: 1_700_000_000 };
        assert_eq!(BeatAck::decode(&a.encode()).unwrap(), a);
        assert!(BeatAck::decode(&[0; 7]).is_err());
    }

    #[test]
    fn read_round_trip() {
        let r = Read {
            key: PubKey::new([7u8; 32]),
        };
        assert_eq!(Read::decode(&r.encode()).unwrap(), r);
        assert!(Read::decode(&[TYPE_READ; 10]).is_err());
    }

    #[test]
    fn reply_round_trip_and_staleness() {
        let r = Reply {
            found: true,
            last_seen: 1000,
            interval_secs: 60,
            now: 1180,
        };
        assert_eq!(Reply::decode(&r.encode()).unwrap(), r);
        assert_eq!(r.staleness(), 180, "three missed beats at a 60s interval");

        let nf = Reply::not_found(500);
        let back = Reply::decode(&nf.encode()).unwrap();
        assert!(!back.found);
        assert_eq!(back.now, 500);
    }
}
