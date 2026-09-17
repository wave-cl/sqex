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
use crate::channel_key::{Envelope, read_envelope_with_recipient, write_envelope};

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
pub const TYPE_ENVELOPES: u8 = 0x03;
pub const TYPE_BLOB: u8 = 0x04;
pub const TYPE_RECORD: u8 = 0x05;
/// SIP-43: a member's post, carried from a replica to the origin.
pub const TYPE_FORWARD: u8 = 0x06;
/// SIP-43: what the constitution's digest covers and a replica cannot
/// recover from it -- the channel's visibility, name and topic.
pub const TYPE_SHAPE: u8 = 0x07;
/// SIP-43: a member's signed membership request -- a join or a leave --
/// carried from a replica to the origin as the member sent it.
pub const TYPE_FORWARD_ACTION: u8 = 0x09;
/// SIP-43: where a device stands at the origin -- its SIP-31 chain and its
/// SIP-17 counter -- which a replica does not track and a device with a
/// fresh store cannot otherwise learn.
pub const TYPE_STANDING: u8 = 0x08;
/// SIP-54: a replica asks the origin for every member's read marks.
pub const TYPE_CURSORS: u8 = 0x0a;
/// SIP-54: a replica asks the origin for the signals logged since a point.
pub const TYPE_SIGNALS: u8 = 0x0b;
/// SIP-54: signals the origin keeps per channel for replicas to pull.
pub const SIGNAL_LOG: usize = 256;
/// SIP-57: a replica asks the origin what was redacted since a time.
pub const TYPE_TOMBSTONES: u8 = 0x0c;
/// SIP-59: an account's home asks an origin which channels the account is
/// in there.
pub const TYPE_MINE: u8 = 0x0d;
/// SIP-59: a forward wrapped with the device's credential, for a device
/// the origin may never have seen.
pub const TYPE_CARRIED: u8 = 0x0e;
/// SIP-59: the home carries an account's Move to an origin.
pub const TYPE_MOVED: u8 = 0x0f;

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
        let greedy = Pull { max: u16::MAX, ..p };
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

/// SIP-35: pull a channel's SIP-17 key envelopes.
///
/// Every recipient's, not one — a replica holds the channel for its members and
/// cannot open any of them. Each is a signed SIP-32 artifact the replica
/// verifies for itself, which is what stops a dishonest origin substituting a
/// key envelope on the way through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullEnvelopes {
    pub channel: [u8; 32],
    pub since_epoch: u32,
}

/// Bytes a `PullEnvelopes` occupies.
pub const PULL_ENVELOPES_LEN: usize = 1 + 32 + 4;

impl PullEnvelopes {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PULL_ENVELOPES_LEN);
        out.push(TYPE_ENVELOPES);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.since_epoch.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullEnvelopes> {
        if b.len() != PULL_ENVELOPES_LEN {
            return Err(Error::Malformed(format!(
                "envelope pull is {} bytes, want {PULL_ENVELOPES_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_ENVELOPES {
            return Err(Error::Malformed(format!(
                "not an envelope pull (type {:#x})",
                b[0]
            )));
        }
        Ok(PullEnvelopes {
            channel: b[1..33].try_into().unwrap(),
            since_epoch: u32::from_be_bytes(b[33..37].try_into().unwrap()),
        })
    }
}

/// One envelope as a peer receives it: the epoch its `Put` was made at, which
/// is bound into the signature and which a peer has no other way to know, and
/// the envelope itself with its recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledEnvelopes {
    pub now: u64,
    pub envelopes: Vec<(u32, Envelope)>,
}

impl PulledEnvelopes {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.envelopes.len() as u16).to_be_bytes());
        for (epoch, e) in &self.envelopes {
            out.extend_from_slice(&epoch.to_be_bytes());
            write_envelope(e, &mut out);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<PulledEnvelopes> {
        if b.len() < 10 {
            return Err(Error::Malformed("pulled envelopes is truncated".into()));
        }
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap()) as usize;
        if count > MAX_PULL as usize {
            return Err(Error::Malformed(format!(
                "pulled envelopes holds {count}, limit is {MAX_PULL}"
            )));
        }
        let mut o = 10;
        let mut envelopes = Vec::with_capacity(count);
        for _ in 0..count {
            if b.len() < o + 4 {
                return Err(Error::Malformed("pulled envelopes is truncated".into()));
            }
            let epoch = u32::from_be_bytes(b[o..o + 4].try_into().unwrap());
            o += 4;
            envelopes.push((epoch, read_envelope_with_recipient(b, &mut o)?));
        }
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "pulled envelopes has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(PulledEnvelopes {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            envelopes,
        })
    }
}

/// SIP-35: pull a blob, or the list of a channel's blobs.
///
/// **A replica cannot read a private channel's bodies**, so it cannot see which
/// attachments they reference. The origin knows — it registers every attachment
/// against its channel for quota and collection — so it lists them. `chunk` is
/// `u32::MAX` to ask for that list rather than for bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullBlob {
    pub channel: [u8; 32],
    pub blob: [u8; 32],
    pub chunk: u32,
}

/// `chunk` value that asks for a channel's blob list rather than for bytes.
pub const BLOB_LIST: u32 = u32::MAX;
/// Bytes a `PullBlob` occupies.
pub const PULL_BLOB_LEN: usize = 1 + 32 + 32 + 4;

impl PullBlob {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PULL_BLOB_LEN);
        out.push(TYPE_BLOB);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.blob);
        out.extend_from_slice(&self.chunk.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullBlob> {
        if b.len() != PULL_BLOB_LEN {
            return Err(Error::Malformed(format!(
                "blob pull is {} bytes, want {PULL_BLOB_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_BLOB {
            return Err(Error::Malformed(format!(
                "not a blob pull (type {:#x})",
                b[0]
            )));
        }
        Ok(PullBlob {
            channel: b[1..33].try_into().unwrap(),
            blob: b[33..65].try_into().unwrap(),
            chunk: u32::from_be_bytes(b[65..69].try_into().unwrap()),
        })
    }
}

/// A channel's blobs, or one chunk of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledBlob {
    /// Present when the request asked for the list.
    pub blobs: Vec<([u8; 32], u64, u32)>,
    /// Present when it asked for bytes: the sealed chunk, opaque here.
    pub sealed: Vec<u8>,
}

impl PulledBlob {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.blobs.len() as u16).to_be_bytes());
        for (id, size, chunks) in &self.blobs {
            out.extend_from_slice(id);
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&chunks.to_be_bytes());
        }
        out.extend_from_slice(&(self.sealed.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn decode(b: &[u8]) -> Result<PulledBlob> {
        if b.len() < 2 {
            return Err(Error::Malformed("pulled blob is truncated".into()));
        }
        let count = u16::from_be_bytes(b[0..2].try_into().unwrap()) as usize;
        let mut o = 2;
        let mut blobs = Vec::with_capacity(count);
        for _ in 0..count {
            if b.len() < o + 44 {
                return Err(Error::Malformed("pulled blob list is truncated".into()));
            }
            blobs.push((
                b[o..o + 32].try_into().unwrap(),
                u64::from_be_bytes(b[o + 32..o + 40].try_into().unwrap()),
                u32::from_be_bytes(b[o + 40..o + 44].try_into().unwrap()),
            ));
            o += 44;
        }
        if b.len() < o + 4 {
            return Err(Error::Malformed("pulled blob is truncated".into()));
        }
        let len = u32::from_be_bytes(b[o..o + 4].try_into().unwrap()) as usize;
        o += 4;
        if b.len() != o + len {
            return Err(Error::Malformed("pulled blob length disagrees".into()));
        }
        Ok(PulledBlob {
            blobs,
            sealed: b[o..o + len].to_vec(),
        })
    }
}

/// SIP-35: pull one account's signed profile record.
///
/// The record half in miniature, and the one artifact whose supersession rule
/// this document borrows wholesale: highest serial wins, as `sqns` has done
/// between servers since its first release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullRecord {
    pub account: PubKey,
}

/// Bytes a `PullRecord` occupies.
pub const PULL_RECORD_LEN: usize = 1 + 32;

impl PullRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PULL_RECORD_LEN);
        out.push(TYPE_RECORD);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullRecord> {
        if b.len() != PULL_RECORD_LEN {
            return Err(Error::Malformed(format!(
                "record pull is {} bytes, want {PULL_RECORD_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_RECORD {
            return Err(Error::Malformed(format!(
                "not a record pull (type {:#x})",
                b[0]
            )));
        }
        Ok(PullRecord {
            account: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// SIP-43: a post a member made at a replica, carried to the origin as the
/// member sent it. `device` is the transport identity it arrived on; the
/// origin resolves the account from its own registry and takes nothing else
/// on the replica's word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    pub device: PubKey,
    pub post: crate::channel::Post,
}

impl Forward {
    pub fn encode(&self) -> Vec<u8> {
        let post = self.post.encode();
        let mut out = Vec::with_capacity(33 + post.len());
        out.push(TYPE_FORWARD);
        out.extend_from_slice(self.device.as_bytes());
        out.extend_from_slice(&post);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Forward> {
        if b.len() < 33 {
            return Err(Error::Malformed(format!(
                "forward is {} bytes, want at least 33",
                b.len()
            )));
        }
        if b[0] != TYPE_FORWARD {
            return Err(Error::Malformed(format!(
                "not a forward (type {:#x})",
                b[0]
            )));
        }
        Ok(Forward {
            device: PubKey::new(b[1..33].try_into().unwrap()),
            post: crate::channel::Post::decode(&b[33..])?,
        })
    }
}

/// The origin's answer to a forwarded post: what its own `/channel/post`
/// would have said to that member, status and body, for the replica to hand
/// back unaltered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarded {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Forwarded {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.body.len());
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Forwarded> {
        if b.len() < 2 {
            return Err(Error::Malformed("forwarded answer cut short".into()));
        }
        Ok(Forwarded {
            status: u16::from_be_bytes([b[0], b[1]]),
            body: b[2..].to_vec(),
        })
    }
}

#[cfg(test)]
mod forward_tests {
    use super::*;

    /// A forward carries the post exactly as the member sent it, and an
    /// answer carries the origin's status and body exactly as it gave them.
    #[test]
    fn a_forward_and_its_answer_round_trip() {
        let post = crate::channel::Post {
            channel: [1; 32],
            epoch: 2,
            msg_seq: 3,
            expires_after: 0,
            chain_seq: 4,
            prev: [5; 32],
            sig: [6; 64],
            receipts: true,
            body: b"hello".to_vec(),
        };
        let f = Forward {
            device: PubKey::new([7; 32]),
            post,
        };
        assert_eq!(Forward::decode(&f.encode()).unwrap(), f);
        let mut wrong = f.encode();
        wrong[0] = TYPE_PULL;
        assert!(Forward::decode(&wrong).is_err());
        assert!(Forward::decode(&[TYPE_FORWARD; 10]).is_err());

        let a = Forwarded {
            status: 421,
            body: vec![1, 2, 3],
        };
        assert_eq!(Forwarded::decode(&a.encode()).unwrap(), a);
        assert!(Forwarded::decode(&[1]).is_err());
    }
}

/// SIP-43: ask the origin for a channel's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullShape {
    pub channel: [u8; 32],
}

impl PullShape {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_SHAPE);
        out.extend_from_slice(&self.channel);
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullShape> {
        if b.len() != 33 {
            return Err(Error::Malformed(format!(
                "shape pull is {} bytes, want 33",
                b.len()
            )));
        }
        if b[0] != TYPE_SHAPE {
            return Err(Error::Malformed(format!(
                "not a shape pull (type {:#x})",
                b[0]
            )));
        }
        Ok(PullShape {
            channel: b[1..33].try_into().unwrap(),
        })
    }
}

/// A channel's shape as its origin holds it: SIP-32's constitution covers
/// these in a digest a replica cannot invert, so the origin states them. A
/// private channel's name and topic are empty here as they are there.
///
/// `| visibility: u8 | name_len: u8 | name | topic_len: u16 | topic |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    pub visibility: crate::channel::Visibility,
    pub name: String,
    pub topic: String,
}

impl Shape {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.name.len() + self.topic.len());
        out.push(self.visibility as u8);
        out.push(self.name.len().min(255) as u8);
        out.extend_from_slice(&self.name.as_bytes()[..self.name.len().min(255)]);
        let topic = &self.topic.as_bytes()[..self.topic.len().min(u16::MAX as usize)];
        out.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        out.extend_from_slice(topic);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Shape> {
        let short = || Error::Malformed("shape cut short".into());
        let visibility = crate::channel::Visibility::from_u8(*b.first().ok_or_else(short)?)?;
        let name_len = *b.get(1).ok_or_else(short)? as usize;
        let name = b.get(2..2 + name_len).ok_or_else(short)?;
        let at = 2 + name_len;
        let topic_len =
            u16::from_be_bytes(b.get(at..at + 2).ok_or_else(short)?.try_into().unwrap()) as usize;
        let topic = b.get(at + 2..at + 2 + topic_len).ok_or_else(short)?;
        if b.len() != at + 2 + topic_len {
            return Err(Error::Malformed("shape has trailing bytes".into()));
        }
        let text = |x: &[u8], what: &str| {
            std::str::from_utf8(x)
                .map(|s| s.to_string())
                .map_err(|_| Error::Malformed(format!("{what} is not UTF-8")))
        };
        Ok(Shape {
            visibility,
            name: text(name, "name")?,
            topic: text(topic, "topic")?,
        })
    }
}

#[cfg(test)]
mod shape_tests {
    use super::*;

    #[test]
    fn a_shape_round_trips_and_a_cut_one_is_refused() {
        let s = Shape {
            visibility: crate::channel::Visibility::Public,
            name: "town square".into(),
            topic: "everything".into(),
        };
        assert_eq!(Shape::decode(&s.encode()).unwrap(), s);
        let empty = Shape {
            visibility: crate::channel::Visibility::Private,
            name: String::new(),
            topic: String::new(),
        };
        assert_eq!(Shape::decode(&empty.encode()).unwrap(), empty);
        let mut cut = s.encode();
        cut.pop();
        assert!(Shape::decode(&cut).is_err());
        let p = PullShape { channel: [3; 32] };
        assert_eq!(PullShape::decode(&p.encode()).unwrap(), p);
    }
}

/// SIP-54: `POST /peer/cursors`, answered with SIP-16's `Marks`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullCursors {
    pub channel: [u8; 32],
}

impl PullCursors {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_CURSORS);
        out.extend_from_slice(&self.channel);
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullCursors> {
        if b.len() != 33 || b[0] != TYPE_CURSORS {
            return Err(Error::Malformed("not a cursors pull".into()));
        }
        Ok(PullCursors {
            channel: b[1..33].try_into().unwrap(),
        })
    }
}

/// SIP-54: `POST /peer/signals`: the channel's signal log above `since`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullSignals {
    pub channel: [u8; 32],
    pub since: u64,
}

impl PullSignals {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(TYPE_SIGNALS);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.since.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullSignals> {
        if b.len() != 41 || b[0] != TYPE_SIGNALS {
            return Err(Error::Malformed("not a signals pull".into()));
        }
        Ok(PullSignals {
            channel: b[1..33].try_into().unwrap(),
            since: u64::from_be_bytes(b[33..41].try_into().unwrap()),
        })
    }
}

/// SIP-54: one signal as the origin logged it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    pub seq: u64,
    pub account: PubKey,
    pub device: PubKey,
    pub kind: u8,
    pub at: u64,
    pub body: Vec<u8>,
}

/// SIP-54: the answer to a signals pull.
///
/// `| next: u64 | count: u16 | count × (seq: u64 | account[32] | device[32] | kind: u8 | at: u64 | len: u16 | body) |`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Signals {
    pub next: u64,
    pub signals: Vec<Logged>,
}

impl Signals {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.signals.len() * 90);
        out.extend_from_slice(&self.next.to_be_bytes());
        out.extend_from_slice(&(self.signals.len() as u16).to_be_bytes());
        for l in &self.signals {
            out.extend_from_slice(&l.seq.to_be_bytes());
            out.extend_from_slice(l.account.as_bytes());
            out.extend_from_slice(l.device.as_bytes());
            out.push(l.kind);
            out.extend_from_slice(&l.at.to_be_bytes());
            out.extend_from_slice(&(l.body.len().min(u16::MAX as usize) as u16).to_be_bytes());
            out.extend_from_slice(&l.body[..l.body.len().min(u16::MAX as usize)]);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Signals> {
        if b.len() < 10 {
            return Err(Error::Malformed("signals cut short".into()));
        }
        let next = u64::from_be_bytes(b[..8].try_into().unwrap());
        let count = u16::from_be_bytes([b[8], b[9]]) as usize;
        if count > SIGNAL_LOG {
            return Err(Error::Malformed("too many signals".into()));
        }
        let mut at = 10;
        let mut signals = Vec::with_capacity(count);
        for _ in 0..count {
            if at + 83 > b.len() {
                return Err(Error::Malformed("signals cut short".into()));
            }
            let seq = u64::from_be_bytes(b[at..at + 8].try_into().unwrap());
            let account = PubKey::new(b[at + 8..at + 40].try_into().unwrap());
            let device = PubKey::new(b[at + 40..at + 72].try_into().unwrap());
            let kind = b[at + 72];
            let when = u64::from_be_bytes(b[at + 73..at + 81].try_into().unwrap());
            let len = u16::from_be_bytes([b[at + 81], b[at + 82]]) as usize;
            at += 83;
            if at + len > b.len() {
                return Err(Error::Malformed("signals cut short".into()));
            }
            signals.push(Logged {
                seq,
                account,
                device,
                kind,
                at: when,
                body: b[at..at + len].to_vec(),
            });
            at += len;
        }
        if at != b.len() {
            return Err(Error::Malformed("trailing bytes after signals".into()));
        }
        Ok(Signals { next, signals })
    }
}

/// SIP-57: `POST /peer/tombstones`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullTombstones {
    pub channel: [u8; 32],
    pub since: u64,
}

impl PullTombstones {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(TYPE_TOMBSTONES);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.since.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullTombstones> {
        if b.len() != 41 || b[0] != TYPE_TOMBSTONES {
            return Err(Error::Malformed("not a tombstones pull".into()));
        }
        Ok(PullTombstones {
            channel: b[1..33].try_into().unwrap(),
            since: u64::from_be_bytes(b[33..41].try_into().unwrap()),
        })
    }
}

/// SIP-57: the answer: `| now: u64 | count: u16 | count × (seq: u64 | at: u64) |`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tombstones {
    pub now: u64,
    pub redacted: Vec<(u64, u64)>,
}

impl Tombstones {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.redacted.len() * 16);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.redacted.len() as u16).to_be_bytes());
        for (seq, at) in &self.redacted {
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&at.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Tombstones> {
        if b.len() < 10 {
            return Err(Error::Malformed("tombstones cut short".into()));
        }
        let now = u64::from_be_bytes(b[..8].try_into().unwrap());
        let count = u16::from_be_bytes([b[8], b[9]]) as usize;
        if b.len() != 10 + count * 16 {
            return Err(Error::Malformed("tombstones cut short".into()));
        }
        let redacted = (0..count)
            .map(|i| {
                let at = 10 + i * 16;
                (
                    u64::from_be_bytes(b[at..at + 8].try_into().unwrap()),
                    u64::from_be_bytes(b[at + 8..at + 16].try_into().unwrap()),
                )
            })
            .collect();
        Ok(Tombstones { now, redacted })
    }
}

/// SIP-43: ask the origin where `device` stands in `channel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullStanding {
    pub channel: [u8; 32],
    pub device: PubKey,
}

impl PullStanding {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(TYPE_STANDING);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(self.device.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullStanding> {
        if b.len() != 65 {
            return Err(Error::Malformed(format!(
                "standing pull is {} bytes, want 65",
                b.len()
            )));
        }
        if b[0] != TYPE_STANDING {
            return Err(Error::Malformed(format!(
                "not a standing pull (type {:#x})",
                b[0]
            )));
        }
        Ok(PullStanding {
            channel: b[1..33].try_into().unwrap(),
            device: PubKey::new(b[33..65].try_into().unwrap()),
        })
    }
}

/// What the origin's own `Channel` would tell that device: the next chain
/// position to sign at and the link to put in it, and the highest counter
/// accepted at the current epoch. `| next_chain: u64 | head[32] | msg_seq: u64 |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    pub next_chain: u64,
    pub head: [u8; 32],
    pub msg_seq: u64,
    /// SIP-53: where the channel's origin went, if it has: the new origin's
    /// key and a hint to its domain. Absent on an exchange from before
    /// SIP-53, which is what a 48-byte answer means.
    pub moved: Option<(PubKey, String)>,
}

impl Standing {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&self.next_chain.to_be_bytes());
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&self.msg_seq.to_be_bytes());
        if let Some((to, domain)) = &self.moved {
            out.extend_from_slice(to.as_bytes());
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Standing> {
        if b.len() < 48 {
            return Err(Error::Malformed(format!(
                "standing is {} bytes, want at least 48",
                b.len()
            )));
        }
        let moved = if b.len() == 48 {
            None
        } else {
            if b.len() < 81 || b.len() != 81 + b[80] as usize {
                return Err(Error::Malformed("standing's move cut short".into()));
            }
            let domain = std::str::from_utf8(&b[81..])
                .map_err(|_| Error::Malformed("domain is not UTF-8".into()))?
                .to_string();
            Some((PubKey::new(b[48..80].try_into().unwrap()), domain))
        };
        Ok(Standing {
            next_chain: u64::from_be_bytes(b[..8].try_into().unwrap()),
            head: b[8..40].try_into().unwrap(),
            msg_seq: u64::from_be_bytes(b[40..48].try_into().unwrap()),
            moved,
        })
    }
}

#[cfg(test)]
mod standing_tests {
    use super::*;

    #[test]
    fn a_standing_round_trips() {
        let p = PullStanding {
            channel: [1; 32],
            device: PubKey::new([2; 32]),
        };
        assert_eq!(PullStanding::decode(&p.encode()).unwrap(), p);
        let s = Standing {
            next_chain: 7,
            head: [3; 32],
            msg_seq: 9,
            moved: None,
        };
        assert_eq!(Standing::decode(&s.encode()).unwrap(), s);
        assert!(Standing::decode(&[0; 47]).is_err());
        // SIP-53: with the move, and an older reader's 48 bytes without.
        let m = Standing {
            moved: Some((PubKey::new([5; 32]), "y.test".into())),
            ..s.clone()
        };
        assert_eq!(Standing::decode(&m.encode()).unwrap(), m);
        assert_eq!(Standing::decode(&m.encode()[..48]).unwrap(), s);
    }
}

/// SIP-43: a signed request a member made at a replica, carried to the
/// origin: which route it was for and the bytes as sent. Only routes the
/// origin lists are honoured -- a join or a leave, each carrying the
/// member's own SIP-31 action -- and the origin resolves `device` to an
/// account from its own registry, as for a forwarded post.
///
/// `| type = 0x09 | device[32] | path_len: u8 | path | body |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAction {
    pub device: PubKey,
    pub path: String,
    pub body: Vec<u8>,
}

impl ForwardAction {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34 + self.path.len() + self.body.len());
        out.push(TYPE_FORWARD_ACTION);
        out.extend_from_slice(self.device.as_bytes());
        out.push(self.path.len().min(255) as u8);
        out.extend_from_slice(&self.path.as_bytes()[..self.path.len().min(255)]);
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(b: &[u8]) -> Result<ForwardAction> {
        let short = || Error::Malformed("forwarded action cut short".into());
        if b.first() != Some(&TYPE_FORWARD_ACTION) {
            return Err(Error::Malformed("not a forwarded action".into()));
        }
        let device = PubKey::new(b.get(1..33).ok_or_else(short)?.try_into().unwrap());
        let len = *b.get(33).ok_or_else(short)? as usize;
        let path = b.get(34..34 + len).ok_or_else(short)?;
        let path = std::str::from_utf8(path)
            .map_err(|_| Error::Malformed("path is not UTF-8".into()))?
            .to_string();
        Ok(ForwardAction {
            device,
            path,
            body: b[34 + len..].to_vec(),
        })
    }
}

#[cfg(test)]
mod forward_action_tests {
    use super::*;

    #[test]
    fn a_forwarded_action_round_trips() {
        let f = ForwardAction {
            device: PubKey::new([1; 32]),
            path: "/channel/join".into(),
            body: vec![9, 8, 7],
        };
        assert_eq!(ForwardAction::decode(&f.encode()).unwrap(), f);
        assert!(ForwardAction::decode(&[TYPE_FORWARD_ACTION; 20]).is_err());
        assert!(ForwardAction::decode(&[0]).is_err());
    }
}

/// SIP-59: the home of an account asks an origin which of the channels it
/// orders the account is a present member of. `| type = 0x0d | account[32] |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullMine {
    pub account: PubKey,
}

impl PullMine {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_MINE);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<PullMine> {
        if b.len() != 33 || b[0] != TYPE_MINE {
            return Err(Error::Malformed("not a mine pull".into()));
        }
        Ok(PullMine {
            account: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// SIP-59: the origin's answer. `| now: u64 | count: u16 | count × channel[32] |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mine {
    pub now: u64,
    pub channels: Vec<[u8; 32]>,
}

impl Mine {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.channels.len() * 32);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.channels.len().min(u16::MAX as usize) as u16).to_be_bytes());
        for c in self.channels.iter().take(u16::MAX as usize) {
            out.extend_from_slice(c);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Mine> {
        let short = || Error::Malformed("mine cut short".into());
        let now = u64::from_be_bytes(b.get(0..8).ok_or_else(short)?.try_into().unwrap());
        let count =
            u16::from_be_bytes(b.get(8..10).ok_or_else(short)?.try_into().unwrap()) as usize;
        if b.len() != 10 + count * 32 {
            return Err(short());
        }
        let channels = (0..count)
            .map(|i| b[10 + i * 32..42 + i * 32].try_into().unwrap())
            .collect();
        Ok(Mine { now, channels })
    }
}

/// SIP-59: a forward for a device the origin may never have seen, with the
/// device's SIP-20 credential as the home holds it. `inner` is a `Forward`
/// or a `ForwardAction` exactly as SIP-43 sends it.
/// `| type = 0x0e | cred_len: u16 | credential | inner |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carried {
    pub credential: crate::credential::Credential,
    pub inner: Vec<u8>,
}

impl Carried {
    pub fn encode(&self) -> Vec<u8> {
        let cred = self.credential.encode();
        let mut out = Vec::with_capacity(3 + cred.len() + self.inner.len());
        out.push(TYPE_CARRIED);
        out.extend_from_slice(&(cred.len() as u16).to_be_bytes());
        out.extend_from_slice(&cred);
        out.extend_from_slice(&self.inner);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Carried> {
        let short = || Error::Malformed("carried forward cut short".into());
        if b.first() != Some(&TYPE_CARRIED) {
            return Err(Error::Malformed("not a carried forward".into()));
        }
        let len = u16::from_be_bytes(b.get(1..3).ok_or_else(short)?.try_into().unwrap()) as usize;
        let cred = b.get(3..3 + len).ok_or_else(short)?;
        let credential = crate::credential::Credential::decode(cred)?;
        let inner = b[3 + len..].to_vec();
        if inner.is_empty() {
            return Err(short());
        }
        Ok(Carried { credential, inner })
    }
}

/// SIP-59: the home carries an account's Move to an origin over the
/// peering link. `| type = 0x0f | Move | dom_len: u8 | domain |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerMoved {
    pub mv: crate::home::Move,
    pub domain: String,
}

impl PeerMoved {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + crate::home::MOVE_LEN + self.domain.len());
        out.push(TYPE_MOVED);
        self.mv.write(&mut out);
        let d = self.domain.as_bytes();
        out.push(d.len().min(255) as u8);
        out.extend_from_slice(&d[..d.len().min(255)]);
        out
    }

    pub fn decode(b: &[u8]) -> Result<PeerMoved> {
        let short = || Error::Malformed("peer move cut short".into());
        if b.first() != Some(&TYPE_MOVED) {
            return Err(Error::Malformed("not a peer move".into()));
        }
        let mut at = 1;
        let mv = crate::home::Move::read(b, &mut at)?;
        let len = *b.get(at).ok_or_else(short)? as usize;
        at += 1;
        let domain = b.get(at..at + len).ok_or_else(short)?;
        if at + len != b.len() {
            return Err(Error::Malformed("trailing bytes after a peer move".into()));
        }
        Ok(PeerMoved {
            mv,
            domain: String::from_utf8(domain.to_vec())
                .map_err(|_| Error::Malformed("domain is not UTF-8".into()))?,
        })
    }
}

#[cfg(test)]
mod home_peer_tests {
    use super::*;

    #[test]
    fn the_home_messages_round_trip() {
        let p = PullMine {
            account: PubKey::new([4; 32]),
        };
        assert_eq!(PullMine::decode(&p.encode()).unwrap(), p);
        assert!(PullMine::decode(&p.encode()[..32]).is_err());

        let m = Mine {
            now: 3,
            channels: vec![[1; 32], [2; 32]],
        };
        assert_eq!(Mine::decode(&m.encode()).unwrap(), m);
        assert!(Mine::decode(&m.encode()[..40]).is_err());

        let seed = [7u8; 32];
        let device = PubKey::new([8; 32]);
        let credential = crate::credential::Credential::issue(
            &seed,
            &device,
            crate::credential::SCOPE_CHAT,
            10,
            20,
        )
        .unwrap();
        let c = Carried {
            credential,
            inner: vec![TYPE_FORWARD, 1, 2, 3],
        };
        assert_eq!(Carried::decode(&c.encode()).unwrap(), c);
        let mut empty = c.encode();
        empty.truncate(empty.len() - 4);
        assert!(Carried::decode(&empty).is_err());

        let mv = crate::home::Move::sign(&seed, &PubKey::new([9; 32]), 5);
        let pm = PeerMoved {
            mv,
            domain: "home.example".into(),
        };
        assert_eq!(PeerMoved::decode(&pm.encode()).unwrap(), pm);
        let mut trailing = pm.encode();
        trailing.push(0);
        assert!(PeerMoved::decode(&trailing).is_err());
    }
}
