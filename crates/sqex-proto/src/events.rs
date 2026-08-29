//! SIP-30 events: the exchange tells a client what changed, instead of being
//! asked.
//!
//! Every other route here is a question and an answer. This one is a question
//! asked once — `POST /events` — whose answer never finishes: the exchange
//! holds the response stream open and writes a frame whenever something a
//! caller is entitled to see changes. An HTTP/3 request is a bidirectional
//! stream, so this needs no new transport, no second connection, and no
//! server-opened stream whose type the peer's h3 layer would have to agree
//! about.
//!
//! # An event is a hint, not the news
//!
//! A frame says *"channel X changed"*, never *what* changed. The client then
//! runs the fetch it already runs. That is deliberate and it is the load-
//! bearing decision in this module: `/channel/fetch` stays the single authority
//! on membership, retention and the reset sequence space, and an event cannot
//! disagree with it because it never claims anything. The cost is one round
//! trip per change. The gain is that traffic becomes proportional to what
//! happens rather than to how long a client has been running, and that there is
//! no second copy of the authorization rules to keep in step.
//!
//! It also means a **lost or duplicated event is survivable by construction**.
//! Acting on a hint twice is a wasted fetch; missing one is repaired by the
//! next hint, or by the slow sweep every client keeps as a floor.
//!
//! # Two rules that cannot be recovered from if broken
//!
//! **Subscribe before you read.** The subscription must be registered at the
//! exchange before the client's first reconciling fetch. An event firing in
//! that gap is then queued rather than dropped, and the worst case is a
//! redundant fetch. Reversed, the client silently misses everything that
//! happened while it was catching up and nothing ever says so. This is the same
//! discipline the long-poll `fetch_waiting` already states — the notifier is
//! taken before the first read.
//!
//! **An unknown kind is ignored, not refused.** SIP-19 inherits this from
//! SIP-15 and it is the entire reason a later kind of event can ship without a
//! flag day. [`Event::Unknown`] exists so that ignoring one is a thing the
//! decoder *does* rather than a thing it fails to do.

use sqnr_core::{Error, PubKey, Result};

/// The subscribe request's type byte.
pub const TYPE_SUBSCRIBE: u8 = 0x01;

/// The event protocol this build speaks.
pub const VERSION: u8 = 1;

/// Largest frame accepted off the wire.
///
/// An event is a hint with at most two keys in it, so this is roughly sixteen
/// times what any current kind needs. It is not a capacity estimate: it is the
/// bound that stops a broken or hostile exchange from making a client buffer
/// without limit while it waits for a length that will never be reached.
pub const MAX_FRAME: usize = 1024;

/// Bytes of length prefix ahead of every frame.
pub const LENGTH_PREFIX: usize = 4;

pub const KIND_CHANNEL: u8 = 0x01;
pub const KIND_SIGNAL: u8 = 0x02;
pub const KIND_CURSOR: u8 = 0x03;
pub const KIND_MEMBERSHIP: u8 = 0x04;
pub const KIND_PROFILE: u8 = 0x05;
pub const KIND_ADMISSION: u8 = 0x06;
pub const KIND_HEARTBEAT: u8 = 0x07;
pub const KIND_RESYNC: u8 = 0x08;

/// What happened to a membership.
pub const MEMBER_JOINED: u8 = 0x01;
pub const MEMBER_LEFT: u8 = 0x02;
pub const MEMBER_REMOVED: u8 = 0x03;
pub const MEMBER_ROLE: u8 = 0x04;

/// Open an event stream.
///
/// Carries a version so a later client can ask for more without a second route.
/// There is nothing else to say: the exchange knows who the caller is from the
/// SIP-3 identity on the connection, and everything it may be told follows from
/// that. A subscription that named channels would be a list the exchange has to
/// keep in step with a membership it already holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subscribe {
    pub version: u8,
}

impl Subscribe {
    pub fn encode(&self) -> Vec<u8> {
        vec![TYPE_SUBSCRIBE, self.version]
    }

    pub fn decode(b: &[u8]) -> Result<Subscribe> {
        if b.len() != 2 {
            return Err(Error::Malformed(format!(
                "subscribe is {} bytes, want 2",
                b.len()
            )));
        }
        if b[0] != TYPE_SUBSCRIBE {
            return Err(Error::Malformed(format!(
                "not a subscribe (type {:#x})",
                b[0]
            )));
        }
        Ok(Subscribe { version: b[1] })
    }
}

/// One thing that changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Entries exist in this channel at or below `last_seq`. Fetch it.
    ///
    /// `last_seq` is **0 for "something changed and we are not saying what"** —
    /// a redaction or a newly delivered key, where there is no single entry to
    /// name. A client may use a non-zero value to skip a fetch it has already
    /// overtaken; it must treat zero as a reason to fetch.
    Channel { channel: [u8; 32], last_seq: u64 },
    /// A signal — typing, today — is waiting for the caller in this channel.
    Signal { channel: [u8; 32] },
    /// Somebody's read mark moved in this channel.
    Cursor { channel: [u8; 32] },
    /// A membership changed. `account` is who: when it is the caller, the
    /// conversation list itself has changed and not merely a member count.
    Membership {
        channel: [u8; 32],
        account: PubKey,
        what: u8,
    },
    /// This account published a profile. Refetch it, ignoring any cache.
    Profile { account: PubKey },
    /// An admission request is waiting (SIP-24). Admins only.
    Admission,
    /// Nothing happened. Proof the stream is alive rather than the exchange
    /// silent, which is the only thing distinguishing the two from here.
    Heartbeat,
    /// The caller fell behind and events were dropped. Re-read everything.
    Resync,
    /// A kind this build does not know. Carried rather than rejected so that
    /// ignoring it is deliberate; see the module docs.
    Unknown(u8),
}

impl Event {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Event::Channel { channel, last_seq } => {
                let mut out = Vec::with_capacity(41);
                out.push(KIND_CHANNEL);
                out.extend_from_slice(channel);
                out.extend_from_slice(&last_seq.to_be_bytes());
                out
            }
            Event::Signal { channel } => one(KIND_SIGNAL, channel),
            Event::Cursor { channel } => one(KIND_CURSOR, channel),
            Event::Membership {
                channel,
                account,
                what,
            } => {
                let mut out = Vec::with_capacity(66);
                out.push(KIND_MEMBERSHIP);
                out.extend_from_slice(channel);
                out.extend_from_slice(account.as_bytes());
                out.push(*what);
                out
            }
            Event::Profile { account } => one(KIND_PROFILE, account.as_bytes()),
            Event::Admission => vec![KIND_ADMISSION],
            Event::Heartbeat => vec![KIND_HEARTBEAT],
            Event::Resync => vec![KIND_RESYNC],
            Event::Unknown(k) => vec![*k],
        }
    }

    /// Decode one frame body.
    ///
    /// A kind we do not know is [`Event::Unknown`] and not an error. A kind we
    /// *do* know, at the wrong length, is an error: that is a broken peer
    /// rather than a newer one, and pretending otherwise would let a malformed
    /// frame pass as a future feature.
    pub fn decode(b: &[u8]) -> Result<Event> {
        let Some(&kind) = b.first() else {
            return Err(Error::Malformed("empty event frame".into()));
        };
        let body = &b[1..];
        let want = |n: usize| -> Result<()> {
            if body.len() == n {
                Ok(())
            } else {
                Err(Error::Malformed(format!(
                    "event {kind:#x} is {} bytes, want {n}",
                    body.len()
                )))
            }
        };
        Ok(match kind {
            KIND_CHANNEL => {
                want(40)?;
                Event::Channel {
                    channel: body[0..32].try_into().unwrap(),
                    last_seq: u64::from_be_bytes(body[32..40].try_into().unwrap()),
                }
            }
            KIND_SIGNAL => {
                want(32)?;
                Event::Signal {
                    channel: body[0..32].try_into().unwrap(),
                }
            }
            KIND_CURSOR => {
                want(32)?;
                Event::Cursor {
                    channel: body[0..32].try_into().unwrap(),
                }
            }
            KIND_MEMBERSHIP => {
                want(65)?;
                Event::Membership {
                    channel: body[0..32].try_into().unwrap(),
                    account: PubKey::new(body[32..64].try_into().unwrap()),
                    what: body[64],
                }
            }
            KIND_PROFILE => {
                want(32)?;
                Event::Profile {
                    account: PubKey::new(body[0..32].try_into().unwrap()),
                }
            }
            KIND_ADMISSION => {
                want(0)?;
                Event::Admission
            }
            KIND_HEARTBEAT => {
                want(0)?;
                Event::Heartbeat
            }
            KIND_RESYNC => {
                want(0)?;
                Event::Resync
            }
            other => Event::Unknown(other),
        })
    }

    /// The event with its length prefix, ready to write to the stream.
    pub fn frame(&self) -> Vec<u8> {
        let body = self.encode();
        let mut out = Vec::with_capacity(LENGTH_PREFIX + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }
}

fn one(kind: u8, key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.push(kind);
    out.extend_from_slice(key);
    out
}

/// Reassembles frames from a byte stream.
///
/// This exists because HTTP/3 body chunks are not messages. h3 may hand a
/// reader two writes in one chunk or one write across two, so a client that
/// treated a chunk as an event would work perfectly until the day two events
/// were produced close enough together to be coalesced — and then silently
/// lose one. The length prefix is what makes the stream self-delimiting, and
/// this is the only thing that reads it.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
}

impl Framer {
    pub fn new() -> Framer {
        Framer::default()
    }

    /// Add a chunk and take every complete event it finished.
    ///
    /// An error here is fatal to the stream rather than to the frame: a length
    /// we will not honour means we no longer know where the next frame starts,
    /// and guessing would be worse than reconnecting.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Event>> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < LENGTH_PREFIX {
                return Ok(out);
            }
            let len = u32::from_be_bytes(self.buf[0..LENGTH_PREFIX].try_into().unwrap()) as usize;
            if len == 0 || len > MAX_FRAME {
                return Err(Error::Malformed(format!(
                    "event frame claims {len} bytes, limit is {MAX_FRAME}"
                )));
            }
            if self.buf.len() < LENGTH_PREFIX + len {
                return Ok(out);
            }
            let body: Vec<u8> = self.buf[LENGTH_PREFIX..LENGTH_PREFIX + len].to_vec();
            self.buf.drain(..LENGTH_PREFIX + len);
            out.push(Event::decode(&body)?);
        }
    }

    /// Bytes held back waiting for the rest of a frame. For tests.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PubKey {
        PubKey::new([n; 32])
    }

    #[test]
    fn every_kind_survives_a_round_trip() {
        let all = [
            Event::Channel {
                channel: [1; 32],
                last_seq: 9_001,
            },
            Event::Signal { channel: [2; 32] },
            Event::Cursor { channel: [3; 32] },
            Event::Membership {
                channel: [4; 32],
                account: key(5),
                what: MEMBER_REMOVED,
            },
            Event::Profile { account: key(6) },
            Event::Admission,
            Event::Heartbeat,
            Event::Resync,
        ];
        for e in all {
            assert_eq!(Event::decode(&e.encode()).unwrap(), e, "{e:?}");
        }
    }

    #[test]
    fn a_subscribe_survives_a_round_trip() {
        let s = Subscribe { version: VERSION };
        assert_eq!(Subscribe::decode(&s.encode()).unwrap(), s);
        assert!(Subscribe::decode(&[0x99, 1]).is_err());
        assert!(Subscribe::decode(&[TYPE_SUBSCRIBE]).is_err());
    }

    /// SIP-15's rule, inherited by SIP-19 and relied on here: a client that
    /// refused what it did not recognise would make every new kind a flag day.
    #[test]
    fn an_unknown_kind_is_ignored_rather_than_refused() {
        let got = Event::decode(&[0x7f, 1, 2, 3]).unwrap();
        assert_eq!(got, Event::Unknown(0x7f));
    }

    /// The other half of that rule. A kind we know, at a length we do not, is a
    /// broken peer — and letting it through as "something newer" would turn
    /// every truncation into a silently ignored event.
    #[test]
    fn a_known_kind_at_the_wrong_length_is_an_error() {
        assert!(Event::decode(&[KIND_CHANNEL, 0, 0]).is_err());
        assert!(Event::decode(&[KIND_HEARTBEAT, 0]).is_err());
        assert!(Event::decode(&[]).is_err());
    }

    /// The defect this type exists to prevent: two events written back to back
    /// arrive as one chunk, and a reader that took a chunk for an event would
    /// have dropped the second.
    #[test]
    fn two_events_coalesced_into_one_chunk_both_come_back() {
        let a = Event::Signal { channel: [7; 32] };
        let b = Event::Heartbeat;
        let mut both = a.frame();
        both.extend_from_slice(&b.frame());

        let mut f = Framer::new();
        assert_eq!(f.feed(&both).unwrap(), vec![a, b]);
        assert_eq!(f.pending(), 0);
    }

    /// And the mirror of it: one event split across chunk boundaries must not
    /// appear until it is whole, and must appear exactly once when it is.
    #[test]
    fn one_event_split_across_chunks_arrives_whole_and_once() {
        let e = Event::Channel {
            channel: [8; 32],
            last_seq: 42,
        };
        let bytes = e.frame();
        let mut f = Framer::new();
        // A byte at a time is the worst case and the one that finds off-by-ones.
        for (i, b) in bytes.iter().enumerate() {
            let got = f.feed(&[*b]).unwrap();
            if i + 1 == bytes.len() {
                assert_eq!(got, vec![e]);
            } else {
                assert!(got.is_empty(), "event surfaced early at byte {i}");
            }
        }
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn a_frame_longer_than_the_limit_is_refused_before_it_is_buffered() {
        let mut f = Framer::new();
        let mut wild = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        wild.push(KIND_HEARTBEAT);
        assert!(f.feed(&wild).is_err());
    }

    #[test]
    fn a_zero_length_frame_is_refused_rather_than_looped_on() {
        let mut f = Framer::new();
        assert!(f.feed(&[0, 0, 0, 0]).is_err());
    }
}
