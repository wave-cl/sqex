//! An operator's live view of what an exchange is doing.
//!
//! `POST /admin/tail`, authorised by a signed SIP-10 transaction, whose answer
//! never finishes — the same shape as SIP-30's `/events` and for the same
//! reason. What travels is a stream of length-prefixed [`Line`]s.
//!
//! # This is not a protocol between peers
//!
//! Nothing here crosses an exchange boundary. It is one operator watching their
//! own exchange, over information SIP-16 §What an operator still sees already
//! says that operator holds. No SIP describes it and none needs to; an exchange
//! tailing *another* exchange would be a different thing and would need one.
//!
//! # What it can and cannot show
//!
//! **No content, ever.** A SIP-30 event names a channel and a sequence number
//! and carries nothing else, and for a private channel the exchange holds no
//! plaintext it could show even if this wanted to. Every field below is a key,
//! a number, a route, or a reason.
//!
//! **It does cross every fan-out scope.** A tail watches events as they are
//! published, which is before any one recipient's view of them: channel
//! membership, SIP-30's "not to the account that caused it", SIP-21's
//! bidirectional block filter on profiles, and the admin-only scoping of
//! admission and report events. That is the disclosure, and the command says so
//! in its own help rather than only here.
//!
//! # Loss is reported
//!
//! A tail must never slow the exchange down, so a subscriber that cannot keep
//! up is dropped past rather than waited for. It is then *told*, by a
//! [`Record::Dropped`] carrying the count. SIP-12 puts the reason best: a relay
//! that silently discards is indistinguishable from one that delivers.

use crate::{Error, Result};
use sqnr_core::PubKey;

/// The version a caller asks for, refused rather than guessed at if unknown.
pub const VERSION: u8 = 1;

/// Largest line this will emit or a reader will accept.
///
/// As with SIP-30's frame limit, this is not a capacity estimate: it is the
/// bound that stops a broken or hostile exchange making a reader buffer without
/// limit while it waits for a length that never arrives.
pub const MAX_LINE: usize = 1024;

/// Bytes of the length prefix in front of every line.
pub const LENGTH_PREFIX: usize = 4;

/// Longest free text in a line — a route, a reason, an address.
pub const MAX_TEXT: usize = 128;

pub const KIND_REQUEST: u8 = 0x01;
pub const KIND_CONNECTION: u8 = 0x02;
pub const KIND_EVENT: u8 = 0x03;
pub const KIND_ADMIN: u8 = 0x04;
pub const KIND_PEER: u8 = 0x05;
pub const KIND_REFUSAL: u8 = 0x06;
pub const KIND_DROPPED: u8 = 0x07;
pub const KIND_HEARTBEAT: u8 = 0x08;

/// Which kinds a caller wants, as a bitfield, so narrowing needs no new op.
pub const WANT_REQUEST: u16 = 1 << 0;
pub const WANT_CONNECTION: u16 = 1 << 1;
pub const WANT_EVENT: u16 = 1 << 2;
pub const WANT_ADMIN: u16 = 1 << 3;
pub const WANT_PEER: u16 = 1 << 4;
pub const WANT_REFUSAL: u16 = 1 << 5;
/// Everything this version knows. A caller asking for bits beyond it gets what
/// exists rather than a refusal, so a newer client works against an older
/// exchange.
pub const WANT_ALL: u16 =
    WANT_REQUEST | WANT_CONNECTION | WANT_EVENT | WANT_ADMIN | WANT_PEER | WANT_REFUSAL;

/// `Dropped` is never filtered out. A reader that asked for a narrow view still
/// has to be told when the exchange could not keep up with it, or the view is
/// quietly wrong rather than narrow.
pub fn wanted(kinds: u16, kind: u8) -> bool {
    match kind {
        // Neither is ever filtered. A reader that narrowed its view still has
        // to be told when the exchange could not keep up with it, and still
        // has to be able to tell a quiet exchange from a dead one.
        KIND_DROPPED | KIND_HEARTBEAT => true,
        KIND_REQUEST => kinds & WANT_REQUEST != 0,
        KIND_CONNECTION => kinds & WANT_CONNECTION != 0,
        KIND_EVENT => kinds & WANT_EVENT != 0,
        KIND_ADMIN => kinds & WANT_ADMIN != 0,
        KIND_PEER => kinds & WANT_PEER != 0,
        KIND_REFUSAL => kinds & WANT_REFUSAL != 0,
        _ => false,
    }
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A route was served. `account` is absent for an anonymous connection.
    Request {
        account: Option<PubKey>,
        route: String,
        status: u16,
        micros: u32,
    },
    /// A connection arrived or ended. The numbers are the ones the journal
    /// already reports at close, available here as it happens.
    Connection {
        opened: bool,
        peer: String,
        identity: Option<PubKey>,
        rtt_ms: u32,
        lost: u64,
        bytes: u64,
    },
    /// A SIP-30 event was published to an account. `event` is that event's own
    /// kind byte; `channel` is present for the kinds that name one.
    Event {
        to: PubKey,
        event: u8,
        channel: Option<[u8; 32]>,
    },
    /// A signed admin op was applied.
    Admin { admin: PubKey, action: String },
    /// Something crossed the exchange-to-exchange wire.
    Peer { peer: PubKey, what: String },
    /// A caller was refused: a rate limit, a whitelist drop, a malformed body.
    Refusal {
        account: Option<PubKey>,
        route: String,
        why: String,
    },
    /// This reader fell behind and lines were discarded rather than queued.
    Dropped { records: u64 },
    /// Nothing has happened for a while. A quiet exchange and a dead one look
    /// identical over a QUIC connection that outlives the application, and the
    /// transport's idle timeout is 60 s — so silence is broken on a timer, as
    /// SIP-30's stream does for the same reason.
    Heartbeat,
}

impl Record {
    pub fn kind(&self) -> u8 {
        match self {
            Record::Request { .. } => KIND_REQUEST,
            Record::Connection { .. } => KIND_CONNECTION,
            Record::Event { .. } => KIND_EVENT,
            Record::Admin { .. } => KIND_ADMIN,
            Record::Peer { .. } => KIND_PEER,
            Record::Refusal { .. } => KIND_REFUSAL,
            Record::Dropped { .. } => KIND_DROPPED,
            Record::Heartbeat => KIND_HEARTBEAT,
        }
    }
}

/// One line of the tail: when, in what order, and what.
///
/// `seq` counts lines the exchange produced for this reader, so a gap is
/// impossible by construction — loss is said outright with [`Record::Dropped`]
/// rather than left to be inferred from a hole, which is SIP-14's lesson about
/// telling silence from loss applied to a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub at: u64,
    pub seq: u64,
    pub record: Record,
}

fn put_text(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(MAX_TEXT);
    out.push(n as u8);
    out.extend_from_slice(&b[..n]);
}

fn take_text(b: &[u8], at: &mut usize) -> Result<String> {
    let n = *b.get(*at).ok_or_else(|| short("text length"))? as usize;
    *at += 1;
    if n > MAX_TEXT {
        return Err(Error::Malformed(format!(
            "tail text is {n} bytes, limit is {MAX_TEXT}"
        )));
    }
    let end = *at + n;
    let s = b.get(*at..end).ok_or_else(|| short("text"))?;
    *at = end;
    Ok(String::from_utf8_lossy(s).into_owned())
}

fn put_key(out: &mut Vec<u8>, k: &Option<PubKey>) {
    match k {
        Some(k) => {
            out.push(1);
            out.extend_from_slice(k.as_bytes());
        }
        None => out.push(0),
    }
}

fn take_key(b: &[u8], at: &mut usize) -> Result<Option<PubKey>> {
    let present = *b.get(*at).ok_or_else(|| short("key flag"))?;
    *at += 1;
    match present {
        0 => Ok(None),
        1 => {
            let end = *at + 32;
            let s = b.get(*at..end).ok_or_else(|| short("key"))?;
            *at = end;
            Ok(Some(PubKey::new(s.try_into().unwrap())))
        }
        other => Err(Error::Malformed(format!(
            "tail key flag is {other}, want 0 or 1"
        ))),
    }
}

fn take_u64(b: &[u8], at: &mut usize) -> Result<u64> {
    let end = *at + 8;
    let s = b.get(*at..end).ok_or_else(|| short("u64"))?;
    *at = end;
    Ok(u64::from_be_bytes(s.try_into().unwrap()))
}

fn take_u32(b: &[u8], at: &mut usize) -> Result<u32> {
    let end = *at + 4;
    let s = b.get(*at..end).ok_or_else(|| short("u32"))?;
    *at = end;
    Ok(u32::from_be_bytes(s.try_into().unwrap()))
}

fn take_u16(b: &[u8], at: &mut usize) -> Result<u16> {
    let end = *at + 2;
    let s = b.get(*at..end).ok_or_else(|| short("u16"))?;
    *at = end;
    Ok(u16::from_be_bytes(s.try_into().unwrap()))
}

fn short(what: &str) -> Error {
    Error::Malformed(format!("tail line cut short reading {what}"))
}

impl Line {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(self.record.kind());
        out.extend_from_slice(&self.at.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        match &self.record {
            Record::Request {
                account,
                route,
                status,
                micros,
            } => {
                put_key(&mut out, account);
                put_text(&mut out, route);
                out.extend_from_slice(&status.to_be_bytes());
                out.extend_from_slice(&micros.to_be_bytes());
            }
            Record::Connection {
                opened,
                peer,
                identity,
                rtt_ms,
                lost,
                bytes,
            } => {
                out.push(u8::from(*opened));
                put_text(&mut out, peer);
                put_key(&mut out, identity);
                out.extend_from_slice(&rtt_ms.to_be_bytes());
                out.extend_from_slice(&lost.to_be_bytes());
                out.extend_from_slice(&bytes.to_be_bytes());
            }
            Record::Event { to, event, channel } => {
                out.extend_from_slice(to.as_bytes());
                out.push(*event);
                match channel {
                    Some(c) => {
                        out.push(1);
                        out.extend_from_slice(c);
                    }
                    None => out.push(0),
                }
            }
            Record::Admin { admin, action } => {
                out.extend_from_slice(admin.as_bytes());
                put_text(&mut out, action);
            }
            Record::Peer { peer, what } => {
                out.extend_from_slice(peer.as_bytes());
                put_text(&mut out, what);
            }
            Record::Refusal {
                account,
                route,
                why,
            } => {
                put_key(&mut out, account);
                put_text(&mut out, route);
                put_text(&mut out, why);
            }
            Record::Dropped { records } => out.extend_from_slice(&records.to_be_bytes()),
            Record::Heartbeat => {}
        }
        out
    }

    /// The length-prefixed form that goes on the wire. The prefix counts the
    /// body only, as SIP-30's does.
    pub fn frame(&self) -> Vec<u8> {
        let body = self.encode();
        let mut out = Vec::with_capacity(LENGTH_PREFIX + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Line> {
        let kind = *b.first().ok_or_else(|| short("kind"))?;
        let mut at = 1usize;
        let when = take_u64(b, &mut at)?;
        let seq = take_u64(b, &mut at)?;
        let record = match kind {
            KIND_REQUEST => Record::Request {
                account: take_key(b, &mut at)?,
                route: take_text(b, &mut at)?,
                status: take_u16(b, &mut at)?,
                micros: take_u32(b, &mut at)?,
            },
            KIND_CONNECTION => {
                let opened = *b.get(at).ok_or_else(|| short("opened"))? != 0;
                at += 1;
                Record::Connection {
                    opened,
                    peer: take_text(b, &mut at)?,
                    identity: take_key(b, &mut at)?,
                    rtt_ms: take_u32(b, &mut at)?,
                    lost: take_u64(b, &mut at)?,
                    bytes: take_u64(b, &mut at)?,
                }
            }
            KIND_EVENT => {
                let to = b.get(at..at + 32).ok_or_else(|| short("event account"))?;
                at += 32;
                let event = *b.get(at).ok_or_else(|| short("event kind"))?;
                at += 1;
                let present = *b.get(at).ok_or_else(|| short("channel flag"))?;
                at += 1;
                let channel = match present {
                    0 => None,
                    1 => {
                        let c = b.get(at..at + 32).ok_or_else(|| short("channel"))?;
                        at += 32;
                        Some(<[u8; 32]>::try_from(c).unwrap())
                    }
                    other => {
                        return Err(Error::Malformed(format!(
                            "tail channel flag is {other}, want 0 or 1"
                        )));
                    }
                };
                Record::Event {
                    to: PubKey::new(to.try_into().unwrap()),
                    event,
                    channel,
                }
            }
            KIND_ADMIN => {
                let admin = b.get(at..at + 32).ok_or_else(|| short("admin key"))?;
                at += 32;
                Record::Admin {
                    admin: PubKey::new(admin.try_into().unwrap()),
                    action: take_text(b, &mut at)?,
                }
            }
            KIND_PEER => {
                let peer = b.get(at..at + 32).ok_or_else(|| short("peer key"))?;
                at += 32;
                Record::Peer {
                    peer: PubKey::new(peer.try_into().unwrap()),
                    what: take_text(b, &mut at)?,
                }
            }
            KIND_REFUSAL => Record::Refusal {
                account: take_key(b, &mut at)?,
                route: take_text(b, &mut at)?,
                why: take_text(b, &mut at)?,
            },
            KIND_DROPPED => Record::Dropped {
                records: take_u64(b, &mut at)?,
            },
            KIND_HEARTBEAT => Record::Heartbeat,
            // Unlike a SIP-30 event, an unknown kind is an error rather than
            // something to ignore. A tail is one operator reading one exchange
            // they deployed: the two halves ship together, and a line nobody
            // can read is a bug to surface rather than a forward-compatible
            // extension to skip.
            other => {
                return Err(Error::Malformed(format!("unknown tail kind {other:#x}")));
            }
        };
        // Every line consumes its body exactly; trailing bytes mean the two
        // sides disagree about the shape, which is worse than a short read.
        if at != b.len() {
            return Err(Error::Malformed(format!(
                "tail line has {} trailing byte(s)",
                b.len() - at
            )));
        }
        Ok(Line {
            at: when,
            seq,
            record,
        })
    }
}

/// Reassembles lines from a byte stream, for the same reason SIP-30 needs one:
/// HTTP/3 body chunks are not messages, so a reader that treated a chunk as a
/// line would work until two lines were coalesced and then silently lose one.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
}

impl Framer {
    pub fn new() -> Framer {
        Framer::default()
    }

    /// Add a chunk and take every complete line it finished. An error is fatal
    /// to the stream rather than to the line: a length we will not honour means
    /// we no longer know where the next one starts.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Line>> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < LENGTH_PREFIX {
                return Ok(out);
            }
            let len = u32::from_be_bytes(self.buf[0..LENGTH_PREFIX].try_into().unwrap()) as usize;
            if len == 0 || len > MAX_LINE {
                return Err(Error::Malformed(format!(
                    "tail line claims {len} bytes, limit is {MAX_LINE}"
                )));
            }
            if self.buf.len() < LENGTH_PREFIX + len {
                return Ok(out);
            }
            let body: Vec<u8> = self.buf[LENGTH_PREFIX..LENGTH_PREFIX + len].to_vec();
            self.buf.drain(..LENGTH_PREFIX + len);
            out.push(Line::decode(&body)?);
        }
    }

    /// Bytes held back waiting for the rest of a line. For tests.
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

    /// One of every kind, so a variant added without an encoding is caught
    /// here rather than at runtime. `Op`'s own round-trip list is hand-kept and
    /// is already missing six variants; this one is checked against `kind()`
    /// below so it cannot drift the same way.
    fn all() -> Vec<Record> {
        vec![
            Record::Request {
                account: Some(key(1)),
                route: "/channel/post".into(),
                status: 200,
                micros: 1234,
            },
            Record::Request {
                account: None,
                route: "/status".into(),
                status: 200,
                micros: 7,
            },
            Record::Connection {
                opened: true,
                peer: "[::ffff:10.0.0.1]:51234".into(),
                identity: Some(key(2)),
                rtt_ms: 36,
                lost: 0,
                bytes: 4096,
            },
            Record::Connection {
                opened: false,
                peer: "10.0.0.2:1".into(),
                identity: None,
                rtt_ms: 0,
                lost: 9,
                bytes: 0,
            },
            Record::Event {
                to: key(3),
                event: 0x01,
                channel: Some([7u8; 32]),
            },
            Record::Event {
                to: key(3),
                event: 0x07,
                channel: None,
            },
            Record::Admin {
                admin: key(4),
                action: "whitelist-add".into(),
            },
            Record::Peer {
                peer: key(5),
                what: "pull".into(),
            },
            Record::Refusal {
                account: Some(key(6)),
                route: "/channel/post".into(),
                why: "rate limited".into(),
            },
            Record::Dropped { records: 12 },
            Record::Heartbeat,
        ]
    }

    #[test]
    fn every_record_round_trips() {
        for (i, record) in all().into_iter().enumerate() {
            let line = Line {
                at: 1_700_000_000 + i as u64,
                seq: i as u64,
                record,
            };
            let back = Line::decode(&line.encode()).expect("decodes");
            assert_eq!(back, line, "round trip failed for {line:?}");
        }
    }

    /// The list above must cover every kind. Without this, adding a variant and
    /// forgetting the fixture leaves it unencoded and untested — the exact way
    /// `Op`'s list drifted.
    #[test]
    fn the_fixture_covers_every_kind() {
        let mut kinds: Vec<u8> = all().iter().map(|r| r.kind()).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(
            kinds,
            vec![
                KIND_REQUEST,
                KIND_CONNECTION,
                KIND_EVENT,
                KIND_ADMIN,
                KIND_PEER,
                KIND_REFUSAL,
                KIND_DROPPED,
                KIND_HEARTBEAT
            ]
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let line = Line {
            at: 1,
            seq: 2,
            record: Record::Dropped { records: 3 },
        };
        let mut b = line.encode();
        b.push(0);
        assert!(Line::decode(&b).is_err(), "trailing bytes were accepted");
    }

    #[test]
    fn an_unknown_kind_is_an_error_not_a_skip() {
        let b = vec![0xfe, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2];
        assert!(Line::decode(&b).is_err());
    }

    #[test]
    fn text_longer_than_the_cap_is_truncated_rather_than_refused() {
        // A route or a reason is diagnostic, so a long one is worth shortening
        // and not worth dropping the line for.
        let line = Line {
            at: 1,
            seq: 1,
            record: Record::Refusal {
                account: None,
                route: "x".repeat(MAX_TEXT + 50),
                why: "y".into(),
            },
        };
        let back = Line::decode(&line.encode()).expect("decodes");
        match back.record {
            Record::Refusal { route, .. } => assert_eq!(route.len(), MAX_TEXT),
            other => panic!("wrong record: {other:?}"),
        }
    }

    /// A reader that narrowed its view must still be told it fell behind, or
    /// the view is quietly wrong rather than narrow.
    #[test]
    fn dropped_is_never_filtered_out() {
        assert!(wanted(0, KIND_DROPPED));
        assert!(wanted(0, KIND_HEARTBEAT));
        assert!(!wanted(0, KIND_REQUEST));
        assert!(wanted(WANT_REQUEST, KIND_REQUEST));
        assert!(!wanted(WANT_REQUEST, KIND_EVENT));
        assert!(wanted(WANT_ALL, KIND_EVENT));
    }

    #[test]
    fn the_framer_reassembles_a_split_line() {
        let line = Line {
            at: 9,
            seq: 1,
            record: Record::Dropped { records: 1 },
        };
        let framed = line.frame();
        let mut f = Framer::new();
        let (a, b) = framed.split_at(3);
        assert!(f.feed(a).unwrap().is_empty());
        assert!(f.pending() > 0);
        assert_eq!(f.feed(b).unwrap(), vec![line]);
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn the_framer_refuses_an_impossible_length() {
        let mut f = Framer::new();
        let mut b = (MAX_LINE as u32 + 1).to_be_bytes().to_vec();
        b.push(0);
        assert!(f.feed(&b).is_err());
    }
}
