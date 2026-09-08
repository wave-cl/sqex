//! SIP-39 cross-exchange calls: what one exchange says to another to bridge a
//! live session between their two users.
//!
//! A SIP-12 session joins two identities connected to the *same* exchange. This
//! module carries the same session across a **relay link** between two
//! exchanges, so `alice@squic.org` and `bob@indra.org` can call each other while
//! each stays connected only to their own home exchange. The link is one
//! long-lived sQUIC connection, brought up like a SIP-35 replica link — mutual
//! SIP-9 authentication, the peer key pinned from discovery and checked against
//! an operator allowlist, never taken from the wire — and gated the same way:
//! an exchange bridges only to peers its operator named.
//!
//! # What crosses the link
//!
//! Control travels as length-prefixed [`Control`] frames on a bidirectional
//! QUIC stream either exchange may write to (a ring is answered seconds later
//! and by the far side, so request/response does not fit). Media travels as
//! [`RelayData`] QUIC datagrams on the same connection. Both are keyed by a
//! 16-byte **bridge** id the initiating exchange chooses, by which the two
//! exchanges refer to the one bridged session.
//!
//! # The exchange still cannot read the call
//!
//! Nothing here touches the ciphertext. SIP-12's key agreement mixes the two
//! parties' static identity keys and their ephemerals; a relay — one exchange
//! or two — sees only public keys and sealed frames. A two-exchange path is a
//! longer courier chain, and the couriers are still excluded. `RelayData`
//! carries the peer's own `seq` and ciphertext untouched; only the local
//! `session_id`, which is not in the frame nonce, is restamped at each end.

use sqnr_core::{Error, PubKey, Result};

/// ALPN for the relay link, distinct from the exchange's `h3` so the accepting
/// side can tell a peering connection from a client one and dispatch it to the
/// relay protocol rather than HTTP/3.
pub const ALPN: &[u8] = b"sqex-relay";

/// The relay protocol version this build speaks.
pub const VERSION: u8 = 1;

/// A bridge identifier: 16 random bytes the initiating exchange chooses, unique
/// on the link for the life of the bridged session.
pub type Bridge = [u8; 16];

/// Bytes of a bridge id.
pub const BRIDGE_LEN: usize = 16;

pub const TYPE_INVITE: u8 = 0x01;
pub const TYPE_RINGING: u8 = 0x02;
pub const TYPE_REJECT: u8 = 0x03;
pub const TYPE_ACCEPT: u8 = 0x04;
pub const TYPE_CLOSE: u8 = 0x05;

/// Why a bridged call did not connect (`Reject`) or ended (`Close`).
///
/// Deliberately coarse. The callee's exchange owes an allowlisted peer that a
/// call did not connect, and no more: a finer answer would make the link a
/// presence oracle, the leak SIP-24's door and SIP-4's beacon both refuse.
pub const REASON_NO_ACCOUNT: u8 = 0;
pub const REASON_UNREACHABLE: u8 = 1;
pub const REASON_DECLINED: u8 = 2;
pub const REASON_BUSY: u8 = 3;
pub const REASON_REFUSED: u8 = 4;
pub const REASON_ENDED: u8 = 5;

/// Longest a control frame may be, decoded off the stream. An `Invite` carries
/// three keys and a domain label; this is comfortably more and bounds a broken
/// or hostile peer's length prefix.
pub const MAX_CONTROL: usize = 512;

/// Bytes of length prefix ahead of every control frame on the stream.
pub const LENGTH_PREFIX: usize = 4;

/// Longest a caller domain may be in an `Invite`. A domain is display and
/// provenance only; routing uses the link the frame arrived on.
pub const MAX_DOMAIN: usize = 253;

/// One control message on the relay link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// X → Y: `caller` on X's domain wishes to open a session with `account`,
    /// offering `caller_eph`. `caller_domain` is X's domain, carried for display
    /// and provenance; Y routes on the link the invite arrived on, never on the
    /// string.
    Invite {
        bridge: Bridge,
        caller: PubKey,
        caller_eph: [u8; 32],
        account: PubKey,
        caller_domain: String,
    },
    /// Y → X: `account`'s devices are ringing.
    Ringing { bridge: Bridge },
    /// Y → X: the call did not connect, for `reason`.
    Reject { bridge: Bridge, reason: u8 },
    /// Y → X: device `callee` answered, offering `callee_eph`.
    Accept {
        bridge: Bridge,
        callee: PubKey,
        callee_eph: [u8; 32],
    },
    /// Either → the other: the bridged session is torn down, for `reason`.
    Close { bridge: Bridge, reason: u8 },
}

impl Control {
    fn bridge_of(b: &[u8]) -> Result<Bridge> {
        b.get(1..1 + BRIDGE_LEN)
            .ok_or_else(|| Error::Malformed("relay control frame truncated".into()))?
            .try_into()
            .map_err(|_| Error::Malformed("bad bridge id".into()))
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Control::Invite {
                bridge,
                caller,
                caller_eph,
                account,
                caller_domain,
            } => {
                let dom = caller_domain.as_bytes();
                let mut out = Vec::with_capacity(1 + BRIDGE_LEN + 32 + 32 + 32 + 1 + dom.len());
                out.push(TYPE_INVITE);
                out.extend_from_slice(bridge);
                out.extend_from_slice(caller.as_bytes());
                out.extend_from_slice(caller_eph);
                out.extend_from_slice(account.as_bytes());
                out.push(dom.len() as u8);
                out.extend_from_slice(dom);
                out
            }
            Control::Ringing { bridge } => {
                let mut out = Vec::with_capacity(1 + BRIDGE_LEN);
                out.push(TYPE_RINGING);
                out.extend_from_slice(bridge);
                out
            }
            Control::Reject { bridge, reason } => {
                let mut out = Vec::with_capacity(1 + BRIDGE_LEN + 1);
                out.push(TYPE_REJECT);
                out.extend_from_slice(bridge);
                out.push(*reason);
                out
            }
            Control::Accept {
                bridge,
                callee,
                callee_eph,
            } => {
                let mut out = Vec::with_capacity(1 + BRIDGE_LEN + 32 + 32);
                out.push(TYPE_ACCEPT);
                out.extend_from_slice(bridge);
                out.extend_from_slice(callee.as_bytes());
                out.extend_from_slice(callee_eph);
                out
            }
            Control::Close { bridge, reason } => {
                let mut out = Vec::with_capacity(1 + BRIDGE_LEN + 1);
                out.push(TYPE_CLOSE);
                out.extend_from_slice(bridge);
                out.push(*reason);
                out
            }
        }
    }

    pub fn decode(b: &[u8]) -> Result<Control> {
        let Some(&kind) = b.first() else {
            return Err(Error::Malformed("empty relay control frame".into()));
        };
        let bridge = Self::bridge_of(b)?;
        let rest = &b[1 + BRIDGE_LEN..];
        Ok(match kind {
            TYPE_INVITE => {
                // caller[32] | caller_eph[32] | account[32] | dom_len | domain
                if rest.len() < 32 + 32 + 32 + 1 {
                    return Err(Error::Malformed("invite truncated".into()));
                }
                let caller = PubKey::new(rest[0..32].try_into().unwrap());
                let caller_eph: [u8; 32] = rest[32..64].try_into().unwrap();
                let account = PubKey::new(rest[64..96].try_into().unwrap());
                let dom_len = rest[96] as usize;
                let dom = &rest[97..];
                if dom.len() != dom_len {
                    return Err(Error::Malformed(format!(
                        "invite domain is {} bytes, header says {dom_len}",
                        dom.len()
                    )));
                }
                let caller_domain = String::from_utf8(dom.to_vec())
                    .map_err(|_| Error::Malformed("invite domain is not UTF-8".into()))?;
                Control::Invite {
                    bridge,
                    caller,
                    caller_eph,
                    account,
                    caller_domain,
                }
            }
            TYPE_RINGING => {
                if !rest.is_empty() {
                    return Err(Error::Malformed("ringing has a trailing body".into()));
                }
                Control::Ringing { bridge }
            }
            TYPE_REJECT => {
                if rest.len() != 1 {
                    return Err(Error::Malformed("reject wants one reason byte".into()));
                }
                Control::Reject {
                    bridge,
                    reason: rest[0],
                }
            }
            TYPE_ACCEPT => {
                if rest.len() != 64 {
                    return Err(Error::Malformed("accept wants callee[32] eph[32]".into()));
                }
                Control::Accept {
                    bridge,
                    callee: PubKey::new(rest[0..32].try_into().unwrap()),
                    callee_eph: rest[32..64].try_into().unwrap(),
                }
            }
            TYPE_CLOSE => {
                if rest.len() != 1 {
                    return Err(Error::Malformed("close wants one reason byte".into()));
                }
                Control::Close {
                    bridge,
                    reason: rest[0],
                }
            }
            other => {
                return Err(Error::Malformed(format!(
                    "unknown relay control {other:#x}"
                )));
            }
        })
    }

    /// The frame with its length prefix, ready to write to the control stream.
    pub fn frame(&self) -> Vec<u8> {
        let body = self.encode();
        let mut out = Vec::with_capacity(LENGTH_PREFIX + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }
}

/// A media datagram on the relay link: the peer's own SIP-12 frame, tagged with
/// the bridge it belongs to. `seq` and `ciphertext` are the parties' own and
/// cross both exchanges untouched; each exchange restamps only the local
/// `session_id` when it re-emits an ordinary [`crate::session::DatagramFrame`]
/// toward its own party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayData {
    pub bridge: Bridge,
    pub seq: u64,
    pub ciphertext: Vec<u8>,
}

impl RelayData {
    /// Bytes of header before the ciphertext.
    pub const HEADER: usize = BRIDGE_LEN + 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER + self.ciphertext.len());
        out.extend_from_slice(&self.bridge);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(b: &[u8]) -> Result<RelayData> {
        if b.len() < Self::HEADER {
            return Err(Error::Malformed(format!(
                "relay datagram is {} bytes, want >= {}",
                b.len(),
                Self::HEADER
            )));
        }
        Ok(RelayData {
            bridge: b[0..BRIDGE_LEN].try_into().unwrap(),
            seq: u64::from_be_bytes(b[BRIDGE_LEN..BRIDGE_LEN + 8].try_into().unwrap()),
            ciphertext: b[Self::HEADER..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> PubKey {
        PubKey::new([n; 32])
    }

    #[test]
    fn control_round_trips() {
        let msgs = vec![
            Control::Invite {
                bridge: [7u8; 16],
                caller: k(1),
                caller_eph: [2u8; 32],
                account: k(3),
                caller_domain: "squic.org".into(),
            },
            Control::Ringing { bridge: [7u8; 16] },
            Control::Reject {
                bridge: [7u8; 16],
                reason: REASON_DECLINED,
            },
            Control::Accept {
                bridge: [7u8; 16],
                callee: k(4),
                callee_eph: [5u8; 32],
            },
            Control::Close {
                bridge: [7u8; 16],
                reason: REASON_ENDED,
            },
        ];
        for m in msgs {
            let bytes = m.encode();
            assert_eq!(Control::decode(&bytes).unwrap(), m);
            // Framed form carries a correct length prefix.
            let f = m.frame();
            let len = u32::from_be_bytes(f[0..4].try_into().unwrap()) as usize;
            assert_eq!(len, bytes.len());
            assert_eq!(&f[4..], &bytes[..]);
        }
    }

    #[test]
    fn invite_domain_length_is_checked() {
        let mut bytes = Control::Invite {
            bridge: [0u8; 16],
            caller: k(1),
            caller_eph: [0u8; 32],
            account: k(2),
            caller_domain: "a.example".into(),
        }
        .encode();
        // Corrupt the declared domain length; decode must refuse, not panic.
        *bytes.last_mut().unwrap() = b'x';
        let n = bytes.len();
        bytes[n - 2] = 200; // dom_len far past the actual bytes
        assert!(Control::decode(&bytes).is_err());
    }

    #[test]
    fn relay_data_preserves_seq_and_ciphertext() {
        let d = RelayData {
            bridge: [9u8; 16],
            seq: 0x0102030405060708,
            ciphertext: vec![0xaa, 0xbb, 0xcc],
        };
        let got = RelayData::decode(&d.encode()).unwrap();
        assert_eq!(got, d);
    }

    #[test]
    fn decoders_reject_garbage_without_panicking() {
        for len in 0..40usize {
            let junk = vec![0xffu8; len];
            let _ = Control::decode(&junk);
            let _ = RelayData::decode(&junk);
        }
    }
}
