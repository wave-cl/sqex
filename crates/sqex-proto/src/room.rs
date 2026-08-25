//! SIP-13 rooms: a roster, and nothing else.
//!
//! A room is named by a 32-byte secret. Members present the same secret and
//! learn who else is there; what they do next is not this module's business —
//! they open ordinary SIP-12 sessions with each other, which is why a room adds
//! no cryptography beyond a hash and a MAC.
//!
//! # What the exchange is not told
//!
//! The secret never leaves the members. The exchange is given only
//! `handle = SHA-256(ROOM_CONTEXT || secret)` and routes on that, so it cannot
//! join a room it carries and its state holds nothing anyone could join with.
//!
//! Each member also presents `proof = HMAC(secret, MEMBER_CONTEXT || identity)`.
//! The exchange cannot check it — it has no secret — and cannot forge one
//! either; it relays proofs unaltered and the *members* verify. That is what
//! stops an exchange adding an identity of its own to the roster and listening
//! to the room it is relaying.
//!
//! What none of this stops is someone who has been told the secret. A room
//! secret is a bearer capability with no revocation, and SIP-13's security
//! section says so rather than implying otherwise.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for deriving a room's handle from its secret.
pub const ROOM_CONTEXT: &[u8] = b"sqex-room-v1";
/// Domain separator for a member's proof that it holds the secret.
pub const MEMBER_CONTEXT: &[u8] = b"sqex-room-member-v1";

/// Most members one room may hold.
///
/// Media is a mesh of pairwise sessions, so cost grows as the square: eight
/// people is 56 relayed streams. Small on purpose.
pub const MAX_MEMBERS: usize = 8;
/// How long a membership lasts without a fresh join.
pub const TTL_SECS: u64 = 30;
/// How often a member should re-join. The same call is the heartbeat and the
/// roster poll, so there is nothing else to send.
pub const HEARTBEAT_SECS: u64 = 2;

pub const TYPE_JOIN: u8 = 0x01;
pub const TYPE_LEAVE: u8 = 0x02;

type HmacSha256 = Hmac<Sha256>;

/// A room's secret: the thing that being in the room consists of knowing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RoomId([u8; 32]);

impl RoomId {
    pub fn new(bytes: [u8; 32]) -> RoomId {
        RoomId(bytes)
    }

    /// Mint a room. Uniformly random and not derived from anything — a room
    /// secret is never a name someone chose.
    pub fn generate() -> RoomId {
        use rand_core::RngCore;
        let mut b = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut b);
        RoomId(b)
    }

    /// What the exchange is told instead of the secret.
    pub fn handle(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ROOM_CONTEXT);
        h.update(self.0);
        h.finalize().into()
    }

    /// This member's proof that it holds the secret, bound to its identity so
    /// it cannot be replayed under another name.
    pub fn proof(&self, identity: &PubKey) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("hmac takes any key length");
        mac.update(MEMBER_CONTEXT);
        mac.update(identity.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Whether `proof` is this room's proof for `identity`.
    ///
    /// Constant time: a member checks this against everyone in the roster, and
    /// leaking how far a comparison got would leak the secret one byte at a
    /// time.
    pub fn verify(&self, identity: &PubKey, proof: &[u8; 32]) -> bool {
        squic::mac::ct_eq(&self.proof(identity), proof)
    }
}

/// Deliberately not `Display` for the secret itself — see [`RoomId::to_base58`],
/// which a caller has to ask for.
impl std::fmt::Debug for RoomId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoomId(<secret>, handle {})", bs58::encode(self.handle()).into_string())
    }
}

impl RoomId {
    /// Render the secret for a person to copy. This is the room.
    pub fn to_base58(self) -> String {
        bs58::encode(self.0).into_string()
    }
}

impl std::str::FromStr for RoomId {
    type Err = Error;
    fn from_str(s: &str) -> Result<RoomId> {
        let raw = bs58::decode(s.trim())
            .into_vec()
            .map_err(|e| Error::Malformed(format!("room id is not base58: {e}")))?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed(format!("room id is {} bytes, want 32", raw.len())))?;
        Ok(RoomId(bytes))
    }
}

// ---- wire messages ----------------------------------------------------------

/// Join a room, or renew a membership — the same message either way.
///
/// `| type: u8 = 0x01 | handle[32] | proof[32] |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Join {
    pub handle: [u8; 32],
    pub proof: [u8; 32],
}

impl Join {
    /// Build the join a holder of `room` sends as `identity`. The secret is not
    /// among the bytes this produces, and there is no constructor that would
    /// put it there.
    pub fn new(room: &RoomId, identity: &PubKey) -> Join {
        Join {
            handle: room.handle(),
            proof: room.proof(identity),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(TYPE_JOIN);
        out.extend_from_slice(&self.handle);
        out.extend_from_slice(&self.proof);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Join> {
        if b.len() != 65 {
            return Err(Error::Malformed(format!(
                "join is {} bytes, want 65",
                b.len()
            )));
        }
        if b[0] != TYPE_JOIN {
            return Err(Error::Malformed(format!("not a join (type {:#x})", b[0])));
        }
        Ok(Join {
            handle: b[1..33].try_into().unwrap(),
            proof: b[33..65].try_into().unwrap(),
        })
    }
}

/// Leave a room. Optional — the TTL is what actually removes people, since a
/// protocol that depends on clients announcing their departure is wrong every
/// time a laptop lid closes.
///
/// `| type: u8 = 0x02 | handle[32] |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leave {
    pub handle: [u8; 32],
}

impl Leave {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_LEAVE);
        out.extend_from_slice(&self.handle);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Leave> {
        if b.len() != 33 {
            return Err(Error::Malformed(format!(
                "leave is {} bytes, want 33",
                b.len()
            )));
        }
        if b[0] != TYPE_LEAVE {
            return Err(Error::Malformed(format!("not a leave (type {:#x})", b[0])));
        }
        Ok(Leave {
            handle: b[1..33].try_into().unwrap(),
        })
    }
}

/// One other member, as the exchange relays them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    pub identity: PubKey,
    /// Relayed unaltered by the exchange, which cannot check it. The receiving
    /// member checks it with [`RoomId::verify`].
    pub proof: [u8; 32],
}

/// Who else is in the room.
///
/// `| now: u64 | count: u16 | (identity[32] proof[32]) * count |`
///
/// The caller is not in its own roster, and the entries are sorted by identity
/// so that two members comparing rosters compare the same thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    pub now: u64,
    pub members: Vec<Member>,
}

impl Roster {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.members.len() * 64);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for m in &self.members {
            out.extend_from_slice(m.identity.as_bytes());
            out.extend_from_slice(&m.proof);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Roster> {
        if b.len() < 10 {
            return Err(Error::Malformed(format!(
                "roster is {} bytes, want at least 10",
                b.len()
            )));
        }
        let now = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap()) as usize;
        if b.len() != 10 + count * 64 {
            return Err(Error::Malformed(format!(
                "roster claims {count} members but carries {} bytes",
                b.len() - 10
            )));
        }
        if count > MAX_MEMBERS {
            return Err(Error::Malformed(format!(
                "roster has {count} members, more than the {MAX_MEMBERS} a room may hold"
            )));
        }
        let mut members = Vec::with_capacity(count);
        for i in 0..count {
            let at = 10 + i * 64;
            let identity: [u8; 32] = b[at..at + 32].try_into().unwrap();
            members.push(Member {
                identity: PubKey::new(identity),
                proof: b[at + 32..at + 64].try_into().unwrap(),
            });
        }
        Ok(Roster { now, members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(b: u8) -> PubKey {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[b; 32]);
        PubKey::new(sk.verifying_key().to_bytes())
    }

    #[test]
    fn a_room_id_survives_being_written_down() {
        let room = RoomId::generate();
        let text = room.to_base58();
        assert_eq!(text.parse::<RoomId>().unwrap(), room);
        assert!(text.len() > 40, "32 bytes of base58 is not short");
    }

    #[test]
    fn a_mistyped_room_id_is_refused_rather_than_truncated() {
        assert!("not base58 at all!".parse::<RoomId>().is_err());
        assert!(bs58::encode([7u8; 31]).into_string().parse::<RoomId>().is_err());
        assert!(bs58::encode([7u8; 33]).into_string().parse::<RoomId>().is_err());
    }

    #[test]
    fn the_handle_does_not_carry_the_secret() {
        let room = RoomId::generate();
        let join = Join::new(&room, &identity(1)).encode();
        // The bytes that go to the exchange must not contain the secret. This
        // is the property the whole design rests on, so it is asserted rather
        // than assumed.
        assert!(
            !join.windows(32).any(|w| w == room.0),
            "the room secret reached the wire"
        );
        assert_ne!(room.handle(), room.0);
    }

    #[test]
    fn a_proof_verifies_only_under_its_own_room_and_its_own_name() {
        let room = RoomId::generate();
        let other = RoomId::generate();
        let me = identity(1);
        let them = identity(2);
        let proof = room.proof(&me);

        assert!(room.verify(&me, &proof));
        assert!(!room.verify(&them, &proof), "a proof is bound to an identity");
        assert!(!other.verify(&me, &proof), "and to a room");

        let mut tampered = proof;
        tampered[0] ^= 1;
        assert!(!room.verify(&me, &tampered));
    }

    #[test]
    fn two_rooms_are_different_rooms() {
        assert_ne!(RoomId::generate().handle(), RoomId::generate().handle());
    }

    #[test]
    fn join_and_leave_round_trip() {
        let room = RoomId::generate();
        let join = Join::new(&room, &identity(3));
        assert_eq!(Join::decode(&join.encode()).unwrap(), join);

        let leave = Leave { handle: room.handle() };
        assert_eq!(Leave::decode(&leave.encode()).unwrap(), leave);
    }

    #[test]
    fn a_join_that_is_the_wrong_shape_is_refused() {
        let room = RoomId::generate();
        let good = Join::new(&room, &identity(3)).encode();

        assert!(Join::decode(&good[..64]).is_err(), "short");
        assert!(Join::decode(&[good.as_slice(), &[0]].concat()).is_err(), "long");
        let mut wrong_type = good.clone();
        wrong_type[0] = TYPE_LEAVE;
        assert!(Join::decode(&wrong_type).is_err(), "a leave is not a join");
        assert!(Leave::decode(&good).is_err(), "nor the reverse");
    }

    #[test]
    fn a_roster_round_trips_and_an_empty_one_is_legal() {
        let room = RoomId::generate();
        let members: Vec<Member> = (1u8..4)
            .map(|b| Member {
                identity: identity(b),
                proof: room.proof(&identity(b)),
            })
            .collect();
        let roster = Roster { now: 1_700_000_000, members };
        assert_eq!(Roster::decode(&roster.encode()).unwrap(), roster);

        let empty = Roster { now: 1, members: vec![] };
        assert_eq!(Roster::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn a_roster_whose_count_lies_is_refused() {
        let roster = Roster {
            now: 1,
            members: vec![Member { identity: identity(1), proof: [0; 32] }],
        };
        let mut bytes = roster.encode();
        bytes[9] = 2; // claim two members, carry one
        assert!(Roster::decode(&bytes).is_err());

        bytes[9] = 200; // claim more than a room may hold
        assert!(Roster::decode(&bytes).is_err());
        assert!(Roster::decode(&[0u8; 4]).is_err(), "too short for a header");
    }
}
