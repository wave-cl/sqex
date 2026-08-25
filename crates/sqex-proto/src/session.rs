//! Relayed sessions: two identities exchange data *through* the exchange.
//!
//! Neither peer need be reachable. Both already hold a working connection to the
//! exchange — that is how they got here — so the exchange carries the session
//! rather than trying to introduce the two directly. That works where hole
//! punching does not: behind symmetric NAT, behind a firewall that allows only
//! outbound, and without either peer running a listener.
//!
//! # The exchange must not be able to read the session
//!
//! Carrying the bytes puts the exchange in the middle, including in the middle
//! of the key agreement — so simply swapping ephemeral keys would let it
//! impersonate each peer to the other. The agreement therefore combines **three**
//! Diffie–Hellman terms, in the manner of X3DH:
//!
//! ```text
//! DH1 = X25519(eph_first,    static_second)
//! DH2 = X25519(static_first, eph_second)
//! DH3 = X25519(eph_first,    eph_second)
//! key = SHA-512(SESSION_CONTEXT || first || second || DH1 || DH2 || DH3)[0..32]
//! ```
//!
//! - **The exchange cannot compute it.** DH1 and DH2 each require a *static*
//!   private key, which only the peers hold. Substituting its own ephemerals
//!   gets it nothing, because it still cannot complete either static term. So
//!   there is no man in this middle, despite the middle being the whole design.
//! - **Mutual authentication** comes free from those same two terms: deriving
//!   the key at all proves possession of the identity key each peer is named by.
//!   No signature is needed, which keeps this in line with SIP-4 and SIP-5 —
//!   the connection and the keys do the work.
//! - **Forward secrecy** comes from DH3: if *both* long-term identity keys leak
//!   later, DH3 still needs an ephemeral secret, and those are discarded when
//!   the session ends.
//!
//! `first` and `second` are the two identities in lexicographic order, so both
//! ends derive the same key without needing to agree on who started.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha512};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for the session key agreement.
pub const SESSION_CONTEXT: &[u8] = b"sqex-session-v1";

/// Largest plaintext one frame may carry.
pub const MAX_FRAME: usize = 32 * 1024;
/// Most bytes that may be queued in one direction awaiting collection.
pub const MAX_QUEUED_BYTES: usize = 1024 * 1024;
/// Most frames that may be queued in one direction.
pub const MAX_QUEUED_FRAMES: usize = 256;
/// How long a session, or an unmatched request to open one, is kept.
pub const TTL_SECS: u64 = 60 * 60;

pub const TYPE_OPEN: u8 = 0x01;
pub const TYPE_SEND: u8 = 0x02;
pub const TYPE_RECV: u8 = 0x03;
pub const TYPE_CLOSE: u8 = 0x04;

/// Which end of the session a peer is, fixed by lexicographic order of the two
/// identities so that both ends agree without negotiating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    First,
    Second,
}

impl Role {
    /// The role `me` plays in a session with `peer`.
    pub fn of(me: &PubKey, peer: &PubKey) -> Role {
        if me.as_bytes() <= peer.as_bytes() {
            Role::First
        } else {
            Role::Second
        }
    }

    /// The direction byte used to separate the two streams' nonces.
    fn direction(self) -> u8 {
        match self {
            Role::First => 0,
            Role::Second => 1,
        }
    }

    fn other(self) -> Role {
        match self {
            Role::First => Role::Second,
            Role::Second => Role::First,
        }
    }
}

/// A derived session key, and the role that keys its framing.
pub struct Session {
    key: [u8; 32],
    role: Role,
}

impl Session {
    /// Derive the shared session key.
    ///
    /// `my_seed` is this peer's Ed25519 seed, `my_ephemeral_secret` the
    /// ephemeral it contributed, `peer` the other identity, and
    /// `peer_ephemeral` what the exchange relayed back from them.
    pub fn derive(
        my_seed: &[u8; 32],
        my_ephemeral_secret: &x25519_dalek::StaticSecret,
        peer: &PubKey,
        peer_ephemeral: &[u8; 32],
    ) -> Result<Session> {
        let my_signing = ed25519_dalek::SigningKey::from_bytes(my_seed);
        let me = PubKey::new(my_signing.verifying_key().to_bytes());
        let my_static = squic::crypto::ed25519_private_to_x25519(&my_signing);
        let peer_static = squic::crypto::ed25519_identity_to_x25519(peer.as_bytes())
            .map_err(|e| Error::Key(format!("peer identity: {e}")))?;
        let peer_eph = x25519_dalek::PublicKey::from(*peer_ephemeral);
        let my_eph_pub = x25519_dalek::PublicKey::from(my_ephemeral_secret);

        let role = Role::of(&me, peer);

        // DH1 pairs the FIRST peer's ephemeral with the SECOND's static; DH2 the
        // other way about. Which of those this peer can compute directly depends
        // on its role, but the two values are the same on both ends.
        let (dh1, dh2) = match role {
            Role::First => (
                squic::crypto::x25519(my_ephemeral_secret, &peer_static),
                squic::crypto::x25519(&my_static, &peer_eph),
            ),
            Role::Second => (
                squic::crypto::x25519(&my_static, &peer_eph),
                squic::crypto::x25519(my_ephemeral_secret, &peer_static),
            ),
        };
        let dh1 = dh1.map_err(|e| Error::Key(format!("session DH1: {e}")))?;
        let dh2 = dh2.map_err(|e| Error::Key(format!("session DH2: {e}")))?;
        let dh3 = squic::crypto::x25519(my_ephemeral_secret, &peer_eph)
            .map_err(|e| Error::Key(format!("session DH3: {e}")))?;

        let (first, second) = match role {
            Role::First => (me, *peer),
            Role::Second => (*peer, me),
        };
        // Bind the ephemerals into the transcript too, so a relayed swap changes
        // the key rather than going unnoticed.
        let (eph_first, eph_second) = match role {
            Role::First => (my_eph_pub.to_bytes(), *peer_ephemeral),
            Role::Second => (*peer_ephemeral, my_eph_pub.to_bytes()),
        };

        let mut h = Sha512::new();
        h.update(SESSION_CONTEXT);
        h.update(first.as_bytes());
        h.update(second.as_bytes());
        h.update(eph_first);
        h.update(eph_second);
        h.update(dh1);
        h.update(dh2);
        h.update(dh3);
        let okm = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[..32]);

        Ok(Session { key, role })
    }

    /// Nonce for a frame: the sender's direction, then the frame's sequence
    /// number. Each direction counts separately, so neither can force the other
    /// to reuse a nonce.
    fn nonce(direction: u8, seq: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = direction;
        n[1..9].copy_from_slice(&seq.to_be_bytes());
        n
    }

    fn cipher(&self) -> Result<ChaCha20Poly1305> {
        ChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| Error::Key(format!("cipher: {e}")))
    }

    /// Seal one outgoing frame.
    pub fn seal(&self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_FRAME {
            return Err(Error::Malformed(format!(
                "frame is {} bytes, limit is {MAX_FRAME}",
                plaintext.len()
            )));
        }
        let nonce = Self::nonce(self.role.direction(), seq);
        self.cipher()?
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| Error::Key(format!("seal frame: {e}")))
    }

    /// Open one incoming frame — sealed by the peer, so keyed on *their*
    /// direction.
    pub fn open(&self, seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce(self.role.other().direction(), seq);
        self.cipher()?
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| Error::Key("cannot open frame: wrong key, or altered".into()))
    }

    pub fn role(&self) -> Role {
        self.role
    }
}

// ---- wire messages ----------------------------------------------------------

/// Ask to open a session with `peer`, offering an ephemeral public key.
/// `| type=0x01 | peer[32] | ephemeral[32] |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open {
    pub peer: PubKey,
    pub ephemeral: [u8; 32],
}

impl Open {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(TYPE_OPEN);
        out.extend_from_slice(self.peer.as_bytes());
        out.extend_from_slice(&self.ephemeral);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Open> {
        if b.len() != 65 {
            return Err(Error::Malformed(format!("open is {} bytes, want 65", b.len())));
        }
        if b[0] != TYPE_OPEN {
            return Err(Error::Malformed(format!("not an open (type {:#x})", b[0])));
        }
        Ok(Open {
            peer: PubKey::new(b[1..33].try_into().unwrap()),
            ephemeral: b[33..65].try_into().unwrap(),
        })
    }
}

/// Whether the other side has asked too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenState {
    /// Recorded; the peer has not asked for a session with you. Nothing about
    /// them is disclosed — not even that they exist.
    Waiting = 0,
    /// Both asked: here is their ephemeral, and the session is live.
    Established = 1,
}

/// The exchange's answer to an open.
/// `| state | session_id: u64 | peer_ephemeral[32] | now: u64 |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenAck {
    pub state: OpenState,
    pub session_id: u64,
    pub peer_ephemeral: [u8; 32],
    pub now: u64,
}

impl OpenAck {
    pub fn waiting(now: u64) -> OpenAck {
        OpenAck {
            state: OpenState::Waiting,
            session_id: 0,
            peer_ephemeral: [0u8; 32],
            now,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49);
        out.push(self.state as u8);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.peer_ephemeral);
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<OpenAck> {
        if b.len() != 49 {
            return Err(Error::Malformed(format!("ack is {} bytes, want 49", b.len())));
        }
        let state = match b[0] {
            0 => OpenState::Waiting,
            1 => OpenState::Established,
            other => return Err(Error::Malformed(format!("unknown open state {other}"))),
        };
        Ok(OpenAck {
            state,
            session_id: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            peer_ephemeral: b[9..41].try_into().unwrap(),
            now: u64::from_be_bytes(b[41..49].try_into().unwrap()),
        })
    }
}

/// One sealed frame on its way through.
/// `| type=0x02 | session_id: u64 | seq: u64 | ciphertext |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFrame {
    pub session_id: u64,
    pub seq: u64,
    pub ciphertext: Vec<u8>,
}

impl SendFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17 + self.ciphertext.len());
        out.push(TYPE_SEND);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(b: &[u8]) -> Result<SendFrame> {
        if b.len() < 17 {
            return Err(Error::Malformed(format!("frame is {} bytes, want >= 17", b.len())));
        }
        if b[0] != TYPE_SEND {
            return Err(Error::Malformed(format!("not a send (type {:#x})", b[0])));
        }
        let ciphertext = b[17..].to_vec();
        if ciphertext.len() > MAX_FRAME + 16 {
            return Err(Error::Malformed(format!(
                "frame payload is {} bytes, limit is {}",
                ciphertext.len(),
                MAX_FRAME + 16
            )));
        }
        Ok(SendFrame {
            session_id: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            seq: u64::from_be_bytes(b[9..17].try_into().unwrap()),
            ciphertext,
        })
    }
}

/// Collect whatever is waiting for me, or close.
/// `| type | session_id: u64 |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BySession {
    pub kind: u8,
    pub session_id: u64,
}

impl BySession {
    pub fn recv(session_id: u64) -> BySession {
        BySession {
            kind: TYPE_RECV,
            session_id,
        }
    }
    pub fn close(session_id: u64) -> BySession {
        BySession {
            kind: TYPE_CLOSE,
            session_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.push(self.kind);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8], expect: u8) -> Result<BySession> {
        if b.len() != 9 {
            return Err(Error::Malformed(format!("request is {} bytes, want 9", b.len())));
        }
        if b[0] != expect {
            return Err(Error::Malformed(format!("unexpected type {:#x}", b[0])));
        }
        Ok(BySession {
            kind: b[0],
            session_id: u64::from_be_bytes(b[1..9].try_into().unwrap()),
        })
    }
}

/// Frames waiting for one peer, in order.
/// `| open: u8 | count: u32 | count x { seq: u64 | len: u32 | ciphertext } |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frames {
    /// Whether the session is still live; false once closed or expired.
    pub open: bool,
    pub frames: Vec<(u64, Vec<u8>)>,
}

impl Frames {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5);
        out.push(u8::from(self.open));
        out.extend_from_slice(&(self.frames.len() as u32).to_be_bytes());
        for (seq, ct) in &self.frames {
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(ct);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Frames> {
        if b.len() < 5 {
            return Err(Error::Malformed("frames too short".into()));
        }
        let open = b[0] != 0;
        let count = u32::from_be_bytes(b[1..5].try_into().unwrap()) as usize;
        if count > MAX_QUEUED_FRAMES {
            return Err(Error::Malformed(format!("claims {count} frames")));
        }
        let mut frames = Vec::with_capacity(count);
        let mut o = 5;
        for _ in 0..count {
            if b.len() < o + 12 {
                return Err(Error::Malformed("truncated frame header".into()));
            }
            let seq = u64::from_be_bytes(b[o..o + 8].try_into().unwrap());
            let len = u32::from_be_bytes(b[o + 8..o + 12].try_into().unwrap()) as usize;
            o += 12;
            if len > MAX_FRAME + 16 || b.len() < o + len {
                return Err(Error::Malformed("truncated frame body".into()));
            }
            frames.push((seq, b[o..o + len].to_vec()));
            o += len;
        }
        if o != b.len() {
            return Err(Error::Malformed("trailing bytes after frames".into()));
        }
        Ok(Frames { open, frames })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn identity(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    fn ephemeral() -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng)
    }

    /// Both ends, given only what the exchange relays, derive the same key.
    fn agree() -> (Session, Session) {
        let (a_seed, a_id) = identity(1);
        let (b_seed, b_id) = identity(2);
        let a_eph = ephemeral();
        let b_eph = ephemeral();
        let a_eph_pub = x25519_dalek::PublicKey::from(&a_eph).to_bytes();
        let b_eph_pub = x25519_dalek::PublicKey::from(&b_eph).to_bytes();

        let a = Session::derive(&a_seed, &a_eph, &b_id, &b_eph_pub).unwrap();
        let b = Session::derive(&b_seed, &b_eph, &a_id, &a_eph_pub).unwrap();
        (a, b)
    }

    #[test]
    fn both_ends_derive_the_same_key() {
        let (a, b) = agree();
        assert_eq!(a.key, b.key);
        assert_ne!(a.role(), b.role(), "and take opposite roles");
    }

    #[test]
    fn roles_are_symmetric_regardless_of_who_asked_first() {
        let (_a_seed, a_id) = identity(1);
        let (_b_seed, b_id) = identity(2);
        assert_eq!(Role::of(&a_id, &b_id).other(), Role::of(&b_id, &a_id));
    }

    #[test]
    fn frames_round_trip_between_the_peers() {
        let (a, b) = agree();
        let ct = a.seal(0, b"hello from a").unwrap();
        assert_eq!(b.open(0, &ct).unwrap(), b"hello from a");

        let ct = b.seal(0, b"hello from b").unwrap();
        assert_eq!(a.open(0, &ct).unwrap(), b"hello from b");
    }

    #[test]
    fn a_frame_cannot_be_replayed_at_another_sequence() {
        let (a, b) = agree();
        let ct = a.seal(7, b"once").unwrap();
        assert!(b.open(7, &ct).is_ok());
        assert!(b.open(8, &ct).is_err(), "the sequence keys the nonce");
    }

    #[test]
    fn a_peer_cannot_open_its_own_frame() {
        // Directions are separated, so a reflected frame does not decrypt.
        let (a, _b) = agree();
        let ct = a.seal(0, b"mine").unwrap();
        assert!(a.open(0, &ct).is_err());
    }

    #[test]
    fn the_exchange_cannot_derive_the_key() {
        // The exchange sees both identities and both ephemeral publics, and
        // holds no private key. Standing in for it: a third party with all the
        // public material and its own ephemeral cannot reach the same key.
        let (a_seed, a_id) = identity(1);
        let (b_seed, b_id) = identity(2);
        let a_eph = ephemeral();
        let b_eph = ephemeral();
        let a_eph_pub = x25519_dalek::PublicKey::from(&a_eph).to_bytes();
        let b_eph_pub = x25519_dalek::PublicKey::from(&b_eph).to_bytes();
        let real = Session::derive(&a_seed, &a_eph, &b_id, &b_eph_pub).unwrap();

        // The exchange substitutes its own ephemeral toward A, as a MITM would.
        let (evil_seed, _evil_id) = identity(3);
        let evil_eph = ephemeral();
        let forged = Session::derive(&evil_seed, &evil_eph, &a_id, &a_eph_pub).unwrap();
        assert_ne!(
            real.key, forged.key,
            "an impostor without a static private key reaches a different key"
        );
        let _ = (b_seed, b_eph_pub);
    }

    #[test]
    fn a_swapped_ephemeral_changes_the_key() {
        let (a_seed, _a_id) = identity(1);
        let (_b_seed, b_id) = identity(2);
        let a_eph = ephemeral();
        let real_b = x25519_dalek::PublicKey::from(&ephemeral()).to_bytes();
        let swapped = x25519_dalek::PublicKey::from(&ephemeral()).to_bytes();
        let s1 = Session::derive(&a_seed, &a_eph, &b_id, &real_b).unwrap();
        let s2 = Session::derive(&a_seed, &a_eph, &b_id, &swapped).unwrap();
        assert_ne!(s1.key, s2.key);
    }

    #[test]
    fn oversized_frames_are_refused() {
        let (a, _b) = agree();
        assert!(a.seal(0, &vec![0u8; MAX_FRAME + 1]).is_err());
        assert!(a.seal(0, &vec![0u8; MAX_FRAME]).is_ok());
    }

    #[test]
    fn open_round_trip() {
        let (_s, id) = identity(4);
        let o = Open {
            peer: id,
            ephemeral: [9u8; 32],
        };
        assert_eq!(Open::decode(&o.encode()).unwrap(), o);
        assert!(Open::decode(&[TYPE_OPEN; 10]).is_err());
    }

    #[test]
    fn open_ack_round_trip() {
        let a = OpenAck {
            state: OpenState::Established,
            session_id: 42,
            peer_ephemeral: [3u8; 32],
            now: 1000,
        };
        assert_eq!(OpenAck::decode(&a.encode()).unwrap(), a);
        assert_eq!(
            OpenAck::decode(&OpenAck::waiting(5).encode()).unwrap().state,
            OpenState::Waiting
        );
        let mut bad = a.encode();
        bad[0] = 9;
        assert!(OpenAck::decode(&bad).is_err());
    }

    #[test]
    fn send_frame_round_trip() {
        let f = SendFrame {
            session_id: 7,
            seq: 3,
            ciphertext: vec![1, 2, 3],
        };
        assert_eq!(SendFrame::decode(&f.encode()).unwrap(), f);
        let mut oversized = f.encode();
        oversized.extend(std::iter::repeat_n(0u8, MAX_FRAME + 17));
        assert!(SendFrame::decode(&oversized).is_err());
    }

    #[test]
    fn frames_round_trip() {
        let f = Frames {
            open: true,
            frames: vec![(0, vec![1, 2]), (1, vec![3, 4, 5])],
        };
        assert_eq!(Frames::decode(&f.encode()).unwrap(), f);
        let empty = Frames {
            open: false,
            frames: vec![],
        };
        assert_eq!(Frames::decode(&empty.encode()).unwrap(), empty);
        let mut trailing = f.encode();
        trailing.push(0);
        assert!(Frames::decode(&trailing).is_err());
    }

    #[test]
    fn by_session_type_is_checked() {
        let r = BySession::recv(1);
        assert_eq!(BySession::decode(&r.encode(), TYPE_RECV).unwrap(), r);
        assert!(BySession::decode(&r.encode(), TYPE_CLOSE).is_err());
    }
}
