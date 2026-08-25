//! The SIP-5 store-and-forward mailbox.
//!
//! A sender leaves a sealed message for a recipient at the exchange; the
//! recipient collects it on a later connection. Both ends are named by their
//! connection (SIP-3), so nothing here is signed — as with the beacon, the
//! connection is the proof of who is acting.
//!
//! # Sealing
//!
//! The payload is sealed to the recipient with a **fresh ephemeral sender key**
//! per message (the NaCl `crypto_box_seal` construction):
//!
//! ```text
//! shared = X25519(ephemeral_secret, recipient_x25519)
//! okm    = SHA-512(SEAL_CONTEXT || ephemeral_pub || recipient_x25519 || shared)
//! key    = okm[0..32]      nonce = okm[32..44]
//! ```
//!
//! The recipient's X25519 key is derived forward from the Ed25519 identity it is
//! named by — the conversion that does not run backwards runs perfectly well
//! forwards. The nonce is derived rather than sent: the ephemeral key is fresh
//! for every message, so the key is never reused and there is nothing for a
//! nonce to disambiguate.
//!
//! **What this does and does not give you.** A later compromise of the
//! *sender's* identity key decrypts nothing, because the sender's long-lived key
//! never enters the exchange. A compromise of the *recipient's* key still opens
//! anything still stored, which the TTL bounds. And because the sender's key is
//! not in the ECDH, **the ciphertext does not prove who sent it** — the sender
//! recorded alongside is the *exchange's* observation of the connection, not a
//! cryptographic fact. An application that needs end-to-end sender
//! authentication signs inside the plaintext.
//!
//! Sealing lives here beside the layouts because the *clients* need it. `sqexd`
//! links this module but never calls `seal` or `open`: the exchange handles
//! ciphertext only, and cannot do otherwise.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha512};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for the mailbox sealing KDF.
pub const SEAL_CONTEXT: &[u8] = b"sqex-mailbox-v1";

/// Largest plaintext a message may carry. Deliberately small: a mailbox is a
/// rendezvous for messages, not a file host, and the ceiling should make that
/// structural rather than a matter of operator restraint.
pub const MAX_PLAINTEXT: usize = 32 * 1024;

/// Most messages one recipient may have waiting.
pub const MAX_MESSAGES: usize = 64;

/// Most stored bytes one recipient may accumulate.
pub const MAX_BYTES: usize = 1024 * 1024;

/// How long an uncollected message is kept, and how long the record that it was
/// collected outlives it.
pub const TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Message types.
pub const TYPE_SEND: u8 = 0x01;
pub const TYPE_LIST: u8 = 0x02;
pub const TYPE_FETCH: u8 = 0x03;
pub const TYPE_DELETE: u8 = 0x04;
pub const TYPE_STATUS: u8 = 0x05;

// ---- sealing ----------------------------------------------------------------

/// A sealed payload: the ephemeral public key that opens it, and the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub ephemeral: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// Derive the message key and nonce from an ECDH result.
fn kdf(ephemeral_pub: &[u8; 32], recipient_x: &[u8; 32], shared: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut h = Sha512::new();
    h.update(SEAL_CONTEXT);
    h.update(ephemeral_pub);
    h.update(recipient_x);
    h.update(shared);
    let okm = h.finalize();
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..44]);
    (key, nonce)
}

/// Seal `plaintext` to `recipient` (named by its Ed25519 identity).
pub fn seal(recipient: &PubKey, plaintext: &[u8]) -> Result<Sealed> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::Malformed(format!(
            "message is {} bytes, limit is {MAX_PLAINTEXT}",
            plaintext.len()
        )));
    }
    let recipient_x = squic::crypto::ed25519_identity_to_x25519(recipient.as_bytes())
        .map_err(|e| Error::Key(format!("recipient key: {e}")))?;

    // A fresh ephemeral key per message: this is what keeps the sender's
    // long-lived key out of the exchange entirely.
    let eph_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient_x);
    if !shared.was_contributory() {
        return Err(Error::Key("recipient key is degenerate".into()));
    }

    let (key, nonce) = kdf(&eph_pub.to_bytes(), &recipient_x.to_bytes(), shared.as_bytes());
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|e| Error::Key(format!("cipher: {e}")))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| Error::Key(format!("seal: {e}")))?;

    Ok(Sealed {
        ephemeral: eph_pub.to_bytes(),
        ciphertext,
    })
}

/// Open a message sealed to the identity behind `recipient_seed`.
pub fn open(recipient_seed: &[u8; 32], sealed: &Sealed) -> Result<Vec<u8>> {
    let signing = ed25519_dalek::SigningKey::from_bytes(recipient_seed);
    let recipient_x = squic::crypto::ed25519_private_to_x25519(&signing);
    let recipient_x_pub = x25519_dalek::PublicKey::from(&recipient_x);

    let eph_pub = x25519_dalek::PublicKey::from(sealed.ephemeral);
    let shared = recipient_x.diffie_hellman(&eph_pub);
    if !shared.was_contributory() {
        return Err(Error::Key("ephemeral key is degenerate".into()));
    }

    let (key, nonce) = kdf(&sealed.ephemeral, &recipient_x_pub.to_bytes(), shared.as_bytes());
    let cipher =
        ChaCha20Poly1305::new_from_slice(&key).map_err(|e| Error::Key(format!("cipher: {e}")))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), sealed.ciphertext.as_ref())
        .map_err(|_| Error::Key("cannot open: not sealed to this identity, or altered".into()))
}

// ---- wire messages ----------------------------------------------------------

/// Leave a message. `| type=0x01 | recipient[32] | ephemeral[32] | ciphertext |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Send {
    pub recipient: PubKey,
    pub sealed: Sealed,
}

impl Send {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65 + self.sealed.ciphertext.len());
        out.push(TYPE_SEND);
        out.extend_from_slice(self.recipient.as_bytes());
        out.extend_from_slice(&self.sealed.ephemeral);
        out.extend_from_slice(&self.sealed.ciphertext);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Send> {
        if b.len() < 65 {
            return Err(Error::Malformed(format!("send is {} bytes, want >= 65", b.len())));
        }
        if b[0] != TYPE_SEND {
            return Err(Error::Malformed(format!("not a send (type {:#x})", b[0])));
        }
        // The tag alone would let a caller store more than MAX_PLAINTEXT; the
        // exchange cannot see the plaintext, so it bounds the ciphertext.
        let ciphertext = b[65..].to_vec();
        if ciphertext.len() > MAX_PLAINTEXT + 16 {
            return Err(Error::Malformed(format!(
                "payload is {} bytes, limit is {}",
                ciphertext.len(),
                MAX_PLAINTEXT + 16
            )));
        }
        Ok(Send {
            recipient: PubKey::new(b[1..33].try_into().unwrap()),
            sealed: Sealed {
                ephemeral: b[33..65].try_into().unwrap(),
                ciphertext,
            },
        })
    }
}

/// The exchange's answer to a send. `| id: u64 | now: u64 |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendAck {
    pub id: u64,
    pub now: u64,
}

impl SendAck {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<SendAck> {
        if b.len() != 16 {
            return Err(Error::Malformed(format!("ack is {} bytes, want 16", b.len())));
        }
        Ok(SendAck {
            id: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            now: u64::from_be_bytes(b[8..16].try_into().unwrap()),
        })
    }
}

/// One waiting message, as listed. `| id | sender[32] | received | len |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub id: u64,
    /// Who the exchange saw send it — its observation, not a cryptographic fact.
    pub sender: PubKey,
    pub received: u64,
    pub len: u32,
}

/// The waiting messages, oldest first. `| count: u32 | count x Entry |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub now: u64,
}

impl Listing {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.entries.len() * 52);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.id.to_be_bytes());
            out.extend_from_slice(e.sender.as_bytes());
            out.extend_from_slice(&e.received.to_be_bytes());
            out.extend_from_slice(&e.len.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Listing> {
        if b.len() < 12 {
            return Err(Error::Malformed("listing too short".into()));
        }
        let now = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let count = u32::from_be_bytes(b[8..12].try_into().unwrap()) as usize;
        if count > MAX_MESSAGES {
            return Err(Error::Malformed(format!("listing claims {count} entries")));
        }
        if b.len() != 12 + count * 52 {
            return Err(Error::Malformed("listing length does not match its count".into()));
        }
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let o = 12 + i * 52;
            entries.push(Entry {
                id: u64::from_be_bytes(b[o..o + 8].try_into().unwrap()),
                sender: PubKey::new(b[o + 8..o + 40].try_into().unwrap()),
                received: u64::from_be_bytes(b[o + 40..o + 48].try_into().unwrap()),
                len: u32::from_be_bytes(b[o + 48..o + 52].try_into().unwrap()),
            });
        }
        Ok(Listing { entries, now })
    }
}

/// A request naming one message by id — fetch, delete, or status.
/// `| type | id: u64 |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ById {
    pub kind: u8,
    pub id: u64,
}

impl ById {
    pub fn fetch(id: u64) -> ById {
        ById {
            kind: TYPE_FETCH,
            id,
        }
    }
    pub fn delete(id: u64) -> ById {
        ById {
            kind: TYPE_DELETE,
            id,
        }
    }
    pub fn status(id: u64) -> ById {
        ById {
            kind: TYPE_STATUS,
            id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.push(self.kind);
        out.extend_from_slice(&self.id.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8], expect: u8) -> Result<ById> {
        if b.len() != 9 {
            return Err(Error::Malformed(format!("request is {} bytes, want 9", b.len())));
        }
        if b[0] != expect {
            return Err(Error::Malformed(format!("unexpected type {:#x}", b[0])));
        }
        Ok(ById {
            kind: b[0],
            id: u64::from_be_bytes(b[1..9].try_into().unwrap()),
        })
    }
}

/// A collected message. `| found | sender[32] | received | ephemeral[32] | ciphertext |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub found: bool,
    pub sender: PubKey,
    pub received: u64,
    pub sealed: Sealed,
}

impl Fetched {
    pub fn none() -> Fetched {
        Fetched {
            found: false,
            sender: PubKey::new([0u8; 32]),
            received: 0,
            sealed: Sealed {
                ephemeral: [0u8; 32],
                ciphertext: Vec::new(),
            },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(73 + self.sealed.ciphertext.len());
        out.push(u8::from(self.found));
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(&self.received.to_be_bytes());
        out.extend_from_slice(&self.sealed.ephemeral);
        out.extend_from_slice(&self.sealed.ciphertext);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Fetched> {
        if b.len() < 73 {
            return Err(Error::Malformed(format!("fetched is {} bytes, want >= 73", b.len())));
        }
        Ok(Fetched {
            found: b[0] != 0,
            sender: PubKey::new(b[1..33].try_into().unwrap()),
            received: u64::from_be_bytes(b[33..41].try_into().unwrap()),
            sealed: Sealed {
                ephemeral: b[41..73].try_into().unwrap(),
                ciphertext: b[73..].to_vec(),
            },
        })
    }
}

/// What became of a message a sender left. `| state | received | collected | now |`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No such message, or it expired.
    Unknown = 0,
    /// Stored, not yet collected.
    Waiting = 1,
    /// The recipient fetched and deleted it.
    Collected = 2,
}

/// The answer to a sender asking after their own message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub received: u64,
    /// When the recipient deleted it; 0 unless `state` is `Collected`.
    pub collected: u64,
    pub now: u64,
}

impl Status {
    pub fn unknown(now: u64) -> Status {
        Status {
            state: State::Unknown,
            received: 0,
            collected: 0,
            now,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(25);
        out.push(self.state as u8);
        out.extend_from_slice(&self.received.to_be_bytes());
        out.extend_from_slice(&self.collected.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Status> {
        if b.len() != 25 {
            return Err(Error::Malformed(format!("status is {} bytes, want 25", b.len())));
        }
        let state = match b[0] {
            0 => State::Unknown,
            1 => State::Waiting,
            2 => State::Collected,
            other => return Err(Error::Malformed(format!("unknown state {other}"))),
        };
        Ok(Status {
            state,
            received: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            collected: u64::from_be_bytes(b[9..17].try_into().unwrap()),
            now: u64::from_be_bytes(b[17..25].try_into().unwrap()),
        })
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

    #[test]
    fn seal_open_round_trip() {
        let (seed, pk) = identity(1);
        let msg = b"the exchange never sees this";
        let sealed = seal(&pk, msg).unwrap();
        assert_eq!(open(&seed, &sealed).unwrap(), msg);
    }

    #[test]
    fn a_different_recipient_cannot_open() {
        let (_seed, pk) = identity(1);
        let (other_seed, _other_pk) = identity(2);
        let sealed = seal(&pk, b"for one identity only").unwrap();
        assert!(open(&other_seed, &sealed).is_err());
    }

    #[test]
    fn altered_ciphertext_is_refused() {
        let (seed, pk) = identity(3);
        let mut sealed = seal(&pk, b"tamper me").unwrap();
        sealed.ciphertext[0] ^= 0xFF;
        assert!(open(&seed, &sealed).is_err());
        // Swapping the ephemeral key is equally fatal: it keys the whole thing.
        let mut sealed2 = seal(&pk, b"tamper me").unwrap();
        sealed2.ephemeral[0] ^= 0xFF;
        assert!(open(&seed, &sealed2).is_err());
    }

    #[test]
    fn each_sealing_is_distinct() {
        // Fresh ephemeral per message: the same plaintext to the same recipient
        // must not produce the same bytes twice.
        let (_seed, pk) = identity(4);
        let a = seal(&pk, b"same words").unwrap();
        let b = seal(&pk, b"same words").unwrap();
        assert_ne!(a.ephemeral, b.ephemeral);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn oversized_plaintext_is_refused() {
        let (_seed, pk) = identity(5);
        assert!(seal(&pk, &vec![0u8; MAX_PLAINTEXT + 1]).is_err());
        assert!(seal(&pk, &vec![0u8; MAX_PLAINTEXT]).is_ok());
    }

    #[test]
    fn send_round_trip() {
        let (_seed, pk) = identity(6);
        let s = Send {
            recipient: pk,
            sealed: seal(&pk, b"hello").unwrap(),
        };
        assert_eq!(Send::decode(&s.encode()).unwrap(), s);
        assert!(Send::decode(&[TYPE_SEND; 10]).is_err());
    }

    #[test]
    fn send_refuses_an_oversized_payload_on_the_wire() {
        let (_seed, pk) = identity(7);
        let mut raw = Send {
            recipient: pk,
            sealed: Sealed {
                ephemeral: [0u8; 32],
                ciphertext: vec![],
            },
        }
        .encode();
        raw.extend(std::iter::repeat_n(0u8, MAX_PLAINTEXT + 17));
        assert!(Send::decode(&raw).is_err(), "the exchange bounds ciphertext it cannot read");
    }

    #[test]
    fn listing_round_trip() {
        let (_seed, pk) = identity(8);
        let l = Listing {
            now: 1000,
            entries: vec![
                Entry {
                    id: 1,
                    sender: pk,
                    received: 900,
                    len: 42,
                },
                Entry {
                    id: 2,
                    sender: pk,
                    received: 950,
                    len: 7,
                },
            ],
        };
        assert_eq!(Listing::decode(&l.encode()).unwrap(), l);
        let empty = Listing {
            now: 5,
            entries: vec![],
        };
        assert_eq!(Listing::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn by_id_round_trip_and_type_check() {
        let f = ById::fetch(9);
        assert_eq!(ById::decode(&f.encode(), TYPE_FETCH).unwrap(), f);
        // A fetch must not be accepted where a delete is expected.
        assert!(ById::decode(&f.encode(), TYPE_DELETE).is_err());
    }

    #[test]
    fn fetched_round_trip() {
        let (_seed, pk) = identity(10);
        let f = Fetched {
            found: true,
            sender: pk,
            received: 123,
            sealed: seal(&pk, b"collected").unwrap(),
        };
        assert_eq!(Fetched::decode(&f.encode()).unwrap(), f);
        assert!(!Fetched::decode(&Fetched::none().encode()).unwrap().found);
    }

    #[test]
    fn status_round_trip() {
        for state in [State::Unknown, State::Waiting, State::Collected] {
            let s = Status {
                state,
                received: 10,
                collected: 20,
                now: 30,
            };
            assert_eq!(Status::decode(&s.encode()).unwrap(), s);
        }
        let mut bad = Status::unknown(1).encode();
        bad[0] = 9;
        assert!(Status::decode(&bad).is_err());
    }
}
