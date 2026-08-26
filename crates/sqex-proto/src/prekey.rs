//! SIP-23 device prekeys: single-use keys so an envelope is fresh at both ends.
//!
//! SIP-17 seals a channel key to a device. Before this, it sealed against that
//! device's **long-term** identity, which made the exchange's pile of stored
//! envelopes a harvest-now decrypt-later attack with an unusually good yield:
//! worthless today, an entire history the moment any one identity key turned
//! up, and *larger* the more often the channel rotated.
//!
//! A prekey is the remedy X3DH reaches for. A device publishes single-use
//! X25519 keys in advance, signed under its own Ed25519 key; the exchange hands
//! each out once; the device destroys the secret on use. The envelope then has
//! a fresh key at both ends, and the recorded ciphertext stays shut.
//!
//! # What this does not buy
//!
//! Nothing about a compromised device. A client that can show you last month's
//! conversation is holding last month's channel keys, and taking the machine
//! takes them. This protects key *distribution*, not key *storage*, and the
//! distinction is the difference between an attacker who copied the exchange's
//! envelopes and one who has somebody's laptop.
//!
//! # Deleting is the mechanism
//!
//! A client that keeps prekey secrets — so that reinstalling is painless, say —
//! has implemented the wire format and none of the property, in the way least
//! likely to be noticed, because everything still works.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for a prekey signature.
pub const PREKEY_CONTEXT: &[u8] = b"sqex-prekey-v1";

pub const TYPE_PUBLISH: u8 = 0x01;
pub const TYPE_TAKE: u8 = 0x02;
pub const TYPE_COUNT: u8 = 0x03;

/// Served once, then gone. The forward secrecy is entirely in this.
pub const KIND_ONE_TIME: u8 = 0x01;
/// Served whenever the one-time pool is empty, and reusable by construction.
///
/// It exists so that a drained pool cannot block a *rotation*: a security
/// mechanism able to prevent a revocation is a poor trade. It bounds the loss
/// to a window rather than to everything.
pub const KIND_FALLBACK: u8 = 0x02;

/// One-time prekeys a device should keep published.
pub const POOL: u16 = 64;
/// Top up when the pool falls below this.
pub const LOW_WATER: u16 = 16;
/// Prekeys one `Publish` may carry.
pub const MAX_PUBLISH: usize = 64;
/// One-time prekeys the exchange stores per device.
pub const MAX_STORED: usize = 128;
/// How long a fallback should live before being replaced. The real granularity
/// of this SIP's guarantee in the worst case.
pub const FALLBACK_MAX_AGE: u64 = 7 * 24 * 60 * 60;

/// Bytes of a prekey on the wire.
pub const PREKEY_LEN: usize = 1 + 4 + 32 + 64;

/// A published prekey: an X25519 public key the device signed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prekey {
    pub kind: u8,
    pub id: u32,
    pub public: [u8; 32],
    pub signature: [u8; 64],
}

/// The bytes a prekey signature covers.
///
/// The device is in the input, so a prekey cannot be lifted from one device's
/// pool and republished under another's name.
fn signing_input(device: &PubKey, kind: u8, id: u32, public: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PREKEY_CONTEXT.len() + 32 + 1 + 4 + 32);
    m.extend_from_slice(PREKEY_CONTEXT);
    m.extend_from_slice(device.as_bytes());
    m.push(kind);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(public);
    m
}

impl Prekey {
    /// Mint and sign one. Returns the secret alongside, which the caller keeps
    /// and **must destroy after use** — that deletion is the whole mechanism.
    pub fn generate(
        device_seed: &[u8; 32],
        kind: u8,
        id: u32,
    ) -> (Prekey, x25519_dalek::StaticSecret) {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let signing = SigningKey::from_bytes(device_seed);
        let device = PubKey::new(signing.verifying_key().to_bytes());
        let signature = signing
            .sign(&signing_input(&device, kind, id, &public))
            .to_bytes();
        (
            Prekey {
                kind,
                id,
                public,
                signature,
            },
            secret,
        )
    }

    /// Check that `device` really published this.
    ///
    /// A sender **MUST** do this itself before sealing. The exchange verifies
    /// at publish time too, but the exchange is the party this signature exists
    /// to constrain, so a sender that trusts its check has verified nothing.
    pub fn verify(&self, device: &PubKey) -> Result<()> {
        if self.id == 0 {
            return Err(Error::Malformed("prekey id 0 is reserved".into()));
        }
        if self.kind != KIND_ONE_TIME && self.kind != KIND_FALLBACK {
            return Err(Error::Malformed(format!("unknown prekey kind {}", self.kind)));
        }
        let vk = VerifyingKey::from_bytes(device.as_bytes())
            .map_err(|e| Error::Key(format!("device key: {e}")))?;
        vk.verify(
            &signing_input(device, self.kind, self.id, &self.public),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::BadSignature)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.signature);
    }

    fn read(b: &[u8], o: usize) -> Prekey {
        Prekey {
            kind: b[o],
            id: u32::from_be_bytes(b[o + 1..o + 5].try_into().unwrap()),
            public: b[o + 5..o + 37].try_into().unwrap(),
            signature: b[o + 37..o + 101].try_into().unwrap(),
        }
    }
}

/// Add one-time prekeys to the caller's pool, and replace its fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub prekeys: Vec<Prekey>,
}

impl Publish {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.prekeys.len() * PREKEY_LEN);
        out.push(TYPE_PUBLISH);
        out.extend_from_slice(&(self.prekeys.len() as u16).to_be_bytes());
        for p in &self.prekeys {
            p.write(&mut out);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Publish> {
        if b.len() < 3 {
            return Err(Error::Malformed(format!(
                "publish is {} bytes, want at least 3",
                b.len()
            )));
        }
        if b[0] != TYPE_PUBLISH {
            return Err(Error::Malformed(format!(
                "not a publish (type {:#x})",
                b[0]
            )));
        }
        let count = u16::from_be_bytes(b[1..3].try_into().unwrap()) as usize;
        if count > MAX_PUBLISH {
            return Err(Error::Malformed(format!(
                "publish carries {count} prekeys, limit is {MAX_PUBLISH}"
            )));
        }
        if b.len() != 3 + count * PREKEY_LEN {
            return Err(Error::Malformed(format!(
                "publish is {} bytes, want {}",
                b.len(),
                3 + count * PREKEY_LEN
            )));
        }
        Ok(Publish {
            prekeys: (0..count).map(|i| Prekey::read(b, 3 + i * PREKEY_LEN)).collect(),
        })
    }
}

/// Ask for one prekey for `device`, consuming it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Take {
    pub device: PubKey,
}

impl Take {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_TAKE);
        out.extend_from_slice(self.device.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Take> {
        if b.len() != 33 {
            return Err(Error::Malformed(format!(
                "take is {} bytes, want 33",
                b.len()
            )));
        }
        if b[0] != TYPE_TAKE {
            return Err(Error::Malformed(format!("not a take (type {:#x})", b[0])));
        }
        Ok(Take {
            device: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// The prekey the exchange served, if the device had published any.
///
/// `found: 0` means it has published nothing, and a caller MUST NOT then seal
/// to it at all — there is deliberately no static-only path, because an
/// optional one is a downgrade a dishonest exchange could force by reporting an
/// empty pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Taken {
    pub found: bool,
    pub prekey: Option<Prekey>,
    pub now: u64,
}

impl Taken {
    pub fn none(now: u64) -> Taken {
        Taken {
            found: false,
            prekey: None,
            now,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + PREKEY_LEN + 8);
        out.push(u8::from(self.found));
        match &self.prekey {
            Some(p) => p.write(&mut out),
            // Not found and found are the same shape, as SIP-4 and SIP-5 do
            // with their own absences.
            None => out.extend(std::iter::repeat_n(0u8, PREKEY_LEN)),
        }
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Taken> {
        if b.len() != 1 + PREKEY_LEN + 8 {
            return Err(Error::Malformed(format!(
                "taken is {} bytes, want {}",
                b.len(),
                1 + PREKEY_LEN + 8
            )));
        }
        let found = b[0] != 0;
        Ok(Taken {
            found,
            prekey: found.then(|| Prekey::read(b, 1)),
            now: u64::from_be_bytes(b[1 + PREKEY_LEN..].try_into().unwrap()),
        })
    }
}

/// What the caller has left, so it knows when to top up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub one_time: u16,
    pub fallback_id: u32,
    pub now: u64,
}

impl Counts {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14);
        out.extend_from_slice(&self.one_time.to_be_bytes());
        out.extend_from_slice(&self.fallback_id.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Counts> {
        if b.len() != 14 {
            return Err(Error::Malformed(format!(
                "counts is {} bytes, want 14",
                b.len()
            )));
        }
        Ok(Counts {
            one_time: u16::from_be_bytes(b[0..2].try_into().unwrap()),
            fallback_id: u32::from_be_bytes(b[2..6].try_into().unwrap()),
            now: u64::from_be_bytes(b[6..14].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    #[test]
    fn a_prekey_verifies_under_the_device_that_signed_it() {
        let (seed, key) = device(1);
        let (p, _secret) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert!(p.verify(&key).is_ok());
    }

    #[test]
    fn a_prekey_does_not_verify_under_another_device() {
        // The device is in the signing input precisely so a prekey cannot be
        // lifted from one pool and republished under another name.
        let (seed, _) = device(1);
        let (_, other) = device(2);
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert!(p.verify(&other).is_err());
    }

    #[test]
    fn a_tampered_prekey_is_refused() {
        let (seed, key) = device(1);
        let (mut p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        p.public[0] ^= 1;
        assert!(p.verify(&key).is_err());

        let (mut p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        p.id = 8;
        assert!(p.verify(&key).is_err());

        // Including the kind: a one-time key re-presented as a reusable
        // fallback would silently give up the forward secrecy.
        let (mut p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        p.kind = KIND_FALLBACK;
        assert!(p.verify(&key).is_err());
    }

    #[test]
    fn id_zero_is_reserved() {
        let (seed, key) = device(1);
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 0);
        assert!(p.verify(&key).is_err());
    }

    #[test]
    fn publish_round_trips() {
        let (seed, _) = device(1);
        let prekeys = (1..=3).map(|i| Prekey::generate(&seed, KIND_ONE_TIME, i).0).collect();
        let p = Publish { prekeys };
        assert_eq!(Publish::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn publish_bounds_its_batch() {
        let (seed, _) = device(1);
        let prekeys = (1..=(MAX_PUBLISH as u32 + 1))
            .map(|i| Prekey::generate(&seed, KIND_ONE_TIME, i).0)
            .collect();
        assert!(Publish::decode(&Publish { prekeys }.encode()).is_err());
    }

    #[test]
    fn taken_round_trips_both_ways() {
        let (seed, _) = device(1);
        let (p, _) = Prekey::generate(&seed, KIND_FALLBACK, 9);
        let got = Taken {
            found: true,
            prekey: Some(p),
            now: 42,
        };
        assert_eq!(Taken::decode(&got.encode()).unwrap(), got);

        let none = Taken::none(42);
        assert_eq!(Taken::decode(&none.encode()).unwrap(), none);
        // Absence and presence are the same length on the wire.
        assert_eq!(none.encode().len(), got.encode().len());
    }

    #[test]
    fn take_and_counts_round_trip() {
        let (_, key) = device(3);
        let t = Take { device: key };
        assert_eq!(Take::decode(&t.encode()).unwrap(), t);
        let c = Counts {
            one_time: 12,
            fallback_id: 5,
            now: 99,
        };
        assert_eq!(Counts::decode(&c.encode()).unwrap(), c);
    }
}
