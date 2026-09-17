//! SIP-59: an account moves home.
//!
//! An account signs, once, which exchange it lives at. The statement is
//! self-contained and portable like a SIP-44 will: anybody holding it can
//! verify it with no record of the account. Presented at the named
//! exchange, the home pulls the account's channels from wherever they live;
//! carried to the exchange the account left, it opens SIP-35's acts-for
//! gate to the home and makes the old home answer *moved* on everything
//! that was the key's there.

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use sqnr_core::{Error, PubKey, Result};

pub const HOME_CONTEXT: &[u8] = b"sqex-home-v1";

/// Origins a `Moving` may name.
pub const MAX_ORIGINS: usize = 16;

pub const MOVE_LEN: usize = 32 + 32 + 8 + 64;

fn short(what: &str) -> Error {
    Error::Malformed(format!("{what} cut short"))
}

fn read_domain(b: &[u8], at: &mut usize, what: &str) -> Result<String> {
    let len = *b.get(*at).ok_or_else(|| short(what))? as usize;
    *at += 1;
    let end = *at + len;
    let raw = b.get(*at..end).ok_or_else(|| short(what))?;
    *at = end;
    String::from_utf8(raw.to_vec())
        .map_err(|_| Error::Malformed(format!("{what} domain is not UTF-8")))
}

fn write_domain(out: &mut Vec<u8>, domain: &str) {
    let d = domain.as_bytes();
    out.push(d.len().min(255) as u8);
    out.extend_from_slice(&d[..d.len().min(255)]);
}

/// An account's statement of the exchange it lives at from `issued` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Move {
    pub account: PubKey,
    pub home: PubKey,
    pub issued: u64,
    pub sig: [u8; 64],
}

impl Move {
    /// What the account signs: the fields under the context, raw. Small and
    /// fixed, so no digest in the middle.
    pub fn to_sign(account: &PubKey, home: &PubKey, issued: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(HOME_CONTEXT.len() + 72);
        out.extend_from_slice(HOME_CONTEXT);
        out.extend_from_slice(account.as_bytes());
        out.extend_from_slice(home.as_bytes());
        out.extend_from_slice(&issued.to_be_bytes());
        out
    }

    /// SIP-58: the statement, given the account's signature over
    /// [`Move::to_sign`] -- for a key that signs elsewhere.
    pub fn from_signature(account: PubKey, home: PubKey, issued: u64, sig: [u8; 64]) -> Move {
        Move {
            account,
            home,
            issued,
            sig,
        }
    }

    pub fn sign(account_seed: &[u8; 32], home: &PubKey, issued: u64) -> Move {
        let signing = SigningKey::from_bytes(account_seed);
        Self::sign_with(&sqnr_core::SoftwareSigner::new(signing), home, issued)
    }

    /// Sign with any signer, a hardware token included.
    pub fn sign_with(signer: &dyn sqnr_core::Signer, home: &PubKey, issued: u64) -> Move {
        let account = PubKey::new(signer.public());
        let sig = signer.sign(&Move::to_sign(&account, home, issued));
        Move::from_signature(account, *home, issued, sig)
    }

    pub fn verify(&self) -> bool {
        VerifyingKey::from_bytes(self.account.as_bytes())
            .map(|vk| {
                vk.verify(
                    &Move::to_sign(&self.account, &self.home, self.issued),
                    &Signature::from_bytes(&self.sig),
                )
                .is_ok()
            })
            .unwrap_or(false)
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(self.home.as_bytes());
        out.extend_from_slice(&self.issued.to_be_bytes());
        out.extend_from_slice(&self.sig);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MOVE_LEN);
        self.write(&mut out);
        out
    }

    pub fn read(b: &[u8], at: &mut usize) -> Result<Move> {
        let end = *at + MOVE_LEN;
        let m = b.get(*at..end).ok_or_else(|| short("move"))?;
        *at = end;
        Ok(Move {
            account: PubKey::new(m[0..32].try_into().unwrap()),
            home: PubKey::new(m[32..64].try_into().unwrap()),
            issued: u64::from_be_bytes(m[64..72].try_into().unwrap()),
            sig: m[72..136].try_into().unwrap(),
        })
    }

    pub fn decode(b: &[u8]) -> Result<Move> {
        if b.len() != MOVE_LEN {
            return Err(Error::Malformed(format!(
                "move is {} bytes, want {MOVE_LEN}",
                b.len()
            )));
        }
        Move::read(b, &mut 0)
    }
}

/// `POST /account/move`: the statement, where the home is reached, and
/// where the account's channels live as the presenter knows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moving {
    pub mv: Move,
    pub domain: String,
    pub origins: Vec<(PubKey, String)>,
}

impl Moving {
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(MOVE_LEN + 2 + self.domain.len() + self.origins.len() * 40);
        self.mv.write(&mut out);
        write_domain(&mut out, &self.domain);
        out.push(self.origins.len().min(MAX_ORIGINS) as u8);
        for (key, domain) in self.origins.iter().take(MAX_ORIGINS) {
            out.extend_from_slice(key.as_bytes());
            write_domain(&mut out, domain);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Moving> {
        let mut at = 0;
        let mv = Move::read(b, &mut at)?;
        let domain = read_domain(b, &mut at, "moving")?;
        let count = *b.get(at).ok_or_else(|| short("moving"))? as usize;
        at += 1;
        if count > MAX_ORIGINS {
            return Err(Error::Malformed(format!(
                "a move names at most {MAX_ORIGINS} origins, not {count}"
            )));
        }
        let mut origins = Vec::with_capacity(count);
        for _ in 0..count {
            let key = b.get(at..at + 32).ok_or_else(|| short("moving origin"))?;
            at += 32;
            let key = PubKey::new(key.try_into().unwrap());
            origins.push((key, read_domain(b, &mut at, "moving origin")?));
        }
        if at != b.len() {
            return Err(Error::Malformed("trailing bytes after a move".into()));
        }
        Ok(Moving {
            mv,
            domain,
            origins,
        })
    }
}

/// The answer to a Move: the exchange's clock, and whether the home named
/// is a peer it will serve -- so the client learns from the exchange that
/// will be asked, not from a silence later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moved {
    pub now: u64,
    pub peered: bool,
}

impl Moved {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.push(u8::from(self.peered));
        out
    }

    pub fn decode(b: &[u8]) -> Result<Moved> {
        if b.len() != 9 {
            return Err(Error::Malformed(format!(
                "moved is {} bytes, want 9",
                b.len()
            )));
        }
        Ok(Moved {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            peered: b[8] != 0,
        })
    }
}

/// The 32-byte ask of `/account/home`.
pub fn asked(b: &[u8]) -> Result<PubKey> {
    if b.len() != 32 {
        return Err(Error::Malformed(format!(
            "an account is 32 bytes, not {}",
            b.len()
        )));
    }
    Ok(PubKey::new(b.try_into().unwrap()))
}

/// Where an account lives, as one exchange has it on record. `since` is
/// the Move's `issued`, or zero where the answer is "here, as far as this
/// exchange knows" and no Move was ever presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Homed {
    pub home: PubKey,
    pub domain: String,
    pub since: u64,
}

impl Homed {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41 + self.domain.len());
        out.extend_from_slice(self.home.as_bytes());
        write_domain(&mut out, &self.domain);
        out.extend_from_slice(&self.since.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Homed> {
        let mut at = 0;
        let home = b.get(0..32).ok_or_else(|| short("homed"))?;
        at += 32;
        let home = PubKey::new(home.try_into().unwrap());
        let domain = read_domain(b, &mut at, "homed")?;
        let since = b.get(at..at + 8).ok_or_else(|| short("homed"))?;
        at += 8;
        if at != b.len() {
            return Err(Error::Malformed("trailing bytes after homed".into()));
        }
        Ok(Homed {
            home,
            domain,
            since: u64::from_be_bytes(since.try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn key(b: u8) -> ([u8; 32], PubKey) {
        let seed = [b; 32];
        let pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        (seed, PubKey::new(pk))
    }

    #[test]
    fn a_move_verifies_and_round_trips() {
        let (seed, account) = key(1);
        let (_, home) = key(2);
        let m = Move::sign(&seed, &home, 1_700_000_000);
        assert_eq!(m.account, account);
        assert!(m.verify());
        let back = Move::decode(&m.encode()).unwrap();
        assert_eq!(back, m);
        assert!(back.verify());
    }

    #[test]
    fn a_move_with_a_byte_flipped_does_not_verify() {
        let (seed, _) = key(1);
        let (_, home) = key(2);
        let mut m = Move::sign(&seed, &home, 7);
        m.issued += 1;
        assert!(!m.verify());
        let mut m = Move::sign(&seed, &home, 7);
        m.sig[3] ^= 1;
        assert!(!m.verify());
        let (_, other) = key(3);
        let mut m = Move::sign(&seed, &home, 7);
        m.home = other;
        assert!(!m.verify());
    }

    #[test]
    fn a_hardware_style_signature_is_the_same_move() {
        let (seed, account) = key(1);
        let (_, home) = key(2);
        let input = Move::to_sign(&account, &home, 9);
        let sig = SigningKey::from_bytes(&seed).sign(&input).to_bytes();
        let m = Move::from_signature(account, home, 9, sig);
        assert_eq!(m, Move::sign(&seed, &home, 9));
        assert!(m.verify());
    }

    #[test]
    fn a_moving_carries_its_hints_and_stops_at_sixteen() {
        let (seed, _) = key(1);
        let (_, home) = key(2);
        let mv = Move::sign(&seed, &home, 1);
        let origins: Vec<(PubKey, String)> = (10..26u8)
            .map(|b| (key(b).1, format!("ex{b}.example")))
            .collect();
        let moving = Moving {
            mv,
            domain: "home.example".into(),
            origins: origins.clone(),
        };
        let back = Moving::decode(&moving.encode()).unwrap();
        assert_eq!(back, moving);
        assert_eq!(back.origins.len(), 16);

        let mut too_many = moving.encode();
        // Patch the count past the limit and append one more.
        let count_at = MOVE_LEN + 1 + "home.example".len();
        too_many[count_at] = 17;
        too_many.extend_from_slice(key(99).1.as_bytes());
        too_many.push(0);
        assert!(Moving::decode(&too_many).is_err());

        let mut trailing = moving.encode();
        trailing.push(0);
        assert!(Moving::decode(&trailing).is_err());
        assert!(Moving::decode(&moving.encode()[..40]).is_err());
    }

    #[test]
    fn answers_round_trip() {
        let m = Moved {
            now: 5,
            peered: true,
        };
        assert_eq!(Moved::decode(&m.encode()).unwrap(), m);
        assert!(Moved::decode(&[0; 8]).is_err());
        let h = Homed {
            home: key(2).1,
            domain: "trunk.exchange".into(),
            since: 44,
        };
        assert_eq!(Homed::decode(&h.encode()).unwrap(), h);
        assert!(Homed::decode(&h.encode()[..35]).is_err());
        assert_eq!(asked(key(3).1.as_bytes()).unwrap(), key(3).1);
        assert!(asked(&[0; 31]).is_err());
    }
}
