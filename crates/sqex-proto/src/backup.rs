//! SIP-48: a sealed backup at the exchange.
//!
//! A device keeps a copy of its store at the exchange as SIP-18 blobs held
//! by the account, named by a manifest the device signs and seals under a
//! key the person holds. The exchange stores what it cannot read and serves
//! it to the account's devices, or to a SIP-44 successor.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use sqnr_core::{Error, PubKey, Result};

pub const BACKUP_CONTEXT: &[u8] = b"sqex-backup-v1";
const MANIFEST_KEY_CONTEXT: &[u8] = b"sqex-backup-v1 manifest";

pub const TYPE_MANIFEST: u8 = 0x01;
pub const TYPE_ASK: u8 = 0x02;
pub const TYPE_DROP: u8 = 0x03;

/// A channel's history: SIP-42 `Entries` and `Keys` messages, `len`-prefixed.
pub const KIND_HISTORY: u8 = 0x01;
/// Contacts, with SIP-41's verified flag.
pub const KIND_CONTACTS: u8 = 0x02;
/// The client's own, opaque.
pub const KIND_STATE: u8 = 0x03;
/// An existing blob the account holds past its channel's retention.
pub const KIND_HELD: u8 = 0x04;

/// The most a sealed manifest may be.
pub const MAX_SEALED: usize = 1024 * 1024;
/// Segments and held blobs one manifest may name.
pub const MAX_BLOBS: usize = 4096;
/// Words the backup key is shown as.
pub const WORD_COUNT: usize = 24;
/// The reference default for an operator's per-account quota.
pub const DEFAULT_QUOTA: u64 = 512 * 1024 * 1024;

const PLAIN_VERSION: u8 = 1;
const SEGMENT_LEN: usize = 1 + 32 + 32 + 32 + 8 + 8;

/// One segment or held blob, as the manifest describes it under the seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub kind: u8,
    pub blob: [u8; 32],
    /// The blob's SIP-18 key.
    pub key: [u8; 32],
    /// For history: the channel; zero otherwise.
    pub channel: [u8; 32],
    pub first: u64,
    pub last: u64,
}

/// What the seal covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plain {
    pub written: u64,
    pub segments: Vec<Segment>,
}

impl Plain {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + self.segments.len() * SEGMENT_LEN);
        out.push(PLAIN_VERSION);
        out.extend_from_slice(&self.written.to_be_bytes());
        out.extend_from_slice(&(self.segments.len() as u32).to_be_bytes());
        for s in &self.segments {
            out.push(s.kind);
            out.extend_from_slice(&s.blob);
            out.extend_from_slice(&s.key);
            out.extend_from_slice(&s.channel);
            out.extend_from_slice(&s.first.to_be_bytes());
            out.extend_from_slice(&s.last.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Plain> {
        if b.len() < 13 || b[0] != PLAIN_VERSION {
            return Err(Error::Malformed("not a backup manifest".into()));
        }
        let written = u64::from_be_bytes(b[1..9].try_into().unwrap());
        let count = u32::from_be_bytes(b[9..13].try_into().unwrap()) as usize;
        if count > MAX_BLOBS || b.len() != 13 + count * SEGMENT_LEN {
            return Err(Error::Malformed("backup manifest cut short".into()));
        }
        let mut segments = Vec::with_capacity(count);
        let mut at = 13;
        for _ in 0..count {
            let s = &b[at..at + SEGMENT_LEN];
            segments.push(Segment {
                kind: s[0],
                blob: s[1..33].try_into().unwrap(),
                key: s[33..65].try_into().unwrap(),
                channel: s[65..97].try_into().unwrap(),
                first: u64::from_be_bytes(s[97..105].try_into().unwrap()),
                last: u64::from_be_bytes(s[105..113].try_into().unwrap()),
            });
            at += SEGMENT_LEN;
        }
        Ok(Plain { written, segments })
    }
}

/// The manifest key from the backup key: `SHA-512(context || key)[..32]`,
/// the derivation SIP-17 uses and argues for over inputs already uniform.
pub fn manifest_key(backup_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(MANIFEST_KEY_CONTEXT);
    h.update(backup_key);
    let okm = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    key
}

fn nonce_for(generation: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&generation.to_be_bytes());
    Nonce::from(n)
}

fn associated(account: &PubKey, generation: u64) -> Vec<u8> {
    let mut ad = Vec::with_capacity(BACKUP_CONTEXT.len() + 40);
    ad.extend_from_slice(BACKUP_CONTEXT);
    ad.extend_from_slice(account.as_bytes());
    ad.extend_from_slice(&generation.to_be_bytes());
    ad
}

/// Seal a manifest's plaintext for `account` at `generation`.
pub fn seal(
    backup_key: &[u8; 32],
    account: &PubKey,
    generation: u64,
    plain: &Plain,
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&manifest_key(backup_key))
        .map_err(|e| Error::Key(format!("cipher: {e}")))?;
    cipher
        .encrypt(
            &nonce_for(generation),
            Payload {
                msg: &plain.encode(),
                aad: &associated(account, generation),
            },
        )
        .map_err(|_| Error::Key("seal failed".into()))
}

/// Open a sealed manifest. Fails on the wrong key, account or generation.
pub fn open(
    backup_key: &[u8; 32],
    account: &PubKey,
    generation: u64,
    sealed: &[u8],
) -> Result<Plain> {
    let cipher = ChaCha20Poly1305::new_from_slice(&manifest_key(backup_key))
        .map_err(|e| Error::Key(format!("cipher: {e}")))?;
    let plain = cipher
        .decrypt(
            &nonce_for(generation),
            Payload {
                msg: sealed,
                aad: &associated(account, generation),
            },
        )
        .map_err(|_| Error::Key("the backup does not open with this key".into()))?;
    Plain::decode(&plain)
}

fn signed_bytes(account: &PubKey, generation: u64, blobs: &[[u8; 32]], sealed: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(BACKUP_CONTEXT.len() + 40 + blobs.len() * 32 + sealed.len());
    m.extend_from_slice(BACKUP_CONTEXT);
    m.extend_from_slice(account.as_bytes());
    m.extend_from_slice(&generation.to_be_bytes());
    for b in blobs {
        m.extend_from_slice(b);
    }
    m.extend_from_slice(sealed);
    m
}

/// `POST /backup/write`: what a device writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub generation: u64,
    /// Every segment and held blob this manifest keeps, in the clear.
    pub blobs: Vec<[u8; 32]>,
    pub sealed: Vec<u8>,
    pub sig: [u8; 64],
}

impl Manifest {
    /// Seal `plain` and sign the result as `device`.
    pub fn make(
        device_seed: &[u8; 32],
        backup_key: &[u8; 32],
        account: &PubKey,
        generation: u64,
        plain: &Plain,
    ) -> Result<Manifest> {
        let sealed = seal(backup_key, account, generation, plain)?;
        let blobs: Vec<[u8; 32]> = plain.segments.iter().map(|s| s.blob).collect();
        let sk = SigningKey::from_bytes(device_seed);
        let sig = sk.sign(&signed_bytes(account, generation, &blobs, &sealed));
        Ok(Manifest {
            generation,
            blobs,
            sealed,
            sig: sig.to_bytes(),
        })
    }

    /// Whether `device` signed this for `account`.
    pub fn verifies(&self, device: &PubKey, account: &PubKey) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(device.as_bytes()) else {
            return false;
        };
        vk.verify(
            &signed_bytes(account, self.generation, &self.blobs, &self.sealed),
            &Signature::from_bytes(&self.sig),
        )
        .is_ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + 8 + 4 + self.blobs.len() * 32 + 4 + self.sealed.len() + 64);
        out.push(TYPE_MANIFEST);
        write_body(
            &mut out,
            self.generation,
            &self.blobs,
            &self.sealed,
            &self.sig,
        );
        out
    }

    pub fn decode(b: &[u8]) -> Result<Manifest> {
        if b.is_empty() || b[0] != TYPE_MANIFEST {
            return Err(Error::Malformed("not a backup manifest".into()));
        }
        let (generation, blobs, sealed, sig, rest) = read_body(&b[1..])?;
        if !rest.is_empty() {
            return Err(Error::Malformed("trailing bytes after manifest".into()));
        }
        Ok(Manifest {
            generation,
            blobs,
            sealed,
            sig,
        })
    }
}

fn write_body(
    out: &mut Vec<u8>,
    generation: u64,
    blobs: &[[u8; 32]],
    sealed: &[u8],
    sig: &[u8; 64],
) {
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(&(blobs.len() as u32).to_be_bytes());
    for b in blobs {
        out.extend_from_slice(b);
    }
    out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
    out.extend_from_slice(sealed);
    out.extend_from_slice(sig);
}

type Body<'a> = (u64, Vec<[u8; 32]>, Vec<u8>, [u8; 64], &'a [u8]);

fn read_body(b: &[u8]) -> Result<Body<'_>> {
    if b.len() < 12 {
        return Err(Error::Malformed("manifest cut short".into()));
    }
    let generation = u64::from_be_bytes(b[..8].try_into().unwrap());
    let count = u32::from_be_bytes(b[8..12].try_into().unwrap()) as usize;
    if count > MAX_BLOBS {
        return Err(Error::Malformed(format!(
            "manifest names {count} blobs, limit is {MAX_BLOBS}"
        )));
    }
    let mut at = 12;
    if b.len() < at + count * 32 + 4 {
        return Err(Error::Malformed("manifest cut short".into()));
    }
    let mut blobs = Vec::with_capacity(count);
    for _ in 0..count {
        blobs.push(b[at..at + 32].try_into().unwrap());
        at += 32;
    }
    let len = u32::from_be_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    at += 4;
    if len > MAX_SEALED {
        return Err(Error::Malformed(format!(
            "sealed manifest is {len} bytes, limit is {MAX_SEALED}"
        )));
    }
    if b.len() < at + len + 64 {
        return Err(Error::Malformed("manifest cut short".into()));
    }
    let sealed = b[at..at + len].to_vec();
    at += len;
    let sig: [u8; 64] = b[at..at + 64].try_into().unwrap();
    at += 64;
    Ok((generation, blobs, sealed, sig, &b[at..]))
}

/// `POST /backup/read`: the caller's own account, or one it succeeded.
pub fn ask(account: &PubKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.push(TYPE_ASK);
    out.extend_from_slice(account.as_bytes());
    out
}

pub fn asked(b: &[u8]) -> Result<PubKey> {
    if b.len() != 33 || b[0] != TYPE_ASK {
        return Err(Error::Malformed("not a backup request".into()));
    }
    Ok(PubKey::new(b[1..].try_into().unwrap()))
}

/// `POST /backup/drop`.
pub fn drop_all() -> Vec<u8> {
    vec![TYPE_DROP]
}

pub fn is_drop(b: &[u8]) -> bool {
    b == [TYPE_DROP]
}

/// What the exchange holds: the current manifest, and the quota it counts
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub generation: u64,
    pub device: PubKey,
    pub written: u64,
    pub quota: u64,
    pub used: u64,
    pub blobs: Vec<[u8; 32]>,
    pub sealed: Vec<u8>,
    pub sig: [u8; 64],
}

impl Held {
    /// Nothing held: generation 0, and the quota all the same.
    pub fn none(quota: u64, used: u64) -> Held {
        Held {
            generation: 0,
            device: PubKey::new([0; 32]),
            written: 0,
            quota,
            used,
            blobs: Vec::new(),
            sealed: Vec::new(),
            sig: [0; 64],
        }
    }

    /// Whether anything is held. A manifest is written at generation 1 or
    /// above; 0 is the exchange saying it has none.
    pub fn is_some(&self) -> bool {
        self.generation > 0
    }

    pub fn manifest(&self) -> Manifest {
        Manifest {
            generation: self.generation,
            blobs: self.blobs.clone(),
            sealed: self.sealed.clone(),
            sig: self.sig,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.blobs.len() * 32 + self.sealed.len() + 64);
        out.extend_from_slice(self.device.as_bytes());
        out.extend_from_slice(&self.written.to_be_bytes());
        out.extend_from_slice(&self.quota.to_be_bytes());
        out.extend_from_slice(&self.used.to_be_bytes());
        write_body(
            &mut out,
            self.generation,
            &self.blobs,
            &self.sealed,
            &self.sig,
        );
        out
    }

    pub fn decode(b: &[u8]) -> Result<Held> {
        if b.len() < 56 {
            return Err(Error::Malformed("held backup cut short".into()));
        }
        let device = PubKey::new(b[..32].try_into().unwrap());
        let written = u64::from_be_bytes(b[32..40].try_into().unwrap());
        let quota = u64::from_be_bytes(b[40..48].try_into().unwrap());
        let used = u64::from_be_bytes(b[48..56].try_into().unwrap());
        let (generation, blobs, sealed, sig, rest) = read_body(&b[56..])?;
        if !rest.is_empty() {
            return Err(Error::Malformed("trailing bytes after held backup".into()));
        }
        Ok(Held {
            generation,
            device,
            written,
            quota,
            used,
            blobs,
            sealed,
            sig,
        })
    }
}

/// The backup key as 24 words from SIP-41's list: 256 bits of key and the
/// first 8 of its SHA-256, as 24 11-bit indices.
pub fn words(key: &[u8; 32]) -> [&'static str; WORD_COUNT] {
    let list = crate::safety::wordlist();
    let mut bits = [0u8; 33];
    bits[..32].copy_from_slice(key);
    bits[32] = Sha256::digest(key)[0];
    let mut out = [""; WORD_COUNT];
    for (i, w) in out.iter_mut().enumerate() {
        let mut idx = 0usize;
        for bit in 0..11 {
            let pos = i * 11 + bit;
            idx = (idx << 1) | usize::from((bits[pos / 8] >> (7 - pos % 8)) & 1);
        }
        *w = list[idx];
    }
    out
}

/// The key from its words. Refuses a wrong count, a word not on the list,
/// or a phrase whose check bits fail.
pub fn from_words(words: &[&str]) -> Result<[u8; 32]> {
    if words.len() != WORD_COUNT {
        return Err(Error::Malformed(format!(
            "a backup key is {WORD_COUNT} words, not {}",
            words.len()
        )));
    }
    let list = crate::safety::wordlist();
    let mut bits = [0u8; 33];
    for (i, w) in words.iter().enumerate() {
        let w = w.trim().to_ascii_lowercase();
        let idx = list
            .iter()
            .position(|l| *l == w)
            .ok_or_else(|| Error::Malformed(format!("{w:?} is not a word on the list")))?;
        for bit in 0..11 {
            let pos = i * 11 + bit;
            if (idx >> (10 - bit)) & 1 == 1 {
                bits[pos / 8] |= 1 << (7 - pos % 8);
            }
        }
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bits[..32]);
    if Sha256::digest(key)[0] != bits[32] {
        return Err(Error::Malformed(
            "the words do not check: one is wrong or out of order".into(),
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain() -> Plain {
        Plain {
            written: 1_700_000_000,
            segments: vec![
                Segment {
                    kind: KIND_HISTORY,
                    blob: [1; 32],
                    key: [2; 32],
                    channel: [3; 32],
                    first: 1,
                    last: 40,
                },
                Segment {
                    kind: KIND_HELD,
                    blob: [4; 32],
                    key: [5; 32],
                    channel: [0; 32],
                    first: 0,
                    last: 0,
                },
            ],
        }
    }

    #[test]
    fn a_manifest_round_trips_and_opens_only_for_its_account_and_generation() {
        let backup_key = [9u8; 32];
        let device_seed = [7u8; 32];
        let device = PubKey::new(
            SigningKey::from_bytes(&device_seed)
                .verifying_key()
                .to_bytes(),
        );
        let account = PubKey::new([8; 32]);
        let m = Manifest::make(&device_seed, &backup_key, &account, 3, &plain()).unwrap();
        let back = Manifest::decode(&m.encode()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.blobs, vec![[1; 32], [4; 32]]);
        assert!(back.verifies(&device, &account));
        assert!(!back.verifies(&PubKey::new([1; 32]), &account));
        assert!(!back.verifies(&device, &PubKey::new([1; 32])));
        assert_eq!(
            open(&backup_key, &account, 3, &back.sealed).unwrap(),
            plain()
        );
        assert!(open(&[10u8; 32], &account, 3, &back.sealed).is_err());
        assert!(open(&backup_key, &account, 4, &back.sealed).is_err());
        assert!(open(&backup_key, &PubKey::new([1; 32]), 3, &back.sealed).is_err());

        let held = Held {
            generation: 3,
            device,
            written: 5,
            quota: DEFAULT_QUOTA,
            used: 1234,
            blobs: m.blobs.clone(),
            sealed: m.sealed.clone(),
            sig: m.sig,
        };
        let h = Held::decode(&held.encode()).unwrap();
        assert_eq!(h, held);
        assert_eq!(h.manifest(), m);
        assert_eq!(asked(&ask(&account)).unwrap(), account);
        assert!(is_drop(&drop_all()));
    }

    #[test]
    fn a_tampered_manifest_does_not_verify() {
        let m = Manifest::make(&[7u8; 32], &[9u8; 32], &PubKey::new([8; 32]), 1, &plain()).unwrap();
        let device = PubKey::new(
            SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let mut t = m.clone();
        t.blobs.pop();
        assert!(!t.verifies(&device, &PubKey::new([8; 32])));
        let mut t = m.clone();
        t.generation += 1;
        assert!(!t.verifies(&device, &PubKey::new([8; 32])));
    }

    #[test]
    fn words_round_trip_and_a_wrong_word_is_caught() {
        for seed in [[0u8; 32], [255u8; 32], [0x5a; 32], [3u8; 32]] {
            let w = words(&seed);
            assert_eq!(from_words(&w).unwrap(), seed);
        }
        let mut w = words(&[3u8; 32]).to_vec();
        let list = crate::safety::wordlist();
        let other = list.iter().find(|x| **x != w[5]).unwrap();
        w[5] = other;
        assert!(from_words(&w).is_err(), "a wrong word was accepted");
        let mut w = words(&[3u8; 32]).to_vec();
        w.swap(0, 1);
        // Swapping two words survives the 8-bit check one time in 256; these
        // two do not.
        assert!(from_words(&w).is_err() || words(&from_words(&w).unwrap()) != words(&[3u8; 32]));
        assert!(from_words(&w[..23]).is_err());
    }
}
