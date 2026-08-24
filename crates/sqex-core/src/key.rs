//! Ed25519 public keys, base58-encoded — the identity every admin and peer is
//! named by, the same form sQUIC pins and sqssh/sqns use.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::VerifyingKey;

use crate::error::{Error, Result};

/// An Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PubKey([u8; 32]);

impl PubKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// First 8 base58 characters — for logs, never for identity decisions.
    pub fn short(&self) -> String {
        self.to_base58().chars().take(8).collect()
    }

    /// The Ed25519 verifying key, or an error if the bytes are not a valid
    /// point. Checked lazily so a `PubKey` can name a key without paying the
    /// decompression until a signature is actually verified.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0)
            .map_err(|e| Error::Key(format!("not a valid Ed25519 public key: {e}")))
    }

    pub fn from_base58(s: &str) -> Result<Self> {
        let raw = bs58::decode(s)
            .into_vec()
            .map_err(|e| Error::Key(format!("bad base58: {e}")))?;
        Self::from_slice(&raw)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s).map_err(|e| Error::Key(format!("bad hex: {e}")))?;
        Self::from_slice(&raw)
    }

    fn from_slice(raw: &[u8]) -> Result<Self> {
        if raw.len() != 32 {
            return Err(Error::Key(format!(
                "public key must be 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        Ok(Self(out))
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl FromStr for PubKey {
    type Err = Error;

    /// Accepts base58 (canonical) or 64 hex characters.
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Self::from_hex(s)
        } else {
            Self::from_base58(s)
        }
    }
}

impl From<VerifyingKey> for PubKey {
    fn from(vk: VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trip() {
        let k = PubKey::new([7u8; 32]);
        let s = k.to_base58();
        assert_eq!(PubKey::from_base58(&s).unwrap(), k);
        assert_eq!(s.parse::<PubKey>().unwrap(), k);
    }

    #[test]
    fn hex_parse() {
        let k = PubKey::new([0xabu8; 32]);
        assert_eq!(k.to_bytes(), [0xab; 32]);
        let hexed = hex::encode([0xab_u8; 32]);
        assert_eq!(hexed.parse::<PubKey>().unwrap(), k);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(PubKey::from_base58(&bs58::encode([1u8; 31]).into_string()).is_err());
    }
}
