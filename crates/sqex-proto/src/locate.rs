//! SIP-60: reaching someone at another exchange.
//!
//! A client asks its own exchange to find somebody by `label@domain`; the
//! exchange discovers the domain, resolves the label there, learns the
//! account's home and devices, and hands them back. The client holds one
//! connection, to its own exchange, and its exchange talks to the others --
//! SIP-39's shape, applied to a conversation's first message.

use sqnr_core::{Error, PubKey, Result};

use crate::device::Devices;

/// Longest `target` a locate carries: a 63-byte name or 44-byte key, an
/// `@`, and a domain -- with room to spare.
pub const MAX_TARGET: usize = 320;

/// `POST /account/locate`: `| len: u16 | target |`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locate {
    pub target: String,
}

impl Locate {
    pub fn encode(&self) -> Vec<u8> {
        let t = self.target.as_bytes();
        let n = t.len().min(MAX_TARGET);
        let mut out = Vec::with_capacity(2 + n);
        out.extend_from_slice(&(n as u16).to_be_bytes());
        out.extend_from_slice(&t[..n]);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Locate> {
        let short = || Error::Malformed("locate cut short".into());
        let n = u16::from_be_bytes(b.get(0..2).ok_or_else(short)?.try_into().unwrap()) as usize;
        if n > MAX_TARGET {
            return Err(Error::Malformed(format!(
                "a target is at most {MAX_TARGET} bytes, not {n}"
            )));
        }
        let t = b.get(2..2 + n).ok_or_else(short)?;
        if 2 + n != b.len() {
            return Err(Error::Malformed("trailing bytes after a locate".into()));
        }
        Ok(Locate {
            target: String::from_utf8(t.to_vec())
                .map_err(|_| Error::Malformed("target is not UTF-8".into()))?,
        })
    }

    /// `label@domain`, or nothing: a label with no domain is asked of the
    /// exchange the client is at, and is not a locate.
    pub fn split(&self) -> Option<(&str, &str)> {
        let (label, domain) = self.target.rsplit_once('@')?;
        if label.is_empty() || domain.is_empty() {
            return None;
        }
        Some((label, domain))
    }
}

/// The answer: the account, where it lives, and its devices as its home
/// lists them (credentials included, so the caller verifies them itself).
/// `| account[32] | home[32] | dom_len: u8 | domain | Devices |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub account: PubKey,
    pub home: PubKey,
    pub domain: String,
    pub devices: Devices,
}

impl Located {
    pub fn encode(&self) -> Vec<u8> {
        let d = self.domain.as_bytes();
        let n = d.len().min(255);
        let mut out = Vec::with_capacity(65 + n + 64);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(self.home.as_bytes());
        out.push(n as u8);
        out.extend_from_slice(&d[..n]);
        out.extend_from_slice(&self.devices.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Located> {
        let short = || Error::Malformed("located cut short".into());
        let account = PubKey::new(b.get(0..32).ok_or_else(short)?.try_into().unwrap());
        let home = PubKey::new(b.get(32..64).ok_or_else(short)?.try_into().unwrap());
        let n = *b.get(64).ok_or_else(short)? as usize;
        let domain = b.get(65..65 + n).ok_or_else(short)?;
        let devices = Devices::decode(b.get(65 + n..).ok_or_else(short)?)?;
        Ok(Located {
            account,
            home,
            domain: String::from_utf8(domain.to_vec())
                .map_err(|_| Error::Malformed("domain is not UTF-8".into()))?,
            devices,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locate_and_its_answer_round_trip() {
        let l = Locate {
            target: "bob@trunk.exchange".into(),
        };
        assert_eq!(Locate::decode(&l.encode()).unwrap(), l);
        assert_eq!(l.split(), Some(("bob", "trunk.exchange")));
        assert_eq!(
            Locate {
                target: "bob".into()
            }
            .split(),
            None
        );
        assert_eq!(
            Locate {
                target: "@x".into()
            }
            .split(),
            None
        );
        let mut trailing = l.encode();
        trailing.push(0);
        assert!(Locate::decode(&trailing).is_err());
        let mut long = vec![0u8; 2];
        long[1] = 0;
        long[0] = 2;
        long.extend(std::iter::repeat_n(b'a', 512));
        assert!(Locate::decode(&long).is_err());

        let seed = [3u8; 32];
        let device = PubKey::new([4; 32]);
        let credential = crate::credential::Credential::issue(
            &seed,
            &device,
            crate::credential::SCOPE_CHAT,
            1,
            9,
        )
        .unwrap();
        let found = Located {
            account: PubKey::new([1; 32]),
            home: PubKey::new([2; 32]),
            domain: "trunk.exchange".into(),
            devices: Devices {
                now: 7,
                devices: vec![crate::device::Device {
                    device,
                    added: 1,
                    not_after: 9,
                    credential: Some(credential),
                }],
            },
        };
        assert_eq!(Located::decode(&found.encode()).unwrap(), found);
        assert!(Located::decode(&found.encode()[..70]).is_err());
    }
}
