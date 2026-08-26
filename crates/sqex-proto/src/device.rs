//! SIP-22 device registry: whose client is this, and can it still be one.
//!
//! SIP-20's credential is verifiable by anybody with no prior record, which is
//! right for a peer checking a message it has just received and leaves two
//! things undone. A connection arrives carrying a device identity and a service
//! needs an account — it could be told once instead of shown a credential on
//! every request. And a credential cannot be withdrawn: `not_after` is the
//! whole mechanism, which is useless to somebody whose laptop was stolen this
//! morning. A revocation list has to live where it can be reached, and this is
//! that party.

use sqnr_core::{Error, PubKey, Result};

use crate::credential::Credential;

pub const TYPE_REGISTER: u8 = 0x01;
pub const TYPE_REVOKE: u8 = 0x02;
pub const TYPE_LIST: u8 = 0x03;

/// Devices one account may have registered.
///
/// A limit on a person rather than on a protocol. It bounds SIP-17's envelope
/// arithmetic, where recipients are devices: a 256-account channel at eight
/// devices each is 2 048 envelopes on a rotation.
pub const MAX_DEVICES: usize = 8;
/// Registrations one account may make per hour.
pub const MAX_REGISTRATIONS_PER_HOUR: usize = 16;

/// Present a credential and be mapped to the account that signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub credential: Credential,
}

impl Register {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.credential.wire_len());
        out.push(TYPE_REGISTER);
        out.extend_from_slice(&self.credential.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Register> {
        if b.is_empty() || b[0] != TYPE_REGISTER {
            return Err(Error::Malformed("not a register".into()));
        }
        Ok(Register {
            credential: Credential::decode(&b[1..])?,
        })
    }
}

/// Stop the exchange resolving a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoke {
    pub device: PubKey,
}

impl Revoke {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_REVOKE);
        out.extend_from_slice(self.device.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Revoke> {
        if b.len() != 33 || b[0] != TYPE_REVOKE {
            return Err(Error::Malformed(format!(
                "revoke is {} bytes, want 33",
                b.len()
            )));
        }
        Ok(Revoke {
            device: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// Ask what an account's devices are. Answerable to anybody: the mapping is
/// public by construction, since every credential carries both keys in the
/// clear to whoever verifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListDevices {
    pub account: PubKey,
}

impl ListDevices {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_LIST);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<ListDevices> {
        if b.len() != 33 || b[0] != TYPE_LIST {
            return Err(Error::Malformed(format!(
                "list is {} bytes, want 33",
                b.len()
            )));
        }
        Ok(ListDevices {
            account: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    pub device: PubKey,
    pub added: u64,
    /// When its credential expires. A registration expires with it, and there
    /// is deliberately no second lifetime: two disagreeing ones would be a way
    /// for a peer verifying offline and an exchange resolving online to reach
    /// different conclusions about the same device.
    pub not_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Devices {
    pub now: u64,
    pub devices: Vec<Device>,
}

impl Devices {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.devices.len() * 48);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.devices.len() as u16).to_be_bytes());
        for d in &self.devices {
            out.extend_from_slice(d.device.as_bytes());
            out.extend_from_slice(&d.added.to_be_bytes());
            out.extend_from_slice(&d.not_after.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Devices> {
        if b.len() < 10 {
            return Err(Error::Malformed(format!(
                "devices is {} bytes, want at least 10",
                b.len()
            )));
        }
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap()) as usize;
        if count > MAX_DEVICES {
            return Err(Error::Malformed(format!(
                "devices lists {count}, limit is {MAX_DEVICES}"
            )));
        }
        if b.len() != 10 + count * 48 {
            return Err(Error::Malformed(format!(
                "devices is {} bytes, want {}",
                b.len(),
                10 + count * 48
            )));
        }
        Ok(Devices {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            devices: (0..count)
                .map(|i| {
                    let at = 10 + i * 48;
                    Device {
                        device: PubKey::new(b[at..at + 32].try_into().unwrap()),
                        added: u64::from_be_bytes(b[at + 32..at + 40].try_into().unwrap()),
                        not_after: u64::from_be_bytes(b[at + 40..at + 48].try_into().unwrap()),
                    }
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::SCOPE_CHAT;
    use ed25519_dalek::SigningKey;

    fn identity(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    #[test]
    fn register_round_trips_with_its_credential() {
        let (account_seed, _) = identity(1);
        let (_, device) = identity(2);
        let r = Register {
            credential: Credential::issue(&account_seed, &device, SCOPE_CHAT, 1, 2).unwrap(),
        };
        assert_eq!(Register::decode(&r.encode()).unwrap(), r);
    }

    #[test]
    fn revoke_and_list_round_trip() {
        let (_, device) = identity(2);
        let r = Revoke { device };
        assert_eq!(Revoke::decode(&r.encode()).unwrap(), r);
        let l = ListDevices { account: device };
        assert_eq!(ListDevices::decode(&l.encode()).unwrap(), l);
    }

    #[test]
    fn devices_round_trip_and_bound_their_count() {
        let (_, a) = identity(3);
        let d = Devices {
            now: 5,
            devices: vec![Device {
                device: a,
                added: 1,
                not_after: 9,
            }],
        };
        assert_eq!(Devices::decode(&d.encode()).unwrap(), d);

        let too_many = Devices {
            now: 5,
            devices: std::iter::repeat_n(
                Device {
                    device: a,
                    added: 1,
                    not_after: 9,
                },
                MAX_DEVICES + 1,
            )
            .collect(),
        };
        assert!(Devices::decode(&too_many.encode()).is_err());
    }
}
