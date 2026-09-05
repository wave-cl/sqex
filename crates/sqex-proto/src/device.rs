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

use crate::credential::{Credential, REVOCATION_LEN, Revocation};

pub const TYPE_REGISTER: u8 = 0x01;
pub const TYPE_REVOKE: u8 = 0x02;
pub const TYPE_LIST: u8 = 0x03;
/// SIP-24: ask to be admitted to a whitelisted exchange.
pub const TYPE_ADMISSION: u8 = 0x04;

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
///
/// Two kinds, and SIP-32 requires an implementation to tell them apart:
///
/// - **Attested** — carrying a [`Revocation`] the account signed. Verifiable by
///   anybody holding the account key, with no reference to any exchange. This is
///   what somebody who has lost a device should produce.
/// - **Local** — `revocation` absent. SIP-22 lets any registered device of an
///   account revoke another subject to seniority, and lets a device sign itself
///   out; a device holds no account key and could not sign the artifact, and the
///   seniority rule that legitimises it is evaluated against `added` times only
///   the exchange holds. So it is correct here and worth nothing to anybody
///   repeating it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoke {
    pub device: PubKey,
    pub revocation: Option<Revocation>,
}

impl Revoke {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34 + REVOCATION_LEN);
        out.push(TYPE_REVOKE);
        out.extend_from_slice(self.device.as_bytes());
        match &self.revocation {
            Some(r) => {
                out.push(1);
                out.extend_from_slice(&r.encode());
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Revoke> {
        if b.len() < 34 || b[0] != TYPE_REVOKE {
            return Err(Error::Malformed(format!(
                "revoke is {} bytes, want at least 34",
                b.len()
            )));
        }
        let device = PubKey::new(b[1..33].try_into().unwrap());
        let revocation = match b[33] {
            0 if b.len() == 34 => None,
            1 if b.len() == 34 + REVOCATION_LEN => Some(Revocation::decode(&b[34..])?),
            _ => {
                return Err(Error::Malformed(format!(
                    "revoke is {} bytes and claims attested = {}",
                    b.len(),
                    b[33]
                )));
            }
        };
        // A revocation naming a device other than the one being revoked is not
        // evidence about this request, whatever it is evidence about.
        if let Some(r) = &revocation
            && r.device != device
        {
            return Err(Error::Malformed(
                "the revocation names a different device".into(),
            ));
        }
        Ok(Revoke { device, revocation })
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device: PubKey,
    pub added: u64,
    /// When its credential expires. A registration expires with it, and there
    /// is deliberately no second lifetime: two disagreeing ones would be a way
    /// for a peer verifying offline and an exchange resolving online to reach
    /// different conclusions about the same device.
    pub not_after: u64,
    /// The SIP-20 credential this registration rests on (SIP-32).
    ///
    /// **The exchange used to verify this and throw it away**, answering with
    /// its own summary — which meant SIP-31's second verification step, binding
    /// a device to the account an entry names, could not be performed by
    /// anybody. Retaining it grants nothing new: a credential names both keys in
    /// the clear to whoever verifies one, which is why SIP-22 already answers
    /// `List` to anybody.
    ///
    /// `None` for a registration made before this rule, which an exchange MUST
    /// report as such rather than inventing a credential or omitting the device.
    /// A client re-registers to supply it, which SIP-22 calls renewal.
    pub credential: Option<Credential>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Devices {
    pub now: u64,
    pub devices: Vec<Device>,
}

impl Devices {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.devices.len() * 200);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.devices.len() as u16).to_be_bytes());
        for d in &self.devices {
            out.extend_from_slice(d.device.as_bytes());
            out.extend_from_slice(&d.added.to_be_bytes());
            out.extend_from_slice(&d.not_after.to_be_bytes());
            // Length-prefixed, and zero where the exchange holds none: a
            // registration made before SIP-32 has a mapping and no artifact
            // behind it, and saying so is the honest answer.
            match &d.credential {
                Some(c) => {
                    let bytes = c.encode();
                    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(&bytes);
                }
                None => out.extend_from_slice(&0u16.to_be_bytes()),
            }
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
        let mut o = 10;
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            if b.len() < o + 50 {
                return Err(Error::Malformed("devices is truncated".into()));
            }
            let device = PubKey::new(b[o..o + 32].try_into().unwrap());
            let added = u64::from_be_bytes(b[o + 32..o + 40].try_into().unwrap());
            let not_after = u64::from_be_bytes(b[o + 40..o + 48].try_into().unwrap());
            let len = u16::from_be_bytes(b[o + 48..o + 50].try_into().unwrap()) as usize;
            o += 50;
            if b.len() < o + len {
                return Err(Error::Malformed("a device credential is truncated".into()));
            }
            let credential = if len == 0 {
                None
            } else {
                Some(Credential::decode(&b[o..o + len])?)
            };
            o += len;
            devices.push(Device {
                device,
                added,
                not_after,
                credential,
            });
        }
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "devices has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Devices {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            devices,
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
        let (account_seed, _) = identity(1);
        let (_, device) = identity(2);

        // Local: a client signing itself out, with nothing anybody can repeat.
        let local = Revoke {
            device,
            revocation: None,
        };
        assert_eq!(Revoke::decode(&local.encode()).unwrap(), local);

        // Attested: the account's own withdrawal, verifiable anywhere.
        let r = Revoke {
            device,
            revocation: Some(Revocation::issue(&account_seed, &device, 1000)),
        };
        assert_eq!(Revoke::decode(&r.encode()).unwrap(), r);

        // A revocation naming some other device is not evidence about this
        // request, whatever else it may be evidence about.
        let (_, other) = identity(3);
        let crossed = Revoke {
            device,
            revocation: Some(Revocation::issue(&account_seed, &other, 1000)),
        };
        assert!(Revoke::decode(&crossed.encode()).is_err());

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
                credential: Some(
                    Credential::issue(&identity(3).0, &a, SCOPE_CHAT, 0, 100).unwrap(),
                ),
            }],
        };
        assert_eq!(Devices::decode(&d.encode()).unwrap(), d);

        // A registration made before SIP-32 has a mapping and no artifact
        // behind it. The listing says so rather than inventing one.
        let bare = Devices {
            now: 5,
            devices: vec![Device {
                device: a,
                added: 1,
                not_after: 9,
                credential: None,
            }],
        };
        assert_eq!(Devices::decode(&bare.encode()).unwrap(), bare);

        let too_many = Devices {
            now: 5,
            devices: std::iter::repeat_n(
                Device {
                    device: a,
                    added: 1,
                    not_after: 9,
                    credential: None,
                },
                MAX_DEVICES + 1,
            )
            .collect(),
        };
        assert!(Devices::decode(&too_many.encode()).is_err());
    }
}

/// SIP-24: ask an exchange that will not serve you to admit you.
///
/// Nothing here is signed by the requester and nothing needs to be. The
/// connection already proves possession of the device key — MAC1 verified it
/// and SIP-2 exposes it — and the credential already proves the account
/// vouched for that key. A third signature would authenticate nothing that is
/// not authenticated, and would be one more thing to get wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub credential: Credential,
    /// Offered for an administrator to read. Attacker-chosen text shown at the
    /// moment of a security decision: the verifiable fact is the account key in
    /// the credential, and an interface MUST display that rather than let a
    /// label stand in for it.
    pub label: String,
}

impl AdmissionRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.credential.wire_len() + self.label.len());
        out.push(TYPE_ADMISSION);
        let c = self.credential.encode();
        out.extend_from_slice(&(c.len() as u16).to_be_bytes());
        out.extend_from_slice(&c);
        out.push(self.label.len() as u8);
        out.extend_from_slice(self.label.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<AdmissionRequest> {
        if b.len() < 4 || b[0] != TYPE_ADMISSION {
            return Err(Error::Malformed("not an admission request".into()));
        }
        let n = u16::from_be_bytes(b[1..3].try_into().unwrap()) as usize;
        if b.len() < 3 + n + 1 {
            return Err(Error::Malformed("admission request is truncated".into()));
        }
        let credential = Credential::decode(&b[3..3 + n])?;
        let label_len = b[3 + n] as usize;
        if b.len() != 4 + n + label_len {
            return Err(Error::Malformed(format!(
                "admission request is {} bytes, want {}",
                b.len(),
                4 + n + label_len
            )));
        }
        Ok(AdmissionRequest {
            credential,
            label: String::from_utf8(b[4 + n..].to_vec())
                .map_err(|_| Error::Malformed("label is not UTF-8".into()))?,
        })
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use crate::credential::SCOPE_CHAT;
    use ed25519_dalek::SigningKey;

    #[test]
    fn an_admission_request_round_trips() {
        let sk = SigningKey::from_bytes(&[1; 32]);
        let (_, device) = {
            let d = SigningKey::from_bytes(&[2; 32]);
            (d.to_bytes(), PubKey::new(d.verifying_key().to_bytes()))
        };
        let r = AdmissionRequest {
            credential: Credential::issue(&sk.to_bytes(), &device, SCOPE_CHAT, 1, 2).unwrap(),
            label: "Colin's laptop".into(),
        };
        assert_eq!(AdmissionRequest::decode(&r.encode()).unwrap(), r);

        let empty = AdmissionRequest {
            label: String::new(),
            ..r
        };
        assert_eq!(AdmissionRequest::decode(&empty.encode()).unwrap(), empty);
    }
}
