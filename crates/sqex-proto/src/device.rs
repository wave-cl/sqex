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
/// SIP-60 §Saying whose list it is: list an account's devices and say whose list it is.
pub const TYPE_LIST_FROM: u8 = 0x05;
/// SIP-89 §When it cannot be resolved: ask what an account has revoked.
pub const TYPE_LIST_REVOKED: u8 = 0x06;

/// SIP-60 §Saying whose list it is `DevicesFrom::from`: this exchange's own registry -- the
/// account's home is here, or nowhere on record.
pub const FROM_HERE: u8 = 0x00;
/// SIP-60 §Saying whose list it is: the home's answer, fresh or kept within SIP-60 §Caching's `DEVICES_TTL`.
pub const FROM_HOME: u8 = 0x01;
/// SIP-60 §Saying whose list it is: this exchange's own registry for an account that lives
/// elsewhere, because the home could not be asked. A snapshot from before
/// the account left: not a list to seal a key to.
pub const FROM_STALE: u8 = 0x02;

/// Devices one account may have registered.
///
/// A limit on a person rather than on a protocol. It bounds SIP-17's envelope
/// arithmetic, where recipients are devices: a 256-account channel at eight
/// devices each is 2 048 envelopes on a rotation.
pub const MAX_DEVICES: usize = 8;
/// A bound on a revocation listing. Larger than [`MAX_DEVICES`] because
/// revocations accumulate over an account's life where live devices do not,
/// and kept finite because a decoder that trusts a length is a decoder that
/// allocates whatever a stranger says.
pub const MAX_REVOKED: usize = 256;
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

/// Ask what an account has revoked: `POST /device/list` with
/// `| type = 0x06 | account[32] |`, answered with [`Revoked`].
///
/// **Answerable to anybody, for the reason [`ListDevices`] already is**: a
/// revocation names both keys in the clear to whoever verifies one, exactly
/// as a credential does, so serving it discloses nothing the device list did
/// not. The same route, dispatched on the type byte; an exchange from before
/// this refuses it as malformed and a caller falls back.
///
/// SIP-89 §When it cannot be resolved needs this and nothing else does yet: a
/// reader holding a quote whose post was signed by a device the account no
/// longer lists must say **unverifiable** rather than **forged**, and without
/// the revocations "revoked since" and "never registered" are one observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListRevoked {
    pub account: PubKey,
}

impl ListRevoked {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_LIST_REVOKED);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<ListRevoked> {
        if b.len() != 33 || b[0] != TYPE_LIST_REVOKED {
            return Err(Error::Malformed(format!(
                "list-revoked is {} bytes, want 33",
                b.len()
            )));
        }
        Ok(ListRevoked {
            account: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// One device an account has withdrawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawn {
    pub device: PubKey,
    /// When this exchange recorded it. **The exchange's clock and not the
    /// account's**, so it is not signed and must not be presented as the
    /// moment the account acted; the signed `issued` is inside `revocation`
    /// where there is one.
    pub at: u64,
    /// The account's own signed revocation, where this exchange kept one.
    ///
    /// `None` for a row recorded before revocations were retained, and for
    /// one carried between exchanges without its artifact. A reader that
    /// cannot check the signature has only this exchange's word — which is
    /// why the state it leads to is *unverifiable* and never *forged*: an
    /// exchange that invented a revocation could withhold a post, which it
    /// can do anyway, and could not make one verify as somebody else's.
    pub revocation: Option<Revocation>,
}

/// What an account has revoked, as this exchange has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    pub now: u64,
    pub rows: Vec<Withdrawn>,
}

impl Revoked {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.rows.len() * (40 + REVOCATION_LEN));
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.rows.len() as u16).to_be_bytes());
        for r in &self.rows {
            out.extend_from_slice(r.device.as_bytes());
            out.extend_from_slice(&r.at.to_be_bytes());
            // Length-prefixed and zero where none is held, as `Devices` does
            // it for a credential and for the same reason: an absent artifact
            // is a fact to report, not a row to omit.
            match &r.revocation {
                Some(v) => {
                    let bytes = v.encode();
                    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    out.extend_from_slice(&bytes);
                }
                None => out.extend_from_slice(&0u16.to_be_bytes()),
            }
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Revoked> {
        if b.len() < 10 {
            return Err(Error::Malformed(format!(
                "revoked is {} bytes, want at least 10",
                b.len()
            )));
        }
        let now = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap()) as usize;
        if count > MAX_REVOKED {
            return Err(Error::Malformed(format!(
                "revoked names {count} devices, at most {MAX_REVOKED}"
            )));
        }
        let mut rows = Vec::with_capacity(count);
        let mut i = 10;
        for _ in 0..count {
            if b.len() < i + 42 {
                return Err(Error::Malformed("revoked ends inside a row".into()));
            }
            let device = PubKey::new(b[i..i + 32].try_into().unwrap());
            let at = u64::from_be_bytes(b[i + 32..i + 40].try_into().unwrap());
            let len = u16::from_be_bytes(b[i + 40..i + 42].try_into().unwrap()) as usize;
            i += 42;
            if b.len() < i + len {
                return Err(Error::Malformed("revoked ends inside a revocation".into()));
            }
            let revocation = if len == 0 {
                None
            } else {
                Some(Revocation::decode(&b[i..i + len])?)
            };
            i += len;
            rows.push(Withdrawn {
                device,
                at,
                revocation,
            });
        }
        Ok(Revoked { now, rows })
    }
}

/// SIP-44 §Which account a device is: `GET /device/account`, the account the caller's transport
/// identity is registered to, and the identity itself -- the caller's own
/// key twice where it is registered to nobody.
/// `| account[32] | device[32] |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Whose {
    pub account: PubKey,
    pub device: PubKey,
}

impl Whose {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(self.device.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Whose> {
        if b.len() != 64 {
            return Err(Error::Malformed(format!(
                "whose is {} bytes, want 64",
                b.len()
            )));
        }
        Ok(Whose {
            account: PubKey::new(b[0..32].try_into().unwrap()),
            device: PubKey::new(b[32..64].try_into().unwrap()),
        })
    }
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

/// SIP-60 §Saying whose list it is: `POST /device/list` with `| type = 0x05 | account[32] |`,
/// answered with [`DevicesFrom`]. The same route as [`ListDevices`],
/// dispatched on the type byte; an exchange from before sqex 0.100.0 refuses it
/// as malformed and a client falls back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListDevicesFrom {
    pub account: PubKey,
}

impl ListDevicesFrom {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_LIST_FROM);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<ListDevicesFrom> {
        if b.len() != 33 || b[0] != TYPE_LIST_FROM {
            return Err(Error::Malformed(format!(
                "list-from is {} bytes, want 33",
                b.len()
            )));
        }
        Ok(ListDevicesFrom {
            account: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// SIP-60 §Saying whose list it is: `| from: u8 | Devices |` -- whose list this is, then SIP-22's
/// list exactly as `ListDevices` would have been answered. A new answer
/// type rather than a field on `Devices`, as SIP-34 requires: `Devices`
/// refuses trailing bytes, and so does this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicesFrom {
    pub from: u8,
    pub devices: Devices,
}

impl DevicesFrom {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 10 + self.devices.devices.len() * 200);
        out.push(self.from);
        out.extend_from_slice(&self.devices.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<DevicesFrom> {
        let Some(&from) = b.first() else {
            return Err(Error::Malformed("devices-from is empty".into()));
        };
        if from > FROM_STALE {
            return Err(Error::Malformed(format!(
                "devices-from {from} is not a kind of list"
            )));
        }
        Ok(DevicesFrom {
            from,
            devices: Devices::decode(&b[1..])?,
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
    fn a_list_from_says_whose_it_is() {
        let (_, a) = identity(3);
        let ask = ListDevicesFrom { account: a };
        assert_eq!(ListDevicesFrom::decode(&ask.encode()).unwrap(), ask);
        // One type byte does not read as the other.
        assert!(ListDevices::decode(&ask.encode()).is_err());
        assert!(ListDevicesFrom::decode(&ListDevices { account: a }.encode()).is_err());

        let list = Devices {
            now: 5,
            devices: vec![Device {
                device: a,
                added: 1,
                not_after: 9,
                credential: None,
            }],
        };
        for from in [FROM_HERE, FROM_HOME, FROM_STALE] {
            let d = DevicesFrom {
                from,
                devices: list.clone(),
            };
            assert_eq!(DevicesFrom::decode(&d.encode()).unwrap(), d);
        }
        let mut bad = DevicesFrom {
            from: FROM_STALE,
            devices: list.clone(),
        }
        .encode();
        bad[0] = 3;
        assert!(DevicesFrom::decode(&bad).is_err());
        assert!(DevicesFrom::decode(&[]).is_err());
        let mut long = DevicesFrom {
            from: FROM_HOME,
            devices: list,
        }
        .encode();
        long.push(0);
        assert!(
            DevicesFrom::decode(&long).is_err(),
            "trailing bytes were admitted"
        );
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

    /// **A revocation listing round-trips, with and without the artifact.**
    ///
    /// The pair matters rather than the encoding: SIP-89 sends a reader to
    /// *unverifiable* when a post's device was revoked, and a row whose
    /// signed revocation this exchange does not hold still has to arrive as a
    /// row. Dropping it would turn "revoked, on the exchange's word alone"
    /// into "never registered", which is the state the reader must not reach.
    #[test]
    fn a_revocation_listing_keeps_a_row_that_has_no_artifact() {
        let account_seed = [9u8; 32];
        let device = PubKey::new([3u8; 32]);
        let signed = Revocation::issue(&account_seed, &device, 1000);
        let listing = Revoked {
            now: 2000,
            rows: vec![
                Withdrawn {
                    device,
                    at: 1001,
                    revocation: Some(signed),
                },
                Withdrawn {
                    device: PubKey::new([4u8; 32]),
                    at: 1002,
                    revocation: None,
                },
            ],
        };
        let back = Revoked::decode(&listing.encode()).unwrap();
        assert_eq!(back, listing);
        assert!(
            back.rows[1].revocation.is_none(),
            "a row with no artifact came back carrying one"
        );
        assert_eq!(
            back.rows.len(),
            2,
            "a row with no artifact was dropped, which reads as never revoked"
        );
    }

    /// An empty listing is a listing, not a malformed answer: an account that
    /// has revoked nothing is the ordinary case.
    #[test]
    fn an_account_that_revoked_nothing_answers_an_empty_listing() {
        let none = Revoked {
            now: 7,
            rows: Vec::new(),
        };
        assert_eq!(Revoked::decode(&none.encode()).unwrap(), none);
    }

    /// And the ask round-trips under its own type byte, so the shared route
    /// can tell it from a device list.
    #[test]
    fn the_revoked_ask_is_told_apart_from_a_device_list() {
        let account = PubKey::new([1u8; 32]);
        let ask = ListRevoked { account };
        assert_eq!(ListRevoked::decode(&ask.encode()).unwrap(), ask);
        // The control: a device list of the same shape is not decodable as
        // this one, which is what keeps the two apart on one route.
        assert!(ListRevoked::decode(&ListDevices { account }.encode()).is_err());
        assert!(ListDevices::decode(&ask.encode()).is_err());
    }
}
