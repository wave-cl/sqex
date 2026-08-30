//! SIP-21 profiles and blocking: what a person shows, and who may reach them.
//!
//! Everywhere else in this stack an identity is 32 bytes rendered as base58,
//! which is exactly right for a protocol and unusable for a conversation. A
//! profile is the only place a person is named by something other than a key —
//! and that is why most of the security thinking here is about impersonation,
//! which the rest of the design does not have to worry about at all.
//!
//! # Every field is a claim, and since SIP-32 a signed one
//!
//! A display name is chosen by its subject, and so is a title.
//!
//! What SIP-32 adds is that the claim is now **attested by the subject** and
//! ordered by a counter it controls, so a party holding a copy cannot rewrite
//! it and cannot replay an old one over a new one. That is a smaller property
//! than a reader will assume: it proves an account chose a name, not that the
//! name is unlike anybody else's. Every warning below about confusable names
//! and titles stands unchanged. Two accounts may publish the same name, or names
//! differing by a homoglyph, a combining mark or a bidirectional override.
//!
//! The **title** is the more dangerous of the two, and it is called `title`
//! rather than `role` for that reason: `role` already means member or admin in
//! SIP-16, where the exchange holds it and attests to it, and reusing the word
//! for a field its subject writes about itself would imply the attested thing
//! while providing the claimed one. A confusable name still needs a reader to
//! mistake one person for another; a title asserts standing directly.

use sqnr_core::{Error, PubKey, Result};

pub const TYPE_PUT: u8 = 0x01;
pub const TYPE_GET: u8 = 0x02;
pub const TYPE_BLOCK: u8 = 0x03;
pub const TYPE_BLOCKED: u8 = 0x04;

pub const BLOCK_ADD: u8 = 0x01;
pub const BLOCK_REMOVE: u8 = 0x02;

/// Withhold the profile from accounts sharing no channel with the subject.
///
/// Bits other than 0 are reserved and MUST be zero: a reserved bit that is
/// merely ignored is a reserved bit somebody will use.
pub const FLAG_WITHHOLD: u8 = 0b0000_0001;

pub const MAX_NAME: usize = 64;
pub const MAX_TITLE: usize = 64;
/// The SIP-18 preview budget. A 96×96 JPEG is a couple of kilobytes.
pub const MAX_AVATAR: usize = 8 * 1024;
pub const MAX_BLOCKED: usize = 1024;
pub const MAX_UPDATES_PER_HOUR: usize = 32;

/// What an account says about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub flags: u8,
    pub name: String,
    /// A short descriptor its subject chooses — a job, a team, a line about
    /// themselves. It carries **no authority of any kind** and an exchange MUST
    /// NOT interpret it.
    pub title: String,
    /// Inline bytes rather than a SIP-18 reference: blobs are attached to
    /// channels and pruned on a channel's window, and a profile is in no
    /// channel, so a reference would need a second lifetime rule existing only
    /// for this.
    pub avatar: Vec<u8>,
}

impl Profile {
    pub fn withheld(&self) -> bool {
        self.flags & FLAG_WITHHOLD != 0
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.flags);
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        out.push(self.title.len() as u8);
        out.extend_from_slice(self.title.as_bytes());
        out.extend_from_slice(&(self.avatar.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.avatar);
    }

    fn read(b: &[u8], o: &mut usize) -> Result<Profile> {
        let at = *o;
        if b.len() < at + 3 {
            return Err(Error::Malformed("profile is truncated".into()));
        }
        let flags = b[at];
        if flags & !FLAG_WITHHOLD != 0 {
            return Err(Error::Malformed(format!(
                "reserved profile flags set: {flags:#010b}"
            )));
        }
        let name_len = b[at + 1] as usize;
        if name_len > MAX_NAME {
            return Err(Error::Malformed(format!(
                "name is {name_len} bytes, limit is {MAX_NAME}"
            )));
        }
        let mut p = at + 2;
        if b.len() < p + name_len + 1 {
            return Err(Error::Malformed("profile is truncated".into()));
        }
        let name = utf8(&b[p..p + name_len], "name")?;
        p += name_len;

        let title_len = b[p] as usize;
        p += 1;
        if title_len > MAX_TITLE {
            return Err(Error::Malformed(format!(
                "title is {title_len} bytes, limit is {MAX_TITLE}"
            )));
        }
        if b.len() < p + title_len + 2 {
            return Err(Error::Malformed("profile is truncated".into()));
        }
        let title = utf8(&b[p..p + title_len], "title")?;
        p += title_len;

        let avatar_len = u16::from_be_bytes(b[p..p + 2].try_into().unwrap()) as usize;
        p += 2;
        if avatar_len > MAX_AVATAR {
            return Err(Error::Malformed(format!(
                "avatar is {avatar_len} bytes, limit is {MAX_AVATAR}"
            )));
        }
        if b.len() < p + avatar_len {
            return Err(Error::Malformed("avatar is truncated".into()));
        }
        *o = p + avatar_len;
        Ok(Profile {
            flags,
            name,
            title,
            avatar: b[p..p + avatar_len].to_vec(),
        })
    }
}

fn utf8(b: &[u8], what: &str) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| Error::Malformed(format!("{what} is not UTF-8")))
}

/// Replace the whole profile. There is no partial update: two short fields and
/// a picture do not need a presence marker each and a rule for clearing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Put {
    /// SIP-32: the subject's signed record, not a bare profile. The exchange
    /// verifies it and stores it whole, so what it later serves is the artifact
    /// rather than its own copy of the fields.
    pub record: Record,
}

impl Put {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TYPE_PUT];
        out.extend_from_slice(&self.record.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Put> {
        if b.is_empty() || b[0] != TYPE_PUT {
            return Err(Error::Malformed("not a profile put".into()));
        }
        Ok(Put {
            record: Record::decode(&b[1..])?,
        })
    }
}

/// A request naming an account: get, block-list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByAccount {
    pub account: PubKey,
}

impl ByAccount {
    pub fn encode(&self, type_byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(type_byte);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8], type_byte: u8) -> Result<ByAccount> {
        if b.len() != 33 || b[0] != type_byte {
            return Err(Error::Malformed(format!(
                "request is {} bytes, want 33",
                b.len()
            )));
        }
        Ok(ByAccount {
            account: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// Add or remove an account from the caller's block list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub account: PubKey,
    pub add: bool,
}

impl Block {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34);
        out.push(TYPE_BLOCK);
        out.extend_from_slice(self.account.as_bytes());
        out.push(if self.add { BLOCK_ADD } else { BLOCK_REMOVE });
        out
    }

    pub fn decode(b: &[u8]) -> Result<Block> {
        if b.len() != 34 || b[0] != TYPE_BLOCK {
            return Err(Error::Malformed(format!(
                "block is {} bytes, want 34",
                b.len()
            )));
        }
        let add = match b[33] {
            BLOCK_ADD => true,
            BLOCK_REMOVE => false,
            other => return Err(Error::Malformed(format!("unknown block op {other}"))),
        };
        Ok(Block {
            account: PubKey::new(b[1..33].try_into().unwrap()),
            add,
        })
    }
}

/// A profile, or its absence in exactly the same shape.
///
/// A profile that does not exist, one withheld from the caller, and one whose
/// subject has blocked the caller are reported identically. This follows SIP-4,
/// and for SIP-4's reason: answering "exists but hidden" would itself be the
/// disclosure that hiding was meant to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Got {
    pub found: bool,
    pub updated: u64,
    pub now: u64,
    /// SIP-32: the record as its subject signed it, where there is one.
    ///
    /// `None` for a profile stored before this rule, or for an absent one. A
    /// reader that finds a profile with no record holds an assertion rather
    /// than evidence, and should know which.
    pub record: Option<Record>,
}

impl Got {
    pub fn none(now: u64) -> Got {
        Got {
            found: false,
            updated: 0,
            now,
            record: None,
        }
    }

    /// The profile itself, or an empty one where there is no record.
    pub fn profile(&self) -> Profile {
        self.record
            .as_ref()
            .map(|r| r.profile.clone())
            .unwrap_or_default()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.push(u8::from(self.found));
        out.extend_from_slice(&self.updated.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        match &self.record {
            Some(r) => {
                out.push(1);
                out.extend_from_slice(&r.encode());
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Got> {
        if b.len() < 18 {
            return Err(Error::Malformed(format!(
                "got is {} bytes, want at least 18",
                b.len()
            )));
        }
        let record = match b[17] {
            0 if b.len() == 18 => None,
            1 => Some(Record::decode(&b[18..])?),
            _ => {
                return Err(Error::Malformed(
                    "profile reply claims a record it does not carry".into(),
                ));
            }
        };
        Ok(Got {
            found: b[0] != 0,
            updated: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            now: u64::from_be_bytes(b[9..17].try_into().unwrap()),
            record,
        })
    }
}

/// The caller's block list, returned only to its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocks {
    pub now: u64,
    pub accounts: Vec<PubKey>,
}

impl Blocks {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.accounts.len() * 32);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.accounts.len() as u16).to_be_bytes());
        for a in &self.accounts {
            out.extend_from_slice(a.as_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Blocks> {
        if b.len() < 10 {
            return Err(Error::Malformed(format!(
                "blocks is {} bytes, want at least 10",
                b.len()
            )));
        }
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap()) as usize;
        if count > MAX_BLOCKED {
            return Err(Error::Malformed(format!(
                "blocks holds {count}, limit is {MAX_BLOCKED}"
            )));
        }
        if b.len() != 10 + count * 32 {
            return Err(Error::Malformed(format!(
                "blocks is {} bytes, want {}",
                b.len(),
                10 + count * 32
            )));
        }
        Ok(Blocks {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            accounts: (0..count)
                .map(|i| PubKey::new(b[10 + i * 32..42 + i * 32].try_into().unwrap()))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn profile() -> Profile {
        Profile {
            flags: 0,
            name: "Colin Lyons".into(),
            title: "Infrastructure".into(),
            avatar: vec![0xff; 128],
        }
    }

    fn signed(p: Profile) -> Record {
        Record::sign(&[7u8; 32], &PubKey::new([9u8; 32]), 3, 1000, p)
    }

    #[test]
    fn a_profile_round_trips() {
        let p = Put { record: signed(profile()) };
        assert_eq!(Put::decode(&p.encode()).unwrap(), p);
        assert!(p.record.verify());
    }

    #[test]
    fn an_empty_profile_round_trips() {
        // Every field may be empty; a person who publishes nothing is not an
        // error.
        let p = Put { record: signed(Profile::default()) };
        assert_eq!(Put::decode(&p.encode()).unwrap(), p);
    }

    /// Each field, one at a time — varying two would let a construction that
    /// omitted one of them still pass.
    #[test]
    fn every_record_field_is_covered() {
        let base = signed(profile());
        assert!(base.verify());

        for (what, tampered) in [
            ("name", Record { profile: Profile { name: "Someone Else".into(), ..profile() }, ..base.clone() }),
            ("title", Record { profile: Profile { title: "Moderator".into(), ..profile() }, ..base.clone() }),
            ("flags", Record { profile: Profile { flags: FLAG_WITHHOLD, ..profile() }, ..base.clone() }),
            ("serial", Record { serial: 4, ..base.clone() }),
            ("issued_at", Record { issued_at: 1001, ..base.clone() }),
            ("account", Record { account: PubKey::new([1u8; 32]), ..base.clone() }),
            ("device", Record { device: PubKey::new([2u8; 32]), ..base.clone() }),
        ] {
            assert!(!tampered.verify(), "a signature survived a changed {what}");
        }
    }

    /// A name of the same length, so the length prefix cannot be what catches
    /// it. Without this the bytes themselves could go unsigned and no test
    /// would notice.
    #[test]
    fn a_name_of_equal_length_cannot_be_swapped() {
        let base = signed(Profile { name: "book club".into(), ..profile() });
        let swapped = Record {
            profile: Profile { name: "team chat".into(), ..base.profile.clone() },
            ..base.clone()
        };
        assert_eq!(base.profile.name.len(), swapped.profile.name.len());
        assert!(!swapped.verify());
    }

    #[test]
    fn absence_and_presence_are_the_same_shape() {
        let now = 42;
        let none = Got::none(now);
        assert_eq!(Got::decode(&none.encode()).unwrap(), none);
        assert!(!none.found);
        // A reader cannot tell "no profile" from "withheld" from "blocked",
        // which is the point.
        assert_eq!(none.profile(), Profile::default());
    }

    #[test]
    fn a_reserved_flag_is_refused() {
        // A reserved bit that is merely ignored is one somebody will use.
        let p = Put {
            record: signed(Profile {
                flags: 0b0000_0010,
                ..profile()
            }),
        };
        assert!(Put::decode(&p.encode()).is_err());
    }

    #[test]
    fn the_withhold_flag_survives_the_wire() {
        let p = Put {
            record: signed(Profile {
                flags: FLAG_WITHHOLD,
                ..profile()
            }),
        };
        let back = Put::decode(&p.encode()).unwrap();
        assert!(back.record.profile.withheld());
    }

    #[test]
    fn oversized_fields_are_refused() {
        for p in [
            Profile { name: "x".repeat(MAX_NAME + 1), ..profile() },
            Profile { title: "x".repeat(MAX_TITLE + 1), ..profile() },
            Profile { avatar: vec![0; MAX_AVATAR + 1], ..profile() },
        ] {
            assert!(Put::decode(&Put { record: signed(p) }.encode()).is_err());
        }
    }

    #[test]
    fn block_and_its_list_round_trip() {
        let b = Block {
            account: key(3),
            add: true,
        };
        assert_eq!(Block::decode(&b.encode()).unwrap(), b);
        let r = Block {
            account: key(3),
            add: false,
        };
        assert_eq!(Block::decode(&r.encode()).unwrap(), r);

        let l = Blocks {
            now: 1,
            accounts: vec![key(1), key(2)],
        };
        assert_eq!(Blocks::decode(&l.encode()).unwrap(), l);
    }

    #[test]
    fn a_get_checks_the_type_it_was_asked_for() {
        let g = ByAccount { account: key(5) };
        assert_eq!(ByAccount::decode(&g.encode(TYPE_GET), TYPE_GET).unwrap(), g);
        assert!(ByAccount::decode(&g.encode(TYPE_GET), TYPE_BLOCKED).is_err());
    }
}

/// Domain separator for a SIP-32 profile record.
pub const PROFILE_CONTEXT: &[u8] = b"sqex-profile-v1";

/// A profile as its subject signed it (SIP-32).
///
/// Shaped after `sqns-core::record::Record` rather than invented: a monotonic
/// `serial`, highest wins. `sqnsd`'s replication says why that works — a peer
/// that alters a record breaks its signature, and a peer that replays an old
/// one loses to the higher serial already held.
///
/// # A counter, not a clock
///
/// SIP-31 declined a client-asserted time for entries because a second clock
/// beside `posted` would be a second answer to a question that already had one.
/// Here there is no sequence number to fall back on and "which of these is
/// current" is the whole question. A counter makes a stale record *lose*; a
/// timestamp would only make it look old, and two clients disagreeing about the
/// time would disagree about the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub account: PubKey,
    /// The device that signed, bound to `account` by a SIP-20 credential — a
    /// profile is edited far too often to want a hardware touch, and a linked
    /// device does not hold its account's key at all.
    pub device: PubKey,
    pub serial: u64,
    /// The subject's own clock. Advisory: for display, and for a reader judging
    /// staleness. Nothing orders by it.
    pub issued_at: u64,
    pub profile: Profile,
    pub signature: [u8; 64],
}

fn record_body(account: &PubKey, device: &PubKey, serial: u64, issued_at: u64, p: &Profile) -> Vec<u8> {
    let mut b = Vec::with_capacity(96);
    b.extend_from_slice(account.as_bytes());
    b.extend_from_slice(device.as_bytes());
    b.extend_from_slice(&serial.to_be_bytes());
    b.extend_from_slice(&issued_at.to_be_bytes());
    p.write(&mut b);
    b
}

fn record_input(body: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut m = Vec::with_capacity(PROFILE_CONTEXT.len() + 32);
    m.extend_from_slice(PROFILE_CONTEXT);
    m.extend_from_slice(&Sha256::digest(body));
    m
}

impl Record {
    pub fn sign(
        device_seed: &[u8; 32],
        account: &PubKey,
        serial: u64,
        issued_at: u64,
        profile: Profile,
    ) -> Record {
        use ed25519_dalek::{Signer, SigningKey};
        let signing = SigningKey::from_bytes(device_seed);
        let device = PubKey::new(signing.verifying_key().to_bytes());
        let body = record_body(account, &device, serial, issued_at, &profile);
        Record {
            account: *account,
            device,
            serial,
            issued_at,
            profile,
            signature: signing.sign(&record_input(&body)).to_bytes(),
        }
    }

    /// Check the signature under the device the record names.
    ///
    /// **Step one of two.** It proves a key signed and says nothing about whose
    /// key it is; binding `device` to `account` is a SIP-20 credential, which a
    /// verifier must check separately — the same two steps SIP-31 requires, and
    /// the same warning, because the first alone returns a satisfying `true`.
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(vk) = VerifyingKey::from_bytes(self.device.as_bytes()) else {
            return false;
        };
        let body = record_body(
            &self.account,
            &self.device,
            self.serial,
            self.issued_at,
            &self.profile,
        );
        vk.verify(&record_input(&body), &Signature::from_bytes(&self.signature))
            .is_ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = record_body(
            &self.account,
            &self.device,
            self.serial,
            self.issued_at,
            &self.profile,
        );
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Record> {
        if b.len() < 80 + 64 {
            return Err(Error::Malformed("record is truncated".into()));
        }
        let mut o = 80;
        let profile = Profile::read(b, &mut o)?;
        if b.len() != o + 64 {
            return Err(Error::Malformed(format!(
                "record is {} bytes, want {}",
                b.len(),
                o + 64
            )));
        }
        Ok(Record {
            account: PubKey::new(b[0..32].try_into().unwrap()),
            device: PubKey::new(b[32..64].try_into().unwrap()),
            serial: u64::from_be_bytes(b[64..72].try_into().unwrap()),
            issued_at: u64::from_be_bytes(b[72..80].try_into().unwrap()),
            profile,
            signature: b[o..o + 64].try_into().unwrap(),
        })
    }
}
