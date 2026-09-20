//! SIP-44: account succession.
//!
//! An account is its key, and a key that is lost took the account with it.
//! Here an account signs, while it can, who succeeds it -- a **will** naming
//! a successor key -- or a **policy** naming guardians a quorum of whom may
//! name one later with **vouches**. The successor presents a **claim**; an
//! exchange verifies it and carries the account across. Every statement is
//! self-contained and checkable by anybody holding the keys it names, so a
//! member who doubts a succession asks for the proof and checks it.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sqnr_core::{Error, PubKey, Result};

pub const SUCCESSION_CONTEXT: &[u8] = b"sqex-succession-v1";

pub const TYPE_WILL: u8 = 0x01;
pub const TYPE_POLICY: u8 = 0x02;
pub const TYPE_VOUCH: u8 = 0x03;
pub const TYPE_CLAIM: u8 = 0x04;
/// SIP-44 §The handover: a will presented by its own signer, now, with the credentials
/// the new key signed for the devices the account keeps.
pub const TYPE_HANDOVER: u8 = 0x05;

/// Guardians a policy may name.
pub const MAX_GUARDIANS: usize = 8;
/// Bytes a claim's proof may occupy.
pub const MAX_PROOF: usize = 4096;

/// `SUCCESSION_CONTEXT || kind || fields`, hashed: what each statement signs.
fn input(kind: u8, fields: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(SUCCESSION_CONTEXT);
    h.update([kind]);
    for f in fields {
        h.update(f);
    }
    let digest = h.finalize();
    let mut out = Vec::with_capacity(SUCCESSION_CONTEXT.len() + 32);
    out.extend_from_slice(SUCCESSION_CONTEXT);
    out.extend_from_slice(&digest);
    out
}

fn sign(seed: &[u8; 32], input: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(input).to_bytes()
}

fn verify(key: &PubKey, input: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key.as_bytes())
        .map(|vk| vk.verify(input, &Signature::from_bytes(sig)).is_ok())
        .unwrap_or(false)
}

fn short(what: &str) -> Error {
    Error::Malformed(format!("{what} cut short"))
}

/// An account's statement, signed in advance, of the key that succeeds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Will {
    pub account: PubKey,
    pub successor: PubKey,
    pub issued: u64,
    pub sig: [u8; 64],
}

pub const WILL_LEN: usize = 1 + 32 + 32 + 8 + 64;

impl Will {
    /// What the account signs: the will's fields under the context.
    pub fn input(account: &PubKey, successor: &PubKey, issued: u64) -> Vec<u8> {
        input(
            TYPE_WILL,
            &[
                account.as_bytes(),
                successor.as_bytes(),
                &issued.to_be_bytes(),
            ],
        )
    }

    pub fn sign(account_seed: &[u8; 32], successor: &PubKey, issued: u64) -> Will {
        let signing = SigningKey::from_bytes(account_seed);
        let account = PubKey::new(signing.verifying_key().to_bytes());
        Will {
            account,
            successor: *successor,
            issued,
            sig: sign(account_seed, &Will::input(&account, successor, issued)),
        }
    }

    pub fn verify(&self) -> bool {
        self.account != self.successor
            && verify(
                &self.account,
                &Will::input(&self.account, &self.successor, self.issued),
                &self.sig,
            )
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WILL_LEN);
        out.push(TYPE_WILL);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(self.successor.as_bytes());
        out.extend_from_slice(&self.issued.to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Will> {
        if b.len() != WILL_LEN {
            return Err(Error::Malformed(format!(
                "will is {} bytes, want {WILL_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_WILL {
            return Err(Error::Malformed(format!("not a will (type {:#x})", b[0])));
        }
        Ok(Will {
            account: PubKey::new(b[1..33].try_into().unwrap()),
            successor: PubKey::new(b[33..65].try_into().unwrap()),
            issued: u64::from_be_bytes(b[65..73].try_into().unwrap()),
            sig: b[73..137].try_into().unwrap(),
        })
    }
}

/// An account's statement of who may name its successor, and how many of
/// them it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub account: PubKey,
    pub threshold: u8,
    pub guardians: Vec<PubKey>,
    pub issued: u64,
    pub sig: [u8; 64],
}

impl Policy {
    pub fn input(account: &PubKey, threshold: u8, guardians: &[PubKey], issued: u64) -> Vec<u8> {
        let mut named = Vec::with_capacity(guardians.len() * 32);
        for g in guardians {
            named.extend_from_slice(g.as_bytes());
        }
        input(
            TYPE_POLICY,
            &[
                account.as_bytes(),
                &[threshold],
                &[guardians.len() as u8],
                &named,
                &issued.to_be_bytes(),
            ],
        )
    }

    /// Sign a policy. Refused where it could never be met: no guardians, a
    /// threshold above the count, a guardian named twice, or the account
    /// guarding itself.
    pub fn sign(
        account_seed: &[u8; 32],
        threshold: u8,
        guardians: &[PubKey],
        issued: u64,
    ) -> Result<Policy> {
        let signing = SigningKey::from_bytes(account_seed);
        let account = PubKey::new(signing.verifying_key().to_bytes());
        let policy = Policy {
            account,
            threshold,
            guardians: guardians.to_vec(),
            issued,
            sig: sign(
                account_seed,
                &Policy::input(&account, threshold, guardians, issued),
            ),
        };
        policy.well_formed()?;
        Ok(policy)
    }

    fn well_formed(&self) -> Result<()> {
        let n = self.guardians.len();
        if n == 0 || n > MAX_GUARDIANS {
            return Err(Error::Malformed(format!(
                "a policy names between 1 and {MAX_GUARDIANS} guardians, not {n}"
            )));
        }
        if self.threshold == 0 || usize::from(self.threshold) > n {
            return Err(Error::Malformed(format!(
                "a threshold of {} cannot be met by {n} guardians",
                self.threshold
            )));
        }
        for (i, g) in self.guardians.iter().enumerate() {
            if *g == self.account {
                return Err(Error::Malformed("an account cannot guard itself".into()));
            }
            if self.guardians[..i].contains(g) {
                return Err(Error::Malformed("a guardian is named twice".into()));
            }
        }
        Ok(())
    }

    pub fn verify(&self) -> bool {
        self.well_formed().is_ok()
            && verify(
                &self.account,
                &Policy::input(&self.account, self.threshold, &self.guardians, self.issued),
                &self.sig,
            )
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(107 + self.guardians.len() * 32);
        out.push(TYPE_POLICY);
        out.extend_from_slice(self.account.as_bytes());
        out.push(self.threshold);
        out.push(self.guardians.len() as u8);
        for g in &self.guardians {
            out.extend_from_slice(g.as_bytes());
        }
        out.extend_from_slice(&self.issued.to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode one from the front of `b`, returning how many bytes it took.
    pub fn read(b: &[u8]) -> Result<(Policy, usize)> {
        if b.first() != Some(&TYPE_POLICY) {
            return Err(Error::Malformed("not a policy".into()));
        }
        let account = PubKey::new(
            b.get(1..33)
                .ok_or_else(|| short("policy"))?
                .try_into()
                .unwrap(),
        );
        let threshold = *b.get(33).ok_or_else(|| short("policy"))?;
        let count = *b.get(34).ok_or_else(|| short("policy"))? as usize;
        if count > MAX_GUARDIANS {
            return Err(Error::Malformed(format!("{count} guardians is too many")));
        }
        let mut at = 35;
        let mut guardians = Vec::with_capacity(count);
        for _ in 0..count {
            let g = b.get(at..at + 32).ok_or_else(|| short("policy"))?;
            guardians.push(PubKey::new(g.try_into().unwrap()));
            at += 32;
        }
        let issued = u64::from_be_bytes(
            b.get(at..at + 8)
                .ok_or_else(|| short("policy"))?
                .try_into()
                .unwrap(),
        );
        at += 8;
        let sig: [u8; 64] = b
            .get(at..at + 64)
            .ok_or_else(|| short("policy"))?
            .try_into()
            .unwrap();
        at += 64;
        let policy = Policy {
            account,
            threshold,
            guardians,
            issued,
            sig,
        };
        policy.well_formed()?;
        Ok((policy, at))
    }

    pub fn decode(b: &[u8]) -> Result<Policy> {
        let (p, n) = Policy::read(b)?;
        if n != b.len() {
            return Err(Error::Malformed("policy has trailing bytes".into()));
        }
        Ok(p)
    }
}

/// A guardian's word that `successor` succeeds `account`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vouch {
    pub account: PubKey,
    pub successor: PubKey,
    pub guardian: PubKey,
    pub issued: u64,
    pub sig: [u8; 64],
}

pub const VOUCH_LEN: usize = 1 + 32 + 32 + 32 + 8 + 64;

impl Vouch {
    pub fn input(account: &PubKey, successor: &PubKey, guardian: &PubKey, issued: u64) -> Vec<u8> {
        input(
            TYPE_VOUCH,
            &[
                account.as_bytes(),
                successor.as_bytes(),
                guardian.as_bytes(),
                &issued.to_be_bytes(),
            ],
        )
    }

    pub fn sign(
        guardian_seed: &[u8; 32],
        account: &PubKey,
        successor: &PubKey,
        issued: u64,
    ) -> Vouch {
        let signing = SigningKey::from_bytes(guardian_seed);
        let guardian = PubKey::new(signing.verifying_key().to_bytes());
        Vouch {
            account: *account,
            successor: *successor,
            guardian,
            issued,
            sig: sign(
                guardian_seed,
                &Vouch::input(account, successor, &guardian, issued),
            ),
        }
    }

    pub fn verify(&self) -> bool {
        verify(
            &self.guardian,
            &Vouch::input(&self.account, &self.successor, &self.guardian, self.issued),
            &self.sig,
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VOUCH_LEN);
        out.push(TYPE_VOUCH);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(self.successor.as_bytes());
        out.extend_from_slice(self.guardian.as_bytes());
        out.extend_from_slice(&self.issued.to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Vouch> {
        if b.len() != VOUCH_LEN {
            return Err(Error::Malformed(format!(
                "vouch is {} bytes, want {VOUCH_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_VOUCH {
            return Err(Error::Malformed(format!("not a vouch (type {:#x})", b[0])));
        }
        Ok(Vouch {
            account: PubKey::new(b[1..33].try_into().unwrap()),
            successor: PubKey::new(b[33..65].try_into().unwrap()),
            guardian: PubKey::new(b[65..97].try_into().unwrap()),
            issued: u64::from_be_bytes(b[97..105].try_into().unwrap()),
            sig: b[105..169].try_into().unwrap(),
        })
    }
}

/// What a successor presents: a will, or a policy with the vouches that
/// meet it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    Will(Will),
    Guardians { policy: Policy, vouches: Vec<Vouch> },
}

impl Proof {
    pub fn account(&self) -> PubKey {
        match self {
            Proof::Will(w) => w.account,
            Proof::Guardians { policy, .. } => policy.account,
        }
    }

    /// The successor every part names, if they all name one.
    pub fn successor(&self) -> Option<PubKey> {
        match self {
            Proof::Will(w) => Some(w.successor),
            Proof::Guardians { vouches, .. } => {
                let first = vouches.first()?.successor;
                vouches
                    .iter()
                    .all(|v| v.successor == first)
                    .then_some(first)
            }
        }
    }

    /// Whether this proves `successor` succeeds the account it names: the
    /// will verifies under the account, or the policy does and at least
    /// `threshold` vouches for that successor verify under distinct
    /// guardians the policy names.
    pub fn proves(&self, successor: &PubKey) -> bool {
        match self {
            Proof::Will(w) => w.successor == *successor && w.verify(),
            Proof::Guardians { policy, vouches } => {
                if !policy.verify() || policy.account == *successor {
                    return false;
                }
                let mut seen: Vec<PubKey> = Vec::new();
                for v in vouches {
                    if v.account == policy.account
                        && v.successor == *successor
                        && policy.guardians.contains(&v.guardian)
                        && !seen.contains(&v.guardian)
                        && v.verify()
                    {
                        seen.push(v.guardian);
                    }
                }
                seen.len() >= usize::from(policy.threshold)
            }
        }
    }

    /// The signature and time a succession entry carries (SIP-44 §Channels):
    /// the will's, or the policy's.
    pub fn stamp(&self) -> (u64, [u8; 64]) {
        match self {
            Proof::Will(w) => (w.issued, w.sig),
            Proof::Guardians { policy, .. } => (policy.issued, policy.sig),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Proof::Will(w) => w.encode(),
            Proof::Guardians { policy, vouches } => {
                let mut out = policy.encode();
                out.push(vouches.len() as u8);
                for v in vouches {
                    out.extend_from_slice(&v.encode());
                }
                out
            }
        }
    }

    pub fn decode(b: &[u8]) -> Result<Proof> {
        if b.len() > MAX_PROOF {
            return Err(Error::Malformed(format!(
                "proof is {} bytes, limit is {MAX_PROOF}",
                b.len()
            )));
        }
        match b.first() {
            Some(&TYPE_WILL) => Ok(Proof::Will(Will::decode(b)?)),
            Some(&TYPE_POLICY) => {
                let (policy, mut at) = Policy::read(b)?;
                let count = *b.get(at).ok_or_else(|| short("claim"))? as usize;
                at += 1;
                if count > MAX_GUARDIANS {
                    return Err(Error::Malformed(format!("{count} vouches is too many")));
                }
                let mut vouches = Vec::with_capacity(count);
                for _ in 0..count {
                    let v = b.get(at..at + VOUCH_LEN).ok_or_else(|| short("claim"))?;
                    vouches.push(Vouch::decode(v)?);
                    at += VOUCH_LEN;
                }
                if at != b.len() {
                    return Err(Error::Malformed("claim has trailing bytes".into()));
                }
                Ok(Proof::Guardians { policy, vouches })
            }
            _ => Err(Error::Malformed("not a will or a policy".into())),
        }
    }
}

/// `POST /account/succeed`, from the successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub proof: Proof,
}

impl Claim {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TYPE_CLAIM];
        out.extend_from_slice(&self.proof.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Claim> {
        if b.first() != Some(&TYPE_CLAIM) {
            return Err(Error::Malformed("not a claim".into()));
        }
        Ok(Claim {
            proof: Proof::decode(&b[1..])?,
        })
    }
}

/// SIP-44 §The handover: `POST /account/handover`. The account, still holding its key,
/// names its successor by the same will SIP-44 uses, and carries a
/// credential from the successor for each device it keeps.
/// `| type = 0x05 | Will | count: u8 | count × Credential(len-prefixed u16) |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handover {
    pub will: Will,
    pub credentials: Vec<crate::credential::Credential>,
}

impl Handover {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![TYPE_HANDOVER];
        out.extend_from_slice(&self.will.encode());
        let n = self.credentials.len().min(crate::device::MAX_DEVICES);
        out.push(n as u8);
        for c in self.credentials.iter().take(n) {
            let bytes = c.encode();
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Handover> {
        if b.first() != Some(&TYPE_HANDOVER) {
            return Err(Error::Malformed("not a handover".into()));
        }
        let will = Will::decode(b.get(1..1 + WILL_LEN).ok_or_else(|| short("handover"))?)?;
        let mut at = 1 + WILL_LEN;
        let n = *b.get(at).ok_or_else(|| short("handover"))? as usize;
        at += 1;
        if n > crate::device::MAX_DEVICES {
            return Err(Error::Malformed(format!(
                "a handover keeps at most {} devices, not {n}",
                crate::device::MAX_DEVICES
            )));
        }
        let mut credentials = Vec::with_capacity(n);
        for _ in 0..n {
            let len = u16::from_be_bytes(
                b.get(at..at + 2)
                    .ok_or_else(|| short("handover"))?
                    .try_into()
                    .unwrap(),
            ) as usize;
            at += 2;
            let bytes = b.get(at..at + len).ok_or_else(|| short("handover"))?;
            at += len;
            credentials.push(crate::credential::Credential::decode(bytes)?);
        }
        if at != b.len() {
            return Err(Error::Malformed("trailing bytes after a handover".into()));
        }
        Ok(Handover { will, credentials })
    }
}

/// What the exchange recorded: served by `/account/succession`.
/// `| successor[32] | now: u64 | proof |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Succeeded {
    pub successor: PubKey,
    pub now: u64,
    pub proof: Proof,
}

impl Succeeded {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + 200);
        out.extend_from_slice(self.successor.as_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&self.proof.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Succeeded> {
        if b.len() < 41 {
            return Err(short("succession"));
        }
        Ok(Succeeded {
            successor: PubKey::new(b[..32].try_into().unwrap()),
            now: u64::from_be_bytes(b[32..40].try_into().unwrap()),
            proof: Proof::decode(&b[40..])?,
        })
    }
}

/// `POST /account/succession`: ask about an account.
/// `| account[32] |`
pub fn ask(account: &PubKey) -> Vec<u8> {
    account.as_bytes().to_vec()
}

pub fn asked(b: &[u8]) -> Result<PubKey> {
    if b.len() != 32 {
        return Err(Error::Malformed(format!(
            "an account is 32 bytes, not {}",
            b.len()
        )));
    }
    Ok(PubKey::new(b.try_into().unwrap()))
}

/// The check a reader of a `succeeded` system entry makes (SIP-44
/// §Channels): the signature the entry carries, under the actor, over the
/// will's input for its subject and time -- or over a policy's, which the
/// entry cannot carry whole, so a reader that finds no will-shaped
/// signature asks for the proof.
pub fn entry_verifies(actor: &PubKey, subject: &PubKey, issued: u64, sig: &[u8; 64]) -> bool {
    actor != subject && verify(actor, &Will::input(actor, subject, issued), sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn key(b: u8) -> PubKey {
        PubKey::new(SigningKey::from_bytes(&seed(b)).verifying_key().to_bytes())
    }

    /// A will verifies as signed, round-trips, and is refused when any
    /// field it signed over has changed.
    #[test]
    fn a_will_is_the_accounts_word_and_nothing_else() {
        let w = Will::sign(&seed(1), &key(2), 1000);
        assert!(w.verify());
        assert_eq!(Will::decode(&w.encode()).unwrap(), w);
        let mut other = w;
        other.successor = key(3);
        assert!(!other.verify(), "a will for another successor");
        let mut later = w;
        later.issued += 1;
        assert!(!later.verify());
        let mut stolen = w;
        stolen.account = key(3);
        assert!(!stolen.verify(), "signed by somebody else");
        let selfish = Will {
            successor: key(1),
            ..Will::sign(&seed(1), &key(1), 1)
        };
        assert!(!selfish.verify(), "an account cannot succeed itself");
        assert!(Proof::Will(w).proves(&key(2)));
        assert!(!Proof::Will(w).proves(&key(3)));
        assert!(entry_verifies(&key(1), &key(2), 1000, &w.sig));
        assert!(!entry_verifies(&key(1), &key(3), 1000, &w.sig));
    }

    /// Guardians: the threshold is what it says, a vouch counts once per
    /// guardian, only for a guardian the policy names, and all for one
    /// successor.
    #[test]
    fn guardians_move_an_account_only_as_a_quorum() {
        let policy = Policy::sign(&seed(1), 2, &[key(3), key(4), key(5)], 7).unwrap();
        assert!(policy.verify());
        assert_eq!(Policy::decode(&policy.encode()).unwrap(), policy);
        let v3 = Vouch::sign(&seed(3), &key(1), &key(2), 8);
        let v4 = Vouch::sign(&seed(4), &key(1), &key(2), 9);
        let v6 = Vouch::sign(&seed(6), &key(1), &key(2), 9);
        let v4_other = Vouch::sign(&seed(4), &key(1), &key(9), 9);
        assert!(v3.verify());
        assert_eq!(Vouch::decode(&v3.encode()).unwrap(), v3);

        let proof = |vouches: Vec<Vouch>| Proof::Guardians {
            policy: policy.clone(),
            vouches,
        };
        assert!(!proof(vec![v3]).proves(&key(2)), "one is not two");
        assert!(proof(vec![v3, v4]).proves(&key(2)));
        assert!(!proof(vec![v3, v3]).proves(&key(2)), "one guardian twice");
        assert!(!proof(vec![v3, v6]).proves(&key(2)), "a stranger's vouch");
        assert!(
            !proof(vec![v3, v4_other]).proves(&key(2)),
            "vouches for different successors"
        );
        assert_eq!(proof(vec![v3, v4_other]).successor(), None);
        let full = proof(vec![v3, v4]);
        assert_eq!(Proof::decode(&full.encode()).unwrap(), full);
        let claim = Claim { proof: full };
        assert_eq!(Claim::decode(&claim.encode()).unwrap(), claim);

        assert!(Policy::sign(&seed(1), 3, &[key(3), key(4)], 7).is_err());
        assert!(Policy::sign(&seed(1), 1, &[key(1)], 7).is_err());
        assert!(Policy::sign(&seed(1), 1, &[key(3), key(3)], 7).is_err());
        assert!(Policy::sign(&seed(1), 0, &[key(3)], 7).is_err());
    }
}

#[cfg(test)]
mod handover_tests {
    use super::*;

    #[test]
    fn a_handover_round_trips() {
        let old = [5u8; 32];
        let new_seed = [6u8; 32];
        let new = PubKey::new(SigningKey::from_bytes(&new_seed).verifying_key().to_bytes());
        let will = Will::sign(&old, &new, 9);
        let device = PubKey::new(SigningKey::from_bytes(&old).verifying_key().to_bytes());
        let credential = crate::credential::Credential::issue(
            &new_seed,
            &device,
            crate::credential::SCOPE_CHAT,
            1,
            99,
        )
        .unwrap();
        let h = Handover {
            will,
            credentials: vec![credential],
        };
        assert_eq!(Handover::decode(&h.encode()).unwrap(), h);
        let mut trailing = h.encode();
        trailing.push(0);
        assert!(Handover::decode(&trailing).is_err());
        assert!(Handover::decode(&h.encode()[..50]).is_err());
        assert!(Claim::decode(&h.encode()).is_err());
    }
}
