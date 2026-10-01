//! SIP-87 a channel key every member contributes to: where the epoch key comes
//! from, and nothing else.
//!
//! SIP-17's channel key is thirty-two bytes an admin generates and hands out.
//! Here the epoch key is derived from a **chain** every member holds and a
//! **commit secret** one member contributes, so no single party chooses it. The
//! carriage is SIP-17's unchanged — the same [`Envelope`](crate::channel_key::Envelope),
//! the same SIP-5 construction, the same SIP-23 prekey — because what travels
//! in it is a commit secret rather than a key.
//!
//! # What this buys, stated narrowly
//!
//! **Post-compromise security.** An attacker holding a member's identity key
//! reads the channel until an epoch whose commit secret it does not receive;
//! any uncompromised member's commit re-randomises the chain, and the secret
//! reaches each device under a prekey destroyed on use.
//!
//! **Not forward secrecy of history.** SIP-87 is explicit that an
//! implementation MUST NOT describe it as giving that: the epoch keys are
//! retained in order to read history, so the haul from a stolen device is what
//! it always was. **Not confidentiality from an admin either** — an admin who
//! is willing to be seen still adds an identity, commits, and reads everything
//! from that epoch forward. What goes away is the *silent* addition, the
//! *retroactive* one, and the one where membership and readership disagree.
//!
//! # Where this file's reading of SIP-87 had to choose
//!
//! `transcript` in a commit body is **`transcript_{n-1}`**: the transcript the
//! committer believes stands *before* this commit. SIP-87 calls it "the
//! transcript hash below" and says `commit_n` is "the commit body above
//! excluding `sig`" — and those two together are only non-circular if the field
//! is the previous transcript rather than the one this commit produces. It is
//! also the reading that does the work the document wants from it: a continuing
//! member checks the claim against its own value and refuses a commit that
//! disagrees, and a joiner needs exactly this value to compute `transcript_n`
//! for itself.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use sqnr_core::{Error, PubKey, Result};

use crate::channel_key::ChannelKey;

/// Domain separator for the chain and the transcript.
pub const CHAIN_CONTEXT: &[u8] = b"sqex-chain-v1";
/// Domain separator for the epoch key.
pub const EPOCH_CONTEXT: &[u8] = b"sqex-epoch-v1";
/// Domain separator for a commit signature.
pub const COMMIT_CONTEXT: &[u8] = b"sqex-commit-v1";

/// Accounts one commit may admit.
pub const MAX_ADDS: usize = 64;
/// Accounts one commit may remove.
pub const MAX_REMOVES: usize = 64;

/// `transcript_0`: thirty-two zero bytes.
pub const GENESIS_TRANSCRIPT: [u8; 32] = [0u8; 32];

/// Bytes of a commit body before `add`/`remove` and after them.
const COMMIT_FIXED: usize = 4 + 32 + 1 + 1 + 32 + 32 + 64;

/// A commit: the entry that creates an epoch.
///
/// An ordinary SIP-16 entry in every respect — signed by the posting device
/// under SIP-31, chained, receipted — carrying this as its body **in the
/// clear**, which is what lets a member read who was admitted before it opens
/// the envelope sealed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// The epoch this commit creates: the channel's current epoch plus one.
    pub epoch: u32,
    /// The **account** the committing device acts for. The device is the
    /// entry's own `device`, and a verifier needs the SIP-20 credential binding
    /// the two — `verify` proves a key signed and nothing about whose it is.
    pub committer: PubKey,
    /// Accounts entering at this epoch, ascending by key bytes, no repeats,
    /// disjoint from `removes`.
    pub adds: Vec<PubKey>,
    /// Accounts leaving at this epoch, on the same terms.
    pub removes: Vec<PubKey>,
    /// The X25519 public key matching the commit secret, so a member can check
    /// that the envelope it was sent agrees with the log. Without that check a
    /// committer could send different secrets to different devices, which is
    /// equivocation about the key rather than about the log and which no amount
    /// of receipt comparison would find.
    pub contribution: [u8; 32],
    /// `transcript_{n-1}`: the transcript the committer believes stands before
    /// this commit. A continuing member MUST refuse a commit that disagrees
    /// with its own; a joining device takes it and computes forward.
    pub transcript: [u8; 32],
    /// Ed25519 over every preceding field under [`COMMIT_CONTEXT`], by the
    /// committing device.
    pub sig: [u8; 64],
}

impl Commit {
    /// The bytes the transcript hashes and the signature covers: the whole body
    /// bar `sig`.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(COMMIT_FIXED + 32 * (self.adds.len() + self.removes.len()));
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(self.committer.as_bytes());
        out.push(self.adds.len() as u8);
        out.push(self.removes.len() as u8);
        for a in &self.adds {
            out.extend_from_slice(a.as_bytes());
        }
        for r in &self.removes {
            out.extend_from_slice(r.as_bytes());
        }
        out.extend_from_slice(&self.contribution);
        out.extend_from_slice(&self.transcript);
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signing_input();
        out.extend_from_slice(&self.sig);
        out
    }

    /// Sign this commit as `device_seed`, filling in `sig`.
    pub fn sign(&mut self, device_seed: &[u8; 32]) {
        let mut input = COMMIT_CONTEXT.to_vec();
        input.extend_from_slice(&self.signing_input());
        self.sig = SigningKey::from_bytes(device_seed).sign(&input).to_bytes();
    }

    /// Does `device`'s signature stand over this commit?
    ///
    /// Proof that *a key* signed, which is half the job — SIP-31 says so of its
    /// own signatures and it is as true here. A verifier MUST also hold the
    /// SIP-20 credential binding `device` to [`Commit::committer`].
    pub fn verify(&self, device: &PubKey) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(device.as_bytes()) else {
            return false;
        };
        let mut input = COMMIT_CONTEXT.to_vec();
        input.extend_from_slice(&self.signing_input());
        vk.verify(&input, &Signature::from_bytes(&self.sig)).is_ok()
    }

    /// Read a commit body.
    ///
    /// **Strict about order and repeats**, because the body is hashed into the
    /// key: two members who read the same bytes must agree on them exactly, and
    /// an unordered list is two encodings of one fact.
    pub fn decode(b: &[u8]) -> Result<Commit> {
        if b.len() < COMMIT_FIXED {
            return Err(Error::Malformed(format!(
                "commit is {} bytes, want at least {COMMIT_FIXED}",
                b.len()
            )));
        }
        let epoch = u32::from_be_bytes(b[0..4].try_into().unwrap());
        let committer = PubKey::new(b[4..36].try_into().unwrap());
        let adds = b[36] as usize;
        let removes = b[37] as usize;
        if adds > MAX_ADDS || removes > MAX_REMOVES {
            return Err(Error::Malformed(format!(
                "commit names {adds} adds and {removes} removes, limits are {MAX_ADDS} and {MAX_REMOVES}"
            )));
        }
        let want = COMMIT_FIXED + 32 * (adds + removes);
        if b.len() != want {
            return Err(Error::Malformed(format!(
                "commit is {} bytes, want exactly {want}",
                b.len()
            )));
        }
        let mut o = 38;
        let read = |n: usize, o: &mut usize| -> Vec<PubKey> {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(PubKey::new(b[*o..*o + 32].try_into().unwrap()));
                *o += 32;
            }
            v
        };
        let adds = read(adds, &mut o);
        let removes = read(removes, &mut o);
        let contribution: [u8; 32] = b[o..o + 32].try_into().unwrap();
        let transcript: [u8; 32] = b[o + 32..o + 64].try_into().unwrap();
        let sig: [u8; 64] = b[o + 64..o + 128].try_into().unwrap();
        ascending(&adds, "adds")?;
        ascending(&removes, "removes")?;
        if adds.iter().any(|a| removes.contains(a)) {
            return Err(Error::Malformed(
                "commit both adds and removes an account".into(),
            ));
        }
        Ok(Commit {
            epoch,
            committer,
            adds,
            removes,
            contribution,
            transcript,
            sig,
        })
    }

    /// Does this commit admit `account`?
    ///
    /// The question SIP-87's `Welcome` rule turns on, and it is asked of the
    /// **log** rather than of the reader's own state: a device MUST treat an
    /// envelope for an epoch whose commit does not name it as an add as a
    /// commit secret regardless of what it holds.
    pub fn admits(&self, account: &PubKey) -> bool {
        self.adds.contains(account)
    }
}

/// The commit a member entry's body carries, where it carries one.
///
/// **How a commit is told apart from a sealed message, and why that is enough.**
/// SIP-87 adds nothing to SIP-16's request wire — it says so twice, and says
/// outright that "an exchange cannot tell which kind a private channel is" — so
/// there is no kind byte and no flag to read. What there is instead is the
/// signature: a commit body is a fixed shape whose every field is covered by an
/// Ed25519 signature under [`COMMIT_CONTEXT`] by the device the exchange stamped
/// on the entry. A sealed body is indistinguishable from random to anyone
/// without the key, and random does not verify.
///
/// `account` is checked against [`Commit::committer`] because the two are
/// separate claims: the exchange's observation of who posted, and the commit's
/// own statement of whose act it is. A commit lifted out of one member's entry
/// and reposted by another is caught here.
pub fn commit_signed_in(body: &[u8], account: &PubKey, device: &PubKey) -> Option<Commit> {
    let commit = Commit::decode(body).ok()?;
    (commit.committer == *account && commit.verify(device)).then_some(commit)
}

/// The same, for a reader that holds no device to check against.
///
/// Only for a fold rebuilt from a store that wrote nothing which failed to
/// verify on arrival — the same basis on which such a fold reports every entry
/// as validly signed. A reader with the entry in front of it MUST use
/// [`commit_signed_in`]; this one proves only that the bytes are shaped like a
/// commit and name the account that posted them.
pub fn commit_in(body: &[u8], account: &PubKey) -> Option<Commit> {
    let commit = Commit::decode(body).ok()?;
    (commit.committer == *account).then_some(commit)
}

fn ascending(keys: &[PubKey], what: &str) -> Result<()> {
    for pair in keys.windows(2) {
        if pair[0].as_bytes() >= pair[1].as_bytes() {
            return Err(Error::Malformed(format!(
                "commit's {what} are not ascending, or repeat"
            )));
        }
    }
    Ok(())
}

/// The X25519 public key a commit secret must publish as its `contribution`.
pub fn contribution_of(commit_secret: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*commit_secret);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

/// Thirty-two bytes, uniformly random, for one commit.
pub fn generate_secret() -> [u8; 32] {
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

/// `transcript_n = SHA-512(sqex-chain-v1 || transcript_{n-1} || commit_n)[0..32]`
pub fn transcript(previous: &[u8; 32], commit: &Commit) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(CHAIN_CONTEXT);
    h.update(previous);
    h.update(commit.signing_input());
    take32(h.finalize().as_slice())
}

/// `chain_n = SHA-512(sqex-chain-v1 || chain_{n-1} || commit_secret || transcript_n)[0..32]`
pub fn chain(previous: &[u8; 32], commit_secret: &[u8; 32], transcript: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(CHAIN_CONTEXT);
    h.update(previous);
    h.update(commit_secret);
    h.update(transcript);
    take32(h.finalize().as_slice())
}

/// `key_n = SHA-512(sqex-epoch-v1 || chain_n || transcript_n)[0..32]`
///
/// A SIP-17 channel key in every respect: entries are sealed under it with
/// SIP-17's per-sender subkeys and the exchange sees an epoch number and
/// ciphertext as before.
pub fn epoch_key(chain: &[u8; 32], transcript: &[u8; 32]) -> ChannelKey {
    let mut h = Sha512::new();
    h.update(EPOCH_CONTEXT);
    h.update(chain);
    h.update(transcript);
    ChannelKey::new(take32(h.finalize().as_slice()))
}

fn take32(okm: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm[..32]);
    out
}

/// Why a device would not derive an epoch key from a commit it was handed.
///
/// Named rather than collapsed into one error, because the whole point of
/// SIP-87's `Welcome` rule is that a device two epochs behind **refuses**
/// instead of deriving nonsense, and a caller that cannot tell that case from a
/// forged contribution cannot report either honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The commit does not create the epoch after the one this chain stands at.
    /// A device restored behind the channel lands here, and there is no way
    /// forward from it but to be admitted again by a commit.
    WrongEpoch { held: u32, commit: u32 },
    /// The committer's stated `transcript_{n-1}` is not the one this device
    /// holds: the two disagree about the channel's history, and SIP-87 makes
    /// that a refusal rather than a warning.
    Transcript,
    /// `X25519(base, commit_secret)` is not the commit's `contribution` — the
    /// secret this device was sent is not the one the committer published.
    Contribution,
    /// A `Welcome` whose chain and whose key for the admitted epoch do not
    /// agree: the inviter handed over two things that cannot both be right.
    Welcome,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::WrongEpoch { held, commit } => write!(
                f,
                "this device's chain stands at epoch {held} and the commit creates {commit}: \
                 it must be admitted again by a commit"
            ),
            Refused::Transcript => {
                f.write_str("the commit states a transcript this device does not hold")
            }
            Refused::Contribution => {
                f.write_str("the commit secret does not match the contribution in the log")
            }
            Refused::Welcome => f.write_str(
                "the welcome's chain does not derive the key it was sent beside: \
                 whoever published it handed over two things that disagree",
            ),
        }
    }
}

/// What a member device holds for an agreed channel: never transmitted except
/// in a `Welcome`, and never given to the exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    /// The epoch this chain stands at. 0 before the first commit.
    pub epoch: u32,
    pub chain: [u8; 32],
    pub transcript: [u8; 32],
}

impl Chain {
    /// `chain_0`: thirty-two random bytes, generated by the channel's creator.
    /// The channel has no epoch until the first commit.
    pub fn create() -> Chain {
        use rand_core::RngCore;
        let mut chain = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut chain);
        Chain {
            epoch: 0,
            chain,
            transcript: GENESIS_TRANSCRIPT,
        }
    }

    pub fn new(epoch: u32, chain: [u8; 32], transcript: [u8; 32]) -> Chain {
        Chain {
            epoch,
            chain,
            transcript,
        }
    }

    /// The chain and transcript a `Welcome` puts a joining device at: the chain
    /// as of the commit that admitted it, and the transcript that commit
    /// produced.
    ///
    /// A joiner takes the commit's `transcript_{n-1}` on trust — it has no
    /// history to check it against, and the inviter is handing it the chain in
    /// the same envelope — and computes `transcript_n` itself, so the value it
    /// goes forward from is one it derived.
    pub fn welcomed(commit: &Commit, chain: [u8; 32]) -> Chain {
        Chain {
            epoch: commit.epoch,
            chain,
            transcript: transcript(&commit.transcript, commit),
        }
    }

    /// Take a commit and the secret sent for it, and derive the epoch key.
    ///
    /// Advances this chain only on success. The three refusals are SIP-87's
    /// three checks and all of them are mandatory: the epoch must be the next
    /// one, the transcript must be the one this device holds, and the secret
    /// must match the contribution the committer published.
    pub fn advance(
        &mut self,
        commit: &Commit,
        commit_secret: &[u8; 32],
    ) -> std::result::Result<ChannelKey, Refused> {
        if commit.epoch != self.epoch + 1 {
            return Err(Refused::WrongEpoch {
                held: self.epoch,
                commit: commit.epoch,
            });
        }
        if commit.transcript != self.transcript {
            return Err(Refused::Transcript);
        }
        if contribution_of(commit_secret) != commit.contribution {
            return Err(Refused::Contribution);
        }
        let next = transcript(&self.transcript, commit);
        let chain_n = chain(&self.chain, commit_secret, &next);
        let key = epoch_key(&chain_n, &next);
        self.epoch = commit.epoch;
        self.chain = chain_n;
        self.transcript = next;
        Ok(key)
    }
}

/// The envelope slots a `Welcome` carries, and the epoch its range starts at.
///
/// **Where this departs from SIP-87's text, and why it has to.** SIP-87 gives
/// the plaintext as `chain[32] || key[32] × (to_epoch - from_epoch + 1)` — one
/// slot more than SIP-17's envelope permits, because SIP-17 fixes the ciphertext
/// at `16 + 32 × range` bytes and a decoder checks it. Since SIP-87's whole
/// promise is that the envelope wire does not change, the chain takes the
/// *first slot of the range* rather than a slot in front of it: the range runs
/// `from_epoch..=commit.epoch`, slot 0 is the chain, and slot `i` is the key for
/// epoch `from_epoch + i`.
///
/// So the smallest `Welcome` is two slots — the chain and the key for the epoch
/// the commit admits this device at — and `from_epoch` is one below that epoch.
/// `history` is whatever earlier keys the inviter chose, ascending and ending
/// at `commit.epoch - 1`; SIP-17 §History is the inviter's choice governs how
/// many, unchanged.
pub fn welcome(
    commit: &Commit,
    chain: &[u8; 32],
    current: &ChannelKey,
    history: &[ChannelKey],
) -> (u32, Vec<ChannelKey>) {
    let mut slots = Vec::with_capacity(2 + history.len());
    slots.push(ChannelKey::new(*chain));
    slots.extend_from_slice(history);
    slots.push(*current);
    (commit.epoch - history.len() as u32 - 1, slots)
}

/// Read a `Welcome`'s slots: the chain, then the keys and the epoch each is for.
///
/// `from_epoch` is the envelope's own, and the keys begin one above it. Two
/// things are refused rather than taken on trust:
///
/// - A range that does not end at the commit's epoch. It would claim to admit
///   this device at an epoch other than the one the log says, and the chain
///   taken from it would leave the device deriving forward from a position
///   nobody else is at.
/// - A key for the admitted epoch that is not the one the chain derives. This is
///   the one check a joiner *can* make on a `Welcome` — it cannot check the
///   chain itself against anything, since `contribution` matches a commit secret
///   and a `Welcome` carries none — and it catches an inviter whose chain and
///   whose key do not agree, which is equivocation with a signature on it.
pub fn read_welcome(
    commit: &Commit,
    from_epoch: u32,
    slots: &[ChannelKey],
) -> std::result::Result<(Chain, Vec<(u32, ChannelKey)>), Refused> {
    let to = from_epoch + slots.len().saturating_sub(1) as u32;
    if slots.len() < 2 || to != commit.epoch {
        return Err(Refused::WrongEpoch {
            held: to,
            commit: commit.epoch,
        });
    }
    let chain = Chain::welcomed(commit, *slots[0].as_bytes());
    let keys: Vec<(u32, ChannelKey)> = slots[1..]
        .iter()
        .enumerate()
        .map(|(i, k)| (from_epoch + 1 + i as u32, *k))
        .collect();
    let derived = epoch_key(&chain.chain, &chain.transcript);
    let carried = keys
        .iter()
        .find(|(e, _)| *e == commit.epoch)
        .map(|(_, k)| k);
    if carried != Some(&derived) {
        return Err(Refused::Welcome);
    }
    Ok((chain, keys))
}

impl std::fmt::Display for Chain {
    /// Never print the chain. A chain secret plus the log is every future
    /// epoch of the channel.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Chain(epoch {}, <redacted>)", self.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded(b: u8) -> ([u8; 32], PubKey) {
        let seed = [b; 32];
        let pk = PubKey::new(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        (seed, pk)
    }

    fn commit_at(epoch: u32, committer: PubKey, prev: [u8; 32], secret: &[u8; 32]) -> Commit {
        Commit {
            epoch,
            committer,
            adds: Vec::new(),
            removes: Vec::new(),
            contribution: contribution_of(secret),
            transcript: prev,
            sig: [0; 64],
        }
    }

    #[test]
    fn a_commit_round_trips() {
        let (seed, pk) = seeded(1);
        let mut c = commit_at(1, pk, GENESIS_TRANSCRIPT, &[7; 32]);
        c.adds = vec![PubKey::new([1; 32]), PubKey::new([9; 32])];
        c.removes = vec![PubKey::new([4; 32])];
        c.sign(&seed);
        let back = Commit::decode(&c.encode()).unwrap();
        assert_eq!(back, c);
        assert!(back.verify(&pk));
    }

    #[test]
    fn a_commit_body_with_unordered_adds_is_refused() {
        let (seed, pk) = seeded(1);
        let mut c = commit_at(1, pk, GENESIS_TRANSCRIPT, &[7; 32]);
        c.adds = vec![PubKey::new([9; 32]), PubKey::new([1; 32])];
        c.sign(&seed);
        assert!(Commit::decode(&c.encode()).is_err());
    }

    #[test]
    fn a_commit_that_adds_and_removes_one_account_is_refused() {
        let (seed, pk) = seeded(1);
        let mut c = commit_at(1, pk, GENESIS_TRANSCRIPT, &[7; 32]);
        c.adds = vec![PubKey::new([9; 32])];
        c.removes = vec![PubKey::new([9; 32])];
        c.sign(&seed);
        assert!(Commit::decode(&c.encode()).is_err());
    }

    #[test]
    fn a_commit_with_a_trailing_byte_is_refused() {
        let (seed, pk) = seeded(1);
        let mut c = commit_at(1, pk, GENESIS_TRANSCRIPT, &[7; 32]);
        c.sign(&seed);
        let mut bytes = c.encode();
        bytes.push(0);
        assert!(Commit::decode(&bytes).is_err());
    }

    #[test]
    fn a_changed_field_breaks_the_signature() {
        let (seed, pk) = seeded(1);
        let mut c = commit_at(1, pk, GENESIS_TRANSCRIPT, &[7; 32]);
        c.sign(&seed);
        assert!(c.verify(&pk));
        c.contribution[0] ^= 1;
        assert!(!c.verify(&pk));
    }

    #[test]
    fn two_members_of_one_chain_derive_one_key() {
        let (_, pk) = seeded(1);
        let start = Chain::create();
        let mut a = start;
        let mut b = start;
        let secret = [3u8; 32];
        let commit = commit_at(1, pk, start.transcript, &secret);
        let ka = a.advance(&commit, &secret).unwrap();
        let kb = b.advance(&commit, &secret).unwrap();
        assert_eq!(ka.as_bytes(), kb.as_bytes());
        assert_eq!(a, b);
        assert_eq!(a.epoch, 1);
    }

    #[test]
    fn the_contribution_alone_does_not_give_the_key() {
        // An outsider enveloped the commit secret holds the secret and the log
        // and still cannot compute the key: `chain_{n-1}` is not in either.
        let (_, pk) = seeded(1);
        let secret = [3u8; 32];
        let mine = Chain::create();
        let theirs = Chain::create();
        let commit = commit_at(1, pk, GENESIS_TRANSCRIPT, &secret);
        let mut a = mine;
        let mut b = theirs;
        let ka = a.advance(&commit, &secret).unwrap();
        let kb = b.advance(&commit, &secret).unwrap();
        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn a_device_two_epochs_behind_refuses_a_commit_secret() {
        let (_, pk) = seeded(1);
        let mut live = Chain::create();
        let behind = live;
        for e in 1..=3 {
            let secret = [e as u8; 32];
            let c = commit_at(e, pk, live.transcript, &secret);
            live.advance(&c, &secret).unwrap();
        }
        // The next commit, handed to a device still at epoch 1.
        let mut stale = behind;
        let secret = [9u8; 32];
        let c = commit_at(1, pk, behind.transcript, &secret);
        stale.advance(&c, &secret).unwrap();
        assert_eq!(stale.epoch, 1);
        let secret = [4u8; 32];
        let fourth = commit_at(4, pk, live.transcript, &secret);
        assert_eq!(
            stale.advance(&fourth, &secret),
            Err(Refused::WrongEpoch { held: 1, commit: 4 })
        );
        assert_eq!(stale.epoch, 1, "a refusal must not move the chain");
    }

    #[test]
    fn a_secret_that_is_not_the_published_contribution_is_refused() {
        let (_, pk) = seeded(1);
        let mut c = Chain::create();
        let commit = commit_at(1, pk, c.transcript, &[3; 32]);
        assert_eq!(c.advance(&commit, &[4; 32]), Err(Refused::Contribution));
        assert_eq!(c.epoch, 0);
    }

    #[test]
    fn a_commit_stating_another_history_is_refused() {
        let (_, pk) = seeded(1);
        let mut c = Chain::create();
        let secret = [3u8; 32];
        let mut commit = commit_at(1, pk, c.transcript, &secret);
        commit.transcript[0] ^= 1;
        assert_eq!(c.advance(&commit, &secret), Err(Refused::Transcript));
    }

    #[test]
    fn disagreement_about_the_member_set_is_a_different_key() {
        // SIP-87: two members who disagree about who was added derive
        // different keys and discover it on the next entry, rather than
        // agreeing on a key while disagreeing about the group.
        let (_, pk) = seeded(1);
        let start = Chain::create();
        let secret = [3u8; 32];
        let honest = commit_at(1, pk, start.transcript, &secret);
        let mut altered = honest.clone();
        altered.adds = vec![PubKey::new([2; 32])];
        let mut a = start;
        let mut b = start;
        let ka = a.advance(&honest, &secret).unwrap();
        let kb = b.advance(&altered, &secret).unwrap();
        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn a_welcomed_device_goes_on_in_step_with_the_members() {
        let (_, pk) = seeded(1);
        let mut founder = Chain::create();
        let s1 = [1u8; 32];
        let c1 = commit_at(1, pk, founder.transcript, &s1);
        founder.advance(&c1, &s1).unwrap();

        // Epoch 2 admits somebody, who is welcomed with the chain as of it.
        let s2 = [2u8; 32];
        let mut c2 = commit_at(2, pk, founder.transcript, &s2);
        c2.adds = vec![PubKey::new([5; 32])];
        let k2 = founder.advance(&c2, &s2).unwrap();
        let mut joiner = Chain::welcomed(&c2, founder.chain);
        assert_eq!(joiner, founder);
        assert_eq!(
            epoch_key(&joiner.chain, &joiner.transcript).as_bytes(),
            k2.as_bytes()
        );

        // And the next commit lands on both alike.
        let s3 = [3u8; 32];
        let c3 = commit_at(3, pk, founder.transcript, &s3);
        assert_eq!(
            founder.advance(&c3, &s3).unwrap().as_bytes(),
            joiner.advance(&c3, &s3).unwrap().as_bytes()
        );
    }

    #[test]
    fn a_joiner_cannot_reach_the_epoch_before_its_own() {
        let (_, pk) = seeded(1);
        let mut founder = Chain::create();
        let s1 = [1u8; 32];
        let c1 = commit_at(1, pk, founder.transcript, &s1);
        let k1 = founder.advance(&c1, &s1).unwrap();
        let s2 = [2u8; 32];
        let mut c2 = commit_at(2, pk, founder.transcript, &s2);
        c2.adds = vec![PubKey::new([5; 32])];
        founder.advance(&c2, &s2).unwrap();
        let joiner = Chain::welcomed(&c2, founder.chain);
        // It holds the chain and the whole log, and epoch 1's key is not in
        // either: the chain runs forward and the secret alone is not the key.
        assert_ne!(
            epoch_key(&joiner.chain, &joiner.transcript).as_bytes(),
            k1.as_bytes()
        );
        assert_ne!(chain(&joiner.chain, &s1, &joiner.transcript), founder.chain);
    }

    /// Walk a chain forward to `until`, returning the keys it produced.
    fn keyed(chain: &mut Chain, who: PubKey, until: u32) -> Vec<ChannelKey> {
        let mut keys = Vec::new();
        for e in 1..=until {
            let secret = [e as u8; 32];
            let c = commit_at(e, who, chain.transcript, &secret);
            keys.push(chain.advance(&c, &secret).unwrap());
        }
        keys
    }

    #[test]
    fn a_welcome_carries_the_chain_in_the_first_slot_of_its_range() {
        let (_, pk) = seeded(1);
        let mut founder = Chain::create();
        let past = keyed(&mut founder, pk, 2);
        let s3 = [3u8; 32];
        let mut c3 = commit_at(3, pk, founder.transcript, &s3);
        c3.adds = vec![PubKey::new([5; 32])];
        let k3 = founder.advance(&c3, &s3).unwrap();

        // The whole history: two past keys plus the admitted epoch's.
        let (from, slots) = welcome(&c3, &founder.chain, &k3, &past);
        assert_eq!(
            from, 0,
            "three keys end at epoch 3, so the range starts at 0"
        );
        assert_eq!(
            slots.len() as u32,
            c3.epoch - from + 1,
            "SIP-17 fixes the ciphertext at 16 + 32 × range"
        );
        let (chain, keys) = read_welcome(&c3, from, &slots).unwrap();
        assert_eq!(chain, founder);
        assert_eq!(
            keys.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(keys[2].1.as_bytes(), k3.as_bytes());

        // And the smallest one: the chain and the epoch it admits, nothing else.
        let (from, slots) = welcome(&c3, &founder.chain, &k3, &[]);
        assert_eq!((from, slots.len()), (2, 2));
        let (chain, keys) = read_welcome(&c3, from, &slots).unwrap();
        assert_eq!(chain, founder);
        assert_eq!(keys, vec![(3, k3)]);
    }

    #[test]
    fn a_welcome_whose_range_misses_the_commit_is_refused() {
        let (_, pk) = seeded(1);
        let mut founder = Chain::create();
        keyed(&mut founder, pk, 2);
        let s3 = [3u8; 32];
        let mut c3 = commit_at(3, pk, founder.transcript, &s3);
        c3.adds = vec![PubKey::new([5; 32])];
        let k3 = founder.advance(&c3, &s3).unwrap();
        let (from, slots) = welcome(&c3, &founder.chain, &k3, &[]);
        // Read at one epoch either side of where it was published: the device
        // would take the chain and go forward from a position nobody is at.
        for at in [from - 1, from + 1] {
            assert!(
                matches!(
                    read_welcome(&c3, at, &slots),
                    Err(Refused::WrongEpoch { .. })
                ),
                "a welcome read at epoch {at} was taken"
            );
        }
        // And the chain alone, with no key beside it, is not a welcome.
        assert!(matches!(
            read_welcome(&c3, from, &slots[..1]),
            Err(Refused::WrongEpoch { .. })
        ));
    }

    #[test]
    fn a_welcome_whose_key_the_chain_does_not_derive_is_refused() {
        // The one check a joiner can make: it holds no commit secret, so
        // `contribution` tells it nothing, and an inviter who hands over a chain
        // and a key that disagree would otherwise be undetectable.
        let (_, pk) = seeded(1);
        let mut founder = Chain::create();
        let s1 = [1u8; 32];
        let mut c1 = commit_at(1, pk, founder.transcript, &s1);
        c1.adds = vec![PubKey::new([5; 32])];
        founder.advance(&c1, &s1).unwrap();
        let (from, slots) = welcome(&c1, &founder.chain, &ChannelKey::new([9; 32]), &[]);
        assert_eq!(read_welcome(&c1, from, &slots), Err(Refused::Welcome));
    }

    #[test]
    fn the_chain_does_not_print_itself() {
        let c = Chain::create();
        assert_eq!(format!("{c}"), "Chain(epoch 0, <redacted>)");
        assert!(!format!("{c:?}").is_empty());
    }
}
