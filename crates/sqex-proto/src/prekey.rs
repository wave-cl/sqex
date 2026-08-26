//! SIP-23 device prekeys: single-use keys so an envelope is fresh at both ends.
//!
//! SIP-17 seals a channel key to a device. Before this, it sealed against that
//! device's **long-term** identity, which made the exchange's pile of stored
//! envelopes a harvest-now decrypt-later attack with an unusually good yield:
//! worthless today, an entire history the moment any one identity key turned
//! up, and *larger* the more often the channel rotated.
//!
//! A prekey is the remedy X3DH reaches for. A device publishes single-use
//! X25519 keys in advance, signed under its own Ed25519 key; the exchange hands
//! each out once; the device destroys the secret on use. The envelope then has
//! a fresh key at both ends, and the recorded ciphertext stays shut.
//!
//! # What this does not buy
//!
//! Nothing about a compromised device. A client that can show you last month's
//! conversation is holding last month's channel keys, and taking the machine
//! takes them. This protects key *distribution*, not key *storage*, and the
//! distinction is the difference between an attacker who copied the exchange's
//! envelopes and one who has somebody's laptop.
//!
//! # Deleting is the mechanism
//!
//! A client that keeps prekey secrets — so that reinstalling is painless, say —
//! has implemented the wire format and none of the property, in the way least
//! likely to be noticed, because everything still works.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for a prekey signature.
pub const PREKEY_CONTEXT: &[u8] = b"sqex-prekey-v1";

pub const TYPE_PUBLISH: u8 = 0x01;
pub const TYPE_TAKE: u8 = 0x02;
pub const TYPE_COUNT: u8 = 0x03;

/// Served once, then gone. The forward secrecy is entirely in this.
pub const KIND_ONE_TIME: u8 = 0x01;
/// Served whenever the one-time pool is empty, and reusable by construction.
///
/// It exists so that a drained pool cannot block a *rotation*: a security
/// mechanism able to prevent a revocation is a poor trade. It bounds the loss
/// to a window rather than to everything.
pub const KIND_FALLBACK: u8 = 0x02;

/// One-time prekeys a device should keep published.
pub const POOL: u16 = 64;
/// Top up when the pool falls below this.
pub const LOW_WATER: u16 = 16;
/// Prekeys one `Publish` may carry.
pub const MAX_PUBLISH: usize = 64;
/// One-time prekeys the exchange stores per device.
pub const MAX_STORED: usize = 128;
/// How long a fallback should live before being replaced. The real granularity
/// of this SIP's guarantee in the worst case.
pub const FALLBACK_MAX_AGE: u64 = 7 * 24 * 60 * 60;

/// Bytes of a prekey on the wire.
pub const PREKEY_LEN: usize = 1 + 4 + 32 + 64;

/// A published prekey: an X25519 public key the device signed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prekey {
    pub kind: u8,
    pub id: u32,
    pub public: [u8; 32],
    pub signature: [u8; 64],
}

/// The bytes a prekey signature covers.
///
/// The device is in the input, so a prekey cannot be lifted from one device's
/// pool and republished under another's name.
fn signing_input(device: &PubKey, kind: u8, id: u32, public: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PREKEY_CONTEXT.len() + 32 + 1 + 4 + 32);
    m.extend_from_slice(PREKEY_CONTEXT);
    m.extend_from_slice(device.as_bytes());
    m.push(kind);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(public);
    m
}

impl Prekey {
    /// Mint and sign one. Returns the secret alongside, which the caller keeps
    /// and **must destroy after use** — that deletion is the whole mechanism.
    pub fn generate(
        device_seed: &[u8; 32],
        kind: u8,
        id: u32,
    ) -> (Prekey, x25519_dalek::StaticSecret) {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let signing = SigningKey::from_bytes(device_seed);
        let device = PubKey::new(signing.verifying_key().to_bytes());
        let signature = signing
            .sign(&signing_input(&device, kind, id, &public))
            .to_bytes();
        (
            Prekey {
                kind,
                id,
                public,
                signature,
            },
            secret,
        )
    }

    /// Check that `device` really published this.
    ///
    /// A sender **MUST** do this itself before sealing. The exchange verifies
    /// at publish time too, but the exchange is the party this signature exists
    /// to constrain, so a sender that trusts its check has verified nothing.
    pub fn verify(&self, device: &PubKey) -> Result<()> {
        if self.id == 0 {
            return Err(Error::Malformed("prekey id 0 is reserved".into()));
        }
        if self.kind != KIND_ONE_TIME && self.kind != KIND_FALLBACK {
            return Err(Error::Malformed(format!("unknown prekey kind {}", self.kind)));
        }
        let vk = VerifyingKey::from_bytes(device.as_bytes())
            .map_err(|e| Error::Key(format!("device key: {e}")))?;
        vk.verify(
            &signing_input(device, self.kind, self.id, &self.public),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Error::BadSignature)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.signature);
    }

    fn read(b: &[u8], o: usize) -> Prekey {
        Prekey {
            kind: b[o],
            id: u32::from_be_bytes(b[o + 1..o + 5].try_into().unwrap()),
            public: b[o + 5..o + 37].try_into().unwrap(),
            signature: b[o + 37..o + 101].try_into().unwrap(),
        }
    }
}

/// Add one-time prekeys to the caller's pool, and replace its fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub prekeys: Vec<Prekey>,
}

impl Publish {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.prekeys.len() * PREKEY_LEN);
        out.push(TYPE_PUBLISH);
        out.extend_from_slice(&(self.prekeys.len() as u16).to_be_bytes());
        for p in &self.prekeys {
            p.write(&mut out);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Publish> {
        if b.len() < 3 {
            return Err(Error::Malformed(format!(
                "publish is {} bytes, want at least 3",
                b.len()
            )));
        }
        if b[0] != TYPE_PUBLISH {
            return Err(Error::Malformed(format!(
                "not a publish (type {:#x})",
                b[0]
            )));
        }
        let count = u16::from_be_bytes(b[1..3].try_into().unwrap()) as usize;
        if count > MAX_PUBLISH {
            return Err(Error::Malformed(format!(
                "publish carries {count} prekeys, limit is {MAX_PUBLISH}"
            )));
        }
        if b.len() != 3 + count * PREKEY_LEN {
            return Err(Error::Malformed(format!(
                "publish is {} bytes, want {}",
                b.len(),
                3 + count * PREKEY_LEN
            )));
        }
        Ok(Publish {
            prekeys: (0..count).map(|i| Prekey::read(b, 3 + i * PREKEY_LEN)).collect(),
        })
    }
}

/// Ask for one prekey for `device`, consuming it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Take {
    pub device: PubKey,
}

impl Take {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_TAKE);
        out.extend_from_slice(self.device.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Take> {
        if b.len() != 33 {
            return Err(Error::Malformed(format!(
                "take is {} bytes, want 33",
                b.len()
            )));
        }
        if b[0] != TYPE_TAKE {
            return Err(Error::Malformed(format!("not a take (type {:#x})", b[0])));
        }
        Ok(Take {
            device: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// The prekey the exchange served, if the device had published any.
///
/// `found: 0` means it has published nothing, and a caller MUST NOT then seal
/// to it at all — there is deliberately no static-only path, because an
/// optional one is a downgrade a dishonest exchange could force by reporting an
/// empty pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Taken {
    pub found: bool,
    pub prekey: Option<Prekey>,
    pub now: u64,
}

impl Taken {
    pub fn none(now: u64) -> Taken {
        Taken {
            found: false,
            prekey: None,
            now,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + PREKEY_LEN + 8);
        out.push(u8::from(self.found));
        match &self.prekey {
            Some(p) => p.write(&mut out),
            // Not found and found are the same shape, as SIP-4 and SIP-5 do
            // with their own absences.
            None => out.extend(std::iter::repeat_n(0u8, PREKEY_LEN)),
        }
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Taken> {
        if b.len() != 1 + PREKEY_LEN + 8 {
            return Err(Error::Malformed(format!(
                "taken is {} bytes, want {}",
                b.len(),
                1 + PREKEY_LEN + 8
            )));
        }
        let found = b[0] != 0;
        Ok(Taken {
            found,
            prekey: found.then(|| Prekey::read(b, 1)),
            now: u64::from_be_bytes(b[1 + PREKEY_LEN..].try_into().unwrap()),
        })
    }
}

/// What the caller has left, so it knows when to top up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub one_time: u16,
    pub fallback_id: u32,
    pub now: u64,
}

impl Counts {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14);
        out.extend_from_slice(&self.one_time.to_be_bytes());
        out.extend_from_slice(&self.fallback_id.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Counts> {
        if b.len() != 14 {
            return Err(Error::Malformed(format!(
                "counts is {} bytes, want 14",
                b.len()
            )));
        }
        Ok(Counts {
            one_time: u16::from_be_bytes(b[0..2].try_into().unwrap()),
            fallback_id: u32::from_be_bytes(b[2..6].try_into().unwrap()),
            now: u64::from_be_bytes(b[6..14].try_into().unwrap()),
        })
    }
}

/// The secrets behind a device's published prekeys, and the rule for spending
/// them.
///
/// SIP-23 puts four cases on a recipient opening an envelope, and only one of
/// them is the happy path:
///
/// - a one-time prekey it holds: use it, and **destroy the secret**;
/// - a one-time prekey it has already consumed: **reject the envelope**;
/// - its current fallback: use it and keep the secret, since a fallback is
///   reusable by construction;
/// - a fallback it has already replaced: reject.
///
/// The two rejections matter more than they look. An exchange that hands one
/// one-time prekey out twice has quietly removed the forward secrecy from both
/// envelopes, and the recipient is the only party positioned to notice — the
/// same shape as SIP-17's `(device, epoch, msg_seq)` rule and there for a
/// related reason. Spent ids are therefore remembered, so that a replay is
/// refused *as a replay* rather than mistaken for an id we never held.
///
/// Minting goes through here too, because ids **MUST NEVER be reused**, and a
/// counter kept anywhere else is a counter that can disagree with the secrets.
pub struct Pool {
    seed: [u8; 32],
    next_id: u32,
    one_time: std::collections::HashMap<u32, x25519_dalek::StaticSecret>,
    fallback: Option<(u32, x25519_dalek::StaticSecret)>,
    spent: std::collections::HashSet<u32>,
}

/// Counts only. `StaticSecret` deliberately has no `Debug`, and a pool that
/// printed its secrets would undo the point of deleting them.
impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("one_time", &self.one_time.len())
            .field("fallback_id", &self.fallback_id())
            .field("spent", &self.spent.len())
            .finish()
    }
}

impl Pool {
    /// An empty pool for the device holding `seed`. Ids start at 1, since 0 is
    /// reserved.
    pub fn new(seed: &[u8; 32]) -> Pool {
        Pool {
            seed: *seed,
            next_id: 1,
            one_time: std::collections::HashMap::new(),
            fallback: None,
            spent: std::collections::HashSet::new(),
        }
    }

    /// Mint `n` one-time prekeys, keeping the secrets. The returned prekeys are
    /// what goes in a `Publish`.
    pub fn mint_one_time(&mut self, n: u16) -> Vec<Prekey> {
        (0..n)
            .map(|_| {
                let id = self.next_id;
                self.next_id += 1;
                let (p, secret) = Prekey::generate(&self.seed, KIND_ONE_TIME, id);
                self.one_time.insert(id, secret);
                p
            })
            .collect()
    }

    /// Mint a fallback, retiring the one it replaces.
    ///
    /// The retired id goes to `spent`: an envelope sealed against a fallback we
    /// have already replaced is refused, which is what makes ageing a fallback
    /// out on a schedule mean anything.
    pub fn mint_fallback(&mut self) -> Prekey {
        let id = self.next_id;
        self.next_id += 1;
        let (p, secret) = Prekey::generate(&self.seed, KIND_FALLBACK, id);
        if let Some((old, _)) = self.fallback.replace((id, secret)) {
            self.spent.insert(old);
        }
        p
    }

    /// The secret for `id`, applying the rule above.
    ///
    /// A one-time secret is removed here rather than after the envelope opens.
    /// The id is spent the moment the exchange served it, so a failed open is
    /// not grounds to keep the secret for a second attempt — that would be the
    /// replay window this check exists to close.
    pub fn take(&mut self, id: u32) -> Result<x25519_dalek::StaticSecret> {
        if id == 0 {
            return Err(Error::Malformed(
                "envelope names prekey id 0, which is invalid".into(),
            ));
        }
        if self.spent.contains(&id) {
            return Err(Error::Key(format!(
                "prekey {id} is spent: the exchange served it twice, or this is a replay"
            )));
        }
        if let Some(secret) = self.one_time.remove(&id) {
            self.spent.insert(id);
            return Ok(secret);
        }
        match &self.fallback {
            Some((f, secret)) if *f == id => Ok(secret.clone()),
            _ => Err(Error::Key(format!("prekey {id} was never published by us"))),
        }
    }

    /// One-time prekeys still unspent, for deciding whether to top up.
    pub fn one_time_left(&self) -> u16 {
        self.one_time.len() as u16
    }

    /// The current fallback's id, or 0 if there is none.
    pub fn fallback_id(&self) -> u32 {
        self.fallback.as_ref().map_or(0, |(id, _)| *id)
    }

    /// Everything the pool would need to be rebuilt, secrets included.
    ///
    /// **This is the only way secrets leave a `Pool`, and it exists because a
    /// client that cannot reload them has no forward secrecy to lose — it has a
    /// conversation it can no longer read.** A caller that writes this anywhere
    /// unencrypted has undone the mechanism as thoroughly as never deleting a
    /// secret in the first place.
    ///
    /// `next_id` and `spent` are as load-bearing as the secrets. Without the
    /// first, a reloaded pool re-mints ids it has already published and the
    /// exchange refuses them. Without the second, a restart silently forgives a
    /// replay that the pool had already refused.
    pub fn save(&self) -> PoolState {
        PoolState {
            next_id: self.next_id,
            one_time: self
                .one_time
                .iter()
                .map(|(id, s)| (*id, s.to_bytes()))
                .collect(),
            fallback: self.fallback.as_ref().map(|(id, s)| (*id, s.to_bytes())),
            spent: self.spent.iter().copied().collect(),
        }
    }

    /// Rebuild a pool from `save`.
    pub fn load(seed: &[u8; 32], state: PoolState) -> Pool {
        Pool {
            seed: *seed,
            next_id: state.next_id.max(1),
            one_time: state
                .one_time
                .into_iter()
                .map(|(id, b)| (id, x25519_dalek::StaticSecret::from(b)))
                .collect(),
            fallback: state
                .fallback
                .map(|(id, b)| (id, x25519_dalek::StaticSecret::from(b))),
            spent: state.spent.into_iter().collect(),
        }
    }
}

/// A pool's contents as plain data, for a client that has somewhere to put it.
///
/// Deliberately not `Debug` and deliberately not serialisable by this crate:
/// `sqex-proto` has no filesystem and no serde, and choosing how these bytes
/// are protected at rest is the caller's decision, not one to make for them.
pub struct PoolState {
    pub next_id: u32,
    pub one_time: Vec<(u32, [u8; 32])>,
    pub fallback: Option<(u32, [u8; 32])>,
    pub spent: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    #[test]
    fn a_prekey_verifies_under_the_device_that_signed_it() {
        let (seed, key) = device(1);
        let (p, _secret) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert!(p.verify(&key).is_ok());
    }

    #[test]
    fn a_prekey_does_not_verify_under_another_device() {
        // The device is in the signing input precisely so a prekey cannot be
        // lifted from one pool and republished under another name.
        let (seed, _) = device(1);
        let (_, other) = device(2);
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert!(p.verify(&other).is_err());
    }

    #[test]
    fn a_tampered_prekey_is_refused() {
        let (seed, key) = device(1);
        let (mut p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        p.public[0] ^= 1;
        assert!(p.verify(&key).is_err());

        let (mut p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        p.id = 8;
        assert!(p.verify(&key).is_err());

        // Including the kind: a one-time key re-presented as a reusable
        // fallback would silently give up the forward secrecy.
        let (mut p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        p.kind = KIND_FALLBACK;
        assert!(p.verify(&key).is_err());
    }

    #[test]
    fn id_zero_is_reserved() {
        let (seed, key) = device(1);
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 0);
        assert!(p.verify(&key).is_err());
    }

    #[test]
    fn publish_round_trips() {
        let (seed, _) = device(1);
        let prekeys = (1..=3).map(|i| Prekey::generate(&seed, KIND_ONE_TIME, i).0).collect();
        let p = Publish { prekeys };
        assert_eq!(Publish::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn publish_bounds_its_batch() {
        let (seed, _) = device(1);
        let prekeys = (1..=(MAX_PUBLISH as u32 + 1))
            .map(|i| Prekey::generate(&seed, KIND_ONE_TIME, i).0)
            .collect();
        assert!(Publish::decode(&Publish { prekeys }.encode()).is_err());
    }

    #[test]
    fn taken_round_trips_both_ways() {
        let (seed, _) = device(1);
        let (p, _) = Prekey::generate(&seed, KIND_FALLBACK, 9);
        let got = Taken {
            found: true,
            prekey: Some(p),
            now: 42,
        };
        assert_eq!(Taken::decode(&got.encode()).unwrap(), got);

        let none = Taken::none(42);
        assert_eq!(Taken::decode(&none.encode()).unwrap(), none);
        // Absence and presence are the same length on the wire.
        assert_eq!(none.encode().len(), got.encode().len());
    }

    #[test]
    fn take_and_counts_round_trip() {
        let (_, key) = device(3);
        let t = Take { device: key };
        assert_eq!(Take::decode(&t.encode()).unwrap(), t);
        let c = Counts {
            one_time: 12,
            fallback_id: 5,
            now: 99,
        };
        assert_eq!(Counts::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn a_one_time_prekey_opens_once_and_a_replay_is_refused() {
        let (seed, key) = device(1);
        let mut pool = Pool::new(&seed);
        let published = pool.mint_one_time(3);
        assert_eq!(published.len(), 3);
        assert!(published[0].verify(&key).is_ok());

        let id = published[0].id;
        assert!(pool.take(id).is_ok());
        // An exchange serving the same one-time prekey twice has removed the
        // forward secrecy from both envelopes, and we are the only party who
        // can see it.
        assert!(pool.take(id).is_err());
        assert_eq!(pool.one_time_left(), 2);
    }

    #[test]
    fn ids_are_never_reused_across_kinds() {
        let (seed, _) = device(1);
        let mut pool = Pool::new(&seed);
        let mut ids: Vec<u32> = pool.mint_one_time(4).iter().map(|p| p.id).collect();
        ids.push(pool.mint_fallback().id);
        ids.extend(pool.mint_one_time(2).iter().map(|p| p.id));
        ids.push(pool.mint_fallback().id);
        let unique: std::collections::HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len());
        assert!(!ids.contains(&0), "id 0 is reserved");
    }

    #[test]
    fn a_fallback_is_reusable_until_it_is_replaced() {
        let (seed, _) = device(1);
        let mut pool = Pool::new(&seed);
        let first = pool.mint_fallback();
        assert_eq!(pool.fallback_id(), first.id);
        // Reusable by construction, which is why it is aged out on a schedule.
        assert!(pool.take(first.id).is_ok());
        assert!(pool.take(first.id).is_ok());

        let second = pool.mint_fallback();
        assert_eq!(pool.fallback_id(), second.id);
        assert!(pool.take(second.id).is_ok());
        // Replacing it is what makes the schedule mean anything.
        assert!(pool.take(first.id).is_err());
    }

    #[test]
    fn an_id_we_never_published_is_refused_and_so_is_zero() {
        let (seed, _) = device(1);
        let mut pool = Pool::new(&seed);
        pool.mint_one_time(2);
        assert!(pool.take(0).is_err());
        assert!(pool.take(999).is_err());
    }

    #[test]
    fn a_reloaded_pool_still_refuses_a_spent_prekey() {
        let (seed, _) = device(1);
        let mut pool = Pool::new(&seed);
        let published = pool.mint_one_time(3);
        let spent = published[0].id;
        pool.take(spent).unwrap();

        let mut reloaded = Pool::load(&seed, pool.save());
        // The spent set survives, or a restart quietly forgives a replay the
        // pool had already refused.
        assert!(reloaded.take(spent).is_err());
    }

    #[test]
    fn a_reloaded_pool_opens_an_envelope_sealed_to_it() {
        // The proof that the right bytes came back, not merely some bytes: seal
        // against the published public key, reload, and open. A pool that
        // round-tripped a secret incorrectly would still hand one over here and
        // would still fail this.
        use crate::channel_key::{ChannelKey, open_envelope, seal_envelope};

        let (seed, key) = device(1);
        let mut pool = Pool::new(&seed);
        let published = pool.mint_one_time(2);
        let target = published[1];

        let epoch_key = ChannelKey::generate();
        let envelope = seal_envelope(&key, target.id, &target.public, 1, &[epoch_key]).unwrap();

        let mut reloaded = Pool::load(&seed, pool.save());
        let secret = reloaded.take(target.id).expect("the secret survived");
        assert_eq!(
            open_envelope(&seed, &secret, &envelope).unwrap(),
            vec![epoch_key]
        );
    }

    #[test]
    fn a_reloaded_pool_does_not_reissue_published_ids() {
        // Pool::new starts at 1, so a client that reloaded by starting over
        // would re-mint ids the exchange has already stored and be refused.
        let (seed, _) = device(1);
        let mut pool = Pool::new(&seed);
        let first: Vec<u32> = pool.mint_one_time(4).iter().map(|p| p.id).collect();

        let mut reloaded = Pool::load(&seed, pool.save());
        let next: Vec<u32> = reloaded.mint_one_time(4).iter().map(|p| p.id).collect();
        assert!(
            next.iter().all(|id| !first.contains(id)),
            "reloading reissued {first:?} as {next:?}"
        );
        assert_eq!(reloaded.fallback_id(), 0);
    }

    #[test]
    fn a_reloaded_pool_keeps_its_fallback() {
        let (seed, _) = device(1);
        let mut pool = Pool::new(&seed);
        let fallback = pool.mint_fallback();

        let mut reloaded = Pool::load(&seed, pool.save());
        assert_eq!(reloaded.fallback_id(), fallback.id);
        // Still reusable, and still refused once replaced.
        assert!(reloaded.take(fallback.id).is_ok());
        reloaded.mint_fallback();
        assert!(reloaded.take(fallback.id).is_err());
    }
}
