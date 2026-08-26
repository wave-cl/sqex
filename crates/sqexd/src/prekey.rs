//! SIP-23 prekeys: published in advance, served once, destroyed on use.
//!
//! The exchange's whole job here is to hand each one-time prekey out **at most
//! once**. It cannot enforce the deletion at the other end — that is the
//! device's — and it cannot be trusted to serve honestly either, which is why a
//! recipient rejects an envelope naming a prekey id it has already consumed.
//! What it can do is not be the thing that breaks the property by accident.
//!
//! It verifies signatures at publish time, and that is worth being clear about:
//! the check stops one device filling another's pool, and it is *not* what
//! makes a sender safe. A sender verifies for itself, because the exchange is
//! the party the signature exists to constrain.

use std::collections::HashMap;
use std::sync::Mutex;

use sqex_proto::prekey::{
    CLEAR_WINDOW, Cleared, Counts, KIND_FALLBACK, KIND_ONE_TIME, MAX_CLEAR, MAX_STORED, Prekey,
    Taken,
};
use sqnr_core::PubKey;

use crate::state::now_unix;

/// Why a publish was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrekeyError {
    /// A signature did not verify under the publishing device.
    BadSignature,
    /// An id this device has used before. Reuse would let the same key be
    /// served twice under different cover.
    ReusedId,
    /// The device already holds as many one-time prekeys as it may.
    PoolFull,
    /// More `Clear` calls than SIP-23 allows in the window.
    ClearQuota,
}

impl PrekeyError {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrekeyError::BadSignature => "bad_signature",
            PrekeyError::ReusedId => "reused_id",
            PrekeyError::PoolFull => "pool_full",
            PrekeyError::ClearQuota => "clear_quota",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            PrekeyError::BadSignature => 401,
            PrekeyError::ReusedId => 409,
            PrekeyError::PoolFull => 507,
            PrekeyError::ClearQuota => 429,
        }
    }
}

#[derive(Default)]
struct Pool {
    /// Oldest first; served from the front.
    one_time: Vec<Prekey>,
    fallback: Option<Prekey>,
    /// Every id this device has ever published, so none is reused. SIP-23 says
    /// ids MUST NEVER be reused, including across a fallback being replaced.
    seen: std::collections::HashSet<u32>,
    /// The highest id ever seen, kept **apart from the prekeys themselves** so
    /// that discarding them does not lower it. Same shape as SIP-16's `msg_seq`
    /// mark and there for the same reason: the record exists to stop a counter
    /// being reused, so pruning what it describes must not move it.
    high_water: u32,
    /// When this device's recent `Clear` calls landed, for the rate limit.
    cleared_at: Vec<u64>,
}

#[derive(Default)]
pub struct Prekeys {
    pools: Mutex<HashMap<PubKey, Pool>>,
}

impl Prekeys {
    pub fn new() -> Prekeys {
        Prekeys::default()
    }

    /// Add one-time prekeys and replace the fallback. All or nothing: a batch
    /// with one bad signature in it publishes none, so a caller is never left
    /// guessing which half landed.
    pub fn publish(
        &self,
        device: &PubKey,
        prekeys: &[Prekey],
    ) -> Result<u16, PrekeyError> {
        for p in prekeys {
            p.verify(device).map_err(|_| PrekeyError::BadSignature)?;
        }
        let mut pools = self.pools.lock().unwrap();
        let pool = pools.entry(*device).or_default();

        for p in prekeys {
            if pool.seen.contains(&p.id) {
                return Err(PrekeyError::ReusedId);
            }
        }
        let arriving = prekeys.iter().filter(|p| p.kind == KIND_ONE_TIME).count();
        if pool.one_time.len() + arriving > MAX_STORED {
            return Err(PrekeyError::PoolFull);
        }

        let mut accepted = 0u16;
        for p in prekeys {
            pool.seen.insert(p.id);
            pool.high_water = pool.high_water.max(p.id);
            accepted += 1;
            match p.kind {
                KIND_FALLBACK => pool.fallback = Some(*p),
                _ => pool.one_time.push(*p),
            }
        }
        Ok(accepted)
    }

    /// Serve one prekey for `device`, consuming it.
    ///
    /// A one-time prekey is served **at most once**; when the pool is empty the
    /// fallback is served instead, which is what stops a drained pool becoming
    /// a failure to rotate. `found: 0` when the device has published nothing,
    /// and a caller must then not seal to it at all.
    pub fn take(&self, device: &PubKey) -> Taken {
        let now = now_unix();
        let mut pools = self.pools.lock().unwrap();
        let Some(pool) = pools.get_mut(device) else {
            return Taken::none(now);
        };
        if !pool.one_time.is_empty() {
            let p = pool.one_time.remove(0);
            return Taken {
                found: true,
                prekey: Some(p),
                now,
            };
        }
        match pool.fallback {
            Some(p) => Taken {
                found: true,
                prekey: Some(p),
                now,
            },
            None => Taken::none(now),
        }
    }

    /// What the caller has left. Answerable only about itself.
    pub fn count(&self, device: &PubKey) -> Counts {
        let pools = self.pools.lock().unwrap();
        let pool = pools.get(device);
        Counts {
            one_time: pool.map(|p| p.one_time.len() as u16).unwrap_or(0),
            fallback_id: pool.and_then(|p| p.fallback.map(|f| f.id)).unwrap_or(0),
            now: now_unix(),
        }
    }

    /// Discard everything this device has published, and say where to resume.
    ///
    /// For one situation: a device that has lost the secrets behind prekeys the
    /// exchange is still serving. Until it publishes again `take` answers
    /// `found: 0`, which is the point — a prekey whose secret is gone is worse
    /// than no prekey, because absence makes a caller refuse to seal while a
    /// stale one makes it seal to something that will never open.
    ///
    /// The ids are **not** forgotten. `next_id` is one above every id this
    /// device has ever used, which is the only way a client whose own record
    /// went with its secrets can publish again at all.
    pub fn clear(&self, device: &PubKey) -> Result<Cleared, PrekeyError> {
        let now = now_unix();
        let mut pools = self.pools.lock().unwrap();
        let pool = pools.entry(*device).or_default();

        pool.cleared_at
            .retain(|t| now.saturating_sub(*t) < CLEAR_WINDOW);
        if pool.cleared_at.len() >= MAX_CLEAR {
            return Err(PrekeyError::ClearQuota);
        }
        pool.cleared_at.push(now);

        let discarded = pool.one_time.len() + usize::from(pool.fallback.is_some());
        pool.one_time.clear();
        pool.fallback = None;
        Ok(Cleared {
            discarded: discarded as u16,
            next_id: pool.high_water.saturating_add(1),
            now,
        })
    }

    /// Whether a device could be sealed to at all. SIP-17's `Missing` reports
    /// this so a stranded client can be found.
    pub fn has_any(&self, device: &PubKey) -> bool {
        let pools = self.pools.lock().unwrap();
        pools
            .get(device)
            .map(|p| !p.one_time.is_empty() || p.fallback.is_some())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn device(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    #[test]
    fn a_one_time_prekey_is_served_exactly_once() {
        // The property the whole SIP rests on.
        let (seed, key) = device(1);
        let store = Prekeys::new();
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert_eq!(store.publish(&key, &[p]).unwrap(), 1);

        let first = store.take(&key);
        assert_eq!(first.prekey.unwrap().id, 1);
        // Nothing left, and no fallback was published, so the honest answer is
        // that this device cannot be sealed to.
        assert!(!store.take(&key).found);
    }

    #[test]
    fn the_fallback_is_served_when_the_pool_runs_dry() {
        let (seed, key) = device(2);
        let store = Prekeys::new();
        let (one, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        let (fb, _) = Prekey::generate(&seed, KIND_FALLBACK, 2);
        store.publish(&key, &[one, fb]).unwrap();

        assert_eq!(store.take(&key).prekey.unwrap().id, 1);
        // Reusable by construction: a drained pool must not be able to block a
        // rotation, so this answers as often as it is asked.
        assert_eq!(store.take(&key).prekey.unwrap().id, 2);
        assert_eq!(store.take(&key).prekey.unwrap().id, 2);
    }

    #[test]
    fn another_device_cannot_fill_a_pool() {
        let (seed, _) = device(3);
        let (_, other) = device(4);
        let store = Prekeys::new();
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert_eq!(store.publish(&other, &[p]), Err(PrekeyError::BadSignature));
    }

    #[test]
    fn an_id_is_never_reused() {
        let (seed, key) = device(5);
        let store = Prekeys::new();
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        store.publish(&key, &[p]).unwrap();
        store.take(&key);
        // Even after the key is gone: an id that comes round again would let
        // the same identifier mean two different keys.
        let (again, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert_eq!(store.publish(&key, &[again]), Err(PrekeyError::ReusedId));
    }

    #[test]
    fn a_batch_with_one_bad_signature_publishes_nothing() {
        let (seed, key) = device(6);
        let (other_seed, _) = device(7);
        let store = Prekeys::new();
        let (good, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        let (bad, _) = Prekey::generate(&other_seed, KIND_ONE_TIME, 2);
        assert!(store.publish(&key, &[good, bad]).is_err());
        assert!(!store.take(&key).found);
    }

    #[test]
    fn a_device_that_published_nothing_cannot_be_sealed_to() {
        let (_, key) = device(8);
        let store = Prekeys::new();
        assert!(!store.has_any(&key));
        assert!(!store.take(&key).found);
    }

    #[test]
    fn clearing_discards_the_prekeys_and_keeps_the_ids() {
        let (seed, key) = device(9);
        let store = Prekeys::new();
        let one: Vec<Prekey> = (1..=3)
            .map(|i| Prekey::generate(&seed, KIND_ONE_TIME, i).0)
            .collect();
        let (fb, _) = Prekey::generate(&seed, KIND_FALLBACK, 4);
        store.publish(&key, &one).unwrap();
        store.publish(&key, &[fb]).unwrap();

        let cleared = store.clear(&key).unwrap();
        assert_eq!(cleared.discarded, 4);
        // One above everything ever seen — the value a device whose own record
        // went with its secrets cannot obtain any other way.
        assert_eq!(cleared.next_id, 5);

        // Nothing left to serve, which is what makes a peer decline to seal
        // rather than seal to something dead.
        assert!(!store.take(&key).found);
        assert!(!store.has_any(&key));
        assert_eq!(store.count(&key).one_time, 0);
        assert_eq!(store.count(&key).fallback_id, 0);
    }

    #[test]
    fn clearing_does_not_forgive_a_reused_id() {
        // The never-reuse rule outlives the prekeys. If clearing forgot the
        // ids, an envelope naming id 1 could mean two different keys.
        let (seed, key) = device(10);
        let store = Prekeys::new();
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        store.publish(&key, &[p]).unwrap();
        store.clear(&key).unwrap();
        let (again, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert_eq!(store.publish(&key, &[again]), Err(PrekeyError::ReusedId));
    }

    #[test]
    fn a_device_can_publish_again_from_next_id() {
        let (seed, key) = device(11);
        let store = Prekeys::new();
        let first: Vec<Prekey> = (1..=4)
            .map(|i| Prekey::generate(&seed, KIND_ONE_TIME, i).0)
            .collect();
        store.publish(&key, &first).unwrap();
        let next = store.clear(&key).unwrap().next_id;

        let fresh: Vec<Prekey> = (next..next + 4)
            .map(|i| Prekey::generate(&seed, KIND_ONE_TIME, i).0)
            .collect();
        assert_eq!(store.publish(&key, &fresh).unwrap(), 4);
        assert_eq!(store.take(&key).prekey.unwrap().id, next);
    }

    #[test]
    fn clearing_a_device_that_published_nothing_is_not_an_error() {
        // A brand-new client and one that lost its store are the same request
        // from here, and both should get an answer they can act on.
        let (_, key) = device(12);
        let store = Prekeys::new();
        let cleared = store.clear(&key).unwrap();
        assert_eq!(cleared.discarded, 0);
        assert_eq!(cleared.next_id, 1, "ids start at 1, since 0 is reserved");
    }

    #[test]
    fn clearing_is_rate_limited() {
        let (_, key) = device(13);
        let store = Prekeys::new();
        for _ in 0..MAX_CLEAR {
            store.clear(&key).unwrap();
        }
        assert_eq!(store.clear(&key), Err(PrekeyError::ClearQuota));
        // Refused distinguishably, as SIP-23 requires; there is nothing to
        // conceal, since the caller is asking about its own state.
        assert_eq!(PrekeyError::ClearQuota.status(), 429);
        // And it is per device.
        let (_, other) = device(14);
        assert!(store.clear(&other).is_ok());
    }
}
