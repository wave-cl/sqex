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
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use sqex_proto::prekey::{
    CLEAR_WINDOW, Cleared, Counts, KIND_FALLBACK, KIND_ONE_TIME, MAX_CLEAR, MAX_STORED, PREKEY_LEN,
    Prekey, Taken,
};
use sqnr_core::PubKey;

use crate::state::now_unix;
use sqex_proto::refusal::Code;

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
    Storage,
    /// More `Clear` calls than SIP-23 allows in the window.
    ClearQuota,
}

impl PrekeyError {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrekeyError::BadSignature => "bad_signature",
            PrekeyError::ReusedId => "reused_id",
            PrekeyError::PoolFull => "pool_full",
            PrekeyError::Storage => "storage",
            PrekeyError::ClearQuota => "clear_quota",
        }
    }

    /// The wire code for this refusal. Exhaustive on purpose: a new variant is
    /// a compile error here until it is given one, which is what keeps the
    /// registry from drifting away from the enum it describes.
    pub fn code(&self) -> Code {
        match self {
            PrekeyError::BadSignature => Code::BadSignature,
            PrekeyError::ReusedId => Code::ReusedId,
            PrekeyError::PoolFull => Code::PoolFull,
            PrekeyError::Storage => Code::Storage,
            PrekeyError::ClearQuota => Code::ClearQuota,
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            PrekeyError::BadSignature => 401,
            PrekeyError::ReusedId => 409,
            PrekeyError::PoolFull => 507,
            PrekeyError::Storage => 500,
            PrekeyError::ClearQuota => 429,
        }
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS prekey (
    device BLOB    NOT NULL,
    id     INTEGER NOT NULL,
    kind   INTEGER NOT NULL,
    wire   BLOB    NOT NULL,
    PRIMARY KEY (device, id)
);
-- Every id a device has ever published, so none is reused. SIP-23 says ids
-- MUST NEVER be reused, including across a fallback being replaced and across
-- a `Clear` — so this outlives the prekeys themselves.
CREATE TABLE IF NOT EXISTS prekey_seen (
    device BLOB    NOT NULL,
    id     INTEGER NOT NULL,
    PRIMARY KEY (device, id)
);
-- The highest id ever seen, kept apart from the prekeys so that discarding
-- them cannot lower it. Same shape as SIP-16's msg_seq mark, same reason.
CREATE TABLE IF NOT EXISTS prekey_high_water (
    device     BLOB PRIMARY KEY,
    high_water INTEGER NOT NULL DEFAULT 0
);
"#;

/// SIP-23 prekeys, on disk.
///
/// **They must be durable, and the reason is not obvious until it bites.** A
/// device registry that survives a restart while its prekeys do not is a
/// registry of devices nothing can be sealed to: `Take` answers `found: 0`,
/// every caller correctly refuses to seal, and no channel key can be
/// distributed to anybody. Worse, it is silent — a client whose own pool looks
/// healthy has no reason to publish again, so the exchange stays empty until
/// something forces the issue.
///
/// Found by restarting a development server and watching a group creation stop
/// at epoch 0 with nothing to say why.
pub struct Prekeys {
    db: Mutex<Connection>,
    /// When each device's recent `Clear` calls landed. In memory on purpose: a
    /// rate limit that resets on restart costs an operator nothing, and it is
    /// the one piece of this that is not worth a write.
    cleared_at: Mutex<HashMap<PubKey, Vec<u64>>>,
}

fn storage<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> PrekeyError + '_ {
    move |e| {
        tracing::error!(error = %e, "prekey storage: {what}");
        PrekeyError::Storage
    }
}

fn wire(p: &Prekey) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREKEY_LEN);
    out.push(p.kind);
    out.extend_from_slice(&p.id.to_be_bytes());
    out.extend_from_slice(&p.public);
    out.extend_from_slice(&p.signature);
    out
}

fn unwire(b: &[u8]) -> Option<Prekey> {
    if b.len() != PREKEY_LEN {
        return None;
    }
    Some(Prekey {
        kind: b[0],
        id: u32::from_be_bytes(b[1..5].try_into().ok()?),
        public: b[5..37].try_into().ok()?,
        signature: b[37..101].try_into().ok()?,
    })
}

impl Prekeys {
    /// Open the store. `None` gives an in-memory database, which is what a
    /// memory-only deployment and every test get.
    pub fn open(path: Option<&Path>) -> rusqlite::Result<Prekeys> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        Ok(Prekeys {
            db: Mutex::new(db),
            cleared_at: Mutex::new(HashMap::new()),
        })
    }

    /// Add one-time prekeys and replace the fallback. All or nothing: a batch
    /// with one bad signature in it publishes none, so a caller is never left
    /// guessing which half landed.
    pub fn publish(&self, device: &PubKey, prekeys: &[Prekey]) -> Result<u16, PrekeyError> {
        for p in prekeys {
            p.verify(device).map_err(|_| PrekeyError::BadSignature)?;
        }
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin publish"))?;

        for p in prekeys {
            let seen: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM prekey_seen WHERE device = ?1 AND id = ?2",
                    params![device.as_bytes(), p.id as i64],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage("check seen"))?;
            if seen.is_some() {
                return Err(PrekeyError::ReusedId);
            }
        }
        let held: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM prekey WHERE device = ?1 AND kind = ?2",
                params![device.as_bytes(), KIND_ONE_TIME as i64],
                |r| r.get(0),
            )
            .map_err(storage("count pool"))?;
        let arriving = prekeys.iter().filter(|p| p.kind == KIND_ONE_TIME).count();
        if held as usize + arriving > MAX_STORED {
            return Err(PrekeyError::PoolFull);
        }

        let mut accepted = 0u16;
        for p in prekeys {
            tx.execute(
                "INSERT INTO prekey_seen (device, id) VALUES (?1, ?2)",
                params![device.as_bytes(), p.id as i64],
            )
            .map_err(storage("record seen"))?;
            tx.execute(
                "INSERT INTO prekey_high_water (device, high_water) VALUES (?1, ?2)
                 ON CONFLICT (device) DO UPDATE SET high_water = MAX(high_water, ?2)",
                params![device.as_bytes(), p.id as i64],
            )
            .map_err(storage("bump high water"))?;
            if p.kind == KIND_FALLBACK {
                // One fallback at a time: publishing a new one replaces it,
                // and the old id stays in `seen` so it can never come round
                // again.
                tx.execute(
                    "DELETE FROM prekey WHERE device = ?1 AND kind = ?2",
                    params![device.as_bytes(), KIND_FALLBACK as i64],
                )
                .map_err(storage("retire fallback"))?;
            }
            tx.execute(
                "INSERT INTO prekey (device, id, kind, wire) VALUES (?1, ?2, ?3, ?4)",
                params![device.as_bytes(), p.id as i64, p.kind as i64, wire(p)],
            )
            .map_err(storage("insert prekey"))?;
            accepted += 1;
        }
        tx.commit().map_err(storage("commit publish"))?;
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
        let mut db = self.db.lock().unwrap();
        let Ok(tx) = db.transaction() else {
            return Taken::none(now);
        };
        // Oldest first, by the id the device assigned — which SIP-23 requires
        // to increase, so it is also the publication order.
        let row: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT id, wire FROM prekey WHERE device = ?1 AND kind = ?2
                 ORDER BY id ASC LIMIT 1",
                params![device.as_bytes(), KIND_ONE_TIME as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap_or(None);
        if let Some((id, w)) = row {
            let _ = tx.execute(
                "DELETE FROM prekey WHERE device = ?1 AND id = ?2",
                params![device.as_bytes(), id],
            );
            let taken = match unwire(&w) {
                Some(p) => Taken {
                    found: true,
                    prekey: Some(p),
                    now,
                },
                None => Taken::none(now),
            };
            let _ = tx.commit();
            return taken;
        }
        let fallback: Option<Vec<u8>> = tx
            .query_row(
                "SELECT wire FROM prekey WHERE device = ?1 AND kind = ?2 LIMIT 1",
                params![device.as_bytes(), KIND_FALLBACK as i64],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        let _ = tx.commit();
        match fallback.as_deref().and_then(unwire) {
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
        let db = self.db.lock().unwrap();
        let one_time: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM prekey WHERE device = ?1 AND kind = ?2",
                params![device.as_bytes(), KIND_ONE_TIME as i64],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let fallback_id: i64 = db
            .query_row(
                "SELECT id FROM prekey WHERE device = ?1 AND kind = ?2 LIMIT 1",
                params![device.as_bytes(), KIND_FALLBACK as i64],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None)
            .unwrap_or(0);
        Counts {
            one_time: one_time as u16,
            fallback_id: fallback_id as u32,
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
        {
            let mut at = self.cleared_at.lock().unwrap();
            let mine = at.entry(*device).or_default();
            mine.retain(|t| now.saturating_sub(*t) < CLEAR_WINDOW);
            if mine.len() >= MAX_CLEAR {
                return Err(PrekeyError::ClearQuota);
            }
            mine.push(now);
        }
        let db = self.db.lock().unwrap();
        let discarded = db
            .execute(
                "DELETE FROM prekey WHERE device = ?1",
                params![device.as_bytes()],
            )
            .map_err(storage("clear prekeys"))?;
        let high_water: i64 = db
            .query_row(
                "SELECT high_water FROM prekey_high_water WHERE device = ?1",
                params![device.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read high water"))?
            .unwrap_or(0);
        Ok(Cleared {
            discarded: discarded as u16,
            next_id: (high_water as u32).saturating_add(1),
            now,
        })
    }

    /// Whether a device could be sealed to at all. SIP-17's `Missing` reports
    /// this so a stranded client can be found.
    pub fn has_any(&self, device: &PubKey) -> bool {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT 1 FROM prekey WHERE device = ?1 LIMIT 1",
            params![device.as_bytes()],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .unwrap_or(None)
        .is_some()
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
        let store = Prekeys::open(None).unwrap();
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
        let store = Prekeys::open(None).unwrap();
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
        let store = Prekeys::open(None).unwrap();
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert_eq!(store.publish(&other, &[p]), Err(PrekeyError::BadSignature));
    }

    #[test]
    fn an_id_is_never_reused() {
        let (seed, key) = device(5);
        let store = Prekeys::open(None).unwrap();
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
        let store = Prekeys::open(None).unwrap();
        let (good, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        let (bad, _) = Prekey::generate(&other_seed, KIND_ONE_TIME, 2);
        assert!(store.publish(&key, &[good, bad]).is_err());
        assert!(!store.take(&key).found);
    }

    #[test]
    fn a_device_that_published_nothing_cannot_be_sealed_to() {
        let (_, key) = device(8);
        let store = Prekeys::open(None).unwrap();
        assert!(!store.has_any(&key));
        assert!(!store.take(&key).found);
    }

    #[test]
    fn clearing_discards_the_prekeys_and_keeps_the_ids() {
        let (seed, key) = device(9);
        let store = Prekeys::open(None).unwrap();
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
        let store = Prekeys::open(None).unwrap();
        let (p, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        store.publish(&key, &[p]).unwrap();
        store.clear(&key).unwrap();
        let (again, _) = Prekey::generate(&seed, KIND_ONE_TIME, 1);
        assert_eq!(store.publish(&key, &[again]), Err(PrekeyError::ReusedId));
    }

    #[test]
    fn a_device_can_publish_again_from_next_id() {
        let (seed, key) = device(11);
        let store = Prekeys::open(None).unwrap();
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
        let store = Prekeys::open(None).unwrap();
        let cleared = store.clear(&key).unwrap();
        assert_eq!(cleared.discarded, 0);
        assert_eq!(cleared.next_id, 1, "ids start at 1, since 0 is reserved");
    }

    #[test]
    fn clearing_is_rate_limited() {
        let (_, key) = device(13);
        let store = Prekeys::open(None).unwrap();
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

    #[test]
    fn prekeys_survive_a_restart() {
        // The bug this exists for: they used to live in a HashMap, so bouncing
        // the exchange made every registered device unsealable-to — silently,
        // because a client's own pool is untouched and it sees no reason to
        // publish again. A group creation stopped at epoch 0 with nothing to
        // say why, and that was the first anybody knew.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prekeys.db");
        let (seed, key) = device(20);
        {
            let store = Prekeys::open(Some(&path)).unwrap();
            let batch: Vec<Prekey> = (1..=4)
                .map(|i| Prekey::generate(&seed, KIND_ONE_TIME, i).0)
                .collect();
            store.publish(&key, &batch).unwrap();
            store
                .publish(&key, &[Prekey::generate(&seed, KIND_FALLBACK, 5).0])
                .unwrap();
            assert_eq!(store.take(&key).prekey.unwrap().id, 1);
        }
        let store = Prekeys::open(Some(&path)).unwrap();
        assert!(store.has_any(&key), "a restart emptied the pool");
        assert_eq!(store.count(&key).one_time, 3, "the served one came back");
        assert_eq!(store.count(&key).fallback_id, 5);
        // And the one already served stays served.
        assert_eq!(store.take(&key).prekey.unwrap().id, 2);
    }

    #[test]
    fn a_restart_does_not_forgive_a_reused_id() {
        // The never-reuse rule is the one that must outlive everything: the
        // prekeys, a Clear, and the process.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prekeys.db");
        let (seed, key) = device(21);
        {
            let store = Prekeys::open(Some(&path)).unwrap();
            store
                .publish(&key, &[Prekey::generate(&seed, KIND_ONE_TIME, 1).0])
                .unwrap();
            store.take(&key);
        }
        let store = Prekeys::open(Some(&path)).unwrap();
        let again = Prekey::generate(&seed, KIND_ONE_TIME, 1).0;
        assert_eq!(store.publish(&key, &[again]), Err(PrekeyError::ReusedId));
        // And Clear still knows where to resume.
        assert_eq!(store.clear(&key).unwrap().next_id, 2);
    }

    #[test]
    fn a_new_fallback_replaces_the_old_one() {
        let (seed, key) = device(22);
        let store = Prekeys::open(None).unwrap();
        store
            .publish(&key, &[Prekey::generate(&seed, KIND_FALLBACK, 1).0])
            .unwrap();
        store
            .publish(&key, &[Prekey::generate(&seed, KIND_FALLBACK, 2).0])
            .unwrap();
        assert_eq!(
            store.count(&key).fallback_id,
            2,
            "two fallbacks are held at once"
        );
        assert_eq!(store.take(&key).prekey.unwrap().id, 2);
    }
}
