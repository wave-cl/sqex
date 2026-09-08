//! SIP-38 name directory: the exchange side of `c@example.com`.
//!
//! A persistent map from a canonical name to an account. **Durable, unlike
//! SIP-28 resolution**: an address is only interesting while it is fresh and a
//! restart that forgot it is telling the truth, but a name is the durable
//! identity a person keeps across address changes and device swaps, and an
//! exchange that forgot its names on a restart would be useless. So this lives
//! in SQLite beside the device registry, not in memory beside the beacon.
//!
//! # Open registration is leased
//!
//! A self-claimed name renews on any activity attributable to its account (a
//! SIP-4 beat, a re-claim, a SIP-28 publish); past its lease it is *stale* — it
//! still resolves, flagged, and its holder may still renew it, but any other
//! account may now claim it. That is the reclamation path for abandoned names,
//! bounded by the lease rather than left to an administrator. An
//! administrator's assignment carries no lease and does not expire.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use sqex_proto::name::{
    CLAIM_AT_CAPACITY, CLAIM_FULL, CLAIM_GRANTED, CLAIM_RATE_LIMITED, CLAIM_TAKEN, Resolved,
};
use sqnr_core::PubKey;

use crate::state::now_unix;

/// Successful self-claims one account may make per hour. Bounds a land-grab
/// (claiming many names to deny them) without touching legitimate use — a
/// person registers a handful of aliases once, not eight an hour forever.
pub const CLAIM_RATE_PER_HOUR: usize = 8;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS name (
    name          TEXT PRIMARY KEY,     -- canonical (lowercased) label
    account       BLOB    NOT NULL,
    registered_at INTEGER NOT NULL,
    last_active   INTEGER NOT NULL,
    -- 1 = an administrator's assignment (no lease); 0 = an open self-claim.
    admin_set     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS name_by_account ON name (account);
"#;

/// One row of the directory, for the administrative `NameList`.
#[derive(Debug, Clone)]
pub struct NameRow {
    pub name: String,
    pub account: PubKey,
    pub admin_set: bool,
    pub registered_at: u64,
    pub last_active: u64,
    pub expires_at: u64,
}

pub struct Names {
    db: Mutex<Connection>,
    /// How long a self-claim survives without renewal.
    lease_secs: u64,
    /// Optional global cap on total bound names (operator's `max_names`). None
    /// is unlimited. Bounds a mint-flood: the per-account cap and claim rate are
    /// both per-account and so bypassable by minting identities, which this is
    /// the backstop for — the same reasoning as squic's `max_connections`.
    max_names: Option<u64>,
    /// Successful-claim timestamps per account, for the hourly rate limit. In
    /// memory: it bounds abuse over an hour, and a restart that forgot it costs
    /// nothing worth protecting. Pruned by `sweep_rate_limiter` so it does not
    /// grow one entry per account that ever claimed.
    claims: Mutex<HashMap<[u8; 32], Vec<u64>>>,
}

impl Names {
    pub fn open(
        path: Option<&Path>,
        lease_secs: u64,
        max_names: Option<u64>,
    ) -> rusqlite::Result<Names> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        Ok(Names {
            db: Mutex::new(db),
            lease_secs,
            max_names,
            claims: Mutex::new(HashMap::new()),
        })
    }

    /// When an open-claimed row last renewed at `last_active` expires. Zero for
    /// an administrator's assignment, which does not expire.
    fn expires(&self, admin_set: bool, last_active: u64) -> u64 {
        if admin_set {
            0
        } else {
            last_active.saturating_add(self.lease_secs)
        }
    }

    /// Self-service claim (open registration). Returns a `CLAIM_*` outcome.
    ///
    /// Idempotent for the caller's own name (refreshes its lease). Reclaims a
    /// lapsed name held by another account. Refuses one held live by another,
    /// one that would exceed the per-account cap, or a caller over the hourly
    /// rate.
    pub fn claim(&self, name: &str, account: &PubKey, max_per_account: usize) -> u8 {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = match db.transaction() {
            Ok(t) => t,
            Err(_) => return CLAIM_TAKEN, // conservative: cannot claim if we cannot write
        };

        let existing: Option<(Vec<u8>, i64, i64)> = tx
            .query_row(
                "SELECT account, admin_set, last_active FROM name WHERE name = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .unwrap_or(None);

        if let Some((holder, admin_set, last_active)) = &existing {
            let held_by_caller = holder.as_slice() == account.as_bytes();
            if held_by_caller {
                // Renew, in place, whatever kind it is.
                let _ = tx.execute(
                    "UPDATE name SET last_active = ?2 WHERE name = ?1",
                    params![name, now as i64],
                );
                let _ = tx.commit();
                return CLAIM_GRANTED;
            }
            let expires = self.expires(*admin_set != 0, *last_active as u64);
            let reclaimable = *admin_set == 0 && now >= expires;
            if !reclaimable {
                return CLAIM_TAKEN;
            }
            // else: lapsed and held by another — fall through and reclaim it.
        }

        // Free or reclaimable. Cap first (so a capacity refusal does not spend
        // rate budget), then the hourly rate.
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM name WHERE account = ?1",
                params![account.as_bytes()],
                |r| r.get(0),
            )
            .unwrap_or(0);
        // A reclaim of another account's name is a new holding for the caller,
        // so the count (which does not include this name) is the right basis.
        if count as usize >= max_per_account {
            return CLAIM_AT_CAPACITY;
        }
        // Global cap (operator's `max_names`): only a brand-new row grows the
        // store, so a reclaim of another account's lapsed name (an UPDATE, net
        // rows unchanged) is exempt. This is the backstop for a mint-flood the
        // per-account limits cannot bound.
        if existing.is_none()
            && let Some(cap) = self.max_names
        {
            let total: i64 = tx
                .query_row("SELECT COUNT(*) FROM name", [], |r| r.get(0))
                .unwrap_or(0);
            if total as u64 >= cap {
                return CLAIM_FULL;
            }
        }
        if self.rate_limited(account, now) {
            return CLAIM_RATE_LIMITED;
        }

        if tx
            .execute(
                "INSERT INTO name (name, account, registered_at, last_active, admin_set)
                 VALUES (?1, ?2, ?3, ?3, 0)
                 ON CONFLICT (name) DO UPDATE SET account = ?2, registered_at = ?3,
                                                  last_active = ?3, admin_set = 0",
                params![name, account.as_bytes(), now as i64],
            )
            .is_err()
        {
            return CLAIM_TAKEN;
        }
        if tx.commit().is_err() {
            return CLAIM_TAKEN;
        }
        self.record_claim(account, now);
        CLAIM_GRANTED
    }

    /// Give up a name the caller's account holds. True if a row was removed.
    pub fn release(&self, name: &str, account: &PubKey) -> bool {
        let db = self.db.lock().unwrap();
        db.execute(
            "DELETE FROM name WHERE name = ?1 AND account = ?2",
            params![name, account.as_bytes()],
        )
        .unwrap_or(0)
            > 0
    }

    /// Resolve a name to its account, with provenance. A stale (past-lease but
    /// unreclaimed) open name still resolves, flagged.
    pub fn resolve(&self, name: &str) -> Resolved {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        let row: Option<(Vec<u8>, i64, i64, i64)> = db
            .query_row(
                "SELECT account, registered_at, last_active, admin_set FROM name WHERE name = ?1",
                params![name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .unwrap_or(None);
        match row {
            None => Resolved::none(now),
            Some((account, registered_at, last_active, admin_set)) => {
                let admin_set = admin_set != 0;
                let last_active = last_active as u64;
                let expires_at = self.expires(admin_set, last_active);
                Resolved {
                    found: true,
                    now,
                    account: PubKey::new(account.try_into().unwrap_or([0; 32])),
                    registered_at: registered_at as u64,
                    last_active,
                    expires_at,
                    stale: !admin_set && now >= expires_at,
                }
            }
        }
    }

    /// The names an account holds, oldest first.
    pub fn names_for(&self, account: &PubKey) -> Vec<String> {
        let db = self.db.lock().unwrap();
        let mut stmt = match db.prepare(
            "SELECT name FROM name WHERE account = ?1 ORDER BY registered_at ASC, name ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![account.as_bytes()], |r| r.get::<_, String>(0))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    /// Administrative assignment (SIP-10). Binds `name` to `account` in any
    /// mode, reassigning an existing binding, with no lease and no cap. Returns
    /// whether anything changed.
    pub fn assign(&self, name: &str, account: &PubKey) -> bool {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        // Keep the original registration time if we already hold this name.
        let prior: Option<i64> = db
            .query_row(
                "SELECT registered_at FROM name WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        let registered_at = prior.unwrap_or(now as i64);
        if let Err(e) = db.execute(
            "INSERT INTO name (name, account, registered_at, last_active, admin_set)
             VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT (name) DO UPDATE SET account = ?2, last_active = ?4, admin_set = 1",
            params![name, account.as_bytes(), registered_at, now as i64],
        ) {
            tracing::error!(error = %e, "name directory: assign");
            return false;
        }
        true
    }

    /// Administrative release (SIP-10). Frees a name in any mode.
    pub fn release_admin(&self, name: &str) -> bool {
        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM name WHERE name = ?1", params![name])
            .unwrap_or(0)
            > 0
    }

    /// The whole directory, for the administrative `NameList`.
    pub fn list(&self) -> Vec<NameRow> {
        let db = self.db.lock().unwrap();
        let mut stmt = match db.prepare(
            "SELECT name, account, registered_at, last_active, admin_set FROM name
             ORDER BY name ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], |r| {
            let name: String = r.get(0)?;
            let account: Vec<u8> = r.get(1)?;
            let registered_at = r.get::<_, i64>(2)? as u64;
            let last_active = r.get::<_, i64>(3)? as u64;
            let admin_set = r.get::<_, i64>(4)? != 0;
            Ok(NameRow {
                name,
                account: PubKey::new(account.try_into().unwrap_or([0; 32])),
                admin_set,
                registered_at,
                last_active,
                expires_at: self.expires(admin_set, last_active),
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Renew every open name an account holds. Called where the account shows
    /// activity — a SIP-4 beat or a SIP-28 publish — so a name that is in use
    /// does not lapse on its lease. Administrator assignments are left alone.
    pub fn renew(&self, account: &PubKey) {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        let _ = db.execute(
            "UPDATE name SET last_active = ?2 WHERE account = ?1 AND admin_set = 0",
            params![account.as_bytes(), now as i64],
        );
    }

    /// How many names are bound. For `/status`.
    pub fn count(&self) -> usize {
        let db = self.db.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM name", [], |r| r.get::<_, i64>(0))
            .map(|n| n as usize)
            .unwrap_or(0)
    }

    /// Drop open names abandoned well past their lease — expired for at least
    /// one further lease period, so the stale window a resolver still sees is
    /// generous. Reclaims storage only; a name becomes reclaimable by another
    /// account at its lease, long before this runs. Returns rows removed.
    pub fn sweep(&self, now: u64) -> usize {
        let db = self.db.lock().unwrap();
        let cutoff = now.saturating_sub(self.lease_secs.saturating_mul(2));
        db.execute(
            "DELETE FROM name WHERE admin_set = 0 AND last_active < ?1",
            params![cutoff as i64],
        )
        .unwrap_or(0)
    }

    /// Record a successful claim and report whether the account is already at
    /// its hourly limit. Only successful new bindings are counted; a self-refresh
    /// or a refused claim spends no budget.
    fn rate_limited(&self, account: &PubKey, now: u64) -> bool {
        let mut claims = self.claims.lock().unwrap();
        let log = claims.entry(*account.as_bytes()).or_default();
        log.retain(|&t| now.saturating_sub(t) < 3600);
        if log.is_empty() {
            // Do not leave an empty vec behind for an account that pruned to
            // nothing — it would otherwise linger until the next periodic sweep.
            claims.remove(account.as_bytes());
            return false;
        }
        log.len() >= CLAIM_RATE_PER_HOUR
    }

    /// Evict rate-limiter entries with no claim in the last hour. Without this
    /// the map grows one entry per account that ever claimed and never shrinks,
    /// because a quiet account's stale entry is only pruned when *it* claims
    /// again. Called from the periodic sweeper beside [`sweep`](Self::sweep).
    pub fn sweep_rate_limiter(&self, now: u64) {
        let mut claims = self.claims.lock().unwrap();
        claims.retain(|_, log| {
            log.retain(|&t| now.saturating_sub(t) < 3600);
            !log.is_empty()
        });
    }

    fn record_claim(&self, account: &PubKey, now: u64) {
        let mut claims = self.claims.lock().unwrap();
        claims.entry(*account.as_bytes()).or_default().push(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqex_proto::name::CLAIM_GRANTED;

    fn pk(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn names(lease: u64) -> Names {
        Names::open(None, lease, None).unwrap()
    }

    fn names_capped(lease: u64, max: u64) -> Names {
        Names::open(None, lease, Some(max)).unwrap()
    }

    /// The global cap (operator's `max_names`) backstops the mint-flood the
    /// per-account cap and rate limit cannot: it bounds *total* names, counting
    /// distinct accounts, and refuses a new binding once full with `CLAIM_FULL`.
    #[test]
    fn the_global_cap_bounds_the_whole_directory() {
        let n = names_capped(3600, 2);
        assert_eq!(n.claim("a", &pk(1), 100), CLAIM_GRANTED);
        assert_eq!(n.claim("b", &pk(2), 100), CLAIM_GRANTED); // different account
        // Full: a third distinct account cannot add a new row, even with room
        // under its own per-account cap.
        assert_eq!(n.claim("c", &pk(3), 100), CLAIM_FULL);
        // A holder may still renew its own name at the cap (no new row).
        assert_eq!(n.claim("a", &pk(1), 100), CLAIM_GRANTED);
        // And releasing frees a slot.
        assert!(n.release("a", &pk(1)));
        assert_eq!(n.claim("c", &pk(3), 100), CLAIM_GRANTED);
    }

    /// Reclaiming another account's lapsed name is an UPDATE, not a new row, so
    /// it is exempt from the global cap — the directory stays full but the name
    /// changes hands.
    #[test]
    fn reclaim_is_exempt_from_the_global_cap() {
        let n = names_capped(0, 1); // zero lease: names are stale at once
        assert_eq!(n.claim("x", &pk(1), 100), CLAIM_GRANTED);
        // Full (1 row), but pk(2) may reclaim x from pk(1) — no new row.
        assert_eq!(n.claim("y", &pk(2), 100), CLAIM_FULL);
        assert_eq!(n.claim("x", &pk(2), 100), CLAIM_GRANTED);
        assert_eq!(n.resolve("x").account, pk(2));
    }

    /// The rate-limiter map is evicted by the sweep, so it does not grow one
    /// entry per account that ever claimed (Finding B).
    #[test]
    fn the_rate_limiter_map_is_swept() {
        let n = names(3600);
        for i in 0..5u8 {
            assert_eq!(n.claim(&format!("n{i}"), &pk(i), 100), CLAIM_GRANTED);
        }
        assert_eq!(n.claims.lock().unwrap().len(), 5, "one entry per claimer");
        // Far in the future, every timestamp is stale → all entries evicted.
        n.sweep_rate_limiter(now_unix() + 100_000);
        assert!(
            n.claims.lock().unwrap().is_empty(),
            "stale rate-limiter entries must be reclaimed"
        );
    }

    #[test]
    fn a_free_name_is_granted_and_resolves() {
        let n = names(3600);
        assert_eq!(n.claim("colin", &pk(1), 4), CLAIM_GRANTED);
        let r = n.resolve("colin");
        assert!(r.found && !r.stale);
        assert_eq!(r.account, pk(1));
        assert!(!n.resolve("nobody").found);
    }

    #[test]
    fn a_taken_name_is_refused_but_the_owner_is_idempotent() {
        let n = names(3600);
        assert_eq!(n.claim("colin", &pk(1), 4), CLAIM_GRANTED);
        // Another account cannot take it.
        assert_eq!(n.claim("colin", &pk(2), 4), CLAIM_TAKEN);
        // The owner re-claiming is granted (a renewal).
        assert_eq!(n.claim("colin", &pk(1), 4), CLAIM_GRANTED);
    }

    #[test]
    fn the_per_account_cap_is_enforced() {
        let n = names(3600);
        for i in 0..3 {
            assert_eq!(n.claim(&format!("n{i}"), &pk(1), 3), CLAIM_GRANTED);
        }
        assert_eq!(n.claim("n3", &pk(1), 3), CLAIM_AT_CAPACITY);
        // A different account still has room.
        assert_eq!(n.claim("n3", &pk(2), 3), CLAIM_GRANTED);
    }

    #[test]
    fn a_lapsed_name_goes_stale_then_is_reclaimable() {
        // Zero lease: a claim is immediately past its lease.
        let n = names(0);
        assert_eq!(n.claim("colin", &pk(1), 4), CLAIM_GRANTED);
        let r = n.resolve("colin");
        assert!(
            r.found && r.stale,
            "a lapsed open name still resolves, flagged"
        );
        // Another account may now take it.
        assert_eq!(n.claim("colin", &pk(2), 4), CLAIM_GRANTED);
        assert_eq!(n.resolve("colin").account, pk(2));
    }

    #[test]
    fn renew_keeps_a_name_live() {
        let n = names(0);
        assert!(n.claim("colin", &pk(1), 4) == CLAIM_GRANTED);
        // With a zero lease it is stale immediately; but the owner reclaiming
        // (or renew) refreshes it, and the owner is always granted.
        n.renew(&pk(1));
        // Still the owner's — a reclaim by another only happens via claim().
        assert_eq!(n.resolve("colin").account, pk(1));
    }

    #[test]
    fn admin_assign_overrides_and_does_not_expire() {
        let n = names(0);
        assert_eq!(n.claim("colin", &pk(1), 4), CLAIM_GRANTED);
        // Admin reassigns to another account.
        assert!(n.assign("colin", &pk(9)));
        let r = n.resolve("colin");
        assert_eq!(r.account, pk(9));
        assert!(!r.stale, "an admin assignment never goes stale");
        assert_eq!(r.expires_at, 0);
        // And an admin-held name is not reclaimable by a self-claim, even with
        // a zero lease.
        assert_eq!(n.claim("colin", &pk(2), 4), CLAIM_TAKEN);
    }

    #[test]
    fn release_frees_a_name_for_its_owner_only() {
        let n = names(3600);
        assert_eq!(n.claim("colin", &pk(1), 4), CLAIM_GRANTED);
        assert!(!n.release("colin", &pk(2)), "not the owner: no-op");
        assert!(n.resolve("colin").found);
        assert!(n.release("colin", &pk(1)));
        assert!(!n.resolve("colin").found);
    }

    #[test]
    fn reverse_lists_an_accounts_names_oldest_first() {
        let n = names(3600);
        for name in ["carl", "colin", "c"] {
            assert_eq!(n.claim(name, &pk(1), 8), CLAIM_GRANTED);
        }
        // Oldest first, ties broken by name — here all three register in the
        // same second, so the order is alphabetical and deterministic.
        assert_eq!(n.names_for(&pk(1)), vec!["c", "carl", "colin"]);
        assert!(n.names_for(&pk(2)).is_empty());
    }

    #[test]
    fn the_hourly_rate_limit_bounds_a_land_grab() {
        let n = names(3600);
        for i in 0..CLAIM_RATE_PER_HOUR {
            assert_eq!(n.claim(&format!("n{i}"), &pk(1), 1000), CLAIM_GRANTED);
        }
        assert_eq!(n.claim("one-more", &pk(1), 1000), CLAIM_RATE_LIMITED);
        // A different account is unaffected.
        assert_eq!(n.claim("theirs", &pk(2), 1000), CLAIM_GRANTED);
    }

    #[test]
    fn sweep_drops_only_long_abandoned_open_names() {
        let n = names(100);
        assert_eq!(n.claim("live", &pk(1), 4), CLAIM_GRANTED);
        assert!(n.assign("kept", &pk(2)));
        // Nothing is abandoned yet.
        assert_eq!(n.sweep(now_unix()), 0);
        // Far in the future, the open name is past 2× its lease; the admin one
        // is not touched.
        let removed = n.sweep(now_unix() + 100_000);
        assert_eq!(removed, 1);
        assert!(!n.resolve("live").found);
        assert!(n.resolve("kept").found);
    }
}
