//! SIP-22 device registry: the exchange side of a portable credential.
//!
//! It answers one question for every service above it — this connection is a
//! client, whose? — and does the one thing SIP-20 structurally cannot, which is
//! revoke.
//!
//! # The rule that makes revocation real
//!
//! **The credential is on the device.** Everything needed to register is in the
//! stolen phone's storage, so a revocation that merely deleted a mapping would
//! be undone by one request from whoever has the hardware, and every other rule
//! here would be intact while the mechanism was decorative. So a revocation is
//! recorded with its time, and a `Register` presenting a credential `issued` at
//! or before that time is refused until the revoked credential expires on
//! SIP-20's own terms.
//!
//! Keyed on `issued` rather than banning the device outright, because a phone
//! that was mislaid may legitimately return — and bringing it back needs the
//! **account** to sign a fresh credential, which is precisely the authority
//! that ought to be needed and the one thing not on the phone.
//!
//! # Durable
//!
//! Unlike prekeys, which are principled to lose on a restart, a registration
//! must survive one: a device should not have to re-register because a server
//! bounced, and a revocation that evaporated would be worse than none.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use sqex_proto::credential::{Credential, Invalid, Revocation, SCOPE_CHAT};
use sqex_proto::device::{Device, Devices, MAX_DEVICES, MAX_REGISTRATIONS_PER_HOUR};
use sqnr_core::PubKey;

use crate::state::now_unix;
use sqex_proto::refusal::Code;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// The credential did not verify, or is not for this service.
    Invalid(Invalid),
    /// The caller is neither the delegate nor an already-registered device of
    /// the account.
    NotAuthorised,
    /// This device is already mapped to a different account.
    Claimed,
    /// Refused because it was revoked, and its credential predates that.
    Revoked,
    /// A device may not revoke one registered before it.
    Senior,
    NoSuchDevice,
    TooManyDevices,
    RateLimited,
    Storage,
}

impl DeviceError {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceError::Invalid(i) => i.as_str(),
            DeviceError::NotAuthorised => "not_authorised",
            DeviceError::Claimed => "already_claimed",
            DeviceError::Revoked => "revoked",
            DeviceError::Senior => "senior_device",
            DeviceError::NoSuchDevice => "no_such_device",
            DeviceError::TooManyDevices => "too_many_devices",
            DeviceError::RateLimited => "rate_limited",
            DeviceError::Storage => "storage",
        }
    }

    /// The wire code for this refusal. Exhaustive on purpose: a new variant is
    /// a compile error here until it is given one, which is what keeps the
    /// registry from drifting away from the enum it describes.
    pub fn code(&self) -> Code {
        match self {
            DeviceError::Invalid(i) => i.code(),
            DeviceError::NotAuthorised => Code::NotAuthorised,
            DeviceError::Claimed => Code::AlreadyClaimed,
            DeviceError::Revoked => Code::Revoked,
            DeviceError::Senior => Code::SeniorDevice,
            DeviceError::NoSuchDevice => Code::NoSuchDevice,
            DeviceError::TooManyDevices => Code::TooManyDevices,
            DeviceError::RateLimited => Code::RateLimited,
            DeviceError::Storage => Code::Storage,
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            DeviceError::Invalid(_) => 401,
            DeviceError::NotAuthorised | DeviceError::Senior => 403,
            DeviceError::Claimed | DeviceError::Revoked => 409,
            DeviceError::NoSuchDevice => 404,
            DeviceError::TooManyDevices | DeviceError::RateLimited => 507,
            DeviceError::Storage => 500,
        }
    }
}

/// Add a column to a table that predates it, if it is not already there.
fn add_column(db: &Connection, table: &str, column: &str, decl: &str) -> rusqlite::Result<()> {
    let mut stmt = db.prepare(&format!("PRAGMA table_info({table})"))?;
    let existing: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .collect();
    if !existing.iter().any(|c| c == column) {
        db.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
    }
    Ok(())
}

fn storage<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> DeviceError + '_ {
    move |e| {
        tracing::error!(error = %e, "device registry: {what}");
        DeviceError::Storage
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS device (
    device    BLOB PRIMARY KEY,
    account   BLOB    NOT NULL,
    added     INTEGER NOT NULL,
    issued    INTEGER NOT NULL,
    not_after INTEGER NOT NULL
);
-- Kept until the revoked credential would have expired anyway. Without this a
-- revocation is undone by one request from whoever holds the hardware.
CREATE TABLE IF NOT EXISTS revoked (
    device    BLOB PRIMARY KEY,
    at        INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    -- Whose device it was. The device row is deleted on revocation, so without
    -- this the account is lost — and SIP-17 needs exactly this fact to let a
    -- member rekey a channel after revoking one of its own devices.
    account   BLOB
);
-- SIP-44: accounts that have been succeeded, by the key that holds them now,
-- with the proof as it was presented so anybody may check it. Once per
-- account, ever.
CREATE TABLE IF NOT EXISTS succession (
    account   BLOB PRIMARY KEY,
    successor BLOB NOT NULL,
    at        INTEGER NOT NULL,
    proof     BLOB NOT NULL
);
-- SIP-44: a policy an account lodged ahead of need, so its guardians hold
-- nothing. Replaced by a later one from the same account.
CREATE TABLE IF NOT EXISTS lodged (
    account BLOB PRIMARY KEY,
    policy  BLOB NOT NULL,
    at      INTEGER NOT NULL
);
-- SIP-45: where each device asked to be woken, until when, and when it last
-- was. Never served back; a place to post to and nothing else.
CREATE TABLE IF NOT EXISTS wake (
    device   BLOB PRIMARY KEY,
    endpoint TEXT NOT NULL,
    expires  INTEGER NOT NULL,
    woken    INTEGER NOT NULL DEFAULT 0
);
-- SIP-59: where an account lives, by its own signed statement -- the
-- latest Move presented here, whether it names this exchange or another.
-- `home` equal to this exchange's key means the account is homed here.
CREATE TABLE IF NOT EXISTS home (
    account BLOB PRIMARY KEY,
    home    BLOB NOT NULL,
    domain  TEXT NOT NULL,
    issued  INTEGER NOT NULL,
    sig     BLOB NOT NULL
);
-- SIP-59: where an account homed here said its channels live -- the hints
-- its Move came with, one row per origin. Only meaningful for accounts
-- whose `home` row names this exchange.
CREATE TABLE IF NOT EXISTS home_origin (
    account BLOB NOT NULL,
    origin  BLOB NOT NULL,
    domain  TEXT NOT NULL,
    PRIMARY KEY (account, origin)
);
-- SIP-60: where an account lives as the domain's exchange said when this
-- exchange located it. The domain exchange's word, kept apart from a
-- signed Move: it makes this exchange proxy and tell, never serve.
CREATE TABLE IF NOT EXISTS learned_home (
    account BLOB PRIMARY KEY,
    home    BLOB NOT NULL,
    domain  TEXT NOT NULL,
    at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_by_account ON device (account);
CREATE INDEX IF NOT EXISTS home_by_home ON home (home);
"#;

/// How far ahead of us an account's clock may be on a revocation.
///
/// A withdrawal that its author's fast clock made unacceptable would be a
/// recovery that failed at the moment it was needed. There is deliberately no
/// bound in the other direction: a revocation that lapsed would re-admit the
/// key it withdrew.
pub const REVOCATION_SKEW: u64 = 5 * 60;

pub struct Registry {
    db: Mutex<Connection>,
}

impl Registry {
    pub fn open(path: Option<&Path>) -> rusqlite::Result<Registry> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        // `CREATE TABLE IF NOT EXISTS` creates tables and never alters one that
        // already exists, so a column added after a release needs this. A
        // deployed exchange has a `revoked` table without `account`.
        add_column(&db, "revoked", "account", "BLOB")?;
        // SIP-32. A deployed registry has rows whose credential was verified
        // and discarded, so this is added rather than declared: those devices
        // keep their mapping and report no credential until they re-register,
        // which SIP-22 already calls renewal.
        add_column(&db, "device", "credential", "BLOB NOT NULL DEFAULT x''")?;
        // The account's own signed withdrawal, where there is one. A
        // device-initiated revocation is legitimate and local, and stores none.
        add_column(&db, "revoked", "revocation", "BLOB NOT NULL DEFAULT x''")?;
        Ok(Registry { db: Mutex::new(db) })
    }

    /// Whether this account revoked any device at or after `since`.
    ///
    /// SIP-17 lets a member who is not an admin advance a channel's epoch when
    /// it holds a revocation made since that epoch was minted — which is what
    /// makes "rotate after revoking" advice somebody can actually follow when
    /// they are an ordinary member of a group.
    pub fn revoked_since(&self, account: &PubKey, since: u64) -> bool {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT 1 FROM revoked WHERE account = ?1 AND at >= ?2 LIMIT 1",
            params![account.as_bytes(), since as i64],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten()
        .is_some()
    }

    /// Map a device to the account whose credential it presents.
    ///
    /// The caller must be the delegate itself, or an already-registered device
    /// of the same account. Self-registration is not a convenience: an account
    /// key may be held in hardware and a hardware key cannot be a transport key
    /// at all, so requiring the account to connect would make the first device
    /// of every hardware-held account impossible to register.
    pub fn register(&self, caller: &PubKey, credential: &Credential) -> Result<(), DeviceError> {
        let now = now_unix();
        credential
            .verify(&credential.account, SCOPE_CHAT, now)
            .map_err(DeviceError::Invalid)?;

        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin register"))?;
        expire(&tx, now)?;

        let authorised = caller == &credential.delegate
            || account_of(&tx, caller, now)? == Some(credential.account);
        if !authorised {
            return Err(DeviceError::NotAuthorised);
        }

        // A device belongs to exactly one account. Otherwise a connection
        // carrying that key would have no defined answer to the question every
        // service above asks.
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT account FROM device WHERE device = ?1",
                params![credential.delegate.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read device"))?;
        if let Some(a) = &existing
            && a != credential.account.as_bytes()
        {
            return Err(DeviceError::Claimed);
        }

        let revoked: Option<i64> = tx
            .query_row(
                "SELECT at FROM revoked WHERE device = ?1",
                params![credential.delegate.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read revocation"))?;
        if let Some(at) = revoked
            && credential.issued <= at as u64
        {
            return Err(DeviceError::Revoked);
        }

        if existing.is_none() {
            let count: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM device WHERE account = ?1",
                    params![credential.account.as_bytes()],
                    |r| r.get(0),
                )
                .map_err(storage("count devices"))?;
            if count as usize >= MAX_DEVICES {
                return Err(DeviceError::TooManyDevices);
            }
            let recent: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM device WHERE account = ?1 AND ?2 - added < 3600",
                    params![credential.account.as_bytes(), now as i64],
                    |r| r.get(0),
                )
                .map_err(storage("count recent"))?;
            if recent as usize >= MAX_REGISTRATIONS_PER_HOUR {
                return Err(DeviceError::RateLimited);
            }
        }

        // Idempotent for a device already mapped: re-registering refreshes the
        // credential, which is how a device renews before its expiry passes.
        tx.execute(
            "INSERT INTO device (device, account, added, issued, not_after, credential)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (device) DO UPDATE SET issued = ?4, not_after = ?5,
                                                credential = ?6",
            params![
                credential.delegate.as_bytes(),
                credential.account.as_bytes(),
                now as i64,
                credential.issued as i64,
                credential.not_after as i64,
                // SIP-32: kept, not just checked. Verifying it and throwing it
                // away left SIP-31's second step — binding a device to the
                // account an entry names — impossible for anybody to perform.
                credential.encode(),
            ],
        )
        .map_err(storage("insert device"))?;
        // A device that comes back with a fresh credential is not revoked any
        // more; the account said so by signing it.
        tx.execute(
            "DELETE FROM revoked WHERE device = ?1",
            params![credential.delegate.as_bytes()],
        )
        .map_err(storage("clear revocation"))?;
        tx.commit().map_err(storage("commit register"))?;
        Ok(())
    }

    /// Stop resolving a device.
    ///
    /// Any registered device of the account may call it, **except that a device
    /// may not revoke one registered before it**. That seniority rule costs
    /// nothing and closes the obvious attack: somebody who steals a newly added
    /// laptop cannot use it to evict the phone that would revoke it.
    pub fn revoke(
        &self,
        caller: &PubKey,
        device: &PubKey,
        attested: Option<&Revocation>,
    ) -> Result<(), DeviceError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin revoke"))?;
        expire(&tx, now)?;

        let target = row(&tx, device)?.ok_or(DeviceError::NoSuchDevice)?;

        // SIP-32. An attested revocation carries its own authority: it is the
        // account's signed withdrawal of a credential the account signed, and
        // it needs no seniority and no registration behind it. Verified against
        // the account the device actually belongs to — a revocation signed by
        // somebody else's account is evidence about somebody else.
        if let Some(r) = attested {
            r.verify(&target.1, now, REVOCATION_SKEW)
                .map_err(DeviceError::Invalid)?;
            if r.device != *device {
                return Err(DeviceError::NotAuthorised);
            }
        }

        // The account itself may revoke any of its devices, registered or not,
        // and is exempt from seniority. It signed every credential; a design in
        // which it can withdraw none of them is not one anybody intended, and
        // seniority exists to stop a compromised recent device evicting its
        // seniors rather than to bind the authority they all derive from.
        //
        // Necessary rather than convenient: an account that registered itself
        // after linking another device would be the junior of the two, so
        // seniority alone would leave it unable to remove a device it
        // authorised.
        // An attested revocation has already proved its authority above, so
        // the local path's rules — registration, and seniority — apply only
        // when there is nothing signed to rest on.
        if attested.is_none() && *caller != target.1 {
            let mine = row(&tx, caller)?.ok_or(DeviceError::NotAuthorised)?;
            if mine.1 != target.1 {
                return Err(DeviceError::NotAuthorised);
            }
            // May name itself, which is how a client signs itself out.
            if caller != device && mine.2 > target.2 {
                return Err(DeviceError::Senior);
            }
        }

        tx.execute(
            "DELETE FROM device WHERE device = ?1",
            params![device.as_bytes()],
        )
        .map_err(storage("delete device"))?;
        tx.execute(
            "INSERT INTO revoked (device, at, not_after, account, revocation)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (device) DO UPDATE SET at = ?2, not_after = ?3,
                                                account = ?4, revocation = ?5",
            params![
                device.as_bytes(),
                now as i64,
                target.3 as i64,
                target.1.as_bytes(),
                attested.map(|r| r.encode()).unwrap_or_default(),
            ],
        )
        .map_err(storage("record revocation"))?;
        tx.commit().map_err(storage("commit revoke"))?;
        Ok(())
    }

    /// An account's devices, oldest first.
    pub fn list(&self, account: &PubKey) -> Result<Devices, DeviceError> {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT device, added, not_after, credential FROM device
                 WHERE account = ?1 AND not_after >= ?2 ORDER BY added ASC, device ASC",
            )
            .map_err(storage("prepare list"))?;
        let devices = stmt
            .query_map(params![account.as_bytes(), now as i64], |r| {
                let stored: Vec<u8> = r.get(3)?;
                Ok(Device {
                    device: PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                    added: r.get::<_, i64>(1)? as u64,
                    not_after: r.get::<_, i64>(2)? as u64,
                    // Empty for a registration made before SIP-32. Reported as
                    // absent rather than invented, so a verifier knows it is
                    // holding a mapping and not evidence.
                    credential: if stored.is_empty() {
                        None
                    } else {
                        Credential::decode(&stored).ok()
                    },
                })
            })
            .map_err(storage("query list"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage("read list"))?;
        Ok(Devices { now, devices })
    }

    /// Resolve a connection's device identity to the account it acts for.
    ///
    /// **An account with no registered devices is its own device.** A key the
    /// registry has never been told about resolves to itself, which is the
    /// ordinary single-client case and must not require anybody to have
    /// understood any of this.
    /// SIP-44: who holds `account` now, if it has been succeeded.
    pub fn successor_of(&self, account: &PubKey) -> Option<PubKey> {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT successor FROM succession WHERE account = ?1",
            params![account.as_bytes()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .ok()
        .flatten()
        .and_then(|b| b.try_into().ok().map(PubKey::new))
    }

    /// SIP-44: the recorded succession of `account`, as `/account/succession`
    /// serves it.
    pub fn succession_of(&self, account: &PubKey) -> Option<(PubKey, u64, Vec<u8>)> {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT successor, at, proof FROM succession WHERE account = ?1",
            params![account.as_bytes()],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()
        .and_then(|(s, at, proof)| s.try_into().ok().map(|k| (PubKey::new(k), at, proof)))
    }

    /// SIP-44: whether `account` has any device registered -- a successor
    /// must be a fresh key.
    pub fn has_devices(&self, account: &PubKey) -> bool {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT 1 FROM device WHERE account = ?1 AND not_after >= ?2 LIMIT 1",
            params![account.as_bytes(), now as i64],
            |_| Ok(true),
        )
        .optional()
        .ok()
        .flatten()
        .unwrap_or(false)
    }

    /// SIP-44: record that `successor` holds `account` from now, and remove
    /// `account`'s devices as though revoked. Refused where `account` was
    /// succeeded already: once, ever.
    pub fn succeed(
        &self,
        account: &PubKey,
        successor: &PubKey,
        proof: &[u8],
    ) -> Result<(), DeviceError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin succeed"))?;
        let done: bool = tx
            .query_row(
                "SELECT 1 FROM succession WHERE account = ?1",
                params![account.as_bytes()],
                |_| Ok(true),
            )
            .optional()
            .map_err(storage("read succession"))?
            .unwrap_or(false);
        if done {
            return Err(DeviceError::NotAuthorised);
        }
        tx.execute(
            "INSERT INTO succession (account, successor, at, proof) VALUES (?1, ?2, ?3, ?4)",
            params![account.as_bytes(), successor.as_bytes(), now as i64, proof],
        )
        .map_err(storage("record succession"))?;
        // Its devices go as revoked ones do, kept in `revoked` until their
        // credentials would have expired, so none is registered again on
        // the strength of a credential the old key signed.
        tx.execute(
            "INSERT OR REPLACE INTO revoked (device, at, not_after, account)
             SELECT device, ?2, not_after, account FROM device WHERE account = ?1",
            params![account.as_bytes(), now as i64],
        )
        .map_err(storage("retire devices"))?;
        tx.execute(
            "DELETE FROM device WHERE account = ?1",
            params![account.as_bytes()],
        )
        .map_err(storage("remove devices"))?;
        tx.execute(
            "DELETE FROM lodged WHERE account = ?1",
            params![account.as_bytes()],
        )
        .map_err(storage("clear lodged"))?;
        // SIP-62: the account's home records follow the key here too.
        follow_succession(&tx, account, successor)?;
        tx.commit().map_err(storage("commit succeed"))?;
        Ok(())
    }

    /// SIP-62: a succession by the account's own hand, with the devices it
    /// keeps registered to the successor under the credentials the new key
    /// signed -- in the one transaction, so no request in between finds
    /// a device that belongs to nobody. The credentials are verified by
    /// the caller; this records.
    pub fn handover(
        &self,
        account: &PubKey,
        successor: &PubKey,
        proof: &[u8],
        kept: &[Credential],
    ) -> Result<(), DeviceError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin handover"))?;
        let done: bool = tx
            .query_row(
                "SELECT 1 FROM succession WHERE account = ?1",
                params![account.as_bytes()],
                |_| Ok(true),
            )
            .optional()
            .map_err(storage("read succession"))?
            .unwrap_or(false);
        if done {
            return Err(DeviceError::NotAuthorised);
        }
        tx.execute(
            "INSERT INTO succession (account, successor, at, proof) VALUES (?1, ?2, ?3, ?4)",
            params![account.as_bytes(), successor.as_bytes(), now as i64, proof],
        )
        .map_err(storage("record succession"))?;
        // The old key's registrations go as SIP-44 has them go; the kept
        // devices come straight back under the new key's credentials, and
        // are not left in `revoked`, since the account kept them.
        tx.execute(
            "INSERT OR REPLACE INTO revoked (device, at, not_after, account)
             SELECT device, ?2, not_after, account FROM device WHERE account = ?1",
            params![account.as_bytes(), now as i64],
        )
        .map_err(storage("retire devices"))?;
        tx.execute(
            "DELETE FROM device WHERE account = ?1",
            params![account.as_bytes()],
        )
        .map_err(storage("remove devices"))?;
        for c in kept {
            tx.execute(
                "INSERT INTO device (device, account, added, issued, not_after, credential)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (device) DO UPDATE SET account = ?2, issued = ?4, not_after = ?5,
                                                    credential = ?6",
                params![
                    c.delegate.as_bytes(),
                    successor.as_bytes(),
                    now as i64,
                    c.issued as i64,
                    c.not_after as i64,
                    c.encode(),
                ],
            )
            .map_err(storage("keep device"))?;
            tx.execute(
                "DELETE FROM revoked WHERE device = ?1",
                params![c.delegate.as_bytes()],
            )
            .map_err(storage("unretire device"))?;
        }
        tx.execute(
            "DELETE FROM lodged WHERE account = ?1",
            params![account.as_bytes()],
        )
        .map_err(storage("clear lodged"))?;
        follow_succession(&tx, account, successor)?;
        tx.commit().map_err(storage("commit handover"))?;
        Ok(())
    }

    /// SIP-62: re-key what this exchange holds of an account under SIP-59
    /// and SIP-60 -- its Move, its origin hints, a learned home -- to its
    /// successor, the Move's signature cleared. At an origin or a copy,
    /// on a succession learned from the log.
    pub fn follow_succession(&self, account: &PubKey, successor: &PubKey) {
        let db = self.db.lock().unwrap();
        let _ = follow_succession(&db, account, successor);
    }

    /// SIP-66: an exchange this registry holds a key for rotated. Every
    /// holding of `from` becomes one of `to`: an account's signed home
    /// **with its signature cleared** (the account named `from`; SIP-62's
    /// shape for a record the exchange acts on and does not vouch for),
    /// the origin hints, the learned homes. How many rows moved.
    pub fn follow_exchange(&self, from: &PubKey, to: &PubKey) -> usize {
        let db = self.db.lock().unwrap();
        let mut n = 0;
        n += db
            .execute(
                "UPDATE home SET home = ?2, sig = x'' WHERE home = ?1",
                params![from.as_bytes(), to.as_bytes()],
            )
            .unwrap_or(0);
        n += db
            .execute(
                "UPDATE OR IGNORE home_origin SET origin = ?2 WHERE origin = ?1",
                params![from.as_bytes(), to.as_bytes()],
            )
            .unwrap_or(0);
        n += db
            .execute(
                "UPDATE learned_home SET home = ?2 WHERE home = ?1",
                params![from.as_bytes(), to.as_bytes()],
            )
            .unwrap_or(0);
        n
    }

    /// SIP-44: keep a policy for `account` ahead of need.
    pub fn lodge(&self, account: &PubKey, policy: &[u8]) -> Result<(), DeviceError> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO lodged (account, policy, at) VALUES (?1, ?2, ?3)
             ON CONFLICT (account) DO UPDATE SET policy = ?2, at = ?3",
            params![account.as_bytes(), policy, now_unix() as i64],
        )
        .map_err(storage("lodge policy"))?;
        Ok(())
    }

    pub fn lodged(&self, account: &PubKey) -> Option<Vec<u8>> {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT policy FROM lodged WHERE account = ?1",
            params![account.as_bytes()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    /// SIP-45: keep where `device` asked to be woken.
    pub fn register_wake(
        &self,
        device: &PubKey,
        endpoint: &str,
        ttl: u32,
    ) -> Result<(), DeviceError> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO wake (device, endpoint, expires, woken) VALUES (?1, ?2, ?3, 0)
             ON CONFLICT (device) DO UPDATE SET endpoint = ?2, expires = ?3",
            params![
                device.as_bytes(),
                endpoint,
                (now_unix() + u64::from(ttl)) as i64
            ],
        )
        .map_err(storage("register wake"))?;
        Ok(())
    }

    pub fn forget_wake(&self, device: &PubKey) {
        let db = self.db.lock().unwrap();
        let _ = db.execute(
            "DELETE FROM wake WHERE device = ?1",
            params![device.as_bytes()],
        );
    }

    /// SIP-45: the devices of `account` -- the registered ones, and the
    /// account itself where it has none -- with a live endpoint, and when
    /// each was last woken.
    pub fn wakeable(&self, account: &PubKey) -> Vec<(PubKey, String, u64)> {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        let mut devices: Vec<PubKey> = db
            .prepare("SELECT device FROM device WHERE account = ?1 AND not_after >= ?2")
            .ok()
            .and_then(|mut st| {
                st.query_map(params![account.as_bytes(), now as i64], |r| {
                    r.get::<_, Vec<u8>>(0)
                })
                .ok()
                .map(|rows| {
                    rows.filter_map(|r| r.ok())
                        .filter_map(|b| b.try_into().ok().map(PubKey::new))
                        .collect()
                })
            })
            .unwrap_or_default();
        if devices.is_empty() {
            devices.push(*account);
        }
        let mut out = Vec::new();
        for d in devices {
            let row: Option<(String, i64)> = db
                .query_row(
                    "SELECT endpoint, woken FROM wake WHERE device = ?1 AND expires >= ?2",
                    params![d.as_bytes(), now as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .ok()
                .flatten();
            if let Some((endpoint, woken)) = row {
                out.push((d, endpoint, woken as u64));
            }
        }
        out
    }

    /// SIP-45: note that `device` was just woken.
    pub fn woke(&self, device: &PubKey) {
        let db = self.db.lock().unwrap();
        let _ = db.execute(
            "UPDATE wake SET woken = ?2 WHERE device = ?1",
            params![device.as_bytes(), now_unix() as i64],
        );
    }

    /// SIP-47: `device` held a stream and let it go. Whatever wake it was
    /// sent has been answered, so the coalescing interval is over: the next
    /// event is the first of a new absence.
    pub fn released(&self, device: &PubKey) {
        let db = self.db.lock().unwrap();
        let _ = db.execute(
            "UPDATE wake SET woken = 0 WHERE device = ?1",
            params![device.as_bytes()],
        );
    }

    /// SIP-47: every device currently registered to any of `accounts`, for
    /// the transport whitelist -- and the soonest their admission changes
    /// by itself, which is the earliest credential expiry among them.
    pub fn registered_to(&self, accounts: &[PubKey]) -> (Vec<PubKey>, Option<u64>) {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        let mut out = Vec::new();
        let mut soonest: Option<u64> = None;
        let Ok(mut stmt) = db
            .prepare("SELECT device, not_after FROM device WHERE account = ?1 AND not_after >= ?2")
        else {
            return (out, None);
        };
        for account in accounts {
            let rows = stmt.query_map(params![account.as_bytes(), now as i64], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)? as u64))
            });
            let Ok(rows) = rows else { continue };
            for (device, not_after) in rows.flatten() {
                if let Ok(b) = device.try_into() {
                    out.push(PubKey::new(b));
                    soonest = Some(soonest.map_or(not_after, |s| s.min(not_after)));
                }
            }
        }
        (out, soonest)
    }

    pub fn account_for(&self, device: &PubKey) -> PubKey {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        account_of(&db, device, now)
            .ok()
            .flatten()
            .unwrap_or(*device)
    }

    /// SIP-59: the credential a registered device presented, if it is one
    /// and the registration carries one. `None` for an account acting as
    /// its own device, which has nothing to carry.
    pub fn credential_of(&self, device: &PubKey) -> Option<Credential> {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT credential FROM device WHERE device = ?1 AND not_after >= ?2",
            params![device.as_bytes(), now as i64],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .ok()
        .flatten()
        .filter(|c| !c.is_empty())
        .and_then(|c| Credential::decode(&c).ok())
    }

    /// SIP-59: record an account's Move. `Ok(false)` when one at least as
    /// new is already here (the statement is not stale on its own terms,
    /// only superseded). The origin hints replace the last ones whenever
    /// the Move names this exchange, and are dropped when it does not.
    pub fn record_move(
        &self,
        mv: &sqex_proto::home::Move,
        domain: &str,
        origins: &[(PubKey, String)],
        me: &PubKey,
    ) -> Result<bool, DeviceError> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin move"))?;
        let held: Option<i64> = tx
            .query_row(
                "SELECT issued FROM home WHERE account = ?1",
                params![mv.account.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read home"))?;
        if let Some(issued) = held
            && mv.issued <= issued as u64
        {
            // SIP-62: a record re-keyed by a handover carries no signature
            // and is replaced by any Move the new key signs.
            let cleared: bool = tx
                .query_row(
                    "SELECT length(sig) < 64 FROM home WHERE account = ?1",
                    params![mv.account.as_bytes()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage("read home sig"))?
                .unwrap_or(false);
            if !cleared {
                return Ok(false);
            }
        }
        tx.execute(
            "INSERT INTO home (account, home, domain, issued, sig) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (account) DO UPDATE SET home = ?2, domain = ?3, issued = ?4, sig = ?5",
            params![
                mv.account.as_bytes(),
                mv.home.as_bytes(),
                domain,
                mv.issued as i64,
                &mv.sig[..],
            ],
        )
        .map_err(storage("record move"))?;
        tx.execute(
            "DELETE FROM home_origin WHERE account = ?1",
            params![mv.account.as_bytes()],
        )
        .map_err(storage("clear origins"))?;
        if mv.home == *me {
            for (origin, domain) in origins {
                tx.execute(
                    "INSERT OR REPLACE INTO home_origin (account, origin, domain) VALUES (?1, ?2, ?3)",
                    params![mv.account.as_bytes(), origin.as_bytes(), domain],
                )
                .map_err(storage("record origin"))?;
            }
        }
        tx.commit().map_err(storage("commit move"))?;
        Ok(true)
    }

    /// SIP-59: the home on record for an account -- key, domain hint,
    /// `issued` -- if a Move was ever presented here.
    ///
    /// SIP-62: a record re-keyed by a handover has its signature cleared
    /// and answers `since = 0`, so the successor's client signs a fresh
    /// Move; the record still says where the account lives.
    pub fn home_of(&self, account: &PubKey) -> Option<(PubKey, String, u64)> {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT home, domain, CASE WHEN length(sig) = 64 THEN issued ELSE 0 END
             FROM home WHERE account = ?1",
            params![account.as_bytes()],
            |r| {
                Ok((
                    PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    /// SIP-59: the Move on record, as presented, for carrying on. `None`
    /// for a record a handover re-keyed (SIP-62): the exchange acts on it
    /// and does not carry it, until the new key has signed one.
    pub fn move_of(&self, account: &PubKey) -> Option<(sqex_proto::home::Move, String)> {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT home, domain, issued, sig FROM home WHERE account = ?1 AND length(sig) = 64",
            params![account.as_bytes()],
            |r| {
                let sig: Vec<u8> = r.get(3)?;
                Ok((
                    sqex_proto::home::Move {
                        account: *account,
                        home: PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                        issued: r.get::<_, i64>(2)? as u64,
                        sig: sig.try_into().unwrap_or([0; 64]),
                    },
                    r.get::<_, String>(1)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    /// SIP-59: where an account that is not here has gone -- its home's key
    /// and domain hint, when the home on record is not `me`.
    pub fn away(&self, account: &PubKey, me: &PubKey) -> Option<(PubKey, String)> {
        self.home_of(account)
            .filter(|(home, _, _)| home != me)
            .map(|(home, domain, _)| (home, domain))
    }

    /// SIP-63: the recorded homes of `accounts`, other than `me` -- what a
    /// transport whitelist admits because of the accounts that chose them,
    /// as SIP-47 admits their devices. A record a handover re-keyed still
    /// names the home and still counts; a later Move naming `me` ends it.
    pub fn homes_of(&self, accounts: &[PubKey], me: &PubKey) -> Vec<PubKey> {
        let mut out = Vec::new();
        for account in accounts {
            if let Some((home, _)) = self.away(account, me)
                && !out.contains(&home)
            {
                out.push(home);
            }
        }
        out
    }

    /// SIP-60: record where the domain's exchange said an account lives. A
    /// signed Move on record for the account is not touched: it outranks
    /// this, and `where_is` reads it first.
    pub fn learn_home(&self, account: &PubKey, home: &PubKey, domain: &str) {
        let db = self.db.lock().unwrap();
        let _ = db.execute(
            "INSERT INTO learned_home (account, home, domain, at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (account) DO UPDATE SET home = ?2, domain = ?3, at = ?4",
            params![
                account.as_bytes(),
                home.as_bytes(),
                domain,
                now_unix() as i64
            ],
        );
    }

    /// SIP-60: where an account lives as far as this exchange knows, when
    /// that is not here -- by its own Move first, by what a domain's
    /// exchange said otherwise. What the proxying and the telling go by;
    /// never what the acts-for gate goes by.
    pub fn where_is(&self, account: &PubKey, me: &PubKey) -> Option<(PubKey, String)> {
        if let Some((home, domain, _)) = self.home_of(account) {
            return (home != *me).then_some((home, domain));
        }
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT home, domain FROM learned_home WHERE account = ?1",
            params![account.as_bytes()],
            |r| {
                Ok((
                    PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                    r.get::<_, String>(1)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()
        .filter(|(home, _)| home != me)
    }

    /// SIP-60: a domain this exchange has on record for an exchange key --
    /// from a signed Move or a learned home naming it. Empty when none.
    pub fn domain_of_exchange(&self, key: &PubKey) -> Option<String> {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT domain FROM home WHERE home = ?1 AND domain != '' LIMIT 1",
            params![key.as_bytes()],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .ok()
        .flatten()
        .or_else(|| {
            db.query_row(
                "SELECT domain FROM learned_home WHERE home = ?1 AND domain != '' LIMIT 1",
                params![key.as_bytes()],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
        })
    }

    /// SIP-60: an origin told this home it put one of its accounts in a
    /// channel; remember the origin so the home task pulls from it. Only
    /// for an account whose Move names this exchange.
    pub fn add_home_origin(
        &self,
        account: &PubKey,
        origin: &PubKey,
        domain: &str,
        me: &PubKey,
    ) -> bool {
        if !self.home_of(account).is_some_and(|(h, _, _)| h == *me) {
            return false;
        }
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO home_origin (account, origin, domain) VALUES (?1, ?2, ?3)
             ON CONFLICT (account, origin) DO UPDATE SET domain = CASE WHEN ?3 = '' THEN domain ELSE ?3 END",
            params![account.as_bytes(), origin.as_bytes(), domain],
        )
        .is_ok()
    }

    /// SIP-59: the accounts whose home on record is `peer`.
    pub fn homed_at(&self, peer: &PubKey) -> Vec<PubKey> {
        let db = self.db.lock().unwrap();
        db.prepare("SELECT account FROM home WHERE home = ?1")
            .ok()
            .and_then(|mut st| {
                st.query_map(params![peer.as_bytes()], |r| r.get::<_, Vec<u8>>(0))
                    .ok()
                    .map(|rows| {
                        rows.filter_map(|r| r.ok())
                            .filter_map(|a| a.try_into().ok().map(PubKey::new))
                            .collect()
                    })
            })
            .unwrap_or_default()
    }

    /// SIP-59: the origins the accounts homed here named, grouped by
    /// origin with the domain hint each came with, and the accounts that
    /// named it.
    pub fn homed_here(&self, me: &PubKey) -> Vec<(PubKey, String, Vec<PubKey>)> {
        let db = self.db.lock().unwrap();
        let mut by: std::collections::BTreeMap<(Vec<u8>, String), Vec<PubKey>> =
            std::collections::BTreeMap::new();
        if let Ok(mut st) = db.prepare(
            "SELECT o.account, o.origin, o.domain FROM home_origin o
             JOIN home h ON h.account = o.account WHERE h.home = ?1",
        ) && let Ok(rows) = st.query_map(params![me.as_bytes()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
            ))
        }) {
            for (account, origin, domain) in rows.flatten() {
                if let Ok(a) = <[u8; 32]>::try_from(account.as_slice()) {
                    by.entry((origin, domain)).or_default().push(PubKey::new(a));
                }
            }
        }
        by.into_iter()
            .filter_map(|((o, d), accounts)| {
                o.try_into().ok().map(|o| (PubKey::new(o), d, accounts))
            })
            .collect()
    }
}

/// SIP-62: the home records of `account` become `successor`'s, the Move's
/// signature cleared (it was the old key's). The successor's own rows, if
/// it has any, stand -- a fresh key has none.
fn follow_succession(
    db: &Connection,
    account: &PubKey,
    successor: &PubKey,
) -> Result<(), DeviceError> {
    db.execute(
        "UPDATE OR IGNORE home SET account = ?2, sig = x'' WHERE account = ?1",
        params![account.as_bytes(), successor.as_bytes()],
    )
    .map_err(storage("re-key home"))?;
    db.execute(
        "UPDATE OR IGNORE home_origin SET account = ?2 WHERE account = ?1",
        params![account.as_bytes(), successor.as_bytes()],
    )
    .map_err(storage("re-key origins"))?;
    db.execute(
        "UPDATE OR IGNORE learned_home SET account = ?2 WHERE account = ?1",
        params![account.as_bytes(), successor.as_bytes()],
    )
    .map_err(storage("re-key learned home"))?;
    for table in ["home", "home_origin", "learned_home"] {
        db.execute(
            &format!("DELETE FROM {table} WHERE account = ?1"),
            params![account.as_bytes()],
        )
        .map_err(storage("drop old key's home rows"))?;
    }
    Ok(())
}

fn account_of(db: &Connection, device: &PubKey, now: u64) -> Result<Option<PubKey>, DeviceError> {
    // A registration expires when its credential does. There is no second TTL:
    // two disagreeing lifetimes would let a peer verifying offline and an
    // exchange resolving online reach different conclusions about one device.
    db.query_row(
        "SELECT account FROM device WHERE device = ?1 AND not_after >= ?2",
        params![device.as_bytes(), now as i64],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(storage("resolve device"))
    .map(|o| o.map(|a| PubKey::new(a.try_into().unwrap_or([0; 32]))))
}

/// `(device, account, added, not_after)`.
#[allow(clippy::type_complexity)]
fn row(
    db: &Connection,
    device: &PubKey,
) -> Result<Option<(PubKey, PubKey, u64, u64)>, DeviceError> {
    db.query_row(
        "SELECT account, added, not_after FROM device WHERE device = ?1",
        params![device.as_bytes()],
        |r| {
            Ok((
                *device,
                PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
            ))
        },
    )
    .optional()
    .map_err(storage("read device row"))
}

/// Drop registrations whose credentials have expired, and revocations whose
/// credentials would have expired anyway — after which the record protects
/// nothing and can go.
fn expire(db: &Connection, now: u64) -> Result<(), DeviceError> {
    db.execute(
        "DELETE FROM device WHERE not_after < ?1",
        params![now as i64],
    )
    .map_err(storage("expire devices"))?;
    db.execute(
        "DELETE FROM revoked WHERE not_after < ?1",
        params![now as i64],
    )
    .map_err(storage("expire revocations"))?;
    Ok(())
}
