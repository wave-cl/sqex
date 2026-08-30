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
CREATE INDEX IF NOT EXISTS device_by_account ON device (account);
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
    pub fn register(
        &self,
        caller: &PubKey,
        credential: &Credential,
    ) -> Result<(), DeviceError> {
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

        tx.execute("DELETE FROM device WHERE device = ?1", params![device.as_bytes()])
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
    pub fn account_for(&self, device: &PubKey) -> PubKey {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        account_of(&db, device, now)
            .ok()
            .flatten()
            .unwrap_or(*device)
    }
}

fn account_of(
    db: &Connection,
    device: &PubKey,
    now: u64,
) -> Result<Option<PubKey>, DeviceError> {
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
    db.execute("DELETE FROM device WHERE not_after < ?1", params![now as i64])
        .map_err(storage("expire devices"))?;
    db.execute(
        "DELETE FROM revoked WHERE not_after < ?1",
        params![now as i64],
    )
    .map_err(storage("expire revocations"))?;
    Ok(())
}
