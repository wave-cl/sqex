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
use sqex_proto::credential::{Credential, Invalid, SCOPE_CHAT};
use sqex_proto::device::{Device, Devices, MAX_DEVICES, MAX_REGISTRATIONS_PER_HOUR};
use sqnr_core::PubKey;

use crate::state::now_unix;

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
    not_after INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_by_account ON device (account);
"#;

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
        Ok(Registry { db: Mutex::new(db) })
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
            "INSERT INTO device (device, account, added, issued, not_after)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (device) DO UPDATE SET issued = ?4, not_after = ?5",
            params![
                credential.delegate.as_bytes(),
                credential.account.as_bytes(),
                now as i64,
                credential.issued as i64,
                credential.not_after as i64,
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
    pub fn revoke(&self, caller: &PubKey, device: &PubKey) -> Result<(), DeviceError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin revoke"))?;
        expire(&tx, now)?;

        let target = row(&tx, device)?.ok_or(DeviceError::NoSuchDevice)?;
        let mine = row(&tx, caller)?.ok_or(DeviceError::NotAuthorised)?;
        if mine.1 != target.1 {
            return Err(DeviceError::NotAuthorised);
        }
        // May name itself, which is how a client signs itself out.
        if caller != device && mine.2 > target.2 {
            return Err(DeviceError::Senior);
        }

        tx.execute("DELETE FROM device WHERE device = ?1", params![device.as_bytes()])
            .map_err(storage("delete device"))?;
        tx.execute(
            "INSERT INTO revoked (device, at, not_after) VALUES (?1, ?2, ?3)
             ON CONFLICT (device) DO UPDATE SET at = ?2, not_after = ?3",
            params![device.as_bytes(), now as i64, target.3 as i64],
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
                "SELECT device, added, not_after FROM device
                 WHERE account = ?1 AND not_after >= ?2 ORDER BY added ASC, device ASC",
            )
            .map_err(storage("prepare list"))?;
        let devices = stmt
            .query_map(params![account.as_bytes(), now as i64], |r| {
                Ok(Device {
                    device: PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                    added: r.get::<_, i64>(1)? as u64,
                    not_after: r.get::<_, i64>(2)? as u64,
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
