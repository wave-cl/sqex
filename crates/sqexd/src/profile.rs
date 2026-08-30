//! SIP-21 profiles and blocking: per-account state that no channel owns.
//!
//! Two halves of one question — what a person shows to others, and who is
//! allowed to reach them.
//!
//! # Blocking asks the exchange to answer untruthfully
//!
//! A blocked account's invitation is dropped and answered as though it landed.
//! That is the exchange saying something untrue on the blocker's behalf, and
//! this module calls it that rather than describing it as a filter: a refusal
//! the caller can detect tells a harasser they have been blocked, and a block
//! that announces itself is worse than none.
//!
//! It is **not** undetectable and MUST NOT be described as though it were.
//! Every request succeeds, but no delivery cursor ever advances and the channel
//! has one member in it, so a determined caller can infer the block — exactly
//! the inference a WhatsApp user draws from a tick that never becomes two. What
//! this buys is that nothing *states* it.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use sqex_proto::profile::{
    Blocks, Got, MAX_BLOCKED, MAX_UPDATES_PER_HOUR, Record, FLAG_WITHHOLD,
};
use sqnr_core::PubKey;

use crate::state::now_unix;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    TooManyBlocked,
    RateLimited,
    /// SIP-32: the record names an account other than the caller's.
    NotYours,
    /// SIP-32: the record's signature does not verify under the device it names.
    BadSignature,
    /// SIP-32: a serial at or below the one held — an old record put back over
    /// a newer one, which is what the counter exists to make lose.
    Stale,
    Storage,
}

impl ProfileError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProfileError::TooManyBlocked => "too_many_blocked",
            ProfileError::RateLimited => "rate_limited",
            ProfileError::NotYours => "not_yours",
            ProfileError::BadSignature => "bad_signature",
            ProfileError::Stale => "stale_serial",
            ProfileError::Storage => "storage",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            ProfileError::TooManyBlocked | ProfileError::RateLimited => 507,
            ProfileError::NotYours | ProfileError::BadSignature => 401,
            ProfileError::Stale => 409,
            ProfileError::Storage => 500,
        }
    }
}

fn storage<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> ProfileError + '_ {
    move |e| {
        tracing::error!(error = %e, "profiles: {what}");
        ProfileError::Storage
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS profile (
    account BLOB PRIMARY KEY,
    flags   INTEGER NOT NULL,
    name    TEXT    NOT NULL,
    title   TEXT    NOT NULL,
    avatar  BLOB    NOT NULL,
    updated INTEGER NOT NULL,
    -- A rate limit on updates, because a profile is served to everyone who
    -- shares a channel with its subject: rewriting it repeatedly is a cheap way
    -- to make an exchange serve a great deal of traffic on somebody else's
    -- behalf.
    hour    INTEGER NOT NULL,
    in_hour INTEGER NOT NULL,
    -- SIP-32. `serial` is the subject's own counter and the highest wins, which
    -- is what makes an old record lose rather than merely look old. `record` is
    -- the signed artifact, stored whole so what is served later is the thing
    -- the subject signed rather than this exchange's copy of its fields.
    serial  INTEGER NOT NULL DEFAULT 0,
    record  BLOB    NOT NULL DEFAULT x''
);
CREATE TABLE IF NOT EXISTS block (
    account BLOB NOT NULL,
    blocked BLOB NOT NULL,
    at      INTEGER NOT NULL,
    PRIMARY KEY (account, blocked)
);
"#;

pub struct Profiles {
    db: Mutex<Connection>,
}

impl Profiles {
    pub fn open(path: Option<&Path>) -> rusqlite::Result<Profiles> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        // A deployed store has profile rows written before SIP-32, which
        // `CREATE TABLE IF NOT EXISTS` will not alter. They keep their fields
        // and report no record, which is the honest answer: what is held is an
        // assertion this exchange accepted, not evidence anybody can check.
        for (column, decl) in [
            ("serial", "INTEGER NOT NULL DEFAULT 0"),
            ("record", "BLOB NOT NULL DEFAULT x''"),
        ] {
            let existing: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('profile') WHERE name = ?1",
                    [column],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if existing == 0 {
                db.execute_batch(&format!("ALTER TABLE profile ADD COLUMN {column} {decl}"))?;
            }
        }
        Ok(Profiles { db: Mutex::new(db) })
    }

    /// Replace a profile whole.
    pub fn put(&self, account: &PubKey, record: &Record) -> Result<(), ProfileError> {
        let p = &record.profile;
        // SIP-32. The record is the subject's own statement, so it is verified
        // here and stored whole — what the exchange serves later is the
        // artifact rather than its copy of the fields.
        if &record.account != account {
            return Err(ProfileError::NotYours);
        }
        if !record.verify() {
            return Err(ProfileError::BadSignature);
        }
        let now = now_unix();
        let hour = now / 3600;
        let db = self.db.lock().unwrap();
        let used: Option<(i64, i64)> = db
            .query_row(
                "SELECT hour, in_hour FROM profile WHERE account = ?1",
                params![account.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage("read rate"))?;
        // Ordering is by serial and rate limiting is by the clock; the two do
        // not interact. A serial at or below the one held is a replay — an old
        // record put back over a new one — and loses, which is the property
        // that makes these replicate without trusting whoever carries them.
        let held: Option<i64> = db
            .query_row(
                "SELECT serial FROM profile WHERE account = ?1",
                params![account.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read serial"))?;
        if let Some(h) = held
            && record.serial <= h as u64
        {
            return Err(ProfileError::Stale);
        }

        let in_hour = match used {
            Some((h, n)) if h as u64 == hour => {
                if n as usize >= MAX_UPDATES_PER_HOUR {
                    return Err(ProfileError::RateLimited);
                }
                n + 1
            }
            _ => 1,
        };

        db.execute(
            "INSERT INTO profile (account, flags, name, title, avatar, updated, hour, in_hour,
                                  serial, record)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT (account) DO UPDATE SET
                 flags = ?2, name = ?3, title = ?4, avatar = ?5,
                 updated = ?6, hour = ?7, in_hour = ?8,
                 serial = ?9, record = ?10",
            params![
                account.as_bytes(),
                p.flags as i64,
                &p.name,
                &p.title,
                &p.avatar,
                now as i64,
                hour as i64,
                in_hour,
                record.serial as i64,
                record.encode(),
            ],
        )
        .map_err(storage("write profile"))?;
        Ok(())
    }

    /// Read a profile.
    ///
    /// `shares_a_channel` decides whether a withholding subject is visible to
    /// this caller. Absent, withheld and blocked all answer identically.
    pub fn get(
        &self,
        caller: &PubKey,
        subject: &PubKey,
        shares_a_channel: &dyn Fn(&PubKey, &PubKey) -> bool,
    ) -> Result<Got, ProfileError> {
        let now = now_unix();
        let db = self.db.lock().unwrap();

        // A subject who blocked the caller is not there as far as they are
        // concerned — including their avatar, which a client should not be
        // decoding for somebody it has been asked to keep away.
        if blocked_by(&db, subject, caller)? {
            return Ok(Got::none(now));
        }

        let row: Option<(i64, i64, Vec<u8>)> = db
            .query_row(
                "SELECT flags, updated, record FROM profile WHERE account = ?1",
                params![subject.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(storage("read profile"))?;
        let Some((flags, updated, stored)) = row else {
            return Ok(Got::none(now));
        };

        // An account always sees its own, whatever the flag says.
        let withheld = flags as u8 & FLAG_WITHHOLD != 0;
        if withheld && caller != subject && !shares_a_channel(caller, subject) {
            return Ok(Got::none(now));
        }

        Ok(Got {
            found: true,
            updated: updated as u64,
            now,
            // The artifact, served whole. Empty for a row written before
            // SIP-32: reported as absent rather than reassembled from the
            // columns, because a record this exchange manufactured would look
            // exactly like one its subject signed and be worth nothing.
            record: if stored.is_empty() {
                None
            } else {
                Record::decode(&stored).ok()
            },
        })
    }

    pub fn set_block(
        &self,
        account: &PubKey,
        other: &PubKey,
        add: bool,
    ) -> Result<(), ProfileError> {
        let db = self.db.lock().unwrap();
        if add {
            let n: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM block WHERE account = ?1",
                    params![account.as_bytes()],
                    |r| r.get(0),
                )
                .map_err(storage("count blocks"))?;
            if n as usize >= MAX_BLOCKED {
                return Err(ProfileError::TooManyBlocked);
            }
            db.execute(
                "INSERT OR IGNORE INTO block (account, blocked, at) VALUES (?1, ?2, ?3)",
                params![account.as_bytes(), other.as_bytes(), now_unix() as i64],
            )
            .map_err(storage("insert block"))?;
        } else {
            db.execute(
                "DELETE FROM block WHERE account = ?1 AND blocked = ?2",
                params![account.as_bytes(), other.as_bytes()],
            )
            .map_err(storage("delete block"))?;
        }
        Ok(())
    }

    /// The caller's list, returned only to its owner.
    pub fn blocks(&self, account: &PubKey) -> Result<Blocks, ProfileError> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT blocked FROM block WHERE account = ?1 ORDER BY at ASC")
            .map_err(storage("prepare blocks"))?;
        let accounts = stmt
            .query_map(params![account.as_bytes()], |r| {
                Ok(PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])))
            })
            .map_err(storage("query blocks"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage("read blocks"))?;
        Ok(Blocks {
            now: now_unix(),
            accounts,
        })
    }

    /// Whether `subject` has blocked `other`. Used by SIP-16 to drop an
    /// invitation without saying so.
    pub fn has_blocked(&self, subject: &PubKey, other: &PubKey) -> bool {
        let db = self.db.lock().unwrap();
        blocked_by(&db, subject, other).unwrap_or(false)
    }
}

fn blocked_by(
    db: &Connection,
    account: &PubKey,
    other: &PubKey,
) -> Result<bool, ProfileError> {
    db.query_row(
        "SELECT 1 FROM block WHERE account = ?1 AND blocked = ?2",
        params![account.as_bytes(), other.as_bytes()],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .map_err(storage("check block"))
    .map(|o| o.is_some())
}
