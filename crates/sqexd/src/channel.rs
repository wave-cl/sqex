//! SIP-16 channels: the first sqex state that has to survive a restart.
//!
//! Every other service in this daemon holds its state in memory, and three of
//! them argue that is *correct* rather than merely easy — the beacon because
//! replaying observations the process did not make would be a lie about what it
//! saw, a session and a room because they are live coordination that a restart
//! honestly ends. A channel cannot hold that position: its entire value is that
//! it remembers. So this module keeps a SQLite database, and an exchange
//! offering the service is promising something the other four never did.
//!
//! # Why SQLite and not the pattern next door
//!
//! `state.rs` persists by serialising everything and renaming the file over the
//! old one. That is right for a whitelist of a few dozen keys and useless here:
//! a channel may hold fifty thousand entries, wants range queries by sequence
//! number, and is pruned by age. Rewriting the log to append to it is not a
//! trade worth making at any size.
//!
//! # The two rules that shape the schema
//!
//! **Sequence numbers are never reused.** `next_seq` lives on the channel row
//! rather than being derived from `MAX(seq)`, because pruning removes entries
//! and a derived counter would hand out a number twice after the log emptied.
//!
//! **A message counter outlives the entries that carried it.** `high_water`
//! records the largest `msg_seq` ever accepted from a device, independently of
//! the entry table, because a client that lost its counter resumes from it
//! (SIP-17) and resuming from the surviving entries would reuse a nonce.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};
use sqex_proto::channel::{
    ABANDON_SECS, ChannelInfo, Create, Entries, Entry, KIND_MEMBER, Listing, MAX_BATCH,
    MAX_BATCH_BYTES, MAX_CHANNELS_PER_IDENTITY, MAX_DIRECTORY, MAX_ENTRIES, MAX_MEMBERS,
    MAX_RETENTION, MIN_RETENTION, Member, Post, Posted, Public, Retain, Role, Visibility,
};
use sqnr_core::PubKey;
use tokio::sync::Notify;

use crate::state::now_unix;

/// Why an operation was refused. These are not malformed requests — the bytes
/// were fine and the answer is no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    NoSuchChannel,
    NotAMember,
    NotAnAdmin,
    /// A join against a private channel. Membership there comes only from an
    /// invitation, and refusing is what stops an identifier being a way in.
    NotPublic,
    Full,
    TooManyChannels,
    /// A post to a private channel that has no epoch yet, or under an epoch
    /// that is not the channel's current one.
    WrongEpoch,
    BadRetention,
    /// Removing the last admin while other members remain.
    LastAdmin,
    Storage,
}

impl ChannelError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelError::NoSuchChannel => "no_such_channel",
            ChannelError::NotAMember => "not_a_member",
            ChannelError::NotAnAdmin => "not_an_admin",
            ChannelError::NotPublic => "not_public",
            ChannelError::Full => "channel_full",
            ChannelError::TooManyChannels => "too_many_channels",
            ChannelError::WrongEpoch => "wrong_epoch",
            ChannelError::BadRetention => "bad_retention",
            ChannelError::LastAdmin => "last_admin",
            ChannelError::Storage => "storage",
        }
    }

    /// The status a refusal is reported with. Distinguishable from a malformed
    /// request, as SIP-16 requires, and never silent.
    pub fn status(&self) -> u16 {
        match self {
            ChannelError::NoSuchChannel => 404,
            ChannelError::NotAMember | ChannelError::NotAnAdmin | ChannelError::NotPublic => 403,
            ChannelError::Full | ChannelError::TooManyChannels => 507,
            ChannelError::WrongEpoch | ChannelError::BadRetention | ChannelError::LastAdmin => 409,
            ChannelError::Storage => 500,
        }
    }
}

fn storage<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> ChannelError + '_ {
    move |e| {
        tracing::error!(error = %e, "channel storage: {what}");
        ChannelError::Storage
    }
}

pub struct Channels {
    db: Mutex<Connection>,
    /// One notifier per channel, so a parked `Fetch` wakes the moment an entry
    /// lands. Kept outside the database lock on purpose: a long poll must never
    /// hold the thing every other request needs.
    waiters: Mutex<HashMap<[u8; 32], Arc<Notify>>>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS channel (
    id             BLOB PRIMARY KEY,
    visibility     INTEGER NOT NULL,
    retention_secs INTEGER NOT NULL,
    max_entries    INTEGER NOT NULL,
    name           TEXT    NOT NULL,
    topic          TEXT    NOT NULL,
    epoch          INTEGER NOT NULL,
    next_seq       INTEGER NOT NULL,
    creator        BLOB    NOT NULL,
    created        INTEGER NOT NULL,
    empty_since    INTEGER
);
CREATE TABLE IF NOT EXISTS member (
    channel BLOB    NOT NULL,
    account BLOB    NOT NULL,
    role    INTEGER NOT NULL,
    joined  INTEGER NOT NULL,
    -- Presence and authority are different things in a public channel, where
    -- an admin who leaves keeps the role: joining and leaving govern reading
    -- and posting, being an admin is attached to the channel. A row with
    -- present = 0 is somebody who administers a room they are not in.
    present INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (channel, account)
);
CREATE TABLE IF NOT EXISTS entry (
    channel       BLOB    NOT NULL,
    seq           INTEGER NOT NULL,
    kind          INTEGER NOT NULL,
    account       BLOB    NOT NULL,
    device        BLOB    NOT NULL,
    posted        INTEGER NOT NULL,
    expires_after INTEGER NOT NULL,
    epoch         INTEGER NOT NULL,
    msg_seq       INTEGER NOT NULL,
    body          BLOB    NOT NULL,
    PRIMARY KEY (channel, seq)
);
CREATE TABLE IF NOT EXISTS high_water (
    channel BLOB    NOT NULL,
    device  BLOB    NOT NULL,
    epoch   INTEGER NOT NULL,
    msg_seq INTEGER NOT NULL,
    PRIMARY KEY (channel, device, epoch)
);
CREATE INDEX IF NOT EXISTS entry_by_age ON entry (posted);
"#;

impl Channels {
    /// Open the log. `None` gives an in-memory database, which is what a
    /// memory-only deployment and every test get.
    pub fn open(path: Option<&Path>) -> rusqlite::Result<Channels> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        // WAL so a reader is not blocked by the writer; FULL so an accepted
        // entry is on the disk before the exchange says it accepted it. This is
        // the service that promised to remember.
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        Ok(Channels {
            db: Mutex::new(db),
            waiters: Mutex::new(HashMap::new()),
        })
    }

    /// The notifier for a channel, created on first use.
    pub fn notifier(&self, channel: &[u8; 32]) -> Arc<Notify> {
        self.waiters
            .lock()
            .unwrap()
            .entry(*channel)
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    fn wake(&self, channel: &[u8; 32]) {
        if let Some(n) = self.waiters.lock().unwrap().get(channel) {
            n.notify_waiters();
        }
    }
}

/// The role of somebody who is *present*: a member who may read and post.
fn role_of(db: &Connection, channel: &[u8; 32], who: &PubKey) -> Option<Role> {
    db.query_row(
        "SELECT role FROM member WHERE channel = ?1 AND account = ?2 AND present = 1",
        params![&channel[..], who.as_bytes()],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .ok()
    .flatten()
    .and_then(|r| Role::from_u8(r as u8).ok())
}

/// Whether somebody administers the channel, present or not. In a public
/// channel the role outlives the membership, so an admin who left may still
/// close, retain, and see who is there.
fn is_admin(db: &Connection, channel: &[u8; 32], who: &PubKey) -> bool {
    db.query_row(
        "SELECT 1 FROM member WHERE channel = ?1 AND account = ?2 AND role = 1",
        params![&channel[..], who.as_bytes()],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .ok()
    .flatten()
    .is_some()
}

/// A channel's bounds, or `None` if it holds nothing.
fn window(db: &Connection, channel: &[u8; 32]) -> (u64, u64) {
    db.query_row(
        "SELECT COALESCE(MIN(seq), 0), COALESCE(MAX(seq), 0) FROM entry WHERE channel = ?1",
        params![&channel[..]],
        |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
    )
    .unwrap_or((0, 0))
}

impl Channels {
    /// Create a channel, idempotently on its identifier.
    ///
    /// A create naming a channel that already exists changes nothing and is
    /// answered the same way whether or not the caller belongs to it — with
    /// `epoch` 0, since reporting the real one would disclose how often a
    /// channel the caller cannot see has rotated.
    pub fn create(&self, caller: &PubKey, req: &Create) -> Result<(bool, u32), ChannelError> {
        if req.retention_secs < MIN_RETENTION || req.retention_secs > MAX_RETENTION {
            return Err(ChannelError::BadRetention);
        }
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin create"))?;

        let existing: Option<u32> = tx
            .query_row(
                "SELECT epoch FROM channel WHERE id = ?1",
                params![&req.channel[..]],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(storage("read channel"))?
            .map(|e| e as u32);

        if let Some(epoch) = existing {
            let mine = role_of(&tx, &req.channel, caller).is_some();
            return Ok((false, if mine { epoch } else { 0 }));
        }

        let mine: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM channel WHERE creator = ?1",
                params![caller.as_bytes()],
                |r| r.get(0),
            )
            .map_err(storage("count channels"))?;
        if mine as usize >= MAX_CHANNELS_PER_IDENTITY {
            return Err(ChannelError::TooManyChannels);
        }
        if req.invites.len() + 1 > MAX_MEMBERS {
            return Err(ChannelError::Full);
        }

        tx.execute(
            "INSERT INTO channel (id, visibility, retention_secs, max_entries, name, topic,
                                  epoch, next_seq, creator, created, empty_since)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 1, ?7, ?8, NULL)",
            params![
                &req.channel[..],
                req.visibility as u8 as i64,
                req.retention_secs as i64,
                req.max_entries as i64,
                // A private channel's name is carried as a sealed metadata
                // entry (SIP-19); at the exchange it must be empty, because a
                // membership graph plus a name says far more than the graph.
                if req.visibility == Visibility::Public { &req.name } else { "" },
                if req.visibility == Visibility::Public { &req.topic } else { "" },
                caller.as_bytes(),
                now as i64,
            ],
        )
        .map_err(storage("insert channel"))?;

        // The creator is the first member and an admin.
        tx.execute(
            "INSERT INTO member (channel, account, role, joined) VALUES (?1, ?2, ?3, ?4)",
            params![
                &req.channel[..],
                caller.as_bytes(),
                Role::Admin as u8 as i64,
                now as i64
            ],
        )
        .map_err(storage("insert creator"))?;

        for i in &req.invites {
            tx.execute(
                "INSERT OR IGNORE INTO member (channel, account, role, joined)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    &req.channel[..],
                    i.account.as_bytes(),
                    i.role as u8 as i64,
                    now as i64
                ],
            )
            .map_err(storage("insert invitee"))?;
        }
        tx.commit().map_err(storage("commit create"))?;
        Ok((true, 0))
    }

    /// Join a public channel. A private one MUST refuse, which is what stops an
    /// identifier being a way in.
    pub fn join(&self, caller: &PubKey, channel: &[u8; 32]) -> Result<(), ChannelError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin join"))?;
        let visibility = visibility_of(&tx, channel)?;
        if visibility != Visibility::Public {
            return Err(ChannelError::NotPublic);
        }
        let (members, _) = counts(&tx, channel)?;
        if role_of(&tx, channel, caller).is_none() && members as usize >= MAX_MEMBERS {
            return Err(ChannelError::Full);
        }
        // An admin returning to a room they administer keeps the role.
        tx.execute(
            "INSERT INTO member (channel, account, role, joined, present)
             VALUES (?1, ?2, 0, ?3, 1)
             ON CONFLICT (channel, account) DO UPDATE SET present = 1",
            params![&channel[..], caller.as_bytes(), now as i64],
        )
        .map_err(storage("insert member"))?;
        tx.execute(
            "UPDATE channel SET empty_since = NULL WHERE id = ?1",
            params![&channel[..]],
        )
        .map_err(storage("clear empty_since"))?;
        tx.commit().map_err(storage("commit join"))?;
        Ok(())
    }

    /// Leave. A private channel or direct message with no members left is
    /// destroyed; a public one persists, because it is a place rather than a
    /// conversation and is listed so somebody finds it later.
    pub fn leave(&self, caller: &PubKey, channel: &[u8; 32]) -> Result<(), ChannelError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin leave"))?;
        let visibility = visibility_of(&tx, channel)?;
        let Some(role) = role_of(&tx, channel, caller) else {
            return Err(ChannelError::NotAMember);
        };

        let (members, admins) = counts(&tx, channel)?;
        // In a private channel leaving gives up the role, so the last admin
        // walking out would strand the others with a channel nobody can
        // administer. In a public one the role is durable and leaving does not
        // touch it.
        if visibility == Visibility::Private
            && role == Role::Admin
            && admins == 1
            && members > 1
        {
            return Err(ChannelError::LastAdmin);
        }

        // Leaving a public channel gives up presence and not authority; in a
        // private one there is no channel left to administer once everybody has
        // gone, so the row goes with the person.
        if visibility == Visibility::Public && role == Role::Admin {
            tx.execute(
                "UPDATE member SET present = 0 WHERE channel = ?1 AND account = ?2",
                params![&channel[..], caller.as_bytes()],
            )
            .map_err(storage("stand down"))?;
        } else {
            tx.execute(
                "DELETE FROM member WHERE channel = ?1 AND account = ?2",
                params![&channel[..], caller.as_bytes()],
            )
            .map_err(storage("delete member"))?;
        }

        if members == 1 {
            if visibility == Visibility::Public {
                tx.execute(
                    "UPDATE channel SET empty_since = ?2 WHERE id = ?1",
                    params![&channel[..], now as i64],
                )
                .map_err(storage("set empty_since"))?;
            } else {
                destroy(&tx, channel)?;
            }
        }
        tx.commit().map_err(storage("commit leave"))?;
        Ok(())
    }

    /// Append an entry and assign it a sequence number.
    pub fn post(
        &self,
        account: &PubKey,
        device: &PubKey,
        req: &Post,
    ) -> Result<Posted, ChannelError> {
        let now = now_unix();
        let seq;
        {
            let mut db = self.db.lock().unwrap();
            let tx = db.transaction().map_err(storage("begin post"))?;
            let (visibility, epoch, retention, next) = channel_row(&tx, &req.channel)?;
            if role_of(&tx, &req.channel, account).is_none() {
                return Err(ChannelError::NotAMember);
            }
            // Epoch 0 means unsealed. That is every entry in a public channel
            // and no member entry in a private one, which is why a private
            // channel refuses posts until its first epoch exists.
            let wanted = if visibility == Visibility::Public { 0 } else { epoch };
            if req.epoch != wanted || (visibility == Visibility::Private && wanted == 0) {
                return Err(ChannelError::WrongEpoch);
            }
            // A per-message timer may only shorten the channel's window.
            if req.expires_after > retention {
                return Err(ChannelError::BadRetention);
            }

            seq = next;
            tx.execute(
                "INSERT INTO entry (channel, seq, kind, account, device, posted,
                                    expires_after, epoch, msg_seq, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    &req.channel[..],
                    seq as i64,
                    KIND_MEMBER as i64,
                    account.as_bytes(),
                    device.as_bytes(),
                    now as i64,
                    req.expires_after as i64,
                    req.epoch as i64,
                    req.msg_seq as i64,
                    &req.body,
                ],
            )
            .map_err(storage("insert entry"))?;
            tx.execute(
                "UPDATE channel SET next_seq = ?2, empty_since = NULL WHERE id = ?1",
                params![&req.channel[..], (seq + 1) as i64],
            )
            .map_err(storage("bump next_seq"))?;
            // Kept apart from the entry on purpose: pruning must not lower it,
            // or a client resuming from it would reuse a nonce.
            tx.execute(
                "INSERT INTO high_water (channel, device, epoch, msg_seq) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (channel, device, epoch)
                 DO UPDATE SET msg_seq = MAX(msg_seq, excluded.msg_seq)",
                params![
                    &req.channel[..],
                    device.as_bytes(),
                    req.epoch as i64,
                    req.msg_seq as i64
                ],
            )
            .map_err(storage("bump high water"))?;
            prune(&tx, &req.channel, now)?;
            tx.commit().map_err(storage("commit post"))?;
        }
        self.wake(&req.channel);
        Ok(Posted {
            seq,
            posted: now,
            now,
        })
    }

    /// Read entries after `since`. The caller must be a member; this is the
    /// rule that stops a private channel being read by anybody who learns its
    /// identifier, and it is checked at the moment of the call, so a removed
    /// member's next fetch is refused.
    pub fn fetch(
        &self,
        caller: &PubKey,
        channel: &[u8; 32],
        since: u64,
    ) -> Result<Entries, ChannelError> {
        let db = self.db.lock().unwrap();
        visibility_of(&db, channel)?;
        if role_of(&db, channel, caller).is_none() {
            return Err(ChannelError::NotAMember);
        }
        let (first, last) = window(&db, channel);
        let mut stmt = db
            .prepare(
                "SELECT seq, kind, account, device, posted, expires_after, epoch, msg_seq, body
                 FROM entry WHERE channel = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3",
            )
            .map_err(storage("prepare fetch"))?;
        let rows = stmt
            .query_map(
                params![&channel[..], since as i64, MAX_BATCH as i64],
                |r| {
                    Ok(Entry {
                        seq: r.get::<_, i64>(0)? as u64,
                        kind: r.get::<_, i64>(1)? as u8,
                        account: PubKey::new(r.get::<_, Vec<u8>>(2)?.try_into().unwrap_or([0; 32])),
                        device: PubKey::new(r.get::<_, Vec<u8>>(3)?.try_into().unwrap_or([0; 32])),
                        posted: r.get::<_, i64>(4)? as u64,
                        expires_after: r.get::<_, i64>(5)? as u32,
                        epoch: r.get::<_, i64>(6)? as u32,
                        msg_seq: r.get::<_, i64>(7)? as u64,
                        body: r.get(8)?,
                    })
                },
            )
            .map_err(storage("query fetch"))?;

        let mut entries = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let e = row.map_err(storage("read entry"))?;
            // Whichever binds first. An entry already counted is never dropped
            // to make room, so a client always makes progress.
            if !entries.is_empty() && bytes + e.wire_len() > MAX_BATCH_BYTES {
                break;
            }
            bytes += e.wire_len();
            entries.push(e);
        }
        Ok(Entries {
            now: now_unix(),
            first,
            last,
            entries,
        })
    }
}

fn visibility_of(db: &Connection, channel: &[u8; 32]) -> Result<Visibility, ChannelError> {
    let v: Option<i64> = db
        .query_row(
            "SELECT visibility FROM channel WHERE id = ?1",
            params![&channel[..]],
            |r| r.get(0),
        )
        .optional()
        .map_err(storage("read visibility"))?;
    match v {
        None => Err(ChannelError::NoSuchChannel),
        Some(v) => Visibility::from_u8(v as u8).map_err(|_| ChannelError::Storage),
    }
}

fn channel_row(
    db: &Connection,
    channel: &[u8; 32],
) -> Result<(Visibility, u32, u32, u64), ChannelError> {
    db.query_row(
        "SELECT visibility, epoch, retention_secs, next_seq FROM channel WHERE id = ?1",
        params![&channel[..]],
        |r| {
            Ok((
                r.get::<_, i64>(0)? as u8,
                r.get::<_, i64>(1)? as u32,
                r.get::<_, i64>(2)? as u32,
                r.get::<_, i64>(3)? as u64,
            ))
        },
    )
    .optional()
    .map_err(storage("read channel row"))?
    .ok_or(ChannelError::NoSuchChannel)
    .and_then(|(v, e, rt, n)| {
        Ok((
            Visibility::from_u8(v).map_err(|_| ChannelError::Storage)?,
            e,
            rt,
            n,
        ))
    })
}

fn counts(db: &Connection, channel: &[u8; 32]) -> Result<(i64, i64), ChannelError> {
    db.query_row(
        "SELECT COALESCE(SUM(present = 1), 0), COALESCE(SUM(role = 1), 0)
         FROM member WHERE channel = ?1",
        params![&channel[..]],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .map_err(storage("count members"))
}

fn destroy(db: &Connection, channel: &[u8; 32]) -> Result<(), ChannelError> {
    for sql in [
        "DELETE FROM entry WHERE channel = ?1",
        "DELETE FROM member WHERE channel = ?1",
        "DELETE FROM high_water WHERE channel = ?1",
        "DELETE FROM channel WHERE id = ?1",
    ] {
        db.execute(sql, params![&channel[..]])
            .map_err(storage("destroy channel"))?;
    }
    Ok(())
}

/// Drop what the channel's policy says it should no longer hold: too old, or
/// too many. The per-message timer only ever shortens.
fn prune(db: &Connection, channel: &[u8; 32], now: u64) -> Result<usize, ChannelError> {
    let mut gone = db
        .execute(
            "DELETE FROM entry WHERE channel = ?1 AND ?2 - posted >= CASE
                 WHEN expires_after > 0 AND expires_after < (
                     SELECT retention_secs FROM channel WHERE id = ?1)
                 THEN expires_after
                 ELSE (SELECT retention_secs FROM channel WHERE id = ?1) END",
            params![&channel[..], now as i64],
        )
        .map_err(storage("prune by age"))?;

    let cap: i64 = db
        .query_row(
            "SELECT max_entries FROM channel WHERE id = ?1",
            params![&channel[..]],
            |r| r.get(0),
        )
        .optional()
        .map_err(storage("read cap"))?
        .unwrap_or(0);
    let cap = if cap == 0 {
        MAX_ENTRIES as i64
    } else {
        cap.min(MAX_ENTRIES as i64)
    };
    gone += db
        .execute(
            "DELETE FROM entry WHERE channel = ?1 AND seq <= (
                 SELECT COALESCE(MAX(seq), 0) - ?2 FROM entry WHERE channel = ?1)",
            params![&channel[..], cap],
        )
        .map_err(storage("prune by count"))?;
    Ok(gone)
}

impl Channels {
    /// Everything a member or an admin may know about a channel.
    ///
    /// An admin need not be a member of a public channel, where the role is
    /// durable — and one deciding whether to close a room should be able to see
    /// who is in it first.
    pub fn info(
        &self,
        caller: &PubKey,
        device: &PubKey,
        channel: &[u8; 32],
    ) -> Result<ChannelInfo, ChannelError> {
        let db = self.db.lock().unwrap();
        let (visibility, epoch, retention, _) = channel_row(&db, channel)?;
        if role_of(&db, channel, caller).is_none() && !is_admin(&db, channel, caller) {
            return Err(ChannelError::NotAMember);
        }
        let (first, last) = window(&db, channel);

        let my_msg_seq: u64 = db
            .query_row(
                "SELECT msg_seq FROM high_water WHERE channel = ?1 AND device = ?2 AND epoch = ?3",
                params![&channel[..], device.as_bytes(), epoch as i64],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(storage("read high water"))?
            .unwrap_or(0) as u64;

        let mut stmt = db
            .prepare(
                "SELECT account, role, joined FROM member
                 WHERE channel = ?1 AND present = 1 ORDER BY account ASC",
            )
            .map_err(storage("prepare members"))?;
        let members = stmt
            .query_map(params![&channel[..]], |r| {
                Ok(Member {
                    account: PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                    role: Role::from_u8(r.get::<_, i64>(1)? as u8).unwrap_or(Role::Member),
                    joined: r.get::<_, i64>(2)? as u64,
                })
            })
            .map_err(storage("query members"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage("read members"))?;

        let (name, topic): (String, String) = db
            .query_row(
                "SELECT name, topic FROM channel WHERE id = ?1",
                params![&channel[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(storage("read name"))?;

        Ok(ChannelInfo {
            visibility,
            epoch,
            retention_secs: retention,
            max_entries: db
                .query_row(
                    "SELECT max_entries FROM channel WHERE id = ?1",
                    params![&channel[..]],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(storage("read cap"))? as u32,
            first,
            last,
            my_msg_seq,
            now: now_unix(),
            members,
            name,
            topic,
        })
    }

    /// Change a channel's retention policy. Shortening applies to entries
    /// already stored and takes effect at the next prune, not only for new
    /// ones — so this prunes now.
    pub fn retain(&self, caller: &PubKey, req: &Retain) -> Result<(), ChannelError> {
        if req.retention_secs < MIN_RETENTION || req.retention_secs > MAX_RETENTION {
            return Err(ChannelError::BadRetention);
        }
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin retain"))?;
        visibility_of(&tx, &req.channel)?;
        if !is_admin(&tx, &req.channel, caller) {
            return Err(ChannelError::NotAnAdmin);
        }
        tx.execute(
            "UPDATE channel SET retention_secs = ?2, max_entries = ?3 WHERE id = ?1",
            params![
                &req.channel[..],
                req.retention_secs as i64,
                req.max_entries as i64
            ],
        )
        .map_err(storage("update retention"))?;
        prune(&tx, &req.channel, now)?;
        tx.commit().map_err(storage("commit retain"))?;
        Ok(())
    }

    /// End a channel. Not reversible and no tombstone: the identifier becomes
    /// free, and a create naming it afterwards makes a new and unrelated
    /// channel.
    pub fn close(&self, caller: &PubKey, channel: &[u8; 32]) -> Result<(), ChannelError> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin close"))?;
        visibility_of(&tx, channel)?;
        if !is_admin(&tx, channel, caller) {
            return Err(ChannelError::NotAnAdmin);
        }
        destroy(&tx, channel)?;
        tx.commit().map_err(storage("commit close"))?;
        Ok(())
    }

    /// Search the public directory. Private channels never appear, under any
    /// query.
    pub fn list(&self, query: &str, offset: u32) -> Result<Listing, ChannelError> {
        let db = self.db.lock().unwrap();
        let like = format!("%{}%", query.replace('%', "\\%").replace('_', "\\_"));
        let total: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM channel WHERE visibility = 1
                 AND (name LIKE ?1 ESCAPE '\\' OR topic LIKE ?1 ESCAPE '\\')",
                params![&like],
                |r| r.get(0),
            )
            .map_err(storage("count directory"))?;

        let mut stmt = db
            .prepare(
                "SELECT c.id, c.name, c.topic,
                        (SELECT COUNT(*) FROM member m WHERE m.channel = c.id AND m.present = 1),
                        (SELECT COALESCE(MAX(seq), 0) FROM entry e WHERE e.channel = c.id)
                 FROM channel c
                 WHERE c.visibility = 1 AND (c.name LIKE ?1 ESCAPE '\\'
                                             OR c.topic LIKE ?1 ESCAPE '\\')
                 ORDER BY c.created ASC LIMIT ?2 OFFSET ?3",
            )
            .map_err(storage("prepare directory"))?;
        let channels = stmt
            .query_map(params![&like, MAX_DIRECTORY as i64, offset as i64], |r| {
                Ok(Public {
                    channel: r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32]),
                    name: r.get(1)?,
                    topic: r.get(2)?,
                    members: r.get::<_, i64>(3)? as u16,
                    last: r.get::<_, i64>(4)? as u64,
                })
            })
            .map_err(storage("query directory"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage("read directory"))?;

        Ok(Listing {
            now: now_unix(),
            total: total as u32,
            channels,
        })
    }

    /// Prune every channel, and close the public ones that have been abandoned.
    ///
    /// A retention window measured in days cannot wait for somebody to touch
    /// the channel — a channel nobody has opened in weeks is exactly the case
    /// that matters — so this runs on a schedule rather than on the operation
    /// path, which is a first for this daemon.
    pub fn sweep(&self) -> (usize, usize) {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let Ok(tx) = db.transaction() else {
            return (0, 0);
        };
        let ids: Vec<[u8; 32]> = {
            let Ok(mut stmt) = tx.prepare("SELECT id FROM channel") else {
                return (0, 0);
            };
            let Ok(rows) = stmt.query_map([], |r| {
                Ok(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0u8; 32]))
            }) else {
                return (0, 0);
            };
            rows.filter_map(|r| r.ok()).collect()
        };

        let (mut pruned, mut closed) = (0usize, 0usize);
        for id in ids {
            pruned += prune(&tx, &id, now).unwrap_or(0);

            // Abandonment is a condition, not a timer on the channel: a public
            // room holding nothing that nobody is in. One with a single old
            // message survives until retention removes it, and then has its
            // window to acquire another.
            let empty = counts(&tx, &id).map(|(m, _)| m == 0).unwrap_or(false)
                && window(&tx, &id) == (0, 0)
                && visibility_of(&tx, &id) == Ok(Visibility::Public);
            if !empty {
                let _ = tx.execute(
                    "UPDATE channel SET empty_since = NULL WHERE id = ?1 AND empty_since IS NOT NULL",
                    params![&id[..]],
                );
                continue;
            }
            let since: Option<i64> = tx
                .query_row(
                    "SELECT empty_since FROM channel WHERE id = ?1",
                    params![&id[..]],
                    |r| r.get(0),
                )
                .optional()
                .ok()
                .flatten();
            match since {
                None => {
                    let _ = tx.execute(
                        "UPDATE channel SET empty_since = ?2 WHERE id = ?1",
                        params![&id[..], now as i64],
                    );
                }
                Some(t) if now.saturating_sub(t as u64) >= ABANDON_SECS => {
                    if destroy(&tx, &id).is_ok() {
                        closed += 1;
                    }
                }
                Some(_) => {}
            }
        }
        let _ = tx.commit();
        (pruned, closed)
    }
}
