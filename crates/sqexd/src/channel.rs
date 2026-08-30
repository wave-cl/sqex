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
use sha2::{Digest, Sha256};
use sqex_proto::channel::{
    ABANDON_SECS, Action, Invitee, ChannelInfo, Create, Directory, Entries, Entry, KIND_MEMBER,
    KIND_SYSTEM, Listing,
    EVENT_ADDED, EVENT_DEMOTED, EVENT_JOINED, EVENT_LEFT, EVENT_PROMOTED, EVENT_REMOVED,
    EVENT_RETENTION, EVENT_ROTATED, MAX_BATCH, MAX_SIGNALS, Mark, Marks, SIGNAL_TTL, Signalled,
    System, direct_message_id,
    ENTRY_HEADER, MAX_BATCH_BYTES, MAX_CHANNEL_BYTES, MAX_CHANNELS_PER_IDENTITY,
    MAX_DIRECTORY, MAX_ENTRIES, MAX_MEMBERS, MAX_NAME, MAX_TOPIC,
    MAX_MINE, MAX_RETENTION, MAX_UNSPOKEN, MIN_RETENTION, Member, Membership, Mines, Post,
    Posted, Public, Retain, Role, Visibility,
};
use sqex_proto::blob_store::{
    Begin as BlobBegin, ByChannelBlob, Chunk, Headed, MAX_BLOB_CHANNELS,
    MAX_CHANNEL_BLOB_BYTES, MAX_UPLOADS,
    PutChunk as BlobPut, UPLOAD_TTL, blob_id,
};
use sqex_proto::channel_key::{
    Absent, Envelope, Got, MAX_EPOCH, Put as KeyPut, PutAck, Stranded,
};
use sqex_proto::entry_sig::{ActionTerms, EntryTerms, GENESIS, Place, link, verify_action, verify_entry};
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
    /// Key distribution against a public channel, which seals nothing.
    NotPrivate,
    /// Adding or removing a member of a direct message, whose membership can
    /// only ever be the two identities it is named after.
    DirectMessage,
    /// An envelope naming prekey id 0. There is no static-only path.
    NoPrekey,
    NoSuchUpload,
    NoSuchBlob,
    NoSuchEntry,
    /// A redaction naming an entry the exchange wrote itself.
    SystemEntry,
    /// A chunk index outside what the upload reserved.
    BadChunk,
    TooManyUploads,
    BlobQuota,
    /// The blob is already attached to as many channels as SIP-18 allows.
    BlobChannels,
    /// The invitee is already in as many channels they have never spoken in as
    /// SIP-16 allows. The anti-spam measure: without it a stranger can add an
    /// identity to unbounded numbers of channels.
    InviteQuota,
    BadRetention,
    /// Removing the last admin while other members remain.
    LastAdmin,
    /// SIP-31: the signature does not verify, or is absent.
    ///
    /// Checked here even though every receiver must check it too. SIP-19 places
    /// its authority rules with receivers *because the exchange cannot check
    /// them*; this one it can, since the signature and the device are both in
    /// the clear — so refusing here means no entry is ever stored that every
    /// receiver would reject.
    BadSignature,
    /// SIP-31: the chain position or link does not follow the one held.
    BrokenChain,
    /// SIP-31: a create reusing an instance this channel identifier has already
    /// used, which would re-admit the entries signed under it.
    UsedInstance,
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
            ChannelError::NotPrivate => "not_private",
            ChannelError::DirectMessage => "direct_message",
            ChannelError::NoPrekey => "no_prekey",
            ChannelError::NoSuchUpload => "no_such_upload",
            ChannelError::NoSuchBlob => "no_such_blob",
            ChannelError::NoSuchEntry => "no_such_entry",
            ChannelError::SystemEntry => "system_entry",
            ChannelError::BadSignature => "bad_signature",
            ChannelError::BrokenChain => "broken_chain",
            ChannelError::UsedInstance => "used_instance",
            ChannelError::BadChunk => "bad_chunk",
            ChannelError::TooManyUploads => "too_many_uploads",
            ChannelError::BlobQuota => "blob_quota",
            ChannelError::BlobChannels => "blob_channel_quota",
            ChannelError::InviteQuota => "invite_quota",
            ChannelError::BadRetention => "bad_retention",
            ChannelError::LastAdmin => "last_admin",
            ChannelError::Storage => "storage",
        }
    }

    /// The status a refusal is reported with. Distinguishable from a malformed
    /// request, as SIP-16 requires, and never silent.
    pub fn status(&self) -> u16 {
        match self {
            ChannelError::NoSuchChannel
            | ChannelError::NoSuchUpload
            | ChannelError::NoSuchBlob
            | ChannelError::NoSuchEntry => 404,
            ChannelError::NotAMember | ChannelError::NotAnAdmin | ChannelError::NotPublic => 403,
            ChannelError::Full
            | ChannelError::TooManyChannels
            | ChannelError::TooManyUploads
            | ChannelError::BlobQuota
            | ChannelError::BlobChannels
            | ChannelError::InviteQuota => 507,
            ChannelError::WrongEpoch
            | ChannelError::BadRetention
            | ChannelError::LastAdmin
            | ChannelError::NotPrivate
            | ChannelError::DirectMessage
            | ChannelError::NoPrekey
            | ChannelError::BadChunk
            | ChannelError::SystemEntry
            | ChannelError::BrokenChain
            | ChannelError::UsedInstance => 409,
            // A forged or absent signature is a refusal to authenticate what
            // was sent, not a conflict with stored state.
            ChannelError::BadSignature => 401,
            ChannelError::Storage => 500,
        }
    }
}

/// Whether adding `account` to another channel would exceed the invitation
/// quota. Counts memberships they are present in and have never posted in;
/// posting in one, or leaving it, frees the budget again.
fn unspoken_full(db: &Connection, account: &PubKey) -> Result<bool, ChannelError> {
    let n: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM member WHERE account = ?1 AND present = 1 AND posted = 0",
            params![account.as_bytes()],
            |r| r.get(0),
        )
        .map_err(storage("count unspoken"))?;
    Ok(n as usize >= MAX_UNSPOKEN)
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

fn storage<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> ChannelError + '_ {
    move |e| {
        tracing::error!(error = %e, "channel storage: {what}");
        ChannelError::Storage
    }
}

pub struct Channels {
    db: Mutex<Connection>,
    /// This exchange's own SIP-9 identity, bound into every SIP-31 signature.
    ///
    /// A direct message's identifier derives from its two accounts, so the same
    /// conversation has identical channel bytes on every exchange in existence.
    /// Without this in the signing input an entry lifts from one exchange into
    /// another's copy of it and verifies there. Required at construction rather
    /// than defaulted, because a default would be a fixed place that every
    /// deployment shared.
    exchange: PubKey,
    /// Stored entry bytes one channel may hold before the oldest are pruned.
    ///
    /// SIP-16 calls its numbers recommended values, and this one is the only
    /// limit an operator plausibly wants lower — it is the one that decides how
    /// much disk a busy channel can take. It is also the only way to exercise
    /// the byte prune without writing 128 MiB.
    max_channel_bytes: u64,
    /// One notifier per channel, so a parked `Fetch` wakes the moment an entry
    /// lands. Kept outside the database lock on purpose: a long poll must never
    /// hold the thing every other request needs.
    waiters: Mutex<HashMap<[u8; 32], Arc<Notify>>>,
    /// Signals waiting for a member, by channel and recipient.
    ///
    /// In memory, and that is principled rather than unfinished: a typing
    /// indicator that survived a restart would be describing a keyboard nobody
    /// is at. SIP-16 forbids storing these at all, and an exchange that dropped
    /// every one of them would still conform.
    #[allow(clippy::type_complexity)]
    signals: Mutex<HashMap<([u8; 32], PubKey), Vec<(PubKey, u8, Vec<u8>, u64)>>>,
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
    empty_since    INTEGER,
    -- When the current epoch was minted. SIP-17 lets a member who is not an
    -- admin advance the epoch when it revoked one of its own devices *since*
    -- this moment, so the exchange has to hold the moment.
    epoch_at       INTEGER NOT NULL DEFAULT 0,
    -- SIP-31: which incarnation of this identifier this is. A direct message's
    -- id derives from its two accounts, so a destroyed one is recreated under
    -- the same 32 bytes with its numbering restarted; without this marker in
    -- every signature, the previous incarnation's entries verify against this
    -- one. Proposed by the creator, because it has to be signed over before the
    -- exchange has minted anything.
    instance       BLOB    NOT NULL
);
-- Instances this channel identifier has already used, so that a recreation
-- cannot reuse one and re-admit the entries signed under it.
--
-- Only direct messages can ever recreate an identifier — a random one that is
-- destroyed is simply gone — so this grows with how often two people have
-- destroyed and rebuilt their conversation, which is a small number.
CREATE TABLE IF NOT EXISTS retired_instance (
    channel  BLOB NOT NULL,
    instance BLOB NOT NULL,
    PRIMARY KEY (channel, instance)
);
-- Accounts this exchange has already shown the front door to.
--
-- Kept so that welcoming happens once and not on every request: somebody who
-- leaves the welcome channel has to stay left, and an exchange that put them
-- back on their next poll would be arguing with them.
CREATE TABLE IF NOT EXISTS welcomed (
    account BLOB PRIMARY KEY,
    at      INTEGER NOT NULL
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
    -- Whether this member has ever posted here, which is what the invitation
    -- quota counts. A flag rather than a query over `entry`, because pruning
    -- removes entries and somebody whose only message aged out would look like
    -- a fresh invitation again.
    posted  INTEGER NOT NULL DEFAULT 0,
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
    -- SIP-31. `chain_seq` is a chain position and deliberately not `msg_seq`,
    -- which is an AEAD nonce and is 0 in a public channel where a chain still
    -- has to run. `body_hash` is what the signature commits to in place of the
    -- body, so a redaction can take the bytes and leave a signature that still
    -- verifies.
    chain_seq     INTEGER NOT NULL,
    prev          BLOB    NOT NULL,
    body_hash     BLOB    NOT NULL,
    sig           BLOB    NOT NULL,
    body          BLOB    NOT NULL,
    PRIMARY KEY (channel, seq)
);
-- SIP-31 chain head per device per channel.
--
-- Kept independently of the entries for the reason `high_water` is: pruning
-- removes entries, so the highest surviving position understates what was used,
-- and a device resuming from an understated mark forks its own chain.
CREATE TABLE IF NOT EXISTS chain (
    channel   BLOB    NOT NULL,
    device    BLOB    NOT NULL,
    chain_seq INTEGER NOT NULL,
    head      BLOB    NOT NULL,
    PRIMARY KEY (channel, device)
);
CREATE TABLE IF NOT EXISTS high_water (
    channel BLOB    NOT NULL,
    device  BLOB    NOT NULL,
    epoch   INTEGER NOT NULL,
    msg_seq INTEGER NOT NULL,
    PRIMARY KEY (channel, device, epoch)
);
CREATE TABLE IF NOT EXISTS envelope (
    channel    BLOB    NOT NULL,
    recipient  BLOB    NOT NULL,
    epoch      INTEGER NOT NULL,
    from_epoch INTEGER NOT NULL,
    to_epoch   INTEGER NOT NULL,
    prekey_id  INTEGER NOT NULL,
    ephemeral  BLOB    NOT NULL,
    ciphertext BLOB    NOT NULL,
    -- One envelope per recipient per epoch. This is what settles the
    -- direct-message creation race: both ends mint epoch 1 and publish, one
    -- Put wins, and the loser is told so and collects instead.
    PRIMARY KEY (channel, recipient, epoch)
);
CREATE TABLE IF NOT EXISTS blob (
    id     BLOB PRIMARY KEY,
    size   INTEGER NOT NULL,
    chunks INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS blob_chunk (
    blob   BLOB    NOT NULL,
    idx    INTEGER NOT NULL,
    sealed BLOB    NOT NULL,
    PRIMARY KEY (blob, idx)
);
-- A blob is attached to channels, never to a message: the exchange cannot read
-- a reference, so it cannot count them. An attachment ages against the
-- channel's window, or the message's own timer if that is shorter, and a blob
-- with no attachments left is deleted.
CREATE TABLE IF NOT EXISTS attachment (
    channel       BLOB    NOT NULL,
    blob          BLOB    NOT NULL,
    attached      INTEGER NOT NULL,
    expires_after INTEGER NOT NULL,
    uploader      BLOB    NOT NULL,
    PRIMARY KEY (channel, blob)
);
CREATE TABLE IF NOT EXISTS upload (
    id            INTEGER PRIMARY KEY,
    channel       BLOB    NOT NULL,
    uploader      BLOB    NOT NULL,
    size          INTEGER NOT NULL,
    chunks        INTEGER NOT NULL,
    expires_after INTEGER NOT NULL,
    started       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS upload_chunk (
    upload INTEGER NOT NULL,
    idx    INTEGER NOT NULL,
    sealed BLOB    NOT NULL,
    PRIMARY KEY (upload, idx)
);
-- Two integers per member rather than an entry per read. A receipt per reader
-- per message is the obvious model and does not survive a group: 256 members
-- reading 100 messages would be 25 600 rows describing 100. Reading is
-- monotonic, so a high-water mark loses nothing anybody wanted, and receipts
-- cost nothing against retention.
CREATE TABLE IF NOT EXISTS cursor (
    channel   BLOB    NOT NULL,
    account   BLOB    NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    read      INTEGER NOT NULL DEFAULT 0,
    receipts  INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (channel, account)
);
CREATE INDEX IF NOT EXISTS entry_by_age ON entry (posted);
"#;

impl Channels {
    /// Open the log. `None` gives an in-memory database, which is what a
    /// memory-only deployment and every test get.
    pub fn open(path: Option<&Path>, exchange: PubKey) -> rusqlite::Result<Channels> {
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
        // A deployed exchange has a `channel` table without `epoch_at`, and
        // `CREATE TABLE IF NOT EXISTS` will not add it.
        add_column(&db, "channel", "epoch_at", "INTEGER NOT NULL DEFAULT 0")?;
        // SIP-31's columns are deliberately *not* added this way, and carry no
        // defaults. A database predating them is wiped rather than migrated,
        // because a default would make an unsigned entry representable — and
        // the whole guarantee is that one is not.
        Ok(Channels {
            db: Mutex::new(db),
            exchange,
            max_channel_bytes: MAX_CHANNEL_BYTES,
            waiters: Mutex::new(HashMap::new()),
            signals: Mutex::new(HashMap::new()),
        })
    }

    /// Where a signature for `channel` must have been made: this exchange, that
    /// channel, and the incarnation currently standing under that identifier.
    fn place(&self, db: &Connection, channel: &[u8; 32]) -> Result<Place, ChannelError> {
        let instance: Vec<u8> = db
            .query_row(
                "SELECT instance FROM channel WHERE id = ?1",
                params![&channel[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read instance"))?
            .ok_or(ChannelError::NoSuchChannel)?;
        Ok(Place {
            exchange: self.exchange,
            instance: instance.try_into().map_err(|_| ChannelError::Storage)?,
            channel: *channel,
        })
    }

    /// Lower the stored-bytes cap. An operator may want a smaller number than
    /// SIP-16 recommends; a test needs one, or it must write 128 MiB to find
    /// out whether the prune runs at all.
    pub fn with_max_channel_bytes(mut self, bytes: u64) -> Channels {
        self.max_channel_bytes = bytes;
        self
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
    pub fn create(
        &self,
        caller: &PubKey,
        device: &PubKey,
        req: &Create,
        blocked: &dyn Fn(&PubKey, &PubKey) -> bool,
    ) -> Result<(bool, u32, [u8; 32]), ChannelError> {
        if req.retention_secs < MIN_RETENTION || req.retention_secs > MAX_RETENTION {
            return Err(ChannelError::BadRetention);
        }
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin create"))?;

        let existing: Option<(u32, [u8; 32])> = tx
            .query_row(
                "SELECT epoch, instance FROM channel WHERE id = ?1",
                params![&req.channel[..]],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(storage("read channel"))?
            .map(|(e, i)| {
                let i: [u8; 32] = i.try_into().map_err(|_| ChannelError::Storage)?;
                Ok::<_, ChannelError>((e as u32, i))
            })
            .transpose()?;

        if let Some((epoch, instance)) = existing {
            if role_of(&tx, &req.channel, caller).is_some() {
                return Ok((false, epoch, instance));
            }
            // A direct message is the one case where a create may touch a
            // channel the caller is not in, and it has to be: the identifier is
            // the derivation over two accounts, so anybody can compute it. Left
            // alone, one request would let a stranger sit in the channel
            // forever and deny two people the ability to ever talk.
            match dm_claim(&tx, &req.channel, caller, &req.invites)? {
                // Reporting the real epoch or instance here would disclose how
                // often a channel the caller cannot see has rotated, and
                // therefore roughly how often somebody was removed from it.
                DmClaim::None => return Ok((false, 0, [0u8; 32])),
                // Returning after leaving: re-add them and keep the history.
                DmClaim::Returning => {
                    // The signature must name the incarnation that stands, and
                    // a returning party cannot know it — they are not a member,
                    // so nothing has told them. Hand it over and change
                    // nothing; the client signs against it and creates again.
                    // One extra round trip, only when returning to a direct
                    // message you had left.
                    if req.instance != instance {
                        return Ok((false, epoch, instance));
                    }
                    tx.execute(
                        "INSERT INTO member (channel, account, role, joined, present)
                         VALUES (?1, ?2, ?3, ?4, 1)
                         ON CONFLICT (channel, account) DO UPDATE SET present = 1",
                        params![
                            &req.channel[..],
                            caller.as_bytes(),
                            Role::Admin as u8 as i64,
                            now as i64
                        ],
                    )
                    .map_err(storage("rejoin direct message"))?;
                    let place = Place {
                        exchange: self.exchange,
                        instance,
                        channel: req.channel,
                    };
                    let action = req.actions.first().ok_or(ChannelError::BadSignature)?;
                    write_system(
                        &tx, &place, &req.channel, EVENT_JOINED, caller, caller, device, &[],
                        action, now,
                    )?;
                    tx.commit().map_err(storage("commit rejoin"))?;
                    return Ok((false, epoch, instance));
                }
                // Somebody with no claim to this identifier is occupying it.
                // Discarding is safe because the claim is provable and
                // exclusive — only these two can produce it — and what goes is
                // only whatever the squatter put there.
                DmClaim::Squatted => destroy(&tx, &req.channel)?,
            }
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
        // An identity named in a `Create`'s invites list counts the same way,
        // or the quota would be one request away from meaningless. Checked
        // before anything is written, so a refusal leaves no half-channel.
        for i in &req.invites {
            if !blocked(&i.account, caller) && unspoken_full(&tx, &i.account)? {
                return Err(ChannelError::InviteQuota);
            }
        }

        // An instance this identifier has used before would re-admit every
        // entry signed under it, which is the whole reason the marker exists.
        // Only a direct message can reach here twice — a random identifier that
        // is destroyed is simply gone — so this set stays small.
        let reused: bool = tx
            .query_row(
                "SELECT 1 FROM retired_instance WHERE channel = ?1 AND instance = ?2",
                params![&req.channel[..], &req.instance[..]],
                |_| Ok(true),
            )
            .optional()
            .map_err(storage("read retired instances"))?
            .unwrap_or(false);
        if reused {
            return Err(ChannelError::UsedInstance);
        }
        tx.execute(
            "INSERT INTO retired_instance (channel, instance) VALUES (?1, ?2)",
            params![&req.channel[..], &req.instance[..]],
        )
        .map_err(storage("retire instance"))?;

        tx.execute(
            "INSERT INTO channel (id, visibility, retention_secs, max_entries, name, topic,
                                  epoch, next_seq, creator, created, empty_since, instance)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 1, ?7, ?8, NULL, ?9)",
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
                &req.instance[..],
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

        let place = Place {
            exchange: self.exchange,
            instance: req.instance,
            channel: req.channel,
        };
        for (n, i) in req.invites.iter().enumerate() {
            // A direct message created by somebody the other party has blocked
            // succeeds and simply does not add them, leaving a channel the
            // caller is alone in and may post into indefinitely. The action at
            // this position simply goes unused.
            if blocked(&i.account, caller) {
                continue;
            }
            let action = req.actions.get(n).ok_or(ChannelError::BadSignature)?;
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
            write_system(
                &tx, &place, &req.channel, EVENT_ADDED, &i.account, caller, device,
                &[i.role as u8], action, now,
            )?;
        }
        tx.commit().map_err(storage("commit create"))?;
        Ok((true, 0, req.instance))
    }

    /// Join a public channel. A private one MUST refuse, which is what stops an
    /// identifier being a way in.
    /// The public channel with this name, making it if it is not there.
    ///
    /// For the exchange's own use at boot, not for a caller: it takes a name
    /// rather than an identifier, which no route does, because the whole point
    /// is that nobody has to be told the identifier to find it.
    ///
    /// `founder` becomes its admin. Without one the channel still works —
    /// anybody may join, read and post — but nothing can rename it or set its
    /// topic, because SIP-16 puts those behind the admin role and there would
    /// be no admin. An exchange with `admins` configured has somebody to hand
    /// it to; one without does not, and a room nobody administers is better
    /// than no room.
    pub fn ensure_public(
        &self,
        name: &str,
        founder: Option<&PubKey>,
    ) -> Result<[u8; 32], ChannelError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin ensure_public"))?;

        // By name, because that is what an operator writes in a config file
        // and what a person types into `/find`. Public names are in the clear,
        // so this is a question the exchange can answer.
        let found: Option<Vec<u8>> = tx
            .query_row(
                "SELECT id FROM channel WHERE visibility = ?1 AND name = ?2
                 ORDER BY created ASC LIMIT 1",
                params![Visibility::Public as i64, name],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("look for the welcome channel"))?;
        if let Some(id) = found {
            let mut out = [0u8; 32];
            out.copy_from_slice(&id);
            return Ok(out);
        }

        let mut channel = [0u8; 32];
        {
            use rand::RngCore;
            rand::rng().fill_bytes(&mut channel);
        }
        tx.execute(
            "INSERT INTO channel
                (id, visibility, retention_secs, max_entries, name, topic,
                 epoch, next_seq, creator, created, epoch_at, instance)
             VALUES (?1, ?2, ?3, 0, ?4, '', 0, 1, ?5, ?6, 0, ?7)",
            params![
                &channel[..],
                Visibility::Public as i64,
                // Thirty days, as a direct message keeps, and inside SIP-16's
                // bounds. An admin can widen or narrow it with `/retain`.
                (30 * 24 * 60 * 60_i64),
                name,
                founder.map(|f| f.as_bytes().to_vec()).unwrap_or_default(),
                now as i64,
                // The identifier is already random and this channel is never
                // recreated under it, so the incarnation can be the identifier
                // itself — it only has to be unique per incarnation, and there
                // is exactly one.
                &channel[..],
            ],
        )
        .map_err(storage("create the welcome channel"))?;
        if let Some(founder) = founder {
            tx.execute(
                "INSERT INTO member (channel, account, role, joined, present)
                 VALUES (?1, ?2, 1, ?3, 1)",
                params![&channel[..], founder.as_bytes(), now as i64],
            )
            .map_err(storage("seat the founder"))?;
        }
        tx.commit().map_err(storage("commit ensure_public"))?;
        Ok(channel)
    }

    /// Put an account into `channel` the first time it is ever seen.
    ///
    /// Returns whether this was that first time. Once only, on purpose:
    /// leaving has to stick, and an exchange that put somebody back on their
    /// next request would be overruling them rather than welcoming them.
    pub fn welcome(&self, account: &PubKey, channel: &[u8; 32]) -> Result<bool, ChannelError> {
        {
            let db = self.db.lock().unwrap();
            let seen: Option<i64> = db
                .query_row(
                    "SELECT at FROM welcomed WHERE account = ?1",
                    params![account.as_bytes()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage("look up welcomed"))?;
            if seen.is_some() {
                return Ok(false);
            }
            db.execute(
                "INSERT OR IGNORE INTO welcomed (account, at) VALUES (?1, ?2)",
                params![account.as_bytes(), now_unix() as i64],
            )
            .map_err(storage("record welcomed"))?;
        }
        // Outside the lock above. Recorded first: a join that fails must not
        // leave this account to be welcomed again on its next request, which
        // would retry for ever.
        //
        // **The one membership change with no actor to sign it.** Every other
        // is caused by somebody who signs for it under SIP-31; this one is the
        // exchange putting a newcomer into its own front room, and the account
        // is not a party to it — it has issued no request and may not even have
        // a device registered yet. So the member row goes in without a system
        // entry, rather than the exchange writing an event nobody authorised or
        // signing one as though the account had. The cost is that a replica
        // sees membership of the welcome channel it cannot derive from the log,
        // and that is stated in SIP-31 rather than hidden here.
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin welcome"))?;
        if visibility_of(&tx, channel)? != Visibility::Public {
            return Err(ChannelError::NotPublic);
        }
        let (members, _) = counts(&tx, channel)?;
        if members as usize >= MAX_MEMBERS {
            return Err(ChannelError::Full);
        }
        tx.execute(
            "INSERT INTO member (channel, account, role, joined, present)
             VALUES (?1, ?2, 0, ?3, 1)
             ON CONFLICT (channel, account) DO UPDATE SET present = 1",
            params![&channel[..], account.as_bytes(), now_unix() as i64],
        )
        .map_err(storage("insert welcomed member"))?;
        tx.execute(
            "UPDATE channel SET empty_since = NULL WHERE id = ?1",
            params![&channel[..]],
        )
        .map_err(storage("clear empty_since"))?;
        tx.commit().map_err(storage("commit welcome"))?;
        self.wake(channel);
        Ok(true)
    }

    pub fn join(
        &self,
        caller: &PubKey,
        device: &PubKey,
        channel: &[u8; 32],
        action: &Action,
    ) -> Result<(), ChannelError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin join"))?;
        let visibility = visibility_of(&tx, channel)?;
        if visibility != Visibility::Public {
            return Err(ChannelError::NotPublic);
        }
        let (members, _) = counts(&tx, channel)?;
        let already = role_of(&tx, channel, caller).is_some();
        if !already && members as usize >= MAX_MEMBERS {
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
        if !already {
            let place = self.place(&tx, channel)?;
            write_system(
                &tx, &place, channel, EVENT_JOINED, caller, caller, device, &[], action, now,
            )?;
        }
        tx.execute(
            "UPDATE channel SET empty_since = NULL WHERE id = ?1",
            params![&channel[..]],
        )
        .map_err(storage("clear empty_since"))?;
        tx.commit().map_err(storage("commit join"))?;
        self.wake(channel);
        Ok(())
    }

    /// Leave. A private channel or direct message with no members left is
    /// destroyed; a public one persists, because it is a place rather than a
    /// conversation and is listed so somebody finds it later.
    pub fn leave(
        &self,
        caller: &PubKey,
        device: &PubKey,
        channel: &[u8; 32],
        action: &Action,
    ) -> Result<(), ChannelError> {
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

        let place = self.place(&tx, channel)?;
        write_system(
            &tx, &place, channel, EVENT_LEFT, caller, caller, device, &[], action, now,
        )?;
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
        self.wake(channel);
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

            // SIP-31. Verified here even though every receiver must verify it
            // too: SIP-19 leaves its authority rules to receivers *because the
            // exchange cannot check them*, and this one it can — the signature
            // and the device are both in the clear. Refusing here means no
            // entry is stored that every receiver would reject.
            let place = self.place(&tx, &req.channel)?;
            let terms = EntryTerms {
                place,
                account: *account,
                device: *device,
                epoch: req.epoch,
                msg_seq: req.msg_seq,
                expires_after: req.expires_after,
                chain_seq: req.chain_seq,
                prev: req.prev,
                body: &req.body,
            };
            if !verify_entry(&terms, &req.sig) {
                return Err(ChannelError::BadSignature);
            }
            advance_chain(
                &tx,
                &req.channel,
                device,
                req.chain_seq,
                &req.prev,
                &terms.input(),
            )?;
            let body_hash = Sha256::digest(&req.body);

            seq = next;
            tx.execute(
                "INSERT INTO entry (channel, seq, kind, account, device, posted,
                                    expires_after, epoch, msg_seq,
                                    chain_seq, prev, body_hash, sig, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
                    req.chain_seq as i64,
                    &req.prev[..],
                    &body_hash[..],
                    &req.sig[..],
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
            // Speaking here is what frees this membership from the invitation
            // quota, and it is one-way: leaving and being re-invited starts the
            // membership row over.
            tx.execute(
                "UPDATE member SET posted = 1 WHERE channel = ?1 AND account = ?2",
                params![&req.channel[..], account.as_bytes()],
            )
            .map_err(storage("mark spoken"))?;
            prune(&tx, &req.channel, now, self.max_channel_bytes)?;
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
                "SELECT seq, kind, account, device, posted, expires_after, epoch, msg_seq,
                        chain_seq, prev, body_hash, sig, body
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
                        chain_seq: r.get::<_, i64>(8)? as u64,
                        prev: r.get::<_, Vec<u8>>(9)?.try_into().unwrap_or(GENESIS),
                        body_hash: r.get::<_, Vec<u8>>(10)?.try_into().unwrap_or([0; 32]),
                        sig: r.get::<_, Vec<u8>>(11)?.try_into().unwrap_or([0; 64]),
                        body: r.get(12)?,
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
        // `delivered` is observed rather than asserted, and what is observed is
        // what was *handed over* — not `since`, which is only what the caller
        // says it already had. Recording it costs one integer and discloses
        // nothing the exchange did not just watch itself do.
        //
        // This once folded `since` in, which handed the caller its own delivery
        // receipt: a fetch naming a large `since` set the mark to it, the mark
        // is monotonic so it never came back down, and `read` is clamped to
        // `delivered` — so a client could then claim to have read entries that
        // do not exist. Nothing is recorded when nothing was returned; the
        // previous fetch that actually handed entries over already moved it.
        if let Some(delivered) = entries.last().map(|e| e.seq) {
            db.execute(
                "INSERT INTO cursor (channel, account, delivered) VALUES (?1, ?2, ?3)
                 ON CONFLICT (channel, account)
                 DO UPDATE SET delivered = MAX(delivered, excluded.delivered)",
                params![&channel[..], caller.as_bytes(), delivered as i64],
            )
            .map_err(storage("record delivery"))?;
        }

        Ok(Entries {
            now: now_unix(),
            first,
            last,
            entries,
            signals: self.take_signals(channel, caller),
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
    // Collected here rather than by the caller, and that is the fix for a leak
    // rather than a preference. Three of the four call sites remembered to
    // gather the attached blobs and collect them afterwards; `leave` did not,
    // so the last member walking out of a private channel orphaned its files
    // for good — rows in `blob` with no attachment and nothing that would ever
    // look at them again. A rule every caller must remember is a rule one of
    // them will not.
    let held = attached_blobs(db, channel)?;
    for sql in [
        "DELETE FROM entry WHERE channel = ?1",
        "DELETE FROM envelope WHERE channel = ?1",
        "DELETE FROM attachment WHERE channel = ?1",
        "DELETE FROM cursor WHERE channel = ?1",
        "DELETE FROM member WHERE channel = ?1",
        "DELETE FROM high_water WHERE channel = ?1",
        "DELETE FROM channel WHERE id = ?1",
    ] {
        db.execute(sql, params![&channel[..]])
            .map_err(storage("destroy channel"))?;
    }
    // A blob attached elsewhere survives; that is SIP-18's rule, and it is why
    // this is a collection rather than a delete.
    for blob in held {
        collect_blob(db, &blob)?;
    }
    Ok(())
}

/// Drop what the channel's policy says it should no longer hold: too old, or
/// too many. The per-message timer only ever shortens.
fn prune(
    db: &Connection,
    channel: &[u8; 32],
    now: u64,
    max_bytes: u64,
) -> Result<usize, ChannelError> {
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

    // And by stored bytes, which the entry count alone does not bound: 50 000
    // entries is nothing at a few hundred bytes each and 1.6 GiB at the 32 KiB
    // maximum. The running total is taken from the newest backwards, and
    // everything from the first entry that breaches the cap downwards goes —
    // the same oldest-first rule the count uses, for the same reason. A single
    // entry can never breach it on its own, since MAX_ENTRY_BODY is 32 KiB.
    gone += db
        .execute(
            "DELETE FROM entry WHERE channel = ?1 AND seq <= (
                 SELECT COALESCE(MAX(seq), 0) FROM (
                     SELECT seq,
                            SUM(length(body) + ?3) OVER (ORDER BY seq DESC) AS running
                     FROM entry WHERE channel = ?1)
                 WHERE running > ?2)",
            params![&channel[..], max_bytes as i64, ENTRY_HEADER as i64],
        )
        .map_err(storage("prune by bytes"))?;
    Ok(gone)
}

impl Channels {
    /// The channels an account belongs to, oldest membership first.
    ///
    /// The only route that answers "which channels am I in", and without it a
    /// private channel cannot be found at all: its identifier is 32 bytes, it
    /// is absent from the directory by construction, and every other operation
    /// takes that identifier as input. A direct message escapes that because
    /// its identifier derives from its two members; a group channel has no
    /// such derivation, so an invitation reached an account with no way to
    /// discover it had happened.
    ///
    /// Carries the epoch, the retained window and this account's read mark, so
    /// a client draws a channel list without a request per channel. It carries
    /// no name, and for a private channel there is none to carry: those are
    /// stored empty here and travel sealed (SIP-19).
    pub fn mine(&self, caller: &PubKey, offset: u32) -> Result<Mines, ChannelError> {
        let db = self.db.lock().unwrap();
        let total: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM member WHERE account = ?1 AND present = 1",
                params![caller.as_bytes()],
                |r| r.get(0),
            )
            .map_err(storage("count memberships"))?;

        let mut stmt = db
            .prepare(
                "SELECT m.channel, c.visibility, m.role, m.joined, c.epoch,
                        COALESCE(cu.read, 0)
                 FROM member m
                 JOIN channel c ON c.id = m.channel
                 LEFT JOIN cursor cu ON cu.channel = m.channel AND cu.account = m.account
                 WHERE m.account = ?1 AND m.present = 1
                 ORDER BY m.joined ASC, m.channel ASC
                 LIMIT ?2 OFFSET ?3",
            )
            .map_err(storage("prepare mine"))?;
        let rows = stmt
            .query_map(
                params![caller.as_bytes(), MAX_MINE as i64, offset as i64],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32]),
                        r.get::<_, i64>(1)? as u8,
                        r.get::<_, i64>(2)? as u8,
                        r.get::<_, i64>(3)? as u64,
                        r.get::<_, i64>(4)? as u32,
                        r.get::<_, i64>(5)? as u64,
                    ))
                },
            )
            .map_err(storage("query mine"))?;

        let mut channels = Vec::new();
        for row in rows {
            let (channel, visibility, role, joined, epoch, read) =
                row.map_err(storage("read membership"))?;
            // The window is per channel and cheap; it is what tells a client
            // whether it has a gap it can never fill.
            let (first, last) = window(&db, &channel);
            channels.push(Membership {
                channel,
                visibility: Visibility::from_u8(visibility).unwrap_or(Visibility::Private),
                role: Role::from_u8(role).unwrap_or(Role::Member),
                joined,
                epoch,
                first,
                last,
                read,
            });
        }
        Ok(Mines {
            now: now_unix(),
            total: total as u32,
            channels,
        })
    }

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

        // The chain the calling device stands at, so a client that lost its own
        // record resumes exactly. It must take the greater of this and what it
        // remembers — see SIP-31: an exchange that under-reported would induce
        // the device to sign twice at one position, and the fork would read as
        // the device's misconduct rather than the exchange's.
        let (next_chain, head) = chain_head(&db, channel, device)?;
        let place = self.place(&db, channel)?;

        Ok(ChannelInfo {
            visibility,
            epoch,
            instance: place.instance,
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
            my_chain_seq: next_chain,
            my_chain_head: head,
            now: now_unix(),
            members,
            name,
            topic,
        })
    }

    /// Change a channel's retention policy. Shortening applies to entries
    /// already stored and takes effect at the next prune, not only for new
    /// ones — so this prunes now.
    /// Rewrite a public channel's directory entry.
    ///
    /// Only `create` ever wrote it before, so a public channel renamed by its
    /// admin changed for everybody in the room and stayed advertised under its
    /// old name to everybody outside it — two names for one place, and the one
    /// strangers saw was the stale one.
    ///
    /// Public only. A private channel's name is deliberately never given to
    /// the exchange, because a membership graph with a name on it says
    /// considerably more than the graph; this refuses rather than stores.
    pub fn set_directory(
        &self,
        caller: &PubKey,
        req: &Directory,
    ) -> Result<(), ChannelError> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin set_directory"))?;
        if visibility_of(&tx, &req.channel)? != Visibility::Public {
            return Err(ChannelError::NotPublic);
        }
        if !is_admin(&tx, &req.channel, caller) {
            return Err(ChannelError::NotAnAdmin);
        }
        tx.execute(
            "UPDATE channel SET name = ?2, topic = ?3 WHERE id = ?1",
            params![
                &req.channel[..],
                req.name.chars().take(MAX_NAME).collect::<String>(),
                req.topic.chars().take(MAX_TOPIC).collect::<String>(),
            ],
        )
        .map_err(storage("update directory"))?;
        tx.commit().map_err(storage("commit set_directory"))?;
        Ok(())
    }

    pub fn retain(
        &self,
        caller: &PubKey,
        device: &PubKey,
        req: &Retain,
    ) -> Result<(), ChannelError> {
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
        let place = self.place(&tx, &req.channel)?;
        // The retention pair is what the caller is authorising, so it is what
        // the signature covers; a bare "somebody changed retention" would let a
        // signed request be replayed with different numbers.
        let mut arg = Vec::with_capacity(8);
        arg.extend_from_slice(&req.retention_secs.to_be_bytes());
        arg.extend_from_slice(&req.max_entries.to_be_bytes());
        write_system(
            &tx, &place, &req.channel, EVENT_RETENTION, caller, caller, device, &arg,
            &req.action, now,
        )?;
        prune(&tx, &req.channel, now, self.max_channel_bytes)?;
        tx.commit().map_err(storage("commit retain"))?;
        self.wake(&req.channel);
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
        // `destroy` collects the attachments; a blob attached elsewhere
        // survives, so closing one channel does not take a photograph out of
        // another.
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
                        (SELECT COALESCE(MAX(seq), 0) FROM entry e WHERE e.channel = c.id),
                        c.instance
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
                    // A joiner signs against this and cannot ask `Info`, which
                    // needs the membership they are trying to get.
                    instance: r.get::<_, Vec<u8>>(5)?.try_into().unwrap_or([0; 32]),
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

        let _ = expire_uploads(&tx, now);

        let (mut pruned, mut closed) = (0usize, 0usize);
        for id in ids {
            pruned += prune(&tx, &id, now, self.max_channel_bytes).unwrap_or(0);
            let _ = prune_attachments(&tx, &id, now);

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
        // Blobs nothing points at any more. `destroy` collects what it takes
        // apart, so this catches only what an older version leaked — and it
        // costs one indexed query per sweep to make an existing deployment
        // heal instead of carrying its leak forever.
        let _ = tx.execute(
            "DELETE FROM blob_chunk WHERE blob NOT IN (SELECT blob FROM attachment)",
            [],
        );
        let _ = tx.execute(
            "DELETE FROM blob WHERE id NOT IN (SELECT blob FROM attachment)",
            [],
        );
        let _ = tx.commit();
        (pruned, closed)
    }
}

/// SIP-16 membership changes and SIP-17 key distribution.
///
/// These are the operations a private channel needs and a public one never
/// uses: a public channel is joined rather than invited into, and seals
/// nothing, so it has no epoch and no envelopes.
impl Channels {
    /// Add an account to a channel. Admins only, and never on a direct
    /// message, where the membership can only ever be the two identities the
    /// channel is named after.
    #[allow(clippy::too_many_arguments)]
    pub fn invite(
        &self,
        caller: &PubKey,
        device: &PubKey,
        channel: &[u8; 32],
        account: &PubKey,
        role: Role,
        action: &Action,
        blocked: &dyn Fn(&PubKey, &PubKey) -> bool,
    ) -> Result<(), ChannelError> {
        let now = now_unix();
        // Silently dropped, and answered as though it landed. That is the
        // exchange saying something untrue on the blocker's behalf, which is
        // what a block is: a refusal the caller can detect tells a harasser
        // they have been blocked.
        if blocked(account, caller) {
            return Ok(());
        }
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin invite"))?;
        visibility_of(&tx, channel)?;
        if !is_admin(&tx, channel, caller) {
            return Err(ChannelError::NotAnAdmin);
        }
        if is_direct_message(&tx, channel)? {
            return Err(ChannelError::DirectMessage);
        }
        let (members, _) = counts(&tx, channel)?;
        let was = role_of(&tx, channel, account);
        if was.is_none() {
            if members as usize >= MAX_MEMBERS {
                return Err(ChannelError::Full);
            }
            // Refused, and refused distinguishably: a quota that dropped the
            // invitation silently would leave the admin believing it landed.
            // Changing an existing member's role is not an invitation and does
            // not consult this.
            if unspoken_full(&tx, account)? {
                return Err(ChannelError::InviteQuota);
            }
        }
        tx.execute(
            "INSERT INTO member (channel, account, role, joined, present)
             VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT (channel, account) DO UPDATE SET present = 1, role = ?3",
            params![
                &channel[..],
                account.as_bytes(),
                role as u8 as i64,
                now as i64
            ],
        )
        .map_err(storage("insert invitee"))?;
        // Inviting somebody already present is how a role changes, so the
        // record says which of the two happened.
        let event = match was {
            None => EVENT_ADDED,
            Some(had) if had == role => EVENT_ADDED,
            Some(_) if role == Role::Admin => EVENT_PROMOTED,
            Some(_) => EVENT_DEMOTED,
        };
        let place = self.place(&tx, channel)?;
        // The role travels in the signature, or a signed promotion could be
        // replayed as a demotion.
        write_system(
            &tx, &place, channel, event, account, caller, device, &[role as u8], action, now,
        )?;
        tx.execute(
            "UPDATE channel SET empty_since = NULL WHERE id = ?1",
            params![&channel[..]],
        )
        .map_err(storage("clear empty_since"))?;
        tx.commit().map_err(storage("commit invite"))?;
        self.wake(channel);
        Ok(())
    }

    /// Remove an account. A removal MUST be followed by a rotation, which the
    /// exchange cannot enforce and does not pretend to — it holds no key and
    /// cannot tell whether one changed.
    pub fn remove(
        &self,
        caller: &PubKey,
        device: &PubKey,
        channel: &[u8; 32],
        account: &PubKey,
        action: &Action,
    ) -> Result<(), ChannelError> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin remove"))?;
        visibility_of(&tx, channel)?;
        if !is_admin(&tx, channel, caller) {
            return Err(ChannelError::NotAnAdmin);
        }
        if is_direct_message(&tx, channel)? {
            return Err(ChannelError::DirectMessage);
        }
        let Some(their_role) = role_of(&tx, channel, account) else {
            return Err(ChannelError::NotAMember);
        };
        let (members, admins) = counts(&tx, channel)?;
        if their_role == Role::Admin && admins == 1 && members > 1 {
            return Err(ChannelError::LastAdmin);
        }
        tx.execute(
            "DELETE FROM member WHERE channel = ?1 AND account = ?2",
            params![&channel[..], account.as_bytes()],
        )
        .map_err(storage("delete member"))?;
        // Their envelopes go too. They keep whatever they already collected —
        // revocation is prospective everywhere in this design — but the
        // exchange stops handing them anything further.
        tx.execute(
            "DELETE FROM envelope WHERE channel = ?1 AND recipient = ?2",
            params![&channel[..], account.as_bytes()],
        )
        .map_err(storage("delete envelopes"))?;
        // The record of who did this is the whole reason system entries exist,
        // and is why an admin cannot redact one.
        let place = self.place(&tx, channel)?;
        write_system(
            &tx, &place, channel, EVENT_REMOVED, account, caller, device, &[], action,
            now_unix(),
        )?;
        tx.commit().map_err(storage("commit remove"))?;
        self.wake(channel);
        Ok(())
    }

    /// Publish envelopes for one epoch.
    ///
    /// `epoch` is the channel's current epoch — adding envelopes without
    /// rotating, which is how a member is handed the key already in use — or
    /// exactly one greater, which is a rotation and advances the channel.
    /// Store envelopes for an epoch.
    ///
    /// `account_of` resolves a **device** to the account it belongs to (SIP-22),
    /// because an envelope is addressed to a device while membership is held
    /// per account. Passed in rather than held, so this store keeps no
    /// dependency on the device registry — the same shape as `blocked` for
    /// SIP-21.
    pub fn put_keys(
        &self,
        caller: &PubKey,
        device: &PubKey,
        req: &KeyPut,
        account_of: &dyn Fn(&PubKey) -> PubKey,
        revoked_since: &dyn Fn(&PubKey, u64) -> bool,
    ) -> Result<PutAck, ChannelError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin put"))?;
        let (visibility, epoch, _, _) = channel_row(&tx, &req.channel)?;
        if visibility != Visibility::Private {
            // A public channel seals nothing, so there is no key to distribute.
            return Err(ChannelError::NotPrivate);
        }
        if role_of(&tx, &req.channel, caller).is_none() {
            return Err(ChannelError::NotAMember);
        }
        if req.epoch != epoch && req.epoch != epoch + 1 {
            return Err(ChannelError::WrongEpoch);
        }
        if req.epoch > MAX_EPOCH {
            return Err(ChannelError::WrongEpoch);
        }

        // An admin may publish to any member's devices. A plain member may
        // publish to the devices of its **own account** and no others — which
        // is SIP-17's same-account rule, and how a device linked after the fact
        // gets the epoch in force without an admin having to come back for it.
        let admin = is_admin(&tx, &req.channel, caller);

        // Ordinarily an admin's act — but not always. A member may rekey after
        // revoking one of its own devices, and without that the advice to
        // rotate after a revocation is advice nobody can follow: losing a phone
        // in a group where you are an ordinary member would leave you able to
        // revoke the device and unable to change the key, so whoever holds it
        // keeps reading every future message until an admin happens to act.
        //
        // It is not an escalation. They already hold the current key and can
        // already read everything; all they gain is stopping a key they know to
        // be compromised from continuing to work.
        let rekeying = !admin && req.epoch != epoch && {
            let minted: i64 = tx
                .query_row(
                    "SELECT epoch_at FROM channel WHERE id = ?1",
                    params![&req.channel[..]],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage("read epoch_at"))?
                .unwrap_or(0);
            revoked_since(caller, minted as u64)
        };

        // A plain member publishes only to the devices of its own account —
        // SIP-17's same-account rule. One rekeying is advancing the epoch for
        // everybody, so it must be able to seal to everybody: permitting the
        // rotation and not its envelopes would be no permission at all.
        if !admin
            && !rekeying
            && req
                .envelopes
                .iter()
                .any(|e| account_of(&e.recipient) != *caller)
        {
            return Err(ChannelError::NotAnAdmin);
        }
        if !admin && req.epoch != epoch && !rekeying {
            return Err(ChannelError::NotAnAdmin);
        }

        for e in &req.envelopes {
            if e.prekey_id == 0 {
                return Err(ChannelError::NoPrekey);
            }
            // The recipient is a device; membership is held per account.
            if role_of(&tx, &req.channel, &account_of(&e.recipient)).is_none() {
                return Err(ChannelError::NotAMember);
            }
            let taken: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM envelope WHERE channel = ?1 AND recipient = ?2 AND epoch = ?3",
                    params![&req.channel[..], e.recipient.as_bytes(), req.epoch as i64],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage("check envelope"))?;
            if taken.is_some() {
                // Somebody got there first. Not an error: the caller is told
                // which epoch stands and collects instead, which is what
                // settles the direct-message creation race.
                return Ok(PutAck {
                    accepted: false,
                    epoch,
                    now,
                });
            }
        }

        for e in &req.envelopes {
            tx.execute(
                "INSERT INTO envelope (channel, recipient, epoch, from_epoch, to_epoch,
                                       prekey_id, ephemeral, ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    &req.channel[..],
                    e.recipient.as_bytes(),
                    req.epoch as i64,
                    e.from_epoch as i64,
                    e.to_epoch as i64,
                    e.prekey_id as i64,
                    &e.ephemeral[..],
                    &e.ciphertext,
                ],
            )
            .map_err(storage("insert envelope"))?;
        }
        if req.epoch == epoch + 1 {
            tx.execute(
                "UPDATE channel SET epoch = ?2, epoch_at = ?3 WHERE id = ?1",
                params![&req.channel[..], req.epoch as i64, now as i64],
            )
            .map_err(storage("advance epoch"))?;
            let place = self.place(&tx, &req.channel)?;
            let action = req.action.as_ref().ok_or(ChannelError::BadSignature)?;
            write_system(
                &tx, &place, &req.channel, EVENT_ROTATED, caller, caller, device,
                &req.epoch.to_be_bytes(), action, now,
            )?;
        }
        tx.commit().map_err(storage("commit put"))?;
        Ok(PutAck {
            accepted: true,
            epoch: req.epoch,
            now,
        })
    }

    /// Collect the envelopes addressed to the caller. Served **only** to the
    /// recipient each names; the exchange stores them opaquely and holds no key
    /// that opens one.
    /// Collect the envelopes sealed to this **device**.
    ///
    /// Two identities, and they do different jobs: membership is checked
    /// against the `account`, and the envelopes are looked up by the `device`
    /// they were addressed to. An account with no registered devices is its own
    /// device, so the single-client case passes the same key twice.
    pub fn get_keys(
        &self,
        account: &PubKey,
        device: &PubKey,
        channel: &[u8; 32],
        since_epoch: u32,
    ) -> Result<Got, ChannelError> {
        let db = self.db.lock().unwrap();
        visibility_of(&db, channel)?;
        if role_of(&db, channel, account).is_none() {
            return Err(ChannelError::NotAMember);
        }
        let mut stmt = db
            .prepare(
                "SELECT from_epoch, to_epoch, prekey_id, ephemeral, ciphertext FROM envelope
                 WHERE channel = ?1 AND recipient = ?2 AND to_epoch >= ?3
                 ORDER BY epoch ASC",
            )
            .map_err(storage("prepare get"))?;
        let envelopes = stmt
            .query_map(
                params![&channel[..], device.as_bytes(), since_epoch as i64],
                |r| {
                    Ok(Envelope {
                        recipient: PubKey::new([0; 32]),
                        from_epoch: r.get::<_, i64>(0)? as u32,
                        to_epoch: r.get::<_, i64>(1)? as u32,
                        prekey_id: r.get::<_, i64>(2)? as u32,
                        ephemeral: r.get::<_, Vec<u8>>(3)?.try_into().unwrap_or([0; 32]),
                        ciphertext: r.get(4)?,
                    })
                },
            )
            .map_err(storage("query get"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage("read envelopes"))?;
        Ok(Got {
            now: now_unix(),
            envelopes,
        })
    }

    /// Who holds no envelope for the current epoch, and whether they could be
    /// sealed to at all.
    ///
    /// Without this a member can be stranded silently: they fetch entries
    /// successfully, open none of them, and look exactly like somebody who is
    /// not reading.
    /// Which devices hold no envelope for the epoch in force.
    ///
    /// **Devices, not accounts**, and the distinction is the whole value of the
    /// call: envelopes are addressed to devices, so asking whether an *account*
    /// has one reports every correctly-sealed member as stranded and never
    /// reports the device that actually is. This is the one diagnostic the
    /// design has for the failure that linking a client creates, and it was
    /// inverted by linking until this took `devices_of`.
    pub fn missing_keys(
        &self,
        caller: &PubKey,
        channel: &[u8; 32],
        devices_of: &dyn Fn(&PubKey) -> Vec<PubKey>,
        has_prekeys: &dyn Fn(&PubKey) -> bool,
    ) -> Result<Absent, ChannelError> {
        let db = self.db.lock().unwrap();
        let (_, epoch, _, _) = channel_row(&db, channel)?;
        let admin = is_admin(&db, channel, caller);
        if !admin && role_of(&db, channel, caller).is_none() {
            return Err(ChannelError::NotAMember);
        }
        let mut stmt = db
            .prepare(
                "SELECT account FROM member WHERE channel = ?1 AND present = 1
                 ORDER BY account ASC",
            )
            .map_err(storage("prepare missing"))?;
        let accounts: Vec<PubKey> = stmt
            .query_map(params![&channel[..]], |r| {
                Ok(PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])))
            })
            .map_err(storage("query missing"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage("read missing"))?;

        let mut sealed = db
            .prepare(
                "SELECT 1 FROM envelope WHERE channel = ?1 AND recipient = ?2 AND epoch = ?3",
            )
            .map_err(storage("prepare sealed"))?;

        let mut stranded = Vec::new();
        for account in accounts {
            // A member may ask only about its own account; an admin about all.
            if !admin && account != *caller {
                continue;
            }
            for device in devices_of(&account) {
                let has: Option<i64> = sealed
                    .query_row(
                        params![&channel[..], device.as_bytes(), epoch as i64],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(storage("check sealed"))?;
                if has.is_none() {
                    stranded.push(Stranded {
                        account,
                        device,
                        has_prekeys: has_prekeys(&device),
                    });
                }
            }
        }

        Ok(Absent {
            epoch,
            now: now_unix(),
            devices: stranded,
        })
    }
}

/// What a create by a non-member may claim about a direct-message identifier.
enum DmClaim {
    /// Not a direct message, or the caller cannot show it is one of its two.
    None,
    /// The caller is one of the two and everybody present is as well.
    Returning,
    /// The caller is one of the two and somebody else is sitting there.
    Squatted,
}

/// Test a caller's claim to a direct-message identifier.
///
/// The claim is provable and exclusive: to make it you must show that the
/// channel is the derivation over yourself and one other account, which nobody
/// but those two can do.
fn dm_claim(
    db: &Connection,
    channel: &[u8; 32],
    caller: &PubKey,
    invites: &[Invitee],
) -> Result<DmClaim, ChannelError> {
    if invites.len() != 1 {
        return Ok(DmClaim::None);
    }
    let other = invites[0].account;
    if direct_message_id(caller, &other) != *channel {
        return Ok(DmClaim::None);
    }
    let mut stmt = db
        .prepare("SELECT account FROM member WHERE channel = ?1")
        .map_err(storage("prepare dm claim"))?;
    let present: Vec<PubKey> = stmt
        .query_map(params![&channel[..]], |r| {
            Ok(PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])))
        })
        .map_err(storage("query dm claim"))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(if present.iter().all(|m| m == caller || m == &other) {
        DmClaim::Returning
    } else {
        DmClaim::Squatted
    })
}

fn attached_blobs(db: &Connection, channel: &[u8; 32]) -> Result<Vec<[u8; 32]>, ChannelError> {
    let mut stmt = db
        .prepare("SELECT blob FROM attachment WHERE channel = ?1")
        .map_err(storage("prepare attached blobs"))?;
    let rows = stmt
        .query_map(params![&channel[..]], |r| {
            Ok(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0u8; 32]))
        })
        .map_err(storage("query attached blobs"))?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

/// Whether two accounts are present in any channel together.
///
/// This is what a withheld profile turns on, and it is deliberately a
/// relationship the exchange already knows: a per-account visibility list would
/// be an address book at the exchange, a much larger disclosure than the
/// profile it protected.
///
/// `ignoring` is the welcome channel, and leaving it out is not a detail. A
/// room every account is put into on sight is shared by *everybody*, so
/// counting it would make every pair of accounts acquainted and a withheld
/// profile withheld from nobody — the flag would still be there, still be
/// settable, and mean nothing. Sharing a lobby is not evidence that two people
/// know each other, which is the whole of what this predicate is for.
impl Channels {
    pub fn share_a_channel(&self, a: &PubKey, b: &PubKey, ignoring: Option<&[u8; 32]>) -> bool {
        let db = self.db.lock().unwrap();
        let skip = ignoring.map(|c| c.to_vec()).unwrap_or_default();
        db.query_row(
            "SELECT 1 FROM member x JOIN member y ON x.channel = y.channel
             WHERE x.account = ?1 AND y.account = ?2 AND x.present = 1 AND y.present = 1
               AND x.channel != ?3
             LIMIT 1",
            params![a.as_bytes(), b.as_bytes(), skip],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten()
        .is_some()
    }

    /// Everybody present in a channel.
    ///
    /// Narrower than [`info`](Self::info) on purpose: a SIP-30 fan-out wants a
    /// list of recipients and nothing else, and `info` reads the window, the
    /// high-water mark, the name and the topic to produce one.
    ///
    /// It takes no caller and performs no authorization, because it *is* the
    /// authorization: what it returns is exactly the set of accounts entitled
    /// to be told that this channel changed. A caller that filtered this list
    /// further would be narrowing an answer that is already the right one; a
    /// caller that added to it would be leaking.
    pub fn members_of(&self, channel: &[u8; 32]) -> Vec<PubKey> {
        let db = self.db.lock().unwrap();
        let Ok(mut stmt) =
            db.prepare("SELECT account FROM member WHERE channel = ?1 AND present = 1")
        else {
            return Vec::new();
        };
        stmt.query_map(params![&channel[..]], |r| {
            Ok(PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])))
        })
        .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
        .unwrap_or_default()
    }

    /// Everybody who shares a channel with `account`, not counting them.
    ///
    /// This is the reach of a profile change: SIP-21 says a profile is for the
    /// people you are already in a room with, so it is also exactly who may be
    /// told that one changed. The caller still has to drop blocks in either
    /// direction — this module knows about membership and nothing about who is
    /// willing to hear from whom.
    pub fn peers_of(&self, account: &PubKey) -> Vec<PubKey> {
        let db = self.db.lock().unwrap();
        let Ok(mut stmt) = db.prepare(
            "SELECT DISTINCT y.account FROM member x JOIN member y ON x.channel = y.channel
             WHERE x.account = ?1 AND y.account != ?1 AND x.present = 1 AND y.present = 1",
        ) else {
            return Vec::new();
        };
        stmt.query_map(params![account.as_bytes()], |r| {
            Ok(PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])))
        })
        .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
        .unwrap_or_default()
    }
}

/// Whether a channel's identifier is the derivation over its two members.
///
/// Recomputed rather than recorded: a flag set at creation would have to be
/// right at creation, and a create whose invitation was dropped leaves a
/// one-member channel at a direct-message identifier. There is no state here to
/// get wrong.
fn is_direct_message(db: &Connection, channel: &[u8; 32]) -> Result<bool, ChannelError> {
    let mut stmt = db
        .prepare("SELECT account FROM member WHERE channel = ?1 ORDER BY account ASC")
        .map_err(storage("prepare dm check"))?;
    let members: Vec<PubKey> = stmt
        .query_map(params![&channel[..]], |r| {
            Ok(PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])))
        })
        .map_err(storage("query dm check"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(storage("read dm check"))?;
    Ok(members.len() == 2 && direct_message_id(&members[0], &members[1]) == *channel)
}

/// SIP-18 blob storage.
///
/// Chunks live in the same database as the channel log, which is a deliberate
/// choice and not the only reasonable one. Files on disk would be faster for
/// bytes this size and would keep the database small; one store gives atomic
/// deletion instead — a blob and its last attachment go in a single
/// transaction, and there is no window in which a row points at a file that is
/// no longer there or a file survives the row that named it. That matters more
/// here than throughput, because the lifetime rules are the hard part.
impl Channels {
    /// Reserve an upload against a channel's blob quota.
    pub fn begin_upload(
        &self,
        uploader: &PubKey,
        req: &BlobBegin,
    ) -> Result<u64, ChannelError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin upload"))?;
        visibility_of(&tx, &req.channel)?;
        if role_of(&tx, &req.channel, uploader).is_none() {
            return Err(ChannelError::NotAMember);
        }
        expire_uploads(&tx, now)?;

        let open: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM upload WHERE uploader = ?1",
                params![uploader.as_bytes()],
                |r| r.get(0),
            )
            .map_err(storage("count uploads"))?;
        if open as usize >= MAX_UPLOADS {
            return Err(ChannelError::TooManyUploads);
        }
        if channel_blob_bytes(&tx, &req.channel)? + req.size > MAX_CHANNEL_BLOB_BYTES {
            return Err(ChannelError::BlobQuota);
        }

        tx.execute(
            "INSERT INTO upload (channel, uploader, size, chunks, expires_after, started)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &req.channel[..],
                uploader.as_bytes(),
                req.size as i64,
                req.chunks as i64,
                req.expires_after as i64,
                now as i64,
            ],
        )
        .map_err(storage("insert upload"))?;
        let id = tx.last_insert_rowid() as u64;
        tx.commit().map_err(storage("commit begin"))?;
        Ok(id)
    }

    /// Write one chunk. Chunks may arrive in any order and a repeat overwrites,
    /// so a client that lost a response retries rather than starting again.
    pub fn put_chunk(
        &self,
        uploader: &PubKey,
        req: &BlobPut,
    ) -> Result<(), ChannelError> {
        let db = self.db.lock().unwrap();
        let (owner, chunks) = upload_row(&db, req.upload)?;
        if &owner != uploader {
            return Err(ChannelError::NotAMember);
        }
        if req.index >= chunks {
            return Err(ChannelError::BadChunk);
        }
        db.execute(
            "INSERT INTO upload_chunk (upload, idx, sealed) VALUES (?1, ?2, ?3)
             ON CONFLICT (upload, idx) DO UPDATE SET sealed = excluded.sealed",
            params![req.upload as i64, req.index as i64, &req.sealed],
        )
        .map_err(storage("insert chunk"))?;
        Ok(())
    }

    /// Assemble, verify the name, and store.
    ///
    /// The exchange hashes what it received and refuses a result that does not
    /// equal the claimed identifier — which is the whole reason the name is
    /// over the ciphertext rather than the plaintext. It cannot read a byte of
    /// this and can still tell it is being told the truth about it.
    pub fn commit_upload(
        &self,
        uploader: &PubKey,
        upload: u64,
        claimed: &[u8; 32],
    ) -> Result<bool, ChannelError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin commit"))?;
        let (owner, chunks) = upload_row(&tx, upload)?;
        if &owner != uploader {
            return Err(ChannelError::NotAMember);
        }
        let (channel, size, expires_after): ([u8; 32], u64, u32) = tx
            .query_row(
                "SELECT channel, size, expires_after FROM upload WHERE id = ?1",
                params![upload as i64],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32]),
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, i64>(2)? as u32,
                    ))
                },
            )
            .map_err(storage("read upload"))?;

        let mut sealed = Vec::with_capacity(chunks as usize);
        for i in 0..chunks {
            let got: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT sealed FROM upload_chunk WHERE upload = ?1 AND idx = ?2",
                    params![upload as i64, i as i64],
                    |r| r.get(0),
                )
                .optional()
                .map_err(storage("read chunk"))?;
            match got {
                Some(c) => sealed.push(c),
                // A missing chunk is refused the same way a wrong hash is: the
                // upload did not come to what it said it would.
                None => return Ok(false),
            }
        }
        if blob_id(&sealed) != *claimed {
            return Ok(false);
        }

        // A commit naming a blob already held stores no second copy. The
        // uploader cannot tell whether the bytes were already there, which is
        // bounded by their having needed the exact key to produce this name.
        tx.execute(
            "INSERT OR IGNORE INTO blob (id, size, chunks) VALUES (?1, ?2, ?3)",
            params![&claimed[..], size as i64, chunks as i64],
        )
        .map_err(storage("insert blob"))?;
        for (i, c) in sealed.iter().enumerate() {
            tx.execute(
                "INSERT OR IGNORE INTO blob_chunk (blob, idx, sealed) VALUES (?1, ?2, ?3)",
                params![&claimed[..], i as i64, c],
            )
            .map_err(storage("insert blob chunk"))?;
        }
        attach(&tx, &channel, claimed, uploader, expires_after, now)?;
        drop_upload(&tx, upload)?;
        tx.commit().map_err(storage("commit upload"))?;
        Ok(true)
    }

    pub fn abort_upload(&self, uploader: &PubKey, upload: u64) -> Result<(), ChannelError> {
        let db = self.db.lock().unwrap();
        let (owner, _) = upload_row(&db, upload)?;
        if &owner != uploader {
            return Err(ChannelError::NotAMember);
        }
        drop_upload(&db, upload)
    }

    /// Whether the caller may fetch a blob: a member of any channel it is
    /// attached to, or anybody at all if one of those channels is public.
    fn may_fetch(db: &Connection, who: &PubKey, blob: &[u8; 32]) -> Result<bool, ChannelError> {
        let mut stmt = db
            .prepare("SELECT channel FROM attachment WHERE blob = ?1")
            .map_err(storage("prepare fetch check"))?;
        let channels: Vec<[u8; 32]> = stmt
            .query_map(params![&blob[..]], |r| {
                Ok(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0u8; 32]))
            })
            .map_err(storage("query fetch check"))?
            .filter_map(|c| c.ok())
            .collect();
        for c in channels {
            if visibility_of(db, &c) == Ok(Visibility::Public) || role_of(db, &c, who).is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn head_blob(&self, who: &PubKey, blob: &[u8; 32]) -> Result<Headed, ChannelError> {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        if !Self::may_fetch(&db, who, blob)? {
            return Ok(Headed::none(now));
        }
        let row: Option<(u64, u32)> = db
            .query_row(
                "SELECT size, chunks FROM blob WHERE id = ?1",
                params![&blob[..]],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u32)),
            )
            .optional()
            .map_err(storage("read blob"))?;
        let attached: u64 = db
            .query_row(
                "SELECT COALESCE(MAX(attached), 0) FROM attachment WHERE blob = ?1",
                params![&blob[..]],
                |r| r.get::<_, i64>(0),
            )
            .map_err(storage("read attached"))? as u64;
        Ok(match row {
            Some((size, chunks)) => Headed {
                found: true,
                size,
                chunks,
                attached,
                now,
            },
            None => Headed::none(now),
        })
    }

    pub fn get_chunk(
        &self,
        who: &PubKey,
        blob: &[u8; 32],
        index: u32,
    ) -> Result<Chunk, ChannelError> {
        let db = self.db.lock().unwrap();
        if !Self::may_fetch(&db, who, blob)? {
            return Ok(Chunk::none(index));
        }
        let sealed: Option<Vec<u8>> = db
            .query_row(
                "SELECT sealed FROM blob_chunk WHERE blob = ?1 AND idx = ?2",
                params![&blob[..], index as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read blob chunk"))?;
        Ok(match sealed {
            Some(sealed) => Chunk {
                found: true,
                index,
                sealed,
            },
            None => Chunk::none(index),
        })
    }

    /// Attach an existing blob to a second channel. This is what a forward
    /// does: it costs the reference, not the file.
    pub fn attach_blob(
        &self,
        who: &PubKey,
        req: &ByChannelBlob,
    ) -> Result<(), ChannelError> {
        let now = now_unix();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin attach"))?;
        visibility_of(&tx, &req.channel)?;
        if role_of(&tx, &req.channel, who).is_none() {
            return Err(ChannelError::NotAMember);
        }
        if !Self::may_fetch(&tx, who, &req.blob)? {
            return Err(ChannelError::NoSuchBlob);
        }
        attach(&tx, &req.channel, &req.blob, who, req.expires_after, now)?;
        tx.commit().map_err(storage("commit attach"))?;
        Ok(())
    }

    /// Remove an attachment, deleting the blob if it was the last.
    ///
    /// This is what a client issues alongside a redaction: the exchange cannot
    /// read the reference, so it has no way to know a blob just lost its last
    /// mention, and only the redacting client does.
    pub fn detach_blob(
        &self,
        who: &PubKey,
        channel: &[u8; 32],
        blob: &[u8; 32],
    ) -> Result<(), ChannelError> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin detach"))?;
        visibility_of(&tx, channel)?;
        let uploader: Option<Vec<u8>> = tx
            .query_row(
                "SELECT uploader FROM attachment WHERE channel = ?1 AND blob = ?2",
                params![&channel[..], &blob[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read attachment"))?;
        let Some(uploader) = uploader else {
            return Err(ChannelError::NoSuchBlob);
        };
        if uploader != who.as_bytes() && !is_admin(&tx, channel, who) {
            return Err(ChannelError::NotAnAdmin);
        }
        tx.execute(
            "DELETE FROM attachment WHERE channel = ?1 AND blob = ?2",
            params![&channel[..], &blob[..]],
        )
        .map_err(storage("delete attachment"))?;
        collect_blob(&tx, blob)?;
        tx.commit().map_err(storage("commit detach"))?;
        Ok(())
    }
}

/// Write one of the exchange's own entries into the log.
///
/// It shares the channel's sequence space, so a client fetching a range gets
/// messages and events already interleaved, in the order they happened, with
/// nothing to merge. `account`, `device`, `msg_seq` and `expires_after` are all
/// zero: the exchange wrote it and no member did.
/// The chain position and head this device stands at in this channel.
///
/// Kept independently of the entries, so pruning cannot understate it — a
/// device resuming from an understated mark would fork its own chain.
fn chain_head(db: &Connection, channel: &[u8; 32], device: &PubKey) -> Result<(u64, [u8; 32]), ChannelError> {
    let row: Option<(i64, Vec<u8>)> = db
        .query_row(
            "SELECT chain_seq, head FROM chain WHERE channel = ?1 AND device = ?2",
            params![&channel[..], device.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(storage("read chain"))?;
    match row {
        None => Ok((0, GENESIS)),
        Some((seq, head)) => Ok((
            seq as u64 + 1,
            head.try_into().map_err(|_| ChannelError::Storage)?,
        )),
    }
}

/// Check a chain step and record it.
///
/// The position offered must be exactly the one expected and the link must be
/// the head held. Anything else is a fork or a gap, and neither may be written.
fn advance_chain(
    db: &Connection,
    channel: &[u8; 32],
    device: &PubKey,
    chain_seq: u64,
    prev: &[u8; 32],
    input: &[u8],
) -> Result<(), ChannelError> {
    let (expect_seq, expect_prev) = chain_head(db, channel, device)?;
    if chain_seq != expect_seq || prev != &expect_prev {
        return Err(ChannelError::BrokenChain);
    }
    db.execute(
        "INSERT INTO chain (channel, device, chain_seq, head) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (channel, device) DO UPDATE SET chain_seq = ?3, head = ?4",
        params![&channel[..], device.as_bytes(), chain_seq as i64, &link(input)[..]],
    )
    .map_err(storage("advance chain"))?;
    Ok(())
}

/// Verify a signed membership action, then take its chain step.
///
/// Returns the terms' signing input so the caller can store the link, and
/// refuses before anything is written — a system entry nobody authorised must
/// not reach the log even briefly.
#[allow(clippy::too_many_arguments)]
fn check_action(
    db: &Connection,
    place: &Place,
    actor: &PubKey,
    actor_device: &PubKey,
    event: u8,
    subject: &PubKey,
    arg: &[u8],
    action: &Action,
) -> Result<(), ChannelError> {
    let terms = ActionTerms {
        place: *place,
        actor: *actor,
        actor_device: *actor_device,
        event,
        subject: *subject,
        arg,
        chain_seq: action.chain_seq,
        prev: action.prev,
    };
    if !verify_action(&terms, &action.sig) {
        return Err(ChannelError::BadSignature);
    }
    let input = terms.input().map_err(|_| ChannelError::BadSignature)?;
    advance_chain(db, &place.channel, actor_device, action.chain_seq, &action.prev, &input)
}

#[allow(clippy::too_many_arguments)]
fn write_system(
    db: &Connection,
    place: &Place,
    channel: &[u8; 32],
    event: u8,
    subject: &PubKey,
    actor: &PubKey,
    actor_device: &PubKey,
    arg: &[u8],
    action: &Action,
    now: u64,
) -> Result<(), ChannelError> {
    check_action(db, place, actor, actor_device, event, subject, arg, action)?;
    let seq: u64 = db
        .query_row(
            "SELECT next_seq FROM channel WHERE id = ?1",
            params![&channel[..]],
            |r| r.get::<_, i64>(0),
        )
        .optional()
        .map_err(storage("read next_seq"))?
        .ok_or(ChannelError::NoSuchChannel)? as u64;

    let body = System {
        event,
        subject: *subject,
        actor: *actor,
        actor_device: *actor_device,
        chain_seq: action.chain_seq,
        prev: action.prev,
        sig: action.sig,
    }
    .encode();
    // The entry's own `sig` stays zero: the exchange wrote this row and did not
    // sign it. The actor's signature is inside the body, which is where a
    // verifier looks for a system entry — a different key in a different role.
    db.execute(
        "INSERT INTO entry (channel, seq, kind, account, device, posted,
                            expires_after, epoch, msg_seq,
                            chain_seq, prev, body_hash, sig, body)
         VALUES (?1, ?2, ?3, ?4, ?4, ?5, 0, 0, 0, 0, ?6, ?6, ?7, ?8)",
        params![
            &channel[..],
            seq as i64,
            KIND_SYSTEM as i64,
            &[0u8; 32][..],
            now as i64,
            &GENESIS[..],
            &[0u8; 64][..],
            &body,
        ],
    )
    .map_err(storage("insert system entry"))?;
    db.execute(
        "UPDATE channel SET next_seq = ?2, empty_since = NULL WHERE id = ?1",
        params![&channel[..], (seq + 1) as i64],
    )
    .map_err(storage("bump next_seq"))?;
    Ok(())
}

fn attach(
    db: &Connection,
    channel: &[u8; 32],
    blob: &[u8; 32],
    who: &PubKey,
    expires_after: u32,
    now: u64,
) -> Result<(), ChannelError> {
    // A blob attached to a new channel gains a fresh window, so without a cap
    // re-forwarding keeps it alive forever. Re-attaching where it already is
    // only refreshes the existing row and is not a new channel.
    let (here, elsewhere): (i64, i64) = db
        .query_row(
            "SELECT COUNT(*) FILTER (WHERE channel = ?2),
                    COUNT(*) FILTER (WHERE channel <> ?2)
             FROM attachment WHERE blob = ?1",
            params![&blob[..], &channel[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(storage("count attachments"))?;
    if here == 0 && elsewhere as usize >= MAX_BLOB_CHANNELS {
        return Err(ChannelError::BlobChannels);
    }
    db.execute(
        "INSERT INTO attachment (channel, blob, attached, expires_after, uploader)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (channel, blob) DO UPDATE SET attached = ?3, expires_after = ?4",
        params![
            &channel[..],
            &blob[..],
            now as i64,
            expires_after as i64,
            who.as_bytes()
        ],
    )
    .map_err(storage("insert attachment"))?;
    Ok(())
}

/// Delete a blob that has no attachments left. A blob attached elsewhere
/// survives; that is SIP-18's rule and it is why closing one channel does not
/// take a photograph out of another.
fn collect_blob(db: &Connection, blob: &[u8; 32]) -> Result<(), ChannelError> {
    let remaining: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM attachment WHERE blob = ?1",
            params![&blob[..]],
            |r| r.get(0),
        )
        .map_err(storage("count attachments"))?;
    if remaining == 0 {
        db.execute("DELETE FROM blob_chunk WHERE blob = ?1", params![&blob[..]])
            .map_err(storage("delete chunks"))?;
        db.execute("DELETE FROM blob WHERE id = ?1", params![&blob[..]])
            .map_err(storage("delete blob"))?;
    }
    Ok(())
}

/// Drop attachments past their window, and any blob that thereby has none.
///
/// The window is the shorter of the channel's retention and the attachment's
/// own timer, which is how a disappearing message's photograph goes when the
/// message does — without that, the entry would be pruned on schedule while the
/// image stayed fetchable for the rest of the channel's window, which is the
/// case people most want the feature for.
fn prune_attachments(db: &Connection, channel: &[u8; 32], now: u64) -> Result<(), ChannelError> {
    let orphans: Vec<[u8; 32]> = {
        let mut stmt = db
            .prepare(
                "SELECT blob FROM attachment WHERE channel = ?1 AND ?2 - attached >= CASE
                     WHEN expires_after > 0 AND expires_after < (
                         SELECT retention_secs FROM channel WHERE id = ?1)
                     THEN expires_after
                     ELSE (SELECT retention_secs FROM channel WHERE id = ?1) END",
            )
            .map_err(storage("prepare attachment prune"))?;
        let rows = stmt
            .query_map(params![&channel[..], now as i64], |r| {
                Ok(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0u8; 32]))
            })
            .map_err(storage("query attachment prune"))?;
        rows.filter_map(|r| r.ok()).collect()
    };
    for blob in orphans {
        db.execute(
            "DELETE FROM attachment WHERE channel = ?1 AND blob = ?2",
            params![&channel[..], &blob[..]],
        )
        .map_err(storage("delete attachment"))?;
        collect_blob(db, &blob)?;
    }
    Ok(())
}

fn channel_blob_bytes(db: &Connection, channel: &[u8; 32]) -> Result<u64, ChannelError> {
    let n: i64 = db
        .query_row(
            "SELECT COALESCE(SUM(b.size), 0) FROM attachment a
             JOIN blob b ON b.id = a.blob WHERE a.channel = ?1",
            params![&channel[..]],
            |r| r.get(0),
        )
        .map_err(storage("sum blob bytes"))?;
    Ok(n as u64)
}

fn upload_row(db: &Connection, upload: u64) -> Result<(PubKey, u32), ChannelError> {
    db.query_row(
        "SELECT uploader, chunks FROM upload WHERE id = ?1",
        params![upload as i64],
        |r| {
            Ok((
                PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                r.get::<_, i64>(1)? as u32,
            ))
        },
    )
    .optional()
    .map_err(storage("read upload"))?
    .ok_or(ChannelError::NoSuchUpload)
}

fn drop_upload(db: &Connection, upload: u64) -> Result<(), ChannelError> {
    db.execute(
        "DELETE FROM upload_chunk WHERE upload = ?1",
        params![upload as i64],
    )
    .map_err(storage("delete upload chunks"))?;
    db.execute("DELETE FROM upload WHERE id = ?1", params![upload as i64])
        .map_err(storage("delete upload"))?;
    Ok(())
}

fn expire_uploads(db: &Connection, now: u64) -> Result<(), ChannelError> {
    let stale: Vec<i64> = {
        let mut stmt = db
            .prepare("SELECT id FROM upload WHERE ?1 - started >= ?2")
            .map_err(storage("prepare upload expiry"))?;
        let rows = stmt
            .query_map(params![now as i64, UPLOAD_TTL as i64], |r| r.get(0))
            .map_err(storage("query upload expiry"))?;
        rows.filter_map(|r| r.ok()).collect()
    };
    for id in stale {
        drop_upload(db, id as u64)?;
    }
    Ok(())
}

/// SIP-16 receipts, redaction, and the relay that stores nothing.
impl Channels {
    /// Set the caller's read mark.
    ///
    /// Monotonic, and never past what was delivered: a client cannot claim to
    /// have read further than it collected.
    pub fn set_cursor(
        &self,
        caller: &PubKey,
        channel: &[u8; 32],
        read: u64,
        receipts: bool,
    ) -> Result<(), ChannelError> {
        let db = self.db.lock().unwrap();
        visibility_of(&db, channel)?;
        if role_of(&db, channel, caller).is_none() {
            return Err(ChannelError::NotAMember);
        }
        // The same rule on the way in. A row that does not exist yet belongs to
        // an account that has never fetched, so nothing has been delivered to
        // it and nothing can have been read — inserting the caller's claim into
        // `delivered` would let a read mark create the delivery it is clamped
        // against.
        //
        // The update clause names `?3` rather than `excluded.read` on purpose:
        // `excluded` is the row this statement *tried* to insert, which now
        // carries a deliberate zero, so reading the claim from there would pin
        // every read mark at nothing.
        db.execute(
            "INSERT INTO cursor (channel, account, delivered, read, receipts)
             VALUES (?1, ?2, 0, 0, ?4)
             ON CONFLICT (channel, account) DO UPDATE SET
                 read = MIN(MAX(read, ?3), delivered),
                 receipts = ?4",
            params![
                &channel[..],
                caller.as_bytes(),
                read as i64,
                i64::from(receipts)
            ],
        )
        .map_err(storage("set cursor"))?;
        Ok(())
    }

    /// Everyone's marks.
    ///
    /// A caller that has opted out of receipts is not shown anybody else's
    /// `read`. Delivery is never withheld, because the exchange observes it
    /// whether or not anyone asks and pretending otherwise would be theatre.
    pub fn cursors(&self, caller: &PubKey, channel: &[u8; 32]) -> Result<Marks, ChannelError> {
        let db = self.db.lock().unwrap();
        visibility_of(&db, channel)?;
        if role_of(&db, channel, caller).is_none() {
            return Err(ChannelError::NotAMember);
        }
        let mine: bool = db
            .query_row(
                "SELECT receipts FROM cursor WHERE channel = ?1 AND account = ?2",
                params![&channel[..], caller.as_bytes()],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(storage("read own receipts"))?
            .map(|r| r != 0)
            // A member that has never set a cursor has not opted out; the
            // default is on, as SIP-16 chose.
            .unwrap_or(true);

        let mut stmt = db
            .prepare(
                "SELECT m.account, COALESCE(c.delivered, 0), COALESCE(c.read, 0)
                 FROM member m
                 LEFT JOIN cursor c ON c.channel = m.channel AND c.account = m.account
                 WHERE m.channel = ?1 AND m.present = 1 ORDER BY m.account ASC",
            )
            .map_err(storage("prepare cursors"))?;
        let marks = stmt
            .query_map(params![&channel[..]], |r| {
                let account = PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32]));
                let read = r.get::<_, i64>(2)? as u64;
                Ok(Mark {
                    account,
                    delivered: r.get::<_, i64>(1)? as u64,
                    // Reciprocity, enforced here rather than left to a client
                    // that might simply not honour it.
                    read: if mine || account == *caller { read } else { 0 },
                })
            })
            .map_err(storage("query cursors"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(storage("read cursors"))?;

        Ok(Marks {
            now: now_unix(),
            marks,
        })
    }

    /// Remove an entry's body, keeping the entry as a tombstone.
    ///
    /// The gap is the record: a reader should be able to see that something was
    /// deleted rather than find a conversation that silently does not follow.
    /// That is the opposite of pruning, which leaves nothing, and the reason is
    /// that a shadow index of who spoke and when — long after the words are
    /// gone — would be a worse disclosure than the gap it filled.
    pub fn redact(
        &self,
        caller: &PubKey,
        channel: &[u8; 32],
        target: u64,
    ) -> Result<(), ChannelError> {
        let db = self.db.lock().unwrap();
        visibility_of(&db, channel)?;
        let row: Option<(Vec<u8>, i64)> = db
            .query_row(
                "SELECT account, kind FROM entry WHERE channel = ?1 AND seq = ?2",
                params![&channel[..], target as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage("read target"))?;
        let Some((author, kind)) = row else {
            return Err(ChannelError::NoSuchEntry);
        };
        // A system entry was written by the exchange and has no posting
        // account, so only the admin clause could reach it — which would let an
        // admin remove somebody and then delete the record saying they had. An
        // audit trail its subject can erase is not one.
        if kind as u8 == KIND_SYSTEM {
            return Err(ChannelError::SystemEntry);
        }
        if author != caller.as_bytes() && !is_admin(&db, channel, caller) {
            return Err(ChannelError::NotAnAdmin);
        }
        db.execute(
            // `sig`, `prev`, `chain_seq` and `body_hash` all survive. The
            // signature commits to the hash rather than to the bytes, so a
            // tombstone still verifies with its body gone and the device's
            // chain runs through it unbroken — which is the whole reason the
            // commitment is arranged that way. Clearing the signature here
            // would make every deleted message read as a forgery.
            "UPDATE entry SET body = x'' WHERE channel = ?1 AND seq = ?2",
            params![&channel[..], target as i64],
        )
        .map_err(storage("redact entry"))?;
        Ok(())
    }

    /// Relay a signal to the channel's other members.
    ///
    /// Never stored, never sequenced, never returned by a fetch by sequence
    /// number. Held only until collected, and dropped on a timer or when a
    /// recipient has more outstanding than it should.
    pub fn signal(
        &self,
        caller: &PubKey,
        channel: &[u8; 32],
        kind: u8,
        body: &[u8],
    ) -> Result<(), ChannelError> {
        let recipients: Vec<PubKey> = {
            let db = self.db.lock().unwrap();
            visibility_of(&db, channel)?;
            if role_of(&db, channel, caller).is_none() {
                return Err(ChannelError::NotAMember);
            }
            let mut stmt = db
                .prepare("SELECT account FROM member WHERE channel = ?1 AND present = 1")
                .map_err(storage("prepare signal recipients"))?;
            let rows = stmt
                .query_map(params![&channel[..]], |r| {
                    Ok(PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])))
                })
                .map_err(storage("query signal recipients"))?;
            rows.filter_map(|r| r.ok()).filter(|a| a != caller).collect()
        };

        let now = now_unix();
        let mut pending = self.signals.lock().unwrap();
        for who in recipients {
            let q = pending.entry((*channel, who)).or_default();
            q.retain(|(_, _, _, at)| now.saturating_sub(*at) < SIGNAL_TTL);
            while q.len() >= MAX_SIGNALS {
                q.remove(0);
            }
            q.push((*caller, kind, body.to_vec(), now));
        }
        drop(pending);
        self.wake(channel);
        Ok(())
    }

    /// Collect and discard whatever is waiting. Delivered at most once.
    fn take_signals(&self, channel: &[u8; 32], who: &PubKey) -> Vec<Signalled> {
        let now = now_unix();
        let mut pending = self.signals.lock().unwrap();
        let Some(q) = pending.remove(&(*channel, *who)) else {
            return Vec::new();
        };
        q.into_iter()
            .filter(|(_, _, _, at)| now.saturating_sub(*at) < SIGNAL_TTL)
            .map(|(account, kind, body, _)| Signalled {
                account,
                kind,
                body,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sqex_proto::channel::MAX_ENTRY_BODY;
    use sqex_proto::entry_sig::{sign_action, sign_entry};

    /// A key that can actually sign. It used to be `PubKey::new([b; 32])`, and
    /// could not be: SIP-31 needs a real keypair behind every identity in a
    /// test, or nothing here can produce a signature the exchange will take.
    /// The seed behind `key(1)`, which every test uses as its first identity.
    const ALICE: u8 = 1;
    /// The identity the quota test invites *to*.
    const VICTIM: u8 = 2;

    fn key(b: u8) -> PubKey {
        PubKey::new(SigningKey::from_bytes(&[b; 32]).verifying_key().to_bytes())
    }

    /// The exchange every test in this module runs against.
    fn exchange() -> PubKey {
        key(200)
    }

    fn open() -> Channels {
        Channels::open(None, exchange()).unwrap()
    }

    fn place_of(c: &Channels, channel: &[u8; 32]) -> Place {
        let db = c.db.lock().unwrap();
        c.place(&db, channel).unwrap()
    }

    /// A post signed as `b`'s device, taking the chain step the exchange is
    /// expecting. Tests that want a *bad* signature build one by hand.
    fn post_as(c: &Channels, b: u8, channel: &[u8; 32], epoch: u32, msg_seq: u64, body: Vec<u8>) -> Post {
        let who = key(b);
        let (place, chain_seq, prev) = {
            let db = c.db.lock().unwrap();
            let place = c.place(&db, channel).unwrap();
            let (n, p) = chain_head(&db, channel, &who).unwrap();
            (place, n, p)
        };
        let terms = EntryTerms {
            place,
            account: who,
            device: who,
            epoch,
            msg_seq,
            expires_after: 0,
            chain_seq,
            prev,
            body: &body,
        };
        Post {
            channel: *channel,
            epoch,
            msg_seq,
            expires_after: 0,
            chain_seq,
            prev,
            sig: sign_entry(&[b; 32], &terms),
            body,
        }
    }

    /// An action signed as `b`'s device, at the chain position expected next.
    fn action_as(c: &Channels, b: u8, place: &Place, event: u8, subject: &PubKey, arg: &[u8]) -> Action {
        let who = key(b);
        let (chain_seq, prev) = {
            let db = c.db.lock().unwrap();
            chain_head(&db, &place.channel, &who).unwrap()
        };
        let terms = ActionTerms {
            place: *place,
            actor: who,
            actor_device: who,
            event,
            subject: *subject,
            arg,
            chain_seq,
            prev,
        };
        Action { chain_seq, prev, sig: sign_action(&[b; 32], &terms).unwrap() }
    }

    /// An action for a channel that does not exist yet, signed against the
    /// instance the create proposes.
    fn create_action(b: u8, channel: &[u8; 32], instance: [u8; 32], n: u64, prev: [u8; 32], subject: &PubKey, role: Role) -> (Action, [u8; 32]) {
        let who = key(b);
        let terms = ActionTerms {
            place: Place { exchange: key(200), instance, channel: *channel },
            actor: who,
            actor_device: who,
            event: EVENT_ADDED,
            subject: *subject,
            arg: &[role as u8],
            chain_seq: n,
            prev,
        };
        let sig = sign_action(&[b; 32], &terms).unwrap();
        let head = link(&terms.input().unwrap());
        (Action { chain_seq: n, prev, sig }, head)
    }

    /// A create by `b`, with its invitees' `added` events signed.
    fn create_by(b: u8, channel: [u8; 32], instance: [u8; 32], visibility: Visibility, retention_secs: u32, invites: Vec<Invitee>) -> Create {
        let mut actions = Vec::new();
        let mut prev = GENESIS;
        for (n, i) in invites.iter().enumerate() {
            let (a, head) = create_action(b, &channel, instance, n as u64, prev, &i.account, i.role);
            prev = head;
            actions.push(a);
        }
        Create {
            channel,
            instance,
            visibility,
            retention_secs,
            max_entries: 0,
            name: String::new(),
            topic: String::new(),
            invites,
            actions,
        }
    }

    fn public_channel(retention_secs: u32) -> Create {
        create_by(1, [7; 32], [77; 32], Visibility::Public, retention_secs, Vec::new())
    }

    fn stored_bytes(c: &Channels) -> u64 {
        let db = c.db.lock().unwrap();
        db.query_row(
            "SELECT COALESCE(SUM(length(body)), 0) FROM entry WHERE channel = ?1",
            params![&[7u8; 32][..]],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as u64
    }

    /// SIP-16: "`delivered` is observed, not asserted. The exchange already
    /// learns each member's high-water mark from the `since` on every `Fetch`."
    ///
    /// But `since` is what the *caller* says it already has, not what the
    /// exchange handed over — and folding it into `delivered` lets a client
    /// name its own delivery receipt. The mark is monotonic, so an inflated one
    /// never comes back down, and `read` is then permitted up to it: a client
    /// can claim to have read messages that do not exist.
    #[test]
    fn delivered_is_observed_and_a_caller_cannot_assert_it() {
        let c = open();
        let alice = key(ALICE);
        c.create(&alice, &alice, &public_channel(MAX_RETENTION), &|_, _| false)
            .unwrap();

        // Nothing has ever been posted here, so nothing can have been
        // delivered to anybody.
        c.fetch(&alice, &[7; 32], 9_999).unwrap();

        let marks = c.cursors(&alice, &[7; 32]).unwrap();
        let mine = marks
            .marks
            .iter()
            .find(|m| m.account == alice)
            .expect("no mark for the caller");
        assert_eq!(
            mine.delivered, 0,
            "a caller's `since` became its own delivery receipt"
        );
    }

    /// The same rule on the other door. A read mark from an account that has
    /// never fetched must not create the delivery it is clamped against.
    #[test]
    fn a_read_mark_cannot_create_the_delivery_it_is_clamped_against() {
        let c = open();
        let alice = key(ALICE);
        c.create(&alice, &alice, &public_channel(MAX_RETENTION), &|_, _| false)
            .unwrap();

        c.set_cursor(&alice, &[7; 32], 500, true).unwrap();

        let marks = c.cursors(&alice, &[7; 32]).unwrap();
        let mine = marks
            .marks
            .iter()
            .find(|m| m.account == alice)
            .expect("no mark for the caller");
        assert_eq!(mine.delivered, 0, "a read mark asserted a delivery");
        assert_eq!(mine.read, 0, "read ran past what was delivered");
    }

    #[test]
    fn a_channel_is_pruned_to_its_byte_cap_oldest_first() {
        // Ten entries at 32 KiB and room for four. The entry count alone would
        // not bound this: 50 000 of them is 1.6 GiB.
        let cap = 4 * (MAX_ENTRY_BODY + ENTRY_HEADER) as u64;
        let c = open().with_max_channel_bytes(cap);
        let alice = key(1);
        c.create(&alice, &alice, &public_channel(MAX_RETENTION), &|_, _| false)
            .unwrap();

        for i in 0..10u8 {
            c.post(
                &alice,
                &alice,
                &post_as(&c, ALICE, &[7; 32], 0, i as u64, vec![i; MAX_ENTRY_BODY]),
            )
            .unwrap();
        }

        assert!(stored_bytes(&c) <= cap, "the cap is not enforced");
        let got = c.fetch(&alice, &[7; 32], 0).unwrap();
        let member: Vec<&Entry> = got.entries.iter().filter(|e| e.kind == KIND_MEMBER).collect();
        assert_eq!(member.len(), 4, "want the four newest kept");
        // Oldest first, exactly as the count prune does: what survives is the
        // tail, and the sequence numbers are not reissued.
        assert_eq!(member[0].body[0], 6);
        assert_eq!(member[3].body[0], 9);
    }

    #[test]
    fn the_byte_cap_does_not_bite_a_small_channel() {
        let c = open();
        let alice = key(1);
        c.create(&alice, &alice, &public_channel(MAX_RETENTION), &|_, _| false)
            .unwrap();
        for i in 0..20u8 {
            c.post(
                &alice,
                &alice,
                &post_as(&c, ALICE, &[7; 32], 0, i as u64, b"a short message".to_vec()),
            )
            .unwrap();
        }
        let got = c.fetch(&alice, &[7; 32], 0).unwrap();
        assert_eq!(got.entries.iter().filter(|e| e.kind == KIND_MEMBER).count(), 20);
    }

    fn channel_n(n: u8, visibility: Visibility) -> Create {
        create_by(ALICE, [n; 32], [n ^ 0x5a; 32], visibility, MAX_RETENTION, Vec::new())
    }

    #[test]
    fn a_stranger_cannot_add_someone_to_unbounded_channels() {
        let c = open();
        let spammer = key(1);
        let victim = key(2);

        // Fill the budget: MAX_UNSPOKEN channels the victim has been added to
        // and never spoken in.
        for n in 0..MAX_UNSPOKEN {
            let mut req = channel_n(n as u8, Visibility::Public);
            req.channel[31] = (n >> 8) as u8;
            c.create(&spammer, &spammer, &req, &|_, _| false).unwrap();
            c.invite(&spammer, &spammer, &req.channel, &victim, Role::Member, &action_as(&c, ALICE, &place_of(&c, &req.channel), EVENT_ADDED, &victim, &[Role::Member as u8]), &|_, _| false)
                .unwrap();
        }

        let one_more = channel_n(200, Visibility::Public);
        c.create(&spammer, &spammer, &one_more, &|_, _| false).unwrap();
        assert!(matches!(
            c.invite(&spammer, &spammer, &one_more.channel, &victim, Role::Member, &action_as(&c, ALICE, &place_of(&c, &one_more.channel), EVENT_ADDED, &victim, &[Role::Member as u8]), &|_, _| false),
            Err(ChannelError::InviteQuota)
        ));
        // Refused distinguishably, and not silently: 507, not a malformed
        // request and not a 200 the admin would read as success.
        assert_eq!(ChannelError::InviteQuota.status(), 507);

        // Named in a Create's invites list, the answer is the same — otherwise
        // the quota is one request away from meaningless.
        let mut with_invite = channel_n(201, Visibility::Private);
        with_invite.invites = vec![Invitee {
            account: victim,
            role: Role::Member,
        }];
        assert!(matches!(
            c.create(&spammer, &spammer, &with_invite, &|_, _| false),
            Err(ChannelError::InviteQuota)
        ));
    }

    #[test]
    fn speaking_in_one_channel_frees_the_budget_and_so_does_leaving() {
        let c = open();
        let spammer = key(1);
        let victim = key(2);
        for n in 0..MAX_UNSPOKEN {
            let mut req = channel_n(n as u8, Visibility::Public);
            req.channel[31] = (n >> 8) as u8;
            c.create(&spammer, &spammer, &req, &|_, _| false).unwrap();
            c.invite(&spammer, &spammer, &req.channel, &victim, Role::Member, &action_as(&c, ALICE, &place_of(&c, &req.channel), EVENT_ADDED, &victim, &[Role::Member as u8]), &|_, _| false)
                .unwrap();
        }
        let next = channel_n(200, Visibility::Public);
        c.create(&spammer, &spammer, &next, &|_, _| false).unwrap();
        assert!(c
            .invite(&spammer, &spammer, &next.channel, &victim, Role::Member, &action_as(&c, ALICE, &place_of(&c, &next.channel), EVENT_ADDED, &victim, &[Role::Member as u8]), &|_, _| false)
            .is_err());

        // Post in one of them.
        let mut spoken = [0u8; 32];
        spoken[31] = 0;
        c.post(
            &victim,
            &victim,
            &post_as(&c, VICTIM, &spoken, 0, 0, b"hello".to_vec()),
        )
        .unwrap();
        c.invite(&spammer, &spammer, &next.channel, &victim, Role::Member, &action_as(&c, ALICE, &place_of(&c, &next.channel), EVENT_ADDED, &victim, &[Role::Member as u8]), &|_, _| false)
            .expect("speaking in one frees the budget");

        // And leaving frees it too.
        let another = channel_n(202, Visibility::Public);
        c.create(&spammer, &spammer, &another, &|_, _| false).unwrap();
        assert!(c
            .invite(&spammer, &spammer, &another.channel, &victim, Role::Member, &action_as(&c, ALICE, &place_of(&c, &another.channel), EVENT_ADDED, &victim, &[Role::Member as u8]), &|_, _| false)
            .is_err());
        let mut quiet = [1u8; 32];
        quiet[31] = 0;
        c.leave(&victim, &victim, &quiet, &action_as(&c, VICTIM, &place_of(&c, &quiet), EVENT_LEFT, &victim, &[])).unwrap();
        c.invite(&spammer, &spammer, &another.channel, &victim, Role::Member, &action_as(&c, ALICE, &place_of(&c, &another.channel), EVENT_ADDED, &victim, &[Role::Member as u8]), &|_, _| false)
            .expect("leaving frees the budget");
    }

    #[test]
    fn changing_an_existing_members_role_is_not_an_invitation() {
        let c = open();
        let admin = key(1);
        let member = key(2);
        let home = channel_n(9, Visibility::Private);
        c.create(&admin, &admin, &home, &|_, _| false).unwrap();
        c.invite(&admin, &admin, &home.channel, &member, Role::Member, &action_as(&c, ALICE, &place_of(&c, &home.channel), EVENT_ADDED, &member, &[Role::Member as u8]), &|_, _| false)
            .unwrap();
        // Fill the rest of the budget elsewhere.
        for n in 0..(MAX_UNSPOKEN - 1) {
            let mut req = channel_n(n as u8, Visibility::Public);
            req.channel[31] = (n >> 8) as u8;
            req.channel[30] = 0xaa;
            c.create(&admin, &admin, &req, &|_, _| false).unwrap();
            c.invite(&admin, &admin, &req.channel, &member, Role::Member, &action_as(&c, ALICE, &place_of(&c, &req.channel), EVENT_ADDED, &member, &[Role::Member as u8]), &|_, _| false)
                .unwrap();
        }
        // Promoting them where they already are must not be refused.
        // Signed as a *promotion*, because that is the event the exchange will
        // write — inviting somebody already present changes their role. A
        // signature naming `added` is refused here, which is the event binding
        // doing its job rather than a quirk of the test.
        c.invite(
            &admin,
            &admin,
            &home.channel,
            &member,
            Role::Admin,
            &action_as(&c, ALICE, &place_of(&c, &home.channel), EVENT_PROMOTED, &member, &[Role::Admin as u8]),
            &|_, _| false,
        )
        .expect("a promotion is not an invitation");
    }

    fn channel_id(n: usize) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0xb1;
        id[1] = n as u8;
        id[2] = (n >> 8) as u8;
        id
    }

    #[test]
    fn a_blob_cannot_be_forwarded_into_unbounded_channels() {
        let c = open();
        let alice = key(1);
        let blob = [0xcc; 32];

        for n in 0..=MAX_BLOB_CHANNELS {
            let mut req = channel_n(0, Visibility::Public);
            req.channel = channel_id(n);
            c.create(&alice, &alice, &req, &|_, _| false).unwrap();
        }
        // A blob already in the first channel, which is what makes alice able
        // to fetch it and therefore able to forward it.
        {
            let db = c.db.lock().unwrap();
            db.execute(
                "INSERT INTO blob (id, size, chunks) VALUES (?1, 10, 1)",
                params![&blob[..]],
            )
            .unwrap();
            attach(&db, &channel_id(0), &blob, &alice, 0, now_unix()).unwrap();
        }

        // Forwarding costs the reference and not the file — but each new
        // attachment gets its own window, so without the cap re-forwarding
        // keeps a blob alive forever.
        for n in 1..MAX_BLOB_CHANNELS {
            c.attach_blob(
                &alice,
                &ByChannelBlob {
                    channel: channel_id(n),
                    blob,
                    expires_after: 0,
                },
            )
            .unwrap();
        }
        assert!(matches!(
            c.attach_blob(
                &alice,
                &ByChannelBlob {
                    channel: channel_id(MAX_BLOB_CHANNELS),
                    blob,
                    expires_after: 0,
                },
            ),
            Err(ChannelError::BlobChannels)
        ));
        assert_eq!(ChannelError::BlobChannels.status(), 507);

        // Re-attaching where it already is refreshes the window and is not a
        // new channel, so it is not refused at the cap.
        c.attach_blob(
            &alice,
            &ByChannelBlob {
                channel: channel_id(0),
                blob,
                expires_after: 0,
            },
        )
        .expect("a refresh is not a new attachment");
    }
}
