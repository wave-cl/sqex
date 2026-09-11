//! The client's memory.
//!
//! Everything a chat client knows that the exchange does not, and mostly
//! cannot: the epoch keys it has opened, the prekey secrets it has published,
//! the message counters it must never reuse, and the entries it has already
//! seen.
//!
//! # Why this has to exist
//!
//! SIP-17 says it in one line — *"a client that has read an envelope keeps its
//! own copy of the keys; the exchange's copy is for collection, not for
//! storage"*. An epoch key arrives sealed against a **one-time** prekey, and
//! opening it spends that prekey. Ask the exchange for the same envelope
//! tomorrow and it will hand over the same bytes, and they will not open,
//! because the secret that opened them is gone. That is the forward secrecy
//! working exactly as designed, and it means the only copy of a channel key
//! that will exist tomorrow is the one written here today.
//!
//! So losing this database loses the conversation. That is correct rather than
//! a bug, and a client must say so plainly instead of showing an empty room.
//!
//! # What is sealed, and what is not
//!
//! Secrets are sealed per row rather than by encrypting the whole file. That
//! avoids taking on SQLCipher, and it leaves the schema legible — you can look
//! at this database and see how many keys are held and for which channels,
//! without any key material being in it.
//!
//! The store key derives from the identity seed, so there is no second
//! passphrase. The consequence is stated where it bites: a YubiKey identity
//! never releases its seed and therefore cannot use this at all, which is the
//! same reason `sqex mail` and `sqex session` refuse one.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha512};
use sqex_proto::channel::KIND_MEMBER;
use sqex_proto::channel_key::{ChannelKey, Replay};
use sqex_proto::entry_sig::GENESIS;
use sqex_proto::prekey::{KIND_FALLBACK, KIND_ONE_TIME, Pool, PoolState};
use sqnr_core::PubKey;

/// Domain separator for the at-rest key. Distinct from every wire context in
/// `sqex-proto`, because this key protects a file and none of them do.
const STORE_CONTEXT: &[u8] = b"sqex-chat-store-v1";

const SCHEMA: &str = r#"
-- Who we can talk to, and therefore who we can hear from. A direct message's
-- identifier derives from the two accounts, so this list is the whole of
-- discovery: the exchange has no route that answers "which channels am I in".
CREATE TABLE IF NOT EXISTS contact (
    account BLOB PRIMARY KEY,
    label   TEXT NOT NULL,
    added   INTEGER NOT NULL
);
-- The keys, sealed. Nothing else in this file needs protecting; these are the
-- conversation.
CREATE TABLE IF NOT EXISTS channel_key (
    exchange BLOB   NOT NULL,
    channel BLOB    NOT NULL,
    epoch   INTEGER NOT NULL,
    sealed  BLOB    NOT NULL,
    PRIMARY KEY (exchange, channel, epoch)
);
-- SIP-23's pool, made durable. `spent` is as load-bearing as the secret: a
-- restart that forgot it would forgive a replay this client had already caught.
-- One pool per exchange. SIP-23's whole value is that a prekey is served
-- once and destroyed on use; publishing one pool to two exchanges has each of
-- them serving "the same" one-time key to a different sender, and the
-- recipient's duplicate check -- SIP-23's own defence -- then fires on a
-- condition that has become normal.
CREATE TABLE IF NOT EXISTS prekey (
    exchange BLOB NOT NULL,
    id     INTEGER NOT NULL,
    kind   INTEGER NOT NULL,
    sealed BLOB,
    spent  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (exchange, id)
);
-- The conversation itself, decrypted once and kept.
--
-- Not a cache. SIP-17 forbids decrypting a counter twice, and the exchange
-- serves an epoch key's envelope only once, so a message this client does not
-- keep is one it can never read again — the entry stays on the exchange and
-- stays shut. Sealed at rest like the keys, because this is the plaintext.
CREATE TABLE IF NOT EXISTS message (
    exchange BLOB   NOT NULL,
    channel BLOB    NOT NULL,
    seq     INTEGER NOT NULL,
    account BLOB    NOT NULL,
    posted  INTEGER NOT NULL,
    kind    INTEGER NOT NULL,
    sealed  BLOB,
    PRIMARY KEY (exchange, channel, seq)
);
-- Note for whoever adds a column here next: this store is on people's
-- machines, so `CREATE TABLE IF NOT EXISTS` is no longer enough. It creates
-- tables and never alters one that already exists, so a new column needs an
-- explicit ALTER guarded by PRAGMA table_info. A new table is still free.
--
-- What we know about a channel between runs.
--
-- `admins` is here because `Timeline` needs it to judge a redaction or a
-- metadata change, and a client that started offline would otherwise fold its
-- own history wrongly — showing an admin's redaction as still-visible, and a
-- channel with no name. `label` is the name from that sealed metadata, or a
-- peer's name for a direct message.
CREATE TABLE IF NOT EXISTS channel_meta (
    exchange BLOB NOT NULL,
    channel BLOB NOT NULL,
    -- 0 direct message, 1 group of unrecorded kind, 2 private group,
    -- 3 public channel. See `Kind` for why 1 still exists and must.
    kind    INTEGER NOT NULL DEFAULT 0,
    label   TEXT    NOT NULL DEFAULT '',
    admins  BLOB    NOT NULL DEFAULT x'', -- concatenated 32-byte accounts
    PRIMARY KEY (exchange, channel)
);
-- SIP-17's replay set. Not secret — it is a list of counters the exchange
-- already published in entry headers — so it is stored in the clear.
CREATE TABLE IF NOT EXISTS seen (
    exchange BLOB   NOT NULL,
    channel BLOB    NOT NULL,
    device  BLOB    NOT NULL,
    epoch   INTEGER NOT NULL,
    msg_seq INTEGER NOT NULL,
    PRIMARY KEY (exchange, channel, device, epoch, msg_seq)
);
-- How far we have read, and how far we have counted.
CREATE TABLE IF NOT EXISTS cursor (
    exchange BLOB NOT NULL,
    channel  BLOB NOT NULL,
    since    INTEGER NOT NULL DEFAULT 0,
    msg_seq  INTEGER NOT NULL DEFAULT 0,
    epoch    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (exchange, channel)
);
-- SIP-31 chain state: where this device stands in each channel.
--
-- Ours to keep, and the reason we keep it rather than asking is in SIP-31: a
-- client that took the exchange's reported position on trust could be told a
-- lower one, sign a second entry at a position it had already used, and produce
-- a fork that reads as its own misconduct. We resume from the greater of this
-- and what we are told.
CREATE TABLE IF NOT EXISTS chain (
    exchange  BLOB NOT NULL,
    channel   BLOB NOT NULL,
    chain_seq INTEGER NOT NULL,
    head      BLOB    NOT NULL,
    PRIMARY KEY (exchange, channel)
);
-- SIP-32: which incarnation of a channel our state belongs to.
--
-- A direct message's identifier is derived from its two accounts, so it
-- survives the channel being destroyed and rebuilt — and everything keyed on it
-- then belongs to a conversation that no longer exists. SIP-16 infers this from
-- a cursor above the exchange's last sequence number, which works and only once
-- something has been fetched. The incarnation says so outright, and says it
-- before the first thing we sign.
CREATE TABLE IF NOT EXISTS incarnation (
    exchange BLOB NOT NULL,
    channel  BLOB NOT NULL,
    instance BLOB NOT NULL,
    -- Set when the incarnation changed under us and we cleared this channel,
    -- and cleared when a poll has reported it. Durable, because a client that
    -- reset and then stopped should still say so when it comes back: the reset
    -- is the whole reason the conversation above the divider is not the one
    -- below it.
    announce INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (exchange, channel)
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
-- SIP-21 profiles, cached. Every field here is a claim its subject makes about
-- itself, which is why `account` is the primary key and the name is not
-- indexed: nothing in this client may ever look somebody up by the name they
-- chose. `fetched` is kept so a stale claim can be refreshed without asking
-- the exchange about everybody on every poll.
--
-- Not sealed. A display name is published to anybody who shares a channel with
-- its subject, so it is not a secret, and the rows that are secret are sealed
-- for a reason this one does not share.
CREATE TABLE IF NOT EXISTS profile (
    exchange BLOB NOT NULL,
    account BLOB NOT NULL,
    name    TEXT    NOT NULL DEFAULT '',
    title   TEXT    NOT NULL DEFAULT '',
    fetched INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (exchange, account)
);
-- SIP-38 handles, cached. The exchange's reverse-lookup of an account's names;
-- `name` is the bare local part (the domain is the connected exchange's, added
-- at display). A hint shown to a human and never used to look anyone up — the
-- account key is the identity, and a handle is the exchange's word, leased and
-- reclaimable. Empty = asked and told nothing, like `profile`.
CREATE TABLE IF NOT EXISTS handle (
    exchange BLOB NOT NULL,
    account BLOB NOT NULL,
    name    TEXT    NOT NULL DEFAULT '',
    fetched INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (exchange, account)
);
-- Attachments fetched once and kept, **as the exchange served them**: the
-- sealed chunks, framed, under the attachment's own key, which lives in the
-- sealed message that named it. Not re-encrypted here -- there is nothing in
-- the clear to protect, and the id is the hash of exactly these bytes, so a
-- row that has rotted is caught on the way out rather than decrypted into
-- rubbish. See `Store::blob`.
--
-- `used` is when it was last read, and is what eviction goes by: a picture
-- somebody keeps coming back to stays, whatever its age.
CREATE TABLE IF NOT EXISTS blob (
    exchange BLOB NOT NULL,
    blob    BLOB    NOT NULL,
    sealed  BLOB    NOT NULL,
    bytes   INTEGER NOT NULL,
    used    INTEGER NOT NULL,
    PRIMARY KEY (exchange, blob)
);
"#;

/// How much of the disc fetched attachments may hold, per store.
///
/// A store is one account, so this is what one account's pictures cost the
/// machine. A quarter of a gigabyte is a few hundred photographs at the size
/// a client fetches unasked, which is far more than anybody is scrolling
/// through and far less than a disc will notice.
pub const BLOB_BUDGET: u64 = 256 * 1024 * 1024;

/// The largest attachment kept. Anything bigger was a download somebody asked
/// for -- a file to save -- and would evict everything else to stay.
pub const BLOB_KEEP_MAX: u64 = 16 * 1024 * 1024;

/// What the store knows about one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channel {
    pub channel: [u8; 32],
    /// More than two people.
    pub group: bool,
    /// Whether anybody may join it, and so whether anything in it is
    /// encrypted.
    ///
    /// **`None` means this store does not know**, and is not the same as
    /// `Some(false)`. A row written before the distinction was recorded says
    /// only "a group", and a client that read that as private would be telling
    /// somebody their words are sealed when they may be in the clear. So the
    /// answer is withheld until the exchange gives one.
    pub public: Option<bool>,
    pub label: String,
    pub admins: Vec<PubKey>,
}

/// The `kind` column, which is an integer and now carries two facts.
///
/// # Why a fourth value rather than a fifth column
///
/// The column recorded group-or-not. Nothing recorded whether a group was
/// public, so a client restoring its own list from disk could not tell a
/// private group from a public channel, and had to draw neither until the
/// exchange answered -- a visible wait on every start, for a fact that never
/// changes.
///
/// A new column would need a migration, and `channel_meta`'s migration is a
/// whole-table rebuild inside a transaction. This needs none: the column is
/// already an `INTEGER`, and every client that has ever read it reads
/// **`kind != 0`** to mean "a group". So 2 and 3 arrive at an old client as
/// groups, which is exactly what they are, and it keeps working.
///
/// The other direction is why [`Kind::Group`] must stay. A row already on disk
/// says 1, and 1 is *ambiguous* -- it was written when nobody was recording
/// the difference. It must not be read as "private": that is the claim that
/// would be a lie. It stays unknown until the exchange says, and the next
/// write records the answer, so a store heals itself one sweep after upgrading
/// and never guesses in the meantime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A direct message. Two people, and never public.
    Direct,
    /// A group, written before anybody recorded whether it was public.
    Group,
    /// A group that is not public.
    Private,
    /// A channel anybody may join, whose contents are in the clear.
    Public,
}

impl Kind {
    fn of(group: bool, public: Option<bool>) -> Self {
        match (group, public) {
            (false, _) => Kind::Direct,
            (true, None) => Kind::Group,
            (true, Some(false)) => Kind::Private,
            (true, Some(true)) => Kind::Public,
        }
    }

    /// Anything unrecognised is a group of unknown kind, which is the answer
    /// that claims least: a value from a newer client than this one is
    /// certainly not a direct message, and might be either sort of group.
    fn from_i64(n: i64) -> Self {
        match n {
            0 => Kind::Direct,
            2 => Kind::Private,
            3 => Kind::Public,
            _ => Kind::Group,
        }
    }

    fn as_i64(self) -> i64 {
        match self {
            Kind::Direct => 0,
            Kind::Group => 1,
            Kind::Private => 2,
            Kind::Public => 3,
        }
    }

    fn group(self) -> bool {
        self != Kind::Direct
    }

    fn public(self) -> Option<bool> {
        match self {
            // A direct message has two members and cannot be joined, so this
            // one is known rather than assumed.
            Kind::Direct | Kind::Private => Some(false),
            Kind::Public => Some(true),
            Kind::Group => None,
        }
    }
}

pub struct Store {
    db: Connection,
    cipher: ChaCha20Poly1305,
    /// Every scoped row this store reads and writes belongs to this.
    ///
    /// `None` until [`Store::scope_to`] is called.
    ///
    /// A channel identifier is **not** unique across exchanges: a direct
    /// message's is derived from its two accounts, so one conversation has
    /// identical channel bytes everywhere it exists. Without this column, two
    /// exchanges' rows for one conversation would share a primary key — which
    /// is not a merge but a collision, and under SIP-17 a reused counter costs
    /// the confidentiality of two messages.
    exchange: Option<PubKey>,
}

/// Grow an older store to carry an exchange on every row that needs one.
///
/// # Why this is a rebuild and not an `ALTER`
///
/// The column has to be part of the **primary key**, and SQLite cannot alter
/// one. So each table is recreated, copied into, and renamed over — all five
/// inside a single transaction, so the migration either lands whole or not at
/// all. There is no half-migrated state to recover from, which matters more
/// here than anywhere else in this codebase: an epoch key arrives sealed
/// against a one-time prekey, opening it spends the prekey, and the row in
/// this file is the only copy that will ever exist.
///
/// # Why existing rows are not attributed
///
/// **This store never recorded which exchange a row came from.** It records
/// the account and nothing else, so the migration cannot know, and guessing
/// would be the one mistake that cannot be undone: a channel key filed under
/// the wrong exchange is a conversation that will not open again.
///
/// So nothing is guessed. Rows are marked [`Store::UNCLAIMED`] and stay that
/// way until an exchange claims them — see [`claim`].
fn migrate(db: &Connection) -> Result<()> {
    let already: bool = db
        .prepare("SELECT 1 FROM pragma_table_info('channel_key') WHERE name = 'exchange'")
        .and_then(|mut s| s.exists([]))
        .map_err(storage("inspect the store's shape"))?;
    // A store that has no `channel_key` table at all is a new one, and the
    // schema will create it in the right shape a moment from now.
    let fresh: bool = !db
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='channel_key'")
        .and_then(|mut s| s.exists([]))
        .map_err(storage("inspect the store's shape"))?;
    if already || fresh {
        return Ok(());
    }

    let zero = &Store::UNCLAIMED[..];
    db.execute_batch("BEGIN IMMEDIATE")
        .map_err(storage("begin the migration"))?;
    let outcome = rebuild(db, zero);
    match outcome {
        Ok(()) => db
            .execute_batch("COMMIT")
            .map_err(storage("commit the migration")),
        Err(e) => {
            // Rolled back explicitly rather than left to a dropped connection:
            // a half-applied schema is the one state this file must never be
            // found in.
            let _ = db.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn rebuild(db: &Connection, zero: &[u8]) -> Result<()> {
    let steps: &[(&str, &str, &str)] = &[
        (
            "channel_key",
            "CREATE TABLE channel_key_new (
                exchange BLOB   NOT NULL, channel BLOB NOT NULL, epoch INTEGER NOT NULL,
                sealed BLOB NOT NULL, PRIMARY KEY (exchange, channel, epoch))",
            "INSERT INTO channel_key_new SELECT ?1, channel, epoch, sealed FROM channel_key",
        ),
        (
            "message",
            "CREATE TABLE message_new (
                exchange BLOB NOT NULL, channel BLOB NOT NULL, seq INTEGER NOT NULL,
                account BLOB NOT NULL, posted INTEGER NOT NULL, kind INTEGER NOT NULL,
                sealed BLOB, PRIMARY KEY (exchange, channel, seq))",
            "INSERT INTO message_new
                 SELECT ?1, channel, seq, account, posted, kind, sealed FROM message",
        ),
        (
            "cursor",
            "CREATE TABLE cursor_new (
                exchange BLOB NOT NULL, channel BLOB NOT NULL,
                since INTEGER NOT NULL DEFAULT 0, msg_seq INTEGER NOT NULL DEFAULT 0,
                epoch INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (exchange, channel))",
            "INSERT INTO cursor_new SELECT ?1, channel, since, msg_seq, epoch FROM cursor",
        ),
        (
            "chain",
            "CREATE TABLE chain_new (
                exchange BLOB NOT NULL, channel BLOB NOT NULL, chain_seq INTEGER NOT NULL,
                head BLOB NOT NULL, PRIMARY KEY (exchange, channel))",
            "INSERT INTO chain_new SELECT ?1, channel, chain_seq, head FROM chain",
        ),
        (
            "incarnation",
            "CREATE TABLE incarnation_new (
                exchange BLOB NOT NULL, channel BLOB NOT NULL, instance BLOB NOT NULL,
                announce INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (exchange, channel))",
            "INSERT INTO incarnation_new SELECT ?1, channel, instance, announce FROM incarnation",
        ),
        (
            "seen",
            "CREATE TABLE seen_new (
                exchange BLOB NOT NULL, channel BLOB NOT NULL, device BLOB NOT NULL,
                epoch INTEGER NOT NULL, msg_seq INTEGER NOT NULL,
                PRIMARY KEY (exchange, channel, device, epoch, msg_seq))",
            "INSERT INTO seen_new SELECT ?1, channel, device, epoch, msg_seq FROM seen",
        ),
        (
            "channel_meta",
            "CREATE TABLE channel_meta_new (
                exchange BLOB NOT NULL, channel BLOB NOT NULL,
                kind INTEGER NOT NULL DEFAULT 0, label TEXT NOT NULL DEFAULT '',
                admins BLOB NOT NULL DEFAULT x'', PRIMARY KEY (exchange, channel))",
            "INSERT INTO channel_meta_new
                 SELECT ?1, channel, kind, label, admins FROM channel_meta",
        ),
        (
            "prekey",
            "CREATE TABLE prekey_new (
                exchange BLOB NOT NULL, id INTEGER NOT NULL, kind INTEGER NOT NULL,
                sealed BLOB, spent INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (exchange, id))",
            "INSERT INTO prekey_new SELECT ?1, id, kind, sealed, spent FROM prekey",
        ),
        (
            "profile",
            "CREATE TABLE profile_new (
                exchange BLOB NOT NULL, account BLOB NOT NULL,
                name TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',
                fetched INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (exchange, account))",
            "INSERT INTO profile_new SELECT ?1, account, name, title, fetched FROM profile",
        ),
        (
            "handle",
            "CREATE TABLE handle_new (
                exchange BLOB NOT NULL, account BLOB NOT NULL,
                name TEXT NOT NULL DEFAULT '', fetched INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (exchange, account))",
            "INSERT INTO handle_new SELECT ?1, account, name, fetched FROM handle",
        ),
    ];
    for (name, create, copy) in steps {
        // **A table this store never had.** The guard above asks one table —
        // `channel_key` — whether the store predates the exchange column, and
        // then this rebuilt all nine as though a store were a single version.
        // It is not: `handle` arrived with SIP-38 and `profile` before it, so
        // a store older than either has `channel_key` and no `handle`, and the
        // copy failed with `no such table: handle`. Twelve of the fourteen
        // stores on the machine this was found on were in exactly that shape,
        // and none of them would open.
        //
        // Skipped rather than rebuilt: `SCHEMA` runs straight after this and
        // creates a missing table in the shape the migration would have
        // produced, and there is nothing to copy into it either way.
        let present: bool = db
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1")
            .and_then(|mut s| s.exists(params![name]))
            .map_err(storage("inspect the store's shape"))?;
        if !present {
            continue;
        }
        db.execute_batch(create)
            .map_err(storage("create the migrated table"))?;
        db.execute(copy, params![zero])
            .map_err(storage("copy rows into the migrated table"))?;
        db.execute_batch(&format!(
            "DROP TABLE {name}; ALTER TABLE {name}_new RENAME TO {name};"
        ))
        .map_err(storage("swap in the migrated table"))?;
    }
    Ok(())
}

/// Attribute rows that predate this column to the exchange in front of us.
///
/// The **first** exchange this store is opened against after the migration
/// takes the unattributed rows, and that is recorded so no later one can take
/// them again. It is the only answer available: nothing in the file says where
/// they came from, and today no client can have put rows from two exchanges in
/// one store, so they are all from whichever one it was.
///
/// The case this gets wrong is somebody whose first connection after upgrading
/// is to a *different* exchange than the history came from. That is why the
/// claim is written down rather than assumed: it is a fact about the store
/// that somebody can be shown and can act on, instead of a silent relabelling.
fn claim(db: &Connection, exchange: &PubKey) -> Result<()> {
    let recorded: Option<Vec<u8>> = db
        .query_row("SELECT value FROM meta WHERE key = 'exchange'", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(storage("read the store's exchange"))?;
    if recorded.is_some() {
        return Ok(());
    }
    let zero = &Store::UNCLAIMED[..];
    let mine = &exchange.as_bytes()[..];
    db.execute_batch("BEGIN IMMEDIATE")
        .map_err(storage("begin the claim"))?;
    let outcome = (|| -> Result<()> {
        for table in [
            "channel_key",
            "message",
            "cursor",
            "chain",
            "incarnation",
            "seen",
            "channel_meta",
            "prekey",
            "profile",
            "handle",
        ] {
            db.execute(
                &format!("UPDATE {table} SET exchange = ?1 WHERE exchange = ?2"),
                params![mine, zero],
            )
            .map_err(storage("claim rows for this exchange"))?;
        }
        db.execute(
            "INSERT INTO meta (key, value) VALUES ('exchange', ?1)
             ON CONFLICT (key) DO NOTHING",
            params![mine],
        )
        .map_err(storage("record the store's exchange"))?;
        Ok(())
    })();
    match outcome {
        Ok(()) => db
            .execute_batch("COMMIT")
            .map_err(storage("commit the claim")),
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

#[derive(Debug)]
pub enum StoreError {
    Storage(String),
    /// A sealed row would not open. The store belongs to a different identity,
    /// or the file has been altered.
    Sealed(String),
    /// Another interactive client already holds this account's store.
    InUse(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Storage(e) => write!(f, "chat store: {e}"),
            StoreError::Sealed(e) => write!(f, "chat store will not open: {e}"),
            StoreError::InUse(who) => write!(
                f,
                "this account's store is already open — {who}.\n\n\
                 Two clients under one identity share a device key and a \
                 prekey pool, and neither can see the other. SIP-17 counters \
                 must never repeat under one key, and each client keeps its \
                 own idea of what the next one is. Opening an epoch key \
                 spends a SIP-23 prekey, and the copy on disk is the only \
                 copy — so each can consume what the other needed, and the \
                 loser cannot get that key again.\n\n\
                 Quit the other client. If you want two at once, link a \
                 second device (`sqex-chat device link`), which gives it a \
                 key and a pool of its own."
            ),
        }
    }
}

impl std::error::Error for StoreError {}

type Result<T> = std::result::Result<T, StoreError>;

fn storage<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> StoreError + '_ {
    move |e| StoreError::Storage(format!("{what}: {e}"))
}

/// Seconds since the epoch, truncated to a prekey id's width.
///
/// u32 seconds runs out in 2106; a prekey id that stops being minted then is a
/// smaller problem than the one this solves.
fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1)
}

/// Chunks as one column: a four-byte length before each.
///
/// The boundaries matter -- the id hashes the chunks as a list, and each one
/// opens under its own nonce -- so they are written down rather than
/// recovered by guessing at the chunk size.
fn frame(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chunks.iter().map(|c| c.len() + 4).sum());
    for c in chunks {
        out.extend_from_slice(&(c.len() as u32).to_le_bytes());
        out.extend_from_slice(c);
    }
    out
}

/// The inverse of [`frame`]. `None` for anything that does not parse to the
/// end, which a damaged row would not.
fn unframe(framed: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut chunks = Vec::new();
    let mut at = 0;
    while at < framed.len() {
        let len = u32::from_le_bytes(framed.get(at..at + 4)?.try_into().ok()?) as usize;
        at += 4;
        chunks.push(framed.get(at..at + len)?.to_vec());
        at += len;
    }
    Some(chunks)
}

/// One message, as it goes into the store.
///
/// A struct rather than eight arguments, which is what it had grown into.
pub struct Kept<'a> {
    pub seq: u64,
    pub account: PubKey,
    pub posted: u64,
    pub kind: u8,
    /// The opened body, or `None` for an entry we hold and could not open.
    pub plain: Option<&'a [u8]>,
}

/// One contact, and what we call them.
#[derive(Debug, Clone)]
pub struct Contact {
    pub account: PubKey,
    pub label: String,
    pub added: u64,
}

/// The directory this client keeps its databases in, created 0700.
///
/// One database per account rather than one overall, so that two identities on
/// one machine cannot read each other's conversations by opening the wrong
/// file — and because the store key is per identity anyway.
pub fn store_path(account: &PubKey) -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| StoreError::Storage("no home directory".into()))?;
    let dir = home.join(".sqex").join("chat");
    std::fs::create_dir_all(&dir).map_err(storage("create ~/.sqex/chat"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(storage("lock down ~/.sqex/chat"))?;
    }
    Ok(dir.join(format!(
        "{}.db",
        bs58::encode(account.as_bytes()).into_string()
    )))
}

impl Store {
    /// Open, or create, the store for the identity holding `seed`.
    ///
    /// `None` gives an in-memory database, which is what the tests use and what
    /// a caller wanting a deliberately amnesiac client would ask for.
    /// The exchange a row belonged to before this store knew about exchanges.
    ///
    /// **This store never recorded which exchange its rows came from**, so a
    /// migration cannot know. Rows carry this until an exchange claims them —
    /// see [`Store::open`].
    const UNCLAIMED: [u8; 32] = [0u8; 32];

    pub fn open(seed: &[u8; 32], path: Option<&std::path::Path>) -> Result<Store> {
        let db = match path {
            Some(p) => Connection::open(p).map_err(storage("open store"))?,
            None => Connection::open_in_memory().map_err(storage("open store"))?,
        };
        if let Some(p) = path {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
            }
        }
        // FULL rather than NORMAL for the same reason sqexd uses it: a key
        // written and then lost to a crash is a conversation that will not open
        // again, and there is no second copy anywhere to fall back on.
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage("set journal_mode"))?;
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(storage("set synchronous"))?;
        // Order matters: an older store has to grow the column before the
        // schema is applied, because `CREATE TABLE IF NOT EXISTS` will not
        // alter a table that already exists — it silently does nothing, which
        // is how a schema change reaches a user's machine and is ignored.
        migrate(&db)?;
        db.execute_batch(SCHEMA).map_err(storage("create schema"))?;

        let mut h = Sha512::new();
        h.update(STORE_CONTEXT);
        h.update(seed);
        let okm = h.finalize();
        let cipher = ChaCha20Poly1305::new_from_slice(&okm[0..32])
            .map_err(|e| StoreError::Sealed(format!("derive store key: {e}")))?;

        Ok(Store {
            db,
            cipher,
            exchange: None,
        })
    }

    /// Say which exchange this store is for, and claim what predates the
    /// column. Called once, by [`crate::client::Chat::new`].
    ///
    /// Scoping is separate from opening because the two happen at different
    /// moments: the contact list is read before anything connects — that is
    /// what lets `add` work while the exchange is down — and the exchange is
    /// not known until it does. Making it an argument to `open` would have
    /// forced a placeholder into that path, and a placeholder that looks like
    /// a real exchange is exactly how rows end up filed under one.
    pub fn scope_to(&mut self, exchange: &PubKey) -> Result<()> {
        claim(&self.db, exchange)?;
        self.exchange = Some(*exchange);
        Ok(())
    }

    /// Which exchange this store is reading and writing for, if it has been
    /// told.
    pub fn exchange(&self) -> Option<PubKey> {
        self.exchange
    }

    /// The exchange, as a query parameter. Every scoped row goes through this.
    ///
    /// **Refuses rather than defaulting.** A store that has not been told
    /// which exchange it is for cannot answer a question about a channel, and
    /// a zero standing in for "not told" would be a value rows get filed
    /// under — indistinguishable, later, from a real one.
    fn scope(&self) -> Result<Vec<u8>> {
        match &self.exchange {
            Some(e) => Ok(e.as_bytes().to_vec()),
            None => Err(StoreError::Storage(
                "this store has not been told which exchange it is for".into(),
            )),
        }
    }

    /// Seal bytes with a fresh random nonce, which travels in front of them.
    fn seal_bytes(&self, plain: &[u8]) -> Result<Vec<u8>> {
        use rand_core::RngCore;
        let mut nonce = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plain)
            .map_err(|e| StoreError::Sealed(format!("seal: {e}")))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unseal_bytes(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < 12 {
            return Err(StoreError::Sealed(
                "row is too short to hold a nonce".into(),
            ));
        }
        self.cipher
            .decrypt(Nonce::from_slice(&sealed[0..12]), &sealed[12..])
            .map_err(|_| {
                StoreError::Sealed(
                    "a row would not open — wrong identity, or the file was altered".into(),
                )
            })
    }

    fn seal(&self, plain: &[u8; 32]) -> Result<Vec<u8>> {
        self.seal_bytes(plain.as_slice())
    }

    fn unseal(&self, sealed: &[u8]) -> Result<[u8; 32]> {
        self.unseal_bytes(sealed)?
            .try_into()
            .map_err(|_| StoreError::Sealed("a row held the wrong number of bytes".into()))
    }

    // ---- contacts -------------------------------------------------------

    pub fn add_contact(&self, account: &PubKey, label: &str, now: u64) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO contact (account, label, added) VALUES (?1, ?2, ?3)
                 ON CONFLICT (account) DO UPDATE SET label = ?2",
                params![account.as_bytes(), label, now as i64],
            )
            .map_err(storage("add contact"))?;
        Ok(())
    }

    pub fn remove_contact(&self, account: &PubKey) -> Result<()> {
        self.db
            .execute(
                "DELETE FROM contact WHERE account = ?1",
                params![account.as_bytes()],
            )
            .map_err(storage("remove contact"))?;
        Ok(())
    }

    pub fn contacts(&self) -> Result<Vec<Contact>> {
        let mut stmt = self
            .db
            .prepare("SELECT account, label, added FROM contact ORDER BY label, added")
            .map_err(storage("prepare contacts"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Contact {
                    account: PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                    label: r.get(1)?,
                    added: r.get::<_, i64>(2)? as u64,
                })
            })
            .map_err(storage("query contacts"))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage("read contacts"))
    }

    // ---- channel keys ---------------------------------------------------

    pub fn put_key(&self, channel: &[u8; 32], epoch: u32, key: &ChannelKey) -> Result<()> {
        let sealed = self.seal(key.as_bytes())?;
        self.db
            .execute(
                "INSERT INTO channel_key (channel, epoch, sealed, exchange)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (exchange, channel, epoch) DO NOTHING",
                params![&channel[..], epoch as i64, sealed, self.scope()?],
            )
            .map_err(storage("store channel key"))?;
        Ok(())
    }

    pub fn key(&self, channel: &[u8; 32], epoch: u32) -> Result<Option<ChannelKey>> {
        let sealed: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT sealed FROM channel_key
                 WHERE channel = ?1 AND epoch = ?2 AND exchange = ?3",
                params![&channel[..], epoch as i64, self.scope()?],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read channel key"))?;
        match sealed {
            Some(s) => Ok(Some(ChannelKey::new(self.unseal(&s)?))),
            None => Ok(None),
        }
    }

    /// The highest epoch we hold a key for, or 0.
    pub fn highest_epoch(&self, channel: &[u8; 32]) -> Result<u32> {
        let e: Option<i64> = self
            .db
            .query_row(
                "SELECT MAX(epoch) FROM channel_key WHERE channel = ?1 AND exchange = ?2",
                params![&channel[..], self.scope()?],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read highest epoch"))?
            .flatten();
        Ok(e.unwrap_or(0) as u32)
    }

    // ---- the prekey pool ------------------------------------------------

    /// Load the pool, or an empty one on first run.
    pub fn pool(&self, seed: &[u8; 32]) -> Result<Pool> {
        let mut stmt = self
            .db
            .prepare("SELECT id, kind, sealed, spent FROM prekey WHERE exchange = ?1")
            .map_err(storage("prepare prekeys"))?;
        let rows = stmt
            .query_map(params![self.scope()?], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u32,
                    r.get::<_, i64>(1)? as u8,
                    r.get::<_, Option<Vec<u8>>>(2)?,
                    r.get::<_, i64>(3)? != 0,
                ))
            })
            .map_err(storage("query prekeys"))?;

        let mut state = PoolState {
            next_id: 0,
            one_time: Vec::new(),
            fallback: None,
            spent: Vec::new(),
        };
        for row in rows {
            let (id, kind, sealed, spent) = row.map_err(storage("read prekey"))?;
            state.next_id = state.next_id.max(id + 1);
            if spent {
                state.spent.push(id);
                continue;
            }
            let Some(sealed) = sealed else { continue };
            let secret = self.unseal(&sealed)?;
            if kind == KIND_FALLBACK {
                state.fallback = Some((id, secret));
            } else {
                state.one_time.push((id, secret));
            }
        }
        if state.next_id == 0 {
            // A store that holds no prekeys is either brand new or one that was
            // lost, and those two are indistinguishable from here — while the
            // exchange tells them apart perfectly, because it still holds the
            // ids the lost store published and SIP-23 has it refuse every one
            // of them forever. Starting again at 1 therefore does not fail
            // gracefully: it fails completely, and the identity can never
            // publish a prekey again.
            //
            // So a fresh pool starts its ids at the wall clock, which is
            // monotonic across a store being lost in a way a counter kept only
            // in the store can never be. It costs nothing — ids are u32 and
            // spent at a few dozen per top-up — and it is why losing this file
            // costs the conversations in it and not the identity itself.
            state.next_id = now_secs().max(1);
        }
        Ok(Pool::load(seed, state))
    }

    /// Write the pool back.
    ///
    /// A spent prekey keeps its row with `sealed` set to NULL: the id must be
    /// remembered so a replay is still refused, and the secret must be gone,
    /// and those are two different requirements that this satisfies at once.
    pub fn save_pool(&mut self, pool: &Pool) -> Result<()> {
        let state = pool.save();
        // Taken before the transaction borrows `self.db` mutably.
        let scope = self.scope()?;
        let tx = self.db.transaction().map_err(storage("begin save pool"))?;
        for (id, secret) in &state.one_time {
            let sealed = {
                use rand_core::RngCore;
                let mut nonce = [0u8; 12];
                rand_core::OsRng.fill_bytes(&mut nonce);
                let ct = self
                    .cipher
                    .encrypt(Nonce::from_slice(&nonce), secret.as_slice())
                    .map_err(|e| StoreError::Sealed(format!("seal: {e}")))?;
                let mut out = Vec::with_capacity(12 + ct.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&ct);
                out
            };
            tx.execute(
                "INSERT INTO prekey (id, kind, sealed, spent, exchange)
                 VALUES (?1, ?2, ?3, 0, ?4)
                 ON CONFLICT (exchange, id) DO UPDATE SET sealed = ?3, spent = 0",
                params![*id as i64, KIND_ONE_TIME as i64, sealed, &scope],
            )
            .map_err(storage("store one-time prekey"))?;
        }
        if let Some((id, secret)) = &state.fallback {
            let sealed = {
                use rand_core::RngCore;
                let mut nonce = [0u8; 12];
                rand_core::OsRng.fill_bytes(&mut nonce);
                let ct = self
                    .cipher
                    .encrypt(Nonce::from_slice(&nonce), secret.as_slice())
                    .map_err(|e| StoreError::Sealed(format!("seal: {e}")))?;
                let mut out = Vec::with_capacity(12 + ct.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&ct);
                out
            };
            tx.execute(
                "INSERT INTO prekey (id, kind, sealed, spent, exchange)
                 VALUES (?1, ?2, ?3, 0, ?4)
                 ON CONFLICT (exchange, id) DO UPDATE SET sealed = ?3, spent = 0",
                params![*id as i64, KIND_FALLBACK as i64, sealed, &scope],
            )
            .map_err(storage("store fallback"))?;
        }
        for id in &state.spent {
            tx.execute(
                "INSERT INTO prekey (id, kind, sealed, spent, exchange)
                 VALUES (?1, ?2, NULL, 1, ?3)
                 ON CONFLICT (exchange, id) DO UPDATE SET sealed = NULL, spent = 1",
                params![*id as i64, KIND_ONE_TIME as i64, &scope],
            )
            .map_err(storage("record spent prekey"))?;
        }
        tx.commit().map_err(storage("commit save pool"))?;
        Ok(())
    }

    // ---- the replay set -------------------------------------------------

    /// Rebuild SIP-17's replay set for one channel.
    ///
    /// `Replay` has no constructor from a set and needs none: `accept` returns
    /// false on a repeat, so replaying the stored triples through it rebuilds
    /// exactly the state that recorded them.
    pub fn replay_for(&self, channel: &[u8; 32]) -> Result<Replay> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT device, epoch, msg_seq FROM seen
                 WHERE channel = ?1 AND exchange = ?2",
            )
            .map_err(storage("prepare seen"))?;
        let rows = stmt
            .query_map(params![&channel[..], self.scope()?], |r| {
                Ok((
                    PubKey::new(r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32])),
                    r.get::<_, i64>(1)? as u32,
                    r.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(storage("query seen"))?;
        let mut replay = Replay::new();
        for row in rows {
            let (device, epoch, msg_seq) = row.map_err(storage("read seen"))?;
            replay.accept(&device, epoch, msg_seq);
        }
        Ok(replay)
    }

    pub fn record_seen(
        &self,
        channel: &[u8; 32],
        device: &PubKey,
        epoch: u32,
        msg_seq: u64,
    ) -> Result<()> {
        self.db
            .execute(
                "INSERT OR IGNORE INTO seen (channel, device, epoch, msg_seq, exchange)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &channel[..],
                    device.as_bytes(),
                    epoch as i64,
                    msg_seq as i64,
                    self.scope()?
                ],
            )
            .map_err(storage("record seen"))?;
        Ok(())
    }

    // ---- the conversation -----------------------------------------------

    /// Keep a message we have just opened.
    ///
    /// `plain` is `None` for an entry we could not open, which is recorded
    /// rather than dropped so the reader can still be told something was there
    /// — and so a later run does not go looking for it again.
    pub fn put_message(&self, channel: &[u8; 32], m: Kept<'_>) -> Result<()> {
        let (seq, account, posted, kind, plain) = (m.seq, m.account, m.posted, m.kind, m.plain);
        let sealed = match plain {
            Some(p) => Some(self.seal_bytes(p)?),
            None => None,
        };
        self.db
            .execute(
                "INSERT INTO message (channel, seq, account, posted, kind, sealed, exchange)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (exchange, channel, seq)
                 DO UPDATE SET sealed = COALESCE(message.sealed, excluded.sealed)",
                params![
                    &channel[..],
                    seq as i64,
                    account.as_bytes(),
                    posted as i64,
                    kind as i64,
                    sealed,
                    self.scope()?
                ],
            )
            .map_err(storage("store message"))?;
        Ok(())
    }

    /// Throw away the words of a message that has been deleted.
    ///
    /// `put_message` keeps a body it already holds, deliberately — a re-fetch
    /// must not be able to blank a message this client managed to open once.
    /// The same rule meant a redaction never reached the copy on disk: the
    /// exchange dropped the bytes, every reader went on holding them, and
    /// "delete" meant hidden rather than gone.
    ///
    /// Set to an empty body rather than to NULL, because NULL means "held and
    /// could not be opened" and the two must stay distinguishable across a
    /// restart.
    pub fn redact_message(&self, channel: &[u8; 32], seq: u64) -> Result<()> {
        // **What it carried goes with it.** SIP-18: deleting a message must
        // delete what it carried, and the exchange can only do its half --
        // the reference is inside a sealed body it cannot read. A client that
        // kept the file is the other half. Read out of the body *before* it
        // is blanked, because afterwards nothing names the files. Every path
        // a redaction reaches the store by comes through here -- the
        // redactor's own, the poll that hears of one, the fold at startup --
        // so this is the one place the rule lives.
        let sealed: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT sealed FROM message
                 WHERE channel = ?1 AND seq = ?2 AND exchange = ?3",
                params![&channel[..], seq as i64, self.scope()?],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read redacted"))?
            .flatten();
        if let Some(sealed) = sealed
            && let Ok(plain) = self.unseal_bytes(&sealed)
            && let Ok(Some(body)) = sqex_proto::message::Body::decode(&plain)
        {
            let post = match body {
                sqex_proto::message::Body::Post(p)
                | sqex_proto::message::Body::Edit { post: p, .. } => Some(p),
                _ => None,
            };
            for a in post.iter().flat_map(|p| p.attachments()) {
                self.forget_blob(&a.blob)?;
            }
        }

        let empty = self.seal_bytes(&[])?;
        self.db
            .execute(
                "UPDATE message SET sealed = ?3
                 WHERE channel = ?1 AND seq = ?2 AND exchange = ?4",
                params![&channel[..], seq as i64, empty, self.scope()?],
            )
            .map_err(storage("redact message"))?;
        Ok(())
    }

    /// How many **member** entries are held for `channel`, opened or not.
    ///
    /// System entries are excluded deliberately, and the distinction is the
    /// whole point. A direct message that has been created and never written
    /// to still carries the system entries of its own creation, so counting
    /// those would report a conversation as holding something unreadable when
    /// what it holds is its own paperwork — and the reader would be warned
    /// about missing messages that were never sent.
    ///
    /// A count rather than `messages().len()`, because the one caller asks
    /// precisely when it cannot open any of them — loading every sealed body
    /// to discover there is at least one would be work done to throw away.
    pub fn held(&self, channel: &[u8; 32]) -> Result<usize> {
        let n: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM message
                 WHERE channel = ?1 AND kind = ?2 AND exchange = ?3",
                params![&channel[..], KIND_MEMBER, self.scope()?],
                |r| r.get(0),
            )
            .map_err(storage("count held"))?;
        Ok(n as usize)
    }

    /// The member entries we hold and never opened, oldest first.
    ///
    /// `put_message` writes a NULL body for an entry it could not open, and
    /// `redact_message` writes an empty one instead precisely so the two stay
    /// apart across a restart — this is the query that distinction exists for.
    ///
    /// The caller has its own list of what the current fold could not open,
    /// but that covers only entries this poll fetched. Anything stored by an
    /// earlier run is never re-folded, so without this the report is empty on
    /// every poll but the first.
    pub fn unopened(&self, channel: &[u8; 32]) -> Result<Vec<u64>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT seq FROM message
                 WHERE channel = ?1 AND kind = ?2 AND sealed IS NULL AND exchange = ?3
                 ORDER BY seq ASC",
            )
            .map_err(storage("prepare unopened"))?;
        let rows = stmt
            .query_map(params![&channel[..], KIND_MEMBER, self.scope()?], |r| {
                r.get::<_, i64>(0).map(|n| n as u64)
            })
            .map_err(storage("query unopened"))?;
        rows.collect::<std::result::Result<Vec<u64>, _>>()
            .map_err(storage("read unopened"))
    }

    /// Everything we have kept for a channel, oldest first.
    ///
    /// Returns the decrypted body bytes; decoding them is the caller's job,
    /// because this module has no opinion about message structure.
    #[allow(clippy::type_complexity)]
    pub fn messages(
        &self,
        channel: &[u8; 32],
    ) -> Result<Vec<(u64, PubKey, u64, u8, Option<Vec<u8>>)>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT seq, account, posted, kind, sealed FROM message
                 WHERE channel = ?1 AND exchange = ?2 ORDER BY seq ASC",
            )
            .map_err(storage("prepare messages"))?;
        let rows = stmt
            .query_map(params![&channel[..], self.scope()?], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    PubKey::new(r.get::<_, Vec<u8>>(1)?.try_into().unwrap_or([0; 32])),
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)? as u8,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })
            .map_err(storage("query messages"))?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, account, posted, kind, sealed) = row.map_err(storage("read message"))?;
            let plain = match sealed {
                Some(s) => Some(self.unseal_bytes(&s)?),
                None => None,
            };
            out.push((seq, account, posted, kind, plain));
        }
        Ok(out)
    }

    // ---- profiles (SIP-21) ----------------------------------------------

    /// Remember what an account says about itself.
    ///
    /// An account that publishes nothing, or withholds it, is stored as empty
    /// rather than left absent: "asked and told nothing" and "never asked" have
    /// to be different, or the client asks again on every poll forever.
    pub fn put_profile(&self, account: &PubKey, name: &str, title: &str, now: u64) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO profile (account, name, title, fetched, exchange)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (exchange, account)
                 DO UPDATE SET name = ?2, title = ?3, fetched = ?4",
                params![account.as_bytes(), name, title, now as i64, self.scope()?],
            )
            .map_err(storage("store profile"))?;
        Ok(())
    }

    /// The name and title we hold for an account, and when we asked.
    pub fn profile(&self, account: &PubKey) -> Result<Option<(String, String, u64)>> {
        self.db
            .query_row(
                "SELECT name, title, fetched FROM profile
                 WHERE account = ?1 AND exchange = ?2",
                params![account.as_bytes(), self.scope()?],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)? as u64,
                    ))
                },
            )
            .optional()
            .map_err(storage("read profile"))
    }

    // ---- handles (SIP-38) -----------------------------------------------

    /// Remember the primary handle (bare local name) the exchange reports for
    /// an account. Empty means asked-and-told-nothing, so the client does not
    /// re-ask on every poll — the same convention `put_profile` uses.
    pub fn put_handle(&self, account: &PubKey, name: &str, now: u64) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO handle (account, name, fetched, exchange)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (exchange, account) DO UPDATE SET name = ?2, fetched = ?3",
                params![account.as_bytes(), name, now as i64, self.scope()?],
            )
            .map_err(storage("store handle"))?;
        Ok(())
    }

    /// The handle (bare name) we hold for an account, and when we asked.
    pub fn handle(&self, account: &PubKey) -> Result<Option<(String, u64)>> {
        self.db
            .query_row(
                "SELECT name, fetched FROM handle WHERE account = ?1 AND exchange = ?2",
                params![account.as_bytes(), self.scope()?],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)),
            )
            .optional()
            .map_err(storage("read handle"))
    }

    // ---- who this client is ---------------------------------------------

    /// The account this client acts for, once it has been linked to one.
    ///
    /// `None` until `device claim` records it. An unlinked client is its own
    /// account, and the caller substitutes its device key — which is the
    /// ordinary single-client case and why this was invisible until a second
    /// device existed.
    pub fn account(&self) -> Result<Option<PubKey>> {
        let v: Option<Vec<u8>> = self
            .db
            .query_row("SELECT value FROM meta WHERE key = 'account'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(storage("read account"))?;
        Ok(v.and_then(|b| b.try_into().ok()).map(PubKey::new))
    }

    pub fn set_account(&self, account: &PubKey) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO meta (key, value) VALUES ('account', ?1)
                 ON CONFLICT (key) DO UPDATE SET value = ?1",
                params![account.as_bytes()],
            )
            .map_err(storage("set account"))?;
        Ok(())
    }

    // ---- what a channel is ----------------------------------------------

    pub fn put_channel(
        &self,
        channel: &[u8; 32],
        group: bool,
        public: Option<bool>,
        label: &str,
        admins: &[PubKey],
    ) -> Result<()> {
        let mut flat = Vec::with_capacity(admins.len() * 32);
        for a in admins {
            flat.extend_from_slice(a.as_bytes());
        }
        self.db
            .execute(
                "INSERT INTO channel_meta (channel, kind, label, admins, exchange)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (exchange, channel)
                 DO UPDATE SET kind = ?2, label = ?3, admins = ?4",
                params![
                    &channel[..],
                    Kind::of(group, public).as_i64(),
                    label,
                    flat,
                    self.scope()?
                ],
            )
            .map_err(storage("store channel"))?;
        Ok(())
    }

    /// Update only the label, leaving the membership alone.
    ///
    /// Separate because they arrive from different places: the name comes from
    /// a sealed entry only members can read, and the admins from the exchange.
    pub fn set_label(&self, channel: &[u8; 32], label: &str) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO channel_meta (channel, label, exchange) VALUES (?1, ?2, ?3)
                 ON CONFLICT (exchange, channel) DO UPDATE SET label = ?2",
                params![&channel[..], label, self.scope()?],
            )
            .map_err(storage("set label"))?;
        Ok(())
    }

    /// Every channel this client knows about.
    pub fn channels(&self) -> Result<Vec<Channel>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT channel, kind, label, admins FROM channel_meta
                 WHERE exchange = ?1 ORDER BY label, channel",
            )
            .map_err(storage("prepare channels"))?;
        let rows = stmt
            .query_map(params![self.scope()?], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32]),
                    Kind::from_i64(r.get::<_, i64>(1)?),
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(storage("query channels"))?;
        let mut out = Vec::new();
        for row in rows {
            let (channel, kind, label, flat) = row.map_err(storage("read channel"))?;
            let admins = flat
                .as_chunks::<32>()
                .0
                .iter()
                .map(|c| PubKey::new(*c))
                .collect();
            out.push(Channel {
                channel,
                group: kind.group(),
                public: kind.public(),
                label,
                admins,
            });
        }
        Ok(out)
    }

    // ---- attachments, kept ----------------------------------------------

    /// Keep a fetched attachment, as served.
    ///
    /// `chunks` are the sealed chunks exactly as the exchange handed them
    /// over, in order; their hash is the blob's id, and [`Store::blob`] checks
    /// that on the way back out. Nothing bigger than [`BLOB_KEEP_MAX`] is
    /// kept, and keeping this one may put down the least recently read
    /// others to stay inside [`BLOB_BUDGET`].
    pub fn keep_blob(&self, blob: &[u8; 32], chunks: &[Vec<u8>]) -> Result<()> {
        self.keep_blob_within(blob, chunks, BLOB_BUDGET)
    }

    /// [`Store::keep_blob`] with the budget as an argument, so eviction can be
    /// tested with a budget a test can fill.
    fn keep_blob_within(&self, blob: &[u8; 32], chunks: &[Vec<u8>], budget: u64) -> Result<()> {
        let bytes: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        if bytes > BLOB_KEEP_MAX || bytes > budget {
            return Ok(());
        }
        let framed = frame(chunks);
        self.db
            .execute(
                "INSERT INTO blob (exchange, blob, sealed, bytes, used)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (exchange, blob) DO UPDATE SET used = ?5",
                params![self.scope()?, &blob[..], framed, bytes as i64, now_secs()],
            )
            .map_err(storage("keep blob"))?;
        self.put_down_blobs(budget)
    }

    /// A kept attachment's sealed chunks, if it is here and still hashes to
    /// its name.
    ///
    /// **Checked, not trusted.** The id is the hash of the chunks, so a row
    /// the disc has damaged fails the same check a dishonest exchange would,
    /// and is put down so the next read fetches instead of finding it again.
    /// Reading marks it used.
    pub fn blob(&self, blob: &[u8; 32]) -> Result<Option<Vec<Vec<u8>>>> {
        let framed: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT sealed FROM blob WHERE exchange = ?1 AND blob = ?2",
                params![self.scope()?, &blob[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read blob"))?;
        let Some(framed) = framed else {
            return Ok(None);
        };
        let chunks = match unframe(&framed) {
            Some(chunks) if sqex_proto::blob_store::blob_id(&chunks) == *blob => chunks,
            _ => {
                self.forget_blob(blob)?;
                return Ok(None);
            }
        };
        self.db
            .execute(
                "UPDATE blob SET used = ?3 WHERE exchange = ?1 AND blob = ?2",
                params![self.scope()?, &blob[..], now_secs()],
            )
            .map_err(storage("touch blob"))?;
        Ok(Some(chunks))
    }

    /// Whether one is here, without reading it.
    ///
    /// For deciding whether to *ask* for a blob: a client that fetches
    /// pictures unasked only up to a size still wants a bigger one it has
    /// already got -- its own upload, or one it fetched last time. Reading the
    /// whole thing to find out would cost what the question is trying to
    /// avoid, and would mark it used. Says nothing about whether it still
    /// hashes to its name; [`Store::blob`] checks that on the read.
    pub fn has_blob(&self, blob: &[u8; 32]) -> Result<bool> {
        self.db
            .query_row(
                "SELECT 1 FROM blob WHERE exchange = ?1 AND blob = ?2",
                params![self.scope()?, &blob[..]],
                |_| Ok(()),
            )
            .optional()
            .map(|found| found.is_some())
            .map_err(storage("look for blob"))
    }

    /// Put one down.
    pub fn forget_blob(&self, blob: &[u8; 32]) -> Result<()> {
        self.db
            .execute(
                "DELETE FROM blob WHERE exchange = ?1 AND blob = ?2",
                params![self.scope()?, &blob[..]],
            )
            .map_err(storage("forget blob"))?;
        Ok(())
    }

    /// What the kept attachments come to, across every exchange in this
    /// store: the file is the unit the disc counts.
    pub fn blob_bytes(&self) -> Result<u64> {
        self.db
            .query_row("SELECT COALESCE(SUM(bytes), 0) FROM blob", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n as u64)
            .map_err(storage("sum blobs"))
    }

    /// Put down the least recently read until the rest fit the budget.
    ///
    /// Across every exchange, because the budget is about the file. Whole
    /// rows, oldest `used` first, stopping as soon as what is left fits.
    fn put_down_blobs(&self, budget: u64) -> Result<()> {
        let mut held = self.blob_bytes()?;
        if held <= budget {
            return Ok(());
        }
        let mut stmt = self
            .db
            .prepare("SELECT exchange, blob, bytes FROM blob ORDER BY used ASC, rowid ASC")
            .map_err(storage("prepare eviction"))?;
        let rows: Vec<(Vec<u8>, Vec<u8>, u64)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(storage("list blobs"))?
            .collect::<std::result::Result<_, _>>()
            .map_err(storage("read blobs"))?;
        for (exchange, blob, bytes) in rows {
            if held <= budget {
                break;
            }
            self.db
                .execute(
                    "DELETE FROM blob WHERE exchange = ?1 AND blob = ?2",
                    params![exchange, blob],
                )
                .map_err(storage("put down blob"))?;
            held = held.saturating_sub(bytes);
        }
        Ok(())
    }

    /// Forget everything numbered in this channel's sequence space.
    ///
    /// SIP-16, "A reset sequence space": a cursor above the exchange's newest
    /// entry means the channel this client knew was destroyed and a new one
    /// created under the same identifier, numbering from 1 again. Only a direct
    /// message can do that, and it always does — its identifier is derived from
    /// the two accounts, so it cannot be made unique per incarnation.
    ///
    /// The two sequence spaces are unrelated, so the old entries cannot stay
    /// beside the new ones: entry 7 of this channel is not entry 7 of the one
    /// before it, and the message table is keyed on (channel, seq). Keeping
    /// them would mean every new entry merging into a stale row and never
    /// appearing — which is the failure this exists to end, not a milder form
    /// of it.
    ///
    /// `channel_meta` is deliberately left: the conversation is between the
    /// same two people and should stay where the reader left it.
    /// Which incarnation this store's state for `channel` belongs to.
    pub fn incarnation(&self, channel: &[u8; 32]) -> Result<Option<[u8; 32]>> {
        let row: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT instance FROM incarnation WHERE channel = ?1 AND exchange = ?2",
                params![&channel[..], self.scope()?],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read incarnation"))?;
        Ok(row.and_then(|b| b.try_into().ok()))
    }

    pub fn set_incarnation(
        &self,
        channel: &[u8; 32],
        instance: &[u8; 32],
        announce: bool,
    ) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO incarnation (channel, instance, announce, exchange)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (exchange, channel) DO UPDATE SET instance = ?2, announce = ?3",
                params![
                    &channel[..],
                    &instance[..],
                    i64::from(announce),
                    self.scope()?
                ],
            )
            .map_err(storage("set incarnation"))?;
        Ok(())
    }

    /// Whether this channel was reset under us since anybody last asked, and
    /// clear the note. Reported once, like the reset it describes.
    pub fn take_announcement(&self, channel: &[u8; 32]) -> Result<bool> {
        let pending: Option<i64> = self
            .db
            .query_row(
                "SELECT announce FROM incarnation WHERE channel = ?1 AND exchange = ?2",
                params![&channel[..], self.scope()?],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read announcement"))?;
        if pending == Some(1) {
            self.db
                .execute(
                    "UPDATE incarnation SET announce = 0
                     WHERE channel = ?1 AND exchange = ?2",
                    params![&channel[..], self.scope()?],
                )
                .map_err(storage("clear announcement"))?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn reset_sequence_space(&self, channel: &[u8; 32]) -> Result<()> {
        for sql in [
            "DELETE FROM message WHERE channel = ?1 AND exchange = ?2",
            "DELETE FROM seen WHERE channel = ?1 AND exchange = ?2",
            "DELETE FROM channel_key WHERE channel = ?1 AND exchange = ?2",
            "DELETE FROM cursor WHERE channel = ?1 AND exchange = ?2",
            // SIP-31 chain state, for the same reason as the rest: a recreated
            // channel is a different channel, and a position carried into it
            // is one the exchange has no record of — every signature after it
            // refused as a broken chain, for good.
            "DELETE FROM chain WHERE channel = ?1 AND exchange = ?2",
        ] {
            self.db
                .execute(sql, params![&channel[..], self.scope()?])
                .map_err(storage("reset sequence space"))?;
        }
        Ok(())
    }

    pub fn forget_channel(&self, channel: &[u8; 32]) -> Result<()> {
        self.db
            .execute(
                "DELETE FROM channel_meta WHERE channel = ?1 AND exchange = ?2",
                params![&channel[..], self.scope()?],
            )
            .map_err(storage("forget channel"))?;
        Ok(())
    }

    // ---- cursors --------------------------------------------------------

    pub fn cursor(&self, channel: &[u8; 32]) -> Result<(u64, u64, u32)> {
        Ok(self
            .db
            .query_row(
                "SELECT since, msg_seq, epoch FROM cursor
                 WHERE channel = ?1 AND exchange = ?2",
                params![&channel[..], self.scope()?],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? as u64,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, i64>(2)? as u32,
                    ))
                },
            )
            .optional()
            .map_err(storage("read cursor"))?
            .unwrap_or((0, 0, 0)))
    }

    /// Read this channel again from the beginning.
    ///
    /// For when a key arrives after the entries it opens: those were held and
    /// could not be read, and nothing else would ever look at them again.
    pub fn rewind(&self, channel: &[u8; 32]) -> Result<()> {
        self.db
            .execute(
                "UPDATE cursor SET since = 0 WHERE channel = ?1 AND exchange = ?2",
                params![&channel[..], self.scope()?],
            )
            .map_err(storage("rewind"))?;
        Ok(())
    }

    pub fn set_since(&self, channel: &[u8; 32], since: u64) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO cursor (channel, since, exchange) VALUES (?1, ?2, ?3)
                 ON CONFLICT (exchange, channel) DO UPDATE SET since = MAX(since, ?2)",
                params![&channel[..], since as i64, self.scope()?],
            )
            .map_err(storage("set since"))?;
        Ok(())
    }

    /// Where we last signed in this channel: the **next** position to use, and
    /// the link to put in it. `(0, GENESIS)` when we have signed nothing here.
    pub fn chain(&self, channel: &[u8; 32]) -> Result<(u64, [u8; 32])> {
        let row: Option<(i64, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT chain_seq, head FROM chain WHERE channel = ?1 AND exchange = ?2",
                params![&channel[..], self.scope()?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage("read chain"))?;
        Ok(match row {
            None => (0, GENESIS),
            Some((seq, head)) => (seq as u64 + 1, head.try_into().unwrap_or(GENESIS)),
        })
    }

    /// Record a chain step the exchange **accepted**.
    ///
    /// Called after the request succeeds, not before it — unlike `set_msg_seq`,
    /// which is recorded first because a burnt nonce costs nothing and a reused
    /// one costs two plaintexts. A position is only spent once something is in
    /// the log at it, so a refused request leaves the chain where it was.
    pub fn set_chain(&self, channel: &[u8; 32], chain_seq: u64, head: &[u8; 32]) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO chain (channel, chain_seq, head, exchange)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (exchange, channel) DO UPDATE SET
                     chain_seq = MAX(chain_seq, ?2),
                     head      = CASE WHEN ?2 >= chain_seq THEN ?3 ELSE head END",
                params![&channel[..], chain_seq as i64, &head[..], self.scope()?],
            )
            .map_err(storage("set chain"))?;
        Ok(())
    }

    /// Record the counter we just used.
    ///
    /// Monotonic within an epoch, and reset by a *higher* epoch rather than by
    /// any change — a stale reply naming an old epoch must not walk the counter
    /// backwards, because the cost of that is nonce reuse.
    pub fn set_msg_seq(&self, channel: &[u8; 32], epoch: u32, msg_seq: u64) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO cursor (channel, epoch, msg_seq, exchange)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (exchange, channel) DO UPDATE SET
                     msg_seq = CASE WHEN ?2 > epoch THEN ?3 ELSE MAX(msg_seq, ?3) END,
                     epoch   = MAX(epoch, ?2)",
                params![&channel[..], epoch as i64, msg_seq as i64, self.scope()?],
            )
            .map_err(storage("set msg_seq"))?;
        Ok(())
    }
}

/// An exclusive hold on one account's store, for as long as a session lasts.
///
/// Dropping it releases the hold, and so does the process ending — however it
/// ends. That is the whole reason for `flock` rather than a file somebody has
/// to remember to delete: a client that was killed, or that panicked, leaves
/// nothing behind to lock its owner out of their own account tomorrow.
///
/// The pid written inside is not the lock. It is there only so a refusal can
/// name which process to go and close.
#[derive(Debug)]
pub struct Lock {
    /// Held, not read. Closing the file is what releases the lock.
    _file: std::fs::File,
}

/// Take the store's lock, or say who has it.
///
/// Deliberately **not** called from [`Store::open`]. The hazard is two
/// *interactive* clients — long-running, polling, sealing, each with its own
/// idea of the next SIP-17 counter. A one-shot `sqex-chat list` or `add` is
/// none of that, and SQLite's own locking is enough for it; refusing those
/// while a client is up would be paying for a problem they do not have.
/// The lock is per **account and exchange**, not per account.
///
/// What it protects is the SIP-17 counter, and since the store began scoping
/// rows by exchange there is one counter per pair — two clients on one account
/// at *different* exchanges no longer share anything they could disagree
/// about. Keeping one lock per account would refuse a second exchange for a
/// conflict that does not exist.
pub fn lock(path: &std::path::Path, exchange: &PubKey) -> Result<Lock> {
    use std::io::{Read, Seek, Write};

    // Named for the exchange as well as the account. The first eight
    // characters of its key are plenty to tell two apart and keep the name
    // readable, which matters because a refusal quotes this path.
    let mut which: String = bs58::encode(exchange.as_bytes()).into_string();
    which.truncate(8);
    let at = path.with_extension(format!("{which}.lock"));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&at)
        .map_err(storage("open the store lock"))?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `file` owns the descriptor and outlives the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let mut held = String::new();
            let _ = file.read_to_string(&mut held);
            let who = held.trim();
            return Err(StoreError::InUse(match who.parse::<u32>() {
                Ok(pid) => format!("another sqex-chat is running as pid {pid}"),
                // The pid is best effort: the holder may not have written it
                // yet. Not knowing which process it is does not make the
                // refusal any less correct.
                Err(_) => "another sqex-chat is running".to_string(),
            }));
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o600));
    }

    let _ = file.set_len(0);
    let _ = file.rewind();
    let _ = write!(file, "{}", std::process::id());
    let _ = file.flush();
    Ok(Lock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Two clients under one identity share a device key and a prekey pool,
    /// and neither can see the other. This is the only thing that can tell
    /// them apart.
    ///
    /// `flock` is held per open file description rather than per process, so
    /// a second `lock` in this very process is refused exactly as a second
    /// client would be — which is what makes this testable at all.
    #[test]
    fn a_second_client_on_one_store_is_refused_and_told_why() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");

        let first = lock(&path, &an_exchange()).unwrap();
        let second = lock(&path, &an_exchange());
        let Err(StoreError::InUse(who)) = &second else {
            panic!("a second client was allowed in: {:?}", second.is_ok());
        };
        // Named, so somebody with two terminals open knows which to close.
        assert!(
            who.contains(&std::process::id().to_string()),
            "the refusal does not say which process holds it: {who:?}"
        );
        // And the reason travels with it: "in use" alone would read as a bug
        // in the client rather than as a thing the reader has to decide.
        let said = second.unwrap_err().to_string();
        assert!(said.contains("prekey"), "{said}");
        assert!(said.contains("device link"), "{said}");

        // And it is a hold, not a record: closing the first hands it over.
        drop(first);
        lock(&path, &an_exchange()).expect("the lock outlived the client that took it");
    }

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    /// The exchange these tests are against.
    ///
    /// Any one will do for most of them — what matters is that there *is* one,
    /// because an unscoped store refuses every question about a channel.
    fn an_exchange() -> PubKey {
        PubKey::new([9; 32])
    }

    /// A store already told which exchange it is for. What a client has.
    fn scoped(seed: &[u8; 32], path: Option<&std::path::Path>) -> Store {
        let mut s = Store::open(seed, path).unwrap();
        s.scope_to(&an_exchange()).unwrap();
        s
    }

    #[test]
    fn a_channel_key_round_trips() {
        let s = scoped(&seed(1), None);
        let k = ChannelKey::generate();
        s.put_key(&[7; 32], 3, &k).unwrap();
        assert_eq!(s.key(&[7; 32], 3).unwrap().unwrap(), k);
        assert!(s.key(&[7; 32], 4).unwrap().is_none());
        assert_eq!(s.highest_epoch(&[7; 32]).unwrap(), 3);
    }

    #[test]
    fn another_identity_cannot_open_the_store() {
        // The store key derives from the identity seed, so opening somebody
        // else's file gets you the schema and none of the contents.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let k = ChannelKey::generate();
        {
            let s = scoped(&seed(1), Some(&path));
            s.put_key(&[7; 32], 1, &k).unwrap();
        }
        let theirs = scoped(&seed(2), Some(&path));
        assert!(matches!(
            theirs.key(&[7; 32], 1),
            Err(StoreError::Sealed(_))
        ));
    }

    #[test]
    fn held_counts_entries_without_opening_them() {
        // The guard that reports a stranded conversation asks this precisely
        // when it can open nothing, so it must count sealed rows as held —
        // a count that only saw opened messages would report zero exactly
        // when the warning is needed, and the conversation would go back to
        // rendering as empty.
        let s = scoped(&seed(1), None);
        assert_eq!(s.held(&[7; 32]).unwrap(), 0, "a channel with nothing in it");

        s.put_message(
            &[7; 32],
            Kept {
                seq: 1,
                account: key(2),
                posted: 100,
                kind: 1,
                plain: Some(b"readable"),
            },
        )
        .unwrap();
        s.put_message(
            &[7; 32],
            Kept {
                seq: 2,
                account: key(2),
                posted: 101,
                kind: 1,
                plain: None,
            },
        )
        .unwrap();

        assert_eq!(s.held(&[7; 32]).unwrap(), 2, "opened and unopened alike");

        // A channel's own creation paperwork is not something the reader is
        // missing. Counting it warns about messages that were never sent —
        // which is exactly what the first version of this did, on a direct
        // message that had been created and never written to.
        s.put_message(
            &[7; 32],
            Kept {
                seq: 3,
                account: key(2),
                posted: 102,
                kind: 0,
                plain: None,
            },
        )
        .unwrap();
        assert_eq!(
            s.held(&[7; 32]).unwrap(),
            2,
            "a system entry is not held content"
        );
        assert_eq!(
            s.held(&[9; 32]).unwrap(),
            0,
            "a different channel is not counted"
        );
    }

    #[test]
    fn unopened_reports_held_entries_that_never_opened() {
        // The distinction this rests on: a NULL body means held and never
        // opened, an empty body means redacted. `redact_message` writes the
        // empty one on purpose so the two survive a restart apart, and a
        // report that confused them would call deleted messages lost history.
        let s = scoped(&seed(1), None);
        assert!(s.unopened(&[7; 32]).unwrap().is_empty(), "nothing held");

        let put = |seq: u64, kind: u8, plain: Option<&[u8]>| {
            s.put_message(
                &[7; 32],
                Kept {
                    seq,
                    account: key(2),
                    posted: 100 + seq,
                    kind,
                    plain,
                },
            )
            .unwrap()
        };
        put(1, 1, Some(b"opened"));
        put(2, 1, None);
        put(3, 0, None);
        put(4, 1, Some(b"also opened"));
        put(5, 1, None);

        assert_eq!(
            s.unopened(&[7; 32]).unwrap(),
            vec![2, 5],
            "only member entries with no body, oldest first"
        );

        // A redaction empties the body rather than nulling it, so a deleted
        // message must not surface as history nobody could read.
        s.redact_message(&[7; 32], 4).unwrap();
        assert_eq!(
            s.unopened(&[7; 32]).unwrap(),
            vec![2, 5],
            "a redacted message is not unopened"
        );

        assert!(
            s.unopened(&[9; 32]).unwrap().is_empty(),
            "a different channel is not counted"
        );
    }

    #[test]
    fn no_key_material_is_on_disk_in_the_clear() {
        // The claim is that secrets are sealed at rest, so test the claim and
        // not a proxy for it: put known bytes in, then look at the actual file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let k = ChannelKey::new([0xab; 32]);
        {
            let mut s = scoped(&seed(1), Some(&path));
            s.put_key(&[7; 32], 1, &k).unwrap();
            let mut pool = Pool::new(&seed(1));
            pool.mint_one_time(4);
            pool.mint_fallback();
            s.save_pool(&pool).unwrap();
            // WAL: force everything into the main file before reading it.
            s.db.pragma_update(None, "wal_checkpoint", "TRUNCATE")
                .unwrap();

            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(32).any(|w| w == [0xab; 32]),
                "the channel key is on disk in the clear"
            );
            for (_, secret) in &pool.save().one_time {
                assert!(
                    !bytes.windows(32).any(|w| w == secret),
                    "a prekey secret is on disk in the clear"
                );
            }
        }
    }

    #[test]
    fn the_pool_survives_a_reopen_and_still_refuses_a_spent_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let spent;
        let kept;
        {
            let mut s = scoped(&seed(1), Some(&path));
            let mut pool = s.pool(&seed(1)).unwrap();
            let published = pool.mint_one_time(4);
            spent = published[0].id;
            kept = published[1].id;
            pool.take(spent).unwrap();
            s.save_pool(&pool).unwrap();
        }
        let s = scoped(&seed(1), Some(&path));
        let mut pool = s.pool(&seed(1)).unwrap();
        assert!(pool.take(spent).is_err(), "a restart forgave a replay");
        assert!(pool.take(kept).is_ok(), "a restart lost a live secret");
    }

    #[test]
    fn a_reopened_pool_does_not_reissue_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let first: Vec<u32>;
        {
            let mut s = scoped(&seed(1), Some(&path));
            let mut pool = s.pool(&seed(1)).unwrap();
            first = pool.mint_one_time(4).iter().map(|p| p.id).collect();
            pool.take(first[0]).unwrap();
            s.save_pool(&pool).unwrap();
        }
        let mut s = scoped(&seed(1), Some(&path));
        let mut pool = s.pool(&seed(1)).unwrap();
        let next: Vec<u32> = pool.mint_one_time(4).iter().map(|p| p.id).collect();
        // Including past the spent one: its row is kept precisely so the
        // counter cannot walk back over it.
        assert!(
            next.iter().all(|id| !first.contains(id)),
            "{first:?} vs {next:?}"
        );
        s.save_pool(&pool).unwrap();
    }

    #[test]
    fn the_replay_set_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let device = key(9);
        {
            let s = scoped(&seed(1), Some(&path));
            s.record_seen(&[7; 32], &device, 1, 0).unwrap();
            s.record_seen(&[7; 32], &device, 1, 1).unwrap();
        }
        let s = scoped(&seed(1), Some(&path));
        let mut replay = s.replay_for(&[7; 32]).unwrap();
        assert!(!replay.accept(&device, 1, 0), "a restart forgot an entry");
        assert!(!replay.accept(&device, 1, 1));
        assert!(replay.accept(&device, 1, 2), "and did not invent one");
        // Scoped per channel: another channel's counters are its own.
        let other = s.replay_for(&[8; 32]).unwrap();
        assert!(other.is_empty());
    }

    #[test]
    fn the_counter_never_walks_backwards() {
        let s = scoped(&seed(1), None);
        s.set_msg_seq(&[7; 32], 1, 5).unwrap();
        s.set_msg_seq(&[7; 32], 1, 3).unwrap();
        assert_eq!(s.cursor(&[7; 32]).unwrap().1, 5, "a stale reply lowered it");
        // A new epoch is a new counter, and that is the one case where a lower
        // number is right.
        s.set_msg_seq(&[7; 32], 2, 0).unwrap();
        let (_, msg_seq, epoch) = s.cursor(&[7; 32]).unwrap();
        assert_eq!((msg_seq, epoch), (0, 2));
    }

    #[test]
    fn contacts_round_trip() {
        let s = scoped(&seed(1), None);
        s.add_contact(&key(2), "bob", 100).unwrap();
        s.add_contact(&key(3), "carol", 101).unwrap();
        s.add_contact(&key(2), "bob on the boat", 102).unwrap();
        let got = s.contacts().unwrap();
        assert_eq!(got.len(), 2, "re-adding renamed rather than duplicated");
        s.remove_contact(&key(3)).unwrap();
        assert_eq!(s.contacts().unwrap().len(), 1);
    }

    #[test]
    fn a_conversation_survives_a_reopen() {
        // The bug this exists for: the fetch cursor was persisted and the
        // messages were not, so a restart showed an empty conversation while
        // the entries sat on the exchange, unopenable a second time.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        {
            let s = scoped(&seed(1), Some(&path));
            s.put_message(
                &[7; 32],
                Kept {
                    seq: 3,
                    account: key(2),
                    posted: 100,
                    kind: 1,
                    plain: Some(b"hello"),
                },
            )
            .unwrap();
            s.put_message(
                &[7; 32],
                Kept {
                    seq: 4,
                    account: key(1),
                    posted: 101,
                    kind: 1,
                    plain: Some(b"hi back"),
                },
            )
            .unwrap();
            // One we could not open: recorded, so the reader can be told.
            s.put_message(
                &[7; 32],
                Kept {
                    seq: 5,
                    account: key(2),
                    posted: 102,
                    kind: 1,
                    plain: None,
                },
            )
            .unwrap();
        }
        let s = scoped(&seed(1), Some(&path));
        let got = s.messages(&[7; 32]).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, 3);
        assert_eq!(got[0].4.as_deref(), Some(&b"hello"[..]));
        assert_eq!(got[1].4.as_deref(), Some(&b"hi back"[..]));
        assert!(
            got[2].4.is_none(),
            "an unopenable entry should stay unopenable"
        );
    }

    #[test]
    fn a_message_is_not_stored_twice() {
        let s = scoped(&seed(1), None);
        s.put_message(
            &[7; 32],
            Kept {
                seq: 3,
                account: key(2),
                posted: 100,
                kind: 1,
                plain: Some(b"once"),
            },
        )
        .unwrap();
        s.put_message(
            &[7; 32],
            Kept {
                seq: 3,
                account: key(2),
                posted: 100,
                kind: 1,
                plain: Some(b"twice"),
            },
        )
        .unwrap();
        let got = s.messages(&[7; 32]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].4.as_deref(), Some(&b"once"[..]));
    }

    #[test]
    fn message_text_is_not_on_disk_in_the_clear() {
        // This is the plaintext of somebody's conversation; it is the most
        // sensitive thing this file holds.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let secret = b"meet me at the usual place";
        {
            let s = scoped(&seed(1), Some(&path));
            s.put_message(
                &[7; 32],
                Kept {
                    seq: 1,
                    account: key(2),
                    posted: 100,
                    kind: 1,
                    plain: Some(secret),
                },
            )
            .unwrap();
            s.db.pragma_update(None, "wal_checkpoint", "TRUNCATE")
                .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret),
            "a message is on disk in the clear"
        );
    }

    #[test]
    fn a_fresh_store_does_not_start_its_ids_at_one() {
        // Found by running the thing: wipe the client's store, keep the
        // identity, and every publish is refused with reused_id — the exchange
        // remembers the ids forever and the client would start again at 1.
        let dir = tempfile::tempdir().unwrap();
        let first: Vec<u32>;
        {
            let mut s = scoped(&seed(1), Some(&dir.path().join("chat.db")));
            let mut pool = s.pool(&seed(1)).unwrap();
            first = pool.mint_one_time(64).iter().map(|p| p.id).collect();
            s.save_pool(&pool).unwrap();
        }
        // The store is gone; the identity is not.
        let mut fresh = scoped(&seed(1), Some(&dir.path().join("new.db")));
        let mut pool = fresh.pool(&seed(1)).unwrap();
        let next: Vec<u32> = pool.mint_one_time(4).iter().map(|p| p.id).collect();
        // The clock floor gets a lost store out of the range it has already
        // used. It is not sufficient on its own — two stores made in the same
        // second get the same ids — which is why the client also asks the
        // exchange what it remembers; see the dm_flow integration test.
        assert!(next[0] > 1_000_000, "ids restarted from the bottom");
        assert_eq!(first.len(), 64);
        let _ = &mut fresh;
    }

    #[test]
    fn a_store_that_has_prekeys_keeps_counting_from_them() {
        // The clock floor applies only to an empty pool: an ordinary reopen
        // must carry on from what it holds, not jump to the wall clock.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let first: Vec<u32>;
        {
            let mut s = scoped(&seed(1), Some(&path));
            let mut pool = s.pool(&seed(1)).unwrap();
            first = pool.mint_one_time(4).iter().map(|p| p.id).collect();
            s.save_pool(&pool).unwrap();
        }
        let s = scoped(&seed(1), Some(&path));
        let mut pool = s.pool(&seed(1)).unwrap();
        let next = pool.mint_one_time(1)[0].id;
        assert_eq!(next, first[3] + 1, "a reopen jumped its counter");
    }

    #[test]
    fn a_channel_and_its_admins_survive_a_reopen() {
        // Timeline needs the admins to judge a redaction or a name change, and
        // a client starting offline would otherwise fold its own history
        // wrongly — showing a redacted message and no channel name.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        {
            let s = scoped(&seed(1), Some(&path));
            s.put_channel(&[7; 32], true, Some(false), "the group", &[key(1), key(2)])
                .unwrap();
            s.put_channel(&[8; 32], false, Some(false), "bob", &[key(1), key(3)])
                .unwrap();
        }
        let s = scoped(&seed(1), Some(&path));
        let got = s.channels().unwrap();
        assert_eq!(got.len(), 2);
        let group = got.iter().find(|c| c.channel == [7; 32]).unwrap();
        assert!(group.group, "the group lost its kind");
        assert_eq!(group.label, "the group");
        assert_eq!(group.admins, vec![key(1), key(2)]);
    }

    #[test]
    fn a_label_and_a_membership_are_set_independently() {
        // They arrive from different places: the name from a sealed entry only
        // members can read, the admins from the exchange.
        let s = scoped(&seed(1), None);
        s.put_channel(&[7; 32], true, Some(false), "", &[key(1)])
            .unwrap();
        s.set_label(&[7; 32], "renamed").unwrap();
        let got = s.channels().unwrap();
        assert_eq!(got[0].label, "renamed");
        assert_eq!(
            got[0].admins,
            vec![key(1)],
            "setting a label dropped the admins"
        );
    }

    /// What a channel is survives being written down.
    ///
    /// The point of the whole thing: a client restoring its list from disk
    /// used to know only "group or not", so it could not tell a private group
    /// from a public channel and drew neither mark until the exchange
    /// answered.
    #[test]
    fn a_public_channel_and_a_private_group_are_told_apart_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        {
            let s = scoped(&seed(1), Some(&path));
            s.put_channel(&[1; 32], true, Some(true), "public", &[])
                .unwrap();
            s.put_channel(&[2; 32], true, Some(false), "private", &[])
                .unwrap();
            s.put_channel(&[3; 32], false, Some(false), "bob", &[])
                .unwrap();
            // A group whose kind nobody has said yet.
            s.put_channel(&[4; 32], true, None, "unanswered", &[])
                .unwrap();
        }
        let s = scoped(&seed(1), Some(&path));
        let got = s.channels().unwrap();
        let of = |id: [u8; 32]| got.iter().find(|c| c.channel == id).unwrap().clone();

        assert_eq!(of([1; 32]).public, Some(true), "a public channel");
        assert_eq!(of([2; 32]).public, Some(false), "a private group");
        assert_eq!(of([3; 32]).public, Some(false), "a direct message");
        assert_eq!(
            of([4; 32]).public,
            None,
            "a group nobody has answered for must stay unanswered, not become \
             private -- that claim is the one that would be a lie"
        );
        // And all four still know whether they are a group.
        assert!(of([1; 32]).group);
        assert!(of([2; 32]).group);
        assert!(!of([3; 32]).group, "a direct message is not a group");
        assert!(of([4; 32]).group);
    }

    /// A row written by a client that had never heard of this reads as a group
    /// of unknown kind -- never as a private one.
    ///
    /// Written as raw SQL, because the point is a row this code did **not**
    /// write. Building the "old" row with the new encoding would test the new
    /// encoding against itself.
    #[test]
    fn a_row_from_before_this_is_a_group_of_unknown_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        {
            let s = scoped(&seed(1), Some(&path));
            // Exactly what every client up to v0.46 wrote for a group.
            s.db.execute(
                "INSERT INTO channel_meta (channel, kind, label, admins, exchange)
                 VALUES (?1, 1, 'old', x'', ?2)",
                params![&[9u8; 32][..], s.scope().unwrap()],
            )
            .unwrap();
        }
        let s = scoped(&seed(1), Some(&path));
        let got = s.channels().unwrap();
        let old = got.iter().find(|c| c.channel == [9; 32]).unwrap();
        assert!(old.group, "it is still a group");
        assert_eq!(
            old.public, None,
            "a row that never recorded the answer must not be read as having \
             given one"
        );
    }

    /// And a value from a **newer** client than this one claims nothing it
    /// cannot support.
    #[test]
    fn a_kind_from_the_future_is_a_group_of_unknown_kind() {
        assert_eq!(Kind::from_i64(4).public(), None);
        assert!(Kind::from_i64(4).group());
        assert_eq!(Kind::from_i64(-1).public(), None);
    }

    /// Every kind survives the trip through the column, which is what lets an
    /// old client keep reading a store a new one has written: it asks
    /// `kind != 0`, and 2 and 3 answer "a group", which they are.
    #[test]
    fn the_column_round_trips_and_stays_readable_to_an_old_client() {
        for (group, public) in [
            (false, Some(false)),
            (true, None),
            (true, Some(false)),
            (true, Some(true)),
        ] {
            let kind = Kind::of(group, public);
            assert_eq!(Kind::from_i64(kind.as_i64()), kind, "{group} {public:?}");
            assert_eq!(kind.group(), group);
            assert_eq!(kind.public(), public);
            // The old reader, written out rather than described.
            assert_eq!(kind.as_i64() != 0, group, "an old client would disagree");
        }
    }

    /// A kept blob comes back as it went in, chunk boundaries and all.
    #[test]
    fn a_kept_blob_round_trips_with_its_chunks_intact() {
        let s = scoped(&seed(1), None);
        let chunks = vec![vec![1u8; 100], vec![2u8; 50], vec![3u8; 7]];
        let id = sqex_proto::blob_store::blob_id(&chunks);
        s.keep_blob(&id, &chunks).unwrap();
        assert_eq!(s.blob(&id).unwrap().as_deref(), Some(chunks.as_slice()));
        assert_eq!(s.blob_bytes().unwrap(), 157);
        assert!(s.blob(&[0u8; 32]).unwrap().is_none(), "one never kept");
        assert!(s.has_blob(&id).unwrap());
        assert!(!s.has_blob(&[0u8; 32]).unwrap(), "one never kept");
        s.forget_blob(&id).unwrap();
        assert!(!s.has_blob(&id).unwrap(), "put down");
    }

    /// A row the disc has damaged is caught on the way out, and put down.
    ///
    /// The id is the hash of the chunks, so this is the same check a served
    /// blob gets -- a kept one is held to no lower a standard than the
    /// exchange is. Written with raw SQL, because the point is bytes this
    /// code did not write.
    #[test]
    fn a_rotted_blob_is_refused_and_put_down() {
        let s = scoped(&seed(1), None);
        let chunks = vec![vec![9u8; 64]];
        let id = sqex_proto::blob_store::blob_id(&chunks);
        s.keep_blob(&id, &chunks).unwrap();
        // One byte turned, in the middle of the chunk.
        s.db.execute(
            "UPDATE blob SET sealed = ?1 WHERE blob = ?2",
            params![
                {
                    let mut f = super::frame(&chunks);
                    f[20] ^= 0x40;
                    f
                },
                &id[..]
            ],
        )
        .unwrap();
        assert!(
            s.blob(&id).unwrap().is_none(),
            "a damaged row was handed back"
        );
        assert_eq!(s.blob_bytes().unwrap(), 0, "and it was not put down");
    }

    /// Past the budget, the least recently *read* goes, and only enough of
    /// them. Not the oldest kept: a picture somebody keeps coming back to
    /// stays, whatever its age.
    #[test]
    fn the_least_recently_read_blobs_are_put_down_to_fit_the_budget() {
        let s = scoped(&seed(1), None);
        let one = vec![vec![1u8; 100]];
        let two = vec![vec![2u8; 100]];
        let three = vec![vec![3u8; 100]];
        let (a, b, c) = (
            sqex_proto::blob_store::blob_id(&one),
            sqex_proto::blob_store::blob_id(&two),
            sqex_proto::blob_store::blob_id(&three),
        );
        // `used` is in whole seconds, so the order is forced by hand rather
        // than by sleeping through it.
        s.keep_blob_within(&a, &one, 1000).unwrap();
        s.db.execute("UPDATE blob SET used = 10 WHERE blob = ?1", params![&a[..]])
            .unwrap();
        s.keep_blob_within(&b, &two, 1000).unwrap();
        s.db.execute("UPDATE blob SET used = 20 WHERE blob = ?1", params![&b[..]])
            .unwrap();
        // Read `a` again: it is the oldest kept and the most recently used.
        assert!(s.blob(&a).unwrap().is_some());
        s.db.execute("UPDATE blob SET used = 30 WHERE blob = ?1", params![&a[..]])
            .unwrap();

        // Room for two; the third pushes one out, and it is `b`.
        s.keep_blob_within(&c, &three, 250).unwrap();
        assert!(s.blob(&a).unwrap().is_some(), "the most recently read went");
        assert!(
            s.blob(&b).unwrap().is_none(),
            "the least recently read stayed"
        );
        assert!(s.blob(&c).unwrap().is_some(), "the one just kept went");
        assert_eq!(s.blob_bytes().unwrap(), 200);
    }

    /// Nothing bigger than the cap is kept. Anything that size was a file
    /// somebody asked to save, and would put down everything else to stay.
    #[test]
    fn an_oversized_blob_is_not_kept() {
        let s = scoped(&seed(1), None);
        let big = vec![vec![0u8; (BLOB_KEEP_MAX + 1) as usize]];
        let id = sqex_proto::blob_store::blob_id(&big);
        s.keep_blob(&id, &big).unwrap();
        assert!(s.blob(&id).unwrap().is_none());
        assert_eq!(s.blob_bytes().unwrap(), 0);
    }

    /// Framing survives an empty chunk and a run of them.
    #[test]
    fn framing_round_trips_edge_cases() {
        for chunks in [
            vec![],
            vec![vec![]],
            vec![vec![], vec![1u8]],
            vec![vec![7u8; 3]; 4],
        ] {
            assert_eq!(
                super::unframe(&super::frame(&chunks)).as_ref(),
                Some(&chunks)
            );
        }
        assert!(
            super::unframe(&[1, 0, 0, 0]).is_none(),
            "a length with no bytes after it"
        );
    }

    #[test]
    fn forgetting_a_channel_removes_it() {
        let s = scoped(&seed(1), None);
        s.put_channel(&[7; 32], true, Some(false), "gone", &[])
            .unwrap();
        s.forget_channel(&[7; 32]).unwrap();
        assert!(s.channels().unwrap().is_empty());
    }
}

/// The migration, and the claim that follows it.
///
/// These run against a **copy** of a store built in the old shape, never
/// against a real one. Losing this file loses the conversations in it for
/// everybody in them, so the migration is the one piece of this codebase where
/// "it worked when I tried it" is not a standard worth meeting.
#[cfg(test)]
mod migration {
    use super::*;

    /// The schema as it stood before rows carried an exchange.
    ///
    /// Kept verbatim rather than generated, because a migration test that
    /// builds its "old" database with the *new* code is testing nothing: it
    /// would pass whatever the migration did, including nothing at all.
    const OLD: &str = r#"
CREATE TABLE contact (account BLOB PRIMARY KEY, label TEXT NOT NULL, added INTEGER NOT NULL);
CREATE TABLE channel_key (channel BLOB NOT NULL, epoch INTEGER NOT NULL, sealed BLOB NOT NULL,
    PRIMARY KEY (channel, epoch));
CREATE TABLE prekey (id INTEGER PRIMARY KEY, kind INTEGER NOT NULL, sealed BLOB,
    spent INTEGER NOT NULL DEFAULT 0);
CREATE TABLE message (channel BLOB NOT NULL, seq INTEGER NOT NULL, account BLOB NOT NULL,
    posted INTEGER NOT NULL, kind INTEGER NOT NULL, sealed BLOB, PRIMARY KEY (channel, seq));
CREATE TABLE channel_meta (channel BLOB PRIMARY KEY, kind INTEGER NOT NULL DEFAULT 0,
    label TEXT NOT NULL DEFAULT '', admins BLOB NOT NULL DEFAULT x'');
CREATE TABLE seen (channel BLOB NOT NULL, device BLOB NOT NULL, epoch INTEGER NOT NULL,
    msg_seq INTEGER NOT NULL, PRIMARY KEY (channel, device, epoch, msg_seq));
CREATE TABLE cursor (channel BLOB PRIMARY KEY, since INTEGER NOT NULL DEFAULT 0,
    msg_seq INTEGER NOT NULL DEFAULT 0, epoch INTEGER NOT NULL DEFAULT 0);
CREATE TABLE chain (channel BLOB PRIMARY KEY, chain_seq INTEGER NOT NULL, head BLOB NOT NULL);
CREATE TABLE incarnation (channel BLOB PRIMARY KEY, instance BLOB NOT NULL,
    announce INTEGER NOT NULL DEFAULT 0);
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE profile (account BLOB PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '', fetched INTEGER NOT NULL DEFAULT 0);
CREATE TABLE handle (account BLOB PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
    fetched INTEGER NOT NULL DEFAULT 0);
"#;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// A store in the old shape, with something in every table that matters.
    fn an_old_store(path: &std::path::Path) {
        let db = Connection::open(path).unwrap();
        db.execute_batch(OLD).unwrap();
        db.execute(
            "INSERT INTO channel_key (channel, epoch, sealed) VALUES (?1, 3, ?2)",
            params![&[7u8; 32][..], &b"a sealed key"[..]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO message (channel, seq, account, posted, kind, sealed)
             VALUES (?1, 1, ?2, 100, 1, ?3)",
            params![&[7u8; 32][..], &[2u8; 32][..], &b"a sealed body"[..]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO seen (channel, device, epoch, msg_seq) VALUES (?1, ?2, 3, 9)",
            params![&[7u8; 32][..], &[2u8; 32][..]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO cursor (channel, since, msg_seq, epoch) VALUES (?1, 5, 9, 3)",
            params![&[7u8; 32][..]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO chain (channel, chain_seq, head) VALUES (?1, 4, ?2)",
            params![&[7u8; 32][..], &[8u8; 32][..]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO channel_meta (channel, kind, label, admins)
             VALUES (?1, 1, 'the old room', x'')",
            params![&[7u8; 32][..]],
        )
        .unwrap();
    }

    fn count(db: &Connection, table: &str) -> i64 {
        db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn an_old_store_keeps_every_row_and_gains_the_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        an_old_store(&path);

        // Before: no exchange anywhere. This is the negative control for the
        // test itself — if the fixture were already in the new shape, the
        // migration would be a no-op and everything below would pass without
        // testing it.
        {
            let db = Connection::open(&path).unwrap();
            let has: bool = db
                .prepare("SELECT 1 FROM pragma_table_info('channel_key') WHERE name = 'exchange'")
                .unwrap()
                .exists([])
                .unwrap();
            assert!(!has, "the fixture must start in the old shape");
        }

        let mut store = Store::open(&seed(1), Some(&path)).unwrap();
        store.scope_to(&PubKey::new([9; 32])).unwrap();

        let db = Connection::open(&path).unwrap();
        for table in [
            "channel_key",
            "message",
            "seen",
            "cursor",
            "chain",
            "channel_meta",
        ] {
            assert_eq!(count(&db, table), 1, "{table} lost its row");
            let has: bool = db
                .prepare(&format!(
                    "SELECT 1 FROM pragma_table_info('{table}') WHERE name = 'exchange'"
                ))
                .unwrap()
                .exists([])
                .unwrap();
            assert!(has, "{table} did not gain the column");
        }
    }

    #[test]
    fn the_first_exchange_claims_what_predates_the_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        an_old_store(&path);

        let mine = PubKey::new([9; 32]);
        let mut store = Store::open(&seed(1), Some(&path)).unwrap();
        store.scope_to(&mine).unwrap();

        // Rows that were there before are now this exchange's, and readable.
        assert_eq!(store.highest_epoch(&[7; 32]).unwrap(), 3);
        assert_eq!(store.cursor(&[7; 32]).unwrap(), (5, 9, 3));
        // `chain` reports the *next* position to sign at, so a stored 4 reads
        // back as 5. Asserting the stored number would have been asserting the
        // fixture rather than the migration.
        assert_eq!(store.chain(&[7; 32]).unwrap().0, 5);

        let db = Connection::open(&path).unwrap();
        let unclaimed: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM channel_key WHERE exchange = ?1",
                params![&Store::UNCLAIMED[..]],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(unclaimed, 0, "nothing may be left unattributed");
    }

    #[test]
    fn a_second_exchange_does_not_take_the_first_ones_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        an_old_store(&path);

        let first = PubKey::new([9; 32]);
        let second = PubKey::new([10; 32]);
        let mut a = Store::open(&seed(1), Some(&path)).unwrap();
        a.scope_to(&first).unwrap();
        drop(a);

        // The claim is recorded, so opening against another exchange finds
        // nothing to take -- and sees none of the first one's rows.
        let mut b = Store::open(&seed(1), Some(&path)).unwrap();
        b.scope_to(&second).unwrap();
        assert_eq!(
            b.highest_epoch(&[7; 32]).unwrap(),
            0,
            "the second exchange must not inherit the first one's keys"
        );
        assert_eq!(b.cursor(&[7; 32]).unwrap(), (0, 0, 0));

        // And the first still has them.
        let mut a = Store::open(&seed(1), Some(&path)).unwrap();
        a.scope_to(&first).unwrap();
        assert_eq!(a.highest_epoch(&[7; 32]).unwrap(), 3);
    }

    /// The whole reason the column exists.
    ///
    /// A direct message's channel identifier is derived from its two accounts,
    /// so one conversation has **identical channel bytes on every exchange**.
    /// Two exchanges' rows for it must not collide.
    #[test]
    fn two_exchanges_keep_separate_rows_for_one_channel_identifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");

        let one = ChannelKey::generate();
        let two = ChannelKey::generate();
        assert_ne!(one, two);

        let mut a = Store::open(&seed(1), Some(&path)).unwrap();
        a.scope_to(&PubKey::new([9; 32])).unwrap();
        a.put_key(&[7; 32], 1, &one).unwrap();

        let mut b = Store::open(&seed(1), Some(&path)).unwrap();
        b.scope_to(&PubKey::new([10; 32])).unwrap();
        b.put_key(&[7; 32], 1, &two).unwrap();

        // Without the column these are one row, and the second `put_key` is a
        // no-op: `ON CONFLICT DO NOTHING`. One of the two conversations would
        // then be sealed under a key this client does not hold, and opening an
        // epoch key spends the prekey it came in on -- so it would not be
        // recoverable by asking again.
        assert_eq!(a.key(&[7; 32], 1).unwrap().unwrap(), one);
        assert_eq!(b.key(&[7; 32], 1).unwrap().unwrap(), two);
    }

    /// SIP-17's replay set is per exchange too.
    ///
    /// Shared, a counter used at one exchange marks the identical coordinates
    /// at another as already seen — and a genuine message is **silently
    /// dropped as a replay**. This table was not in the original list of what
    /// needed the column; it was found by reading each one.
    #[test]
    fn the_replay_set_does_not_reject_another_exchanges_messages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let device = PubKey::new([2; 32]);

        let mut a = Store::open(&seed(1), Some(&path)).unwrap();
        a.scope_to(&PubKey::new([9; 32])).unwrap();
        a.record_seen(&[7; 32], &device, 1, 5).unwrap();
        // `accept` returns false for a counter already used, which is the
        // rejection this table exists to make.
        assert!(
            !a.replay_for(&[7; 32]).unwrap().accept(&device, 1, 5),
            "the exchange that saw it rejects it as a replay"
        );

        let mut b = Store::open(&seed(1), Some(&path)).unwrap();
        b.scope_to(&PubKey::new([10; 32])).unwrap();
        assert!(
            b.replay_for(&[7; 32]).unwrap().accept(&device, 1, 5),
            "another exchange's counter is not this one's replay, and a message \
             at the same coordinates there must not be silently dropped"
        );
    }

    #[test]
    fn an_unscoped_store_refuses_rather_than_guessing() {
        // Reading the contact list needs no exchange, which is what lets the
        // CLI's `add` work before anything connects.
        let store = Store::open(&seed(1), None).unwrap();
        assert!(store.contacts().is_ok());
        // Anything about a channel does, and says so rather than answering
        // from rows nobody claimed.
        assert!(store.highest_epoch(&[7; 32]).is_err());
    }

    /// A store older than some of the tables the migration rebuilds.
    ///
    /// # Why this is not the same fixture with a row removed
    ///
    /// `OLD` is the schema as it stood at **one** moment. A store on somebody's
    /// disk is the schema as it stood at whatever moment they last opened it,
    /// and `handle` arrived with SIP-38 while `profile` arrived before that —
    /// so a real store can have `channel_key` and neither of those. The
    /// migration decided "this store predates the exchange column" by asking
    /// `channel_key` alone and then rebuilt all nine tables as though a store
    /// were a single version, and failed with `no such table: handle`.
    ///
    /// Twelve of the fourteen stores on the machine where this was found were
    /// in exactly that shape, and none of them would open.
    #[test]
    fn a_store_older_than_the_tables_it_lacks_still_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("older.db");
        {
            let db = Connection::open(&path).unwrap();
            // Everything `OLD` has except the two tables that came later.
            let older: String = OLD
                .lines()
                .collect::<Vec<_>>()
                .join("\n")
                .replace(
                    "CREATE TABLE profile (account BLOB PRIMARY KEY, name TEXT NOT NULL DEFAULT '',\n    title TEXT NOT NULL DEFAULT '', fetched INTEGER NOT NULL DEFAULT 0);",
                    "",
                )
                .replace(
                    "CREATE TABLE handle (account BLOB PRIMARY KEY, name TEXT NOT NULL DEFAULT '',\n    fetched INTEGER NOT NULL DEFAULT 0);",
                    "",
                );
            assert!(
                !older.contains("CREATE TABLE handle") && !older.contains("CREATE TABLE profile"),
                "the fixture still has the tables this is about"
            );
            db.execute_batch(&older).unwrap();
            db.execute(
                "INSERT INTO channel_key (channel, epoch, sealed) VALUES (?1, 3, ?2)",
                params![&[7u8; 32][..], &b"a sealed key"[..]],
            )
            .unwrap();
        }

        // Opening it at all is the thing: this failed with
        // `no such table: handle` and the store could not be used.
        let _store = Store::open(&seed(1), Some(&path)).expect("an older store still opens");

        // Read back through SQL rather than the store's accessors: the
        // fixture's `sealed` bytes are a placeholder and not real ciphertext,
        // so decrypting one would fail for a reason that has nothing to do
        // with the migration.
        let db = Connection::open(&path).unwrap();
        let rows: i64 = db
            .query_row("SELECT count(*) FROM channel_key", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "the row did not survive the rebuild");
        let has_exchange: bool = db
            .prepare("SELECT 1 FROM pragma_table_info('channel_key') WHERE name = 'exchange'")
            .and_then(|mut s| s.exists([]))
            .unwrap();
        assert!(has_exchange, "the table it did have was not migrated");
        // And the tables it never had are there now, in the new shape — the
        // schema creates them, which is why the migration can skip them.
        for missing in ["handle", "profile"] {
            let made: bool = db
                .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1")
                .and_then(|mut s| s.exists(params![missing]))
                .unwrap();
            assert!(made, "{missing} was skipped and never created");
            let scoped: bool = db
                .prepare(&format!(
                    "SELECT 1 FROM pragma_table_info('{missing}') WHERE name = 'exchange'"
                ))
                .and_then(|mut s| s.exists([]))
                .unwrap();
            assert!(scoped, "{missing} was created in the old shape");
        }
    }

    #[test]
    fn migrating_twice_is_not_a_second_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        an_old_store(&path);
        for _ in 0..3 {
            let mut s = Store::open(&seed(1), Some(&path)).unwrap();
            s.scope_to(&PubKey::new([9; 32])).unwrap();
            assert_eq!(s.highest_epoch(&[7; 32]).unwrap(), 3);
        }
    }
}

#[cfg(test)]
mod locking {
    use super::*;

    fn an_exchange(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    /// Two clients on one account **at one exchange** still conflict.
    ///
    /// That is what the lock is for: they would each keep their own idea of
    /// the next SIP-17 counter, and reusing one costs the confidentiality of
    /// two messages.
    #[test]
    fn one_account_at_one_exchange_is_still_one_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let first = lock(&path, &an_exchange(9)).unwrap();
        assert!(lock(&path, &an_exchange(9)).is_err());
        drop(first);
        assert!(lock(&path, &an_exchange(9)).is_ok());
    }

    /// One account at **two** exchanges is two clients, and always was.
    ///
    /// Since the store scopes rows by exchange there is a counter per pair, so
    /// there is nothing here for them to disagree about. A lock per account
    /// would refuse the second for a conflict that does not exist.
    #[test]
    fn one_account_at_two_exchanges_is_not_a_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let _first = lock(&path, &an_exchange(9)).unwrap();
        assert!(
            lock(&path, &an_exchange(10)).is_ok(),
            "a second exchange shares no counter with the first"
        );
    }
}

#[cfg(test)]
mod against_real_stores {
    use super::*;

    /// Every store this machine actually holds, opened from a **copy**.
    ///
    /// Ignored by default: it reads whatever is in `~/.sqex/chat`, which is
    /// nothing on a build machine and somebody's whole conversation history on
    /// a real one. Run it deliberately, and never against the originals — the
    /// copy is the point.
    ///
    /// This is the check the fixture could not be: `OLD` is the schema at one
    /// moment and these files are the schema at fourteen different ones.
    #[test]
    #[ignore = "reads ~/.sqex/chat; run deliberately with --ignored"]
    fn every_store_on_this_machine_opens() {
        let from = match std::env::var("SQEX_STORE_COPIES") {
            Ok(d) => std::path::PathBuf::from(d),
            Err(_) => return,
        };
        let mut looked = 0;
        for entry in std::fs::read_dir(&from).expect("the copies") {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "db") {
                continue;
            }
            looked += 1;
            Store::open(&[1u8; 32], Some(&path))
                .unwrap_or_else(|e| panic!("{} would not open: {e}", path.display()));
        }
        assert!(
            looked > 0,
            "no stores were looked at, so nothing was tested"
        );
        eprintln!("opened {looked} stores");
    }
}
