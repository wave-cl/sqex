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
    channel BLOB    NOT NULL,
    epoch   INTEGER NOT NULL,
    sealed  BLOB    NOT NULL,
    PRIMARY KEY (channel, epoch)
);
-- SIP-23's pool, made durable. `spent` is as load-bearing as the secret: a
-- restart that forgot it would forgive a replay this client had already caught.
CREATE TABLE IF NOT EXISTS prekey (
    id     INTEGER PRIMARY KEY,
    kind   INTEGER NOT NULL,
    sealed BLOB,
    spent  INTEGER NOT NULL DEFAULT 0
);
-- The conversation itself, decrypted once and kept.
--
-- Not a cache. SIP-17 forbids decrypting a counter twice, and the exchange
-- serves an epoch key's envelope only once, so a message this client does not
-- keep is one it can never read again — the entry stays on the exchange and
-- stays shut. Sealed at rest like the keys, because this is the plaintext.
CREATE TABLE IF NOT EXISTS message (
    channel BLOB    NOT NULL,
    seq     INTEGER NOT NULL,
    account BLOB    NOT NULL,
    posted  INTEGER NOT NULL,
    kind    INTEGER NOT NULL,
    sealed  BLOB,
    PRIMARY KEY (channel, seq)
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
    channel BLOB PRIMARY KEY,
    kind    INTEGER NOT NULL DEFAULT 0,   -- 0 direct message, 1 group
    label   TEXT    NOT NULL DEFAULT '',
    admins  BLOB    NOT NULL DEFAULT x''  -- concatenated 32-byte accounts
);
-- SIP-17's replay set. Not secret — it is a list of counters the exchange
-- already published in entry headers — so it is stored in the clear.
CREATE TABLE IF NOT EXISTS seen (
    channel BLOB    NOT NULL,
    device  BLOB    NOT NULL,
    epoch   INTEGER NOT NULL,
    msg_seq INTEGER NOT NULL,
    PRIMARY KEY (channel, device, epoch, msg_seq)
);
-- How far we have read, and how far we have counted.
CREATE TABLE IF NOT EXISTS cursor (
    channel  BLOB PRIMARY KEY,
    since    INTEGER NOT NULL DEFAULT 0,
    msg_seq  INTEGER NOT NULL DEFAULT 0,
    epoch    INTEGER NOT NULL DEFAULT 0
);
-- SIP-31 chain state: where this device stands in each channel.
--
-- Ours to keep, and the reason we keep it rather than asking is in SIP-31: a
-- client that took the exchange's reported position on trust could be told a
-- lower one, sign a second entry at a position it had already used, and produce
-- a fork that reads as its own misconduct. We resume from the greater of this
-- and what we are told.
CREATE TABLE IF NOT EXISTS chain (
    channel   BLOB PRIMARY KEY,
    chain_seq INTEGER NOT NULL,
    head      BLOB    NOT NULL
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
    channel  BLOB PRIMARY KEY,
    instance BLOB NOT NULL,
    -- Set when the incarnation changed under us and we cleared this channel,
    -- and cleared when a poll has reported it. Durable, because a client that
    -- reset and then stopped should still say so when it comes back: the reset
    -- is the whole reason the conversation above the divider is not the one
    -- below it.
    announce INTEGER NOT NULL DEFAULT 0
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
    account BLOB PRIMARY KEY,
    name    TEXT    NOT NULL DEFAULT '',
    title   TEXT    NOT NULL DEFAULT '',
    fetched INTEGER NOT NULL DEFAULT 0
);
"#;

pub struct Store {
    db: Connection,
    cipher: ChaCha20Poly1305,
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
        db.execute_batch(SCHEMA).map_err(storage("create schema"))?;

        let mut h = Sha512::new();
        h.update(STORE_CONTEXT);
        h.update(seed);
        let okm = h.finalize();
        let cipher = ChaCha20Poly1305::new_from_slice(&okm[0..32])
            .map_err(|e| StoreError::Sealed(format!("derive store key: {e}")))?;

        Ok(Store { db, cipher })
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
                "INSERT INTO channel_key (channel, epoch, sealed) VALUES (?1, ?2, ?3)
                 ON CONFLICT (channel, epoch) DO NOTHING",
                params![&channel[..], epoch as i64, sealed],
            )
            .map_err(storage("store channel key"))?;
        Ok(())
    }

    pub fn key(&self, channel: &[u8; 32], epoch: u32) -> Result<Option<ChannelKey>> {
        let sealed: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT sealed FROM channel_key WHERE channel = ?1 AND epoch = ?2",
                params![&channel[..], epoch as i64],
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
                "SELECT MAX(epoch) FROM channel_key WHERE channel = ?1",
                params![&channel[..]],
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
            .prepare("SELECT id, kind, sealed, spent FROM prekey")
            .map_err(storage("prepare prekeys"))?;
        let rows = stmt
            .query_map([], |r| {
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
                "INSERT INTO prekey (id, kind, sealed, spent) VALUES (?1, ?2, ?3, 0)
                 ON CONFLICT (id) DO UPDATE SET sealed = ?3, spent = 0",
                params![*id as i64, KIND_ONE_TIME as i64, sealed],
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
                "INSERT INTO prekey (id, kind, sealed, spent) VALUES (?1, ?2, ?3, 0)
                 ON CONFLICT (id) DO UPDATE SET sealed = ?3, spent = 0",
                params![*id as i64, KIND_FALLBACK as i64, sealed],
            )
            .map_err(storage("store fallback"))?;
        }
        for id in &state.spent {
            tx.execute(
                "INSERT INTO prekey (id, kind, sealed, spent) VALUES (?1, ?2, NULL, 1)
                 ON CONFLICT (id) DO UPDATE SET sealed = NULL, spent = 1",
                params![*id as i64, KIND_ONE_TIME as i64],
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
            .prepare("SELECT device, epoch, msg_seq FROM seen WHERE channel = ?1")
            .map_err(storage("prepare seen"))?;
        let rows = stmt
            .query_map(params![&channel[..]], |r| {
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
                "INSERT OR IGNORE INTO seen (channel, device, epoch, msg_seq)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    &channel[..],
                    device.as_bytes(),
                    epoch as i64,
                    msg_seq as i64
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
                "INSERT INTO message (channel, seq, account, posted, kind, sealed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (channel, seq)
                 DO UPDATE SET sealed = COALESCE(message.sealed, excluded.sealed)",
                params![
                    &channel[..],
                    seq as i64,
                    account.as_bytes(),
                    posted as i64,
                    kind as i64,
                    sealed
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
        let empty = self.seal_bytes(&[])?;
        self.db
            .execute(
                "UPDATE message SET sealed = ?3 WHERE channel = ?1 AND seq = ?2",
                params![&channel[..], seq as i64, empty],
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
                "SELECT COUNT(*) FROM message WHERE channel = ?1 AND kind = ?2",
                params![&channel[..], KIND_MEMBER],
                |r| r.get(0),
            )
            .map_err(storage("count held"))?;
        Ok(n as usize)
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
                 WHERE channel = ?1 ORDER BY seq ASC",
            )
            .map_err(storage("prepare messages"))?;
        let rows = stmt
            .query_map(params![&channel[..]], |r| {
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
                "INSERT INTO profile (account, name, title, fetched)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (account) DO UPDATE SET name = ?2, title = ?3, fetched = ?4",
                params![account.as_bytes(), name, title, now as i64],
            )
            .map_err(storage("store profile"))?;
        Ok(())
    }

    /// The name and title we hold for an account, and when we asked.
    pub fn profile(&self, account: &PubKey) -> Result<Option<(String, String, u64)>> {
        self.db
            .query_row(
                "SELECT name, title, fetched FROM profile WHERE account = ?1",
                params![account.as_bytes()],
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
        label: &str,
        admins: &[PubKey],
    ) -> Result<()> {
        let mut flat = Vec::with_capacity(admins.len() * 32);
        for a in admins {
            flat.extend_from_slice(a.as_bytes());
        }
        self.db
            .execute(
                "INSERT INTO channel_meta (channel, kind, label, admins)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (channel) DO UPDATE SET kind = ?2, label = ?3, admins = ?4",
                params![&channel[..], i64::from(group), label, flat],
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
                "INSERT INTO channel_meta (channel, label) VALUES (?1, ?2)
                 ON CONFLICT (channel) DO UPDATE SET label = ?2",
                params![&channel[..], label],
            )
            .map_err(storage("set label"))?;
        Ok(())
    }

    /// Every channel this client knows about: id, group, label, admins.
    #[allow(clippy::type_complexity)]
    pub fn channels(&self) -> Result<Vec<([u8; 32], bool, String, Vec<PubKey>)>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT channel, kind, label, admins FROM channel_meta ORDER BY label, channel",
            )
            .map_err(storage("prepare channels"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32]),
                    r.get::<_, i64>(1)? != 0,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(storage("query channels"))?;
        let mut out = Vec::new();
        for row in rows {
            let (channel, group, label, flat) = row.map_err(storage("read channel"))?;
            let admins = flat
                .as_chunks::<32>()
                .0
                .iter()
                .map(|c| PubKey::new(*c))
                .collect();
            out.push((channel, group, label, admins));
        }
        Ok(out)
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
                "SELECT instance FROM incarnation WHERE channel = ?1",
                params![&channel[..]],
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
                "INSERT INTO incarnation (channel, instance, announce) VALUES (?1, ?2, ?3)
                 ON CONFLICT (channel) DO UPDATE SET instance = ?2, announce = ?3",
                params![&channel[..], &instance[..], i64::from(announce)],
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
                "SELECT announce FROM incarnation WHERE channel = ?1",
                params![&channel[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read announcement"))?;
        if pending == Some(1) {
            self.db
                .execute(
                    "UPDATE incarnation SET announce = 0 WHERE channel = ?1",
                    params![&channel[..]],
                )
                .map_err(storage("clear announcement"))?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn reset_sequence_space(&self, channel: &[u8; 32]) -> Result<()> {
        for sql in [
            "DELETE FROM message WHERE channel = ?1",
            "DELETE FROM seen WHERE channel = ?1",
            "DELETE FROM channel_key WHERE channel = ?1",
            "DELETE FROM cursor WHERE channel = ?1",
            // SIP-31 chain state, for the same reason as the rest: a recreated
            // channel is a different channel, and a position carried into it
            // is one the exchange has no record of — every signature after it
            // refused as a broken chain, for good.
            "DELETE FROM chain WHERE channel = ?1",
        ] {
            self.db
                .execute(sql, params![&channel[..]])
                .map_err(storage("reset sequence space"))?;
        }
        Ok(())
    }

    pub fn forget_channel(&self, channel: &[u8; 32]) -> Result<()> {
        self.db
            .execute(
                "DELETE FROM channel_meta WHERE channel = ?1",
                params![&channel[..]],
            )
            .map_err(storage("forget channel"))?;
        Ok(())
    }

    // ---- cursors --------------------------------------------------------

    pub fn cursor(&self, channel: &[u8; 32]) -> Result<(u64, u64, u32)> {
        Ok(self
            .db
            .query_row(
                "SELECT since, msg_seq, epoch FROM cursor WHERE channel = ?1",
                params![&channel[..]],
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
                "UPDATE cursor SET since = 0 WHERE channel = ?1",
                params![&channel[..]],
            )
            .map_err(storage("rewind"))?;
        Ok(())
    }

    pub fn set_since(&self, channel: &[u8; 32], since: u64) -> Result<()> {
        self.db
            .execute(
                "INSERT INTO cursor (channel, since) VALUES (?1, ?2)
                 ON CONFLICT (channel) DO UPDATE SET since = MAX(since, ?2)",
                params![&channel[..], since as i64],
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
                "SELECT chain_seq, head FROM chain WHERE channel = ?1",
                params![&channel[..]],
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
                "INSERT INTO chain (channel, chain_seq, head) VALUES (?1, ?2, ?3)
                 ON CONFLICT (channel) DO UPDATE SET
                     chain_seq = MAX(chain_seq, ?2),
                     head      = CASE WHEN ?2 >= chain_seq THEN ?3 ELSE head END",
                params![&channel[..], chain_seq as i64, &head[..]],
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
                "INSERT INTO cursor (channel, epoch, msg_seq) VALUES (?1, ?2, ?3)
                 ON CONFLICT (channel) DO UPDATE SET
                     msg_seq = CASE WHEN ?2 > epoch THEN ?3 ELSE MAX(msg_seq, ?3) END,
                     epoch   = MAX(epoch, ?2)",
                params![&channel[..], epoch as i64, msg_seq as i64],
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
pub fn lock(path: &std::path::Path) -> Result<Lock> {
    use std::io::{Read, Seek, Write};

    let at = path.with_extension("lock");
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

        let first = lock(&path).unwrap();
        let second = lock(&path);
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
        lock(&path).expect("the lock outlived the client that took it");
    }

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    #[test]
    fn a_channel_key_round_trips() {
        let s = Store::open(&seed(1), None).unwrap();
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
            let s = Store::open(&seed(1), Some(&path)).unwrap();
            s.put_key(&[7; 32], 1, &k).unwrap();
        }
        let theirs = Store::open(&seed(2), Some(&path)).unwrap();
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
        let s = Store::open(&seed(1), None).unwrap();
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
    fn no_key_material_is_on_disk_in_the_clear() {
        // The claim is that secrets are sealed at rest, so test the claim and
        // not a proxy for it: put known bytes in, then look at the actual file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let k = ChannelKey::new([0xab; 32]);
        {
            let mut s = Store::open(&seed(1), Some(&path)).unwrap();
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
            let mut s = Store::open(&seed(1), Some(&path)).unwrap();
            let mut pool = s.pool(&seed(1)).unwrap();
            let published = pool.mint_one_time(4);
            spent = published[0].id;
            kept = published[1].id;
            pool.take(spent).unwrap();
            s.save_pool(&pool).unwrap();
        }
        let s = Store::open(&seed(1), Some(&path)).unwrap();
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
            let mut s = Store::open(&seed(1), Some(&path)).unwrap();
            let mut pool = s.pool(&seed(1)).unwrap();
            first = pool.mint_one_time(4).iter().map(|p| p.id).collect();
            pool.take(first[0]).unwrap();
            s.save_pool(&pool).unwrap();
        }
        let mut s = Store::open(&seed(1), Some(&path)).unwrap();
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
            let s = Store::open(&seed(1), Some(&path)).unwrap();
            s.record_seen(&[7; 32], &device, 1, 0).unwrap();
            s.record_seen(&[7; 32], &device, 1, 1).unwrap();
        }
        let s = Store::open(&seed(1), Some(&path)).unwrap();
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
        let s = Store::open(&seed(1), None).unwrap();
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
        let s = Store::open(&seed(1), None).unwrap();
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
            let s = Store::open(&seed(1), Some(&path)).unwrap();
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
        let s = Store::open(&seed(1), Some(&path)).unwrap();
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
        let s = Store::open(&seed(1), None).unwrap();
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
            let s = Store::open(&seed(1), Some(&path)).unwrap();
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
            let mut s = Store::open(&seed(1), Some(&dir.path().join("chat.db"))).unwrap();
            let mut pool = s.pool(&seed(1)).unwrap();
            first = pool.mint_one_time(64).iter().map(|p| p.id).collect();
            s.save_pool(&pool).unwrap();
        }
        // The store is gone; the identity is not.
        let mut fresh = Store::open(&seed(1), Some(&dir.path().join("new.db"))).unwrap();
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
            let mut s = Store::open(&seed(1), Some(&path)).unwrap();
            let mut pool = s.pool(&seed(1)).unwrap();
            first = pool.mint_one_time(4).iter().map(|p| p.id).collect();
            s.save_pool(&pool).unwrap();
        }
        let s = Store::open(&seed(1), Some(&path)).unwrap();
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
            let s = Store::open(&seed(1), Some(&path)).unwrap();
            s.put_channel(&[7; 32], true, "the group", &[key(1), key(2)])
                .unwrap();
            s.put_channel(&[8; 32], false, "bob", &[key(1), key(3)])
                .unwrap();
        }
        let s = Store::open(&seed(1), Some(&path)).unwrap();
        let got = s.channels().unwrap();
        assert_eq!(got.len(), 2);
        let group = got.iter().find(|c| c.0 == [7; 32]).unwrap();
        assert!(group.1, "the group lost its kind");
        assert_eq!(group.2, "the group");
        assert_eq!(group.3, vec![key(1), key(2)]);
    }

    #[test]
    fn a_label_and_a_membership_are_set_independently() {
        // They arrive from different places: the name from a sealed entry only
        // members can read, the admins from the exchange.
        let s = Store::open(&seed(1), None).unwrap();
        s.put_channel(&[7; 32], true, "", &[key(1)]).unwrap();
        s.set_label(&[7; 32], "renamed").unwrap();
        let got = s.channels().unwrap();
        assert_eq!(got[0].2, "renamed");
        assert_eq!(got[0].3, vec![key(1)], "setting a label dropped the admins");
    }

    #[test]
    fn forgetting_a_channel_removes_it() {
        let s = Store::open(&seed(1), None).unwrap();
        s.put_channel(&[7; 32], true, "gone", &[]).unwrap();
        s.forget_channel(&[7; 32]).unwrap();
        assert!(s.channels().unwrap().is_empty());
    }
}
