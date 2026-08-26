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
use sqex_proto::channel_key::{ChannelKey, Replay};
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
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
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
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Storage(e) => write!(f, "chat store: {e}"),
            StoreError::Sealed(e) => write!(f, "chat store will not open: {e}"),
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
    let home = dirs::home_dir()
        .ok_or_else(|| StoreError::Storage("no home directory".into()))?;
    let dir = home.join(".sqex").join("chat");
    std::fs::create_dir_all(&dir).map_err(storage("create ~/.sqex/chat"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(storage("lock down ~/.sqex/chat"))?;
    }
    Ok(dir.join(format!("{}.db", bs58::encode(account.as_bytes()).into_string())))
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
            return Err(StoreError::Sealed("row is too short to hold a nonce".into()));
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
                    account: PubKey::new(
                        r.get::<_, Vec<u8>>(0)?.try_into().unwrap_or([0; 32]),
                    ),
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
                params![&channel[..], device.as_bytes(), epoch as i64, msg_seq as i64],
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
    pub fn put_message(
        &self,
        channel: &[u8; 32],
        seq: u64,
        account: &PubKey,
        posted: u64,
        kind: u8,
        plain: Option<&[u8]>,
    ) -> Result<()> {
        let sealed = match plain {
            Some(p) => Some(self.seal_bytes(p)?),
            None => None,
        };
        self.db
            .execute(
                "INSERT INTO message (channel, seq, account, posted, kind, sealed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (channel, seq) DO NOTHING",
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
            .prepare("SELECT channel, kind, label, admins FROM channel_meta ORDER BY label, channel")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
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
            s.db.pragma_update(None, "wal_checkpoint", "TRUNCATE").unwrap();

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
        assert!(next.iter().all(|id| !first.contains(id)), "{first:?} vs {next:?}");
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
            s.put_message(&[7; 32], 3, &key(2), 100, 1, Some(b"hello")).unwrap();
            s.put_message(&[7; 32], 4, &key(1), 101, 1, Some(b"hi back")).unwrap();
            // One we could not open: recorded, so the reader can be told.
            s.put_message(&[7; 32], 5, &key(2), 102, 1, None).unwrap();
        }
        let s = Store::open(&seed(1), Some(&path)).unwrap();
        let got = s.messages(&[7; 32]).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, 3);
        assert_eq!(got[0].4.as_deref(), Some(&b"hello"[..]));
        assert_eq!(got[1].4.as_deref(), Some(&b"hi back"[..]));
        assert!(got[2].4.is_none(), "an unopenable entry should stay unopenable");
    }

    #[test]
    fn a_message_is_not_stored_twice() {
        let s = Store::open(&seed(1), None).unwrap();
        s.put_message(&[7; 32], 3, &key(2), 100, 1, Some(b"once")).unwrap();
        s.put_message(&[7; 32], 3, &key(2), 100, 1, Some(b"twice")).unwrap();
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
            s.put_message(&[7; 32], 1, &key(2), 100, 1, Some(secret)).unwrap();
            s.db.pragma_update(None, "wal_checkpoint", "TRUNCATE").unwrap();
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
            s.put_channel(&[7; 32], true, "the group", &[key(1), key(2)]).unwrap();
            s.put_channel(&[8; 32], false, "bob", &[key(1), key(3)]).unwrap();
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
