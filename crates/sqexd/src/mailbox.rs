//! The SIP-5 mailbox: sealed messages held for their recipients.
//!
//! The exchange stores ciphertext and metadata. It cannot read a payload — the
//! sealing is to the recipient's key (see `sqex_proto::mailbox`) and nothing
//! here has the material to open it. What it does see, and cannot avoid seeing,
//! is *who sent to whom, how big, and when*: that metadata is the honest cost of
//! a rendezvous point, and SIP-5 says so rather than calling this private
//! communication.
//!
//! **Delivery is at-least-once.** A recipient lists, fetches, then deletes by
//! id. Fetching alone changes nothing, so a connection lost mid-collection
//! costs a retry rather than a message.
//!
//! **Collection is visible to the sender.** Deleting drops the payload but
//! leaves a small tombstone — id, sender, and when it was collected — so a
//! sender can ask what became of what it left. That is a deliberate disclosure
//! of recipient behaviour, chosen over silence; see SIP-5's security notes.
//!
//! **State is durable (SIP-5 §Durability).** The mailbox is SQLite beside the other
//! stores, so an operator's restart is not a delivery failure: items,
//! collection records, the identifier sequence and what a home collected
//! from a former home (SIP-68) survive for the item's TTL. A memory-only
//! deployment gets the same code over an in-memory database, and says so
//! on `/status`.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use sqex_proto::mailbox::{
    Entry, Listing, MAX_BYTES, MAX_MESSAGES, Sealed, State, Status, TTL_SECS,
};
use sqnr_core::PubKey;

use crate::state::now_unix;
use sqex_proto::refusal::Code;

/// Why a send was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The recipient already holds the most messages allowed.
    TooManyMessages,
    /// The recipient's stored bytes would exceed the allowance.
    QuotaExceeded,
}

impl SendError {
    pub fn as_str(&self) -> &'static str {
        match self {
            SendError::TooManyMessages => "recipient_full",
            SendError::QuotaExceeded => "recipient_quota",
        }
    }

    /// The wire code for this refusal. Exhaustive on purpose: a new variant is
    /// a compile error here until it is given one, which is what keeps the
    /// registry from drifting away from the enum it describes.
    pub fn code(&self) -> Code {
        match self {
            SendError::TooManyMessages => Code::RecipientFull,
            SendError::QuotaExceeded => Code::RecipientQuota,
        }
    }
}

const SCHEMA: &str = r#"
-- One row per item, and the tombstone it leaves: the payload columns are
-- NULL once collected, the record stays until the TTL. Identifiers never
-- repeat across a restart (AUTOINCREMENT), so a sender's Status names the
-- message it sent and no later one.
CREATE TABLE IF NOT EXISTS mail (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    sender    BLOB    NOT NULL,
    recipient BLOB    NOT NULL,
    received  INTEGER NOT NULL,
    ephemeral BLOB,
    ciphertext BLOB,
    collected INTEGER
);
CREATE INDEX IF NOT EXISTS mail_by_recipient ON mail (recipient, id);
-- SIP-68: what was collected from a former home, so a pull answered twice
-- -- across a restart too -- stores nothing twice.
CREATE TABLE IF NOT EXISTS collected_from (
    origin    BLOB    NOT NULL,
    remote_id INTEGER NOT NULL,
    recipient BLOB    NOT NULL,
    received  INTEGER NOT NULL,
    PRIMARY KEY (origin, remote_id, recipient)
);
"#;

/// Every message the exchange is holding.
pub struct Mailbox {
    db: Mutex<Connection>,
    durable: bool,
}

impl Default for Mailbox {
    fn default() -> Mailbox {
        Mailbox::new()
    }
}

fn key32(b: Vec<u8>) -> PubKey {
    PubKey::new(b.try_into().unwrap_or([0; 32]))
}

impl Mailbox {
    /// A mailbox in memory: what a memory-only deployment and the tests get.
    pub fn new() -> Mailbox {
        Mailbox::open(None).expect("an in-memory mailbox opens")
    }

    /// SIP-5 §Durability: the mailbox on disk at `path`, or in memory with `None`.
    pub fn open(path: Option<&Path>) -> rusqlite::Result<Mailbox> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        Ok(Mailbox {
            db: Mutex::new(db),
            durable: path.is_some(),
        })
    }

    /// SIP-5 §Durability: whether a restart keeps what is here.
    pub fn durable(&self) -> bool {
        self.durable
    }

    /// Drop everything past its TTL. Called on every operation, so there is
    /// no background task and no unbounded growth from a recipient that never
    /// collects.
    fn expire(db: &Connection, now: u64) {
        let cutoff = now.saturating_sub(TTL_SECS) as i64;
        let _ = db.execute("DELETE FROM mail WHERE received < ?1", params![cutoff]);
        let _ = db.execute(
            "DELETE FROM collected_from WHERE received < ?1",
            params![cutoff],
        );
    }

    /// The recipient's waiting count and bytes, for the quotas.
    fn load(db: &Connection, recipient: &PubKey) -> (usize, usize) {
        db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(ciphertext)), 0) FROM mail
             WHERE recipient = ?1 AND ciphertext IS NOT NULL",
            params![recipient.as_bytes()],
            |r| Ok((r.get::<_, i64>(0)? as usize, r.get::<_, i64>(1)? as usize)),
        )
        .unwrap_or((0, 0))
    }

    fn insert(
        db: &Connection,
        sender: &PubKey,
        recipient: &PubKey,
        received: u64,
        sealed: &Sealed,
    ) -> Result<u64, SendError> {
        let (count, bytes) = Self::load(db, recipient);
        if count >= MAX_MESSAGES {
            return Err(SendError::TooManyMessages);
        }
        if bytes + sealed.ciphertext.len() > MAX_BYTES {
            return Err(SendError::QuotaExceeded);
        }
        db.execute(
            "INSERT INTO mail (sender, recipient, received, ephemeral, ciphertext)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                sender.as_bytes(),
                recipient.as_bytes(),
                received as i64,
                &sealed.ephemeral[..],
                &sealed.ciphertext
            ],
        )
        .map_err(|_| SendError::QuotaExceeded)?;
        Ok(db.last_insert_rowid() as u64)
    }

    /// Store a sealed message for `recipient`. Returns its id.
    pub fn send(
        &self,
        sender: PubKey,
        recipient: PubKey,
        sealed: Sealed,
    ) -> Result<(u64, u64), SendError> {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        let id = Self::insert(&db, &sender, &recipient, now, &sealed)?;
        Ok((id, now))
    }

    /// SIP-68: every item waiting for `recipient`, oldest first, as the
    /// home collects it -- what this exchange observed, and the sealed
    /// payload. Nothing is removed by asking.
    pub fn waiting_for(&self, recipient: &PubKey) -> Vec<sqex_proto::peer::MailItem> {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        db.prepare(
            "SELECT id, sender, received, ephemeral, ciphertext FROM mail
             WHERE recipient = ?1 AND ciphertext IS NOT NULL ORDER BY id",
        )
        .ok()
        .and_then(|mut st| {
            st.query_map(params![recipient.as_bytes()], |r| {
                Ok(sqex_proto::peer::MailItem {
                    id: r.get::<_, i64>(0)? as u64,
                    sender: key32(r.get(1)?),
                    received: r.get::<_, i64>(2)? as u64,
                    sealed: Sealed {
                        ephemeral: r.get::<_, Vec<u8>>(3)?.try_into().unwrap_or([0; 32]),
                        ciphertext: r.get(4)?,
                    },
                })
            })
            .ok()
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default()
    }

    /// SIP-68: store an item collected from `origin` for `recipient` as the
    /// former home observed it -- its sender and time kept -- once per
    /// `(origin, id)`. `Ok(true)` stored, `Ok(false)` already held, `Err`
    /// over the recipient's quota.
    pub fn deliver(
        &self,
        recipient: PubKey,
        origin: &PubKey,
        item: &sqex_proto::peer::MailItem,
    ) -> Result<bool, SendError> {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        let held: Option<i64> = db
            .query_row(
                "SELECT 1 FROM collected_from WHERE origin = ?1 AND remote_id = ?2 AND recipient = ?3",
                params![origin.as_bytes(), item.id as i64, recipient.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        if held.is_some() {
            return Ok(false);
        }
        Self::insert(&db, &item.sender, &recipient, item.received, &item.sealed)?;
        let _ = db.execute(
            "INSERT OR IGNORE INTO collected_from (origin, remote_id, recipient, received)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                origin.as_bytes(),
                item.id as i64,
                recipient.as_bytes(),
                item.received as i64
            ],
        );
        Ok(true)
    }

    /// SIP-5 §Collection by a device: the messages waiting for any of `recipients` -- a device's
    /// own and its account's -- together, oldest first by arrival.
    pub fn list_for(&self, recipients: &[PubKey]) -> Listing {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        let mut entries: Vec<Entry> = Vec::new();
        for r in recipients {
            if let Ok(mut st) = db.prepare(
                "SELECT id, sender, received, LENGTH(ciphertext) FROM mail
                 WHERE recipient = ?1 AND ciphertext IS NOT NULL ORDER BY id",
            ) && let Ok(rows) = st.query_map(params![r.as_bytes()], |row| {
                Ok(Entry {
                    id: row.get::<_, i64>(0)? as u64,
                    sender: key32(row.get(1)?),
                    received: row.get::<_, i64>(2)? as u64,
                    len: row.get::<_, i64>(3)? as u32,
                })
            }) {
                entries.extend(rows.flatten());
            }
        }
        entries.sort_by_key(|e| (e.received, e.id));
        entries.dedup_by_key(|e| e.id);
        Listing { entries, now }
    }

    /// SIP-5 §Collection by a device: [`Self::fetch`] for whichever of `recipients` the item is for.
    pub fn fetch_for(&self, recipients: &[PubKey], id: u64) -> Option<(PubKey, u64, Sealed)> {
        recipients.iter().find_map(|r| self.fetch(r, id))
    }

    /// SIP-5 §Collection by a device: [`Self::delete`] for whichever of `recipients` the item is for.
    pub fn delete_for(&self, recipients: &[PubKey], id: u64) -> bool {
        recipients.iter().any(|r| self.delete(r, id))
    }

    /// The messages waiting for `recipient`, oldest first.
    pub fn list(&self, recipient: &PubKey) -> Listing {
        self.list_for(std::slice::from_ref(recipient))
    }

    /// Read one message. Only its recipient may, and fetching does not remove
    /// it — collection is completed by [`delete`](Self::delete).
    pub fn fetch(&self, recipient: &PubKey, id: u64) -> Option<(PubKey, u64, Sealed)> {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        db.query_row(
            "SELECT sender, received, ephemeral, ciphertext FROM mail
             WHERE id = ?1 AND recipient = ?2 AND ciphertext IS NOT NULL",
            params![id as i64, recipient.as_bytes()],
            |r| {
                Ok((
                    key32(r.get(0)?),
                    r.get::<_, i64>(1)? as u64,
                    Sealed {
                        ephemeral: r.get::<_, Vec<u8>>(2)?.try_into().unwrap_or([0; 32]),
                        ciphertext: r.get(3)?,
                    },
                ))
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Complete collection: drop the payload, keep the tombstone. Only the
    /// recipient may. Returns whether anything was collected. The payload
    /// columns are set to NULL, which SQLite may or may not scrub from the
    /// file: SIP-5 says deletion is still not erasure.
    pub fn delete(&self, recipient: &PubKey, id: u64) -> bool {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        db.execute(
            "UPDATE mail SET ephemeral = NULL, ciphertext = NULL, collected = ?3
             WHERE id = ?1 AND recipient = ?2 AND ciphertext IS NOT NULL",
            params![id as i64, recipient.as_bytes(), now as i64],
        )
        .map(|n| n == 1)
        .unwrap_or(false)
    }

    /// What became of a message. Only the identity that sent it may ask; anyone
    /// else is told nothing, which is the same answer as for a message that
    /// never existed.
    pub fn status(&self, sender: &PubKey, id: u64) -> Status {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        db.query_row(
            "SELECT received, collected FROM mail WHERE id = ?1 AND sender = ?2",
            params![id as i64, sender.as_bytes()],
            |r| {
                let received = r.get::<_, i64>(0)? as u64;
                let collected: Option<i64> = r.get(1)?;
                Ok(Status {
                    state: if collected.is_some() {
                        State::Collected
                    } else {
                        State::Waiting
                    },
                    received,
                    collected: collected.unwrap_or(0) as u64,
                    now,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
        .unwrap_or_else(|| Status::unknown(now))
    }

    /// How many messages are waiting to be collected, across all recipients.
    pub fn waiting(&self) -> usize {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT COUNT(*) FROM mail WHERE ciphertext IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n as usize)
        .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn sealed(n: usize) -> Sealed {
        Sealed {
            ephemeral: [7u8; 32],
            ciphertext: vec![0u8; n],
        }
    }

    #[test]
    fn send_list_fetch_delete() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        let (id, _) = m.send(from, to, sealed(10)).unwrap();

        let l = m.list(&to);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].id, id);
        assert_eq!(l.entries[0].sender, from);
        assert_eq!(l.entries[0].len, 10);

        // Fetching does not remove: delivery is at-least-once.
        assert!(m.fetch(&to, id).is_some());
        assert!(m.fetch(&to, id).is_some());
        assert_eq!(m.list(&to).entries.len(), 1);

        assert!(m.delete(&to, id));
        assert!(m.list(&to).entries.is_empty());
        assert!(!m.delete(&to, id), "deleting twice collects nothing");
    }

    #[test]
    fn only_the_recipient_may_fetch_or_delete() {
        let m = Mailbox::new();
        let (from, to, other) = (key(1), key(2), key(3));
        let (id, _) = m.send(from, to, sealed(4)).unwrap();

        assert!(m.fetch(&other, id).is_none(), "not yours to read");
        assert!(!m.delete(&other, id), "not yours to delete");
        assert!(m.fetch(&to, id).is_some(), "still there for its recipient");
    }

    #[test]
    fn the_sender_learns_that_it_was_collected() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        let (id, _) = m.send(from, to, sealed(4)).unwrap();

        assert_eq!(m.status(&from, id).state, State::Waiting);
        m.delete(&to, id);
        let s = m.status(&from, id);
        assert_eq!(s.state, State::Collected);
        assert!(s.collected > 0, "and when");
    }

    #[test]
    fn only_the_sender_may_ask_after_a_message() {
        let m = Mailbox::new();
        let (from, to, nosy) = (key(1), key(2), key(3));
        let (id, _) = m.send(from, to, sealed(4)).unwrap();
        assert_eq!(
            m.status(&nosy, id).state,
            State::Unknown,
            "a stranger learns nothing, not even that it exists"
        );
        // Not even the recipient can use status to enumerate.
        assert_eq!(m.status(&to, id).state, State::Unknown);
    }

    #[test]
    fn the_queue_is_oldest_first() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        let (a, _) = m.send(from, to, sealed(1)).unwrap();
        let (b, _) = m.send(from, to, sealed(1)).unwrap();
        let (c, _) = m.send(from, to, sealed(1)).unwrap();
        let ids: Vec<u64> = m.list(&to).entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![a, b, c]);

        // Collecting from the middle leaves the order intact.
        m.delete(&to, b);
        let ids: Vec<u64> = m.list(&to).entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![a, c]);
    }

    #[test]
    fn a_full_mailbox_refuses_more() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        for _ in 0..MAX_MESSAGES {
            m.send(from, to, sealed(1)).unwrap();
        }
        assert_eq!(m.send(from, to, sealed(1)), Err(SendError::TooManyMessages));

        // Collecting one makes room again.
        let first = m.list(&to).entries[0].id;
        m.delete(&to, first);
        assert!(m.send(from, to, sealed(1)).is_ok());
    }

    #[test]
    fn the_byte_quota_is_enforced() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        // A few large messages, then one that would tip it over.
        let big = MAX_BYTES / 4;
        for _ in 0..4 {
            m.send(from, to, sealed(big)).unwrap();
        }
        assert_eq!(m.send(from, to, sealed(1)), Err(SendError::QuotaExceeded));
    }

    #[test]
    fn quotas_are_per_recipient() {
        let m = Mailbox::new();
        let from = key(1);
        for _ in 0..MAX_MESSAGES {
            m.send(from, key(2), sealed(1)).unwrap();
        }
        assert!(
            m.send(from, key(3), sealed(1)).is_ok(),
            "one full mailbox must not block another"
        );
    }

    #[test]
    fn waiting_counts_only_uncollected() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        let (id, _) = m.send(from, to, sealed(1)).unwrap();
        m.send(from, to, sealed(1)).unwrap();
        assert_eq!(m.waiting(), 2);
        m.delete(&to, id);
        assert_eq!(m.waiting(), 1, "a tombstone is not a waiting message");
    }
}

#[cfg(test)]
mod durable {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    /// SIP-5 §Durability: an item, its collection record and the identifier sequence
    /// are there after the store is opened again; a collected item's payload
    /// is not.
    #[test]
    fn what_a_restart_keeps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.db");
        let (from, to) = (key(1), key(2));
        let sealed = |b: u8| Sealed {
            ephemeral: [b; 32],
            ciphertext: vec![b; 16],
        };
        let (first, second) = {
            let m = Mailbox::open(Some(&path)).unwrap();
            assert!(m.durable());
            let (first, _) = m.send(from, to, sealed(1)).unwrap();
            let (second, _) = m.send(from, to, sealed(2)).unwrap();
            assert!(m.delete(&to, first));
            (first, second)
        };
        // Opened again: the waiting item waits, the collected one is a
        // record, and the next id does not repeat either.
        let m = Mailbox::open(Some(&path)).unwrap();
        let l = m.list(&to);
        assert_eq!(
            l.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![second]
        );
        assert_eq!(m.fetch(&to, second).unwrap().2, sealed(2));
        assert!(m.fetch(&to, first).is_none());
        assert_eq!(m.status(&from, first).state, State::Collected);
        assert_eq!(m.status(&from, second).state, State::Waiting);
        let (third, _) = m.send(from, to, sealed(3)).unwrap();
        assert!(third > second, "an identifier repeated across a restart");
        // The collected payload is gone from the file.
        let db = rusqlite::Connection::open(&path).unwrap();
        let payload: Option<Vec<u8>> = db
            .query_row(
                "SELECT ciphertext FROM mail WHERE id = ?1",
                params![first as i64],
                |r| r.get(0),
            )
            .unwrap();
        assert!(payload.is_none());
        // And what a home collected from a former home is remembered too.
        let origin = key(9);
        let item = sqex_proto::peer::MailItem {
            id: 77,
            sender: key(3),
            received: now_unix(),
            sealed: sealed(4),
        };
        assert!(m.deliver(to, &origin, &item).unwrap());
        drop(m);
        let m = Mailbox::open(Some(&path)).unwrap();
        assert!(
            !m.deliver(to, &origin, &item).unwrap(),
            "stored twice across a restart"
        );
        assert!(m.durable());
        assert!(!Mailbox::new().durable());
    }
}
