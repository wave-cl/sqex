//! SIP-27: statements identities have made about each other.
//!
//! The exchange holds them and is **not an authority over them**. It checks
//! that an issuer signed and that the shape is well formed, and it cannot check
//! whether a claim is true — nothing can, which is why the SIP puts the
//! decision with the consumer and why nothing here computes a score.
//!
//! Durable, unlike the beacon and the endpoint store beside it, and for a
//! reason that follows from what an attestation is: it is meant to be repeated
//! to third parties who never saw the connection, so it outlives the connection
//! by design and losing it on a restart would lose something nobody could
//! reproduce. It is also, in practice, permanent whatever this does — once read
//! it can be retained and replayed by anyone.
//!
//! That paragraph was true of the intent and false of the code until
//! 2026-09-30: this was a `Mutex<HashMap>` and every lodged statement went with
//! the process. The store is SQLite now, beside the other stores and keyed off
//! `state_file` like them, and `durable()` reports it so an operator running
//! memory-only can see which it has.
//!
//! **Why the restart mattered more than losing the statements.** A revocation
//! naming an attestation this exchange does not hold is refused, deliberately —
//! see `LodgeError::NoSuchAttestation`. So an ephemeral store did not merely
//! forget Alice's claim; it made her legitimate withdrawal of it *unlodgeable*,
//! answering 404 to the one party entitled to withdraw. The asymmetry is what
//! made the gap incoherent rather than merely lossy.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, params};
use sqex_proto::attest::{Attestation, CLAIM_REVOKES, Held, Invalid, MAX_PER_SUBJECT};
use sqnr_core::PubKey;

use crate::state::now_unix;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS attestation (
    subject BLOB    NOT NULL,
    -- The signing input's digest, which is what a revocation names. Keyed on it
    -- with the subject so lodging the same statement twice changes nothing and
    -- a re-lodge after expiry-and-reissue is a new statement.
    digest  BLOB    NOT NULL,
    issuer  BLOB    NOT NULL,
    claim   INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    -- The signed artifact, stored whole. What is served later is the thing the
    -- issuer signed rather than this exchange's copy of its fields -- the same
    -- reason SIP-32 made `profile.record` a blob.
    record  BLOB    NOT NULL,
    -- Arrival order, for the per-subject cap and for a stable read order.
    at      INTEGER NOT NULL,
    PRIMARY KEY (subject, digest)
);
CREATE INDEX IF NOT EXISTS attestation_expires ON attestation (expires);
"#;

/// Every attestation the exchange has been given, by subject.
pub struct Attestations {
    db: Mutex<Connection>,
    durable: bool,
}

/// Why a lodgement was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LodgeError {
    /// The signature, window or self-issue check failed.
    Invalid(Invalid),
    /// A revocation naming an attestation this exchange does not hold, or one
    /// by a different issuer. Refused rather than stored, because a revocation
    /// that names nothing is indistinguishable from one that names something
    /// the reader has not seen.
    NoSuchAttestation,
    /// The store could not be written. Distinct from the two above because they
    /// are answers about the statement and this is not: a caller that is told
    /// its attestation was refused will not offer it again, and one told the
    /// exchange failed may.
    Storage,
}

fn storage<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> LodgeError + '_ {
    move |e| {
        tracing::error!(error = %e, "attestations: {what}");
        LodgeError::Storage
    }
}

impl Attestations {
    /// Open the store. `None` is memory-only, which is what the tests use and
    /// what an exchange with no `state_file` gets.
    pub fn open(path: Option<&Path>) -> rusqlite::Result<Attestations> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        Ok(Attestations {
            db: Mutex::new(db),
            durable: path.is_some(),
        })
    }

    /// Whether what is lodged here survives a restart. Reported on `/status`,
    /// for the same reason SIP-5 §Durability made the mailbox say so: a promise
    /// about outliving a connection that the store cannot keep is worse than an
    /// absent one, and an operator cannot otherwise tell.
    pub fn durable(&self) -> bool {
        self.durable
    }

    /// Take one, if it verifies.
    ///
    /// **Anybody may lodge**, not only the issuer: an attestation carries its
    /// own proof, so who handed it over establishes nothing and requiring the
    /// issuer to do it would mean an issuer who has gone away can never be
    /// quoted. That is the property the SIP means by "equally valid handed over
    /// on a USB stick".
    pub fn lodge(&self, a: Attestation) -> Result<(), LodgeError> {
        let now = now_unix();
        a.verify(now).map_err(LodgeError::Invalid)?;

        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage("begin"))?;

        if a.claim == CLAIM_REVOKES {
            // A withdrawal names an earlier attestation by its digest, and
            // **only its own issuer may withdraw it** — otherwise a withdrawal
            // would be a way to silence somebody else.
            let named: Option<[u8; 32]> = a.body.clone().try_into().ok();
            let Some(named) = named else {
                return Err(LodgeError::NoSuchAttestation);
            };
            let removed = tx
                .execute(
                    "DELETE FROM attestation
                     WHERE subject = ?1 AND digest = ?2 AND issuer = ?3",
                    params![a.subject.as_bytes(), &named[..], a.issuer.as_bytes()],
                )
                .map_err(storage("withdraw"))?;
            if removed == 0 {
                return Err(LodgeError::NoSuchAttestation);
            }
            // The revocation itself is kept, so a consumer that arrives later
            // can see that the issuer withdrew rather than that the claim was
            // never made.
            insert(&tx, &a, now)?;
            tx.commit().map_err(storage("commit"))?;
            return Ok(());
        }

        // Lodging the same statement twice changes nothing; the primary key on
        // (subject, digest) is what makes that so, and `INSERT OR IGNORE` is
        // how it is said rather than a read followed by a write.
        //
        // A cap, not a quorum. It bounds storage and says nothing about weight
        // — a count of attestations measures how many keys somebody made.
        let held: usize = tx
            .query_row(
                "SELECT COUNT(*) FROM attestation WHERE subject = ?1",
                params![a.subject.as_bytes()],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(storage("count"))?;
        let already: usize = tx
            .query_row(
                "SELECT COUNT(*) FROM attestation WHERE subject = ?1 AND digest = ?2",
                params![a.subject.as_bytes(), &a.digest()[..]],
                |r| r.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(storage("count held"))?;
        if already == 0 {
            // Oldest out first, by arrival, exactly as the vector this replaced
            // did with `remove(0)`.
            if held >= MAX_PER_SUBJECT {
                let over = held - MAX_PER_SUBJECT + 1;
                tx.execute(
                    "DELETE FROM attestation WHERE rowid IN (
                         SELECT rowid FROM attestation WHERE subject = ?1
                         ORDER BY at, rowid LIMIT ?2
                     )",
                    params![a.subject.as_bytes(), over as i64],
                )
                .map_err(storage("trim"))?;
            }
            insert(&tx, &a, now)?;
        }
        tx.commit().map_err(storage("commit"))?;
        Ok(())
    }

    /// What is held about `subject`, optionally from one issuer.
    ///
    /// The filter is SIP-27's requirement rather than a convenience: only
    /// attestations from issuers a consumer already trusts carry weight, so
    /// asking about one is the ordinary case.
    pub fn about(&self, subject: &PubKey, issuer: Option<&PubKey>) -> Held {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        // Expiry is enforced here as well as in `sweep`, so a statement that has
        // run out is never served even if nothing has swept yet.
        let rows = db
            .prepare(
                "SELECT record FROM attestation
                 WHERE subject = ?1 AND expires > ?2
                   AND (?3 IS NULL OR issuer = ?3)
                 ORDER BY at, rowid",
            )
            .and_then(|mut q| {
                q.query_map(
                    params![
                        subject.as_bytes(),
                        now as i64,
                        issuer.map(|i| i.as_bytes().to_vec())
                    ],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
            });
        let attestations = match rows {
            Ok(rows) => rows
                .iter()
                .filter_map(|b| Attestation::decode(b).ok())
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "attestations: read");
                Vec::new()
            }
        };
        Held { now, attestations }
    }

    /// Drop what has expired, and say how many. **Expiry is the only guarantee
    /// this design offers** — a revocation is a signed statement a consumer may
    /// never see — so it is enforced on read as well as here.
    ///
    /// This is called from the periodic sweep. It was not, until 2026-09-30,
    /// which mattered little while the store died with the process and matters
    /// now that it does not: nothing else deletes a row.
    pub fn sweep(&self) -> usize {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        match db.execute(
            "DELETE FROM attestation WHERE expires <= ?1",
            params![now as i64],
        ) {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(error = %e, "attestations: sweep");
                0
            }
        }
    }

    /// How many subjects have anything unexpired said about them. For `/status`.
    pub fn len(&self) -> usize {
        let now = now_unix();
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT COUNT(DISTINCT subject) FROM attestation WHERE expires > ?1",
            params![now as i64],
            |r| r.get::<_, i64>(0).map(|n| n as usize),
        )
        .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn insert(tx: &rusqlite::Transaction<'_>, a: &Attestation, now: u64) -> Result<(), LodgeError> {
    tx.execute(
        "INSERT OR IGNORE INTO attestation
             (subject, digest, issuer, claim, expires, record, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            a.subject.as_bytes(),
            &a.digest()[..],
            a.issuer.as_bytes(),
            a.claim as i64,
            a.expires_at as i64,
            a.encode(),
            now as i64,
        ],
    )
    .map_err(storage("insert"))?;
    Ok(())
}
