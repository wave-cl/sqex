//! SIP-88 feeds: a per-account append-only log, served to anybody who asks.
//!
//! The exchange numbers nothing here. A post arrives carrying its own serial
//! and its own link to the one before it, both signed by a device of the
//! account whose feed it is, and this module's whole job is to check that
//! claim and keep what it accepted.
//!
//! # What that buys, and what it costs
//!
//! Because the serial is the author's, **a feed cannot be forked by the
//! exchange that serves it**: an exchange under-reporting its head produces a
//! refusal rather than two posts at one position, since `prev` is checked
//! against the head actually held. A refusal costs the author nothing — the
//! exchange numbered nothing and spent nothing, so the post is re-signable at
//! the higher serial.
//!
//! What it costs is that two devices of one account appending at once will
//! have one of them refused. That is designed for rather than avoided; see
//! SIP-88 §One chain.
//!
//! # The serial space is dense
//!
//! Every removal from the middle leaves a tombstone and only eviction from the
//! oldest end advances `oldest`, so a hole between the two means the exchange
//! dropped a post. That is a promise this module keeps and a reader relies on.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use sqex_proto::feed::{
    DIR_BACKWARD, Headed, MAX_BODY, MAX_FEED_BYTES, MAX_PAGE, MAX_PAGE_BYTES, MAX_POSTS,
    MAX_RETENTION, MIN_RETENTION, Page, Post, Read, Stored,
};
use sqex_proto::refusal::Code;
use sqnr_core::PubKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedError {
    /// The post names an account other than the caller's.
    NotYours,
    /// The signature does not verify under the device it names.
    BadSignature,
    /// `SHA-256(body)` is not the `body_hash` the signature commits to. Kept
    /// apart from `BadSignature` deliberately: one is a damaged body and the
    /// other is an accusation against an author.
    BadBody,
    /// The body is over `MAX_BODY`.
    TooLarge,
    /// A serial that is not exactly `newest + 1`.
    Stale,
    /// `prev` is not the head this exchange holds.
    BrokenChain,
    /// A reserved flag bit was set. A reserved bit that is merely ignored is a
    /// reserved bit somebody will use.
    Reserved,
    /// Nothing is held at that serial, or it is already a tombstone.
    NoSuchPost,
    /// A retention outside SIP-88's bounds.
    BadRetention,
    Storage,
}

impl FeedError {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeedError::NotYours => "not_yours",
            FeedError::BadSignature => "bad_signature",
            FeedError::BadBody => "malformed",
            FeedError::TooLarge => "body_too_large",
            FeedError::Stale => "stale_serial",
            FeedError::BrokenChain => "broken_chain",
            FeedError::Reserved => "malformed",
            FeedError::NoSuchPost => "no_such_entry",
            FeedError::BadRetention => "bad_retention",
            FeedError::Storage => "storage",
        }
    }

    /// The wire code for this refusal. Exhaustive on purpose: a new variant is
    /// a compile error here until it is given one, which is what keeps the
    /// registry from drifting away from the enum it describes.
    ///
    /// Every code here already exists. `stale_serial` is SIP-21's and means
    /// exactly this — a serial that loses to the one held — and `broken_chain`
    /// is SIP-31's for the same failure in a channel.
    pub fn code(&self) -> Code {
        match self {
            FeedError::NotYours => Code::NotYours,
            FeedError::BadSignature => Code::BadSignature,
            FeedError::BadBody | FeedError::Reserved => Code::Malformed,
            FeedError::TooLarge => Code::BodyTooLarge,
            FeedError::Stale => Code::StaleSerial,
            FeedError::BrokenChain => Code::BrokenChain,
            FeedError::NoSuchPost => Code::NoSuchEntry,
            FeedError::BadRetention => Code::BadRetention,
            FeedError::Storage => Code::Storage,
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            FeedError::NotYours | FeedError::BadSignature => 401,
            FeedError::BadBody | FeedError::Reserved | FeedError::BadRetention => 400,
            FeedError::TooLarge => 413,
            FeedError::Stale | FeedError::BrokenChain => 409,
            FeedError::NoSuchPost => 404,
            FeedError::Storage => 500,
        }
    }
}

fn storage<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> FeedError + '_ {
    move |e| {
        tracing::error!(error = %e, "feeds: {what}");
        FeedError::Storage
    }
}

const SCHEMA: &str = r#"
-- One row per feed: where it has got to, and the policy its author set.
--
-- Separate from `post` so that `/feed/head` and every row of `/feed/since`
-- are a single-row read. A reader following five hundred people polls this
-- table five hundred times a minute and must never touch the log to do it.
CREATE TABLE IF NOT EXISTS feed (
    account    BLOB PRIMARY KEY,
    -- The lowest serial still held, and the highest ever accepted. `newest`
    -- does not go backwards when posts are evicted: the serial belongs to the
    -- author and this exchange never reissues one.
    oldest     INTEGER NOT NULL,
    newest     INTEGER NOT NULL,
    -- The next post's `prev`: SIP-31's `link` of the head's signing input.
    head_input BLOB    NOT NULL,
    posts      INTEGER NOT NULL,
    bytes      INTEGER NOT NULL,
    retention_secs INTEGER NOT NULL,
    max_posts  INTEGER NOT NULL
);
-- The log. `post` is the signed artifact stored whole and served back
-- verbatim, as SIP-32's profile record is: what a reader checks must be the
-- thing the author signed and not this exchange's copy of its fields.
--
-- `received` is the exchange's own observation of arrival and is what
-- retention and `expires_after` are measured from -- **never `issued_at`**,
-- which is the author's clock. Measured from that, an author sets it far
-- ahead and the post never prunes, or far behind and it vanishes on arrival.
CREATE TABLE IF NOT EXISTS post (
    account    BLOB    NOT NULL,
    serial     INTEGER NOT NULL,
    received   INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    post       BLOB    NOT NULL,
    PRIMARY KEY (account, serial)
);
CREATE INDEX IF NOT EXISTS post_by_expiry ON post (expires_at);
"#;

/// Every feed this exchange holds.
///
/// Named `Feeds` rather than `Feed` because `crate::events::Feed` is already a
/// subscriber's event queue and the two would read alike at a call site.
pub struct Feeds {
    db: Mutex<Connection>,
}

/// What a feed's head row says.
struct HeadRow {
    oldest: u64,
    newest: u64,
    head_input: [u8; 32],
    posts: u32,
    bytes: u64,
    retention_secs: u32,
    max_posts: u32,
}

impl Feeds {
    pub fn open(path: Option<&Path>) -> rusqlite::Result<Feeds> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch(SCHEMA)?;
        Ok(Feeds { db: Mutex::new(db) })
    }

    fn head_row(db: &Connection, account: &PubKey) -> Option<HeadRow> {
        db.query_row(
            "SELECT oldest, newest, head_input, posts, bytes, retention_secs, max_posts
             FROM feed WHERE account = ?1",
            params![account.as_bytes()],
            |r| {
                let head: Vec<u8> = r.get(2)?;
                Ok(HeadRow {
                    oldest: r.get::<_, i64>(0)? as u64,
                    newest: r.get::<_, i64>(1)? as u64,
                    head_input: head.try_into().unwrap_or([0; 32]),
                    posts: r.get::<_, i64>(3)? as u32,
                    bytes: r.get::<_, i64>(4)? as u64,
                    retention_secs: r.get::<_, i64>(5)? as u32,
                    max_posts: r.get::<_, i64>(6)? as u32,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Append a post to `account`'s own feed.
    ///
    /// `account` is the caller resolved to an account (SIP-22), and the post
    /// must name it: a device appends to its own account's feed and no other.
    pub fn append(
        &self,
        account: &PubKey,
        post: &Post,
        now: u64,
    ) -> Result<(u64, [u8; 32]), FeedError> {
        if &post.account != account {
            return Err(FeedError::NotYours);
        }
        if post.flags != 0 {
            return Err(FeedError::Reserved);
        }
        if post.body.len() > MAX_BODY {
            return Err(FeedError::TooLarge);
        }
        // The body must be the one the signature commits to. Checked before
        // the signature so a damaged body is reported as damage rather than
        // as a forgery -- without this an author could lodge a post
        // committing to bytes nobody read, and the tombstone it leaves behind
        // would commit to nothing.
        if !post.body_matches() {
            return Err(FeedError::BadBody);
        }
        if !post.verify() {
            return Err(FeedError::BadSignature);
        }

        let db = self.db.lock().unwrap();
        let held = Self::head_row(&db, account);
        let (newest, head_input, mut oldest, mut posts, mut bytes, retention, max) = match &held {
            Some(h) => (
                h.newest,
                h.head_input,
                h.oldest,
                h.posts,
                h.bytes,
                h.retention_secs,
                h.max_posts,
            ),
            None => (
                0,
                sqex_proto::entry_sig::GENESIS,
                0,
                0,
                0,
                sqex_proto::feed::DEFAULT_RETENTION,
                MAX_POSTS,
            ),
        };
        if post.serial != newest + 1 {
            return Err(FeedError::Stale);
        }
        if post.prev != head_input {
            return Err(FeedError::BrokenChain);
        }

        let bytes_in = post.encode();
        let expires_at = if post.expires_after == 0 {
            i64::MAX
        } else {
            now.saturating_add(u64::from(post.expires_after)) as i64
        };
        db.execute(
            "INSERT INTO post (account, serial, received, expires_at, post)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                account.as_bytes(),
                post.serial as i64,
                now as i64,
                expires_at,
                &bytes_in
            ],
        )
        .map_err(storage("insert post"))?;
        posts += 1;
        bytes += bytes_in.len() as u64;
        if oldest == 0 {
            oldest = post.serial;
        }

        // **Past the cap, evict from the oldest end rather than refuse.**
        //
        // This diverges from `mailbox.rs`, which refuses past its quota, and
        // the divergence is deliberate: SIP-16's `max_entries` is the
        // precedent, and SIP-88 gives the reason -- a feed its author must
        // garden is a feed that goes quiet. Eviction from the oldest end
        // leaves nothing behind, which is also what stops tombstones
        // accumulating without bound.
        while posts > max || bytes > MAX_FEED_BYTES {
            let Some((serial, len)) = db
                .query_row(
                    "SELECT serial, LENGTH(post) FROM post
                     WHERE account = ?1 ORDER BY serial ASC LIMIT 1",
                    params![account.as_bytes()],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                )
                .optional()
                .map_err(storage("find the oldest post"))?
            else {
                break;
            };
            if serial as u64 == post.serial {
                // The post just accepted is the only one left and is itself
                // over the byte cap. Nothing is gained by evicting it.
                break;
            }
            db.execute(
                "DELETE FROM post WHERE account = ?1 AND serial = ?2",
                params![account.as_bytes(), serial],
            )
            .map_err(storage("evict the oldest post"))?;
            posts = posts.saturating_sub(1);
            bytes = bytes.saturating_sub(len as u64);
            oldest = serial as u64 + 1;
        }

        let head = post.link();
        db.execute(
            "INSERT INTO feed (account, oldest, newest, head_input, posts, bytes,
                               retention_secs, max_posts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (account) DO UPDATE SET
                 oldest = ?2, newest = ?3, head_input = ?4, posts = ?5, bytes = ?6",
            params![
                account.as_bytes(),
                oldest as i64,
                post.serial as i64,
                &head[..],
                posts as i64,
                bytes as i64,
                retention as i64,
                max as i64
            ],
        )
        .map_err(storage("update the head"))?;
        Ok((post.serial, head))
    }

    /// A page of `subject`'s feed, as `caller` may see it.
    ///
    /// `blocked` is injected rather than read here: the block list is
    /// `Profiles`'s and the two services do not know each other's storage.
    pub fn read(
        &self,
        caller: &PubKey,
        req: &Read,
        now: u64,
        blocked: &dyn Fn(&PubKey, &PubKey) -> bool,
    ) -> Page {
        let subject = &req.account;
        if blocked(subject, caller) {
            return Page::none(now);
        }
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        let Some(head) = Self::head_row(&db, subject) else {
            return Page::none(now);
        };
        let want = req.limit.clamp(1, MAX_PAGE) as usize;
        let sql = if req.dir == DIR_BACKWARD {
            "SELECT received, post FROM post
             WHERE account = ?1 AND serial < ?2 ORDER BY serial DESC LIMIT ?3"
        } else {
            "SELECT received, post FROM post
             WHERE account = ?1 AND serial > ?2 ORDER BY serial ASC LIMIT ?3"
        };
        // Backward from 0 means from the end, and `u64::MAX` is how that is
        // said to a `serial <` comparison.
        let from = if req.dir == DIR_BACKWARD && req.since == 0 {
            i64::MAX
        } else {
            req.since as i64
        };
        let mut posts = Vec::new();
        let mut total = 0usize;
        if let Ok(mut stmt) = db.prepare(sql)
            && let Ok(rows) = stmt.query_map(params![subject.as_bytes(), from, want as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, Vec<u8>>(1)?))
            })
        {
            for row in rows.flatten() {
                let (received, bytes) = row;
                total += bytes.len();
                if total > MAX_PAGE_BYTES && !posts.is_empty() {
                    break;
                }
                let Ok(post) = Post::decode(&bytes) else {
                    continue;
                };
                posts.push(Stored { received, post });
            }
        }
        Page {
            found: true,
            oldest: head.oldest,
            newest: head.newest,
            now,
            posts,
        }
    }

    /// Where a feed has got to, as `caller` may see it.
    pub fn head(
        &self,
        caller: &PubKey,
        subject: &PubKey,
        now: u64,
        blocked: &dyn Fn(&PubKey, &PubKey) -> bool,
    ) -> Headed {
        if blocked(subject, caller) {
            return Headed::none(now);
        }
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        let Some(h) = Self::head_row(&db, subject) else {
            return Headed::none(now);
        };
        Headed {
            found: true,
            oldest: h.oldest,
            newest: h.newest,
            head_input: h.head_input,
            posts: h.posts,
            bytes: h.bytes,
            retention_secs: h.retention_secs,
            max_posts: h.max_posts,
            now,
            // SIP-88 §Succession is not built; the field is on the wire so
            // that building it is not a wire change.
            seams: Vec::new(),
        }
    }

    /// Drop a post's body, keeping its hash and signature.
    ///
    /// The tombstone is what keeps the serial space dense, and keeping the
    /// signature is what stops a withdrawn post reading as a forgery.
    pub fn withdraw(&self, account: &PubKey, serial: u64, now: u64) -> Result<(), FeedError> {
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        let held: Option<Vec<u8>> = db
            .query_row(
                "SELECT post FROM post WHERE account = ?1 AND serial = ?2",
                params![account.as_bytes(), serial as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("read a post to withdraw"))?;
        let Some(bytes) = held else {
            return Err(FeedError::NoSuchPost);
        };
        let post = Post::decode(&bytes).map_err(|_| FeedError::Storage)?;
        if post.withdrawn() {
            return Err(FeedError::NoSuchPost);
        }
        let stone = post.tombstone().encode();
        let freed = bytes.len().saturating_sub(stone.len()) as i64;
        db.execute(
            "UPDATE post SET post = ?3, expires_at = ?4 WHERE account = ?1 AND serial = ?2",
            params![account.as_bytes(), serial as i64, &stone, i64::MAX],
        )
        .map_err(storage("write a tombstone"))?;
        db.execute(
            "UPDATE feed SET bytes = MAX(0, bytes - ?2) WHERE account = ?1",
            params![account.as_bytes(), freed],
        )
        .map_err(storage("account for a withdrawal"))?;
        Ok(())
    }

    /// Set a feed's retention and size, whole. There is no partial update.
    pub fn set(
        &self,
        account: &PubKey,
        retention_secs: u32,
        max_posts: u32,
    ) -> Result<(), FeedError> {
        if !(MIN_RETENTION..=MAX_RETENTION).contains(&retention_secs) {
            return Err(FeedError::BadRetention);
        }
        if max_posts == 0 || max_posts > MAX_POSTS {
            return Err(FeedError::BadRetention);
        }
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO feed (account, oldest, newest, head_input, posts, bytes,
                               retention_secs, max_posts)
             VALUES (?1, 0, 0, ?4, 0, 0, ?2, ?3)
             ON CONFLICT (account) DO UPDATE SET retention_secs = ?2, max_posts = ?3",
            params![
                account.as_bytes(),
                retention_secs as i64,
                max_posts as i64,
                &sqex_proto::entry_sig::GENESIS[..]
            ],
        )
        .map_err(storage("set a feed's policy"))?;
        Ok(())
    }

    /// Where a feed has got to, for one row of a `/feed/since`. `None` where
    /// the caller is told nothing about it.
    /// Whether this exchange holds a feed for `account` at all.
    ///
    /// Not a read of the feed and not subject to blocking: the question is
    /// "does this account exist here", which `/account/home` needs to answer
    /// so that SIP-88 §Where a feed lives is true. Before this, an account
    /// that had only ever published a feed was unknown to `/account/home`,
    /// so a SIP-89 citation of it could not be resolved even on the exchange
    /// that was serving the feed.
    pub fn has_feed(&self, account: &PubKey) -> bool {
        let db = self.db.lock().unwrap();
        Self::head_row(&db, account).is_some()
    }

    pub fn moved(
        &self,
        caller: &PubKey,
        subject: &PubKey,
        now: u64,
        blocked: &dyn Fn(&PubKey, &PubKey) -> bool,
    ) -> Option<(u64, u64)> {
        if blocked(subject, caller) {
            return None;
        }
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        Self::head_row(&db, subject).map(|h| (h.oldest, h.newest))
    }

    /// Drop what has passed its own timer, leaving a tombstone.
    ///
    /// **A tombstone where SIP-16 prunes without one.** SIP-16 refuses a
    /// pruning tombstone because a shadow index of who spoke and when, long
    /// after the words are gone, is a worse disclosure than the gap. Here the
    /// index is already public -- it is the author's own signed serials,
    /// served to anybody -- so the tombstone discloses nothing new, and the
    /// dense serial space it preserves is worth more than the objection costs.
    fn expire(db: &Connection, now: u64) {
        let Ok(mut stmt) = db.prepare(
            "SELECT account, serial, post FROM post WHERE expires_at <= ?1 AND LENGTH(post) > ?2",
        ) else {
            return;
        };
        let Ok(rows) = stmt.query_map(
            params![now as i64, (sqex_proto::feed::POST_HEADER + 64) as i64],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            },
        ) else {
            return;
        };
        let due: Vec<_> = rows.flatten().collect();
        drop(stmt);
        for (account, serial, bytes) in due {
            let Ok(post) = Post::decode(&bytes) else {
                continue;
            };
            let stone = post.tombstone().encode();
            let freed = bytes.len().saturating_sub(stone.len()) as i64;
            let _ = db.execute(
                "UPDATE post SET post = ?3, expires_at = ?4 WHERE account = ?1 AND serial = ?2",
                params![&account, serial, &stone, i64::MAX],
            );
            let _ = db.execute(
                "UPDATE feed SET bytes = MAX(0, bytes - ?2) WHERE account = ?1",
                params![&account, freed],
            );
        }
    }

    /// Evict what is past its feed's retention, from the oldest end.
    ///
    /// Called from the periodic sweep rather than on every append: a feed may
    /// hold ten thousand posts and a retention scan is not something to do on
    /// the path a person is waiting on.
    pub fn sweep(&self, now: u64) -> usize {
        let db = self.db.lock().unwrap();
        Self::expire(&db, now);
        let Ok(mut stmt) = db.prepare("SELECT account, retention_secs FROM feed") else {
            return 0;
        };
        let Ok(rows) = stmt.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)? as u64))
        }) else {
            return 0;
        };
        let feeds: Vec<_> = rows.flatten().collect();
        drop(stmt);
        let mut dropped = 0usize;
        for (account, retention) in feeds {
            let cutoff = now.saturating_sub(retention) as i64;
            let gone = db
                .execute(
                    "DELETE FROM post WHERE account = ?1 AND received < ?2",
                    params![&account, cutoff],
                )
                .unwrap_or(0);
            if gone == 0 {
                continue;
            }
            dropped += gone;
            // `oldest` follows what is left; `newest` never goes backwards,
            // because the serial belongs to the author and this exchange does
            // not reissue one.
            let left: Option<(i64, i64, i64)> = db
                .query_row(
                    "SELECT MIN(serial), COUNT(*), COALESCE(SUM(LENGTH(post)), 0)
                     FROM post WHERE account = ?1",
                    params![&account],
                    |r| Ok((r.get(0).unwrap_or(0), r.get(1)?, r.get(2)?)),
                )
                .optional()
                .ok()
                .flatten();
            if let Some((oldest, posts, bytes)) = left {
                let _ = db.execute(
                    "UPDATE feed SET oldest = ?2, posts = ?3, bytes = ?4 WHERE account = ?1",
                    params![&account, oldest, posts, bytes],
                );
            }
        }
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn key(b: u8) -> PubKey {
        PubKey::new(SigningKey::from_bytes(&seed(b)).verifying_key().to_bytes())
    }

    fn nobody_blocked(_: &PubKey, _: &PubKey) -> bool {
        false
    }

    fn asking(account: PubKey, since: u64, limit: u16, dir: u8) -> Read {
        Read {
            account,
            since,
            limit,
            dir,
        }
    }

    /// Append `n` posts, returning the head after each.
    fn fill(f: &Feeds, author_seed: u8, n: u64, now: u64) -> [u8; 32] {
        let me = key(author_seed);
        let mut prev = sqex_proto::entry_sig::GENESIS;
        for serial in 1..=n {
            let p = Post::sign(
                &seed(author_seed),
                &me,
                serial,
                &prev,
                now + serial,
                0,
                format!("post {serial}").into_bytes(),
            );
            let (_, head) = f.append(&me, &p, now + serial).unwrap();
            prev = head;
        }
        prev
    }

    #[test]
    fn a_feed_is_appended_to_and_read_back() {
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        fill(&f, 1, 3, 1_000);

        let page = f.read(&key(2), &asking(me, 0, 10, 0), 2_000, &nobody_blocked);
        assert!(page.found);
        assert_eq!(page.oldest, 1);
        assert_eq!(page.newest, 3);
        assert_eq!(page.posts.len(), 3);
        assert!(page.posts.iter().all(|s| s.post.verify()));
        assert_eq!(page.posts[0].post.serial, 1, "forward pages oldest first");
    }

    #[test]
    fn a_feed_pages_backwards_from_the_end() {
        // The thing a channel's Fetch has no equivalent for: a reader
        // arriving at a long feed wants the last few, not the first few.
        let f = Feeds::open(None).unwrap();
        fill(&f, 1, 5, 1_000);
        let page = f.read(
            &key(2),
            &asking(key(1), 0, 2, DIR_BACKWARD),
            2_000,
            &nobody_blocked,
        );
        assert_eq!(page.posts.len(), 2);
        assert_eq!(page.posts[0].post.serial, 5, "newest first");
        assert_eq!(page.posts[1].post.serial, 4);
    }

    #[test]
    fn a_serial_that_is_not_the_next_one_is_refused_and_costs_nothing() {
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        let head = fill(&f, 1, 1, 1_000);

        // Two at once: the loser is refused, and the exchange numbered
        // nothing, so the same body re-signs at the higher serial.
        let a = Post::sign(&seed(1), &me, 2, &head, 1_001, 0, b"first".to_vec());
        let b = Post::sign(&seed(1), &me, 2, &head, 1_002, 0, b"second".to_vec());
        let (_, head2) = f.append(&me, &a, 1_001).unwrap();
        assert_eq!(f.append(&me, &b, 1_002), Err(FeedError::Stale));

        let again = Post::sign(&seed(1), &me, 3, &head2, 1_003, 0, b"second".to_vec());
        assert!(
            f.append(&me, &again, 1_003).is_ok(),
            "the loser could not re-sign"
        );
        let page = f.read(&key(2), &asking(me, 0, 10, 0), 2_000, &nobody_blocked);
        assert_eq!(page.posts.len(), 3, "the refusal left a gap");
    }

    #[test]
    fn a_broken_chain_is_refused_distinctly_from_a_stale_serial() {
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        fill(&f, 1, 1, 1_000);
        // The right serial, the wrong link.
        let p = Post::sign(&seed(1), &me, 2, &[9; 32], 1_002, 0, b"x".to_vec());
        assert_eq!(f.append(&me, &p, 1_002), Err(FeedError::BrokenChain));
    }

    #[test]
    fn nobody_appends_to_somebody_elses_feed() {
        let f = Feeds::open(None).unwrap();
        // Signed by 2's device, naming 2's account, offered as 1's.
        let theirs = Post::sign(
            &seed(2),
            &key(2),
            1,
            &sqex_proto::entry_sig::GENESIS,
            1_000,
            0,
            b"not mine".to_vec(),
        );
        assert_eq!(f.append(&key(1), &theirs, 1_000), Err(FeedError::NotYours));
    }

    #[test]
    fn a_damaged_body_is_refused_as_damage_and_not_as_a_forgery() {
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        let mut p = Post::sign(
            &seed(1),
            &me,
            1,
            &sqex_proto::entry_sig::GENESIS,
            1_000,
            0,
            b"real".to_vec(),
        );
        p.body = b"tampered".to_vec();
        assert_eq!(
            f.append(&me, &p, 1_000),
            Err(FeedError::BadBody),
            "a damaged body was called a forgery"
        );
    }

    #[test]
    fn a_withdrawal_leaves_a_tombstone_and_no_hole() {
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        fill(&f, 1, 3, 1_000);
        // The control: it is there, with a body, before the withdrawal.
        let before = f.read(&key(2), &asking(me, 0, 10, 0), 2_000, &nobody_blocked);
        assert!(
            before
                .posts
                .iter()
                .any(|s| s.post.serial == 2 && !s.post.withdrawn()),
            "the control failed: nothing was there to withdraw"
        );

        f.withdraw(&me, 2, 2_000).unwrap();
        let after = f.read(&key(2), &asking(me, 0, 10, 0), 2_000, &nobody_blocked);
        assert_eq!(after.posts.len(), 3, "the serial space grew a hole");
        let stone = after.posts.iter().find(|s| s.post.serial == 2).unwrap();
        assert!(stone.post.withdrawn());
        assert!(stone.post.verify(), "a tombstone read as forged");
        assert_eq!(f.withdraw(&me, 2, 2_000), Err(FeedError::NoSuchPost));
    }

    #[test]
    fn a_blocked_reader_is_told_exactly_what_a_stranger_to_an_empty_feed_is() {
        let f = Feeds::open(None).unwrap();
        fill(&f, 1, 2, 1_000);
        let blocks = |subject: &PubKey, caller: &PubKey| *subject == key(1) && *caller == key(3);
        let blocked = f.head(&key(3), &key(1), 5_000, &blocks);
        let absent = f.head(&key(3), &key(7), 5_000, &nobody_blocked);
        assert_eq!(blocked, absent, "a block is distinguishable from absence");
        assert_eq!(
            f.read(&key(3), &asking(key(1), 0, 10, 0), 5_000, &blocks),
            f.read(&key(3), &asking(key(7), 0, 10, 0), 5_000, &nobody_blocked)
        );
        // The control: unblocked, the same caller sees it.
        assert!(f.head(&key(3), &key(1), 5_000, &nobody_blocked).found);
    }

    #[test]
    fn a_post_past_its_timer_becomes_a_tombstone_rather_than_a_hole() {
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        let p = Post::sign(
            &seed(1),
            &me,
            1,
            &sqex_proto::entry_sig::GENESIS,
            1_000,
            60,
            b"fleeting".to_vec(),
        );
        f.append(&me, &p, 1_000).unwrap();
        let before = f.read(&key(2), &asking(me, 0, 10, 0), 1_030, &nobody_blocked);
        assert!(
            !before.posts[0].post.withdrawn(),
            "the control failed: it had already gone"
        );
        let after = f.read(&key(2), &asking(me, 0, 10, 0), 1_100, &nobody_blocked);
        assert_eq!(after.posts.len(), 1, "an expiry left a hole");
        assert!(after.posts[0].post.withdrawn());
    }

    #[test]
    fn past_the_cap_the_oldest_goes_and_oldest_follows_it() {
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        f.set(&me, MIN_RETENTION, 3).unwrap();
        fill(&f, 1, 5, 1_000);
        let page = f.read(&key(2), &asking(me, 0, 10, 0), 2_000, &nobody_blocked);
        assert_eq!(page.posts.len(), 3, "the cap did not bind");
        assert_eq!(page.oldest, 3);
        assert_eq!(page.newest, 5, "newest went backwards");
        assert_eq!(page.posts[0].post.serial, 3);
    }

    #[test]
    fn retention_runs_on_arrival_and_not_on_the_authors_clock() {
        // The author dates a post far in the future. If retention ran on
        // `issued_at` it would never prune; it runs on `received`.
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        let p = Post::sign(
            &seed(1),
            &me,
            1,
            &sqex_proto::entry_sig::GENESIS,
            4_000_000_000,
            0,
            b"from the future".to_vec(),
        );
        f.append(&me, &p, 1_000).unwrap();
        f.set(&me, MIN_RETENTION, MAX_POSTS).unwrap();
        assert_eq!(f.sweep(1_000 + MIN_RETENTION as u64 + 1), 1);
        assert!(
            f.read(&key(2), &asking(me, 0, 10, 0), 9_999_999, &nobody_blocked)
                .posts
                .is_empty(),
            "a post dated to the future outlived its retention"
        );
    }

    #[test]
    fn a_reserved_flag_is_refused() {
        let f = Feeds::open(None).unwrap();
        let me = key(1);
        let mut p = Post::sign(
            &seed(1),
            &me,
            1,
            &sqex_proto::entry_sig::GENESIS,
            1_000,
            0,
            b"x".to_vec(),
        );
        p.flags = 1;
        assert_eq!(f.append(&me, &p, 1_000), Err(FeedError::Reserved));
    }

    #[test]
    fn a_retention_outside_the_bounds_is_refused() {
        let f = Feeds::open(None).unwrap();
        assert_eq!(f.set(&key(1), 1, 10), Err(FeedError::BadRetention));
        assert_eq!(
            f.set(&key(1), MAX_RETENTION + 1, 10),
            Err(FeedError::BadRetention)
        );
        assert_eq!(
            f.set(&key(1), MIN_RETENTION, 0),
            Err(FeedError::BadRetention)
        );
        assert!(f.set(&key(1), MIN_RETENTION, 10).is_ok());
    }
}
