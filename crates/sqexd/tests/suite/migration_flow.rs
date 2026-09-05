//! Opening a database written by an older sqexd.
//!
//! **This file exists because nothing like it did, and a deployed exchange
//! broke.** `replicated` shipped in 0.31.0; `derivable` was added to its
//! `CREATE TABLE` body in 0.32.0, which does nothing for an exchange that
//! already has the table, because `CREATE TABLE IF NOT EXISTS` never adds a
//! column. Every `fetch` and `info` reads that column, so the exchange answered
//! `storage` to every one of them — and no test noticed, because every test
//! starts from an empty database where the `CREATE TABLE` is what runs.
//!
//! The rule these tests enforce: **a column added to an existing table needs an
//! `add_column`, not an edit to the schema string.** The schema string is what
//! a fresh database gets; `add_column` is what every other database gets, and
//! they have to agree.

use std::path::Path;

use rusqlite::Connection;
use sqexd::channel::Channels;
use sqnr_core::PubKey;

/// Every column the current schema declares, per table, read from a database
/// this build created from scratch.
fn columns_of(db: &Connection, table: &str) -> Vec<String> {
    let mut stmt = db
        .prepare(&format!("PRAGMA table_info({table})"))
        .expect("table_info");
    stmt.query_map([], |r| r.get::<_, String>(1))
        .expect("query table_info")
        .filter_map(|c| c.ok())
        .collect()
}

fn open_at(path: &Path) -> Channels {
    Channels::open(Some(path), PubKey::new([9u8; 32]), Some([9u8; 32])).unwrap()
}

/// **The regression.** A database whose `replicated` table predates
/// `derivable` — which is every exchange that ran 0.31.0 — must come back with
/// the column after this build opens it, and must answer a read rather than
/// `storage`.
#[test]
fn a_database_from_before_a_column_existed_gains_it_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("channels.db");

    // The 0.31.0 shape, written by hand: the table as it was, without the
    // column that came later.
    {
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS replicated (
                 channel BLOB PRIMARY KEY,
                 origin  BLOB NOT NULL,
                 window_secs INTEGER NOT NULL,
                 equivocation BLOB
             );",
        )
        .unwrap();
        assert!(
            !columns_of(&db, "replicated").contains(&"derivable".to_string()),
            "the fixture must start without the column, or it proves nothing"
        );
    }

    let store = open_at(&path);
    {
        let db = Connection::open(&path).unwrap();
        assert!(
            columns_of(&db, "replicated").contains(&"derivable".to_string()),
            "opening an older database did not add the column"
        );
    }

    // And the read path that broke works. A channel this exchange originated
    // has no `replicated` row at all, so this is the ordinary case that was
    // failing on every fetch.
    let channel = [1u8; 32];
    let caller = PubKey::new([2u8; 32]);
    let err = store.fetch(&caller, &caller, &channel, 0, false).unwrap_err();
    assert!(
        !matches!(err, sqexd::channel::ChannelError::Storage),
        "a fetch still fails with a storage error: {err:?}"
    );
    assert!(matches!(
        err,
        sqexd::channel::ChannelError::NoSuchChannel | sqexd::channel::ChannelError::NotAMember
    ));
    assert_eq!(store.origin_of(&channel), None);
}

/// The same failure one table over: a database from before SIP-34 added its
/// columns to `entry`. Those were migrated correctly, and this asserts it
/// rather than assuming — the bug above was one missing line among four
/// correct ones.
#[test]
fn a_database_from_before_receipts_gains_their_columns_too() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("channels.db");

    {
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS entry (
                 channel       BLOB    NOT NULL,
                 seq           INTEGER NOT NULL,
                 kind          INTEGER NOT NULL,
                 account       BLOB    NOT NULL,
                 device        BLOB    NOT NULL,
                 posted        INTEGER NOT NULL,
                 expires_after INTEGER NOT NULL,
                 epoch         INTEGER NOT NULL,
                 msg_seq       INTEGER NOT NULL,
                 chain_seq     INTEGER NOT NULL,
                 prev          BLOB    NOT NULL,
                 body_hash     BLOB    NOT NULL,
                 sig           BLOB    NOT NULL,
                 body          BLOB    NOT NULL,
                 PRIMARY KEY (channel, seq)
             );
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
                 instance       BLOB    NOT NULL
             );",
        )
        .unwrap();
    }

    let store = open_at(&path);
    let db = Connection::open(&path).unwrap();
    for column in ["entry_hash", "head", "receipt"] {
        assert!(
            columns_of(&db, "entry").contains(&column.to_string()),
            "entry.{column} was not added to an older database"
        );
    }
    for column in ["epoch_at", "head"] {
        assert!(
            columns_of(&db, "channel").contains(&column.to_string()),
            "channel.{column} was not added to an older database"
        );
    }
    let _ = store;
}

/// **The general guard, against the schema a release actually meets.**
///
/// `schema/deployed.sql` is the structure of the live exchange's database,
/// captured at a release. A database in that shape must come out of `open`
/// with every column a fresh one has — so a column added to a `CREATE TABLE`
/// body without a matching `add_column` fails here, before a deploy, instead
/// of when somebody's chat stops working.
///
/// It is deliberately a snapshot rather than something derived: its whole value
/// is being *behind* the current schema.
#[test]
fn a_database_in_the_shape_the_last_release_left_comes_up_to_date() {
    let dir = tempfile::tempdir().unwrap();
    let fresh_path = dir.path().join("fresh.db");
    let deployed_path = dir.path().join("deployed.db");

    let fresh = open_at(&fresh_path);
    {
        let db = Connection::open(&deployed_path).unwrap();
        db.execute_batch(include_str!("schema/deployed.sql"))
            .expect("the captured schema should be loadable");
    }
    let deployed = open_at(&deployed_path);

    let a = Connection::open(&fresh_path).unwrap();
    let b = Connection::open(&deployed_path).unwrap();
    let tables: Vec<String> = {
        let mut stmt = a
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        stmt.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|n| n.ok())
            .filter(|n| !n.starts_with("sqlite_"))
            .collect()
    };
    assert!(tables.len() > 10, "the schema should declare more than this");

    let mut missing: Vec<String> = Vec::new();
    for t in &tables {
        let want = columns_of(&a, t);
        let got = columns_of(&b, t);
        for column in want {
            if !got.contains(&column) {
                missing.push(format!("{t}.{column}"));
            }
        }
    }
    let _ = (fresh, deployed);
    assert!(
        missing.is_empty(),
        "these columns exist in a fresh database and not in an upgraded one, so a \
         deployed exchange answers `storage` the first time it reads them. Add an \
         `add_column` for each rather than editing the CREATE TABLE alone: {missing:?}"
    );
}
