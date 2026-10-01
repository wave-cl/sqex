//! The operator's live view: who is watching, and what they are owed.
//!
//! Deliberately the same shape as [`crate::events`] beside it — a registry, a
//! bounded queue per watcher, a pump that drains into a sink. The differences
//! are all consequences of one thing: an event stream belongs to an account
//! and is part of the service, while a tail belongs to an operator and is a
//! **diagnostic that must never cost the service anything**.
//!
//! # What that buys and what it costs
//!
//! **Nobody watching costs nothing.** [`Tails::publish`] takes a closure and
//! checks one relaxed atomic before calling it, so on the ordinary path — no
//! operator attached — a record is never built, nothing is formatted, and
//! nothing is allocated. That is the whole reason the emission points can sit
//! on the request path at all.
//!
//! **A slow watcher is dropped past, not waited for.** A full queue is never
//! blocked on; the lines are discarded and counted, and the count is *sent* as
//! [`Record::Dropped`] rather than left to be inferred. SIP-12 gives the
//! reason: a relay that silently discards is indistinguishable from one that
//! delivers. SIP-30's stream answers the same problem with a resync, which
//! works there because an event carries no news and the client can re-fetch;
//! here there is nothing to re-fetch, so the honest answer is to say how much
//! was lost.
//!
//! `seq` therefore counts lines *sent to this watcher*, not lines produced, so
//! a gap in it is impossible and loss is only ever reported outright.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, atomic::AtomicUsize};

use sqex_proto::tail::{Line, Record, wanted};
use tokio::sync::mpsc;

/// Lines held for one watcher before they start being discarded.
///
/// Larger than SIP-30's queue because a tail sees far more than one account's
/// events — a busy exchange produces a line per request — and because the
/// consequence of overflow is worse: an event stream's overflow costs a fetch,
/// and a tail's costs information nothing can recover.
pub const QUEUE: usize = 512;

/// Watchers at once.
///
/// Two, not one, so an operator can open a second while a first is wedged; and
/// not more, because each is a fan-out the request path pays for and this is a
/// diagnostic rather than a subscription service.
pub const MAX_TAILS: usize = 2;

/// One operator's end of a tail.
pub struct Watch {
    pub rx: mpsc::Receiver<Line>,
    pub id: u64,
    /// Lines discarded because this watcher was not keeping up. The pump reads
    /// and clears it, and reports the count in the stream.
    pub dropped: Arc<AtomicU64>,
    /// Counts lines sent to *this* watcher, so the sequence it sees has no
    /// gaps and loss is only ever said with `Dropped`.
    pub seq: Arc<AtomicU64>,
}

struct Sub {
    id: u64,
    kinds: u16,
    tx: mpsc::Sender<Line>,
    dropped: Arc<AtomicU64>,
    seq: Arc<AtomicU64>,
}

/// Live tails, and the fast path for when there are none.
#[derive(Default)]
pub struct Tails {
    subs: Mutex<Vec<Sub>>,
    next: AtomicU64,
    /// Read on every emission point, so it is the thing that must be cheap.
    /// Kept in step with `subs` under the same lock; a stale `true` costs one
    /// wasted record build and a stale `false` cannot happen, because it is
    /// set before the watcher is returned.
    watching: AtomicBool,
    /// How many watchers have ever been opened, for `/status`.
    opened: AtomicUsize,
}

impl Tails {
    pub fn new() -> Tails {
        Tails::default()
    }

    /// Open a tail, or `None` if the exchange already carries the most it will.
    pub fn open(&self, kinds: u16) -> Option<Watch> {
        let mut subs = self.subs.lock().unwrap();
        if subs.len() >= MAX_TAILS {
            return None;
        }
        let (tx, rx) = mpsc::channel(QUEUE);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let dropped = Arc::new(AtomicU64::new(0));
        let seq = Arc::new(AtomicU64::new(0));
        subs.push(Sub {
            id,
            kinds,
            tx,
            dropped: Arc::clone(&dropped),
            seq: Arc::clone(&seq),
        });
        self.watching.store(true, Ordering::Relaxed);
        self.opened.fetch_add(1, Ordering::Relaxed);
        Some(Watch {
            rx,
            id,
            dropped,
            seq,
        })
    }

    pub fn close(&self, watch: &Watch) {
        let mut subs = self.subs.lock().unwrap();
        subs.retain(|s| s.id != watch.id);
        self.watching.store(!subs.is_empty(), Ordering::Relaxed);
    }

    /// Whether anybody is watching. The emission points call this before doing
    /// any work at all.
    pub fn watching(&self) -> bool {
        self.watching.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.subs.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total tails opened since start. For `/status`, so the capability is
    /// visible to anybody reading the exchange rather than only in the audit
    /// log.
    pub fn opened(&self) -> usize {
        self.opened.load(Ordering::Relaxed)
    }

    /// Offer a record, building it only if somebody is watching.
    ///
    /// **Never blocks and never awaits.** It is called from the request path
    /// and, like [`crate::events::Subscribers::publish`], it must not be
    /// called while holding the channel database lock — reading a member list
    /// takes that same non-reentrant guard.
    pub fn publish<F: FnOnce() -> Record>(&self, make: F) {
        if !self.watching.load(Ordering::Relaxed) {
            return;
        }
        let mut subs = self.subs.lock().unwrap();
        if subs.is_empty() {
            return;
        }
        let record = make();
        let kind = record.kind();
        let at = crate::state::now_unix();
        for sub in subs.iter_mut() {
            if !wanted(sub.kinds, kind) {
                continue;
            }
            let line = Line {
                at,
                seq: sub.seq.fetch_add(1, Ordering::Relaxed),
                record: record.clone(),
            };
            if sub.tx.try_send(line).is_err() {
                // Undo the sequence number: it belongs to a line that was
                // never sent, and a watcher must see an unbroken run.
                sub.seq.fetch_sub(1, Ordering::Relaxed);
                sub.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Where a pumped line goes. The exchange writes to an HTTP/3 response stream;
/// a test writes to a vector.
///
/// Parallel to [`crate::events::Sink`] rather than the same trait: that one is
/// typed to `Event`, and generifying a shipped trait to share three lines here
/// would change two implementors and their tests for no gain.
#[allow(async_fn_in_trait)]
pub trait Sink {
    async fn write(&mut self, line: Line) -> Result<(), ()>;
}

/// Drain a watch into a sink until one end gives out.
///
/// Two things happen that are not forwarding. **A drop count is reported
/// before the lines that follow it**, so a reader learns it lost something at
/// the point it lost it rather than at the end. **Silence is broken on a
/// timer**, because a quiet exchange and a dead one are the same from the far
/// side of a connection that outlives the application.
pub async fn pump<S: Sink>(watch: &mut Watch, sink: &mut S, heartbeat: std::time::Duration) {
    let mut beat = tokio::time::interval(heartbeat);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    beat.tick().await; // the first tick is immediate, and the head just went out

    loop {
        let missed = watch.dropped.swap(0, Ordering::Relaxed);
        if missed > 0 {
            let line = Line {
                at: crate::state::now_unix(),
                seq: watch.seq.fetch_add(1, Ordering::Relaxed),
                record: Record::Dropped { records: missed },
            };
            if sink.write(line).await.is_err() {
                return;
            }
            continue;
        }

        let line = tokio::select! {
            got = watch.rx.recv() => match got {
                Some(l) => l,
                // Every publisher is gone, which cannot happen while the
                // server lives. Treat it as the end rather than spinning.
                None => return,
            },
            _ = beat.tick() => Line {
                at: crate::state::now_unix(),
                seq: watch.seq.fetch_add(1, Ordering::Relaxed),
                record: Record::Heartbeat,
            },
        };

        // The operator went away. That is how these end, and it is not an error.
        if sink.write(line).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqex_proto::tail::{WANT_ALL, WANT_REQUEST};
    use std::time::Duration;

    fn a_request() -> Record {
        Record::Request {
            account: None,
            route: "/status".into(),
            status: 200,
            micros: 1,
            conn: 1,
        }
    }

    struct Recorder(Vec<Line>);
    impl Sink for Recorder {
        async fn write(&mut self, line: Line) -> Result<(), ()> {
            self.0.push(line);
            Ok(())
        }
    }

    /// The property the emission points depend on: with nobody watching, the
    /// record is never built. Proved by a closure that panics.
    #[test]
    fn nobody_watching_never_builds_the_record() {
        let tails = Tails::new();
        assert!(!tails.watching());
        tails.publish(|| panic!("a record was built with nobody watching"));
    }

    #[test]
    fn a_closed_tail_stops_the_fast_path_again() {
        let tails = Tails::new();
        let w = tails.open(WANT_ALL).expect("opens");
        assert!(tails.watching());
        tails.close(&w);
        assert!(!tails.watching());
        tails.publish(|| panic!("a record was built after the tail closed"));
    }

    #[test]
    fn only_two_tails_at_once() {
        let tails = Tails::new();
        let a = tails.open(WANT_ALL).expect("first");
        let _b = tails.open(WANT_ALL).expect("second");
        assert!(tails.open(WANT_ALL).is_none(), "a third was allowed");
        tails.close(&a);
        assert!(tails.open(WANT_ALL).is_some(), "a slot did not free");
    }

    #[test]
    fn a_narrowed_tail_sees_only_what_it_asked_for() {
        let tails = Tails::new();
        let mut w = tails.open(WANT_REQUEST).expect("opens");
        tails.publish(a_request);
        tails.publish(|| Record::Admin {
            admin: sqnr_core::PubKey::new([1u8; 32]),
            action: "whitelist-add".into(),
        });
        let first = w.rx.try_recv().expect("the request line");
        assert_eq!(first.record.kind(), sqex_proto::tail::KIND_REQUEST);
        assert!(w.rx.try_recv().is_err(), "the admin line was not filtered");
    }

    /// Overflow is counted rather than blocked on, and the count reaches the
    /// reader. The control is the assertion that `seq` has no gap: a watcher
    /// must never have to infer loss from a jump.
    #[tokio::test]
    async fn overflow_is_reported_and_the_sequence_has_no_hole() {
        let tails = Tails::new();
        let mut w = tails.open(WANT_ALL).expect("opens");
        for _ in 0..(QUEUE + 25) {
            tails.publish(a_request);
        }
        assert!(
            w.dropped.load(Ordering::Relaxed) >= 25,
            "overflow was not counted"
        );

        let mut sink = Recorder(Vec::new());
        // One pass of the pump reports the drop before anything else.
        let missed = w.dropped.swap(0, Ordering::Relaxed);
        sink.write(Line {
            at: 0,
            seq: w.seq.fetch_add(1, Ordering::Relaxed),
            record: Record::Dropped { records: missed },
        })
        .await
        .unwrap();
        while let Ok(l) = w.rx.try_recv() {
            sink.write(l).await.unwrap();
        }

        let mut seqs: Vec<u64> = sink.0.iter().map(|l| l.seq).collect();
        seqs.sort_unstable();
        for (i, s) in seqs.iter().enumerate() {
            assert_eq!(*s, i as u64, "the sequence a watcher sees has a hole");
        }
        assert!(
            sink.0
                .iter()
                .any(|l| matches!(l.record, Record::Dropped { records } if records >= 25)),
            "the drop was never reported"
        );
    }

    /// Measurement, not an assertion. The emission points sit on the request
    /// path, so the claim "a tail nobody is watching costs nothing" is the one
    /// that has to be true; `nobody_watching_never_builds_the_record` proves
    /// the record is never built, and this says what the check itself costs.
    ///
    /// ```text
    /// cargo test -p sqexd --lib -- --ignored --nocapture tail::tests::what_publishing_costs
    /// ```
    #[test]
    #[ignore]
    fn what_publishing_costs() {
        const N: u32 = 1_000_000;
        let idle = Tails::new();
        let began = std::time::Instant::now();
        for _ in 0..N {
            idle.publish(a_request);
        }
        let quiet = began.elapsed();

        let busy = Tails::new();
        let mut w = busy.open(WANT_ALL).expect("opens");
        let began = std::time::Instant::now();
        for _ in 0..N {
            busy.publish(a_request);
            let _ = w.rx.try_recv();
        }
        let watched = began.elapsed();

        println!(
            "publish with nobody watching: {:.1} ns/call\npublish with one watcher:     {:.1} ns/call",
            quiet.as_nanos() as f64 / N as f64,
            watched.as_nanos() as f64 / N as f64,
        );
    }

    #[tokio::test]
    async fn silence_is_broken_by_a_heartbeat() {
        let tails = Tails::new();
        let mut w = tails.open(WANT_ALL).expect("opens");
        let mut sink = Recorder(Vec::new());
        let _ = tokio::time::timeout(
            Duration::from_millis(120),
            pump(&mut w, &mut sink, Duration::from_millis(20)),
        )
        .await;
        assert!(
            sink.0.iter().any(|l| l.record == Record::Heartbeat),
            "a quiet tail sent nothing, so it cannot be told from a dead one"
        );
    }
}
