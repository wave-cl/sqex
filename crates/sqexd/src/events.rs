//! SIP-30 subscribers: who is listening, and what they are owed.
//!
//! Deliberately the same shape as `Connections` in [`crate::server`]: a map
//! from a SIP-3 identity to the live things attached to it, added when a
//! connection arrives and removed when it goes. That one carries datagrams for
//! a relayed session; this one carries events for a chat client. Keeping them
//! alike is worth more than merging them — one is unreliable by design and the
//! other is not, and a single type would have to be honest about only one.
//!
//! # The queue, and what happens when it fills
//!
//! Each subscription is a bounded channel. A slow reader must not be able to
//! make the exchange buffer without limit on its behalf, so a full queue is not
//! waited on: the subscriber is marked **behind**, further events for it are
//! dropped, and the serving task replaces the whole backlog with one
//! [`Event::Resync`] as soon as it can write again.
//!
//! That is only safe because a SIP-30 event carries no news. Dropping a hundred
//! hints costs a client one extra fetch, because the fetch was always where the
//! truth was. If events carried payloads this design would be data loss.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sqex_proto::events::Event;
use sqnr_core::key::PubKey;
use tokio::sync::mpsc;

/// Events held for one subscriber before the backlog is replaced by a resync.
pub const QUEUE: usize = 256;

/// Streams one identity may hold open at once.
///
/// SIP-22 gives a person several devices and each runs a client, so this cannot
/// be one. It is small because it is a limit on abuse rather than on use: an
/// identity that wants a fifth stream has a bug or an intention.
pub const MAX_PER_IDENTITY: usize = 4;

/// One client's end of a subscription.
pub struct Feed {
    pub rx: mpsc::Receiver<Event>,
    /// Set by a publisher that found the queue full. The serving task swaps it
    /// back to false and writes one [`Event::Resync`] in place of everything it
    /// could not deliver.
    pub behind: Arc<AtomicBool>,
    /// Identifies this stream among an identity's several, so ending one does
    /// not end the others.
    pub id: u64,
    pub who: PubKey,
}

struct Sub {
    id: u64,
    tx: mpsc::Sender<Event>,
    behind: Arc<AtomicBool>,
}

/// Live event streams, by the identity that opened them.
#[derive(Default)]
pub struct Subscribers {
    by_identity: Mutex<HashMap<PubKey, Vec<Sub>>>,
    next: AtomicU64,
}

impl Subscribers {
    /// Open a stream for `who`, or `None` if they already hold the most this
    /// exchange will keep for one identity.
    pub fn subscribe(&self, who: PubKey) -> Option<Feed> {
        let mut map = self.by_identity.lock().unwrap();
        let subs = map.entry(who).or_default();
        if subs.len() >= MAX_PER_IDENTITY {
            return None;
        }
        let (tx, rx) = mpsc::channel(QUEUE);
        let behind = Arc::new(AtomicBool::new(false));
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        subs.push(Sub {
            id,
            tx,
            behind: Arc::clone(&behind),
        });
        Some(Feed {
            rx,
            behind,
            id,
            who,
        })
    }

    /// Forget one stream, and the identity entirely once its last one goes.
    pub fn unsubscribe(&self, feed: &Feed) {
        let mut map = self.by_identity.lock().unwrap();
        if let Some(subs) = map.get_mut(&feed.who) {
            subs.retain(|s| s.id != feed.id);
            if subs.is_empty() {
                map.remove(&feed.who);
            }
        }
    }

    /// Tell everybody in `to` that something changed.
    ///
    /// Best effort in both directions: a recipient with no stream open is
    /// skipped, and a recipient whose queue is full is marked behind rather
    /// than waited on. Nothing here blocks, and nothing here can fail in a way
    /// the caller could act on — which is why it returns nothing and why every
    /// call site can ignore it.
    ///
    /// **Never call this while holding the channel database lock.** The
    /// recipient list has to be read out of that database first, and the guard
    /// is not reentrant.
    pub fn publish(&self, to: &[PubKey], event: Event) {
        let mut map = self.by_identity.lock().unwrap();
        for who in to {
            let Some(subs) = map.get_mut(who) else {
                continue;
            };
            for sub in subs.iter_mut() {
                if sub.behind.load(Ordering::Relaxed) {
                    // Already owes a resync; another hint would be one more
                    // thing to throw away.
                    continue;
                }
                if sub.tx.try_send(event).is_err() {
                    sub.behind.store(true, Ordering::Relaxed);
                }
            }
        }
    }

    /// How many streams an identity holds. For tests and `/status`.
    pub fn count(&self, who: &PubKey) -> usize {
        self.by_identity
            .lock()
            .unwrap()
            .get(who)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Streams open across every identity.
    pub fn total(&self) -> usize {
        self.by_identity
            .lock()
            .unwrap()
            .values()
            .map(|v| v.len())
            .sum()
    }
}

/// Where a pumped event goes.
///
/// The exchange writes to an HTTP/3 response stream; a test writes to a vector.
/// Splitting them is what lets the two rules below — a resync replaces a
/// backlog, and silence is broken by a heartbeat — be checked without standing
/// up a connection to watch them through.
// The trait is used generically and never behind `dyn`, and both implementors
// are in this crate, so the auto-trait bounds this lint is about are decided at
// each call site rather than left unspecified for somebody else.
#[allow(async_fn_in_trait)]
pub trait Sink {
    async fn write(&mut self, event: Event) -> Result<(), ()>;
}

/// Drain a feed into a sink until one end gives out.
///
/// Two things happen here that are not just forwarding.
///
/// **A resync replaces the backlog rather than following it.** A subscriber
/// marked behind has already lost events, so the queued ones describe a world
/// with holes in it; delivering them and *then* saying "resync" would have the
/// client act on stale hints first. The check is at the top of the loop, before
/// anything is read.
///
/// **Silence is broken on a timer.** A quiet stream and a dead exchange look
/// identical from the client, and a QUIC connection outlives an application
/// that has stopped speaking. The heartbeat is the only thing that separates
/// them.
pub async fn pump<S: Sink>(feed: &mut Feed, sink: &mut S, heartbeat: std::time::Duration) {
    let mut beat = tokio::time::interval(heartbeat);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    beat.tick().await; // the first tick is immediate, and the head just went out

    loop {
        if feed.behind.swap(false, Ordering::Relaxed) {
            while feed.rx.try_recv().is_ok() {}
            if sink.write(Event::Resync).await.is_err() {
                return;
            }
            continue;
        }

        let event = tokio::select! {
            got = feed.rx.recv() => match got {
                Some(e) => e,
                // Every publisher is gone, which cannot happen while the
                // server lives. Treat it as the end rather than spinning.
                None => return,
            },
            _ = beat.tick() => Event::Heartbeat,
        };

        // The client went away. That is how these end, and it is not an error.
        if sink.write(event).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn key(n: u8) -> PubKey {
        PubKey::new([n; 32])
    }

    #[tokio::test]
    async fn an_event_reaches_a_subscriber_and_nobody_else() {
        let subs = Subscribers::default();
        let mut a = subs.subscribe(key(1)).unwrap();
        let mut b = subs.subscribe(key(2)).unwrap();

        subs.publish(&[key(1)], Event::Heartbeat);

        assert_eq!(a.rx.try_recv().ok(), Some(Event::Heartbeat));
        assert!(
            b.rx.try_recv().is_err(),
            "published to an unaddressed identity"
        );
    }

    #[tokio::test]
    async fn every_stream_an_identity_holds_is_told() {
        let subs = Subscribers::default();
        let mut one = subs.subscribe(key(1)).unwrap();
        let mut two = subs.subscribe(key(1)).unwrap();

        subs.publish(&[key(1)], Event::Admission);

        assert_eq!(one.rx.try_recv().ok(), Some(Event::Admission));
        assert_eq!(two.rx.try_recv().ok(), Some(Event::Admission));
    }

    #[tokio::test]
    async fn a_reader_that_stops_reading_is_marked_behind_rather_than_buffered() {
        let subs = Subscribers::default();
        let feed = subs.subscribe(key(1)).unwrap();

        for _ in 0..QUEUE + 50 {
            subs.publish(&[key(1)], Event::Heartbeat);
        }

        assert!(
            feed.behind.load(Ordering::Relaxed),
            "an overrun subscriber was not marked behind"
        );
        // The bound is the point: the queue holds QUEUE and not one more.
        assert_eq!(feed.rx.len(), QUEUE);
    }

    #[tokio::test]
    async fn an_identity_cannot_hold_more_streams_than_the_cap() {
        let subs = Subscribers::default();
        let held: Vec<_> = (0..MAX_PER_IDENTITY)
            .map(|_| subs.subscribe(key(1)).unwrap())
            .collect();
        assert!(subs.subscribe(key(1)).is_none());
        assert_eq!(subs.count(&key(1)), MAX_PER_IDENTITY);

        // And one going away makes room for one more, rather than the cap
        // being a lifetime total.
        subs.unsubscribe(&held[0]);
        assert_eq!(subs.count(&key(1)), MAX_PER_IDENTITY - 1);
        assert!(subs.subscribe(key(1)).is_some());
    }

    #[tokio::test]
    async fn the_last_stream_leaving_forgets_the_identity() {
        let subs = Subscribers::default();
        let feed = subs.subscribe(key(1)).unwrap();
        assert_eq!(subs.total(), 1);
        subs.unsubscribe(&feed);
        assert_eq!(subs.total(), 0);
        assert_eq!(subs.count(&key(1)), 0);
    }

    #[tokio::test]
    async fn publishing_to_nobody_is_not_an_error() {
        let subs = Subscribers::default();
        subs.publish(&[key(9)], Event::Heartbeat);
        assert_eq!(subs.total(), 0);
    }

    /// Collects what the pump writes, and can be told to break.
    #[derive(Default)]
    struct Recorder {
        got: std::sync::Arc<Mutex<Vec<Event>>>,
        /// Fail the write once this many have been taken, so a test can end the
        /// pump at a point it chooses.
        stop_after: usize,
    }

    impl Sink for Recorder {
        async fn write(&mut self, event: Event) -> Result<(), ()> {
            let mut got = self.got.lock().unwrap();
            if got.len() >= self.stop_after {
                return Err(());
            }
            got.push(event);
            Ok(())
        }
    }

    fn recorder(stop_after: usize) -> (Recorder, std::sync::Arc<Mutex<Vec<Event>>>) {
        let got = std::sync::Arc::new(Mutex::new(Vec::new()));
        (
            Recorder {
                got: std::sync::Arc::clone(&got),
                stop_after,
            },
            got,
        )
    }

    #[tokio::test]
    async fn what_is_published_is_what_is_written() {
        let subs = Subscribers::default();
        let mut feed = subs.subscribe(key(1)).unwrap();
        let want = Event::Channel {
            channel: [3; 32],
            last_seq: 7,
        };
        subs.publish(&[key(1)], want);

        // Dropping the publisher is what lets the pump finish: with nothing
        // left to send and no heartbeat due for an hour, it would otherwise sit
        // waiting — which is exactly what it should do in service.
        drop(subs);

        let (mut rec, got) = recorder(2);
        pump(&mut feed, &mut rec, Duration::from_secs(3600)).await;

        assert_eq!(*got.lock().unwrap(), vec![want]);
    }

    /// The rule that makes the drop-on-overflow policy safe: a client that fell
    /// behind is told so *before* it is told anything else. Delivering the
    /// queued hints first would have it act on a world it can no longer see.
    #[tokio::test]
    async fn a_backlog_is_replaced_by_one_resync_and_not_followed_by_it() {
        let subs = Subscribers::default();
        let mut feed = subs.subscribe(key(1)).unwrap();

        // Enough to overflow: the queue fills and the rest mark it behind.
        for i in 0..QUEUE + 10 {
            subs.publish(
                &[key(1)],
                Event::Channel {
                    channel: [1; 32],
                    last_seq: i as u64,
                },
            );
        }
        assert!(
            feed.behind.load(Ordering::Relaxed),
            "control: never overflowed"
        );
        drop(subs);

        let (mut rec, got) = recorder(2);
        pump(&mut feed, &mut rec, Duration::from_secs(3600)).await;

        let written = got.lock().unwrap().clone();
        assert_eq!(
            written,
            vec![Event::Resync],
            "the backlog was delivered instead of replaced"
        );
        // And the backlog is gone rather than waiting behind the resync.
        assert!(
            feed.rx.try_recv().is_err(),
            "stale hints survived the resync"
        );
    }

    /// A stream with nothing to say still has to say so, or a client cannot
    /// tell it from an exchange that stopped.
    #[tokio::test]
    async fn a_silent_stream_still_beats() {
        let subs = Subscribers::default();
        let mut feed = subs.subscribe(key(1)).unwrap();
        // Nothing is ever published to this one.

        let (mut rec, got) = recorder(3);
        pump(&mut feed, &mut rec, Duration::from_millis(5)).await;

        assert_eq!(
            *got.lock().unwrap(),
            vec![Event::Heartbeat; 3],
            "a quiet stream said nothing at all"
        );
    }

    /// A client that goes away ends the pump instead of spinning against a
    /// stream nobody is reading.
    #[tokio::test]
    async fn a_broken_sink_ends_the_pump() {
        let subs = Subscribers::default();
        let mut feed = subs.subscribe(key(1)).unwrap();
        subs.publish(&[key(1)], Event::Admission);

        let (mut rec, got) = recorder(0);
        // Returns rather than hanging: that it completes at all is the test.
        pump(&mut feed, &mut rec, Duration::from_millis(5)).await;

        assert!(got.lock().unwrap().is_empty());
    }
}
