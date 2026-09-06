//! SIP-25: pairing two identities that have each asked for the other.
//!
//! **An introduction is served only when both sides have asked.** That is the
//! consent rule and it is not a refinement: an identity that could request an
//! introduction to anyone could locate anyone bound to this exchange, and a
//! coordinated pair of simultaneous connections to an address a third party
//! chose is the shape a reflection abuse takes.
//!
//! Until the pair completes, a request discloses nothing — not the address, and
//! not that anybody asked, which would itself be a signal about somebody who
//! has not consented.
//!
//! In memory, like the beacon: a pending introduction is seconds old by
//! construction, and one that survived a restart would be pairing two parties
//! who have both since gone.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use sqex_proto::rendezvous::{Introduced, START_LEAD_SECS};
use sqnr_core::PubKey;
use tokio::sync::Notify;

use crate::state::now_unix;

/// How long a request stays outstanding after the caller stops waiting.
///
/// Slightly longer than the longest wait, so a pair that arrives just as one
/// side gives up still completes for the other rather than both sides missing
/// each other by a second.
const PENDING_TTL: u64 = 45;

/// One outstanding request.
#[derive(Debug, Clone, Copy)]
struct Asked {
    /// Where the exchange saw this caller. **Observed, never asserted.**
    addr: SocketAddr,
    at: u64,
    /// Set once the pair completed, so both sides are told the same moment to
    /// begin — the second caller must not compute a later start than the first
    /// was already given.
    start_at: Option<u64>,
}

/// Who has asked to meet whom.
#[derive(Default)]
pub struct Rendezvous {
    asked: Mutex<HashMap<(PubKey, PubKey), Asked>>,
    /// One notifier per unordered pair, so the party already waiting wakes the
    /// instant the other arrives rather than on a poll interval. A coordinated
    /// start is only as good as how close together the two answers are.
    waiters: Mutex<HashMap<(PubKey, PubKey), Arc<Notify>>>,
}

impl Rendezvous {
    pub fn new() -> Rendezvous {
        Rendezvous::default()
    }

    /// The notifier for a pair, in a stable order so both sides find the same
    /// one whichever way round they name each other.
    fn notifier(&self, a: &PubKey, b: &PubKey) -> Arc<Notify> {
        let pair = if a.as_bytes() <= b.as_bytes() {
            (*a, *b)
        } else {
            (*b, *a)
        };
        Arc::clone(
            self.waiters
                .lock()
                .unwrap()
                .entry(pair)
                .or_insert_with(|| Arc::new(Notify::new())),
        )
    }

    /// Record that `asker` wants to meet `peer`, and answer if both now do.
    ///
    /// **An identity cannot ask to meet itself**, which would introduce a
    /// caller to its own address for no purpose and is the degenerate case a
    /// consent rule keyed on a pair has to exclude explicitly.
    pub fn request(&self, asker: &PubKey, addr: SocketAddr, peer: &PubKey) -> Introduced {
        let now = now_unix();
        if asker == peer {
            return Introduced::waiting(now);
        }
        let mut asked = self.asked.lock().unwrap();
        asked.retain(|_, a| now.saturating_sub(a.at) < PENDING_TTL);
        asked.insert(
            (*asker, *peer),
            Asked {
                addr,
                at: now,
                start_at: None,
            },
        );

        // The other direction, asked independently. Nothing about this request
        // creates it, which is what "genuinely independent" means in SIP-25's
        // reflection argument.
        let Some(theirs) = asked.get(&(*peer, *asker)).copied() else {
            return Introduced::waiting(now);
        };

        // One start for both sides. Whoever completes the pair computes it; the
        // other reads it back, so neither is told a moment the other was not.
        let start_at = theirs.start_at.unwrap_or(now + START_LEAD_SECS);
        if let Some(mine) = asked.get_mut(&(*asker, *peer)) {
            mine.start_at = Some(start_at);
        }
        if let Some(t) = asked.get_mut(&(*peer, *asker)) {
            t.start_at = Some(start_at);
        }
        drop(asked);
        self.notifier(asker, peer).notify_waiters();

        Introduced {
            ready: true,
            addr: Some(theirs.addr),
            start_at,
            now,
        }
    }

    /// What this caller would be told now, without recording a new request.
    pub fn poll(&self, asker: &PubKey, peer: &PubKey) -> Introduced {
        let now = now_unix();
        let asked = self.asked.lock().unwrap();
        match (asked.get(&(*asker, *peer)), asked.get(&(*peer, *asker))) {
            (Some(mine), Some(theirs))
                if now.saturating_sub(theirs.at) < PENDING_TTL
                    && now.saturating_sub(mine.at) < PENDING_TTL =>
            {
                Introduced {
                    ready: true,
                    addr: Some(theirs.addr),
                    start_at: mine.start_at.unwrap_or(now + START_LEAD_SECS),
                    now,
                }
            }
            _ => Introduced::waiting(now),
        }
    }

    /// Wait for the other side, up to `wait_secs`.
    ///
    /// The first party to ask holds its request open; the second completes the
    /// pair and both are answered within a wake-up of each other. Polling would
    /// have worked and would have made the two answers as far apart as the poll
    /// interval, which is the one thing a coordinated start cannot afford.
    pub async fn wait(&self, asker: &PubKey, peer: &PubKey, wait_secs: u16) -> Introduced {
        let first = self.request(asker, self.observed(asker, peer), peer);
        if first.ready || wait_secs == 0 {
            return first;
        }
        let notify = self.notifier(asker, peer);
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(u64::from(wait_secs));
        loop {
            if tokio::time::timeout_at(deadline, notify.notified())
                .await
                .is_err()
            {
                return self.poll(asker, peer);
            }
            let again = self.poll(asker, peer);
            if again.ready {
                return again;
            }
        }
    }

    /// The address already recorded for this asker, for a re-request inside a
    /// wait. Falls back to an unspecified address, which `request` will replace
    /// on the next real call.
    fn observed(&self, asker: &PubKey, peer: &PubKey) -> SocketAddr {
        self.asked
            .lock()
            .unwrap()
            .get(&(*asker, *peer))
            .map(|a| a.addr)
            .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// Drop what has expired.
    pub fn sweep(&self) {
        let now = now_unix();
        let mut asked = self.asked.lock().unwrap();
        asked.retain(|_, a| now.saturating_sub(a.at) < PENDING_TTL);
        let live: Vec<(PubKey, PubKey)> = asked.keys().copied().collect();
        self.waiters
            .lock()
            .unwrap()
            .retain(|(a, b), _| live.contains(&(*a, *b)) || live.contains(&(*b, *a)));
    }

    /// How many requests are outstanding. For `/status`.
    pub fn len(&self) -> usize {
        self.asked.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn pk(b: u8) -> PubKey {
        PubKey::new(SigningKey::from_bytes(&[b; 32]).verifying_key().to_bytes())
    }
    fn addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 5400))
    }

    /// The bug this fixes: `waiters` gained one `Notify` per distinct pair that
    /// ever long-polled and nothing reclaimed them, because `sweep()` had no
    /// caller. With no live `asked` entries, a sweep must drop them all.
    #[test]
    fn stale_waiters_are_reclaimed_by_sweep() {
        let r = Rendezvous::new();
        let a = pk(1);
        for i in 2..12u8 {
            // What `wait()` does when the first ask does not complete.
            r.notifier(&a, &pk(i));
        }
        assert_eq!(r.waiters.lock().unwrap().len(), 10);
        r.sweep(); // no matching asks were recorded, so every waiter is stale
        assert!(r.waiters.lock().unwrap().is_empty());
        assert!(r.is_empty());
    }

    /// A sweep must not disturb a pair that is still within its window — an
    /// in-flight wait keeps both its `asked` entry and its notifier.
    #[test]
    fn a_live_pair_survives_a_sweep() {
        let r = Rendezvous::new();
        let (a, b) = (pk(1), pk(2));
        let _ = r.request(&a, addr(), &b); // records a fresh `asked` entry
        r.notifier(&a, &b); // and its waiter
        r.sweep();
        assert_eq!(r.len(), 1);
        assert_eq!(r.waiters.lock().unwrap().len(), 1);
    }
}
