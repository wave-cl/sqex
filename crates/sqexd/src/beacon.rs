//! The SIP-4 liveness beacon: what the exchange has observed.
//!
//! An identity connects and beats; this records *when it last did so*, keyed by
//! the Ed25519 identity the transport bound (SIP-3), never by the X25519 key it
//! verified and never by the address it came from. Publishing the address would
//! turn a liveness service into a location service, which SIP-4 forbids.
//!
//! State is in memory only. A restart is an honest gap in observation — the
//! exchange stops having seen anything, which is exactly true — and a beacon
//! whose identities beat every minute repopulates within a minute. Persisting it
//! would mean replaying observations the process did not make.
//!
//! Nothing here decides liveness. It reports a timestamp and the interval the
//! identity declared, and lets each consumer choose its own tolerance; SIP-4
//! requires that an exchange not answer "up" or "down" on a consumer's behalf.

use std::collections::HashMap;
use std::sync::Mutex;

use sqex_proto::beacon::Reply;
use sqnr_core::PubKey;

use crate::state::now_unix;

/// One identity's last observation.
#[derive(Debug, Clone, Copy)]
struct Observation {
    last_seen: u64,
    interval_secs: u32,
    /// Withheld from queries by any identity other than its owner.
    withhold: bool,
}

/// Every identity the exchange has seen beat.
#[derive(Default)]
pub struct Beacons {
    seen: Mutex<HashMap<PubKey, Observation>>,
}

impl Beacons {
    pub fn new() -> Beacons {
        Beacons::default()
    }

    /// Record that `identity` beat now. Returns the time recorded, which the
    /// caller acknowledges so a beating identity learns the exchange's clock.
    pub fn record(&self, identity: PubKey, interval_secs: u32, withhold: bool) -> u64 {
        let now = now_unix();
        self.seen.lock().unwrap().insert(
            identity,
            Observation {
                last_seen: now,
                interval_secs,
                withhold,
            },
        );
        now
    }

    /// What the exchange can tell `asker` about `target`.
    ///
    /// A withheld record is disclosed only to its owner, so `asker` is the
    /// querier's own bound identity, or `None` for an anonymous querier (who is
    /// therefore never the owner). Reading is otherwise open: SIP-4 privileges
    /// beating, not asking.
    pub fn read(&self, target: &PubKey, asker: Option<&PubKey>) -> Reply {
        let now = now_unix();
        let seen = self.seen.lock().unwrap();
        match seen.get(target) {
            Some(o) if !o.withhold || asker == Some(target) => Reply {
                found: true,
                last_seen: o.last_seen,
                interval_secs: o.interval_secs,
                now,
            },
            // Withheld records are reported exactly as absent ones: telling a
            // stranger "this exists but you may not see it" is itself the
            // disclosure being withheld.
            _ => Reply::not_found(now),
        }
    }

    /// How many identities have beat since the process started.
    pub fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    #[test]
    fn a_beat_is_readable() {
        let b = Beacons::new();
        let id = key(1);
        let acked = b.record(id, 60, false);

        let r = b.read(&id, None);
        assert!(r.found);
        assert_eq!(r.interval_secs, 60);
        assert_eq!(r.last_seen, acked, "the ack reports the time recorded");
        assert!(r.now >= r.last_seen);
    }

    #[test]
    fn an_unseen_identity_is_not_found_but_still_reports_now() {
        let b = Beacons::new();
        let r = b.read(&key(9), None);
        assert!(!r.found);
        assert!(r.now > 0, "now is reported even when nothing was found");
    }

    #[test]
    fn withheld_is_hidden_from_others_and_visible_to_its_owner() {
        let b = Beacons::new();
        let me = key(1);
        let other = key(2);
        b.record(me, 30, true);

        assert!(!b.read(&me, None).found, "hidden from an anonymous querier");
        assert!(!b.read(&me, Some(&other)).found, "hidden from another identity");
        assert!(b.read(&me, Some(&me)).found, "its owner can read it");
    }

    #[test]
    fn a_later_beat_replaces_the_earlier_one() {
        let b = Beacons::new();
        let id = key(3);
        b.record(id, 60, false);
        b.record(id, 120, true); // re-declared interval and withhold
        let r = b.read(&id, Some(&id));
        assert_eq!(r.interval_secs, 120);
        assert!(!b.read(&id, None).found, "withhold now applies");
        assert_eq!(b.len(), 1, "same identity, one record");
    }
}
