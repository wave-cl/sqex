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
    /// Nobody at the keyboard, by the identity's own last word.
    away: bool,
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
    pub fn record(&self, identity: PubKey, interval_secs: u32, withhold: bool, away: bool) -> u64 {
        let now = now_unix();
        self.seen.lock().unwrap().insert(
            identity,
            Observation {
                last_seen: now,
                interval_secs,
                withhold,
                away,
            },
        );
        now
    }

    /// What the exchange can tell `asker` about `target`, from `target`'s own
    /// beat alone.
    ///
    /// A withheld record is disclosed only to its owner, so `asker` is the
    /// querier's own bound identity, or `None` for an anonymous querier (who is
    /// therefore never the owner). Reading is otherwise open: SIP-4 privileges
    /// beating, not asking.
    ///
    /// This is the answer for a **device** key, which SIP-50 keeps as it was:
    /// a device is asked about as a device. An account with registered devices
    /// is answered by [`read_across`].
    pub fn read(&self, target: &PubKey, asker: Option<&PubKey>) -> Reply {
        self.read_across(std::slice::from_ref(target), asker, false)
    }

    /// SIP-50: one answer for `set`, which is an account and every device
    /// whose registration stands.
    ///
    /// **The freshest beat in the set, not the account's own.** Before this, a
    /// person whose only client was a phone was absent for ever: the phone
    /// beats under its *device* key (SIP-22), and a consumer asking about the
    /// account found nothing there. The interval reported is therefore that
    /// device's declared interval, because there is no such thing as the
    /// account's.
    ///
    /// **Withholding inverts.** A withhold from *any* member withholds the
    /// whole account from public readers -- the account is one person, and the
    /// device they set it on speaks for them -- while the members themselves
    /// still see it, as SIP-4 lets an identity see its own withheld beacon.
    /// So a person who withholds on their desktop is not disclosed by their
    /// phone having beaten.
    ///
    /// `reach` is the caller's to determine, because it comes from the device
    /// registry and not from here; it is answered whether or not anything was
    /// found, and forced to false when the set is withheld -- withholding
    /// withholds.
    pub fn read_across(&self, set: &[PubKey], asker: Option<&PubKey>, reach: bool) -> Reply {
        let now = now_unix();
        let seen = self.seen.lock().unwrap();
        let mine = asker.is_some_and(|a| set.contains(a));
        let withheld = !mine && set.iter().any(|k| seen.get(k).is_some_and(|o| o.withhold));
        if withheld {
            // Withheld records are reported exactly as absent ones: telling a
            // stranger "this exists but you may not see it" is itself the
            // disclosure being withheld.
            return Reply::not_found(now);
        }
        let freshest = set
            .iter()
            .filter_map(|k| seen.get(k))
            .max_by_key(|o| o.last_seen);
        match freshest {
            Some(o) => Reply {
                found: true,
                last_seen: o.last_seen,
                interval_secs: o.interval_secs,
                now,
                away: o.away,
                reach,
            },
            // Nothing in the set has beaten. Still an answer about reach: an
            // account that has never beaten and can be woken is the ordinary
            // state of somebody whose only client is a phone.
            None => Reply {
                reach,
                ..Reply::not_found(now)
            },
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
        let acked = b.record(id, 60, false, false);

        let r = b.read(&id, None);
        assert!(r.found);
        assert_eq!(r.interval_secs, 60);
        assert_eq!(r.last_seen, acked, "the ack reports the time recorded");
        assert!(r.now >= r.last_seen);
    }

    /// Away is the identity's own last word, and the next beat is the next
    /// word: a beat without it is somebody back at the keyboard.
    #[test]
    fn away_is_what_the_last_beat_said() {
        let b = Beacons::new();
        let id = key(4);
        b.record(id, 30, false, true);
        assert!(b.read(&id, None).away);
        b.record(id, 30, false, false);
        assert!(!b.read(&id, None).away);
        // And never disclosed for a record that is withheld: not found is
        // not found.
        b.record(id, 30, true, true);
        let r = b.read(&id, Some(&key(5)));
        assert!(!r.found && !r.away);
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
        b.record(me, 30, true, false);

        assert!(!b.read(&me, None).found, "hidden from an anonymous querier");
        assert!(
            !b.read(&me, Some(&other)).found,
            "hidden from another identity"
        );
        assert!(b.read(&me, Some(&me)).found, "its owner can read it");
    }

    #[test]
    fn a_later_beat_replaces_the_earlier_one() {
        let b = Beacons::new();
        let id = key(3);
        b.record(id, 60, false, false);
        b.record(id, 120, true, false); // re-declared interval and withhold
        let r = b.read(&id, Some(&id));
        assert_eq!(r.interval_secs, 120);
        assert!(!b.read(&id, None).found, "withhold now applies");
        assert_eq!(b.len(), 1, "same identity, one record");
    }

    /// **The freshest beat in the set, which is the whole point of SIP-50.**
    ///
    /// A person whose only client is a phone beats under the *device* key
    /// (SIP-22), so an account read that looked only at the account's own key
    /// found nothing and reported them absent for ever. The interval comes
    /// from whichever device that beat was, because there is no such thing as
    /// the account's interval.
    #[test]
    fn an_account_is_read_from_whichever_of_its_devices_beat_last() {
        let b = Beacons::new();
        let (account, phone, desktop) = (key(1), key(2), key(3));

        // Only the phone has ever beaten: the account itself never has.
        b.record(phone, 90, false, false);
        let r = b.read_across(&[account, phone, desktop], None, false);
        assert!(
            r.found,
            "the account reads as absent while its phone is beating"
        );
        assert_eq!(
            r.interval_secs, 90,
            "the interval is the device's, not the account's"
        );

        // The desktop beats after it, and is the fresher of the two.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        b.record(desktop, 30, false, true);
        let r = b.read_across(&[account, phone, desktop], None, false);
        assert_eq!(r.interval_secs, 30, "the older beat won");
        assert!(r.away, "and its flags came with it");

        // Asked about as a device, a device answers for itself alone.
        let just_the_phone = b.read(&phone, None);
        assert_eq!(just_the_phone.interval_secs, 90);
    }

    /// **A withhold from any member withholds the account**, and the members
    /// themselves still see it. The account is one person, and the device
    /// they set it on speaks for them -- so withholding on a desktop is not
    /// undone by a phone that has beaten.
    #[test]
    fn one_device_withholding_withholds_the_whole_account() {
        let b = Beacons::new();
        let (account, phone, desktop, stranger) = (key(1), key(2), key(3), key(9));
        let set = [account, phone, desktop];

        b.record(phone, 60, false, false);
        assert!(b.read_across(&set, Some(&stranger), false).found);

        b.record(desktop, 60, true, false);
        let to_a_stranger = b.read_across(&set, Some(&stranger), false);
        assert!(
            !to_a_stranger.found,
            "the phone's beat disclosed a withheld account"
        );
        assert!(
            !to_a_stranger.reach,
            "withholding withholds the reach bit too"
        );

        // Its own devices see it, as SIP-4 lets an identity see its own.
        for me in &set {
            assert!(
                b.read_across(&set, Some(me), true).found,
                "a member of the set cannot see its own account"
            );
        }
        // And nobody at all is a stranger.
        assert!(!b.read_across(&set, None, false).found);
    }

    /// **Reach is answered whether or not anything beat.** An account that
    /// has never beaten and holds a wake registration is the ordinary state
    /// of somebody whose only client is a phone that is asleep: not there,
    /// and not gone.
    #[test]
    fn an_account_that_never_beat_still_says_it_can_be_woken() {
        let b = Beacons::new();
        let set = [key(1), key(2)];
        let r = b.read_across(&set, None, true);
        assert!(!r.found, "nothing has beaten");
        assert!(r.reach, "and a ring would still reach it");
        assert_eq!(r.last_seen, 0);

        let quiet = b.read_across(&set, None, false);
        assert!(!quiet.found && !quiet.reach);
    }
}
