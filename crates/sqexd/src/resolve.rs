//! SIP-28: what the exchange has been told about where identities are.
//!
//! **In memory only, and that is the same argument SIP-4's beacon makes.** A
//! restart is an honest gap: the exchange stops having been told anything,
//! which is exactly true. Persisting would mean serving addresses on the
//! strength of a claim this process never received — and since the SIP has an
//! exchange treat a beat as refreshing a publication, a service that is proving
//! it is alive republishes within its own beacon interval anyway.
//!
//! Nothing here is signed and nothing here is authority. The exchange asserts
//! the answer; the consumer pins the key it asked for when it connects, and
//! that pinning is what makes a dishonest answer a denial rather than an
//! impersonation.

use std::collections::HashMap;
use std::sync::Mutex;

use sqex_proto::resolve::{Endpoint, MAX_CAPABILITIES, MAX_ENDPOINTS, Resolved, Successor};
use sqnr_core::PubKey;

use crate::state::now_unix;

/// One identity's published set.
#[derive(Debug, Clone)]
struct Published {
    endpoints: Vec<Endpoint>,
    /// SIP-26, held here rather than in its own store: it has the same
    /// provenance and the same expiry as the endpoints beside it, and a second
    /// store would give it a second lifetime it does not want.
    capabilities: Vec<String>,
    published_at: u64,
    expires_at: u64,
    /// SIP-28's successor pointer, which is *not* a retirement — see the type's
    /// own documentation for why the difference matters.
    successor: Option<Successor>,
}

/// Everything the exchange has been told about where keys are.
#[derive(Default)]
pub struct Endpoints {
    published: Mutex<HashMap<PubKey, Published>>,
}

/// Why a publication was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishError {
    /// More endpoints than an identity may claim.
    TooMany,
}

impl Endpoints {
    pub fn new() -> Endpoints {
        Endpoints::default()
    }

    /// Replace `identity`'s endpoint set.
    ///
    /// The whole set, always: SIP-28 has no partial update, because
    /// reconciling one against a trusting store is where stale addresses live
    /// forever. A successor pointer already set survives, since it describes
    /// the identity rather than the publication.
    pub fn publish(
        &self,
        identity: PubKey,
        ttl_secs: u32,
        endpoints: Vec<Endpoint>,
        capabilities: Vec<String>,
    ) -> Result<u64, PublishError> {
        if endpoints.len() > MAX_ENDPOINTS {
            return Err(PublishError::TooMany);
        }
        if capabilities.len() > MAX_CAPABILITIES {
            return Err(PublishError::TooMany);
        }
        let now = now_unix();
        let mut held = self.published.lock().unwrap();
        let successor = held.get(&identity).and_then(|p| p.successor.clone());
        held.insert(
            identity,
            Published {
                endpoints,
                capabilities,
                published_at: now,
                expires_at: now.saturating_add(u64::from(ttl_secs)),
                successor,
            },
        );
        Ok(now)
    }

    /// Note that `identity` was seen alive, so its publication is still
    /// current.
    ///
    /// SIP-28 says an exchange SHOULD treat a beat as refreshing the
    /// publisher's endpoints, so a service proving it is alive does not
    /// separately have to prove its address is. It extends the window rather
    /// than resetting the publication: `published_at` is when the claim was
    /// made, and a beat is not a new claim.
    pub fn refresh(&self, identity: &PubKey, ttl_secs: u32) {
        let now = now_unix();
        if let Some(p) = self.published.lock().unwrap().get_mut(identity) {
            p.expires_at = p.expires_at.max(now.saturating_add(u64::from(ttl_secs)));
        }
    }

    /// Record where an identity says it has moved.
    pub fn set_successor(&self, identity: PubKey, successor: Successor) {
        let now = now_unix();
        let mut held = self.published.lock().unwrap();
        match held.get_mut(&identity) {
            Some(p) => p.successor = Some(successor),
            None => {
                // An identity may point at a successor without ever having
                // published an address — leaving a forwarding note is not the
                // same act as being reachable.
                held.insert(
                    identity,
                    Published {
                        endpoints: Vec::new(),
                        capabilities: Vec::new(),
                        published_at: now,
                        expires_at: now,
                        successor: Some(successor),
                    },
                );
            }
        }
    }

    /// Where `key` says it can be reached, if the claim has not expired.
    ///
    /// `last_seen` is the caller's to supply, from the SIP-4 beacon: this store
    /// holds what identities *said* and the beacon holds what the exchange
    /// *saw*, and keeping them apart is what stops one being mistaken for the
    /// other.
    pub fn resolve(&self, key: &PubKey, last_seen: u64) -> Resolved {
        let now = now_unix();
        let held = self.published.lock().unwrap();
        match held.get(key) {
            // Expired is reported as absent, not as an empty answer with a
            // stale timestamp: SIP-28 says endpoints MUST be dropped when they
            // expire, and serving them with a note would be serving them.
            Some(p) if p.expires_at > now && !p.endpoints.is_empty() => Resolved {
                found: true,
                endpoints: p.endpoints.clone(),
                published_at: p.published_at,
                expires_at: p.expires_at,
                last_seen,
                now,
                capabilities: p.capabilities.clone(),
            },
            _ => Resolved::none(now),
        }
    }

    /// The successor an identity named, if it named one.
    pub fn successor(&self, key: &PubKey) -> Option<Successor> {
        self.published
            .lock()
            .unwrap()
            .get(key)
            .and_then(|p| p.successor.clone())
    }

    /// Drop what has expired. Called on the same sweep as everything else that
    /// ages; nothing depends on its timing, because `resolve` refuses an
    /// expired set whether or not this has run.
    pub fn sweep(&self) {
        let now = now_unix();
        self.published
            .lock()
            .unwrap()
            .retain(|_, p| p.expires_at > now || p.successor.is_some());
    }

    /// How many identities have a live publication. For `/status`.
    pub fn len(&self) -> usize {
        let now = now_unix();
        self.published
            .lock()
            .unwrap()
            .values()
            .filter(|p| p.expires_at > now && !p.endpoints.is_empty())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqex_proto::resolve::KIND_IPV4;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn v4(last: u8) -> Endpoint {
        Endpoint {
            kind: KIND_IPV4,
            host: vec![10, 0, 0, last],
            port: 443,
            priority: 0,
            weight: 0,
        }
    }

    /// **An expired set is absent, not stale.** SIP-28 says endpoints MUST be
    /// dropped when they expire, and serving them with a note saying so would
    /// be serving them.
    ///
    /// Tested with a zero TTL rather than a sleep: `expires_at` is then `now`,
    /// and the rule is `expires_at > now`, so the boundary is exercised exactly
    /// rather than approximately.
    #[test]
    fn an_expired_publication_is_absent_rather_than_stale() {
        let store = Endpoints::new();
        store.publish(key(1), 0, vec![v4(1)], vec![]).unwrap();
        let got = store.resolve(&key(1), 0);
        assert!(!got.found, "an expired set was served");
        assert!(got.endpoints.is_empty());

        // The same publication with a window is served.
        store.publish(key(1), 300, vec![v4(1)], vec![]).unwrap();
        assert!(store.resolve(&key(1), 0).found);
    }

    /// A beat extends the window without pretending a new claim was made:
    /// `published_at` is when the identity said where it was, and being seen
    /// alive is not saying it again.
    #[test]
    fn a_beat_extends_the_window_without_moving_the_claim() {
        let store = Endpoints::new();
        store.publish(key(2), 0, vec![v4(2)], vec![]).unwrap();
        assert!(!store.resolve(&key(2), 0).found);

        store.refresh(&key(2), 300);
        let got = store.resolve(&key(2), 0);
        assert!(got.found, "a beat did not refresh an endpoint set");
        assert!(got.expires_at > got.now);
        assert!(
            got.published_at <= got.now,
            "a beat must not backdate or advance the claim itself"
        );

        // A beat for an identity that published nothing creates nothing: it is
        // evidence about liveness, not a claim about an address.
        store.refresh(&key(3), 300);
        assert!(!store.resolve(&key(3), 0).found);
    }

    #[test]
    fn the_whole_set_is_replaced_and_the_cap_is_enforced() {
        let store = Endpoints::new();
        store.publish(key(4), 300, vec![v4(1), v4(2)], vec![]).unwrap();
        store.publish(key(4), 300, vec![v4(3)], vec![]).unwrap();
        assert_eq!(store.resolve(&key(4), 0).endpoints, vec![v4(3)]);

        let too_many: Vec<Endpoint> = (0..=MAX_ENDPOINTS as u8).map(v4).collect();
        assert_eq!(
            store.publish(key(5), 300, too_many, vec![]),
            Err(PublishError::TooMany)
        );
    }

    /// A successor describes the identity rather than the publication, so
    /// republishing an address does not erase where somebody said they went.
    #[test]
    fn a_successor_survives_republication_and_expiry() {
        let store = Endpoints::new();
        let moved = Successor {
            successor: key(9),
            reason: "new hardware".into(),
        };
        store.publish(key(6), 300, vec![v4(1)], vec![]).unwrap();
        store.set_successor(key(6), moved.clone());
        store.publish(key(6), 300, vec![v4(2)], vec![]).unwrap();
        assert_eq!(store.successor(&key(6)), Some(moved.clone()));

        // And a sweep keeps it after the endpoints have gone: a forwarding note
        // outliving the address it forwarded from is the whole use.
        store.publish(key(6), 0, vec![v4(2)], vec![]).unwrap();
        store.sweep();
        assert_eq!(store.successor(&key(6)), Some(moved));

        // An identity that only ever left a note is not resolvable, because it
        // never said where it was.
        store.set_successor(key(7), Successor { successor: key(9), reason: String::new() });
        assert!(!store.resolve(&key(7), 0).found);
    }

    #[test]
    fn a_sweep_drops_what_has_expired() {
        let store = Endpoints::new();
        store.publish(key(8), 0, vec![v4(1)], vec![]).unwrap();
        assert_eq!(store.len(), 0, "an expired set is not counted as live");
        store.sweep();
        assert!(store.is_empty());
        store.publish(key(8), 300, vec![v4(1)], vec![]).unwrap();
        store.sweep();
        assert_eq!(store.len(), 1);
    }
}
