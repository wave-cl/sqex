//! SIP-56: rate limits, per account, on what costs the exchange and the
//! members something. A token bucket per (kind, account, scope), refused
//! with how long to wait. Reads are never limited here.

use std::collections::HashMap;
use std::sync::Mutex;

use sqnr_core::PubKey;

/// What is limited. The scope a bucket is keyed by is the kind's: a
/// channel for posts and signals, nothing for the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Posts,
    Signals,
    Joins,
    Creates,
    Uploads,
    Reports,
    /// SIP-35 §Open peering: the writes a peer causes -- hints, Moves, rehome notices,
    /// carried registrations -- per caller key.
    Peering,
    /// SIP-65: cross-exchange calls dialled or rung, per caller account.
    Calls,
}

/// A limit: `burst` tokens, refilled at `per_sec`. Zero burst is unlimited.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limit {
    pub burst: f64,
    pub per_sec: f64,
}

impl Limit {
    /// `n` per `secs`, as a bucket of `n` refilled over `secs`.
    pub const fn per(n: u32, secs: u32) -> Limit {
        Limit {
            burst: n as f64,
            per_sec: n as f64 / secs as f64,
        }
    }

    pub const fn unlimited() -> Limit {
        Limit {
            burst: 0.0,
            per_sec: 0.0,
        }
    }
}

/// The exchange's limits, as configured.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    pub posts: Limit,
    pub signals: Limit,
    pub joins: Limit,
    pub creates: Limit,
    pub uploads: Limit,
    pub reports: Limit,
    pub peering: Limit,
    pub calls: Limit,
}

impl Default for Limits {
    /// SIP-56's reference defaults.
    fn default() -> Limits {
        Limits {
            posts: Limit::per(30, 60),
            signals: Limit::per(60, 60),
            joins: Limit::per(20, 3600),
            creates: Limit::per(10, 3600),
            uploads: Limit::per(60, 3600),
            reports: Limit::per(20, 3600),
            peering: Limit::per(60, 3600),
            calls: Limit::per(20, 3600),
        }
    }
}

impl Limits {
    fn of(&self, kind: Kind) -> Limit {
        match kind {
            Kind::Posts => self.posts,
            Kind::Signals => self.signals,
            Kind::Joins => self.joins,
            Kind::Creates => self.creates,
            Kind::Uploads => self.uploads,
            Kind::Reports => self.reports,
            Kind::Peering => self.peering,
            Kind::Calls => self.calls,
        }
    }
}

struct Bucket {
    tokens: f64,
    at: f64,
}

/// A bucket's key: what, whose, and where.
type Key = (Kind, PubKey, [u8; 32]);

/// Every live bucket.
pub struct Limiter {
    limits: Limits,
    buckets: Mutex<HashMap<Key, Bucket>>,
}

fn now_f() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl Limiter {
    pub fn new(limits: Limits) -> Limiter {
        Limiter {
            limits,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `who` in `scope`, or say how many whole seconds
    /// until one is there.
    pub fn take(&self, kind: Kind, who: &PubKey, scope: [u8; 32]) -> Result<(), u64> {
        let limit = self.limits.of(kind);
        if limit.burst <= 0.0 {
            return Ok(());
        }
        let now = now_f();
        let mut buckets = self.buckets.lock().unwrap();
        let b = buckets.entry((kind, *who, scope)).or_insert(Bucket {
            tokens: limit.burst,
            at: now,
        });
        b.tokens = (b.tokens + (now - b.at) * limit.per_sec).min(limit.burst);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - b.tokens) / limit.per_sec).ceil().max(1.0) as u64)
        }
    }

    /// Forget buckets that have refilled: a full bucket is the same as no
    /// bucket. Called from the sweep.
    pub fn sweep(&self) {
        let now = now_f();
        let limits = self.limits;
        self.buckets.lock().unwrap().retain(|(kind, _, _), b| {
            let l = limits.of(*kind);
            b.tokens + (now - b.at) * l.per_sec < l.burst
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_refuses_past_its_burst_and_says_how_long() {
        let l = Limiter::new(Limits {
            posts: Limit::per(3, 60),
            ..Limits::default()
        });
        let who = PubKey::new([1; 32]);
        for _ in 0..3 {
            assert_eq!(l.take(Kind::Posts, &who, [0; 32]), Ok(()));
        }
        let wait = l.take(Kind::Posts, &who, [0; 32]).unwrap_err();
        assert!((1..=20).contains(&wait), "{wait}");
        // Another channel, another bucket; another account likewise.
        assert_eq!(l.take(Kind::Posts, &who, [1; 32]), Ok(()));
        assert_eq!(l.take(Kind::Posts, &PubKey::new([2; 32]), [0; 32]), Ok(()));
        // Unlimited never refuses.
        let u = Limiter::new(Limits {
            posts: Limit::unlimited(),
            ..Limits::default()
        });
        for _ in 0..1000 {
            assert_eq!(u.take(Kind::Posts, &who, [0; 32]), Ok(()));
        }
    }
}
