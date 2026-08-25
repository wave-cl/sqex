//! Single-use challenge nonces for admin-command replay protection.
//!
//! The server hands out a random nonce, the admin signs it inside a command,
//! and the server consumes it exactly once. A consumed or expired nonce cannot
//! be reused, so a captured command cannot be replayed.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;

/// A single-use challenge nonce.
type Nonce = [u8; 32];

pub struct Challenges {
    ttl: Duration,
    pending: Mutex<HashMap<Nonce, Instant>>,
}

impl Challenges {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a fresh nonce, valid for `ttl`. Opportunistically drops expired
    /// entries so a caller that never returns cannot grow the set without
    /// bound.
    pub fn issue(&self) -> Nonce {
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let now = Instant::now();
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, expires| *expires > now);
        pending.insert(nonce, now + self.ttl);
        nonce
    }

    /// Consume a nonce: true only if it was issued, not expired, and not
    /// already used. Removes it either way it was present.
    pub fn consume(&self, nonce: &Nonce) -> bool {
        let now = Instant::now();
        let mut pending = self.pending.lock().unwrap();
        match pending.remove(nonce) {
            Some(expires) => expires > now,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_then_consume_once() {
        let c = Challenges::new(Duration::from_secs(30));
        let n = c.issue();
        assert!(c.consume(&n));
        assert!(!c.consume(&n)); // single use
    }

    #[test]
    fn unknown_nonce_rejected() {
        let c = Challenges::new(Duration::from_secs(30));
        assert!(!c.consume(&[0u8; 32]));
    }

    #[test]
    fn expired_nonce_rejected() {
        let c = Challenges::new(Duration::from_millis(0));
        let n = c.issue();
        std::thread::sleep(Duration::from_millis(5));
        assert!(!c.consume(&n));
    }
}
