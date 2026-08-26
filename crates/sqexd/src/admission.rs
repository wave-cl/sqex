//! SIP-24 admission requests: asking to be served, and being decided about.
//!
//! A managed whitelist is SIP-2's closed-set match and has no way in — a key
//! not already on it cannot get there by anything the peer does. That is
//! correct for a closed set and impractical the moment a person is several
//! keys, so an unadmitted peer may **ask**, presenting the SIP-20 credential
//! that shows which account vouches for it, and an administrator decides with a
//! SIP-10 transaction.
//!
//! # The reply is always the same, and that is the point
//!
//! This endpoint has to be reachable by a peer the exchange will not otherwise
//! serve — that is what it is for — so it is the one place a refused caller
//! gets a real answer. If that answer varied it would be an oracle: submit a
//! credential naming an account and learn from the response whether that
//! account is admitted here. So every well-formed request is acknowledged
//! identically, whether the credential verified, whether the account is known,
//! and whether anything was queued at all. Every limit below is enforced
//! silently: an overrun changes what is stored and never what is answered.
//!
//! This does not weaken sQUIC's silent server, which is MAC1's property at the
//! transport layer — every request here arrives on a connection that already
//! passed it. What this protects is the weaker thing: that a peer which got
//! through the door learns nothing from asking.

use std::collections::HashMap;
use std::sync::Mutex;

use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqnr_core::PubKey;

use crate::state::now_unix;

/// Requests held at once.
pub const MAX_PENDING: usize = 64;
/// Requests held for one account.
pub const MAX_PER_ACCOUNT: usize = 8;
pub const MAX_LABEL: usize = 64;

/// One request, as an administrator sees it.
#[derive(Debug, Clone)]
pub struct Pending {
    pub device: PubKey,
    pub account: PubKey,
    pub not_after: u64,
    pub label: String,
    pub first_seen: u64,
    /// How many devices of this account are already admitted — the fact an
    /// administrator actually decides on. A third device of an account admitted
    /// twice before is a different proposition from the first request anybody
    /// has ever made for an unknown account.
    pub siblings: usize,
}

#[derive(Default)]
pub struct Admissions {
    pending: Mutex<HashMap<PubKey, Pending>>,
    /// Devices already declined, so a denied one does not refill the queue on
    /// its next connection. Expires with the credential that was denied.
    denied: Mutex<HashMap<PubKey, u64>>,
}

impl Admissions {
    pub fn new() -> Admissions {
        Admissions::default()
    }

    /// Take a request. Answers nothing; the caller acknowledges unconditionally.
    ///
    /// The credential's `delegate` must equal the caller's verified transport
    /// key: a request whose credential names some other device is somebody
    /// forwarding a credential they found.
    pub fn request(
        &self,
        caller: &PubKey,
        credential: &Credential,
        label: &str,
        siblings: usize,
    ) {
        let now = now_unix();
        if &credential.delegate != caller {
            return;
        }
        if credential
            .verify(&credential.account, SCOPE_CHAT, now)
            .is_err()
        {
            return;
        }
        if label.len() > MAX_LABEL {
            return;
        }

        let mut denied = self.denied.lock().unwrap();
        denied.retain(|_, until| *until > now);
        if denied.contains_key(caller) {
            return;
        }
        drop(denied);

        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, p| p.not_after > now);
        if pending.contains_key(caller) {
            return;
        }
        if pending.len() >= MAX_PENDING {
            return;
        }
        if pending
            .values()
            .filter(|p| p.account == credential.account)
            .count()
            >= MAX_PER_ACCOUNT
        {
            return;
        }
        pending.insert(
            *caller,
            Pending {
                device: *caller,
                account: credential.account,
                not_after: credential.not_after,
                label: label.to_string(),
                first_seen: now,
                siblings,
            },
        );
    }

    /// What an administrator has to decide about, oldest first.
    pub fn list(&self) -> Vec<Pending> {
        let now = now_unix();
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, p| p.not_after > now);
        let mut out: Vec<Pending> = pending.values().cloned().collect();
        out.sort_by_key(|p| (p.first_seen, *p.device.as_bytes()));
        out
    }

    /// Remove a request that has been decided, returning what it claimed.
    pub fn take(&self, device: &PubKey) -> Option<Pending> {
        self.pending.lock().unwrap().remove(device)
    }

    /// Remember a refusal, so the same device does not reappear in the queue.
    ///
    /// Not permanent: an administrator may admit the device later, and the
    /// record expires with the credential that was denied rather than becoming
    /// a blocklist nobody maintains.
    pub fn deny(&self, device: &PubKey) {
        let until = self
            .take(device)
            .map(|p| p.not_after)
            .unwrap_or_else(|| now_unix() + 3600);
        self.denied.lock().unwrap().insert(*device, until);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn identity(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    fn credential(account_b: u8, device: &PubKey) -> Credential {
        let (seed, _) = identity(account_b);
        let n = now_unix();
        Credential::issue(&seed, device, SCOPE_CHAT, n - 1, n + 3600).unwrap()
    }

    #[test]
    fn a_request_is_queued_with_what_an_admin_decides_on() {
        let (_, device) = identity(2);
        let a = Admissions::new();
        a.request(&device, &credential(1, &device), "my laptop", 3);
        let list = a.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].device, device);
        assert_eq!(list[0].siblings, 3);
        assert_eq!(list[0].label, "my laptop");
    }

    #[test]
    fn a_credential_naming_another_device_is_discarded() {
        // Somebody forwarding a credential they found.
        let (_, mine) = identity(2);
        let (_, theirs) = identity(3);
        let a = Admissions::new();
        a.request(&theirs, &credential(1, &mine), "", 0);
        assert!(a.list().is_empty());
    }

    #[test]
    fn an_unverifiable_credential_is_discarded_and_says_nothing() {
        let (_, device) = identity(2);
        let mut bad = credential(1, &device);
        bad.signature[0] ^= 1;
        let a = Admissions::new();
        a.request(&device, &bad, "", 0);
        assert!(a.list().is_empty());
    }

    #[test]
    fn a_denied_device_does_not_refill_the_queue() {
        let (_, device) = identity(2);
        let a = Admissions::new();
        a.request(&device, &credential(1, &device), "", 0);
        a.deny(&device);
        assert!(a.list().is_empty());
        a.request(&device, &credential(1, &device), "", 0);
        assert!(a.list().is_empty(), "the decision stands");
    }

    #[test]
    fn the_queue_is_bounded_per_account_and_overall() {
        let a = Admissions::new();
        for i in 0..(MAX_PER_ACCOUNT + 4) {
            let (_, d) = identity(100 + i as u8);
            a.request(&d, &credential(1, &d), "", 0);
        }
        assert_eq!(a.list().len(), MAX_PER_ACCOUNT);
    }

    #[test]
    fn asking_twice_changes_nothing() {
        let (_, device) = identity(2);
        let a = Admissions::new();
        a.request(&device, &credential(1, &device), "first", 0);
        a.request(&device, &credential(1, &device), "second", 0);
        let list = a.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].label, "first");
    }
}
