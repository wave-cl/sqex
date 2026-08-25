//! The SIP-5 mailbox: sealed messages held for their recipients.
//!
//! The exchange stores ciphertext and metadata. It cannot read a payload — the
//! sealing is to the recipient's key (see `sqex_proto::mailbox`) and nothing
//! here has the material to open it. What it does see, and cannot avoid seeing,
//! is *who sent to whom, how big, and when*: that metadata is the honest cost of
//! a rendezvous point, and SIP-5 says so rather than calling this private
//! communication.
//!
//! **Delivery is at-least-once.** A recipient lists, fetches, then deletes by
//! id. Fetching alone changes nothing, so a connection lost mid-collection
//! costs a retry rather than a message.
//!
//! **Collection is visible to the sender.** Deleting drops the payload but
//! leaves a small tombstone — id, sender, and when it was collected — so a
//! sender can ask what became of what it left. That is a deliberate disclosure
//! of recipient behaviour, chosen over silence; see SIP-5's security notes.
//!
//! State is in memory. Unlike the beacon, where that is *principled* (a restart
//! is an honest gap in observation), here it is a **limitation**: a restart
//! drops undelivered mail. Persistence is the obvious next step and is recorded
//! as such in SIP-5.

use std::collections::HashMap;
use std::sync::Mutex;

use sqex_proto::mailbox::{Entry, Listing, MAX_BYTES, MAX_MESSAGES, Sealed, State, Status, TTL_SECS};
use sqnr_core::PubKey;

use crate::state::now_unix;

/// Why a send was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The recipient already holds the most messages allowed.
    TooManyMessages,
    /// The recipient's stored bytes would exceed the allowance.
    QuotaExceeded,
}

impl SendError {
    pub fn as_str(&self) -> &'static str {
        match self {
            SendError::TooManyMessages => "recipient_full",
            SendError::QuotaExceeded => "recipient_quota",
        }
    }
}

/// One stored message, or the tombstone left after it was collected.
struct Message {
    id: u64,
    sender: PubKey,
    recipient: PubKey,
    received: u64,
    /// `None` once collected — the payload is dropped, the record is not.
    sealed: Option<Sealed>,
    collected: Option<u64>,
}

impl Message {
    fn len(&self) -> usize {
        self.sealed.as_ref().map_or(0, |s| s.ciphertext.len())
    }

    /// A tombstone is kept for the same span as a message, so a sender has as
    /// long to ask as a recipient had to collect.
    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.received) > TTL_SECS
    }
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    /// Every message and tombstone, by id.
    messages: HashMap<u64, Message>,
    /// Waiting message ids per recipient, oldest first — the queue.
    queues: HashMap<PubKey, Vec<u64>>,
}

/// Every message the exchange is holding.
#[derive(Default)]
pub struct Mailbox {
    inner: Mutex<Inner>,
}

impl Mailbox {
    pub fn new() -> Mailbox {
        Mailbox::default()
    }

    /// Store a sealed message for `recipient`. Returns its id.
    pub fn send(
        &self,
        sender: PubKey,
        recipient: PubKey,
        sealed: Sealed,
    ) -> Result<(u64, u64), SendError> {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);

        let queued: Vec<u64> = inner.queues.get(&recipient).cloned().unwrap_or_default();
        if queued.len() >= MAX_MESSAGES {
            return Err(SendError::TooManyMessages);
        }
        let waiting: usize = queued
            .iter()
            .filter_map(|id| inner.messages.get(id))
            .map(Message::len)
            .sum();
        if waiting + sealed.ciphertext.len() > MAX_BYTES {
            return Err(SendError::QuotaExceeded);
        }

        inner.next_id += 1;
        let id = inner.next_id;
        inner.queues.entry(recipient).or_default().push(id);
        inner.messages.insert(
            id,
            Message {
                id,
                sender,
                recipient,
                received: now,
                sealed: Some(sealed),
                collected: None,
            },
        );
        Ok((id, now))
    }

    /// The messages waiting for `recipient`, oldest first.
    pub fn list(&self, recipient: &PubKey) -> Listing {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);
        let entries = inner
            .queues
            .get(recipient)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| inner.messages.get(id))
                    .map(|m| Entry {
                        id: m.id,
                        sender: m.sender,
                        received: m.received,
                        len: m.len() as u32,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Listing { entries, now }
    }

    /// Read one message. Only its recipient may, and fetching does not remove
    /// it — collection is completed by [`delete`](Self::delete).
    pub fn fetch(&self, recipient: &PubKey, id: u64) -> Option<(PubKey, u64, Sealed)> {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);
        let m = inner.messages.get(&id)?;
        if m.recipient != *recipient {
            return None; // not yours: indistinguishable from absent
        }
        let sealed = m.sealed.clone()?;
        Some((m.sender, m.received, sealed))
    }

    /// Complete collection: drop the payload, keep the tombstone. Only the
    /// recipient may. Returns whether anything was collected.
    pub fn delete(&self, recipient: &PubKey, id: u64) -> bool {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);
        let Some(m) = inner.messages.get_mut(&id) else {
            return false;
        };
        if m.recipient != *recipient || m.sealed.is_none() {
            return false;
        }
        m.sealed = None;
        m.collected = Some(now);
        if let Some(q) = inner.queues.get_mut(recipient) {
            q.retain(|q_id| *q_id != id);
        }
        true
    }

    /// What became of a message. Only the identity that sent it may ask; anyone
    /// else is told nothing, which is the same answer as for a message that
    /// never existed.
    pub fn status(&self, sender: &PubKey, id: u64) -> Status {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);
        match inner.messages.get(&id) {
            Some(m) if m.sender == *sender => Status {
                state: if m.collected.is_some() {
                    State::Collected
                } else {
                    State::Waiting
                },
                received: m.received,
                collected: m.collected.unwrap_or(0),
                now,
            },
            _ => Status::unknown(now),
        }
    }

    /// How many messages are waiting to be collected, across all recipients.
    pub fn waiting(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.messages.values().filter(|m| m.sealed.is_some()).count()
    }
}

impl Inner {
    /// Drop everything past its TTL. Called on every operation, so there is no
    /// background task and no unbounded growth from a recipient that never
    /// collects.
    fn expire(&mut self, now: u64) {
        let expired: Vec<u64> = self
            .messages
            .values()
            .filter(|m| m.expired(now))
            .map(|m| m.id)
            .collect();
        if expired.is_empty() {
            return;
        }
        for id in &expired {
            self.messages.remove(id);
        }
        for q in self.queues.values_mut() {
            q.retain(|id| !expired.contains(id));
        }
        self.queues.retain(|_, q| !q.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn sealed(n: usize) -> Sealed {
        Sealed {
            ephemeral: [7u8; 32],
            ciphertext: vec![0u8; n],
        }
    }

    #[test]
    fn send_list_fetch_delete() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        let (id, _) = m.send(from, to, sealed(10)).unwrap();

        let l = m.list(&to);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries[0].id, id);
        assert_eq!(l.entries[0].sender, from);
        assert_eq!(l.entries[0].len, 10);

        // Fetching does not remove: delivery is at-least-once.
        assert!(m.fetch(&to, id).is_some());
        assert!(m.fetch(&to, id).is_some());
        assert_eq!(m.list(&to).entries.len(), 1);

        assert!(m.delete(&to, id));
        assert!(m.list(&to).entries.is_empty());
        assert!(!m.delete(&to, id), "deleting twice collects nothing");
    }

    #[test]
    fn only_the_recipient_may_fetch_or_delete() {
        let m = Mailbox::new();
        let (from, to, other) = (key(1), key(2), key(3));
        let (id, _) = m.send(from, to, sealed(4)).unwrap();

        assert!(m.fetch(&other, id).is_none(), "not yours to read");
        assert!(!m.delete(&other, id), "not yours to delete");
        assert!(m.fetch(&to, id).is_some(), "still there for its recipient");
    }

    #[test]
    fn the_sender_learns_that_it_was_collected() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        let (id, _) = m.send(from, to, sealed(4)).unwrap();

        assert_eq!(m.status(&from, id).state, State::Waiting);
        m.delete(&to, id);
        let s = m.status(&from, id);
        assert_eq!(s.state, State::Collected);
        assert!(s.collected > 0, "and when");
    }

    #[test]
    fn only_the_sender_may_ask_after_a_message() {
        let m = Mailbox::new();
        let (from, to, nosy) = (key(1), key(2), key(3));
        let (id, _) = m.send(from, to, sealed(4)).unwrap();
        assert_eq!(
            m.status(&nosy, id).state,
            State::Unknown,
            "a stranger learns nothing, not even that it exists"
        );
        // Not even the recipient can use status to enumerate.
        assert_eq!(m.status(&to, id).state, State::Unknown);
    }

    #[test]
    fn the_queue_is_oldest_first() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        let (a, _) = m.send(from, to, sealed(1)).unwrap();
        let (b, _) = m.send(from, to, sealed(1)).unwrap();
        let (c, _) = m.send(from, to, sealed(1)).unwrap();
        let ids: Vec<u64> = m.list(&to).entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![a, b, c]);

        // Collecting from the middle leaves the order intact.
        m.delete(&to, b);
        let ids: Vec<u64> = m.list(&to).entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![a, c]);
    }

    #[test]
    fn a_full_mailbox_refuses_more() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        for _ in 0..MAX_MESSAGES {
            m.send(from, to, sealed(1)).unwrap();
        }
        assert_eq!(m.send(from, to, sealed(1)), Err(SendError::TooManyMessages));

        // Collecting one makes room again.
        let first = m.list(&to).entries[0].id;
        m.delete(&to, first);
        assert!(m.send(from, to, sealed(1)).is_ok());
    }

    #[test]
    fn the_byte_quota_is_enforced() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        // A few large messages, then one that would tip it over.
        let big = MAX_BYTES / 4;
        for _ in 0..4 {
            m.send(from, to, sealed(big)).unwrap();
        }
        assert_eq!(m.send(from, to, sealed(1)), Err(SendError::QuotaExceeded));
    }

    #[test]
    fn quotas_are_per_recipient() {
        let m = Mailbox::new();
        let from = key(1);
        for _ in 0..MAX_MESSAGES {
            m.send(from, key(2), sealed(1)).unwrap();
        }
        assert!(
            m.send(from, key(3), sealed(1)).is_ok(),
            "one full mailbox must not block another"
        );
    }

    #[test]
    fn waiting_counts_only_uncollected() {
        let m = Mailbox::new();
        let (from, to) = (key(1), key(2));
        let (id, _) = m.send(from, to, sealed(1)).unwrap();
        m.send(from, to, sealed(1)).unwrap();
        assert_eq!(m.waiting(), 2);
        m.delete(&to, id);
        assert_eq!(m.waiting(), 1, "a tombstone is not a waiting message");
    }
}
