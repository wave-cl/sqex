//! Relayed sessions: the exchange carries bytes between two identities.
//!
//! The exchange is deliberately a courier here and nothing more. It matches two
//! identities that have each asked for the other, relays one ephemeral public
//! key in each direction, and thereafter moves opaque frames between two
//! queues. It cannot derive the session key — that needs a static private key
//! from each peer, which it does not have (see `sqex_proto::session`) — so it
//! cannot read what it carries, and cannot impersonate either end.
//!
//! **Consent is strictly mutual.** A session exists only once *both* identities
//! have asked for the other. Until then a requester is told nothing at all: not
//! the peer's ephemeral, not whether the peer has ever connected, not whether
//! the peer exists. An identity therefore cannot be used to probe for another.
//!
//! State is in memory, and here that is the honest shape: a session is live
//! coordination between two connected peers, so a restart ends the sessions it
//! was carrying rather than silently resuming half of one.

use std::collections::HashMap;
use std::sync::Mutex;

use sqex_proto::session::{
    Frames, MAX_QUEUED_BYTES, MAX_QUEUED_FRAMES, OpenAck, OpenState, Role, TTL_SECS,
};
use sqnr_core::PubKey;

use crate::state::now_unix;

/// Why a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// No such live session, or the caller is not one of its two peers.
    NoSession,
    /// The peer has not collected; the queue in that direction is full.
    Backpressure,
}

impl SendError {
    pub fn as_str(&self) -> &'static str {
        match self {
            SendError::NoSession => "no_session",
            SendError::Backpressure => "backpressure",
        }
    }
}

/// An unmatched request to open a session.
struct Pending {
    ephemeral: [u8; 32],
    at: u64,
}

/// A live session between two identities, held in lexicographic order.
struct Live {
    first: PubKey,
    second: PubKey,
    eph_first: [u8; 32],
    eph_second: [u8; 32],
    /// Frames from `first`, waiting for `second`, and vice versa.
    to_second: Vec<(u64, Vec<u8>)>,
    to_first: Vec<(u64, Vec<u8>)>,
    created: u64,
    open: bool,
}

impl Live {
    fn role_of(&self, who: &PubKey) -> Option<Role> {
        if *who == self.first {
            Some(Role::First)
        } else if *who == self.second {
            Some(Role::Second)
        } else {
            None
        }
    }

    /// The queue a peer in `role` writes into.
    fn outbound(&mut self, role: Role) -> &mut Vec<(u64, Vec<u8>)> {
        match role {
            Role::First => &mut self.to_second,
            Role::Second => &mut self.to_first,
        }
    }

    /// The queue a peer in `role` reads from.
    fn inbound(&mut self, role: Role) -> &mut Vec<(u64, Vec<u8>)> {
        match role {
            Role::First => &mut self.to_first,
            Role::Second => &mut self.to_second,
        }
    }

    fn peer_ephemeral_for(&self, role: Role) -> [u8; 32] {
        match role {
            Role::First => self.eph_second,
            Role::Second => self.eph_first,
        }
    }

    /// The ephemeral the peer in `role` contributed when this session was made.
    fn own_ephemeral_for(&self, role: Role) -> [u8; 32] {
        match role {
            Role::First => self.eph_first,
            Role::Second => self.eph_second,
        }
    }

    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created) > TTL_SECS
    }
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    /// (requester, target) -> their offered ephemeral.
    pending: HashMap<(PubKey, PubKey), Pending>,
    sessions: HashMap<u64, Live>,
}

/// Every session the exchange is carrying.
#[derive(Default)]
pub struct Sessions {
    inner: Mutex<Inner>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions::default()
    }

    /// Ask to open a session with `peer`, offering `ephemeral`.
    ///
    /// Returns `Established` with the peer's ephemeral only when the peer has
    /// asked for `me` too. Otherwise the request is recorded and the caller
    /// learns nothing.
    pub fn open(&self, me: PubKey, peer: PubKey, ephemeral: [u8; 32]) -> OpenAck {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);

        if me == peer {
            // A session with yourself has no second end to consent.
            return OpenAck::waiting(now);
        }

        // Already established? Answer idempotently, so a repeated open (a retry,
        // or a peer that lost its ack) resumes rather than starting again.
        //
        // A *retry* re-offers the ephemeral it offered before. An open carrying
        // a different one is not a retry — it is somebody starting again, most
        // often because they restarted and have no idea a session survives them.
        // Answering that idempotently would hand back an ephemeral their new
        // secret cannot pair with, and both ends would derive keys that do not
        // match: connected, apparently healthy, and permanently unable to read
        // each other. So a fresh ephemeral discards the old session instead.
        let existing = inner
            .sessions
            .iter()
            .find(|(_, l)| l.open && l.role_of(&me).is_some() && l.role_of(&peer).is_some())
            .map(|(id, l)| (*id, l.role_of(&me).expect("membership just checked")));
        if let Some((id, role)) = existing {
            let live = &inner.sessions[&id];
            if live.own_ephemeral_for(role) == ephemeral {
                return OpenAck {
                    state: OpenState::Established,
                    session_id: id,
                    peer_ephemeral: live.peer_ephemeral_for(role),
                    now,
                };
            }
            inner.sessions.remove(&id);
        }

        // Has the peer already asked for me? Then both have consented.
        if let Some(theirs) = inner.pending.remove(&(peer, me)) {
            inner.pending.remove(&(me, peer));
            inner.next_id += 1;
            let id = inner.next_id;
            let my_role = Role::of(&me, &peer);
            let (first, second, eph_first, eph_second) = match my_role {
                Role::First => (me, peer, ephemeral, theirs.ephemeral),
                Role::Second => (peer, me, theirs.ephemeral, ephemeral),
            };
            inner.sessions.insert(
                id,
                Live {
                    first,
                    second,
                    eph_first,
                    eph_second,
                    to_second: Vec::new(),
                    to_first: Vec::new(),
                    created: now,
                    open: true,
                },
            );
            return OpenAck {
                state: OpenState::Established,
                session_id: id,
                peer_ephemeral: theirs.ephemeral,
                now,
            };
        }

        // Record the request and disclose nothing.
        inner
            .pending
            .insert((me, peer), Pending { ephemeral, at: now });
        OpenAck::waiting(now)
    }

    /// Relay one sealed frame from `me` to the other end.
    pub fn send(
        &self,
        me: &PubKey,
        session_id: u64,
        seq: u64,
        ciphertext: Vec<u8>,
    ) -> Result<(), SendError> {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);
        let live = inner
            .sessions
            .get_mut(&session_id)
            .filter(|l| l.open)
            .ok_or(SendError::NoSession)?;
        let role = live.role_of(me).ok_or(SendError::NoSession)?;

        let queue = live.outbound(role);
        let queued: usize = queue.iter().map(|(_, c)| c.len()).sum();
        if queue.len() >= MAX_QUEUED_FRAMES || queued + ciphertext.len() > MAX_QUEUED_BYTES {
            // The peer is not collecting. Refusing is the only honest answer:
            // dropping silently would look like delivery.
            return Err(SendError::Backpressure);
        }
        queue.push((seq, ciphertext));
        Ok(())
    }

    /// Collect whatever is waiting for `me`, draining it.
    pub fn recv(&self, me: &PubKey, session_id: u64) -> Frames {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);
        let Some(live) = inner.sessions.get_mut(&session_id) else {
            return Frames {
                open: false,
                frames: Vec::new(),
            };
        };
        let Some(role) = live.role_of(me) else {
            // Not a member: indistinguishable from a session that is not there.
            return Frames {
                open: false,
                frames: Vec::new(),
            };
        };
        let open = live.open;
        let frames = std::mem::take(live.inbound(role));
        Frames { open, frames }
    }

    /// End a session. Either peer may; the other learns when it next collects.
    pub fn close(&self, me: &PubKey, session_id: u64) -> bool {
        let now = now_unix();
        let mut inner = self.inner.lock().unwrap();
        inner.expire(now);
        match inner.sessions.get_mut(&session_id) {
            Some(live) if live.role_of(me).is_some() && live.open => {
                live.open = false;
                true
            }
            _ => false,
        }
    }

    /// The other party to a live session, if `me` is a party to it.
    ///
    /// This is all the datagram forwarder needs: it does not queue, inspect or
    /// store anything, it only needs to know where to point a packet.
    pub fn counterpart(&self, me: &PubKey, session_id: u64) -> Option<PubKey> {
        let inner = self.inner.lock().unwrap();
        let live = inner.sessions.get(&session_id).filter(|l| l.open)?;
        match live.role_of(me)? {
            Role::First => Some(live.second),
            Role::Second => Some(live.first),
        }
    }

    /// How many sessions are live.
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.sessions.values().filter(|l| l.open).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Inner {
    fn expire(&mut self, now: u64) {
        self.pending
            .retain(|_, p| now.saturating_sub(p.at) <= TTL_SECS);
        // A closed session is kept no longer than it takes the other end to
        // notice; the TTL covers both cases.
        self.sessions.retain(|_, l| !l.expired(now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    #[test]
    fn a_session_needs_both_to_ask() {
        let s = Sessions::new();
        let (a, b) = (key(1), key(2));

        let ack = s.open(a, b, [10u8; 32]);
        assert_eq!(ack.state, OpenState::Waiting);
        assert_eq!(ack.session_id, 0);
        assert_eq!(
            ack.peer_ephemeral, [0u8; 32],
            "nothing about the peer is disclosed before they consent"
        );

        let ack_b = s.open(b, a, [20u8; 32]);
        assert_eq!(ack_b.state, OpenState::Established);
        assert_eq!(ack_b.peer_ephemeral, [10u8; 32], "and now A's ephemeral");

        // A asks again and now learns B's.
        let ack_a = s.open(a, b, [10u8; 32]);
        assert_eq!(ack_a.state, OpenState::Established);
        assert_eq!(ack_a.session_id, ack_b.session_id, "the same session");
        assert_eq!(ack_a.peer_ephemeral, [20u8; 32]);
    }

    #[test]
    fn asking_for_someone_who_never_asks_reveals_nothing() {
        let s = Sessions::new();
        let (a, b) = (key(1), key(2));
        for _ in 0..5 {
            assert_eq!(s.open(a, b, [1u8; 32]).state, OpenState::Waiting);
        }
        assert_eq!(s.len(), 0, "no session exists to be probed");
    }

    #[test]
    fn frames_flow_both_ways() {
        let s = Sessions::new();
        let (a, b) = (key(1), key(2));
        s.open(a, b, [10u8; 32]);
        let id = s.open(b, a, [20u8; 32]).session_id;

        s.send(&a, id, 0, vec![1, 2, 3]).unwrap();
        s.send(&a, id, 1, vec![4]).unwrap();

        // A does not receive its own frames.
        assert!(s.recv(&a, id).frames.is_empty());

        let got = s.recv(&b, id);
        assert!(got.open);
        assert_eq!(got.frames, vec![(0, vec![1, 2, 3]), (1, vec![4])]);
        assert!(s.recv(&b, id).frames.is_empty(), "collecting drains");

        s.send(&b, id, 0, vec![9]).unwrap();
        assert_eq!(s.recv(&a, id).frames, vec![(0, vec![9])]);
    }

    #[test]
    fn a_stranger_can_neither_send_nor_receive() {
        let s = Sessions::new();
        let (a, b, eve) = (key(1), key(2), key(3));
        s.open(a, b, [10u8; 32]);
        let id = s.open(b, a, [20u8; 32]).session_id;

        assert_eq!(s.send(&eve, id, 0, vec![1]), Err(SendError::NoSession));
        let got = s.recv(&eve, id);
        assert!(!got.open, "reported exactly as no session");
        assert!(got.frames.is_empty());
        assert!(!s.close(&eve, id), "and cannot end it");
    }

    #[test]
    fn either_peer_may_close_and_the_other_learns() {
        let s = Sessions::new();
        let (a, b) = (key(1), key(2));
        s.open(a, b, [10u8; 32]);
        let id = s.open(b, a, [20u8; 32]).session_id;

        assert!(s.close(&b, id));
        assert!(!s.recv(&a, id).open, "A sees the session has ended");
        assert_eq!(s.send(&a, id, 0, vec![1]), Err(SendError::NoSession));
        assert!(!s.close(&b, id), "closing twice does nothing");
    }

    #[test]
    fn backpressure_rather_than_silent_loss() {
        let s = Sessions::new();
        let (a, b) = (key(1), key(2));
        s.open(a, b, [10u8; 32]);
        let id = s.open(b, a, [20u8; 32]).session_id;

        for i in 0..MAX_QUEUED_FRAMES {
            s.send(&a, id, i as u64, vec![1]).unwrap();
        }
        assert_eq!(
            s.send(&a, id, 999, vec![1]),
            Err(SendError::Backpressure),
            "a peer that is not collecting must not look like one that is"
        );

        // Once B collects, A can send again.
        s.recv(&b, id);
        assert!(s.send(&a, id, 999, vec![1]).is_ok());
    }

    #[test]
    fn counterpart_is_only_visible_to_a_party() {
        let s = Sessions::new();
        let (a, b, eve) = (key(1), key(2), key(3));
        s.open(a, b, [10u8; 32]);
        let id = s.open(b, a, [20u8; 32]).session_id;

        assert_eq!(s.counterpart(&a, id), Some(b));
        assert_eq!(s.counterpart(&b, id), Some(a));
        assert_eq!(s.counterpart(&eve, id), None, "a stranger cannot aim a packet");
        assert_eq!(s.counterpart(&a, 999), None, "nor can anyone at a phantom session");

        s.close(&a, id);
        assert_eq!(s.counterpart(&a, id), None, "a closed session forwards nothing");
    }

    #[test]
    fn a_session_with_yourself_is_refused() {
        let s = Sessions::new();
        let a = key(1);
        assert_eq!(s.open(a, a, [1u8; 32]).state, OpenState::Waiting);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn roles_are_assigned_by_key_order_not_who_asked_first() {
        let s = Sessions::new();
        let (low, high) = (key(1), key(9));
        // The higher key asks first.
        s.open(high, low, [90u8; 32]);
        let ack = s.open(low, high, [10u8; 32]);
        assert_eq!(ack.state, OpenState::Established);
        assert_eq!(
            ack.peer_ephemeral, [90u8; 32],
            "the low key still receives the high key's ephemeral"
        );
    }
}
