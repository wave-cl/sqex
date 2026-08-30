//! SIP-13 rooms: who is present, and nothing else.
//!
//! The exchange holds a map from a room *handle* — `SHA-256(context || secret)`
//! — to the identities that have presented it. It never sees the secret, so it
//! cannot join a room it carries, and its memory contains nothing that would
//! let anyone else join one either.
//!
//! It also cannot check the proofs it stores, and does not try. A proof is a MAC
//! under the room secret; verifying it requires the secret, which is exactly
//! what the exchange has been kept away from. It relays them unaltered and the
//! members verify each other — which is what stops the exchange adding an
//! identity of its own to a roster and listening to the room.
//!
//! Membership is soft state with a TTL, so a member that crashes leaves without
//! having said anything. State is in memory only: a room is live coordination
//! between connected peers, and a restart honestly ends it.

use std::collections::HashMap;
use std::sync::Mutex;

use sqex_proto::room::{MAX_MEMBERS, Member, Roster, TTL_SECS};
use sqnr_core::PubKey;

use crate::state::now_unix;
use sqex_proto::refusal::Code;

/// Why a join was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    /// The room already holds `MAX_MEMBERS`. Nobody is evicted to make space.
    Full,
}

impl JoinError {
    pub fn as_str(&self) -> &'static str {
        match self {
            JoinError::Full => "room is full",
        }
    }

    /// The wire code for this refusal. Exhaustive on purpose: a new variant is
    /// a compile error here until it is given one, which is what keeps the
    /// registry from drifting away from the enum it describes.
    pub fn code(&self) -> Code {
        match self {
            JoinError::Full => Code::RoomFull,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Presence {
    proof: [u8; 32],
    last_seen: u64,
}

/// Every room the exchange currently carries.
#[derive(Default)]
pub struct Rooms {
    /// handle -> identity -> presence
    rooms: Mutex<HashMap<[u8; 32], HashMap<PubKey, Presence>>>,
}

impl Rooms {
    pub fn new() -> Rooms {
        Rooms::default()
    }

    /// Record `identity` as present in `handle`, and report who else is.
    ///
    /// Idempotent: this is the join, the heartbeat and the roster poll, which is
    /// why a member needs no other request. The caller is left out of its own
    /// roster, and the rest are sorted by identity so that two members
    /// comparing rosters compare the same thing.
    pub fn join(
        &self,
        handle: [u8; 32],
        identity: PubKey,
        proof: [u8; 32],
    ) -> Result<Roster, JoinError> {
        let now = now_unix();
        let mut rooms = self.rooms.lock().unwrap();
        let members = rooms.entry(handle).or_default();
        members.retain(|_, p| now.saturating_sub(p.last_seen) < TTL_SECS);

        if !members.contains_key(&identity) && members.len() >= MAX_MEMBERS {
            // Refusing discloses that the room is full, which cannot be helped.
            // Evicting someone to make room would disclose rather more.
            if members.is_empty() {
                rooms.remove(&handle);
            }
            return Err(JoinError::Full);
        }
        members.insert(identity, Presence { proof, last_seen: now });

        let mut others: Vec<Member> = members
            .iter()
            .filter(|(id, _)| **id != identity)
            .map(|(id, p)| Member { identity: *id, proof: p.proof })
            .collect();
        others.sort_by(|a, b| a.identity.as_bytes().cmp(b.identity.as_bytes()));
        Ok(Roster { now, members: others })
    }

    /// Remove `identity` from `handle`. Returns whether it was there.
    ///
    /// A courtesy: the TTL is what actually removes people. It saves the others
    /// up to `TTL_SECS` of talking to someone who has gone.
    pub fn leave(&self, handle: &[u8; 32], identity: &PubKey) -> bool {
        let mut rooms = self.rooms.lock().unwrap();
        let Some(members) = rooms.get_mut(handle) else {
            return false;
        };
        let was_there = members.remove(identity).is_some();
        // A room exists exactly while it has members.
        if members.is_empty() {
            rooms.remove(handle);
        }
        was_there
    }

    /// Forget everyone whose membership has expired, and every room thereby
    /// emptied. Called from the same sweep as the other stores.
    pub fn expire(&self) {
        let now = now_unix();
        let mut rooms = self.rooms.lock().unwrap();
        rooms.retain(|_, members| {
            members.retain(|_, p| now.saturating_sub(p.last_seen) < TTL_SECS);
            !members.is_empty()
        });
    }

    /// How many rooms are live, for `/status`. Not which, and not who.
    ///
    /// Sweeps first: a count that includes rooms whose last member stopped
    /// heartbeating twenty minutes ago is not a count of anything.
    pub fn len(&self) -> usize {
        self.expire();
        self.rooms.lock().unwrap().len()
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

    fn handle(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn a_member_does_not_appear_in_its_own_roster() {
        let r = Rooms::new();
        let roster = r.join(handle(1), key(1), [9; 32]).unwrap();
        assert!(roster.members.is_empty(), "the first member is alone");
        assert!(roster.now > 0);
    }

    #[test]
    fn everyone_sees_everyone_else_in_the_same_order() {
        let r = Rooms::new();
        for id in [3u8, 1, 2] {
            r.join(handle(1), key(id), [id; 32]).unwrap();
        }
        let roster = r.join(handle(1), key(1), [1; 32]).unwrap();
        let names: Vec<u8> = roster.members.iter().map(|m| m.identity.as_bytes()[0]).collect();
        assert_eq!(names, vec![2, 3], "sorted, and without the caller");
        assert_eq!(roster.members[0].proof, [2; 32], "proofs relayed unaltered");
    }

    #[test]
    fn rooms_do_not_leak_into_each_other() {
        let r = Rooms::new();
        r.join(handle(1), key(1), [1; 32]).unwrap();
        let other = r.join(handle(2), key(2), [2; 32]).unwrap();
        assert!(other.members.is_empty(), "a different handle is a different room");
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn a_full_room_refuses_rather_than_evicting() {
        let r = Rooms::new();
        for id in 0..MAX_MEMBERS as u8 {
            r.join(handle(1), key(id), [id; 32]).unwrap();
        }
        assert_eq!(r.join(handle(1), key(99), [99; 32]), Err(JoinError::Full));

        // The people already there are undisturbed, and can still renew.
        let roster = r.join(handle(1), key(0), [0; 32]).unwrap();
        assert_eq!(roster.members.len(), MAX_MEMBERS - 1);
    }

    #[test]
    fn a_full_rooms_own_members_can_still_heartbeat() {
        let r = Rooms::new();
        for id in 0..MAX_MEMBERS as u8 {
            r.join(handle(1), key(id), [id; 32]).unwrap();
        }
        assert!(
            r.join(handle(1), key(1), [1; 32]).is_ok(),
            "renewing is not joining, or a full room would empty itself"
        );
    }

    #[test]
    fn leaving_removes_you_and_an_empty_room_ceases_to_exist() {
        let r = Rooms::new();
        r.join(handle(1), key(1), [1; 32]).unwrap();
        r.join(handle(1), key(2), [2; 32]).unwrap();

        assert!(r.leave(&handle(1), &key(2)));
        assert!(r.join(handle(1), key(1), [1; 32]).unwrap().members.is_empty());

        assert!(r.leave(&handle(1), &key(1)));
        assert!(r.is_empty(), "the room is gone with its last member");
        assert!(!r.leave(&handle(1), &key(1)), "and leaving twice says so");
    }

    #[test]
    fn an_expired_membership_is_forgotten_without_anyone_saying_so() {
        let r = Rooms::new();
        r.join(handle(1), key(1), [1; 32]).unwrap();
        r.join(handle(1), key(2), [2; 32]).unwrap();

        // Backdate one member past the TTL, as a crashed client would look.
        {
            let mut rooms = r.rooms.lock().unwrap();
            let m = rooms.get_mut(&handle(1)).unwrap();
            m.get_mut(&key(2)).unwrap().last_seen = now_unix() - TTL_SECS - 1;
        }
        let roster = r.join(handle(1), key(1), [1; 32]).unwrap();
        assert!(roster.members.is_empty(), "the crashed member is gone");
    }

    #[test]
    fn a_sweep_drops_rooms_nobody_is_in() {
        let r = Rooms::new();
        r.join(handle(1), key(1), [1; 32]).unwrap();
        {
            let mut rooms = r.rooms.lock().unwrap();
            rooms.get_mut(&handle(1)).unwrap().get_mut(&key(1)).unwrap().last_seen =
                now_unix() - TTL_SECS - 1;
        }
        r.expire();
        assert!(r.is_empty());
    }
}
