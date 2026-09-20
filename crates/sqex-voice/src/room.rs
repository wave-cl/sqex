//! Being in a room: who is here, and a session with each of them.
//!
//! SIP-13 gives the exchange a roster and nothing else. Everything that makes a
//! room a *conversation* happens here on the client: verifying that each listed
//! member really holds the room secret, opening an ordinary SIP-12 session with
//! each one that does, and keeping per-peer state for the media.
//!
//! Two things are worth knowing about the shape of this.
//!
//! **Verification is ours because it cannot be the exchange's.** A proof is a
//! MAC under the room secret, and the exchange was never given the secret — that
//! is the point. So it relays proofs it cannot check, and a member that fails
//! the check here is one we never open a session with, never decrypt from, and
//! show as rejected. That is what stops whoever runs the exchange from adding an
//! identity of their own to the roster and listening.
//!
//! **Establishment is best effort, every tick.** SIP-12 needs both sides to
//! have asked, and each side asks on its own two-second cadence, so a new peer
//! takes a few seconds to come up. Somebody who joins and leaves inside that
//! window must not wedge anything, so a pending session is simply dropped when
//! its identity stops appearing in the roster.

use std::collections::HashMap;

use sqex_proto::refusal::{Code, Refusal};
use sqex_proto::room::{Homed, Join, JoinShared, Leave, RoomId, Roster};
use sqex_proto::session::{
    BySession, CallAck, CallOpen, CallState, Open, OpenAck, OpenState, Session,
};
use sqnr::Client;
use sqnr_core::PubKey;

use crate::audio::Rate;
use crate::jitter::{Jitter, Playback};

/// One other person in the room, once we can actually hear them.
pub struct Peer {
    pub identity: PubKey,
    pub session: Session,
    pub session_id: u64,
    pub jitter: Jitter,
    /// Decoding, concealment and comfort noise for this peer, in one place.
    pub playback: Playback,
    /// Our next outgoing sequence number *to this peer*. Each session counts
    /// separately — they have separate keys, and the sequence number is in the
    /// nonce.
    pub out_seq: u64,
    /// Smoothed loudness of what they last said, for showing who is speaking.
    pub level: f32,
    /// When we last opened a frame from them. See [`Membership::STALE`].
    pub last_heard: std::time::Instant,
}

impl Peer {
    /// Fold one frame's loudness into the speaking indicator. Decays quickly
    /// enough to follow a conversation and slowly enough not to flicker
    /// between syllables.
    pub fn note_level(&mut self, frame_rms: f32) {
        self.level = self.level * 0.7 + frame_rms * 0.3;
    }

    pub fn is_speaking(&self) -> bool {
        self.level > 0.01
    }

    /// Note that something from them arrived and could be opened.
    pub fn heard(&mut self) {
        self.last_heard = std::time::Instant::now();
    }
}

/// What changed on the last poll, so the caller can say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A session is up; we can hear them now.
    Joined(PubKey),
    /// They left, or stopped heartbeating.
    Left(PubKey),
    /// Listed in the roster but could not prove they hold the room secret.
    /// Ignored entirely — and worth telling the operator about.
    Rejected(PubKey),
    /// Still in the room, but nothing has arrived from them for a long time.
    /// The session was thrown away and is being built again.
    Restarted(PubKey),
    /// SIP-39 §Pairs across exchanges: in the room at another exchange our exchange will not bridge
    /// to. Present, and not heard.
    Unreachable(PubKey),
}

/// SIP-39 §Pairs across exchanges: how one attempt at a bridge came out.
enum Bridged {
    Peer(Box<Peer>),
    Waiting,
    Refused,
}

/// This client's membership of one room.
///
/// # A rule for async methods here
///
/// Every `async` method must take `&mut self`, or borrow nothing from it at
/// all. A `Peer` owns an `opus::Decoder`, which is `Send` but **not `Sync`**,
/// so a shared borrow of a `Membership` held across an await makes the whole
/// future require `Membership: Sync` — which it is not, and cannot be.
///
/// The consequence is not subtle but it is remote from the cause: the room
/// could only ever be awaited by whoever built it, never spawned onto an
/// executor, so nothing but a program dedicated to that one call could hold a
/// room. `&self` here reads as harmless and is not.
pub struct Membership {
    room: RoomId,
    me: PubKey,
    seed: [u8; 32],
    depth: u64,
    /// What our playback device runs at. Every peer's decoder is built here,
    /// whatever rate they chose to encode at — Opus converts.
    rate: Rate,
    /// Peers with a live session, keyed by session id — which is what arriving
    /// datagrams carry.
    pub peers: HashMap<u64, Peer>,
    /// Reverse index, so a roster diff can find a peer by name.
    by_identity: HashMap<PubKey, u64>,
    /// Identities we are still trying to reach, and the ephemeral we offered
    /// them. Re-offering the same one every tick is what SIP-12 expects.
    pending: HashMap<PubKey, x25519_dalek::StaticSecret>,
    /// Peers in `pending` only because the session we had with them went
    /// stale, as against ones we have never reached at all.
    ///
    /// These are **not** counted as connecting. See [`Membership::connecting`].
    rebuilding: std::collections::HashSet<PubKey>,
    /// Names we have already complained about, so a forged member produces one
    /// line rather than one every two seconds.
    rejected: std::collections::HashSet<PubKey>,
    /// SIP-39 §Sharing on the relay link: the relay peers to ask our exchange to share the room with --
    /// the channel's origin, for a member at a copy. Empty for a member at
    /// the origin, who still asks the shared way so as to be told homes.
    share: Vec<(PubKey, String)>,
    /// SIP-39 §Group calls across exchanges: where each remote member is. A member not here is local.
    homes: HashMap<PubKey, PubKey>,
    /// SIP-39 §Sharing on the relay link: the exchange refused the shared join as malformed -- it is
    /// from before sqex 0.69.0 (SIP-39 §Joining with a share) -- so the plain join is used from then on.
    unshared: bool,
    /// SIP-65 §The member's word: the exchange refused the join with words as malformed -- it
    /// is from before 0.91.0 (SIP-65 §The member's word) -- so the shared join (SIP-39 §Joining with a share) is used from then on.
    unworded: bool,
    /// SIP-39 §Sharing on the relay link: members whose home is not a peer of our exchange, or whose
    /// bridge the exchange refused: in the call and not heard.
    pub unreachable: std::collections::HashSet<PubKey>,
}

impl Membership {
    /// How long a peer may send us nothing before we conclude the session is
    /// broken rather than the person quiet.
    ///
    /// Silence is a real signal here only because nothing suppresses it: with
    /// no discontinuous transmission, a peer in a room sends fifty frames a
    /// second whether or not anyone is talking, so ten seconds of nothing means
    /// the path is wrong, not the room. The usual cause is the peer having
    /// restarted: it opened a new session, ours was discarded to make way, and
    /// its frames now arrive under a session id we do not hold. Rebuilding is
    /// the cure, and it costs a few seconds of one peer.
    ///
    /// If voice activity detection is ever added, this rule has to go with it.
    pub const STALE: std::time::Duration = std::time::Duration::from_secs(10);

    pub fn new(room: RoomId, me: PubKey, seed: [u8; 32], depth: u64, rate: Rate) -> Membership {
        Membership {
            room,
            me,
            seed,
            depth,
            rate,
            peers: HashMap::new(),
            by_identity: HashMap::new(),
            pending: HashMap::new(),
            rebuilding: std::collections::HashSet::new(),
            rejected: std::collections::HashSet::new(),
            share: Vec::new(),
            homes: HashMap::new(),
            unshared: false,
            unworded: false,
            unreachable: std::collections::HashSet::new(),
        }
    }

    /// SIP-39 §Sharing on the relay link: ask the exchange to share the room with these relay peers,
    /// each with the domain it is found by where known (SIP-65 §The member's word).
    pub fn with_share(mut self, share: Vec<(PubKey, String)>) -> Membership {
        self.share = share;
        self
    }

    /// SIP-39 §Group calls across exchanges: where `id` is, if not here.
    pub fn home_of(&self, id: &PubKey) -> Option<PubKey> {
        self.homes.get(id).copied()
    }

    /// Everyone we can currently hear, sorted, for display.
    pub fn present(&self) -> Vec<&Peer> {
        let mut all: Vec<&Peer> = self.peers.values().collect();
        all.sort_by(|a, b| a.identity.as_bytes().cmp(b.identity.as_bytes()));
        all
    }

    /// How many peers we are still working on connecting to.
    ///
    /// **A peer whose session went stale is not one of them.** A call ends
    /// when somebody was seen, nobody is present and nobody is connecting;
    /// counting a stale peer here kept that third condition false forever,
    /// so a relayed call whose only other party hung up never ended. It sat
    /// saying "connecting to 1…" -- to somebody who had left -- until the
    /// person gave up and pressed the button themselves.
    ///
    /// Excluding them does not cost the recovery this was built for. A peer
    /// that really is rebuilding re-establishes **in the same poll** that
    /// discarded the old session: the sweep and the re-offer are steps 3 and
    /// 4 of one pass, and a live run shows the `Restarted` and `Joined`
    /// events sixteen microseconds apart. Lingering in `pending` is what a
    /// peer who has gone looks like, and the whole point of this count is to
    /// tell those apart.
    pub fn connecting(&self) -> usize {
        self.pending
            .keys()
            .filter(|id| !self.rebuilding.contains(id))
            .count()
    }

    /// Heartbeat, fetch the roster, and reconcile it with what we have.
    ///
    /// Every request here goes through `Client::post`, which takes `&mut self`,
    /// so this is deliberately sequential: at most a handful of round trips
    /// every two seconds. Media never waits behind it — datagrams need only a
    /// shared reference to the connection.
    pub async fn poll(&mut self, client: &mut Client) -> Result<Vec<Event>, String> {
        let roster = if self.unshared {
            Self::heartbeat(self.room, self.me, client).await?
        } else {
            let homed = if self.unworded {
                Self::heartbeat_shared(self.room, self.me, &self.share, client).await?
            } else {
                match Self::heartbeat_worded(self.room, self.me, self.seed, &self.share, client)
                    .await?
                {
                    Some(homed) => Some(homed),
                    None => {
                        self.unworded = true;
                        Self::heartbeat_shared(self.room, self.me, &self.share, client).await?
                    }
                }
            };
            match homed {
                Some(homed) => {
                    self.homes = homed
                        .members
                        .iter()
                        .filter(|m| !m.is_local())
                        .map(|m| (m.identity, m.home))
                        .collect();
                    // SIP-65 §The member's word: a member homed at an exchange we have not
                    // named is named from now on, with a word: that is how
                    // the second side of an unlisted pair comes to hold a
                    // word to share back with. The exchange already holds
                    // the link, so no domain is needed.
                    for home in self.homes.values() {
                        if !self.share.iter().any(|(k, _)| k == home)
                            && self.share.len() < sqex_proto::room::MAX_SHARE
                        {
                            self.share.push((*home, String::new()));
                        }
                    }
                    Roster {
                        now: homed.now,
                        members: homed
                            .members
                            .iter()
                            .map(|m| sqex_proto::room::Member {
                                identity: m.identity,
                                proof: m.proof,
                            })
                            .collect(),
                    }
                }
                None => {
                    self.unshared = true;
                    Self::heartbeat(self.room, self.me, client).await?
                }
            }
        };
        let mut events = Vec::new();

        // 1. Keep only the members who can prove they belong here.
        let mut verified: Vec<PubKey> = Vec::with_capacity(roster.members.len());
        for m in &roster.members {
            if self.room.verify(&m.identity, &m.proof) {
                verified.push(m.identity);
            } else if self.rejected.insert(m.identity) {
                events.push(Event::Rejected(m.identity));
            }
        }

        // 2. Anyone gone from the roster is gone from the room.
        let still_here = |id: &PubKey| verified.contains(id);
        let departed: Vec<PubKey> = self
            .by_identity
            .keys()
            .filter(|id| !still_here(id))
            .copied()
            .collect();
        for id in departed {
            if let Some(sid) = self.by_identity.remove(&id) {
                self.peers.remove(&sid);
            }
            events.push(Event::Left(id));
        }
        self.pending.retain(|id, _| still_here(id));
        self.rebuilding.retain(|id| still_here(id));
        self.rejected
            .retain(|id| roster.members.iter().any(|m| m.identity == *id));

        // 3. Throw away any session that has gone quiet, and let step 4 build
        //    it again with a fresh ephemeral.
        let stale: Vec<(u64, PubKey)> = self
            .peers
            .values()
            .filter(|p| p.last_heard.elapsed() > Self::STALE)
            .map(|p| (p.session_id, p.identity))
            .collect();
        for (sid, id) in stale {
            self.peers.remove(&sid);
            self.by_identity.remove(&id);
            // Step 4 will re-offer; until that succeeds this peer is being
            // rebuilt, not reached for the first time, and must not read as
            // a connection in progress.
            self.rebuilding.insert(id);
            events.push(Event::Restarted(id));
        }

        // 4. Offer a session to anyone new, and keep offering to anyone we have
        //    offered to before but not yet reached.
        for id in &verified {
            if self.by_identity.contains_key(id) {
                continue;
            }
            self.pending
                .entry(*id)
                .or_insert_with(|| x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng));
        }
        // Take the ephemeral out by value, so no borrow of `self` is alive
        // across the await inside. See the note on `Membership`.
        let waiting: Vec<(PubKey, x25519_dalek::StaticSecret)> = self
            .pending
            .iter()
            .map(|(id, eph)| (*id, eph.clone()))
            .collect();
        let (seed, depth, rate, me) = (self.seed, self.depth, self.rate, self.me);
        for (id, eph) in waiting {
            // SIP-39 §Pairs across exchanges: toward a member elsewhere, the lower of the two places
            // the bridge and the higher opens as for anybody local.
            let bridge_to = self
                .homes
                .get(&id)
                .filter(|_| me.as_bytes() < id.as_bytes())
                .copied();
            let got = match bridge_to {
                Some(home) => {
                    match Self::try_bridge(seed, depth, rate, eph, client, id, home).await? {
                        Bridged::Peer(p) => Some(*p),
                        Bridged::Waiting => None,
                        Bridged::Refused => {
                            if self.unreachable.insert(id) {
                                events.push(Event::Unreachable(id));
                            }
                            None
                        }
                    }
                }
                None => Self::try_establish(seed, depth, rate, eph, client, id).await?,
            };
            let Some(peer) = got else {
                continue;
            };
            {
                self.unreachable.remove(&id);
                // Reached: whatever it was before, it is a peer now.
                self.rebuilding.remove(&id);
                events.push(Event::Joined(peer.identity));
                self.by_identity.insert(peer.identity, peer.session_id);
                self.peers.insert(peer.session_id, peer);
                self.pending.remove(&id);
            }
        }
        self.unreachable.retain(|id| still_here(id));

        Ok(events)
    }

    /// SIP-39 §Sharing on the relay link: the shared join. `None` when the exchange does not know it,
    /// which is an exchange from before sqex 0.69.0 (SIP-39 §Group calls across exchanges) and not an error.
    async fn heartbeat_shared(
        room: RoomId,
        me: PubKey,
        share: &[(PubKey, String)],
        client: &mut Client,
    ) -> Result<Option<Homed>, String> {
        let keys: Vec<PubKey> = share.iter().map(|(k, _)| *k).collect();
        let (code, body) = client
            .post("/room/join", JoinShared::new(&room, &me, keys).encode())
            .await?;
        Self::homed_answer(code, body)
    }

    /// SIP-65 §The member's word: the shared join with a word per exchange named, signed by
    /// this device now. `None` when the exchange does not know it.
    async fn heartbeat_worded(
        room: RoomId,
        me: PubKey,
        seed: [u8; 32],
        share: &[(PubKey, String)],
        client: &mut Client,
    ) -> Result<Option<Homed>, String> {
        let issued = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let req = sqex_proto::room::JoinSharedWord {
            handle: room.handle(),
            proof: room.proof(&me),
            share: share
                .iter()
                .map(|(k, d)| {
                    (
                        *k,
                        d.clone(),
                        sqex_proto::session::RoomWord::sign(&seed, &room.handle(), k, issued, None),
                    )
                })
                .collect(),
        };
        let (code, body) = client.post("/room/join", req.encode()).await?;
        Self::homed_answer(code, body)
    }

    fn homed_answer(code: u16, body: Vec<u8>) -> Result<Option<Homed>, String> {
        match code {
            200 => Homed::decode(&body).map(Some).map_err(|e| e.to_string()),
            400 => Ok(None),
            _ => match Refusal::decode(&body) {
                Ok(r) if r.code == Code::RoomFull => Err("the room is full".into()),
                Ok(r) => Err(format!("join failed ({code}): {r}")),
                Err(_) => Err(format!(
                    "join failed ({code}): {}",
                    String::from_utf8_lossy(&body)
                )),
            },
        }
    }

    /// SIP-39 §Pairs across exchanges: one attempt at a bridged session with `id`, at `home`, placed
    /// by our exchange.
    #[allow(clippy::too_many_arguments)]
    async fn try_bridge(
        seed: [u8; 32],
        depth: u64,
        rate: Rate,
        eph: x25519_dalek::StaticSecret,
        client: &mut Client,
        id: PubKey,
        home: PubKey,
    ) -> Result<Bridged, String> {
        // The device invite of SIP-39 §Pairs across exchanges stays with the relay peer list, so the
        // open is the plain one (SIP-65 §Device invites).
        let open = CallOpen {
            ephemeral: x25519_dalek::PublicKey::from(&eph).to_bytes(),
            target: format!("{id}@{home}"),
            word: None,
        };
        let (code, body) = client.post("/session/call", open.encode()).await?;
        if code != 200 {
            return Ok(Bridged::Refused);
        }
        let ack = CallAck::decode(&body).map_err(|e| e.to_string())?;
        match ack.state {
            CallState::Ringing => return Ok(Bridged::Waiting),
            // Reported once by the exchange and then cleared, so the next
            // tick asks again; a member whose home is not a peer of ours
            // stays unreachable and is shown so.
            CallState::Rejected => return Ok(Bridged::Refused),
            CallState::Established => {}
        }
        let session = Session::derive(&seed, &eph, &ack.peer, &ack.peer_ephemeral)
            .map_err(|e| e.to_string())?;
        Ok(Bridged::Peer(Box::new(Peer {
            identity: id,
            session,
            session_id: ack.session_id,
            jitter: Jitter::new(depth),
            playback: Playback::new(rate.hz())?,
            out_seq: 0,
            level: 0.0,
            last_heard: std::time::Instant::now(),
        })))
    }

    /// Say we are still here, and get back who else is.
    ///
    /// Takes the room and our own key by value rather than borrowing `self`.
    /// See the note on [`Membership`]: a borrow of this struct held across an
    /// await makes every future containing it unspawnable, and both of these
    /// are `Copy`, so there is nothing to gain by borrowing.
    async fn heartbeat(room: RoomId, me: PubKey, client: &mut Client) -> Result<Roster, String> {
        let (code, body) = client
            .post("/room/join", Join::new(&room, &me).encode())
            .await?;
        match code {
            200 => Roster::decode(&body).map_err(|e| e.to_string()),
            // Was `507 => "the room is full"`, which inferred a reason from a
            // status that several quota refusals share. The exchange says which.
            _ => match Refusal::decode(&body) {
                Ok(r) if r.code == Code::RoomFull => Err("the room is full".into()),
                Ok(r) => Err(format!("join failed ({code}): {r}")),
                Err(_) => Err(format!(
                    "join failed ({code}): {}",
                    String::from_utf8_lossy(&body)
                )),
            },
        }
    }

    /// One attempt at a SIP-12 session with `id`. `Ok(None)` means the peer has
    /// not asked for us yet, which is ordinary and not an error.
    /// Offer a session to `id` and build a [`Peer`] if they have offered back.
    ///
    /// Borrows nothing from `self` — see the note on [`Membership`]. Everything
    /// it needs is `Copy` but for the ephemeral secret, which is cloned by the
    /// caller; re-offering the *same* ephemeral each tick is what SIP-12
    /// expects, so it must be the stored one and not a fresh one.
    #[allow(clippy::too_many_arguments)]
    async fn try_establish(
        seed: [u8; 32],
        depth: u64,
        rate: Rate,
        eph: x25519_dalek::StaticSecret,
        client: &mut Client,
        id: PubKey,
    ) -> Result<Option<Peer>, String> {
        let open = Open {
            peer: id,
            ephemeral: x25519_dalek::PublicKey::from(&eph).to_bytes(),
        };
        let (code, body) = client.post("/session/open", open.encode()).await?;
        if code != 200 {
            // A peer that vanished mid-handshake is not a failure of ours; the
            // next roster will drop them.
            return Ok(None);
        }
        let ack = OpenAck::decode(&body).map_err(|e| e.to_string())?;
        if ack.state != OpenState::Established {
            return Ok(None);
        }
        let session =
            Session::derive(&seed, &eph, &id, &ack.peer_ephemeral).map_err(|e| e.to_string())?;
        Ok(Some(Peer {
            identity: id,
            session,
            session_id: ack.session_id,
            jitter: Jitter::new(depth),
            playback: Playback::new(rate.hz())?,
            out_seq: 0,
            level: 0.0,
            last_heard: std::time::Instant::now(),
        }))
    }

    /// Tell the exchange we are going, so the others do not spend a TTL talking
    /// to nobody. Best effort — the TTL is what actually removes us.
    ///
    /// The sessions are closed too, and that matters more than tidiness: a
    /// session outlives the call by an hour, and a stale one left lying about
    /// is what the next conversation between the same two people trips over.
    ///
    /// Takes `&mut self` although it reads only. Holding a `&Membership` across
    /// an await makes the whole future require `Membership: Sync`, and it is
    /// not — a `Peer` owns an `opus::Decoder`, which is `Send` but not `Sync`.
    /// So a room could be awaited only by whoever built it, and never spawned,
    /// which is exactly what a desktop client has to do. Leaving is a mutation
    /// in every sense but the borrow checker's, so this costs nothing.
    pub async fn leave(&mut self, client: &mut Client) {
        // Collect the ids before awaiting anything. Iterating the map across an
        // await keeps a `Keys<'_, u64, Peer>` alive over it, and a borrow of a
        // `Peer` is not `Send` because the decoder inside it is not `Sync` --
        // which would make this whole future unspawnable. A handful of u64s is
        // a cheap price for a room that something other than a terminal can
        // hold.
        let sessions: Vec<u64> = self.peers.keys().copied().collect();
        for sid in sessions {
            let _ = client
                .post("/session/close", BySession::close(sid).encode())
                .await;
        }
        let _ = client
            .post(
                "/room/leave",
                Leave {
                    handle: self.room.handle(),
                }
                .encode(),
            )
            .await;
    }
}

/// The first eight characters of a key, for a status line that has to fit
/// several of them.
pub fn short(key: &PubKey) -> String {
    key.to_string().chars().take(8).collect()
}

#[cfg(test)]
mod connecting_tests {
    use super::*;

    fn a_room() -> Membership {
        Membership::new(
            RoomId::new([1u8; 32]),
            PubKey::new([2u8; 32]),
            [3u8; 32],
            4,
            crate::audio::Rate::DEFAULT,
        )
    }

    fn an_ephemeral() -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng)
    }

    /// A peer we have never reached is one we are connecting to. A peer whose
    /// session went stale is not.
    ///
    /// **This is what left a relayed call running after the other side hung
    /// up.** A call is over when somebody was seen, nobody is present and
    /// nobody is connecting. A departed peer stayed in `pending` -- the
    /// exchange lists a member for three times as long as a session is
    /// allowed to be silent -- so the third condition never held and the
    /// call sat saying "connecting to 1…" to somebody who had left, until
    /// the person pressed the button themselves.
    #[test]
    fn a_peer_being_rebuilt_is_not_a_peer_being_reached() {
        let mut m = a_room();
        let never_reached = PubKey::new([7u8; 32]);
        let went_stale = PubKey::new([8u8; 32]);

        m.pending.insert(never_reached, an_ephemeral());
        m.pending.insert(went_stale, an_ephemeral());
        assert_eq!(m.connecting(), 2, "both are new arrivals so far");

        // The second one is only here because its session went quiet.
        m.rebuilding.insert(went_stale);
        assert_eq!(
            m.connecting(),
            1,
            "a stale peer is being rebuilt, not reached"
        );

        // And with nobody left but the stale one, nothing is connecting --
        // which is what lets the call end.
        m.pending.remove(&never_reached);
        assert_eq!(
            m.connecting(),
            0,
            "a call with only a departed peer is over"
        );
        assert!(m.present().is_empty(), "and nobody is present");
    }
}
