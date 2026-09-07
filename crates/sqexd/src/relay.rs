//! SIP-39 cross-exchange calls: the relay link and the bridge bookkeeping.
//!
//! A local SIP-12 session lives entirely in [`crate::session::Sessions`], which
//! matches two connections at one exchange. A **bridged** session spans two
//! exchanges joined by a *relay link* — one long-lived sQUIC connection brought
//! up like a SIP-35 replica link (mutual SIP-9 auth, the peer key pinned from
//! configuration and never taken from the wire) and gated by an operator
//! allowlist. Control travels as length-prefixed [`Control`] frames on a
//! bidirectional stream either end may write; media travels as [`RelayData`]
//! datagrams on the same connection.
//!
//! This module is deliberately passive state plus free functions that the
//! server drives, so it never has to reach back into the private innards of
//! [`Server`]; the few effects it needs — ring a device, deliver a datagram,
//! resolve a device to its account — are `pub(crate)` methods on the server.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use quinn::Connection;
use sqnr_core::PubKey;
use tokio::sync::mpsc;

use sqex_proto::h3::H3Client;
use sqex_proto::name;
use sqex_proto::relay::{self, Control, RelayData};
use sqex_proto::session::{CallAck, CallState, DatagramFrame, OpenAck, OpenState};
use squic::Config as SquicConfig;

use crate::server::Server;

/// The high bit of a session id marks a bridged session, keeping bridged ids
/// disjoint from the ids [`crate::session::Sessions`] hands local sessions so
/// the one datagram path can tell which subsystem a frame belongs to.
pub const BRIDGE_BIT: u64 = 1 << 63;

/// How long a bridge that has not connected is kept.
///
/// A caller that gives up leaves its bridge behind, and `place_call` is keyed by
/// `(caller, target)` — so without an expiry the abandoned bridge answers every
/// later call to that peer and the pair becomes **permanently uncallable**. That
/// is not hypothetical: it is what a live call ran into. Two minutes covers a
/// ring window with room to spare, and a call nobody has answered in that time
/// is not going to be.
pub const RINGING_TTL_SECS: u64 = 120;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ringing,
    Established,
    Rejected(u8),
}

/// How a bridge is indexed, kept on the record so removal can undo it.
#[derive(Clone)]
enum Index {
    Caller { caller: PubKey, target: String },
    Callee { caller: PubKey, account: PubKey },
}

struct BridgeRec {
    /// The peer exchange this bridge runs over (which link).
    peer: PubKey,
    /// The addressed account (B). Read when authorizing a decline: only a
    /// device of this account may refuse this bridge.
    account: PubKey,
    /// The caller device (A).
    caller: PubKey,
    caller_eph: [u8; 32],
    /// The answering device (B's), once known.
    callee: Option<PubKey>,
    callee_eph: [u8; 32],
    /// The local bridged session id, 0 until established. High bit set.
    session_id: u64,
    /// The local party's identity: A on the caller side, B's device on the
    /// callee side. Set once the session is established.
    local: PubKey,
    /// Caller-side polling result. Unused on the callee side.
    outcome: Outcome,
    /// When this bridge was made, so it can be expired. A live SIP-12 session
    /// has a TTL and a sweep; a bridged one had neither.
    created: u64,
    index: Index,
}

/// How the relay turns a domain into an exchange to dial.
pub enum Find {
    /// SIP-33: the domain's DNSSEC-signed `_sqex` record, pinned on first
    /// contact. What a deployment uses, and why `relay_peers` carries no
    /// addresses — where a peer is, is DNS's business.
    Discover,
    /// A fixed map, for **tests only**: two exchanges on loopback have no DNS
    /// to find each other through. Deliberately unreachable from configuration
    /// — an operator able to pin an address by hand would be back to the thing
    /// discovery replaced.
    Fixed(HashMap<String, (PubKey, SocketAddr)>),
}

impl Find {
    async fn find(&self, domain: &str) -> Result<(PubKey, SocketAddr), String> {
        match self {
            Find::Fixed(map) => map
                .get(domain)
                .copied()
                .ok_or_else(|| format!("no peer for {domain}")),
            Find::Discover => {
                let found = sqex_discovery::discover(domain)
                    .await
                    .map_err(|e| format!("discover {domain}: {e}"))?;
                // Worth saying once: a first contact is when the key this
                // exchange will hold a peer to gets fixed.
                if found.newly_pinned {
                    tracing::info!(domain, key = %found.key, "pinned a peer exchange");
                }
                Ok((found.key, sqex_discovery::resolve_addr(&found.address)?))
            }
        }
    }
}

struct Link {
    /// Which connection this entry is for. A peer that reconnects replaces the
    /// entry, and the old connection's cleanup must not then remove the new
    /// one — so teardown checks this before removing anything.
    id: usize,
    conn: Connection,
    /// Where this peer was found. Kept so a later call to the same domain is
    /// answered from the link rather than another DNS round trip.
    addr: SocketAddr,
    /// Pre-framed control bytes to write to the shared control stream.
    control: mpsc::UnboundedSender<Vec<u8>>,
}

#[derive(Default)]
struct RelayInner {
    links: HashMap<PubKey, Link>,
    bridges: HashMap<relay::Bridge, BridgeRec>,
    by_session: HashMap<u64, relay::Bridge>,
    caller_index: HashMap<(PubKey, String), relay::Bridge>,
    callee_index: HashMap<(PubKey, PubKey), relay::Bridge>,
    /// What a domain resolved to, for as long as its link lives. Dropped with
    /// the link, so it cannot go stale on its own.
    domains: HashMap<String, PubKey>,
    next_seq: u64,
}

/// SIP-39 relay state: the peer allowlist, the bridge ceiling, and the live
/// links and bridges.
pub struct Relay {
    seed: [u8; 32],
    peers: Vec<PubKey>,
    find: Find,
    max_bridges: Option<u64>,
    inner: Mutex<RelayInner>,
}

impl Relay {
    pub fn new(seed: [u8; 32], peers: Vec<PubKey>, max_bridges: Option<u64>, find: Find) -> Relay {
        Relay {
            seed,
            peers,
            find,
            max_bridges,
            inner: Mutex::new(RelayInner::default()),
        }
    }

    /// True if this exchange federates with anybody at all.
    pub fn configured(&self) -> bool {
        !self.peers.is_empty()
    }

    /// Whether an incoming link's SIP-9 identity is on the allowlist. This is
    /// the whole gate at the link layer.
    pub fn allowed(&self, key: &PubKey) -> bool {
        self.peers.contains(key)
    }

    fn at_capacity(&self) -> bool {
        let n = self.inner.lock().unwrap().bridges.len() as u64;
        self.max_bridges.is_some_and(|m| n >= m)
    }

    /// Drop bridges that have outlived themselves. Called from the periodic
    /// sweeper, so an exchange nobody is calling still tidies up.
    pub fn sweep(&self, now: u64) {
        expire(&mut self.inner.lock().unwrap(), now);
    }

    /// Concurrent bridged calls, for `/status`.
    pub fn bridge_count(&self) -> usize {
        self.inner.lock().unwrap().bridges.len()
    }

    fn next_session(inner: &mut RelayInner) -> u64 {
        inner.next_seq += 1;
        BRIDGE_BIT | inner.next_seq
    }
}

fn random_bridge() -> relay::Bridge {
    use rand::RngCore;
    let mut b = [0u8; relay::BRIDGE_LEN];
    rand::rng().fill_bytes(&mut b);
    b
}

/// The ALPN negotiated on a connection, if any — how the accept loop tells a
/// relay link (`sqex-relay`) from an HTTP/3 client (`h3`).
pub fn alpn_of(conn: &Connection) -> Option<Vec<u8>> {
    conn.handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|h| h.protocol)
}

fn caller_ack(rec: &BridgeRec, now: u64) -> CallAck {
    match rec.outcome {
        Outcome::Ringing => CallAck::ringing(now),
        Outcome::Rejected(reason) => CallAck::rejected(reason, now),
        Outcome::Established => CallAck {
            state: CallState::Established,
            reason: 0,
            session_id: rec.session_id,
            peer: rec.callee.unwrap_or(PubKey::new([0u8; 32])),
            peer_ephemeral: rec.callee_eph,
            now,
        },
    }
}

fn send_control(inner: &RelayInner, peer: &PubKey, ctrl: Control) {
    if let Some(link) = inner.links.get(peer) {
        let _ = link.control.send(ctrl.frame());
    }
}

/// Forget a link, but only if it is still *this* link.
///
/// Two ways this went wrong in the field, and both are the same root: the entry
/// was keyed by peer alone. A peer that reconnected replaced the entry, and the
/// old connection's cleanup then removed the **new** one — leaving an exchange
/// that rang a phone and had nowhere to send the answer. And teardown hung off
/// the writer alone, so a dead reader left a link that could send and never
/// receive: invites went out, accepts were never read, and every call over it
/// hung until a restart.
fn forget_link(server: &Server, peer: PubKey, id: usize) {
    let mut inner = server.relay.inner.lock().unwrap();
    if inner.links.get(&peer).map(|l| l.id) != Some(id) {
        return; // already replaced by a newer connection
    }
    inner.links.remove(&peer);
    inner.domains.retain(|_, k| *k != peer);
}

fn drop_bridge(inner: &mut RelayInner, bridge: &relay::Bridge) {
    if let Some(rec) = inner.bridges.remove(bridge) {
        if rec.session_id != 0 {
            inner.by_session.remove(&rec.session_id);
        }
        match rec.index {
            Index::Caller { caller, target } => {
                inner.caller_index.remove(&(caller, target));
            }
            Index::Callee { caller, account } => {
                inner.callee_index.remove(&(caller, account));
            }
        }
    }
}

/// Drop bridges that have outlived their usefulness, telling the far side so a
/// phone that is still ringing stops.
///
/// A bridge that never connected goes after [`RINGING_TTL_SECS`]; one carrying a
/// call follows SIP-12's own session TTL, because that is how long a call may
/// legitimately last. Mirrors `Sessions::expire`, which bridged sessions had no
/// equivalent of.
fn expire(inner: &mut RelayInner, now: u64) {
    let dead: Vec<(relay::Bridge, PubKey)> = inner
        .bridges
        .iter()
        .filter(|(_, rec)| {
            let age = now.saturating_sub(rec.created);
            match rec.outcome {
                Outcome::Established => age > sqex_proto::session::TTL_SECS,
                _ => age > RINGING_TTL_SECS,
            }
        })
        .map(|(bridge, rec)| (*bridge, rec.peer))
        .collect();
    for (bridge, peer) in dead {
        send_control(
            inner,
            &peer,
            Control::Close {
                bridge,
                reason: relay::REASON_ENDED,
            },
        );
        drop_bridge(inner, &bridge);
    }
}

/// Place, or re-poll, a cross-exchange call. Idempotent for a given
/// `(caller, target)`: the first call resolves the far side and sends the
/// invite; later ones report where it stands, so the client polls it like an
/// [`crate::session::Sessions`] open.
pub async fn place_call(
    server: &Arc<Server>,
    caller: PubKey,
    eph: [u8; 32],
    target: String,
    now: u64,
) -> CallAck {
    // Clear anything that has outlived itself first. The re-poll below answers
    // from whatever is indexed under `(caller, target)`, so a bridge left
    // behind by a caller that gave up would answer here for ever — which is
    // exactly the way this failed in the field.
    expire(&mut server.relay.inner.lock().unwrap(), now);

    // Already in flight? Report where it stands.
    //
    // A refusal is reported **once and then cleared**. Without that the bridge
    // that carried the rejection stays indexed under `(caller, target)` and
    // every later call to the same peer answers with the old refusal — one
    // declined call would make that peer permanently uncallable.
    {
        let mut inner = server.relay.inner.lock().unwrap();
        if let Some(bridge) = inner.caller_index.get(&(caller, target.clone())).copied()
            && let Some(rec) = inner.bridges.get(&bridge)
        {
            let ack = caller_ack(rec, now);
            if ack.state == CallState::Rejected {
                drop_bridge(&mut inner, &bridge);
            }
            return ack;
        }
    }

    let Some((label, domain)) = target.rsplit_once('@') else {
        // No @domain: this is a local peer and belongs on the plain open path.
        return CallAck::rejected(relay::REASON_REFUSED, now);
    };
    let domain = domain.to_ascii_lowercase();
    // Discover first, then judge the key. The allowlist is a judgement about a
    // *key*, and discovery is what produces one — so the order is fixed by what
    // each step knows, not by preference (SIP-39).
    let (peer_key, peer_addr) = match find_peer(server, &domain).await {
        Ok(found) => found,
        Err(e) => {
            // A pinned key that has changed lands here too, and that is a thing
            // an operator must be able to find afterwards rather than a call
            // that quietly did not connect.
            tracing::warn!(%domain, %e, "no peer exchange for this domain");
            return CallAck::rejected(relay::REASON_UNREACHABLE, now);
        }
    };
    if !server.relay.allowed(&peer_key) {
        // Found, but not somebody this operator federates with.
        return CallAck::rejected(relay::REASON_REFUSED, now);
    }
    if server.relay.at_capacity() {
        return CallAck::rejected(relay::REASON_REFUSED, now);
    }

    let account = match label.parse::<PubKey>() {
        Ok(k) => k,
        Err(_) => match resolve_name_at(peer_addr, &peer_key, &server.relay.seed, label).await {
            Some(a) => a,
            None => return CallAck::rejected(relay::REASON_NO_ACCOUNT, now),
        },
    };

    if ensure_link(server, peer_key, peer_addr).await.is_err() {
        return CallAck::rejected(relay::REASON_UNREACHABLE, now);
    }

    let bridge = random_bridge();
    let mut inner = server.relay.inner.lock().unwrap();
    // Lost a race with another poll while resolving? Report that one.
    if let Some(b) = inner.caller_index.get(&(caller, target.clone())).copied()
        && let Some(rec) = inner.bridges.get(&b)
    {
        return caller_ack(rec, now);
    }
    inner.bridges.insert(
        bridge,
        BridgeRec {
            peer: peer_key,
            account,
            caller,
            caller_eph: eph,
            callee: None,
            callee_eph: [0u8; 32],
            session_id: 0,
            local: caller,
            outcome: Outcome::Ringing,
            created: now,
            index: Index::Caller {
                caller,
                target: target.clone(),
            },
        },
    );
    inner.caller_index.insert((caller, target), bridge);
    send_control(
        &inner,
        &peer_key,
        Control::Invite {
            bridge,
            caller,
            caller_eph: eph,
            account,
            caller_domain: String::new(),
        },
    );
    CallAck::ringing(now)
}

/// If a plain [`crate::session::Open`] toward `caller` is really this device
/// answering a cross-exchange call, complete the bridge and return the ack;
/// otherwise `None`, and the caller falls through to the local session path.
pub fn try_answer(
    server: &Server,
    device: PubKey,
    caller: PubKey,
    eph: [u8; 32],
    now: u64,
) -> Option<OpenAck> {
    let account = server.account_of(&device);
    let mut inner = server.relay.inner.lock().unwrap();
    let bridge = *inner.callee_index.get(&(caller, account))?;
    match inner.bridges.get(&bridge)?.callee {
        Some(dev) if dev == device => {
            // Idempotent re-open by the same device.
            let rec = inner.bridges.get(&bridge)?;
            return Some(OpenAck {
                state: OpenState::Established,
                session_id: rec.session_id,
                peer_ephemeral: rec.caller_eph,
                now,
            });
        }
        Some(_) => return None, // already answered elsewhere
        None => {}
    }
    let sid = Relay::next_session(&mut inner);
    let (caller_eph, peer) = {
        let rec = inner.bridges.get_mut(&bridge)?;
        rec.callee = Some(device);
        rec.callee_eph = eph;
        rec.session_id = sid;
        rec.local = device;
        (rec.caller_eph, rec.peer)
    };
    inner.by_session.insert(sid, bridge);
    send_control(
        &inner,
        &peer,
        Control::Accept {
            bridge,
            callee: device,
            callee_eph: eph,
        },
    );
    Some(OpenAck {
        state: OpenState::Established,
        session_id: sid,
        peer_ephemeral: caller_eph,
        now,
    })
}

/// A device refusing a ringing cross-exchange call: tell the caller's exchange
/// why, and drop the bridge.
///
/// **Only a device of the bridge's addressed account may decline it.** Without
/// that check anyone holding a bridge id could hang up somebody else's call, and
/// anyone could probe for live bridges by guessing. The route answers every
/// decline identically whatever this returns — accepted, unknown bridge, or
/// somebody else's — so the refusal discloses nothing either.
pub fn decline(server: &Server, device: PubKey, bridge: relay::Bridge, reason: u8) -> bool {
    let account = server.account_of(&device);
    let mut inner = server.relay.inner.lock().unwrap();
    let peer = match inner.bridges.get(&bridge) {
        Some(rec) if rec.account == account => rec.peer,
        _ => return false,
    };
    send_control(&inner, &peer, Control::Reject { bridge, reason });
    drop_bridge(&mut inner, &bridge);
    true
}

/// Tear down a bridged session and tell the peer. Returns false if the id is
/// not a bridge, so the caller can fall through to the local close path.
pub fn close_bridge(server: &Server, session_id: u64) -> bool {
    if session_id & BRIDGE_BIT == 0 {
        return false;
    }
    let mut inner = server.relay.inner.lock().unwrap();
    let Some(bridge) = inner.by_session.get(&session_id).copied() else {
        return true;
    };
    let peer = inner.bridges.get(&bridge).map(|r| r.peer);
    if let Some(peer) = peer {
        send_control(
            &inner,
            &peer,
            Control::Close {
                bridge,
                reason: relay::REASON_ENDED,
            },
        );
    }
    drop_bridge(&mut inner, &bridge);
    true
}

/// A media datagram for a bridged session: send it across the link instead of
/// to a local connection. Returns true when the id is a bridge id (so the
/// local forwarder does nothing more), whether or not it could be delivered.
pub fn maybe_divert(server: &Server, from: &PubKey, frame: &DatagramFrame) -> bool {
    if frame.session_id & BRIDGE_BIT == 0 {
        return false;
    }
    let inner = server.relay.inner.lock().unwrap();
    let Some(bridge) = inner.by_session.get(&frame.session_id).copied() else {
        return true;
    };
    let Some(rec) = inner.bridges.get(&bridge) else {
        return true;
    };
    // Only the local party of this bridge may send on it.
    if rec.local != *from {
        return true;
    }
    let Some(link) = inner.links.get(&rec.peer) else {
        return true;
    };
    let conn = link.conn.clone();
    let data = RelayData {
        bridge,
        seq: frame.seq,
        ciphertext: frame.ciphertext.clone(),
    }
    .encode();
    drop(inner);
    let _ = conn.send_datagram(Bytes::from(data));
    true
}

fn inject(server: &Server, data: RelayData) {
    let (sid, local) = {
        let inner = server.relay.inner.lock().unwrap();
        let Some(rec) = inner.bridges.get(&data.bridge) else {
            return;
        };
        if rec.session_id == 0 {
            return;
        }
        (rec.session_id, rec.local)
    };
    let frame = DatagramFrame {
        session_id: sid,
        seq: data.seq,
        ciphertext: data.ciphertext,
    }
    .encode();
    server.deliver_local_datagram(&local, Bytes::from(frame));
}

fn on_control(server: &Server, peer: PubKey, ctrl: Control) {
    match ctrl {
        Control::Invite {
            bridge,
            caller,
            caller_eph,
            account,
            ..
        } => {
            if server.relay.at_capacity() {
                let inner = server.relay.inner.lock().unwrap();
                send_control(
                    &inner,
                    &peer,
                    Control::Reject {
                        bridge,
                        reason: relay::REASON_REFUSED,
                    },
                );
                return;
            }
            // The ring is a SIP-30 event, so an account with no open stream on
            // any device cannot hear it. Say so rather than ringing into the
            // void and leaving the caller to poll until it gives up.
            //
            // This cannot be `no-account`: SIP-22 makes a device with no
            // registered account its own account, so every 32-byte key is a
            // potential account and there is nothing to look up. Unreachable is
            // the honest answer, and the only one available here.
            if server.reachable(&account) == 0 {
                let inner = server.relay.inner.lock().unwrap();
                send_control(
                    &inner,
                    &peer,
                    Control::Reject {
                        bridge,
                        reason: relay::REASON_UNREACHABLE,
                    },
                );
                return;
            }
            {
                let mut inner = server.relay.inner.lock().unwrap();
                inner.bridges.insert(
                    bridge,
                    BridgeRec {
                        peer,
                        account,
                        caller,
                        caller_eph,
                        callee: None,
                        callee_eph: [0u8; 32],
                        session_id: 0,
                        local: PubKey::new([0u8; 32]),
                        outcome: Outcome::Ringing,
                        created: crate::state::now_unix(),
                        index: Index::Callee { caller, account },
                    },
                );
                inner.callee_index.insert((caller, account), bridge);
                send_control(&inner, &peer, Control::Ringing { bridge });
            }
            // Ring the account's devices (SIP-30, per device).
            server.ring_crosscall(account, bridge, caller);
        }
        Control::Ringing { .. } => {} // caller side: nothing to do, still ringing
        Control::Accept {
            bridge,
            callee,
            callee_eph,
        } => {
            let mut inner = server.relay.inner.lock().unwrap();
            if inner.bridges.contains_key(&bridge) {
                let sid = Relay::next_session(&mut inner);
                if let Some(rec) = inner.bridges.get_mut(&bridge) {
                    rec.callee = Some(callee);
                    rec.callee_eph = callee_eph;
                    rec.session_id = sid;
                    rec.local = rec.caller;
                    rec.outcome = Outcome::Established;
                }
                inner.by_session.insert(sid, bridge);
            }
        }
        Control::Reject { bridge, reason } => {
            let mut inner = server.relay.inner.lock().unwrap();
            if let Some(rec) = inner.bridges.get_mut(&bridge) {
                rec.outcome = Outcome::Rejected(reason);
            }
        }
        Control::Close { bridge, .. } => {
            let mut inner = server.relay.inner.lock().unwrap();
            drop_bridge(&mut inner, &bridge);
        }
    }
}

async fn resolve_name_at(
    addr: SocketAddr,
    key: &PubKey,
    seed: &[u8; 32],
    name: &str,
) -> Option<PubKey> {
    let mut client = H3Client::connect(addr, key.as_bytes(), seed).await.ok()?;
    let (status, body) = client
        .post(
            "/name/resolve",
            name::Resolve {
                name: name.to_string(),
            }
            .encode(),
        )
        .await
        .ok()?;
    if status != 200 {
        return None;
    }
    let resolved = name::Resolved::decode(&body).ok()?;
    resolved.found.then_some(resolved.account)
}

fn dial_config(seed: &[u8; 32]) -> SquicConfig {
    SquicConfig {
        alpn_protocols: vec![relay::ALPN.to_vec()],
        keep_alive: Some(Duration::from_secs(15)),
        handshake_timeout: Some(Duration::from_secs(5)),
        client_key: Some(hex::encode(seed)),
        advertise_identity: true,
        enable_datagrams: true,
        ..Default::default()
    }
}

/// The exchange serving `domain`, from the live link if there already is one.
///
/// Discovery is a DNS round trip, and a link that is up means the peer has
/// already been found — so this runs at link setup rather than once per call.
/// The cached answer is dropped with the link, which is what keeps it from
/// going stale on its own.
async fn find_peer(server: &Arc<Server>, domain: &str) -> Result<(PubKey, SocketAddr), String> {
    {
        let inner = server.relay.inner.lock().unwrap();
        if let Some(key) = inner.domains.get(domain)
            && let Some(link) = inner.links.get(key)
        {
            return Ok((*key, link.addr));
        }
    }
    let (key, addr) = server.relay.find.find(domain).await?;
    server
        .relay
        .inner
        .lock()
        .unwrap()
        .domains
        .insert(domain.to_string(), key);
    Ok((key, addr))
}

/// Bring up a link to a peer exchange if one is not already open.
async fn ensure_link(server: &Arc<Server>, key: PubKey, addr: SocketAddr) -> Result<(), String> {
    if server.relay.inner.lock().unwrap().links.contains_key(&key) {
        return Ok(());
    }
    let conn = squic::dial(addr, key.as_bytes(), dial_config(&server.relay.seed))
        .await
        .map_err(|e| format!("relay dial {addr}: {e}"))?;
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("relay open_bi: {e}"))?;
    register_link(server, key, addr, conn, send, recv);
    Ok(())
}

/// Register a link's send/recv halves and spawn its pumps. The control stream
/// is full-duplex and shared for both directions of traffic on this link.
fn register_link(
    server: &Arc<Server>,
    peer: PubKey,
    addr: SocketAddr,
    conn: Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
) {
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let id = conn.stable_id();
    {
        let mut inner = server.relay.inner.lock().unwrap();
        inner.links.insert(
            peer,
            Link {
                id,
                conn: conn.clone(),
                addr,
                control: tx,
            },
        );
    }
    // Every way this link can end removes it, and each checks that the entry is
    // still this one. Hanging teardown off the writer alone left links that
    // could send and never receive.
    let server_w = Arc::clone(server);
    tokio::spawn(async move {
        writer(send, rx).await;
        forget_link(&server_w, peer, id);
    });
    let server_c = Arc::clone(server);
    tokio::spawn(async move {
        control_reader(&server_c, peer, recv).await;
        forget_link(&server_c, peer, id);
    });
    let server_d = Arc::clone(server);
    let conn_d = conn.clone();
    tokio::spawn(async move {
        datagram_reader(&server_d, conn_d).await;
        forget_link(&server_d, peer, id);
    });
    // And the connection itself, which is what notices an idle death that no
    // read or write is waiting on.
    let server_x = Arc::clone(server);
    tokio::spawn(async move {
        conn.closed().await;
        forget_link(&server_x, peer, id);
    });
}

async fn writer(mut send: quinn::SendStream, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if send.write_all(&frame).await.is_err() {
            return;
        }
    }
    let _ = send.finish();
}

async fn control_reader(server: &Server, peer: PubKey, mut recv: quinn::RecvStream) {
    loop {
        let mut len = [0u8; relay::LENGTH_PREFIX];
        if recv.read_exact(&mut len).await.is_err() {
            return;
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > relay::MAX_CONTROL {
            return;
        }
        let mut body = vec![0u8; n];
        if recv.read_exact(&mut body).await.is_err() {
            return;
        }
        match Control::decode(&body) {
            Ok(ctrl) => on_control(server, peer, ctrl),
            Err(_) => return, // a peer that cannot frame is not one to keep
        }
    }
}

async fn datagram_reader(server: &Server, conn: Connection) {
    while let Ok(bytes) = conn.read_datagram().await {
        if let Ok(data) = RelayData::decode(&bytes) {
            inject(server, data);
        }
    }
}

/// The accept side of a relay link: check the allowlist, take the control
/// stream the dialer opened, and pump it. Refuses a peer not on the list the
/// same way every peering route does — by closing without explanation.
pub async fn serve_relay(server: &Arc<Server>, conn: Connection, identity: Option<PubKey>) {
    let Some(who) = identity else {
        conn.close(0u32.into(), b"");
        return;
    };
    if !server.relay.allowed(&who) {
        conn.close(0u32.into(), b"");
        return;
    }
    let (send, recv) = match conn.accept_bi().await {
        Ok(s) => s,
        Err(_) => return,
    };
    // On this side the address is simply where the peer dialled from; nothing
    // is discovered, because nothing is being dialled.
    let addr = conn.remote_address();
    register_link(server, who, addr, conn, send, recv);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn relay() -> Relay {
        Relay::new([0u8; 32], vec![], None, Find::Fixed(HashMap::new()))
    }

    /// A bridge whose caller gave up mid-ring must not outlive its usefulness.
    ///
    /// This is the failure as it actually happened: `place_call` is keyed by
    /// `(caller, target)`, so an abandoned bridge answered every later call to
    /// that peer and the pair became permanently uncallable. A restart was the
    /// only way out.
    #[test]
    fn a_bridge_abandoned_mid_ring_does_not_block_the_next_call() {
        let r = relay();
        let bridge = [1u8; 16];
        let target = "bob@far.test".to_string();
        {
            let mut inner = r.inner.lock().unwrap();
            inner.bridges.insert(
                bridge,
                BridgeRec {
                    peer: key(9),
                    account: key(2),
                    caller: key(1),
                    caller_eph: [0u8; 32],
                    callee: None,
                    callee_eph: [0u8; 32],
                    session_id: 0,
                    local: key(1),
                    outcome: Outcome::Ringing,
                    created: 1_000,
                    index: Index::Caller {
                        caller: key(1),
                        target: target.clone(),
                    },
                },
            );
            inner.caller_index.insert((key(1), target.clone()), bridge);
        }

        // Still ringing, and still the answer to a re-poll.
        r.sweep(1_000 + RINGING_TTL_SECS);
        assert_eq!(r.bridge_count(), 1, "a ringing bridge is not swept early");

        r.sweep(1_000 + RINGING_TTL_SECS + 1);
        assert_eq!(r.bridge_count(), 0, "an abandoned ring must be swept");
        // And the index goes with it, or the next call to that peer still finds
        // a bridge that is no longer there.
        assert!(
            !r.inner
                .lock()
                .unwrap()
                .caller_index
                .contains_key(&(key(1), target)),
            "the index outlived the bridge"
        );
    }

    /// A call in progress is not a call to tidy away: it follows SIP-12's own
    /// session lifetime, which is far longer than a ring.
    #[test]
    fn a_connected_bridge_lives_as_long_as_a_session_may() {
        let r = relay();
        {
            let mut inner = r.inner.lock().unwrap();
            inner.bridges.insert(
                [2u8; 16],
                BridgeRec {
                    peer: key(9),
                    account: key(2),
                    caller: key(1),
                    caller_eph: [0u8; 32],
                    callee: Some(key(2)),
                    callee_eph: [0u8; 32],
                    session_id: BRIDGE_BIT | 1,
                    local: key(1),
                    outcome: Outcome::Established,
                    created: 1_000,
                    index: Index::Callee {
                        caller: key(1),
                        account: key(2),
                    },
                },
            );
        }
        r.sweep(1_000 + RINGING_TTL_SECS + 1);
        assert_eq!(r.bridge_count(), 1, "a live call is not an abandoned ring");
        r.sweep(1_000 + sqex_proto::session::TTL_SECS + 1);
        assert_eq!(r.bridge_count(), 0, "but it does not outlive a session");
    }
}
