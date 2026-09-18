//! The sqex HTTP/3 server: bind, serve, route, and execute admin commands.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use bytes::Buf;
use ed25519_dalek::SigningKey;
use serde_json::json;
use sqex_proto::Op;
use sqex_proto::exchange::{PeerEntry, Peers, Pong};
use sqex_proto::refusal::{Code, Refusal};
use sqnr_core::key::PubKey;
use sqnr_core::{Error, Result, SignedTransaction};
use squic::Config as SquicConfig;

use crate::admission::Admissions;
use crate::attest::{Attestations, LodgeError};
use crate::beacon::Beacons;
use crate::challenge::Challenges;
use crate::channel::{ChannelError, Channels};
use crate::config::{Config, NameMode, OriginConfig};
use crate::device::Registry;
use crate::events::Subscribers;
use crate::mailbox::Mailbox;
use crate::name::Names;
use crate::prekey::Prekeys;
use crate::profile::Profiles;
use crate::rendezvous::Rendezvous;
use crate::resolve::Endpoints;
use crate::room::Rooms;
use crate::session::Sessions;
use crate::state::{AuditEntry, State, WhitelistEntry, now_unix};
use sqex_proto::attest::{Attestation, Query as AttestQuery};
use sqex_proto::backup::Manifest as BackupManifest;
use sqex_proto::beacon::{Beat, BeatAck, Read};
use sqex_proto::blob_store::{
    Begin as BlobBegin, Begun, ByBlob, ByChannelBlob, ByUpload, Commit as BlobCommit, Committed,
    GetChunk, Limits, PutChunk as BlobPut, TYPE_ABORT as BL_ABORT, TYPE_ATTACH as BL_ATTACH,
    TYPE_DETACH as BL_DETACH, TYPE_HEAD as BL_HEAD,
};
use sqex_proto::channel::{
    Ack as ChannelAck, ByAccount as ChannelByAccount, ByChannel, ByChannelSigned, ByTarget,
    Create as ChannelCreate, CreateAt, Created, Cursor as ChannelCursor,
    Directory as ChannelDirectory, Fetch as ChannelFetch, Home, Invite as ChannelInvite, Invitee,
    List as ChannelList, Mine as ChannelMine, Post as ChannelPost, Retain as ChannelRetain,
    SignalOut, TYPE_CLOSE as CH_CLOSE, TYPE_CURSORS as CH_CURSORS, TYPE_DISMISS as CH_DISMISS,
    TYPE_EQUIVOCATION as CH_EQUIVOCATION, TYPE_HOME as CH_HOME, TYPE_INFO as CH_INFO,
    TYPE_JOIN as CH_JOIN, TYPE_LEAVE as CH_LEAVE, TYPE_MUTE as CH_MUTE, TYPE_REDACT as CH_REDACT,
    TYPE_REMOVE as CH_REMOVE, TYPE_REPLICATE as CH_REPLICATE, TYPE_REPORTS as CH_REPORTS,
    TYPE_STRANDED as CH_STRANDED, TYPE_UNMUTE as CH_UNMUTE, TYPE_UNREPLICATE as CH_UNREPLICATE,
};
use sqex_proto::channel_key::{Get as KeyGet, Put as KeyPut, TYPE_MISSING as CH_MISSING};
use sqex_proto::device::{
    AdmissionRequest, ListDevices, Register as DeviceRegister, Revoke as DeviceRevoke,
};
use sqex_proto::events::{Event as EventKind, MEMBER_JOINED, MEMBER_LEFT, MEMBER_REMOVED};
use sqex_proto::home::Moving;
use sqex_proto::locate::{Locate, Located};
use sqex_proto::mailbox::{
    ById, Fetched, Send as MailSend, SendAck, TYPE_DELETE, TYPE_FETCH, TYPE_STATUS,
};
use sqex_proto::message::{RING_RINGING, Signal};
use sqex_proto::name;
use sqex_proto::peer::{
    Carried, Changed, Forward as PeerForward, ForwardAction, Forwarded, Hello as PeerHello, Hi,
    Mine, PEER_VERSION, PeerInvited, PeerMoved, PeerWait, Pull as PeerPull, PullBlob,
    PullEnvelopes, PullMine, PullRecord, PullShape, PullStanding,
};
use sqex_proto::prekey::{Publish as PrekeyPublish, Take as PrekeyTake};
use sqex_proto::profile::{
    Block as ProfileBlock, ByAccount, Put as ProfilePut, TYPE_GET as PR_GET,
};
use sqex_proto::rendezvous::Introduce;
use sqex_proto::resolve::{
    Publish as ResolvePublish, Resolve as ResolveGet, Successor as ResolveSuccessor,
};
use sqex_proto::room::{Join as RoomJoin, Leave as RoomLeave, Left};
use sqex_proto::session::{
    BySession, CallAck, CallDecline, CallOpen, DatagramFrame, Open, SendFrame, TYPE_CLOSE,
    TYPE_RECV,
};
use sqex_proto::succession::{self, Claim, Handover, Policy, Proof};
use sqex_proto::wake::Register as WakeRegister;

/// The server's own version, reported in status. The protocol lives in
/// sqnr-core, but this string identifies the daemon.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ALPN for sqex: plain HTTP/3.
const ALPN: &[u8] = b"h3";

/// How often channels are pruned and abandoned ones reclaimed. Frequent enough
/// that a short retention window means what it says, rare enough to be
/// invisible.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Largest body for the blob upload route, and only that route.
///
/// SIP-18's chunk is 256 KiB against a uniform 64 KiB cap, and it says an
/// exchange adding the blob service raises the limit there and keeps it
/// everywhere else. Uniformity is worth something — one number bounding every
/// request is easy to reason about — so the exception is exactly one path.
const MAX_CHUNK_BODY: usize = sqex_proto::blob_store::CHUNK + 1024;

/// Content type of a SIP-30 event stream. Not JSON and not a document: a
/// sequence of length-prefixed frames with no end.
const EVENT_STREAM: &str = "application/vnd.sqex.events";

/// How often a quiet event stream says it is still there.
///
/// Under the transport's 60 s idle timeout, so a stream cannot be reaped for
/// having nothing to say, and beside SIP-16's 25 s `MAX_WAIT` for the same
/// reason that number was chosen. Its real job is at the client: silence and a
/// dead exchange are indistinguishable without it.
const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(20);

/// Largest admin-command body we will read.
const MAX_BODY: usize = 64 * 1024;

/// Said when the SIP-38 name route is disabled (`name_registration = "off"`).
const NAME_ROUTE_OFF: &str = "this exchange does not offer names";

/// SIP-63: how many `/peer/wait` requests one caller may hold open at
/// once. A replica holds one per origin and never meets it; a stranger
/// past it is refused uniformly, which SIP-61 reads as "does not wait".
const MAX_WAITS_PER_PEER: usize = 8;

/// SIP-63: one held wait, counted against its caller until dropped.
struct WaitHeld {
    server: Arc<Server>,
    who: PubKey,
}

impl Drop for WaitHeld {
    fn drop(&mut self) {
        let mut waits = self.server.waits.lock().unwrap();
        if let Some(n) = waits.get_mut(&self.who) {
            *n -= 1;
            if *n == 0 {
                waits.remove(&self.who);
            }
        }
    }
}

/// What the transport established about the caller on one connection.
///
/// Both facts come from the same MAC1-verified Initial: the X25519 key SIP-2
/// exposes, and the Ed25519 name SIP-3 lets a caller assert. A caller may have
/// neither (an anonymous, ephemeral connection), the key alone (a persistent
/// caller that did not advertise), or both.
#[derive(Clone, Copy)]
pub struct Peer {
    /// MAC1-verified X25519 transport key (SIP-2).
    pub key: Option<[u8; 32]>,
    /// MAC1-bound Ed25519 identity, if the caller advertised one (SIP-3).
    pub identity: Option<PubKey>,
    /// Where this connection actually came from.
    ///
    /// **Observed, never asserted.** SIP-25 introduces two identities by
    /// telling each the other's address, and the only address it may disclose
    /// is the one the exchange saw — a caller-supplied one would make the
    /// introduction route a way to point traffic at somebody who never asked
    /// for it. SIP-4 forbids publishing this as a *liveness* answer for a
    /// different reason, and nothing else here reads it.
    pub addr: std::net::SocketAddr,
}

/// Live connections by the identity that advertised itself on them (SIP-3).
///
/// Only datagram forwarding needs this: relaying a packet means writing it to
/// the *other* peer's connection, which the request path never has to do. An
/// identity may hold several connections at once; a datagram goes to all of
/// them, and the peer's session keys mean only the intended one can open it.
#[derive(Default)]
struct Connections {
    by_identity: Mutex<HashMap<PubKey, Vec<quinn::Connection>>>,
    /// Every connection with a verified transport key, whether or not it
    /// advertised an identity -- the whitelist is a set of transport keys,
    /// and closing what it no longer allows has to find the anonymous ones
    /// too.
    by_key: Mutex<Vec<([u8; 32], quinn::Connection)>>,
}

impl Connections {
    fn add_keyed(&self, key: [u8; 32], conn: quinn::Connection) {
        self.by_key.lock().unwrap().push((key, conn));
    }

    fn remove_keyed(&self, conn: &quinn::Connection) {
        self.by_key
            .lock()
            .unwrap()
            .retain(|(_, c)| c.stable_id() != conn.stable_id());
    }

    /// Every live connection whose transport key `allowed` refuses.
    fn not_allowed(&self, allowed: impl Fn(&[u8; 32]) -> bool) -> Vec<quinn::Connection> {
        self.by_key
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, conn)| conn.close_reason().is_none() && !allowed(key))
            .map(|(_, conn)| conn.clone())
            .collect()
    }

    fn add(&self, id: PubKey, conn: quinn::Connection) {
        self.by_identity
            .lock()
            .unwrap()
            .entry(id)
            .or_default()
            .push(conn);
    }

    /// Forget a connection, and the identity entirely once its last one goes.
    fn remove(&self, id: &PubKey, conn: &quinn::Connection) {
        let mut map = self.by_identity.lock().unwrap();
        if let Some(v) = map.get_mut(id) {
            v.retain(|c| c.stable_id() != conn.stable_id());
            if v.is_empty() {
                map.remove(id);
            }
        }
    }

    /// Every live connection for an identity. Closed ones are dropped as found,
    /// so a peer that has gone away stops being written to.
    fn get(&self, id: &PubKey) -> Vec<quinn::Connection> {
        let mut map = self.by_identity.lock().unwrap();
        let Some(v) = map.get_mut(id) else {
            return Vec::new();
        };
        v.retain(|c| c.close_reason().is_none());
        if v.is_empty() {
            map.remove(id);
            return Vec::new();
        }
        v.clone()
    }
}

/// Everything a request handler needs.
pub struct Server {
    pub public_key: PubKey,
    config_path: Option<PathBuf>,
    state: Mutex<State>,
    admins: RwLock<Vec<PubKey>>,
    challenges: Challenges,
    beacons: Beacons,
    /// SIP-25: who has asked to be introduced to whom. Nothing is disclosed
    /// until both sides have asked, independently.
    rendezvous: Rendezvous,
    /// SIP-27: what identities have said about each other. The exchange holds
    /// these and is not an authority over them — it checks that an issuer
    /// signed, and cannot check whether a claim is true.
    attestations: Attestations,
    /// SIP-28: where identities say they can be reached. Beside the beacon on
    /// purpose — this holds what they *said*, the beacon holds what the
    /// exchange *saw*, and a resolution carries both so a consumer can tell
    /// them apart.
    endpoints: Endpoints,
    mailbox: Mailbox,
    pub(crate) rooms: Rooms,
    channels: Channels,
    prekeys: Prekeys,
    pub(crate) devices: Registry,
    /// SIP-38: the per-domain name directory. Durable, unlike the SIP-28
    /// endpoint store beside it — a name is the identity a person keeps, not an
    /// address that is only interesting while fresh.
    names: Names,
    /// SIP-38 registration policy: whether names may be self-claimed, only
    /// administrator-assigned, or the route is off entirely.
    name_registration: NameMode,
    /// SIP-38: how many names one account may self-claim (open mode).
    max_names_per_account: usize,
    profiles: Profiles,
    admissions: Admissions,
    pub(crate) sessions: Sessions,
    live_conns: Connections,
    /// SIP-39: cross-exchange call relay — the peer allowlist, the bridge
    /// ceiling, and the live links and bridges.
    pub(crate) relay: crate::relay::Relay,
    /// SIP-30 event streams, by the identity that opened them.
    pub events: Subscribers,
    started: Instant,
    connections: AtomicU64,
    /// Requests served since boot.
    ///
    /// Counted because nothing else could say how much this exchange is being
    /// asked, and "how much" is the whole argument for SIP-30: a polling client
    /// costs requests proportional to how long it has been running, and an
    /// event-driven one costs them proportional to what has happened. Without a
    /// number, the difference between those is a claim.
    requests: AtomicU64,
    /// The channel every account is put into the first time it is seen.
    ///
    /// Resolved once at boot rather than looked up per request: it is a name
    /// in a config file and an identifier everywhere else, and doing that
    /// translation on the request path would be a query per request for an
    /// answer that never changes.
    welcome: Option<[u8; 32]>,
    /// The transport, kept so something other than the accept loop can read
    /// it. `/status` is that something: sQUIC counts what arrives on each
    /// envelope version, and until this field existed nothing outside the
    /// accept loop could ask for the number.
    transport: Arc<squic::ServerListener>,
    /// The envelope versions this exchange accepts (SIP-29), as resolved at
    /// bind — either sQUIC's default or the config's override. Reported next
    /// to what is actually arriving, because each is only readable against the
    /// other: a version with no traffic is safe to retire, and traffic on a
    /// version already refused is an outage nobody can see, since a refused
    /// envelope is dropped in silence at both ends.
    accepted_envelope_versions: Vec<u8>,
    /// SIP-35: the exchanges this one will serve replication to.
    ///
    /// The operational half of the gate. Being here lets a peer speak the
    /// peering routes; it gives it no channel, which takes a signed
    /// authorisation from one of that channel's admins.
    replication_peers: Vec<crate::config::ReplicationPeer>,
    /// SIP-63: the peering routes are served to any identified caller. A
    /// caller not on the list above is then a peer with no standing grant;
    /// what it may pull is what a member's signed statement entitles it to.
    open_peering: bool,
    /// SIP-63: how many `/peer/wait` requests each caller holds open now.
    waits: Mutex<HashMap<PubKey, usize>>,
    /// SIP-64: the handovers this exchange signed, oldest first, served
    /// to anyone who asks; re-read when the file changes, so a rotation
    /// done before 0.81.0 can be added without a restart. With the file's
    /// modification time as last read.
    lineage: RwLock<(sqex_proto::lineage::Lineage, Option<std::time::SystemTime>)>,
    lineage_file: PathBuf,
    /// SIP-65: calls are carried for an exchange nobody listed.
    open_calls: bool,
    /// SIP-65: the `(caller, eph)` pairs rung on lately, so a word is
    /// honoured once within `CALL_WORD_SECS`. Value: when it was seen.
    call_words: Mutex<HashMap<(PubKey, [u8; 32]), u64>>,
    /// SIP-64: when each origin's lineage was last asked for, so a
    /// repudiated entry at a pre-SIP-64 origin does not ask every pull.
    lineage_asked: Mutex<HashMap<PubKey, std::time::Instant>>,
    lineage_retry: std::time::Duration,
    /// SIP-35: the origins this one replicates *from*, and the seed it dials
    /// them with — its own SIP-9 identity, because a peering connection is an
    /// ordinary SIP-3 one and an exchange's identity is that key.
    replicate: Vec<OriginConfig>,
    exchange_seed: [u8; 32],
    /// SIP-45: wakes for devices that cannot hold a stream, posted off the
    /// request path. Set once the `Arc` exists, since the task holds it.
    waker: std::sync::OnceLock<crate::wake::Waker>,
    /// SIP-47: when the earliest device credential the whitelist admits
    /// runs out -- the one moment the door changes with nobody at it.
    admission_expiry: Mutex<Option<u64>>,
    /// SIP-53: when each origin was last reached, so a replica can say how
    /// long one has been away. An origin never reached counts from start.
    contacts: Mutex<HashMap<PubKey, u64>>,
    /// SIP-59: poked when an account moves here, so the home task pulls
    /// its channels at once rather than at its next interval.
    pub(crate) homed: tokio::sync::Notify,
    /// SIP-53: how long an origin must be out of reach before a replica
    /// takes a rehome to itself.
    pub(crate) rehome_away_secs: u64,
    /// SIP-56: the rate limits, per account.
    pub(crate) limiter: crate::limits::Limiter,
    /// SIP-55: the peers' public directories as last read.
    pub(crate) directories: crate::directory::Directories,
    /// SIP-55: how often they are read.
    pub(crate) directory_secs: u64,
    /// SIP-59: seconds between pulls for the accounts homed here.
    pub(crate) home_secs: u64,
    /// SIP-60: this exchange's own domain, if the operator said.
    domain: Option<String>,
    /// SIP-45: whether `http://` to loopback is an acceptable endpoint --
    /// for the tests, which stand a listener up there.
    wake_loopback: bool,
    /// SIP-43: the way to each origin for a member's post, by origin key.
    /// SIP-43: one forwarder per origin this exchange replicates from --
    /// the configured ones, and (SIP-53) any an origin moved to, added as
    /// they are learned.
    origins: RwLock<HashMap<PubKey, Arc<crate::replica::Forwarder>>>,
    /// SIP-43: uploads this replica is carrying to an origin, by the number
    /// it gave the client: the origin, the origin's number, and whose it is.
    carried_uploads: Mutex<HashMap<u64, (PubKey, u64, PubKey)>>,
    next_carried: AtomicU64,
}

impl Server {
    /// The channel store, for the replication tasks `serve` spawns — and for
    /// tests, which is why this crate is a library at all.
    pub fn channels(&self) -> &Channels {
        &self.channels
    }

    /// The profile store, for the same reason.
    pub fn profiles(&self) -> &Profiles {
        &self.profiles
    }

    /// The prekey pool. Exposed so a test can assert that replication does not
    /// fill it, which is SIP-35's sharpest refusal and is invisible otherwise.
    pub fn prekeys(&self) -> &Prekeys {
        &self.prekeys
    }

    fn is_admin(&self, key: &PubKey) -> bool {
        self.admins.read().unwrap().iter().any(|a| a == key)
    }

    /// **The managed whitelist, applied to the transport.** With the list
    /// enabled, sQUIC drops a handshake from any key not on it before the
    /// DH -- the silent server -- so a peer that is not listed never gets a
    /// connection, let alone a refusal; and a peer already connected when
    /// it is removed is closed here, since the transport only decides at the
    /// door. Disabled, the transport accepts anyone holding the server key,
    /// as before.
    ///
    /// Three sets are allowed through, not one: the list, the administrators
    /// (or enabling the list would lock out the only keys that can disable
    /// it), and the SIP-35 peering exchanges (which have an allowlist of
    /// their own and do not belong on this one). All three are Ed25519 keys
    /// forward-derived to the X25519 the transport verifies.
    ///
    /// What this costs, and is chosen: an administrator whose key lives on a
    /// YubiKey has no X25519 to derive and cannot connect while the list is
    /// on; and SIP-24's admission request, which exists so an unlisted
    /// device can ask, cannot arrive from one -- the device's key has to be
    /// added by an administrator who was told it some other way. The
    /// per-request gate in `route` stays as well: it is what refuses a
    /// connection that was admitted and then removed, in the moment before
    /// this closes it.
    /// Whether a connection with this transport key is admitted while the
    /// list is on: the same set the transport was given -- the list, the
    /// administrators, the peering exchanges -- read back from it, so the
    /// route gate and the door cannot disagree. Everyone, when it is off.
    fn admitted(&self, key: Option<[u8; 32]>) -> bool {
        if !self.state.lock().unwrap().enabled() {
            return true;
        }
        key.is_some_and(|k| self.transport.has_key(&k))
    }

    fn sync_transport(&self, state: &State) {
        if !state.enabled() {
            self.transport.disable_whitelist();
            return;
        }
        let derive = |k: &PubKey| {
            squic::crypto::ed25519_public_to_x25519(k.as_bytes())
                .ok()
                .map(|x| x.to_bytes())
        };
        let mut allowed: Vec<[u8; 32]> = state.transport_keys();
        allowed.extend(self.admins.read().unwrap().iter().filter_map(derive));
        allowed.extend(self.replication_peers.iter().filter_map(|p| derive(&p.key)));
        // SIP-47: a registered device of an admitted account is admitted for
        // as long as the registration stands. Admitted *because of* the
        // account, not listed beside it -- `whitelist list` does not show
        // it, and removing the account removes its devices with it.
        let (devices, expiry) = self.devices.registered_to(&state.keys());
        allowed.extend(devices.iter().filter_map(derive));
        // SIP-63: so is the recorded home of an admitted account, for as
        // long as its Move names one -- the same shape, the person's own
        // signature naming a key that acts for them.
        allowed.extend(
            self.devices
                .homes_of(&state.keys(), &self.public_key)
                .iter()
                .filter_map(derive),
        );
        *self.admission_expiry.lock().unwrap() = expiry;
        self.transport.enable_whitelist(&allowed);
        // Whoever is connected and no longer allowed goes -- a moment from
        // now, not this instant: the op that enabled the list may have come
        // over one of these connections (an administrator signing over an
        // anonymous one), and its answer has not been written yet. The
        // route gate refuses anything they ask in the meantime.
        let allowed: std::collections::HashSet<[u8; 32]> = allowed.into_iter().collect();
        let going = self.live_conns.not_allowed(|key| allowed.contains(key));
        let gone = going.len();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            for conn in going {
                conn.close(0u32.into(), b"not whitelisted");
            }
        });
        tracing::info!(
            listed = state.keys().len(),
            allowed = allowed.len(),
            closed = gone,
            "transport whitelist enabled"
        );
    }

    /// SIP-43/53: the forwarder toward `origin`, configured or learned.
    pub(crate) fn forwarder(&self, origin: &PubKey) -> Option<Arc<crate::replica::Forwarder>> {
        self.origins.read().unwrap().get(origin).cloned()
    }

    /// SIP-53: a forwarder toward an origin learned from a rehome.
    pub(crate) fn add_forwarder(&self, origin: PubKey, addr: std::net::SocketAddr, domain: String) {
        self.origins
            .write()
            .unwrap()
            .entry(origin)
            .or_insert_with(|| Arc::new(crate::replica::Forwarder::new(origin, addr, domain)));
    }

    /// SIP-66: drop the way to `origin`, so the next reach resolves anew.
    pub(crate) fn forget_forwarder(&self, origin: &PubKey) {
        self.origins.write().unwrap().remove(origin);
    }

    /// SIP-56: take a token or say how long to wait, as a refusal.
    pub(crate) fn limit(
        &self,
        kind: crate::limits::Kind,
        who: &PubKey,
        scope: [u8; 32],
    ) -> std::result::Result<(), ChannelError> {
        self.limiter
            .take(kind, who, scope)
            .map_err(ChannelError::RateLimited)
    }

    /// SIP-63: one write a peer caused -- a hint, a Move, a rehome notice,
    /// a carried registration -- against the caller's own bucket. The one
    /// reply on a peering route that is not the uniform refusal: it is
    /// about the caller and says nothing of any channel or account.
    pub(crate) fn peer_write(&self, who: &PubKey) -> std::result::Result<(), ChannelError> {
        self.limit(crate::limits::Kind::Peering, who, [0; 32])
    }

    /// SIP-54: a signal pulled from the origin's log, handed to this
    /// exchange's members as if its sender had sent it here. Skipped when
    /// the sender's device is connected here: it did send it here, and
    /// was delivered at the time.
    pub(crate) fn deliver_pulled_signal(&self, channel: &[u8; 32], l: &sqex_proto::peer::Logged) {
        if !self.live_conns.get(&l.device).is_empty() {
            return;
        }
        if self
            .channels
            .signal(&l.account, &l.device, channel, l.kind, &l.body)
            .is_err()
        {
            return;
        }
        self.tell_others(channel, &l.account, EventKind::Signal { channel: *channel });
        if let Ok(Some(Signal::CallState { target, state, .. })) = Signal::decode(&l.body)
            && state == RING_RINGING
        {
            self.tell_others(
                channel,
                &l.account,
                EventKind::Ringing {
                    channel: *channel,
                    seq: target,
                },
            );
        }
    }

    /// SIP-54: marks pulled from the origin, merged; the members are told
    /// where anything moved.
    pub(crate) fn merge_pulled_cursors(
        &self,
        channel: &[u8; 32],
        marks: &sqex_proto::channel::Marks,
    ) {
        if self.channels.merge_cursors(channel, marks).unwrap_or(false) {
            self.tell(channel, EventKind::Cursor { channel: *channel });
        }
    }

    /// SIP-53: where a domain's exchange is, by the relay's finder.
    pub(crate) async fn relay_find(
        self: &Arc<Self>,
        domain: &str,
    ) -> std::result::Result<(PubKey, std::net::SocketAddr), String> {
        crate::relay::find_by_domain(self, domain).await
    }

    /// SIP-60: where another exchange is reached -- the forwarder toward it
    /// if there is one, otherwise by the domain this exchange has for it
    /// (a Move or a learned home naming it, or the peer directory),
    /// discovered and checked against the key. Brings up a forwarder for
    /// it, since whatever comes next goes through one.
    pub(crate) async fn reach(
        self: &Arc<Self>,
        key: &PubKey,
    ) -> Option<(std::net::SocketAddr, String)> {
        self.reach_by(key, "").await
    }

    /// [`Self::reach`] with a domain hint tried first -- the one an
    /// account's Move or an origin's telling came with.
    pub(crate) async fn reach_by(
        self: &Arc<Self>,
        key: &PubKey,
        hint: &str,
    ) -> Option<(std::net::SocketAddr, String)> {
        if let Some(f) = self.forwarder(key) {
            return Some((f.addr, f.domain.clone()));
        }
        let hint = hint.trim().to_ascii_lowercase();
        let domain = (!hint.is_empty())
            .then_some(hint)
            .or_else(|| self.devices.domain_of_exchange(key))
            .or_else(|| {
                self.peer_directory()
                    .peers
                    .into_iter()
                    .find(|p| p.key == *key)
                    .map(|p| p.domain)
                    .filter(|d| !d.is_empty())
            })?;
        let (found, moved_from, addr) = crate::relay::find_peer_moved(self, &domain).await.ok()?;
        if found != *key {
            // SIP-66: the domain names another key. Its successor, on the
            // retiring key's own word -- a handover the pin followed, or the
            // successor's lineage naming the key held -- and never on the
            // zone's word alone.
            let succeeded =
                moved_from == Some(*key) || self.lineage_names(&found, addr, &domain, key).await;
            if !succeeded {
                tracing::warn!(%domain, expected = %key, found = %found, "a domain names another key");
                return None;
            }
            // A configured origin is the operator's: SIP-40's `predecessors`
            // in `[[replicate]]` is how they say a rotation happened.
            if self.replicate.iter().any(|o| o.origin == *key) {
                tracing::warn!(
                    %domain, from = %key, to = %found,
                    "a configured origin rotated; update [[replicate]] (SIP-40 predecessors)"
                );
                return None;
            }
            self.follow_exchange(key, &found, addr, &domain).await;
            return Some((addr, domain));
        }
        self.add_forwarder(*key, addr, domain.clone());
        Some((addr, domain))
    }

    /// SIP-66: whether `successor`, reached at `addr` for `domain`, serves a
    /// lineage that verifies for it and names `held` among its earlier keys.
    async fn lineage_names(
        &self,
        successor: &PubKey,
        addr: std::net::SocketAddr,
        domain: &str,
        held: &PubKey,
    ) -> bool {
        let Ok(mut client) =
            sqex_proto::h3::H3Client::connect(addr, successor.as_bytes(), &self.exchange_seed)
                .await
        else {
            return false;
        };
        let Ok((200, body)) = client.post("/exchange/lineage", Vec::new()).await else {
            return false;
        };
        let Ok(lineage) = sqex_proto::lineage::Lineage::decode(&body) else {
            return false;
        };
        match lineage.predecessors_for(successor, Some(domain)) {
            Ok(earlier) => earlier.contains(held),
            Err(e) => {
                tracing::warn!(%domain, key = %successor, %e, "a successor's lineage was refused");
                false
            }
        }
    }

    /// SIP-66: re-key every holding of `from` to `to` -- the registry's
    /// homes and hints, the channel store's copies and lineage, the way
    /// there -- and learn `to`'s lineage, so what `from` receipted goes on
    /// verifying. Logged once: the one time an operator sees it happen.
    pub(crate) async fn follow_exchange(
        self: &Arc<Self>,
        from: &PubKey,
        to: &PubKey,
        addr: std::net::SocketAddr,
        domain: &str,
    ) {
        let registry = self.devices.follow_exchange(from, to);
        let copies = self.channels.follow_origin(from, to);
        self.origins.write().unwrap().remove(from);
        self.add_forwarder(*to, addr, domain.to_string());
        tracing::info!(
            %domain, from = %from, to = %to, registry, copies,
            "an exchange rotated its key; every holding of it followed (SIP-66)"
        );
        // Asked now rather than on the next pull, since the copies' past
        // is under the old key and the next pull is what verifies it.
        if let Ok(mut client) =
            sqex_proto::h3::H3Client::connect(addr, to.as_bytes(), &self.exchange_seed).await
            && let Ok((200, body)) = client.post("/exchange/lineage", Vec::new()).await
            && let Ok(lineage) = sqex_proto::lineage::Lineage::decode(&body)
            && let Ok(earlier) = lineage.predecessors_for(to, Some(domain))
        {
            self.channels.learn_lineage(to, &earlier);
            self.lineage_due(to, false);
        }
    }

    /// SIP-60: after writing a membership for `account`, tell its home --
    /// where that is another exchange -- off the request path. Best
    /// effort: a home that cannot be reached was not told, and the member
    /// finds the channel the way they always could.
    pub(crate) fn tell_home(self: &Arc<Self>, account: PubKey, channel: [u8; 32]) {
        let Some((home, _)) = self.devices.where_is(&account, &self.public_key) else {
            return;
        };
        let server = Arc::clone(self);
        tokio::spawn(async move {
            let Some((addr, _)) = server.reach(&home).await else {
                tracing::debug!(%account, %home, "cannot reach a member's home to tell it");
                return;
            };
            let mine = server.own_domain();
            let Ok(mut client) =
                sqex_proto::h3::H3Client::connect(addr, home.as_bytes(), &server.exchange_seed)
                    .await
            else {
                return;
            };
            let req = sqex_proto::peer::PeerInvited {
                account,
                channel,
                domain: mine,
            };
            match client.post("/peer/invited", req.encode()).await {
                Ok((200, _)) => tracing::info!(%account, %home, "told a member's home"),
                Ok((code, _)) => {
                    tracing::debug!(%account, %home, code, "a home did not take the telling")
                }
                Err(e) => tracing::debug!(%account, %home, error = %e, "telling a home failed"),
            }
        });
    }

    /// SIP-60: this exchange's own domain, as far as it knows one -- what
    /// it tells a home to find it by. The peer directory never lists this
    /// exchange, so it comes from the SIP-33 record the operator configured
    /// in `domain`, or is empty.
    pub(crate) fn own_domain(&self) -> String {
        self.domain.clone().unwrap_or_default()
    }

    /// SIP-53: note that `origin` answered just now.
    pub(crate) fn reached(&self, origin: &PubKey) {
        self.contacts.lock().unwrap().insert(*origin, now_unix());
    }

    /// SIP-53: how long `origin` has been out of reach -- since it last
    /// answered, or since this exchange started where it never has.
    pub(crate) fn away_secs(&self, origin: &PubKey) -> u64 {
        let since = self
            .contacts
            .lock()
            .unwrap()
            .get(origin)
            .copied()
            .unwrap_or(0);
        if since == 0 {
            self.started.elapsed().as_secs()
        } else {
            now_unix().saturating_sub(since)
        }
    }

    /// SIP-47: a device was registered or revoked, or a credential the
    /// door was relying on has run out. Re-derive the whitelist if it is
    /// on; nothing to do if it is not.
    fn resync_transport(&self) {
        let state = self.state.lock().unwrap();
        if state.enabled() {
            self.sync_transport(&state);
        }
    }

    /// Whether the soonest device-credential expiry the whitelist rests on
    /// has passed, so the door must be re-derived without anybody asking.
    fn admission_due(&self) -> bool {
        self.admission_expiry
            .lock()
            .unwrap()
            .is_some_and(|t| t < now_unix())
    }

    /// SIP-39: whether this exchange federates with `key`.
    ///
    /// Read from the managed state on every check rather than from a snapshot,
    /// so `sqex admin peer add` takes effect on the next call rather than the
    /// next restart. Neither caller holds the state lock, and this takes it for
    /// the length of a map lookup.
    /// Whether `who` may speak the SIP-35 peering routes at all.
    ///
    /// The operational half of the gate, and only that half — what a peer may
    /// then *pull* is [`Self::may_pull`]. SIP-63: an exchange that peers
    /// openly answers anyone, as a peer that holds no grant of its own --
    /// the entitlement functions see an empty `for` list and decide from
    /// the log and the home records alone.
    fn peering(&self, who: &PubKey) -> Option<crate::config::ReplicationPeer> {
        self.replication_peers
            .iter()
            .find(|p| p.key == *who)
            .cloned()
            .or_else(|| {
                self.open_peering.then(|| crate::config::ReplicationPeer {
                    key: *who,
                    acts_for: Vec::new(),
                })
            })
    }

    /// SIP-63: whether `key`, found for a domain, may be asked on a
    /// client's behalf -- a listed peer, or anyone when peering openly.
    /// Calls are not asked here; they keep SIP-39's list.
    pub(crate) fn may_ask(&self, key: &PubKey) -> bool {
        self.open_peering || self.peers_with(key)
    }

    /// SIP-64: this exchange's lineage, re-read when the file changed. A
    /// file that has gone wrong since start is logged and the last good
    /// lineage kept: a peer is never served a chain that fails its own
    /// check, and the operator sees why.
    pub(crate) fn lineage_now(&self) -> sqex_proto::lineage::Lineage {
        let now = crate::lineage::modified(&self.lineage_file);
        {
            let held = self.lineage.read().unwrap();
            if held.1 == now {
                return held.0.clone();
            }
        }
        let mut held = self.lineage.write().unwrap();
        if held.1 != now {
            match crate::lineage::load(&self.lineage_file, &self.public_key) {
                Ok(l) => {
                    tracing::info!(links = l.links.len(), "lineage file re-read");
                    *held = (l, now);
                }
                Err(e) => {
                    tracing::error!(%e, "lineage file changed and is refused; serving the last good one");
                    held.1 = now;
                }
            }
        }
        held.0.clone()
    }

    /// SIP-65: a name as this exchange resolves it, for the callee check.
    pub(crate) fn resolve_name(&self, label: &str) -> sqex_proto::name::Resolved {
        self.names.resolve(label)
    }

    /// SIP-65: whether calls are carried for an exchange nobody listed.
    pub(crate) fn open_calls(&self) -> bool {
        self.open_calls
    }

    /// SIP-65: whether `key` may be dialled or accepted on the link -- a
    /// listed relay peer, or anyone when calls are open. What such a link
    /// may then carry is decided per invite.
    pub(crate) fn may_link(&self, key: &PubKey) -> bool {
        self.open_calls || self.peers_with(key)
    }

    /// SIP-65: honour a caller's word once. `true` the first time this
    /// `(caller, eph)` is seen within `CALL_WORD_SECS`; the cache is swept
    /// as it is consulted.
    pub(crate) fn first_word(&self, caller: &PubKey, eph: &[u8; 32], now: u64) -> bool {
        let mut seen = self.call_words.lock().unwrap();
        seen.retain(|_, at| now.saturating_sub(*at) < sqex_proto::session::CALL_WORD_SECS);
        if seen.contains_key(&(*caller, *eph)) {
            return false;
        }
        seen.insert((*caller, *eph), now);
        true
    }

    /// SIP-65: the account behind a caller's word -- the device itself, or
    /// the account its credential names, verified. `None` when the
    /// credential does not hold.
    pub(crate) fn account_behind(
        &self,
        caller: &PubKey,
        word: &sqex_proto::session::CallWord,
        now: u64,
    ) -> Option<PubKey> {
        match &word.credential {
            None => Some(*caller),
            Some(c) => {
                if c.delegate != *caller
                    || c.verify(&c.account, sqex_proto::credential::SCOPE_CHAT, now)
                        .is_err()
                {
                    return None;
                }
                Some(c.account)
            }
        }
    }

    /// SIP-64: whether to ask `origin` for its lineage now -- never asked
    /// this process, or (`again`) a repudiated entry and the last ask is
    /// `lineage_retry` behind us. Marks the ask.
    pub(crate) fn lineage_due(&self, origin: &PubKey, again: bool) -> bool {
        let mut asked = self.lineage_asked.lock().unwrap();
        let due = match asked.get(origin) {
            None => true,
            Some(at) => again && at.elapsed() >= self.lineage_retry,
        };
        if due {
            asked.insert(*origin, std::time::Instant::now());
        }
        due
    }

    /// SIP-63: hold one more wait for `who`, or say the caller is over
    /// `MAX_WAITS_PER_PEER`. The guard lets go when dropped.
    fn hold_wait(self: &Arc<Self>, who: PubKey) -> Option<WaitHeld> {
        let mut waits = self.waits.lock().unwrap();
        let n = waits.entry(who).or_insert(0);
        if *n >= MAX_WAITS_PER_PEER {
            return None;
        }
        *n += 1;
        Some(WaitHeld {
            server: Arc::clone(self),
            who,
        })
    }

    /// Whether an admitted peer may pull this channel.
    ///
    /// Two ways to be entitled, and they are different kinds of consent:
    ///
    /// - A **full replica** carries a channel only where one of its admins has
    ///   signed a `0x0b` into the log. It serves other people's clients, so a
    ///   second operator ends up holding the membership graph — SIP-35 puts
    ///   that decision with the members rather than with either operator.
    /// - A peer that **acts for accounts** — a read replica, or somebody's own
    ///   exchange syncing their own conversations — carries a channel where one
    ///   of those accounts is a present member. No per-channel signature,
    ///   because those accounts can already fetch every one of those entries as
    ///   clients; the entries arriving on their own box is the same disclosure
    ///   in a different place.
    ///
    /// **What this does not establish is that the peer really is theirs.** That
    /// is the origin operator's assertion, made in its config, and a private
    /// group's other members did not agree to it. The stronger form is an
    /// authorisation signed by the account itself, which SIP-35 now names as
    /// the upgrade for a deployment that will not trust its operator this far.
    ///
    /// SIP-59 adds the third kind, and the strongest: the peer is the
    /// **recorded home** of a present member, by that member's own signed
    /// Move. The three are a union, not modes of a peer -- a full replica
    /// that is also somebody's home carries both.
    fn may_pull(&self, peer: &crate::config::ReplicationPeer, channel: &[u8; 32]) -> bool {
        self.channels.replicates_to(channel, &peer.key)
            || peer
                .acts_for
                .iter()
                .any(|a| self.channels.is_member(channel, a))
            || self
                .devices
                .homed_at(&peer.key)
                .iter()
                .any(|a| self.channels.is_member(channel, a))
    }

    /// SIP-43: whether a peer may carry `account`'s post into `channel`. A
    /// full replica may for a channel authorised to it; a peer acting for
    /// accounts may for one of them; SIP-59: so may the account's home.
    fn may_forward(
        &self,
        peer: &crate::config::ReplicationPeer,
        channel: &[u8; 32],
        account: &PubKey,
    ) -> bool {
        self.channels.replicates_to(channel, &peer.key)
            || peer.acts_for.contains(account)
            || self.acts_for(peer, account)
    }

    /// SIP-59: whether `peer` may act for `account` at all -- configured to,
    /// or the account's recorded home.
    fn acts_for(&self, peer: &crate::config::ReplicationPeer, account: &PubKey) -> bool {
        peer.acts_for.contains(account)
            || self
                .devices
                .home_of(account)
                .is_some_and(|(home, _, _)| home == peer.key)
    }

    /// SIP-59: the refusal a former home gives on a service that was the
    /// key's, naming where the account lives now. `None` while the account
    /// is here or unknown.
    pub(crate) fn moved_away(&self, account: &PubKey) -> Option<(u16, &'static str, Vec<u8>)> {
        let (home, domain) = self.devices.away(account, &self.public_key)?;
        Some(refuse(403, Code::Moved, Some(&format!("{home} {domain}"))))
    }

    pub(crate) fn peers_with(&self, key: &PubKey) -> bool {
        self.state.lock().unwrap().peers_with(key)
    }

    /// SIP-46: the peer list as a directory. Never this exchange itself,
    /// and a label only where it is a domain.
    pub(crate) fn peer_directory(&self) -> Peers {
        let me = self.public_key;
        let peers = self
            .state
            .lock()
            .unwrap()
            .peer_list()
            .into_iter()
            .filter(|(k, _)| *k != me)
            .map(|(key, entry)| PeerEntry {
                key,
                domain: entry
                    .label
                    .map(|l| l.trim().to_lowercase())
                    .filter(|l| sqex_proto::exchange::is_domain(l))
                    .unwrap_or_default(),
            })
            .collect();
        Peers { peers }
    }

    /// SIP-40 §Consumers other than pins: the relay-peer entry for `from`,
    /// if there is one, is replaced by one for `to`. A relay-peer key is a key
    /// held for a domain, found by discovering that domain, so when the pin
    /// follows a handover the entry SHOULD follow with it. Returns whether
    /// anything changed; the caller logs it. Provenance: `added_by` is the
    /// outgoing key, because that is who authorised this — no administrator
    /// signed a transaction, the retiring exchange signed a handover — and an
    /// empty `added_by` would read as "seeded from config", which is a
    /// different fact (a seed is re-applied on restart; this is persisted).
    pub(crate) fn follow_peer_handover(&self, domain: &str, from: &PubKey, to: PubKey) -> bool {
        let mut state = self.state.lock().unwrap();
        if !state.peers_with(from) {
            return false;
        }
        state.remove_peer(from);
        state.add_peer(
            to,
            crate::state::WhitelistEntry {
                added_by: Some(from.to_string()),
                label: Some(format!("{domain}, SIP-40 handover")),
                added_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
        );
        if let Err(e) = state.save() {
            tracing::warn!(
                domain,
                "peer list followed a handover but could not be saved: {e}"
            );
        }
        true
    }

    /// Whether this exchange federates with anybody at all.
    pub(crate) fn peering_enabled(&self) -> bool {
        self.state.lock().unwrap().peering_enabled()
    }

    /// Requests served since boot, event streams included — one per stream
    /// opened, not one per frame written, which is the distinction that makes
    /// this number mean anything.
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Tell everybody present in a channel that it changed (SIP-30).
    ///
    /// The member list is read here, at the route layer, and that placement is
    /// load-bearing rather than tidy. `Channels::wake` — the long poll's
    /// notifier — looks like the obvious home for this, but it is called at
    /// seven sites with the caller's `Mutex<Connection>` guard still in scope,
    /// and reading a member list takes that same non-reentrant lock. Publishing
    /// from inside `wake` would deadlock the daemon. Nothing here holds the
    /// database, and `Channels` stays unaware that subscriptions exist.
    pub(crate) fn tell(&self, channel: &[u8; 32], event: EventKind) {
        let to = self.channels.members_of(channel);
        self.events.publish(&to, event);
        self.wake(&to, &event);
        // SIP-61: and the peers waiting on this channel, for everything a
        // pull would carry -- an entry woke them already; a signal, a
        // read mark or a redaction only gets here.
        self.channels.wake(channel);
    }

    /// SIP-45: the same people, to their devices that are not listening.
    fn wake(&self, to: &[PubKey], event: &EventKind) {
        if let Some(w) = self.waker.get() {
            w.tell(to, event);
        }
    }

    /// The same, less one account — for a change that account made itself and
    /// already knows about.
    fn tell_others(&self, channel: &[u8; 32], not: &PubKey, event: EventKind) {
        let to: Vec<PubKey> = self
            .channels
            .members_of(channel)
            .into_iter()
            .filter(|m| m != not)
            .collect();
        self.events.publish(&to, event);
        self.wake(&to, &event);
        self.channels.wake(channel);
    }

    /// The same, plus one account who may no longer be present — somebody
    /// removed needs to hear about it more than anybody left behind does.
    fn tell_including(&self, channel: &[u8; 32], also: &PubKey, event: EventKind) {
        let mut to = self.channels.members_of(channel);
        if !to.contains(also) {
            to.push(*also);
        }
        self.events.publish(&to, event);
        self.wake(&to, &event);
        self.channels.wake(channel);
    }

    // --- SIP-39: effects the relay module drives, kept here so it needs no
    // access to the server's private innards. ---

    /// The account a device belongs to (SIP-22); a device that belongs to no
    /// account is its own account.
    pub(crate) fn account_of(&self, device: &PubKey) -> PubKey {
        self.devices.account_for(device)
    }

    /// Ring every device of `account` for an incoming cross-exchange call
    /// (SIP-30, per device, as SIP-36 rings within a channel).
    pub(crate) fn ring_crosscall(&self, account: PubKey, bridge: [u8; 16], caller: PubKey) {
        self.events
            .publish(&[account], EventKind::CrossCall { bridge, caller });
    }

    /// How many of an account's devices could hear a ring — its open SIP-30
    /// streams. Zero means a cross-exchange invite has nobody to reach, which
    /// is worth answering rather than ringing into the void.
    pub(crate) fn reachable(&self, account: &PubKey) -> usize {
        self.events.count(account)
    }

    /// Send one already-framed session datagram to every connection a local
    /// identity holds — the bridged-session end of what `forward_datagrams`
    /// does for a local session.
    pub(crate) fn deliver_local_datagram(&self, to: &PubKey, bytes: bytes::Bytes) {
        for conn in self.live_conns.get(to) {
            let _ = conn.send_datagram(bytes.clone());
        }
    }
}

/// A bound-but-not-yet-serving server, so a caller can read the assigned
/// address and public key before the accept loop starts.
pub struct Bound {
    pub listener: Arc<squic::ServerListener>,
    pub server: Arc<Server>,
    pub local_addr: std::net::SocketAddr,
    pub public_key: PubKey,
}

/// Bind the UDP socket and construct server state. Does not accept yet.
/// Bind, finding relay peers the way a deployment does: SIP-33 discovery.
pub async fn bind(
    config: Config,
    config_path: Option<PathBuf>,
    signing_key: SigningKey,
) -> Result<Bound> {
    bind_with(
        config,
        config_path,
        signing_key,
        crate::relay::Find::Discover,
    )
    .await
}

/// The same, told how to find a relay peer.
///
/// Exists for the end-to-end tests, which run two exchanges on loopback with
/// invented domains and so have no DNS to discover each other through. The seam
/// is an argument rather than a configuration key on purpose: an operator able
/// to pin a peer's address by hand would be back to the thing SIP-33 discovery
/// replaced.
pub async fn bind_with(
    config: Config,
    config_path: Option<PathBuf>,
    signing_key: SigningKey,
    find: crate::relay::Find,
) -> Result<Bound> {
    let public_key = PubKey::new(signing_key.verifying_key().to_bytes());
    // SIP-64: a lineage that does not end at this key is not this
    // exchange's, and is refused here rather than served.
    let lineage =
        crate::lineage::load(&config.lineage_file, &public_key).map_err(Error::Malformed)?;
    let lineage_mtime = crate::lineage::modified(&config.lineage_file);
    let own_predecessors = lineage
        .predecessors_for(&public_key, None)
        .unwrap_or_default();
    let state = State::load(
        config.state_file.clone(),
        &config.seed_whitelist,
        &config.seed_relay_peers,
    )?;
    let channel_db = config
        .state_file
        .as_ref()
        .map(|p| p.with_file_name("channels.db"));
    let device_db = config
        .state_file
        .as_ref()
        .map(|p| p.with_file_name("devices.db"));
    let profile_db = config
        .state_file
        .as_ref()
        .map(|p| p.with_file_name("profiles.db"));
    // Prekeys persist for the same reason the device registry does: a registry
    // of devices nothing can be sealed to is not a registry, and a restart that
    // emptied them would be silent — a client whose own pool looks healthy has
    // no reason to publish again.
    let prekey_db = config
        .state_file
        .as_ref()
        .map(|p| p.with_file_name("prekeys.db"));
    // Durable like the device registry, for the same reason: a name is the
    // identity a person keeps, and one that vanished on a restart would be
    // worse than none.
    let name_db = config
        .state_file
        .as_ref()
        .map(|p| p.with_file_name("names.db"));

    // The managed whitelist is applied to the transport as well as to the
    // routes -- see `Server::sync_transport`. It is not set here because the
    // set is the managed state's, read after the listener exists and kept in
    // step with every change; `allowed_keys` at construction would be a
    // second copy that stopped being true at the first admin op.
    let squic_config = SquicConfig {
        // `h3` for clients; `sqex-relay` (SIP-39) for a peering exchange's link,
        // which the accept loop tells apart by the negotiated ALPN.
        alpn_protocols: vec![ALPN.to_vec(), sqex_proto::relay::ALPN.to_vec()],
        max_idle_timeout: std::time::Duration::from_secs(60),
        // Sessions may carry real-time media over datagrams (SIP-12). Costs
        // nothing for the connections that never send one.
        enable_datagrams: true,
        ..Default::default()
    };

    // Only override squic's own default when the config actually named a set
    // of versions (SIP-29). Pinning one here would silently override it.
    let mut squic_config = squic_config;
    if let Some(versions) = &config.accepted_envelope_versions {
        squic_config.accepted_envelope_versions = versions.clone();
    }
    // Bound concurrently-established connections when the operator set a cap.
    if let Some(n) = config.max_connections {
        squic_config.max_connections = Some(n);
    }
    if let Some(c) = config.congestion {
        squic_config.congestion_controller = c;
    }

    let accepted_envelope_versions = squic_config.accepted_envelope_versions.clone();
    let listener = Arc::new(
        squic::listen(config.listen, &signing_key, squic_config)
            .await
            .map_err(|e| Error::Malformed(format!("cannot listen on {}: {e}", config.listen)))?,
    );
    let local_addr = listener
        .local_addr()
        .map_err(|e| Error::Malformed(format!("cannot read local address: {e}")))?;

    let welcome_name = config.welcome_channel.clone();
    let founder = config.admins.first().copied();
    let server = Arc::new(Server {
        public_key,
        config_path,
        state: Mutex::new(state),
        admins: RwLock::new(config.admins),
        welcome: None,
        replication_peers: config.replication_peers.clone(),
        open_peering: config.open_peering,
        waits: Mutex::new(HashMap::new()),
        lineage: RwLock::new((lineage, lineage_mtime)),
        lineage_file: config.lineage_file.clone(),
        lineage_asked: Mutex::new(HashMap::new()),
        lineage_retry: config.lineage_retry,
        open_calls: config.open_calls,
        call_words: Mutex::new(HashMap::new()),
        replicate: config.replicate.clone(),
        exchange_seed: signing_key.to_bytes(),
        waker: std::sync::OnceLock::new(),
        admission_expiry: Mutex::new(None),
        wake_loopback: config.wake_loopback,
        carried_uploads: Mutex::new(HashMap::new()),
        next_carried: AtomicU64::new(0),
        origins: RwLock::new(
            config
                .replicate
                .iter()
                .map(|o| {
                    (
                        o.origin,
                        Arc::new(crate::replica::Forwarder::new(
                            o.origin,
                            o.addr,
                            o.domain.clone(),
                        )),
                    )
                })
                .collect(),
        ),
        contacts: Mutex::new(HashMap::new()),
        homed: tokio::sync::Notify::new(),
        rehome_away_secs: config.rehome_away_secs,
        limiter: crate::limits::Limiter::new(config.limits),
        directories: crate::directory::Directories::default(),
        directory_secs: config.directory_secs,
        home_secs: config.home_secs,
        domain: config.domain.clone(),
        transport: Arc::clone(&listener),
        accepted_envelope_versions,
        challenges: Challenges::new(config.challenge_ttl),
        beacons: Beacons::new(),
        endpoints: Endpoints::new(),
        attestations: Attestations::new(),
        rendezvous: Rendezvous::new(),
        mailbox: Mailbox::new(),
        rooms: Rooms::new(),
        // The channel log lives beside the state file, so a memory-only
        // deployment gets a memory-only log and nothing has to be configured
        // twice. This is the one service that cannot honestly be memory-only
        // in production, and an operator choosing that is choosing it.
        // The exchange's own key goes in, because SIP-31 binds every signature
        // to the place it was made and this is that place. Without it a signed
        // entry lifts into another exchange's copy of the same direct message
        // — whose identifier is byte-identical, being derived from the two
        // accounts — and verifies there.
        channels: Channels::open(
            channel_db.as_deref(),
            public_key,
            // SIP-34: the exchange signs receipts with the SIP-9 identity its
            // clients already pin, and deliberately not with a second key. A
            // separate signing key would need its own distribution, pinning and
            // rotation, vouched for by this one — a longer chain with no
            // shorter root.
            Some(signing_key.to_bytes()),
        )
        .map_err(|e| Error::Malformed(format!("cannot open the channel log: {e}")))?
        .with_backup_quota(config.backup_quota),
        // Durable, and it was not always. The argument for keeping prekeys in
        // memory was that a key surviving a restart the device did not is a key
        // whose secret is gone, so serving it produces an envelope nobody can
        // open — and that losing the pool costs a client one publish.
        //
        // Both halves are wrong. A server bounce does not restart its clients;
        // those are independent events, and the common one by far is the server
        // restarting while every device is fine. And it does not cost one
        // publish, because a client cannot tell: its own pool is untouched, so
        // `top_up_prekeys` sees a healthy count and republishes nothing. The
        // exchange simply stops being able to distribute a channel key to
        // anybody, silently, until something forces the issue.
        //
        // The case the old reasoning worried about is real and is now handled
        // where it belongs: SIP-23's `Clear` lets a device that has lost its
        // secrets discard what the exchange still holds.
        prekeys: Prekeys::open(prekey_db.as_deref())
            .map_err(|e| Error::Malformed(format!("cannot open the prekey store: {e}")))?,
        // Durable, unlike prekeys: a device should not have to re-register
        // because a server bounced, and a revocation that evaporated on a
        // restart would be worse than none at all.
        devices: Registry::open(device_db.as_deref())
            .map_err(|e| Error::Malformed(format!("cannot open the device registry: {e}")))?,
        // Durable, beside the device registry — a name is the identity a person
        // keeps across address and device changes (SIP-38).
        names: Names::open(name_db.as_deref(), config.name_lease_secs, config.max_names)
            .map_err(|e| Error::Malformed(format!("cannot open the name directory: {e}")))?,
        name_registration: config.name_registration,
        max_names_per_account: config.max_names_per_account,
        profiles: Profiles::open(profile_db.as_deref())
            .map_err(|e| Error::Malformed(format!("cannot open profiles: {e}")))?,
        // In memory: a pending request is a question somebody asked once, and
        // a queue that survived a restart would be a backlog of decisions
        // nobody remembers being asked to make. Asking again costs a request.
        admissions: Admissions::new(),
        sessions: Sessions::new(),
        live_conns: Connections::default(),
        // No peer list here. The relay used to hold a snapshot taken at
        // startup, which is exactly what made adding a peer a restart.
        relay: crate::relay::Relay::new(signing_key.to_bytes(), config.max_bridges, find),
        events: Subscribers::default(),
        started: Instant::now(),
        connections: AtomicU64::new(0),
        requests: AtomicU64::new(0),
    });
    // SIP-66: what this exchange held for its own earlier keys is its own
    // now -- an account's Move naming the key it rotated from, an origin
    // hint, a learned home -- with the Move's signature cleared, as at any
    // other holder. Done at every start, so a store from before the
    // rotation is repaired the same way.
    for earlier in &own_predecessors {
        let n = server.devices.follow_exchange(earlier, &public_key);
        if n > 0 {
            tracing::info!(from = %earlier, rows = n, "holdings of this exchange's earlier key followed to it (SIP-66)");
        }
    }
    // The front door, made once and found by name thereafter. An exchange
    // with nothing in it is a room with no doors: a new account can reach
    // nobody, and be reached by nobody, until somebody hands it a sixty-four
    // character identifier out of band.
    //
    // The first configured administrator becomes its admin. Without one the
    // channel is still a channel — anybody may join, read and post — but
    // nothing can rename it or set its topic, because SIP-16 puts those behind
    // a role there would be nobody to hold. A room nobody administers beats no
    // room.
    // The transport gate, from the state as loaded: an exchange restarted
    // with the list enabled is closed from its first packet.
    server.sync_transport(&server.state.lock().unwrap());

    let mut server = server;
    if !welcome_name.is_empty() {
        match server
            .channels
            .ensure_public(&welcome_name, founder.as_ref())
        {
            Ok(channel) => {
                Arc::get_mut(&mut server)
                    .expect("nothing else holds this yet")
                    .welcome = Some(channel);
                tracing::info!(
                    channel = %bs58::encode(channel).into_string(),
                    admin = ?founder.map(|f| f.to_string()),
                    "welcome channel #{welcome_name}"
                );
            }
            // Not fatal. An exchange that refused to start because it could
            // not make a convenience would be trading the whole service for
            // part of one.
            Err(e) => tracing::warn!("no welcome channel: {e:?}"),
        }
    }

    // SIP-45: started here rather than in the struct, because the task needs
    // the `Arc` and the `Arc` needs the struct -- and after the welcome
    // channel, whose `get_mut` needs the `Arc` unshared, weakly or not. Weak,
    // so the server can go.
    let _ = server
        .waker
        .set(crate::wake::start(Arc::downgrade(&server)));

    Ok(Bound {
        listener,
        server,
        local_addr,
        public_key,
    })
}

/// Serve until interrupted.
pub async fn serve(bound: Bound) -> Result<()> {
    let Bound {
        listener,
        server,
        local_addr,
        public_key,
    } = bound;

    // The peer count belongs on the startup line now that peering is state
    // rather than configuration. An operator who restarts can no longer read
    // the config to find out who this exchange federates with, and a peer list
    // that came back empty — a state file that failed to load, a seed that did
    // not apply — would otherwise look exactly like a healthy start until the
    // first cross-exchange call failed. Count only: which exchanges these are
    // is not something to put where anyone can read it, since SIP-39 refuses
    // uniformly on purpose and a public list would be the oracle that avoids.
    tracing::info!(
        listen = %local_addr,
        key = %public_key,
        admins = server.admins.read().unwrap().len(),
        relay_peers = server.state.lock().unwrap().peer_count(),
        replication_peers = server.replication_peers.len(),
        peering = if server.open_peering { "open" } else { "listed" },
        calls = if server.open_calls { "open" } else { "listed" },
        lineage = server.lineage.read().unwrap().0.links.len(),
        lineage_file = %server.lineage_file.display(),
        "sqexd {} listening (HTTP/3)", VERSION
    );
    tracing::info!("connection string: sqx://{local_addr}/{public_key}");

    // SIP-35. One task per origin, each dialling with this exchange's own
    // identity so the origin's whitelist can see who is asking. Started before
    // the accept loop because a replica is useful whether or not anybody is
    // talking to *it* — outliving an origin's availability is half the reason
    // to hold a copy.
    for origin in &server.replicate {
        let task = crate::replica::Origin {
            key: origin.origin,
            addr: origin.addr,
            channels: origin.channels.clone(),
            interval: origin.interval,
            predecessors: origin.predecessors.clone(),
        };
        tracing::info!(
            origin = %origin.origin,
            addr = %origin.addr,
            channels = origin.channels.len(),
            "replicating"
        );
        let forwarder = server
            .forwarder(&origin.origin)
            .expect("a configured origin has a forwarder");
        tokio::spawn(crate::replica::run(
            Arc::clone(&server),
            server.exchange_seed,
            task,
            forwarder,
        ));
    }

    // SIP-55: the peers' directories, read on an interval for searches.
    tokio::spawn(crate::directory::run(
        Arc::clone(&server),
        server.exchange_seed,
    ));

    // SIP-53: channels whose origin moved somewhere this exchange was not
    // configured for are pulled from wherever the rehome said.
    {
        let configured: Vec<PubKey> = server.replicate.iter().map(|o| o.origin).collect();
        let interval = server
            .replicate
            .iter()
            .map(|o| o.interval)
            .min()
            .unwrap_or(std::time::Duration::from_secs(30));
        tokio::spawn(crate::replica::run_moved(
            Arc::clone(&server),
            server.exchange_seed,
            configured,
            interval,
        ));
    }

    // SIP-59: the accounts homed here have their channels pulled from
    // wherever each said they live.
    {
        let configured: Vec<(PubKey, Vec<[u8; 32]>)> = server
            .replicate
            .iter()
            .map(|o| (o.origin, o.channels.clone()))
            .collect();
        tokio::spawn(crate::replica::run_homed(
            Arc::clone(&server),
            server.exchange_seed,
            configured,
            std::time::Duration::from_secs(server.home_secs),
        ));
    }

    let accept_loop = async {
        loop {
            let incoming = match listener.accept().await {
                Some(i) => i,
                None => break,
            };
            // Capture the MAC1-verified peer key BEFORE awaiting the Incoming:
            // peer_key drains on read and is keyed off the original DCID.
            let peer = Peer {
                key: listener.peer_key(&incoming),
                identity: listener.peer_identity(&incoming).map(PubKey::new),
                addr: incoming.remote_address(),
            };
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        server.connections.fetch_add(1, Ordering::Relaxed);
                        // SIP-39: a peering exchange's link negotiates the
                        // `sqex-relay` ALPN and is driven by the relay protocol,
                        // not HTTP/3.
                        if crate::relay::alpn_of(&conn).as_deref() == Some(sqex_proto::relay::ALPN)
                        {
                            crate::relay::serve_relay(&server, conn, peer.identity).await;
                        } else {
                            let ended = serve_h3(server, conn.clone(), peer).await;
                            // **The transport, in numbers, once per
                            // connection.** A slow download looked identical
                            // from outside whether the path was lossy, the
                            // window never grew, or the client was slow to
                            // read, and this is the only place the server's
                            // own window and loss count are visible.
                            let s = conn.stats();
                            tracing::info!(
                                rtt_ms = s.path.rtt.as_millis() as u64,
                                cwnd = s.path.cwnd,
                                mtu = s.path.current_mtu,
                                sent = s.path.sent_packets,
                                lost = s.path.lost_packets,
                                congestion_events = s.path.congestion_events,
                                tx_bytes = s.udp_tx.bytes,
                                rx_bytes = s.udp_rx.bytes,
                                "connection ended"
                            );
                            if let Err(e) = ended {
                                tracing::debug!("connection ended: {e}");
                            }
                        }
                    }
                    Err(e) => tracing::debug!("handshake failed: {e}"),
                }
            });
        }
    };

    // The daemon's first background sweep. Every other service expires lazily
    // on the operation path, which is right when the state is soft and the
    // window is seconds. A retention window measured in days cannot wait for
    // somebody to touch the channel: a channel nobody has opened in weeks is
    // exactly the case that matters.
    let sweeper = {
        let server = Arc::clone(&server);
        async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let channels = Arc::clone(&server);
                // The sweep is blocking work against SQLite, so it does not
                // belong on a runtime thread that is also answering requests.
                let done = tokio::task::spawn_blocking(move || channels.channels.sweep()).await;
                if let Ok((pruned, closed)) = done
                    && (pruned > 0 || closed > 0)
                {
                    tracing::info!(pruned, closed, "swept channels");
                }
                // SIP-25: the rendezvous store is in-memory. `request` prunes
                // expired `asked` opportunistically, but the per-pair `waiters`
                // notifiers are only reclaimed here — without this sweep they
                // accumulate one entry per distinct pair that ever long-polled,
                // an unbounded leak. Cheap in-memory work, no spawn_blocking.
                server.rendezvous.sweep();
                // SIP-38: drop names abandoned well past their lease. A single
                // SQLite DELETE, so spawn_blocking like the channel sweep above.
                let names = Arc::clone(&server);
                if let Ok(dropped) =
                    tokio::task::spawn_blocking(move || names.names.sweep(now_unix())).await
                    && dropped > 0
                {
                    tracing::info!(dropped, "swept abandoned names");
                }
                // SIP-38: evict stale rate-limiter entries so the in-memory map
                // does not grow one entry per account that ever claimed. Cheap
                // in-memory work, no spawn_blocking.
                server.names.sweep_rate_limiter(now_unix());
                // SIP-39: bridges have their own lifetime, and an exchange
                // nobody is calling still has to tidy up the ones abandoned
                // mid-ring.
                server.relay.sweep(now_unix());
                // SIP-56: buckets that have refilled are no buckets.
                server.limiter.sweep();
                // SIP-47: a device is admitted for as long as its credential
                // stands, and a credential runs out with nobody at the door
                // to say so. The one time-driven change to the whitelist.
                if server.admission_due() {
                    server.resync_transport();
                }
            }
        }
    };

    tokio::select! {
        _ = accept_loop => tracing::warn!("listener stopped accepting"),
        _ = sweeper => tracing::warn!("sweeper stopped"),
        _ = shutdown_signal() => {
            tracing::info!("shutting down");
            if let Err(e) = server.state.lock().unwrap().save() {
                tracing::error!("final state save failed: {e}");
            }
        }
    }
    Ok(())
}

/// Drive one HTTP/3 connection: accept request streams and answer each.
async fn serve_h3(server: Arc<Server>, conn: quinn::Connection, peer: Peer) -> Result<()> {
    // An identified connection can carry session datagrams, so register it and
    // pump them for as long as it lives. Anonymous connections cannot be a
    // party to a session, so they are never registered and never forwarded to.
    if let Some(key) = peer.key {
        server.live_conns.add_keyed(key, conn.clone());
    }
    let registered = peer.identity.inspect(|id| {
        server.live_conns.add(*id, conn.clone());
        tokio::spawn(forward_datagrams(Arc::clone(&server), conn.clone(), *id));
    });

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(|e| Error::Malformed(format!("h3 setup: {e}")))?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(server, resolver, peer).await {
                        tracing::debug!("request error: {e}");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("h3 accept error: {e}");
                break;
            }
        }
    }
    server.live_conns.remove_keyed(&conn);
    if let Some(id) = registered {
        server.live_conns.remove(&id, &conn);
    }
    Ok(())
}

/// Relay session datagrams for one connection until it closes.
///
/// This is the whole unreliable path: read a datagram, check the sender is a
/// party to the session it names, write it to the other party's connection.
/// Nothing is queued, retried, acknowledged or inspected — a packet that cannot
/// be delivered right now is dropped, which is the correct behaviour for media
/// and the reason this path exists (SIP-12).
async fn forward_datagrams(server: Arc<Server>, conn: quinn::Connection, from: PubKey) {
    loop {
        let Ok(bytes) = conn.read_datagram().await else {
            return; // connection closed
        };
        let Ok(frame) = DatagramFrame::decode(&bytes) else {
            continue; // malformed: drop it, say nothing
        };
        // SIP-39: a bridged session's counterpart is on another exchange —
        // divert the frame onto the relay link rather than a local connection.
        if crate::relay::maybe_divert(&server, &from, &frame) {
            continue;
        }
        let Some(to) = server.sessions.counterpart(&from, frame.session_id) else {
            continue; // not a party, or no live session: drop it
        };
        // Forwarded verbatim: the exchange cannot read the ciphertext and has
        // no reason to touch the header it routed on.
        for peer_conn in server.live_conns.get(&to) {
            let _ = peer_conn.send_datagram(bytes.clone());
        }
    }
}

async fn handle_stream(
    server: Arc<Server>,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, bytes::Bytes>,
    peer: Peer,
) -> Result<()> {
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| Error::Malformed(format!("resolve: {e}")))?;

    server.requests.fetch_add(1, Ordering::Relaxed);

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Which route, at debug: the counter says how many, and a client
    // measuring what a session costs needs to know what they were.
    tracing::debug!(%method, %path, "request");

    // Read the request body (bounded), if any.
    // SIP-43: a chunk carried from a replica arrives on the peering route.
    let cap = if path == "/blob/put" || path == "/peer/forward" {
        MAX_CHUNK_BODY
    } else {
        MAX_BODY
    };
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| Error::Malformed(format!("recv body: {e}")))?
    {
        while chunk.remaining() > 0 {
            let n = chunk.chunk().len();
            if body.len() + n > cap {
                let (status, ct, out) = refuse(413, Code::BodyTooLarge, None);
                return respond(&mut stream, status, ct, out).await;
            }
            body.extend_from_slice(chunk.chunk());
            chunk.advance(n);
        }
    }

    // The one route whose answer never finishes. It is handled here rather
    // than in `route` because `route` returns a body and this one does not
    // have one — it has a stream that stays open for as long as the client
    // does (SIP-30).
    if method == http::Method::POST && path == "/events" {
        return serve_events(&server, &body, peer, &mut stream).await;
    }

    let (status, content_type, out) = route(&server, method.as_str(), &path, &body, peer).await;
    respond(&mut stream, status, content_type, out).await
}

/// Hold a response stream open and write SIP-30 events to it until the client
/// goes away.
///
/// The shape matters more than the code. The subscription is registered
/// **before** the response head is sent, and the client does not begin its
/// reconciling fetch until it has that head — so anything happening in between
/// is queued rather than missed. Reversed, a client would silently lose every
/// change that landed while it was catching up, and nothing at either end would
/// say so. This is the same ordering `fetch_waiting` states for the long poll:
/// take the notifier before the first read.
async fn serve_events(
    server: &Arc<Server>,
    body: &[u8],
    peer: Peer,
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
) -> Result<()> {
    // The **account**, not the device on the connection. Every publisher
    // addresses accounts — membership, profiles and admission all are — so a
    // subscription filed under a device key would simply never be found. It
    // costs one registry lookup and it is the same resolution `route` does for
    // every other chat route; an account with no registered devices is its own
    // device, which is why the single-client tests could not tell the two
    // apart and why this only showed up against a store that had seen a
    // linked device (SIP-22).
    let Some(me) = peer.identity.map(|d| server.devices.account_for(&d)) else {
        let (status, ct, out) = no_identity("an event stream");
        return respond(stream, status, ct, out).await;
    };
    match sqex_proto::events::Subscribe::decode(body) {
        Ok(sub) if sub.version == sqex_proto::events::VERSION => {}
        Ok(sub) => {
            let (status, ct, out) = refuse(
                400,
                Code::UnsupportedVersion,
                Some(&format!(
                    "this exchange speaks event version {}, not {}",
                    sqex_proto::events::VERSION,
                    sub.version
                )),
            );
            return respond(stream, status, ct, out).await;
        }
        Err(e) => {
            let (status, ct, out) = refuse(400, Code::Malformed, Some(&e.to_string()));
            return respond(stream, status, ct, out).await;
        }
    }

    let device = peer.identity.unwrap_or(me);
    let Some(mut feed) = server.events.subscribe(me, device) else {
        let (status, ct, out) = refuse(
            429,
            Code::TooManyStreams,
            Some(&format!(
                "an identity may hold {} event streams at once",
                crate::events::MAX_PER_IDENTITY
            )),
        );
        return respond(stream, status, ct, out).await;
    };

    // No content-length, and no `finish`: `respond` sets one and ends the
    // stream, which is right for every other route and fatal to this one.
    let head = http::Response::builder()
        .status(200)
        .header("content-type", EVENT_STREAM)
        .body(())
        .map_err(|e| Error::Malformed(format!("response build: {e}")))?;
    let opened = stream.send_response(head).await;
    if opened.is_err() {
        let _ = server.events.unsubscribe(&feed);
        return Ok(());
    }

    crate::events::pump(&mut feed, &mut H3Sink { stream }, HEARTBEAT).await;
    if server.events.unsubscribe(&feed) {
        // SIP-47: the device held a stream and let it go. Whatever wake
        // brought it has been answered; the next event wakes it afresh.
        server.devices.released(&feed.device);
    }
    Ok(())
}

/// Where the h3 response stream meets the pump. The pump itself lives in
/// [`crate::events`] with the thing it drains, so its two rules — a resync
/// replaces a backlog, silence is broken by a heartbeat — can be tested without
/// standing up a QUIC connection to watch them.
struct H3Sink<'a> {
    stream: &'a mut h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
}

impl crate::events::Sink for H3Sink<'_> {
    async fn write(&mut self, event: EventKind) -> std::result::Result<(), ()> {
        self.stream
            .send_data(bytes::Bytes::from(event.frame()))
            .await
            .map_err(|_| ())
    }
}

/// Pure-ish routing: all state access, no stream I/O.
async fn route(
    server: &Arc<Server>,
    method: &str,
    path: &str,
    body: &[u8],
    peer: Peer,
) -> (u16, &'static str, Vec<u8>) {
    // A connection carries a *device* identity (SIP-3) and the chat services
    // work in **accounts**, so resolve once and use the right one deliberately:
    // membership, roles and display are per account; sealing subkeys, message
    // counters and prekeys are per device. An account with no registered
    // devices is its own device, which is the ordinary single-client case.
    let device = peer.identity;
    let account = device.map(|d| server.devices.account_for(&d));
    // The pair, for the SIP-31 routes: membership is an account's, the
    // signature is always a device's, and every signed route needs both.
    let who = match (account, device) {
        (Some(a), Some(d)) => Some((a, d)),
        _ => None,
    };

    // **The managed whitelist, once enabled, closes every route a client
    // uses.** SIP-2's closed set, matched against the MAC1-verified transport
    // key, so a peer not on it is refused before anything below runs -- before
    // the welcome, before any store is read. Four kinds of route stay open,
    // each for a reason the design already gives: `/admin/*`, signature-gated
    // and the only way to run the list itself (a YubiKey admin has no stable
    // transport key to be on it with); `/admission/request`, SIP-24's one way
    // in, which answers everyone identically so it is not an oracle;
    // `/health` and `/status`, the exchange's own numbers and no one's
    // content; and `/peer/*`, exchange to exchange, which has an allowlist of
    // its own in `replication_peers`. Until now the list gated one route,
    // `/exchange/ping`, put there to show the mechanism -- so enabling it
    // changed nothing for anybody, which read as the list not working.
    if !open_regardless(path) && !server.admitted(peer.key) {
        return refuse(403, Code::NotWhitelisted, None);
    }

    // SIP-44: a succeeded account is nobody's client, and so are its
    // devices. Told where the account went, on every route a client uses,
    // so a client still holding the old key learns rather than wonders. The
    // succession routes themselves stay open: reading one is how anybody
    // checks it, and a claim comes from the successor, who is not this.
    if let Some(me) = account
        && !open_regardless(path)
        && !path.starts_with("/account/")
        && let Some(successor) = server.devices.successor_of(&me)
    {
        return refuse(403, Code::Succeeded, Some(&successor.to_string()));
    }

    // SIP-59: an account that lives elsewhere now is told so on every
    // service that was the key's here and is written by its own devices --
    // prekeys, wake, backup, endpoints -- so a client still pointed at its
    // old exchange learns rather than splits its pool. The recipient-side
    // routes (a sender's `/mailbox/send`, `/prekey/take`, `/resolve/get`)
    // make the same check on their subject, in their own arms. Channel
    // routes go on serving: the account is still a member here.
    if let Some(me) = account
        && matches!(
            path,
            "/prekey/publish" | "/wake/register" | "/backup/write" | "/resolve/publish"
        )
        && let Some(moved) = server.moved_away(&me)
    {
        return moved;
    }

    // The front door, held open once per account.
    //
    // Here rather than on one particular route because there is no single
    // request a new account always makes first — a client publishes prekeys, a
    // CLI might list channels, a linked device registers. `welcome` is a
    // no-op after the first time, and it is the only thing on this path that
    // touches an account's membership without being asked to.
    if let (Some(me), Some(channel)) = (account, server.welcome)
        && let Err(e) = server.channels.welcome(&me, &channel)
    {
        tracing::warn!("could not welcome {me}: {e:?}");
    }

    match (method, path) {
        ("GET", "/health") => (
            200,
            "application/json",
            json!({ "status": "ok", "service": "sqex", "version": VERSION })
                .to_string()
                .into_bytes(),
        ),
        ("GET", "/status") => (200, "application/json", server.status_json()),
        ("GET", "/admin/challenge") => {
            let nonce = server.challenges.issue();
            (200, "application/octet-stream", nonce.to_vec())
        }
        // **This route answers JSON, and must keep doing so.** Every other
        // refusal is a `sqex_proto::refusal::Refusal`; this one is read by
        // `sqnr::flow::sign_and_submit`, an external crate pinned by tag, which
        // does `serde_json::from_slice(&body).unwrap_or(Null)` and then reads
        // `error` and `detail` out of it. A binary body would not fail there —
        // it would degrade silently to a refusal with no reason, which is worse
        // than the substring matching this change exists to remove. Converting
        // it means releasing sqnr first.
        ("POST", "/admin/command") => match server.execute(body).await {
            Ok(json_body) => (200, "application/json", json_body),
            Err(e) => {
                let (code, kind) = error_status(&e);
                (
                    code,
                    "application/json",
                    json!({ "error": kind, "detail": e.to_string() })
                        .to_string()
                        .into_bytes(),
                )
            }
        },
        // SIP-4 liveness beacon. Beating requires an advertised Ed25519
        // identity (SIP-3) and nothing else — this is an *open* set: any
        // identity may beat, registered or not, which is the whole point.
        // Reading is open to anyone holding the server key.
        ("POST", "/beacon/beat") => match Beat::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(beat) => match peer.identity {
                None => no_identity("beating"),
                Some(id) => {
                    let now =
                        server
                            .beacons
                            .record(id, beat.interval_secs, beat.withhold, beat.away);
                    // SIP-28: a service proving it is alive should not have to
                    // separately prove its address is current. The window is
                    // extended by the interval it declared, so an identity that
                    // keeps beating keeps its endpoints — and one that stops
                    // loses them on the same schedule its own beacon claims.
                    server
                        .endpoints
                        .refresh(&id, beat.interval_secs.saturating_mul(2));
                    // SIP-38: a beat is activity attributable to the account, so
                    // it renews the account's self-claimed names — a name in use
                    // does not lapse on its lease.
                    server.names.renew(&server.devices.account_for(&id));
                    tracing::debug!(identity = %id.short(), interval = beat.interval_secs, "beat");
                    (200, "application/octet-stream", BeatAck { now }.encode())
                }
            },
        },
        // SIP-25 rendezvous. **Both sides must have asked**, and until they
        // have, the answer says nothing — not the address, and not that
        // anybody asked, which would itself be a signal about somebody who has
        // not consented. The address disclosed is the one this exchange
        // observed on the connection, never one a caller supplied: an
        // introduction to an address a third party chose is the shape a
        // reflection abuse takes.
        //
        // This coordinates and does not punch. `squic::dial` binds a fresh
        // ephemeral port, so a peer cannot dial from the port named here, and
        // reusing that mapping is the whole mechanism — see SIP-25.
        ("POST", "/rendezvous/introduce") => match (peer.identity, Introduce::decode(body)) {
            (None, _) => no_identity("asking for an introduction"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                // Recorded with the observed address first, so a wait that
                // finds the pair already complete answers from real data.
                let first = server.rendezvous.request(&me, peer.addr, &req.peer);
                let out = if first.ready || req.wait_secs == 0 {
                    first
                } else {
                    server.rendezvous.wait(&me, &req.peer, req.wait_secs).await
                };
                (200, "application/octet-stream", out.encode())
            }
        },

        // SIP-27 attestation. **Anybody may lodge one**: it carries its own
        // proof, so who handed it over establishes nothing, and requiring the
        // issuer to do it would mean an issuer who has gone away can never be
        // quoted again.
        ("POST", "/attest/lodge") => match Attestation::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(a) => match server.attestations.lodge(a) {
                Ok(()) => (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                ),
                Err(LodgeError::Invalid(why)) => refuse(
                    401,
                    Code::BadSignature,
                    Some(&format!("attestation refused: {why:?}")),
                ),
                Err(LodgeError::NoSuchAttestation) => refuse(
                    404,
                    Code::NoSuchEntry,
                    Some(
                        "a revocation must name an attestation this exchange holds, by its own issuer",
                    ),
                ),
            },
        },
        // Open to anybody, because an attestation is meant to travel. The
        // exchange returns what it holds and **no count that means anything**:
        // anyone can generate identities and have them vouch for each other, so
        // only issuers a consumer already trusts carry weight, which is what
        // the issuer filter is for.
        ("POST", "/attest/read") => match AttestQuery::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(q) => (
                200,
                "application/octet-stream",
                server
                    .attestations
                    .about(&q.subject, q.issuer.as_ref())
                    .encode(),
            ),
        },

        // SIP-28 resolution. **The exchange is trusted for availability and
        // privacy, not for authenticity**: a consumer pins the key it asked for
        // when it connects, so a wrong address is a failed handshake rather
        // than an impersonation. Nothing here is signed, and nothing here is
        // authority.
        ("POST", "/resolve/publish") => match (peer.identity, ResolvePublish::decode(body)) {
            (None, _) => no_identity("publishing endpoints"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            // Only for itself. The handshake established which key is speaking,
            // and a caller may publish for that identity and no other — which
            // is the whole reason no signature is needed.
            (Some(id), Ok(req)) => {
                match server
                    .endpoints
                    .publish(id, req.ttl_secs, req.endpoints, req.capabilities)
                {
                    Ok(_) => {
                        // SIP-38: publishing an address is activity attributable
                        // to the account, so it renews the account's names too.
                        server.names.renew(&server.devices.account_for(&id));
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(_) => refuse(
                        507,
                        Code::TooManyEndpoints,
                        Some("an identity may publish at most 8 endpoints"),
                    ),
                }
            }
        },
        ("POST", "/resolve/get") => match (peer.identity, ResolveGet::decode(body)) {
            (None, _) => no_identity("resolving a key"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            // SIP-59: a key whose account lives elsewhere is resolved there.
            (Some(_), Ok(req))
                if server
                    .moved_away(&server.devices.account_for(&req.key))
                    .is_some() =>
            {
                server
                    .moved_away(&server.devices.account_for(&req.key))
                    .unwrap()
            }
            (Some(_), Ok(req)) => {
                // The beacon observation travels with the answer, because it is
                // the one thing a signed record structurally cannot say: not
                // where a service claims to be, but that somebody saw it there.
                // Read on the asker's behalf, so an identity that withholds its
                // liveness withholds it here too.
                let seen = server
                    .beacons
                    .read(&req.key, peer.identity.as_ref())
                    .last_seen;
                (
                    200,
                    "application/octet-stream",
                    server.endpoints.resolve(&req.key, seen).encode(),
                )
            }
        },
        // A forwarding note, and **not a retirement**: it is authenticated by
        // the connection, so whoever holds the key can set it — after a theft,
        // that is the attacker. An exchange cannot express "this key was
        // stolen, use this one instead".
        // SIP-44: a successor presents the account's will, or its guardians'
        // word, and the exchange carries the account across.
        ("POST", "/account/succeed") => match (peer.identity, Claim::decode(body)) {
            (None, _) => no_identity("succeeding an account"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(claim)) => succeed(server, &me, claim).await,
        },
        // SIP-59: an account's own signed statement of where it lives. The
        // carrier is not checked -- the signature is the authority -- and
        // the answer says whether the home named is a peer this exchange
        // will serve, so the client learns that here and not from a
        // silence later.
        ("POST", "/account/move") => match (peer.identity, Moving::decode(body)) {
            (None, _) => no_identity("moving an account"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(_), Ok(moving)) => {
                record_move(server, &moving.mv, &moving.domain, &moving.origins)
            }
        },
        // SIP-60: find somebody at another exchange -- their key, their
        // home, their devices -- on the client's behalf, and remember
        // where they live.
        ("POST", "/account/locate") => match (peer.identity, Locate::decode(body)) {
            (None, _) => no_identity("locating an account"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(_), Ok(req)) => locate(server, &req).await,
        },
        // SIP-60: a create for a channel that lives at another exchange --
        // a direct message at the lower key's home -- carried there as the
        // creator's own signed act, after the creator's Move.
        ("POST", "/channel/create_at") => match (who, CreateAt::decode(body)) {
            (None, _) => no_identity("creating a channel elsewhere"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                if req.origin == server.public_key {
                    return Box::pin(route(server, method, "/channel/create", &req.create, peer))
                        .await;
                }
                let Some((_, domain)) = server.reach(&req.origin).await else {
                    return refuse(503, Code::OriginAway, None);
                };
                let Some(forwarder) = server.forwarder(&req.origin) else {
                    return refuse(503, Code::OriginAway, None);
                };
                if let Some((mv, home_domain)) = server.devices.move_of(&me)
                    && mv.home == server.public_key
                {
                    forwarder
                        .carry_move(&server.exchange_seed, &mv, &home_domain)
                        .await;
                }
                match forwarder
                    .action(
                        &server.exchange_seed,
                        &dev,
                        server.devices.credential_of(&dev).as_ref(),
                        "/channel/create",
                        &req.create,
                    )
                    .await
                {
                    Ok(answer) => {
                        if answer.status == 200 {
                            server.homed.notify_one();
                        }
                        (answer.status, "application/octet-stream", answer.body)
                    }
                    Err(e) => {
                        tracing::warn!(origin = %req.origin, %domain, "create-at failed: {e}");
                        refuse(503, Code::OriginAway, None)
                    }
                }
            }
        },
        // SIP-59: where an account lives, as this exchange has it.
        ("POST", "/account/home") => match (peer.identity, sqex_proto::home::asked(body)) {
            (None, _) => no_identity("asking an account's home"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(_), Ok(asked)) => match server.devices.home_of(&asked) {
                Some((home, domain, since)) => (
                    200,
                    "application/octet-stream",
                    sqex_proto::home::Homed {
                        home,
                        domain,
                        since,
                    }
                    .encode(),
                ),
                // Known here: the caller itself, which is connected here,
                // or an account with devices, names or memberships here.
                None if account == Some(asked)
                    || server.devices.has_devices(&asked)
                    || server.channels.has_memberships(&asked)
                    || !server.names.names_for(&asked).is_empty() =>
                {
                    (
                        200,
                        "application/octet-stream",
                        sqex_proto::home::Homed {
                            home: server.public_key,
                            domain: String::new(),
                            since: 0,
                        }
                        .encode(),
                    )
                }
                None => refuse(404, Code::NotFound, None),
            },
        },
        // SIP-62: the account, still holding its key, names its successor
        // and keeps its devices under the new key's credentials.
        ("POST", "/account/handover") => match (account, Handover::decode(body)) {
            (None, _) => no_identity("handing an account over"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(h)) => handover(server, &me, h).await,
        },
        // SIP-44: what was recorded, for anybody to check.
        ("POST", "/account/succession") => match (peer.identity, succession::asked(body)) {
            (None, _) => no_identity("reading a succession"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(_), Ok(account)) => match server.devices.succession_of(&account) {
                Some((successor, now, proof)) => match Proof::decode(&proof) {
                    Ok(proof) => (
                        200,
                        "application/octet-stream",
                        succession::Succeeded {
                            successor,
                            now,
                            proof,
                        }
                        .encode(),
                    ),
                    Err(_) => refuse(500, Code::Storage, None),
                },
                None => refuse(404, Code::NotFound, None),
            },
        },
        // SIP-44: the policy an account lodged, for its guardians and its
        // successor to find when the account is gone.
        ("POST", "/account/lodged") => match (peer.identity, succession::asked(body)) {
            (None, _) => no_identity("reading a policy"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(_), Ok(account)) => match server.devices.lodged(&account) {
                Some(policy) => (200, "application/octet-stream", policy),
                None => refuse(404, Code::NotFound, None),
            },
        },
        // SIP-44: an account keeps its policy here ahead of need.
        ("POST", "/account/lodge") => match (peer.identity, Policy::decode(body)) {
            (None, _) => no_identity("lodging a policy"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(policy)) => {
                if policy.account != me || !policy.verify() {
                    return refuse(403, Code::NotYours, None);
                }
                match server.devices.lodge(&me, &policy.encode()) {
                    Ok(()) => (
                        200,
                        "application/octet-stream",
                        ChannelAck { now: now_unix() }.encode(),
                    ),
                    Err(_) => refuse(500, Code::Storage, None),
                }
            }
        },
        // SIP-48: the account's sealed backup. Written by a device of the
        // account; read by one, or by the account that succeeded it.
        ("POST", "/backup/write") => match (who, BackupManifest::decode(body)) {
            (None, _) => no_identity("writing a backup"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(m)) => match server.channels.write_backup(&me, &dev, &m) {
                Ok(()) => (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                ),
                Err(ChannelError::StaleGeneration(g)) => {
                    let e = ChannelError::StaleGeneration(g);
                    refuse(e.status(), e.code(), Some(&g.to_string()))
                }
                Err(e) => refused(e),
            },
        },
        ("POST", "/backup/read") => match (account, sqex_proto::backup::asked(body)) {
            (None, _) => no_identity("reading a backup"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(of)) => {
                // Yours, or one you succeeded (SIP-44).
                if of != me && server.devices.successor_of(&of) != Some(me) {
                    return refuse(403, Code::NotYours, None);
                }
                // Nothing held is generation 0, not a refusal: a 404 here
                // would read as an exchange without the route.
                match server.channels.read_backup(&of) {
                    Ok(h) => (200, "application/octet-stream", h.encode()),
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/backup/drop") => match account {
            None => no_identity("dropping a backup"),
            Some(_) if !sqex_proto::backup::is_drop(body) => {
                refuse(400, Code::Malformed, Some("not a drop"))
            }
            Some(me) => match server.channels.drop_backup(&me) {
                Ok(()) => (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                ),
                Err(e) => refused(e),
            },
        },
        // SIP-45: where to wake this device, and until when.
        ("POST", "/wake/register") => match (peer.identity, WakeRegister::decode(body)) {
            (None, _) => no_identity("registering a wake"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(device), Ok(req)) => {
                if !sqex_proto::wake::acceptable(&req.endpoint, server.wake_loopback) {
                    return refuse(
                        400,
                        Code::Malformed,
                        Some("an endpoint is an https:// address"),
                    );
                }
                match server
                    .devices
                    .register_wake(&device, &req.endpoint, req.ttl)
                {
                    Ok(()) => (
                        200,
                        "application/octet-stream",
                        ChannelAck { now: now_unix() }.encode(),
                    ),
                    Err(_) => refuse(500, Code::Storage, None),
                }
            }
        },
        ("POST", "/wake/forget") => match peer.identity {
            None => no_identity("forgetting a wake"),
            Some(_) if !sqex_proto::wake::is_forget(body) => {
                refuse(400, Code::Malformed, Some("not a forget"))
            }
            Some(device) => {
                server.devices.forget_wake(&device);
                (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                )
            }
        },
        ("POST", "/resolve/successor") => match (peer.identity, ResolveSuccessor::decode(body)) {
            (None, _) => no_identity("naming a successor"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(id), Ok(req)) => {
                server.endpoints.set_successor(id, req);
                (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                )
            }
        },

        ("POST", "/beacon/read") => match Read::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(read) => {
                let reply = server.beacons.read(&read.key, peer.identity.as_ref());
                (200, "application/octet-stream", reply.encode())
            }
        },

        // SIP-13 rooms. The exchange holds a roster and nothing else: it is
        // given a handle, never the room secret, so it cannot join a room it
        // carries. It relays each member's proof without checking it — checking
        // needs the secret it has deliberately not been told — and the members
        // verify each other.
        // SIP-24 admission. The one route a peer the exchange will not serve
        // can reach, which is why the reply never varies: if it did, submitting
        // a credential would tell a caller whether that account is admitted
        // here. Every limit is enforced silently — an overrun changes what is
        // stored and never what is answered.
        ("POST", "/admission/request") => match (device, AdmissionRequest::decode(body)) {
            (None, _) => no_identity("requesting admission"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                let siblings = server
                    .devices
                    .list(&req.credential.account)
                    .map(|d| d.devices.len())
                    .unwrap_or(0);
                server.admissions.request(
                    &me,
                    peer.key.as_ref(),
                    &req.credential,
                    &req.label,
                    siblings,
                );
                // Whoever can act on it. An admission request that waits for
                // an admin to think of refreshing is the case this replaces.
                let admins: Vec<PubKey> = server.admins.read().unwrap().clone();
                server.events.publish(&admins, EventKind::Admission);
                // `now` is the only field, and it is here for the reason SIP-4
                // gives: a client with a wrong clock has something to notice it
                // against. It is identical for every caller.
                (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                )
            }
        },

        // SIP-21 profiles and blocking. Every field is a claim its subject
        // makes; nothing here is attested, and a client must show the key
        // alongside a name wherever the distinction could matter.
        ("POST", "/profile/put") => match (account, ProfilePut::decode(body)) {
            (None, _) => no_identity("publishing a profile"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.profiles.put(&me, &req.record) {
                Ok(()) => {
                    // SIP-21 scopes a profile to the people you are already in
                    // a room with, so that is exactly who may be told it
                    // changed — less anybody blocking, or blocked by, the
                    // publisher. What they learn is that it changed; whether
                    // they may *see* it is still decided at `/profile/get`.
                    let to: Vec<PubKey> = server
                        .channels
                        .peers_of(&me)
                        .into_iter()
                        .filter(|other| {
                            !server.profiles.has_blocked(other, &me)
                                && !server.profiles.has_blocked(&me, other)
                        })
                        .collect();
                    server
                        .events
                        .publish(&to, EventKind::Profile { account: me });
                    (
                        200,
                        "application/octet-stream",
                        ChannelAck { now: now_unix() }.encode(),
                    )
                }
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },
        ("POST", "/profile/get") => match (account, ByAccount::decode(body, PR_GET)) {
            (None, _) => no_identity("reading a profile"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                // The welcome channel does not count towards knowing
                // somebody: everybody is in it, so counting it would leave a
                // withheld profile withheld from nobody.
                let shares = |a: &PubKey, b: &PubKey| {
                    server
                        .channels
                        .share_a_channel(a, b, server.welcome.as_ref())
                };
                match server.profiles.get(&me, &req.account, &shares) {
                    Ok(got) => (200, "application/octet-stream", got.encode()),
                    Err(e) => refuse(e.status(), e.code(), None),
                }
            }
        },
        ("POST", "/block/set") => match (account, ProfileBlock::decode(body)) {
            (None, _) => no_identity("blocking"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.profiles.set_block(&me, &req.account, req.add) {
                Ok(()) => (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                ),
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },
        // Returned only to its owner: a list of who somebody wants to avoid is
        // more sensitive than the member list it protects them from, so it
        // takes no argument and answers about nobody else.
        ("POST", "/block/list") => match account {
            None => no_identity("listing blocks"),
            Some(me) => match server.profiles.blocks(&me) {
                Ok(list) => (200, "application/octet-stream", list.encode()),
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },

        // SIP-22 device registry. A credential is evidence and not authority:
        // it tells the exchange which account vouches for a key, and does not
        // entitle that key to anything.
        ("POST", "/device/register") => match (device, DeviceRegister::decode(body)) {
            (None, _) => no_identity("registering a device"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            // The caller is the delegate itself, or an already-registered
            // device of the same account. The account is never required to
            // connect, because a hardware-held one cannot.
            (Some(me), Ok(req)) => match server.devices.register(&me, &req.credential) {
                Ok(()) => {
                    server.resync_transport();
                    (
                        200,
                        "application/octet-stream",
                        ChannelAck { now: now_unix() }.encode(),
                    )
                }
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },
        ("POST", "/device/revoke") => match (device, DeviceRevoke::decode(body)) {
            (None, _) => no_identity("revoking a device"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                match server
                    .devices
                    .revoke(&me, &req.device, req.revocation.as_ref())
                {
                    Ok(()) => {
                        server.resync_transport();
                        // SIP-59: an account homed here has origins that
                        // may have registered this device from a carried
                        // credential; the signed withdrawal goes to each.
                        if let (Some(a), Some(_)) = (account, &req.revocation)
                            && server
                                .devices
                                .home_of(&a)
                                .is_some_and(|(h, _, _)| h == server.public_key)
                        {
                            carry_revocation(server, a, me, body.to_vec());
                        }
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refuse(e.status(), e.code(), None),
                }
            }
        },
        // Answerable to anybody: the mapping is public by construction, since
        // every credential carries both keys in the clear to whoever verifies
        // one. Pretending otherwise would protect something already published
        // while making a member list impossible to render.
        // SIP-67: whose device the caller is, from the registry -- the one
        // party that knows after a handover moved it. Its own key twice
        // where it is registered to nobody: every key is an account until
        // the registry says otherwise (SIP-22).
        ("GET", "/device/account") => match peer.identity {
            None => no_identity("asking whose device this is"),
            Some(me) => (
                200,
                "application/octet-stream",
                sqex_proto::device::Whose {
                    account: server.devices.account_for(&me),
                    device: me,
                }
                .encode(),
            ),
        },
        ("POST", "/device/list") => match ListDevices::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(req) => match server.devices.list(&req.account) {
                // SIP-60: an account with no devices here whose home is
                // elsewhere is listed as its home lists it.
                Ok(list) if list.devices.is_empty() => {
                    if let Some((home, _)) =
                        server.devices.where_is(&req.account, &server.public_key)
                        && let Some((addr, _)) = server.reach(&home).await
                        && let Some(theirs) = crate::relay::devices_at(
                            addr,
                            &home,
                            &server.exchange_seed,
                            &req.account,
                        )
                        .await
                    {
                        return (200, "application/octet-stream", theirs.encode());
                    }
                    (200, "application/octet-stream", list.encode())
                }
                Ok(list) => (200, "application/octet-stream", list.encode()),
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },

        // SIP-38 names. A name binds to an **account**, so the account's devices
        // (SIP-22) and endpoints (SIP-28) follow once a name resolves — this is
        // only the hop in the middle. Registration mode is the operator's
        // policy: `open` (self-claim), `closed` (administrator-assigned only),
        // or `off` (the route is not offered). The binding is exchange-asserted;
        // see the trust boundary in SIP-38.
        ("POST", "/name/claim") => match (account, name::Claim::decode(body)) {
            (None, _) => no_identity("claiming a name"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            // Self-claim is open-mode only. Closed answers `CLOSED` in the
            // reply's own vocabulary rather than a transport refusal, because
            // the namespace is public and a caller has earned a real answer;
            // off does not offer the route at all.
            (Some(me), Ok(req)) => match server.name_registration {
                NameMode::Open => {
                    let outcome = server
                        .names
                        .claim(&req.name, &me, server.max_names_per_account);
                    (
                        200,
                        "application/octet-stream",
                        name::ClaimAck {
                            outcome,
                            now: now_unix(),
                        }
                        .encode(),
                    )
                }
                NameMode::Closed => (
                    200,
                    "application/octet-stream",
                    name::ClaimAck {
                        outcome: name::CLAIM_CLOSED,
                        now: now_unix(),
                    }
                    .encode(),
                ),
                NameMode::Off => refuse(404, Code::NoSuchEntry, Some(NAME_ROUTE_OFF)),
            },
        },
        ("POST", "/name/release") => match (account, name::Release::decode(body)) {
            (None, _) => no_identity("releasing a name"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) if server.name_registration != NameMode::Off => {
                // A no-op unless the caller's account holds it; either way an
                // Ack, since resolution already discloses the holder.
                server.names.release(&req.name, &me);
                (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                )
            }
            // Off: the route is not offered. Spelled as the concrete
            // (identity, decoded) case rather than a bare wildcard arm, so the
            // route-coverage scan's end-of-dispatch sentinel keeps marking the
            // real wildcard and nothing before it.
            (Some(_), Ok(_)) => refuse(404, Code::NoSuchEntry, Some(NAME_ROUTE_OFF)),
        },
        // Answerable to anyone: the namespace is public by construction. A name
        // exists to be found, and a directory that would not say whether one is
        // taken would not be a directory.
        ("POST", "/name/resolve") => match name::Resolve::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(req) if server.name_registration != NameMode::Off => (
                200,
                "application/octet-stream",
                server.names.resolve(&req.name).encode(),
            ),
            Ok(_) => refuse(404, Code::NoSuchEntry, Some(NAME_ROUTE_OFF)),
        },
        ("POST", "/name/reverse") => match name::Reverse::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(req) if server.name_registration != NameMode::Off => (
                200,
                "application/octet-stream",
                name::Names {
                    now: now_unix(),
                    names: server.names.names_for(&req.account),
                }
                .encode(),
            ),
            Ok(_) => refuse(404, Code::NoSuchEntry, Some(NAME_ROUTE_OFF)),
        },

        // SIP-18 blobs. The exchange holds sealed chunks and no key that
        // opens one; every message here moves ciphertext, an identifier or a
        // channel, and none has a field for the key. A convenience endpoint
        // that accepted one — for thumbnailing, scanning, transcoding — would
        // break the SIP while conforming to every other rule in it.
        ("POST", "/blob/limits") => (
            200,
            "application/octet-stream",
            Limits {
                chunk: sqex_proto::blob_store::CHUNK as u32,
                max_blob: sqex_proto::blob_store::MAX_BLOB,
                max_chunks: sqex_proto::blob_store::MAX_CHUNKS,
                now: now_unix(),
            }
            .encode(),
        ),
        // The blob store's writes, one arm each so the dispatch table reads
        // as a table; all six answer the same way.
        ("POST", "/blob/begin") => blob_write(server, account, device, path, body).await,
        ("POST", "/blob/put") => blob_write(server, account, device, path, body).await,
        ("POST", "/blob/commit") => blob_write(server, account, device, path, body).await,
        ("POST", "/blob/abort") => blob_write(server, account, device, path, body).await,
        ("POST", "/blob/attach") => blob_write(server, account, device, path, body).await,
        ("POST", "/blob/detach") => blob_write(server, account, device, path, body).await,
        ("POST", "/blob/head") => match (account, ByBlob::decode(body, BL_HEAD)) {
            (None, _) => no_identity("reading a blob"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.head_blob(&me, &req.blob) {
                Ok(h) => (200, "application/octet-stream", h.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/blob/get") => match (account, GetChunk::decode(body)) {
            (None, _) => no_identity("fetching a chunk"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.get_chunk(&me, &req.blob, req.index) {
                Ok(c) => (200, "application/octet-stream", c.encode()),
                Err(e) => refused(e),
            },
        },

        // SIP-23 prekeys. The exchange hands each one-time key out at most
        // once; it cannot enforce the deletion at the other end, and is not
        // trusted to serve honestly either — a recipient rejects an envelope
        // naming an id it has already consumed. What it can do is not break
        // the property by accident.
        ("POST", "/prekey/publish") => match (device, PrekeyPublish::decode(body)) {
            (None, _) => no_identity("publishing prekeys"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.prekeys.publish(&me, &req.prekeys) {
                Ok(accepted) => {
                    let mut out = accepted.to_be_bytes().to_vec();
                    out.extend_from_slice(&now_unix().to_be_bytes());
                    (200, "application/octet-stream", out)
                }
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },
        // **Unauthorised by necessity, but not unidentified.** Anybody who may
        // seal to a device has to be able to fetch a prekey for it, so there is
        // no membership or ownership test to apply here — SIP-23 is explicit
        // about that. What there is no reason to allow is doing it *namelessly*:
        // every caller with a legitimate use already advertises an identity, and
        // each call spends a one-time prekey, so an anonymous caller could drain
        // a pool with nothing to attribute it to and nothing to rate-limit
        // against. Requiring an identity costs a legitimate caller nothing and
        // gives the drain a name.
        ("POST", "/prekey/take") => match (device, PrekeyTake::decode(body)) {
            (None, _) => no_identity("taking a prekey"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            // SIP-60: the device's account lives elsewhere; its pool is
            // there, and one prekey is taken there and handed on once.
            (Some(_), Ok(req))
                if server
                    .devices
                    .where_is(&server.devices.account_for(&req.device), &server.public_key)
                    .is_some() =>
            {
                let (home, _) = server
                    .devices
                    .where_is(&server.devices.account_for(&req.device), &server.public_key)
                    .unwrap();
                match server.reach(&home).await {
                    Some((addr, _)) => match crate::relay::take_prekey_at(
                        addr,
                        &home,
                        &server.exchange_seed,
                        &req.device,
                    )
                    .await
                    {
                        Some((status, body)) => (status, "application/octet-stream", body),
                        None => refuse(
                            404,
                            Code::NoPrekey,
                            Some("the device's home did not answer"),
                        ),
                    },
                    None => refuse(
                        404,
                        Code::NoPrekey,
                        Some("the device's home cannot be reached"),
                    ),
                }
            }
            (Some(_), Ok(req)) => (
                200,
                "application/octet-stream",
                server.prekeys.take(&req.device).encode(),
            ),
        },
        ("POST", "/prekey/count") => match device {
            None => no_identity("counting prekeys"),
            Some(me) => (
                200,
                "application/octet-stream",
                server.prekeys.count(&me).encode(),
            ),
        },
        // Discards the caller's own prekeys and says where to resume. For a
        // device that has lost the secrets behind prekeys this exchange is
        // still serving: until it publishes again `take` answers found: 0,
        // which makes a peer decline to seal rather than seal to something
        // that will never open. The body is ignored, as `count`'s is — the
        // route is the whole request.
        ("POST", "/prekey/clear") => match device {
            None => no_identity("clearing prekeys"),
            Some(me) => match server.prekeys.clear(&me) {
                Ok(cleared) => (200, "application/octet-stream", cleared.encode()),
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },

        // SIP-16 channels: a durable, ordered log. Every route here requires
        // membership or an admin role, and it is checked at the moment of the
        // call — a removed member's next fetch is refused, including one
        // already parked in a long poll.
        ("POST", "/channel/create") => match (who, ChannelCreate::decode(body)) {
            (None, _) => no_identity("creating a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                let blocked = |s: &PubKey, o: &PubKey| server.profiles.has_blocked(s, o);
                match server
                    .limit(crate::limits::Kind::Creates, &me, [0; 32])
                    .and_then(|()| server.channels.create(&me, &dev, &req, &blocked))
                {
                    Ok((created, epoch, instance)) => {
                        // Everybody invited learns of a channel that did not
                        // exist when they last looked, which is the whole of
                        // how a conversation somebody else started arrives.
                        server.tell(
                            &req.channel,
                            EventKind::Membership {
                                channel: req.channel,
                                account: me,
                                what: MEMBER_JOINED,
                            },
                        );
                        // SIP-60: and so does the home of anybody invited
                        // who lives at another exchange.
                        if created {
                            for inv in &req.invites {
                                server.tell_home(inv.account, req.channel);
                            }
                        }
                        (
                            200,
                            "application/octet-stream",
                            Created {
                                created,
                                epoch,
                                instance,
                                now: now_unix(),
                            }
                            .encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/join") => match (who, ByChannelSigned::decode(body, CH_JOIN)) {
            (None, _) => no_identity("joining a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                // SIP-43: a join at a replica is the member's own signed act,
                // carried to the origin as a post is.
                if let Some(answer) = forward_action(server, &dev, &req.channel, path, body).await {
                    return answer;
                }
                match server
                    .limit(crate::limits::Kind::Joins, &me, [0; 32])
                    .and_then(|()| server.channels.join(&me, &dev, &req.channel, &req.action))
                {
                    Ok(()) => {
                        server.tell(
                            &req.channel,
                            EventKind::Membership {
                                channel: req.channel,
                                account: me,
                                what: MEMBER_JOINED,
                            },
                        );
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/leave") => match (who, ByChannelSigned::decode(body, CH_LEAVE)) {
            (None, _) => no_identity("leaving a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                if let Some(answer) = forward_action(server, &dev, &req.channel, path, body).await {
                    return answer;
                }
                match server.channels.leave(&me, &dev, &req.channel, &req.action) {
                    Ok(()) => {
                        server.tell_including(
                            &req.channel,
                            &me,
                            EventKind::Membership {
                                channel: req.channel,
                                account: me,
                                what: MEMBER_LEFT,
                            },
                        );
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/post") => match (account, ChannelPost::decode(body)) {
            (None, _) => no_identity("posting to a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                // The device is what SIP-17 derives the sealing subkey from and
                // what counts its own messages, so it is carried separately.
                let device = device.unwrap_or(me);
                // SIP-43: a channel that lives elsewhere is posted to here
                // and ordered there. Nothing is stored on the way; the
                // origin's answer is the member's answer. SIP-56: unless the
                // copy already knows the member is muted, in which case it
                // refuses as the origin would and carries nothing.
                if let Some(origin) = server.channels.origin_of(&req.channel) {
                    if server.channels.muted(&req.channel, &me) {
                        return refused(ChannelError::Muted);
                    }
                    let Some(forwarder) = server.forwarder(&origin) else {
                        return refuse(421, Code::Replicated, None);
                    };
                    return match forwarder
                        .forward(
                            &server.exchange_seed,
                            &device,
                            server.devices.credential_of(&device).as_ref(),
                            &req,
                        )
                        .await
                    {
                        Ok(answer) => {
                            // SIP-59: a copy held for a homed account is
                            // pulled by the home task; it reads the answer
                            // back at once, as a configured replica does.
                            if answer.status == 200 {
                                server.homed.notify_one();
                            }
                            (answer.status, "application/octet-stream", answer.body)
                        }
                        Err(e) => {
                            tracing::warn!(origin = %origin, "forward failed: {e}");
                            refuse(503, Code::OriginAway, None)
                        }
                    };
                }
                let (status, body) = post_here(server, &me, &device, &req);
                (status, "application/octet-stream", body)
            }
        },
        // SIP-43: where a channel lives. Answered to anyone who may read it,
        // which is what `info` decides.
        // SIP-53: an admin moves the channel's origin -- from the origin, a
        // planned move to a replica; from a replica, to itself, its origin
        // being gone.
        ("POST", "/channel/rehome") => match (who, sqex_proto::channel::Rehome::decode(body)) {
            (None, _) => no_identity("moving a channel's origin"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                let away = server
                    .channels
                    .origin_of(&req.channel)
                    .map(|o| server.away_secs(&o));
                match server.channels.rehome(
                    &me,
                    &dev,
                    &req.channel,
                    &req.subject,
                    &req.domain,
                    &req.action,
                    away,
                    server.rehome_away_secs,
                ) {
                    Ok(seq) => {
                        server.tell_others(
                            &req.channel,
                            &me,
                            EventKind::Channel {
                                channel: req.channel,
                                last_seq: seq,
                            },
                        );
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(ChannelError::OriginReachable(secs)) => {
                        let e = ChannelError::OriginReachable(secs);
                        refuse(e.status(), e.code(), Some(&secs.to_string()))
                    }
                    Err(e) => refused(e),
                }
            }
        },
        // SIP-53: a rehome carried by a client to an exchange that has not
        // seen it -- another replica, or the old origin come back.
        ("POST", "/channel/rehomed") => match (account, sqex_proto::channel::Rehomed::decode(body))
        {
            (None, _) => no_identity("carrying a rehome"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                if let Err(e) = server.channels.info(
                    &me,
                    &device.unwrap_or(me),
                    &req.channel,
                    server.welcome.as_ref(),
                ) {
                    return refused(e);
                }
                match server
                    .channels
                    .adopt_rehome(&req.channel, &req.entry, &req.domain)
                {
                    Ok(_) => (
                        200,
                        "application/octet-stream",
                        ChannelAck { now: now_unix() }.encode(),
                    ),
                    Err(e) => refused(e),
                }
            }
        },
        // SIP-53: the caller's own entries stranded here past a rehome.
        ("POST", "/channel/stranded") => match (account, ByChannel::decode(body, CH_STRANDED)) {
            (None, _) => no_identity("asking after stranded entries"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => (
                200,
                "application/octet-stream",
                sqex_proto::channel::Stranded {
                    entries: server.channels.stranded_for(&req.channel, &me),
                }
                .encode(),
            ),
        },
        ("POST", "/channel/home") => match (account, ByChannel::decode(body, CH_HOME)) {
            (None, _) => no_identity("asking where a channel lives"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                if let Err(e) = server.channels.info(
                    &me,
                    &device.unwrap_or(me),
                    &req.channel,
                    server.welcome.as_ref(),
                ) {
                    return refused(e);
                }
                let home = match server.channels.origin_of(&req.channel) {
                    // The domain: the forwarder's where one is up, else the
                    // hint a rehome carried (SIP-53).
                    Some(origin) => Home {
                        origin,
                        domain: server
                            .forwarder(&origin)
                            .map(|f| f.domain.clone())
                            .or_else(|| server.channels.moved_to(&req.channel).map(|(_, d)| d))
                            .unwrap_or_default(),
                        former: server.channels.former_origins(&req.channel),
                    },
                    // This exchange orders it. No domain: the member is
                    // connected here already, and the exchange does not
                    // know its own name -- SIP-33 gives that to clients.
                    None => Home {
                        origin: server.public_key,
                        former: server.channels.former_origins(&req.channel),
                        domain: String::new(),
                    },
                };
                (200, "application/octet-stream", home.encode())
            }
        },
        ("POST", "/channel/info") => match (account, ByChannel::decode(body, CH_INFO)) {
            (None, _) => no_identity("reading a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                let device = device.unwrap_or(me);
                match server
                    .channels
                    .info(&me, &device, &req.channel, server.welcome.as_ref())
                {
                    Ok(mut info) => {
                        // SIP-43: where the device stands is the origin's to
                        // say. A replica tracks no chains, and a device that
                        // took this exchange's zero for an answer would sign
                        // from zero and be refused where it counts.
                        if let Some(origin) = server.channels.origin_of(&req.channel)
                            && let Some(forwarder) = server.forwarder(&origin)
                            && let Some(standing) = forwarder
                                .standing(&server.exchange_seed, &req.channel, &device)
                                .await
                        {
                            info.my_chain_seq = standing.next_chain;
                            info.my_chain_head = standing.head;
                            info.my_msg_seq = standing.msg_seq;
                        }
                        (200, "application/octet-stream", info.encode())
                    }
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/retain") => match (who, ChannelRetain::decode(body)) {
            (None, _) => no_identity("setting retention"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server.channels.retain(&me, &dev, &req) {
                Ok(()) => (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                ),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/directory") => match (who, ChannelDirectory::decode(body)) {
            (None, _) => no_identity("naming a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server.channels.set_directory(&me, &dev, &req) {
                Ok(()) => (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                ),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/close") => match (account, ByChannel::decode(body, CH_CLOSE)) {
            (None, _) => no_identity("closing a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.close(&me, &req.channel) {
                Ok(()) => (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                ),
                Err(e) => refused(e),
            },
        },
        // The only route that answers "which channels am I in". Answerable
        // about the caller and nobody else — it takes no account, so there is
        // no way to ask about somebody. Without it a private channel cannot be
        // found at all: it is absent from the directory by construction and
        // every other operation takes its 32-byte identifier as input.
        ("POST", "/channel/mine") => match (account, ChannelMine::decode(body)) {
            (None, _) => no_identity("listing your channels"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.mine(&me, req.offset) {
                Ok(mine) => (200, "application/octet-stream", mine.encode()),
                Err(e) => refused(e),
            },
        },
        // SIP-56: an admin mutes or unmutes a member -- an entry, carried
        // to the origin from a copy as a join is.
        ("POST", "/channel/mute") | ("POST", "/channel/unmute") => {
            let on = path == "/channel/mute";
            let type_byte = if on { CH_MUTE } else { CH_UNMUTE };
            match (who, ChannelByAccount::decode(body, type_byte)) {
                (None, _) => no_identity("muting a member"),
                (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
                (Some((me, dev)), Ok(req)) => {
                    if let Some(answer) =
                        forward_action(server, &dev, &req.channel, path, body).await
                    {
                        return answer;
                    }
                    match server.channels.mute(
                        &me,
                        &dev,
                        &req.channel,
                        &req.account,
                        &req.action,
                        on,
                    ) {
                        Ok(()) => {
                            server.tell(
                                &req.channel,
                                EventKind::Channel {
                                    channel: req.channel,
                                    last_seq: 0,
                                },
                            );
                            (
                                200,
                                "application/octet-stream",
                                ChannelAck { now: now_unix() }.encode(),
                            )
                        }
                        Err(e) => refused(e),
                    }
                }
            }
        }
        // SIP-56: a member reports an entry to the admins; carried to the
        // origin from a copy, held there, and the admins told.
        ("POST", "/channel/report") => match (account, sqex_proto::channel::Report::decode(body)) {
            (None, _) => no_identity("reporting"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                if let Some(answer) =
                    forward_action(server, &device.unwrap_or(me), &req.channel, path, body).await
                {
                    return answer;
                }
                let (status, body) = report_here(server, &me, &req);
                (status, "application/octet-stream", body)
            }
        },
        ("POST", "/channel/reports") => match (account, ByChannel::decode(body, CH_REPORTS)) {
            (None, _) => no_identity("reading reports"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.reports(&me, &req.channel) {
                Ok(r) => (200, "application/octet-stream", r.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/dismiss") => match (account, ByTarget::decode(body, CH_DISMISS)) {
            (None, _) => no_identity("dismissing a report"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.dismiss(&me, &req.channel, req.target) {
                Ok(()) => (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                ),
                Err(e) => refused(e),
            },
        },
        // SIP-55: this exchange's directory and its peers', each row with
        // its home. Answerable to anybody, as the directory is.
        ("POST", "/channel/search") => match sqex_proto::channel::Search::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(req) => match crate::directory::search(server, &req.query, req.offset) {
                Ok(found) => (200, "application/octet-stream", found.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/list") => match ChannelList::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(req) => match server.channels.list(&req.query, req.offset) {
                Ok(listing) => (200, "application/octet-stream", listing.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/invite") => match (who, ChannelInvite::decode(body)) {
            (None, _) => no_identity("inviting to a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                let (channel, guest) = (
                    req.channel,
                    Invitee {
                        account: req.account,
                        role: req.role,
                    },
                );
                let blocked = |s: &PubKey, o: &PubKey| server.profiles.has_blocked(s, o);
                match server.channels.invite(
                    &me,
                    &dev,
                    &channel,
                    &guest.account,
                    guest.role,
                    &req.action,
                    &blocked,
                ) {
                    Ok(()) => {
                        server.tell(
                            &channel,
                            EventKind::Membership {
                                channel,
                                account: guest.account,
                                what: MEMBER_JOINED,
                            },
                        );
                        server.tell_home(guest.account, channel);
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },
        // SIP-35: who may hold a copy of this channel, decided by an admin and
        // written into the log the members read — never by an operator out of
        // band, which would make a channel's copies invisible to the people in
        // it.
        ("POST", "/channel/replicate") => match (who, ChannelByAccount::decode(body, CH_REPLICATE))
        {
            (None, _) => no_identity("authorising replication"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server.channels.replicate(
                &me,
                &dev,
                &req.channel,
                &req.account,
                &req.action,
                true,
            ) {
                Ok(()) => {
                    server.tell(
                        &req.channel,
                        EventKind::Channel {
                            channel: req.channel,
                            last_seq: 0,
                        },
                    );
                    (
                        200,
                        "application/octet-stream",
                        ChannelAck { now: now_unix() }.encode(),
                    )
                }
                Err(e) => refused(e),
            },
        },
        // **The end of a subscription, and not a recall.** What a replica
        // already holds was lawfully obtained and no protocol can unsend it.
        ("POST", "/channel/unreplicate") => {
            match (who, ChannelByAccount::decode(body, CH_UNREPLICATE)) {
                (None, _) => no_identity("withdrawing replication"),
                (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
                (Some((me, dev)), Ok(req)) => match server.channels.replicate(
                    &me,
                    &dev,
                    &req.channel,
                    &req.account,
                    &req.action,
                    false,
                ) {
                    Ok(()) => {
                        server.tell(
                            &req.channel,
                            EventKind::Channel {
                                channel: req.channel,
                                last_seq: 0,
                            },
                        );
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                },
            }
        }

        ("POST", "/channel/remove") => match (who, ChannelByAccount::decode(body, CH_REMOVE)) {
            (None, _) => no_identity("removing from a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                match server
                    .channels
                    .remove(&me, &dev, &req.channel, &req.account, &req.action)
                {
                    Ok(()) => {
                        // The removed account is told too. It is the one party to
                        // this that cannot find out by asking again.
                        server.tell_including(
                            &req.channel,
                            &req.account,
                            EventKind::Membership {
                                channel: req.channel,
                                account: req.account,
                                what: MEMBER_REMOVED,
                            },
                        );
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },

        // SIP-17 channel keys. The exchange stores envelopes opaquely, serves
        // each only to the recipient it names, and holds no key that opens one.
        ("POST", "/channel/key/put") => match (who, KeyPut::decode(body)) {
            (None, _) => no_identity("publishing channel keys"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                // SIP-60: a rotation made at a copy is the member's own
                // signed act with the envelopes it sealed, carried to the
                // origin as a post is -- without it a member reading a
                // sealed channel through a copy could never re-key it.
                if let Some(answer) = forward_action(server, &dev, &req.channel, path, body).await {
                    return answer;
                }
                // A device is resolved to its account here rather than inside
                // the channel store, which keeps that store free of any
                // knowledge of the registry.
                let account_of = |d: &PubKey| server.devices.account_for(d);
                // SIP-17: a member who is not an admin may advance the epoch
                // when it revoked one of its own devices since this one was
                // minted. The exchange holds both facts; neither store needs
                // to know about the other.
                let revoked_since = |a: &PubKey, since: u64| server.devices.revoked_since(a, since);
                match server
                    .channels
                    .put_keys(&me, &dev, &req, &account_of, &revoked_since)
                {
                    Ok(ack) => (200, "application/octet-stream", ack.encode()),
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/key/get") => match (account, device, KeyGet::decode(body)) {
            (None, _, _) | (_, None, _) => no_identity("collecting channel keys"),
            (_, _, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Some(mine), Ok(req)) => {
                match server
                    .channels
                    .get_keys(&me, &mine, &req.channel, req.since_epoch)
                {
                    Ok(got) => (200, "application/octet-stream", got.encode()),
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/key/missing") => match (account, ByChannel::decode(body, CH_MISSING)) {
            (None, _) => no_identity("listing stranded devices"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                let has = |d: &PubKey| server.prekeys.has_any(d);
                // An account with none registered is its own device (SIP-22).
                let devices_of = |a: &PubKey| {
                    server
                        .devices
                        .list(a)
                        .map(|d| {
                            if d.devices.is_empty() {
                                vec![*a]
                            } else {
                                d.devices.iter().map(|x| x.device).collect()
                            }
                        })
                        .unwrap_or_else(|_| vec![*a])
                };
                match server
                    .channels
                    .missing_keys(&me, &req.channel, &devices_of, &has)
                {
                    Ok(absent) => (200, "application/octet-stream", absent.encode()),
                    Err(e) => refused(e),
                }
            }
        },

        ("POST", "/channel/cursor") => match (account, ChannelCursor::decode(body)) {
            (None, _) => no_identity("setting a read mark"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                match server
                    .channels
                    .set_cursor(&me, &req.channel, req.read, req.receipts)
                {
                    Ok(()) => {
                        // SIP-54: recorded here for this exchange's readers,
                        // and carried to the origin for everybody else's.
                        // Best effort: a mark the origin did not get is a
                        // mark the next one covers.
                        let _ =
                            forward_action(server, &device.unwrap_or(me), &req.channel, path, body)
                                .await;
                        server.tell_others(
                            &req.channel,
                            &me,
                            EventKind::Cursor {
                                channel: req.channel,
                            },
                        );
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/cursors") => match (account, ByChannel::decode(body, CH_CURSORS)) {
            (None, _) => no_identity("reading marks"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.cursors(&me, &req.channel) {
                Ok(marks) => (200, "application/octet-stream", marks.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/redact") => match (account, ByTarget::decode(body, CH_REDACT)) {
            (None, _) => no_identity("redacting an entry"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                // SIP-57: at a copy, carried to the origin; the tombstone
                // comes back on the next pull.
                if let Some(answer) =
                    forward_action(server, &device.unwrap_or(me), &req.channel, path, body).await
                {
                    return answer;
                }
                match server.channels.redact(&me, &req.channel, req.target) {
                    Ok(()) => {
                        // No sequence number to name: a redaction changes an entry
                        // that is already numbered. Zero is the wire's word for
                        // "fetch and see".
                        server.tell(
                            &req.channel,
                            EventKind::Channel {
                                channel: req.channel,
                                last_seq: 0,
                            },
                        );
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },
        // Relayed to the other members and stored nowhere. An exchange that
        // dropped every one of these would still conform.
        ("POST", "/channel/signal") => match (who, SignalOut::decode(body)) {
            (None, _) => no_identity("signalling"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                match server
                    .limit(crate::limits::Kind::Signals, &dev, req.channel)
                    .and_then(|()| {
                        server
                            .channels
                            .signal(&me, &dev, &req.channel, req.kind, &req.body)
                    }) {
                    Ok(()) => {
                        // SIP-54: delivered here at once, and carried to
                        // the origin, whose log every copy pulls.
                        let _ = forward_action(server, &dev, &req.channel, path, body).await;
                        // Not to the sender: a client does not need telling
                        // that its own keyboard is being used.
                        server.tell_others(
                            &req.channel,
                            &me,
                            EventKind::Signal {
                                channel: req.channel,
                            },
                        );
                        // SIP-36. A ringing phone is not a keyboard, and a
                        // client that has quietened its signal polling —
                        // which SIP-30 exists to let it do — would otherwise
                        // hear this at whatever cadence it saved.
                        //
                        // **The signal is what the exchange can see, and the
                        // entry is not.** SIP-36's flow reads as though the
                        // invitation drives this event, but in a private
                        // channel the body is sealed under SIP-17 and the
                        // exchange cannot tell a call from a sentence. The
                        // ring state is in the clear and carries the
                        // invitation's `seq`, so it is what this is derived
                        // from — and it discloses nothing the signal did not
                        // already disclose by existing.
                        if let Ok(Some(Signal::CallState { target, state, .. })) =
                            Signal::decode(&req.body)
                            && state == RING_RINGING
                        {
                            server.tell_others(
                                &req.channel,
                                &me,
                                EventKind::Ringing {
                                    channel: req.channel,
                                    seq: target,
                                },
                            );
                        }
                        (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },

        // SIP-35 peering. **Every refusal here is the same refusal.** These
        // routes are reachable by strangers, and a reply that varied by cause
        // would make them an existence oracle for private channels — the same
        // rule SIP-24 gives its admission endpoint and SIP-4 a withheld beacon.
        // So an unknown peer, an absent channel, a channel that exists and is
        // not replicated to this peer, and an origin that cannot receipt all
        // produce one 404 with nothing in it.
        ("POST", "/peer/hello") => match (peer.identity, PeerHello::decode(body)) {
            (Some(who), Ok(hello)) if server.peering(&who).is_some() => {
                let hi = Hi {
                    now: now_unix(),
                    version: hello.version.min(PEER_VERSION),
                    exchange: server.public_key,
                    window_secs: sqex_proto::channel::MAX_RETENTION,
                };
                (200, "application/octet-stream", hi.encode())
            }
            _ => peering_refused(),
        },
        ("POST", "/peer/pull") => match (peer.identity, PeerPull::decode(body)) {
            (Some(who), Ok(req))
                if server
                    .peering(&who)
                    .is_some_and(|p| server.may_pull(&p, &req.channel)) =>
            {
                match server.channels.pull(&req.channel, req.since, req.max) {
                    Ok(pulled) => (200, "application/octet-stream", pulled.encode()),
                    // Not `refused(e)`: the cause is exactly what must not
                    // leak. A peer that got this far is authorised, and
                    // anything still wrong is this exchange's problem.
                    Err(_) => peering_refused(),
                }
            }
            _ => peering_refused(),
        },

        // SIP-43: a channel's shape, for a peer that may pull it. The
        // constitution's digest covers visibility, name and topic; the
        // origin states them so a replica need not guess private.
        ("POST", "/peer/channel") => match (peer.identity, PullShape::decode(body)) {
            (Some(who), Ok(req))
                if server
                    .peering(&who)
                    .is_some_and(|p| server.may_pull(&p, &req.channel)) =>
            {
                match server.channels.shape_of(&req.channel) {
                    Ok(shape) => (200, "application/octet-stream", shape.encode()),
                    Err(_) => peering_refused(),
                }
            }
            _ => peering_refused(),
        },

        // SIP-43: where a device stands in a channel, for a replica whose
        // member asked it. Gated as a pull is.
        ("POST", "/peer/standing") => match (peer.identity, PullStanding::decode(body)) {
            (Some(who), Ok(req))
                if server
                    .peering(&who)
                    .is_some_and(|p| server.may_pull(&p, &req.channel)) =>
            {
                match server.channels.device_standing(&req.channel, &req.device) {
                    Ok(standing) => (200, "application/octet-stream", standing.encode()),
                    Err(_) => peering_refused(),
                }
            }
            _ => peering_refused(),
        },

        // SIP-54: a replica pulls every member's marks, and the signal log.
        ("POST", "/peer/cursors") => {
            match (peer.identity, sqex_proto::peer::PullCursors::decode(body)) {
                (Some(who), Ok(req))
                    if server
                        .peering(&who)
                        .is_some_and(|p| server.may_pull(&p, &req.channel)) =>
                {
                    match server.channels.all_cursors(&req.channel) {
                        Ok(marks) => (200, "application/octet-stream", marks.encode()),
                        Err(_) => peering_refused(),
                    }
                }
                _ => peering_refused(),
            }
        }
        ("POST", "/peer/signals") => {
            match (peer.identity, sqex_proto::peer::PullSignals::decode(body)) {
                (Some(who), Ok(req))
                    if server
                        .peering(&who)
                        .is_some_and(|p| server.may_pull(&p, &req.channel)) =>
                {
                    (
                        200,
                        "application/octet-stream",
                        server
                            .channels
                            .signals_since(&req.channel, req.since)
                            .encode(),
                    )
                }
                _ => peering_refused(),
            }
        }
        // SIP-57: what the origin redacted since a time, for a copy.
        ("POST", "/peer/tombstones") => match (
            peer.identity,
            sqex_proto::peer::PullTombstones::decode(body),
        ) {
            (Some(who), Ok(req))
                if server
                    .peering(&who)
                    .is_some_and(|p| server.may_pull(&p, &req.channel)) =>
            {
                (
                    200,
                    "application/octet-stream",
                    sqex_proto::peer::Tombstones {
                        now: now_unix(),
                        redacted: server.channels.tombstones_since(&req.channel, req.since),
                    }
                    .encode(),
                )
            }
            _ => peering_refused(),
        },
        // SIP-53: the new origin, or another replica, telling this exchange
        // a channel moved. Gated as a pull is.
        ("POST", "/peer/rehomed") => {
            match (peer.identity, sqex_proto::channel::Rehomed::decode(body)) {
                (Some(who), Ok(req)) if server.peering(&who).is_some() => {
                    if let Err(e) = server.peer_write(&who) {
                        return refused(e);
                    }
                    match server
                        .channels
                        .adopt_rehome(&req.channel, &req.entry, &req.domain)
                    {
                        Ok(_) => (
                            200,
                            "application/octet-stream",
                            ChannelAck { now: now_unix() }.encode(),
                        ),
                        Err(_) => peering_refused(),
                    }
                }
                _ => peering_refused(),
            }
        }
        // SIP-43: a member's post carried by a replica. The gate is SIP-35's:
        // a peer on the list, authorised for the channel or acting for the
        // poster, and one refusal for everything else. The account is this
        // exchange's own reading of the device; the replica's word is not
        // asked for.
        // SIP-59: which channels this exchange orders an account is in, for
        // the peer that is the account's home or is configured for it.
        ("POST", "/peer/mine") => match (peer.identity, PullMine::decode(body)) {
            (Some(who), Ok(req))
                if server
                    .peering(&who)
                    .is_some_and(|p| server.acts_for(&p, &req.account)) =>
            {
                (
                    200,
                    "application/octet-stream",
                    Mine {
                        now: now_unix(),
                        channels: server.channels.ordered_with(&req.account),
                    }
                    .encode(),
                )
            }
            _ => peering_refused(),
        },
        // SIP-59: a Move carried by the account's home. Recorded as
        // `/account/move` records it; nothing about the carrier is checked
        // beyond the peer list, since the signature is the authority.
        ("POST", "/peer/moved") => match (peer.identity, PeerMoved::decode(body)) {
            (Some(who), Ok(req)) if server.peering(&who).is_some() => {
                if let Err(e) = server.peer_write(&who) {
                    return refused(e);
                }
                record_move(server, &req.mv, &req.domain, &[])
            }
            _ => peering_refused(),
        },
        // SIP-61: a replica waits here for any of its channels to change.
        // Channels the peer may not pull are left out of every answer and
        // never waited on, so the answer says nothing about them.
        ("POST", "/peer/wait") => match (peer.identity, PeerWait::decode(body)) {
            (Some(who), Ok(req)) if server.peering(&who).is_some() => {
                let p = server.peering(&who).unwrap();
                // SIP-63: past the caller's share of held waits, the
                // uniform refusal -- which a replica reads as "does not
                // wait" and polls instead, rather than looping on an
                // empty answer.
                let Some(_held) = server.hold_wait(who) else {
                    return peering_refused();
                };
                let watched: Vec<([u8; 32], u64)> = req
                    .channels
                    .iter()
                    .filter(|(c, _)| server.may_pull(&p, c))
                    .cloned()
                    .collect();
                let secs = req.wait_secs.min(sqex_proto::channel::MAX_WAIT);
                let changed = wait_for_changes(server, &watched, secs).await;
                (
                    200,
                    "application/octet-stream",
                    Changed {
                        now: now_unix(),
                        channels: changed,
                    }
                    .encode(),
                )
            }
            _ => peering_refused(),
        },
        // SIP-60: an origin says it put one of the accounts homed here in a
        // channel. Acted on only for an account whose own Move names this
        // exchange: the origin hint is kept and the home task pulls, carrying
        // the Move first.
        ("POST", "/peer/invited") => match (peer.identity, PeerInvited::decode(body)) {
            (Some(who), Ok(req)) if server.peering(&who).is_some() => {
                if let Err(e) = server.peer_write(&who) {
                    return refused(e);
                }
                let domain = req.domain.trim().to_ascii_lowercase();
                if server
                    .devices
                    .add_home_origin(&req.account, &who, &domain, &server.public_key)
                {
                    tracing::info!(account = %req.account, origin = %who, "told of a channel at another exchange");
                    server.homed.notify_one();
                } else {
                    tracing::debug!(account = %req.account, origin = %who, "told of a channel for an account with no move here");
                }
                (
                    200,
                    "application/octet-stream",
                    ChannelAck { now: now_unix() }.encode(),
                )
            }
            _ => peering_refused(),
        },
        // SIP-59: a forward wrapped with the device's credential, for a
        // device this origin may never have seen. Verified under the
        // account the credential names and registered as the account's
        // own act, then handled as the forward inside it.
        ("POST", "/peer/forward") if body.first() == Some(&sqex_proto::peer::TYPE_CARRIED) => {
            match (peer.identity, Carried::decode(body)) {
                (Some(who), Ok(carried)) if server.peering(&who).is_some() => {
                    let device = match carried.inner.first() {
                        Some(&sqex_proto::peer::TYPE_FORWARD) => {
                            PeerForward::decode(&carried.inner).map(|f| f.device)
                        }
                        _ => ForwardAction::decode(&carried.inner).map(|f| f.device),
                    };
                    let Ok(device) = device else {
                        return peering_refused();
                    };
                    if carried.credential.delegate != device {
                        return peering_refused();
                    }
                    // SIP-63: a registration this exchange had not seen is
                    // a write the caller caused, counted against it.
                    if server.devices.account_for(&device) == device
                        && let Err(e) = server.peer_write(&who)
                    {
                        return refused(e);
                    }
                    if server
                        .devices
                        .register(&carried.credential.delegate, &carried.credential)
                        .is_err()
                    {
                        return peering_refused();
                    }
                    server.resync_transport();
                    Box::pin(route(server, method, path, &carried.inner, peer)).await
                }
                _ => peering_refused(),
            }
        }
        ("POST", "/peer/forward") => match (peer.identity, PeerForward::decode(body)) {
            (Some(who), Ok(req)) => {
                let account = server.devices.account_for(&req.device);
                let allowed = server
                    .peering(&who)
                    .is_some_and(|p| server.may_forward(&p, &req.post.channel, &account));
                if !allowed {
                    return peering_refused();
                }
                let (status, body) = post_here(server, &account, &req.device, &req.post);
                (
                    200,
                    "application/octet-stream",
                    Forwarded { status, body }.encode(),
                )
            }
            // A join or a leave, the member's own signed act. Routed here by
            // hand to the two handlers a member may reach this way, and to
            // nothing else: this is not a proxy.
            (Some(who), Err(_)) if body.first() == Some(&sqex_proto::peer::TYPE_FORWARD_ACTION) => {
                let Ok(req) = ForwardAction::decode(body) else {
                    return peering_refused();
                };
                let account = server.devices.account_for(&req.device);
                let (status, body) = match req.path.as_str() {
                    "/channel/join" => match ByChannelSigned::decode(&req.body, CH_JOIN) {
                        Ok(r)
                            if server
                                .peering(&who)
                                .is_some_and(|p| server.may_forward(&p, &r.channel, &account)) =>
                        {
                            match server
                                .limit(crate::limits::Kind::Joins, &account, [0; 32])
                                .and_then(|()| {
                                    server.channels.join(
                                        &account,
                                        &req.device,
                                        &r.channel,
                                        &r.action,
                                    )
                                }) {
                                Ok(()) => {
                                    server.tell(
                                        &r.channel,
                                        EventKind::Membership {
                                            channel: r.channel,
                                            account,
                                            what: MEMBER_JOINED,
                                        },
                                    );
                                    (200, ChannelAck { now: now_unix() }.encode())
                                }
                                Err(e) => {
                                    let (s, _, b) = refused(e);
                                    (s, b)
                                }
                            }
                        }
                        _ => return peering_refused(),
                    },
                    "/channel/leave" => match ByChannelSigned::decode(&req.body, CH_LEAVE) {
                        Ok(r)
                            if server
                                .peering(&who)
                                .is_some_and(|p| server.may_forward(&p, &r.channel, &account)) =>
                        {
                            match server.channels.leave(
                                &account,
                                &req.device,
                                &r.channel,
                                &r.action,
                            ) {
                                Ok(()) => {
                                    server.tell_including(
                                        &r.channel,
                                        &account,
                                        EventKind::Membership {
                                            channel: r.channel,
                                            account,
                                            what: MEMBER_LEFT,
                                        },
                                    );
                                    (200, ChannelAck { now: now_unix() }.encode())
                                }
                                Err(e) => {
                                    let (s, _, b) = refused(e);
                                    (s, b)
                                }
                            }
                        }
                        _ => return peering_refused(),
                    },
                    // SIP-56: an admin's mute, or a member's report, from a copy.
                    "/channel/mute" | "/channel/unmute" => {
                        let on = req.path == "/channel/mute";
                        match ChannelByAccount::decode(
                            &req.body,
                            if on { CH_MUTE } else { CH_UNMUTE },
                        ) {
                            Ok(r)
                                if server.peering(&who).is_some_and(|p| {
                                    server.may_forward(&p, &r.channel, &account)
                                }) =>
                            {
                                match server.channels.mute(
                                    &account,
                                    &req.device,
                                    &r.channel,
                                    &r.account,
                                    &r.action,
                                    on,
                                ) {
                                    Ok(()) => {
                                        server.tell(
                                            &r.channel,
                                            EventKind::Channel {
                                                channel: r.channel,
                                                last_seq: 0,
                                            },
                                        );
                                        (200, ChannelAck { now: now_unix() }.encode())
                                    }
                                    Err(e) => {
                                        let (s, _, b) = refused(e);
                                        (s, b)
                                    }
                                }
                            }
                            _ => return peering_refused(),
                        }
                    }
                    "/channel/report" => match sqex_proto::channel::Report::decode(&req.body) {
                        Ok(r)
                            if server
                                .peering(&who)
                                .is_some_and(|p| server.may_forward(&p, &r.channel, &account)) =>
                        {
                            report_here(server, &account, &r)
                        }
                        _ => return peering_refused(),
                    },
                    // SIP-57: a redaction made at a copy, by the author or an
                    // admin as the origin judges them.
                    "/channel/redact" => match ByTarget::decode(&req.body, CH_REDACT) {
                        Ok(r)
                            if server
                                .peering(&who)
                                .is_some_and(|p| server.may_forward(&p, &r.channel, &account)) =>
                        {
                            match server.channels.redact(&account, &r.channel, r.target) {
                                Ok(()) => {
                                    server.tell(
                                        &r.channel,
                                        EventKind::Channel {
                                            channel: r.channel,
                                            last_seq: 0,
                                        },
                                    );
                                    (200, ChannelAck { now: now_unix() }.encode())
                                }
                                Err(e) => {
                                    let (s, _, b) = refused(e);
                                    (s, b)
                                }
                            }
                        }
                        _ => return peering_refused(),
                    },
                    // SIP-54: a member's read mark, set at a copy.
                    "/channel/cursor" => match ChannelCursor::decode(&req.body) {
                        Ok(r)
                            if server
                                .peering(&who)
                                .is_some_and(|p| server.may_forward(&p, &r.channel, &account)) =>
                        {
                            match server
                                .channels
                                .set_cursor_forwarded(&account, &r.channel, r.read, r.receipts)
                            {
                                Ok(()) => {
                                    server.tell_others(
                                        &r.channel,
                                        &account,
                                        EventKind::Cursor { channel: r.channel },
                                    );
                                    (200, ChannelAck { now: now_unix() }.encode())
                                }
                                Err(e) => {
                                    let (s, _, b) = refused(e);
                                    (s, b)
                                }
                            }
                        }
                        _ => return peering_refused(),
                    },
                    // SIP-54: a signal sent at a copy, queued here and logged
                    // for every copy to pull.
                    "/channel/signal" => match SignalOut::decode(&req.body) {
                        Ok(r)
                            if server
                                .peering(&who)
                                .is_some_and(|p| server.may_forward(&p, &r.channel, &account)) =>
                        {
                            match server
                                .limit(crate::limits::Kind::Signals, &req.device, r.channel)
                                .and_then(|()| {
                                    server.channels.signal(
                                        &account,
                                        &req.device,
                                        &r.channel,
                                        r.kind,
                                        &r.body,
                                    )
                                }) {
                                Ok(()) => {
                                    server.tell_others(
                                        &r.channel,
                                        &account,
                                        EventKind::Signal { channel: r.channel },
                                    );
                                    if let Ok(Some(Signal::CallState { target, state, .. })) =
                                        Signal::decode(&r.body)
                                        && state == RING_RINGING
                                    {
                                        server.tell_others(
                                            &r.channel,
                                            &account,
                                            EventKind::Ringing {
                                                channel: r.channel,
                                                seq: target,
                                            },
                                        );
                                    }
                                    (200, ChannelAck { now: now_unix() }.encode())
                                }
                                Err(e) => {
                                    let (s, _, b) = refused(e);
                                    (s, b)
                                }
                            }
                        }
                        _ => return peering_refused(),
                    },
                    // An upload, a chunk, its commit or abort, an attach or a
                    // detach: the blob store's own checks apply -- an upload
                    // is its uploader's, an attach a member's -- and the
                    // peer gate is the channel's where the request names one.
                    "/blob/begin" | "/blob/put" | "/blob/commit" | "/blob/abort"
                    | "/blob/attach" | "/blob/detach" => {
                        let named = match req.path.as_str() {
                            "/blob/begin" => BlobBegin::decode(&req.body).ok().map(|b| b.channel),
                            "/blob/attach" => ByChannelBlob::decode(&req.body, BL_ATTACH)
                                .ok()
                                .map(|b| b.channel),
                            "/blob/detach" => ByChannelBlob::decode(&req.body, BL_DETACH)
                                .ok()
                                .map(|b| b.channel),
                            _ => None,
                        };
                        let allowed = server.peering(&who).is_some_and(|p| match named {
                            Some(channel) => server.may_forward(&p, &channel, &account),
                            None => true,
                        });
                        if !allowed {
                            return peering_refused();
                        }
                        blob_here(server, &account, &req.path, &req.body)
                    }
                    // SIP-60: a rotation from a copy -- the member's signed
                    // action and the envelopes it sealed.
                    "/channel/key/put" => match KeyPut::decode(&req.body) {
                        Ok(r)
                            if server
                                .peering(&who)
                                .is_some_and(|p| server.may_forward(&p, &r.channel, &account)) =>
                        {
                            let account_of = |d: &PubKey| server.devices.account_for(d);
                            let revoked_since =
                                |a: &PubKey, since: u64| server.devices.revoked_since(a, since);
                            match server.channels.put_keys(
                                &account,
                                &req.device,
                                &r,
                                &account_of,
                                &revoked_since,
                            ) {
                                Ok(ack) => (200, ack.encode()),
                                Err(e) => {
                                    let (s, _, b) = refused(e);
                                    (s, b)
                                }
                            }
                        }
                        _ => return peering_refused(),
                    },
                    // SIP-60: a create carried from the creator's home -- a
                    // direct message at the lower key's home. The creator's
                    // own signed act, under the acts-for gate for the creator.
                    "/channel/create" => match ChannelCreate::decode(&req.body) {
                        Ok(r)
                            if server
                                .peering(&who)
                                .is_some_and(|p| server.acts_for(&p, &account)) =>
                        {
                            let blocked =
                                |s: &PubKey, o: &PubKey| server.profiles.has_blocked(s, o);
                            match server
                                .limit(crate::limits::Kind::Creates, &account, [0; 32])
                                .and_then(|()| {
                                    server.channels.create(&account, &req.device, &r, &blocked)
                                }) {
                                Ok((created, epoch, instance)) => {
                                    server.tell(
                                        &r.channel,
                                        EventKind::Membership {
                                            channel: r.channel,
                                            account,
                                            what: MEMBER_JOINED,
                                        },
                                    );
                                    if created {
                                        server.tell_home(account, r.channel);
                                        for inv in &r.invites {
                                            server.tell_home(inv.account, r.channel);
                                        }
                                    }
                                    (
                                        200,
                                        Created {
                                            created,
                                            epoch,
                                            instance,
                                            now: now_unix(),
                                        }
                                        .encode(),
                                    )
                                }
                                Err(e) => {
                                    let (s, _, b) = refused(e);
                                    (s, b)
                                }
                            }
                        }
                        _ => return peering_refused(),
                    },
                    // SIP-59: the account's signed withdrawal of one of its
                    // devices, carried by its home to an origin that
                    // registered the device from a carried credential. Only
                    // the attested form: an unsigned revocation is the
                    // caller's word, and the caller here is a peer.
                    "/device/revoke" => match DeviceRevoke::decode(&req.body) {
                        Ok(r)
                            if r.revocation.is_some()
                                && server
                                    .peering(&who)
                                    .is_some_and(|p| server.acts_for(&p, &account)) =>
                        {
                            match server.devices.revoke(
                                &req.device,
                                &r.device,
                                r.revocation.as_ref(),
                            ) {
                                Ok(()) => {
                                    server.resync_transport();
                                    (200, ChannelAck { now: now_unix() }.encode())
                                }
                                Err(e) => {
                                    let (s, _, b) = refuse(e.status(), e.code(), None);
                                    (s, b)
                                }
                            }
                        }
                        _ => return peering_refused(),
                    },
                    _ => return peering_refused(),
                };
                (
                    200,
                    "application/octet-stream",
                    Forwarded { status, body }.encode(),
                )
            }
            _ => peering_refused(),
        },

        // SIP-35: the proof, for a client whose fetch was refused because this
        // exchange holds two histories for one position. **Served rather than
        // resolved**: a replica has no basis to decide which branch is real,
        // and picking one would turn evidence into a disagreement between two
        // honest-looking servers. Open to any member, because the artifact is
        // checkable by anybody holding the origin's public key and is worth
        // nothing kept private.
        ("POST", "/channel/equivocation") => {
            match (account, ByChannel::decode(body, CH_EQUIVOCATION)) {
                (None, _) => no_identity("reading an equivocation"),
                (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
                // Membership, which the comment above always claimed and the
                // code did not check: `Some(_)` bound the account and discarded
                // it, so any identity naming a channel id — including a direct
                // message's, computable from two public keys — learned whether
                // this exchange holds a replica of it, its `instance`, and two
                // timestamps. A non-member is refused exactly as for a channel
                // that is not here, which is also the answer when there is no
                // equivocation, so the three are one answer.
                (Some(who), Ok(req)) => match server.channels.equivocation_seen(&who, &req.channel)
                {
                    Some(proof) => (200, "application/octet-stream", proof),
                    None => refuse(404, Code::NoSuchChannel, None),
                },
            }
        }

        ("POST", "/peer/envelopes") => match (peer.identity, PullEnvelopes::decode(body)) {
            (Some(who), Ok(req))
                if server
                    .peering(&who)
                    .is_some_and(|p| server.may_pull(&p, &req.channel)) =>
            {
                match server
                    .channels
                    .pull_envelopes(&req.channel, req.since_epoch)
                {
                    Ok(got) => (200, "application/octet-stream", got.encode()),
                    Err(_) => peering_refused(),
                }
            }
            _ => peering_refused(),
        },
        ("POST", "/peer/blobs") => match (peer.identity, PullBlob::decode(body)) {
            (Some(who), Ok(req))
                if server
                    .peering(&who)
                    .is_some_and(|p| server.may_pull(&p, &req.channel)) =>
            {
                match server
                    .channels
                    .pull_blob(&req.channel, &req.blob, req.chunk)
                {
                    Ok(got) => (200, "application/octet-stream", got.encode()),
                    Err(_) => peering_refused(),
                }
            }
            _ => peering_refused(),
        },
        // A peer is not a person and has no standing of its own: what it may
        // hold is what the members of the channels it carries could already
        // see. So a withheld profile is served to it only where the subject is
        // in one of those channels, which is SIP-21's "shares a channel" rule
        // read through the authorisation.
        ("POST", "/peer/records") => match (peer.identity, PullRecord::decode(body)) {
            (Some(who), Ok(req)) if server.peering(&who).is_some() => {
                match server.profiles.get(&who, &req.account, &|_, subject| {
                    server.channels.shares_replicated(&who, subject)
                }) {
                    Ok(got) => (200, "application/octet-stream", got.encode()),
                    Err(_) => peering_refused(),
                }
            }
            _ => peering_refused(),
        },

        // SIP-52: what a device that has been away needs, in one answer
        // composed from the routes around it. See `crate::catchup`.
        ("POST", "/channel/catchup") => {
            match (account, device, sqex_proto::catchup::Catchup::decode(body)) {
                (None, _, _) | (_, None, _) => no_identity("catching up"),
                (_, _, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
                (Some(me), Some(mine), Ok(req)) => (
                    200,
                    "application/octet-stream",
                    crate::catchup::answer(
                        &server.channels,
                        &server.prekeys,
                        &me,
                        &mine,
                        &req,
                        now_unix(),
                    )
                    .encode(),
                ),
            }
        }
        ("POST", "/channel/fetch") => match (account, ChannelFetch::decode(body)) {
            (None, _) => no_identity("fetching entries"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                match fetch_waiting(server, &me, &device.unwrap_or(me), &req).await {
                    Ok(entries) => (200, "application/octet-stream", entries.encode()),
                    Err(e) => refused(e),
                }
            }
        },

        // SIP-49: a join that names relay peers is answered with homes, and
        // the room is shared with those peers from then on. The plain join
        // is SIP-13's, answered as it always was.
        ("POST", "/room/join") if body.first() == Some(&sqex_proto::room::TYPE_JOIN_SHARED) => {
            match (peer.identity, sqex_proto::room::JoinShared::decode(body)) {
                (None, _) => no_identity("joining a room"),
                (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
                (Some(me), Ok(join)) => {
                    if let Some(stranger) = join.share.iter().find(|k| !server.peers_with(k)) {
                        return refuse(
                            403,
                            Code::NotYours,
                            Some(&format!(
                                "{stranger} is not an exchange this one federates with"
                            )),
                        );
                    }
                    match server
                        .rooms
                        .join_shared(join.handle, me, join.proof, &join.share)
                    {
                        Ok((homed, due)) => {
                            if due {
                                let server = Arc::clone(server);
                                tokio::spawn(async move {
                                    crate::relay::share_room(&server, join.handle).await;
                                });
                            }
                            (200, "application/octet-stream", homed.encode())
                        }
                        Err(e) => refuse(507, e.code(), None),
                    }
                }
            }
        }
        ("POST", "/room/join") => match (peer.identity, RoomJoin::decode(body)) {
            (None, _) => no_identity("joining a room"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(join)) => match server.rooms.join(join.handle, me, join.proof) {
                Ok(roster) => (200, "application/octet-stream", roster.encode()),
                Err(e) => refuse(507, e.code(), None),
            },
        },
        ("POST", "/room/leave") => match (peer.identity, RoomLeave::decode(body)) {
            (None, _) => no_identity("leaving a room"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(leave)) => {
                let was_there = server.rooms.leave(&leave.handle, &me);
                // SIP-49: the peers are told a leave at once rather than a
                // TTL later.
                if was_there && server.rooms.is_shared(&leave.handle) {
                    let server = Arc::clone(server);
                    tokio::spawn(async move {
                        crate::relay::share_room(&server, leave.handle).await;
                    });
                }
                (200, "application/octet-stream", Left { was_there }.encode())
            }
        },

        // SIP-5 store-and-forward mailbox. Every operation is by the caller's
        // transport identity (SIP-3): a sender is whoever connected, and a
        // mailbox belongs to whoever can connect as its key. Nothing is signed.
        ("POST", "/mailbox/send") => match (peer.identity, MailSend::decode(body)) {
            (None, _) => no_identity("sending"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            // SIP-59: a recipient that lives elsewhere is named, not stored
            // for -- a mailbox in two places is two exchanges' word.
            (Some(_), Ok(msg)) if server.moved_away(&msg.recipient).is_some() => {
                server.moved_away(&msg.recipient).unwrap()
            }
            (Some(from), Ok(msg)) => match server.mailbox.send(from, msg.recipient, msg.sealed) {
                Ok((id, now)) => (
                    200,
                    "application/octet-stream",
                    SendAck { id, now }.encode(),
                ),
                Err(e) => refuse(507, e.code(), None),
            },
        },
        ("POST", "/mailbox/list") => match peer.identity {
            None => no_identity("listing"),
            Some(me) => (
                200,
                "application/octet-stream",
                server.mailbox.list(&me).encode(),
            ),
        },
        ("POST", "/mailbox/fetch") => match (peer.identity, ById::decode(body, TYPE_FETCH)) {
            (None, _) => no_identity("fetching"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                let out = match server.mailbox.fetch(&me, req.id) {
                    Some((sender, received, sealed)) => Fetched {
                        found: true,
                        sender,
                        received,
                        sealed,
                    },
                    None => Fetched::none(),
                };
                (200, "application/octet-stream", out.encode())
            }
        },
        ("POST", "/mailbox/delete") => match (peer.identity, ById::decode(body, TYPE_DELETE)) {
            (None, _) => no_identity("deleting"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                let deleted = server.mailbox.delete(&me, req.id);
                (200, "application/octet-stream", vec![u8::from(deleted)])
            }
        },
        ("POST", "/mailbox/status") => match (peer.identity, ById::decode(body, TYPE_STATUS)) {
            (None, _) => no_identity("asking"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => (
                200,
                "application/octet-stream",
                server.mailbox.status(&me, req.id).encode(),
            ),
        },

        // SIP-12 relayed sessions. Consent is strictly mutual: an open
        // discloses nothing until the named peer has asked in return. The
        // exchange relays frames it cannot read — the session key needs a
        // static private key from each peer, which it does not hold.
        ("POST", "/session/open") => match (peer.identity, Open::decode(body)) {
            (None, _) => no_identity("opening a session"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(open)) => {
                // SIP-39: this open may be a device answering a cross-exchange
                // call, whose caller is on another exchange and so has no local
                // pending open to match. If so, the relay completes the bridge;
                // otherwise it is an ordinary local open.
                let ack =
                    crate::relay::try_answer(server, me, open.peer, open.ephemeral, now_unix())
                        .unwrap_or_else(|| server.sessions.open(me, open.peer, open.ephemeral));
                (200, "application/octet-stream", ack.encode())
            }
        },
        // SIP-39: place (or poll) a cross-exchange call. The target is
        // name@domain or key@domain; this exchange resolves and bridges it.
        ("POST", "/session/call") => match (peer.identity, CallOpen::decode(body)) {
            (None, _) => no_identity("placing a call"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(call)) => {
                // SIP-65: an open exchange dials with no list at all.
                let ack = if server.peering_enabled() || server.open_calls {
                    crate::relay::place_call(server, me, call, now_unix()).await
                } else {
                    // Federated with nobody: refuse identically, no oracle.
                    CallAck::rejected(sqex_proto::relay::REASON_REFUSED, now_unix())
                };
                (200, "application/octet-stream", ack.encode())
            }
        },
        // SIP-39: refuse a ringing cross-exchange call, so the caller is told
        // rather than left polling. Answered **identically** whatever happened —
        // accepted, unknown bridge, or somebody else's call — because this is a
        // route a stranger can reach and a reply that varied would make it an
        // oracle for which calls are in flight and whom they are for.
        ("POST", "/session/decline") => match (peer.identity, CallDecline::decode(body)) {
            (None, _) => no_identity("declining a call"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(d)) => {
                let _ = crate::relay::decline(server, me, d.bridge, d.reason);
                (200, "application/octet-stream", vec![1u8])
            }
        },
        ("POST", "/session/send") => match (peer.identity, SendFrame::decode(body)) {
            (None, _) => no_identity("sending"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(f)) => {
                match server.sessions.send(&me, f.session_id, f.seq, f.ciphertext) {
                    Ok(()) => (200, "application/octet-stream", vec![1u8]),
                    Err(e) => refuse(409, e.code(), None),
                }
            }
        },
        ("POST", "/session/recv") => match (peer.identity, BySession::decode(body, TYPE_RECV)) {
            (None, _) => no_identity("receiving"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(r)) => (
                200,
                "application/octet-stream",
                server.sessions.recv(&me, r.session_id).encode(),
            ),
        },
        ("POST", "/session/close") => match (peer.identity, BySession::decode(body, TYPE_CLOSE)) {
            (None, _) => no_identity("closing"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(r)) => {
                // SIP-39: a bridged session id tears down across the link;
                // anything else is an ordinary local close.
                let closed = crate::relay::close_bridge(server, me, r.session_id)
                    || server.sessions.close(&me, r.session_id);
                (200, "application/octet-stream", vec![u8::from(closed)])
            }
        },

        // SIP-46: the exchanges this one federates with, for anyone to read.
        // The runtime peer list and nothing else; a peer's label is its
        // domain when the label is a DNS name, and empty otherwise -- an
        // operator's note is not a place to be reached.
        // SIP-64: this exchange's earlier keys, to anyone. Every link was
        // in a public zone once; a peer's `post` with no body asks too.
        ("GET", "/exchange/lineage") | ("POST", "/exchange/lineage") => (
            200,
            "application/octet-stream",
            server.lineage_now().encode(),
        ),
        ("GET", "/exchange/peers") => {
            let peers = server.peer_directory();
            (200, "application/octet-stream", peers.encode())
        }
        // The route the whitelist gated before it gated everything: kept, and
        // its own check with it, as the smallest thing a listed peer can ask.
        ("GET", "/exchange/ping") => {
            if server.admitted(peer.key) {
                (
                    200,
                    "application/octet-stream",
                    Pong { now: now_unix() }.encode(),
                )
            } else {
                refuse(403, Code::NotWhitelisted, None)
            }
        }
        // A route this exchange does not have. `sqex-chat` used to recognise
        // this by matching the literal "not found" on a 404; it is a code now.
        _ => refuse(404, Code::NotFound, None),
    }
}

impl Server {
    /// Build the status JSON from an already-borrowed state (so it can run both
    /// from the public endpoint and from inside a locked batch).
    fn status_value(&self, state: &State) -> serde_json::Value {
        json!({
            "version": VERSION,
            "uptime_secs": self.started.elapsed().as_secs(),
            "connections": self.connections.load(Ordering::Relaxed),
            "whitelist_enabled": state.enabled(),
            "whitelist_count": state.keys().len(),
            "beacons": self.beacons.len(),
            "rendezvous_pending": self.rendezvous.len(),
            "names": self.names.count(),
            "requests": self.requests(),
            "event_streams": self.events.total(),
            "mail_waiting": self.mailbox.waiting(),
            "sessions": self.sessions.len(),
            "rooms": self.rooms.len(),
            "admins": self.admins.read().unwrap().len(),
            "transport": self.transport_value(),
        })
    }

    /// What sQUIC itself can say about the traffic reaching this exchange.
    ///
    /// `initials_by_envelope_version` counts accepted Initial packets, not
    /// connections — a handshake retransmits, so a single client shows up
    /// several times. Read it as "is anything still arriving on this
    /// version", which is the only question it needs to answer.
    fn transport_value(&self) -> serde_json::Value {
        let load = self.transport.load_stats();
        let arriving: serde_json::Map<String, serde_json::Value> = load
            .accepted_by_version
            .iter()
            .map(|(version, count)| (version.to_string(), json!(count)))
            .collect();
        json!({
            "under_load": load.under_load,
            "cookie_replies_sent": load.cookie_replies_sent,
            "mac2_verified": load.mac2_verified,
            "accepted_envelope_versions": self.accepted_envelope_versions,
            "initials_by_envelope_version": arriving,
        })
    }

    fn status_json(&self) -> Vec<u8> {
        let state = self.state.lock().unwrap();
        self.status_value(&state).to_string().into_bytes()
    }

    /// Decode, authenticate, and apply a signed transaction (a batch of ops);
    /// return the JSON response body on success. The batch is applied
    /// atomically: every op is decoded and checked first, so one bad op means
    /// none are applied.
    async fn execute(&self, body: &[u8]) -> Result<Vec<u8>> {
        let signed = SignedTransaction::decode(body)?;
        let txn = &signed.transaction;

        // 1. The nonce must be one we issued and have not seen.
        if !self.challenges.consume(&txn.nonce) {
            return Err(Error::BadChallenge);
        }
        // 2. Signature + server binding.
        signed.verify(&self.public_key)?;
        // 3. The signer must be an administrator.
        if !self.is_admin(&signed.admin) {
            return Err(Error::NotAdmin);
        }

        // 4. Decode every op up front. Reject if the summary the operator signed
        //    does not match what this op actually is — so the displayed context
        //    provably corresponds to what will execute.
        let mut ops = Vec::with_capacity(txn.ops.len());
        for wire in &txn.ops {
            let op = Op::decode(&wire.payload)?;
            if op.summary() != wire.summary {
                return Err(Error::Malformed(format!(
                    "op summary {:?} does not match payload ({})",
                    wire.summary,
                    op.name()
                )));
            }
            ops.push(op);
        }

        // 5. Apply the batch under one lock, then persist once.
        let mut state = self.state.lock().unwrap();
        let mut results = Vec::with_capacity(ops.len());
        let mut mutated = false;
        for op in &ops {
            results.push(self.apply(&mut state, op, &signed.admin));
            if op.is_mutation() {
                mutated = true;
                state.record(AuditEntry {
                    time: now_unix(),
                    admin: signed.admin.to_base58(),
                    action: op.name().to_string(),
                    target: op.target(),
                    outcome: "ok".into(),
                });
                tracing::info!(admin = %signed.admin.short(), action = op.name(), "admin op applied");
            }
        }
        if mutated {
            state.save()?;
            self.sync_transport(&state);
        }
        Ok(json!({ "results": results }).to_string().into_bytes())
    }

    /// Carry out one already-authenticated op against the locked state, and
    /// return its JSON result. `admin` is the signer, recorded as provenance on
    /// an add.
    fn apply(&self, state: &mut State, op: &Op, admin: &PubKey) -> serde_json::Value {
        match op {
            Op::WhitelistEnable => {
                state.set_enabled(true);
                json!({ "ok": true, "enabled": true })
            }
            Op::WhitelistDisable => {
                state.set_enabled(false);
                json!({ "ok": true, "enabled": false })
            }
            Op::WhitelistAdd { key, label } => {
                let changed = state.add(
                    *key,
                    WhitelistEntry {
                        added_by: Some(admin.to_base58()),
                        label: label.clone(),
                        added_at: now_unix(),
                    },
                );
                json!({ "ok": true, "changed": changed })
            }
            Op::WhitelistRemove(k) => {
                let changed = state.remove(k);
                json!({ "ok": true, "changed": changed })
            }
            Op::WhitelistList => {
                let keys: Vec<serde_json::Value> = state
                    .list()
                    .into_iter()
                    .map(|(k, e)| {
                        json!({
                            "key": k.to_base58(),
                            "added_by": e.added_by,
                            "label": e.label,
                            "added_at": e.added_at,
                        })
                    })
                    .collect();
                json!({ "enabled": state.enabled(), "keys": keys })
            }
            // SIP-39. Deliberately the same shape as the whitelist arms above:
            // an operator administering "who may connect" and "who we federate
            // with" is doing one kind of thing, and the two should not need
            // different habits.
            Op::PeerAdd { key, label } => {
                // The cap is the same one the config used to enforce at load.
                // It has to be enforced here too now, or a list that could not
                // be configured could still be assembled one op at a time.
                if !state.peers_with(key) && state.peer_count() >= sqex_proto::peer::MAX_PEERS {
                    return json!({
                        "ok": false,
                        "error": format!(
                            "already peering with {}, limit is {}",
                            state.peer_count(),
                            sqex_proto::peer::MAX_PEERS
                        ),
                    });
                }
                // Refusing to peer with ourselves: a self-bridge is a loop with
                // no second party, and the failure it produces later is much
                // harder to read than this sentence.
                if *key == self.public_key {
                    return json!({
                        "ok": false,
                        "error": "an exchange cannot be its own relay peer",
                    });
                }
                let changed = state.add_peer(
                    *key,
                    WhitelistEntry {
                        added_by: Some(admin.to_base58()),
                        label: label.clone(),
                        added_at: now_unix(),
                    },
                );
                json!({ "ok": true, "added": changed, "peers": state.peer_count() })
            }
            // SIP-58: the account's own signed grant, carried by an
            // administrator. Registered exactly as the delegate presenting
            // it would be: the credential is verified, the administrator is
            // not checked against the account, and the audit log says who
            // carried it. Admission follows under SIP-47 when the account
            // is listed; `sync_transport` runs after every mutation.
            Op::DeviceRegister(credential) => {
                match self.devices.register(&credential.delegate, credential) {
                    Ok(()) => json!({
                        "ok": true,
                        "device": credential.delegate.to_base58(),
                        "account": credential.account.to_base58(),
                        "not_after": credential.not_after,
                    }),
                    Err(e) => json!({ "ok": false, "error": e.as_str() }),
                }
            }
            Op::DeviceRevoke(revocation) => {
                match self
                    .devices
                    .revoke(&revocation.account, &revocation.device, Some(revocation))
                {
                    Ok(()) => json!({
                        "ok": true,
                        "device": revocation.device.to_base58(),
                        "account": revocation.account.to_base58(),
                    }),
                    Err(e) => json!({ "ok": false, "error": e.as_str() }),
                }
            }
            Op::PeerRemove(key) => {
                let changed = state.remove_peer(key);
                // Said plainly, because it is the question an operator asks
                // next: this stops the next call, not one already up.
                json!({
                    "ok": true,
                    "removed": changed,
                    "peers": state.peer_count(),
                    "note": "bridges already open are not torn down",
                })
            }
            Op::PeerList => {
                let peers: Vec<serde_json::Value> = state
                    .peer_list()
                    .into_iter()
                    .map(|(k, e)| {
                        json!({
                            "key": k.to_base58(),
                            "added_by": e.added_by,
                            "label": e.label,
                            "added_at": e.added_at,
                        })
                    })
                    .collect();
                json!({ "peering": state.peering_enabled(), "peers": peers })
            }
            Op::Status => self.status_value(state),
            Op::ReloadAdmins => match self.reload_admins() {
                Ok(n) => json!({ "ok": true, "admins": n }),
                Err(e) => json!({ "ok": false, "error": e.to_string() }),
            },
            Op::AuditTail(n) => {
                let entries = state.audit_tail(*n as usize);
                json!({ "entries": entries })
            }
            Op::AdmissionList => {
                let pending: Vec<serde_json::Value> = self
                    .admissions
                    .list()
                    .into_iter()
                    .map(|p| {
                        json!({
                            // The verifiable fact, first. The label is what
                            // somebody typed and an interface must not let it
                            // stand in for this.
                            "device": p.device.to_base58(),
                            "account": p.account.to_base58(),
                            "not_after": p.not_after,
                            "label": p.label,
                            "first_seen": p.first_seen,
                            "admitted_siblings": p.siblings,
                        })
                    })
                    .collect();
                json!({ "pending": pending })
            }
            Op::AdmissionApprove { device, label } => {
                // Provenance records the account the credential named, so a
                // whitelist entry says whose device it was admitted as.
                let claimed = self.admissions.take(device);
                let changed = state.add(
                    *device,
                    WhitelistEntry {
                        added_by: Some(admin.to_base58()),
                        label: label.clone().or_else(|| {
                            claimed
                                .as_ref()
                                .map(|p| format!("device of {}", p.account.to_base58()))
                        }),
                        added_at: now_unix(),
                    },
                );
                json!({ "ok": true, "changed": changed })
            }
            Op::AdmissionDeny(device) => {
                self.admissions.deny(device);
                json!({ "ok": true })
            }
            // SIP-38 administration. The administrator's override: binds or
            // frees a name in any registration mode. `NameAssign` reassigns an
            // existing binding and is exempt from the per-account cap — the cap
            // governs self-service, and an administrator's decision is not that.
            Op::NameAssign { name, account } => {
                let changed = self.names.assign(name, account);
                json!({ "ok": changed, "name": name, "account": account.to_base58() })
            }
            Op::NameRelease(name) => {
                let changed = self.names.release_admin(name);
                json!({ "ok": true, "changed": changed })
            }
            Op::NameList => {
                let names: Vec<serde_json::Value> = self
                    .names
                    .list()
                    .into_iter()
                    .map(|r| {
                        json!({
                            "name": r.name,
                            "account": r.account.to_base58(),
                            // Whether it is an administrator's assignment (no
                            // lease) or an open self-claim.
                            "admin_set": r.admin_set,
                            "registered_at": r.registered_at,
                            "last_active": r.last_active,
                            // Zero for an administrator's assignment.
                            "expires_at": r.expires_at,
                        })
                    })
                    .collect();
                json!({ "names": names })
            }
        }
    }

    /// Re-read the admin list from the config file.
    fn reload_admins(&self) -> Result<usize> {
        let Some(path) = &self.config_path else {
            return Err(Error::Malformed("no config file to reload from".into()));
        };
        let config = Config::from_file(path)?;
        let n = config.admins.len();
        *self.admins.write().unwrap() = config.admins;
        Ok(n)
    }
}

/// The answer to an identity-bound request from a connection that carries no
/// identity. There is nothing to act as, so this is a refusal, not an empty
/// result.
/// A refusal the bytes did not cause: the request was fine and the answer is
/// no. Distinguishable from a malformed request, as SIP-16 requires, and never
/// silent.
/// The routes the managed whitelist never closes. See `route`.
fn open_regardless(path: &str) -> bool {
    path == "/health"
        || path == "/status"
        || path == "/admission/request"
        || path.starts_with("/admin/")
        || path.starts_with("/peer/")
}

fn refused(e: ChannelError) -> (u16, &'static str, Vec<u8>) {
    let detail = e.detail();
    refuse(e.status(), e.code(), detail.as_deref())
}

/// SIP-44: verify a claim and carry the account across -- devices, names,
/// channels, blocks, resolution -- or refuse it whole. One refusal for every
/// way a claim can be wrong that is not a malformed body: a will is a
/// statement about who may act, and which check somebody else's failed is
/// not theirs to learn.
async fn succeed(server: &Server, me: &PubKey, claim: Claim) -> (u16, &'static str, Vec<u8>) {
    let refused = || refuse(403, Code::NotYours, None);
    let proof = claim.proof;
    let account = proof.account();
    let Some(successor) = proof.successor() else {
        return refused();
    };
    if successor != *me
        || account == successor
        || !proof.proves(&successor)
        || server.devices.successor_of(&account).is_some()
        || server.devices.successor_of(&successor).is_some()
        || server.devices.has_devices(&successor)
        || !server.names.names_for(&successor).is_empty()
        // SIP-62: a key that is a member somewhere is an account too.
        || server.channels.has_memberships(&successor)
    {
        return refused();
    }
    if server
        .devices
        .succeed(&account, &successor, &proof.encode())
        .is_err()
    {
        return refused();
    }
    let (issued, sig) = proof.stamp();
    let moved = server.names.succeed(&account, &successor);
    server.profiles.succeed(&account, &successor);
    server.endpoints.set_successor(
        account,
        ResolveSuccessor {
            successor,
            reason: "succeeded".into(),
        },
    );
    let channels = match server
        .channels
        .succeed_account(&account, &successor, issued, &sig)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(account = %account, "succession recorded but channels did not follow: {e:?}");
            Vec::new()
        }
    };
    for channel in &channels {
        server.tell(
            channel,
            EventKind::Channel {
                channel: *channel,
                last_seq: server.channels.highest(channel),
            },
        );
    }
    tracing::info!(
        account = %account,
        successor = %successor,
        names = moved,
        channels = channels.len(),
        "account succeeded"
    );
    (
        200,
        "application/octet-stream",
        ChannelAck { now: now_unix() }.encode(),
    )
}

/// SIP-62: verify a handover and carry it out through SIP-44's path, with
/// the devices kept. One refusal for every way it can be wrong, as for a
/// claim.
async fn handover(server: &Server, me: &PubKey, h: Handover) -> (u16, &'static str, Vec<u8>) {
    let refused = || refuse(403, Code::NotYours, None);
    let (account, successor) = (h.will.account, h.will.successor);
    if account != *me
        || account == successor
        || !h.will.verify()
        || server.devices.successor_of(&account).is_some()
        || server.devices.successor_of(&successor).is_some()
        || server.devices.has_devices(&successor)
        || !server.names.names_for(&successor).is_empty()
        || server.channels.has_memberships(&successor)
    {
        return refused();
    }
    let now = now_unix();
    let mine: Vec<PubKey> = match server.devices.list(&account) {
        Ok(d) if d.devices.is_empty() => vec![account],
        Ok(d) => d.devices.iter().map(|x| x.device).collect(),
        Err(_) => return refused(),
    };
    for c in &h.credentials {
        if c.account != successor
            || !mine.contains(&c.delegate)
            || c.verify(&successor, sqex_proto::credential::SCOPE_CHAT, now)
                .is_err()
        {
            return refused();
        }
    }
    let proof = Proof::Will(h.will).encode();
    if server
        .devices
        .handover(&account, &successor, &proof, &h.credentials)
        .is_err()
    {
        return refused();
    }
    server.resync_transport();
    let (issued, sig) = (h.will.issued, h.will.sig);
    let moved = server.names.succeed(&account, &successor);
    server.profiles.succeed(&account, &successor);
    server.endpoints.set_successor(
        account,
        ResolveSuccessor {
            successor,
            reason: "succeeded".into(),
        },
    );
    let channels = match server
        .channels
        .succeed_account(&account, &successor, issued, &sig)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(account = %account, "handover recorded but channels did not follow: {e:?}");
            Vec::new()
        }
    };
    for channel in &channels {
        server.tell(
            channel,
            EventKind::Channel {
                channel: *channel,
                last_seq: server.channels.highest(channel),
            },
        );
    }
    tracing::info!(
        account = %account,
        successor = %successor,
        devices = h.credentials.len(),
        names = moved,
        channels = channels.len(),
        "account handed over"
    );
    (
        200,
        "application/octet-stream",
        ChannelAck { now: now_unix() }.encode(),
    )
}

/// SIP-43: carry a member's signed join or leave for a channel that lives
/// elsewhere, and answer with the origin's answer. `None` when the channel
/// lives here, and the route goes on as it would.
async fn forward_action(
    server: &Server,
    device: &PubKey,
    channel: &[u8; 32],
    path: &str,
    body: &[u8],
) -> Option<(u16, &'static str, Vec<u8>)> {
    let origin = server.channels.origin_of(channel)?;
    let Some(forwarder) = server.forwarder(&origin) else {
        return Some(refuse(421, Code::Replicated, None));
    };
    Some(
        match forwarder
            .action(
                &server.exchange_seed,
                device,
                server.devices.credential_of(device).as_ref(),
                path,
                body,
            )
            .await
        {
            Ok(answer) => {
                if answer.status == 200 {
                    server.homed.notify_one();
                }
                (answer.status, "application/octet-stream", answer.body)
            }
            Err(e) => {
                tracing::warn!(origin = %origin, "forward failed: {e}");
                refuse(503, Code::OriginAway, None)
            }
        },
    )
}

/// A blob-store write from a client: carried to the origin where the channel
/// lives elsewhere (SIP-43), answered here otherwise.
async fn blob_write(
    server: &Server,
    account: Option<PubKey>,
    device: Option<PubKey>,
    path: &str,
    body: &[u8],
) -> (u16, &'static str, Vec<u8>) {
    let Some(me) = account else {
        return no_identity("using the blob store");
    };
    // SIP-43: an upload for a channel that lives elsewhere is carried to the
    // origin, chunk by chunk, and the replica keeps nothing but the number
    // it gave the client for the origin's upload.
    if let Some(answer) = carry_blob(server, &me, &device.unwrap_or(me), path, body).await {
        return answer;
    }
    let (status, body) = blob_here(server, &me, path, body);
    (status, "application/octet-stream", body)
}

/// The blob store's write routes, answered here: the status and body a
/// client gets. One function, because SIP-43 has the same requests arrive
/// carried from a replica, and a carried one must get exactly what a
/// direct one would.
fn blob_here(server: &Server, me: &PubKey, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let ack = || ChannelAck { now: now_unix() }.encode();
    let refused = |e: ChannelError| {
        let (status, _, body) = refused(e);
        (status, body)
    };
    let malformed = |e: Error| {
        let (status, _, body) = refuse(400, Code::Malformed, Some(&e.to_string()));
        (status, body)
    };
    match path {
        "/blob/begin" => match BlobBegin::decode(body) {
            Err(e) => malformed(e),
            Ok(req) => match server
                .limit(crate::limits::Kind::Uploads, me, [0; 32])
                .and_then(|()| server.channels.begin_upload(me, &req))
            {
                Ok(upload) => (
                    200,
                    Begun {
                        upload,
                        now: now_unix(),
                    }
                    .encode(),
                ),
                Err(e) => refused(e),
            },
        },
        "/blob/put" => match BlobPut::decode(body) {
            Err(e) => malformed(e),
            Ok(req) => match server.channels.put_chunk(me, &req) {
                Ok(()) => (200, ack()),
                Err(e) => refused(e),
            },
        },
        "/blob/commit" => match BlobCommit::decode(body) {
            Err(e) => malformed(e),
            Ok(req) => match server.channels.commit_upload(me, req.upload, &req.blob) {
                Ok(stored) => (
                    200,
                    Committed {
                        stored,
                        blob: req.blob,
                        now: now_unix(),
                    }
                    .encode(),
                ),
                Err(e) => refused(e),
            },
        },
        "/blob/abort" => match ByUpload::decode(body, BL_ABORT) {
            Err(e) => malformed(e),
            Ok(req) => match server.channels.abort_upload(me, req.upload) {
                Ok(()) => (200, ack()),
                Err(e) => refused(e),
            },
        },
        "/blob/attach" => match ByChannelBlob::decode(body, BL_ATTACH) {
            Err(e) => malformed(e),
            Ok(req) => match server.channels.attach_blob(me, &req) {
                Ok(()) => (200, ack()),
                Err(e) => refused(e),
            },
        },
        "/blob/detach" => match ByChannelBlob::decode(body, BL_DETACH) {
            Err(e) => malformed(e),
            Ok(req) => match server.channels.detach_blob(me, &req.channel, &req.blob) {
                Ok(()) => (200, ack()),
                Err(e) => refused(e),
            },
        },
        _ => {
            let (status, _, body) = refuse(404, Code::NotFound, None);
            (status, body)
        }
    }
}

/// The bit that marks an upload number this replica gave a client for an
/// upload it is carrying to an origin. Its own uploads count from one.
const CARRIED_BIT: u64 = 1 << 63;

/// SIP-43: carry a blob-store write to the origin of the channel it is for.
///
/// `begin`, `attach` and `detach` name a channel; where it lives elsewhere
/// the request goes there as sent, and for a `begin` the origin's upload
/// number comes back translated to one of this exchange's, so `put`,
/// `commit` and `abort` naming it are carried too, with the origin's number
/// put back. Nothing is stored here on the way: the blob arrives back by
/// the ordinary pull once the origin holds it. `None` when the request is
/// this exchange's own to answer.
async fn carry_blob(
    server: &Server,
    me: &PubKey,
    device: &PubKey,
    path: &str,
    body: &[u8],
) -> Option<(u16, &'static str, Vec<u8>)> {
    let away = |origin: &PubKey, e: String| {
        tracing::warn!(origin = %origin, "carry failed: {e}");
        refuse(503, Code::OriginAway, None)
    };
    match path {
        "/blob/begin" => {
            let req = BlobBegin::decode(body).ok()?;
            let origin = server.channels.origin_of(&req.channel)?;
            let Some(forwarder) = server.forwarder(&origin) else {
                return Some(refuse(421, Code::Replicated, None));
            };
            let answer = match forwarder
                .action(
                    &server.exchange_seed,
                    device,
                    server.devices.credential_of(device).as_ref(),
                    path,
                    body,
                )
                .await
            {
                Ok(a) => a,
                Err(e) => return Some(away(&origin, e)),
            };
            if answer.status != 200 {
                return Some((answer.status, "application/octet-stream", answer.body));
            }
            let Ok(begun) = Begun::decode(&answer.body) else {
                return Some(away(&origin, "the origin's answer did not decode".into()));
            };
            let local = {
                let mut carried = server.carried_uploads.lock().unwrap();
                let n = server.next_carried.fetch_add(1, Ordering::Relaxed) + 1;
                let local = CARRIED_BIT | n;
                carried.insert(local, (origin, begun.upload, *me));
                local
            };
            Some((
                200,
                "application/octet-stream",
                Begun {
                    upload: local,
                    now: begun.now,
                }
                .encode(),
            ))
        }
        "/blob/put" | "/blob/commit" | "/blob/abort" => {
            // The upload number is the first field of each, after the type.
            let local = match path {
                "/blob/put" => BlobPut::decode(body).ok()?.upload,
                "/blob/commit" => BlobCommit::decode(body).ok()?.upload,
                _ => ByUpload::decode(body, BL_ABORT).ok()?.upload,
            };
            if local & CARRIED_BIT == 0 {
                return None;
            }
            let (origin, theirs, owner) = *server.carried_uploads.lock().unwrap().get(&local)?;
            if owner != *me {
                let (s, t, b) = refuse(403, Code::NotYours, None);
                return Some((s, t, b));
            }
            let Some(forwarder) = server.forwarder(&origin) else {
                return Some(refuse(421, Code::Replicated, None));
            };
            // The same bytes with the origin's number in place of ours.
            let rewritten = match path {
                "/blob/put" => {
                    let mut r = BlobPut::decode(body).ok()?;
                    r.upload = theirs;
                    r.encode()
                }
                "/blob/commit" => {
                    let mut r = BlobCommit::decode(body).ok()?;
                    r.upload = theirs;
                    r.encode()
                }
                _ => ByUpload { upload: theirs }.encode(BL_ABORT),
            };
            let answer = match forwarder
                .action(
                    &server.exchange_seed,
                    device,
                    server.devices.credential_of(device).as_ref(),
                    path,
                    &rewritten,
                )
                .await
            {
                Ok(a) => a,
                Err(e) => return Some(away(&origin, e)),
            };
            if path != "/blob/put" && answer.status == 200 {
                server.carried_uploads.lock().unwrap().remove(&local);
            }
            Some((answer.status, "application/octet-stream", answer.body))
        }
        "/blob/attach" | "/blob/detach" => {
            let type_byte = if path == "/blob/attach" {
                BL_ATTACH
            } else {
                BL_DETACH
            };
            let req = ByChannelBlob::decode(body, type_byte).ok()?;
            let origin = server.channels.origin_of(&req.channel)?;
            let Some(forwarder) = server.forwarder(&origin) else {
                return Some(refuse(421, Code::Replicated, None));
            };
            Some(
                match forwarder
                    .action(
                        &server.exchange_seed,
                        device,
                        server.devices.credential_of(device).as_ref(),
                        path,
                        body,
                    )
                    .await
                {
                    Ok(a) => (a.status, "application/octet-stream", a.body),
                    Err(e) => away(&origin, e),
                },
            )
        }
        _ => None,
    }
}

/// Order a post at this exchange and say what became of it: the status and
/// body `/channel/post` answers a member with. One function, because SIP-43
/// has the same answer travel back through a replica, and a forwarded post
/// must get exactly what a direct one would.
/// SIP-56: record a report and tell the channel's admins.
fn report_here(
    server: &Server,
    account: &PubKey,
    req: &sqex_proto::channel::Report,
) -> (u16, Vec<u8>) {
    match server
        .limit(crate::limits::Kind::Reports, account, [0; 32])
        .and_then(|()| {
            server
                .channels
                .report(account, &req.channel, req.target, req.reason, &req.note)
        }) {
        Ok(()) => {
            let admins = server.channels.admins_of(&req.channel);
            server.events.publish(
                &admins,
                EventKind::Reported {
                    channel: req.channel,
                },
            );
            (200, ChannelAck { now: now_unix() }.encode())
        }
        Err(e) => {
            let (status, _, body) = refused(e);
            (status, body)
        }
    }
}

fn post_here(
    server: &Server,
    account: &PubKey,
    device: &PubKey,
    req: &ChannelPost,
) -> (u16, Vec<u8>) {
    // SIP-56: counted against the member, here or carried from a copy.
    let outcome = server
        .limit(crate::limits::Kind::Posts, account, req.channel)
        .and_then(|()| server.channels.post(account, device, req));
    match outcome {
        Ok(posted) => {
            server.tell(
                &req.channel,
                EventKind::Channel {
                    channel: req.channel,
                    last_seq: posted.seq,
                },
            );
            (200, posted.encode())
        }
        Err(e) => {
            let (status, _, body) = refused(e);
            (status, body)
        }
    }
}

/// A fetch that answers at once when there is something, and otherwise holds
/// the request open until an entry lands or the wait runs out.
///
/// This is the first request in this daemon that does not answer immediately,
/// and the shape matters: the notifier is taken before the first read, so an
/// entry arriving in the gap between looking and waiting still wakes us, and
/// nothing here holds the database lock across an await.
async fn fetch_waiting(
    server: &Arc<Server>,
    me: &PubKey,
    device: &PubKey,
    req: &ChannelFetch,
) -> std::result::Result<sqex_proto::channel::Entries, ChannelError> {
    let notify = server.channels.notifier(&req.channel);
    let first = server
        .channels
        .fetch(me, device, &req.channel, req.since, req.receipts)?;
    if !first.entries.is_empty() || !first.signals.is_empty() || req.wait_secs == 0 {
        return Ok(first);
    }
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(req.wait_secs as u64);
    loop {
        let waited = tokio::time::timeout_at(deadline, notify.notified()).await;
        // Re-check membership as well as entries: an answer is owed to whoever
        // the caller is *now*, not who they were when they parked.
        let again = server
            .channels
            .fetch(me, device, &req.channel, req.since, req.receipts)?;
        // A signal is as good a reason to answer as an entry: SIP-16 says a
        // held request returns as soon as either arrives for the caller.
        if !again.entries.is_empty() || !again.signals.is_empty() || waited.is_err() {
            return Ok(again);
        }
    }
}

fn no_identity(action: &str) -> (u16, &'static str, Vec<u8>) {
    refuse(
        403,
        Code::NoIdentity,
        Some(&format!(
            "{action} requires an advertised Ed25519 identity (SIP-3)"
        )),
    )
}

/// The one answer every SIP-35 peering route gives when it will not serve.
///
/// **Identical for every cause**, and that is the whole point: an unknown peer,
/// an absent channel, a channel that exists and is not replicated to this peer,
/// and an origin that cannot issue receipts must be indistinguishable. These
/// routes are reachable by strangers, and a reply that varied would turn them
/// into an existence oracle for private channels — the rule SIP-24 gives its
/// admission endpoint and SIP-4 a withheld beacon.
///
/// It carries no detail for the same reason. A detail string is a reply that
/// varies.
/// SIP-61: the channels among `watched` that have an entry past the seq
/// the peer holds, at once; else the first to change -- an entry, a
/// signal, a read mark, a redaction -- within `secs`; else none. The
/// notifiers are taken before the first look, as `fetch_waiting` takes
/// its one, so a change in the gap still wakes the wait.
async fn wait_for_changes(
    server: &Arc<Server>,
    watched: &[([u8; 32], u64)],
    secs: u16,
) -> Vec<[u8; 32]> {
    let notifiers: Vec<_> = watched
        .iter()
        .map(|(c, _)| server.channels.notifier(c))
        .collect();
    let past = |server: &Server| -> Vec<[u8; 32]> {
        watched
            .iter()
            .filter(|(c, since)| server.channels.last_seq(c) > *since)
            .map(|(c, _)| *c)
            .collect()
    };
    let already = past(server);
    if !already.is_empty() || secs == 0 || watched.is_empty() {
        return already;
    }
    // One task per notifier, each reporting its index once; the first to
    // report ends the wait, and the rest are dropped with the receiver.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<usize>(watched.len().max(1));
    let tasks: Vec<_> = notifiers
        .into_iter()
        .enumerate()
        .map(|(i, n)| {
            let tx = tx.clone();
            tokio::spawn(async move {
                n.notified().await;
                let _ = tx.send(i).await;
            })
        })
        .collect();
    drop(tx);
    let woken = tokio::time::timeout(std::time::Duration::from_secs(secs as u64), rx.recv()).await;
    for t in &tasks {
        t.abort();
    }
    let mut changed = past(server);
    if let Ok(Some(i)) = woken
        && let Some((c, _)) = watched.get(i)
        && !changed.contains(c)
    {
        changed.push(*c);
    }
    changed
}

/// SIP-60: locate `label@domain` -- the domain's exchange, the label
/// resolved there, the account's home (followed once), its devices as the
/// home lists them -- and remember where the account lives.
async fn locate(server: &Arc<Server>, req: &Locate) -> (u16, &'static str, Vec<u8>) {
    let Some((label, domain)) = req.split() else {
        return refuse(400, Code::Malformed, Some("a target is label@domain"));
    };
    let domain = domain.trim().to_ascii_lowercase();
    let Ok((key, addr)) = crate::relay::find_peer(server, &domain).await else {
        return refuse(404, Code::NotFound, Some("no exchange for that domain"));
    };
    if !server.may_ask(&key) {
        return refuse(403, Code::NotAuthorised, Some("not a federated domain"));
    }
    let seed = server.exchange_seed;
    let account = match label.parse::<PubKey>() {
        Ok(k) => k,
        Err(_) => match crate::relay::resolve_name_at(addr, &key, &seed, label).await {
            Some(a) => a,
            None => return refuse(404, Code::NotFound, Some("no such name there")),
        },
    };
    // The home, followed once where the domain's exchange says the account
    // moved on -- as a call is placed (SIP-59).
    let (mut home, mut home_domain, mut home_addr) = (key, domain.clone(), addr);
    if let Some((h, d)) = crate::relay::home_at(addr, &key, &seed, &account).await
        && h != key
        && !d.is_empty()
        && let Ok((found, a)) = crate::relay::find_peer(server, &d).await
        && found == h
        && server.may_ask(&h)
    {
        (home, home_domain, home_addr) = (h, d, a);
    }
    let devices = crate::relay::devices_at(home_addr, &home, &seed, &account)
        .await
        .unwrap_or(sqex_proto::device::Devices {
            now: now_unix(),
            devices: Vec::new(),
        });
    if home != server.public_key {
        server.devices.learn_home(&account, &home, &home_domain);
        server.add_forwarder(home, home_addr, home_domain.clone());
    }
    (
        200,
        "application/octet-stream",
        Located {
            account,
            home,
            domain: home_domain,
            devices,
        }
        .encode(),
    )
}

/// SIP-59: carry an account's signed device revocation to every origin its
/// home pulls from, off the request path -- the answer here is the home's,
/// and an origin out of reach learns when the credential runs out.
fn carry_revocation(server: &Server, account: PubKey, device: PubKey, body: Vec<u8>) {
    let me = server.public_key;
    let forwarders: Vec<Arc<crate::replica::Forwarder>> = server
        .devices
        .homed_here(&me)
        .into_iter()
        .filter(|(_, _, accounts)| accounts.contains(&account))
        .filter_map(|(origin, _, _)| server.forwarder(&origin))
        .collect();
    let seed = server.exchange_seed;
    tokio::spawn(async move {
        for f in forwarders {
            if let Err(e) = f
                .action(&seed, &device, None, "/device/revoke", &body)
                .await
            {
                tracing::warn!(origin = %f.key, "carrying a revocation failed: {e}");
            }
        }
    });
}

/// SIP-59: verify and record an account's Move, whichever route carried
/// it. A stale one -- not later than the one on record -- is refused with
/// the word SIP-48 uses for the same thing. Where the Move names this
/// exchange, the home task is poked to pull at once.
fn record_move(
    server: &Server,
    mv: &sqex_proto::home::Move,
    domain: &str,
    origins: &[(PubKey, String)],
) -> (u16, &'static str, Vec<u8>) {
    if !mv.verify() {
        return refuse(403, Code::BadSignature, None);
    }
    let domain = domain.trim().to_ascii_lowercase();
    let me = server.public_key;
    match server.devices.record_move(mv, &domain, origins, &me) {
        Ok(true) => {
            if mv.home == me {
                tracing::info!(account = %mv.account, origins = origins.len(), "an account moved here");
                server.homed.notify_one();
            } else {
                tracing::info!(account = %mv.account, home = %mv.home, domain, "an account moved away");
            }
            // SIP-63: a whitelist admits the home an admitted account
            // named, and stops when the account names another.
            server.resync_transport();
            (
                200,
                "application/octet-stream",
                sqex_proto::home::Moved {
                    now: now_unix(),
                    // SIP-63: open peering answers any home, and `peering`
                    // says so; a listed exchange answers from its list.
                    peered: mv.home == me || server.peering(&mv.home).is_some(),
                }
                .encode(),
            )
        }
        Ok(false) => refuse(409, Code::StaleGeneration, None),
        Err(_) => refuse(500, Code::Storage, None),
    }
}

fn peering_refused() -> (u16, &'static str, Vec<u8>) {
    refuse(404, Code::NoSuchChannel, None)
}

fn error_status(e: &Error) -> (u16, &'static str) {
    match e {
        Error::Malformed(_) => (400, "malformed"),
        Error::BadChallenge => (401, "bad_challenge"),
        Error::WrongServer => (400, "wrong_server"),
        Error::BadSignature => (401, "bad_signature"),
        Error::NotAdmin => (403, "not_admin"),
        Error::Key(_) => (400, "bad_key"),
    }
}

/// A refusal, as a value the caller can match on.
///
/// Replaces two older shapes — `{"error": …}` as JSON and a bare `text/plain`
/// line for a request that would not decode. Both made a caller search a
/// document for a word; see `sqex_proto::refusal` for why that could not be
/// made safe.
fn refuse(status: u16, code: Code, detail: Option<&str>) -> (u16, &'static str, Vec<u8>) {
    let r = match detail {
        Some(d) => Refusal::detailed(code, d),
        None => Refusal::new(code),
    };
    (status, "application/octet-stream", r.encode())
}

async fn respond(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    status: u16,
    content_type: &str,
    body: Vec<u8>,
) -> Result<()> {
    let resp = http::Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("content-length", body.len())
        .body(())
        .map_err(|e| Error::Malformed(format!("response build: {e}")))?;
    stream
        .send_response(resp)
        .await
        .map_err(|e| Error::Malformed(format!("send response: {e}")))?;
    stream
        .send_data(bytes::Bytes::from(body))
        .await
        .map_err(|e| Error::Malformed(format!("send data: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| Error::Malformed(format!("finish: {e}")))?;
    Ok(())
}

async fn shutdown_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return "signal-setup-failed",
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = term.recv() => "SIGTERM",
    }
}
