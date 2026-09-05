//! The sqex HTTP/3 server: bind, serve, route, and execute admin commands.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use bytes::Buf;
use ed25519_dalek::SigningKey;
use serde_json::json;
use sqex_proto::exchange::Pong;
use sqex_proto::refusal::{Code, Refusal};
use sqnr_core::key::PubKey;
use sqnr_core::{Error, Result, SignedTransaction};
use sqex_proto::Op;
use squic::Config as SquicConfig;

use crate::beacon::Beacons;
use crate::admission::Admissions;
use crate::challenge::Challenges;
use crate::channel::{ChannelError, Channels};
use crate::config::Config;
use crate::device::Registry;
use crate::events::Subscribers;
use sqex_proto::events::{Event as EventKind, MEMBER_JOINED, MEMBER_LEFT, MEMBER_REMOVED};
use crate::mailbox::Mailbox;
use crate::prekey::Prekeys;
use crate::profile::Profiles;
use crate::room::Rooms;
use crate::session::Sessions;
use crate::state::{AuditEntry, State, WhitelistEntry, now_unix};
use sqex_proto::beacon::{Beat, BeatAck, Read};
use sqex_proto::channel::{
    Ack as ChannelAck, ByChannel, ByChannelSigned, ByTarget, Cursor as ChannelCursor, Invitee,
    SignalOut, TYPE_CURSORS as CH_CURSORS, TYPE_REDACT as CH_REDACT, Create as ChannelCreate, Created, Fetch as ChannelFetch,
    ByAccount as ChannelByAccount, Invite as ChannelInvite, List as ChannelList, Mine as ChannelMine,
    Directory as ChannelDirectory, Post as ChannelPost, TYPE_REMOVE as CH_REMOVE,
    TYPE_REPLICATE as CH_REPLICATE, TYPE_UNREPLICATE as CH_UNREPLICATE,
    Retain as ChannelRetain, TYPE_CLOSE as CH_CLOSE,
    TYPE_INFO as CH_INFO, TYPE_JOIN as CH_JOIN, TYPE_LEAVE as CH_LEAVE,
};
use sqex_proto::mailbox::{ById, Fetched, Send as MailSend, SendAck, TYPE_DELETE, TYPE_FETCH, TYPE_STATUS};
use sqex_proto::blob_store::{
    Begin as BlobBegin, ByBlob, ByChannelBlob, Begun, Commit as BlobCommit, Committed, GetChunk,
    Limits, PutChunk as BlobPut, TYPE_ABORT as BL_ABORT, TYPE_DETACH as BL_DETACH,
    TYPE_HEAD as BL_HEAD, ByUpload,
};
use sqex_proto::channel_key::{
    Get as KeyGet, Put as KeyPut, TYPE_MISSING as CH_MISSING,
};
use sqex_proto::message::{RING_RINGING, Signal};
use sqex_proto::peer::{Hello as PeerHello, Hi, PEER_VERSION, Pull as PeerPull};
use sqex_proto::device::{
    AdmissionRequest, ListDevices, Register as DeviceRegister, Revoke as DeviceRevoke,
};
use sqex_proto::prekey::{Publish as PrekeyPublish, Take as PrekeyTake};
use sqex_proto::profile::{
    Block as ProfileBlock, ByAccount, Put as ProfilePut, TYPE_GET as PR_GET,
};
use sqex_proto::room::{Join as RoomJoin, Leave as RoomLeave, Left};
use sqex_proto::session::{BySession, DatagramFrame, Open, SendFrame, TYPE_CLOSE, TYPE_RECV};

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

/// What the transport established about the caller on one connection.
///
/// Both facts come from the same MAC1-verified Initial: the X25519 key SIP-2
/// exposes, and the Ed25519 name SIP-3 lets a caller assert. A caller may have
/// neither (an anonymous, ephemeral connection), the key alone (a persistent
/// caller that did not advertise), or both.
#[derive(Clone, Copy, Default)]
pub struct Peer {
    /// MAC1-verified X25519 transport key (SIP-2).
    pub key: Option<[u8; 32]>,
    /// MAC1-bound Ed25519 identity, if the caller advertised one (SIP-3).
    pub identity: Option<PubKey>,
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
}

impl Connections {
    fn add(&self, id: PubKey, conn: quinn::Connection) {
        self.by_identity.lock().unwrap().entry(id).or_default().push(conn);
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
    mailbox: Mailbox,
    rooms: Rooms,
    channels: Channels,
    prekeys: Prekeys,
    devices: Registry,
    profiles: Profiles,
    admissions: Admissions,
    sessions: Sessions,
    live_conns: Connections,
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
    replication_peers: Vec<PubKey>,
}

impl Server {
    fn is_admin(&self, key: &PubKey) -> bool {
        self.admins.read().unwrap().iter().any(|a| a == key)
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
    fn tell(&self, channel: &[u8; 32], event: EventKind) {
        let to = self.channels.members_of(channel);
        self.events.publish(&to, event);
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
    }

    /// The same, plus one account who may no longer be present — somebody
    /// removed needs to hear about it more than anybody left behind does.
    fn tell_including(&self, channel: &[u8; 32], also: &PubKey, event: EventKind) {
        let mut to = self.channels.members_of(channel);
        if !to.contains(also) {
            to.push(*also);
        }
        self.events.publish(&to, event);
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
pub async fn bind(
    config: Config,
    config_path: Option<PathBuf>,
    signing_key: SigningKey,
) -> Result<Bound> {
    let public_key = PubKey::new(signing_key.verifying_key().to_bytes());
    let state = State::load(config.state_file.clone(), &config.seed_whitelist)?;
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

    // The managed whitelist is enforced at the HTTP/3 layer, so sQUIC's own
    // transport whitelist stays off: anyone holding the server key may connect,
    // and the app decides per request. This keeps the signature-gated admin
    // surface reachable no matter the whitelist state.
    let squic_config = SquicConfig {
        alpn_protocols: vec![ALPN.to_vec()],
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
        transport: Arc::clone(&listener),
        accepted_envelope_versions,
        challenges: Challenges::new(config.challenge_ttl),
        beacons: Beacons::new(),
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
            .map_err(|e| Error::Malformed(format!("cannot open the channel log: {e}")))?,
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
        profiles: Profiles::open(profile_db.as_deref())
            .map_err(|e| Error::Malformed(format!("cannot open profiles: {e}")))?,
        // In memory: a pending request is a question somebody asked once, and
        // a queue that survived a restart would be a backlog of decisions
        // nobody remembers being asked to make. Asking again costs a request.
        admissions: Admissions::new(),
        sessions: Sessions::new(),
        live_conns: Connections::default(),
        events: Subscribers::default(),
        started: Instant::now(),
        connections: AtomicU64::new(0),
        requests: AtomicU64::new(0),
    });

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
    let mut server = server;
    if !welcome_name.is_empty() {
        match server.channels.ensure_public(&welcome_name, founder.as_ref()) {
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

    tracing::info!(
        listen = %local_addr,
        key = %public_key,
        admins = server.admins.read().unwrap().len(),
        "sqexd {} listening (HTTP/3)", VERSION
    );
    tracing::info!("connection string: sqx://{local_addr}/{public_key}");

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
            };
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        server.connections.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = serve_h3(server, conn, peer).await {
                            tracing::debug!("connection ended: {e}");
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
async fn serve_h3(
    server: Arc<Server>,
    conn: quinn::Connection,
    peer: Peer,
) -> Result<()> {
    // An identified connection can carry session datagrams, so register it and
    // pump them for as long as it lives. Anonymous connections cannot be a
    // party to a session, so they are never registered and never forwarded to.
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

    // Read the request body (bounded), if any.
    let cap = if path == "/blob/put" {
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

    let (status, content_type, out) =
        route(&server, method.as_str(), &path, &body, peer).await;
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

    let Some(mut feed) = server.events.subscribe(me) else {
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
        server.events.unsubscribe(&feed);
        return Ok(());
    }

    crate::events::pump(&mut feed, &mut H3Sink { stream }, HEARTBEAT).await;
    server.events.unsubscribe(&feed);
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
                    let now = server
                        .beacons
                        .record(id, beat.interval_secs, beat.withhold);
                    tracing::debug!(identity = %id.short(), interval = beat.interval_secs, "beat");
                    (200, "application/octet-stream", BeatAck { now }.encode())
                }
            },
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
                server
                    .admissions
                    .request(&me, peer.key.as_ref(), &req.credential, &req.label, siblings);
                // Whoever can act on it. An admission request that waits for
                // an admin to think of refreshing is the case this replaces.
                let admins: Vec<PubKey> = server.admins.read().unwrap().clone();
                server.events.publish(&admins, EventKind::Admission);
                // `now` is the only field, and it is here for the reason SIP-4
                // gives: a client with a wrong clock has something to notice it
                // against. It is identical for every caller.
                (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
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
                    server.events.publish(&to, EventKind::Profile { account: me });
                    (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
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
                    server.channels.share_a_channel(a, b, server.welcome.as_ref())
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
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
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
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },
        ("POST", "/device/revoke") => match (device, DeviceRevoke::decode(body)) {
            (None, _) => no_identity("revoking a device"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server
                .devices
                .revoke(&me, &req.device, req.revocation.as_ref())
            {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refuse(e.status(), e.code(), None),
            },
        },
        // Answerable to anybody: the mapping is public by construction, since
        // every credential carries both keys in the clear to whoever verifies
        // one. Pretending otherwise would protect something already published
        // while making a member list impossible to render.
        ("POST", "/device/list") => match ListDevices::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(req) => match server.devices.list(&req.account) {
                Ok(list) => (200, "application/octet-stream", list.encode()),
                Err(e) => refuse(e.status(), e.code(), None),
            },
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
        ("POST", "/blob/begin") => match (account, BlobBegin::decode(body)) {
            (None, _) => no_identity("beginning an upload"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.begin_upload(&me, &req) {
                Ok(upload) => (
                    200,
                    "application/octet-stream",
                    Begun { upload, now: now_unix() }.encode(),
                ),
                Err(e) => refused(e),
            },
        },
        ("POST", "/blob/put") => match (account, BlobPut::decode(body)) {
            (None, _) => no_identity("uploading a chunk"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.put_chunk(&me, &req) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/blob/commit") => match (account, BlobCommit::decode(body)) {
            (None, _) => no_identity("committing an upload"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                match server.channels.commit_upload(&me, req.upload, &req.blob) {
                    Ok(stored) => (
                        200,
                        "application/octet-stream",
                        Committed { stored, blob: req.blob, now: now_unix() }.encode(),
                    ),
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/blob/abort") => match (account, ByUpload::decode(body, BL_ABORT)) {
            (None, _) => no_identity("aborting an upload"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.abort_upload(&me, req.upload) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
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
        ("POST", "/blob/attach") => {
            match (account, ByChannelBlob::decode(body, sqex_proto::blob_store::TYPE_ATTACH)) {
                (None, _) => no_identity("attaching a blob"),
                (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
                (Some(me), Ok(req)) => match server.channels.attach_blob(&me, &req) {
                    Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                    Err(e) => refused(e),
                },
            }
        }
        ("POST", "/blob/detach") => match (account, ByChannelBlob::decode(body, BL_DETACH)) {
            (None, _) => no_identity("detaching a blob"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => {
                match server.channels.detach_blob(&me, &req.channel, &req.blob) {
                    Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                    Err(e) => refused(e),
                }
            }
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
        // Unauthenticated by necessity: anybody who may seal to a device has
        // to be able to fetch one. Draining a pool is therefore a denial of
        // service anyone can cause, which the fallback turns into a loss of
        // forward secrecy rather than a failure to rotate.
        ("POST", "/prekey/take") => match PrekeyTake::decode(body) {
            Err(e) => refuse(400, Code::Malformed, Some(&e.to_string())),
            Ok(req) => (
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
                match server.channels.create(&me, &dev, &req, &blocked) {
                    Ok((created, epoch, instance)) => {
                        // Everybody invited learns of a channel that did not
                        // exist when they last looked, which is the whole of
                        // how a conversation somebody else started arrives.
                        server.tell(&req.channel, EventKind::Membership {
                            channel: req.channel, account: me, what: MEMBER_JOINED,
                        });
                        (
                            200,
                            "application/octet-stream",
                            Created { created, epoch, instance, now: now_unix() }.encode(),
                        )
                    }
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/join") => match (who, ByChannelSigned::decode(body, CH_JOIN)) {
            (None, _) => no_identity("joining a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server
                .channels
                .join(&me, &dev, &req.channel, &req.action)
            {
                Ok(()) => {
                    server.tell(&req.channel, EventKind::Membership {
                        channel: req.channel, account: me, what: MEMBER_JOINED,
                    });
                    (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
                }
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/leave") => match (who, ByChannelSigned::decode(body, CH_LEAVE)) {
            (None, _) => no_identity("leaving a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server
                .channels
                .leave(&me, &dev, &req.channel, &req.action)
            {
                Ok(()) => {
                    server.tell_including(&req.channel, &me, EventKind::Membership {
                        channel: req.channel, account: me, what: MEMBER_LEFT,
                    });
                    (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
                }
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/post") => match (account, ChannelPost::decode(body)) {
            (None, _) => no_identity("posting to a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.post(
                &me,
                // The device is what SIP-17 derives the sealing subkey from and
                // what counts its own messages, so it is carried separately.
                &device.unwrap_or(me),
                &req,
            ) {
                Ok(posted) => {
                    server.tell(
                        &req.channel,
                        EventKind::Channel { channel: req.channel, last_seq: posted.seq },
                    );
                    (200, "application/octet-stream", posted.encode())
                }
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/info") => match (account, ByChannel::decode(body, CH_INFO)) {
            (None, _) => no_identity("reading a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.info(&me, &device.unwrap_or(me), &req.channel) {
                Ok(info) => (200, "application/octet-stream", info.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/retain") => match (who, ChannelRetain::decode(body)) {
            (None, _) => no_identity("setting retention"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server.channels.retain(&me, &dev, &req) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/directory") => match (who, ChannelDirectory::decode(body)) {
            (None, _) => no_identity("naming a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server.channels.set_directory(&me, &dev, &req) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/close") => match (account, ByChannel::decode(body, CH_CLOSE)) {
            (None, _) => no_identity("closing a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match server.channels.close(&me, &req.channel) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
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
                let (channel, guest) = (req.channel, Invitee { account: req.account, role: req.role });
                let blocked = |s: &PubKey, o: &PubKey| server.profiles.has_blocked(s, o);
                match server
                    .channels
                    .invite(&me, &dev, &channel, &guest.account, guest.role, &req.action, &blocked)
                {
                    Ok(()) => {
                        server.tell(&channel, EventKind::Membership {
                            channel, account: guest.account, what: MEMBER_JOINED,
                        });
                        (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
                    }
                    Err(e) => refused(e),
                }
            }
        },
        // SIP-35: who may hold a copy of this channel, decided by an admin and
        // written into the log the members read — never by an operator out of
        // band, which would make a channel's copies invisible to the people in
        // it.
        ("POST", "/channel/replicate") => match (who, ChannelByAccount::decode(body, CH_REPLICATE)) {
            (None, _) => no_identity("authorising replication"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server.channels.replicate(
                &me, &dev, &req.channel, &req.account, &req.action, true,
            ) {
                Ok(()) => {
                    server.tell(&req.channel, EventKind::Channel { channel: req.channel, last_seq: 0 });
                    (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
                }
                Err(e) => refused(e),
            },
        },
        // **The end of a subscription, and not a recall.** What a replica
        // already holds was lawfully obtained and no protocol can unsend it.
        ("POST", "/channel/unreplicate") => match (who, ChannelByAccount::decode(body, CH_UNREPLICATE)) {
            (None, _) => no_identity("withdrawing replication"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server.channels.replicate(
                &me, &dev, &req.channel, &req.account, &req.action, false,
            ) {
                Ok(()) => {
                    server.tell(&req.channel, EventKind::Channel { channel: req.channel, last_seq: 0 });
                    (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
                }
                Err(e) => refused(e),
            },
        },

        ("POST", "/channel/remove") => match (who, ChannelByAccount::decode(body, CH_REMOVE)) {
            (None, _) => no_identity("removing from a channel"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => match server
                .channels
                .remove(&me, &dev, &req.channel, &req.account, &req.action)
            {
                Ok(()) => {
                    // The removed account is told too. It is the one party to
                    // this that cannot find out by asking again.
                    server.tell_including(&req.channel, &req.account, EventKind::Membership {
                        channel: req.channel, account: req.account, what: MEMBER_REMOVED,
                    });
                    (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
                }
                Err(e) => refused(e),
            },
        },

        // SIP-17 channel keys. The exchange stores envelopes opaquely, serves
        // each only to the recipient it names, and holds no key that opens one.
        ("POST", "/channel/key/put") => match (who, KeyPut::decode(body)) {
            (None, _) => no_identity("publishing channel keys"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
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
                match server.channels.get_keys(&me, &mine, &req.channel, req.since_epoch) {
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
                        server.tell_others(&req.channel, &me, EventKind::Cursor { channel: req.channel });
                        (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
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
            (Some(me), Ok(req)) => match server.channels.redact(&me, &req.channel, req.target) {
                Ok(()) => {
                    // No sequence number to name: a redaction changes an entry
                    // that is already numbered. Zero is the wire's word for
                    // "fetch and see".
                    server.tell(&req.channel, EventKind::Channel { channel: req.channel, last_seq: 0 });
                    (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
                }
                Err(e) => refused(e),
            },
        },
        // Relayed to the other members and stored nowhere. An exchange that
        // dropped every one of these would still conform.
        ("POST", "/channel/signal") => match (who, SignalOut::decode(body)) {
            (None, _) => no_identity("signalling"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some((me, dev)), Ok(req)) => {
                match server.channels.signal(&me, &dev, &req.channel, req.kind, &req.body) {
                    Ok(()) => {
                        // Not to the sender: a client does not need telling
                        // that its own keyboard is being used.
                        server.tell_others(&req.channel, &me, EventKind::Signal { channel: req.channel });
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
                                EventKind::Ringing { channel: req.channel, seq: target },
                            );
                        }
                        (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode())
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
            (Some(who), Ok(hello)) if server.replication_peers.contains(&who) => {
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
                if server.replication_peers.contains(&who)
                    && server.channels.replicates_to(&req.channel, &who) =>
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

        ("POST", "/channel/fetch") => match (account, ChannelFetch::decode(body)) {
            (None, _) => no_identity("fetching entries"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(me), Ok(req)) => match fetch_waiting(server, &me, &device.unwrap_or(me), &req).await {
                Ok(entries) => (200, "application/octet-stream", entries.encode()),
                Err(e) => refused(e),
            },
        },

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
                (200, "application/octet-stream", Left { was_there }.encode())
            }
        },

        // SIP-5 store-and-forward mailbox. Every operation is by the caller's
        // transport identity (SIP-3): a sender is whoever connected, and a
        // mailbox belongs to whoever can connect as its key. Nothing is signed.
        ("POST", "/mailbox/send") => match (peer.identity, MailSend::decode(body)) {
            (None, _) => no_identity("sending"),
            (_, Err(e)) => refuse(400, Code::Malformed, Some(&e.to_string())),
            (Some(from), Ok(msg)) => {
                match server.mailbox.send(from, msg.recipient, msg.sealed) {
                    Ok((id, now)) => (
                        200,
                        "application/octet-stream",
                        SendAck { id, now }.encode(),
                    ),
                    Err(e) => refuse(507, e.code(), None),
                }
            }
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
            (Some(me), Ok(open)) => (
                200,
                "application/octet-stream",
                server.sessions.open(me, open.peer, open.ephemeral).encode(),
            ),
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
            (Some(me), Ok(r)) => (
                200,
                "application/octet-stream",
                vec![u8::from(server.sessions.close(&me, r.session_id))],
            ),
        },

        // A protected exchange endpoint, to demonstrate whitelist enforcement.
        ("GET", "/exchange/ping") => {
            if server.state.lock().unwrap().peer_allowed(peer.key) {
                (200, "application/octet-stream", Pong { now: now_unix() }.encode())
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
fn refused(e: ChannelError) -> (u16, &'static str, Vec<u8>) {
    refuse(e.status(), e.code(), None)
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
    let first = server.channels.fetch(me, device, &req.channel, req.since, req.receipts)?;
    if !first.entries.is_empty() || !first.signals.is_empty() || req.wait_secs == 0 {
        return Ok(first);
    }
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(req.wait_secs as u64);
    loop {
        let waited = tokio::time::timeout_at(deadline, notify.notified()).await;
        // Re-check membership as well as entries: an answer is owed to whoever
        // the caller is *now*, not who they were when they parked.
        let again = server.channels.fetch(me, device, &req.channel, req.since, req.receipts)?;
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
