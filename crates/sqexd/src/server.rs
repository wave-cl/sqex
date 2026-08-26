//! The sqex HTTP/3 server: bind, serve, route, and execute admin commands.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use bytes::Buf;
use ed25519_dalek::SigningKey;
use serde_json::json;
use sqnr_core::key::PubKey;
use sqnr_core::{Error, Result, SignedTransaction};
use sqex_proto::Op;
use squic::Config as SquicConfig;

use crate::beacon::Beacons;
use crate::challenge::Challenges;
use crate::channel::{ChannelError, Channels};
use crate::config::Config;
use crate::device::Registry;
use crate::mailbox::Mailbox;
use crate::prekey::Prekeys;
use crate::profile::Profiles;
use crate::room::Rooms;
use crate::session::Sessions;
use crate::state::{AuditEntry, State, WhitelistEntry, now_unix};
use sqex_proto::beacon::{Beat, BeatAck, Read};
use sqex_proto::channel::{
    Ack as ChannelAck, ByChannel, ByTarget, Cursor as ChannelCursor, Invitee, Role,
    SignalOut, TYPE_CURSORS as CH_CURSORS, TYPE_REDACT as CH_REDACT, Create as ChannelCreate, Created, Fetch as ChannelFetch,
    List as ChannelList, Post as ChannelPost, Retain as ChannelRetain, TYPE_CLOSE as CH_CLOSE,
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
use sqex_proto::device::{ListDevices, Register as DeviceRegister, Revoke as DeviceRevoke};
use sqex_proto::prekey::{Publish as PrekeyPublish, Take as PrekeyTake};
use sqex_proto::profile::{
    Block as ProfileBlock, ByAccount, Put as ProfilePut, TYPE_GET as PR_GET,
};
use sqex_proto::room::{Join as RoomJoin, Leave as RoomLeave};
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
    sessions: Sessions,
    live_conns: Connections,
    started: Instant,
    connections: AtomicU64,
}

impl Server {
    fn is_admin(&self, key: &PubKey) -> bool {
        self.admins.read().unwrap().iter().any(|a| a == key)
    }
}

/// A bound-but-not-yet-serving server, so a caller can read the assigned
/// address and public key before the accept loop starts.
pub struct Bound {
    pub listener: squic::ServerListener,
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

    let listener = squic::listen(config.listen, &signing_key, squic_config)
        .await
        .map_err(|e| Error::Malformed(format!("cannot listen on {}: {e}", config.listen)))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| Error::Malformed(format!("cannot read local address: {e}")))?;

    let server = Arc::new(Server {
        public_key,
        config_path,
        state: Mutex::new(state),
        admins: RwLock::new(config.admins),
        challenges: Challenges::new(config.challenge_ttl),
        beacons: Beacons::new(),
        mailbox: Mailbox::new(),
        rooms: Rooms::new(),
        // The channel log lives beside the state file, so a memory-only
        // deployment gets a memory-only log and nothing has to be configured
        // twice. This is the one service that cannot honestly be memory-only
        // in production, and an operator choosing that is choosing it.
        channels: Channels::open(channel_db.as_deref())
            .map_err(|e| Error::Malformed(format!("cannot open the channel log: {e}")))?,
        // Prekeys are in memory on purpose: a one-time key that survived a
        // restart the device did not is a key whose secret is gone, and
        // serving it would only produce an envelope nobody can open. Losing
        // the pool costs a client one publish.
        prekeys: Prekeys::new(),
        // Durable, unlike prekeys: a device should not have to re-register
        // because a server bounced, and a revocation that evaporated on a
        // restart would be worse than none at all.
        devices: Registry::open(device_db.as_deref())
            .map_err(|e| Error::Malformed(format!("cannot open the device registry: {e}")))?,
        profiles: Profiles::open(profile_db.as_deref())
            .map_err(|e| Error::Malformed(format!("cannot open profiles: {e}")))?,
        sessions: Sessions::new(),
        live_conns: Connections::default(),
        started: Instant::now(),
        connections: AtomicU64::new(0),
    });

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
                return respond(&mut stream, 413, "text/plain", b"body too large".to_vec()).await;
            }
            body.extend_from_slice(chunk.chunk());
            chunk.advance(n);
        }
    }

    let (status, content_type, out) =
        route(&server, method.as_str(), &path, &body, peer).await;
    respond(&mut stream, status, content_type, out).await
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
            Err(e) => (400, "text/plain", e.to_string().into_bytes()),
            Ok(beat) => match peer.identity {
                None => (
                    403,
                    "application/json",
                    json!({ "error": "no_identity",
                            "detail": "beating requires an advertised Ed25519 identity (SIP-3)" })
                    .to_string()
                    .into_bytes(),
                ),
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
            Err(e) => (400, "text/plain", e.to_string().into_bytes()),
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
        // SIP-21 profiles and blocking. Every field is a claim its subject
        // makes; nothing here is attested, and a client must show the key
        // alongside a name wherever the distinction could matter.
        ("POST", "/profile/put") => match (account, ProfilePut::decode(body)) {
            (None, _) => no_identity("publishing a profile"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.profiles.put(&me, &req.profile) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => (
                    e.status(),
                    "application/json",
                    json!({ "error": e.as_str() }).to_string().into_bytes(),
                ),
            },
        },
        ("POST", "/profile/get") => match (account, ByAccount::decode(body, PR_GET)) {
            (None, _) => no_identity("reading a profile"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => {
                let shares = |a: &PubKey, b: &PubKey| server.channels.share_a_channel(a, b);
                match server.profiles.get(&me, &req.account, &shares) {
                    Ok(got) => (200, "application/octet-stream", got.encode()),
                    Err(e) => (
                        e.status(),
                        "application/json",
                        json!({ "error": e.as_str() }).to_string().into_bytes(),
                    ),
                }
            }
        },
        ("POST", "/block/set") => match (account, ProfileBlock::decode(body)) {
            (None, _) => no_identity("blocking"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.profiles.set_block(&me, &req.account, req.add) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => (
                    e.status(),
                    "application/json",
                    json!({ "error": e.as_str() }).to_string().into_bytes(),
                ),
            },
        },
        // Returned only to its owner: a list of who somebody wants to avoid is
        // more sensitive than the member list it protects them from, so it
        // takes no argument and answers about nobody else.
        ("POST", "/block/list") => match account {
            None => no_identity("listing blocks"),
            Some(me) => match server.profiles.blocks(&me) {
                Ok(list) => (200, "application/octet-stream", list.encode()),
                Err(e) => (
                    e.status(),
                    "application/json",
                    json!({ "error": e.as_str() }).to_string().into_bytes(),
                ),
            },
        },

        // SIP-22 device registry. A credential is evidence and not authority:
        // it tells the exchange which account vouches for a key, and does not
        // entitle that key to anything.
        ("POST", "/device/register") => match (device, DeviceRegister::decode(body)) {
            (None, _) => no_identity("registering a device"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            // The caller is the delegate itself, or an already-registered
            // device of the same account. The account is never required to
            // connect, because a hardware-held one cannot.
            (Some(me), Ok(req)) => match server.devices.register(&me, &req.credential) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => (
                    e.status(),
                    "application/json",
                    json!({ "error": e.as_str() }).to_string().into_bytes(),
                ),
            },
        },
        ("POST", "/device/revoke") => match (device, DeviceRevoke::decode(body)) {
            (None, _) => no_identity("revoking a device"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.devices.revoke(&me, &req.device) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => (
                    e.status(),
                    "application/json",
                    json!({ "error": e.as_str() }).to_string().into_bytes(),
                ),
            },
        },
        // Answerable to anybody: the mapping is public by construction, since
        // every credential carries both keys in the clear to whoever verifies
        // one. Pretending otherwise would protect something already published
        // while making a member list impossible to render.
        ("POST", "/device/list") => match ListDevices::decode(body) {
            Err(e) => (400, "text/plain", e.to_string().into_bytes()),
            Ok(req) => match server.devices.list(&req.account) {
                Ok(list) => (200, "application/octet-stream", list.encode()),
                Err(e) => (
                    e.status(),
                    "application/json",
                    json!({ "error": e.as_str() }).to_string().into_bytes(),
                ),
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
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
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
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.put_chunk(&me, &req) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/blob/commit") => match (account, BlobCommit::decode(body)) {
            (None, _) => no_identity("committing an upload"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
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
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.abort_upload(&me, req.upload) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/blob/head") => match (account, ByBlob::decode(body, BL_HEAD)) {
            (None, _) => no_identity("reading a blob"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.head_blob(&me, &req.blob) {
                Ok(h) => (200, "application/octet-stream", h.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/blob/get") => match (account, GetChunk::decode(body)) {
            (None, _) => no_identity("fetching a chunk"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.get_chunk(&me, &req.blob, req.index) {
                Ok(c) => (200, "application/octet-stream", c.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/blob/attach") => {
            match (account, ByChannelBlob::decode(body, sqex_proto::blob_store::TYPE_ATTACH)) {
                (None, _) => no_identity("attaching a blob"),
                (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
                (Some(me), Ok(req)) => match server.channels.attach_blob(&me, &req) {
                    Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                    Err(e) => refused(e),
                },
            }
        }
        ("POST", "/blob/detach") => match (account, ByChannelBlob::decode(body, BL_DETACH)) {
            (None, _) => no_identity("detaching a blob"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
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
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.prekeys.publish(&me, &req.prekeys) {
                Ok(accepted) => {
                    let mut out = accepted.to_be_bytes().to_vec();
                    out.extend_from_slice(&now_unix().to_be_bytes());
                    (200, "application/octet-stream", out)
                }
                Err(e) => (
                    e.status(),
                    "application/json",
                    json!({ "error": e.as_str() }).to_string().into_bytes(),
                ),
            },
        },
        // Unauthenticated by necessity: anybody who may seal to a device has
        // to be able to fetch one. Draining a pool is therefore a denial of
        // service anyone can cause, which the fallback turns into a loss of
        // forward secrecy rather than a failure to rotate.
        ("POST", "/prekey/take") => match PrekeyTake::decode(body) {
            Err(e) => (400, "text/plain", e.to_string().into_bytes()),
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

        // SIP-16 channels: a durable, ordered log. Every route here requires
        // membership or an admin role, and it is checked at the moment of the
        // call — a removed member's next fetch is refused, including one
        // already parked in a long poll.
        ("POST", "/channel/create") => match (account, ChannelCreate::decode(body)) {
            (None, _) => no_identity("creating a channel"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => {
                let blocked = |s: &PubKey, o: &PubKey| server.profiles.has_blocked(s, o);
                match server.channels.create(&me, &req, &blocked) {
                    Ok((created, epoch)) => (
                        200,
                        "application/octet-stream",
                        Created { created, epoch, now: now_unix() }.encode(),
                    ),
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/join") => match (account, ByChannel::decode(body, CH_JOIN)) {
            (None, _) => no_identity("joining a channel"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.join(&me, &req.channel) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/leave") => match (account, ByChannel::decode(body, CH_LEAVE)) {
            (None, _) => no_identity("leaving a channel"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.leave(&me, &req.channel) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/post") => match (account, ChannelPost::decode(body)) {
            (None, _) => no_identity("posting to a channel"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.post(
                &me,
                // The device is what SIP-17 derives the sealing subkey from and
                // what counts its own messages, so it is carried separately.
                &device.unwrap_or(me),
                &req,
            ) {
                Ok(posted) => (200, "application/octet-stream", posted.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/info") => match (account, ByChannel::decode(body, CH_INFO)) {
            (None, _) => no_identity("reading a channel"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.info(&me, &device.unwrap_or(me), &req.channel) {
                Ok(info) => (200, "application/octet-stream", info.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/retain") => match (account, ChannelRetain::decode(body)) {
            (None, _) => no_identity("setting retention"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.retain(&me, &req) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/close") => match (account, ByChannel::decode(body, CH_CLOSE)) {
            (None, _) => no_identity("closing a channel"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.close(&me, &req.channel) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/list") => match ChannelList::decode(body) {
            Err(e) => (400, "text/plain", e.to_string().into_bytes()),
            Ok(req) => match server.channels.list(&req.query, req.offset) {
                Ok(listing) => (200, "application/octet-stream", listing.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/invite") => match (account, decode_invite(body)) {
            (None, _) => no_identity("inviting to a channel"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok((channel, who))) => {
                let blocked = |s: &PubKey, o: &PubKey| server.profiles.has_blocked(s, o);
                match server
                    .channels
                    .invite(&me, &channel, &who.account, who.role, &blocked)
                {
                    Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/remove") => match (account, decode_remove(body)) {
            (None, _) => no_identity("removing from a channel"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok((channel, who))) => match server.channels.remove(&me, &channel, &who) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },

        // SIP-17 channel keys. The exchange stores envelopes opaquely, serves
        // each only to the recipient it names, and holds no key that opens one.
        ("POST", "/channel/key/put") => match (account, KeyPut::decode(body)) {
            (None, _) => no_identity("publishing channel keys"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.put_keys(&me, &req) {
                Ok(ack) => (200, "application/octet-stream", ack.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/key/get") => match (account, KeyGet::decode(body)) {
            (None, _) => no_identity("collecting channel keys"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => {
                match server.channels.get_keys(&me, &req.channel, req.since_epoch) {
                    Ok(got) => (200, "application/octet-stream", got.encode()),
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/key/missing") => match (account, ByChannel::decode(body, CH_MISSING)) {
            (None, _) => no_identity("listing stranded devices"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => {
                let has = |d: &PubKey| server.prekeys.has_any(d);
                match server.channels.missing_keys(&me, &req.channel, &has) {
                    Ok(absent) => (200, "application/octet-stream", absent.encode()),
                    Err(e) => refused(e),
                }
            }
        },

        ("POST", "/channel/cursor") => match (account, ChannelCursor::decode(body)) {
            (None, _) => no_identity("setting a read mark"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => {
                match server
                    .channels
                    .set_cursor(&me, &req.channel, req.read, req.receipts)
                {
                    Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                    Err(e) => refused(e),
                }
            }
        },
        ("POST", "/channel/cursors") => match (account, ByChannel::decode(body, CH_CURSORS)) {
            (None, _) => no_identity("reading marks"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.cursors(&me, &req.channel) {
                Ok(marks) => (200, "application/octet-stream", marks.encode()),
                Err(e) => refused(e),
            },
        },
        ("POST", "/channel/redact") => match (account, ByTarget::decode(body, CH_REDACT)) {
            (None, _) => no_identity("redacting an entry"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match server.channels.redact(&me, &req.channel, req.target) {
                Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                Err(e) => refused(e),
            },
        },
        // Relayed to the other members and stored nowhere. An exchange that
        // dropped every one of these would still conform.
        ("POST", "/channel/signal") => match (account, SignalOut::decode(body)) {
            (None, _) => no_identity("signalling"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => {
                match server.channels.signal(&me, &req.channel, req.kind, &req.body) {
                    Ok(()) => (200, "application/octet-stream", ChannelAck { now: now_unix() }.encode()),
                    Err(e) => refused(e),
                }
            }
        },

        ("POST", "/channel/fetch") => match (account, ChannelFetch::decode(body)) {
            (None, _) => no_identity("fetching entries"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => match fetch_waiting(server, &me, &req).await {
                Ok(entries) => (200, "application/octet-stream", entries.encode()),
                Err(e) => refused(e),
            },
        },

        ("POST", "/room/join") => match (peer.identity, RoomJoin::decode(body)) {
            (None, _) => no_identity("joining a room"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(join)) => match server.rooms.join(join.handle, me, join.proof) {
                Ok(roster) => (200, "application/octet-stream", roster.encode()),
                Err(e) => (
                    507,
                    "application/json",
                    json!({ "error": e.as_str() }).to_string().into_bytes(),
                ),
            },
        },
        ("POST", "/room/leave") => match (peer.identity, RoomLeave::decode(body)) {
            (None, _) => no_identity("leaving a room"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(leave)) => {
                let was_there = server.rooms.leave(&leave.handle, &me);
                (
                    200,
                    "application/json",
                    json!({ "left": was_there }).to_string().into_bytes(),
                )
            }
        },

        // SIP-5 store-and-forward mailbox. Every operation is by the caller's
        // transport identity (SIP-3): a sender is whoever connected, and a
        // mailbox belongs to whoever can connect as its key. Nothing is signed.
        ("POST", "/mailbox/send") => match (peer.identity, MailSend::decode(body)) {
            (None, _) => no_identity("sending"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(from), Ok(msg)) => {
                match server.mailbox.send(from, msg.recipient, msg.sealed) {
                    Ok((id, now)) => (
                        200,
                        "application/octet-stream",
                        SendAck { id, now }.encode(),
                    ),
                    Err(e) => (
                        507,
                        "application/json",
                        json!({ "error": e.as_str() }).to_string().into_bytes(),
                    ),
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
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
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
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(req)) => {
                let deleted = server.mailbox.delete(&me, req.id);
                (200, "application/octet-stream", vec![u8::from(deleted)])
            }
        },
        ("POST", "/mailbox/status") => match (peer.identity, ById::decode(body, TYPE_STATUS)) {
            (None, _) => no_identity("asking"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
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
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(open)) => (
                200,
                "application/octet-stream",
                server.sessions.open(me, open.peer, open.ephemeral).encode(),
            ),
        },
        ("POST", "/session/send") => match (peer.identity, SendFrame::decode(body)) {
            (None, _) => no_identity("sending"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(f)) => {
                match server.sessions.send(&me, f.session_id, f.seq, f.ciphertext) {
                    Ok(()) => (200, "application/octet-stream", vec![1u8]),
                    Err(e) => (
                        409,
                        "application/json",
                        json!({ "error": e.as_str() }).to_string().into_bytes(),
                    ),
                }
            }
        },
        ("POST", "/session/recv") => match (peer.identity, BySession::decode(body, TYPE_RECV)) {
            (None, _) => no_identity("receiving"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(r)) => (
                200,
                "application/octet-stream",
                server.sessions.recv(&me, r.session_id).encode(),
            ),
        },
        ("POST", "/session/close") => match (peer.identity, BySession::decode(body, TYPE_CLOSE)) {
            (None, _) => no_identity("closing"),
            (_, Err(e)) => (400, "text/plain", e.to_string().into_bytes()),
            (Some(me), Ok(r)) => (
                200,
                "application/octet-stream",
                vec![u8::from(server.sessions.close(&me, r.session_id))],
            ),
        },

        // A protected exchange endpoint, to demonstrate whitelist enforcement.
        ("GET", "/exchange/ping") => {
            if server.state.lock().unwrap().peer_allowed(peer.key) {
                (
                    200,
                    "application/json",
                    json!({ "pong": true }).to_string().into_bytes(),
                )
            } else {
                (
                    403,
                    "application/json",
                    json!({ "error": "not_whitelisted" })
                        .to_string()
                        .into_bytes(),
                )
            }
        }
        _ => (404, "text/plain", b"not found".to_vec()),
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
            "mail_waiting": self.mailbox.waiting(),
            "sessions": self.sessions.len(),
            "rooms": self.rooms.len(),
            "admins": self.admins.read().unwrap().len(),
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
    (
        e.status(),
        "application/json",
        json!({ "error": e.as_str() }).to_string().into_bytes(),
    )
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
    req: &ChannelFetch,
) -> std::result::Result<sqex_proto::channel::Entries, ChannelError> {
    let notify = server.channels.notifier(&req.channel);
    let first = server.channels.fetch(me, &req.channel, req.since)?;
    if !first.entries.is_empty() || !first.signals.is_empty() || req.wait_secs == 0 {
        return Ok(first);
    }
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(req.wait_secs as u64);
    loop {
        let waited = tokio::time::timeout_at(deadline, notify.notified()).await;
        // Re-check membership as well as entries: an answer is owed to whoever
        // the caller is *now*, not who they were when they parked.
        let again = server.channels.fetch(me, &req.channel, req.since)?;
        // A signal is as good a reason to answer as an entry: SIP-16 says a
        // held request returns as soon as either arrives for the caller.
        if !again.entries.is_empty() || !again.signals.is_empty() || waited.is_err() {
            return Ok(again);
        }
    }
}

/// SIP-16 `Invite`: a channel, an account and the role it is given.
fn decode_invite(b: &[u8]) -> Result<([u8; 32], Invitee)> {
    if b.len() != 66 {
        return Err(Error::Malformed(format!(
            "invite is {} bytes, want 66",
            b.len()
        )));
    }
    if b[0] != sqex_proto::channel::TYPE_INVITE {
        return Err(Error::Malformed(format!("not an invite (type {:#x})", b[0])));
    }
    Ok((
        b[1..33].try_into().unwrap(),
        Invitee {
            account: PubKey::new(b[33..65].try_into().unwrap()),
            role: Role::from_u8(b[65])?,
        },
    ))
}

/// SIP-16 `Remove`: a channel and an account.
fn decode_remove(b: &[u8]) -> Result<([u8; 32], PubKey)> {
    if b.len() != 65 {
        return Err(Error::Malformed(format!(
            "remove is {} bytes, want 65",
            b.len()
        )));
    }
    if b[0] != sqex_proto::channel::TYPE_REMOVE {
        return Err(Error::Malformed(format!("not a remove (type {:#x})", b[0])));
    }
    Ok((
        b[1..33].try_into().unwrap(),
        PubKey::new(b[33..65].try_into().unwrap()),
    ))
}

fn no_identity(action: &str) -> (u16, &'static str, Vec<u8>) {
    (
        403,
        "application/json",
        json!({
            "error": "no_identity",
            "detail": format!("{action} requires an advertised Ed25519 identity (SIP-3)"),
        })
        .to_string()
        .into_bytes(),
    )
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
