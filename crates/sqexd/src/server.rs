//! The sqex HTTP/3 server: bind, serve, route, and execute admin commands.

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

use crate::challenge::Challenges;
use crate::config::Config;
use crate::state::{AuditEntry, State, now_unix};

/// The server's own version, reported in status. The protocol lives in
/// sqnr-core, but this string identifies the daemon.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ALPN for sqex: plain HTTP/3.
const ALPN: &[u8] = b"h3";

/// Largest admin-command body we will read.
const MAX_BODY: usize = 64 * 1024;

/// Everything a request handler needs.
pub struct Server {
    pub public_key: PubKey,
    config_path: Option<PathBuf>,
    state: Mutex<State>,
    admins: RwLock<Vec<PubKey>>,
    challenges: Challenges,
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

    // The managed whitelist is enforced at the HTTP/3 layer, so sQUIC's own
    // transport whitelist stays off: anyone holding the server key may connect,
    // and the app decides per request. This keeps the signature-gated admin
    // surface reachable no matter the whitelist state.
    let squic_config = SquicConfig {
        alpn_protocols: vec![ALPN.to_vec()],
        max_idle_timeout: std::time::Duration::from_secs(60),
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
            let peer_x25519 = listener.peer_key(&incoming);
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        server.connections.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = serve_h3(server, conn, peer_x25519).await {
                            tracing::debug!("connection ended: {e}");
                        }
                    }
                    Err(e) => tracing::debug!("handshake failed: {e}"),
                }
            });
        }
    };

    tokio::select! {
        _ = accept_loop => tracing::warn!("listener stopped accepting"),
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
    peer_x25519: Option<[u8; 32]>,
) -> Result<()> {
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| Error::Malformed(format!("h3 setup: {e}")))?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(server, resolver, peer_x25519).await {
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
    Ok(())
}

async fn handle_stream(
    server: Arc<Server>,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, bytes::Bytes>,
    peer_x25519: Option<[u8; 32]>,
) -> Result<()> {
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| Error::Malformed(format!("resolve: {e}")))?;

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Read the request body (bounded), if any.
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| Error::Malformed(format!("recv body: {e}")))?
    {
        while chunk.remaining() > 0 {
            let n = chunk.chunk().len();
            if body.len() + n > MAX_BODY {
                return respond(&mut stream, 413, "text/plain", b"body too large".to_vec()).await;
            }
            body.extend_from_slice(chunk.chunk());
            chunk.advance(n);
        }
    }

    let (status, content_type, out) =
        route(&server, method.as_str(), &path, &body, peer_x25519).await;
    respond(&mut stream, status, content_type, out).await
}

/// Pure-ish routing: all state access, no stream I/O.
async fn route(
    server: &Arc<Server>,
    method: &str,
    path: &str,
    body: &[u8],
    peer_x25519: Option<[u8; 32]>,
) -> (u16, &'static str, Vec<u8>) {
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
        // A protected exchange endpoint, to demonstrate whitelist enforcement.
        ("GET", "/exchange/ping") => {
            if server.state.lock().unwrap().peer_allowed(peer_x25519) {
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
            results.push(self.apply(&mut state, op));
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
    /// return its JSON result.
    fn apply(&self, state: &mut State, op: &Op) -> serde_json::Value {
        match op {
            Op::WhitelistEnable => {
                state.set_enabled(true);
                json!({ "ok": true, "enabled": true })
            }
            Op::WhitelistDisable => {
                state.set_enabled(false);
                json!({ "ok": true, "enabled": false })
            }
            Op::WhitelistAdd(k) => {
                let changed = state.add(*k);
                json!({ "ok": true, "changed": changed })
            }
            Op::WhitelistRemove(k) => {
                let changed = state.remove(k);
                json!({ "ok": true, "changed": changed })
            }
            Op::WhitelistList => {
                let keys: Vec<String> = state.keys().iter().map(|k| k.to_base58()).collect();
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
