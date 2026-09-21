//! SIP-85: a connection carried by the home.
//!
//! A member's tunnel connection negotiates `sqex-tunnel` and is dispatched
//! here from the accept loop. Each stream the member opens is one tunnel:
//! an [`Open`](tunnel::Open) naming the target's key and domain, one
//! [`Opened`](tunnel::Opened) back, then packets both ways. The home
//! resolves the domain the way it finds a relay peer (SIP-33, following a
//! SIP-40 handover), refuses unless the key it found is the key the member
//! named, binds a fresh UDP socket towards the target and copies bytes
//! between socket and stream, reading none of them. The target sees this
//! exchange's address; the member's sQUIC handshake with it runs end to end.
//!
//! The order of refusals is the document's: membership first, before the
//! domain is resolved, so a stranger cannot use the home as a resolver or a
//! key oracle by what it answers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quinn::Connection;
use sqex_proto::tunnel::{self, Opened};
use sqnr_core::PubKey;
use tokio::net::UdpSocket;

use crate::server::{Peer, Server};

/// One tunnel the home carries, as the server's registry records it.
#[derive(Debug, Clone)]
pub struct Open {
    /// The stream's id on its connection, unique while it lives.
    pub id: u64,
    pub target: PubKey,
    pub domain: String,
    /// The socket the target sees this member arrive from.
    pub local: SocketAddr,
}

/// A token bucket of bytes: `per_sec` a second, up to one second's worth
/// held. Over budget, a packet is dropped -- which is what UDP does, and
/// the inner connection's own loss recovery is what copes.
struct Bucket {
    tokens: f64,
    at: Instant,
    per_sec: f64,
}

impl Bucket {
    fn new(per_sec: u64) -> Bucket {
        Bucket {
            tokens: per_sec as f64,
            at: Instant::now(),
            per_sec: per_sec as f64,
        }
    }

    fn take(&mut self, n: usize) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * self.per_sec)
            .min(self.per_sec);
        self.at = now;
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

/// The accept side of a tunnel connection: one task per stream the member
/// opens, for as long as the connection lives. A connection with no
/// identity is closed at once -- membership is decided by who this is.
pub async fn serve(server: &Arc<Server>, conn: Connection, peer: Peer) {
    let Some(who) = peer.identity else {
        conn.close(0u32.into(), b"");
        return;
    };
    tracing::info!(member = %who, from = %peer.addr, "tunnel connection");
    // SIP-85 §Closing: "when the member is no longer admitted". The door
    // closes the connections of a key it stops allowing by walking the
    // registry the HTTP/3 connections are in -- and a tunnel connection was
    // not in it, so a member removed from the list kept every tunnel it had
    // open (found by the test that removed one, 2026-09-21). Registered
    // under its transport key like any other, and taken out on every
    // ending, by its own id.
    if let Some(key) = peer.key {
        server.live_conns.add_keyed(key, conn.clone());
    }
    while let Ok((send, recv)) = conn.accept_bi().await {
        let server = Arc::clone(server);
        tokio::spawn(async move {
            carry(server, who, peer.key, send, recv).await;
        });
    }
    // The connection ended; every tunnel on it ends with its stream, and
    // its stream's task takes the registry entry out as it goes.
    server.live_conns.remove_keyed(&conn);
    tracing::info!(member = %who, "tunnel connection ended");
}

async fn answer(send: &mut quinn::SendStream, status: u8, family: u8) {
    let _ = send.write_all(&Opened { status, family }.encode()).await;
    let _ = send.finish();
}

/// One tunnel, from `Open` to the end of its stream.
async fn carry(
    server: Arc<Server>,
    who: PubKey,
    key: Option<[u8; 32]>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let open = match tunnel::read_open(&mut recv).await {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!(member = %who, "tunnel open unreadable: {e}");
            return;
        }
    };
    let target = PubKey::new(open.key);
    let id = u64::from(recv.id());

    // 1. Membership, before anything about the target is looked at.
    if !server.tunnels_for(key, &who) {
        tracing::info!(member = %who, "tunnel refused: not a member");
        answer(&mut send, tunnel::STATUS_REFUSED, 0).await;
        return;
    }
    // 2. Rate, and how many this member holds. The slot is taken now and
    // given back on any later refusal, so two opens racing cannot both
    // take the last one.
    if server
        .limit(crate::limits::Kind::Tunnels, &who, [0; 32])
        .is_err()
    {
        tracing::info!(member = %who, "tunnel refused: rate");
        answer(&mut send, tunnel::STATUS_OVER_LIMIT, 0).await;
        return;
    }
    let held = {
        let mut tunnels = server.tunnels.lock().unwrap();
        let mine = tunnels.entry(who).or_default();
        if mine.len() >= server.tunnels_per_member {
            Err(mine.len())
        } else {
            mine.push(Open {
                id,
                target,
                domain: open.domain.clone(),
                // Placeholder until the socket is bound; replaced below.
                local: SocketAddr::from(([0, 0, 0, 0], 0)),
            });
            Ok(())
        }
    };
    if let Err(held) = held {
        tracing::info!(member = %who, held, "tunnel refused: too many");
        answer(&mut send, tunnel::STATUS_OVER_LIMIT, 0).await;
        return;
    }
    let give_back = |server: &Server| {
        let mut tunnels = server.tunnels.lock().unwrap();
        if let Some(mine) = tunnels.get_mut(&who) {
            mine.retain(|t| t.id != id);
            if mine.is_empty() {
                tunnels.remove(&who);
            }
        }
    };
    // 3. Resolution, the way a relay peer is found. 4. The key must be the
    // one the member named: the member does not take a key from the home,
    // and the home does not carry to a key the name does not vouch for.
    // 5. Not itself: a tunnel to this exchange carries nothing a direct
    // connection would not, and a chain of them is a loop.
    let addr = match crate::relay::find_peer(&server, &open.domain).await {
        Ok((found, _)) if found == target && target == server.public_key => {
            tracing::info!(member = %who, "tunnel refused: target is this exchange");
            give_back(&server);
            answer(&mut send, tunnel::STATUS_REFUSED, 0).await;
            return;
        }
        Ok((found, addr)) if found == target => addr,
        Ok((found, _)) => {
            tracing::info!(member = %who, domain = %open.domain, named = %target, found = %found,
                "tunnel refused: wrong key");
            give_back(&server);
            answer(&mut send, tunnel::STATUS_WRONG_KEY, 0).await;
            return;
        }
        Err(e) => {
            tracing::info!(member = %who, domain = %open.domain, "tunnel refused: no address: {e}");
            give_back(&server);
            answer(&mut send, tunnel::STATUS_NO_ADDRESS, 0).await;
            return;
        }
    };
    let bind: SocketAddr = if addr.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(member = %who, "tunnel socket: {e}");
            give_back(&server);
            answer(&mut send, tunnel::STATUS_NO_ADDRESS, 0).await;
            return;
        }
    };
    if let Err(e) = socket.connect(addr).await {
        tracing::warn!(member = %who, target = %addr, "tunnel connect: {e}");
        give_back(&server);
        answer(&mut send, tunnel::STATUS_NO_ADDRESS, 0).await;
        return;
    }
    let local = socket.local_addr().unwrap_or(bind);
    {
        let mut tunnels = server.tunnels.lock().unwrap();
        if let Some(t) = tunnels
            .get_mut(&who)
            .and_then(|mine| mine.iter_mut().find(|t| t.id == id))
        {
            t.local = local;
        }
    }
    let family = if addr.is_ipv4() { 4 } else { 6 };
    if send
        .write_all(
            &Opened {
                status: tunnel::STATUS_OPEN,
                family,
            }
            .encode(),
        )
        .await
        .is_err()
    {
        give_back(&server);
        return;
    }
    tracing::info!(member = %who, target = %target, domain = %open.domain, to = %addr, from = %local,
        "tunnel open");

    // The pumps, and an idle watch beside them. Both directions stamp one
    // clock; the watch ends the tunnel when neither has stamped it for
    // IDLE_SECS. The reads themselves are not raced against a timer: a
    // stream read cancelled part-way through a packet would lose the bytes
    // it had, and the framing with them.
    let socket = Arc::new(socket);
    let up_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let idle = Duration::from_secs(server.tunnel_idle_secs);
    let stamp =
        move |last: &AtomicU64| last.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);

    let mut up = {
        let socket = Arc::clone(&socket);
        let up_bytes = Arc::clone(&up_bytes);
        let last = Arc::clone(&last);
        let mut bucket = Bucket::new(server.tunnel_bytes_per_sec);
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                match tunnel::read_packet(&mut recv).await {
                    Ok(Some(bytes)) => {
                        stamp(&last);
                        if !bucket.take(bytes.len()) {
                            server.tunnel_dropped.0.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        if socket.send(&bytes).await.is_err() {
                            return "socket send failed";
                        }
                        up_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        server
                            .tunnel_forwarded
                            .0
                            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    }
                    Ok(None) => return "member gone",
                    Err(_) => return "member sent a bad packet",
                }
            }
        })
    };
    let mut down = {
        let socket = Arc::clone(&socket);
        let down_bytes = Arc::clone(&down_bytes);
        let last = Arc::clone(&last);
        let mut bucket = Bucket::new(server.tunnel_bytes_per_sec);
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok(n) = socket.recv(&mut buf).await else {
                    return "socket receive failed";
                };
                stamp(&last);
                if n > tunnel::MAX_PACKET || !bucket.take(n) {
                    server.tunnel_dropped.1.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if send.write_all(&tunnel::packet(&buf[..n])).await.is_err() {
                    return "member gone";
                }
                down_bytes.fetch_add(n as u64, Ordering::Relaxed);
                server
                    .tunnel_forwarded
                    .1
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
        })
    };
    let mut watch = {
        let last = Arc::clone(&last);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(idle / 4);
            loop {
                tick.tick().await;
                let since = started.elapsed().as_millis() as u64 - last.load(Ordering::Relaxed);
                if since >= idle.as_millis() as u64 {
                    return "idle";
                }
            }
        })
    };
    let why = tokio::select! {
        r = &mut up => r.unwrap_or("up pump panicked"),
        r = &mut down => r.unwrap_or("down pump panicked"),
        r = &mut watch => r.unwrap_or("idle watch panicked"),
    };
    up.abort();
    down.abort();
    watch.abort();
    // Whichever ended it, the rest is aborted with it: the socket closes
    // with its last holder, the stream with its task.
    give_back(&server);
    server.tunnel_closes.lock().unwrap().push(why);
    tracing::info!(
        member = %who,
        target = %target,
        up = up_bytes.load(Ordering::Relaxed),
        down = down_bytes.load(Ordering::Relaxed),
        secs = started.elapsed().as_secs(),
        why,
        "tunnel closed"
    );
}
