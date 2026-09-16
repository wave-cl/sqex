//! The client's side of SIP-25: being introduced, and then connecting.
//!
//! [`rendezvous`](crate::rendezvous) is the wire and the exchange's half --
//! it coordinates and does not punch. This is the half that punches: ask
//! from a chosen port, drop the connection and reuse the port, punch, then
//! dial or listen (lower key dials, higher listens, the tiebreak SIP-12
//! already uses), with each end pinning the other's identity. Finally
//! [`agree`] a SIP-12 session key over the connection just made, from the
//! same four terms as a relayed session, so the frames are sealed exactly
//! as they would be relayed and one media loop serves both paths.
//!
//! The one port is the whole mechanism: the address the exchange observes
//! is the NAT mapping *this socket* made, so the connection that gets
//! introduced and the connection that punches have to leave from the same
//! place. That is why the introduction goes over a throwaway connection
//! from a chosen port rather than over whatever connection the caller
//! already holds.
//!
//! Here rather than in `sqex-voice` because `sqex meet` -- the two-homes
//! field test that would move SIP-25 out of Draft -- must run the same
//! code a client ships, and the CLI does not carry a codec.

use std::net::SocketAddr;
use std::time::Duration;

use crate::h3::H3Client;
use crate::rendezvous::{Introduce, Introduced, MAX_WAIT};
use crate::session::Session;
use sqnr_core::PubKey;

/// The session id both sides use on a direct connection. Nothing assigns
/// one -- there is no exchange to -- and there is only ever one session on
/// the connection, so it is a constant rather than a negotiation.
pub const DIRECT_SESSION: u64 = 1;

/// How long each stage may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// How long to wait for the other side to ask for the introduction, in
    /// seconds; clamped to [`MAX_WAIT`] by the exchange.
    pub introduce_wait: u16,
    /// How long the dialer gives the handshake.
    pub handshake: Duration,
    /// How long the listener waits for the dialer to arrive.
    pub accept: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            introduce_wait: 8,
            handshake: Duration::from_secs(5),
            accept: Duration::from_secs(8),
        }
    }
}

/// What the exchange said: where we were seen from, where they were seen
/// from, and how long until the moment both were given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Introduction {
    /// The local port the introduction was made from, which the direct
    /// connection must also leave from.
    pub ours: SocketAddr,
    /// Where the exchange saw the peer.
    pub theirs: SocketAddr,
    /// The lead until the shared start, on the exchange's clock.
    pub lead: Duration,
}

/// The wording for an introduction that was made and led nowhere. It names
/// the NAT kind that does this, because nothing else about the failure
/// does.
pub const UNREACHABLE: &str = "no direct connection: this needs endpoint-independent NAT \
                               mapping at both ends, and symmetric NAT allocates a fresh \
                               external port per destination";

/// A local port this process can hold and then hand to squic.
///
/// Bound, read back, released. Racy in principle, and the alternative --
/// letting squic bind first and asking what it got -- would mean the
/// exchange connection and the peer connection could not share one.
fn pick_local_port() -> Result<SocketAddr, String> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let addr = probe.local_addr().map_err(|e| e.to_string())?;
    drop(probe);
    Ok(addr)
}

/// Ask the exchange to introduce us to `peer`, from a port of our own.
///
/// `Ok(None)` when the wait ended without the peer asking: nothing is said
/// about whether they asked at all, which is SIP-25's rule, and nothing has
/// been disclosed. Sleeps out the lead before returning, so the caller may
/// go straight on to [`link`].
pub async fn introduce(
    exchange: SocketAddr,
    server: &[u8; 32],
    seed: &[u8; 32],
    peer: PubKey,
    wait: u16,
) -> Result<Option<Introduction>, String> {
    let ours = pick_local_port()?;
    let mut client = H3Client::connect_from(exchange, server, seed, Some(ours)).await?;
    let req = Introduce {
        peer,
        wait_secs: wait.min(MAX_WAIT),
    };
    // A long poll, by design.
    let (code, body) = client
        .post("/rendezvous/introduce", req.encode())
        .await
        .map_err(|e| e.to_string())?;
    if code != 200 {
        return Err(format!("introduction refused ({code})"));
    }
    let got = Introduced::decode(&body).map_err(|e| e.to_string())?;
    // **The exchange connection is dropped here, and the port is reused.**
    // A NAT keeps a mapping alive for tens of seconds after the last packet,
    // so rebinding the same port lands in the same mapping -- the one the
    // peer was just told about. Dropping the client aborts its driver, which
    // is what actually lets the socket go; the pause is for the kernel to
    // agree.
    drop(client);
    if !got.ready {
        return Ok(None);
    }
    let theirs = got.addr.ok_or("an introduction with no address")?;
    // Measured as a delay from the exchange's own clock rather than as an
    // absolute time on ours, because the three clocks do not agree and only
    // one of them is shared.
    let lead = Duration::from_secs(got.start_at.saturating_sub(got.now));
    tokio::time::sleep(lead.max(Duration::from_millis(200))).await;
    Ok(Some(Introduction { ours, theirs, lead }))
}

/// Whether this side dials: lower key dials, higher key listens. The
/// tiebreak is on bytes both sides already hold, and it is the same one
/// SIP-12 uses to decide which peer is `first`.
pub fn dials(me: &PubKey, peer: &PubKey) -> bool {
    me.as_bytes() < peer.as_bytes()
}

/// Make the connection an introduction described: punch, then dial or
/// listen, by [`dials`]. Both ends pin the other's identity.
pub async fn link(
    intro: Introduction,
    seed: &[u8; 32],
    peer: PubKey,
    budget: Budget,
) -> Result<quinn::Connection, String> {
    let me = PubKey::new(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    );
    if me == peer {
        return Err("a call needs two identities".into());
    }
    if dials(&me, &peer) {
        dial_peer(intro, seed, peer, budget).await
    } else {
        listen_for(intro, seed, peer, budget).await
    }
}

/// The dialing half of [`link`]: from the introduced port, pinned to the
/// peer's identity, advertising our own.
pub async fn dial_peer(
    intro: Introduction,
    seed: &[u8; 32],
    peer: PubKey,
    budget: Budget,
) -> Result<quinn::Connection, String> {
    squic::dial(
        intro.theirs,
        peer.as_bytes(),
        squic::Config {
            local_bind: Some(intro.ours),
            punch: vec![intro.theirs],
            client_key: Some(hex::encode(seed)),
            advertise_identity: true,
            handshake_timeout: Some(budget.handshake),
            enable_datagrams: true,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| format!("{UNREACHABLE} ({e})"))
}

/// The listening half of [`link`]: on the introduced port, admitting the
/// peer and nobody else.
///
/// The whitelist is on the transport key, which is what squic
/// authenticates at the handshake; the advertised identity is checked as
/// well, so that a key which merely maps to the same point is not enough.
/// Somebody else arriving is skipped, not fatal: the peer may still be on
/// the way.
pub async fn listen_for(
    intro: Introduction,
    seed: &[u8; 32],
    peer: PubKey,
    budget: Budget,
) -> Result<quinn::Connection, String> {
    let theirs = squic::crypto::ed25519_identity_to_x25519(peer.as_bytes())
        .map_err(|e| format!("the peer's key is not a valid identity: {e}"))?;
    let listener = squic::listen(
        intro.ours,
        &ed25519_dalek::SigningKey::from_bytes(seed),
        squic::Config {
            punch: vec![intro.theirs],
            allowed_keys: Some(vec![theirs.to_bytes()]),
            enable_datagrams: true,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| format!("cannot listen on {}: {e}", intro.ours))?;
    let deadline = tokio::time::Instant::now() + budget.accept;
    loop {
        match tokio::time::timeout_at(deadline, listener.accept()).await {
            Ok(Some(incoming)) => {
                if listener.peer_identity(&incoming) != Some(*peer.as_bytes()) {
                    continue;
                }
                return incoming
                    .await
                    .map_err(|e| format!("a peer arrived and the handshake failed: {e}"));
            }
            Ok(None) => return Err("the listener closed".into()),
            Err(_) => return Err(UNREACHABLE.into()),
        }
    }
}

/// Agree a SIP-12 session key over a direct connection: each side sends
/// its ephemeral public key on one stream and reads the other's. The
/// dialer opens the stream; the listener accepts it.
///
/// The exchange is not party to this, and the connection is authenticated
/// to the peer both ways, so the two ephemerals reach each other and nobody
/// else -- the same guarantee SIP-12 gets from the exchange relaying them.
pub async fn agree(
    conn: &quinn::Connection,
    seed: &[u8; 32],
    peer: PubKey,
    dialing: bool,
) -> Result<(Session, u64), String> {
    let eph = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let mine = x25519_dalek::PublicKey::from(&eph).to_bytes();
    let (mut send, mut recv) = if dialing {
        conn.open_bi()
            .await
            .map_err(|e| format!("open the key stream: {e}"))?
    } else {
        conn.accept_bi()
            .await
            .map_err(|e| format!("accept the key stream: {e}"))?
    };
    send.write_all(&mine)
        .await
        .map_err(|e| format!("send the ephemeral: {e}"))?;
    send.finish()
        .map_err(|e| format!("finish the key stream: {e}"))?;
    let mut theirs = [0u8; 32];
    recv.read_exact(&mut theirs)
        .await
        .map_err(|e| format!("read the peer's ephemeral: {e}"))?;
    let session = Session::derive(seed, &eph, &peer, &theirs).map_err(|e| e.to_string())?;
    Ok((session, DIRECT_SESSION))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of the two dials and it is the same one from both points of
    /// view; nobody dials themselves.
    #[test]
    fn exactly_one_side_dials_and_both_agree_which() {
        let a = PubKey::new([1u8; 32]);
        let b = PubKey::new([2u8; 32]);
        assert!(dials(&a, &b));
        assert!(!dials(&b, &a));
        assert!(!dials(&a, &a));
    }

    /// The budget is bounded by what the exchange will wait, and its
    /// default fits inside a ring.
    #[test]
    fn the_default_budget_fits_inside_a_ring_window() {
        let b = Budget::default();
        assert!(b.introduce_wait <= MAX_WAIT);
        let worst = Duration::from_secs(b.introduce_wait as u64)
            + Duration::from_secs(crate::rendezvous::START_LEAD_SECS)
            + b.handshake.max(b.accept);
        assert!(worst < Duration::from_secs(30), "{worst:?}");
    }
}
