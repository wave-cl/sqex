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
use crate::rendezvous::{Answer, Introduce, Introduced, MAX_WAIT};
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

/// SIP-25 §Address families: said instead of [`UNREACHABLE`] when the two never had a path to
/// try. The distinction is the point -- one is a punch that failed and the
/// other is a punch that could not be attempted, and blaming the NAT for the
/// second sends whoever reads it to look in the wrong place.
///
/// There are two of these because SIP-25 §Address families reaches the same conclusion in two
/// places, and they are **not the same finding**. A live run on 2026-09-18
/// could not tell which had fired, because both said one sentence: the
/// exchange's half of SIP-25 §Address families could not be shown to have run at all, and the
/// timestamps on two devices were half a second apart with no shared clock
/// to order them by. Whoever reads a log should not have to infer this.
///
/// Both open with the same clause, so anything matching on "no direct
/// connection" still matches, and both close by naming the network rather
/// than the NAT, which is the wrong answer this pair exists to stop giving.
pub const NO_SHARED_FAMILY_BY_EXCHANGE: &str = "no direct connection: the exchange says you both asked for one, from different address \
     families, so neither of you could be given an address to dial. This is the network, \
     not the NAT";

/// The other half: an exchange introduced the two and disclosed an address
/// this host has no route to. The compatibility rule of SIP-25 §Asking for the third answer -- an exchange is
/// not the authority on what a client's network can reach -- and the only
/// answer available from an exchange from before sqex 0.88.0 (SIP-25 §Address families).
pub const NO_SHARED_FAMILY_IN_THE_ADDRESS: &str = "no direct connection: the exchange offered an address on an address family this device \
     has no route to, so there was nothing to dial. This is the network, not the NAT";

/// Which side worked out that the two are on different address families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Learned {
    /// The exchange answered `ready = 2`. Nothing else produces this, so a
    /// log carrying it **is** the evidence that the exchange's half of SIP-25 §Address families ran.
    FromExchange,
    /// We were introduced and refused the address ourselves.
    FromTheAddress,
}

impl Learned {
    /// What to tell whoever is reading, which differs by who found it out.
    pub fn why(self) -> &'static str {
        match self {
            Learned::FromExchange => NO_SHARED_FAMILY_BY_EXCHANGE,
            Learned::FromTheAddress => NO_SHARED_FAMILY_IN_THE_ADDRESS,
        }
    }
}

/// A local port this process can hold and then hand to squic, in the same
/// address family as `reach`.
///
/// Bound, read back, released. Racy in principle, and the alternative --
/// letting squic bind first and asking what it got -- would mean the
/// exchange connection and the peer connection could not share one.
///
/// **The family has to match what this port will dial.** An IPv4 wildcard
/// cannot connect to an IPv6 remote: quinn refuses it as an invalid remote
/// address, and a call to an exchange that resolves to IPv6 could never
/// take the direct path -- it always fell back to the relay. The same port
/// then dials the peer, whose address the exchange reports in the family it
/// saw, which is this one.
fn pick_local_port(reach: SocketAddr) -> Result<SocketAddr, String> {
    // Canonical: an exchange named by a v4-mapped address is reached over
    // IPv4, and binding IPv6 for it would pick a port in the wrong family.
    let wildcard: SocketAddr = if canonical(reach).is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let probe = std::net::UdpSocket::bind(wildcard).map_err(|e| e.to_string())?;
    let addr = probe.local_addr().map_err(|e| e.to_string())?;
    drop(probe);
    Ok(addr)
}

/// What came of asking to be introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Meeting {
    /// Both asked, on a family they share, and here is the address.
    Introduced(Introduction),
    /// The wait ended without the peer asking. Nothing is said about whether
    /// they asked at all, which is SIP-25's rule, and nothing was disclosed.
    NobodyAsked,
    /// SIP-25 §Both asked, and share no family: both asked, and the two are on networks with no address family
    /// in common, so neither could dial the other. Carries which side worked
    /// that out, because the two are different findings and a log that cannot
    /// separate them cannot show the exchange's half ran.
    NoSharedFamily(Learned),
}

/// Wait until the port we are about to reuse is free, up to `within`.
///
/// Dropping the exchange connection aborts its driver and the socket goes
/// with it -- but not synchronously, and this used to be a flat 200 ms
/// floor. **The second party to ask barely waits at all**: it reads back the
/// start time the first computed, so its lead has usually elapsed by the
/// time it has the answer, and 200 ms was the whole of its pause. The
/// listener then bound the port the exchange connection had not yet let go
/// and failed with "address already in use", which the caller reported as a
/// punch that did not work -- the wrong reason again, and the one this half
/// of the code exists to stop giving.
///
/// Returns whether it came free. Binding and dropping leaves it free for
/// squic to take a moment later; nothing else here is competing for it.
async fn wait_until_free(addr: SocketAddr, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if std::net::UdpSocket::bind(addr).is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// SIP-25 §Address families: whether an address the exchange disclosed is one this side could
/// dial from the port it asked over.
///
/// **Checked whatever the exchange said.** An exchange is not the authority
/// on what this machine's network can reach, and one from before sqex 0.88.0 (SIP-25 §Asking for the third answer)
/// pairs on identity alone -- it will hand over an address of any family.
/// Dialling one there is no route to fails inside the transport, which
/// reports it as a punch that did not work and sends whoever reads that to
/// look at a NAT which was never the problem.
fn dialable_from(ours: SocketAddr, theirs: SocketAddr) -> bool {
    canonical(ours).is_ipv6() == canonical(theirs).is_ipv6()
}

/// An IPv4 peer of a **dual-stack** listener is observed as `::ffff:a.b.c.d`,
/// and `is_ipv6()` calls that IPv6 -- so an exchange bound on `[::]` reports
/// every IPv4 client in a form that compares unequal to IPv4.
///
/// This is not hypothetical. On 2026-09-18, with both parties on IPv4 and
/// the desktop holding no IPv6 address at all, both ends still reported that
/// they had reached the exchange on different families and fell back to the
/// relay. The families were the same; only the spelling differed, and every
/// comparison in SIP-25 §The family of a request is the family it arrived over was made on the spelling.
///
/// Canonicalising here rather than only at the exchange is deliberate: an
/// exchange that has not been redeployed still discloses the mapped form,
/// and a caller that cannot read it has no direct call. Dialling the
/// canonical address is also the correct thing to do on its own terms --
/// `a.b.c.d` is what an IPv4 socket can send to.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Ask the exchange to introduce us to `peer`, from a port of our own.
///
/// Sleeps out the lead before returning [`Meeting::Introduced`], so the caller
/// may go straight on to [`link`].
pub async fn introduce(
    exchange: SocketAddr,
    server: &[u8; 32],
    seed: &[u8; 32],
    peer: PubKey,
    wait: u16,
) -> Result<Meeting, String> {
    let ours = pick_local_port(exchange)?;
    let mut client = H3Client::connect_from(exchange, server, seed, Some(ours)).await?;
    let req = Introduce {
        peer,
        wait_secs: wait.min(MAX_WAIT),
        family_aware: true,
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
    match got.answer {
        Answer::Waiting => return Ok(Meeting::NobodyAsked),
        Answer::NoSharedFamily => {
            return Ok(Meeting::NoSharedFamily(Learned::FromExchange));
        }
        Answer::Ready => {}
    }
    // Canonical, so what we dial is an address of the family we hold, and
    // so the comparison below is about families and not about spelling.
    let theirs = canonical(got.addr.ok_or("an introduction with no address")?);
    if !dialable_from(ours, theirs) {
        return Ok(Meeting::NoSharedFamily(Learned::FromTheAddress));
    }
    // Measured as a delay from the exchange's own clock rather than as an
    // absolute time on ours, because the three clocks do not agree and only
    // one of them is shared.
    let lead = Duration::from_secs(got.start_at.saturating_sub(got.now));
    tokio::time::sleep(lead.max(Duration::from_millis(200))).await;
    // Whatever the lead was, do not hand `link` a port the exchange
    // connection still holds. Bounded, because a port that never comes free
    // is a reason to relay rather than to wait out the call.
    wait_until_free(ours, Duration::from_secs(2)).await;
    Ok(Meeting::Introduced(Introduction { ours, theirs, lead }))
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

    /// The port a just-dropped socket held comes free, and the wait says so
    /// rather than guessing at a fixed pause.
    #[tokio::test]
    async fn a_port_in_use_is_waited_for_and_a_free_one_is_not() {
        let held = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = held.local_addr().unwrap();

        // Still held: the wait runs out and says so.
        let began = std::time::Instant::now();
        assert!(!wait_until_free(addr, Duration::from_millis(200)).await);
        assert!(began.elapsed() >= Duration::from_millis(200));

        // Released: the wait returns, and well inside its budget.
        drop(held);
        let began = std::time::Instant::now();
        assert!(wait_until_free(addr, Duration::from_secs(2)).await);
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "waited {:?} for a port that was already free",
            began.elapsed()
        );
    }

    /// Two parties on IPv4 share a family even when the exchange, listening
    /// dual-stack, spells one of them `::ffff:a.b.c.d`.
    ///
    /// This is the live run of 2026-09-18: both ends on IPv4, the desktop
    /// holding no IPv6 address at all, and both still reporting that they
    /// had reached the exchange on different families.
    #[test]
    fn a_mapped_ipv4_address_is_ipv4_and_not_another_family() {
        let plain: SocketAddr = "203.0.113.7:9000".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:9000".parse().unwrap();
        let real_v6: SocketAddr = "[2001:db8::1]:9000".parse().unwrap();

        // The spelling that started this: unequal as written, one family.
        assert_ne!(plain, mapped, "the two spellings really are different");
        assert!(
            dialable_from(plain, mapped),
            "an IPv4 host cannot dial its own peer because an exchange spelled it in IPv6"
        );
        assert!(dialable_from(mapped, plain));
        assert!(dialable_from(mapped, mapped));

        // And a genuine IPv6 peer is still another family, which is the
        // distinction SIP-25 §Address families exists to draw.
        assert!(!dialable_from(plain, real_v6));
        assert!(!dialable_from(mapped, real_v6));
        assert!(dialable_from(real_v6, real_v6));

        // What we would dial, and the port it keeps.
        assert_eq!(canonical(mapped), plain);
        assert_eq!(canonical(plain), plain);
        assert_eq!(canonical(real_v6), real_v6);
        assert_eq!(canonical(mapped).port(), 9000);
    }

    /// The port is picked in the family we will actually reach the exchange
    /// over, which for a mapped address is IPv4.
    #[test]
    fn a_mapped_exchange_address_gets_an_ipv4_local_port() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:443".parse().unwrap();
        let ours = pick_local_port(mapped).expect("a local port");
        assert!(
            ours.is_ipv4(),
            "bound {ours}, which cannot send to an IPv4 exchange"
        );
    }

    /// The two ways SIP-25 §Address families reaches its conclusion say different things, and
    /// a reader can tell which fired. This is the whole of the change: on
    /// 2026-09-18 a live run produced this message on both devices and
    /// nothing in either log said whether the exchange had refused the pair
    /// or the caller had refused the address.
    #[test]
    fn each_side_of_the_family_answer_says_which_side_found_it() {
        let by_exchange = Learned::FromExchange.why();
        let in_the_address = Learned::FromTheAddress.why();
        assert_ne!(
            by_exchange, in_the_address,
            "a log cannot show the exchange's half ran if both paths say one thing"
        );
        // Only the exchange's answer can mention that both asked: the other
        // path knows nothing of the peer's request.
        assert!(by_exchange.contains("you both asked"), "{by_exchange}");
        assert!(!in_the_address.contains("both asked"), "{in_the_address}");
        // And only ours can name the address it was handed.
        assert!(
            in_the_address.contains("offered an address"),
            "{in_the_address}"
        );

        for why in [by_exchange, in_the_address] {
            // The opening clause anything matches on, and the closing one
            // that keeps a reader away from the NAT.
            assert!(why.starts_with("no direct connection: "), "{why}");
            assert!(why.ends_with("This is the network, not the NAT"), "{why}");
            assert!(!why.contains("symmetric"), "{why}");
        }
    }

    /// SIP-25 §Both asked, and share no family: an address of the other family is not one this side can dial,
    /// whatever the exchange said about it.
    #[test]
    fn an_address_of_the_other_family_is_not_dialable() {
        let v4: SocketAddr = "203.0.113.7:5400".parse().unwrap();
        let v6: SocketAddr = "[2a02:8084:d05:2a80::1]:52555".parse().unwrap();
        assert!(dialable_from(v4, v4));
        assert!(dialable_from(v6, v6));
        assert!(!dialable_from(v4, v6), "this is the live run's failure");
        assert!(!dialable_from(v6, v4));
    }

    /// The local port matches the family of what it will reach: an IPv4
    /// wildcard cannot dial an IPv6 exchange, and a call to one that
    /// resolved to IPv6 could never take the direct path.
    #[test]
    fn the_local_port_matches_the_family_it_will_reach() {
        let v6: SocketAddr = "[2a01:4f8:c015:2190::1]:443".parse().unwrap();
        assert!(pick_local_port(v6).unwrap().is_ipv6());
        let v4: SocketAddr = "203.0.113.7:443".parse().unwrap();
        assert!(pick_local_port(v4).unwrap().is_ipv4());
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
