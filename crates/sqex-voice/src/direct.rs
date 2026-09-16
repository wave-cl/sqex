//! A call that goes straight between the two people on it (SIP-25).
//!
//! The flow itself -- the introduction, the punch, the dial or listen, and
//! the key agreement over the connection -- is
//! [`sqex_proto::direct`], shared with `sqex meet`. This composes it into
//! one attempt and reports what became of it.
//!
//! **What this does not do is decide to fall back.** [`connect`] answers
//! `Ok(None)` when nobody was there to be introduced to and `Err` when the
//! introduction was made and the connection failed; the caller relays in
//! either case, and says why in the second.

pub use sqex_proto::direct::{
    Budget, DIRECT_SESSION, Introduction, UNREACHABLE, agree, dial_peer, dials, introduce, link,
    listen_for,
};
use sqex_proto::session::Session;
use sqnr_core::PubKey;

use crate::engine::{Endpoint, Event, Report};

/// The whole of it: introduce, link, agree.
///
/// `Ok(None)`: nobody to be introduced to within the wait -- the peer did
/// not ask, and this side says nothing about why. `Err`: the introduction
/// was made and the connection was not, and the message says what stood in
/// the way. Either way the caller relays instead.
pub async fn connect(
    endpoint: Endpoint,
    seed: &[u8; 32],
    peer: PubKey,
    budget: Budget,
    report: &mut dyn Report,
) -> Result<Option<(quinn::Connection, Session, u64)>, String> {
    let Some(intro) = introduce(
        endpoint.address,
        endpoint.server.as_bytes(),
        seed,
        peer,
        budget.introduce_wait,
    )
    .await?
    else {
        return Ok(None);
    };
    let conn = link(intro, seed, peer, budget).await?;
    let me = PubKey::new(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    );
    let (session, id) = agree(&conn, seed, peer, dials(&me, &peer)).await?;
    report.event(Event::Direct {
        peer: conn.remote_address(),
    });
    Ok(Some((conn, session, id)))
}
