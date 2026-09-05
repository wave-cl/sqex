//! Telling somebody you want to call them.
//!
//! # Why a ring exists at all
//!
//! A SIP-12 session opens only when *both* identities have named the other, and
//! the exchange will not say that somebody is waiting. `OpenState::Waiting` is
//! explicit about it:
//!
//! > Recorded; the peer has not asked for a session with you. Nothing about
//! > them is disclosed — not even that they exist.
//!
//! That is a privacy property, not a gap: an exchange that answered "somebody
//! wants you" would leak the shape of everyone's contacts to anyone who asked.
//! So there is no way to *discover* an incoming call, and a caller has to say
//! so out of band. This is that.
//!
//! # Why the mailbox
//!
//! A ring rides the SIP-5 mailbox, sealed to the recipient's **identity key**.
//! That is the property that decides it: sealing to an identity needs nothing
//! from the recipient beforehand, so a first-ever caller can ring somebody who
//! has never heard of them. A chat channel could not — SIP-23 forbids sealing
//! to a device that has published no prekeys, which is exactly the person you
//! have never spoken to.
//!
//! Two things fall out for free. Mailbox delivery leaves a tombstone when it is
//! collected, so a caller can tell that their ring was *picked up* rather than
//! merely sent. And the mailbox's own quotas bound how much ringing anyone can
//! do without any new machinery.
//!
//! # What a ring is not
//!
//! **A ring is not authenticated.** Who sent it is the exchange's observation
//! of who connected (SIP-3), not a signature, and the exchange could lie. So a
//! ring is a *request to look*, never a statement of fact, and an interface
//! must not present the caller as established until the session is.
//!
//! The damage that can do is bounded, and worth stating because it is the
//! reason this is acceptable: answering names an identity, and the session
//! derives from *that* identity's key. Accepting a forged ring therefore
//! cannot connect you to the forger — it opens a session with whoever was
//! named, and if they are not calling, nothing establishes. A lie costs the
//! liar a call that never happens.

use sqex_proto::mailbox::{self, ById, Fetched, Listing, Send};
use sqnr::Client;
use sqnr_core::PubKey;

/// Marks a mailbox message as a ring rather than anything else that may one day
/// share the mailbox. Unknown versions are ignored rather than refused, so a
/// later ring can add a field without every older client treating it as
/// corruption.
const RING_V1: u8 = 0x01;

/// How long a ring is worth acting on.
///
/// The mailbox holds a message for a week, which is right for mail and absurd
/// for a telephone: nobody wants Tuesday's call ringing on Thursday. A ring
/// older than this is deleted and never shown.
pub const RING_TTL_SECS: u64 = 60;

/// Somebody would like to call you.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ring {
    /// Who the exchange saw send it. **Its observation, not a proof** — see the
    /// module note.
    pub from: PubKey,
    /// When the exchange received it, by the exchange's clock. Used only to
    /// discard stale rings, so a difference of a few seconds does not matter.
    pub at: u64,
    /// The mailbox id it arrived as, so it can be deleted once dealt with.
    pub id: u64,
}

/// The sealed body. Deliberately almost empty: everything a ring needs to say
/// is *that it happened*, and who from — and who from is the exchange's to
/// report, not the payload's to claim.
fn body() -> Vec<u8> {
    vec![RING_V1]
}

fn is_ring(plaintext: &[u8]) -> bool {
    plaintext.first() == Some(&RING_V1)
}

/// Ring `peer`: leave a sealed note saying you would like to talk.
///
/// Best effort by design. A ring that does not arrive costs a call that has to
/// be arranged some other way; a call that refuses to start because the ring
/// failed would be worse, so callers should not treat this as fatal.
pub async fn ring(client: &mut Client, peer: PubKey) -> Result<(), String> {
    let sealed = mailbox::seal(&peer, &body()).map_err(|e| e.to_string())?;
    let (code, reply) = client
        .post(
            "/mailbox/send",
            Send {
                recipient: peer,
                sealed,
            }
            .encode(),
        )
        .await?;
    if code != 200 {
        return Err(format!(
            "ring refused ({code}): {}",
            crate::engine::said(&reply)
        ));
    }
    Ok(())
}

/// Collect the rings waiting for us, discarding anything stale or unreadable.
///
/// Every message it looks at is deleted, whether or not it was a ring we could
/// use: a mailbox that fills with things nobody collects stops accepting the
/// ones that matter, and the quota is per recipient.
///
/// `blocked` never rings. Reusing one block list rather than inventing a second
/// is deliberate — there should be one answer to "make them stop", not one for
/// messages and a different one for calls.
pub async fn collect(
    client: &mut Client,
    seed: &[u8; 32],
    blocked: &[PubKey],
) -> Result<Vec<Ring>, String> {
    let (code, body_bytes) = client.post("/mailbox/list", Vec::new()).await?;
    if code != 200 {
        return Err(format!("list refused ({code})"));
    }
    let listing = Listing::decode(&body_bytes).map_err(|e| e.to_string())?;

    let mut rings = Vec::new();
    for entry in &listing.entries {
        let stale = listing.now.saturating_sub(entry.received) > RING_TTL_SECS;
        let blocked_sender = blocked.contains(&entry.sender);

        // A blocked or stale message is dropped without being opened. Nothing
        // is learned from it, and opening it would only spend the time.
        if stale || blocked_sender {
            delete(client, entry.id).await;
            continue;
        }
        let (code, fetched) = client
            .post("/mailbox/fetch", ById::fetch(entry.id).encode())
            .await?;
        if code != 200 {
            continue;
        }
        let Ok(got) = Fetched::decode(&fetched) else {
            continue;
        };
        if !got.found {
            continue;
        }
        // Anything we cannot open, or that is not a ring, is somebody else's
        // business or a version we do not know. Delete it either way: leaving
        // it would have us re-fetch it on every sweep forever.
        match mailbox::open(seed, &got.sealed) {
            Ok(plaintext) if is_ring(&plaintext) => {
                rings.push(Ring {
                    from: entry.sender,
                    at: entry.received,
                    id: entry.id,
                });
            }
            _ => {}
        }
        delete(client, entry.id).await;
    }
    Ok(rings)
}

/// Best effort: a ring that is acted on but not deleted would ring again.
async fn delete(client: &mut Client, id: u64) {
    let _ = client
        .post("/mailbox/delete", ById::delete(id).encode())
        .await;
}
