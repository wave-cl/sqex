//! SIP-27: statements identities have made about each other.
//!
//! The exchange holds them and is **not an authority over them**. It checks
//! that an issuer signed and that the shape is well formed, and it cannot check
//! whether a claim is true — nothing can, which is why the SIP puts the
//! decision with the consumer and why nothing here computes a score.
//!
//! Durable, unlike the beacon and the endpoint store beside it, and for a
//! reason that follows from what an attestation is: it is meant to be repeated
//! to third parties who never saw the connection, so it outlives the connection
//! by design and losing it on a restart would lose something nobody could
//! reproduce. It is also, in practice, permanent whatever this does — once read
//! it can be retained and replayed by anyone.

use std::collections::HashMap;
use std::sync::Mutex;

use sqex_proto::attest::{
    Attestation, CLAIM_REVOKES, Held, Invalid, MAX_PER_SUBJECT,
};
use sqnr_core::PubKey;

use crate::state::now_unix;

/// Every attestation the exchange has been given, by subject.
#[derive(Default)]
pub struct Attestations {
    held: Mutex<HashMap<PubKey, Vec<Attestation>>>,
}

/// Why a lodgement was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LodgeError {
    /// The signature, window or self-issue check failed.
    Invalid(Invalid),
    /// A revocation naming an attestation this exchange does not hold, or one
    /// by a different issuer. Refused rather than stored, because a revocation
    /// that names nothing is indistinguishable from one that names something
    /// the reader has not seen.
    NoSuchAttestation,
}

impl Attestations {
    pub fn new() -> Attestations {
        Attestations::default()
    }

    /// Take one, if it verifies.
    ///
    /// **Anybody may lodge**, not only the issuer: an attestation carries its
    /// own proof, so who handed it over establishes nothing and requiring the
    /// issuer to do it would mean an issuer who has gone away can never be
    /// quoted. That is the property the SIP means by "equally valid handed over
    /// on a USB stick".
    pub fn lodge(&self, a: Attestation) -> Result<(), LodgeError> {
        let now = now_unix();
        a.verify(now).map_err(LodgeError::Invalid)?;

        let mut held = self.held.lock().unwrap();
        if a.claim == CLAIM_REVOKES {
            // A withdrawal names an earlier attestation by its digest, and
            // **only its own issuer may withdraw it** — otherwise a withdrawal
            // would be a way to silence somebody else.
            let named: Option<[u8; 32]> = a.body.clone().try_into().ok();
            let Some(named) = named else {
                return Err(LodgeError::NoSuchAttestation);
            };
            let list = held.entry(a.subject).or_default();
            let before = list.len();
            list.retain(|x| !(x.digest() == named && x.issuer == a.issuer));
            if list.len() == before {
                return Err(LodgeError::NoSuchAttestation);
            }
            // The revocation itself is kept, so a consumer that arrives later
            // can see that the issuer withdrew rather than that the claim was
            // never made.
            list.push(a);
            return Ok(());
        }

        let list = held.entry(a.subject).or_default();
        // Lodging the same statement twice changes nothing. Keyed on the
        // digest, so a re-lodge after expiry-and-reissue is a new statement and
        // an identical one is not.
        let digest = a.digest();
        if list.iter().any(|x| x.digest() == digest) {
            return Ok(());
        }
        // A cap, not a quorum. It bounds storage and says nothing about weight
        // — a count of attestations measures how many keys somebody made.
        while list.len() >= MAX_PER_SUBJECT {
            list.remove(0);
        }
        list.push(a);
        Ok(())
    }

    /// What is held about `subject`, optionally from one issuer.
    ///
    /// The filter is SIP-27's requirement rather than a convenience: only
    /// attestations from issuers a consumer already trusts carry weight, so
    /// asking about one is the ordinary case.
    pub fn about(&self, subject: &PubKey, issuer: Option<&PubKey>) -> Held {
        let now = now_unix();
        let held = self.held.lock().unwrap();
        let attestations = held
            .get(subject)
            .map(|list| {
                list.iter()
                    .filter(|a| a.expires_at > now)
                    .filter(|a| issuer.is_none_or(|i| &a.issuer == i))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Held { now, attestations }
    }

    /// Drop what has expired. **Expiry is the only guarantee this design
    /// offers** — a revocation is a signed statement a consumer may never see —
    /// so it is enforced on read as well as here.
    pub fn sweep(&self) {
        let now = now_unix();
        let mut held = self.held.lock().unwrap();
        for list in held.values_mut() {
            list.retain(|a| a.expires_at > now);
        }
        held.retain(|_, list| !list.is_empty());
    }

    /// How many subjects have anything said about them. For `/status`.
    pub fn len(&self) -> usize {
        self.held.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
