//! SIP-27: one identity signs a statement about another.
//!
//! **These need signatures, unlike almost everything else the exchange holds.**
//! SIP-4, SIP-5 and SIP-28 lean on the transport — the connection proves who is
//! speaking, and the claim dies with it. An attestation is meant to be repeated
//! to third parties who never saw the connection, so it must carry its own
//! proof. That is the one place transport authentication is insufficient, and
//! saying so sharpens what the rest are for.
//!
//! The exchange is a convenient place to lodge them and **not an authority over
//! them**. A signed attestation is equally valid handed over on a USB stick.
//!
//! # No scores, and no counts that mean anything
//!
//! There is no global view of who is trustworthy and this must not grow one.
//! Anyone can generate identities and have them vouch for each other, so a
//! count of attestations measures how many keys somebody made. Only
//! attestations from issuers a consumer *already* trusts carry weight, which is
//! why [`Query`] filters by issuer and why nothing here computes a number.
//!
//! # What is not here
//!
//! **No negative claims.** The registry below holds statements an issuer makes
//! in somebody's favour and nothing against them. SIP-27 raised this as an open
//! question rather than a detail, and it is settled here in the conservative
//! direction: an unaccountable assertion that an identity misbehaved is a
//! defamation vector with no adjudicator, and the mechanism that would carry it
//! is the same one that carries everything else, so adding it later is possible
//! and removing it would not be.
//!
//! The escape hatch means somebody can encode anything at all in an unregistered
//! type, and an exchange cannot police semantics it does not parse. What stops
//! that becoming the same problem is a client rule rather than a server one:
//! **a claim of a type this build does not know MUST NOT be rendered as text
//! about a person.** It is reported as present and unreadable, which is what it
//! is.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for an attestation signature.
pub const ATTEST_CONTEXT: &[u8] = b"sqex-attestation-v1";

/// The subject operates the service named in the claim body.
///
/// SIP-27's own example: that a base58 string operates a particular service is
/// not something the key can establish alone.
pub const CLAIM_OPERATES: u8 = 0x01;
/// The issuer knows the subject by the name in the claim body. A nickname with
/// an author, which is the only kind that means anything.
pub const CLAIM_KNOWN_AS: u8 = 0x02;
/// The issuer examined the subject and says so. The body is free text
/// describing what was examined; it is not a certification of anything.
pub const CLAIM_REVIEWED: u8 = 0x03;
/// Withdraws an earlier attestation by this issuer, named by its digest.
///
/// A signed statement like any other, because a withdrawal that anybody could
/// make would be a way to silence an issuer.
pub const CLAIM_REVOKES: u8 = 0x04;

/// Bytes a claim body may occupy.
pub const MAX_CLAIM: usize = 256;
/// Attestations one subject may accumulate before the oldest are dropped.
///
/// A cap, not a quorum: it bounds storage and says nothing about weight. See
/// the module note on why a count is not evidence.
pub const MAX_PER_SUBJECT: usize = 64;
/// The longest an attestation may claim to be valid for.
///
/// **Expiry is the only guarantee this design offers.** A revocation is a
/// signed statement that a consumer may never see, so a claim whose window is
/// open for years is one that cannot be taken back in practice. A year is long
/// enough to be useful and short enough to be survivable.
pub const MAX_VALIDITY: u64 = 365 * 24 * 3600;

/// A signed statement by one identity about another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub subject: PubKey,
    pub issuer: PubKey,
    /// One of the `CLAIM_*` constants, or a type this build does not know.
    pub claim: u8,
    /// The claim's own parameter. Free bytes; UTF-8 for every registered type.
    pub body: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: [u8; 64],
}

/// Bytes an attestation occupies before its body.
pub const ATTESTATION_HEADER: usize = 32 + 32 + 1 + 2 + 8 + 8 + 64;

/// What an attestation's signature commits to.
///
/// Hash-then-sign over a fixed width, as SIP-10, SIP-20 and SIP-31 all do: the
/// signer sees a small fixed message whatever the body's size.
fn signing_input(
    subject: &PubKey,
    issuer: &PubKey,
    claim: u8,
    body: &[u8],
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(subject.as_bytes());
    h.update(issuer.as_bytes());
    h.update([claim]);
    h.update((body.len() as u16).to_be_bytes());
    h.update(body);
    h.update(issued_at.to_be_bytes());
    h.update(expires_at.to_be_bytes());
    let mut out = Vec::with_capacity(ATTEST_CONTEXT.len() + 32);
    out.extend_from_slice(ATTEST_CONTEXT);
    out.extend_from_slice(&h.finalize());
    out
}

/// Why an attestation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    BadSignature,
    /// `expires_at` is not after `issued_at`, or the window is longer than
    /// [`MAX_VALIDITY`].
    BadWindow,
    NotYetValid,
    Expired,
    /// An identity attesting to itself, which establishes nothing and would let
    /// anybody fill their own record.
    SelfIssued,
}

impl Attestation {
    /// Sign one as `issuer_seed`'s identity.
    pub fn sign(
        issuer_seed: &[u8; 32],
        subject: &PubKey,
        claim: u8,
        body: Vec<u8>,
        issued_at: u64,
        expires_at: u64,
    ) -> Attestation {
        let signing = SigningKey::from_bytes(issuer_seed);
        let issuer = PubKey::new(signing.verifying_key().to_bytes());
        let signature = signing
            .sign(&signing_input(
                subject, &issuer, claim, &body, issued_at, expires_at,
            ))
            .to_bytes();
        Attestation {
            subject: *subject,
            issuer,
            claim,
            body,
            issued_at,
            expires_at,
            signature,
        }
    }

    /// Check it. **Proves an issuer signed, and nothing about whether the claim
    /// is true** — the exchange cannot know that and neither can this.
    pub fn verify(&self, now: u64) -> std::result::Result<(), Invalid> {
        if self.issuer == self.subject {
            return Err(Invalid::SelfIssued);
        }
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_VALIDITY
        {
            return Err(Invalid::BadWindow);
        }
        if now < self.issued_at {
            return Err(Invalid::NotYetValid);
        }
        if now > self.expires_at {
            return Err(Invalid::Expired);
        }
        let vk = VerifyingKey::from_bytes(self.issuer.as_bytes())
            .map_err(|_| Invalid::BadSignature)?;
        vk.verify(
            &signing_input(
                &self.subject,
                &self.issuer,
                self.claim,
                &self.body,
                self.issued_at,
                self.expires_at,
            ),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Invalid::BadSignature)
    }

    /// This attestation's name: the hash of what it signed over.
    ///
    /// What a [`CLAIM_REVOKES`] body names, and it is the signing input rather
    /// than the serialised bytes so that the name does not depend on how it was
    /// written down.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(signing_input(
            &self.subject,
            &self.issuer,
            self.claim,
            &self.body,
            self.issued_at,
            self.expires_at,
        ))
        .into()
    }

    /// Whether this build knows what the claim means.
    ///
    /// **A claim of an unknown type MUST NOT be rendered as text about a
    /// person.** The escape hatch lets anybody encode anything, including the
    /// negative claims this version deliberately does not register, and a
    /// client that printed unknown bodies would be carrying them anyway.
    pub fn readable(&self) -> bool {
        matches!(
            self.claim,
            CLAIM_OPERATES | CLAIM_KNOWN_AS | CLAIM_REVIEWED | CLAIM_REVOKES
        ) && std::str::from_utf8(&self.body).is_ok()
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.subject.as_bytes());
        out.extend_from_slice(self.issuer.as_bytes());
        out.push(self.claim);
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.signature);
    }

    pub fn read(b: &[u8], o: &mut usize) -> Result<Attestation> {
        if b.len() < *o + 67 {
            return Err(Error::Malformed("attestation is truncated".into()));
        }
        let at = *o;
        let len = u16::from_be_bytes(b[at + 65..at + 67].try_into().unwrap()) as usize;
        if len > MAX_CLAIM {
            return Err(Error::Malformed(format!(
                "claim is {len} bytes, limit is {MAX_CLAIM}"
            )));
        }
        if b.len() < at + ATTESTATION_HEADER + len {
            return Err(Error::Malformed("attestation is truncated".into()));
        }
        let body = b[at + 67..at + 67 + len].to_vec();
        let rest = at + 67 + len;
        *o = at + ATTESTATION_HEADER + len;
        Ok(Attestation {
            subject: PubKey::new(b[at..at + 32].try_into().unwrap()),
            issuer: PubKey::new(b[at + 32..at + 64].try_into().unwrap()),
            claim: b[at + 64],
            body,
            issued_at: u64::from_be_bytes(b[rest..rest + 8].try_into().unwrap()),
            expires_at: u64::from_be_bytes(b[rest + 8..rest + 16].try_into().unwrap()),
            signature: b[rest + 16..rest + 80].try_into().unwrap(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + ATTESTATION_HEADER + self.body.len());
        out.push(TYPE_LODGE);
        self.write(&mut out);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Attestation> {
        if b.is_empty() || b[0] != TYPE_LODGE {
            return Err(Error::Malformed("not a lodge".into()));
        }
        let mut o = 1;
        let a = Attestation::read(b, &mut o)?;
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "lodge has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(a)
    }
}

pub const TYPE_LODGE: u8 = 0x01;
pub const TYPE_QUERY: u8 = 0x02;

/// Ask what has been said about an identity.
///
/// `issuer` is the filter SIP-27 requires: **only attestations from issuers a
/// consumer already trusts carry weight**, so asking about one is the ordinary
/// case and asking about all of them is the unusual one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    pub subject: PubKey,
    /// `None` for everything held about the subject.
    pub issuer: Option<PubKey>,
}

/// Bytes a `Query` occupies.
pub const QUERY_LEN: usize = 1 + 32 + 1 + 32;

impl Query {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(QUERY_LEN);
        out.push(TYPE_QUERY);
        out.extend_from_slice(self.subject.as_bytes());
        match &self.issuer {
            Some(i) => {
                out.push(1);
                out.extend_from_slice(i.as_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Query> {
        if b.len() != QUERY_LEN {
            return Err(Error::Malformed(format!(
                "query is {} bytes, want {QUERY_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_QUERY {
            return Err(Error::Malformed(format!("not a query (type {:#x})", b[0])));
        }
        Ok(Query {
            subject: PubKey::new(b[1..33].try_into().unwrap()),
            issuer: (b[33] != 0).then(|| PubKey::new(b[34..66].try_into().unwrap())),
        })
    }
}

/// What is held about a subject.
///
/// **No count is reported as if it meant something**, and a consumer should not
/// compute one: anyone can generate identities and have them vouch for each
/// other. The list is an input to the reader's own policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub now: u64,
    pub attestations: Vec<Attestation>,
}

impl Held {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.attestations.len() as u16).to_be_bytes());
        for a in &self.attestations {
            a.write(&mut out);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Held> {
        if b.len() < 10 {
            return Err(Error::Malformed("held is truncated".into()));
        }
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap()) as usize;
        if count > MAX_PER_SUBJECT {
            return Err(Error::Malformed(format!(
                "held carries {count}, limit is {MAX_PER_SUBJECT}"
            )));
        }
        let mut o = 10;
        let mut attestations = Vec::with_capacity(count);
        for _ in 0..count {
            attestations.push(Attestation::read(b, &mut o)?);
        }
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "held has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Held {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            attestations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    fn said(issuer: u8, subject: u8, claim: u8, body: &str) -> Attestation {
        let (seed, _) = who(issuer);
        let (_, about) = who(subject);
        Attestation::sign(&seed, &about, claim, body.as_bytes().to_vec(), 1000, 2000)
    }

    /// **Proves an issuer signed, and nothing about whether the claim is
    /// true.** Every field is bound, so a statement cannot be lifted onto a
    /// different subject or a longer window.
    #[test]
    fn an_attestation_verifies_and_every_field_is_bound() {
        let a = said(1, 2, CLAIM_OPERATES, "ex.squic.org");
        assert_eq!(a.verify(1500), Ok(()));

        let spoils: [fn(&mut Attestation); 5] = [
            |a| a.subject = PubKey::new([9; 32]),
            |a| a.issuer = PubKey::new([9; 32]),
            |a| a.claim = CLAIM_KNOWN_AS,
            |a| a.body[0] ^= 1,
            |a| a.expires_at += 1,
        ];
        for spoil in spoils {
            let mut bad = a.clone();
            spoil(&mut bad);
            assert!(
                matches!(bad.verify(1500), Err(Invalid::BadSignature)),
                "a changed field must break the signature"
            );
        }
    }

    /// The window is the only guarantee, so it is checked at both ends and
    /// bounded: a statement open for years is one that cannot be taken back.
    #[test]
    fn the_validity_window_is_enforced_at_both_ends_and_bounded() {
        let a = said(1, 2, CLAIM_OPERATES, "x");
        assert_eq!(a.verify(999), Err(Invalid::NotYetValid));
        assert_eq!(a.verify(2001), Err(Invalid::Expired));

        let (seed, _) = who(1);
        let (_, about) = who(2);
        let forever = Attestation::sign(&seed, &about, CLAIM_OPERATES, vec![], 0, MAX_VALIDITY + 1);
        assert_eq!(forever.verify(10), Err(Invalid::BadWindow));
        let backwards = Attestation::sign(&seed, &about, CLAIM_OPERATES, vec![], 2000, 1000);
        assert_eq!(backwards.verify(1500), Err(Invalid::BadWindow));
    }

    /// **An identity cannot vouch for itself.** It establishes nothing, and
    /// without the rule anybody could fill their own record.
    #[test]
    fn an_identity_cannot_attest_to_itself() {
        let (seed, me) = who(3);
        let a = Attestation::sign(&seed, &me, CLAIM_KNOWN_AS, b"myself".to_vec(), 1000, 2000);
        assert_eq!(a.verify(1500), Err(Invalid::SelfIssued));
    }

    /// **A claim this build does not know is not text about a person.** The
    /// escape hatch lets anybody encode anything — including the negative
    /// claims this version deliberately does not register — and a client that
    /// printed unknown bodies would be carrying them.
    #[test]
    fn an_unknown_claim_type_is_not_readable() {
        let known = said(1, 2, CLAIM_OPERATES, "ex.squic.org");
        assert!(known.readable());

        let unknown = said(1, 2, 0x7f, "something somebody made up");
        // It verifies — the signature does not care what the type means — and
        // it is still not renderable.
        assert_eq!(unknown.verify(1500), Ok(()));
        assert!(!unknown.readable(), "an unknown claim must not be printed");

        // Nor is a registered type carrying bytes that are not text.
        let (seed, _) = who(1);
        let (_, about) = who(2);
        let binary = Attestation::sign(&seed, &about, CLAIM_KNOWN_AS, vec![0xff, 0xfe], 1000, 2000);
        assert!(!binary.readable());
    }

    #[test]
    fn a_digest_names_what_was_signed_and_not_how_it_was_written() {
        let a = said(1, 2, CLAIM_OPERATES, "ex.squic.org");
        let mut o = 1;
        let round_tripped = Attestation::read(&a.encode(), &mut o).unwrap();
        assert_eq!(round_tripped, a);
        assert_eq!(round_tripped.digest(), a.digest());
        // A different statement is a different name.
        assert_ne!(said(1, 2, CLAIM_KNOWN_AS, "ex.squic.org").digest(), a.digest());
        assert_ne!(said(1, 4, CLAIM_OPERATES, "ex.squic.org").digest(), a.digest());
    }

    #[test]
    fn the_wire_round_trips_and_bounds_what_it_carries() {
        let a = said(1, 2, CLAIM_REVIEWED, "read the source");
        assert_eq!(Attestation::decode(&a.encode()).unwrap(), a);
        let mut extra = a.encode();
        extra.push(0);
        assert!(Attestation::decode(&extra).is_err());
        assert!(Attestation::decode(&a.encode()[..30]).is_err());

        let (seed, _) = who(1);
        let (_, about) = who(2);
        let big = Attestation::sign(
            &seed,
            &about,
            CLAIM_REVIEWED,
            vec![0; MAX_CLAIM + 1],
            1000,
            2000,
        );
        assert!(Attestation::decode(&big.encode()).is_err());

        let q = Query { subject: about, issuer: Some(who(1).1) };
        assert_eq!(Query::decode(&q.encode()).unwrap(), q);
        let all = Query { subject: about, issuer: None };
        assert_eq!(Query::decode(&all.encode()).unwrap(), all);

        let held = Held { now: 1500, attestations: vec![a.clone(), said(4, 2, CLAIM_KNOWN_AS, "A")] };
        assert_eq!(Held::decode(&held.encode()).unwrap(), held);
    }

    /// The registry holds nothing an issuer could use to say somebody
    /// misbehaved. Written as a test so that adding one is a deliberate act
    /// with a failing assertion in front of it, rather than a quiet extension.
    #[test]
    fn no_registered_claim_is_a_statement_against_somebody() {
        for claim in [CLAIM_OPERATES, CLAIM_KNOWN_AS, CLAIM_REVIEWED, CLAIM_REVOKES] {
            let a = said(1, 2, claim, "x");
            assert!(a.readable());
        }
        // Four, and no more. A fifth registered type is a decision this
        // assertion asks somebody to make on purpose.
        let registered = [CLAIM_OPERATES, CLAIM_KNOWN_AS, CLAIM_REVIEWED, CLAIM_REVOKES];
        assert_eq!(registered.len(), 4);
        for code in 0u8..=255 {
            if !registered.contains(&code) {
                assert!(!said(1, 2, code, "x").readable());
            }
        }
    }
}
