//! SIP-20 portable delegation credentials: one identity authorising another.
//!
//! An **account** signs a self-contained artifact naming a **delegate**, and
//! anybody holding the account's public key can verify it with no prior record
//! of the grant and no involvement from whoever issued it. SIP-11 specified
//! this SIP's existence and its shape, and deferred it until a second consumer
//! needed one; chat is that consumer.
//!
//! # Why chat needs it, which is sharper than convenience
//!
//! SIP-17 derives a sender's subkey from the sender's key and has each sender
//! count its own messages from zero. Two clients under one identity would
//! therefore share a subkey and reuse a nonce, which costs ChaCha20-Poly1305
//! both plaintexts and its authentication. Separating a person from a client is
//! what makes the nonce space safe, and this is what performs the separation: a
//! device is the unit because a device is the thing that holds a counter.
//!
//! # A credential is evidence, not authority
//!
//! It says which account vouches for a key. It does not entitle that key to
//! anything, and a service that admits a device merely because its credential
//! names an admitted account has moved a decision from the operator to whoever
//! holds an account key.
//!
//! # Where this lives
//!
//! The context string is `sqnr-delegate-v1` because an account key is an sqnr
//! identity and may be held in hardware. The type is here rather than in
//! sqnr-core because sqex is what verifies one today; if sqnr gains the ability
//! to *issue* one from a YubiKey, this belongs there and sqex should depend on
//! it rather than keep a second copy.

use crate::refusal::Code;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for a delegation signature.
pub const DELEGATION_CONTEXT: &[u8] = b"sqnr-delegate-v1";
/// Domain separator for a revocation signature (SIP-32).
///
/// `sqnr-` rather than `sqex-`, for the same reason the delegation context is:
/// an account key is an sqnr identity and may be held in hardware. A revocation
/// belongs to the identity that signs it, not to the service that stores it.
pub const REVOCATION_CONTEXT: &[u8] = b"sqnr-revoke-v1";

/// Bytes of a revocation.
pub const REVOCATION_LEN: usize = 32 + 32 + 8 + 64;

/// The scope this stack's chat services check for.
pub const SCOPE_CHAT: &str = "sqex-chat";

pub const MAX_SCOPE: usize = 32;
/// Bytes of a credential, before its scope.
pub const CREDENTIAL_LEN: usize = 32 + 32 + 1 + 8 + 8 + 64;
/// A sensible lifetime. Short because a compromised delegate stays valid until
/// it expires, and an offline verifier has nothing else to go on.
pub const RECOMMENDED_LIFETIME: u64 = 90 * 24 * 60 * 60;

/// An account's grant to one delegate, for one scope, until one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub account: PubKey,
    pub delegate: PubKey,
    /// A flat ASCII service label, compared for equality. Not a hierarchy and
    /// not a permission set: a grammar would have to be parsed identically by
    /// every verifier before it could be trusted, and disagreement about what a
    /// scope permits is worse than having none, because the failure is silent
    /// and lands in the permissive direction.
    pub scope: String,
    pub issued: u64,
    pub not_after: u64,
    pub signature: [u8; 64],
}

/// Everything but the signature, which is what the signature covers.
fn body(account: &PubKey, delegate: &PubKey, scope: &str, issued: u64, not_after: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(81 + scope.len());
    b.extend_from_slice(account.as_bytes());
    b.extend_from_slice(delegate.as_bytes());
    b.push(scope.len() as u8);
    b.extend_from_slice(scope.as_bytes());
    b.extend_from_slice(&issued.to_be_bytes());
    b.extend_from_slice(&not_after.to_be_bytes());
    b
}

/// Hash-then-sign, as SIP-10 does and for the same reason: the signing input is
/// 48 bytes whatever the credential's length, so a hardware key that cannot
/// stream a large message can still produce one. A YubiKey holding the account
/// identity signs its own devices into existence.
fn signing_input(body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DELEGATION_CONTEXT.len() + 32);
    m.extend_from_slice(DELEGATION_CONTEXT);
    m.extend_from_slice(&Sha256::digest(body));
    m
}

/// Why a credential was not honoured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// It names an account other than the one being asked about. A credential
    /// naming an account the verifier did not ask about is not evidence of
    /// anything.
    WrongAccount,
    /// Outside `issued..=not_after` by the verifier's clock.
    Expired,
    NotYetValid,
    /// For a different service. A credential for one scope MUST NOT authorise
    /// another, and an unrecognised scope is never treated as permissive.
    WrongScope,
    BadSignature,
}

impl Invalid {
    pub fn as_str(&self) -> &'static str {
        match self {
            Invalid::WrongAccount => "wrong_account",
            Invalid::Expired => "expired",
            Invalid::NotYetValid => "not_yet_valid",
            Invalid::WrongScope => "wrong_scope",
            Invalid::BadSignature => "bad_signature",
        }
    }

    /// The wire code for this reason. Exhaustive on purpose: a new variant is a
    /// compile error here until it is given one, which is what keeps the
    /// registry from drifting away from the enum.
    pub fn code(&self) -> Code {
        match self {
            Invalid::WrongAccount => Code::WrongAccount,
            Invalid::Expired => Code::Expired,
            Invalid::NotYetValid => Code::NotYetValid,
            Invalid::WrongScope => Code::WrongScope,
            Invalid::BadSignature => Code::BadSignature,
        }
    }
}

impl Credential {
    /// Issue one. The account signs; the delegate is named and not consulted.
    ///
    /// Signing in advance is the point: it needs the account online once, which
    /// is what a hardware-held identity can manage, rather than at every
    /// verification, which it cannot.
    pub fn issue(
        account_seed: &[u8; 32],
        delegate: &PubKey,
        scope: &str,
        issued: u64,
        not_after: u64,
    ) -> Result<Credential> {
        if scope.len() > MAX_SCOPE {
            return Err(Error::Malformed(format!(
                "scope is {} bytes, limit is {MAX_SCOPE}",
                scope.len()
            )));
        }
        if not_after <= issued {
            return Err(Error::Malformed(
                "a credential must expire after it was issued".into(),
            ));
        }
        let signing = SigningKey::from_bytes(account_seed);
        let account = PubKey::new(signing.verifying_key().to_bytes());
        let b = body(&account, delegate, scope, issued, not_after);
        Ok(Credential {
            account,
            delegate: *delegate,
            scope: scope.to_string(),
            issued,
            not_after,
            signature: signing.sign(&signing_input(&b)).to_bytes(),
        })
    }

    /// Check it, in the order SIP-20 gives, stopping at the first failure.
    ///
    /// The delegate key is not checked for anything. It is a name the account
    /// has bound itself to, and whether the holder of it is present is a
    /// question the *transport* answers — SIP-3 proves possession at the
    /// handshake, and this says what that possession means.
    pub fn verify(
        &self,
        expect_account: &PubKey,
        expect_scope: &str,
        now: u64,
    ) -> std::result::Result<(), Invalid> {
        if &self.account != expect_account {
            return Err(Invalid::WrongAccount);
        }
        if now < self.issued {
            return Err(Invalid::NotYetValid);
        }
        if now > self.not_after {
            return Err(Invalid::Expired);
        }
        if self.scope != expect_scope {
            return Err(Invalid::WrongScope);
        }
        let vk =
            VerifyingKey::from_bytes(self.account.as_bytes()).map_err(|_| Invalid::BadSignature)?;
        let b = body(
            &self.account,
            &self.delegate,
            &self.scope,
            self.issued,
            self.not_after,
        );
        vk.verify(&signing_input(&b), &Signature::from_bytes(&self.signature))
            .map_err(|_| Invalid::BadSignature)
    }

    pub fn wire_len(&self) -> usize {
        CREDENTIAL_LEN + self.scope.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = body(
            &self.account,
            &self.delegate,
            &self.scope,
            self.issued,
            self.not_after,
        );
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Credential> {
        if b.len() < 65 {
            return Err(Error::Malformed(format!(
                "credential is {} bytes, want at least 65",
                b.len()
            )));
        }
        let scope_len = b[64] as usize;
        if scope_len > MAX_SCOPE {
            return Err(Error::Malformed(format!(
                "scope is {scope_len} bytes, limit is {MAX_SCOPE}"
            )));
        }
        if b.len() != CREDENTIAL_LEN + scope_len {
            return Err(Error::Malformed(format!(
                "credential is {} bytes, want {}",
                b.len(),
                CREDENTIAL_LEN + scope_len
            )));
        }
        let o = 65 + scope_len;
        Ok(Credential {
            account: PubKey::new(b[0..32].try_into().unwrap()),
            delegate: PubKey::new(b[32..64].try_into().unwrap()),
            scope: String::from_utf8(b[65..65 + scope_len].to_vec())
                .map_err(|_| Error::Malformed("scope is not UTF-8".into()))?,
            issued: u64::from_be_bytes(b[o..o + 8].try_into().unwrap()),
            not_after: u64::from_be_bytes(b[o + 8..o + 16].try_into().unwrap()),
            signature: b[o + 16..o + 80].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    fn credential() -> (Credential, PubKey) {
        let (account_seed, account) = identity(1);
        let (_, device) = identity(2);
        (
            Credential::issue(&account_seed, &device, SCOPE_CHAT, 1000, 2000).unwrap(),
            account,
        )
    }

    #[test]
    fn a_credential_round_trips_and_verifies() {
        let (c, account) = credential();
        assert_eq!(Credential::decode(&c.encode()).unwrap(), c);
        assert_eq!(c.encode().len(), c.wire_len());
        assert!(c.verify(&account, SCOPE_CHAT, 1500).is_ok());
    }

    #[test]
    fn it_is_bounded_in_time_at_both_ends() {
        let (c, account) = credential();
        assert_eq!(
            c.verify(&account, SCOPE_CHAT, 999),
            Err(Invalid::NotYetValid)
        );
        assert!(c.verify(&account, SCOPE_CHAT, 1000).is_ok());
        assert!(c.verify(&account, SCOPE_CHAT, 2000).is_ok());
        assert_eq!(c.verify(&account, SCOPE_CHAT, 2001), Err(Invalid::Expired));
    }

    #[test]
    fn a_scope_does_not_authorise_another() {
        // An unrecognised scope is never permissive: that is the whole reason
        // the field is required rather than optional.
        let (c, account) = credential();
        assert_eq!(
            c.verify(&account, "sqex-admin", 1500),
            Err(Invalid::WrongScope)
        );
    }

    #[test]
    fn a_credential_naming_another_account_is_not_evidence() {
        let (c, _) = credential();
        let (_, someone_else) = identity(9);
        assert_eq!(
            c.verify(&someone_else, SCOPE_CHAT, 1500),
            Err(Invalid::WrongAccount)
        );
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let (base, account) = credential();
        let (_, other_device) = identity(7);

        let mut tampered = base.clone();
        tampered.delegate = other_device;
        assert_eq!(
            tampered.verify(&account, SCOPE_CHAT, 1500),
            Err(Invalid::BadSignature)
        );

        // Extending the lifetime is the attack worth naming: without the
        // signature covering it, a credential would never really expire.
        let mut tampered = base.clone();
        tampered.not_after = u64::MAX;
        assert_eq!(
            tampered.verify(&account, SCOPE_CHAT, 1500),
            Err(Invalid::BadSignature)
        );

        let mut tampered = base.clone();
        tampered.issued = 0;
        assert_eq!(
            tampered.verify(&account, SCOPE_CHAT, 1500),
            Err(Invalid::BadSignature)
        );

        // And the scope, so a chat device cannot become an administrator.
        let mut tampered = base;
        tampered.scope = "sqex-admin".into();
        assert_eq!(
            tampered.verify(&account, "sqex-admin", 1500),
            Err(Invalid::BadSignature)
        );
    }

    #[test]
    fn the_signing_input_is_fixed_width_so_hardware_can_sign_it() {
        // 16 bytes of context and a 32-byte digest, whatever the credential.
        let (short, _) = credential();
        let (account_seed, _) = identity(1);
        let (_, device) = identity(2);
        let long =
            Credential::issue(&account_seed, &device, &"x".repeat(MAX_SCOPE), 1000, 2000).unwrap();
        assert_eq!(signing_input(&short.encode()).len(), 48);
        assert_eq!(signing_input(&long.encode()).len(), 48);
    }

    #[test]
    fn an_expiry_before_its_issue_is_refused_at_source() {
        let (account_seed, _) = identity(1);
        let (_, device) = identity(2);
        assert!(Credential::issue(&account_seed, &device, SCOPE_CHAT, 2000, 1000).is_err());
        assert!(Credential::issue(&account_seed, &device, SCOPE_CHAT, 1000, 1000).is_err());
    }

    #[test]
    fn an_overlong_scope_is_refused_both_ways() {
        let (account_seed, _) = identity(1);
        let (_, device) = identity(2);
        assert!(
            Credential::issue(&account_seed, &device, &"x".repeat(MAX_SCOPE + 1), 1, 2).is_err()
        );

        let (c, _) = credential();
        let mut bytes = c.encode();
        bytes[64] = (MAX_SCOPE + 1) as u8;
        assert!(Credential::decode(&bytes).is_err());
    }
}

/// An account withdrawing a device it credentialed (SIP-32).
///
/// The mirror of a [`Credential`], and deliberately the same shape: one
/// identity speaking about another, meant to be repeated. A credential was a
/// portable artifact anybody could check and its undoing was a request over an
/// authenticated connection — so the mechanism SIP-22 advertises as the thing a
/// portable credential structurally cannot do was itself the thing that could
/// not travel.
///
/// # Signed by the account, and why not by a device
///
/// SIP-22 lets any registered device of an account revoke another, subject to
/// seniority. A device could sign, and the result would not be checkable by
/// anybody: seniority is evaluated against `added` times only the exchange
/// holds. A signed statement whose authority cannot be evaluated is worse than
/// an unsigned one, because it looks like evidence. So the portable form is the
/// one whose authority is self-contained, and device-initiated revocation
/// survives as an explicitly **local** act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revocation {
    pub account: PubKey,
    pub device: PubKey,
    /// The account's own clock. Advisory, and checked only for not being in the
    /// future: what makes a revocation bite is that it exists, not when.
    pub issued: u64,
    pub signature: [u8; 64],
}

fn revocation_body(account: &PubKey, device: &PubKey, issued: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(72);
    b.extend_from_slice(account.as_bytes());
    b.extend_from_slice(device.as_bytes());
    b.extend_from_slice(&issued.to_be_bytes());
    b
}

fn revocation_input(body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(REVOCATION_CONTEXT.len() + 32);
    m.extend_from_slice(REVOCATION_CONTEXT);
    m.extend_from_slice(&Sha256::digest(body));
    m
}

impl Revocation {
    /// Sign one. The account withdraws; the device is named and not consulted.
    pub fn issue(account_seed: &[u8; 32], device: &PubKey, issued: u64) -> Revocation {
        let signing = SigningKey::from_bytes(account_seed);
        let account = PubKey::new(signing.verifying_key().to_bytes());
        let body = revocation_body(&account, device, issued);
        Revocation {
            account,
            device: *device,
            issued,
            signature: signing.sign(&revocation_input(&body)).to_bytes(),
        }
    }

    /// Check it, stopping at the first failure.
    ///
    /// `now` allows a small skew forward: an account whose clock runs fast must
    /// not produce a revocation nobody will accept. There is no expiry — a
    /// withdrawal that lapsed would re-admit the key it withdrew.
    pub fn verify(
        &self,
        expect_account: &PubKey,
        now: u64,
        skew: u64,
    ) -> std::result::Result<(), Invalid> {
        if &self.account != expect_account {
            return Err(Invalid::WrongAccount);
        }
        if self.issued > now.saturating_add(skew) {
            return Err(Invalid::NotYetValid);
        }
        let vk =
            VerifyingKey::from_bytes(self.account.as_bytes()).map_err(|_| Invalid::BadSignature)?;
        let body = revocation_body(&self.account, &self.device, self.issued);
        vk.verify(
            &revocation_input(&body),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| Invalid::BadSignature)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = revocation_body(&self.account, &self.device, self.issued);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Revocation> {
        if b.len() != REVOCATION_LEN {
            return Err(Error::Malformed(format!(
                "revocation is {} bytes, want {REVOCATION_LEN}",
                b.len()
            )));
        }
        Ok(Revocation {
            account: PubKey::new(b[0..32].try_into().unwrap()),
            device: PubKey::new(b[32..64].try_into().unwrap()),
            issued: u64::from_be_bytes(b[64..72].try_into().unwrap()),
            signature: b[72..136].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;

    fn key(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    #[test]
    fn a_revocation_verifies_under_the_account_alone() {
        let (seed, account) = key(1);
        let (_, device) = key(2);
        let r = Revocation::issue(&seed, &device, 1000);
        assert_eq!(r.verify(&account, 1000, 60), Ok(()));
        // The whole point: no exchange is consulted.
        assert_eq!(Revocation::decode(&r.encode()).unwrap(), r);
    }

    /// Each field, one at a time. Varying two would let a construction that
    /// omitted one of them still pass.
    #[test]
    fn every_field_is_covered() {
        let (seed, account) = key(1);
        let (_, device) = key(2);
        let (_, other) = key(3);
        let r = Revocation::issue(&seed, &device, 1000);

        for (what, tampered) in [
            ("device", Revocation { device: other, ..r }),
            ("issued", Revocation { issued: 1001, ..r }),
            (
                "account",
                Revocation {
                    account: other,
                    ..r
                },
            ),
        ] {
            let expect = if what == "account" { &other } else { &account };
            assert!(
                tampered.verify(expect, 2000, 60).is_err(),
                "a signature survived a changed {what}"
            );
        }
    }

    #[test]
    fn a_revocation_naming_another_account_is_not_evidence() {
        let (seed, _) = key(1);
        let (_, device) = key(2);
        let (_, stranger) = key(3);
        let r = Revocation::issue(&seed, &device, 1000);
        assert_eq!(r.verify(&stranger, 2000, 60), Err(Invalid::WrongAccount));
    }

    /// A withdrawal that lapsed would re-admit the key it withdrew, so there is
    /// no expiry — only a bound on claiming the future.
    #[test]
    fn a_revocation_does_not_expire_but_cannot_be_postdated() {
        let (seed, account) = key(1);
        let (_, device) = key(2);
        let r = Revocation::issue(&seed, &device, 1000);
        assert_eq!(r.verify(&account, u64::MAX / 2, 60), Ok(()), "it expired");
        assert_eq!(
            Revocation::issue(&seed, &device, 9_999).verify(&account, 1000, 60),
            Err(Invalid::NotYetValid)
        );
    }

    /// The two contexts must not be interchangeable, or a delegation could be
    /// presented as its own withdrawal.
    #[test]
    fn the_contexts_are_separate() {
        assert_ne!(DELEGATION_CONTEXT, REVOCATION_CONTEXT);
        assert!(!REVOCATION_CONTEXT.starts_with(DELEGATION_CONTEXT));
        assert!(!DELEGATION_CONTEXT.starts_with(REVOCATION_CONTEXT));
    }
}
