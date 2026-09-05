//! SIP-31 signed and chained channel entries: proof of authorship that outlives
//! the connection that carried it.
//!
//! SIP-16 says an entry's `account` and `device` are "the exchange's
//! observation of the connection that posted" and "neither is a cryptographic
//! fact". SIP-17 then hands every member the means to derive every other
//! device's sealing subkey, so a valid ciphertext proves only that *some*
//! member made it. Put together: any member can mint a well-formed entry
//! attributable to any other, and the only thing stopping them is the exchange
//! declining to stamp somebody else's device on their connection.
//!
//! That check is enough while the entry stays where it was written and worth
//! nothing once it is repeated — to a replica, an export, a restored backup.
//! SIP-27 set the test: an attestation repeated to third parties who never saw
//! the connection must carry its own proof.
//!
//! # Three terms stop a signature travelling
//!
//! [`Place`] holds them, and each closes a replay that is otherwise available.
//!
//! - `exchange` is the origin's SIP-9 key. A direct message's identifier is
//!   derived from its two accounts, so one conversation has **identical**
//!   channel bytes on every exchange in existence; without this an entry lifts
//!   from one into another's copy of the same conversation and verifies. SIP-10
//!   binds its server key against exactly this.
//! - `instance` dates the channel *incarnation*. A recreated direct message
//!   reuses its identifier and restarts its numbering, so without this every
//!   entry of the first incarnation replays into the second.
//! - `channel` is the conversation itself.
//!
//! The account is bound in the terms below rather than left implicit, because
//! nothing in SIP-20 forbids two accounts credentialing one device, and without
//! it one signed entry is attributable to either.
//!
//! # Verifying a signature is half the job
//!
//! [`verify_entry`] proves *a key* signed. It says nothing about whose key it
//! is. A verifier MUST also check a SIP-20 [`crate::credential::Credential`]
//! binding that device to the entry's account — SIP-20 puts it plainly, "a
//! credential naming an account the verifier did not ask about is not evidence
//! of anything". This is the check most likely to be skipped, because the
//! incomplete version returns `true` on every honest message and is wrong only
//! on the attack.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for an entry signature.
pub const ENTRY_CONTEXT: &[u8] = b"sqex-entry-v1";
/// Domain separator for a membership-action signature.
///
/// Distinct from [`ENTRY_CONTEXT`] so an entry signature can never be presented
/// as an action signature or the reverse.
pub const ACTION_CONTEXT: &[u8] = b"sqex-action-v1";

/// Bytes an action's own parameters may occupy: a role byte, an epoch, a
/// retention pair, or a SIP-32 constitution digest.
///
/// **Widened from 8 to 32 by SIP-32, and it costs nothing on any wire.** `arg`
/// is never transmitted: both sides reconstruct it — the exchange from the
/// request it received, the client from the request it sent — which is exactly
/// what makes it a binding rather than a claim.
pub const MAX_ARG: usize = 32;

/// A device's first link in a channel. Not a hash of anything — there is
/// nothing before it.
pub const GENESIS: [u8; 32] = [0u8; 32];

/// Where a signature was made, and therefore where it is valid.
///
/// All three terms exist to stop a signature travelling; see the module
/// documentation for what each of them closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    /// The origin exchange's pinned SIP-9 Ed25519 identity.
    pub exchange: PubKey,
    /// 32 random bytes the exchange mints per channel *incarnation*, zero where
    /// SIP-16 requires the epoch to be withheld.
    pub instance: [u8; 32],
    pub channel: [u8; 32],
}

/// Everything an entry signature commits to.
///
/// The body is committed to by hash rather than inline, which is what lets a
/// redacted entry keep a signature that still verifies after its bytes are
/// gone. Signing the body directly would force a choice between discarding the
/// signature on redaction — making every deleted message look forged — and
/// refusing to redact at all.
#[derive(Debug, Clone, Copy)]
pub struct EntryTerms<'a> {
    pub place: Place,
    pub account: PubKey,
    pub device: PubKey,
    pub epoch: u32,
    pub msg_seq: u64,
    pub expires_after: u32,
    pub chain_seq: u64,
    pub prev: [u8; 32],
    pub body: &'a [u8],
}

/// Everything a membership-action signature commits to.
#[derive(Debug, Clone, Copy)]
pub struct ActionTerms<'a> {
    pub place: Place,
    pub actor: PubKey,
    pub actor_device: PubKey,
    /// The SIP-16 system event this will produce.
    pub event: u8,
    pub subject: PubKey,
    /// The operation's own parameters: a role byte, `retention || max_entries`,
    /// an epoch, or nothing.
    pub arg: &'a [u8],
    pub chain_seq: u64,
    pub prev: [u8; 32],
}

impl Place {
    fn write(&self, h: &mut Sha256) {
        h.update(self.exchange.as_bytes());
        h.update(self.instance);
        h.update(self.channel);
    }
}

impl EntryTerms<'_> {
    /// The 45 bytes an entry signature is made over: the context, then one
    /// digest of everything else.
    ///
    /// Hash-then-sign over a fixed width follows SIP-10 and SIP-20 for the
    /// reason both give — a signer sees a small fixed message whether the body
    /// is empty or 32 KiB.
    pub fn input(&self) -> Vec<u8> {
        self.input_hashed(&Sha256::digest(self.body).into())
    }

    /// The same, from a body hash rather than a body.
    ///
    /// What a **tombstone** is verified with. SIP-16's redaction takes the
    /// bytes and keeps the entry, so the hash the exchange retained is the only
    /// thing left to check against — which is the whole reason the commitment
    /// is to the hash rather than to the body. Signing the body inline would
    /// have forced a choice between discarding the signature on redaction,
    /// making every deleted message read as forged, and refusing to redact.
    pub fn input_hashed(&self, body_hash: &[u8; 32]) -> Vec<u8> {
        let mut h = Sha256::new();
        self.place.write(&mut h);
        h.update(self.account.as_bytes());
        h.update(self.device.as_bytes());
        h.update(self.epoch.to_be_bytes());
        h.update(self.msg_seq.to_be_bytes());
        h.update(self.expires_after.to_be_bytes());
        h.update(self.chain_seq.to_be_bytes());
        h.update(self.prev);
        h.update(body_hash);

        let mut out = Vec::with_capacity(ENTRY_CONTEXT.len() + 32);
        out.extend_from_slice(ENTRY_CONTEXT);
        out.extend_from_slice(&h.finalize());
        out
    }
}

impl ActionTerms<'_> {
    /// The 46 bytes an action signature is made over.
    pub fn input(&self) -> Result<Vec<u8>> {
        if self.arg.len() > MAX_ARG {
            return Err(Error::Malformed(format!(
                "action arg is {} bytes, limit is {MAX_ARG}",
                self.arg.len()
            )));
        }
        let mut h = Sha256::new();
        self.place.write(&mut h);
        h.update(self.actor.as_bytes());
        h.update(self.actor_device.as_bytes());
        h.update([self.event]);
        h.update(self.subject.as_bytes());
        h.update([self.arg.len() as u8]);
        h.update(self.arg);
        h.update(self.chain_seq.to_be_bytes());
        h.update(self.prev);

        let mut out = Vec::with_capacity(ACTION_CONTEXT.len() + 32);
        out.extend_from_slice(ACTION_CONTEXT);
        out.extend_from_slice(&h.finalize());
        Ok(out)
    }
}

/// The next `prev` in a device's chain: the hash of the signing input it just
/// made.
///
/// **The chain links signing inputs, not entries.** A client cannot hash an
/// entry before the exchange has numbered and timestamped it, so a chain over
/// entries would be uncomputable by the only party able to sign it. A signing
/// input is fully determined at the moment of signing.
pub fn link(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Sign an entry as `device_seed`'s device.
///
/// The caller is responsible for `terms.device` being this seed's public key;
/// a signature under one device naming another simply fails to verify.
pub fn sign_entry(device_seed: &[u8; 32], terms: &EntryTerms) -> [u8; 64] {
    SigningKey::from_bytes(device_seed)
        .sign(&terms.input())
        .to_bytes()
}

/// Check an entry signature under the device the terms name.
///
/// Proves a key signed and nothing about whose key it is; see the module
/// documentation for the SIP-20 step that must follow.
pub fn verify_entry(terms: &EntryTerms, sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(terms.device.as_bytes()) else {
        return false;
    };
    vk.verify(&terms.input(), &Signature::from_bytes(sig))
        .is_ok()
}

/// Check an entry signature against a body hash rather than a body.
///
/// For a tombstone, whose bytes are gone and whose hash survives.
pub fn verify_entry_hashed(terms: &EntryTerms, body_hash: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(terms.device.as_bytes()) else {
        return false;
    };
    vk.verify(&terms.input_hashed(body_hash), &Signature::from_bytes(sig))
        .is_ok()
}

/// Sign a membership action as `device_seed`'s device.
pub fn sign_action(device_seed: &[u8; 32], terms: &ActionTerms) -> Result<[u8; 64]> {
    Ok(SigningKey::from_bytes(device_seed)
        .sign(&terms.input()?)
        .to_bytes())
}

/// Check an action signature under the actor's device.
pub fn verify_action(terms: &ActionTerms, sig: &[u8; 64]) -> bool {
    let Ok(input) = terms.input() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(terms.actor_device.as_bytes()) else {
        return false;
    };
    vk.verify(&input, &Signature::from_bytes(sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> ([u8; 32], PubKey) {
        let seed = [n; 32];
        let pk = PubKey::new(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        (seed, pk)
    }

    fn place() -> Place {
        let (_, exchange) = key(9);
        Place {
            exchange,
            instance: [4; 32],
            channel: [7; 32],
        }
    }

    fn entry_terms<'a>(body: &'a [u8], device: PubKey, account: PubKey) -> EntryTerms<'a> {
        EntryTerms {
            place: place(),
            account,
            device,
            epoch: 3,
            msg_seq: 11,
            expires_after: 60,
            chain_seq: 5,
            prev: [1; 32],
            body,
        }
    }

    /// Every field, changed one at a time. Varying two at once would let a
    /// construction that omitted one of them still pass.
    #[test]
    fn every_entry_term_is_covered() {
        let (seed, device) = key(1);
        let (_, account) = key(2);
        let body = b"hello".to_vec();
        let base = entry_terms(&body, device, account);
        let sig = sign_entry(&seed, &base);
        assert!(verify_entry(&base, &sig), "the honest case must verify");

        let (_, other_key) = key(3);
        let other_body = b"hellp".to_vec();

        let mutations: Vec<(&str, EntryTerms)> = vec![
            (
                "exchange",
                EntryTerms {
                    place: Place {
                        exchange: other_key,
                        ..base.place
                    },
                    ..base
                },
            ),
            (
                "instance",
                EntryTerms {
                    place: Place {
                        instance: [5; 32],
                        ..base.place
                    },
                    ..base
                },
            ),
            (
                "channel",
                EntryTerms {
                    place: Place {
                        channel: [8; 32],
                        ..base.place
                    },
                    ..base
                },
            ),
            (
                "account",
                EntryTerms {
                    account: other_key,
                    ..base
                },
            ),
            ("epoch", EntryTerms { epoch: 4, ..base }),
            (
                "msg_seq",
                EntryTerms {
                    msg_seq: 12,
                    ..base
                },
            ),
            (
                "expires_after",
                EntryTerms {
                    expires_after: 61,
                    ..base
                },
            ),
            (
                "chain_seq",
                EntryTerms {
                    chain_seq: 6,
                    ..base
                },
            ),
            (
                "prev",
                EntryTerms {
                    prev: [2; 32],
                    ..base
                },
            ),
            (
                "body",
                EntryTerms {
                    body: &other_body,
                    ..base
                },
            ),
        ];

        for (what, terms) in mutations {
            assert!(
                !verify_entry(&terms, &sig),
                "a signature survived a changed {what}, so {what} is not covered"
            );
        }
    }

    /// `device` is covered too, but differently: it is the verification key, so
    /// changing it makes the signature check against somebody else entirely.
    #[test]
    fn a_signature_does_not_verify_under_another_device() {
        let (seed, device) = key(1);
        let (_, account) = key(2);
        let (_, impostor) = key(3);
        let body = b"hello".to_vec();

        let terms = entry_terms(&body, device, account);
        let sig = sign_entry(&seed, &terms);

        let claimed = EntryTerms {
            device: impostor,
            ..terms
        };
        assert!(!verify_entry(&claimed, &sig));
    }

    /// The forgery this SIP exists to stop: a member holding the channel key
    /// can seal bytes under another device's SIP-17 subkey, but cannot sign
    /// them as that device.
    #[test]
    fn a_member_cannot_sign_as_another_member() {
        let (alice_seed, _alice) = key(1);
        let (_, bob) = key(2);
        let (_, bob_account) = key(2);
        let body = b"bob would never say this".to_vec();

        // Alice writes the terms exactly as Bob would have.
        let as_bob = entry_terms(&body, bob, bob_account);
        let forged = sign_entry(&alice_seed, &as_bob);

        assert!(
            !verify_entry(&as_bob, &forged),
            "Alice signed an entry that verified as Bob's"
        );
    }

    #[test]
    fn every_action_term_is_covered() {
        let (seed, actor_device) = key(1);
        let (_, actor) = key(2);
        let (_, subject) = key(3);
        let arg = [1u8];
        let base = ActionTerms {
            place: place(),
            actor,
            actor_device,
            event: 0x02,
            subject,
            arg: &arg,
            chain_seq: 5,
            prev: [1; 32],
        };
        let sig = sign_action(&seed, &base).unwrap();
        assert!(verify_action(&base, &sig));

        let (_, other_key) = key(4);
        let other_arg = [2u8];

        let mutations: Vec<(&str, ActionTerms)> = vec![
            (
                "exchange",
                ActionTerms {
                    place: Place {
                        exchange: other_key,
                        ..base.place
                    },
                    ..base
                },
            ),
            (
                "instance",
                ActionTerms {
                    place: Place {
                        instance: [5; 32],
                        ..base.place
                    },
                    ..base
                },
            ),
            (
                "channel",
                ActionTerms {
                    place: Place {
                        channel: [8; 32],
                        ..base.place
                    },
                    ..base
                },
            ),
            (
                "actor",
                ActionTerms {
                    actor: other_key,
                    ..base
                },
            ),
            (
                "event",
                ActionTerms {
                    event: 0x03,
                    ..base
                },
            ),
            (
                "subject",
                ActionTerms {
                    subject: other_key,
                    ..base
                },
            ),
            (
                "arg",
                ActionTerms {
                    arg: &other_arg,
                    ..base
                },
            ),
            (
                "chain_seq",
                ActionTerms {
                    chain_seq: 6,
                    ..base
                },
            ),
            (
                "prev",
                ActionTerms {
                    prev: [2; 32],
                    ..base
                },
            ),
        ];

        for (what, terms) in mutations {
            assert!(
                !verify_action(&terms, &sig),
                "a signature survived a changed {what}, so {what} is not covered"
            );
        }
    }

    /// An empty `arg` and a one-byte `arg` must not hash alike, or a role could
    /// be stripped from a signed promotion.
    #[test]
    fn an_arg_is_length_prefixed() {
        let (seed, actor_device) = key(1);
        let (_, actor) = key(2);
        let (_, subject) = key(3);
        let arg = [0u8];
        let with = ActionTerms {
            place: place(),
            actor,
            actor_device,
            event: 0x01,
            subject,
            arg: &arg,
            chain_seq: 0,
            prev: GENESIS,
        };
        let without = ActionTerms { arg: &[], ..with };

        let sig = sign_action(&seed, &with).unwrap();
        assert!(verify_action(&with, &sig));
        assert!(!verify_action(&without, &sig));
    }

    #[test]
    fn an_oversized_arg_is_refused() {
        let (seed, actor_device) = key(1);
        let (_, actor) = key(2);
        let long = [0u8; MAX_ARG + 1];
        let terms = ActionTerms {
            place: place(),
            actor,
            actor_device,
            event: 0x01,
            subject: actor,
            arg: &long,
            chain_seq: 0,
            prev: GENESIS,
        };
        assert!(terms.input().is_err());
        assert!(sign_action(&seed, &terms).is_err());
        assert!(!verify_action(&terms, &[0; 64]));
    }

    /// The two contexts are what stop an action signature standing in for an
    /// entry signature over the same underlying bytes.
    #[test]
    fn the_two_contexts_are_separate() {
        let entry = ENTRY_CONTEXT;
        let action = ACTION_CONTEXT;
        assert_ne!(entry, action);
        assert!(
            !action.starts_with(entry),
            "one context is a prefix of the other, so a digest could be shifted between them"
        );
    }

    /// A chain link is over the signing input, which is what a client can
    /// compute before the exchange has numbered anything.
    #[test]
    fn a_link_follows_the_signing_input() {
        let (_, device) = key(1);
        let (_, account) = key(2);
        let body = b"one".to_vec();
        let a = entry_terms(&body, device, account);
        let b = EntryTerms { chain_seq: 6, ..a };

        assert_eq!(link(&a.input()), link(&a.input()), "a link must be stable");
        assert_ne!(link(&a.input()), link(&b.input()));
        assert_ne!(
            link(&a.input()),
            GENESIS,
            "a real link must not look like a genesis"
        );
    }
}
