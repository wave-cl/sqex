//! SIP-34 exchange receipts: the exchange's signature over its own act.
//!
//! SIP-31 removed the exchange from *authorship* and deliberately left it where
//! it was for *ordering*, because ordering is a claim about the exchange's own
//! act rather than about somebody else. This is that claim, signed.
//!
//! A receipt says: this exchange, at this key, placed this entry at this
//! position in this channel at this time, on top of this history. Nothing in it
//! was unavailable to the exchange before. What changes is that it can no
//! longer be un-said.
//!
//! # The head is a property of history, not of contents
//!
//! [`advance`] runs once per entry as it is numbered, and the result is
//! persisted. It MUST NOT be recomputed from the entries an exchange currently
//! holds: pruning removes entries, so a recomputed head is a different head, and
//! every receipt issued before the prune stops verifying against every receipt
//! issued after. This is the rule SIP-31 already gives for its per-device chain
//! marks and it fails the same way when ignored.
//!
//! An exchange that has lost a channel's head has lost the ability to issue
//! receipts for it and must stop, rather than start a fresh chain — which on
//! the wire is indistinguishable from equivocation.
//!
//! # Two receipts that cannot both be true
//!
//! [`Equivocation`] is 376 bytes, self-contained, and checkable by anybody
//! holding the exchange's public key. That portability is the whole point:
//! before this, an exchange telling two members different things was detectable
//! only by the two of them meeting, and at the end of it neither could show a
//! third party anything.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sqnr_core::{Error, PubKey, Result};

use crate::entry_sig::Place;

/// Domain separator for a receipt signature.
///
/// Distinct from SIP-31's contexts so a receipt can never be presented as an
/// entry or action signature, or the reverse.
pub const RECEIPT_CONTEXT: &[u8] = b"sqex-receipt-v1";

/// A channel's head before its first entry. Not a hash of anything.
pub const HEAD_GENESIS: [u8; 32] = [0u8; 32];

/// Bytes an [`Equivocation`] occupies on the wire.
pub const EQUIVOCATION_LEN: usize = 32 + 32 + 32 + 8 + (8 + 32 + 32 + 64) * 2;

/// Advance a channel's running head over one entry.
///
/// `entry_hash` is SHA-256 of the entry's SIP-31 signing input — the value
/// [`crate::entry_sig::link`] already computes for the per-device chain. It is
/// the same function of the same bytes and this crate keeps one primitive for
/// both; see the SIP-34 note on why they are not two hashes.
pub fn advance(prev_head: &[u8; 32], entry_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev_head);
    h.update(entry_hash);
    h.finalize().into()
}

/// Everything a receipt commits to.
///
/// `place` carries SIP-31's three binding terms unchanged and for the same
/// reasons: without `exchange` a receipt lifts into another exchange's copy of
/// the same conversation, and without `instance` it lifts from a destroyed
/// channel into its successor. A direct message's identifier is derived from
/// its two accounts, so neither is hypothetical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptTerms {
    pub place: Place,
    /// The position the exchange assigned.
    pub seq: u64,
    /// The time the exchange stamped. Signing it makes it attributable, not
    /// accurate — see SIP-34's security considerations.
    pub posted: u64,
    /// SHA-256 of the entry's SIP-31 signing input.
    pub entry_hash: [u8; 32],
    /// The channel's running head *after* this entry.
    pub head: [u8; 32],
}

impl ReceiptTerms {
    /// The 47 bytes a receipt is made over: the context, then one digest of
    /// everything else.
    ///
    /// Hash-then-sign over a fixed width, as SIP-10, SIP-20 and SIP-31 all do.
    pub fn input(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(self.place.exchange.as_bytes());
        h.update(self.place.instance);
        h.update(self.place.channel);
        h.update(self.seq.to_be_bytes());
        h.update(self.posted.to_be_bytes());
        h.update(self.entry_hash);
        h.update(self.head);

        let mut out = Vec::with_capacity(RECEIPT_CONTEXT.len() + 32);
        out.extend_from_slice(RECEIPT_CONTEXT);
        out.extend_from_slice(&h.finalize());
        out
    }
}

/// Sign a receipt as the exchange's SIP-9 identity.
///
/// **The signer is the key clients already pin and must not be a separate
/// key.** A dedicated signing key is better hygiene in the abstract, but it
/// signs once per post and so cannot live offline; the alternative is a second
/// online key with its own distribution and rotation problem, vouched for by
/// the first. That is a longer chain with no shorter root.
pub fn sign(exchange_seed: &[u8; 32], terms: &ReceiptTerms) -> [u8; 64] {
    SigningKey::from_bytes(exchange_seed)
        .sign(&terms.input())
        .to_bytes()
}

/// Check a receipt under the exchange key **the verifier pinned**.
///
/// The caller passes the key it pinned under SIP-9 or discovered under SIP-33.
/// A verifier that takes the signing key from the response, from a field, or
/// from the connection alone has checked that the sender is self-consistent and
/// nothing else.
pub fn verify(terms: &ReceiptTerms, sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(terms.place.exchange.as_bytes()) else {
        return false;
    };
    vk.verify(&terms.input(), &Signature::from_bytes(sig))
        .is_ok()
}

/// One side of a contradiction: what an exchange said about one position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Branch {
    pub posted: u64,
    pub entry_hash: [u8; 32],
    pub head: [u8; 32],
    pub receipt: [u8; 64],
}

/// Two receipts that verify under one exchange key and name one position with
/// different content.
///
/// Portable on purpose: a third party holding only the exchange's public key
/// can check both signatures and observe the contradiction, without either
/// party's cooperation and without having seen either connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Equivocation {
    pub place: Place,
    pub seq: u64,
    pub a: Branch,
    pub b: Branch,
}

impl Equivocation {
    /// Build one from two receipts for the same position, checking that it is
    /// actually a contradiction rather than two copies of one truth.
    ///
    /// Both signatures are verified here. An unverified pair is not evidence of
    /// anything — anybody can write two conflicting structs — and the whole
    /// value of the artifact is that a stranger can check it.
    pub fn new(place: Place, seq: u64, a: Branch, b: Branch) -> Result<Equivocation> {
        if a.posted == b.posted && a.entry_hash == b.entry_hash && a.head == b.head {
            return Err(Error::Malformed(
                "the two receipts agree, which is not equivocation".into(),
            ));
        }
        for (which, br) in [("a", &a), ("b", &b)] {
            let terms = ReceiptTerms {
                place,
                seq,
                posted: br.posted,
                entry_hash: br.entry_hash,
                head: br.head,
            };
            if !verify(&terms, &br.receipt) {
                return Err(Error::Malformed(format!(
                    "branch {which} does not verify under the exchange key"
                )));
            }
        }
        Ok(Equivocation { place, seq, a, b })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EQUIVOCATION_LEN);
        out.extend_from_slice(self.place.exchange.as_bytes());
        out.extend_from_slice(&self.place.instance);
        out.extend_from_slice(&self.place.channel);
        out.extend_from_slice(&self.seq.to_be_bytes());
        for br in [&self.a, &self.b] {
            out.extend_from_slice(&br.posted.to_be_bytes());
            out.extend_from_slice(&br.entry_hash);
            out.extend_from_slice(&br.head);
            out.extend_from_slice(&br.receipt);
        }
        out
    }

    /// Read one, verifying both signatures as [`Equivocation::new`] does.
    ///
    /// A decoder that returned an unchecked struct would hand callers something
    /// that looks like proof and is not.
    pub fn decode(b: &[u8]) -> Result<Equivocation> {
        if b.len() != EQUIVOCATION_LEN {
            return Err(Error::Malformed(format!(
                "equivocation is {} bytes, want {EQUIVOCATION_LEN}",
                b.len()
            )));
        }
        let place = Place {
            exchange: PubKey::new(b[0..32].try_into().unwrap()),
            instance: b[32..64].try_into().unwrap(),
            channel: b[64..96].try_into().unwrap(),
        };
        let seq = u64::from_be_bytes(b[96..104].try_into().unwrap());
        let branch = |at: usize| Branch {
            posted: u64::from_be_bytes(b[at..at + 8].try_into().unwrap()),
            entry_hash: b[at + 8..at + 40].try_into().unwrap(),
            head: b[at + 40..at + 72].try_into().unwrap(),
            receipt: b[at + 72..at + 136].try_into().unwrap(),
        };
        Equivocation::new(place, seq, branch(104), branch(240))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry_sig::{EntryTerms, link};

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn exchange() -> (SigningKey, PubKey) {
        let sk = SigningKey::from_bytes(&seed(9));
        let pk = PubKey::new(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn place(pk: PubKey) -> Place {
        Place {
            exchange: pk,
            instance: seed(2),
            channel: seed(3),
        }
    }

    fn terms(pk: PubKey) -> ReceiptTerms {
        ReceiptTerms {
            place: place(pk),
            seq: 7,
            posted: 1_700_000_000,
            entry_hash: seed(4),
            head: seed(5),
        }
    }

    #[test]
    fn a_receipt_verifies_and_every_field_is_bound() {
        let (sk, pk) = exchange();
        let t = terms(pk);
        let sig = sign(&seed(9), &t);
        assert!(verify(&t, &sig), "the receipt as signed must verify");
        assert_eq!(sk.verifying_key().to_bytes(), *pk.as_bytes());

        // The negative control, run field by field: changing any one of them
        // must break the signature. A receipt that survived a changed `seq`
        // would be liftable to another position, which is the whole attack.
        let spoils: [fn(&mut ReceiptTerms); 6] = [
            |t| t.seq += 1,
            |t| t.posted += 1,
            |t| t.entry_hash[0] ^= 1,
            |t| t.head[0] ^= 1,
            |t| t.place.instance[0] ^= 1,
            |t| t.place.channel[0] ^= 1,
        ];
        for spoil in spoils {
            let mut bad = t;
            spoil(&mut bad);
            assert!(
                !verify(&bad, &sig),
                "a changed field must break the receipt"
            );
        }
    }

    #[test]
    fn a_receipt_does_not_verify_under_another_exchange() {
        let (_, pk) = exchange();
        let sig = sign(&seed(9), &terms(pk));
        let other = PubKey::new(SigningKey::from_bytes(&seed(8)).verifying_key().to_bytes());
        let mut t = terms(pk);
        t.place.exchange = other;
        assert!(
            !verify(&t, &sig),
            "the key is bound into the input as well as verifying it"
        );
    }

    #[test]
    fn the_entry_hash_is_sip_31s_chain_link() {
        // Not a restatement of the definition: it is the claim that this crate
        // has one primitive rather than two that can drift.
        let e = EntryTerms {
            place: place(exchange().1),
            account: PubKey::new(seed(1)),
            device: PubKey::new(seed(2)),
            epoch: 0,
            msg_seq: 1,
            expires_after: 0,
            chain_seq: 0,
            prev: seed(0),
            body: b"hello",
        };
        assert_eq!(link(&e.input()), Sha256::digest(e.input()).as_slice());
    }

    #[test]
    fn an_omitted_entry_changes_every_head_after_it() {
        // Why the head covers omission and a per-entry hash does not: two
        // readers shown different subsets diverge permanently at the first
        // difference.
        let (a, b, c) = (seed(0xa), seed(0xb), seed(0xc));
        let shown_all = advance(&advance(&advance(&HEAD_GENESIS, &a), &b), &c);
        let shown_without_b = advance(&advance(&HEAD_GENESIS, &a), &c);
        assert_ne!(shown_all, shown_without_b);
    }

    #[test]
    fn an_equivocation_round_trips_and_refuses_what_is_not_one() {
        let (_, pk) = exchange();
        let one = terms(pk);
        let mut two = one;
        two.entry_hash[0] ^= 1;
        two.head[0] ^= 1;

        let br = |t: &ReceiptTerms| Branch {
            posted: t.posted,
            entry_hash: t.entry_hash,
            head: t.head,
            receipt: sign(&seed(9), t),
        };
        let proof = Equivocation::new(place(pk), one.seq, br(&one), br(&two)).unwrap();
        assert_eq!(proof.encode().len(), EQUIVOCATION_LEN);
        assert_eq!(Equivocation::decode(&proof.encode()).unwrap(), proof);

        // Negative control one: two receipts that agree are not a proof of
        // anything, and must not be presentable as one.
        assert!(Equivocation::new(place(pk), one.seq, br(&one), br(&one)).is_err());

        // Negative control two: a branch anybody could have written. The
        // artifact is worthless if a decoder hands it back unchecked.
        let mut forged = br(&two);
        forged.receipt[0] ^= 1;
        assert!(Equivocation::new(place(pk), one.seq, br(&one), forged).is_err());

        let mut bytes = proof.encode();
        bytes[104 + 8] ^= 1;
        assert!(
            Equivocation::decode(&bytes).is_err(),
            "decode must verify, not just parse"
        );
        assert!(Equivocation::decode(&bytes[..EQUIVOCATION_LEN - 1]).is_err());
    }
}
