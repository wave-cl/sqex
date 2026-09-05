//! SIP-35: holding a copy of somebody else's channel, and checking it.
//!
//! **A replica that skips the verification here has built a cache, and a cache
//! of somebody else's assertions is worth less than nothing** — it launders one
//! exchange's word into two. The checking is the whole difference between this
//! and a mirror, and it is why this module refuses far more than it stores.
//!
//! What is checked, per entry, before anything is written:
//!
//! 1. **SIP-31 step 1** — the device's signature over the entry's own fields.
//! 2. **SIP-31 step 2** — a SIP-20 credential binding that device to the
//!    account the entry names, with scope `sqex-chat`. Step 1 alone proves a
//!    key signed and says nothing about whose key it is; SIP-31 warns that this
//!    is the check most likely to be skipped, because the incomplete version
//!    returns `true` on every honest message.
//! 3. **SIP-34** — the receipt, under the **origin's** key, and the head
//!    linkage against the entry before it.
//!
//! SIP-31's chain step is checked too, and its two failures mean different
//! things: a gap is stored, because pruning and retention produce one and it is
//! ordinary; a fork is stored **with** the conflicting pair, because a fork is
//! evidence and discarding it destroys the only copy of it.
//!
//! # What this does not replicate, and must not
//!
//! Prekeys, above all. SIP-23's entire value is that a prekey is served once
//! and destroyed on use; two exchanges each holding the pool each serve the
//! same one to a different sender, and the recipient's duplicate check — SIP-23's
//! own defence — fires on a condition that is now normal. Signals and read
//! cursors are permanently the exchange's word, and repeating either across a
//! peering link turns one assertion into two, which reads as corroboration and
//! is not. Block lists are deliberately unsigned, and making them replicate
//! would require the signed, portable statement about somebody that SIP-32
//! refused to create.

use std::net::SocketAddr;

use sqex_proto::channel::{Entry, KIND_MEMBER};
use sqex_proto::entry_sig::{EntryTerms, Place, link, verify_entry, verify_entry_hashed};
use sqex_proto::peer::Pulled;
use sqex_proto::receipt::{self, Branch, Equivocation, ReceiptTerms};
use sha2::{Digest, Sha256};
use sqnr_core::PubKey;

use crate::channel::Channels;

/// One origin this exchange replicates from.
#[derive(Debug, Clone)]
pub struct Origin {
    /// The origin's SIP-9 identity — pinned, and the key every receipt is
    /// checked under. **Never taken from the connection or from `Pulled`:** a
    /// replica that accepted the signing key from the party supplying the
    /// entries would have been handed the forgery power this whole document
    /// removes.
    pub key: PubKey,
    pub addr: SocketAddr,
    pub channels: Vec<[u8; 32]>,
}

/// Why an entry was refused. Kept apart from the storage errors because these
/// are statements about the *origin*, and one of them is evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// SIP-31 step 1: the signature does not verify under the device it names.
    Forged,
    /// SIP-31 step 2: no credential binds that device to that account. The
    /// signature stands and the attribution does not, and SIP-35 says an entry
    /// failing this MUST NOT be stored.
    Unattributed,
    /// SIP-34: a receipt that does not verify under the origin's pinned key.
    Repudiated,
    /// SIP-34: the head does not follow the one held for the entry before it.
    /// The origin advanced its head over something this replica was not shown.
    Diverged,
    /// The entry arrived with no receipt at all. An origin that cannot receipt
    /// cannot be replicated from — there would be nothing to verify.
    Unclaimed,
}

/// What one pull produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Took {
    pub stored: u64,
    pub refused: Vec<(u64, Refused)>,
    /// Set when the origin was caught saying two things about one position.
    /// The replica stops here and does not choose between the branches.
    pub equivocated: bool,
}

/// Verify a batch under the origin's pinned key and store what survives.
///
/// `credentials` answers SIP-31's step 2: it maps a device to the account a
/// verified SIP-20 credential binds it to, or `None` where no credential can be
/// obtained. Passed in rather than fetched here, so this function is testable
/// without a network and so the registry it comes from is the caller's choice.
pub fn take(
    store: &Channels,
    origin: &PubKey,
    channel: &[u8; 32],
    pulled: &Pulled,
    credentials: &dyn Fn(&PubKey) -> Option<PubKey>,
) -> Took {
    let mut took = Took::default();
    // Marked replicated before anything is written, so an entry can never land
    // in a channel this exchange would then treat as its own — and so every
    // write route refuses it from the first entry rather than the second pull.
    if store
        .adopt(channel, &pulled.instance, origin, pulled.window_secs)
        .is_err()
    {
        return took;
    }
    let place = Place {
        exchange: *origin,
        instance: pulled.instance,
        channel: *channel,
    };
    // The head of the entry before the first in this batch, where we hold it.
    // `None` is a gap, which is ordinary; it is not a divergence.
    let mut held: Option<(u64, [u8; 32])> = last_head(store, channel);

    for e in &pulled.entries {
        let Some(stamp) = e.stamp else {
            took.refused.push((e.seq, Refused::Unclaimed));
            continue;
        };
        let terms = ReceiptTerms {
            place,
            seq: e.seq,
            posted: e.posted,
            entry_hash: stamp.entry_hash,
            head: stamp.head,
        };
        if !receipt::verify(&terms, &stamp.receipt) {
            took.refused.push((e.seq, Refused::Repudiated));
            continue;
        }
        // Two receipts that verify under one origin key, naming one position
        // and differing in content. SIP-34 makes this 376 self-contained bytes
        // a stranger can check.
        if let Some(proof) = conflicting(store, &place, e, &stamp) {
            let _ = store.record_equivocation(channel, &proof.encode());
            took.equivocated = true;
            return took;
        }
        if let Some(err) = entry_refused(&place, e, credentials) {
            took.refused.push((e.seq, err));
            continue;
        }
        // SIP-34 step 3, and only where the predecessor is held.
        if let Some((seq, prev)) = held
            && seq + 1 == e.seq
            && receipt::advance(&prev, &stamp.entry_hash) != stamp.head
        {
            took.refused.push((e.seq, Refused::Diverged));
            continue;
        }
        if store
            .store_pulled(channel, e, &stamp.entry_hash, &stamp.head, &stamp.receipt)
            .is_ok()
        {
            took.stored += 1;
            held = Some((e.seq, stamp.head));
        }
    }
    took
}

/// SIP-31 steps 1 and 2 over one entry.
fn entry_refused(
    place: &Place,
    e: &Entry,
    credentials: &dyn Fn(&PubKey) -> Option<PubKey>,
) -> Option<Refused> {
    // A system entry carries no signature of its own — its actor's is inside
    // the body, and the origin verified it before writing the row. The receipt
    // is what a replica can check about one, and it already has.
    if e.kind != KIND_MEMBER {
        return None;
    }
    let terms = EntryTerms {
        place: *place,
        account: e.account,
        device: e.device,
        epoch: e.epoch,
        msg_seq: e.msg_seq,
        expires_after: e.expires_after,
        chain_seq: e.chain_seq,
        prev: e.prev,
        body: &e.body,
    };
    // A tombstone's body is gone and its hash is all that is left to check
    // against, which is exactly why SIP-31 commits to the hash.
    let signed = if e.body.is_empty() && e.body_hash != Sha256::digest([] as [u8; 0]).as_slice() {
        verify_entry_hashed(&terms, &e.body_hash, &e.sig)
    } else {
        verify_entry(&terms, &e.sig)
    };
    if !signed {
        return Some(Refused::Forged);
    }
    // An account with no registered device *is* its own device (SIP-22), so a
    // self-signed entry needs no credential. That is the ordinary
    // single-client case and not an unattributed one.
    if e.device != e.account {
        match credentials(&e.device) {
            Some(account) if account == e.account => {}
            _ => return Some(Refused::Unattributed),
        }
    }
    None
}

/// Whether this entry contradicts a receipt already held for its position.
fn conflicting(
    store: &Channels,
    place: &Place,
    e: &Entry,
    stamp: &sqex_proto::channel::Receipted,
) -> Option<Equivocation> {
    let (posted, entry_hash, head, receipt) = store.stamp_at(&place.channel, e.seq)?;
    if posted == e.posted && entry_hash == stamp.entry_hash && head == stamp.head {
        return None;
    }
    Equivocation::new(
        *place,
        e.seq,
        Branch {
            posted,
            entry_hash,
            head,
            receipt,
        },
        Branch {
            posted: e.posted,
            entry_hash: stamp.entry_hash,
            head: stamp.head,
            receipt: stamp.receipt,
        },
    )
    .ok()
}

fn last_head(store: &Channels, channel: &[u8; 32]) -> Option<(u64, [u8; 32])> {
    let seq = store.highest(channel);
    if seq == 0 {
        return None;
    }
    store.stamp_at(channel, seq).map(|(_, _, head, _)| (seq, head))
}

/// The link an entry produces, exposed so a caller can rebuild a chain.
pub fn entry_hash_of(place: &Place, e: &Entry) -> [u8; 32] {
    let terms = EntryTerms {
        place: *place,
        account: e.account,
        device: e.device,
        epoch: e.epoch,
        msg_seq: e.msg_seq,
        expires_after: e.expires_after,
        chain_seq: e.chain_seq,
        prev: e.prev,
        body: &e.body,
    };
    link(&terms.input_hashed(&e.body_hash))
}
