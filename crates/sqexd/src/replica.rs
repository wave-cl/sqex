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

//! # The two halves
//!
//! [`take`] is the verification and storage half: given a batch and a way to
//! resolve devices to accounts, it decides what may be written and writes it.
//! It is synchronous and has no transport, which is what lets an equivocating
//! origin be played against it in a test without writing a dishonest exchange.
//!
//! [`pull_once`] and [`run`] are the transport half, over
//! [`crate::peer_client`] — the eighty lines of h3-over-sQUIC a replica needs,
//! rather than a dependency on `sqnr` and, through it, on libpcsclite for a
//! YubiKey no server touches.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use sqex_proto::blob_store::blob_id;
use sqex_proto::channel::{EVENT_SUCCEEDED, KIND_SYSTEM, System};
use sqex_proto::channel::{Entry, KIND_MEMBER};
use sqex_proto::channel_key::{Envelope, verify_envelope};
use sqex_proto::credential::SCOPE_CHAT;
use sqex_proto::device::{Devices, ListDevices};
use sqex_proto::entry_sig::{EntryTerms, Place, link, verify_entry, verify_entry_hashed};
use sqex_proto::peer::{
    BLOB_LIST, Forward, Forwarded, Hello, Hi, MAX_PULL, PEER_VERSION, Pull, PullBlob,
    PullEnvelopes, PullRecord, Pulled, PulledBlob, PulledEnvelopes,
};
use sqex_proto::profile::Got as ProfileGot;
use sqex_proto::receipt::{self, Branch, Equivocation, ReceiptTerms};
use sqex_proto::succession;
use sqnr_core::PubKey;

use crate::channel::Channels;
use sqex_proto::h3::H3Client;

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
    pub interval: std::time::Duration,
    /// SIP-40: the keys the origin held before `key`, newest first. What it
    /// signed under them verifies under them; a replica that forgets them
    /// refuses everything from before the handover.
    pub predecessors: Vec<PubKey>,
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
    take_under(store, origin, &[], channel, pulled, credentials)
}

/// [`take`], with the keys the origin held before its current one (SIP-40).
///
/// Nothing already signed is re-signed at a handover: an entry from before
/// it carries a receipt under the key the origin held then, and a signature
/// whose SIP-31 place names that key. Each is checked under the current key
/// first and then each predecessor, and the one that verifies is the one
/// the entry is understood under. A replica that only knew the successor
/// refused every entry from before the handover -- including the
/// constitution, which left it unable to derive a roster for a channel that
/// had merely been around longer than the key.
pub fn take_under(
    store: &Channels,
    origin: &PubKey,
    predecessors: &[PubKey],
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
    let places: Vec<Place> = std::iter::once(origin)
        .chain(predecessors.iter())
        .map(|key| Place {
            exchange: *key,
            instance: pulled.instance,
            channel: *channel,
        })
        .collect();
    // The head of the entry before the first in this batch, where we hold it.
    // `None` is a gap, which is ordinary; it is not a divergence.
    let mut held: Option<(u64, [u8; 32])> = last_head(store, channel);

    for e in &pulled.entries {
        let Some(stamp) = e.stamp else {
            took.refused.push((e.seq, Refused::Unclaimed));
            continue;
        };
        let Some(place) = places.iter().find(|place| {
            receipt::verify(
                &ReceiptTerms {
                    place: **place,
                    seq: e.seq,
                    posted: e.posted,
                    entry_hash: stamp.entry_hash,
                    head: stamp.head,
                },
                &stamp.receipt,
            )
        }) else {
            took.refused.push((e.seq, Refused::Repudiated));
            continue;
        };
        let place = *place;
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
        match store.store_pulled(channel, e, &stamp.entry_hash, &stamp.head, &stamp.receipt) {
            Ok(true) => {
                took.stored += 1;
                held = Some((e.seq, stamp.head));
            }
            // Held already: verified when it first arrived.
            Ok(false) => held = Some((e.seq, stamp.head)),
            Err(_) => {}
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
    store
        .stamp_at(channel, seq)
        .map(|(_, _, head, _)| (seq, head))
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

/// Pull once from an origin and take what verifies.
///
/// A `Hello` first, so the two ends agree on a version and this replica learns
/// the origin's own retention window before anything is asked for. It
/// authenticates nothing — the sQUIC connection already did that, both ways.
pub async fn pull_once(
    client: &mut H3Client,
    server: &crate::server::Server,
    origin: &Origin,
) -> Result<HashMap<[u8; 32], Took>, String> {
    pull_once_from(client, server, origin, &HashMap::new()).await
}

/// Entries this replica refused and will ask for again: per channel, the
/// position to pull from and how many times it has tried. A refusal can be
/// the moment's -- the origin's registry answered late, a credential the
/// copy could not yet bind -- and a copy that pulled from its highest
/// stored position would never see the entry again. Bounded: an entry
/// refused `HOLE_TRIES` times is left where it is, and the wait (SIP-61)
/// is told not to fire on it.
pub type Holes = HashMap<[u8; 32], (u64, u32)>;

/// How many pulls a refused entry is asked for again.
pub const HOLE_TRIES: u32 = 30;

/// SIP-61/62: remember the holes a pull left, drop the ones it filled, and
/// give up on the ones that will not fill.
pub fn note_holes(holes: &mut Holes, took: &HashMap<[u8; 32], Took>) {
    for (channel, t) in took {
        match t.refused.iter().map(|(seq, _)| *seq).min() {
            Some(lowest) => {
                let e = holes
                    .entry(*channel)
                    .or_insert((lowest.saturating_sub(1), 0));
                e.0 = e.0.min(lowest.saturating_sub(1));
                e.1 += 1;
                if e.1 >= HOLE_TRIES {
                    tracing::warn!(
                        channel = %bs58::encode(channel).into_string(),
                        seq = lowest,
                        "an entry refused {HOLE_TRIES} times is left behind"
                    );
                    holes.remove(channel);
                }
            }
            None if t.stored > 0 => {
                holes.remove(channel);
            }
            None => {}
        }
    }
}

/// SIP-62: the holes a replica finds in what it already holds, when it
/// starts -- entries refused before this process began. Seeded once, so a
/// hole nothing will fill costs `HOLE_TRIES` pulls per start and not one
/// per cycle.
pub fn holes_in(store: &Channels, channels: &[[u8; 32]]) -> Holes {
    channels
        .iter()
        .filter_map(|c| store.lowest_gap(c).map(|at| (*c, (at, 0))))
        .collect()
}

/// [`pull_once`], pulling each channel in `holes` from the position noted
/// there rather than from the highest held.
pub async fn pull_once_from(
    client: &mut H3Client,
    server: &crate::server::Server,
    origin: &Origin,
    holes: &Holes,
) -> Result<HashMap<[u8; 32], Took>, String> {
    let store = server.channels();
    let (code, body) = client
        .post(
            "/peer/hello",
            Hello {
                version: PEER_VERSION,
                since: 0,
            }
            .encode(),
        )
        .await?;
    if code != 200 {
        // The origin refuses every peering route identically, so this says
        // "not served" and deliberately not why.
        return Err(format!("the origin refused peering ({code})"));
    }
    let hi = Hi::decode(&body).map_err(|e| e.to_string())?;
    if hi.exchange != origin.key {
        // The connection was authenticated against the pinned key, so this
        // cannot normally differ — and if it ever does, the party supplying the
        // entries is not the party we pinned and nothing it says is checkable.
        return Err("the origin reported an identity we did not pin".into());
    }
    // SIP-53: answered, so not away.
    server.reached(&origin.key);

    let mut all = HashMap::new();
    for channel in &origin.channels {
        // SIP-53: a channel this origin no longer orders -- moved to another
        // exchange, or to this one -- is not pulled from here.
        match store.origin_of(channel) {
            Some(o) if o == origin.key => {}
            Some(_) => continue,
            None if store.origin_history(channel).contains(&server.public_key) => {
                // This exchange took the channel over while the origin was
                // gone; the origin is back, and is told. It follows or it
                // refuses; either way it is not pulled from.
                if let Some(e) = store.my_rehome(channel) {
                    let carried = sqex_proto::channel::Rehomed {
                        channel: *channel,
                        domain: String::new(),
                        entry: e,
                    };
                    let _ = client.post("/peer/rehomed", carried.encode()).await;
                }
                continue;
            }
            None => {}
        }
        // **Stop pulling a channel this origin has already contradicted itself
        // about.** SIP-35 requires it, and the reason is not squeamishness:
        // continuing would accumulate history from a party already caught
        // telling two of them, with no basis for preferring what comes next.
        if store.equivocation_for(channel).is_some() {
            continue;
        }
        let since = match holes.get(channel) {
            Some((from, _)) => store.highest(channel).min(*from),
            None => store.highest(channel),
        };
        let (code, body) = client
            .post(
                "/peer/pull",
                Pull {
                    channel: *channel,
                    since,
                    max: MAX_PULL,
                }
                .encode(),
            )
            .await?;
        if code != 200 {
            // Not authorised, not held, or not served — which one is exactly
            // what the origin declines to say, so this declines to guess.
            continue;
        }
        let pulled = Pulled::decode(&body).map_err(|e| e.to_string())?;
        if pulled.origin != origin.key {
            return Err("a pull reported an origin we did not pin".into());
        }

        // SIP-31's step 2 needs a credential per device, and the devices are
        // only known once the batch is in hand. Resolved before anything is
        // verified, so `take` stays synchronous and testable without a network
        // — and so a device appearing twice costs one lookup.
        let mut creds: HashMap<PubKey, Option<PubKey>> = HashMap::new();
        for e in &pulled.entries {
            if e.kind == KIND_MEMBER && e.device != e.account && !creds.contains_key(&e.device) {
                creds.insert(e.device, account_for(client, &e.account, &e.device).await);
            }
        }
        let lookup = move |d: &PubKey| creds.get(d).copied().flatten();
        // SIP-53: what earlier origins signed and receipted verifies under
        // them, as SIP-40's predecessors do.
        let mut predecessors = origin.predecessors.clone();
        predecessors.extend(store.origin_history(channel));
        let mut took = take_under(store, &origin.key, &predecessors, channel, &pulled, &lookup);
        // SIP-54: the members' marks and the signal log, merged and handed
        // on as if made here.
        pull_soft_state(client, server, channel).await;
        // SIP-53: a rehome among what was pulled moved the channel. Where it
        // went is asked of the origin, which recorded the hint, so the task
        // for moved channels can find it.
        if store.origin_of(channel) != Some(origin.key)
            && let Some((to, domain)) = standing_moved(client, channel, &server.public_key).await
            && store.origin_of(channel) == Some(to)
        {
            store.set_origin_domain(channel, &domain);
        }

        // **What was refused below the lowest entry held is asked for
        // again.** A pull asks from the highest entry held, so an entry
        // refused once -- under a key this replica had not been told of yet,
        // say -- would never be asked for again, and the constitution among
        // them would leave the channel underived for good. The origin says
        // where its own copy starts; while this replica's starts later, the
        // gap is pulled from the origin's first, and what is already held is
        // ignored on the way in.
        let lowest = store.lowest(channel);
        if !took.equivocated && pulled.first > 0 && lowest > pulled.first {
            let (code, body) = client
                .post(
                    "/peer/pull",
                    Pull {
                        channel: *channel,
                        since: pulled.first - 1,
                        max: MAX_PULL,
                    }
                    .encode(),
                )
                .await?;
            if code == 200
                && let Ok(below) = Pulled::decode(&body)
                && below.origin == origin.key
            {
                let mut creds: HashMap<PubKey, Option<PubKey>> = HashMap::new();
                for e in &below.entries {
                    if e.kind == KIND_MEMBER
                        && e.device != e.account
                        && !creds.contains_key(&e.device)
                    {
                        creds.insert(e.device, account_for(client, &e.account, &e.device).await);
                    }
                }
                let lookup = move |d: &PubKey| creds.get(d).copied().flatten();
                let again = take_under(store, &origin.key, &predecessors, channel, &below, &lookup);
                if again.stored > 0 {
                    // The events just filled in come before the ones already
                    // applied, so the roster is derived again from the top.
                    if let Err(e) = store.rederive(channel) {
                        tracing::warn!(error = ?e, "could not derive the roster again");
                    }
                }
                took.stored += again.stored;
                took.refused.extend(again.refused);
                took.equivocated |= again.equivocated;
            }
        }

        // SIP-44: a succession by guardians carries a policy's signature the
        // entry cannot be checked against on its own. The origin's record
        // holds the whole proof; checked here, and the seat moved only when
        // it proves what the entry says.
        for e in pulled.entries.iter().filter(|e| e.kind == KIND_SYSTEM) {
            let Ok(Some(sys)) = System::decode(&e.body) else {
                continue;
            };
            if sys.event != EVENT_SUCCEEDED {
                continue;
            }
            let mut verified =
                succession::entry_verifies(&sys.actor, &sys.subject, sys.chain_seq, &sys.sig);
            if !verified
                && let Ok((200, body)) = client
                    .post("/account/succession", succession::ask(&sys.actor))
                    .await
                && let Ok(record) = succession::Succeeded::decode(&body)
                && record.successor == sys.subject
                && record.proof.account() == sys.actor
                && record.proof.proves(&sys.subject)
            {
                let _ = store.apply_succession(channel, &sys.actor, &sys.subject);
                verified = true;
            }
            // SIP-62: what this exchange holds of the account under SIP-59
            // and SIP-60 follows the key, once the succession is checked.
            if verified {
                server.devices.follow_succession(&sys.actor, &sys.subject);
            }
        }

        // The rest of what a member needs to actually read this channel here.
        // Skipped when the origin has just been caught contradicting itself:
        // there is no point accumulating more from a party already refused.
        if !took.equivocated {
            pull_shape(client, store, channel).await;
            pull_envelopes(client, store, origin, channel, &pulled.instance).await;
            pull_blobs(client, store, channel).await;
            pull_profiles(client, server, store, channel).await;
        }
        all.insert(*channel, took);
    }
    Ok(all)
}

/// SIP-43: ask the origin once what a channel looks like -- public or
/// private, and its name and topic -- which the constitution's digest
/// covers and this replica cannot recover from it. Until answered the row
/// reads as private and unnamed; an origin from before SIP-43 refuses the
/// route, and the row stays so.
async fn pull_shape(client: &mut H3Client, store: &Channels, channel: &[u8; 32]) {
    if store.shape_known(channel) {
        return;
    }
    let Ok((200, body)) = client
        .post(
            "/peer/channel",
            sqex_proto::peer::PullShape { channel: *channel }.encode(),
        )
        .await
    else {
        return;
    };
    match sqex_proto::peer::Shape::decode(&body) {
        Ok(shape) => {
            if let Err(e) = store.take_shape(channel, &shape) {
                tracing::warn!(error = ?e, "could not record a channel's shape");
            }
        }
        Err(e) => tracing::warn!(error = %e, "the origin's shape did not decode"),
    }
}

/// Pull a channel's SIP-17 key envelopes and keep the ones that verify.
///
/// **Each is checked under its publisher's key, not taken on the origin's
/// word.** SIP-32 made an envelope a self-contained signed object for exactly
/// this: a copy-holder can check it. An origin that substituted a key envelope
/// on the way through would be caught here, and a replica that skipped the
/// check would be handing members a key somebody else chose.
async fn pull_envelopes(
    client: &mut H3Client,
    store: &Channels,
    origin: &Origin,
    channel: &[u8; 32],
    instance: &[u8; 32],
) {
    let Ok((200, body)) = client
        .post(
            "/peer/envelopes",
            PullEnvelopes {
                channel: *channel,
                since_epoch: 0,
            }
            .encode(),
        )
        .await
    else {
        return;
    };
    let Ok(got) = PulledEnvelopes::decode(&body) else {
        return;
    };
    for (epoch, e) in &got.envelopes {
        if acceptable_envelope(&origin.key, instance, channel, *epoch, e) {
            let _ = store.store_envelope(channel, *epoch, e);
        } else {
            tracing::warn!(
                origin = %origin.key,
                channel = %bs58::encode(channel).into_string(),
                "an envelope did not verify under its publisher and was not stored"
            );
        }
    }
}

/// Whether a pulled envelope may be stored.
///
/// A thin name over SIP-32's own check, and it exists as a name so a test can
/// prove the replica *calls* it. The check itself is that the publisher signed
/// this envelope for this place — an origin that substituted a key envelope on
/// the way through changes the bytes the publisher signed over.
pub fn acceptable_envelope(
    origin: &PubKey,
    instance: &[u8; 32],
    channel: &[u8; 32],
    epoch: u32,
    e: &Envelope,
) -> bool {
    verify_envelope(origin, instance, channel, epoch, e)
}

/// Whether a pulled blob's bytes are the blob they were served as.
///
/// **This is the whole check a blob needs**, and the reason it carries no
/// signature: SIP-18 names a blob by the hash of its ciphertext, so bytes that
/// hash to the name *are* the blob and bytes that do not are something else.
pub fn acceptable_blob(id: &[u8; 32], chunks: &[Vec<u8>]) -> bool {
    &blob_id(chunks) == id
}

/// Pull a channel's blobs, keeping only those whose bytes hash to the id.
///
/// **This is why a blob needs no signature.** SIP-18 names a blob by the hash
/// of its ciphertext, so a replica that recomputes the hash has checked
/// everything there is to check — an origin cannot substitute a byte without
/// changing the name.
async fn pull_blobs(client: &mut H3Client, store: &Channels, channel: &[u8; 32]) {
    let Ok((200, body)) = client
        .post(
            "/peer/blobs",
            PullBlob {
                channel: *channel,
                blob: [0; 32],
                chunk: BLOB_LIST,
            }
            .encode(),
        )
        .await
    else {
        return;
    };
    let Ok(list) = PulledBlob::decode(&body) else {
        return;
    };
    for (id, size, chunks) in list.blobs {
        if store.holds_blob(&id) {
            continue;
        }
        let mut sealed = Vec::with_capacity(chunks as usize);
        for idx in 0..chunks {
            let Ok((200, body)) = client
                .post(
                    "/peer/blobs",
                    PullBlob {
                        channel: *channel,
                        blob: id,
                        chunk: idx,
                    }
                    .encode(),
                )
                .await
            else {
                break;
            };
            match PulledBlob::decode(&body) {
                Ok(chunk) => sealed.push(chunk.sealed),
                Err(_) => break,
            }
        }
        if sealed.len() != chunks as usize {
            continue;
        }
        if !acceptable_blob(&id, &sealed) {
            tracing::warn!(
                blob = %bs58::encode(id).into_string(),
                "a pulled blob did not hash to its own name and was not stored"
            );
            continue;
        }
        let _ = store.store_blob(channel, &id, size, &sealed);
    }
}

/// Pull the signed profile of every member this replica now derives.
///
/// Highest serial wins, which is the supersession rule `sqns` has used between
/// servers since its first release and the one SIP-35 adopts wholesale. The
/// origin's own store enforces it on the way in, so a replay of an older record
/// changes nothing.
async fn pull_profiles(
    client: &mut H3Client,
    server: &crate::server::Server,
    store: &Channels,
    channel: &[u8; 32],
) {
    for account in store.members_of(channel) {
        let Ok((200, body)) = client
            .post("/peer/records", PullRecord { account }.encode())
            .await
        else {
            continue;
        };
        let Ok(got) = ProfileGot::decode(&body) else {
            continue;
        };
        // A record the subject signed, or nothing. `put` verifies it and
        // refuses a lower serial than the one held.
        if let Some(record) = got.record {
            let _ = server.profiles().put(&account, &record);
        }
    }
}

/// Ask an origin which account a device belongs to, and **verify the credential
/// it hands back** rather than trusting the mapping.
///
/// The registry is served on an ordinary client route, so a replica needs no
/// peering privilege for SIP-31's step 2 — and what comes back is a signed
/// SIP-20 artifact it checks for itself. SIP-20 puts the reason plainly: a
/// credential naming an account the verifier did not ask about is not evidence
/// of anything.
///
/// Asked by the **account the entry names**, since SIP-22's list is by
/// account: asking by the device key found nothing for any linked device,
/// and a copy refused every entry a linked device ever signed (SIP-62
/// turned that up, since a handover makes every account's own key a
/// linked device of the new one).
pub async fn account_for(
    client: &mut H3Client,
    account: &PubKey,
    device: &PubKey,
) -> Option<PubKey> {
    let (code, body) = client
        .post("/device/list", ListDevices { account: *account }.encode())
        .await
        .ok()?;
    if code != 200 {
        return None;
    }
    let devices = Devices::decode(&body).ok()?;
    for d in &devices.devices {
        if &d.device == device
            && let Some(c) = &d.credential
            // Verified against the account the credential itself names, and
            // the caller then checks that account against the entry's — SIP-20
            // is explicit that a credential naming an account the verifier did
            // not ask about is not evidence of anything.
            && c.verify(&c.account, SCOPE_CHAT, devices.now).is_ok()
        {
            return Some(c.account);
        }
    }
    None
}

/// Replicate from one origin, for as long as this exchange runs.
///
/// Redials on failure rather than giving up: an origin that is down is an
/// availability problem, and outliving one is half the reason to replicate.
/// SIP-43: this replica's way to an origin for a member's post, and the
/// nudge that makes the pull loop fetch the answer back promptly.
///
/// Its own connection rather than the pull loop's, so a post never waits
/// behind a pull and a pull never behind a post; brought up on first use and
/// dropped on the first transport error, so the next post redials. One post
/// at a time per origin -- they are small, and ordering the origin's
/// answers is the origin's job, not this lock's.
pub struct Forwarder {
    pub key: PubKey,
    pub addr: SocketAddr,
    /// Where the origin is reached by SIP-33, for `/channel/home`.
    pub domain: String,
    client: tokio::sync::Mutex<Option<H3Client>>,
    /// Rung after a post the origin took, so the entry is pulled now.
    pub poke: tokio::sync::Notify,
}

impl Forwarder {
    pub fn new(key: PubKey, addr: SocketAddr, domain: String) -> Forwarder {
        Forwarder {
            key,
            addr,
            domain,
            client: tokio::sync::Mutex::new(None),
            poke: tokio::sync::Notify::new(),
        }
    }

    /// Carry a member's signed join or leave to the origin, as
    /// [`forward`](Self::forward) carries a post.
    pub async fn action(
        &self,
        seed: &[u8; 32],
        device: &PubKey,
        carry: Option<&sqex_proto::credential::Credential>,
        path: &str,
        body: &[u8],
    ) -> std::result::Result<Forwarded, String> {
        let mut slot = self.client.lock().await;
        if slot.is_none() {
            *slot = Some(
                H3Client::connect(self.addr, self.key.as_bytes(), seed)
                    .await
                    .map_err(|e| format!("dial the origin: {e}"))?,
            );
        }
        let client = slot.as_mut().expect("just filled");
        let req = sqex_proto::peer::ForwardAction {
            device: *device,
            path: path.to_string(),
            body: body.to_vec(),
        };
        let (code, body) = match client
            .post("/peer/forward", carried(carry, req.encode()))
            .await
        {
            Ok(a) => a,
            Err(e) => {
                *slot = None;
                return Err(format!("the origin did not answer: {e}"));
            }
        };
        if code != 200 {
            return Err(format!("the origin refused the forward ({code})"));
        }
        let forwarded = Forwarded::decode(&body).map_err(|e| e.to_string())?;
        if forwarded.status == 200 {
            self.poke.notify_one();
        }
        Ok(forwarded)
    }

    /// SIP-60: carry an account's Move to the origin ahead of an act made
    /// for it, so the acts-for gate is open when the act arrives. Best
    /// effort and idempotent: an origin holding it already says stale.
    pub async fn carry_move(&self, seed: &[u8; 32], mv: &sqex_proto::home::Move, domain: &str) {
        let mut slot = self.client.lock().await;
        if slot.is_none() {
            *slot = match H3Client::connect(self.addr, self.key.as_bytes(), seed).await {
                Ok(c) => Some(c),
                Err(_) => return,
            };
        }
        let client = slot.as_mut().expect("just filled");
        let req = sqex_proto::peer::PeerMoved {
            mv: *mv,
            domain: domain.to_string(),
        };
        if client.post("/peer/moved", req.encode()).await.is_err() {
            *slot = None;
        }
    }

    /// Ask the origin where `device` stands in `channel`, for an `info`
    /// answered here: a replica tracks no chains, and a device with a fresh
    /// store would otherwise sign from zero and be refused.
    pub async fn standing(
        &self,
        seed: &[u8; 32],
        channel: &[u8; 32],
        device: &PubKey,
    ) -> Option<sqex_proto::peer::Standing> {
        let mut slot = self.client.lock().await;
        if slot.is_none() {
            *slot = Some(
                H3Client::connect(self.addr, self.key.as_bytes(), seed)
                    .await
                    .ok()?,
            );
        }
        let client = slot.as_mut().expect("just filled");
        let req = sqex_proto::peer::PullStanding {
            channel: *channel,
            device: *device,
        };
        match client.post("/peer/standing", req.encode()).await {
            Ok((200, body)) => sqex_proto::peer::Standing::decode(&body).ok(),
            Ok(_) => None,
            Err(_) => {
                *slot = None;
                None
            }
        }
    }

    /// Carry a member's post to the origin and bring back its answer: the
    /// status and body the origin's own `/channel/post` gave. `Err` is the
    /// origin out of reach, or refusing this replica as a peer -- which to
    /// the member is the same thing, and is said as `origin_away`.
    pub async fn forward(
        &self,
        seed: &[u8; 32],
        device: &PubKey,
        carry: Option<&sqex_proto::credential::Credential>,
        post: &sqex_proto::channel::Post,
    ) -> std::result::Result<Forwarded, String> {
        let mut slot = self.client.lock().await;
        if slot.is_none() {
            *slot = Some(
                H3Client::connect(self.addr, self.key.as_bytes(), seed)
                    .await
                    .map_err(|e| format!("dial the origin: {e}"))?,
            );
        }
        let client = slot.as_mut().expect("just filled");
        let req = Forward {
            device: *device,
            post: post.clone(),
        };
        let answer = client
            .post("/peer/forward", carried(carry, req.encode()))
            .await;
        let (code, body) = match answer {
            Ok(a) => a,
            Err(e) => {
                // The connection is suspect; the next post starts a new one.
                *slot = None;
                return Err(format!("the origin did not answer: {e}"));
            }
        };
        if code != 200 {
            // SIP-35's uniform peering refusal, or an origin from before
            // SIP-43: either way it cannot be reached for this.
            return Err(format!("the origin refused the forward ({code})"));
        }
        let forwarded = Forwarded::decode(&body).map_err(|e| e.to_string())?;
        if forwarded.status == 200 {
            self.poke.notify_one();
        }
        Ok(forwarded)
    }
}

/// SIP-59: a forward for a device with a credential goes wrapped in it, so
/// an origin that never saw the device can still bind it to its account.
/// An account acting as its own device has nothing to carry, and the
/// forward goes as SIP-43 sends it -- which an origin from before SIP-59
/// still understands.
fn carried(carry: Option<&sqex_proto::credential::Credential>, inner: Vec<u8>) -> Vec<u8> {
    match carry {
        Some(credential) => sqex_proto::peer::Carried {
            credential: credential.clone(),
            inner,
        }
        .encode(),
        None => inner,
    }
}

/// SIP-61: how a wait on the origin ended.
enum Waited {
    /// Something changed in at least one channel.
    Changed,
    /// The wait ran out with nothing.
    Quiet,
    /// The origin does not speak SIP-61 (or refuses this peer the route).
    Unsupported,
    /// The connection went; the caller redials.
    Lost,
}

/// How long after an origin refused a wait before trying it again.
const WAIT_RETRY: std::time::Duration = std::time::Duration::from_secs(600);

/// SIP-61: hold one request at the origin naming `channels` and where each
/// stands here, for up to `secs`. At most `MAX_WAIT_CHANNELS` are named.
///
/// `seen` is the highest seq this replica was *shown* per channel, refused
/// entries included: a wait keyed on what is stored would answer at once
/// for ever while an entry the replica refuses sits at the origin.
async fn wait_on(
    client: &mut H3Client,
    store: &Channels,
    channels: &[[u8; 32]],
    seen: &HashMap<[u8; 32], u64>,
    secs: u16,
) -> Waited {
    let named: Vec<([u8; 32], u64)> = channels
        .iter()
        .take(sqex_proto::peer::MAX_WAIT_CHANNELS)
        .map(|c| (*c, store.last_seq(c).max(seen.get(c).copied().unwrap_or(0))))
        .collect();
    let req = sqex_proto::peer::PeerWait {
        wait_secs: secs.min(sqex_proto::channel::MAX_WAIT),
        channels: named,
    };
    match client.post("/peer/wait", req.encode()).await {
        Ok((200, body)) => match sqex_proto::peer::Changed::decode(&body) {
            Ok(c) if c.channels.is_empty() => Waited::Quiet,
            Ok(_) => Waited::Changed,
            Err(_) => Waited::Unsupported,
        },
        Ok(_) => Waited::Unsupported,
        Err(_) => Waited::Lost,
    }
}

/// Between pulls: wait on the origin (SIP-61) where it lets us, sleep the
/// interval where it does not, and come back early for a poke either way.
/// `waits_from` is when the origin may next be asked to wait, after a
/// refusal. Returns whether the connection is still good.
#[allow(clippy::too_many_arguments)]
async fn pause_or_wait(
    client: &mut H3Client,
    store: &Channels,
    channels: &[[u8; 32]],
    seen: &HashMap<[u8; 32], u64>,
    interval: std::time::Duration,
    poke: &tokio::sync::Notify,
    waits_from: &mut tokio::time::Instant,
) -> bool {
    if tokio::time::Instant::now() < *waits_from || channels.is_empty() {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = poke.notified() => {}
        }
        return true;
    }
    let secs = interval
        .as_secs()
        .clamp(1, sqex_proto::channel::MAX_WAIT as u64) as u16;
    tokio::select! {
        waited = wait_on(client, store, channels, seen, secs) => match waited {
            Waited::Changed | Waited::Quiet => true,
            Waited::Unsupported => {
                *waits_from = tokio::time::Instant::now() + WAIT_RETRY;
                true
            }
            Waited::Lost => false,
        },
        _ = poke.notified() => true,
    }
}

/// SIP-61: what a pull showed this replica, refused entries included, so a
/// wait does not fire on an entry it will refuse again.
fn note_seen(seen: &mut HashMap<[u8; 32], u64>, took: &HashMap<[u8; 32], Took>) {
    for (channel, t) in took {
        if let Some(top) = t.refused.iter().map(|(seq, _)| *seq).max() {
            let e = seen.entry(*channel).or_insert(0);
            *e = (*e).max(top);
        }
    }
}

/// SIP-61 for the loops that pull from several origins a cycle: wait on
/// all of them at once, and come back when any changes, when `notify`
/// fires, or when the interval runs out. Each origin's connection is
/// spent on its wait; the next cycle dials afresh.
async fn wait_any(
    server: &Arc<crate::server::Server>,
    waits: Vec<(H3Client, Vec<[u8; 32]>)>,
    seen: &HashMap<[u8; 32], u64>,
    interval: std::time::Duration,
    notify: &tokio::sync::Notify,
) {
    let secs = interval
        .as_secs()
        .clamp(1, sqex_proto::channel::MAX_WAIT as u64) as u16;
    let mut set = tokio::task::JoinSet::new();
    for (mut client, channels) in waits {
        if channels.is_empty() {
            continue;
        }
        let server = Arc::clone(server);
        let seen = seen.clone();
        set.spawn(
            async move { wait_on(&mut client, server.channels(), &channels, &seen, secs).await },
        );
    }
    let sleep = tokio::time::sleep(interval);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return,
            _ = notify.notified() => return,
            next = set.join_next() => match next {
                Some(Ok(Waited::Changed)) => return,
                Some(_) => continue,
                None => {
                    // Nothing left to wait on: sleep out the interval.
                    tokio::select! {
                        _ = &mut sleep => {}
                        _ = notify.notified() => {}
                    }
                    return;
                }
            },
        }
    }
}

/// Waits its interval between pulls, floored by SIP-35 at `PEER_MIN_INTERVAL`
/// — a replica that hammered an origin would be a worse citizen than one that
/// lagged -- or less, when a post this replica forwarded was taken and the
/// member who wrote it is waiting to read it back. SIP-61: where the origin
/// lets a replica wait on it, the wait replaces the sleep and a change at
/// the origin is pulled at once.
pub async fn run(
    server: Arc<crate::server::Server>,
    seed: [u8; 32],
    origin: Origin,
    forwarder: Arc<Forwarder>,
) {
    let pause = |interval: std::time::Duration| {
        let forwarder = Arc::clone(&forwarder);
        async move {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = forwarder.poke.notified() => {}
            }
        }
    };
    let mut waits_from = tokio::time::Instant::now();
    let mut seen: HashMap<[u8; 32], u64> = HashMap::new();
    let mut holes: Holes = holes_in(server.channels(), &origin.channels);
    loop {
        match H3Client::connect(origin.addr, origin.key.as_bytes(), &seed).await {
            Err(e) => {
                tracing::warn!(origin = %origin.key, error = %e, "cannot reach the origin");
            }
            Ok(mut client) => {
                // One connection, many pulls: a fresh handshake per pull would
                // cost more than the pull.
                loop {
                    match pull_once_from(&mut client, &server, &origin, &holes).await {
                        Err(e) => {
                            tracing::warn!(origin = %origin.key, error = %e, "pull failed");
                            break;
                        }
                        Ok(took) => {
                            report(&origin, &took);
                            note_seen(&mut seen, &took);
                            note_holes(&mut holes, &took);
                        }
                    }
                    if !pause_or_wait(
                        &mut client,
                        server.channels(),
                        &origin.channels,
                        &seen,
                        origin.interval,
                        &forwarder.poke,
                        &mut waits_from,
                    )
                    .await
                    {
                        break;
                    }
                }
            }
        }
        pause(origin.interval).await;
    }
}

/// SIP-53: pull the channels whose origin was learned from a rehome rather
/// than from configuration -- another replica's, or the old origin's own,
/// once it follows. Each is found by SIP-33 discovery of the domain the
/// rehome carried, checked against the key, and pulled as any origin is.
pub async fn run_moved(
    server: Arc<crate::server::Server>,
    seed: [u8; 32],
    configured: Vec<PubKey>,
    interval: std::time::Duration,
) {
    let never = tokio::sync::Notify::new();
    let mut waits: Vec<(H3Client, Vec<[u8; 32]>)> = Vec::new();
    let mut seen: HashMap<[u8; 32], u64> = HashMap::new();
    let mut holes: Holes = HashMap::new();
    let mut seeded: std::collections::HashSet<PubKey> = std::collections::HashSet::new();
    loop {
        wait_any(&server, std::mem::take(&mut waits), &seen, interval, &never).await;
        for (origin, domain, channels) in server.channels().moved_channels(&configured) {
            if domain.is_empty() {
                continue;
            }
            let Ok(found) = server.relay_find(&domain).await else {
                tracing::debug!(%domain, "cannot find a moved origin");
                continue;
            };
            if found.0 != origin {
                tracing::warn!(%domain, expected = %origin, found = %found.0, "a moved origin's domain names another key");
                continue;
            }
            server.add_forwarder(origin, found.1, domain.clone());
            let task = Origin {
                key: origin,
                addr: found.1,
                channels,
                interval,
                predecessors: Vec::new(),
            };
            if !seeded.contains(&origin) {
                holes.extend(holes_in(server.channels(), &task.channels));
                seeded.insert(origin);
            }
            match H3Client::connect(task.addr, task.key.as_bytes(), &seed).await {
                Err(e) => {
                    tracing::warn!(origin = %origin, error = %e, "cannot reach a moved origin")
                }
                Ok(mut client) => match pull_once_from(&mut client, &server, &task, &holes).await {
                    Err(e) => {
                        tracing::warn!(origin = %origin, error = %e, "pull from a moved origin failed")
                    }
                    Ok(took) => {
                        report(&task, &took);
                        note_seen(&mut seen, &took);
                        note_holes(&mut holes, &took);
                        waits.push((client, task.channels.clone()));
                    }
                },
            }
        }
    }
}

/// SIP-59: pull for the accounts homed here. Each origin an account's Move
/// named is found by its domain hint and checked against the key; the Move
/// is carried to it (idempotent -- an origin that holds it already says
/// stale, and that is fine), it is asked which of its channels the account
/// is in, and those are pulled as any origin's are. Channels a configured
/// origin already pulls, and channels this exchange orders itself, are
/// left out. Runs at once when an account moves here, and on `interval`
/// otherwise.
pub async fn run_homed(
    server: Arc<crate::server::Server>,
    seed: [u8; 32],
    configured: Vec<(PubKey, Vec<[u8; 32]>)>,
    interval: std::time::Duration,
) {
    let mut waits: Vec<(H3Client, Vec<[u8; 32]>)> = Vec::new();
    let mut seen: HashMap<[u8; 32], u64> = HashMap::new();
    let mut holes: Holes = HashMap::new();
    let mut seeded: std::collections::HashSet<PubKey> = std::collections::HashSet::new();
    loop {
        // SIP-61: wait on every origin pulled last cycle; a move here or a
        // forward through here comes back early either way.
        wait_any(
            &server,
            std::mem::take(&mut waits),
            &seen,
            interval,
            &server.homed,
        )
        .await;
        let me = server.public_key;
        for (origin, domain, accounts) in server.devices.homed_here(&me) {
            if origin == me {
                continue;
            }
            // By the hint the account gave, or by whatever else this
            // exchange knows the origin by (SIP-60's `reach`).
            let Some((addr, _)) = server.reach_by(&origin, &domain).await else {
                tracing::debug!(%origin, %domain, "cannot find an account's origin");
                continue;
            };
            let mut client = match H3Client::connect(addr, origin.as_bytes(), &seed).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(origin = %origin, error = %e, "cannot reach an account's origin");
                    continue;
                }
            };
            let already: Vec<[u8; 32]> = configured
                .iter()
                .filter(|(k, _)| *k == origin)
                .flat_map(|(_, cs)| cs.iter().copied())
                .collect();
            let mut channels: Vec<[u8; 32]> = Vec::new();
            for account in &accounts {
                if let Some((mv, home_domain)) = server.devices.move_of(account) {
                    let carried = sqex_proto::peer::PeerMoved {
                        mv,
                        domain: home_domain,
                    };
                    match client.post("/peer/moved", carried.encode()).await {
                        Ok((200, _)) | Ok((409, _)) => {}
                        Ok((code, _)) => {
                            tracing::debug!(origin = %origin, account = %account, code, "the origin did not take the move")
                        }
                        Err(e) => {
                            tracing::warn!(origin = %origin, error = %e, "carrying a move failed");
                            break;
                        }
                    }
                }
                let ask = sqex_proto::peer::PullMine { account: *account };
                match client.post("/peer/mine", ask.encode()).await {
                    Ok((200, body)) => {
                        if let Ok(mine) = sqex_proto::peer::Mine::decode(&body) {
                            for c in mine.channels {
                                if !already.contains(&c)
                                    && !channels.contains(&c)
                                    && !server.channels().orders(&c)
                                {
                                    channels.push(c);
                                }
                            }
                        }
                    }
                    Ok((code, _)) => {
                        tracing::debug!(origin = %origin, account = %account, code, "the origin refused a mine pull")
                    }
                    Err(e) => {
                        tracing::warn!(origin = %origin, error = %e, "a mine pull failed");
                        break;
                    }
                }
            }
            if channels.is_empty() {
                continue;
            }
            let task = Origin {
                key: origin,
                addr,
                channels,
                interval,
                predecessors: Vec::new(),
            };
            if !seeded.contains(&origin) {
                holes.extend(holes_in(server.channels(), &task.channels));
                seeded.insert(origin);
            }
            match pull_once_from(&mut client, &server, &task, &holes).await {
                Err(e) => {
                    tracing::warn!(origin = %origin, error = %e, "pull for a homed account failed")
                }
                Ok(took) => {
                    report(&task, &took);
                    note_seen(&mut seen, &took);
                    note_holes(&mut holes, &took);
                    waits.push((client, task.channels.clone()));
                }
            }
        }
    }
}

/// SIP-54: pull the origin's read marks and signal log for a channel and
/// apply them here. Best effort: an origin from before SIP-54 refuses both
/// as it refuses any peering route it lacks, and nothing changes.
async fn pull_soft_state(
    client: &mut H3Client,
    server: &crate::server::Server,
    channel: &[u8; 32],
) {
    let store = server.channels();
    if let Ok((200, body)) = client
        .post(
            "/peer/cursors",
            sqex_proto::peer::PullCursors { channel: *channel }.encode(),
        )
        .await
        && let Ok(marks) = sqex_proto::channel::Marks::decode(&body)
    {
        server.merge_pulled_cursors(channel, &marks);
    }
    // SIP-57: redactions since the last look, a little before it in case
    // of clocks: applying one twice is nothing.
    let looked = store.tombstone_mark(channel);
    if let Ok((200, body)) = client
        .post(
            "/peer/tombstones",
            sqex_proto::peer::PullTombstones {
                channel: *channel,
                since: looked.saturating_sub(5),
            }
            .encode(),
        )
        .await
        && let Ok(t) = sqex_proto::peer::Tombstones::decode(&body)
    {
        let mut changed = false;
        for (seq, _) in &t.redacted {
            changed |= store.apply_tombstone(channel, *seq);
        }
        if changed {
            server.tell(
                channel,
                sqex_proto::events::Event::Channel {
                    channel: *channel,
                    last_seq: 0,
                },
            );
        }
        store.set_tombstone_mark(channel, t.now);
    }
    let since = store.signal_mark(channel);
    if let Ok((200, body)) = client
        .post(
            "/peer/signals",
            sqex_proto::peer::PullSignals {
                channel: *channel,
                since,
            }
            .encode(),
        )
        .await
        && let Ok(signals) = sqex_proto::peer::Signals::decode(&body)
    {
        for l in &signals.signals {
            server.deliver_pulled_signal(channel, l);
        }
        if signals.next > 0 {
            store.set_signal_mark(channel, signals.next);
        }
    }
}

/// SIP-53: ask an origin where a channel went, via the standing it answers
/// for any device -- here this exchange's own key.
async fn standing_moved(
    client: &mut H3Client,
    channel: &[u8; 32],
    me: &PubKey,
) -> Option<(PubKey, String)> {
    let req = sqex_proto::peer::PullStanding {
        channel: *channel,
        device: *me,
    };
    match client.post("/peer/standing", req.encode()).await {
        Ok((200, body)) => sqex_proto::peer::Standing::decode(&body).ok()?.moved,
        _ => None,
    }
}

/// Say what a pull did, at the level each outcome deserves.
///
/// An equivocation is an error and is meant to be found in a log by somebody
/// who was not looking for it — it is the finding this whole arrangement exists
/// to produce, and a replica that noticed one quietly would have wasted the
/// noticing.
fn report(origin: &Origin, took: &HashMap<[u8; 32], Took>) {
    for (channel, t) in took {
        let channel = bs58::encode(channel).into_string();
        if t.equivocated {
            tracing::error!(
                origin = %origin.key,
                %channel,
                "the origin equivocated: two receipts for one position, and this replica has the proof"
            );
        } else if !t.refused.is_empty() {
            tracing::warn!(
                origin = %origin.key, %channel,
                stored = t.stored, refused = t.refused.len(),
                "pulled, with entries refused"
            );
        } else if t.stored > 0 {
            tracing::info!(origin = %origin.key, %channel, stored = t.stored, "pulled");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sqex_proto::blob_store::blob_id;
    use sqex_proto::channel_key::{ChannelKey, seal_envelope, sign_envelope};

    /// **An envelope is checked under its publisher, not taken on the origin's
    /// word.** SIP-32 made it a self-contained signed object precisely so a
    /// copy-holder could check it; a replica that skipped this would be handing
    /// members a channel key somebody else chose.
    #[test]
    fn an_envelope_the_publisher_did_not_sign_is_not_acceptable() {
        let seed = [3u8; 32];
        let recipient = PubKey::new(
            SigningKey::from_bytes(&[4u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let origin = PubKey::new(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let instance = [5u8; 32];
        let channel = [6u8; 32];
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let prekey = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let good = sign_envelope(
            &seed,
            &origin,
            &instance,
            &channel,
            1,
            seal_envelope(&recipient, 7, &prekey, 1, &[ChannelKey::generate()]).unwrap(),
        );
        assert!(acceptable_envelope(&origin, &instance, &channel, 1, &good));

        // Every term the signature binds, one at a time. An envelope that
        // survived a changed channel or epoch would lift from one place into
        // another, which is the whole reason those terms are in the input.
        let mut tampered = good.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(!acceptable_envelope(
            &origin, &instance, &channel, 1, &tampered
        ));
        assert!(!acceptable_envelope(&origin, &instance, &channel, 2, &good));
        assert!(!acceptable_envelope(
            &origin, &instance, &[7u8; 32], 1, &good
        ));
        assert!(!acceptable_envelope(
            &origin, &[8u8; 32], &channel, 1, &good
        ));
        assert!(!acceptable_envelope(
            &PubKey::new([1u8; 32]),
            &instance,
            &channel,
            1,
            &good
        ));
    }

    /// A blob is its hash, so bytes that do not hash to the name are not the
    /// blob — and the check needs no key, which is why blobs replicate at all.
    #[test]
    fn bytes_that_do_not_hash_to_the_name_are_not_the_blob() {
        let chunks = vec![b"one".to_vec(), b"two".to_vec()];
        let id = blob_id(&chunks);
        assert!(acceptable_blob(&id, &chunks));

        let mut altered = chunks.clone();
        altered[1][0] ^= 1;
        assert!(!acceptable_blob(&id, &altered));
        // Order is part of the name: two chunks swapped are a different blob,
        // and a replica that accepted them would hold a file nobody uploaded.
        assert!(!acceptable_blob(
            &id,
            &[chunks[1].clone(), chunks[0].clone()]
        ));
        assert!(!acceptable_blob(&id, &chunks[..1]));
    }
}
