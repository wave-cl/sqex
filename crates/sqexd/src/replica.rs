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

use sqex_proto::channel::{Entry, KIND_MEMBER};
use sqex_proto::credential::SCOPE_CHAT;
use sqex_proto::device::{Devices, ListDevices};
use sqex_proto::entry_sig::{EntryTerms, Place, link, verify_entry, verify_entry_hashed};
use sqex_proto::blob_store::blob_id;
use sqex_proto::channel_key::{Envelope, verify_envelope};
use sqex_proto::peer::{
    BLOB_LIST, Hello, Hi, MAX_PULL, PEER_VERSION, Pull, PullBlob, PullEnvelopes, PullRecord,
    Pulled, PulledBlob, PulledEnvelopes,
};
use sqex_proto::profile::Got as ProfileGot;
use sqex_proto::receipt::{self, Branch, Equivocation, ReceiptTerms};
use sha2::{Digest, Sha256};
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
    let store = server.channels();
    let (code, body) = client
        .post(
            "/peer/hello",
            Hello { version: PEER_VERSION, since: 0 }.encode(),
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

    let mut all = HashMap::new();
    for channel in &origin.channels {
        // **Stop pulling a channel this origin has already contradicted itself
        // about.** SIP-35 requires it, and the reason is not squeamishness:
        // continuing would accumulate history from a party already caught
        // telling two of them, with no basis for preferring what comes next.
        if store.equivocation_for(channel).is_some() {
            continue;
        }
        let since = store.highest(channel);
        let (code, body) = client
            .post(
                "/peer/pull",
                Pull { channel: *channel, since, max: MAX_PULL }.encode(),
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
                creds.insert(e.device, account_for(client, &e.device).await);
            }
        }
        let lookup = move |d: &PubKey| creds.get(d).copied().flatten();
        let took = take(store, &origin.key, channel, &pulled, &lookup);

        // The rest of what a member needs to actually read this channel here.
        // Skipped when the origin has just been caught contradicting itself:
        // there is no point accumulating more from a party already refused.
        if !took.equivocated {
            pull_envelopes(client, store, origin, channel, &pulled.instance).await;
            pull_blobs(client, store, channel).await;
            pull_profiles(client, server, store, channel).await;
        }
        all.insert(*channel, took);
    }
    Ok(all)
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
            PullEnvelopes { channel: *channel, since_epoch: 0 }.encode(),
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
            PullBlob { channel: *channel, blob: [0; 32], chunk: BLOB_LIST }.encode(),
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
                    PullBlob { channel: *channel, blob: id, chunk: idx }.encode(),
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
pub async fn account_for(client: &mut H3Client, device: &PubKey) -> Option<PubKey> {
    // SIP-22 makes an account with no registered devices its own device, so the
    // registry answers about a device key as readily as an account key, and the
    // row that names this device is the one being looked for.
    let (code, body) = client
        .post("/device/list", ListDevices { account: *device }.encode())
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
/// Waits its interval between pulls, floored by SIP-35 at `PEER_MIN_INTERVAL`
/// — a replica that hammered an origin would be a worse citizen than one that
/// lagged.
pub async fn run(server: Arc<crate::server::Server>, seed: [u8; 32], origin: Origin) {
    loop {
        match H3Client::connect(origin.addr, origin.key.as_bytes(), &seed).await {
            Err(e) => {
                tracing::warn!(origin = %origin.key, error = %e, "cannot reach the origin");
            }
            Ok(mut client) => {
                // One connection, many pulls: a fresh handshake per pull would
                // cost more than the pull.
                loop {
                    match pull_once(&mut client, &server, &origin).await {
                        Err(e) => {
                            tracing::warn!(origin = %origin.key, error = %e, "pull failed");
                            break;
                        }
                        Ok(took) => report(&origin, &took),
                    }
                    tokio::time::sleep(origin.interval).await;
                }
            }
        }
        tokio::time::sleep(origin.interval).await;
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
        let recipient =
            PubKey::new(SigningKey::from_bytes(&[4u8; 32]).verifying_key().to_bytes());
        let origin = PubKey::new(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
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
        assert!(!acceptable_envelope(&origin, &instance, &channel, 1, &tampered));
        assert!(!acceptable_envelope(&origin, &instance, &channel, 2, &good));
        assert!(!acceptable_envelope(&origin, &instance, &[7u8; 32], 1, &good));
        assert!(!acceptable_envelope(&origin, &[8u8; 32], &channel, 1, &good));
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
        assert!(!acceptable_blob(&id, &[chunks[1].clone(), chunks[0].clone()]));
        assert!(!acceptable_blob(&id, &chunks[..1]));
    }
}
