//! The protocol half: prekeys, epoch keys, posting and fetching.
//!
//! Everything here is done by the client, and that is the point — if the
//! exchange could do any of it, the design would be wrong. It seals, it opens,
//! it verifies prekey signatures itself, and it refuses a replayed counter,
//! because the exchange is either unable or is the party being constrained.

use sha2::{Digest, Sha256};
use sqex_proto::blob::Attachment;
use sqex_proto::channel::{
    Ack, Action, ByAccount, ByChannel, ByChannelSigned, ByTarget, ChannelInfo, Create, Created,
    EVENT_ADDED, EVENT_CREATED, EVENT_DEMOTED, EVENT_JOINED, EVENT_LEFT, EVENT_PROMOTED,
    EVENT_REMOVED, EVENT_RENAMED, EVENT_REPLICATE, EVENT_RETENTION, EVENT_ROTATED,
    EVENT_UNREPLICATE, Entries, Entry, Fetch, Invite, Invitee, KIND_MEMBER, KIND_SYSTEM, List,
    Listing, MAX_MINE, MAX_NAME, MAX_RETENTION, MAX_TOPIC, MIN_RETENTION, Mark, Marks, Membership,
    Mine, Mines, Post, Posted, Retain, Role, TYPE_CLOSE, TYPE_CURSORS, TYPE_EQUIVOCATION,
    TYPE_INFO, TYPE_JOIN, TYPE_LEAVE, TYPE_REDACT, TYPE_REMOVE, TYPE_REPLICATE, TYPE_UNREPLICATE,
    Visibility, constitution, direct_message_id,
};
use sqex_proto::channel_key::{
    Absent, ChannelKey, Envelope, Get as KeyGet, Got, Put as KeyPut, PutAck, TYPE_MISSING,
    open_envelope, seal_envelope, sign_envelope, verify_envelope,
};
use sqex_proto::credential::{Credential, Revocation, SCOPE_CHAT};
use sqex_proto::device::{AdmissionRequest, Device, Devices, ListDevices, Register, Revoke};
use sqex_proto::entry_sig::{
    ActionTerms, EntryTerms, GENESIS, Place, link, sign_action, sign_entry, verify_entry,
    verify_entry_hashed,
};
use sqex_proto::message::{Body, MAX_EMOJI, Part, Post as SipPost};
use sqex_proto::prekey::{
    Cleared, Counts, LOW_WATER, POOL, Pool, Prekey, Publish, TYPE_CLEAR, TYPE_COUNT, Take, Taken,
};
use sqex_proto::profile::{
    self, Block, Blocks, ByAccount as ProfileByAccount, Got as GotProfile, Profile,
    Put as ProfilePut, Record as ProfileRecord,
};
use sqex_proto::receipt::{self, Equivocation, ReceiptTerms};
use sqex_proto::refusal::{Code as RefusalCode, Refusal};
use sqex_proto::timeline::{Received, Timeline};
use sqex_proto::timeline::{Standing, Verdict};
use sqnr::Client;
use sqnr_core::PubKey;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::store::{Kept, Store, StoreError};

/// A direct message's retention window, in seconds.
///
/// SIP-16's default is 30 days and this follows it. It is the exchange's
/// promise about when entries are pruned, not a security property — a member
/// who read a message has it.
const RETENTION_SECS: u32 = 30 * 24 * 60 * 60;

/// How long a fetch may park waiting for something to arrive.
///
/// Under SIP-16's `MAX_WAIT` of 25 s, so the exchange never has to clamp it.
pub const WAIT_SECS: u16 = 20;

/// How long a name we hold is used before it is asked for again.
///
/// SIP-21 caps updates at 32 an hour, so an hour is about the shortest
/// interval at which asking oftener could tell us much.
const PROFILE_TTL: u64 = 60 * 60;

/// How long "we asked and were told nothing" is believed.
///
/// Much shorter, because it is much weaker: everybody starts out with no
/// profile, so this is the entry that stands between somebody publishing a
/// name and anybody seeing it.
const PROFILE_MISS_TTL: u64 = 3 * 60;

/// How long the credential in an admission request stays valid.
///
/// Long enough for somebody to read the request and act on it, short enough
/// that one left unanswered stops being usable rather than sitting in a queue
/// as a standing grant.
const ADMISSION_LIFETIME: u64 = 7 * 24 * 60 * 60;

/// How many profiles one poll will ask about.
///
/// A direct message has two members and a group a handful, so this only ever
/// binds on a large public channel — where a round trip per person on the
/// first poll would be felt. The rest arrive on the polls that follow.
const PROFILES_PER_POLL: usize = 16;

/// How long to wait before each redial, in milliseconds, holding at the last.
///
/// Quick at first, because much the commonest interruption is a few seconds of
/// nothing — a laptop lid, a changed network — and waiting half a minute to
/// notice it came back would be its own fault. Slow at the end, because an
/// exchange that has been down a minute is being worked on, and a client
/// knocking twice a second is not helping.
const BACKOFF_MS: &[u64] = &[500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000];

/// How long one ordinary request may take before the connection is presumed
/// dead.
///
/// Without this the client hangs. QUIC's idle timeout is 30 s, so a request
/// issued to an exchange that has just died does not fail — it waits, and the
/// event loop waits with it, keyboard and all. Thirty seconds of frozen
/// interface, and the connection light could not turn amber because nothing
/// was running to turn it. Eight seconds is far longer than any of these
/// requests takes against a working exchange and far short of the wait that
/// made the client look broken.
const PATIENCE: Duration = Duration::from_secs(8);

/// The same, for a request that moves a file.
///
/// A blob is as large as somebody chose to send and goes over whatever link
/// they have. Holding it to a control-plane deadline would fail an upload that
/// was working perfectly.
const BLOB_PATIENCE: Duration = Duration::from_secs(300);

/// How much of each tick may be spent advancing a dial in progress.
///
/// The interface has a keyboard to serve. `connect_as` allows five seconds for
/// a handshake, and blocking on it would freeze typing for five seconds — so
/// the dial is held across ticks and given a slice of each.
const DIAL_SLICE: Duration = Duration::from_millis(50);

/// A dial in progress: a handshake held across ticks so the interface stays
/// live while it happens.
///
/// `Send` is required, and it did not used to be. The reconnect is advanced a
/// slice at a time rather than spawned, which needs no bound at all — see the
/// note in [`crate::events`]. But the bound is not the same thing as the task:
/// without it a `Chat` cannot cross a thread, so the whole client can only be
/// driven by whoever built it, and a program that also wants to draw a window
/// or carry a call has nowhere to put it. Permitting a task costs nothing; the
/// reconnect still does not use one.
type Dialing = Pin<Box<dyn Future<Output = std::result::Result<Client, String>> + Send>>;

/// A wait with up to a fifth taken off it or added to it.
///
/// One client reconnecting has no need of this. A room of them coming back
/// after an exchange restarts does: without jitter they knock at the same
/// instant and go on doing it in step, which is the one pattern that turns a
/// restart into an outage.
fn jittered(ms: u64) -> u64 {
    let spread = ms / 5;
    if spread == 0 {
        return ms;
    }
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    ms - spread + n % (2 * spread + 1)
}

/// Whether the exchange is reachable, as far as anything has been able to tell.
///
/// Deliberately three states and not two. "Down" covers both a blip and an
/// outage, and they want opposite things from a reader: one is worth ignoring
/// and the other is worth doing something about. Nothing here ever stops
/// trying — [`Link::Gone`] means *this has been failing long enough that you
/// should not count on it*, not that the client has given up. A chat client
/// that gives up is worse than one that keeps knocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Link {
    /// The last thing we asked for got an answer. A refusal counts: a 403 is
    /// proof the connection is alive.
    ///
    /// The default, because a client draws its first frame having just
    /// connected. Starting anywhere else would show a fault that is not there.
    #[default]
    Up,
    /// Down, with a redial scheduled or in flight.
    Retrying,
    /// Down through the whole backoff ramp — a minute or so. Still retrying.
    Gone,
}

#[derive(Debug)]
pub enum ChatError {
    Store(StoreError),
    Transport(String),
    /// The exchange refused, and said why in a way this client can act on.
    Refused(u16, Refusal),
    /// The exchange refused and the body was not a refusal we could read —
    /// an exchange older than this client, which answered JSON or a bare line.
    Unreadable(u16, String),
    Protocol(String),
    /// We are a member with no key for the current epoch. SIP-17 asks that this
    /// be said plainly rather than shown as an empty conversation.
    NoKey(u32),
    /// The exchange answered a chat route with the router's own 404. It is
    /// running, and it does not implement chat at all.
    NoChatHere(String),
    /// An envelope for that recipient and epoch already exists. SIP-17 has the
    /// exchange refuse a second, so re-keying somebody means a new epoch.
    AlreadyKeyed(u32),
    /// The operation is an admin's and this account is not one.
    NotAnAdmin,
    /// SIP-35: this exchange holds two receipts for one position from the
    /// channel's origin, and will present neither branch as the conversation.
    ///
    /// **Surfaced rather than worked around.** The proof is 376 bytes anybody
    /// holding the origin's public key can check, and it is carried here so a
    /// person can be shown it and can pass it on — the whole value of the
    /// artifact is that it travels.
    ///
    /// Boxed because it is 376 bytes and every other variant is small: an
    /// error type is returned from every call on this client, and one variant
    /// should not set the size of all of them.
    Equivocated(Box<Equivocation>),
    /// The other party has published no prekeys, so SIP-23 forbids sealing to
    /// them at all. Not an error in the conversation — the channel exists and
    /// they are in it — but nothing can be said until they start their client.
    NotReady(PubKey),
}

/// Turn a refused response into the error a caller can act on.
///
/// The decision is made on `Refusal::code` — a value — and never on the text of
/// the body. It used to be made with `said.contains("not_an_admin")`, which was
/// correct only while no code was a substring of another and no free-text
/// detail ever contained one. A detail is now a separate field that this
/// function does not read.
fn classify(path: &str, code: u16, body: &[u8]) -> ChatError {
    match Refusal::decode(body) {
        Ok(r) => match r.code {
            // The router's own 404 for a path it does not have, as against a
            // chat route's 404 for a channel or blob that is not there. The two
            // mean entirely different things to whoever reads the message: one
            // is "your exchange is too old", the other is "that thing is gone".
            RefusalCode::NotFound => ChatError::NoChatHere(path.to_string()),
            // Matters because the client no longer decides locally whether it
            // may rotate: SIP-17 lets a member rekey after revoking one of its
            // own devices, and only the exchange holds the facts to judge it.
            RefusalCode::NotAnAdmin => ChatError::NotAnAdmin,
            _ => ChatError::Refused(code, r),
        },
        // An exchange older than this client, where refusals were JSON and a
        // request that would not decode got a bare line. Matched by text, which
        // is what this change removed from the path above — kept only so an old
        // exchange still yields something a caller can act on. A JSON body does
        // not decode as a refusal by accident: its length prefix would have to
        // agree with its own size, and even then an unrecognised code lands in
        // `Unknown`, which matches no branch here.
        Err(_) => {
            let said = String::from_utf8_lossy(body).into_owned();
            if code == 404 && said.trim() == "not found" {
                return ChatError::NoChatHere(path.to_string());
            }
            ChatError::Unreadable(code, said)
        }
    }
}

impl std::fmt::Display for ChatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChatError::Store(e) => write!(f, "{e}"),
            ChatError::Transport(e) => write!(f, "{e}"),
            ChatError::Refused(code, r) => write!(f, "the exchange refused ({code}): {r}"),
            ChatError::Unreadable(code, body) => {
                write!(f, "the exchange refused ({code}) and said: {body}")
            }
            ChatError::Protocol(e) => write!(f, "{e}"),
            ChatError::NoKey(epoch) => write!(
                f,
                "no key for epoch {epoch} — you were not sent one, so this conversation \
                 cannot be read until somebody sends it"
            ),
            ChatError::NoChatHere(path) => write!(
                f,
                "this exchange has no {path} — it is running, but it is older than the \
                 chat services (SIPs 16-24, sqex 0.9.0). Upgrade it, or point at one \
                 that has them"
            ),
            ChatError::AlreadyKeyed(epoch) => write!(
                f,
                "they already have an envelope for epoch {epoch} and the exchange will not \
                 replace it — if they cannot open it, rotate to hand out a new key"
            ),
            ChatError::NotAnAdmin => write!(f, "that is an admin's to do, and you are not one"),
            // Said plainly, and without deciding anything. Neither branch is
            // shown, because a client that picked one would be resolving on the
            // reader's behalf a contradiction only the exchange could have
            // created.
            ChatError::Equivocated(p) => write!(
                f,
                "this exchange signed two different histories for position {} of this \
                 conversation. It is not a disagreement to resolve — one party made both \
                 claims — so nothing here is being shown as the conversation. The proof is \
                 {} bytes and anybody holding the exchange's key can check it",
                p.seq,
                sqex_proto::receipt::EQUIVOCATION_LEN
            ),
            ChatError::NotReady(who) => write!(
                f,
                "{who} has not started their client yet, so there is nowhere to send a \
                 key — the conversation exists and will work as soon as they do"
            ),
        }
    }
}

impl std::error::Error for ChatError {}

impl From<StoreError> for ChatError {
    fn from(e: StoreError) -> ChatError {
        ChatError::Store(e)
    }
}

type Result<T> = std::result::Result<T, ChatError>;

/// Everybody a channel key must reach.
fn members_of(info: &ChannelInfo) -> Vec<PubKey> {
    info.members.iter().map(|m| m.account).collect()
}

/// Everyone a channel key must actually reach.
///
/// **Devices, not accounts.** SIP-17 derives its per-sender subkey from the
/// device precisely so two clients under one identity do not share one and
/// reuse a nonce — so an envelope has to be openable by the device that will
/// use it, and a device holds its own key, not its account's.
///
/// An account with no registered devices is its own device, which is the
/// ordinary single-client case and why this was invisible for so long.
impl Chat {
    async fn devices_of(&mut self, members: &[PubKey]) -> Result<Vec<PubKey>> {
        let mut out = Vec::new();
        for account in members {
            let body = self
                .post("/device/list", ListDevices { account: *account }.encode())
                .await?;
            let listed = Devices::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
            if listed.devices.is_empty() {
                out.push(*account);
            } else {
                out.extend(listed.devices.iter().map(|d| d.device));
            }
        }
        Ok(out)
    }
}

/// Whether an account may mint an epoch here.
fn is_admin(info: &ChannelInfo, who: &PubKey) -> bool {
    info.members
        .iter()
        .any(|m| m.account == *who && m.role == Role::Admin)
}

/// What a fetch turned up, and everything the reader must be told about it.
pub struct Conversation {
    pub timeline: Timeline,
    /// Entries we hold and could not open. Carried rather than dropped, so a
    /// client can say something was there.
    pub unreadable: Vec<u64>,
    /// True when our `since` was below the exchange's oldest retained entry: we
    /// have been away longer than the window and there is history we can never
    /// fill. It must be shown as a gap and not as the whole conversation.
    pub gap: bool,
    /// True when this channel's sequence space restarted: it was destroyed and
    /// recreated under the same identifier, so what came before is unrelated to
    /// what follows and has been dropped (SIP-16).
    pub restarted: bool,
    /// Entries held under a superseded epoch we have no key for. Gone for
    /// good, as against `unreadable`, which is something to wait for.
    pub lost: usize,
    /// The epoch in force, when we hold no key for it — SIP-17's *stranded*
    /// member: one who can fetch entries and open none of them.
    ///
    /// Reported on every poll rather than only when this one folded an
    /// unreadable entry. Those two are not the same, and the difference is a
    /// real conversation that read as empty: entries stored by an earlier run
    /// are not re-folded, so a later poll finds nothing to classify and says
    /// nothing, while the reader sits in front of messages nobody can open.
    pub no_key: Option<u32>,
    /// Somebody is typing (SIP-19's only signal).
    pub typing: bool,
    pub last: u64,
    /// Who may redact and rename, as of this fetch. Returned so a caller can
    /// keep its own copy current: the next start may be offline, and folding a
    /// history without it shows a redacted message and an unnamed channel.
    pub admins: Vec<PubKey>,
}

/// What a redaction actually managed to remove.
///
/// Reported rather than swallowed because the two halves can come apart: the
/// words go at the exchange, and a file may not. A caller that said "deleted"
/// regardless would be describing something that did not happen.
pub struct Redacted {
    /// Files this client detached, so the exchange no longer serves them here.
    pub detached: usize,
    /// Files it could not: already gone, or attached by somebody else. A reader
    /// holding the id may still be able to fetch these.
    pub left_behind: Vec<[u8; 32]>,
    /// Whether the message being deleted was one this client could read. If it
    /// was not, we never learned what it carried, and detaching nothing is not
    /// the same as there having been nothing to detach.
    pub opened: bool,
}

pub struct Chat {
    client: Client,
    seed: [u8; 32],
    /// Where to dial to get back. `None` when nobody said — a `Chat` that
    /// cannot reconnect must not pretend to be reconnecting, and must not
    /// short-circuit its own requests either, so it keeps the behaviour it had
    /// before any of this existed: every call tries.
    endpoint: Option<(SocketAddr, [u8; 32])>,
    link: Link,
    /// How many redials have failed since the link was last up. Indexes
    /// `BACKOFF_MS`, and reaching the end of it is what makes the link `Gone`.
    attempts: usize,
    /// When the next redial is due.
    next_dial: Instant,
    /// A dial in progress, held across ticks so the interface stays live while
    /// it handshakes.
    dialing: Option<Dialing>,
    /// The SIP-30 event stream, when one is open. `None` means nothing is
    /// pushing, and the caller is on its own cadence until it resubscribes —
    /// which is exactly the state a fresh connection starts in.
    events: Option<crate::events::Stream>,
    /// The account we act for. Membership, roles, direct-message identifiers
    /// and display are all per account.
    pub me: PubKey,
    /// This client's own key. Sealing subkeys, message counters and prekeys are
    /// all per device, which is the distinction SIP-17 and SIP-22 exist to
    /// draw — two clients under one identity must not share a subkey.
    device: PubKey,
    /// The exchange we are talking to, bound into every SIP-31 signature.
    ///
    /// Required rather than defaulted: a direct message's identifier derives
    /// from its two accounts, so the same conversation has identical channel
    /// bytes everywhere, and a signature that did not name the exchange would
    /// verify in another one's copy of it.
    exchange: PubKey,
    /// Whether to ask this exchange for SIP-34 receipts.
    ///
    /// Starts true and is lowered on the first refusal, so a client discovers
    /// what an exchange offers by asking rather than by being configured. It is
    /// never raised again for this `Chat`: an exchange does not acquire
    /// receipts mid-connection, and retrying every call would turn a settled
    /// answer into a request per fetch.
    receipts: AtomicBool,
    store: Store,
}

/// Whether a refusal means *this exchange does not issue receipts*.
///
/// Two codes, because there are two kinds of exchange that do not: one that
/// knows the type byte and has no key to sign with, and one old enough never to
/// have heard of it, which refuses the byte as malformed exactly as it refuses
/// any type it does not know. SIP-34 requires a client to treat both as
/// *unclaimed* and to ask again plainly — never as evidence against the
/// entries it then receives.
fn declines_receipts(e: &ChatError) -> bool {
    matches!(
        e,
        ChatError::Refused(_, r) if r.code == RefusalCode::NoReceipts || r.code == RefusalCode::Malformed
    )
}

impl Chat {
    /// `device` is this client's own key — what it seals under, publishes
    /// prekeys for, and counts messages with. The **account** it acts for is
    /// usually the same key, and is not once the client has been linked to
    /// one, which is what `device claim` records.
    pub fn new(
        client: Client,
        seed: [u8; 32],
        device: PubKey,
        exchange: PubKey,
        store: Store,
    ) -> Chat {
        let me = store.account().ok().flatten().unwrap_or(device);
        Chat {
            client,
            seed,
            exchange,
            receipts: AtomicBool::new(true),
            endpoint: None,
            link: Link::Up,
            attempts: 0,
            next_dial: Instant::now(),
            dialing: None,
            events: None,
            me,
            device,
            store,
        }
    }

    /// A `ChannelInfo` carrying nothing but what a caller fills in.
    ///
    /// Used where a signature is needed before there is a channel to ask about
    /// — creating one, where the creator proposes the incarnation itself.
    fn empty_info() -> ChannelInfo {
        ChannelInfo {
            visibility: Visibility::Private,
            epoch: 0,
            instance: [0u8; 32],
            retention_secs: 0,
            max_entries: 0,
            first: 0,
            last: 0,
            my_msg_seq: 0,
            my_chain_seq: 0,
            my_chain_head: GENESIS,
            now: 0,
            members: Vec::new(),
            name: String::new(),
            topic: String::new(),
        }
    }

    /// Check the exchange's SIP-34 receipt on an entry.
    ///
    /// `held` is the head of the entry at `seq - 1` where this reader holds it,
    /// and `None` otherwise. The difference between those two cases is the
    /// difference between a gap and a divergence, and SIP-34 is emphatic they
    /// are not the same: a gap is produced by pruning, retention and joining a
    /// channel with history, and MUST NOT be presented as misconduct.
    ///
    /// The key is the one **this client pinned**, never one taken from the
    /// response or from the connection — a receipt checked under a key the
    /// sender chose proves only that the sender is self-consistent.
    fn standing_for(
        exchange: PubKey,
        channel: &[u8; 32],
        instance: [u8; 32],
        e: &Entry,
        held: Option<[u8; 32]>,
    ) -> Standing {
        let Some(stamp) = &e.stamp else {
            return Standing::Unclaimed;
        };
        let place = Place {
            exchange,
            instance,
            channel: *channel,
        };
        let terms = ReceiptTerms {
            place,
            seq: e.seq,
            posted: e.posted,
            entry_hash: stamp.entry_hash,
            head: stamp.head,
        };
        if !receipt::verify(&terms, &stamp.receipt) {
            return Standing::Repudiated;
        }
        // A member entry's hash is recomputable, so an exchange that receipted
        // a hash unrelated to the entry it served is caught here. A system
        // entry's is not — SIP-31's `arg` is never transmitted — so the served
        // hash is taken on the exchange's word, which `Receipted` says plainly.
        if e.kind == KIND_MEMBER {
            let entry = EntryTerms {
                place,
                account: e.account,
                device: e.device,
                epoch: e.epoch,
                msg_seq: e.msg_seq,
                expires_after: e.expires_after,
                chain_seq: e.chain_seq,
                prev: e.prev,
                body: &e.body,
            };
            if link(&entry.input_hashed(&e.body_hash)) != stamp.entry_hash {
                return Standing::Repudiated;
            }
        }
        match held {
            None => Standing::Unlinked,
            Some(prev) if receipt::advance(&prev, &stamp.entry_hash) == stamp.head => {
                Standing::Vouched
            }
            Some(_) => Standing::Diverged,
        }
    }

    /// Check an entry the way SIP-31 requires — **both steps**.
    ///
    /// Step one is the signature under the device the entry names, which proves
    /// a key signed and nothing about whose key it is. Step two is a SIP-20
    /// credential binding that device to the account the entry names, which
    /// this client now verifies for itself from `bound` rather than taking the
    /// exchange's mapping on trust. Until SIP-32 the credential was verified at
    /// registration and discarded, so step two could not be performed by
    /// anybody at all.
    ///
    /// A system entry carries no signature of its own; its actor's is inside
    /// the body, and the exchange verified it before writing the row.
    fn verdict_for(
        exchange: PubKey,
        channel: &[u8; 32],
        instance: [u8; 32],
        e: &Entry,
        chain: &mut HashMap<PubKey, (u64, [u8; 32])>,
        bound: &HashMap<PubKey, Option<PubKey>>,
    ) -> Verdict {
        if e.kind == KIND_SYSTEM {
            return Verdict::Valid;
        }
        let terms = EntryTerms {
            place: Place {
                exchange,
                instance,
                channel: *channel,
            },
            account: e.account,
            device: e.device,
            epoch: e.epoch,
            msg_seq: e.msg_seq,
            expires_after: e.expires_after,
            chain_seq: e.chain_seq,
            prev: e.prev,
            body: &e.body,
        };
        // A tombstone's body is gone, so the hash it committed to is the only
        // thing left to check against — which is exactly why the commitment is
        // to the hash and not the bytes.
        let signed = if e.body.is_empty() && e.body_hash != Sha256::digest(&[] as &[u8]).as_slice()
        {
            verify_entry_hashed(&terms, &e.body_hash, &e.sig)
        } else {
            verify_entry(&terms, &e.sig)
        };
        if !signed {
            return Verdict::Forged;
        }
        // Step two. An account with no registered device *is* its own device
        // (SIP-22), so a self-signed entry needs no credential — that is the
        // ordinary single-client case and not an unattributed one.
        if e.device != e.account {
            match bound.get(&e.device) {
                // A credential we verified, naming a different account. The
                // entry claims somebody it does not belong to.
                Some(Some(account)) if account != &e.account => return Verdict::Forged,
                Some(Some(_)) => {}
                // Registered, with no credential the exchange could produce.
                // The signature stands and the attribution does not.
                Some(None) | None => return Verdict::Unattributed,
            }
        }
        let input = terms.input_hashed(&e.body_hash);
        match chain.get(&e.device) {
            Some(&(seq, head)) if e.chain_seq == seq && e.prev == head => {
                chain.insert(e.device, (e.chain_seq + 1, link(&input)));
                Verdict::Valid
            }
            // At or below a position this device has already signed at. SIP-31
            // defines the fork literally — "two entries by one device at one
            // `chain_seq`, both validly signed" — and it is the only verdict
            // here that is evidence rather than housekeeping.
            //
            // Comparing for equality alone missed the literal case: after an
            // entry at position N the mark holds N+1, so a *second* entry at N
            // failed the equality and fell through to `Gap`, which SIP-31 says
            // MUST NOT be presented as misconduct.
            //
            // A repeat below the mark does **not** rewind it. Rewinding would
            // reset the chain to the replayed position and make every honest
            // entry after it look like misconduct too — one replay turning
            // into a transcript full of them.
            Some(&(seq, _)) if e.chain_seq <= seq => {
                if e.chain_seq == seq {
                    chain.insert(e.device, (e.chain_seq + 1, link(&input)));
                }
                Verdict::Fork
            }
            // Above the mark: positions are missing rather than repeated.
            // Pruning, retention and joining a channel without its history all
            // produce this, and it is ordinary.
            Some(_) => {
                chain.insert(e.device, (e.chain_seq + 1, link(&input)));
                Verdict::Gap
            }
            // The first entry we have seen from this device in this range. We
            // may simply have started reading in the middle, which is ordinary,
            // so continuity is claimed from here rather than backwards.
            None => {
                chain.insert(e.device, (e.chain_seq + 1, link(&input)));
                Verdict::Valid
            }
        }
    }

    /// Verified device-to-account bindings for a set of accounts (SIP-32).
    ///
    /// `Some(account)` is a SIP-20 credential **this client checked**, not a
    /// mapping the exchange reported. `None` is a device the registry lists and
    /// cannot produce a credential for — a registration made before SIP-32, or
    /// an exchange withholding one — and it is carried rather than dropped so a
    /// reader is told the difference between evidence and an assertion.
    async fn bindings(&mut self, accounts: &[PubKey]) -> Result<HashMap<PubKey, Option<PubKey>>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut out = HashMap::new();
        for account in accounts {
            let body = self
                .post("/device/list", ListDevices { account: *account }.encode())
                .await?;
            let listed = Devices::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
            for d in listed.devices {
                let verified = d.credential.as_ref().is_some_and(|c| {
                    c.delegate == d.device && c.verify(account, SCOPE_CHAT, now).is_ok()
                });
                out.insert(d.device, verified.then_some(*account));
            }
        }
        Ok(out)
    }

    /// Where a signature for `channel` must be made, given what `info` told us.
    fn place(&self, channel: &[u8; 32], info: &ChannelInfo) -> Place {
        Place {
            exchange: self.exchange,
            instance: info.instance,
            channel: *channel,
        }
    }

    /// The next SIP-31 chain position and link for this channel.
    ///
    /// **The greater of what we remember and what we are told**, never the
    /// exchange's report alone. An exchange that under-reported would otherwise
    /// have us sign a second time at a position already used, and the resulting
    /// fork would read as this client's misconduct rather than as its own. The
    /// same discipline `send_body` already applies to the SIP-17 counter, for a
    /// different reason and with the same shape.
    fn chain_at(&self, channel: &[u8; 32], info: &ChannelInfo) -> Result<(u64, [u8; 32])> {
        // SIP-32. A direct message's identifier is derived from its two
        // accounts, so it survives the channel being destroyed and rebuilt —
        // and everything this store keeps under it then belongs to a
        // conversation that no longer exists. Resuming a chain into a new
        // incarnation means every signature after it is refused as a broken
        // chain, permanently, which is SIP-16's "goes silent for good" in a
        // place it had not been looked for.
        //
        // Checked here rather than on the next fetch because this runs before
        // the first thing we sign, and the incarnation says outright what a
        // cursor above the exchange's last sequence number only implies.
        //
        // **Only against an incarnation the exchange stated.** A create carries
        // one this client *proposed*, which is new by construction — comparing
        // against that would reset the channel on every `open_dm`, which is a
        // routine call, and take the conversation with it. `actions_for_create`
        // therefore reads the chain directly.
        if info.instance != [0u8; 32] {
            match self.store.incarnation(channel)? {
                Some(known) if known == info.instance => {}
                Some(_) => {
                    self.store.reset_sequence_space(channel)?;
                    // Noted for the next poll to report. The reset is the whole
                    // reason the conversation above the divider is not the one
                    // below it, and a reader should be told.
                    self.store.set_incarnation(channel, &info.instance, true)?;
                }
                None => self.store.set_incarnation(channel, &info.instance, false)?,
            }
        }
        let (mine, head) = self.store.chain(channel)?;
        Ok(if mine >= info.my_chain_seq {
            (mine, head)
        } else {
            (info.my_chain_seq, info.my_chain_head)
        })
    }

    /// Create a channel, signing for every membership event it will write.
    ///
    /// The creator proposes the incarnation, because SIP-31 binds it into every
    /// signature and the exchange has minted nothing at the moment we sign. Two
    /// answers come back with `created: 0` and mean different things: we are
    /// already a member, which is the idempotent case and needs nothing; or we
    /// are returning to a direct message we had left, where the incarnation
    /// that stands is not the one we proposed. Only in the second do we sign
    /// again — this time for a `joined` rather than an `added`, which is the
    /// event that actually gets written, and which we could not have known to
    /// sign for before asking.
    async fn create_signed(&mut self, mut req: Create) -> Result<Created> {
        let instance = {
            use rand_core::RngCore;
            let mut b = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut b);
            b
        };
        req.instance = instance;
        let (actions, _head) = self.actions_for_create(&req, instance)?;
        req.actions = actions;

        let out = self.post("/channel/create", req.encode()).await?;
        let ack = Created::decode(&out).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if ack.created || ack.instance == instance || ack.instance == [0u8; 32] {
            return Ok(ack);
        }

        // Returning. Sign a `joined` against the incarnation that stands.
        let info = ChannelInfo {
            instance: ack.instance,
            my_chain_seq: 0,
            my_chain_head: GENESIS,
            ..Self::empty_info()
        };
        let (action, _head) =
            self.sign_action_at(&req.channel, &info, EVENT_JOINED, &self.me, &[])?;
        req.instance = ack.instance;
        req.actions = vec![action];
        let out = self.post("/channel/create", req.encode()).await?;
        Created::decode(&out).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// One `added` per invitee, in list order, against the proposed instance,
    /// with the chain head they leave behind.
    fn actions_for_create(
        &self,
        req: &Create,
        instance: [u8; 32],
    ) -> Result<(Vec<Action>, [u8; 32])> {
        let mut out = Vec::with_capacity(req.invites.len() + 1);
        // A create is this device's first act in a channel that did not exist,
        // so the chain starts here: `created` takes the first position and each
        // invitee the next.
        //
        // **From zero, always.** A create either makes a channel the exchange
        // has no chain for — so nothing else could be right — or finds one we
        // are already in, where it writes nothing and these signatures go
        // unused. Reading the store instead would carry a position from a
        // previous incarnation of a derived identifier into a channel that has
        // never seen this device, and every signature after it would be refused
        // as a broken chain.
        let (start, mut prev) = (0u64, GENESIS);

        // SIP-32. The digest covers the constitution as the exchange will store
        // it — a private channel's name and topic are kept empty there, because
        // a membership graph with a name on it says more than the graph, so
        // signing what was asked for rather than what is kept would commit to
        // something that never existed.
        let public = req.visibility == Visibility::Public;
        let founding = constitution(
            req.visibility,
            req.retention_secs,
            req.max_entries,
            if public { &req.name } else { "" },
            if public { &req.topic } else { "" },
        );
        let sign = |event: u8,
                    subject: PubKey,
                    arg: &[u8],
                    n: u64,
                    prev_link: [u8; 32]|
         -> Result<(Action, [u8; 32])> {
            let terms = ActionTerms {
                place: Place {
                    exchange: self.exchange,
                    instance,
                    channel: req.channel,
                },
                actor: self.me,
                actor_device: self.device,
                event,
                subject,
                arg,
                chain_seq: n,
                prev: prev_link,
            };
            let sig =
                sign_action(&self.seed, &terms).map_err(|e| ChatError::Protocol(e.to_string()))?;
            let input = terms
                .input()
                .map_err(|e| ChatError::Protocol(e.to_string()))?;
            Ok((
                Action {
                    chain_seq: n,
                    prev: prev_link,
                    sig,
                },
                link(&input),
            ))
        };

        let (opening, head) = sign(EVENT_CREATED, self.me, &founding, start, prev)?;
        out.push(opening);
        prev = head;

        for (n, i) in req.invites.iter().enumerate() {
            let at = start + 1 + n as u64;
            let (action, head) = sign(EVENT_ADDED, i.account, &[i.role as u8], at, prev)?;
            out.push(action);
            prev = head;
        }
        Ok((out, prev))
    }

    /// Sign a membership action, and hand back the step to record if the
    /// exchange accepts it.
    fn sign_action_at(
        &self,
        channel: &[u8; 32],
        info: &ChannelInfo,
        event: u8,
        subject: &PubKey,
        arg: &[u8],
    ) -> Result<(Action, [u8; 32])> {
        let (chain_seq, prev) = self.chain_at(channel, info)?;
        let terms = ActionTerms {
            place: self.place(channel, info),
            actor: self.me,
            actor_device: self.device,
            event,
            subject: *subject,
            arg,
            chain_seq,
            prev,
        };
        let sig =
            sign_action(&self.seed, &terms).map_err(|e| ChatError::Protocol(e.to_string()))?;
        let input = terms
            .input()
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok((
            Action {
                chain_seq,
                prev,
                sig,
            },
            link(&input),
        ))
    }

    /// Where to dial when the connection is lost.
    ///
    /// Separate from [`new`](Self::new) so that the four test files and the
    /// one caller that build a `Chat` are unaffected, and because it is a real
    /// choice: without it there is no reconnection at all, which is what this
    /// client did until now — one `connect_as` at startup, and a dropped QUIC
    /// connection meant every request afterwards failed forever.
    pub fn dials(&mut self, addr: SocketAddr, server_pub: [u8; 32]) {
        self.endpoint = Some((addr, server_pub));
    }

    /// Whether the exchange is reachable, as far as anything has been able to
    /// tell.
    pub fn link(&self) -> Link {
        self.link
    }

    /// Whether requests should be refused without trying.
    ///
    /// Only once there is somewhere to dial: otherwise a single dropped packet
    /// would put a `Chat` into a state nothing could get it out of.
    fn offline(&self) -> bool {
        self.endpoint.is_some() && self.link != Link::Up
    }

    /// Note that something got through.
    fn up(&mut self) {
        self.link = Link::Up;
        self.attempts = 0;
    }

    /// Note that the connection failed, and decide when to try again.
    fn down(&mut self) {
        let wait = BACKOFF_MS[self.attempts.min(BACKOFF_MS.len() - 1)];
        self.attempts += 1;
        self.next_dial = Instant::now() + Duration::from_millis(jittered(wait));
        self.link = if self.attempts >= BACKOFF_MS.len() {
            Link::Gone
        } else {
            Link::Retrying
        };
    }

    /// Try again now, whatever the backoff had planned.
    ///
    /// What `/reconnect` is for: `Gone` should have an answer that is not
    /// "restart the client".
    pub fn reconnect_now(&mut self) {
        self.dialing = None;
        self.attempts = 0;
        self.next_dial = Instant::now();
        if self.link == Link::Up {
            self.link = Link::Retrying;
        }
    }

    /// Advance the reconnection, if there is one to advance.
    ///
    /// Called once per tick of whatever loop owns this. Cheap and immediate
    /// when the link is up or there is nowhere to dial; otherwise it spends at
    /// most [`DIAL_SLICE`] on a handshake and comes back, keeping whatever
    /// progress it made for the next tick.
    ///
    /// A reconnect replays nothing. SIP-3 puts the identity in the Initial and
    /// every command carries its own signature, so a fresh connection is the
    /// whole of what is needed — there is no session to restore.
    pub async fn keep_alive(&mut self) {
        if self.link == Link::Up {
            return;
        }
        let Some((addr, server_pub)) = self.endpoint else {
            return;
        };
        if self.dialing.is_none() {
            if Instant::now() < self.next_dial {
                return;
            }
            let seed = self.seed;
            self.dialing = Some(Box::pin(async move {
                Client::connect_as(addr, &server_pub, &seed).await
            }));
        }
        let dial = self.dialing.as_mut().expect("just set");
        match tokio::time::timeout(DIAL_SLICE, dial).await {
            // Still handshaking. The future is kept, so the next tick carries
            // on rather than starting over.
            Err(_) => {}
            Ok(Ok(client)) => {
                self.dialing = None;
                self.client = client;
                // The old subscription belonged to the old connection. Dropping
                // it here rather than letting it error out is what makes
                // `subscribed()` mean "there is a stream on *this* connection".
                self.events = None;
                self.up();
            }
            Ok(Err(_)) => {
                self.dialing = None;
                self.down();
            }
        }
    }

    /// Whether a SIP-30 event stream is open.
    ///
    /// False after every reconnect, which is the signal to resubscribe.
    pub fn subscribed(&self) -> bool {
        self.events.is_some()
    }

    /// Open an event stream, if there is not one already.
    ///
    /// **A caller must reconcile after this returns, not before.** The exchange
    /// has the subscription registered by the time this comes back, so anything
    /// that changes during the reconcile is queued and delivered afterwards. A
    /// client that read first and subscribed second would lose every change
    /// that landed in between, and nothing at either end would report it.
    ///
    /// Returns whether a new stream was opened, so a caller can tell "already
    /// subscribed" from "just subscribed, go and reconcile".
    pub async fn subscribe(&mut self) -> Result<bool> {
        if self.events.is_some() {
            return Ok(false);
        }
        if self.offline() {
            return Err(ChatError::Transport("the exchange is unreachable".into()));
        }
        match crate::events::Stream::open(&self.client).await {
            Ok(stream) => {
                self.events = Some(stream);
                self.up();
                Ok(true)
            }
            // A refusal came *from* the exchange, so the connection is fine and
            // must not be put into backoff. There is nothing to retry quickly
            // either: a client holding too many streams will still hold too
            // many a second later.
            Err(crate::events::Refusal::Status(code, said)) => {
                Err(classify("/events", code, &said))
            }
            Err(crate::events::Refusal::Transport(e)) => {
                self.down();
                Err(ChatError::Transport(e))
            }
        }
    }

    /// Everything the exchange has pushed since this was last called.
    ///
    /// Never waits. A stream that has ended, or that has gone quiet for longer
    /// than its heartbeat allows, is dropped here — so the next
    /// [`subscribed`](Self::subscribed) reports false and the caller
    /// resubscribes and reconciles.
    pub fn take_events(&mut self) -> Vec<sqex_proto::events::Event> {
        let Some(stream) = self.events.as_mut() else {
            return Vec::new();
        };
        let drained = stream.drain();
        if drained.ended || stream.stale() {
            self.events = None;
        }
        drained.events
    }

    /// This client's own key, as against the account it acts for.
    pub fn device(&self) -> PubKey {
        self.device
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// One request, with the exchange's refusals turned into something a
    /// person can act on. `pub(crate)` so the blob module shares exactly this
    /// handling rather than growing a second, laxer copy of it.
    pub(crate) async fn post_raw(&mut self, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        self.post_within(path, body, BLOB_PATIENCE).await
    }

    async fn post(&mut self, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        self.post_within(path, body, PATIENCE).await
    }

    async fn post_within(
        &mut self,
        path: &str,
        body: Vec<u8>,
        patience: Duration,
    ) -> Result<Vec<u8>> {
        // Nothing is attempted while the link is down. The poll loop asks
        // about every conversation every 700 ms, so writing each of those into
        // a connection known to be dead costs a round of errors a second and
        // tells nobody anything the light does not already say.
        if self.offline() {
            return Err(ChatError::Transport(
                "not connected to the exchange".to_string(),
            ));
        }
        let sent = match tokio::time::timeout(patience, self.client.post(path, body)).await {
            Ok(sent) => sent,
            // Silence is a failure, and has to be treated as one here rather
            // than waited out: a connection whose far end has gone reports
            // nothing at all until QUIC's idle timer expires.
            Err(_) => {
                self.down();
                return Err(ChatError::Transport(format!(
                    "the exchange stopped answering ({}s)",
                    patience.as_secs()
                )));
            }
        };
        let (code, body) = match sent {
            Ok(got) => {
                // Any answer at all proves the connection: a refusal is as
                // good as a success for this purpose, and better evidence than
                // a success at a route that happens to be cached.
                self.up();
                got
            }
            Err(e) => {
                self.down();
                return Err(ChatError::Transport(e));
            }
        };
        if code != 200 {
            return Err(classify(path, code, &body));
        }
        Ok(body)
    }

    // ---- prekeys --------------------------------------------------------

    /// Publish prekeys if the pool is low, and make sure a fallback exists.
    ///
    /// SIP-23 asks a device to keep `POOL` published and top up below
    /// `LOW_WATER`. Called on startup, and again whenever we spend one.
    pub async fn top_up_prekeys(&mut self) -> Result<()> {
        let mut pool = self.store.pool(&self.seed)?;
        if pool.one_time_left() == 0 && pool.fallback_id() == 0 {
            pool = self.restart_pool(pool).await?;
        }
        // What the **exchange** holds, not what we remember publishing. They
        // can differ, and the difference is invisible from here: an exchange
        // restored from a backup, or one that lost its pool, leaves a client
        // whose own count looks healthy with nothing published and no reason to
        // notice. The failure that produces is silent and total — every seal to
        // this device is refused, so no channel key reaches it.
        //
        // Our own count still matters and is not redundant: a secret we no
        // longer hold is useless however many the exchange is serving, so the
        // pool is topped up to satisfy whichever of the two is short.
        let served = match self.post("/prekey/count", vec![TYPE_COUNT]).await {
            Ok(body) => Counts::decode(&body)
                .map(|c| c.one_time)
                .unwrap_or(pool.one_time_left()),
            Err(_) => pool.one_time_left(),
        };
        let have = pool.one_time_left().min(served);

        let mut publish = Vec::new();
        if have < LOW_WATER {
            publish.extend(pool.mint_one_time(POOL - have));
        }
        // A fallback after every batch, not only the first: its id is the only
        // thing `Count` reports, so it is what a future client with a lost
        // store will have to start above.
        if pool.fallback_id() == 0 || !publish.is_empty() {
            publish.push(pool.mint_fallback());
        }
        if publish.is_empty() {
            return Ok(());
        }
        // Persist before publishing. The other order loses the secret for a
        // prekey the exchange is already handing out, which is an envelope
        // nobody can open.
        self.store.save_pool(&pool)?;
        for batch in publish.chunks(sqex_proto::prekey::MAX_PUBLISH) {
            self.post(
                "/prekey/publish",
                Publish {
                    prekeys: batch.to_vec(),
                }
                .encode(),
            )
            .await?;
        }
        Ok(())
    }

    /// Discard whatever the exchange still holds for us, and resume above it.
    ///
    /// An empty pool is a new client or a client whose store was lost, and the
    /// two are indistinguishable from here — but not from the exchange, which
    /// remembers every id this device published and refuses each one forever,
    /// and which is still serving prekeys whose secrets went with the store.
    /// Both halves of that are SIP-23's `Clear`: it discards the prekeys, so a
    /// peer gets `found: 0` and declines to seal rather than sealing to
    /// something that will never open, and it answers with `next_id`, which is
    /// the only way a client whose own record is gone can publish again.
    ///
    /// A brand-new device clears nothing and gets `next_id` 1, so this is one
    /// request on first run rather than a special case to detect.
    async fn restart_pool(&mut self, pool: Pool) -> Result<Pool> {
        let mut state = pool.save();
        match self.post("/prekey/clear", vec![TYPE_CLEAR]).await {
            Ok(body) => {
                let cleared =
                    Cleared::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
                state.next_id = state.next_id.max(cleared.next_id);
            }
            // An exchange without `Clear` predates the amendment. Fall back to
            // what `Count` can say — the current fallback's id is a lower bound
            // on what has been used — and to the clock floor beneath it. The
            // stale prekeys stay, so sending may fail until they drain; that is
            // the state this amendment exists to fix and it is not a reason to
            // refuse to start.
            Err(ChatError::Refused(..)) | Err(ChatError::NoChatHere(_)) => {
                let body = self.post("/prekey/count", vec![TYPE_COUNT]).await?;
                let counts =
                    Counts::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
                state.next_id = state.next_id.max(counts.fallback_id.saturating_add(1));
            }
            Err(e) => return Err(e),
        }
        Ok(Pool::load(&self.seed, state))
    }

    /// Ask for a prekey for `them`, and check it ourselves.
    async fn take_prekey_for(&mut self, them: PubKey) -> Result<Prekey> {
        let body = self
            .post("/prekey/take", Take { device: them }.encode())
            .await?;
        let taken = Taken::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if !taken.found {
            // SIP-23 is deliberate about this: there is no static-only path, so
            // refusing to seal is the correct behaviour and it is visible.
            return Err(ChatError::NotReady(them));
        }
        let p = taken
            .prekey
            .ok_or_else(|| ChatError::Protocol("a found prekey with no prekey in it".into()))?;
        // The exchange is the party this signature exists to constrain, so
        // trusting its check would be verifying nothing.
        p.verify(&them)
            .map_err(|e| ChatError::Protocol(format!("prekey for {them} does not verify: {e}")))?;
        Ok(p)
    }

    /// The channels this account is in, as the exchange sees them.
    ///
    /// The only way to learn about a channel nobody told us about. For direct
    /// messages it is a cross-check rather than a discovery — the identifier
    /// derives from the two accounts — but it is what finds a conversation
    /// somebody started with us while this client had never heard of them.
    pub async fn mine(&mut self) -> Result<Vec<Membership>> {
        let mut all = Vec::new();
        let mut offset = 0u32;
        loop {
            let body = self.post("/channel/mine", Mine { offset }.encode()).await?;
            let page = Mines::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
            let got = page.channels.len();
            all.extend(page.channels);
            // The total can move under paging as memberships change; stopping
            // on a short page rather than on the count avoids looping forever
            // if it grows while we read.
            if got < MAX_MINE || all.len() as u32 >= page.total {
                break;
            }
            offset += got as u32;
        }
        Ok(all)
    }

    // ---- opening a conversation -----------------------------------------

    /// The channel two accounts share. Derived, not asked for.
    pub fn dm_with(&self, them: &PubKey) -> [u8; 32] {
        direct_message_id(&self.me, them)
    }

    /// Make sure the direct message with `them` exists and we hold its key.
    ///
    /// Idempotent: `Create` against a channel we are already in answers without
    /// changing anything, so this is also the ordinary way to reopen one.
    pub async fn open_dm(&mut self, them: &PubKey) -> Result<[u8; 32]> {
        let channel = self.dm_with(them);
        self.create_signed(Create {
            channel,
            // Both are filled in by `create_signed`, which proposes the
            // incarnation and signs one action per invitee against it.
            instance: [0u8; 32],
            actions: Vec::new(),
            visibility: Visibility::Private,
            retention_secs: RETENTION_SECS,
            max_entries: 0,
            // A private channel's name is carried sealed (SIP-19); at the
            // exchange it must be empty, because a membership graph plus a
            // name says far more than the graph.
            name: String::new(),
            topic: String::new(),
            invites: vec![Invitee {
                account: *them,
                role: Role::Admin,
            }],
        })
        .await?;

        self.collect_keys(&channel).await?;
        Ok(channel)
    }

    /// Make sure the channel has an epoch and that we hold its key.
    ///
    /// Separate from `open_dm`, and it has to be. A direct message can be
    /// opened with somebody who has never run a client: they become a member
    /// immediately, but SIP-23 forbids sealing a key to a device that has
    /// published no prekeys, so there is nothing to mint *to* yet. That is a
    /// conversation waiting to start, not a failure to open one, and the
    /// difference is what a person sees on the screen.
    pub async fn ensure_epoch(&mut self, channel: &[u8; 32]) -> Result<u32> {
        let info = self.info(channel).await?;
        // A public channel has no epoch and never gains one. Everything in it
        // is stored in the clear, because anybody may join and would therefore
        // hold any key it used — SIP-16 says so plainly, and encrypting anyway
        // would produce something that looks end-to-end and is not.
        if info.visibility == Visibility::Public {
            return Ok(0);
        }
        // The exchange's epoch going *backwards* is the other face of SIP-16's
        // reset sequence space, and the only one a writer sees. `poll` catches
        // the reader who is ahead of the log; somebody whose cursor happens to
        // sit below the new channel's newest entry never trips that rule, and
        // for a direct message — whose identifier is derived from the two
        // accounts — the destroyed channel and its successor have the same
        // name. So this client would carry a key from a channel that no longer
        // exists into a new one, and `put_key` will not overwrite an epoch key
        // (rightly: replacing one loses everything sealed under it). The result
        // is a message sealed under a key nobody else has, accepted by the
        // exchange and openable by no one.
        if info.epoch < self.store.highest_epoch(channel)? {
            self.store.reset_sequence_space(channel)?;
        }
        if info.epoch == 0 {
            let to = self.devices_of(&members_of(&info)).await?;
            self.mint_epoch(channel, 1, &to).await?;
            return Ok(self.info(channel).await?.epoch);
        }
        if self.store.key(channel, info.epoch)?.is_none() {
            self.collect_keys(channel).await?;
            if self.store.key(channel, info.epoch)?.is_none() {
                // No key for the epoch in force. Either nobody sealed one to
                // us, or we lost the store that held it — and the envelope
                // will not open again, because the prekey it was sealed
                // against is spent.
                //
                // Minting the next epoch is the way out that SIP-17 already
                // provides, and it is an **admin's** move. In a direct message
                // both parties are admins so it always applies; in a group, a
                // member who was simply never given the key would be seizing an
                // epoch they were deliberately left out of, so a member without
                // the role is told plainly instead.
                if !is_admin(&info, &self.me) {
                    return Err(ChatError::NoKey(info.epoch));
                }
                let to = self.devices_of(&members_of(&info)).await?;
                self.mint_epoch(channel, info.epoch + 1, &to).await?;
                let after = self.info(channel).await?.epoch;
                return self
                    .store
                    .key(channel, after)?
                    .map(|_| after)
                    .ok_or(ChatError::NoKey(after));
            }
        }
        Ok(info.epoch)
    }

    /// Mint an epoch key and seal it to every member.
    ///
    /// Including ourselves: our own other devices need it, and the exchange
    /// keeps the envelope for collection rather than for storage.
    ///
    /// A member who has published no prekeys is **skipped rather than fatal**.
    /// SIP-17 says a rotation must not be blocked by one member being
    /// unreachable — a security mechanism able to prevent a revocation is a
    /// poor trade — and SIP-23 says a device that has published nothing cannot
    /// be sealed to at all. They heal it themselves by publishing prekeys and
    /// collecting, which is why `Missing` exists. The one case where being
    /// unreachable *is* fatal is a two-party conversation, where skipping the
    /// other party leaves nobody to talk to.
    async fn mint_epoch(
        &mut self,
        channel: &[u8; 32],
        epoch: u32,
        members: &[PubKey],
    ) -> Result<()> {
        let key = ChannelKey::generate();
        // The incarnation this epoch belongs to: SIP-32 binds it into every
        // publication signature, so an envelope cannot lift into another
        // incarnation of a channel whose identifier is derived.
        let instance = self.info(channel).await?.instance;
        let mut envelopes = Vec::new();
        let mut skipped = Vec::new();
        for who in members {
            match self.take_prekey_for(*who).await {
                Ok(p) => envelopes.push(sign_envelope(
                    &self.seed,
                    &self.exchange,
                    &instance,
                    channel,
                    epoch,
                    seal_envelope(who, p.id, &p.public, epoch, &[key])
                        .map_err(|e| ChatError::Protocol(e.to_string()))?,
                )),
                Err(ChatError::NotReady(w)) if members.len() > 2 => skipped.push(w),
                Err(e) => return Err(e),
            }
        }
        if envelopes.is_empty() {
            return Err(ChatError::NotReady(
                skipped.first().copied().unwrap_or(self.me),
            ));
        }
        // A put that advances the epoch writes a `rotated` system entry, so it
        // signs for it. A same-epoch put writes none and carries no action —
        // which is why who published which envelope stays a transport
        // observation, and SIP-31 names that as its nearest residual gap.
        let info = self.info(channel).await?;
        let rotating = epoch > info.epoch;
        let signed = if rotating {
            Some(self.sign_action_at(
                channel,
                &info,
                EVENT_ROTATED,
                &self.me,
                &epoch.to_be_bytes(),
            )?)
        } else {
            None
        };
        let body = self
            .post(
                "/channel/key/put",
                KeyPut {
                    channel: *channel,
                    epoch,
                    envelopes,
                    action: signed.as_ref().map(|(a, _)| *a),
                }
                .encode(),
            )
            .await?;
        let ack = PutAck::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if ack.accepted {
            if let Some((a, head)) = signed {
                self.store.set_chain(channel, a.chain_seq, &head)?;
            }
            self.store.put_key(channel, epoch, &key)?;
        } else {
            // Somebody else minted the same epoch first. One `Put` wins and the
            // loser collects instead — this is the creation race settling, not
            // an error, and in a direct message it is the ordinary outcome of
            // both ends starting at once.
            self.collect_keys(channel).await?;
        }
        // We spent one prekey per member getting here, our own included.
        self.top_up_prekeys().await?;
        Ok(())
    }

    /// Collect any epoch keys waiting for us and store them.
    ///
    /// The envelope is a one-shot: opening it spends the prekey it was sealed
    /// against, so what is written here is the only copy that will exist
    /// tomorrow.
    pub async fn collect_keys(&mut self, channel: &[u8; 32]) -> Result<usize> {
        // The incarnation these envelopes must have been published to.
        let instance = self.info(channel).await?.instance;
        let since = self.store.highest_epoch(channel)?;
        let body = self
            .post(
                "/channel/key/get",
                KeyGet {
                    channel: *channel,
                    since_epoch: since,
                }
                .encode(),
            )
            .await?;
        let got = Got::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if got.envelopes.is_empty() {
            return Ok(0);
        }

        let mut pool = self.store.pool(&self.seed)?;
        let mut opened = 0;
        let mut unattested = 0usize;
        for env in &got.envelopes {
            if self.store.key(channel, env.from_epoch)?.is_some() {
                continue;
            }
            let secret = match pool.take(env.prekey_id) {
                Ok(s) => s,
                // A spent prekey here is the exchange serving one twice, or a
                // replay. Either way it is not openable and not fatal: the
                // other epochs in this batch may still be good.
                Err(_) => continue,
            };
            // SIP-32: who put this here. An envelope whose signature does not
            // verify is one somebody other than its claimed publisher supplied,
            // and a channel key is not a thing to accept from an unknown hand.
            // Recorded rather than merely skipped, because a member being
            // handed a key by nobody in particular is worth knowing about.
            // `Got` omits the recipient — it only ever answers one — so the
            // signature is checked against *us*, which is who the exchange
            // served it to. Verifying the zeroes it arrived with would fail on
            // every honest envelope.
            let addressed = Envelope {
                recipient: self.device,
                ..env.clone()
            };
            if !verify_envelope(
                &self.exchange,
                &instance,
                channel,
                env.from_epoch,
                &addressed,
            ) {
                unattested += 1;
                continue;
            }
            let keys = match open_envelope(&self.seed, &secret, env) {
                Ok(k) => k,
                Err(_) => continue,
            };
            for (i, k) in keys.into_iter().enumerate() {
                self.store.put_key(channel, env.from_epoch + i as u32, &k)?;
                opened += 1;
            }
        }
        // Counted rather than logged: this crate has no logger, and a caller
        // that wants to say something has the number.
        let _ = unattested;
        // Deleting is the mechanism, and it only counts once it is durable.
        self.store.save_pool(&pool)?;
        if opened > 0 {
            // Entries under these epochs were held and unreadable; now they are
            // not. Nothing else would ever revisit them.
            self.store.rewind(channel)?;
        }
        if opened > 0 {
            self.top_up_prekeys().await?;
        }
        Ok(opened)
    }

    /// Rebuild a conversation from what this client kept.
    ///
    /// Needs no network and must not: the entries are still on the exchange but
    /// they will not open a second time, so this store is the only place the
    /// conversation exists. `admins` is what `Timeline` needs to judge a
    /// redaction or a metadata change, and it is remembered from the last poll
    /// so that a client starting offline still folds correctly.
    pub fn history(&self, channel: &[u8; 32], admins: &[PubKey]) -> Result<Timeline> {
        let mut timeline = Timeline::new();
        let held = self.store.messages(channel)?;
        let mut with_body: Vec<u64> = Vec::new();
        for (seq, account, posted, kind, plain) in held {
            if plain.as_ref().is_some_and(|p| !p.is_empty()) {
                with_body.push(seq);
            }
            timeline.apply(
                &Received {
                    seq,
                    account,
                    posted,
                    kind,
                    // What this client verified when the entry arrived. The
                    // store keeps no signatures, so nothing can be re-checked
                    // here — which is only honest because `poll` refuses to
                    // write an entry that failed.
                    verdict: Verdict::Valid,
                    // Nor can a receipt be re-checked from the store, and
                    // unlike the verdict this one is not safely defaulted to
                    // the good case: a rebuilt timeline has no receipt in front
                    // of it, and *unclaimed* is exactly what that is.
                    tombstone: plain.as_ref().is_some_and(|p| p.is_empty()),
                    standing: Standing::Unclaimed,
                    body: plain.and_then(|p| Body::decode(&p).ok().flatten()),
                },
                admins,
            );
        }

        // Anything the fold says was deleted, and whose words are still here.
        //
        // The poll path clears a body as the redaction arrives, but that only
        // helps from now on: a message deleted before this client learned to
        // do it kept its plaintext, and would have kept it for good. Folding
        // is where we find out which those are, and it happens once per
        // channel at startup rather than on every poll.
        for seq in with_body {
            if timeline.get(seq).is_some_and(|m| m.redacted) {
                self.store.redact_message(channel, seq)?;
            }
        }
        Ok(timeline)
    }

    // ---- devices (SIP-20 and SIP-22) ------------------------------------

    /// The devices this account has registered, and when each expires.
    pub async fn my_devices(&mut self) -> Result<Vec<Device>> {
        let body = self
            .post("/device/list", ListDevices { account: self.me }.encode())
            .await?;
        Ok(Devices::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .devices)
    }

    /// Sign a credential naming `device`, so that device may act for us.
    ///
    /// The credential is **portable and self-contained**: anybody holding the
    /// account key can verify it with no record of the grant, which is what
    /// lets a device present it to an exchange that has never heard of it. That
    /// is also why it cannot be withdrawn — revocation is SIP-22's half, and it
    /// lives at the exchange because a signature cannot un-sign itself.
    pub fn issue_credential(&self, device: &PubKey, lifetime: u64) -> Result<Credential> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Credential::issue(&self.seed, device, SCOPE_CHAT, now, now + lifetime)
            .map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Register ourselves as a device of the account that signed `credential`.
    ///
    /// Called by the **new** device, on its own connection: the credential's
    /// delegate must equal the caller's transport identity, so a credential
    /// somebody found is a credential they cannot use.
    pub async fn register_self(&mut self, credential: &Credential) -> Result<()> {
        self.post(
            "/device/register",
            Register {
                credential: credential.clone(),
            }
            .encode(),
        )
        .await?;
        Ok(())
    }

    /// Hand the epoch in force to our own other devices.
    ///
    /// SIP-17 permits this without an admin — a device may seal to devices of
    /// its own account — and it is how a client linked after a conversation
    /// started gets in without anybody rotating. Rotating instead would be the
    /// wrong tool: it would deny the new device everything said before it, and
    /// disturb every other member to do it.
    ///
    /// One envelope per request, because the exchange refuses a whole batch if
    /// any single recipient already holds one for that epoch — and a sibling
    /// that already has its key is the ordinary case, not a failure.
    pub async fn reseal_to_siblings(&mut self, channel: &[u8; 32]) -> Result<usize> {
        let info = self.info(channel).await?;
        if info.epoch == 0 {
            return Ok(0);
        }
        let key = self
            .store
            .key(channel, info.epoch)?
            .ok_or(ChatError::NoKey(info.epoch))?;

        let mut sealed = 0;
        let mut siblings = 0;
        for device in self.my_devices().await? {
            if device.device == self.device {
                continue;
            }
            siblings += 1;
            let p = match self.take_prekey_for(device.device).await {
                Ok(p) => p,
                // Not yet started, so nothing to seal to. It will collect once
                // it has published, and asking again costs one request.
                Err(ChatError::NotReady(_)) => continue,
                Err(e) => return Err(e),
            };
            let envelope = sign_envelope(
                &self.seed,
                &self.exchange,
                &info.instance,
                channel,
                info.epoch,
                seal_envelope(&device.device, p.id, &p.public, info.epoch, &[key])
                    .map_err(|e| ChatError::Protocol(e.to_string()))?,
            );
            let body = self
                .post(
                    "/channel/key/put",
                    KeyPut {
                        channel: *channel,
                        epoch: info.epoch,
                        envelopes: vec![envelope],
                        // The current epoch: this adds an envelope and rotates
                        // nothing, so there is no system entry to sign for.
                        action: None,
                    }
                    .encode(),
                )
                .await?;
            if PutAck::decode(&body)
                .map_err(|e| ChatError::Protocol(e.to_string()))?
                .accepted
            {
                sealed += 1;
            }
        }
        self.top_up_prekeys().await?;
        if siblings > 0 && sealed == 0 {
            // They already hold this epoch, or they have published nothing to
            // seal against. Either is ordinary, and saying nothing at all is
            // how the one operation a linked device depends on fails invisibly.
            // One envelope per recipient per epoch, and the exchange will not
            // replace it — so a sibling that already has one either holds the
            // key or lost the secret that opened it, and from here those look
            // identical. Naming the remedy beats reporting a non-event.
            return Err(ChatError::Protocol(format!(
                "{siblings} other device(s) already hold an envelope for epoch {}; \
                 if one of them still cannot read this, /rotate",
                info.epoch
            )));
        }
        Ok(sealed)
    }

    /// Whether this client still acts for the account it was linked to.
    ///
    /// `None` when it was never linked — an account with no registered devices
    /// is its own device, and there is nothing to check. `Some(false)` means it
    /// has been revoked, which is otherwise learned only by being refused as a
    /// stranger to every conversation it can see.
    pub async fn still_linked(&mut self) -> Result<Option<bool>> {
        if self.me == self.device {
            return Ok(None);
        }
        let devices = self.my_devices().await?;
        Ok(Some(devices.iter().any(|d| d.device == self.device)))
    }

    /// Which devices in this channel hold no key for the epoch in force.
    ///
    /// SIP-17 says to check after inviting somebody and after any device
    /// registers, because those are the two moments that create a member who
    /// can fetch entries and open none of them — a state nothing else reports.
    pub async fn stranded(&mut self, channel: &[u8; 32]) -> Result<Absent> {
        let body = self
            .post(
                "/channel/key/missing",
                ByChannel { channel: *channel }.encode(TYPE_MISSING),
            )
            .await?;
        Absent::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Withdraw a device, **attested** — the account's signed withdrawal.
    ///
    /// What a portable credential structurally cannot do. Note what it does
    /// *not* undo: SIP-17 is explicit that a revoked device keeps every key it
    /// was ever given, so this bounds what happens next rather than reaching
    /// back. Rotating is what actually cuts them off from what follows.
    ///
    /// SIP-32 makes the withdrawal an artifact rather than a request, so it is
    /// verifiable by anybody holding the account key and cannot be quietly
    /// dropped by whoever repeats the registry. Only a client acting as the
    /// account itself can produce one — which is the case somebody who has lost
    /// a device is in, and the recovery SIP-22 names.
    pub async fn revoke_device(&mut self, device: &PubKey) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let revocation = Revocation::issue(&self.seed, device, now);
        self.post(
            "/device/revoke",
            Revoke {
                device: *device,
                revocation: Some(revocation),
            }
            .encode(),
        )
        .await?;
        Ok(())
    }

    /// Sign this client out, **locally**.
    ///
    /// A device holds no account key, so this produces no artifact anybody can
    /// repeat: the exchange records it on its own authority, under SIP-22's
    /// seniority rule. That is the right shape for signing out a client you
    /// still hold, and the wrong one for a device you have lost — use
    /// [`Chat::revoke_device`] with the account for that.
    pub async fn sign_out_device(&mut self, device: &PubKey) -> Result<()> {
        self.post(
            "/device/revoke",
            Revoke {
                device: *device,
                revocation: None,
            }
            .encode(),
        )
        .await?;
        Ok(())
    }

    // ---- groups ---------------------------------------------------------

    /// Create a private group and invite its first members.
    ///
    /// The identifier is random, not derived: a group has no two accounts to
    /// derive from, which is exactly why it cannot be found without SIP-16's
    /// `Mine` and why that amendment exists. The name is **not** given to the
    /// exchange — a private channel's name is stored empty there, because a
    /// membership graph plus a name says considerably more than the graph — so
    /// it is posted as a sealed metadata entry once the epoch exists.
    pub async fn create_group(&mut self, name: &str, invite: &[PubKey]) -> Result<[u8; 32]> {
        let mut channel = [0u8; 32];
        {
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut channel);
        }
        self.create_signed(Create {
            channel,
            // Both are filled in by `create_signed`, which proposes the
            // incarnation and signs one action per invitee against it.
            instance: [0u8; 32],
            actions: Vec::new(),
            visibility: Visibility::Private,
            retention_secs: RETENTION_SECS,
            max_entries: 0,
            name: String::new(),
            topic: String::new(),
            invites: invite
                .iter()
                .map(|a| Invitee {
                    account: *a,
                    role: Role::Member,
                })
                .collect(),
        })
        .await?;
        self.ensure_epoch(&channel).await?;
        if !name.is_empty() {
            self.set_name(&channel, name).await?;
        }
        Ok(channel)
    }

    /// Make a public channel: anybody may find it and anybody may join.
    ///
    /// Its name and topic go to the exchange **in the clear**, which is the
    /// point — the directory is how somebody finds a room they were never told
    /// about. A private channel's name is sealed precisely because it has a
    /// membership graph beside it; a public one has nothing to protect.
    pub async fn create_public(&mut self, name: &str, topic: &str) -> Result<[u8; 32]> {
        let mut channel = [0u8; 32];
        {
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut channel);
        }
        self.create_signed(Create {
            channel,
            // Both are filled in by `create_signed`, which proposes the
            // incarnation and signs one action per invitee against it.
            instance: [0u8; 32],
            actions: Vec::new(),
            visibility: Visibility::Public,
            retention_secs: RETENTION_SECS,
            max_entries: 0,
            name: name.chars().take(MAX_NAME).collect(),
            topic: topic.chars().take(MAX_TOPIC).collect(),
            invites: Vec::new(),
        })
        .await?;
        Ok(channel)
    }

    /// Search the public directory. An empty query returns everything.
    pub async fn find(&mut self, query: &str, offset: u32) -> Result<Listing> {
        let body = self
            .post(
                "/channel/list",
                List {
                    offset,
                    query: query.to_string(),
                }
                .encode(),
            )
            .await?;
        Listing::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Join a public channel. A private one refuses, which is what stops its
    /// identifier being a way in.
    ///
    /// `instance` comes from the directory record this channel was found in.
    /// It has to: SIP-31 binds it into the signature, and `Info` — the other
    /// place it appears — requires the membership this call is asking for.
    pub async fn join(&mut self, channel: &[u8; 32], instance: [u8; 32]) -> Result<()> {
        // Our own chain state, not the exchange's: we cannot ask, and we are
        // the only party that could be harmed by a lower answer.
        let (chain_seq, prev) = self.store.chain(channel)?;
        let terms = ActionTerms {
            place: Place {
                exchange: self.exchange,
                instance,
                channel: *channel,
            },
            actor: self.me,
            actor_device: self.device,
            event: EVENT_JOINED,
            subject: self.me,
            arg: &[],
            chain_seq,
            prev,
        };
        let sig =
            sign_action(&self.seed, &terms).map_err(|e| ChatError::Protocol(e.to_string()))?;
        let head = link(
            &terms
                .input()
                .map_err(|e| ChatError::Protocol(e.to_string()))?,
        );
        self.post(
            "/channel/join",
            ByChannelSigned {
                channel: *channel,
                action: Action {
                    chain_seq,
                    prev,
                    sig,
                },
            }
            .encode(TYPE_JOIN),
        )
        .await?;
        self.store.set_chain(channel, chain_seq, &head)?;
        Ok(())
    }

    /// Name a channel, for everyone who can read it. Leaves the topic alone.
    pub async fn set_name(&mut self, channel: &[u8; 32], name: &str) -> Result<Posted> {
        self.set_metadata(channel, Some(name), None).await
    }

    /// Set a channel's topic, leaving its name alone.
    pub async fn set_topic(&mut self, channel: &[u8; 32], topic: &str) -> Result<Posted> {
        self.set_metadata(channel, None, Some(topic)).await
    }

    /// Give somebody the admin role, or take it back.
    ///
    /// The exchange's invite is what does this: inviting an account that is
    /// already a member updates its role rather than adding it again, and it
    /// deliberately does not consult the invitation quota when it does. Admin
    /// only, and refused in a direct message, where both parties are admins
    /// from the start and there is nobody to promote.
    pub async fn grant(&mut self, channel: &[u8; 32], who: &PubKey, role: Role) -> Result<()> {
        let info = self.info(channel).await?;
        // The role is in the signature: without it a signed promotion could be
        // replayed as a demotion, which is the same request with one byte
        // changed.
        let event = if role == Role::Admin {
            EVENT_PROMOTED
        } else {
            EVENT_DEMOTED
        };
        let (action, head) = self.sign_action_at(channel, &info, event, who, &[role as u8])?;
        self.post(
            "/channel/invite",
            Invite {
                channel: *channel,
                account: *who,
                role,
                action,
            }
            .encode(),
        )
        .await?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        Ok(())
    }

    /// Set a channel's picture, or take it away with `None`.
    pub async fn set_avatar(
        &mut self,
        channel: &[u8; 32],
        avatar: Option<Attachment>,
    ) -> Result<Posted> {
        self.publish_metadata(channel, None, None, Some(avatar))
            .await
    }

    /// Change a channel's name, its topic, or both.
    pub async fn set_metadata(
        &mut self,
        channel: &[u8; 32],
        name: Option<&str>,
        topic: Option<&str>,
    ) -> Result<Posted> {
        self.publish_metadata(channel, name, topic, None).await
    }

    /// Publish a new metadata record, changing only what was asked for.
    ///
    /// A sealed entry rather than a field, so the exchange never learns what a
    /// private channel is called. Only an admin's is honoured by a reader.
    ///
    /// `Body::Metadata` is the whole record and a reader assigns all of it
    /// (`Timeline::apply`), which is correct — it is the sender's job to say
    /// what the record now is. So the fields not being changed are carried over
    /// rather than sent empty. Sending them empty is what made `/name` destroy
    /// a channel's topic with nothing able to restore it.
    ///
    /// `avatar` is an option of an option on purpose: `None` leaves the
    /// picture as it is, and `Some(None)` removes it. Collapsing those would
    /// mean a rename could not help but delete the picture, which is the same
    /// bug in a different field.
    async fn publish_metadata(
        &mut self,
        channel: &[u8; 32],
        name: Option<&str>,
        topic: Option<&str>,
        avatar: Option<Option<Attachment>>,
    ) -> Result<Posted> {
        // The current record comes from the folded history rather than from
        // `info`: for a private channel the exchange holds neither field, and
        // for a public one it holds the values from creation, which a later
        // sealed rename has since replaced.
        let info = self.info(channel).await?;
        let admins: Vec<PubKey> = info
            .members
            .iter()
            .filter(|m| m.role == Role::Admin)
            .map(|m| m.account)
            .collect();

        // Refused here, because nothing downstream will refuse it visibly.
        // A metadata entry from a member is accepted by the exchange — which
        // cannot read it — posted, and then discarded by every reader's fold,
        // which honours only an admin's. Sending it and reporting success was
        // telling somebody a channel had been renamed when nothing had.
        if !is_admin(&info, &self.me) {
            return Err(ChatError::Protocol(format!(
                "only an admin can change this channel's name, topic or picture, \
                 and you are not one here — {}",
                match admins.len() {
                    0 => "and neither is anybody: this channel has no admin".to_string(),
                    1 => format!("ask {}", admins[0]),
                    _ => format!(
                        "ask one of {}",
                        admins
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                }
            )));
        }

        // Catch up before reading the record, not after. `history` folds what
        // is in the store, and a client that has not polled since somebody set
        // the topic holds none of it — so it would publish an empty one and
        // destroy the field it was not asked to touch. That is the same bug
        // this carrying-over was written to fix, one step further back.
        let mut scratch = Timeline::new();
        let _ = self.poll(channel, &mut scratch, 0).await;
        let held = self.history(channel, &admins)?;
        let name = name.unwrap_or(&held.name).to_string();
        let topic = topic.unwrap_or(&held.topic).to_string();
        let posted = self
            .send_body(
                channel,
                Body::Metadata {
                    name: name.clone(),
                    topic: topic.clone(),
                    avatar: avatar.unwrap_or_else(|| held.avatar.clone()),
                },
            )
            .await?;

        // And the directory, for a public channel only.
        //
        // The entry above is what members fold; the directory is what somebody
        // who has never been here searches. Until now only `create` wrote the
        // second, so renaming a public channel changed it for everybody in the
        // room and left it advertised under its old name to everybody outside
        // — two names for one place, and strangers got the stale one.
        //
        // Public only, and the exchange refuses otherwise: a private channel's
        // name is deliberately never given to it, because a membership graph
        // with a name on it says considerably more than the graph.
        if info.visibility == Visibility::Public {
            // SIP-32: this writes a `renamed` event now, so it signs for one.
            // The digest covers the constitution as it will stand — the name and
            // topic being set, over the retention already in force.
            let arg = constitution(
                Visibility::Public,
                info.retention_secs,
                info.max_entries,
                &name,
                &topic,
            );
            let me = self.me;
            let (action, head) = self.sign_action_at(channel, &info, EVENT_RENAMED, &me, &arg)?;
            self.post(
                "/channel/directory",
                sqex_proto::channel::Directory {
                    channel: *channel,
                    name,
                    topic,
                    action,
                }
                .encode(),
            )
            .await?;
            self.store.set_chain(channel, action.chain_seq, &head)?;
        }
        Ok(posted)
    }

    /// Add somebody, and give them the key.
    ///
    /// Inviting does **not** rotate: SIP-17 leaves it to the inviter whether a
    /// new member gets the history, and sealing them the current epoch grants
    /// it. Rotating instead would deny it, which is a different decision and
    /// not one to make silently on somebody's behalf.
    pub async fn invite(&mut self, channel: &[u8; 32], who: &PubKey) -> Result<()> {
        let info = self.info(channel).await?;
        let (action, head) =
            self.sign_action_at(channel, &info, EVENT_ADDED, who, &[Role::Member as u8])?;
        self.post(
            "/channel/invite",
            Invite {
                channel: *channel,
                account: *who,
                role: Role::Member,
                action,
            }
            .encode(),
        )
        .await?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        let key = self
            .store
            .key(channel, info.epoch)?
            .ok_or(ChatError::NoKey(info.epoch))?;
        let mut envelopes = Vec::new();
        for device in self.devices_of(&[*who]).await? {
            let p = self.take_prekey_for(device).await?;
            envelopes.push(sign_envelope(
                &self.seed,
                &self.exchange,
                &info.instance,
                channel,
                info.epoch,
                seal_envelope(&device, p.id, &p.public, info.epoch, &[key])
                    .map_err(|e| ChatError::Protocol(e.to_string()))?,
            ));
        }
        let body = self
            .post(
                "/channel/key/put",
                KeyPut {
                    channel: *channel,
                    epoch: info.epoch,
                    envelopes,
                    // Handing the current key to a new member. No rotation, so
                    // no system entry and nothing to sign for.
                    action: None,
                }
                .encode(),
            )
            .await?;
        let ack = PutAck::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.top_up_prekeys().await?;
        if !ack.accepted {
            // An envelope for this recipient at this epoch already exists, and
            // SIP-17 has the exchange refuse a second — that one-per-recipient
            // rule is what settles the creation race. So a re-invite cannot
            // re-key somebody: if they cannot open the envelope that is already
            // there, the only way to hand them a key is a new epoch.
            return Err(ChatError::AlreadyKeyed(info.epoch));
        }
        Ok(())
    }

    /// Mint the next epoch and seal it to everyone currently in the channel.
    ///
    /// The general remedy an admin has. It is what `remove` does implicitly,
    /// and it is the only way to re-key a member whose envelope for the epoch
    /// in force is one they can no longer open — a lost store, most often.
    /// What was said under the old epoch stays readable to whoever already
    /// holds its key and unreadable to whoever does not; this hands out the
    /// next one, not the last.
    pub async fn rotate(&mut self, channel: &[u8; 32]) -> Result<u32> {
        let info = self.info(channel).await?;
        // Not gated on being an admin here. SIP-17 lets a member rekey after
        // revoking one of its own devices, and the exchange is the party that
        // can check it — it holds both the revocation and the moment the epoch
        // was minted. Refusing locally would make that rule unreachable.
        let _ = is_admin(&info, &self.me);
        let to = self.devices_of(&members_of(&info)).await?;
        self.mint_epoch(channel, info.epoch + 1, &to).await?;
        Ok(self.info(channel).await?.epoch)
    }

    /// Add somebody without giving them the key.
    ///
    /// The exchange permits it and SIP-17 describes the result: a member who
    /// can fetch entries and open none of them. Exposed for tests, because the
    /// distinction between history that is gone and a key that has not arrived
    /// is only worth having if both sides of it are checked.
    #[doc(hidden)]
    pub async fn post_invite_without_key(
        &mut self,
        channel: &[u8; 32],
        who: &PubKey,
    ) -> Result<()> {
        let info = self.info(channel).await?;
        let (action, head) =
            self.sign_action_at(channel, &info, EVENT_ADDED, who, &[Role::Member as u8])?;
        self.post(
            "/channel/invite",
            Invite {
                channel: *channel,
                account: *who,
                role: Role::Member,
                action,
            }
            .encode(),
        )
        .await?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        Ok(())
    }

    /// Remove somebody, and rotate so what follows is not theirs.
    ///
    /// The rotation is the point and it is not optional: the exchange refuses
    /// them further entries, but a removed member keeps every key it was ever
    /// given (SIP-17 says so plainly), so without a new epoch they can still
    /// read everything posted after they left from the exchange's own copy —
    /// or from anyone who forwards it.
    pub async fn remove(&mut self, channel: &[u8; 32], who: &PubKey) -> Result<()> {
        let info = self.info(channel).await?;
        let (action, head) = self.sign_action_at(channel, &info, EVENT_REMOVED, who, &[])?;
        self.post(
            "/channel/remove",
            ByAccount {
                channel: *channel,
                account: *who,
                action,
            }
            .encode(TYPE_REMOVE),
        )
        .await?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        let info = self.info(channel).await?;
        let to = self.devices_of(&members_of(&info)).await?;
        self.mint_epoch(channel, info.epoch + 1, &to).await?;
        Ok(())
    }

    /// SIP-35: authorise, or withdraw, another exchange's right to hold a copy
    /// of this channel.
    ///
    /// **This is publication to another operator, not a setting.** A replica
    /// learns the whole shape of the conversation — who is a member, when each
    /// joined, who posted and when, and how large every message was — and
    /// `unreplicate` ends a subscription rather than recalling a copy. SIP-35
    /// requires an implementation to present it that way, so a caller
    /// surfacing this to a person must say so; there is no undo below this
    /// line, and there cannot be.
    ///
    /// The authorisation is a signed entry, so it lands in the log the members
    /// already read. An arrangement between two operators would have been
    /// simpler and would have made a channel's copies invisible to the people
    /// in it.
    pub async fn replicate(
        &mut self,
        channel: &[u8; 32],
        replica: &PubKey,
        authorise: bool,
    ) -> Result<()> {
        let (event, path, type_byte) = if authorise {
            (EVENT_REPLICATE, "/channel/replicate", TYPE_REPLICATE)
        } else {
            (EVENT_UNREPLICATE, "/channel/unreplicate", TYPE_UNREPLICATE)
        };
        let info = self.info(channel).await?;
        let (action, head) = self.sign_action_at(channel, &info, event, replica, &[])?;
        self.post(
            path,
            ByAccount {
                channel: *channel,
                account: *replica,
                action,
            }
            .encode(type_byte),
        )
        .await?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        Ok(())
    }

    /// Leave a channel.
    pub async fn leave(&mut self, channel: &[u8; 32]) -> Result<()> {
        let info = self.info(channel).await?;
        let me = self.me;
        let (action, head) = self.sign_action_at(channel, &info, EVENT_LEFT, &me, &[])?;
        self.post(
            "/channel/leave",
            ByChannelSigned {
                channel: *channel,
                action,
            }
            .encode(TYPE_LEAVE),
        )
        .await?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        Ok(())
    }

    // ---- talking --------------------------------------------------------

    pub async fn info(&mut self, channel: &[u8; 32]) -> Result<ChannelInfo> {
        let body = self
            .post(
                "/channel/info",
                ByChannel { channel: *channel }.encode(TYPE_INFO),
            )
            .await?;
        ChannelInfo::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Seal a message and post it.
    ///
    /// Minting on demand is how most first messages go, so this may distribute
    /// a key before it posts anything.
    pub async fn send(&mut self, channel: &[u8; 32], text: &str) -> Result<Posted> {
        self.send_post(channel, SipPost::text(text)).await
    }

    /// Delete a message: remove its bytes at the exchange, and tell other
    /// clients to show it as deleted.
    ///
    /// SIP-16 requires both halves. `/channel/redact` removes the body and
    /// leaves the entry as a tombstone, so a reader can see that something was
    /// deleted rather than find a conversation that silently does not follow.
    /// The SIP-19 body is what other clients render. Issuing only the SIP-19
    /// body would leave the words sitting at the exchange for anyone who joined
    /// later with history access, which is the mistake worth not making.
    ///
    /// The exchange call goes first: if the second half fails, the words are
    /// already gone, which is the direction to fail in.
    ///
    /// The caller must be the account that posted `target`, or an admin here.
    /// The exchange decides that — it is why this is an operation there and not
    /// only a message.
    ///
    /// # The files go too
    ///
    /// SIP-18: "deleting a message must delete what it carried". The exchange
    /// cannot do this half — the references live inside a sealed body it cannot
    /// read — so the client that is deleting the message detaches them, and it
    /// is the only party that can, because it is the only one that can read
    /// what it is deleting. Without this a reader who already saw the message
    /// keeps the blob id and can still fetch the file afterwards.
    pub async fn redact(&mut self, channel: &[u8; 32], target: u64) -> Result<Redacted> {
        // Before anything is destroyed, while the plaintext is still ours to
        // read. An edit replaces a post's parts, so the files this entry has
        // referenced over its life are the union of the original and every edit
        // that named it — detaching only the current set would leave the ones
        // an edit dropped.
        let mut blobs: Vec<[u8; 32]> = Vec::new();
        let mut opened = false;
        for (seq, _, _, _, plain) in self.store.messages(channel)? {
            let Some(bytes) = plain else { continue };
            let Ok(Some(body)) = Body::decode(&bytes) else {
                continue;
            };
            let post = match (&body, seq == target) {
                (Body::Post(p), true) => {
                    opened = true;
                    p
                }
                (Body::Edit { target: t, post }, _) if *t == target => post,
                _ => continue,
            };
            for a in post.attachments() {
                if !blobs.contains(&a.blob) {
                    blobs.push(a.blob);
                }
            }
        }

        let mut left = Vec::new();
        for blob in &blobs {
            // A blob already gone, or attached by somebody else, refuses. That
            // is not a reason to keep the words: report it and carry on, since
            // leaving the body behind is the worse of the two failures.
            if self.detach(channel, blob).await.is_err() {
                left.push(*blob);
            }
        }

        self.post(
            "/channel/redact",
            ByTarget {
                channel: *channel,
                target,
            }
            .encode(TYPE_REDACT),
        )
        .await?;
        self.send_body(channel, Body::Redact { target }).await?;
        // Ours too, and now: the next poll would fetch our own notice back and
        // do it, but "deleted" should not mean "deleted in a moment".
        self.store.redact_message(channel, target)?;
        Ok(Redacted {
            detached: blobs.len() - left.len(),
            left_behind: left,
            // A message we never opened is one whose references we cannot know.
            // Said plainly rather than reported as nothing to do: the two look
            // identical from here and are not the same.
            opened,
        })
    }

    /// Ask an exchange that does not whitelist us to let us in (SIP-24).
    ///
    /// The credential names this very client, signed by this identity, so the
    /// request carries a verifiable account key. `label` does not: it is text
    /// the requester chose, shown to an administrator at the moment of a
    /// security decision, and an interface **MUST** display the key rather
    /// than let the label stand in for it.
    ///
    /// The answer says only that the request was received. It is identical for
    /// every caller, whatever the exchange goes on to decide, so a caller must
    /// not read approval, refusal or delay into it.
    pub async fn request_admission(&mut self, label: &str) -> Result<()> {
        let credential = self.issue_credential(&self.device, ADMISSION_LIFETIME)?;
        let body = self
            .post(
                "/admission/request",
                AdmissionRequest {
                    credential,
                    label: label.to_string(),
                }
                .encode(),
            )
            .await?;
        Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(())
    }

    /// Change how long this channel keeps entries, and how many.
    ///
    /// Admin only, and the exchange prunes immediately — so narrowing a window
    /// is a deletion, not a policy that takes effect later. `max_entries` of 0
    /// means no limit on count.
    pub async fn set_retention(
        &mut self,
        channel: &[u8; 32],
        retention_secs: u32,
        max_entries: u32,
    ) -> Result<()> {
        if !(MIN_RETENTION..=MAX_RETENTION).contains(&retention_secs) {
            return Err(ChatError::Protocol(format!(
                "retention is {MIN_RETENTION} to {MAX_RETENTION} seconds"
            )));
        }
        let info = self.info(channel).await?;
        // The pair travels in the signature. A bare "somebody changed
        // retention" would let a signed request be replayed with different
        // numbers, which is the whole of what this request decides.
        let mut arg = Vec::with_capacity(8);
        arg.extend_from_slice(&retention_secs.to_be_bytes());
        arg.extend_from_slice(&max_entries.to_be_bytes());
        let (action, head) =
            self.sign_action_at(channel, &info, EVENT_RETENTION, &self.me, &arg)?;
        let body = self
            .post(
                "/channel/retain",
                Retain {
                    channel: *channel,
                    retention_secs,
                    max_entries,
                    action,
                }
                .encode(),
            )
            .await?;
        Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        Ok(())
    }

    /// End a channel: entries, envelopes and attachments, all of it.
    ///
    /// Not reversible and no tombstone. The identifier becomes free, and a
    /// create naming it afterwards makes a new and unrelated channel — which
    /// for a direct message, whose identifier is derived from the two accounts,
    /// is exactly how a conversation comes back with its numbering restarted
    /// (SIP-16, "A reset sequence space").
    ///
    /// This is also the only thing that gives the creator's quota back: SIP-16
    /// notes it otherwise "only ever depletes".
    ///
    /// Forgetting it locally is the caller's to do, and deliberately not done
    /// here: a client that dropped its own keys before the exchange confirmed
    /// would have destroyed the conversation twice over if the call failed.
    pub async fn close(&mut self, channel: &[u8; 32]) -> Result<()> {
        let body = self
            .post(
                "/channel/close",
                ByChannel { channel: *channel }.encode(TYPE_CLOSE),
            )
            .await?;
        Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(())
    }

    /// How far everybody else has read.
    ///
    /// This client has published its own cursor with `receipts: true` since it
    /// was written and has never once read anybody else's, so the receipts
    /// went out and nothing came back. An account that opted out of receipts
    /// reports `read: 0` and a real `delivered` — the exchange withholds their
    /// reading, not their existence.
    pub async fn marks(&mut self, channel: &[u8; 32]) -> Result<Vec<Mark>> {
        let body = self
            .post(
                "/channel/cursors",
                ByChannel { channel: *channel }.encode(TYPE_CURSORS),
            )
            .await?;
        Ok(Marks::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .marks)
    }

    /// Publish what this account says about itself (SIP-21).
    ///
    /// Nothing here is attested. A display name is a claim its subject makes,
    /// and so is a title — which is called `title` and not `role` precisely
    /// because `role` already means something the exchange holds and vouches
    /// for. Publishing one does not make it true of anybody.
    pub async fn set_profile(&mut self, profile: Profile) -> Result<()> {
        if profile.name.len() > profile::MAX_NAME {
            return Err(ChatError::Protocol(format!(
                "a display name is at most {} bytes",
                profile::MAX_NAME
            )));
        }
        if profile.title.len() > profile::MAX_TITLE {
            return Err(ChatError::Protocol(format!(
                "a title is at most {} bytes",
                profile::MAX_TITLE
            )));
        }
        let (name, title) = (profile.name.clone(), profile.title.clone());
        // SIP-32: a signed record, ordered by a counter we keep. The serial
        // must climb past whatever the exchange already holds, or the record
        // loses to the one that is there — which is the property that makes an
        // old profile unable to be put back over a new one.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let me = self.me;
        let held = self
            .profile_of(&me)
            .await
            .ok()
            .and_then(|g| g.record.map(|r| r.serial))
            .unwrap_or(0);
        let record = ProfileRecord::sign(&self.seed, &me, held + 1, now, profile);
        let body = self
            .post("/profile/put", ProfilePut { record }.encode())
            .await?;
        Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        // Written through to our own store, because nobody will tell us.
        // Everybody who shares a channel with this account gets a SIP-30
        // profile event and refetches; the publisher is the one account that
        // gets no such event about itself, and reading its own name back out
        // of the cache would have shown the old one until the hour was up.
        // The publisher being the last to know is a silly way to fail.
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.store.put_profile(&self.me, &name, &title, at)?;
        Ok(())
    }

    /// What an account says about itself, if it will say.
    ///
    /// A profile withheld from us and one that was never published answer the
    /// same way, on purpose: the difference would say whether somebody exists.
    /// `Got::found` is that answer, and a caller must not read anything more
    /// into it.
    pub async fn profile_of(&mut self, account: &PubKey) -> Result<GotProfile> {
        let body = self
            .post(
                "/profile/get",
                ProfileByAccount { account: *account }.encode(profile::TYPE_GET),
            )
            .await?;
        GotProfile::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Stop an account reaching us, or let it again.
    ///
    /// The exchange drops what a blocked account sends and answers it exactly
    /// as though it had landed, so blocking is not a signal the blocked party
    /// can read. Nothing here tells them either.
    pub async fn set_block(&mut self, account: &PubKey, add: bool) -> Result<()> {
        let body = self
            .post(
                "/block/set",
                Block {
                    account: *account,
                    add,
                }
                .encode(),
            )
            .await?;
        Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(())
    }

    /// Who we have blocked. Answered to nobody else — a list of who somebody
    /// wants to avoid is more sensitive than the membership it protects them
    /// from — which is why it takes no argument.
    pub async fn blocked(&mut self) -> Result<Vec<PubKey>> {
        let body = self
            .post("/block/list", vec![profile::TYPE_BLOCKED])
            .await?;
        Ok(Blocks::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .accounts)
    }

    /// Fetch the profiles of accounts we do not hold a recent one for.
    ///
    /// Bounded by what has not been asked for lately rather than by what is on
    /// screen: a name is asked for once and then read from the store, because
    /// asking the exchange who everybody is on every poll would turn a display
    /// convenience into a stream of traffic about who this client is reading.
    ///
    /// Failures are silent by design. A name is decoration; a conversation that
    /// stopped working because a name could not be fetched would be the tail
    /// wagging the dog.
    pub async fn refresh_profiles(&mut self, accounts: &[PubKey], now: u64) -> Result<usize> {
        self.fetch_profiles(accounts, now, false).await
    }

    /// The same, ignoring what we already hold.
    ///
    /// For when somebody has *asked* who these people are. Honouring a cache
    /// there is refusing to answer the question that was put.
    pub async fn refetch_profiles(&mut self, accounts: &[PubKey], now: u64) -> Result<usize> {
        self.fetch_profiles(accounts, now, true).await
    }

    async fn fetch_profiles(
        &mut self,
        accounts: &[PubKey],
        now: u64,
        force: bool,
    ) -> Result<usize> {
        let mut asked = 0;
        for account in accounts {
            // Our own included. It was skipped as a pointless round trip —
            // you know what you called yourself — but `/who` lists you among
            // the members, and naming everybody else while showing yourself as
            // a bare key is the one row a reader cannot account for.
            let held = self.store.profile(account)?;
            // Two ages, because the two facts are not equally strong. "They
            // are called X" is worth keeping for an hour — SIP-21 caps updates
            // at 32 an hour, so asking oftener could not learn much. "We asked
            // and were told nothing" is barely a fact at all, and it is the
            // state *everybody* starts in: caching it for an hour meant a
            // freshly published name was invisible to everyone who had ever
            // looked, which is exactly when somebody publishes one and wonders
            // why nothing happened.
            let age = |name: &str| {
                if name.is_empty() {
                    PROFILE_MISS_TTL
                } else {
                    PROFILE_TTL
                }
            };
            if !force && held.is_some_and(|(name, _, at)| now.saturating_sub(at) < age(&name)) {
                continue;
            }
            let got = match self.profile_of(account).await {
                Ok(got) => got,
                Err(_) => continue,
            };
            // A profile withheld from us and one never published answer the
            // same way, and both are stored as empty: we asked, and were told
            // nothing.
            // SIP-32: shown only if the subject signed it. A record that does
            // not verify is somebody else's assertion about this account, and a
            // profile is exactly the field a reader would act on.
            let (name, title) = match got.record.as_ref().filter(|r| r.verify()) {
                Some(r) if got.found => (r.profile.name.clone(), r.profile.title.clone()),
                _ => (String::new(), String::new()),
            };
            self.store.put_profile(account, &name, &title, now)?;
            asked += 1;
        }
        Ok(asked)
    }

    /// The display name we hold for an account, if it published one.
    ///
    /// A caller **MUST NOT** show this on its own. SIP-21: "A client MUST show
    /// the key alongside the name wherever the distinction could matter … and
    /// MUST NOT let a name be the only thing a person sees at those moments."
    /// Two accounts may publish the same name, or names differing by a
    /// homoglyph or a bidirectional override, and only the key tells them
    /// apart.
    pub fn display_name(&self, account: &PubKey) -> Option<String> {
        let (name, _, _) = self.store.profile(account).ok().flatten()?;
        (!name.is_empty()).then_some(name)
    }

    /// The title an account claims. Carries no authority of any kind.
    pub fn title_of(&self, account: &PubKey) -> Option<String> {
        let (_, title, _) = self.store.profile(account).ok().flatten()?;
        (!title.is_empty()).then_some(title)
    }

    /// React to a message, or take a reaction back.
    ///
    /// Keyed on (account, target, emoji) by the fold, so adding one that is
    /// already there changes nothing and removing one that is not is ordinary
    /// rather than an error. That is what lets a client send this without
    /// first knowing what it has already sent.
    ///
    /// A reaction is an ordinary sealed entry: the exchange counts nothing and
    /// learns nothing, and a reader who lacks the key sees neither the message
    /// nor what anyone thought of it.
    pub async fn react(
        &mut self,
        channel: &[u8; 32],
        target: u64,
        emoji: &str,
        add: bool,
    ) -> Result<Posted> {
        // The wire limit is on bytes, and an emoji is several of them, so
        // this is checked the same way rather than in characters — a
        // character-length check would pass something the decoder refuses.
        if emoji.is_empty() || emoji.len() > MAX_EMOJI {
            return Err(ChatError::Protocol(format!(
                "a reaction is 1 to {MAX_EMOJI} bytes, and {:?} is {}",
                emoji,
                emoji.len()
            )));
        }
        self.send_body(
            channel,
            Body::Reaction {
                target,
                add,
                emoji: emoji.to_string(),
            },
        )
        .await
    }

    /// Replace the text of a message already sent.
    ///
    /// A reader honours this only from the account that posted the target and
    /// only within [`EDIT_WINDOW`] of it, and the reader is where that is
    /// enforced — the exchange cannot check either, since it cannot read the
    /// entry. Checking here as well is a courtesy, so that a client tells
    /// somebody their edit will be ignored rather than sending one that
    /// silently is.
    pub async fn edit(&mut self, channel: &[u8; 32], target: u64, post: SipPost) -> Result<Posted> {
        post.validate()
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.send_body(channel, Body::Edit { target, post }).await
    }

    /// Reply to a message: an ordinary post carrying [`Part::Reply`].
    pub async fn reply(&mut self, channel: &[u8; 32], target: u64, text: &str) -> Result<Posted> {
        let mut post = SipPost::text(text);
        post.parts.push(Part::Reply(target));
        self.send_post(channel, post).await
    }

    /// Send a message built by the caller — text, attachments, a reply, or a
    /// combination. `send` is this with one text part.
    pub async fn send_post(&mut self, channel: &[u8; 32], post: SipPost) -> Result<Posted> {
        post.validate()
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.send_body(channel, Body::Post(post)).await
    }

    /// Seal and post any SIP-19 body — a message, an edit, a reaction, or the
    /// channel's own metadata.
    pub async fn send_body(&mut self, channel: &[u8; 32], body: Body) -> Result<Posted> {
        let epoch = self.ensure_epoch(channel).await?;
        let info = self.info(channel).await?;

        // The counter must never repeat under one key. Take the higher of what
        // we remember and what the exchange accepted from us — the exchange
        // keeps it independently of pruning precisely so a client that lost the
        // number can resume without guessing.
        let (_, mine, seen_epoch) = self.store.cursor(channel)?;
        let local = if seen_epoch == epoch { mine } else { 0 };
        let msg_seq = local.max(info.my_msg_seq) + 1;

        let plain = body.encode();
        let sealed = if epoch == 0 {
            // Public: posted as it stands. The counter is still kept, because
            // the exchange orders on it and a reader still sees which device
            // said what — it simply is not a nonce here, since there is no key.
            plain.clone()
        } else {
            self.store
                .key(channel, epoch)?
                .ok_or(ChatError::NoKey(epoch))?
                .seal(channel, epoch, &self.device, msg_seq, &plain)
                .map_err(|e| ChatError::Protocol(e.to_string()))?
        };

        // Recorded before the post, not after. If the answer is lost in flight
        // the entry may still have landed, and burning a counter costs nothing
        // while reusing one costs the confidentiality of two messages.
        self.store.set_msg_seq(channel, epoch, msg_seq)?;

        // SIP-31. Signed over the body **as posted** — ciphertext here, plain
        // in a public channel — so that anybody can check who wrote it without
        // holding a key. The chain position is the greater of what we remember
        // and what the exchange reports, never its report alone.
        let (chain_seq, prev) = self.chain_at(channel, &info)?;
        let terms = EntryTerms {
            place: self.place(channel, &info),
            account: self.me,
            device: self.device,
            epoch,
            msg_seq,
            expires_after: 0,
            chain_seq,
            prev,
            body: &sealed,
        };
        let sig = sign_entry(&self.seed, &terms);
        let head = link(&terms.input());

        // SIP-34. Asked for, because the answer is what tells a poster its entry
        // was numbered rather than accepted and quietly discarded. An exchange
        // that does not offer receipts refuses the type byte, and we ask again
        // plainly — once, and never again on this connection.
        let mut req = Post {
            channel: *channel,
            epoch,
            msg_seq,
            expires_after: 0,
            chain_seq,
            prev,
            sig,
            receipts: self.receipts.load(Ordering::Relaxed),
            body: sealed,
        };
        let out = match self.post("/channel/post", req.encode()).await {
            Ok(out) => out,
            Err(e) if req.receipts && declines_receipts(&e) => {
                self.receipts.store(false, Ordering::Relaxed);
                req.receipts = false;
                self.post("/channel/post", req.encode()).await?
            }
            Err(e) => return Err(e),
        };
        // Only now. A chain position is spent when something is in the log at
        // it, so a refused post leaves the chain where it was — the opposite of
        // the counter above, and for the opposite reason.
        self.store.set_chain(channel, chain_seq, &head)?;
        let posted =
            Posted::decode(&out, req.receipts).map_err(|e| ChatError::Protocol(e.to_string()))?;

        // Keep what we just said, rather than waiting for the exchange to hand
        // it back on the next fetch. Between posting and that fetch the client
        // was the only party that could not see its own message, which is a
        // strange enough thing to be true that something eventually depends on
        // it: redaction reads the message it is deleting to find the files it
        // referenced, and a message sent moments ago is exactly the one a
        // person deletes.
        //
        // Idempotent against the echo — `put_message` conflicts on (channel,
        // seq) and keeps the body it already holds.
        self.store.put_message(
            channel,
            Kept {
                seq: posted.seq,
                account: self.me,
                posted: posted.posted,
                kind: KIND_MEMBER,
                plain: Some(&plain),
            },
        )?;
        Ok(posted)
    }

    /// Say we are typing. Best-effort: a signal nobody stores is not worth an
    /// error path.
    pub async fn typing(&mut self, channel: &[u8; 32], on: bool) {
        use sqex_proto::channel::SignalOut;
        use sqex_proto::message::{SIGNAL_TYPING, Signal};
        let body = Signal::Typing(on).encode();
        // Through `post` like everything else, so that it neither writes into
        // a dead connection nor misses the chance to notice a live one.
        let _ = self
            .post(
                "/channel/signal",
                SignalOut {
                    channel: *channel,
                    kind: SIGNAL_TYPING,
                    body,
                }
                .encode(),
            )
            .await;
    }

    /// Ask an exchange for the proof behind an `equivocated` refusal.
    ///
    /// Checked here, not displayed on trust: `Equivocation::decode` verifies
    /// both signatures, so a client cannot be talked into accusing an exchange
    /// by an exchange that simply said so.
    async fn equivocation(&mut self, channel: &[u8; 32]) -> Result<Equivocation> {
        let body = self
            .post(
                "/channel/equivocation",
                ByChannel { channel: *channel }.encode(TYPE_EQUIVOCATION),
            )
            .await?;
        Equivocation::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// SIP-36: invite this channel to a call, and return where the invitation
    /// landed along with the room secret.
    ///
    /// The secret is minted here, uniformly at random as SIP-13 requires, and
    /// is sealed into the channel with the rest of the body — so it reaches
    /// exactly the members and their devices, and the exchange carries a room
    /// it cannot join.
    ///
    /// `expires_after` is not set from here: `send_body` posts without one, and
    /// SIP-36 asks for a short one on a `Call` because the entry holds a bearer
    /// capability that outlives its usefulness within a minute. Setting it
    /// needs a `send_body` that takes a timer, which is a change to a shared
    /// path; recorded here rather than quietly skipped. It shortens an exposure
    /// and closes nothing — the room lives as long as it lives, and a member
    /// who read the entry keeps the secret.
    pub async fn call(
        &mut self,
        channel: &[u8; 32],
        media: u8,
        ring_secs: u16,
    ) -> Result<(Posted, [u8; 32])> {
        use rand_core::RngCore;
        let mut secret = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut secret);
        let posted = self
            .send_body(
                channel,
                Body::Call {
                    media,
                    ring_secs,
                    secret,
                },
            )
            .await?;
        Ok((posted, secret))
    }

    /// SIP-36: record how a call ended.
    ///
    /// An ordinary entry — signed, chained, sealed and receipted like any other
    /// — and the only durable account of the call. Any member may post one, and
    /// two targeting one invitation are not an error: two parties observed the
    /// same call ending.
    pub async fn end_call(
        &mut self,
        channel: &[u8; 32],
        target: u64,
        outcome: u8,
        duration: u32,
    ) -> Result<Posted> {
        self.send_body(
            channel,
            Body::CallEnd {
                target,
                outcome,
                duration,
            },
        )
        .await
    }

    /// SIP-36: say what this device is doing about a call.
    ///
    /// Ephemeral and forgeable, like every signal. It drives a ringing screen
    /// and nothing else — the call's outcome comes from the log, and from the
    /// missed-call derivation when no entry arrives.
    pub async fn ring_state(&mut self, channel: &[u8; 32], target: u64, state: u8) {
        use sqex_proto::channel::SignalOut;
        use sqex_proto::message::{SIGNAL_CALL_STATE, Signal};
        let body = Signal::CallState {
            target,
            state,
            device: self.device,
        }
        .encode();
        let _ = self
            .post(
                "/channel/signal",
                SignalOut {
                    channel: *channel,
                    kind: SIGNAL_CALL_STATE,
                    body,
                }
                .encode(),
            )
            .await;
    }

    /// Fetch what is new, open it, and fold it into a conversation.
    ///
    /// `timeline` carries what we already had, so this is incremental: the
    /// exchange is asked only for entries past our cursor.
    pub async fn poll(
        &mut self,
        channel: &[u8; 32],
        timeline: &mut Timeline,
        wait_secs: u16,
    ) -> Result<Conversation> {
        let (mut since, _, _) = self.store.cursor(channel)?;
        // A long poll is *meant* to sit there: `wait_secs` is how long the
        // exchange may hold the request open with nothing to say. Judging it
        // by the ordinary deadline would call a working long poll a dead
        // connection.
        let mut req = Fetch {
            channel: *channel,
            since,
            wait_secs,
            receipts: self.receipts.load(Ordering::Relaxed),
        };
        let patience = PATIENCE + Duration::from_secs(u64::from(wait_secs));
        let body = match self
            .post_within("/channel/fetch", req.encode(), patience)
            .await
        {
            Ok(body) => body,
            Err(e) if req.receipts && declines_receipts(&e) => {
                self.receipts.store(false, Ordering::Relaxed);
                req.receipts = false;
                self.post_within("/channel/fetch", req.encode(), patience)
                    .await?
            }
            // SIP-35: the exchange is refusing to choose between two histories
            // its origin signed for one position. Fetch what it has instead of
            // reporting a bare refusal — a reader told only "no" learns
            // nothing, and this is the one refusal that comes with evidence.
            Err(ChatError::Refused(_, r)) if r.code == RefusalCode::Equivocated => {
                return Err(match self.equivocation(channel).await {
                    Ok(proof) => ChatError::Equivocated(Box::new(proof)),
                    Err(e) => e,
                });
            }
            Err(e) => return Err(e),
        };
        let mut entries =
            Entries::decode(&body, req.receipts).map_err(|e| ChatError::Protocol(e.to_string()))?;

        // Being *above* the newest retained entry is not being ahead of the
        // conversation: it is holding the cursor of a channel that no longer
        // exists (SIP-16, "A reset sequence space"). The one we knew was
        // destroyed and a new one created under the same identifier, numbering
        // from 1 — which only a direct message can do, and always does, because
        // its identifier is derived from the two accounts.
        //
        // Left alone this never recovers. Every entry the new channel accepts
        // is numbered at or below our cursor, so `Fetch` returns nothing for
        // good, including our own posts: the exchange takes them and we never
        // read one back. It presents as typing a message and watching nothing
        // appear, with no error at either end.
        //
        // `last > 0` is what separates this from a channel whose entries have
        // all passed the retention window. That reports `last == 0` and needs
        // no reset — it heals itself as soon as an entry arrives above our
        // cursor, and resetting would throw away history for nothing.
        // Either inference: a cursor above the exchange's newest entry, or an
        // incarnation that changed under us before we got here. The second is
        // the sharper signal and usually fires first, because it is checked
        // before anything is signed rather than after something is fetched.
        let restarted = (since > 0 && entries.last > 0 && entries.last < since)
            || self.store.take_announcement(channel)?;
        if restarted {
            self.store.reset_sequence_space(channel)?;
            // The caller's fold goes too. Every message in it is filed under a
            // sequence number that now belongs to a different channel, so
            // keeping it would merge two conversations — and where the numbers
            // collide, silently replace one message with another.
            *timeline = Timeline::new();
            since = 0;
            // Receipts are not renegotiated here: the answer we got above is
            // this exchange's answer, and asking again would only reopen a
            // question already settled on this connection.
            let again = Fetch {
                channel: *channel,
                since: 0,
                wait_secs: 0,
                receipts: req.receipts,
            };
            let body = self.post("/channel/fetch", again.encode()).await?;
            entries = Entries::decode(&body, again.receipts)
                .map_err(|e| ChatError::Protocol(e.to_string()))?;
        }

        // Being below the oldest retained entry means we have been away longer
        // than the window. There is history we can never fill, and presenting
        // what remains as the whole conversation would be a lie.
        let gap = since > 0 && entries.first > since;

        // Who may redact and whose metadata counts — Timeline needs this, and
        // it is only in the member list.
        let mut info = self.info(channel).await?;

        // Somebody may have rotated while this client was running — after a
        // removal, or after revoking a device. Collect once when we hold no key
        // for the epoch in force, or a client would sit showing unreadable
        // entries until it was restarted.
        if info.epoch > 0 && self.store.key(channel, info.epoch)?.is_none() {
            self.collect_keys(channel).await?;
            info = self.info(channel).await?;
        }
        let admins: Vec<PubKey> = info
            .members
            .iter()
            .filter(|m| m.role == Role::Admin)
            .map(|m| m.account)
            .collect();

        let mut replay = self.store.replay_for(channel)?;
        // SIP-31 chain state per device, over this run of entries. Continuity
        // is claimed from the first entry seen from each device rather than
        // backwards, because starting to read in the middle of a channel is
        // ordinary and is not a gap anybody caused.
        let mut seen_chains: HashMap<PubKey, (u64, [u8; 32])> = HashMap::new();
        // SIP-34's linkage runs over the channel rather than over one device,
        // so it is a single running value rather than a map: the head of the
        // entry we checked last, if it was the one immediately before.
        let mut last_head: Option<(u64, [u8; 32])> = None;
        // Fetched once for the batch rather than per entry: SIP-31's second
        // step needs a credential for every device that signed one, and the
        // members are who could have.
        let bound = self.bindings(&members_of(&info)).await.unwrap_or_default();
        let mut last = since;
        for e in &entries.entries {
            last = last.max(e.seq);
            if e.kind == KIND_MEMBER {
                // SIP-17: a counter we have already seen under this key is
                // either the exchange replaying or somebody else doing it, and
                // it must not be decrypted.
                if !replay.accept(&e.device, e.epoch, e.msg_seq) {
                    continue;
                }
            }
            let plain = if e.epoch == 0 {
                // Epoch 0 is unsealed by construction: every entry in a public
                // channel, and the exchange's own system entries everywhere.
                Some(e.body.clone())
            } else {
                self.store
                    .key(channel, e.epoch)
                    .ok()
                    .flatten()
                    .and_then(|k| k.open(channel, e.epoch, &e.device, e.msg_seq, &e.body).ok())
            };
            // Kept, not cached. The counter may not be decrypted twice and the
            // exchange serves an epoch key's envelope once, so a message not
            // written here is one this client can never read again.
            // Recorded only once it has actually been opened. SIP-17's rule is
            // that a counter must not be *decrypted* twice; marking one seen on
            // an attempt that failed would refuse the entry for good, which is
            // exactly what happens to a device linked after the fact — it polls
            // before its key arrives, and every message it could not read then
            // stays unreadable forever.
            if plain.is_some() && e.kind == KIND_MEMBER {
                self.store
                    .record_seen(channel, &e.device, e.epoch, e.msg_seq)?;
            }
            // SIP-16 redaction leaves the entry with no body at all. That is
            // a deleted message, not one this client could not open, and the
            // difference has to be read off the entry rather than off `plain`:
            // a sealed tombstone has nothing to unseal, so opening it fails
            // exactly as a missing key does.
            let tombstone = e.body.is_empty();
            // SIP-31, before anything is stored or shown: an entry nobody
            // signed for is not a message, and folding it first would put it in
            // front of a reader while the check was still pending.
            let verdict = Self::verdict_for(
                self.exchange,
                channel,
                info.instance,
                e,
                &mut seen_chains,
                &bound,
            );
            // SIP-34, and separately: a receipt says where the exchange put the
            // entry and nothing about who wrote it. Both are checked; a
            // verifier doing only one has learned half of what it thinks.
            let held = last_head
                .filter(|(seq, _)| seq + 1 == e.seq)
                .map(|(_, head)| head);
            let standing = Self::standing_for(self.exchange, channel, info.instance, e, held);
            if let Some(stamp) = &e.stamp {
                last_head = Some((e.seq, stamp.head));
            }
            if verdict == Verdict::Forged {
                // Not stored, not folded, and not counted as read. `history`
                // rebuilds from this store without the signatures — they are
                // not kept — so anything written here is taken on trust later,
                // and the only way that stays honest is to write nothing that
                // failed to verify now.
                timeline.apply(
                    &Received {
                        seq: e.seq,
                        account: e.account,
                        posted: e.posted,
                        kind: e.kind,
                        tombstone,
                        body: None,
                        verdict,
                        standing,
                    },
                    &admins,
                );
                continue;
            }
            self.store.put_message(
                channel,
                Kept {
                    seq: e.seq,
                    account: e.account,
                    posted: e.posted,
                    kind: e.kind,
                    // Stored as empty rather than absent, so that reopening
                    // this store still tells the two apart.
                    plain: if tombstone {
                        Some(&[][..])
                    } else {
                        plain.as_deref()
                    },
                },
            )?;
            // A tombstone fetched fresh must overwrite a body we already hold.
            // `put_message` keeps what it has, which is right for a re-fetch
            // and wrong for this.
            if tombstone {
                self.store.redact_message(channel, e.seq)?;
            }
            let body = plain.and_then(|p| Body::decode(&p).ok().flatten());
            let redacts = match &body {
                Some(Body::Redact { target }) => Some(*target),
                _ => None,
            };
            timeline.apply(
                &Received {
                    seq: e.seq,
                    account: e.account,
                    posted: e.posted,
                    kind: e.kind,
                    tombstone,
                    body,
                    verdict,
                    standing,
                },
                &admins,
            );
            // The words go from disk as well as from the exchange. Gated on
            // the fold having *honoured* the redaction rather than on having
            // seen one: only the message's own account or an admin may delete
            // it, and asking the timeline reuses that rule instead of keeping
            // a second copy of it here — a forged redaction must not be able
            // to make this client destroy somebody else's message.
            if let Some(target) = redacts
                && timeline.get(target).is_some_and(|m| m.redacted)
            {
                self.store.redact_message(channel, target)?;
            }
        }
        if last > since {
            self.store.set_since(channel, last)?;
        }

        let typing = entries.signals.iter().any(|s| {
            use sqex_proto::message::{SIGNAL_TYPING, Signal};
            s.kind == SIGNAL_TYPING
                && matches!(Signal::decode(&s.body), Ok(Some(Signal::Typing(true))))
        });

        // Everything the timeline could not open, minus what is gone for good:
        // the two are counted apart because they deserve different words, and
        // reporting a permanent loss every session as though it were a fault
        // is how a status line stops being read.
        // Whether an unopened entry is gone or merely late is one question
        // about the channel, not one per message: if we hold the key for the
        // epoch in force, anything still shut is under an older one, and a
        // rotation hands out the next epoch and never a past one. If we do not
        // hold it, the opposite — an admin can still send it.
        //
        // Derived rather than recorded, deliberately. An earlier version wrote
        // the judgement onto each row as it arrived, which went stale the
        // moment a rotation changed the answer and left rows nothing would
        // ever revisit.
        // Learn who these people call themselves, before the caller has to
        // render them. Doing it here rather than in the interface means every
        // client gets it, and means a name is known from the moment a
        // conversation exists rather than from the moment somebody speaks —
        // which is what a list of conversations needs.
        //
        // Members rather than speakers, and capped: the exchange already
        // returned the member list, but a large public channel would otherwise
        // make the first poll do a round trip per person. What is left over is
        // picked up by the next poll.
        let members: Vec<PubKey> = info
            .members
            .iter()
            .map(|m| m.account)
            .take(PROFILES_PER_POLL)
            .collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Silent on failure. A name is decoration, and a conversation that
        // stopped working because one could not be fetched would be the tail
        // wagging the dog.
        let _ = self.refresh_profiles(&members, now).await;

        let have_current = self.store.key(channel, info.epoch)?.is_some();
        // A public channel is stored in the clear and has no epoch, so having
        // no key for it is the ordinary state rather than a fault. And a
        // private channel we hold nothing in is not stranded, it is empty —
        // saying "this cannot be read" of a conversation with nothing in it
        // would be a warning about nothing.
        let no_key = (!have_current
            && info.visibility != Visibility::Public
            && self.store.held(channel)? > 0)
            .then_some(info.epoch);
        // What this poll's fold could not open, *plus* what earlier runs left
        // unopened. The fold alone reports only entries fetched just now, so a
        // conversation whose history was already on disk read as an ordinary
        // empty one on every poll after the first — the same blind spot the
        // `no_key` guard had, in the one place that reports history as gone.
        let mut shut = self.store.unopened(channel)?;
        for seq in timeline.unreadable() {
            if !shut.contains(seq) {
                shut.push(*seq);
            }
        }
        shut.sort_unstable();
        Ok(Conversation {
            lost: if have_current { shut.len() } else { 0 },
            unreadable: if have_current { Vec::new() } else { shut },
            no_key,
            timeline: timeline.clone(),
            gap,
            restarted,
            typing,
            last,
            admins,
        })
    }

    /// Post a cursor exactly as given, including whether to share reading.
    ///
    /// Exposed for the test that shows reciprocity: the exchange withholds
    /// everybody else's reading from an account that withholds its own, and
    /// that is worth proving rather than trusting.
    pub async fn post_cursor(
        &mut self,
        channel: &[u8; 32],
        cursor: sqex_proto::channel::Cursor,
    ) -> Result<()> {
        let _ = channel;
        let body = self.post("/channel/cursor", cursor.encode()).await?;
        Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(())
    }

    /// Mark everything up to `seq` read, so the other side's client can say so.
    pub async fn mark_read(&mut self, channel: &[u8; 32], seq: u64) -> Result<()> {
        use sqex_proto::channel::Cursor;
        let body = self
            .post(
                "/channel/cursor",
                Cursor {
                    channel: *channel,
                    read: seq,
                    receipts: true,
                }
                .encode(),
            )
            .await?;
        Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use sqex_proto::channel::KIND_MEMBER;
    use sqex_proto::receipt::HEAD_GENESIS;

    fn dev(n: u8) -> ([u8; 32], PubKey) {
        let seed = [n; 32];
        (
            seed,
            PubKey::new(SigningKey::from_bytes(&seed).verifying_key().to_bytes()),
        )
    }

    /// One entry, honestly signed, at whatever chain position it is given.
    fn entry_at(seq: u64, chain_seq: u64, prev: [u8; 32], body: &[u8]) -> Entry {
        let (seed, device) = dev(1);
        let (_, exchange) = dev(9);
        let terms = EntryTerms {
            place: Place {
                exchange,
                instance: [4; 32],
                channel: [7; 32],
            },
            account: device,
            device,
            epoch: 0,
            msg_seq: 0,
            expires_after: 0,
            chain_seq,
            prev,
            body,
        };
        Entry {
            seq,
            kind: KIND_MEMBER,
            account: device,
            device,
            posted: 100 + seq,
            expires_after: 0,
            epoch: 0,
            msg_seq: 0,
            chain_seq,
            prev,
            body_hash: Sha256::digest(body).into(),
            sig: sign_entry(&seed, &terms),
            stamp: None,
            body: body.to_vec(),
        }
    }

    /// Stamp an entry as the exchange at seed 9 would, on top of `prev_head`.
    fn stamped(mut e: Entry, prev_head: [u8; 32]) -> Entry {
        let (seed, exchange) = dev(9);
        let terms = EntryTerms {
            place: Place {
                exchange,
                instance: [4; 32],
                channel: [7; 32],
            },
            account: e.account,
            device: e.device,
            epoch: e.epoch,
            msg_seq: e.msg_seq,
            expires_after: e.expires_after,
            chain_seq: e.chain_seq,
            prev: e.prev,
            body: &e.body,
        };
        let entry_hash = link(&terms.input_hashed(&e.body_hash));
        let head = receipt::advance(&prev_head, &entry_hash);
        let sig = receipt::sign(
            &seed,
            &ReceiptTerms {
                place: Place {
                    exchange,
                    instance: [4; 32],
                    channel: [7; 32],
                },
                seq: e.seq,
                posted: e.posted,
                entry_hash,
                head,
            },
        );
        e.stamp = Some(sqex_proto::channel::Receipted {
            entry_hash,
            head,
            receipt: sig,
        });
        e
    }

    fn standing(e: &Entry, held: Option<[u8; 32]>) -> Standing {
        Chat::standing_for(dev(9).1, &[7u8; 32], [4u8; 32], e, held)
    }

    /// **The asymmetry SIP-34 says an implementation is most likely to get
    /// backwards.** Absent is *unclaimed* and says nothing about the entry;
    /// present-and-invalid is *repudiated* and is surfaced. Collapsing them
    /// builds a mechanism the exchange can switch off by corrupting its own
    /// signatures — so they are checked here as distinct values, in both
    /// directions.
    #[test]
    fn an_absent_receipt_and_a_bad_one_are_not_the_same_state() {
        let plain = entry_at(1, 0, GENESIS, b"hello");
        assert_eq!(standing(&plain, None), Standing::Unclaimed);
        assert_eq!(
            standing(&plain, Some([3u8; 32])),
            Standing::Unclaimed,
            "an entry with no receipt is unclaimed however much history we hold"
        );

        let good = stamped(plain.clone(), HEAD_GENESIS);
        assert_eq!(standing(&good, Some(HEAD_GENESIS)), Standing::Vouched);

        let mut spoiled = good.clone();
        spoiled.stamp.as_mut().unwrap().receipt[0] ^= 1;
        assert_eq!(standing(&spoiled, Some(HEAD_GENESIS)), Standing::Repudiated);
        assert_ne!(standing(&spoiled, Some(HEAD_GENESIS)), Standing::Unclaimed);
    }

    /// A gap is not a divergence, and SIP-34 is emphatic that presenting one as
    /// the other accuses an exchange of rewriting when it may only have pruned.
    #[test]
    fn a_gap_is_reported_differently_from_a_divergence() {
        let first = stamped(entry_at(1, 0, GENESIS, b"one"), HEAD_GENESIS);
        let head_1 = first.stamp.unwrap().head;
        let second = stamped(entry_at(2, 1, link_of(0, GENESIS, b"one"), b"two"), head_1);

        // Holding the entry before it: the linkage is checkable and holds.
        assert_eq!(standing(&second, Some(head_1)), Standing::Vouched);
        // Not holding it — pruned, expired, or joined mid-channel. Ordinary.
        assert_eq!(standing(&second, None), Standing::Unlinked);
        // Holding it, and the linkage fails: the exchange advanced its head
        // over something we were never shown.
        assert_eq!(standing(&second, Some([0xEE; 32])), Standing::Diverged);
    }

    /// A receipt naming a hash that is not this entry's is repudiated, not
    /// merely unlinked. Without this an exchange could receipt one entry and
    /// serve another, and every linkage check downstream would still agree
    /// with itself.
    #[test]
    fn a_receipt_over_a_different_entry_is_refused() {
        let good = stamped(entry_at(1, 0, GENESIS, b"hello"), HEAD_GENESIS);
        let mut lifted = good.clone();
        lifted.body = b"goodbye".to_vec();
        lifted.body_hash = Sha256::digest(b"goodbye").into();
        assert_eq!(standing(&lifted, Some(HEAD_GENESIS)), Standing::Repudiated);
    }

    /// The key is the one this client pinned. A receipt checked under a key
    /// taken from the response would prove only that the sender agrees with
    /// itself.
    #[test]
    fn a_receipt_is_checked_under_the_pinned_key_and_no_other() {
        let good = stamped(entry_at(1, 0, GENESIS, b"hello"), HEAD_GENESIS);
        assert_eq!(
            Chat::standing_for(dev(8).1, &[7u8; 32], [4u8; 32], &good, Some(HEAD_GENESIS)),
            Standing::Repudiated
        );
    }

    /// The chain link an entry produces, so a test can build the next one.
    fn link_of(chain_seq: u64, prev: [u8; 32], body: &[u8]) -> [u8; 32] {
        let (_, device) = dev(1);
        let (_, exchange) = dev(9);
        let terms = EntryTerms {
            place: Place {
                exchange,
                instance: [4; 32],
                channel: [7; 32],
            },
            account: device,
            device,
            epoch: 0,
            msg_seq: 0,
            expires_after: 0,
            chain_seq,
            prev,
            body,
        };
        link(&terms.input_hashed(&Sha256::digest(body).into()))
    }

    fn judge(entries: &[Entry]) -> Vec<Verdict> {
        let (_, exchange) = dev(9);
        let mut chain = HashMap::new();
        let bound = HashMap::new();
        entries
            .iter()
            .map(|e| Chat::verdict_for(exchange, &[7u8; 32], [4u8; 32], e, &mut chain, &bound))
            .collect()
    }

    /// SIP-31's own definition: "two entries by one device at one `chain_seq`,
    /// both validly signed" is a **fork**, and a client MUST surface it.
    ///
    /// This is the case nothing produces by accident, so nothing had tested it.
    /// Both entries below are honestly signed — the misconduct is that the
    /// device signed twice at position 0, which cannot happen without that
    /// device signing twice or somebody replaying.
    #[test]
    fn two_entries_at_one_chain_position_are_a_fork() {
        let first = entry_at(1, 0, GENESIS, b"first");
        let second = entry_at(2, 0, GENESIS, b"second");
        let v = judge(&[first, second]);
        assert_eq!(v[0], Verdict::Valid, "the first entry is honest");
        assert_eq!(
            v[1],
            Verdict::Fork,
            "a second entry at chain position 0 is a fork, not a gap"
        );
    }

    /// The other half of the distinction, and the reason it matters: a gap is
    /// ordinary — pruning and retention both produce one — and SIP-31 says a
    /// client MUST NOT present it as misconduct. Without this the fix above
    /// could pass by calling everything a fork.
    #[test]
    fn a_skipped_chain_position_is_an_ordinary_gap() {
        let first = entry_at(1, 0, GENESIS, b"first");
        let later = entry_at(2, 7, [3u8; 32], b"after a prune");
        let v = judge(&[first, later]);
        assert_eq!(v[0], Verdict::Valid);
        assert_eq!(
            v[1],
            Verdict::Gap,
            "a forward jump is pruning, and must not be reported as misconduct"
        );
    }

    /// One replay must not poison everything after it.
    ///
    /// The mark is not rewound to the replayed position, so the device's next
    /// honest entry still lands where the chain expects it. Rewinding would
    /// turn a single act of misconduct into a transcript that reports it on
    /// every line, and a reader cannot tell one forged entry from a broken
    /// client if the whole conversation is flagged.
    #[test]
    fn a_replay_does_not_make_the_entries_after_it_look_forged() {
        let v = judge(&[
            entry_at(1, 0, GENESIS, b"first"),
            entry_at(2, 1, link_of(0, GENESIS, b"first"), b"second"),
            entry_at(3, 0, GENESIS, b"first"),
            entry_at(
                4,
                2,
                link_of(1, link_of(0, GENESIS, b"first"), b"second"),
                b"third",
            ),
        ]);
        assert_eq!(v[0], Verdict::Valid);
        assert_eq!(v[1], Verdict::Valid);
        assert_eq!(v[2], Verdict::Fork, "the replay is the evidence");
        assert_eq!(
            v[3],
            Verdict::Valid,
            "the honest entry after a replay must still read as honest"
        );
    }

    /// The case that could not be written before this change.
    ///
    /// `classify` used to decide with `said.contains("not_an_admin")` against
    /// the whole body, and the body carried a free-text detail. A refusal about
    /// something else whose detail merely *mentions* the words would have been
    /// reported as `NotAnAdmin`, and the client would have taken an admin's
    /// branch on a storage failure. The detail is a separate field now, and
    /// nothing reads it to decide anything.
    #[test]
    fn a_detail_that_mentions_a_code_does_not_choose_the_branch() {
        let body = Refusal::detailed(
            RefusalCode::Storage,
            "while checking not_an_admin and direct_message rules",
        )
        .encode();

        // The old substring test, shown failing on these very bytes.
        let said = String::from_utf8_lossy(&body).into_owned();
        assert!(
            said.contains("not_an_admin"),
            "the detail must really contain the word, or this proves nothing"
        );

        match classify("/channel/grant", 403, &body) {
            ChatError::Refused(403, r) => assert_eq!(r.code, RefusalCode::Storage),
            other => panic!("detail decided the branch: {other:?}"),
        }
    }

    #[test]
    fn a_real_refusal_still_chooses_its_branch() {
        let admin = Refusal::new(RefusalCode::NotAnAdmin).encode();
        assert!(matches!(
            classify("/channel/grant", 403, &admin),
            ChatError::NotAnAdmin
        ));

        let gone = Refusal::new(RefusalCode::NotFound).encode();
        match classify("/channel/fetch", 404, &gone) {
            ChatError::NoChatHere(p) => assert_eq!(p, "/channel/fetch"),
            other => panic!("wanted NoChatHere, got {other:?}"),
        }
    }

    /// A chat route's own 404 — "that channel is not there" — must not be read
    /// as "this exchange has no chat", which is what `NoChatHere` claims.
    #[test]
    fn a_missing_channel_is_not_a_missing_exchange() {
        let body = Refusal::new(RefusalCode::NoSuchChannel).encode();
        match classify("/channel/fetch", 404, &body) {
            ChatError::Refused(404, r) => assert_eq!(r.code, RefusalCode::NoSuchChannel),
            other => panic!("a missing channel read as {other:?}"),
        }
    }

    /// An exchange older than this client answers JSON, or a bare line for a
    /// request that would not decode. Neither is a refusal we can read, and
    /// saying so beats guessing.
    #[test]
    fn an_older_exchange_still_gets_an_answer() {
        match classify("/channel/fetch", 404, b"not found") {
            ChatError::NoChatHere(p) => assert_eq!(p, "/channel/fetch"),
            other => panic!("legacy 404 read as {other:?}"),
        }
        match classify("/channel/put", 403, br#"{"error":"not_an_admin"}"#) {
            ChatError::Unreadable(403, said) => assert!(said.contains("not_an_admin")),
            other => panic!("legacy JSON read as {other:?}"),
        }
    }
}
