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
    EVENT_ADDED, EVENT_CREATED, EVENT_DEMOTED, EVENT_JOINED, EVENT_LEFT, EVENT_MUTED,
    EVENT_PROMOTED, EVENT_REHOMED, EVENT_REMOVED, EVENT_RENAMED, EVENT_REPLICATE, EVENT_RETENTION,
    EVENT_ROTATED, EVENT_UNMUTED, EVENT_UNREPLICATE, Entries, Entry, Fetch, Found, Home, Invite,
    Invitee, KIND_MEMBER, KIND_SYSTEM, List, Listing, MAX_MINE, MAX_NAME, MAX_RETENTION, MAX_TOPIC,
    MIN_RETENTION, Mark, Marks, Membership, Mine, Mines, Post, Posted, Rehome, Rehomed, Report,
    Reported, Reports, Retain, Role, Row, Search, Stranded, System, TYPE_CLOSE, TYPE_CURSORS,
    TYPE_DISMISS, TYPE_EQUIVOCATION, TYPE_HOME, TYPE_INFO, TYPE_JOIN, TYPE_LEAVE, TYPE_MUTE,
    TYPE_REDACT, TYPE_REMOVE, TYPE_REPLICATE, TYPE_REPORTS, TYPE_STRANDED, TYPE_UNMUTE,
    TYPE_UNREPLICATE, Visibility, constitution, direct_message_id,
};
use sqex_proto::channel_key::{
    Absent, ChannelKey, Envelope, Get as KeyGet, Got, Put as KeyPut, PutAck, TYPE_MISSING,
    open_envelope, seal_envelope, sign_envelope, verify_envelope,
};
use sqex_proto::credential::{Credential, Revocation, SCOPE_CHAT};
use sqex_proto::device::{
    AdmissionRequest, Device, Devices, DevicesFrom, FROM_STALE, ListDevices, ListDevicesFrom,
    Register, Revoke,
};
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
use sqex_proto::tunnel::Carrier;
use sqnr::Client;
use sqnr_core::PubKey;
use std::collections::{HashMap, HashSet};
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

/// How long a poll will believe what it was last told about a channel.
///
/// **A poll that fetched nothing has nothing to attribute.** `poll` asked the
/// exchange who is in the channel, and then asked it once per member which
/// devices they hold, on *every* poll — so a client watching a quiet
/// conversation at 700ms was making four requests a tick to learn that nothing
/// had happened, three of them about a membership that had not moved.
///
/// Anything that *does* move the membership or the epoch arrives as an entry,
/// and an entry refreshes both at once, so this only bounds how stale the
/// answer can be when nothing at all is arriving. Fifteen seconds of that is a
/// question worth not asking a thousand times.
const POLL_TTL: std::time::Duration = std::time::Duration::from_secs(15);

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

/// How many chunks of one file are asked for at once. See [`Chat::post_many`].
const IN_FLIGHT: usize = 8;

/// How many device lists are asked for at once. Small answers, so more of
/// them: a channel of sixty members is four waves rather than eight.
const LISTS_IN_FLIGHT: usize = 16;

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
type Dialing =
    Pin<Box<dyn Future<Output = std::result::Result<(Client, Option<Carrier>), String>> + Send>>;

/// SIP-85: the home this client reaches its exchange through, and the
/// tunnel it holds there now. Reconnecting re-opens the tunnel first when
/// the old one is gone -- a dial to the old carrier's loopback socket
/// reaches nothing.
pub struct Via {
    pub home: (SocketAddr, [u8; 32]),
    pub target_key: [u8; 32],
    pub target_domain: String,
    carrier: Option<Carrier>,
}

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
    /// SIP-47: this device is not in the named account's device list, so
    /// the account has not registered it -- or registered a different key.
    NotListed(PubKey),
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
    /// SIP-43: the conversation lives at another exchange, and this one could
    /// not reach it to order the post. Nothing was sent; the draft stands.
    OriginAway,
    /// SIP-35 §Passing a limit through: the origin answered a forwarded act and refused it, with
    /// its status where the exchange said.
    OriginRefused(Option<u16>),
    /// SIP-44: this account has been succeeded by the key named. Everything it
    /// held is that key's now, and this device is nobody's until it is
    /// linked to it.
    Succeeded(Option<PubKey>),
    /// SIP-59: the account this concerns lives at another exchange now --
    /// its key, and the domain it is reached by where the refusing exchange
    /// knew one. This exchange hands the key's services off there.
    Moved(Option<PubKey>, String),
    /// SIP-60 §Sealing to a list: this account lives at another exchange this one could not
    /// ask, and the device list here is from before it left -- a device
    /// revoked since may be on it and one linked since is not. No key was
    /// sealed to it; the epoch stays where it is until the home answers.
    DevicesStale(PubKey),
    /// SIP-5 §Collection by a device: a mail item this device fetched is sealed to a key it does
    /// not hold -- its account's, on a device that was not entrusted with
    /// it -- and must not be deleted from here.
    MailSealedElsewhere(u64),
}

/// SIP-60 §When a client presents a Move unasked: what [`Chat::ensure_home`] found on connecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeSaid {
    /// This exchange had no record and this store's own home has lost it:
    /// a Move naming it was presented again.
    Presented,
    /// This exchange has no record and this store has never made or
    /// presented a Move: a new store, at an exchange somebody pointed it
    /// at. Nothing was presented -- the first "this is my home" is the
    /// person's ([`Chat::claim_home`]), and until then the client is a
    /// visitor here.
    Unclaimed,
    /// This exchange already records the account's home.
    OnRecord,
    /// This store is filed under another exchange: the account lives at
    /// `home`, and this client is a visitor here. No Move naming this
    /// exchange was presented; `told` is whether one naming `home` was,
    /// because this exchange recorded itself as the home from before the
    /// store's own Move; `behind` is the other case -- this exchange
    /// records itself as the home and the store cannot show it is wrong,
    /// so the account may have been moved here from another device.
    Visitor {
        home: PubKey,
        told: bool,
        behind: bool,
    },
    /// This client does not hold the account key, or this exchange has no
    /// chat: not its to say.
    NotMine,
}

/// SIP-59: what a move did.
#[derive(Debug, Clone)]
pub struct Moved {
    pub mv: sqex_proto::home::Move,
    /// Whether the exchange left lists the new home as a peer: without
    /// that, the home's pulls from it are refused and its operator must be
    /// asked.
    pub peered_here: bool,
    pub peered_at_home: bool,
    /// Store rows re-filed under the new home.
    pub refiled: usize,
    /// Rows that could not follow because the new scope already held them.
    pub left: usize,
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
            RefusalCode::OriginAway => ChatError::OriginAway,
            // SIP-35 §Passing a limit through: the origin answered, and said no -- a different
            // situation from one that could not be reached.
            RefusalCode::OriginRefused => {
                ChatError::OriginRefused(r.detail.as_deref().and_then(|d| d.parse().ok()))
            }
            RefusalCode::Succeeded => {
                ChatError::Succeeded(r.detail.as_deref().and_then(|d| d.parse().ok()))
            }
            RefusalCode::Moved => {
                let detail = r.detail.clone().unwrap_or_default();
                let (key, domain) = detail.split_once(' ').unwrap_or((detail.as_str(), ""));
                ChatError::Moved(key.parse().ok(), domain.to_string())
            }
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
            ChatError::NotListed(account) => write!(
                f,
                "{account} has not registered this device: the key it registered is not \
                 this one, or the registration has not reached this exchange"
            ),
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
            ChatError::Succeeded(Some(by)) => write!(
                f,
                "this account has been succeeded by {by}: its names and conversations are that \
                 key's now, and this device is nobody's until it is linked to it"
            ),
            ChatError::Succeeded(None) => write!(
                f,
                "this account has been succeeded: its names and conversations belong to another \
                 key now"
            ),
            ChatError::OriginAway => write!(
                f,
                "this conversation lives at another exchange, which cannot be reached right now; \
                 nothing was sent"
            ),
            ChatError::OriginRefused(code) => write!(
                f,
                "this conversation lives at another exchange, which refused what your exchange \
                 carried there{}; nothing was sent",
                code.map(|c| format!(" ({c})")).unwrap_or_default()
            ),
            ChatError::MailSealedElsewhere(id) => write!(
                f,
                "message {id} is sealed to a key this device does not hold -- the account's; a \
                 device that holds it can read it (`device entrust`), and it stays on the \
                 exchange until one does"
            ),
            ChatError::Moved(key, domain) => {
                let at = match (key, domain.is_empty()) {
                    (_, false) => domain.clone(),
                    (Some(k), true) => k.to_string(),
                    (None, true) => "another exchange".to_string(),
                };
                write!(
                    f,
                    "that account moved to {at}; this exchange hands its services off there"
                )
            }
            ChatError::DevicesStale(who) => write!(
                f,
                "{who} lives at another exchange this one could not ask, and its device list \
                 here is from before it left; no new key was sealed -- try again when its home \
                 can be reached"
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

/// SIP-40: the keys `exchange` succeeded, newest first, as far back as the
/// pin store remembers. Empty for a key that never moved or is not pinned.
fn predecessors_of(exchange: &PubKey) -> Vec<PubKey> {
    let Ok(known) = sqex_discovery::Known::load(&sqex_discovery::known::path()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut at = *exchange;
    while let Some(from) = known.predecessor_of(&at) {
        if out.contains(&from) || from == *exchange || out.len() > 8 {
            break;
        }
        out.push(from);
        at = from;
    }
    out
}

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
            let listed = self.devices_to_seal_to(account).await?;
            if listed.devices.is_empty() {
                out.push(*account);
            } else {
                out.extend(listed.devices.iter().map(|d| d.device));
            }
        }
        Ok(out)
    }

    /// SIP-60 §Sealing to a list: an account's devices as a list a key may be sealed to.
    /// Asked with the newer type byte, which says whose list it is; a
    /// stale one -- this exchange's own registry for an account that lives
    /// elsewhere, because the home could not be asked -- is refused as
    /// [`ChatError::DevicesStale`], so the epoch stays where it is rather
    /// than reaching a device the account may have revoked. An exchange
    /// from before sqex 0.100.0 refuses the type byte as malformed, and is asked
    /// the old way, which is what this client did before.
    async fn devices_to_seal_to(&mut self, account: &PubKey) -> Result<Devices> {
        match self
            .post(
                "/device/list",
                ListDevicesFrom { account: *account }.encode(),
            )
            .await
        {
            Ok(body) => {
                let got =
                    DevicesFrom::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
                if got.from == FROM_STALE {
                    return Err(ChatError::DevicesStale(*account));
                }
                Ok(got.devices)
            }
            Err(ChatError::Refused(400, r)) if r.code == RefusalCode::Malformed => {
                let body = self
                    .post("/device/list", ListDevices { account: *account }.encode())
                    .await?;
                Devices::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
            }
            Err(e) => Err(e),
        }
    }
}

/// Which device each account signs from, as far as the exchange will say.
///
/// `None` for an account with no linked device: SIP-22 makes such an account
/// its own device, so there is nothing to bind and nothing missing.
type Bindings = HashMap<PubKey, Option<PubKey>>;

/// Whether an account may mint an epoch here.
fn is_admin(info: &ChannelInfo, who: &PubKey) -> bool {
    info.members
        .iter()
        .any(|m| m.account == *who && m.role == Role::Admin)
}

/// What a fetch brought back, before anything has been made of it.
///
/// Opaque on purpose: it is a body off the wire plus the two things needed to
/// read it — the cursor it was asked from, and whether receipts were asked for.
/// Nothing can be learned from one without [`Chat::absorb`], which holds the
/// keys.
#[derive(Debug)]
pub struct Fetched {
    channel: [u8; 32],
    since: u64,
    receipts: bool,
    body: Vec<u8>,
}

impl Fetched {
    /// Which conversation this is an answer about.
    pub fn channel(&self) -> [u8; 32] {
        self.channel
    }

    /// An `Entries` reply that arrived inside a catch-up (SIP-47 §Catching up in one round trip) rather than
    /// as the answer to a fetch: the same bytes, absorbed the same way.
    fn carried(channel: [u8; 32], since: u64, body: Vec<u8>) -> Fetched {
        Fetched {
            channel,
            since,
            receipts: false,
            body,
        }
    }
}

/// One channel of a catch-up (SIP-47 §Catching up in one round trip), as this client got it: the keys already
/// opened and kept, the entries still to be absorbed.
#[derive(Debug)]
pub struct Caught {
    pub channel: [u8; 32],
    /// `sqex_proto::catchup::STATUS_*`.
    pub status: u8,
    /// The exchange holds entries this answer did not carry.
    pub more: bool,
    /// The entries, to absorb into the caller's timeline. `None` when the
    /// channel was absent or deferred.
    pub fetched: Option<Fetched>,
    pub keys_opened: usize,
}

/// A catch-up answer (SIP-47 §The catch-up answer), after the keys in it were kept.
#[derive(Debug)]
pub struct CaughtUp {
    pub now: u64,
    /// This device's remaining one-time prekeys, as the exchange counts them.
    pub prekeys: u16,
    pub caught: Vec<Caught>,
    pub unnamed: Vec<Unnamed>,
}

pub use sqex_proto::catchup::{Named, Unnamed};

/// A fetch that has not been sent yet, and need not be sent from here.
///
/// # Why this exists
///
/// `/channel/fetch` takes a `wait_secs`: the exchange holds the request open
/// and answers the moment an entry or a signal arrives (SIP-16). One request
/// then delivers a message in a single trip and costs nothing while nothing is
/// happening — which is what a chat client wants and what every caller here
/// declined, passing `wait_secs = 0` and asking again on a timer, because
/// `Chat` is one borrow and a request parked in it for twenty-five seconds is
/// twenty-five seconds in which nothing else can be sent.
///
/// So the parked half is taken out. A `Watch` owns a [`sqnr::Requests`] — a
/// handle on the same connection, its own HTTP/3 stream, no second handshake
/// and no second socket — and knows nothing else. It cannot touch the store,
/// cannot spend a counter and cannot decide the link is down; it fetches bytes
/// and hands them back for [`Chat::absorb`] to make sense of.
///
/// **It does not follow a reconnection.** The handle belongs to the connection
/// it was taken from, so a `Watch` outstanding when the client redials is
/// answering about a connection that is gone. A caller that redials should drop
/// it and take another; what comes back from the old one is stale, not wrong,
/// but there is no reason to wait for it.
pub struct Watch {
    requests: sqnr::Requests,
    channel: [u8; 32],
    since: u64,
    receipts: bool,
    wait: u16,
}

impl Watch {
    /// Which conversation this is parked on.
    pub fn channel(&self) -> [u8; 32] {
        self.channel
    }

    /// How long the exchange may hold it open with nothing to say.
    pub fn waits(&self) -> u16 {
        self.wait
    }

    /// Park it, and hand back what arrives.
    ///
    /// Returns when the exchange has something -- an entry or a signal -- or
    /// when `wait` expires with nothing, which is an ordinary empty answer and
    /// not an error. Consumes itself: a fetch is asked from a cursor, and one
    /// answered is one whose cursor has moved.
    ///
    /// Refusals are returned rather than acted on: this has no client to lower
    /// a link on or to renegotiate receipts with. A caller that gets an error
    /// here should fall back to [`Chat::poll`], which does both.
    pub async fn arrived(self) -> Result<Fetched> {
        let req = Fetch {
            channel: self.channel,
            since: self.since,
            wait_secs: self.wait,
            receipts: self.receipts,
        };
        // The exchange's own wait, plus what an ordinary request is allowed.
        // Judging a long poll by the ordinary deadline would call a working one
        // a dead connection.
        let patience = PATIENCE + Duration::from_secs(u64::from(self.wait));
        let sent =
            tokio::time::timeout(patience, self.requests.post("/channel/fetch", req.encode()))
                .await
                .map_err(|_| {
                    ChatError::Transport(format!(
                        "the exchange stopped answering ({}s)",
                        patience.as_secs()
                    ))
                })?;
        let (code, body) = sent.map_err(ChatError::Transport)?;
        if code != 200 {
            return Err(classify("/channel/fetch", code, &body));
        }
        Ok(Fetched {
            channel: self.channel,
            since: self.since,
            receipts: self.receipts,
            body,
        })
    }
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
    /// A call somebody has just said they are taking, by the `seq` of its
    /// invitation (SIP-36 `RING_ACCEPTED`).
    ///
    /// Reported because the log cannot report it. Answering posts no entry —
    /// SIP-36 is right that a durable record must not be derived from a signal
    /// — so a caller watching only the timeline never learns the callee picked
    /// up, goes on showing "ringing", and then derives **missed** when the ring
    /// window passes, of a call that is up and being spoken on.
    ///
    /// Ephemeral, forgeable and best-effort, like every signal: it drives what
    /// is on screen and nothing that is written down.
    pub accepted: Option<u64>,
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
    pub(crate) seed: [u8; 32],
    /// Where to dial to get back. `None` when nobody said — a `Chat` that
    /// cannot reconnect must not pretend to be reconnecting, and must not
    /// short-circuit its own requests either, so it keeps the behaviour it had
    /// before any of this existed: every call tries.
    endpoint: Option<(SocketAddr, [u8; 32])>,
    /// SIP-85: set when the connection is carried by a home.
    via: Option<Via>,
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
    /// Somewhere to be told a frame arrived, so a caller need not ask on a
    /// timer. See [`crate::events::Wake`] and `Chat::wake_on_events`.
    wake_events: Option<crate::events::Wake>,
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
    /// What the exchange last said about a channel, and when, for polling
    /// only. See [`Chat::poll`]'s use of it and `POLL_TTL`.
    told_about: HashMap<[u8; 32], (ChannelInfo, std::time::Instant)>,
    /// SIP-43: where each channel lives, asked once. The exchange that orders
    /// a channel is the one every signature on it names and every receipt
    /// verifies under, and it is this connection's exchange only for a
    /// channel that lives here.
    homes: HashMap<[u8; 32], Home>,
    /// SIP-60: where people this client located live -- their home's key
    /// and domain -- for opening a direct message where it belongs.
    located: HashMap<PubKey, (PubKey, String)>,
    /// SIP-5 §Collection by a device: mail items this device has opened, and so may delete.
    mail_opened: std::collections::HashSet<u64>,
    /// SIP-44 §The handover: channels whose store gap was asked for this run.
    gap_asked: std::collections::HashSet<[u8; 32]>,
    /// SIP-57: the timer this client puts on what it sends, per channel;
    /// seconds, none where unset.
    timers: HashMap<[u8; 32], u32>,
    /// SIP-53: the exchanges a channel was ordered by before its current
    /// origin, newest first. What they signed and receipted verifies under
    /// them, as a key's predecessors do (SIP-40).
    former: HashMap<[u8; 32], Vec<PubKey>>,
    /// SIP-53 §Posting again: forks already dealt with, `(channel, fork)`, so a `Home`
    /// answer read again does not strand again.
    forks_seen: HashSet<([u8; 32], u64)>,
    /// SIP-53 §Posting again: forks met while folding a batch -- a rehome entry read --
    /// dealt with once the batch is done, where a network call is possible.
    pending_forks: Vec<([u8; 32], PubKey, u64)>,
    /// SIP-53 §Posting again: channels whose entries carried a receipt under no origin
    /// this client knows -- the first sign, for a client whose cursor is
    /// above a fork, that the origin changed. Its home is asked again.
    reask_home: HashSet<[u8; 32]>,
    /// SIP-60 §A device hints its home: origins this client has hinted its home at this run.
    hinted: HashSet<PubKey>,
    /// SIP-40: the keys each exchange held before its current one, as the
    /// pin store remembers them, newest first. What was signed under them
    /// still verifies under them and under nothing else.
    predecessors: HashMap<PubKey, Vec<PubKey>>,
    /// Which device belongs to which account, per channel, for the same.
    bound_in: HashMap<[u8; 32], (Bindings, std::time::Instant)>,
    /// The domain this exchange was discovered under (SIP-33), for rendering a
    /// SIP-38 handle as `name@domain`. `None` when reached by a literal
    /// host+key, where there is no domain to show.
    domain: Option<String>,
    /// SIP-40: set when opening this store found rows filed under a key the
    /// pin store says this exchange's key was moved from, and re-filed them.
    /// The interface should say so once; see [`Chat::followed_handover`].
    followed: Option<(PubKey, crate::store::Followed)>,
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
        mut store: Store,
    ) -> Chat {
        // The store is told which exchange it is for here, and only here.
        // Every row about a channel is scoped by it, because a channel
        // identifier is not unique across exchanges: a direct message's is
        // derived from its two accounts, so one conversation has identical
        // channel bytes everywhere it exists.
        //
        // A failure is not fatal and must not be: the scope only fails if the
        // store cannot be written to at all, and a client that refused to
        // start over it would be one nobody could use to find out why. It is
        // reported by the first operation that needs it.
        // Ignored deliberately, and not fatal: this fails only if the store
        // cannot be written to at all, and a client that refused to start over
        // it would be one nobody could use to find out why. The first
        // operation that needs a scope reports it, in words.
        let _ = store.scope_to(&exchange);
        // SIP-40. If the pin store says this key succeeded another, and this
        // store still files anything under the other, the rows follow the
        // pin — before the first poll, so the client never sees an empty
        // exchange and starts a second history beside the real one. Runs on
        // every open and is a no-op once nothing is left under the old key;
        // a store that moved before this existed is repaired the same way.
        let followed = sqex_discovery::Known::load(&sqex_discovery::known::path())
            .ok()
            .and_then(|k| k.predecessor_of(&exchange))
            .filter(|from| store.holds_rows_for(from).unwrap_or(false))
            .and_then(|from| match store.follow_handover(&from, &exchange) {
                Ok(done) => Some((from, done)),
                // Not fatal, for the same reason `scope_to` is not: a store
                // that cannot be written to is reported by the first thing
                // that needs it. The rows stay where they were.
                Err(_) => None,
            });
        let me = store.account().ok().flatten().unwrap_or(device);
        let mut predecessors = HashMap::new();
        predecessors.insert(exchange, predecessors_of(&exchange));
        Chat {
            client,
            seed,
            exchange,
            predecessors,
            receipts: AtomicBool::new(true),
            told_about: HashMap::new(),
            homes: HashMap::new(),
            located: HashMap::new(),
            mail_opened: std::collections::HashSet::new(),
            gap_asked: std::collections::HashSet::new(),
            former: HashMap::new(),
            forks_seen: HashSet::new(),
            pending_forks: Vec::new(),
            reask_home: HashSet::new(),
            hinted: HashSet::new(),
            timers: HashMap::new(),
            bound_in: HashMap::new(),
            domain: None,
            followed,
            endpoint: None,
            via: None,
            link: Link::Up,
            attempts: 0,
            next_dial: Instant::now(),
            dialing: None,
            events: None,
            wake_events: None,
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
    /// [`standing_for`](Self::standing_for) under the first of `keys` whose
    /// receipt verifies. SIP-40: nothing already signed is re-signed, so an
    /// entry receipted before a handover verifies under the key the exchange
    /// held then, and a holder of the moved-from key as history can check
    /// it. `keys` is the current key first, then its predecessors.
    fn standing_under(
        keys: &[PubKey],
        channel: &[u8; 32],
        instance: [u8; 32],
        e: &Entry,
        held: Option<[u8; 32]>,
    ) -> Standing {
        let mut last = Standing::Unclaimed;
        for key in keys {
            last = Self::standing_for(*key, channel, instance, e, held);
            if last != Standing::Repudiated {
                return last;
            }
        }
        last
    }

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
        keys: &[PubKey],
        channel: &[u8; 32],
        instance: [u8; 32],
        e: &Entry,
        chain: &mut HashMap<PubKey, (u64, [u8; 32])>,
        bound: &HashMap<PubKey, Option<PubKey>>,
    ) -> Verdict {
        if e.kind == KIND_SYSTEM {
            return Verdict::Valid;
        }
        // SIP-31 binds the exchange into the signature, and SIP-40 re-signs
        // nothing: an entry from before a handover names the key the
        // exchange held then. Checked under the current key first, then
        // each predecessor the pin store remembers; the one that verifies
        // is the one the chain link is computed under, so a chain that
        // crosses the handover still links.
        let mut terms = None;
        for key in keys {
            let candidate = EntryTerms {
                place: Place {
                    exchange: *key,
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
            // A tombstone's body is gone, so the hash it committed to is the
            // only thing left to check against — which is exactly why the
            // commitment is to the hash and not the bytes.
            let signed =
                if e.body.is_empty() && e.body_hash != Sha256::digest(&[] as &[u8]).as_slice() {
                    verify_entry_hashed(&candidate, &e.body_hash, &e.sig)
                } else {
                    verify_entry(&candidate, &e.sig)
                };
            if signed {
                terms = Some(candidate);
                break;
            }
        }
        let Some(terms) = terms else {
            return Verdict::Forged;
        };
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
    ///
    /// **One `/device/list` per member, all in flight together.** Asked one
    /// after another, a channel of sixty members was sixty round trips --
    /// four seconds against an exchange sixty milliseconds away -- on every
    /// poll that brought an entry, before that entry could be shown. Nothing
    /// about the answer for one account depends on another's.
    async fn bindings(&mut self, accounts: &[PubKey]) -> Result<Bindings> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let asks = accounts
            .iter()
            .map(|account| ListDevices { account: *account }.encode())
            .collect();
        let answers = self
            .post_many_within("/device/list", asks, PATIENCE, LISTS_IN_FLIGHT)
            .await?;
        let mut out = HashMap::new();
        for (account, body) in accounts.iter().zip(answers) {
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
            exchange: self.exchange_of(channel),
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
    async fn create_signed(&mut self, req: Create) -> Result<Created> {
        self.create_signed_at(req, None).await
    }

    /// [`Self::create_signed`], for a channel that is to live at `origin`
    /// (SIP-60): signed under it, carried by this exchange.
    async fn create_signed_at(
        &mut self,
        mut req: Create,
        origin: Option<PubKey>,
    ) -> Result<Created> {
        let instance = {
            use rand_core::RngCore;
            let mut b = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut b);
            b
        };
        req.instance = instance;
        let (actions, _head) = self.actions_for_create(&req, instance)?;
        req.actions = actions;

        let out = match origin {
            Some(origin) => {
                let out = self
                    .post(
                        "/channel/create_at",
                        sqex_proto::channel::CreateAt {
                            origin,
                            create: req.encode(),
                        }
                        .encode(),
                    )
                    .await?;
                // SIP-60 §A device hints its home: the home knows the origin now, and a home from
                // before it does not hint itself.
                let domain = self
                    .homes
                    .get(&req.channel)
                    .map(|h| h.domain.clone())
                    .unwrap_or_default();
                let _ = self.hint_home(&origin, &domain).await;
                out
            }
            None => self.post("/channel/create", req.encode()).await?,
        };
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
        let out = match origin {
            Some(origin) => {
                self.post(
                    "/channel/create_at",
                    sqex_proto::channel::CreateAt {
                        origin,
                        create: req.encode(),
                    }
                    .encode(),
                )
                .await?
            }
            None => self.post("/channel/create", req.encode()).await?,
        };
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
        // SIP-60: under the exchange the channel is to live at, which is
        // this one unless `open_dm` said otherwise.
        let exchange = self.exchange_of(&req.channel);
        let sign = |event: u8,
                    subject: PubKey,
                    arg: &[u8],
                    n: u64,
                    prev_link: [u8; 32]|
         -> Result<(Action, [u8; 32])> {
            let terms = ActionTerms {
                place: Place {
                    exchange,
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

    /// SIP-85: this connection is carried by `home`; keep the carrier, and
    /// open another there when reconnecting finds it closed.
    pub fn via(
        &mut self,
        home: (SocketAddr, [u8; 32]),
        target_key: [u8; 32],
        target_domain: String,
        carrier: Carrier,
    ) {
        self.via = Some(Via {
            home,
            target_key,
            target_domain,
            carrier: Some(carrier),
        });
    }

    /// SIP-85: the home this connection goes through, if any.
    pub fn via_home(&self) -> Option<SocketAddr> {
        self.via.as_ref().map(|v| v.home.0)
    }

    /// The domain this exchange was discovered under, so a SIP-38 handle can be
    /// shown as `name@domain`. Set once, after connecting.
    /// SIP-40: what opening the store re-filed from a predecessor key, if
    /// anything. For the interface to say once — the user's conversations
    /// were briefly somewhere they could not see, and should know why.
    pub fn followed_handover(&self) -> Option<(PubKey, crate::store::Followed)> {
        self.followed.clone()
    }

    pub fn set_domain(&mut self, domain: Option<String>) {
        self.domain = domain;
    }

    /// The domain this client is connected under, if it discovered one.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Resolve a SIP-38 name to the account behind it (`POST /name/resolve`).
    /// `name` is the bare local part; the exchange it is resolved against is the
    /// one this client is connected to. Errors if no account holds the name.
    pub async fn resolve_name(&mut self, name: &str) -> Result<PubKey> {
        let name =
            sqex_proto::name::canonical(name).map_err(|e| ChatError::Protocol(e.to_string()))?;
        let body = self
            .post(
                "/name/resolve",
                sqex_proto::name::Resolve { name: name.clone() }.encode(),
            )
            .await?;
        let r = sqex_proto::name::Resolved::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        if !r.found {
            return Err(ChatError::Protocol(format!("no account is named {name}")));
        }
        Ok(r.account)
    }

    /// Claim a SIP-38 name for this account (`POST /name/claim`).
    ///
    /// Returns the exchange's own outcome — `CLAIM_GRANTED`, `CLAIM_TAKEN`,
    /// `CLAIM_CLOSED` and the rest — rather than an error, because **a refusal
    /// here is an answer and not a fault**. Whether self-claim is offered at
    /// all is the operator's policy: `open` lets anybody take a free name,
    /// `closed` answers `CLAIM_CLOSED` in the reply's own vocabulary, and
    /// `off` does not carry the route. Collapsing those into "it failed" would
    /// leave a caller unable to tell "somebody else has it" from "not here,
    /// ask an administrator".
    ///
    /// The binding is **exchange-asserted**. A name resolving to an account is
    /// that exchange's word for it, and is not evidence of anything about the
    /// account itself; see SIP-38's trust boundary.
    pub async fn claim_name(&mut self, name: &str) -> Result<u8> {
        let name =
            sqex_proto::name::canonical(name).map_err(|e| ChatError::Protocol(e.to_string()))?;
        let body = self
            .post("/name/claim", sqex_proto::name::Claim { name }.encode())
            .await?;
        Ok(sqex_proto::name::ClaimAck::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .outcome)
    }

    /// Give up a SIP-38 name this account holds (`POST /name/release`).
    ///
    /// **A no-op unless this account holds it**, and an acknowledgement either
    /// way — the exchange's `resolve` already discloses who holds a name, so
    /// there is nothing an error here would protect and something it would
    /// leak: whether the caller was the holder.
    ///
    /// Nothing is destroyed. A name is a lease at one exchange, and letting go
    /// of one leaves every conversation, key and counter exactly where it was;
    /// what stops is `name@domain` resolving to this account. Somebody else may
    /// take it afterwards, which is the part worth saying out loud before
    /// anybody presses it.
    pub async fn release_name(&mut self, name: &str) -> Result<()> {
        let name =
            sqex_proto::name::canonical(name).map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.post("/name/release", sqex_proto::name::Release { name }.encode())
            .await?;
        Ok(())
    }

    /// The SIP-38 handles the exchange reports for an account
    /// (`POST /name/reverse`), oldest first. The exchange's word — a hint for
    /// display, never an authority.
    pub async fn reverse_names(&mut self, account: &PubKey) -> Result<Vec<String>> {
        let body = self
            .post(
                "/name/reverse",
                sqex_proto::name::Reverse { account: *account }.encode(),
            )
            .await?;
        Ok(sqex_proto::name::Names::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .names)
    }

    /// The cached handle for an account as `name@domain`, if one is known and a
    /// domain is set. This is the exchange's reverse-lookup, shown *below* a
    /// SIP-21 profile nickname — never in place of one (the display precedence
    /// is profile name → handle → short key, composed by the interface).
    pub fn handle(&self, account: &PubKey) -> Option<String> {
        let (name, _) = self.store.handle(account).ok().flatten()?;
        let domain = self.domain.as_deref()?;
        (!name.is_empty()).then(|| format!("{name}@{domain}"))
    }

    /// A handle on the connection this client holds.
    ///
    /// For another part of the same program to reach the same exchange as the
    /// same identity without dialling again — a call, in practice. It is the
    /// same connection: one handshake, one socket, one keep-alive timer, and
    /// each request its own stream over the one path.
    ///
    /// **Worth more than the handshake it saves.** An exchange fans a relayed
    /// datagram out to every connection an identity holds, so a client holding
    /// a chat connection beside a call connection has every audio frame written
    /// to the one where nothing reads it.
    ///
    /// `None` when there is nothing live to hand out. The handle does not
    /// follow a reconnection either: it belongs to the connection it was taken
    /// from, and a caller that wants the new one asks again.
    ///
    /// Datagrams have a single reader — see `sqnr::Client` — so whoever takes
    /// this is the one that may read them. Nothing here ever does.
    pub fn connection(&self) -> Option<sqnr::Client> {
        (!self.offline()).then(|| self.client.clone())
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

    /// The interface saw the connection fail -- a request of its own that
    /// timed out -- and says so, so the next [`keep_alive`](Self::keep_alive)
    /// redials rather than waiting for this side to notice.
    pub fn link_lost(&mut self) {
        if self.link == Link::Up {
            self.down();
        }
    }

    /// Try again now, whatever the backoff had planned.
    ///
    /// What `/reconnect` is for: `Gone` should have an answer that is not
    /// "restart the client".
    pub fn reconnect_now(&mut self) {
        self.dialing = None;
        self.attempts = 0;
        self.next_dial = Instant::now();
        // SIP-85: through a home, starting over means a fresh tunnel too --
        // the one held may be the thing that went wrong.
        if let Some(carrier) = self.via.as_ref().and_then(|v| v.carrier.as_ref()) {
            carrier.close();
        }
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
            // SIP-85: through a home, **every redial is a fresh tunnel**. A
            // carrier carries one connection: its pump routes replies to the
            // one port it heard from first, so dialling its socket again --
            // while the old endpoint is still retransmitting into it -- put
            // two connections on one pump, and both saw seconds of delay and
            // died within the minute, on repeat. The old carrier is closed
            // here, before the dial, so the old endpoint's packets stop.
            let reopen = self.via.as_mut().map(|v| {
                if let Some(old) = v.carrier.take() {
                    old.close();
                }
                (v.home, v.target_key, v.target_domain.clone())
            });
            self.dialing = Some(Box::pin(async move {
                match reopen {
                    Some((home, target_key, domain)) => {
                        let carrier =
                            Carrier::open(home.0, &home.1, &seed, &target_key, &domain).await?;
                        let client =
                            Client::connect_as(carrier.local_addr(), &server_pub, &seed).await?;
                        Ok((client, Some(carrier)))
                    }
                    None => Ok((Client::connect_as(addr, &server_pub, &seed).await?, None)),
                }
            }));
        }
        let dial = self.dialing.as_mut().expect("just set");
        match tokio::time::timeout(DIAL_SLICE, dial).await {
            // Still handshaking. The future is kept, so the next tick carries
            // on rather than starting over.
            Err(_) => {}
            Ok(Ok((client, carrier))) => {
                self.dialing = None;
                self.client = client;
                if let (Some(via), Some(carrier)) = (self.via.as_mut(), carrier) {
                    self.endpoint = Some((carrier.local_addr(), via.target_key));
                    via.carrier = Some(carrier);
                }
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

    /// Be told when the event stream has something, rather than asking.
    ///
    /// Draining never waits, which is what keeps it out of the keyboard's way,
    /// and it leaves a client that drains on a timer learning about a message
    /// when its timer comes round rather than when the message arrives. Set
    /// this and the stream's reader will notify it as each batch is queued.
    ///
    /// Set it **before** subscribing: the stream open at the time is the one
    /// that was told where to knock.
    pub fn wake_on_events(&mut self, wake: crate::events::Wake) {
        self.wake_events = Some(wake);
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
        match crate::events::Stream::open(&self.client, self.wake_events.clone()).await {
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

    /// Several requests to one route, in flight together, answered in order.
    ///
    /// **A file is fetched a chunk at a time, and each chunk was a round
    /// trip.** Forty chunks against an exchange sixty milliseconds away is
    /// two and a half seconds of waiting before bandwidth counts for
    /// anything. Each request is its own HTTP/3 stream on the one connection
    /// already -- `sqnr::Requests` is a handle on it that needs no borrow of
    /// `Chat` -- so there was never a reason for the second to wait on the
    /// first except that this code did.
    ///
    /// Bounded at [`IN_FLIGHT`], because a hundred-megabyte file is four
    /// hundred chunks and the exchange has other callers. Refused whole on the
    /// first failure, the way one request is, and the link is marked the same
    /// way: any answer proves it, silence or a transport error counts against
    /// it. Every body is a `Vec` because the caller has them all in hand
    /// (chunks to put) or can name them all (chunks to get).
    pub(crate) async fn post_many(
        &mut self,
        path: &str,
        bodies: Vec<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>> {
        self.post_many_within(path, bodies, BLOB_PATIENCE, IN_FLIGHT)
            .await
    }

    /// [`Chat::post_many`] with the deadline and the bound as arguments: a
    /// chunk of a file and a device list are not held to the same clock, and
    /// sixteen small answers in flight is not what eight large ones are.
    async fn post_many_within(
        &mut self,
        path: &str,
        bodies: Vec<Vec<u8>>,
        patience: Duration,
        in_flight: usize,
    ) -> Result<Vec<Vec<u8>>> {
        self.post_each(path, bodies, patience, in_flight)
            .await
            .into_iter()
            .collect()
    }

    /// Several requests to one route, in flight together, **each with its
    /// own answer**. For a caller that would have carried on past one
    /// failure when it asked one at a time -- a profile that would not come
    /// is a name not shown, not a conversation not shown.
    ///
    /// The link is marked from the batch as a whole: any answer at all proves
    /// it, and it is lowered only when nothing answered and something failed
    /// to.
    async fn post_each(
        &mut self,
        path: &str,
        bodies: Vec<Vec<u8>>,
        patience: Duration,
        in_flight: usize,
    ) -> Vec<Result<Vec<u8>>> {
        use futures::stream::StreamExt;
        if self.offline() {
            return bodies
                .iter()
                .map(|_| {
                    Err(ChatError::Transport(
                        "not connected to the exchange".to_string(),
                    ))
                })
                .collect();
        }
        let requests = self.client.requests();
        let path_owned = path.to_string();
        let answers: Vec<std::result::Result<(u16, Vec<u8>), ChatError>> =
            futures::stream::iter(bodies)
                .map(|body| {
                    let requests = requests.clone();
                    let path = path_owned.clone();
                    async move {
                        match tokio::time::timeout(patience, requests.post(&path, body)).await {
                            Ok(Ok(got)) => Ok(got),
                            Ok(Err(e)) => Err(ChatError::Transport(e)),
                            Err(_) => Err(ChatError::Transport(format!(
                                "the exchange stopped answering ({}s)",
                                patience.as_secs()
                            ))),
                        }
                    }
                })
                .buffered(in_flight)
                .collect()
                .await;
        if answers.iter().any(|a| a.is_ok()) {
            self.up();
        } else if answers.iter().any(|a| a.is_err()) {
            self.down();
        }
        answers
            .into_iter()
            .map(|a| match a? {
                (200, body) => Ok(body),
                (code, body) => Err(classify(path, code, &body)),
            })
            .collect()
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
    ///
    /// SIP-44 §The handover: a conversation whose other party changed key keeps its
    /// channel, and is found here before anything is derived.
    pub fn dm_with(&self, them: &PubKey) -> [u8; 32] {
        if let Ok(Some(c)) = self.store.dm_alias(them) {
            return c;
        }
        direct_message_id(&self.me, them)
    }

    /// Make sure the direct message with `them` exists and we hold its key.
    ///
    /// Idempotent: `Create` against a channel we are already in answers without
    /// changing anything, so this is also the ordinary way to reopen one.
    pub async fn open_dm(&mut self, them: &PubKey) -> Result<[u8; 32]> {
        let channel = self.dm_with(them);
        // SIP-60: a direct message lives at the home of the lower key. When
        // that is theirs and elsewhere, it is created there, from here,
        // signed under it; this exchange carries the create and pulls the
        // copy once their home has told it.
        let origin = self
            .located
            .get(them)
            .filter(|(home, _)| *home != self.exchange && them.as_bytes() < self.me.as_bytes())
            .cloned();
        if let Some((home, domain)) = &origin {
            self.homes.insert(
                channel,
                Home {
                    origin: *home,
                    domain: domain.clone(),
                    former: Vec::new(),
                },
            );
            self.store.set_home(&channel, home);
            self.predecessors
                .entry(*home)
                .or_insert_with(|| predecessors_of(home));
        }
        let created = self
            .create_signed_at(
                Create {
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
                },
                origin.as_ref().map(|(h, _)| *h),
            )
            .await;
        // SIP-60 §A direct message opened twice: the identifier was folded here -- the conversation lives
        // at the lower key's home, and this exchange says so by refusing the
        // create as a copy refuses a write. Opened there instead, as SIP-60
        // would have opened it; the copy is read here once it is pulled.
        let mut wait = origin.is_some();
        match created {
            Ok(_) => {}
            Err(ChatError::Refused(_, r))
                if r.code == RefusalCode::Replicated && origin.is_none() =>
            {
                let home = self.home(&channel).await?;
                let there = Create {
                    channel,
                    instance: [0u8; 32],
                    actions: Vec::new(),
                    visibility: Visibility::Private,
                    retention_secs: RETENTION_SECS,
                    max_entries: 0,
                    name: String::new(),
                    topic: String::new(),
                    invites: vec![Invitee {
                        account: *them,
                        role: Role::Admin,
                    }],
                };
                self.create_signed_at(there, Some(home.origin)).await?;
                wait = true;
            }
            Err(e) => return Err(e),
        }
        if wait {
            // The copy arrives once their home has told this exchange and
            // it has pulled; a message opened elsewhere is not readable
            // here until then.
            let mut here = false;
            for _ in 0..50 {
                if self.info(&channel).await.is_ok() {
                    here = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            if !here {
                return Err(ChatError::OriginAway);
            }
        }

        self.collect_keys(&channel).await?;
        Ok(channel)
    }

    // ---- SIP-44 §The handover: account key handover ------------------------------------

    /// Hand this account over to a new key while the old one is still
    /// held: the will under the account's key, a credential from the new
    /// key for each device the account has (this one included), presented
    /// together. On success this client acts for the successor, the new
    /// seed is kept sealed in the store, and the conversations this
    /// account had by derived identifier are remembered under the new key.
    /// `new_seed` is made here when not given.
    pub async fn handover(&mut self, new_seed: Option<[u8; 32]>) -> Result<PubKey> {
        let old_seed = self.account_seed().ok_or_else(|| {
            ChatError::Protocol(format!(
                "this client acts for {} and cannot sign for it; sign the will and the \
                 credentials with the account's key and pass them with --signed",
                self.me
            ))
        })?;
        let new_seed = new_seed.unwrap_or_else(|| {
            use rand_core::RngCore;
            let mut b = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut b);
            b
        });
        let new = PubKey::new(
            ed25519_dalek::SigningKey::from_bytes(&new_seed)
                .verifying_key()
                .to_bytes(),
        );
        let will = sqex_proto::succession::Will::sign(&old_seed, &new, now_secs());
        let mut devices: Vec<PubKey> = self.my_devices().await?.iter().map(|d| d.device).collect();
        if devices.is_empty() {
            devices.push(self.device);
        }
        let now = now_secs();
        let credentials = devices
            .iter()
            .map(|d| {
                Credential::issue(
                    &new_seed,
                    d,
                    SCOPE_CHAT,
                    now.saturating_sub(60),
                    now + 90 * 86_400,
                )
                .map_err(|e| ChatError::Protocol(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        self.handover_signed(will, credentials).await?;
        self.store.set_account_seed(&new_seed)?;
        Ok(new)
    }

    /// Present a handover signed elsewhere -- the will by the account, the
    /// credentials by the successor (SIP-58) -- and become the successor's
    /// device. The conversations this account had by derived identifier
    /// are remembered under the new key.
    pub async fn handover_signed(
        &mut self,
        will: sqex_proto::succession::Will,
        credentials: Vec<Credential>,
    ) -> Result<()> {
        let old = self.me;
        let new = will.successor;
        let mine = credentials
            .iter()
            .find(|c| c.delegate == self.device)
            .cloned()
            .ok_or_else(|| {
                ChatError::Protocol("no credential in the handover names this device".into())
            })?;
        // The direct messages this account is in, by the old derivation,
        // before the seats move.
        let mut dms: Vec<(PubKey, [u8; 32])> = Vec::new();
        for m in self.mine().await? {
            if let Ok(info) = self.info(&m.channel).await
                && info.members.len() == 2
                && let Some(other) = info.members.iter().map(|x| x.account).find(|a| *a != old)
                && direct_message_id(&old, &other) == m.channel
            {
                dms.push((other, m.channel));
            }
        }
        self.post(
            "/account/handover",
            sqex_proto::succession::Handover { will, credentials }.encode(),
        )
        .await?;
        self.store.set_credential(&mine.encode())?;
        self.store.set_account(&new)?;
        self.me = new;
        for (other, channel) in dms {
            self.store.set_dm_alias(&other, &channel)?;
        }
        Ok(())
    }

    /// SIP-44 §The handover: a correspondent's key changed, seen in a channel's log. The
    /// contact follows; where the channel was the direct message with the
    /// old key, it is the direct message with the new.
    fn follow_correspondent(&mut self, channel: &[u8; 32], old: &PubKey, new: &PubKey) {
        if *old == self.me || *new == self.me {
            return;
        }
        let _ = self.store.rekey_contact(old, new);
        if direct_message_id(&self.me, old) == *channel
            || self.store.dm_alias(old).ok().flatten() == Some(*channel)
        {
            let _ = self.store.set_dm_alias(new, channel);
        }
    }

    // ---- SIP-60: reaching someone at another exchange -----------------------

    /// Find somebody at another exchange through this one: their key, their
    /// home and their devices. Remembered, so a direct message with them is
    /// opened where it lives.
    pub async fn locate(&mut self, target: &str) -> Result<sqex_proto::locate::Located> {
        let body = self
            .post(
                "/account/locate",
                sqex_proto::locate::Locate {
                    target: target.trim().to_string(),
                }
                .encode(),
            )
            .await?;
        let found = sqex_proto::locate::Located::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.located
            .insert(found.account, (found.home, found.domain.clone()));
        Ok(found)
    }

    /// Where this client last located `account`, if it did.
    pub fn located_home(&self, account: &PubKey) -> Option<&(PubKey, String)> {
        self.located.get(account)
    }

    /// SIP-60: say where this account lives, once. Where the exchange has
    /// no Move on record for it, sign one naming this exchange and present
    /// it -- which is what lets the home act when an origin tells it of a
    /// channel. Only a client holding the account key; a linked device
    /// leaves it to the account.
    ///
    /// SIP-60 §When a client presents a Move unasked: and only where this store is filed under this exchange, or
    /// under none yet. Pointed at an exchange the account has never used,
    /// SIP-60's rule moved the account there on the way in -- a wrong
    /// `--server-host`, a probe -- with no origins, so the real home was
    /// never told. Here the client is a [`HomeSaid::Visitor`] and presents
    /// nothing. A Move it does present names the home it leaves, as
    /// `move` does.
    pub async fn ensure_home(&mut self) -> Result<HomeSaid> {
        if self.account_seed().is_none() {
            return Ok(HomeSaid::NotMine);
        }
        let me = self.me;
        let record = match self.account_home(&me).await {
            Ok(h) => (h.since != 0).then_some((h.home, h.since)),
            Err(ChatError::NoChatHere(_)) => return Ok(HomeSaid::NotMine),
            Err(ChatError::Refused(404, _)) => None,
            Err(e) => return Err(e),
        };
        let exchange = self.exchange;
        if let Some(home) = self.store.filed_under()?
            && home != exchange
        {
            // SIP-60 §When a client presents a Move unasked: a visitor. Where this exchange records *itself* as
            // the home, one of two parties is behind: this exchange (a
            // Move made here by accident, never displaced) or this store
            // (another device moved the account here since). Only the
            // first is told, and only where the store can show it -- the
            // Move that filed the store is later than this record. A store
            // that cannot show it acts on nothing and says so; acting
            // would move the account back over the other device's Move.
            let told = match (record, self.store.home_issued()?) {
                (Some((at, since)), Some(issued)) if at == exchange && issued > since => {
                    let mv = self.sign_move(&home)?;
                    self.store.record_home_issued(mv.issued)?;
                    self.present_move(&sqex_proto::home::Moving {
                        mv,
                        domain: String::new(),
                        origins: Vec::new(),
                    })
                    .await
                    .is_ok()
                }
                _ => false,
            };
            let behind = matches!(record, Some((at, _)) if at == exchange) && !told;
            return Ok(HomeSaid::Visitor { home, told, behind });
        }
        if record.is_some() {
            return Ok(HomeSaid::OnRecord);
        }
        // SIP-60 §When a client presents a Move unasked (2026-09-21): a store
        // that has never made or presented a Move is a new one, filed under
        // this exchange by nothing but its first connection. Its first Move
        // is the person's to make, not this client's to guess: a probe
        // pointed at the wrong exchange moved a live account this way.
        if self.store.home_issued()?.is_none() {
            return Ok(HomeSaid::Unclaimed);
        }
        self.present_first_move().await?;
        Ok(HomeSaid::Presented)
    }

    /// The account's first "this is my home", or its home again: present a
    /// Move naming the exchange this client is connected to. The person's
    /// act -- a client that found [`HomeSaid::Unclaimed`] calls this only
    /// where the person named this exchange as the home. Refused where the
    /// store is filed under another exchange (that is a move, `move_home`)
    /// or this exchange already records the account's home elsewhere.
    pub async fn claim_home(&mut self) -> Result<HomeSaid> {
        if self.account_seed().is_none() {
            return Ok(HomeSaid::NotMine);
        }
        let exchange = self.exchange;
        if let Some(home) = self.store.filed_under()?
            && home != exchange
        {
            return Err(ChatError::Protocol(format!(
                "this store lives at {home}; moving it is `move`, not a claim"
            )));
        }
        let me = self.me;
        match self.account_home(&me).await {
            Ok(h) if h.since != 0 && h.home != exchange => {
                return Err(ChatError::Protocol(format!(
                    "this exchange records the account's home as {}; move there, or from there",
                    h.home
                )));
            }
            Ok(h) if h.since != 0 => return Ok(HomeSaid::OnRecord),
            Ok(_) | Err(ChatError::Refused(404, _)) => {}
            Err(ChatError::NoChatHere(_)) => return Ok(HomeSaid::NotMine),
            Err(e) => return Err(e),
        }
        self.present_first_move().await?;
        Ok(HomeSaid::Presented)
    }

    /// SIP-60 §When a client presents a Move unasked (2026-09-21): record
    /// the exchange this client is connected to as the account's home,
    /// beside the identity (`<identity>.home`), where every start reads it
    /// as the default exchange -- unless this exchange records the account
    /// as living elsewhere, in which case nothing is written and `None` is
    /// returned. What a claim, a reach-out from the home session and a
    /// restore (a backup lives at the home) all record; idempotent when the
    /// sidecar already names this exchange. A linked device records its
    /// account's home the same way.
    pub async fn record_home_beside(
        &mut self,
        identity: &std::path::Path,
    ) -> Result<Option<sqex_proto::home_file::Home>> {
        let me = self.me;
        let exchange = self.exchange;
        match self.account_home(&me).await {
            Ok(h) if h.since != 0 && h.home != exchange => return Ok(None),
            Ok(_) | Err(ChatError::Refused(404, _)) | Err(ChatError::NoChatHere(_)) => {}
            Err(e) => return Err(e),
        }
        let home = sqex_proto::home_file::Home {
            domain: self.domain.clone(),
            key: Some(exchange),
        };
        if !sqex_proto::home_file::load(identity)
            .is_some_and(|h| h.names(&exchange, self.domain.as_deref()))
        {
            sqex_proto::home_file::set(identity, &home).map_err(ChatError::Protocol)?;
        }
        Ok(Some(home))
    }

    async fn present_first_move(&mut self) -> Result<()> {
        let exchange = self.exchange;
        let mv = self.sign_move(&exchange)?;
        let domain = self.domain.clone().unwrap_or_default();
        let origins = self.origins_of_mine().await.unwrap_or_default();
        self.store.record_home_issued(mv.issued)?;
        self.present_move(&sqex_proto::home::Moving {
            mv,
            domain,
            origins,
        })
        .await?;
        Ok(())
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
            return self.epoch_settled(channel, 1).await;
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
                let after = self.epoch_settled(channel, info.epoch + 1).await?;
                return self
                    .store
                    .key(channel, after)?
                    .map(|_| after)
                    .ok_or(ChatError::NoKey(after));
            }
        }
        Ok(info.epoch)
    }

    /// The channel's epoch as this exchange reports it, once it is at least
    /// `at_least`. At the origin that is at once; at a copy (SIP-43,
    /// SIP-60) the rotation was carried to the origin and comes back with
    /// the next pull, which the copy makes promptly after a forward -- so
    /// this waits a little rather than posting under the epoch before.
    async fn epoch_settled(&mut self, channel: &[u8; 32], at_least: u32) -> Result<u32> {
        let mut epoch = self.info(channel).await?.epoch;
        if epoch >= at_least || self.homed_elsewhere(channel).is_none() {
            return Ok(epoch);
        }
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            epoch = self.info(channel).await?.epoch;
            if epoch >= at_least {
                break;
            }
        }
        Ok(epoch)
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
                    &self.exchange_of(channel),
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
        self.absorb_keys(channel, &instance, got).await
    }

    /// Open the envelopes a `Got` carries and keep what they hold. The
    /// second half of [`collect_keys`](Self::collect_keys), on its own so a
    /// A catch-up (SIP-47 §The catch-up answer) -- which carries a `Got` per channel -- opens them
    /// through exactly this and no second implementation of the prekey rules.
    async fn absorb_keys(
        &mut self,
        channel: &[u8; 32],
        instance: &[u8; 32],
        got: Got,
    ) -> Result<usize> {
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
            // Under any key the channel's receipts verify under: the
            // exchange that orders it, its earlier keys (SIP-40, SIP-40 §Lineage)
            // and the exchanges that ordered it before (SIP-53) -- the
            // envelope names the place as it was when published.
            let addressed = Envelope {
                recipient: self.device,
                ..env.clone()
            };
            if !self
                .keys_of(channel)
                .iter()
                .any(|key| verify_envelope(key, instance, channel, env.from_epoch, &addressed))
            {
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

    /// SIP-60 §Reading the folded log: the folded log of a direct message this exchange ended, as
    /// `/channel/folded` answers it to either member -- `None` where there
    /// is none, or this client is not one of the two.
    pub async fn folded_entries(&mut self, channel: &[u8; 32]) -> Result<Option<Entries>> {
        let body = match self
            .post(
                "/channel/folded",
                ByChannel { channel: *channel }.encode(sqex_proto::channel::TYPE_FOLDED),
            )
            .await
        {
            Ok(body) => body,
            Err(ChatError::Refused(_, r)) if r.code == RefusalCode::NoSuchChannel => {
                return Ok(None);
            }
            Err(ChatError::Refused(_, r)) if r.code == RefusalCode::NotFound => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        Entries::decode(&body, false)
            .map(Some)
            .map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// SIP-60 §The client keeps what it read: before the incarnation this client holds is reset, read what
    /// it had not yet read of it from the folded log, under the keys still
    /// held and the incarnation it was signed in -- so what goes to history
    /// is whole. Best effort: an exchange with no folded log, or a channel
    /// that was simply rebuilt, has nothing to add.
    async fn read_folded(
        &mut self,
        timeline: &mut Timeline,
        channel: &[u8; 32],
        info: &ChannelInfo,
        known: [u8; 32],
        admins: &[PubKey],
    ) {
        // **Once.** A client that polled in the gap between the fold and the
        // home's copy arriving has already archived this incarnation from
        // the folded log (`folded_away`), and its reset took the cursor with
        // it -- so a second reading here would find every entry "unread",
        // fold the whole log into the store again, and the reset that
        // follows would archive the same stray twice. CI saw two copies
        // where the laptop, whose pull lands before the next poll, saw one.
        if self.store.archived(channel, &known).unwrap_or(false) {
            return;
        }
        let Ok(Some(folded)) = self.folded_entries(channel).await else {
            return;
        };
        let (since, _, _) = self.store.cursor(channel).unwrap_or_default();
        let unread: Vec<Entry> = folded
            .entries
            .into_iter()
            .filter(|e| e.seq > since)
            .collect();
        if unread.is_empty() {
            return;
        }
        // The stray was ordered by the exchange this client is at, whatever
        // `/channel/home` says of the identifier now; SIP-53 keeps the
        // exchanges that ordered a channel before, and this is one.
        let here = self.exchange;
        let former = self.former.entry(*channel).or_default();
        if !former.contains(&here) {
            former.push(here);
        }
        let was = ChannelInfo {
            instance: known,
            ..info.clone()
        };
        let bound = self.bindings(&members_of(&was)).await.unwrap_or_default();
        // A failure here loses nothing that was read: the fold below keeps
        // what the store holds, and the log stays at the exchange.
        let _ = self.fold_entries(
            timeline, channel, &was, admins, &bound, &unread, since, false,
        );
    }

    /// SIP-60 §The client keeps what it read: the earlier incarnations of a channel this client read --
    /// each folded as `history` folds the current one, oldest first. Shown
    /// before the conversation, and never merged into it: their sequence
    /// numbers belong to channels that no longer exist.
    pub fn earlier(&self, channel: &[u8; 32], admins: &[PubKey]) -> Result<Vec<Timeline>> {
        let mut out = Vec::new();
        for generation in self.store.message_history(channel)? {
            let mut timeline = Timeline::new();
            for (seq, account, posted, kind, plain) in generation {
                timeline.apply(
                    &Received {
                        seq,
                        account,
                        posted,
                        kind,
                        verdict: Verdict::Valid,
                        tombstone: plain.as_ref().is_some_and(|p| p.is_empty()),
                        standing: Standing::Unclaimed,
                        system: (kind == KIND_SYSTEM)
                            .then(|| {
                                plain
                                    .as_deref()
                                    .and_then(|p| System::decode(p).ok().flatten())
                            })
                            .flatten(),
                        body: (kind == KIND_MEMBER)
                            .then(|| plain.and_then(|p| Body::decode(&p).ok().flatten()))
                            .flatten(),
                    },
                    admins,
                );
            }
            out.push(timeline);
        }
        // Oldest first, by the time of the first thing each holds: the
        // numbering is local, and a generation a sibling handed over may
        // have been numbered after one that came before it.
        out.sort_by_key(|t| t.messages().next().map(|m| m.posted).unwrap_or(0));
        Ok(out)
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
                    // Two decoders, chosen by kind and never both: a system
                    // entry carries SIP-16's own layout and a member entry a
                    // SIP-19 body, and neither decoder would make sense of the
                    // other's bytes.
                    system: (kind == KIND_SYSTEM)
                        .then(|| {
                            plain
                                .as_deref()
                                .and_then(|p| System::decode(p).ok().flatten())
                        })
                        .flatten(),
                    body: (kind == KIND_MEMBER)
                        .then(|| plain.and_then(|p| Body::decode(&p).ok().flatten()))
                        .flatten(),
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

    /// SIP-5 §Collection by a device: the mail waiting for this device and for its account, as
    /// the exchange lists them together.
    pub async fn mail_list(&mut self) -> Result<sqex_proto::mailbox::Listing> {
        let body = self.post("/mailbox/list", Vec::new()).await?;
        sqex_proto::mailbox::Listing::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// SIP-5 §Collection by a device: fetch and open one item with every key this device holds --
    /// its own, then the account's (SIP-44 §Which account a device is). `Ok(None)` where
    /// there is no such item; `Err(MailSealedElsewhere)` where it is for a
    /// key this device does not hold, which it must then not delete.
    pub async fn mail_read(&mut self, id: u64) -> Result<Option<(PubKey, Vec<u8>)>> {
        let body = self
            .post(
                "/mailbox/fetch",
                sqex_proto::mailbox::ById::fetch(id).encode(),
            )
            .await?;
        let f = sqex_proto::mailbox::Fetched::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        if !f.found {
            return Ok(None);
        }
        let mut keys = vec![self.seed];
        if let Some(seed) = self.account_seed()
            && seed != self.seed
        {
            keys.push(seed);
        }
        for seed in &keys {
            if let Ok(plain) = sqex_proto::mailbox::open(seed, &f.sealed) {
                self.mail_opened.insert(id);
                return Ok(Some((f.sender, plain)));
            }
        }
        Err(ChatError::MailSealedElsewhere(id))
    }

    /// SIP-5 §Collection by a device: complete collection of an item this device has read. An
    /// item it has not opened is refused here rather than at the exchange:
    /// deleting completes collection for every device of the account.
    pub async fn mail_delete(&mut self, id: u64) -> Result<bool> {
        // Not opened in this process -- a command-line client runs one
        // command per process -- so it is fetched and opened now; an item
        // this device cannot open is refused by the read.
        if !self.mail_opened.contains(&id) && self.mail_read(id).await?.is_none() {
            return Ok(false);
        }
        let body = self
            .post(
                "/mailbox/delete",
                sqex_proto::mailbox::ById::delete(id).encode(),
            )
            .await?;
        Ok(body.first().copied().unwrap_or(0) != 0)
    }

    // ---- SIP-44 succession: what to do before a key is lost, and after ----
    //
    // The CLI has had all of this since SIP-44 landed, posting the routes by
    // hand; a graphical client had no way to reach any of it, so sigil's own
    // documentation said "done from a terminal today". These are the same
    // five acts with the same refusals, in the client where the account is.

    /// SIP-44 §The will: sign that `successor` may take this account, to be
    /// presented by that key when this one is gone.
    ///
    /// Only the account itself can write one -- a linked device holds the
    /// account's credential and not its seed, and a will it signed would be
    /// the device's, which nobody can succeed to. Refused in words there,
    /// and for an account naming itself.
    pub fn sign_will(&self, successor: &PubKey) -> Result<sqex_proto::succession::Will> {
        if self.me != self.device {
            return Err(ChatError::Protocol(
                "only the account itself can write a will; this is one of its devices".into(),
            ));
        }
        if *successor == self.me {
            return Err(ChatError::Protocol(
                "an account cannot succeed itself".into(),
            ));
        }
        Ok(sqex_proto::succession::Will::sign(
            &self.seed,
            successor,
            now_secs(),
        ))
    }

    /// SIP-44 §Guardians: sign a policy naming who may name this account's
    /// successor, and how many of them it takes. The account's own act, as
    /// a will is; `Policy::sign` refuses one that could never be met.
    pub fn sign_policy(
        &self,
        threshold: u8,
        guardians: &[PubKey],
    ) -> Result<sqex_proto::succession::Policy> {
        if self.me != self.device {
            return Err(ChatError::Protocol(
                "only the account itself can name guardians; this is one of its devices".into(),
            ));
        }
        sqex_proto::succession::Policy::sign(&self.seed, threshold, guardians, now_secs())
            .map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// SIP-44 §Guardians: lodge a policy at the exchange, where the guardians
    /// and the successor can find it when the account cannot be asked.
    pub async fn lodge_policy(&mut self, policy: &sqex_proto::succession::Policy) -> Result<()> {
        self.post("/account/lodge", policy.encode()).await?;
        Ok(())
    }

    /// SIP-44 §Guardians: the policy lodged for `account`, if any.
    pub async fn lodged_policy(
        &mut self,
        account: &PubKey,
    ) -> Result<Option<sqex_proto::succession::Policy>> {
        match self
            .post("/account/lodged", sqex_proto::succession::ask(account))
            .await
        {
            Ok(body) => Ok(Some(
                sqex_proto::succession::Policy::decode(&body)
                    .map_err(|e| ChatError::Protocol(e.to_string()))?,
            )),
            // Not succeeded, or nothing lodged -- and an exchange from
            // before the route says the same thing in the router's words.
            Err(ChatError::Refused(404, _)) | Err(ChatError::NoChatHere(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// SIP-44 §Guardians: as a guardian, sign that `successor` succeeds
    /// `account` -- your word, to be given to the successor to collect.
    pub fn vouch(&self, account: &PubKey, successor: &PubKey) -> sqex_proto::succession::Vouch {
        sqex_proto::succession::Vouch::sign(&self.seed, account, successor, now_secs())
    }

    /// SIP-44 §The successor: present a proof -- a will, or a policy with the
    /// vouches that meet it -- and take the account it names.
    ///
    /// Checked here before it is sent, in the same words the CLI uses: the
    /// proof has to name *this* key as successor, and has to prove it. The
    /// exchange checks both again and moves the account's names, channels
    /// and place in each to this key; its old devices are nobody's after.
    pub async fn succeed(&mut self, proof: sqex_proto::succession::Proof) -> Result<()> {
        if proof.successor() != Some(self.device) {
            return Err(ChatError::Protocol(
                "this proof names somebody else as successor".into(),
            ));
        }
        if !proof.proves(&self.device) {
            return Err(ChatError::Protocol(
                "this proof does not prove it: a signature is wrong, or the quorum is short".into(),
            ));
        }
        self.post(
            "/account/succeed",
            sqex_proto::succession::Claim { proof }.encode(),
        )
        .await?;
        Ok(())
    }

    /// SIP-44: what the exchange recorded of `account`'s succession, if it
    /// was succeeded.
    pub async fn succession_of(
        &mut self,
        account: &PubKey,
    ) -> Result<Option<sqex_proto::succession::Succeeded>> {
        match self
            .post("/account/succession", sqex_proto::succession::ask(account))
            .await
        {
            Ok(body) => Ok(Some(
                sqex_proto::succession::Succeeded::decode(&body)
                    .map_err(|e| ChatError::Protocol(e.to_string()))?,
            )),
            // Not succeeded, or nothing lodged -- and an exchange from
            // before the route says the same thing in the router's words.
            Err(ChatError::Refused(404, _)) | Err(ChatError::NoChatHere(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// SIP-44 §Which account a device is: whose device this is, as the registry has it -- the one party
    /// that knows after a handover moved it.
    pub async fn whose(&mut self) -> Result<sqex_proto::device::Whose> {
        if self.offline() {
            return Err(ChatError::Transport(
                "not connected to the exchange".to_string(),
            ));
        }
        let got = match tokio::time::timeout(PATIENCE, self.client.get("/device/account")).await {
            Ok(Ok(got)) => {
                self.up();
                got
            }
            Ok(Err(e)) => {
                self.down();
                return Err(ChatError::Transport(e));
            }
            Err(_) => {
                self.down();
                return Err(ChatError::Transport(
                    "the exchange stopped answering".into(),
                ));
            }
        };
        let (code, body) = got;
        if code != 200 {
            return Err(classify("/device/account", code, &body));
        }
        sqex_proto::device::Whose::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// SIP-44 §Which account a device is: follow this device's own account as the registry has it.
    /// Where the account answered is not the one the store names -- a
    /// handover (SIP-44 §The handover) presented from a sibling moved this device -- the
    /// store's account, its credential and its direct messages follow, as
    /// the presenting device's did. Returns the account followed to, if any.
    pub async fn follow_account(&mut self) -> Result<Option<PubKey>> {
        let whose = match self.whose().await {
            Ok(w) => w,
            // An exchange from before 0.84.0 has no such answer; the store
            // stands.
            Err(ChatError::Refused(404, _)) | Err(ChatError::NoChatHere(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        if whose.device != self.device || whose.account == self.me {
            return Ok(None);
        }
        let old = self.me;
        let new = whose.account;
        // The direct messages this device holds by the old derivation,
        // before the account changes under them.
        //
        // The exchange has already moved the membership to the new key
        // (SIP-44 §The handover: channels follow), so the members are `new` and the
        // other party, in whichever order the exchange lists them. The
        // other party is the one that is neither -- taking "the first that
        // is not `old`" found `new` half the time and derived nothing.
        let mut dms: Vec<(PubKey, [u8; 32])> = Vec::new();
        for m in self.mine().await? {
            if let Ok(info) = self.info(&m.channel).await
                && info.members.len() == 2
                && let Some(other) = info
                    .members
                    .iter()
                    .map(|x| x.account)
                    .find(|a| *a != old && *a != new)
                && direct_message_id(&old, &other) == m.channel
            {
                dms.push((other, m.channel));
            }
        }
        if new == self.device {
            // The account itself now, which needs no credential.
            self.store.set_account(&new)?;
            self.me = new;
        } else {
            self.claim_listed(&new).await?;
        }
        for (other, channel) in dms {
            self.store.set_dm_alias(&other, &channel)?;
        }
        Ok(Some(new))
    }

    /// SIP-47 §Pairing, step 3: a device that was registered by a sibling
    /// and holds no credential finds itself in `account`'s device list, with
    /// the credential the sibling presented (SIP-32), and only then treats
    /// the account as its own. It keeps the credential -- SIP-42's `Hello`
    /// needs it -- publishes prekeys under its own key so it can be sealed
    /// to, and collects whatever its siblings already sealed.
    ///
    /// The list is public and the credential names both keys in the clear;
    /// nothing here is taken on the exchange's word. The credential is
    /// verified under `account` for this device before anything is written.
    pub async fn claim_listed(&mut self, account: &PubKey) -> Result<Credential> {
        let body = self
            .post("/device/list", ListDevices { account: *account }.encode())
            .await?;
        let listed = Devices::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        let mine = listed
            .devices
            .iter()
            .find(|d| d.device == self.device)
            .ok_or(ChatError::NotListed(*account))?;
        let credential = mine.credential.clone().ok_or_else(|| {
            ChatError::Protocol("the registration carries no credential (SIP-32)".into())
        })?;
        if credential.delegate != self.device
            || credential.account != *account
            || credential.verify(account, SCOPE_CHAT, listed.now).is_err()
        {
            return Err(ChatError::NotListed(*account));
        }
        self.store.set_credential(&credential.encode())?;
        self.store.set_account(account)?;
        self.me = *account;
        self.top_up_prekeys().await?;
        for m in self.mine().await? {
            let _ = self.collect_keys(&m.channel).await;
        }
        Ok(credential)
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
        let seed = self.account_seed().ok_or_else(|| {
            ChatError::Protocol(format!(
                "this client acts for {} and cannot sign for it; `sqex device link` with the \
                 account's key instead",
                self.me
            ))
        })?;
        Credential::issue(&seed, device, SCOPE_CHAT, now, now + lifetime)
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
        // Kept, and acted on: the credential is what this device shows a
        // sibling (SIP-42), and the account is what it is from now on.
        self.store.set_credential(&credential.encode())?;
        self.store.set_account(&credential.account)?;
        self.me = credential.account;
        Ok(())
    }

    /// SIP-47 §Pairing, step 2: register **another** device of this account,
    /// from this one.
    ///
    /// The exchange takes a registration from "the delegate itself, or an
    /// already-registered device of the same account" -- and only
    /// [`register_self`](Self::register_self) existed, which is the first
    /// kind. So the second kind had no producer anywhere: a phone showed its
    /// key, a desktop wrote a credential for it, and the phone's
    /// [`claim_listed`](Self::claim_listed) then looked for itself in the
    /// account's list and was never there, because writing a credential is
    /// not registering anything. The way that did work was carrying the
    /// credential across by hand.
    ///
    /// This is the posting. It touches nothing local: the store's account,
    /// credential and identity stay this device's own, since the credential
    /// is somebody else's. The caller must be registered here itself
    /// (`register_self` first, as `sigil` does), or the exchange refuses it as
    /// not authorised -- an account acting as its own device has no
    /// registration for the exchange to look up.
    pub async fn register_device(&mut self, credential: &Credential) -> Result<()> {
        if credential.delegate == self.device {
            return Err(ChatError::Protocol(
                "that credential names this device; use register_self".into(),
            ));
        }
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

    /// This device's own credential, if it has one: what it presents to a
    /// sibling (SIP-42). A device that is its own account has none.
    pub fn credential(&self) -> Option<Credential> {
        self.store
            .credential()
            .ok()
            .flatten()
            .and_then(|b| Credential::decode(&b).ok())
    }

    /// The exchange's key, which every receipt here is under.
    pub fn exchange_key(&self) -> PubKey {
        self.exchange
    }

    /// One try at meeting one of this account's other devices (SIP-42):
    /// a SIP-12 `open` toward `sibling` on this connection, offering
    /// `ephemeral`. `None` while they have not opened toward us, or while
    /// the exchange is out of reach; `Some` is the live session and the
    /// link it runs on.
    ///
    /// Returns a future that borrows nothing from this client, so a session
    /// loop that is itself a spawned task can await it: `Chat` holds a
    /// SQLite connection and is not `Sync`, and an `async fn` on `&self`
    /// would hold `&Chat` across the await.
    pub fn meet_sibling(
        &self,
        ephemeral: &x25519_dalek::StaticSecret,
        sibling: &PubKey,
    ) -> impl std::future::Future<
        Output = Result<Option<(crate::sync::Relayed, sqex_proto::session::Session)>>,
    > + Send
    + 'static {
        let client = self.connection();
        let seed = self.seed;
        let ephemeral = ephemeral.clone();
        let sibling = *sibling;
        async move {
            let Some(client) = client else {
                return Ok(None);
            };
            crate::sync::Relayed::meet(client, &seed, &ephemeral, &sibling).await
        }
    }

    /// Whether the exchange lists `device` for this account today (SIP-42's
    /// door checks the current list, not a remembered one), and the
    /// exchange's clock, to judge a credential by. An account with no
    /// linked device is its own device.
    pub async fn sibling_listed(&mut self, device: &PubKey) -> Result<(bool, u64)> {
        let body = self
            .post("/device/list", ListDevices { account: self.me }.encode())
            .await?;
        let listed = Devices::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        let found = if listed.devices.is_empty() {
            *device == self.me
        } else {
            listed
                .devices
                .iter()
                .any(|d| d.device == *device && d.not_after >= listed.now)
        };
        Ok((found, listed.now))
    }

    /// What a sibling could be handed (SIP-42): every channel with signed
    /// entries held, its instance, the range, and how many epoch keys.
    pub fn held_for_siblings(&self) -> Result<Vec<crate::sync::Held>> {
        let mut out = Vec::new();
        for (channel, first, last) in self.store.entry_ranges()? {
            let instance = self.store.incarnation(&channel)?.unwrap_or([0; 32]);
            let epochs = self.store.keys_of(&channel)?.len() as u16;
            out.push(crate::sync::Held {
                channel,
                instance,
                first,
                last,
                epochs,
            });
        }
        Ok(out)
    }

    /// SIP-42 §Generations: the ended incarnations this device keeps, as a sibling is
    /// offered them.
    pub fn held_generations(&self) -> Result<Vec<crate::store::Generation>> {
        Ok(self
            .store
            .generations()?
            .into_iter()
            // A generation with no signed entry has nothing a sibling can
            // verify, and is not offered.
            .filter(|g| g.last > 0)
            .collect())
    }

    /// SIP-42 §Generations: whether `key` is an exchange this device knows -- the one
    /// it talks to, one a channel of its lives or lived at, or an earlier
    /// key of one of those. A sibling's word for an origin it does not
    /// know is not taken.
    pub fn knows_exchange(&self, key: &PubKey) -> bool {
        if *key == self.exchange {
            return true;
        }
        if self.homes.values().any(|h| h.origin == *key) {
            return true;
        }
        if self.former.values().any(|f| f.contains(key)) {
            return true;
        }
        self.predecessors
            .iter()
            .any(|(k, older)| k == key || older.contains(key))
    }

    /// SIP-42 §Generations: take a sibling's entries of an ended incarnation as a
    /// generation. Verified as `import` verifies the live one -- each
    /// entry's signature, its device's credential, the chain -- with the
    /// receipts under `origin` and its earlier keys in place of the
    /// exchange the channel lives at. What verifies is kept signed, opened
    /// under the generation's keys, and shown as an earlier copy. Returns
    /// how many entries were new.
    pub async fn import_earlier(
        &mut self,
        channel: &[u8; 32],
        instance: [u8; 32],
        origin: &PubKey,
        entries: &[Entry],
    ) -> Result<usize> {
        if entries.is_empty() {
            return Ok(0);
        }
        let generation = match self.store.generation_of(channel, &instance)? {
            Some(g) => g,
            None => self
                .store
                .new_generation(channel, &instance, origin.as_bytes())?,
        };
        let mut keys = vec![*origin];
        keys.extend(
            self.predecessors
                .entry(*origin)
                .or_insert_with(|| predecessors_of(origin))
                .iter()
                .copied(),
        );
        let mut accounts: Vec<PubKey> = entries.iter().map(|e| e.account).collect();
        accounts.sort();
        accounts.dedup();
        let bound = self.bindings(&accounts).await.unwrap_or_default();
        let epoch_keys: HashMap<u32, ChannelKey> = self
            .store
            .history_keys(channel, generation)?
            .into_iter()
            .collect();
        let mut chains: HashMap<PubKey, (u64, [u8; 32])> = HashMap::new();
        let mut kept = 0;
        for e in entries {
            if self.store.has_history_entry(channel, generation, e.seq) {
                continue;
            }
            // Only what the origin signed for: the sibling's word about
            // where an entry sat counts for nothing.
            if !matches!(
                Self::standing_under(&keys, channel, instance, e, None),
                Standing::Vouched | Standing::Unlinked
            ) {
                continue;
            }
            if Self::verdict_for(&keys, channel, instance, e, &mut chains, &bound)
                == Verdict::Forged
            {
                continue;
            }
            let mut raw = Vec::with_capacity(e.wire_len());
            e.write_receipted(&mut raw);
            self.store
                .put_history_entry(channel, generation, e.seq, &raw)?;
            let tombstone = e.body.is_empty();
            let plain = if e.epoch == 0 {
                Some(e.body.clone())
            } else {
                epoch_keys
                    .get(&e.epoch)
                    .and_then(|k| k.open(channel, e.epoch, &e.device, e.msg_seq, &e.body).ok())
            };
            self.store.put_history_message(
                channel,
                generation,
                Kept {
                    seq: e.seq,
                    account: e.account,
                    posted: e.posted,
                    kind: e.kind,
                    plain: if tombstone {
                        Some(&[][..])
                    } else {
                        plain.as_deref()
                    },
                },
            )?;
            kept += 1;
        }
        Ok(kept)
    }

    /// Take entries a sibling handed over (SIP-42): verified exactly as a
    /// fetch is, folded into `timeline`, and kept -- signed, so they can be
    /// handed on. Nothing here moves the fetch cursor. Returns how many
    /// were new.
    pub async fn import(
        &mut self,
        timeline: &mut Timeline,
        channel: &[u8; 32],
        instance: [u8; 32],
        entries: &[Entry],
    ) -> Result<usize> {
        if entries.is_empty() {
            return Ok(0);
        }
        // Another incarnation of the channel is another conversation
        // (SIP-16): merged, the numbers would collide. Not this device's to
        // reset on a sibling's word; a fetch finds out and resets.
        if let Some(known) = self.store.incarnation(channel)?
            && known != instance
        {
            return Err(ChatError::Protocol(
                "the sibling holds another incarnation of this channel".into(),
            ));
        }
        let info = self.info(channel).await?;
        if info.instance != instance {
            return Err(ChatError::Protocol(
                "the sibling's entries are from an incarnation the exchange does not serve".into(),
            ));
        }
        let admins: Vec<PubKey> = info
            .members
            .iter()
            .filter(|m| m.role == Role::Admin)
            .map(|m| m.account)
            .collect();
        let bound = self.bindings(&members_of(&info)).await.unwrap_or_default();
        let held = self.store.highest_entry(channel)?;
        // Only what is new -- the rest was verified when it arrived -- and
        // only what the exchange signed for. A fetch stores an unreceipted
        // entry, because the exchange served it and may not do receipts;
        // here the sibling served it, and its word about where the exchange
        // put an entry counts for nothing. The signature is checked in the
        // fold, as on a fetch.
        let fresh: Vec<Entry> = entries
            .iter()
            .filter(|e| e.seq > held || !self.has_entry(channel, e.seq))
            .filter(|e| {
                matches!(
                    Self::standing_under(&self.keys_of(channel), channel, instance, e, None),
                    Standing::Vouched | Standing::Unlinked
                )
            })
            .cloned()
            .collect();
        let before = self.store.entry_count(channel)?;
        self.fold_entries(timeline, channel, &info, &admins, &bound, &fresh, 0, true)?;
        // What was kept, not what was offered: an entry that failed its
        // checks was refused in there, silently to the sibling.
        Ok((self.store.entry_count(channel)? - before) as usize)
    }

    /// Whether a signed copy of the entry at `seq` is held.
    pub fn has_entry(&self, channel: &[u8; 32], seq: u64) -> bool {
        self.store
            .entries_after(channel, seq.saturating_sub(1), 1)
            .ok()
            .is_some_and(|v| v.first().is_some_and(|(s, _)| *s == seq))
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
                &self.exchange_of(channel),
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
    /// SIP-16 §Searching the federation: the directory across this exchange and its peers, each row
    /// naming where the channel lives and whether it is joinable here.
    /// An exchange from before sqex 0.72.0 (SIP-16 §Federated directory) answers with its own directory only,
    /// every row at home.
    pub async fn search(&mut self, query: &str, offset: u32) -> Result<Found> {
        match self
            .post(
                "/channel/search",
                Search {
                    offset,
                    query: query.to_string(),
                }
                .encode(),
            )
            .await
        {
            Ok(body) => Found::decode(&body).map_err(|e| ChatError::Protocol(e.to_string())),
            Err(ChatError::NoChatHere(_)) => {
                let listing = self.find(query, offset).await?;
                Ok(Found {
                    now: listing.now,
                    total: listing.total,
                    rows: listing
                        .channels
                        .into_iter()
                        .map(|p| Row {
                            channel: p.channel,
                            instance: p.instance,
                            home: self.exchange,
                            domain: String::new(),
                            here: true,
                            members: p.members,
                            last: p.last,
                            name: p.name,
                            topic: p.topic,
                        })
                        .collect(),
                })
            }
            Err(e) => Err(e),
        }
    }

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
        // SIP-43: where it lives, before signing -- a joiner has never asked
        // `info` for this channel, and the place a join is signed under is
        // the origin's, which is not this exchange's for a copy. A public
        // channel's home is answered to anyone; an exchange from before
        // SIP-43 is the origin of everything it serves. A refusal here is
        // not the join's to report: the join itself will say.
        let _ = self.home(channel).await;
        // Our own chain state first, and the exchange's where it will say --
        // a public channel's `info` is answered to anyone at a copy, and
        // carries where this device stands at the origin, which a member the
        // origin seated by welcome and a store that remembers nothing would
        // otherwise not know. The greater of the two, never the report alone.
        let (chain_seq, prev) = match self.info(channel).await {
            Ok(info) => self.chain_at(channel, &info)?,
            Err(_) => self.store.chain(channel)?,
        };
        let terms = ActionTerms {
            place: Place {
                exchange: self.exchange_of(channel),
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

    /// SIP-56: mute a member -- they read and may not write -- or unmute
    /// them. An admin's signed entry, like a removal.
    pub async fn mute(&mut self, channel: &[u8; 32], who: &PubKey, on: bool) -> Result<()> {
        let info = self.info(channel).await?;
        let (event, path, type_byte) = if on {
            (EVENT_MUTED, "/channel/mute", TYPE_MUTE)
        } else {
            (EVENT_UNMUTED, "/channel/unmute", TYPE_UNMUTE)
        };
        let (action, head) = self.sign_action_at(channel, &info, event, who, &[])?;
        self.post(
            path,
            ByAccount {
                channel: *channel,
                account: *who,
                action,
            }
            .encode(type_byte),
        )
        .await?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        Ok(())
    }

    /// SIP-56: report an entry to the channel's admins. Not an entry: the
    /// exchange holds it for the admins and nobody else sees it -- but the
    /// note is stored in the clear.
    pub async fn report(
        &mut self,
        channel: &[u8; 32],
        target: u64,
        reason: u8,
        note: &str,
    ) -> Result<()> {
        self.post(
            "/channel/report",
            Report {
                channel: *channel,
                target,
                reason,
                note: note.to_string(),
            }
            .encode(),
        )
        .await?;
        Ok(())
    }

    /// SIP-56: the channel's reports, for an admin.
    pub async fn reports(&mut self, channel: &[u8; 32]) -> Result<Vec<Reported>> {
        let body = self
            .post(
                "/channel/reports",
                ByChannel { channel: *channel }.encode(TYPE_REPORTS),
            )
            .await?;
        Ok(Reports::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .reports)
    }

    /// SIP-56: dismiss a report.
    pub async fn dismiss(&mut self, channel: &[u8; 32], id: u64) -> Result<()> {
        self.post(
            "/channel/dismiss",
            ByTarget {
                channel: *channel,
                target: id,
            }
            .encode(TYPE_DISMISS),
        )
        .await?;
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
                &self.exchange_of(channel),
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
        let info = ChannelInfo::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        // SIP-43: where it lives, learned with the first look and kept. Before
        // anything is signed or verified for it, since both name the origin.
        if !self.homes.contains_key(channel) {
            self.home(channel).await?;
        }
        Ok(info)
    }

    /// SIP-43: where a channel lives -- the exchange that orders it, and the
    /// domain it is reached by when the operator recorded one. This
    /// connection's exchange, where it does not answer the question: an
    /// exchange from before SIP-43 is the origin of everything it serves.
    pub async fn home(&mut self, channel: &[u8; 32]) -> Result<Home> {
        if let Some(h) = self.homes.get(channel) {
            return Ok(h.clone());
        }
        let home = match self
            .post(
                "/channel/home",
                ByChannel { channel: *channel }.encode(TYPE_HOME),
            )
            .await
        {
            Ok(body) => Home::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?,
            Err(ChatError::NoChatHere(_)) => Home {
                origin: self.exchange,
                domain: String::new(),
                former: Vec::new(),
            },
            Err(e) => return Err(e),
        };
        // SIP-53: what earlier origins signed and receipted verifies under
        // them.
        for (_, f) in &home.former {
            if *f != home.origin {
                let former = self.former.entry(*channel).or_default();
                if !former.contains(f) {
                    former.push(*f);
                }
                self.predecessors
                    .entry(*f)
                    .or_insert_with(|| predecessors_of(f));
            }
        }
        self.store.set_home(channel, &home.origin);
        self.predecessors
            .entry(home.origin)
            .or_insert_with(|| predecessors_of(&home.origin));
        self.homes.insert(*channel, home.clone());
        // SIP-60 §A device hints its home: a channel of this account's that lives elsewhere is one
        // its home should be pulling; said once per origin.
        if home.origin != self.exchange {
            let (origin, domain) = (home.origin, home.domain.clone());
            let _ = self.hint_home(&origin, &domain).await;
        }
        // SIP-53 §Posting again: a former origin whose regime ended below what this client
        // holds is a fork this client was on the losing side of.
        let forks: Vec<(u64, PubKey)> = home
            .former
            .iter()
            .filter(|(_, f)| *f != home.origin)
            .copied()
            .collect();
        for (ended, f) in forks {
            // `ended` is the position of the rehome that ended the regime:
            // the first of the new one. The fork is the position before it.
            let _ = self.fork_check(channel, &f, ended.saturating_sub(1)).await;
        }
        Ok(home)
    }

    /// SIP-53 §Posting again: deal with a fork at `fork` that `former` lost. What this
    /// client holds above it under the former origin's receipts is of the
    /// losing regime: its own posts are kept aside as stranded, the rest
    /// dropped, the cursor put back to the fork, and the chain continued
    /// from what the winning origin holds. Returns how many posts were
    /// stranded; nothing where the fork is above what is held, or was dealt
    /// with already.
    pub async fn fork_check(
        &mut self,
        channel: &[u8; 32],
        former: &PubKey,
        fork: u64,
    ) -> Result<usize> {
        self.fork_found(channel, former, fork, false).await
    }

    /// `fork_check`, with `own_act` where this client is making the fork
    /// itself by rehoming at a replica: then the chain is put back to what
    /// the replica holds whether or not this connection's view held
    /// anything above it -- the other connection's view may, and the
    /// rehome must chain from what the replica has seen.
    async fn fork_found(
        &mut self,
        channel: &[u8; 32],
        former: &PubKey,
        fork: u64,
        own_act: bool,
    ) -> Result<usize> {
        let seen = !self.forks_seen.insert((*channel, fork));
        let highest = self.store.highest_entry(channel)?.max(
            self.store
                .messages(channel)?
                .last()
                .map(|m| m.0)
                .unwrap_or(0),
        );
        let nothing_held = highest <= fork;
        if (seen || nothing_held) && !own_act {
            return Ok(0);
        }
        if seen || nothing_held {
            self.chain_back_to_origin(channel).await?;
            return Ok(0);
        }
        let current = self.exchange_of(channel);
        let instance = self.store.incarnation(channel)?.unwrap_or([0; 32]);
        let mut under_former = vec![*former];
        under_former.extend(
            self.predecessors
                .entry(*former)
                .or_insert_with(|| predecessors_of(former))
                .iter()
                .copied(),
        );
        let under_current = vec![current];
        // Which of the held entries above the fork the former origin
        // receipted: those are the losing regime. One held without a receipt
        // was fetched before the fork was known, and is taken as losing too.
        let mut losing: HashSet<u64> = HashSet::new();
        for (seq, bytes) in self.store.entries_after(channel, fork, usize::MAX)? {
            let Ok(e) = Entry::read_receipted(&bytes, &mut 0) else {
                continue;
            };
            let old = matches!(
                Self::standing_under(&under_former, channel, instance, &e, None),
                Standing::Vouched | Standing::Unlinked
            );
            let new = current != *former
                && matches!(
                    Self::standing_under(&under_current, channel, instance, &e, None),
                    Standing::Vouched | Standing::Unlinked
                );
            if (old && !new) || e.stamp.is_none() {
                losing.insert(seq);
            }
        }
        let plain: HashMap<u64, (PubKey, u64, Option<Vec<u8>>)> = self
            .store
            .messages(channel)?
            .into_iter()
            .filter(|m| m.0 > fork)
            .map(|(seq, account, posted, kind, plain)| {
                (
                    seq,
                    (
                        account,
                        posted,
                        (kind == KIND_MEMBER).then_some(plain).flatten(),
                    ),
                )
            })
            .collect();
        // A message held with no signed entry beside it was read before this
        // client kept entries; above a fork it can only be the losing side.
        let mut stranded = 0;
        for (seq, (account, posted, body)) in &plain {
            let held_signed = self.has_entry(channel, *seq);
            if held_signed && !losing.contains(seq) {
                continue;
            }
            if *account != self.me {
                continue;
            }
            if let Some(body) = body
                && matches!(Body::decode(body), Ok(Some(Body::Post(_))))
            {
                self.store
                    .put_stranded(channel, *seq, *posted, fork, body)?;
                stranded += 1;
            }
        }
        self.store.truncate_above(channel, fork)?;
        if !losing.is_empty() || own_act {
            self.chain_back_to_origin(channel).await?;
        }
        Ok(stranded)
    }

    /// SIP-53 §Posting again: the chain continues from the last entry the winning origin
    /// holds. Asked plainly: `info` asks `home`, which may have asked here.
    async fn chain_back_to_origin(&mut self, channel: &[u8; 32]) -> Result<()> {
        let asked = self
            .post(
                "/channel/info",
                ByChannel { channel: *channel }.encode(TYPE_INFO),
            )
            .await
            .ok()
            .and_then(|b| ChannelInfo::decode(&b).ok());
        let Some(info) = asked else {
            return Ok(());
        };
        // A replica tracked no chains (SIP-53). SIP-43 §The heads by position has it report the
        // chain as its entries show it, and serve the heads by position;
        // an exchange from before that reports zero, and this client
        // rebuilds from the entries it holds itself (SIP-53 §Posting again).
        let (target_seq, target_head) = if info.my_chain_seq > 0 {
            (info.my_chain_seq, info.my_chain_head)
        } else if let Ok(Some((seq, head))) = self
            .chain_heads(channel, 0)
            .await
            .map(|h| h.last().copied())
        {
            (seq + 1, head)
        } else {
            self.chain_from_held(channel, info.last)?
                .unwrap_or((0, sqex_proto::entry_sig::GENESIS))
        };
        let (mine, _) = self.store.chain(channel)?;
        if mine > target_seq {
            self.store.reset_chain(channel, target_seq, &target_head)?;
        }
        Ok(())
    }

    /// SIP-43 §The heads by position: this device's chain heads by position as the exchange holds
    /// them, from `from` up. Empty where the exchange predates the route.
    pub async fn chain_heads(
        &mut self,
        channel: &[u8; 32],
        from: u64,
    ) -> Result<Vec<(u64, [u8; 32])>> {
        let body = match self
            .post(
                "/channel/chain",
                sqex_proto::channel::ChainAsk {
                    channel: *channel,
                    from,
                }
                .encode(),
            )
            .await
        {
            Ok(body) => body,
            Err(ChatError::Refused(404, _)) | Err(ChatError::NoChatHere(_)) => {
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        Ok(sqex_proto::channel::Heads::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .heads)
    }

    /// SIP-53 §Posting again: this device's chain as the entries held up to `upto` have
    /// it -- the next position and the link -- or `None` where it signed
    /// nothing held. A post of this device's links over its entry terms;
    /// an action of this device's (a system entry naming it) links over an
    /// input the exchange never transmits, so the head this device logged
    /// when it signed is what stands there.
    fn chain_from_held(&self, channel: &[u8; 32], upto: u64) -> Result<Option<(u64, [u8; 32])>> {
        let instance = self.store.incarnation(channel)?.unwrap_or([0; 32]);
        let keys = self.keys_of(channel);
        let mut last: Option<(u64, [u8; 32])> = None;
        let mut take = |next: u64, head: [u8; 32]| {
            if last.is_none_or(|(n, _)| next > n) {
                last = Some((next, head));
            }
        };
        for (seq, bytes) in self.store.entries_after(channel, 0, usize::MAX)? {
            if seq > upto {
                break;
            }
            let Ok(e) = Entry::read_receipted(&bytes, &mut 0) else {
                continue;
            };
            if e.kind == KIND_SYSTEM {
                if let Ok(Some(sys)) = System::decode(&e.body)
                    && sys.actor_device == self.device
                    && let Some(head) = self.store.head_after(channel, sys.chain_seq)?
                {
                    take(sys.chain_seq + 1, head);
                }
                continue;
            }
            if e.device != self.device {
                continue;
            }
            for key in &keys {
                let terms = EntryTerms {
                    place: Place {
                        exchange: *key,
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
                let signed = if e.body.is_empty()
                    && e.body_hash != Sha256::digest(&[] as &[u8]).as_slice()
                {
                    verify_entry_hashed(&terms, &e.body_hash, &e.sig)
                } else {
                    verify_entry(&terms, &e.sig)
                };
                if signed {
                    take(e.chain_seq + 1, link(&terms.input_hashed(&e.body_hash)));
                    break;
                }
            }
        }
        Ok(last)
    }

    /// SIP-53 §Posting again: this client's own posts a move stranded, oldest first:
    /// `(seq, posted, post)`.
    pub fn stranded_posts(&self, channel: &[u8; 32]) -> Result<Vec<(u64, u64, SipPost)>> {
        let mut out = Vec::new();
        for (seq, posted, _, plain) in self.store.stranded(channel)? {
            if let Ok(Some(Body::Post(p))) = Body::decode(&plain) {
                out.push((seq, posted, p));
            }
        }
        Ok(out)
    }

    /// SIP-53 §Posting again: post a stranded post again, as a fresh entry saying when it
    /// was first said. A reply to something above the fork loses its
    /// reply: what it answered was stranded too.
    pub async fn post_again(&mut self, channel: &[u8; 32], seq: u64) -> Result<Posted> {
        let (posted, fork, plain) = self
            .store
            .stranded(channel)?
            .into_iter()
            .find(|(s, _, _, _)| *s == seq)
            .map(|(_, posted, fork, plain)| (posted, fork, plain))
            .ok_or_else(|| ChatError::Protocol("no such stranded post".into()))?;
        let Ok(Some(Body::Post(mut post))) = Body::decode(&plain) else {
            return Err(ChatError::Protocol(
                "the stranded body is not a post".into(),
            ));
        };
        post.parts
            .retain(|p| !matches!(p, Part::Said(_) | Part::Via(_)));
        post.parts
            .retain(|p| !matches!(p, Part::Reply(t) if *t > fork));
        post.parts.push(Part::Said(posted));
        let sent = self.send_body(channel, Body::Post(post)).await?;
        self.store.drop_stranded(channel, seq)?;
        Ok(sent)
    }

    /// SIP-53 §Posting again: let a stranded post go unsent.
    pub fn forget_stranded(&mut self, channel: &[u8; 32], seq: u64) -> Result<()> {
        Ok(self.store.drop_stranded(channel, seq)?)
    }

    /// SIP-60 §A device hints its home: tell this client's home to pull the account's channels from
    /// `origin`, reached by `domain` where the home does not know it. Once
    /// per origin per run; `Ok(false)` where the exchange is not this
    /// account's home, or predates the route.
    pub async fn hint_home(&mut self, origin: &PubKey, domain: &str) -> Result<bool> {
        if *origin == self.exchange || !self.hinted.insert(*origin) {
            return Ok(false);
        }
        let body = match self
            .post(
                "/account/hint",
                sqex_proto::home::Hint {
                    origin: *origin,
                    domain: domain.to_string(),
                }
                .encode(),
            )
            .await
        {
            Ok(body) => body,
            Err(ChatError::Refused(404, _)) | Err(ChatError::NoChatHere(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(sqex_proto::home::Hinted::decode(&body)
            .map(|h| h.pulling)
            .unwrap_or(false))
    }

    /// The exchange a channel's signatures name and its receipts verify
    /// under: its origin where that is known, this one otherwise.
    pub fn exchange_of(&self, channel: &[u8; 32]) -> PubKey {
        self.homes
            .get(channel)
            .map(|h| h.origin)
            .unwrap_or(self.exchange)
    }

    /// The keys a channel's signatures and receipts may verify under: the
    /// exchange that orders it, then the keys that exchange held before
    /// (SIP-40).
    fn keys_of(&self, channel: &[u8; 32]) -> Vec<PubKey> {
        let current = self.exchange_of(channel);
        let mut keys = vec![current];
        if let Some(older) = self.predecessors.get(&current) {
            keys.extend(older.iter().copied());
        }
        // SIP-53: and every exchange that ordered the channel before.
        if let Some(former) = self.former.get(channel) {
            for f in former {
                keys.push(*f);
                if let Some(older) = self.predecessors.get(f) {
                    keys.extend(older.iter().copied());
                }
            }
        }
        keys
    }

    /// SIP-57: put a timer on what this client sends in `channel`, in
    /// seconds; 0 for none. Signed into each entry, so the exchange, every
    /// copy and every reader delete at the same time.
    pub fn set_timer(&mut self, channel: &[u8; 32], secs: u32) {
        if secs == 0 {
            self.timers.remove(channel);
        } else {
            self.timers.insert(*channel, secs);
        }
    }

    pub fn timer(&self, channel: &[u8; 32]) -> u32 {
        self.timers.get(channel).copied().unwrap_or(0)
    }

    /// SIP-57: delete every timed message whose time has come, from the
    /// store and from `timeline` where it is that channel's. Returns what
    /// went.
    pub fn expire(&mut self, timeline: Option<(&[u8; 32], &mut Timeline)>) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let gone = self.store.expire_timed(now)?;
        if let Some((channel, t)) = timeline {
            for (c, seq) in &gone {
                if c == channel {
                    t.forget(*seq);
                }
            }
        }
        Ok(gone.len())
    }

    /// SIP-53: the channel's origin is `subject` from here. The one it had
    /// is kept as a former origin, and signing moves to the new one.
    fn moved_origin(&mut self, channel: &[u8; 32], subject: &PubKey) {
        let was = self.exchange_of(channel);
        if was == *subject {
            return;
        }
        let former = self.former.entry(*channel).or_default();
        if !former.contains(&was) {
            former.insert(0, was);
        }
        let domain = self
            .homes
            .get(channel)
            .filter(|h| h.origin == *subject)
            .map(|h| h.domain.clone())
            .unwrap_or_default();
        self.homes.insert(
            *channel,
            Home {
                origin: *subject,
                domain,
                former: Vec::new(),
            },
        );
        self.store.set_home(channel, subject);
        self.predecessors
            .entry(*subject)
            .or_insert_with(|| predecessors_of(subject));
    }

    /// SIP-53: move the channel's origin to `subject` -- an exchange it is
    /// replicated to, from the origin; or the exchange this client is at,
    /// from a replica whose origin is gone. Signed under the origin the
    /// channel has now; from here it is `subject`'s.
    pub async fn rehome(
        &mut self,
        channel: &[u8; 32],
        subject: &PubKey,
        domain: &str,
    ) -> Result<()> {
        let info = self.info(channel).await?;
        // SIP-53 §Posting again: rehoming at a replica whose origin is gone strands, by that
        // act, everything above the replica's last position -- this client's
        // own included -- and the rehome must chain from what the replica
        // holds, or it links to a hash the replica has never seen.
        if *subject == self.exchange {
            let was = self.exchange_of(channel);
            if was != *subject {
                let _ = self.fork_found(channel, &was, info.last, true).await;
            }
        }
        let (action, head) = self.sign_action_at(channel, &info, EVENT_REHOMED, subject, &[])?;
        self.post(
            "/channel/rehome",
            Rehome {
                channel: *channel,
                subject: *subject,
                domain: domain.to_string(),
                action,
            }
            .encode(),
        )
        .await?;
        self.store.set_chain(channel, action.chain_seq, &head)?;
        self.moved_origin(channel, subject);
        if let Some(h) = self.homes.get_mut(channel) {
            h.domain = domain.to_string();
        }
        Ok(())
    }

    /// SIP-53: carry a rehome this client holds to the exchange it is at,
    /// which has not seen it -- another replica, or the old origin come
    /// back. The exchange verifies it and follows, or refuses.
    pub async fn carry_rehome(&mut self, channel: &[u8; 32]) -> Result<bool> {
        let Some(entry) = self.rehome_entry(channel)? else {
            return Ok(false);
        };
        let domain = self
            .homes
            .get(channel)
            .map(|h| h.domain.clone())
            .unwrap_or_default();
        self.post(
            "/channel/rehomed",
            Rehomed {
                channel: *channel,
                domain,
                entry,
            }
            .encode(),
        )
        .await?;
        // The exchange just learned the channel moved; what it answers for
        // the channel's home has changed, and so may what this client holds
        // above the fork (SIP-53 §Posting again).
        self.homes.remove(channel);
        let _ = self.home(channel).await;
        Ok(true)
    }

    /// SIP-53: the latest rehome entry this client holds for a channel,
    /// receipted, if any.
    fn rehome_entry(&self, channel: &[u8; 32]) -> Result<Option<Entry>> {
        // Under any connection: the entry was read at the new origin, and is
        // carried from a connection to the old one (SIP-53 §Posting again found this).
        let raw = self.store.entries_anywhere(channel)?;
        let mut found = None;
        for (_, b) in &raw {
            let mut at = 0;
            if let Ok(e) = Entry::read_receipted(b, &mut at)
                && e.kind == KIND_SYSTEM
                && System::decode(&e.body)
                    .ok()
                    .flatten()
                    .is_some_and(|s| s.event == EVENT_REHOMED)
            {
                found = Some(e);
            }
        }
        Ok(found)
    }

    /// SIP-53: this client's own entries an exchange ordered past a fork
    /// it lost. The bodies as posted, to be posted again.
    pub async fn stranded_entries(
        &mut self,
        channel: &[u8; 32],
    ) -> Result<Vec<(u64, u64, Vec<u8>)>> {
        let body = self
            .post(
                "/channel/stranded",
                ByChannel { channel: *channel }.encode(TYPE_STRANDED),
            )
            .await?;
        Ok(Stranded::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .entries)
    }

    // ---- SIP-59: moving home ----------------------------------------------

    /// Sign the statement that `home` is this account's exchange from now.
    /// Only the account key signs it: a linked device holds a credential,
    /// not the account, and is told to have the account sign (`sqex home
    /// sign`, which can drive a hardware key).
    pub fn sign_move(&self, home: &PubKey) -> Result<sqex_proto::home::Move> {
        let Some(seed) = self.account_seed() else {
            return Err(ChatError::Protocol(format!(
                "this client acts for {} and cannot sign for it; run `sqex home sign {home}` \
                 with the account's key and pass the result with --signed",
                self.me
            )));
        };
        Ok(sqex_proto::home::Move::sign(&seed, home, now_secs()))
    }

    /// What signs for the account here: this device's own key where the
    /// device is the account, or the account seed the store keeps from a
    /// handover this client made (SIP-44 §The handover). `None` for a linked device of an
    /// account held elsewhere.
    /// The account's seed, where this device holds it: its own where it
    /// is the account, the one it made (SIP-44 §The handover) or was entrusted with
    /// (SIP-44 §Entrusting the key) otherwise.
    pub fn account_seed(&self) -> Option<[u8; 32]> {
        if self.me == self.device {
            return Some(self.seed);
        }
        // Only the key of the account this device is *now*: a seed kept
        // from before a handover another device presented (SIP-44 §Entrusting the key) would
        // sign as a retired account, and every verifier would take it.
        self.store.account_seed().ok().flatten().filter(|seed| {
            PubKey::new(
                ed25519_dalek::SigningKey::from_bytes(seed)
                    .verifying_key()
                    .to_bytes(),
            ) == self.me
        })
    }

    /// SIP-44 §Entrusting the key: keep an account seed a sibling entrusted to this device.
    /// The store keeps it sealed; the caller checked it is this account's.
    pub fn take_account_seed(&mut self, seed: [u8; 32]) {
        let _ = self.store.set_account_seed(&seed);
    }

    /// SIP-44 §Entrusting the key: whether this device holds the account key.
    pub fn holds_account_key(&self) -> bool {
        self.account_seed().is_some()
    }

    /// Where this account's channels live, as this client knows: this
    /// exchange first, then every other origin among its channels, each
    /// with the domain this client has for it.
    pub async fn origins_of_mine(&mut self) -> Result<Vec<(PubKey, String)>> {
        let mut out = vec![(self.exchange, self.domain.clone().unwrap_or_default())];
        let mine = self.mine().await?;
        for m in mine {
            let home = match self.home(&m.channel).await {
                Ok(h) => h,
                Err(_) => continue,
            };
            if !out.iter().any(|(k, _)| *k == home.origin) {
                out.push((home.origin, home.domain.clone()));
            }
            if out.len() >= sqex_proto::home::MAX_ORIGINS {
                break;
            }
        }
        Ok(out)
    }

    /// Present a Move here, whoever signed it.
    pub async fn present_move(
        &mut self,
        moving: &sqex_proto::home::Moving,
    ) -> Result<sqex_proto::home::Moved> {
        let body = self.post("/account/move", moving.encode()).await?;
        sqex_proto::home::Moved::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Where an account lives, as this exchange has it.
    pub async fn account_home(&mut self, account: &PubKey) -> Result<sqex_proto::home::Homed> {
        let body = self
            .post("/account/home", account.as_bytes().to_vec())
            .await?;
        sqex_proto::home::Homed::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Move this account's home to the exchange at `addr` with key `home`,
    /// reached by `domain`: sign the Move (or take one signed elsewhere),
    /// register this device there if it is a linked one, present the Move
    /// there with where the channels live and here without, and re-file
    /// the store under the new home. Afterwards this `Chat` is still
    /// connected to the old exchange; the caller starts again against the
    /// new one, which is where the store now says it belongs.
    pub async fn move_home(
        &mut self,
        addr: SocketAddr,
        home: &PubKey,
        domain: &str,
        signed: Option<sqex_proto::home::Move>,
    ) -> Result<Moved> {
        if *home == self.exchange {
            return Err(ChatError::Protocol(
                "that is already this account's home".into(),
            ));
        }
        let mv = match signed {
            Some(m) if m.account == self.me && m.home == *home && m.verify() => m,
            Some(_) => {
                return Err(ChatError::Protocol(
                    "the signed move is not this account's, or does not name that home".into(),
                ));
            }
            None => self.sign_move(home)?,
        };
        let origins = self.origins_of_mine().await?;

        let mut there = Client::connect_as(addr, home.as_bytes(), &self.seed)
            .await
            .map_err(|e| ChatError::Transport(format!("could not reach {domain}: {e}")))?;
        // The Move first, then the device: a home the account is moving
        // *back* to is its former home until the Move is presented, and a
        // former home refuses a device's registration with `moved`
        // (SIP-60 §At a former home). The Move needs no registration -- its signature is
        // the authority.
        let moving = sqex_proto::home::Moving {
            mv,
            domain: domain.to_string(),
            origins,
        };
        let (code, body) = there
            .post("/account/move", moving.encode())
            .await
            .map_err(|e| ChatError::Transport(e.to_string()))?;
        if code != 200 {
            return Err(classify("/account/move", code, &body));
        }
        let at_home = sqex_proto::home::Moved::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        if let Some(credential) = self.credential() {
            let (code, body) = there
                .post("/device/register", Register { credential }.encode())
                .await
                .map_err(|e| ChatError::Transport(e.to_string()))?;
            if code != 200 {
                return Err(classify("/device/register", code, &body));
            }
        }

        // Told here too, so the gate opens before the home's first pull
        // rather than after its carry; the home carries it on to the rest.
        // The home's carry can win the race -- it is poked the moment the
        // Move lands -- and this exchange then already holds this very
        // Move and refuses it as stale. That is the same telling, done.
        let here = match self
            .present_move(&sqex_proto::home::Moving {
                mv,
                domain: domain.to_string(),
                origins: Vec::new(),
            })
            .await
        {
            Ok(here) => here,
            Err(ChatError::Refused(409, r)) if r.code == RefusalCode::StaleGeneration => {
                sqex_proto::home::Moved {
                    now: at_home.now,
                    peered: true,
                }
            }
            Err(e) => return Err(e),
        };

        let from = self.exchange;
        let refiled = self.store.move_home(&from, home)?;
        self.store.record_home_issued(mv.issued)?;
        Ok(Moved {
            mv,
            peered_here: here.peered,
            peered_at_home: at_home.peered,
            refiled: refiled.moved,
            left: refiled.left,
        })
    }

    /// Whether a channel lives at another exchange than this connection's.
    pub fn homed_elsewhere(&self, channel: &[u8; 32]) -> Option<&Home> {
        self.homes
            .get(channel)
            .filter(|h| h.origin != self.exchange)
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
        // Who to ask about, decided first, so the asking can happen all at
        // once. **Two round trips per member, one member at a time**, was
        // how this ran: sixty-five members whose misses had aged out was
        // eight seconds between a message arriving and being shown, every
        // three minutes, on the busiest channel there is.
        let mut stale = Vec::new();
        for account in accounts {
            // Our own included. It was skipped as a pointless round trip —
            // you know what you called yourself — but `/who` lists you among
            // the members, and naming everybody else while showing yourself as
            // a bare key is the one row a reader cannot account for.
            let held = self.store.profile(account)?;
            if !force && held.is_some_and(|(name, _, at)| now.saturating_sub(at) < age(&name)) {
                continue;
            }
            stale.push(*account);
        }
        if stale.is_empty() {
            return Ok(0);
        }
        let asks = stale
            .iter()
            .map(|account| ProfileByAccount { account: *account }.encode(profile::TYPE_GET))
            .collect();
        let answers = self
            .post_each("/profile/get", asks, PATIENCE, LISTS_IN_FLIGHT)
            .await;
        let mut asked = 0;
        let mut handles = Vec::new();
        for (account, answer) in stale.iter().zip(answers) {
            let got = match answer.and_then(|body| {
                GotProfile::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
            }) {
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
            // SIP-38: the account's handle, on the same cadence and the same
            // "asked, told nothing" caching. The exchange's reverse-lookup is
            // its word — a display hint under the profile nickname, never an
            // authority — so a failure here is swallowed, not surfaced.
            let handle_stale = force
                || match self.store.handle(account)? {
                    Some((n, at)) => now.saturating_sub(at) >= age(&n),
                    None => true,
                };
            if handle_stale {
                handles.push(*account);
            }
            asked += 1;
        }
        let asks = handles
            .iter()
            .map(|account| sqex_proto::name::Reverse { account: *account }.encode())
            .collect();
        let answers = self
            .post_each("/name/reverse", asks, PATIENCE, LISTS_IN_FLIGHT)
            .await;
        for (account, answer) in handles.iter().zip(answers) {
            let primary = answer
                .ok()
                .and_then(|body| sqex_proto::name::Names::decode(&body).ok())
                .and_then(|mut n| (!n.names.is_empty()).then(|| n.names.remove(0)));
            self.store
                .put_handle(account, primary.as_deref().unwrap_or(""), now)?;
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
    pub async fn edit(
        &mut self,
        channel: &[u8; 32],
        target: u64,
        mut post: SipPost,
    ) -> Result<Posted> {
        self.stamp_via(channel, &mut post).await;
        post.validate()
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.send_body(channel, Body::Edit { target, post }).await
    }

    /// SIP-43: a post made through a copy says so, in the poster's own
    /// words and under the poster's own signature -- `Via` is a part of the
    /// body, sealed with it, and no exchange adds or learns anything. It
    /// names this connection's exchange by key; a reader's own pin store
    /// turns that into a domain. Left alone where the channel lives here,
    /// or where the post already says.
    async fn stamp_via(&mut self, channel: &[u8; 32], post: &mut SipPost) {
        // Asked here, not assumed: a store that remembers nothing may post
        // before it has ever looked at the channel. Cached after the first.
        let _ = self.home(channel).await;
        if self.homed_elsewhere(channel).is_some() && post.via().is_none() {
            post.parts.push(Part::Via(self.exchange));
        }
    }

    /// SIP-43: what to call the exchange a message says it came through --
    /// the domain this machine's pin store knows the key under, or the key.
    /// The pin store, not the message: a domain named in a message would be
    /// the poster's to choose, and this is the reader's own knowledge.
    pub fn via_name(exchange: &PubKey) -> String {
        let known = sqex_discovery::Known::load(&sqex_discovery::known::path()).ok();
        known
            .as_ref()
            .and_then(|k| {
                k.entries()
                    .iter()
                    .find(|e| e.key == *exchange)
                    .map(|e| e.domain.clone())
            })
            .unwrap_or_else(|| {
                let key = exchange.to_string();
                format!("{}…", &key[..key.len().min(8)])
            })
    }

    /// Reply to a message: an ordinary post carrying [`Part::Reply`].
    pub async fn reply(&mut self, channel: &[u8; 32], target: u64, text: &str) -> Result<Posted> {
        let mut post = SipPost::text(text);
        post.parts.push(Part::Reply(target));
        self.send_post(channel, post).await
    }

    /// Send a message built by the caller — text, attachments, a reply, or a
    /// combination. `send` is this with one text part.
    pub async fn send_post(&mut self, channel: &[u8; 32], mut post: SipPost) -> Result<Posted> {
        self.stamp_via(channel, &mut post).await;
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
        // SIP-57: the timer is signed into the entry, so every holder sees
        // the same one.
        let expires_after = self.timers.get(channel).copied().unwrap_or(0);
        let terms = EntryTerms {
            place: self.place(channel, &info),
            account: self.me,
            device: self.device,
            epoch,
            msg_seq,
            expires_after,
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
            expires_after,
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
        // SIP-57: our own timed message goes from our store at its time too.
        if expires_after > 0 {
            self.store.note_timer(
                channel,
                posted.seq,
                posted.posted + u64::from(expires_after),
            )?;
        }
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
    ///
    /// Two halves, and they are separable on purpose — see [`Chat::watch`] and
    /// [`Chat::absorb`]. The asking is transport and can be parked anywhere;
    /// the making sense of the answer needs the store, the keys and the
    /// counters, and belongs to whoever holds this.
    pub async fn poll(
        &mut self,
        channel: &[u8; 32],
        timeline: &mut Timeline,
        wait_secs: u16,
    ) -> Result<Conversation> {
        let got = match self.ask(channel, wait_secs).await {
            Ok(got) => got,
            // SIP-60 §The client keeps what it read: a channel this client read that its exchange no
            // longer serves may have been folded there -- the conversation
            // lives at the lower key's home now, and this exchange may not
            // hold a copy yet, or ever. What was read is kept as an earlier
            // copy, the folded log read for the rest, and the reader told.
            Err(e @ ChatError::Refused(_, _))
                if matches!(&e, ChatError::Refused(_, r)
                    if r.code == RefusalCode::NoSuchChannel || r.code == RefusalCode::NotFound)
                    && self.folded_away(channel, timeline).await? =>
            {
                *timeline = Timeline::new();
                return Ok(Conversation {
                    timeline: Timeline::new(),
                    unreadable: Vec::new(),
                    gap: false,
                    restarted: true,
                    lost: 0,
                    no_key: None,
                    typing: false,
                    accepted: None,
                    last: 0,
                    admins: Vec::new(),
                });
            }
            Err(e) => return Err(e),
        };
        // SIP-57: what has run out goes, from the store and the timeline,
        // before the conversation is read out; what arrives already past
        // its time is not folded at all.
        let _ = self.expire(Some((channel, timeline)));
        self.absorb(timeline, got).await
    }

    /// SIP-60 §A direct message opened twice: whether a channel this exchange no longer serves was folded
    /// here -- `/channel/folded` answers a log -- and, if so, keep what was
    /// read as an earlier copy, once. `false` where nothing was held, or
    /// the exchange holds no folded log.
    async fn folded_away(&mut self, channel: &[u8; 32], timeline: &mut Timeline) -> Result<bool> {
        let held = !self.store.messages(channel)?.is_empty();
        if !held {
            return Ok(false);
        }
        let Some(known) = self.store.incarnation(channel)? else {
            return Ok(false);
        };
        let Ok(Some(_)) = self.folded_entries(channel).await else {
            return Ok(false);
        };
        // The exchange no longer answers `info` for it; the last answer it
        // gave, or the members as the messages held name them, is what the
        // remainder is read under.
        let info = match self.told_about.get(channel) {
            Some((info, _)) => ChannelInfo {
                instance: known,
                ..info.clone()
            },
            None => {
                let mut accounts: Vec<PubKey> =
                    self.store.messages(channel)?.iter().map(|m| m.1).collect();
                accounts.sort();
                accounts.dedup();
                ChannelInfo {
                    visibility: Visibility::Private,
                    epoch: 0,
                    instance: known,
                    retention_secs: 0,
                    max_entries: 0,
                    first: 0,
                    last: 0,
                    my_msg_seq: 0,
                    my_chain_seq: 0,
                    my_chain_head: [0; 32],
                    now: now_secs(),
                    members: accounts
                        .into_iter()
                        .map(|account| sqex_proto::channel::Member {
                            account,
                            role: Role::Member,
                            joined: 0,
                        })
                        .collect(),
                    name: String::new(),
                    topic: String::new(),
                }
            }
        };
        self.read_folded(timeline, channel, &info, known, &[]).await;
        self.store.reset_sequence_space(channel)?;
        Ok(true)
    }

    /// A fetch for `channel` that can be parked off this client.
    ///
    /// See [`Watch`] for why. The cursor is read now, so a watch taken and then
    /// left for a minute asks from where the conversation was when it was
    /// taken -- which is right: anything that arrives in between is what it is
    /// waiting for.
    ///
    /// `None` when there is no connection to park on. `wait` is clamped by the
    /// exchange to `sqex_proto::channel::MAX_WAIT`.
    pub fn watch(&self, channel: &[u8; 32], wait: u16) -> Option<Watch> {
        if self.offline() {
            return None;
        }
        let (since, _, _) = self.store.cursor(channel).ok()?;
        Some(Watch {
            requests: self.client.requests(),
            channel: *channel,
            since,
            receipts: self.receipts.load(Ordering::Relaxed),
            wait,
        })
    }

    /// The asking half of [`poll`](Self::poll), on this client's own borrow.
    async fn ask(&mut self, channel: &[u8; 32], wait_secs: u16) -> Result<Fetched> {
        let (mut since, _, _) = self.store.cursor(channel)?;
        // SIP-44 §The handover: a hole in what this store holds is asked for again, once
        // per channel per run -- an entry a copy refused and later took
        // sits below the cursor, where a fetch from the cursor never looks.
        if !self.gap_asked.contains(channel)
            && let Ok(Some(gap)) = self.store.lowest_gap(channel)
        {
            self.gap_asked.insert(*channel);
            since = since.min(gap);
        }
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
        Ok(Fetched {
            channel: *channel,
            since,
            receipts: req.receipts,
            body,
        })
    }

    /// Open, verify, keep and fold a run of entries for `channel`: the loop
    /// [`absorb`](Self::absorb) runs over a fetch, and the one
    /// [`import`](Self::import) runs over what a sibling handed over
    /// (SIP-42). Returns the highest `seq` seen. With `keep_signed`, each
    /// receipted entry is kept as served, signatures and all, so a sibling
    /// can be handed it in turn.
    #[allow(clippy::too_many_arguments)]
    fn fold_entries(
        &mut self,
        timeline: &mut Timeline,
        channel: &[u8; 32],
        info: &ChannelInfo,
        admins: &[PubKey],
        bound: &HashMap<PubKey, Option<PubKey>>,
        entries: &[Entry],
        since: u64,
        keep_signed: bool,
    ) -> Result<u64> {
        // The incarnation these entries were checked against, noted once so
        // a device that only ever reads a channel still knows which one it
        // holds -- SIP-42 hands history over by it. A change is not this
        // function's to act on: `chain_at` resets on the exchange's word,
        // before anything is signed into the new one.
        if info.instance != [0u8; 32] && self.store.incarnation(channel)?.is_none() {
            self.store.set_incarnation(channel, &info.instance, false)?;
        }
        let mut replay = self.store.replay_for(channel)?;
        let keys = self.keys_of(channel);
        // SIP-31 chain state per device, over this run of entries. Continuity
        // is claimed from the first entry seen from each device rather than
        // backwards, because starting to read in the middle of a channel is
        // ordinary and is not a gap anybody caused.
        let mut seen_chains: HashMap<PubKey, (u64, [u8; 32])> = HashMap::new();
        // SIP-34's linkage runs over the channel rather than over one device,
        // so it is a single running value rather than a map: the head of the
        // entry we checked last, if it was the one immediately before.
        let mut last_head: Option<(u64, [u8; 32])> = None;
        let mut last = since;
        for e in entries {
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
            let verdict =
                Self::verdict_for(&keys, channel, info.instance, e, &mut seen_chains, bound);
            // SIP-34, and separately: a receipt says where the exchange put the
            // entry and nothing about who wrote it. Both are checked; a
            // verifier doing only one has learned half of what it thinks.
            let held = last_head
                .filter(|(seq, _)| seq + 1 == e.seq)
                .map(|(_, head)| head);
            let standing = Self::standing_under(&keys, channel, info.instance, e, held);
            if let Some(stamp) = &e.stamp {
                last_head = Some((e.seq, stamp.head));
            }
            // SIP-53 §Posting again: a receipt under no origin this client knows is how a
            // client with its cursor above a fork first meets the new origin.
            if standing == Standing::Repudiated {
                self.reask_home.insert(*channel);
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
                        // Nobody vouched for it, so nothing is decoded from
                        // it either.
                        system: None,
                        verdict,
                        standing,
                    },
                    admins,
                );
                continue;
            }
            // SIP-57: a timed message already past its time is not folded,
            // stored or shown; the exchange's backstop merely had not run.
            if e.expires_after > 0 && now_secs() >= e.posted + u64::from(e.expires_after) {
                continue;
            }
            // SIP-42: the entry as served, signature and receipt included,
            // so a sibling device can be handed history it can verify. Only
            // a receipted one: without the receipt a copy could not be
            // checked against the exchange's own word about its position.
            if keep_signed && e.stamp.is_some() {
                let mut raw = Vec::with_capacity(e.wire_len());
                e.write_receipted(&mut raw);
                self.store.put_entry(channel, e.seq, &raw)?;
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
            // SIP-57: a timed message goes at its time, here as everywhere.
            // SIP-16 lets a client count from its own read time; this one
            // takes the exchange's backstop, which every holder agrees on.
            if e.expires_after > 0 {
                self.store
                    .note_timer(channel, e.seq, e.posted + u64::from(e.expires_after))?;
            }
            // A tombstone fetched fresh must overwrite a body we already hold.
            // `put_message` keeps what it has, which is right for a re-fetch
            // and wrong for this.
            if tombstone {
                self.store.redact_message(channel, e.seq)?;
            }
            // An entry the exchange wrote itself carries SIP-16's `System`
            // layout, not a SIP-19 body. Decoded here rather than dropped:
            // membership and metadata changes are the exchange's own signed
            // record and a reader should see them in the conversation.
            let system = (e.kind == KIND_SYSTEM)
                .then(|| {
                    plain
                        .as_deref()
                        .and_then(|p| System::decode(p).ok().flatten())
                })
                .flatten();
            // SIP-53: the origin moved. From here the channel's signatures
            // and receipts are under the new origin's key, and what came
            // before verifies under the old one, kept as a former origin.
            if let Some(sys) = &system
                && sys.event == EVENT_REHOMED
            {
                let was = self.exchange_of(channel);
                self.moved_origin(channel, &sys.subject);
                // SIP-53 §Posting again: everything held above the position before this
                // entry, under the old origin, is the losing side of a fork.
                if was != sys.subject {
                    self.pending_forks
                        .push((*channel, was, e.seq.saturating_sub(1)));
                }
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
                    system,
                    verdict,
                    standing,
                },
                admins,
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
        Ok(last)
    }

    /// Make a conversation out of what a fetch brought back.
    ///
    /// The other half of [`poll`](Self::poll), and the only half that needs
    /// this client: it opens entries with the epoch keys, spends SIP-17
    /// counters, writes the store and folds `timeline`. A caller that parked
    /// the fetch elsewhere — see [`Chat::watch`] — hands the [`Fetched`] here
    /// and gets exactly what `poll` would have returned.
    pub async fn absorb(&mut self, timeline: &mut Timeline, got: Fetched) -> Result<Conversation> {
        let Fetched {
            channel,
            mut since,
            receipts,
            body,
        } = got;
        let channel = &channel;
        let mut entries =
            Entries::decode(&body, receipts).map_err(|e| ChatError::Protocol(e.to_string()))?;

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
        // SIP-60 §The client keeps what it read adds the third and plainest: the exchange's `info` names an
        // incarnation other than the one this store holds -- the copy this
        // client read replaced by another under the same identifier, a direct
        // message folded into the conversation at its lower key's home, or
        // one rebuilt. A conversation longer than what it replaced never
        // trips the cursor rule, and a reader that signs nothing never trips
        // the announcement. Asked cheaply: `info` is cached per `POLL_TTL`
        // and needed below in any case -- and refreshed when anything
        // arrived, as below, because what arrived may be the first of the
        // new incarnation and must not be opened under the old one's keys.
        let arrived = !entries.entries.is_empty();
        let mut fresh = false;
        let mut told = match self.told_about.get(channel) {
            Some((info, at)) if !arrived && at.elapsed() < POLL_TTL => info.clone(),
            _ => {
                fresh = true;
                let info = self.info(channel).await?;
                self.told_about
                    .insert(*channel, (info.clone(), std::time::Instant::now()));
                info
            }
        };
        let known = self.store.incarnation(channel)?;
        let differs = |told: &ChannelInfo| {
            told.instance != [0u8; 32] && known.is_some_and(|k| k != told.instance)
        };
        let restarted = differs(&told)
            || (since > 0 && entries.last > 0 && entries.last < since)
            || self.store.take_announcement(channel)?;
        if restarted {
            // Whichever rule fired, the incarnation recorded below must be
            // the one the exchange serves *now*, or the next poll finds it
            // changed again and resets a second time -- taking with it a key
            // collected in between, which the exchange serves once.
            if !fresh {
                told = self.info(channel).await?;
                self.told_about
                    .insert(*channel, (told.clone(), std::time::Instant::now()));
            }
            let changed = differs(&told);
            // SIP-60 §The client keeps what it read: what was read of the incarnation that ended is kept
            // (the reset archives it), and what was not yet read is read
            // first, under the keys still held, so the history is whole.
            if let Some(known) = known {
                let admins: Vec<PubKey> = told
                    .members
                    .iter()
                    .filter(|m| m.role == Role::Admin)
                    .map(|m| m.account)
                    .collect();
                self.read_folded(timeline, channel, &told, known, &admins)
                    .await;
            }
            self.store.reset_sequence_space(channel)?;
            if told.instance != [0u8; 32] {
                self.store.set_incarnation(channel, &told.instance, false)?;
            }
            if changed {
                // Where it lives may have changed with it -- a folded
                // identifier's conversation is ordered elsewhere -- and the
                // answer cached on this connection is the old one. Asked
                // again; the exchange that ordered the copy that ended
                // joins the keys the log may verify under (SIP-53).
                let was = self.exchange_of(channel);
                self.homes.remove(channel);
                if let Ok(home) = self.home(channel).await
                    && home.origin != was
                {
                    let former = self.former.entry(*channel).or_default();
                    if !former.contains(&was) {
                        former.push(was);
                    }
                }
            }
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
                receipts,
            };
            let body = self.post("/channel/fetch", again.encode()).await?;
            entries = Entries::decode(&body, again.receipts)
                .map_err(|e| ChatError::Protocol(e.to_string()))?;
        }

        // SIP-44 §The handover: a correspondent who changed key is followed as a contact
        // and as a conversation, before anything is folded.
        let successions: Vec<(PubKey, PubKey)> = entries
            .entries
            .iter()
            .filter(|e| e.kind == KIND_SYSTEM)
            .filter_map(|e| System::decode(&e.body).ok().flatten())
            .filter(|s| s.event == sqex_proto::channel::EVENT_SUCCEEDED)
            .map(|s| (s.actor, s.subject))
            .collect();
        for (old, new) in successions {
            self.follow_correspondent(channel, &old, &new);
        }

        // Being below the oldest retained entry means we have been away longer
        // than the window. There is history we can never fill, and presenting
        // what remains as the whole conversation would be a lie.
        let gap = since > 0 && entries.first > since;

        // Who may redact and whose metadata counts — Timeline needs this, and
        // it is only in the member list.
        //
        // **Asked again only when something arrived**, or when what we were
        // told has gone stale: see `POLL_TTL`. A poll that fetched no entries
        // has nothing to attribute and nothing to fold, and the membership it
        // would be asking about cannot have moved without an entry saying so.
        let arrived = arrived || !entries.entries.is_empty();
        let mut info = match self.told_about.get(channel) {
            Some((info, at)) if !arrived && at.elapsed() < POLL_TTL => info.clone(),
            _ => {
                let fresh = self.info(channel).await?;
                self.told_about
                    .insert(*channel, (fresh.clone(), std::time::Instant::now()));
                fresh
            }
        };

        // Somebody may have rotated while this client was running — after a
        // removal, or after revoking a device. Collect once when we hold no key
        // for the epoch in force, or a client would sit showing unreadable
        // entries until it was restarted.
        if info.epoch > 0 && self.store.key(channel, info.epoch)?.is_none() {
            self.collect_keys(channel).await?;
            info = self.info(channel).await?;
            self.told_about
                .insert(*channel, (info.clone(), std::time::Instant::now()));
        }
        let admins: Vec<PubKey> = info
            .members
            .iter()
            .filter(|m| m.role == Role::Admin)
            .map(|m| m.account)
            .collect();

        // Fetched once for the batch rather than per entry: SIP-31's second
        // step needs a credential for every device that signed one, and the
        // members are who could have.
        // The same question, and the same answer: one `/device/list` per member
        // per poll, to bind signatures on entries that did not arrive.
        let bound = match self.bound_in.get(channel) {
            Some((bound, at)) if !arrived && at.elapsed() < POLL_TTL => bound.clone(),
            _ => {
                let fresh = self.bindings(&members_of(&info)).await.unwrap_or_default();
                self.bound_in
                    .insert(*channel, (fresh.clone(), std::time::Instant::now()));
                fresh
            }
        };
        let last = self.fold_entries(
            timeline,
            channel,
            &info,
            &admins,
            &bound,
            &entries.entries,
            since,
            receipts,
        )?;
        if last > since {
            self.store.set_since(channel, last)?;
        }
        // SIP-53 §Posting again: a rehome read in this batch is a fork; what was held above
        // it under the old origin is dealt with now, and the next poll reads
        // the winning history from there. A receipt under a key this client
        // does not know has the home asked again, which finds the fork the
        // same way.
        let forks = std::mem::take(&mut self.pending_forks);
        for (c, was, fork) in forks {
            let _ = self.fork_check(&c, &was, fork).await;
        }
        if self.reask_home.remove(channel) {
            self.homes.remove(channel);
            let _ = self.home(channel).await;
        }

        let typing = entries.signals.iter().any(|s| {
            use sqex_proto::message::{SIGNAL_TYPING, Signal};
            s.kind == SIGNAL_TYPING
                && matches!(Signal::decode(&s.body), Ok(Some(Signal::Typing(true))))
        });
        // The other signal SIP-36 defines, and the one nothing here read. Only
        // acceptance is taken: a decline and a hangup both post a `CallEnd`, so
        // the log already carries them, and taking those from a signal as well
        // would be believing a forgeable message about something durable.
        let accepted = entries.signals.iter().rev().find_map(|s| {
            use sqex_proto::message::{RING_ACCEPTED, SIGNAL_CALL_STATE, Signal};
            match (s.kind, Signal::decode(&s.body)) {
                (SIGNAL_CALL_STATE, Ok(Some(Signal::CallState { target, state, .. })))
                    if state == RING_ACCEPTED =>
                {
                    Some(target)
                }
                _ => None,
            }
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
            accepted,
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
    /// SIP-47 §Catching up in one round trip: everything that moved in the named channels, in one round
    /// trip -- the entries since each cursor and the envelopes waiting for
    /// this device there, plus the channels the account is in that were not
    /// named and this device's prekey count.
    ///
    /// Envelopes are opened here, on the path `collect_keys` uses, before
    /// anything is returned; entries come back as [`Fetched`] for the caller
    /// to absorb into its timelines exactly as a poll's answer is. The store
    /// therefore sees the same rows whichever route fed it.
    ///
    /// `Err(ChatError::NoChatHere(_))` is an exchange from before sqex 0.70.0 (SIP-47 §Catching up in one round trip); a
    /// caller falls back to polling, which is what it did.
    pub async fn catchup(&mut self, named: &[Named], budget: u32) -> Result<CaughtUp> {
        use sqex_proto::catchup::{Catchup, STATUS_OK};
        let body = self
            .post(
                "/channel/catchup",
                Catchup {
                    budget,
                    named: named.to_vec(),
                }
                .encode(),
            )
            .await?;
        let answer = sqex_proto::catchup::CaughtUp::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        let mut caught = Vec::with_capacity(answer.caught.len());
        for (c, asked) in answer.caught.into_iter().zip(named) {
            let mut keys_opened = 0;
            let mut fetched = None;
            if c.status == STATUS_OK {
                if !c.got.is_empty() {
                    let got =
                        Got::decode(&c.got).map_err(|e| ChatError::Protocol(e.to_string()))?;
                    if !got.envelopes.is_empty() {
                        // The incarnation, for verifying who published each
                        // envelope: one round trip, only for a channel that
                        // actually handed keys over.
                        let instance = self.info(&c.channel).await?.instance;
                        keys_opened = self.absorb_keys(&c.channel, &instance, got).await?;
                    }
                }
                if !c.fetched.is_empty() {
                    fetched = Some(Fetched::carried(c.channel, asked.since, c.fetched));
                }
            }
            caught.push(Caught {
                channel: c.channel,
                status: c.status,
                more: c.more,
                fetched,
                keys_opened,
            });
        }
        Ok(CaughtUp {
            now: answer.now,
            prekeys: answer.prekeys,
            caught,
            unnamed: answer.unnamed,
        })
    }

    /// What this client would name in a catch-up (SIP-47 §Catching up in one round trip): every channel the
    /// store holds, with where it got to in each.
    pub fn named_for_catchup(&self) -> Result<Vec<Named>> {
        let mut named = Vec::new();
        for c in self.store.channels()? {
            let (since, _, _) = self.store.cursor(&c.channel)?;
            let since_epoch = self.store.highest_epoch(&c.channel)?;
            named.push(Named {
                channel: c.channel,
                since,
                since_epoch,
            });
        }
        Ok(named)
    }

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

/// The clock, in whole seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    /// SIP-40: an entry signed and receipted under the key the exchange held
    /// before a handover verifies under that key as a predecessor, and only
    /// there -- and the chain link is taken under the key that verified, so
    /// the next entry, signed under the successor, still links.
    #[test]
    fn what_was_signed_under_a_predecessor_still_verifies_under_it() {
        let (_, old) = dev(9);
        let (_, new) = dev(10);
        let e0 = entry_at(0, 0, GENESIS, b"before the handover");
        let mut chain = HashMap::new();
        let bound = HashMap::new();
        assert_eq!(
            Chat::verdict_for(&[new], &[7u8; 32], [4u8; 32], &e0, &mut chain, &bound),
            Verdict::Forged,
            "the successor alone cannot verify what the predecessor signed"
        );
        let mut chain = HashMap::new();
        assert_eq!(
            Chat::verdict_for(&[new, old], &[7u8; 32], [4u8; 32], &e0, &mut chain, &bound),
            Verdict::Valid
        );
        // The head recorded is the link under the key that verified.
        assert_eq!(
            chain[&dev(1).1],
            (1, link_of(0, GENESIS, b"before the handover"))
        );
        // A receipt the old key issued: repudiated under the new key alone,
        // vouched for once the old key is offered as history.
        let good = stamped(e0, HEAD_GENESIS);
        assert_eq!(
            Chat::standing_under(&[new], &[7u8; 32], [4u8; 32], &good, Some(HEAD_GENESIS)),
            Standing::Repudiated
        );
        assert_eq!(
            Chat::standing_under(
                &[new, old],
                &[7u8; 32],
                [4u8; 32],
                &good,
                Some(HEAD_GENESIS)
            ),
            Standing::Vouched
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
            .map(|e| Chat::verdict_for(&[exchange], &[7u8; 32], [4u8; 32], e, &mut chain, &bound))
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
