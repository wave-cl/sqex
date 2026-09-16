//! SIP-42: history between your own devices.
//!
//! Two devices of one account hand each other the channel history each
//! holds -- the signed entries, the epoch keys that open them, and the
//! blobs they name -- over a session the exchange carries and cannot read.
//! A device admits only a sibling, shown by a SIP-20 credential from its
//! own account for the key the session was opened to, and takes from it
//! only what it can verify exactly as a fetch is verified: by the entries'
//! own signatures and the exchange's receipts. The sibling is the wire.
//!
//! Three things live here: the messages, a [`Link`] they travel on, and
//! [`Sync`], the exchange run a step at a time so that whoever owns the
//! store -- a session loop with a window to keep painting -- can run it
//! between other work.

use std::collections::{HashMap, HashSet, VecDeque};

use sqex_proto::channel::{Entry, KIND_MEMBER};
use sqex_proto::channel_key::ChannelKey;
use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqex_proto::refusal::{Code, Refusal};
use sqex_proto::session::{BySession, Frames, MAX_FRAME, SendFrame, Session};
use sqex_proto::timeline::Timeline;
use sqnr_core::{PubKey, Result as ProtoResult};

use crate::client::{Chat, ChatError};

type Result<T> = std::result::Result<T, ChatError>;

pub const TYPE_HELLO: u8 = 0x01;
pub const TYPE_HAVE: u8 = 0x02;
pub const TYPE_WANT: u8 = 0x03;
pub const TYPE_ENTRIES: u8 = 0x04;
pub const TYPE_KEYS: u8 = 0x05;
pub const TYPE_BLOB: u8 = 0x06;
pub const TYPE_DONE: u8 = 0x07;

/// Entries per page, as SIP-35's pull.
pub const PAGE: usize = 256;
/// Bytes per page, as SIP-35's pull.
pub const PAGE_BYTES: usize = 1024 * 1024;
/// The most a message may be: a page and its header, or a blob chunk.
pub const MAX_MESSAGE: usize = PAGE_BYTES + 4096;

/// Plaintext per SIP-12 frame: the frame cap less the seal's tag.
const PIECE: usize = MAX_FRAME - 64;

/// What one side holds of one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub channel: [u8; 32],
    pub instance: [u8; 32],
    pub first: u64,
    pub last: u64,
    pub epochs: u16,
}

/// One message, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello {
        account: PubKey,
        credential: Option<Credential>,
    },
    Have(Vec<Held>),
    /// Everything wanted, in one message: `since` is the highest seq held.
    Want(Vec<([u8; 32], u64)>),
    Entries {
        channel: [u8; 32],
        instance: [u8; 32],
        entries: Vec<Entry>,
    },
    Keys {
        channel: [u8; 32],
        keys: Vec<(u32, [u8; 32])>,
    },
    Blob {
        id: [u8; 32],
        chunk: u32,
        of: u32,
        bytes: Vec<u8>,
    },
    Done,
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Message::Hello {
                account,
                credential,
            } => {
                out.push(TYPE_HELLO);
                out.extend_from_slice(account.as_bytes());
                if let Some(c) = credential {
                    out.extend_from_slice(&c.encode());
                }
            }
            Message::Have(held) => {
                out.push(TYPE_HAVE);
                out.extend_from_slice(&(held.len() as u16).to_be_bytes());
                for h in held {
                    out.extend_from_slice(&h.channel);
                    out.extend_from_slice(&h.instance);
                    out.extend_from_slice(&h.first.to_be_bytes());
                    out.extend_from_slice(&h.last.to_be_bytes());
                    out.extend_from_slice(&h.epochs.to_be_bytes());
                }
            }
            Message::Want(wants) => {
                out.push(TYPE_WANT);
                out.extend_from_slice(&(wants.len() as u16).to_be_bytes());
                for (channel, since) in wants {
                    out.extend_from_slice(channel);
                    out.extend_from_slice(&since.to_be_bytes());
                }
            }
            Message::Entries {
                channel,
                instance,
                entries,
            } => {
                out.push(TYPE_ENTRIES);
                out.extend_from_slice(channel);
                out.extend_from_slice(instance);
                out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
                for e in entries {
                    e.write_receipted(&mut out);
                }
            }
            Message::Keys { channel, keys } => {
                out.push(TYPE_KEYS);
                out.extend_from_slice(channel);
                out.extend_from_slice(&(keys.len() as u16).to_be_bytes());
                for (epoch, key) in keys {
                    out.extend_from_slice(&epoch.to_be_bytes());
                    out.extend_from_slice(key);
                }
            }
            Message::Blob {
                id,
                chunk,
                of,
                bytes,
            } => {
                out.push(TYPE_BLOB);
                out.extend_from_slice(id);
                out.extend_from_slice(&chunk.to_be_bytes());
                out.extend_from_slice(&of.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Message::Done => out.push(TYPE_DONE),
        }
        out
    }

    pub fn decode(b: &[u8]) -> ProtoResult<Message> {
        use sqnr_core::Error::Malformed;
        let short = || Malformed("sync message cut short".into());
        let take32 = |at: &mut usize| -> ProtoResult<[u8; 32]> {
            let s = b.get(*at..*at + 32).ok_or_else(short)?;
            *at += 32;
            Ok(s.try_into().unwrap())
        };
        let take_u64 = |at: &mut usize| -> ProtoResult<u64> {
            let s = b.get(*at..*at + 8).ok_or_else(short)?;
            *at += 8;
            Ok(u64::from_be_bytes(s.try_into().unwrap()))
        };
        let take_u32 = |at: &mut usize| -> ProtoResult<u32> {
            let s = b.get(*at..*at + 4).ok_or_else(short)?;
            *at += 4;
            Ok(u32::from_be_bytes(s.try_into().unwrap()))
        };
        let take_u16 = |at: &mut usize| -> ProtoResult<u16> {
            let s = b.get(*at..*at + 2).ok_or_else(short)?;
            *at += 2;
            Ok(u16::from_be_bytes(s.try_into().unwrap()))
        };
        let kind = *b.first().ok_or_else(short)?;
        let mut at = 1;
        let message = match kind {
            TYPE_HELLO => {
                let account = PubKey::new(take32(&mut at)?);
                let credential = if at == b.len() {
                    None
                } else {
                    Some(Credential::decode(&b[at..])?)
                };
                at = b.len();
                Message::Hello {
                    account,
                    credential,
                }
            }
            TYPE_HAVE => {
                let count = take_u16(&mut at)? as usize;
                let mut held = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    held.push(Held {
                        channel: take32(&mut at)?,
                        instance: take32(&mut at)?,
                        first: take_u64(&mut at)?,
                        last: take_u64(&mut at)?,
                        epochs: take_u16(&mut at)?,
                    });
                }
                Message::Have(held)
            }
            TYPE_WANT => {
                let count = take_u16(&mut at)? as usize;
                let mut wants = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    wants.push((take32(&mut at)?, take_u64(&mut at)?));
                }
                Message::Want(wants)
            }
            TYPE_ENTRIES => {
                let channel = take32(&mut at)?;
                let instance = take32(&mut at)?;
                let count = take_u16(&mut at)? as usize;
                if count > PAGE {
                    return Err(Malformed(format!("{count} entries in one page")));
                }
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(Entry::read_receipted(b, &mut at)?);
                }
                Message::Entries {
                    channel,
                    instance,
                    entries,
                }
            }
            TYPE_KEYS => {
                let channel = take32(&mut at)?;
                let count = take_u16(&mut at)? as usize;
                let mut keys = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    keys.push((take_u32(&mut at)?, take32(&mut at)?));
                }
                Message::Keys { channel, keys }
            }
            TYPE_BLOB => {
                let id = take32(&mut at)?;
                let chunk = take_u32(&mut at)?;
                let of = take_u32(&mut at)?;
                let bytes = b[at..].to_vec();
                at = b.len();
                Message::Blob {
                    id,
                    chunk,
                    of,
                    bytes,
                }
            }
            TYPE_DONE => Message::Done,
            other => return Err(Malformed(format!("unknown sync message {other:#x}"))),
        };
        if at != b.len() {
            return Err(Malformed(format!(
                "sync message has {} trailing bytes",
                b.len() - at
            )));
        }
        Ok(message)
    }
}

/// What the frames travel on: something that carries sealed frames both
/// ways, in order, reliably -- a SIP-12 session's reliable path, or a
/// stream on a direct connection. Sealing is [`Sync`]'s; the link moves
/// ciphertext, each frame with the sequence number it was sealed under.
pub trait Link {
    /// Hand a sealed frame over. `Ok(false)` means the far side cannot take
    /// more right now (SIP-12 backpressure); the same frame is offered
    /// again on a later step.
    fn send(
        &mut self,
        seq: u64,
        sealed: &[u8],
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    /// Everything that arrived since last asked, in order, with each
    /// frame's sequence number; empty when nothing has. `Err` when the link
    /// is gone.
    fn recv(&mut self) -> impl std::future::Future<Output = Result<Vec<(u64, Vec<u8>)>>> + Send;
}

/// Where a sync has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nothing exchanged yet: `Hello` goes first.
    Greeting,
    /// Greeted; waiting to be admitted and to hear what they hold.
    Listing,
    /// Wants exchanged; serving theirs and taking what they send.
    Trading,
    /// Both sides said `Done` and everything sent has gone.
    Finished,
    /// Ended without finishing; `why` says how.
    Failed,
}

/// What a sync did, for the person: counted, not narrated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Progress {
    /// Entries kept, of every kind.
    pub entries_in: usize,
    /// Of those, the ones somebody wrote: what a person would call messages.
    pub messages_in: usize,
    pub entries_out: usize,
    pub keys_in: usize,
    pub blobs_in: usize,
    pub channels_in: HashSet<[u8; 32]>,
}

/// One sync with one sibling, run a step at a time.
///
/// Symmetric: each side runs the same machine, and either may end up
/// giving more than it gets. The store is the caller's [`Chat`], borrowed
/// for each step and given back, so the caller keeps painting between
/// steps. Messages ride the session's reliable path as a byte stream, each
/// prefixed by its length, cut into frames where a frame is full; a page
/// or a blob chunk larger than a frame simply spans several.
pub struct Sync {
    session: Session,
    /// The key the session was opened to: who the credential must name.
    peer: PubKey,
    phase: Phase,
    pub why: Option<String>,
    pub progress: Progress,

    // Outbound: sealed frames waiting for the link to take them.
    out_seq: u64,
    outbox: VecDeque<(u64, Vec<u8>)>,
    // Inbound: plaintext bytes not yet a whole message.
    inbox: Vec<u8>,

    /// What we owe them: channels they wanted, with where they had got to.
    owed: VecDeque<([u8; 32], u64)>,
    /// Channels we have sent keys for this session.
    keyed: HashSet<[u8; 32]>,
    got_have: bool,
    got_want: bool,
    sent_done: bool,
    got_done: bool,

    /// Timelines for the channels being imported, so entries fold in order
    /// as they arrive.
    timelines: HashMap<[u8; 32], Timeline>,
    /// Blobs named by imported entries and not held; a blob nobody asked
    /// for is dropped on the floor.
    blobs_wanted: HashSet<[u8; 32]>,
    blob_parts: HashMap<[u8; 32], Vec<Option<Vec<u8>>>>,
}

impl Sync {
    /// Begin, with the session key agreed for the sibling at `peer`.
    pub fn new(session: Session, peer: PubKey) -> Sync {
        Sync {
            session,
            peer,
            phase: Phase::Greeting,
            why: None,
            progress: Progress::default(),
            out_seq: 0,
            outbox: VecDeque::new(),
            inbox: Vec::new(),
            owed: VecDeque::new(),
            keyed: HashSet::new(),
            got_have: false,
            got_want: false,
            sent_done: false,
            got_done: false,
            timelines: HashMap::new(),
            blobs_wanted: HashSet::new(),
            blob_parts: HashMap::new(),
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn peer(&self) -> PubKey {
        self.peer
    }

    fn fail(&mut self, why: impl Into<String>) {
        self.phase = Phase::Failed;
        self.why = Some(why.into());
        self.outbox.clear();
    }

    /// Queue a message: length-prefixed, cut into frames, sealed.
    fn queue(&mut self, message: &Message) -> Result<()> {
        let body = message.encode();
        let mut stream = Vec::with_capacity(4 + body.len());
        stream.extend_from_slice(&(body.len() as u32).to_be_bytes());
        stream.extend_from_slice(&body);
        for piece in stream.chunks(PIECE) {
            let sealed = self
                .session
                .seal(self.out_seq, piece)
                .map_err(|e| ChatError::Protocol(e.to_string()))?;
            self.outbox.push_back((self.out_seq, sealed));
            self.out_seq += 1;
        }
        Ok(())
    }

    /// One step: take what arrived, serve a page of what is owed, send
    /// what the link will take. Returns whether there is more to do.
    pub async fn step<L: Link>(&mut self, chat: &mut Chat, link: &mut L) -> Result<bool> {
        match self.phase {
            Phase::Finished | Phase::Failed => return Ok(false),
            Phase::Greeting => {
                let hello = Message::Hello {
                    account: chat.me,
                    credential: chat.credential(),
                };
                self.queue(&hello)?;
                self.phase = Phase::Listing;
            }
            _ => {}
        }

        // In. A link that has gone ends the sync, and says so both ways.
        let arrived = match link.recv().await {
            Ok(a) => a,
            Err(e) => {
                self.fail(format!("the link ended: {e}"));
                return Err(e);
            }
        };
        for (seq, sealed) in arrived {
            match self.session.open(seq, &sealed) {
                Ok(plain) => self.inbox.extend_from_slice(&plain),
                Err(e) => {
                    self.fail(format!("a frame from the sibling did not open: {e}"));
                    return Ok(false);
                }
            }
        }
        while let Some(message) = self.next_message()? {
            if let Err(e) = self.take(chat, message).await {
                self.fail(e.to_string());
                return Ok(false);
            }
            if self.phase == Phase::Failed {
                return Ok(false);
            }
        }

        // Serve one page of what is owed, once the last has gone.
        if self.phase == Phase::Trading
            && self.outbox.is_empty()
            && let Some((channel, since)) = self.owed.front().copied()
        {
            self.serve(chat, channel, since)?;
        }
        // Done once they have said all they want and it has been served.
        if self.phase == Phase::Trading && self.got_want && self.owed.is_empty() && !self.sent_done
        {
            self.queue(&Message::Done)?;
            self.sent_done = true;
        }

        // Out, as far as the link will take it.
        while let Some((seq, sealed)) = self.outbox.front() {
            match link.send(*seq, sealed).await {
                Ok(true) => {
                    self.outbox.pop_front();
                }
                Ok(false) => break,
                Err(e) => {
                    self.fail(format!("the link ended: {e}"));
                    return Err(e);
                }
            }
        }

        if self.sent_done && self.got_done && self.outbox.is_empty() {
            self.phase = Phase::Finished;
            return Ok(false);
        }
        Ok(true)
    }

    /// The next whole message in the inbox, if one has arrived.
    fn next_message(&mut self) -> Result<Option<Message>> {
        if self.inbox.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(self.inbox[..4].try_into().unwrap()) as usize;
        if len > MAX_MESSAGE {
            return Err(ChatError::Protocol(format!(
                "the sibling sent a {len}-byte message"
            )));
        }
        if self.inbox.len() < 4 + len {
            return Ok(None);
        }
        let rest = self.inbox.split_off(4 + len);
        let body = std::mem::replace(&mut self.inbox, rest);
        let message =
            Message::decode(&body[4..]).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(Some(message))
    }

    async fn take(&mut self, chat: &mut Chat, message: Message) -> Result<()> {
        match message {
            Message::Hello {
                account,
                credential,
            } => {
                // The door. Our own account; a credential from it for the key
                // this session was opened to, current by the exchange's clock
                // and on its device list today; or the account itself, which
                // needs none.
                if account != chat.me {
                    self.fail("the other side is not this account");
                    return Ok(());
                }
                let (listed, now) = chat.sibling_listed(&self.peer).await?;
                match credential {
                    Some(c) => {
                        if c.delegate != self.peer {
                            self.fail("the credential names another device");
                            return Ok(());
                        }
                        if let Err(e) = c.verify(&chat.me, SCOPE_CHAT, now) {
                            self.fail(format!("the credential does not verify: {e:?}"));
                            return Ok(());
                        }
                        if !listed {
                            self.fail("the exchange no longer lists that device");
                            return Ok(());
                        }
                    }
                    None => {
                        if self.peer != chat.me || !listed {
                            self.fail("no credential, and not the account itself");
                            return Ok(());
                        }
                    }
                }
                // Admitted: say what we hold.
                let held = chat.held_for_siblings()?;
                self.queue(&Message::Have(held))?;
            }
            Message::Have(theirs) => {
                // Want what they hold beyond what we do, in an incarnation
                // we know or do not know at all. One message, so its arrival
                // is the whole list.
                let mut wants = Vec::new();
                let ranges = chat.store().entry_ranges()?;
                for h in &theirs {
                    let known = chat.store().incarnation(&h.channel)?;
                    if known.is_some_and(|k| k != h.instance) {
                        continue;
                    }
                    // From where this side lacks nothing of theirs: its own
                    // top when its copy starts at or before theirs, and
                    // from under their first otherwise -- a device that
                    // fetched only the exchange's newest holds the top of
                    // the channel and none of what came before it.
                    let mine = ranges
                        .iter()
                        .find(|(c, _, _)| *c == h.channel)
                        .map(|(_, first, last)| (*first, *last));
                    let since = match mine {
                        None => 0,
                        Some((first, last)) if first <= h.first => last,
                        Some(_) => h.first.saturating_sub(1),
                    };
                    let my_epochs = chat.store().keys_of(&h.channel)?.len();
                    if h.last > since || usize::from(h.epochs) > my_epochs {
                        wants.push((h.channel, since));
                    }
                }
                self.queue(&Message::Want(wants))?;
                self.got_have = true;
                if self.got_want {
                    self.phase = Phase::Trading;
                }
            }
            Message::Want(wants) => {
                self.owed.extend(wants);
                self.got_want = true;
                if self.got_have {
                    self.phase = Phase::Trading;
                }
            }
            Message::Keys { channel, keys } => {
                for (epoch, key) in keys {
                    chat.store()
                        .put_key(&channel, epoch, &ChannelKey::new(key))?;
                    self.progress.keys_in += 1;
                }
                self.progress.channels_in.insert(channel);
            }
            Message::Entries {
                channel,
                instance,
                entries,
            } => {
                let timeline = self.timelines.entry(channel).or_default();
                let posts: Vec<u64> = entries
                    .iter()
                    .filter(|e| e.kind == KIND_MEMBER && !chat.has_entry(&channel, e.seq))
                    .map(|e| e.seq)
                    .collect();
                let n = chat.import(timeline, &channel, instance, &entries).await?;
                self.progress.entries_in += n;
                self.progress.messages_in += posts
                    .iter()
                    .filter(|seq| chat.has_entry(&channel, **seq))
                    .count();
                if n > 0 {
                    self.progress.channels_in.insert(channel);
                }
                // Blobs the entries name that this device lacks, to be taken
                // when they come.
                for e in &entries {
                    for id in blobs_named(chat, &channel, e) {
                        if !chat.store().has_blob(&id)? {
                            self.blobs_wanted.insert(id);
                        }
                    }
                }
            }
            Message::Blob {
                id,
                chunk,
                of,
                bytes,
            } => {
                if !self.blobs_wanted.contains(&id) || of == 0 || chunk >= of {
                    return Ok(());
                }
                let parts = self
                    .blob_parts
                    .entry(id)
                    .or_insert_with(|| vec![None; of as usize]);
                if parts.len() != of as usize {
                    return Ok(());
                }
                parts[chunk as usize] = Some(bytes);
                if parts.iter().all(Option::is_some) {
                    let chunks: Vec<Vec<u8>> = self
                        .blob_parts
                        .remove(&id)
                        .unwrap()
                        .into_iter()
                        .flatten()
                        .collect();
                    // SIP-18: the name is the hash of the sealed chunks.
                    if sqex_proto::blob_store::blob_id(&chunks) == id {
                        chat.store().keep_blob(&id, &chunks)?;
                        self.blobs_wanted.remove(&id);
                        self.progress.blobs_in += 1;
                    }
                }
            }
            Message::Done => {
                self.got_done = true;
            }
        }
        Ok(())
    }

    /// Serve the next page of one owed channel: keys once, then entries,
    /// then the blobs the page names; the channel is owed no more once a
    /// page comes back short.
    fn serve(&mut self, chat: &mut Chat, channel: [u8; 32], since: u64) -> Result<()> {
        if self.keyed.insert(channel) {
            let keys: Vec<(u32, [u8; 32])> = chat
                .store()
                .keys_of(&channel)?
                .into_iter()
                .map(|(e, k)| (e, *k.as_bytes()))
                .collect();
            if !keys.is_empty() {
                self.queue(&Message::Keys { channel, keys })?;
            }
        }
        let instance = chat.store().incarnation(&channel)?.unwrap_or([0; 32]);
        let raw = chat.store().entries_after(&channel, since, PAGE)?;
        let mut entries = Vec::with_capacity(raw.len());
        let mut bytes = 0;
        let mut last = since;
        for (seq, b) in &raw {
            if bytes + b.len() > PAGE_BYTES && !entries.is_empty() {
                break;
            }
            let mut at = 0;
            if let Ok(e) = Entry::read_receipted(b, &mut at) {
                bytes += b.len();
                last = *seq;
                entries.push(e);
            }
        }
        let count = entries.len();
        let named: Vec<[u8; 32]> = entries
            .iter()
            .flat_map(|e| blobs_named(chat, &channel, e))
            .collect();
        if count > 0 {
            self.queue(&Message::Entries {
                channel,
                instance,
                entries,
            })?;
            self.progress.entries_out += count;
        }
        for id in named {
            if let Some(chunks) = chat.store().blob(&id)? {
                let of = chunks.len() as u32;
                for (i, bytes) in chunks.into_iter().enumerate() {
                    self.queue(&Message::Blob {
                        id,
                        chunk: i as u32,
                        of,
                        bytes,
                    })?;
                }
            }
        }
        // More of this channel next time, or done with it.
        if count > 0 && last < chat.store().highest_entry(&channel)? {
            if let Some(front) = self.owed.front_mut() {
                front.1 = last;
            }
        } else {
            self.owed.pop_front();
        }
        Ok(())
    }
}

/// The blobs an entry names, read through the key this device holds; an
/// entry that cannot be opened names nothing this device can send.
fn blobs_named(chat: &Chat, channel: &[u8; 32], e: &Entry) -> Vec<[u8; 32]> {
    use sqex_proto::message::Body;
    let plain = if e.epoch == 0 {
        Some(e.body.clone())
    } else {
        chat.store()
            .key(channel, e.epoch)
            .ok()
            .flatten()
            .and_then(|k| k.open(channel, e.epoch, &e.device, e.msg_seq, &e.body).ok())
    };
    let Some(plain) = plain else {
        return Vec::new();
    };
    match Body::decode(&plain) {
        Ok(Some(Body::Post(p))) | Ok(Some(Body::Edit { post: p, .. })) => {
            p.attachments().map(|a| a.blob).collect()
        }
        _ => Vec::new(),
    }
}

/// SIP-12's reliable path as a [`Link`]: frames go by `/session/send` and
/// come back by `/session/recv`, on the connection this device already
/// holds to its exchange.
pub struct Relayed {
    client: sqnr::Client,
    session_id: u64,
}

impl Relayed {
    pub fn new(client: sqnr::Client, session_id: u64) -> Relayed {
        Relayed { client, session_id }
    }

    /// One try at meeting a sibling: SIP-12 `open` toward `peer`, offering
    /// `ephemeral`. `None` while they have not opened toward us -- the
    /// exchange says nothing else about them, and a caller asks again
    /// later with the same ephemeral. `Some` is the live session, keyed.
    pub async fn meet(
        mut client: sqnr::Client,
        seed: &[u8; 32],
        ephemeral: &x25519_dalek::StaticSecret,
        peer: &PubKey,
    ) -> Result<Option<(Relayed, Session)>> {
        use sqex_proto::session::{Open, OpenAck, OpenState};
        let open = Open {
            peer: *peer,
            ephemeral: x25519_dalek::PublicKey::from(ephemeral).to_bytes(),
        };
        let (code, body) = client
            .post("/session/open", open.encode())
            .await
            .map_err(ChatError::Transport)?;
        if code != 200 {
            return Err(ChatError::Protocol(format!(
                "session open refused ({code})"
            )));
        }
        let ack = OpenAck::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if ack.state != OpenState::Established {
            return Ok(None);
        }
        let session = Session::derive(seed, ephemeral, peer, &ack.peer_ephemeral)
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(Some((Relayed::new(client, ack.session_id), session)))
    }

    /// Say the session is over.
    pub async fn close(&mut self) {
        let _ = self
            .client
            .post("/session/close", BySession::close(self.session_id).encode())
            .await;
    }
}

impl Link for Relayed {
    async fn send(&mut self, seq: u64, sealed: &[u8]) -> Result<bool> {
        let frame = SendFrame {
            session_id: self.session_id,
            seq,
            ciphertext: sealed.to_vec(),
        };
        let (code, body) = self
            .client
            .post("/session/send", frame.encode())
            .await
            .map_err(ChatError::Transport)?;
        match code {
            200 => Ok(true),
            409 if Refusal::decode(&body).is_ok_and(|r| r.code == Code::Backpressure) => Ok(false),
            other => Err(ChatError::Protocol(format!(
                "session send refused ({other})"
            ))),
        }
    }

    async fn recv(&mut self) -> Result<Vec<(u64, Vec<u8>)>> {
        let (code, body) = self
            .client
            .post("/session/recv", BySession::recv(self.session_id).encode())
            .await
            .map_err(ChatError::Transport)?;
        if code != 200 {
            return Err(ChatError::Protocol(format!(
                "session recv refused ({code})"
            )));
        }
        let frames = Frames::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if !frames.open && frames.frames.is_empty() {
            return Err(ChatError::Protocol("the session closed".into()));
        }
        Ok(frames.frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    /// Every message round-trips, and one with something after its end is
    /// refused.
    #[test]
    fn messages_round_trip() {
        let all = vec![
            Message::Hello {
                account: key(1),
                credential: None,
            },
            Message::Have(vec![Held {
                channel: [2; 32],
                instance: [3; 32],
                first: 1,
                last: 40,
                epochs: 2,
            }]),
            Message::Want(vec![([2; 32], 7), ([9; 32], 0)]),
            Message::Want(vec![]),
            Message::Keys {
                channel: [2; 32],
                keys: vec![(1, [4; 32]), (2, [5; 32])],
            },
            Message::Blob {
                id: [6; 32],
                chunk: 0,
                of: 2,
                bytes: vec![1, 2, 3],
            },
            Message::Done,
        ];
        for m in all {
            assert_eq!(Message::decode(&m.encode()).unwrap(), m, "{m:?}");
        }
        let mut raw = Message::Done.encode();
        raw.push(0);
        assert!(Message::decode(&raw).is_err());
        assert!(Message::decode(&[0x42]).is_err());
        assert!(Message::decode(&[TYPE_HAVE, 0, 1]).is_err(), "cut short");
    }
}
