//! SIP-16 channels: a durable, ordered log the exchange prunes.
//!
//! A channel is the first thing in this stack the exchange must *remember*.
//! Every other service argues that forgetting is correct — the beacon because
//! replaying observations it did not make would be a lie, a session and a room
//! because a restart honestly ends them — and a conversation cannot make that
//! argument. So this one persists, and an exchange offering it is promising
//! something the other four never did.
//!
//! # What this module is and is not
//!
//! It is layouts and limits. The exchange assigns each accepted entry a
//! sequence number and that total order is the only one; there is no causal
//! clock here, because the exchange is already the sole authority on
//! availability and membership and a sequence number sits on that side of the
//! line (SIP-28 draws it).
//!
//! An entry's `body` is **opaque**. In a public channel it is a SIP-19 message
//! in the clear; in a private one it is sealed under SIP-17 and nothing here
//! can read it. Neither case is this module's business.
//!
//! # Scope of the current implementation
//!
//! Public channels only, which is why `epoch` and `msg_seq` are carried on the
//! wire and always zero: SIP-16 says a public channel seals nothing, so there
//! is no key to select and no nonce to count. The fields are present because
//! the format is the format — a later private-channel implementation must not
//! be a different wire.

use sqnr_core::{Error, PubKey, Result};

/// Domain separator for a channel identifier derived from two accounts.
pub const CHANNEL_CONTEXT: &[u8] = b"sqex-channel-v1";

pub const TYPE_CREATE: u8 = 0x01;
pub const TYPE_JOIN: u8 = 0x02;
pub const TYPE_INVITE: u8 = 0x03;
pub const TYPE_REMOVE: u8 = 0x04;
pub const TYPE_LEAVE: u8 = 0x05;
pub const TYPE_POST: u8 = 0x06;
pub const TYPE_FETCH: u8 = 0x07;
pub const TYPE_INFO: u8 = 0x08;
pub const TYPE_RETAIN: u8 = 0x09;
pub const TYPE_SIGNAL: u8 = 0x0a;
pub const TYPE_LIST: u8 = 0x0b;
pub const TYPE_CURSOR: u8 = 0x0c;
pub const TYPE_CURSORS: u8 = 0x0d;
pub const TYPE_REDACT: u8 = 0x0e;
pub const TYPE_CLOSE: u8 = 0x0f;
pub const TYPE_MINE: u8 = 0x10;

/// An entry the exchange wrote itself: membership and rotation events, which
/// it can attest to because it is the authority on both.
pub const KIND_SYSTEM: u8 = 0x00;
/// An entry a member posted.
pub const KIND_MEMBER: u8 = 0x01;

pub const EVENT_ADDED: u8 = 0x01;
pub const EVENT_REMOVED: u8 = 0x02;
pub const EVENT_LEFT: u8 = 0x03;
pub const EVENT_JOINED: u8 = 0x04;
pub const EVENT_PROMOTED: u8 = 0x05;
pub const EVENT_DEMOTED: u8 = 0x06;
pub const EVENT_ROTATED: u8 = 0x07;
pub const EVENT_RETENTION: u8 = 0x08;

/// The body of an entry the exchange wrote itself.
///
/// These are the exchange's record and a client MUST NOT post one. Two reasons,
/// and both matter: the exchange cannot seal, so it could not write into a
/// private channel's sealed stream even if it wanted to — and a client-posted
/// membership event would be a claim by the very admin whose action it
/// describes, which is no record at all. It is already the sole authority on
/// membership and already holds every one of these facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct System {
    pub event: u8,
    pub subject: PubKey,
    pub actor: PubKey,
}

impl System {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(self.event);
        out.extend_from_slice(self.subject.as_bytes());
        out.extend_from_slice(self.actor.as_bytes());
        out
    }

    /// `Ok(None)` for an event we do not know, which a reader ignores — the
    /// same rule SIP-19 applies to its own body types.
    pub fn decode(b: &[u8]) -> Result<Option<System>> {
        if b.len() != 65 {
            return Err(Error::Malformed(format!(
                "system entry is {} bytes, want 65",
                b.len()
            )));
        }
        if b[0] == 0 || b[0] > EVENT_RETENTION {
            return Ok(None);
        }
        Ok(Some(System {
            event: b[0],
            subject: key_at(b, 1),
            actor: key_at(b, 33),
        }))
    }
}

/// Members one channel may hold.
pub const MAX_MEMBERS: usize = 256;
/// Bytes of entry body. Bounded by the 64 KiB request cap: a `Post` must fit
/// one request whole, because nothing in this stack streams.
pub const MAX_ENTRY_BODY: usize = 32 * 1024;
/// Entries retained per channel before the oldest are pruned.
pub const MAX_ENTRIES: u64 = 50_000;
/// Stored entry bytes per channel.
pub const MAX_CHANNEL_BYTES: u64 = 128 * 1024 * 1024;

pub const MIN_RETENTION: u32 = 60 * 60;
pub const DEFAULT_RETENTION: u32 = 30 * 24 * 60 * 60;
pub const MAX_RETENTION: u32 = 365 * 24 * 60 * 60;

/// Channels one identity may have created and not yet closed.
pub const MAX_CHANNELS_PER_IDENTITY: usize = 256;
/// Channels an identity may be invited to and not yet posted in.
///
/// The anti-spam measure. Anyone may invite anyone, so without it an identity
/// can be added to unbounded numbers of channels by strangers. An invitation
/// makes somebody a member immediately — there is no pending state at the
/// exchange to count — so this counts memberships never spoken in, and a
/// further invite is refused until they post in one or leave it.
pub const MAX_UNSPOKEN: usize = 64;
/// Entries returned by one `Fetch`.
pub const MAX_BATCH: usize = 64;
/// Bytes returned by one `Fetch`, whichever binds first.
pub const MAX_BATCH_BYTES: usize = 512 * 1024;
/// Rows returned by one directory `List`.
pub const MAX_DIRECTORY: usize = 64;
/// Memberships returned by one `Mine`.
pub const MAX_MINE: usize = 64;
/// Longest a `Fetch` may be held open.
pub const MAX_WAIT: u16 = 25;
/// A public channel with no members and no entries for this long is closed by
/// the exchange. Narrow on purpose: a room somebody reads has members, and one
/// with history has entries, so neither is touched.
pub const ABANDON_SECS: u64 = 30 * 24 * 60 * 60;

pub const MAX_NAME: usize = 64;
pub const MAX_TOPIC: usize = 256;
pub const MAX_QUERY: usize = 64;

/// Whether a channel is listed and readable by anyone who joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Visibility {
    Private = 0,
    Public = 1,
}

impl Visibility {
    pub fn from_u8(b: u8) -> Result<Visibility> {
        match b {
            0 => Ok(Visibility::Private),
            1 => Ok(Visibility::Public),
            other => Err(Error::Malformed(format!("unknown visibility {other}"))),
        }
    }
}

/// What an account may do. There are two and no more; a finer permission model
/// is a policy question for whatever is built on this, not for the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Member = 0,
    Admin = 1,
}

impl Role {
    pub fn from_u8(b: u8) -> Result<Role> {
        match b {
            0 => Ok(Role::Member),
            1 => Ok(Role::Admin),
            other => Err(Error::Malformed(format!("unknown role {other}"))),
        }
    }
}

/// A channel identifier: 32 bytes, random for a room, derived for a direct
/// message so both ends arrive at the same one without having spoken.
pub fn direct_message_id(a: &PubKey, b: &PubKey) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    // Lexicographic order, as SIP-12 does: it settles which value goes first
    // without either side negotiating, and makes the derivation identical on
    // both ends. Accounts, never devices — from device keys each pair of
    // clients would get its own channel.
    let (first, second) = if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };
    let mut h = Sha256::new();
    h.update(CHANNEL_CONTEXT);
    h.update([0x01]);
    h.update(first.as_bytes());
    h.update(second.as_bytes());
    h.finalize().into()
}

fn want(b: &[u8], n: usize, what: &str) -> Result<()> {
    if b.len() < n {
        return Err(Error::Malformed(format!(
            "{what} is {} bytes, want at least {n}",
            b.len()
        )));
    }
    Ok(())
}

fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}
fn key_at(b: &[u8], o: usize) -> PubKey {
    PubKey::new(b[o..o + 32].try_into().unwrap())
}

/// An account named in a `Create`'s invite list, with the role it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invitee {
    pub account: PubKey,
    pub role: Role,
}

/// Create a channel, idempotently on its identifier.
///
/// The `invites` list is what makes the direct-message race safe: both ends
/// derive the same identifier and create it naming the other, so whichever
/// request lands first produces a channel already containing both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Create {
    pub channel: [u8; 32],
    pub visibility: Visibility,
    pub retention_secs: u32,
    pub max_entries: u32,
    pub name: String,
    pub topic: String,
    pub invites: Vec<Invitee>,
}

impl Create {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.name.len() + self.topic.len());
        out.push(TYPE_CREATE);
        out.extend_from_slice(&self.channel);
        out.push(self.visibility as u8);
        out.extend_from_slice(&self.retention_secs.to_be_bytes());
        out.extend_from_slice(&self.max_entries.to_be_bytes());
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&(self.topic.len() as u16).to_be_bytes());
        out.extend_from_slice(self.topic.as_bytes());
        out.push(self.invites.len() as u8);
        for i in &self.invites {
            out.extend_from_slice(i.account.as_bytes());
            out.push(i.role as u8);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Create> {
        want(b, 43, "create")?;
        if b[0] != TYPE_CREATE {
            return Err(Error::Malformed(format!("not a create (type {:#x})", b[0])));
        }
        let channel: [u8; 32] = b[1..33].try_into().unwrap();
        let visibility = Visibility::from_u8(b[33])?;
        let retention_secs = u32at(b, 34);
        let max_entries = u32at(b, 38);

        let name_len = b[42] as usize;
        if name_len > MAX_NAME {
            return Err(Error::Malformed(format!(
                "name is {name_len} bytes, limit is {MAX_NAME}"
            )));
        }
        let mut o = 43;
        want(b, o + name_len + 2, "create")?;
        let name = utf8(&b[o..o + name_len], "name")?;
        o += name_len;

        let topic_len = u16at(b, o) as usize;
        o += 2;
        if topic_len > MAX_TOPIC {
            return Err(Error::Malformed(format!(
                "topic is {topic_len} bytes, limit is {MAX_TOPIC}"
            )));
        }
        want(b, o + topic_len + 1, "create")?;
        let topic = utf8(&b[o..o + topic_len], "topic")?;
        o += topic_len;

        let count = b[o] as usize;
        o += 1;
        if count > MAX_MEMBERS {
            return Err(Error::Malformed(format!(
                "create invites {count} accounts, limit is {MAX_MEMBERS}"
            )));
        }
        if b.len() != o + count * 33 {
            return Err(Error::Malformed(format!(
                "create is {} bytes, want {}",
                b.len(),
                o + count * 33
            )));
        }
        let mut invites = Vec::with_capacity(count);
        for i in 0..count {
            let at = o + i * 33;
            invites.push(Invitee {
                account: key_at(b, at),
                role: Role::from_u8(b[at + 32])?,
            });
        }
        Ok(Create {
            channel,
            visibility,
            retention_secs,
            max_entries,
            name,
            topic,
            invites,
        })
    }
}

fn utf8(b: &[u8], what: &str) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| Error::Malformed(format!("{what} is not UTF-8")))
}

/// A request naming only a channel: join, leave, info, close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByChannel {
    pub channel: [u8; 32],
}

impl ByChannel {
    pub fn encode(&self, type_byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(type_byte);
        out.extend_from_slice(&self.channel);
        out
    }

    pub fn decode(b: &[u8], type_byte: u8) -> Result<ByChannel> {
        if b.len() != 33 {
            return Err(Error::Malformed(format!(
                "request is {} bytes, want 33",
                b.len()
            )));
        }
        if b[0] != type_byte {
            return Err(Error::Malformed(format!(
                "wrong request type ({:#x}, want {type_byte:#x})",
                b[0]
            )));
        }
        Ok(ByChannel {
            channel: b[1..33].try_into().unwrap(),
        })
    }
}

/// Append an entry to a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Post {
    pub channel: [u8; 32],
    pub epoch: u32,
    pub msg_seq: u64,
    /// Disappearing-message timer in seconds, 0 for none. The exchange prunes
    /// at `posted + expires_after` as a backstop; a client deletes its own copy
    /// at its own read time plus the timer, which is the feature as a person
    /// experiences it.
    pub expires_after: u32,
    pub body: Vec<u8>,
}

impl Post {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49 + self.body.len());
        out.push(TYPE_POST);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.msg_seq.to_be_bytes());
        out.extend_from_slice(&self.expires_after.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Post> {
        want(b, 49, "post")?;
        if b[0] != TYPE_POST {
            return Err(Error::Malformed(format!("not a post (type {:#x})", b[0])));
        }
        let body = b[49..].to_vec();
        if body.len() > MAX_ENTRY_BODY {
            return Err(Error::Malformed(format!(
                "entry body is {} bytes, limit is {MAX_ENTRY_BODY}",
                body.len()
            )));
        }
        Ok(Post {
            channel: b[1..33].try_into().unwrap(),
            epoch: u32at(b, 33),
            msg_seq: u64at(b, 37),
            expires_after: u32at(b, 45),
            body,
        })
    }
}

/// Read entries after `since`, waiting up to `wait_secs` for one to arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fetch {
    pub channel: [u8; 32],
    pub since: u64,
    pub wait_secs: u16,
}

impl Fetch {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(43);
        out.push(TYPE_FETCH);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.since.to_be_bytes());
        out.extend_from_slice(&self.wait_secs.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Fetch> {
        if b.len() != 43 {
            return Err(Error::Malformed(format!(
                "fetch is {} bytes, want 43",
                b.len()
            )));
        }
        if b[0] != TYPE_FETCH {
            return Err(Error::Malformed(format!("not a fetch (type {:#x})", b[0])));
        }
        Ok(Fetch {
            channel: b[1..33].try_into().unwrap(),
            since: u64at(b, 33),
            // Clamped rather than refused: a client asking to wait longer than
            // the exchange will is not making an error, and answering early is
            // always permitted.
            wait_secs: u16at(b, 41).min(MAX_WAIT),
        })
    }
}

/// Change a channel's retention policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retain {
    pub channel: [u8; 32],
    pub retention_secs: u32,
    pub max_entries: u32,
}

impl Retain {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(TYPE_RETAIN);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.retention_secs.to_be_bytes());
        out.extend_from_slice(&self.max_entries.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Retain> {
        if b.len() != 41 {
            return Err(Error::Malformed(format!(
                "retain is {} bytes, want 41",
                b.len()
            )));
        }
        if b[0] != TYPE_RETAIN {
            return Err(Error::Malformed(format!("not a retain (type {:#x})", b[0])));
        }
        Ok(Retain {
            channel: b[1..33].try_into().unwrap(),
            retention_secs: u32at(b, 33),
            max_entries: u32at(b, 37),
        })
    }
}

/// Search the public directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    pub offset: u32,
    pub query: String,
}

/// Add an account to a channel, or change the role of one already in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invite {
    pub channel: [u8; 32],
    pub account: PubKey,
    pub role: Role,
}

impl Invite {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(66);
        out.push(TYPE_INVITE);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(self.account.as_bytes());
        out.push(self.role as u8);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Invite> {
        if b.len() != 66 {
            return Err(Error::Malformed(format!(
                "invite is {} bytes, want 66",
                b.len()
            )));
        }
        if b[0] != TYPE_INVITE {
            return Err(Error::Malformed(format!("not an invite (type {:#x})", b[0])));
        }
        Ok(Invite {
            channel: b[1..33].try_into().unwrap(),
            account: PubKey::new(b[33..65].try_into().unwrap()),
            role: Role::from_u8(b[65])?,
        })
    }
}

/// A channel and an account, for the operations that name one: `Remove`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByAccount {
    pub channel: [u8; 32],
    pub account: PubKey,
}

impl ByAccount {
    pub fn encode(&self, type_byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(type_byte);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8], type_byte: u8) -> Result<ByAccount> {
        if b.len() != 65 {
            return Err(Error::Malformed(format!(
                "request is {} bytes, want 65",
                b.len()
            )));
        }
        if b[0] != type_byte {
            return Err(Error::Malformed(format!(
                "wrong type {:#x}, want {type_byte:#x}",
                b[0]
            )));
        }
        Ok(ByAccount {
            channel: b[1..33].try_into().unwrap(),
            account: PubKey::new(b[33..65].try_into().unwrap()),
        })
    }
}

/// Ask which channels this account is in. It names no account, because the
/// only one it can answer about is the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mine {
    pub offset: u32,
}

impl Mine {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5);
        out.push(TYPE_MINE);
        out.extend_from_slice(&self.offset.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Mine> {
        if b.len() != 5 {
            return Err(Error::Malformed(format!(
                "mine is {} bytes, want 5",
                b.len()
            )));
        }
        if b[0] != TYPE_MINE {
            return Err(Error::Malformed(format!("not a mine (type {:#x})", b[0])));
        }
        Ok(Mine {
            offset: u32::from_be_bytes(b[1..5].try_into().unwrap()),
        })
    }
}

impl List {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.query.len());
        out.push(TYPE_LIST);
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.push(self.query.len() as u8);
        out.extend_from_slice(self.query.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<List> {
        want(b, 6, "list")?;
        if b[0] != TYPE_LIST {
            return Err(Error::Malformed(format!("not a list (type {:#x})", b[0])));
        }
        let query_len = b[5] as usize;
        if query_len > MAX_QUERY {
            return Err(Error::Malformed(format!(
                "query is {query_len} bytes, limit is {MAX_QUERY}"
            )));
        }
        if b.len() != 6 + query_len {
            return Err(Error::Malformed(format!(
                "list is {} bytes, want {}",
                b.len(),
                6 + query_len
            )));
        }
        Ok(List {
            offset: u32at(b, 1),
            query: utf8(&b[6..], "query")?,
        })
    }
}

/// The exchange's clock, returned by operations with nothing else to say.
///
/// Echoed for the reason SIP-4 gives: a caller's clock may be wrong, so
/// anything measured in time is measured in the exchange's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub now: u64,
}

impl Ack {
    pub fn encode(&self) -> Vec<u8> {
        self.now.to_be_bytes().to_vec()
    }

    pub fn decode(b: &[u8]) -> Result<Ack> {
        if b.len() != 8 {
            return Err(Error::Malformed(format!("ack is {} bytes, want 8", b.len())));
        }
        Ok(Ack { now: u64at(b, 0) })
    }
}

/// Answer to a create. `created` is 0 when the channel already existed.
///
/// `epoch` is 0 for a caller that is not a member, whatever the channel's real
/// epoch is: reporting it would disclose how often a channel the caller cannot
/// see has rotated, and therefore roughly how often somebody was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Created {
    pub created: bool,
    pub epoch: u32,
    pub now: u64,
}

impl Created {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13);
        out.push(u8::from(self.created));
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Created> {
        if b.len() != 13 {
            return Err(Error::Malformed(format!(
                "created is {} bytes, want 13",
                b.len()
            )));
        }
        Ok(Created {
            created: b[0] != 0,
            epoch: u32at(b, 1),
            now: u64at(b, 5),
        })
    }
}

/// Answer to a post: the sequence number the exchange assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Posted {
    pub seq: u64,
    pub posted: u64,
    pub now: u64,
}

impl Posted {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.posted.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Posted> {
        if b.len() != 24 {
            return Err(Error::Malformed(format!(
                "posted is {} bytes, want 24",
                b.len()
            )));
        }
        Ok(Posted {
            seq: u64at(b, 0),
            posted: u64at(b, 8),
            now: u64at(b, 16),
        })
    }
}

/// One entry in the log.
///
/// `account` and `device` are both the exchange's observation of the connection
/// that posted — the device from SIP-3, the account from the registry — and
/// neither is a cryptographic fact. `account` is who a reader displays; `device`
/// is what SIP-17 derives the sealing subkey from, which is why both travel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub kind: u8,
    pub account: PubKey,
    pub device: PubKey,
    pub posted: u64,
    pub expires_after: u32,
    pub epoch: u32,
    pub msg_seq: u64,
    pub body: Vec<u8>,
}

/// Bytes of entry header before the body.
pub const ENTRY_HEADER: usize = 8 + 1 + 32 + 32 + 8 + 4 + 4 + 8 + 4;

impl Entry {
    pub fn wire_len(&self) -> usize {
        ENTRY_HEADER + self.body.len()
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(self.device.as_bytes());
        out.extend_from_slice(&self.posted.to_be_bytes());
        out.extend_from_slice(&self.expires_after.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.msg_seq.to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
    }

    fn read(b: &[u8], o: &mut usize) -> Result<Entry> {
        want(b, *o + ENTRY_HEADER, "entry")?;
        let at = *o;
        let len = u32at(b, at + 97) as usize;
        if len > MAX_ENTRY_BODY {
            return Err(Error::Malformed(format!(
                "entry body is {len} bytes, limit is {MAX_ENTRY_BODY}"
            )));
        }
        want(b, at + ENTRY_HEADER + len, "entry")?;
        *o = at + ENTRY_HEADER + len;
        Ok(Entry {
            seq: u64at(b, at),
            kind: b[at + 8],
            account: key_at(b, at + 9),
            device: key_at(b, at + 41),
            posted: u64at(b, at + 73),
            expires_after: u32at(b, at + 81),
            epoch: u32at(b, at + 85),
            msg_seq: u64at(b, at + 89),
            body: b[at + ENTRY_HEADER..at + ENTRY_HEADER + len].to_vec(),
        })
    }
}

/// Answer to a fetch.
///
/// `first` and `last` are the oldest and newest sequence numbers the exchange
/// still holds. A caller whose `since` is below `first` has been away longer
/// than the retention window and has a gap it cannot fill — it must show that
/// rather than present what remains as the whole conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entries {
    pub now: u64,
    pub first: u64,
    pub last: u64,
    pub entries: Vec<Entry>,
    /// Relayed, never stored, and delivered at most once. An exchange that
    /// dropped every one of these would still conform: signals are a courtesy
    /// and nothing may depend on one arriving.
    pub signals: Vec<Signalled>,
}

/// One signal, as it reached us. The body is SIP-19's; nothing here reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signalled {
    pub account: PubKey,
    pub kind: u8,
    pub body: Vec<u8>,
}

/// Bytes a signal body may carry. Small on purpose — a signal that needed more
/// than this would be a message, and a message belongs in the log.
pub const MAX_SIGNAL_BODY: usize = 256;
/// Signals held for one member of one channel before the oldest are dropped.
pub const MAX_SIGNALS: usize = 32;
/// How long an undelivered signal is kept.
pub const SIGNAL_TTL: u64 = 30;

impl Entries {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(26 + self.entries.len() * ENTRY_HEADER);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&self.first.to_be_bytes());
        out.extend_from_slice(&self.last.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for e in &self.entries {
            e.write(&mut out);
        }
        out.extend_from_slice(&(self.signals.len() as u16).to_be_bytes());
        for s in &self.signals {
            out.extend_from_slice(s.account.as_bytes());
            out.push(s.kind);
            out.extend_from_slice(&(s.body.len() as u16).to_be_bytes());
            out.extend_from_slice(&s.body);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Entries> {
        want(b, 26, "entries")?;
        let count = u16at(b, 24) as usize;
        if count > MAX_BATCH {
            return Err(Error::Malformed(format!(
                "entries holds {count}, limit is {MAX_BATCH}"
            )));
        }
        let mut o = 26;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(Entry::read(b, &mut o)?);
        }
        want(b, o + 2, "entries")?;
        let count = u16at(b, o) as usize;
        o += 2;
        if count > MAX_SIGNALS {
            return Err(Error::Malformed(format!(
                "entries carries {count} signals, limit is {MAX_SIGNALS}"
            )));
        }
        let mut signals = Vec::with_capacity(count);
        for _ in 0..count {
            want(b, o + 35, "signal")?;
            let len = u16at(b, o + 33) as usize;
            if len > MAX_SIGNAL_BODY {
                return Err(Error::Malformed(format!(
                    "signal body is {len} bytes, limit is {MAX_SIGNAL_BODY}"
                )));
            }
            want(b, o + 35 + len, "signal")?;
            signals.push(Signalled {
                account: key_at(b, o),
                kind: b[o + 32],
                body: b[o + 35..o + 35 + len].to_vec(),
            });
            o += 35 + len;
        }
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "entries has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Entries {
            now: u64at(b, 0),
            first: u64at(b, 8),
            last: u64at(b, 16),
            entries,
            signals,
        })
    }
}

/// One member, as reported by `Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    pub account: PubKey,
    pub role: Role,
    pub joined: u64,
}

/// Everything a member or admin may know about a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelInfo {
    pub visibility: Visibility,
    pub epoch: u32,
    pub retention_secs: u32,
    pub max_entries: u32,
    pub first: u64,
    pub last: u64,
    /// The highest `msg_seq` the exchange has accepted from the calling device
    /// at the current epoch, or 0. How a client that lost its counter resumes
    /// without guessing; kept independently of the entries, so pruning does not
    /// erase it.
    pub my_msg_seq: u64,
    pub now: u64,
    pub members: Vec<Member>,
    pub name: String,
    pub topic: String,
}

impl ChannelInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.members.len() * 41);
        out.push(self.visibility as u8);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.retention_secs.to_be_bytes());
        out.extend_from_slice(&self.max_entries.to_be_bytes());
        out.extend_from_slice(&self.first.to_be_bytes());
        out.extend_from_slice(&self.last.to_be_bytes());
        out.extend_from_slice(&self.my_msg_seq.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for m in &self.members {
            out.extend_from_slice(m.account.as_bytes());
            out.push(m.role as u8);
            out.extend_from_slice(&m.joined.to_be_bytes());
        }
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&(self.topic.len() as u16).to_be_bytes());
        out.extend_from_slice(self.topic.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<ChannelInfo> {
        want(b, 47, "channel")?;
        let count = u16at(b, 45) as usize;
        if count > MAX_MEMBERS {
            return Err(Error::Malformed(format!(
                "channel lists {count} members, limit is {MAX_MEMBERS}"
            )));
        }
        let mut o = 47;
        want(b, o + count * 41, "channel")?;
        let mut members = Vec::with_capacity(count);
        for i in 0..count {
            let at = o + i * 41;
            members.push(Member {
                account: key_at(b, at),
                role: Role::from_u8(b[at + 32])?,
                joined: u64at(b, at + 33),
            });
        }
        o += count * 41;

        want(b, o + 1, "channel")?;
        let name_len = b[o] as usize;
        o += 1;
        want(b, o + name_len + 2, "channel")?;
        let name = utf8(&b[o..o + name_len], "name")?;
        o += name_len;
        let topic_len = u16at(b, o) as usize;
        o += 2;
        if b.len() != o + topic_len {
            return Err(Error::Malformed(format!(
                "channel is {} bytes, want {}",
                b.len(),
                o + topic_len
            )));
        }
        Ok(ChannelInfo {
            visibility: Visibility::from_u8(b[0])?,
            epoch: u32at(b, 1),
            retention_secs: u32at(b, 5),
            max_entries: u32at(b, 9),
            first: u64at(b, 13),
            last: u64at(b, 21),
            my_msg_seq: u64at(b, 29),
            now: u64at(b, 37),
            members,
            name,
            topic: utf8(&b[o..o + topic_len], "topic")?,
        })
    }
}

/// One row of the public directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public {
    pub channel: [u8; 32],
    pub members: u16,
    pub last: u64,
    pub name: String,
    pub topic: String,
}

/// One channel this account belongs to.
///
/// No `name` and no `topic`: for a private channel there is nothing the
/// exchange could put there, since those are stored empty and travel as a
/// sealed metadata entry (SIP-19). What it does carry is what the exchange
/// holds and a client cannot compute — the epoch in force, the retained
/// window, and this account's own read mark — so a channel list draws without
/// a request per channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Membership {
    pub channel: [u8; 32],
    pub visibility: Visibility,
    pub role: Role,
    pub joined: u64,
    pub epoch: u32,
    pub first: u64,
    pub last: u64,
    pub read: u64,
}

/// The channels an account is in. Answerable about the caller and nobody else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mines {
    pub now: u64,
    pub total: u32,
    pub channels: Vec<Membership>,
}

impl Mines {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + self.channels.len() * 70);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&(self.channels.len() as u16).to_be_bytes());
        for m in &self.channels {
            out.extend_from_slice(&m.channel);
            out.push(m.visibility as u8);
            out.push(m.role as u8);
            out.extend_from_slice(&m.joined.to_be_bytes());
            out.extend_from_slice(&m.epoch.to_be_bytes());
            out.extend_from_slice(&m.first.to_be_bytes());
            out.extend_from_slice(&m.last.to_be_bytes());
            out.extend_from_slice(&m.read.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Mines> {
        want(b, 14, "mines")?;
        let count = u16::from_be_bytes(b[12..14].try_into().unwrap()) as usize;
        if count > MAX_MINE {
            return Err(Error::Malformed(format!(
                "mine holds {count}, limit is {MAX_MINE}"
            )));
        }
        want(b, 14 + count * 70, "mines")?;
        let mut channels = Vec::with_capacity(count);
        for i in 0..count {
            let at = 14 + i * 70;
            channels.push(Membership {
                channel: b[at..at + 32].try_into().unwrap(),
                visibility: Visibility::from_u8(b[at + 32])?,
                role: Role::from_u8(b[at + 33])?,
                joined: u64::from_be_bytes(b[at + 34..at + 42].try_into().unwrap()),
                epoch: u32::from_be_bytes(b[at + 42..at + 46].try_into().unwrap()),
                first: u64::from_be_bytes(b[at + 46..at + 54].try_into().unwrap()),
                last: u64::from_be_bytes(b[at + 54..at + 62].try_into().unwrap()),
                read: u64::from_be_bytes(b[at + 62..at + 70].try_into().unwrap()),
            });
        }
        Ok(Mines {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            total: u32::from_be_bytes(b[8..12].try_into().unwrap()),
            channels,
        })
    }
}

/// Answer to a directory search. `total` is how many matched, which may exceed
/// what one reply carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub now: u64,
    pub total: u32,
    pub channels: Vec<Public>,
}

impl Listing {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + self.channels.len() * 64);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&(self.channels.len() as u16).to_be_bytes());
        for c in &self.channels {
            out.extend_from_slice(&c.channel);
            out.extend_from_slice(&c.members.to_be_bytes());
            out.extend_from_slice(&c.last.to_be_bytes());
            out.push(c.name.len() as u8);
            out.extend_from_slice(c.name.as_bytes());
            out.extend_from_slice(&(c.topic.len() as u16).to_be_bytes());
            out.extend_from_slice(c.topic.as_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Listing> {
        want(b, 14, "listing")?;
        let count = u16at(b, 12) as usize;
        if count > MAX_DIRECTORY {
            return Err(Error::Malformed(format!(
                "listing holds {count}, limit is {MAX_DIRECTORY}"
            )));
        }
        let mut o = 14;
        let mut channels = Vec::with_capacity(count);
        for _ in 0..count {
            want(b, o + 43, "listing")?;
            let channel: [u8; 32] = b[o..o + 32].try_into().unwrap();
            let members = u16at(b, o + 32);
            let last = u64at(b, o + 34);
            let name_len = b[o + 42] as usize;
            o += 43;
            want(b, o + name_len + 2, "listing")?;
            let name = utf8(&b[o..o + name_len], "name")?;
            o += name_len;
            let topic_len = u16at(b, o) as usize;
            o += 2;
            want(b, o + topic_len, "listing")?;
            let topic = utf8(&b[o..o + topic_len], "topic")?;
            o += topic_len;
            channels.push(Public {
                channel,
                members,
                last,
                name,
                topic,
            });
        }
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "listing has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Listing {
            now: u64at(b, 0),
            total: u32at(b, 8),
            channels,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn create() -> Create {
        Create {
            channel: [7; 32],
            visibility: Visibility::Public,
            retention_secs: DEFAULT_RETENTION,
            max_entries: 0,
            name: "planning".into(),
            topic: "what we are doing".into(),
            invites: vec![Invitee {
                account: key(2),
                role: Role::Member,
            }],
        }
    }

    #[test]
    fn create_round_trips() {
        let c = create();
        assert_eq!(Create::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn create_with_nothing_optional_round_trips() {
        let c = Create {
            name: String::new(),
            topic: String::new(),
            invites: vec![],
            ..create()
        };
        assert_eq!(Create::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut b = create().encode();
        b.push(0);
        assert!(Create::decode(&b).is_err());
    }

    #[test]
    fn a_wrong_type_byte_is_refused() {
        let mut b = create().encode();
        b[0] = TYPE_POST;
        assert!(Create::decode(&b).is_err());
    }

    #[test]
    fn an_oversized_name_is_refused() {
        // Hand-built: the encoder would happily write a length byte that
        // overflows, and the decoder is what has to hold the line.
        let mut b = vec![TYPE_CREATE];
        b.extend_from_slice(&[0u8; 32]);
        b.push(Visibility::Public as u8);
        b.extend_from_slice(&DEFAULT_RETENTION.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.push((MAX_NAME + 1) as u8);
        b.extend(std::iter::repeat_n(b'x', MAX_NAME + 1));
        b.extend_from_slice(&0u16.to_be_bytes());
        b.push(0);
        assert!(Create::decode(&b).is_err());
    }

    #[test]
    fn post_round_trips_and_bounds_its_body() {
        let p = Post {
            channel: [1; 32],
            epoch: 0,
            msg_seq: 0,
            expires_after: 300,
            body: b"hello".to_vec(),
        };
        assert_eq!(Post::decode(&p.encode()).unwrap(), p);

        let big = Post {
            body: vec![0; MAX_ENTRY_BODY + 1],
            ..p
        };
        assert!(Post::decode(&big.encode()).is_err());
    }

    #[test]
    fn an_empty_body_is_allowed() {
        // SIP-19 decides what a body must contain; SIP-16 carries bytes.
        let p = Post {
            channel: [1; 32],
            epoch: 0,
            msg_seq: 0,
            expires_after: 0,
            body: vec![],
        };
        assert_eq!(Post::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn fetch_clamps_a_wait_it_will_not_honour() {
        let f = Fetch {
            channel: [1; 32],
            since: 0,
            wait_secs: 9_999,
        };
        assert_eq!(Fetch::decode(&f.encode()).unwrap().wait_secs, MAX_WAIT);
    }

    #[test]
    fn entries_round_trip_with_several() {
        let e = |seq: u64, body: &[u8]| Entry {
            seq,
            kind: KIND_MEMBER,
            account: key(1),
            device: key(1),
            posted: 1000 + seq,
            expires_after: 0,
            epoch: 0,
            msg_seq: seq,
            body: body.to_vec(),
        };
        let got = Entries {
            now: 2000,
            first: 1,
            last: 3,
            entries: vec![e(1, b"one"), e(2, b""), e(3, b"three")],
            signals: vec![],
        };
        assert_eq!(Entries::decode(&got.encode()).unwrap(), got);
    }

    #[test]
    fn an_empty_fetch_still_reports_the_window() {
        // The gap a client must notice lives in `first`, so it has to survive
        // a reply carrying nothing.
        let got = Entries {
            now: 5,
            first: 40,
            last: 91,
            entries: vec![],
            signals: vec![],
        };
        let back = Entries::decode(&got.encode()).unwrap();
        assert_eq!((back.first, back.last), (40, 91));
    }

    #[test]
    fn entries_carry_signals_alongside_the_log() {
        let got = Entries {
            now: 1,
            first: 0,
            last: 0,
            entries: vec![],
            signals: vec![
                Signalled {
                    account: key(3),
                    kind: 0x01,
                    body: vec![1],
                },
                Signalled {
                    account: key(4),
                    kind: 0x01,
                    body: vec![],
                },
            ],
        };
        assert_eq!(Entries::decode(&got.encode()).unwrap(), got);
    }

    #[test]
    fn cursor_and_marks_round_trip() {
        let c = Cursor {
            channel: [2; 32],
            read: 17,
            receipts: false,
        };
        assert_eq!(Cursor::decode(&c.encode()).unwrap(), c);

        let m = Marks {
            now: 5,
            marks: vec![Mark {
                account: key(1),
                delivered: 9,
                read: 7,
            }],
        };
        assert_eq!(Marks::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn a_signal_bounds_its_body() {
        let s = SignalOut {
            channel: [1; 32],
            kind: 0x01,
            body: vec![1],
        };
        assert_eq!(SignalOut::decode(&s.encode()).unwrap(), s);
        let big = SignalOut {
            body: vec![0; MAX_SIGNAL_BODY + 1],
            ..s
        };
        assert!(SignalOut::decode(&big.encode()).is_err());
    }

    #[test]
    fn by_target_round_trips() {
        let t = ByTarget {
            channel: [5; 32],
            target: 12,
        };
        assert_eq!(ByTarget::decode(&t.encode(TYPE_REDACT), TYPE_REDACT).unwrap(), t);
        assert!(ByTarget::decode(&t.encode(TYPE_REDACT), TYPE_CURSOR).is_err());
    }

    #[test]
    fn a_system_entry_round_trips_and_ignores_what_it_does_not_know() {
        let e = System {
            event: EVENT_REMOVED,
            subject: key(1),
            actor: key(2),
        };
        assert_eq!(System::decode(&e.encode()).unwrap(), Some(e));

        let mut later = e.encode();
        later[0] = 0x7f;
        assert_eq!(System::decode(&later).unwrap(), None, "a later event is ignored");

        assert!(System::decode(&e.encode()[..64]).is_err(), "truncation is not");
    }

    #[test]
    fn channel_info_round_trips() {
        let c = ChannelInfo {
            visibility: Visibility::Public,
            epoch: 0,
            retention_secs: DEFAULT_RETENTION,
            max_entries: 100,
            first: 1,
            last: 9,
            my_msg_seq: 4,
            now: 77,
            members: vec![
                Member {
                    account: key(1),
                    role: Role::Admin,
                    joined: 10,
                },
                Member {
                    account: key(2),
                    role: Role::Member,
                    joined: 20,
                },
            ],
            name: "planning".into(),
            topic: String::new(),
        };
        assert_eq!(ChannelInfo::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn listing_round_trips() {
        let l = Listing {
            now: 1,
            total: 2,
            channels: vec![Public {
                channel: [9; 32],
                members: 3,
                last: 42,
                name: "open".into(),
                topic: "anyone".into(),
            }],
        };
        assert_eq!(Listing::decode(&l.encode()).unwrap(), l);
    }

    #[test]
    fn a_direct_message_identifier_does_not_depend_on_who_asks() {
        // Both ends must derive the same channel without having spoken, which
        // is the whole reason the derivation is ordered.
        let (a, b) = (key(0x11), key(0x99));
        assert_eq!(direct_message_id(&a, &b), direct_message_id(&b, &a));
        assert_ne!(direct_message_id(&a, &b), direct_message_id(&a, &a));
    }

    #[test]
    fn by_channel_checks_the_type_it_was_asked_for() {
        let c = ByChannel { channel: [3; 32] };
        let bytes = c.encode(TYPE_JOIN);
        assert_eq!(ByChannel::decode(&bytes, TYPE_JOIN).unwrap(), c);
        // A join decoded as a leave is a bug in the router, and should not
        // silently succeed just because the shapes match.
        assert!(ByChannel::decode(&bytes, TYPE_LEAVE).is_err());
    }

    #[test]
    fn invite_and_remove_round_trip() {
        let i = Invite {
            channel: [3; 32],
            account: PubKey::new([4; 32]),
            role: Role::Admin,
        };
        assert_eq!(Invite::decode(&i.encode()).unwrap(), i);
        assert_eq!(i.encode().len(), 66);

        let r = ByAccount {
            channel: [3; 32],
            account: PubKey::new([4; 32]),
        };
        assert_eq!(ByAccount::decode(&r.encode(TYPE_REMOVE), TYPE_REMOVE).unwrap(), r);
        // The type byte is checked, so a remove cannot be read as anything else.
        assert!(ByAccount::decode(&r.encode(TYPE_REMOVE), TYPE_INVITE).is_err());
    }

    #[test]
    fn the_mine_request_round_trips() {
        let m = Mine { offset: 64 };
        assert_eq!(Mine::decode(&m.encode()).unwrap(), m);
        assert!(Mine::decode(&[TYPE_LIST, 0, 0, 0, 0]).is_err());
        assert!(Mine::decode(&[TYPE_MINE]).is_err());
    }

    #[test]
    fn mine_round_trips() {
        let m = Mines {
            now: 99,
            total: 130,
            channels: vec![
                Membership {
                    channel: [7; 32],
                    visibility: Visibility::Private,
                    role: Role::Admin,
                    joined: 100,
                    epoch: 3,
                    first: 4,
                    last: 40,
                    read: 12,
                },
                Membership {
                    channel: [8; 32],
                    visibility: Visibility::Public,
                    role: Role::Member,
                    joined: 200,
                    epoch: 0,
                    first: 1,
                    last: 9,
                    read: 0,
                },
            ],
        };
        assert_eq!(Mines::decode(&m.encode()).unwrap(), m);
        // total may exceed what one reply carries; that is what paging is for.
        assert!(m.total as usize > m.channels.len());
    }

    #[test]
    fn mine_is_bounded_and_a_short_reply_is_refused() {
        let many = Mines {
            now: 0,
            total: 0,
            channels: vec![
                Membership {
                    channel: [1; 32],
                    visibility: Visibility::Public,
                    role: Role::Member,
                    joined: 0,
                    epoch: 0,
                    first: 0,
                    last: 0,
                    read: 0,
                };
                MAX_MINE + 1
            ],
        };
        assert!(Mines::decode(&many.encode()).is_err());

        // Truncated mid-row rather than mid-header, which is the case a length
        // check on the header alone would wave through.
        let one = Mines {
            now: 0,
            total: 1,
            channels: vec![many.channels[0]],
        };
        let mut bytes = one.encode();
        bytes.truncate(bytes.len() - 4);
        assert!(Mines::decode(&bytes).is_err());
    }

    #[test]
    fn an_empty_mine_is_valid() {
        // Somebody in no channels at all — a new account, and the first thing
        // a fresh client sees.
        let m = Mines {
            now: 5,
            total: 0,
            channels: Vec::new(),
        };
        assert_eq!(Mines::decode(&m.encode()).unwrap(), m);
    }
}

/// Set the caller's read mark, and say whether it wants others'.
///
/// `receipts` of 0 opts out, and the exchange then withholds every other
/// account's `read` from this caller while continuing to report `delivered`.
/// The reciprocity is enforced there rather than left to each client's good
/// manners, which is what stops somebody taking the signal without giving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub channel: [u8; 32],
    pub read: u64,
    pub receipts: bool,
}

impl Cursor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(42);
        out.push(TYPE_CURSOR);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.read.to_be_bytes());
        out.push(u8::from(self.receipts));
        out
    }

    pub fn decode(b: &[u8]) -> Result<Cursor> {
        if b.len() != 42 || b[0] != TYPE_CURSOR {
            return Err(Error::Malformed(format!(
                "cursor is {} bytes, want 42",
                b.len()
            )));
        }
        Ok(Cursor {
            channel: b[1..33].try_into().unwrap(),
            read: u64at(b, 33),
            receipts: b[41] != 0,
        })
    }
}

/// How far one account has got.
///
/// `delivered` is **observed** rather than asserted: the exchange learns it
/// from the `since` on every fetch. `read` is the one thing only a client
/// knows, so it is the one thing a client states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    pub account: PubKey,
    pub delivered: u64,
    pub read: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marks {
    pub now: u64,
    pub marks: Vec<Mark>,
}

impl Marks {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.marks.len() * 48);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.marks.len() as u16).to_be_bytes());
        for m in &self.marks {
            out.extend_from_slice(m.account.as_bytes());
            out.extend_from_slice(&m.delivered.to_be_bytes());
            out.extend_from_slice(&m.read.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Marks> {
        want(b, 10, "marks")?;
        let count = u16at(b, 8) as usize;
        if count > MAX_MEMBERS {
            return Err(Error::Malformed(format!(
                "marks holds {count}, limit is {MAX_MEMBERS}"
            )));
        }
        if b.len() != 10 + count * 48 {
            return Err(Error::Malformed(format!(
                "marks is {} bytes, want {}",
                b.len(),
                10 + count * 48
            )));
        }
        Ok(Marks {
            now: u64at(b, 0),
            marks: (0..count)
                .map(|i| {
                    let at = 10 + i * 48;
                    Mark {
                        account: key_at(b, at),
                        delivered: u64at(b, at + 32),
                        read: u64at(b, at + 40),
                    }
                })
                .collect(),
        })
    }
}

/// A request naming a channel and an entry: redact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByTarget {
    pub channel: [u8; 32],
    pub target: u64,
}

impl ByTarget {
    pub fn encode(&self, type_byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(type_byte);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.target.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8], type_byte: u8) -> Result<ByTarget> {
        if b.len() != 41 || b[0] != type_byte {
            return Err(Error::Malformed(format!(
                "request is {} bytes, want 41",
                b.len()
            )));
        }
        Ok(ByTarget {
            channel: b[1..33].try_into().unwrap(),
            target: u64at(b, 33),
        })
    }
}

/// Relay a signal to the channel's other members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalOut {
    pub channel: [u8; 32],
    pub kind: u8,
    pub body: Vec<u8>,
}

impl SignalOut {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34 + self.body.len());
        out.push(TYPE_SIGNAL);
        out.extend_from_slice(&self.channel);
        out.push(self.kind);
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(b: &[u8]) -> Result<SignalOut> {
        want(b, 34, "signal")?;
        if b[0] != TYPE_SIGNAL {
            return Err(Error::Malformed(format!("not a signal (type {:#x})", b[0])));
        }
        let body = b[34..].to_vec();
        if body.len() > MAX_SIGNAL_BODY {
            return Err(Error::Malformed(format!(
                "signal body is {} bytes, limit is {MAX_SIGNAL_BODY}",
                body.len()
            )));
        }
        Ok(SignalOut {
            channel: b[1..33].try_into().unwrap(),
            kind: b[33],
            body,
        })
    }
}
