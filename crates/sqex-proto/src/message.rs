//! SIP-19 chat messages: what a channel entry actually contains.
//!
//! The exchange never inspects any of this — the same relationship SIP-15 has
//! to SIP-12. In a public channel it is stored in the clear; in a private one
//! it is sealed under SIP-17 first, and nothing here can read that.
//!
//! # Ignoring is the feature
//!
//! A body whose type a reader does not know is **ignored, not refused**. It is
//! well formed; it is simply from a later version of this document. That is
//! what reserves the space for a new kind of message — a poll, a location, a
//! call record — without a flag day, and it is the only reason such a thing can
//! be added at all. A part works the same way at a smaller scale: `len` lets a
//! reader step over one it does not understand and show the rest of the post.
//!
//! A body that is **malformed** — truncated, a length that overruns, invalid
//! UTF-8 where UTF-8 is required — is an error and is reported as one. "I do
//! not know this" and "this is broken" are different facts, and collapsing them
//! hides real corruption behind a forward-compatibility rule.

use sqnr_core::{Error, PubKey, Result};

use crate::blob::{Attachment, utf8};

pub const TYPE_POST: u8 = 0x01;
pub const TYPE_REACTION: u8 = 0x02;
pub const TYPE_EDIT: u8 = 0x03;
pub const TYPE_REDACT: u8 = 0x04;
pub const TYPE_METADATA: u8 = 0x05;
/// SIP-36: an invitation to a call, carrying a SIP-13 room secret.
pub const TYPE_CALL: u8 = 0x06;
/// SIP-36: the durable record of how a call ended.
pub const TYPE_CALL_END: u8 = 0x07;

/// SIP-36 `media` bit 0: audio.
pub const MEDIA_AUDIO: u8 = 0x01;

pub const CALL_ANSWERED: u8 = 0x01;
pub const CALL_DECLINED: u8 = 0x02;
pub const CALL_MISSED: u8 = 0x03;
pub const CALL_CANCELLED: u8 = 0x04;
pub const CALL_FAILED: u8 = 0x05;

pub const RING_RINGING: u8 = 0x01;
pub const RING_ACCEPTED: u8 = 0x02;
pub const RING_DECLINED: u8 = 0x03;
pub const RING_BUSY: u8 = 0x04;
pub const RING_ENDED: u8 = 0x05;

/// SIP-36: should this device leave the room, having seen a sibling accept the
/// same call?
///
/// Two of one person's devices may accept before either sees the other's
/// signal. SIP-13 offers no arbitration and cannot — a room is named by a
/// secret, holding it *is* what membership consists of, and there is no
/// authority to appeal to. So this is convention: the lower-sorting key wins,
/// the same tiebreak SIP-12 uses to decide which peer is `first`.
///
/// **Not a guarantee, and an implementation must not treat it as one.** If the
/// signal is dropped — and SIP-16 permits dropping every signal — both devices
/// stay in the room and one person is present twice. That is cosmetic: both
/// belong to the same person, both legitimately hold the secret, and no
/// security property depends on the count. Saying so is better than specifying
/// a consensus protocol for a wart.
pub fn yields_to(mine: &PubKey, sibling: &PubKey) -> bool {
    sibling.as_bytes() < mine.as_bytes()
}

pub const PART_TEXT: u8 = 0x01;
pub const PART_ATTACHMENT: u8 = 0x02;
pub const PART_LINK: u8 = 0x03;
pub const PART_REPLY: u8 = 0x04;
pub const PART_MENTION: u8 = 0x05;

pub const REACT_ADD: u8 = 0x01;
pub const REACT_REMOVE: u8 = 0x02;

pub const SIGNAL_TYPING: u8 = 0x01;
/// Reserved: a read marker in an earlier draft, now SIP-16's durable cursor.
/// A receiver ignores it, as it ignores any unknown kind.
pub const SIGNAL_RESERVED_READ: u8 = 0x02;
/// SIP-36: ring state. The one signal kind an exchange treats differently —
/// delivered per device rather than per account, and back to the sender's own
/// other devices. See SIP-36's two delivery rules.
pub const SIGNAL_CALL_STATE: u8 = 0x03;

pub const MAX_TEXT: usize = 16 * 1024;
pub const MAX_PARTS: usize = 32;
pub const MAX_ATTACHMENTS: usize = 4;
pub const MAX_LINKS: usize = 4;
pub const MAX_MENTIONS: usize = 32;
pub const MAX_EMOJI: usize = 32;
pub const MAX_URL: usize = 2 * 1024;
pub const MAX_TITLE: usize = 256;
pub const MAX_DESC: usize = 1024;
pub const MAX_NAME: usize = 64;
pub const MAX_TOPIC: usize = 256;

/// How long after an entry an edit to it is still honoured.
///
/// A policy rather than a guarantee: the two systems most people arrive from
/// picked fifteen minutes and twenty-four hours, and neither can stop a client
/// that ignores the rule, because the enforcement is a receiver declining to
/// display something. The looser of the two is chosen — an edit window that
/// expires while somebody is asleep produces a typo nobody can fix.
pub const EDIT_WINDOW: u64 = 24 * 60 * 60;

/// A preview of a link, composed by the **sender's client** and never by the
/// exchange.
///
/// An exchange that fetched URLs would tell every linked host that a message
/// mentioning it had been posted, from an address identifying the exchange
/// rather than any reader, and would make a URL an instruction to the exchange
/// to make a request. The consequence is that everything but `url` is
/// attacker-chosen: a reader MUST show the `url` and MUST NOT let the preview
/// stand in for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub url: String,
    pub title: String,
    pub description: String,
    pub image: Option<Attachment>,
}

/// One element of a post, in the order the sender intends them shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Text(String),
    Attachment(Attachment),
    Link(Link),
    /// The SIP-16 sequence number being replied to.
    Reply(u64),
    /// An identity, carrying no display name — a name inside the message is a
    /// name the sender controls, rendered where a reader looks for identity.
    Mention(PubKey),
}

/// A message, an edit to one, a reaction, a redaction, or channel metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Post(Post),
    Reaction {
        target: u64,
        add: bool,
        emoji: String,
    },
    Edit {
        target: u64,
        post: Post,
    },
    /// A notification, not the removal itself: SIP-16's operation removes the
    /// bytes, and this tells clients to show the message as deleted.
    Redact {
        target: u64,
    },
    Metadata {
        name: String,
        topic: String,
        avatar: Option<Attachment>,
    },
    /// SIP-36: an invitation to a call.
    ///
    /// **The secret is a bearer capability with no revocation, in a durable
    /// log.** SIP-13 says of every room secret that anyone given it can join
    /// and can pass it on, and that there is no way to remove somebody.
    /// Sealing the body under SIP-17 restricts who is *given* it to the
    /// channel's members, which is the strongest available answer and does
    /// nothing about the rest: a member removed tomorrow keeps every secret
    /// they read today, and a call that ended has not closed its room.
    Call {
        /// A bitfield. Bit 0 is audio; **every other bit is reserved and a
        /// receiver ignores what it does not know** — including bit 1, which
        /// is not video. There is no video framing in this stack, SIP-15
        /// defines audio and says nothing about a second stream, and a client
        /// must not infer one.
        media: u8,
        /// How long the caller intends to wait. Advisory to a callee's
        /// interface, and load-bearing for one thing: deciding that an
        /// unanswered call was missed.
        ring_secs: u16,
        /// A SIP-13 room secret, generated uniformly at random by the caller.
        secret: [u8; 32],
    },
    /// SIP-36: how a call ended.
    ///
    /// **The only durable account of the call**, signed and chained like any
    /// other entry, which is the point of putting it in the log rather than
    /// deriving it from signals. Two of these targeting one `Call` are not an
    /// error — two parties observed the same call ending.
    CallEnd {
        /// The `seq` of the `Call` entry, in the shape `Reaction`, `Edit` and
        /// `Redact` already use.
        target: u64,
        outcome: u8,
        /// Seconds of media, and 0 for every outcome but answered.
        duration: u32,
    },
}

/// The parts of a message, and a count of what could not be shown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Post {
    pub parts: Vec<Part>,
    /// Parts of a kind this reader does not know. A post with none it
    /// understood is not an empty post, and a client should say so rather than
    /// showing a blank.
    pub unknown: usize,
}

impl Post {
    /// Check the per-kind caps SIP-19 places on a post.
    ///
    /// Too many of a kind is **malformed**, not unknown: the ignore rules cover
    /// a kind a reader has not heard of, and say nothing about a sender
    /// exceeding a limit it was told. Collapsing those would let a post carry
    /// eleven text parts and leave every client to guess which one to show.
    pub fn validate(&self) -> Result<()> {
        let mut text = 0usize;
        let mut reply = 0usize;
        let mut attachments = 0usize;
        let mut links = 0usize;
        let mut mentions = 0usize;
        for p in &self.parts {
            match p {
                Part::Text(_) => text += 1,
                Part::Reply(_) => reply += 1,
                Part::Attachment(_) => attachments += 1,
                Part::Link(_) => links += 1,
                Part::Mention(_) => mentions += 1,
            }
        }
        // The two "at most one" kinds are the ones whose excess has no sensible
        // reading at all: a post with two bodies, or two things it replies to.
        cap(text, 1, "text parts")?;
        cap(reply, 1, "reply parts")?;
        cap(attachments, MAX_ATTACHMENTS, "attachments")?;
        cap(links, MAX_LINKS, "link previews")?;
        cap(mentions, MAX_MENTIONS, "mentions")?;
        Ok(())
    }

    pub fn text(s: &str) -> Post {
        Post {
            parts: vec![Part::Text(s.into())],
            unknown: 0,
        }
    }

    /// The single text part, if there is one.
    pub fn body_text(&self) -> Option<&str> {
        self.parts.iter().find_map(|p| match p {
            Part::Text(t) => Some(t.as_str()),
            _ => None,
        })
    }

    /// What this replies to, if anything.
    pub fn reply_to(&self) -> Option<u64> {
        self.parts.iter().find_map(|p| match p {
            Part::Reply(t) => Some(*t),
            _ => None,
        })
    }

    pub fn attachments(&self) -> impl Iterator<Item = &Attachment> {
        self.parts.iter().filter_map(|p| match p {
            Part::Attachment(a) => Some(a),
            _ => None,
        })
    }

    pub fn mentions(&self) -> impl Iterator<Item = &PubKey> {
        self.parts.iter().filter_map(|p| match p {
            Part::Mention(m) => Some(m),
            _ => None,
        })
    }
}

fn cap(have: usize, limit: usize, what: &str) -> Result<()> {
    if have > limit {
        return Err(Error::Malformed(format!(
            "post has {have} {what}, limit is {limit}"
        )));
    }
    Ok(())
}

fn write_part(part: &Part, out: &mut Vec<u8>) {
    let (kind, body) = match part {
        Part::Text(t) => (PART_TEXT, t.as_bytes().to_vec()),
        Part::Attachment(a) => (PART_ATTACHMENT, a.encode()),
        Part::Reply(t) => (PART_REPLY, t.to_be_bytes().to_vec()),
        Part::Mention(m) => (PART_MENTION, m.as_bytes().to_vec()),
        Part::Link(l) => {
            let mut b = Vec::new();
            b.extend_from_slice(&(l.url.len() as u16).to_be_bytes());
            b.extend_from_slice(l.url.as_bytes());
            b.extend_from_slice(&(l.title.len() as u16).to_be_bytes());
            b.extend_from_slice(l.title.as_bytes());
            b.extend_from_slice(&(l.description.len() as u16).to_be_bytes());
            b.extend_from_slice(l.description.as_bytes());
            match &l.image {
                Some(a) => {
                    b.push(1);
                    a.write(&mut b);
                }
                None => b.push(0),
            }
            (PART_LINK, b)
        }
    };
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
}

/// `Ok(None)` for a part of a kind we do not know: `len` is what lets a reader
/// step over it and show the rest.
fn read_part(kind: u8, b: &[u8]) -> Result<Option<Part>> {
    match kind {
        PART_TEXT => {
            if b.len() > MAX_TEXT {
                return Err(Error::Malformed(format!(
                    "text is {} bytes, limit is {MAX_TEXT}",
                    b.len()
                )));
            }
            Ok(Some(Part::Text(utf8(b, "text")?)))
        }
        PART_ATTACHMENT => {
            let mut o = 0;
            let a = Attachment::read(b, &mut o)?;
            if o != b.len() {
                return Err(Error::Malformed("attachment part has trailing bytes".into()));
            }
            Ok(Some(Part::Attachment(a)))
        }
        PART_REPLY => {
            if b.len() != 8 {
                return Err(Error::Malformed(format!(
                    "reply is {} bytes, want 8",
                    b.len()
                )));
            }
            Ok(Some(Part::Reply(u64::from_be_bytes(b.try_into().unwrap()))))
        }
        PART_MENTION => {
            if b.len() != 32 {
                return Err(Error::Malformed(format!(
                    "mention is {} bytes, want 32",
                    b.len()
                )));
            }
            Ok(Some(Part::Mention(PubKey::new(b.try_into().unwrap()))))
        }
        PART_LINK => {
            let mut o = 0;
            let url = read_str(b, &mut o, MAX_URL, "url")?;
            let title = read_str(b, &mut o, MAX_TITLE, "title")?;
            let description = read_str(b, &mut o, MAX_DESC, "description")?;
            if b.len() <= o {
                return Err(Error::Malformed("link preview is truncated".into()));
            }
            let has_image = b[o] != 0;
            o += 1;
            let image = if has_image {
                Some(Attachment::read(b, &mut o)?)
            } else {
                None
            };
            if o != b.len() {
                return Err(Error::Malformed("link part has trailing bytes".into()));
            }
            Ok(Some(Part::Link(Link {
                url,
                title,
                description,
                image,
            })))
        }
        _ => Ok(None),
    }
}

fn read_str(b: &[u8], o: &mut usize, cap: usize, what: &str) -> Result<String> {
    if b.len() < *o + 2 {
        return Err(Error::Malformed(format!("{what} length is truncated")));
    }
    let n = u16::from_be_bytes(b[*o..*o + 2].try_into().unwrap()) as usize;
    *o += 2;
    if n > cap {
        return Err(Error::Malformed(format!(
            "{what} is {n} bytes, limit is {cap}"
        )));
    }
    if b.len() < *o + n {
        return Err(Error::Malformed(format!("{what} is truncated")));
    }
    let s = utf8(&b[*o..*o + n], what)?;
    *o += n;
    Ok(s)
}

fn write_post(post: &Post, out: &mut Vec<u8>) {
    out.push(post.parts.len() as u8);
    for p in &post.parts {
        write_part(p, out);
    }
}

fn read_post(b: &[u8], o: &mut usize) -> Result<Post> {
    if b.len() <= *o {
        return Err(Error::Malformed("post is truncated".into()));
    }
    let count = b[*o] as usize;
    *o += 1;
    if count > MAX_PARTS {
        return Err(Error::Malformed(format!(
            "post has {count} parts, limit is {MAX_PARTS}"
        )));
    }
    let mut parts = Vec::with_capacity(count);
    let mut unknown = 0;
    for _ in 0..count {
        if b.len() < *o + 5 {
            return Err(Error::Malformed("part header is truncated".into()));
        }
        let kind = b[*o];
        let len = u32::from_be_bytes(b[*o + 1..*o + 5].try_into().unwrap()) as usize;
        *o += 5;
        if b.len() < *o + len {
            return Err(Error::Malformed("part body is truncated".into()));
        }
        match read_part(kind, &b[*o..*o + len])? {
            Some(p) => parts.push(p),
            None => unknown += 1,
        }
        *o += len;
    }
    // Unknown parts are skipped and do not count: a reader cannot tell what
    // kind they were, so it cannot tell which cap they would have fallen under.
    let post = Post { parts, unknown };
    post.validate()?;
    Ok(post)
}

impl Body {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Body::Post(p) => {
                out.push(TYPE_POST);
                write_post(p, &mut out);
            }
            Body::Reaction { target, add, emoji } => {
                out.push(TYPE_REACTION);
                out.extend_from_slice(&target.to_be_bytes());
                out.push(if *add { REACT_ADD } else { REACT_REMOVE });
                out.push(emoji.len() as u8);
                out.extend_from_slice(emoji.as_bytes());
            }
            Body::Edit { target, post } => {
                out.push(TYPE_EDIT);
                out.extend_from_slice(&target.to_be_bytes());
                write_post(post, &mut out);
            }
            Body::Redact { target } => {
                out.push(TYPE_REDACT);
                out.extend_from_slice(&target.to_be_bytes());
            }
            Body::Metadata {
                name,
                topic,
                avatar,
            } => {
                out.push(TYPE_METADATA);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&(topic.len() as u16).to_be_bytes());
                out.extend_from_slice(topic.as_bytes());
                match avatar {
                    Some(a) => {
                        out.push(1);
                        a.write(&mut out);
                    }
                    None => out.push(0),
                }
            }
            Body::Call {
                media,
                ring_secs,
                secret,
            } => {
                out.push(TYPE_CALL);
                out.push(*media);
                out.extend_from_slice(&ring_secs.to_be_bytes());
                out.extend_from_slice(secret);
            }
            Body::CallEnd {
                target,
                outcome,
                duration,
            } => {
                out.push(TYPE_CALL_END);
                out.extend_from_slice(&target.to_be_bytes());
                out.push(*outcome);
                out.extend_from_slice(&duration.to_be_bytes());
            }
        }
        out
    }

    /// `Ok(None)` for a body of a type we do not know.
    ///
    /// SIP-19 reserves the type space so a kind of message can be added without
    /// a flag day, and ignoring what we do not know is what keeps that promise.
    pub fn decode(b: &[u8]) -> Result<Option<Body>> {
        if b.is_empty() {
            return Err(Error::Malformed("body is empty".into()));
        }
        let mut o = 1;
        match b[0] {
            TYPE_POST => {
                let post = read_post(b, &mut o)?;
                done(b, o)?;
                Ok(Some(Body::Post(post)))
            }
            TYPE_REACTION => {
                if b.len() < 11 {
                    return Err(Error::Malformed("reaction is truncated".into()));
                }
                let target = u64::from_be_bytes(b[1..9].try_into().unwrap());
                let add = match b[9] {
                    REACT_ADD => true,
                    REACT_REMOVE => false,
                    other => {
                        return Err(Error::Malformed(format!("unknown reaction op {other}")));
                    }
                };
                let n = b[10] as usize;
                if n > MAX_EMOJI {
                    return Err(Error::Malformed(format!(
                        "emoji is {n} bytes, limit is {MAX_EMOJI}"
                    )));
                }
                if b.len() != 11 + n {
                    return Err(Error::Malformed("reaction is truncated".into()));
                }
                Ok(Some(Body::Reaction {
                    target,
                    add,
                    emoji: utf8(&b[11..], "emoji")?,
                }))
            }
            TYPE_EDIT => {
                if b.len() < 9 {
                    return Err(Error::Malformed("edit is truncated".into()));
                }
                o = 9;
                let post = read_post(b, &mut o)?;
                done(b, o)?;
                Ok(Some(Body::Edit {
                    target: u64::from_be_bytes(b[1..9].try_into().unwrap()),
                    post,
                }))
            }
            TYPE_REDACT => {
                if b.len() != 9 {
                    return Err(Error::Malformed(format!(
                        "redact is {} bytes, want 9",
                        b.len()
                    )));
                }
                Ok(Some(Body::Redact {
                    target: u64::from_be_bytes(b[1..9].try_into().unwrap()),
                }))
            }
            TYPE_METADATA => {
                if b.len() < 2 {
                    return Err(Error::Malformed("metadata is truncated".into()));
                }
                let name_len = b[1] as usize;
                if name_len > MAX_NAME {
                    return Err(Error::Malformed(format!(
                        "name is {name_len} bytes, limit is {MAX_NAME}"
                    )));
                }
                o = 2;
                if b.len() < o + name_len + 2 {
                    return Err(Error::Malformed("metadata is truncated".into()));
                }
                let name = utf8(&b[o..o + name_len], "name")?;
                o += name_len;
                let topic_len = u16::from_be_bytes(b[o..o + 2].try_into().unwrap()) as usize;
                o += 2;
                if topic_len > MAX_TOPIC {
                    return Err(Error::Malformed(format!(
                        "topic is {topic_len} bytes, limit is {MAX_TOPIC}"
                    )));
                }
                if b.len() < o + topic_len + 1 {
                    return Err(Error::Malformed("metadata is truncated".into()));
                }
                let topic = utf8(&b[o..o + topic_len], "topic")?;
                o += topic_len;
                let has_avatar = b[o] != 0;
                o += 1;
                let avatar = if has_avatar {
                    Some(Attachment::read(b, &mut o)?)
                } else {
                    None
                };
                done(b, o)?;
                Ok(Some(Body::Metadata {
                    name,
                    topic,
                    avatar,
                }))
            }
            TYPE_CALL => {
                if b.len() != 1 + 1 + 2 + 32 {
                    return Err(Error::Malformed(format!(
                        "call is {} bytes, want 36",
                        b.len()
                    )));
                }
                Ok(Some(Body::Call {
                    media: b[1],
                    ring_secs: u16::from_be_bytes(b[2..4].try_into().unwrap()),
                    secret: b[4..36].try_into().unwrap(),
                }))
            }
            TYPE_CALL_END => {
                if b.len() != 1 + 8 + 1 + 4 {
                    return Err(Error::Malformed(format!(
                        "call end is {} bytes, want 14",
                        b.len()
                    )));
                }
                Ok(Some(Body::CallEnd {
                    target: u64::from_be_bytes(b[1..9].try_into().unwrap()),
                    outcome: b[9],
                    duration: u32::from_be_bytes(b[10..14].try_into().unwrap()),
                }))
            }
            _ => Ok(None),
        }
    }
}

fn done(b: &[u8], o: usize) -> Result<()> {
    if o != b.len() {
        return Err(Error::Malformed(format!(
            "body has {} trailing bytes",
            b.len() - o
        )));
    }
    Ok(())
}

/// A signal: relayed by SIP-16, never stored, worthless a minute later.
///
/// Typing is the only one, and it is the only one that should be. A read marker
/// looks like its neighbour and is not — reading is durable state somebody
/// wants back tomorrow, which makes it a cursor at the exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Typing(bool),
    /// SIP-36 ring state.
    ///
    /// **Nothing durable may be derived from one.** SIP-16 sets the standard of
    /// service plainly — an exchange that dropped every signal it was ever
    /// given would still conform — and SIP-31 notes that a signal carries an
    /// account the exchange asserted and is forgeable by it permanently. So an
    /// exchange can synthesise one of these naming any member and any device:
    /// it can make a client show that somebody declined, or silence a ringing
    /// device by claiming a sibling accepted. A client MUST NOT write a call's
    /// outcome from one, MUST NOT show its claim as a fact about a person, and
    /// falls back on [`crate::timeline::CallRecord::outcome`] when signals do
    /// not arrive. They drive a ringing screen and nothing else.
    CallState {
        /// The `seq` of the `Call` entry this is about.
        target: u64,
        state: u8,
        /// The SIP-22 device key of the signalling client, which is what makes
        /// SIP-36's fan-out rules expressible. **The exchange does not take
        /// this on trust for its own routing** — it excludes the device it
        /// observed on the connection, for the reason SIP-16 gives about
        /// `account`: a client's claim about who it is is not a fact.
        device: PubKey,
    },
}

impl Signal {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Signal::Typing(on) => vec![SIGNAL_TYPING, u8::from(*on)],
            Signal::CallState {
                target,
                state,
                device,
            } => {
                let mut out = Vec::with_capacity(1 + 8 + 1 + 32);
                out.push(SIGNAL_CALL_STATE);
                out.extend_from_slice(&target.to_be_bytes());
                out.push(*state);
                out.extend_from_slice(device.as_bytes());
                out
            }
        }
    }

    /// `Ok(None)` for a kind we do not know, including the reserved read
    /// marker that became SIP-16's cursor.
    pub fn decode(b: &[u8]) -> Result<Option<Signal>> {
        if b.is_empty() {
            return Err(Error::Malformed("signal is empty".into()));
        }
        match b[0] {
            SIGNAL_TYPING => {
                if b.len() != 2 {
                    return Err(Error::Malformed(format!(
                        "typing signal is {} bytes, want 2",
                        b.len()
                    )));
                }
                Ok(Some(Signal::Typing(b[1] != 0)))
            }
            SIGNAL_CALL_STATE => {
                if b.len() != 1 + 8 + 1 + 32 {
                    return Err(Error::Malformed(format!(
                        "call state signal is {} bytes, want 42",
                        b.len()
                    )));
                }
                Ok(Some(Signal::CallState {
                    target: u64::from_be_bytes(b[1..9].try_into().unwrap()),
                    state: b[9],
                    device: PubKey::new(b[10..42].try_into().unwrap()),
                }))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{Attachment, KIND_IMAGE};

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn attachment() -> Attachment {
        Attachment {
            kind: KIND_IMAGE,
            blob: [3; 32],
            key: [4; 32],
            size: 900,
            chunks: 1,
            mime: "image/png".into(),
            meta: vec![0, 64, 0, 64],
            preview: vec![7; 16],
        }
    }

    fn round_trip(b: Body) {
        assert_eq!(Body::decode(&b.encode()).unwrap(), Some(b));
    }

    #[test]
    fn a_plain_message_round_trips() {
        round_trip(Body::Post(Post::text("hello")));
    }

    #[test]
    fn every_part_kind_round_trips_together() {
        round_trip(Body::Post(Post {
            parts: vec![
                Part::Reply(41),
                Part::Text("look at this".into()),
                Part::Mention(key(9)),
                Part::Attachment(attachment()),
                Part::Link(Link {
                    url: "https://example.invalid/x".into(),
                    title: "A title the sender chose".into(),
                    description: "and a description they also chose".into(),
                    image: Some(attachment()),
                }),
            ],
            unknown: 0,
        }));
    }

    #[test]
    fn a_link_without_an_image_round_trips() {
        round_trip(Body::Post(Post {
            parts: vec![Part::Link(Link {
                url: "https://example.invalid/".into(),
                title: String::new(),
                description: String::new(),
                image: None,
            })],
            unknown: 0,
        }));
    }

    #[test]
    fn reactions_edits_redactions_and_metadata_round_trip() {
        round_trip(Body::Reaction {
            target: 7,
            add: true,
            emoji: "👍".into(),
        });
        round_trip(Body::Reaction {
            target: 7,
            add: false,
            emoji: "👍🏽".into(),
        });
        round_trip(Body::Edit {
            target: 7,
            post: Post::text("fixed the typo"),
        });
        round_trip(Body::Redact { target: 7 });
        round_trip(Body::Metadata {
            name: "planning".into(),
            topic: "what we are doing".into(),
            avatar: Some(attachment()),
        });
        round_trip(Body::Metadata {
            name: String::new(),
            topic: String::new(),
            avatar: None,
        });
    }

    #[test]
    fn an_unknown_body_type_is_ignored_not_refused() {
        // The promise SIP-19 exists to keep: a poll, a location, a call record
        // can be added later and an older client carries on.
        let mut bytes = Body::Post(Post::text("hi")).encode();
        bytes[0] = 0x7f;
        assert_eq!(Body::decode(&bytes).unwrap(), None);
    }

    #[test]
    fn an_unknown_part_kind_is_skipped_and_the_rest_shown() {
        // The same promise one scale down: `len` is what lets a reader step
        // over a part and still display the sentence beside it.
        let mut out = vec![TYPE_POST, 2];
        out.push(0x6f);
        out.extend_from_slice(&3u32.to_be_bytes());
        out.extend_from_slice(b"???");
        write_part(&Part::Text("but this shows".into()), &mut out);

        let body = Body::decode(&out).unwrap().unwrap();
        let Body::Post(post) = body else { panic!() };
        assert_eq!(post.body_text(), Some("but this shows"));
        assert_eq!(post.unknown, 1);
    }

    #[test]
    fn a_post_of_only_unknown_parts_is_not_an_empty_post() {
        // A client should say something was there rather than show a blank.
        let mut out = vec![TYPE_POST, 1];
        out.push(0x6f);
        out.extend_from_slice(&1u32.to_be_bytes());
        out.push(0);
        let Body::Post(post) = Body::decode(&out).unwrap().unwrap() else {
            panic!()
        };
        assert!(post.parts.is_empty());
        assert_eq!(post.unknown, 1);
    }

    #[test]
    fn malformed_is_an_error_and_unknown_is_not() {
        // Collapsing the two would hide real corruption behind a
        // forward-compatibility rule.
        assert!(Body::decode(&[]).is_err());
        assert!(Body::decode(&[TYPE_REDACT]).is_err());
        assert!(Body::decode(&[TYPE_REDACT, 0, 0, 0, 0, 0, 0, 0, 1, 99]).is_err());

        let mut bytes = Body::Post(Post::text("hi")).encode();
        bytes.push(0);
        assert!(Body::decode(&bytes).is_err(), "trailing bytes are corruption");
    }

    #[test]
    fn invalid_utf8_where_utf8_is_required_is_an_error() {
        let mut out = vec![TYPE_POST, 1];
        out.push(PART_TEXT);
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&[0xff, 0xfe]);
        assert!(Body::decode(&out).is_err());
    }

    #[test]
    fn oversized_fields_are_refused() {
        let mut out = vec![TYPE_POST, 1];
        out.push(PART_TEXT);
        out.extend_from_slice(&((MAX_TEXT + 1) as u32).to_be_bytes());
        out.extend(std::iter::repeat_n(b'x', MAX_TEXT + 1));
        assert!(Body::decode(&out).is_err());

        let long = Body::Reaction {
            target: 1,
            add: true,
            emoji: "x".repeat(MAX_EMOJI + 1),
        };
        assert!(Body::decode(&long.encode()).is_err());
    }

    #[test]
    fn typing_is_the_only_signal_and_the_read_marker_is_reserved() {
        let s = Signal::Typing(true);
        assert_eq!(Signal::decode(&s.encode()).unwrap(), Some(s));
        assert_eq!(
            Signal::decode(&Signal::Typing(false).encode()).unwrap(),
            Some(Signal::Typing(false))
        );
        // Reading became a durable cursor at the exchange; the old kind is
        // ignored rather than misread.
        assert_eq!(Signal::decode(&[SIGNAL_RESERVED_READ, 0, 0]).unwrap(), None);
        assert!(Signal::decode(&[]).is_err());
    }

    #[test]
    fn a_post_may_carry_only_one_body_and_one_reply() {
        // Two of either has no sensible reading: a client would have to guess
        // which text to show, or which message this answers.
        let two_texts = Body::Post(Post {
            parts: vec![Part::Text("one".into()), Part::Text("two".into())],
            unknown: 0,
        });
        assert!(Body::decode(&two_texts.encode()).is_err());

        let two_replies = Body::Post(Post {
            parts: vec![Part::Reply(1), Part::Reply(2)],
            unknown: 0,
        });
        assert!(Body::decode(&two_replies.encode()).is_err());
    }

    #[test]
    fn the_per_kind_caps_are_enforced_on_decode() {
        let many = |p: Part, n: usize| {
            Body::Post(Post {
                parts: std::iter::repeat_n(p, n).collect(),
                unknown: 0,
            })
        };
        // At the limit, fine.
        assert!(
            Body::decode(&many(Part::Attachment(attachment()), MAX_ATTACHMENTS).encode()).is_ok()
        );
        assert!(Body::decode(&many(Part::Mention(key(1)), MAX_MENTIONS).encode()).is_ok());
        // One over, refused.
        assert!(
            Body::decode(&many(Part::Attachment(attachment()), MAX_ATTACHMENTS + 1).encode())
                .is_err()
        );
        assert!(Body::decode(&many(Part::Mention(key(1)), MAX_MENTIONS + 1).encode()).is_err());
    }

    #[test]
    fn an_edit_is_held_to_the_same_caps_as_a_post() {
        // An edit carries a post, so a rule the post obeys must survive being
        // delivered as a correction to one.
        let bad = Body::Edit {
            target: 1,
            post: Post {
                parts: vec![Part::Text("one".into()), Part::Text("two".into())],
                unknown: 0,
            },
        };
        assert!(Body::decode(&bad.encode()).is_err());
    }

    #[test]
    fn unknown_parts_do_not_count_against_any_cap() {
        // A reader cannot tell what kind they were, so it cannot tell which
        // cap they would have fallen under.
        let mut out = vec![TYPE_POST, (MAX_PARTS) as u8];
        write_part(&Part::Text("the only text".into()), &mut out);
        for _ in 0..(MAX_PARTS - 1) {
            out.push(0x6f);
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        let Body::Post(post) = Body::decode(&out).unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(post.body_text(), Some("the only text"));
        assert_eq!(post.unknown, MAX_PARTS - 1);
    }

    #[test]
    fn validate_lets_a_sender_check_before_encoding() {
        assert!(Post::text("fine").validate().is_ok());
        assert!(
            Post {
                parts: vec![Part::Text("a".into()), Part::Text("b".into())],
                unknown: 0,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn accessors_find_what_a_client_needs() {
        let post = Post {
            parts: vec![
                Part::Reply(12),
                Part::Text("see above".into()),
                Part::Mention(key(5)),
                Part::Attachment(attachment()),
            ],
            unknown: 0,
        };
        assert_eq!(post.reply_to(), Some(12));
        assert_eq!(post.body_text(), Some("see above"));
        assert_eq!(post.mentions().count(), 1);
        assert_eq!(post.attachments().count(), 1);
    }
}

#[cfg(test)]
mod call_tests {
    use super::*;

    #[test]
    fn a_call_and_its_ending_round_trip() {
        let call = Body::Call {
            media: MEDIA_AUDIO,
            ring_secs: 30,
            secret: [7; 32],
        };
        assert_eq!(Body::decode(&call.encode()).unwrap(), Some(call.clone()));
        let end = Body::CallEnd {
            target: 41,
            outcome: CALL_ANSWERED,
            duration: 95,
        };
        assert_eq!(Body::decode(&end.encode()).unwrap(), Some(end.clone()));

        // Truncation is malformed, not unknown: the ignore rules are for a type
        // a reader has not heard of.
        assert!(Body::decode(&call.encode()[..20]).is_err());
        assert!(Body::decode(&end.encode()[..8]).is_err());
    }

    /// **Bit 1 is not video.** SIP-15 defines audio and says nothing about a
    /// second stream, so a client must not infer one — and an implementation
    /// tempted to read this bit would be inventing a wire format.
    #[test]
    fn every_media_bit_but_audio_is_reserved_and_carried_untouched() {
        for bits in [0x00u8, 0x02, 0xFE, 0xFF] {
            let b = Body::Call {
                media: MEDIA_AUDIO | bits,
                ring_secs: 1,
                secret: [0; 32],
            };
            let Some(Body::Call { media, .. }) = Body::decode(&b.encode()).unwrap() else {
                panic!("a call must decode as a call whatever its reserved bits");
            };
            assert_eq!(media & MEDIA_AUDIO, MEDIA_AUDIO);
            assert_eq!(media, MEDIA_AUDIO | bits, "reserved bits are carried, not masked");
        }
    }

    #[test]
    fn a_ring_state_round_trips_and_an_unknown_kind_is_ignored() {
        let s = Signal::CallState {
            target: 9,
            state: RING_RINGING,
            device: PubKey::new([3; 32]),
        };
        assert_eq!(Signal::decode(&s.encode()).unwrap(), Some(s));
        assert!(Signal::decode(&s.encode()[..10]).is_err());
        // The forward-compatibility rule SIP-19 already had, still holding.
        assert_eq!(Signal::decode(&[0x7f, 0, 0]).unwrap(), None);
    }

    /// The tiebreak is on key order and is symmetric: exactly one of two
    /// devices yields, never both and never neither.
    #[test]
    fn exactly_one_of_two_devices_yields() {
        let low = PubKey::new([1; 32]);
        let high = PubKey::new([2; 32]);
        assert!(yields_to(&high, &low));
        assert!(!yields_to(&low, &high));
        // A device never yields to itself, which would leave nobody in the room.
        assert!(!yields_to(&low, &low));
    }
}
