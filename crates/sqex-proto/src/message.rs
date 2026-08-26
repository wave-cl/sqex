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
    Ok(Post { parts, unknown })
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
}

impl Signal {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Signal::Typing(on) => vec![SIGNAL_TYPING, u8::from(*on)],
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
