//! SIP-88 feeds: a per-account append-only signed log.
//!
//! An account's public output, numbered by the author rather than by the
//! exchange and served to anybody who asks. There are no members, no roles and
//! nothing to join: the account key is the whole identifier.
//!
//! The exchange stores a post and serves it back verbatim. It checks the
//! signature, the serial and the chain, and it never looks inside `body` --
//! which is a SIP-19 `Body` and this crate's `message` module's business.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sqnr_core::{Error, PubKey, Result};

/// Domain separator for a feed post's signature.
///
/// Distinct from SIP-31's `sqex-entry-v1` so a channel entry's signature can
/// never be presented as a feed post's or the reverse. `sqex-` rather than
/// `sqnr-` because a post is signed by a **device**, under a SIP-20
/// credential; the `sqnr-` prefix is for what an account key signs itself.
pub const FEED_CONTEXT: &[u8] = b"sqex-feed-v1";

/// Request type bytes.
pub const TYPE_APPEND: u8 = 0x01;
pub const TYPE_READ: u8 = 0x02;
pub const TYPE_WITHDRAW: u8 = 0x03;
pub const TYPE_SINCE: u8 = 0x04;
pub const TYPE_HEAD: u8 = 0x05;
pub const TYPE_SET: u8 = 0x06;
/// SIP-90: the accounts at this exchange that asked to be findable.
pub const TYPE_LISTED: u8 = 0x07;

/// SIP-90: rows one [`Listing`] may carry.
pub const MAX_LISTING: u16 = 256;

/// Which way [`Read`] pages.
///
/// Backward is the one a channel's `Fetch` has no equivalent for, and the
/// reason is the difference between the two shapes: a conversation is caught
/// up to from where you left it, and a feed is browsed from the end.
pub const DIR_FORWARD: u8 = 0x00;
pub const DIR_BACKWARD: u8 = 0x01;

/// What [`Moved`] says about one feed asked about.
///
/// `0x00` is never transmitted: a row that did not change is absent from the
/// reply, which is what keeps a five-hundred-row poll to twelve bytes in the
/// common case.
pub const STATE_UNCHANGED: u8 = 0x00;
pub const STATE_MOVED: u8 = 0x01;
/// Absent, withheld, or blocked -- one answer for all three, as SIP-21 answers
/// a profile `Get`, because answering "exists but hidden" would itself be the
/// disclosure that hiding was meant to prevent.
pub const STATE_GONE: u8 = 0x02;
/// `oldest` is above the serial asked: a gap the caller cannot fill.
pub const STATE_TRUNCATED: u8 = 0x03;
/// `newest` is below the serial asked. A feed's serial belongs to its author
/// and never restarts, so this is **always** a fault and never a new log --
/// which is the one client bug SIP-16 §A reset sequence space has and this
/// shape cannot.
pub const STATE_RESET: u8 = 0x04;
/// The feed is at another exchange; `head_input` carries its home's key.
pub const STATE_ELSEWHERE: u8 = 0x05;
/// The account succeeded its key; `head_input` carries the successor's.
pub const STATE_SUCCEEDED: u8 = 0x06;

/// Where a [`Moved`] row's answer came from.
///
/// `0x03` is not optional and is the reason this byte exists: a batched route
/// that cannot tell "nothing new" from "I could not ask" is a route that
/// silently stops delivering, and a client has no way to notice. SIP-60
/// §Saying whose list it is made the same argument about a device list.
pub const FROM_HERE: u8 = 0x00;
pub const FROM_HOME: u8 = 0x01;
pub const FROM_KEPT: u8 = 0x02;
pub const FROM_UNASKED: u8 = 0x03;

/// A post's body, which is a SIP-19 `Body` and nothing this module reads.
pub const MAX_BODY: usize = 32 * 1024;
/// Posts kept per feed before the oldest are evicted.
///
/// Lower than SIP-16's 50 000 entries per channel, and `MAX_FEED_BYTES` far
/// below its 128 MiB, for one reason: a channel is created deliberately and an
/// identity may hold only 256, while **every account has a feed**.
pub const MAX_POSTS: u32 = 10_000;
pub const MAX_FEED_BYTES: u64 = 16 * 1024 * 1024;
/// Posts in one [`Page`], and the bytes they may occupy, whichever binds first.
pub const MAX_PAGE: u16 = 64;
pub const MAX_PAGE_BYTES: usize = 512 * 1024;
/// Feeds one [`Since`] may ask about.
pub const MAX_SINCE: u16 = 512;
/// Succession seams one [`Headed`] may carry.
pub const MAX_SEAMS: u8 = 8;
/// Retention bounds. The default is **a year** rather than SIP-16's thirty
/// days, because a feed is an archive and one that evaporated in a month would
/// be worse than none.
pub const MIN_RETENTION: u32 = 3600;
pub const DEFAULT_RETENTION: u32 = 365 * 24 * 3600;
pub const MAX_RETENTION: u32 = 365 * 24 * 3600;

/// Bytes of a post before its body: the header as SIP-88 states it.
pub const POST_HEADER: usize = 32 + 32 + 8 + 32 + 8 + 4 + 1 + 32 + 4;

/// Bytes of a [`Headed`] before its seams.
const HEADED_FIXED: usize = 1 + 8 + 8 + 32 + 4 + 8 + 4 + 4 + 8 + 1 + 1;

/// A post in a feed, as it is signed and as it is stored.
///
/// `encode` is the header followed by the body followed by the signature, so
/// the wire bytes and the signed bytes cannot drift: everything above `body`
/// is also a term of [`PostTerms::input`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Post {
    pub account: PubKey,
    /// The device that signed, bound to `account` by a SIP-20 credential. An
    /// account key may be held in hardware and a linked device does not hold
    /// its account's key at all, which is SIP-31's reason and holds here.
    pub device: PubKey,
    /// Position in the feed, from 1. **The author's number, not the
    /// exchange's** -- which is why a feed cannot be forked by the exchange
    /// that serves it, and why a hole means what it says.
    pub serial: u64,
    /// [`crate::entry_sig::link`] of the post at `serial - 1`, or
    /// [`crate::entry_sig::GENESIS`] for the first.
    pub prev: [u8; 32],
    /// The author's clock. Advisory: nothing orders by it, retention is
    /// measured from the exchange's own `received`, and a reader merging feeds
    /// clamps it. See SIP-88 §What the clocks are.
    pub issued_at: u64,
    /// Seconds after which the exchange drops the body, 0 for never.
    pub expires_after: u32,
    /// Reserved, and MUST be zero. A reserved bit that is merely ignored is a
    /// reserved bit somebody will use.
    pub flags: u8,
    /// `SHA-256(body)`, carried so a tombstone's signature still verifies once
    /// its bytes are gone.
    pub body_hash: [u8; 32],
    /// A SIP-19 `Body`, always in the clear. Empty for a tombstone.
    pub body: Vec<u8>,
    pub signature: [u8; 64],
}

/// What a post's signature is made over.
///
/// Separate from [`Post`] because a signer builds one before there is a post
/// to hold the signature, and a verifier builds one from a post it was handed
/// -- the same split SIP-31 draws between `EntryTerms` and an `Entry`.
#[derive(Debug, Clone, Copy)]
pub struct PostTerms<'a> {
    pub account: &'a PubKey,
    pub device: &'a PubKey,
    pub serial: u64,
    pub prev: &'a [u8; 32],
    pub issued_at: u64,
    pub expires_after: u32,
    pub flags: u8,
    pub body: &'a [u8],
}

impl PostTerms<'_> {
    /// The 44 bytes a post's signature is made over: the context, then one
    /// digest of everything else.
    ///
    /// Hash-then-sign over a fixed width, as SIP-10, SIP-20, SIP-27 and SIP-31
    /// all do -- a signer sees the same small message whether the body is
    /// empty or 32 KiB.
    pub fn input(&self) -> Vec<u8> {
        self.input_hashed(&Sha256::digest(self.body).into())
    }

    /// The same, from a body hash rather than a body.
    ///
    /// **What a tombstone is verified with.** SIP-88 §Withdrawal keeps
    /// `body_hash` and `sig` when it drops the bytes, precisely so a withdrawn
    /// post still verifies and the chain runs through it unbroken. An exchange
    /// that cleared them would make every withdrawn post read as a forgery.
    pub fn input_hashed(&self, body_hash: &[u8; 32]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(self.account.as_bytes());
        h.update(self.device.as_bytes());
        h.update(self.serial.to_be_bytes());
        h.update(self.prev);
        h.update(self.issued_at.to_be_bytes());
        h.update(self.expires_after.to_be_bytes());
        h.update([self.flags]);
        h.update(body_hash);

        let mut out = Vec::with_capacity(FEED_CONTEXT.len() + 32);
        out.extend_from_slice(FEED_CONTEXT);
        out.extend_from_slice(&h.finalize());
        out
    }
}

/// Sign a post as `device_seed`'s device.
pub fn sign_post(device_seed: &[u8; 32], terms: &PostTerms) -> [u8; 64] {
    SigningKey::from_bytes(device_seed)
        .sign(&terms.input())
        .to_bytes()
}

/// Check a post's signature under the device it names.
///
/// **Step one of two.** It proves a key signed and says nothing about whose key
/// it is; binding `device` to `account` is a SIP-20 credential, which a
/// verifier must check separately -- the same two steps SIP-31 requires, and
/// the same warning, because the first alone returns a satisfying `true`.
pub fn verify_post(terms: &PostTerms, body_hash: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(terms.device.as_bytes()) else {
        return false;
    };
    vk.verify(&terms.input_hashed(body_hash), &Signature::from_bytes(sig))
        .is_ok()
}

impl Post {
    /// This post's terms, for verifying or for linking the next one.
    pub fn terms(&self) -> PostTerms<'_> {
        PostTerms {
            account: &self.account,
            device: &self.device,
            serial: self.serial,
            prev: &self.prev,
            issued_at: self.issued_at,
            expires_after: self.expires_after,
            flags: self.flags,
            body: &self.body,
        }
    }

    /// Build and sign a post. `prev` is [`crate::entry_sig::link`] of the
    /// previous post's input, or [`crate::entry_sig::GENESIS`] for the first.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        device_seed: &[u8; 32],
        account: &PubKey,
        serial: u64,
        prev: &[u8; 32],
        issued_at: u64,
        expires_after: u32,
        body: Vec<u8>,
    ) -> Post {
        let device = PubKey::new(
            SigningKey::from_bytes(device_seed)
                .verifying_key()
                .to_bytes(),
        );
        let terms = PostTerms {
            account,
            device: &device,
            serial,
            prev,
            issued_at,
            expires_after,
            flags: 0,
            body: &body,
        };
        let signature = sign_post(device_seed, &terms);
        Post {
            account: *account,
            device,
            serial,
            prev: *prev,
            issued_at,
            expires_after,
            flags: 0,
            body_hash: Sha256::digest(&body).into(),
            body,
            signature,
        }
    }

    /// Whether the signature holds, against the body hash this post carries.
    ///
    /// A post whose `body` does not hash to its own `body_hash` is **not**
    /// rejected here -- that is a separate fact an exchange checks on append
    /// and a reader checks with [`Post::body_matches`], and collapsing the two
    /// would report a damaged body as a forged signature.
    pub fn verify(&self) -> bool {
        verify_post(&self.terms(), &self.body_hash, &self.signature)
    }

    /// Whether the body is the one the signature commits to. Always true of a
    /// tombstone, whose body is gone and whose hash is kept.
    pub fn body_matches(&self) -> bool {
        self.body.is_empty() || <[u8; 32]>::from(Sha256::digest(&self.body)) == self.body_hash
    }

    /// The next post's `prev`.
    pub fn link(&self) -> [u8; 32] {
        crate::entry_sig::link(&self.terms().input_hashed(&self.body_hash))
    }

    /// A tombstone: this post with its body dropped, as SIP-88 §Withdrawal
    /// stores it. The signature and the hash stay, so it still verifies.
    pub fn tombstone(&self) -> Post {
        Post {
            body: Vec::new(),
            ..self.clone()
        }
    }

    /// Whether the body has been withdrawn or has expired.
    pub fn withdrawn(&self) -> bool {
        self.body.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(POST_HEADER + self.body.len() + 64);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(self.device.as_bytes());
        out.extend_from_slice(&self.serial.to_be_bytes());
        out.extend_from_slice(&self.prev);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_after.to_be_bytes());
        out.push(self.flags);
        out.extend_from_slice(&self.body_hash);
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Post> {
        if b.len() < POST_HEADER + 64 {
            return Err(Error::Malformed("post is truncated".into()));
        }
        let body_len = u32::from_be_bytes(b[149..153].try_into().unwrap()) as usize;
        if body_len > MAX_BODY {
            return Err(Error::Malformed(format!(
                "post body is {body_len} bytes, limit is {MAX_BODY}"
            )));
        }
        if b.len() != POST_HEADER + body_len + 64 {
            return Err(Error::Malformed(format!(
                "post is {} bytes, want {}",
                b.len(),
                POST_HEADER + body_len + 64
            )));
        }
        let at = POST_HEADER;
        Ok(Post {
            account: PubKey::new(b[0..32].try_into().unwrap()),
            device: PubKey::new(b[32..64].try_into().unwrap()),
            serial: u64::from_be_bytes(b[64..72].try_into().unwrap()),
            prev: b[72..104].try_into().unwrap(),
            issued_at: u64::from_be_bytes(b[104..112].try_into().unwrap()),
            expires_after: u32::from_be_bytes(b[112..116].try_into().unwrap()),
            flags: b[116],
            body_hash: b[117..149].try_into().unwrap(),
            body: b[at..at + body_len].to_vec(),
            signature: b[at + body_len..at + body_len + 64].try_into().unwrap(),
        })
    }
}

// ---- requests ---------------------------------------------------------

/// Append a post to one's own feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Append {
    pub post: Post,
}

impl Append {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + POST_HEADER + self.post.body.len() + 64);
        out.push(TYPE_APPEND);
        out.extend_from_slice(&self.post.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Append> {
        if b.is_empty() || b[0] != TYPE_APPEND {
            return Err(Error::Malformed("not a feed append".into()));
        }
        Ok(Append {
            post: Post::decode(&b[1..])?,
        })
    }
}

/// Read a page of somebody's feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Read {
    pub account: PubKey,
    /// Forward: serials above this. Backward: serials below it, and 0 means
    /// from `newest`.
    pub since: u64,
    pub limit: u16,
    pub dir: u8,
}

impl Read {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(44);
        out.push(TYPE_READ);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(&self.since.to_be_bytes());
        out.extend_from_slice(&self.limit.to_be_bytes());
        out.push(self.dir);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Read> {
        if b.len() != 44 || b[0] != TYPE_READ {
            return Err(Error::Malformed(format!(
                "feed read is {} bytes, want 44",
                b.len()
            )));
        }
        let dir = b[43];
        if dir != DIR_FORWARD && dir != DIR_BACKWARD {
            return Err(Error::Malformed(format!("unknown feed read dir {dir}")));
        }
        Ok(Read {
            account: PubKey::new(b[1..33].try_into().unwrap()),
            since: u64::from_be_bytes(b[33..41].try_into().unwrap()),
            limit: u16::from_be_bytes(b[41..43].try_into().unwrap()),
            dir,
        })
    }
}

/// Withdraw one of one's own posts, leaving a tombstone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdraw {
    pub account: PubKey,
    pub serial: u64,
}

impl Withdraw {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(TYPE_WITHDRAW);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(&self.serial.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Withdraw> {
        if b.len() != 41 || b[0] != TYPE_WITHDRAW {
            return Err(Error::Malformed(format!(
                "feed withdraw is {} bytes, want 41",
                b.len()
            )));
        }
        Ok(Withdraw {
            account: PubKey::new(b[1..33].try_into().unwrap()),
            serial: u64::from_be_bytes(b[33..41].try_into().unwrap()),
        })
    }
}

/// Which of these feeds have moved since the serial I hold?
///
/// One request over many feeds, which is the whole reason this route exists:
/// SIP-50 rejected client-side reconstruction as "N+1 requests per contact per
/// poll", and a reader following two hundred people has the same arithmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Since {
    pub feeds: Vec<(PubKey, u64)>,
}

impl Since {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.feeds.len() * 40);
        out.push(TYPE_SINCE);
        out.extend_from_slice(&(self.feeds.len() as u16).to_be_bytes());
        for (account, serial) in &self.feeds {
            out.extend_from_slice(account.as_bytes());
            out.extend_from_slice(&serial.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Since> {
        if b.len() < 3 || b[0] != TYPE_SINCE {
            return Err(Error::Malformed("feed since is truncated".into()));
        }
        let count = u16::from_be_bytes(b[1..3].try_into().unwrap());
        if count > MAX_SINCE {
            return Err(Error::Malformed(format!(
                "feed since asks about {count} feeds, limit is {MAX_SINCE}"
            )));
        }
        let want = 3 + count as usize * 40;
        if b.len() != want {
            return Err(Error::Malformed(format!(
                "feed since is {} bytes, want {want}",
                b.len()
            )));
        }
        let mut feeds = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let at = 3 + i * 40;
            feeds.push((
                PubKey::new(b[at..at + 32].try_into().unwrap()),
                u64::from_be_bytes(b[at + 32..at + 40].try_into().unwrap()),
            ));
        }
        Ok(Since { feeds })
    }
}

/// Where a feed has got to, and what its policy is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub account: PubKey,
}

impl Head {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(TYPE_HEAD);
        out.extend_from_slice(self.account.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Head> {
        if b.len() != 33 || b[0] != TYPE_HEAD {
            return Err(Error::Malformed(format!(
                "feed head is {} bytes, want 33",
                b.len()
            )));
        }
        Ok(Head {
            account: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// Set one's own feed's retention and size. Whole replacement, as SIP-21's
/// profile is: there is no partial update to get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Set {
    pub retention_secs: u32,
    pub max_posts: u32,
    /// SIP-90: this account asks to be findable in this exchange's feed
    /// directory. 0 is the default and means absent from it.
    ///
    /// **Here rather than on the SIP-21 profile**, which refuses unknown
    /// flag bits by design — so a bit there would break every reader of
    /// every profile for a feature only feed-aware clients want. It is also
    /// the right shape for this record: SIP-88 calls `Set` unsigned because
    /// "pruning is the exchange's act, nothing a reader repeats depends on
    /// the policy", and being listed in one exchange's directory is exactly
    /// that.
    pub listed: bool,
}

impl Set {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10);
        out.push(TYPE_SET);
        out.extend_from_slice(&self.retention_secs.to_be_bytes());
        out.extend_from_slice(&self.max_posts.to_be_bytes());
        out.push(u8::from(self.listed));
        out
    }

    pub fn decode(b: &[u8]) -> Result<Set> {
        if b.len() != 10 || b[0] != TYPE_SET {
            return Err(Error::Malformed(format!(
                "feed set is {} bytes, want 10",
                b.len()
            )));
        }
        Ok(Set {
            retention_secs: u32::from_be_bytes(b[1..5].try_into().unwrap()),
            max_posts: u32::from_be_bytes(b[5..9].try_into().unwrap()),
            listed: b[9] != 0,
        })
    }
}

/// SIP-90: ask for a page of this exchange's feed directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listed {
    /// Only accounts listed after this moment, so a caller pages forward.
    pub since: u64,
    pub limit: u16,
}

impl Listed {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(11);
        out.push(TYPE_LISTED);
        out.extend_from_slice(&self.since.to_be_bytes());
        out.extend_from_slice(&self.limit.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Listed> {
        if b.len() != 11 || b[0] != TYPE_LISTED {
            return Err(Error::Malformed(format!(
                "feed listed is {} bytes, want 11",
                b.len()
            )));
        }
        Ok(Listed {
            since: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            limit: u16::from_be_bytes(b[9..11].try_into().unwrap()),
        })
    }
}

/// SIP-90: who asked to be findable here, and when they asked.
///
/// **A key and a moment, and nothing else.** No last-activity time, no post
/// count, no topic — SIP-88 refused a directory because one "listed with a
/// last-activity time and mirrored to every peer every sixty seconds, is a
/// timestamped census of every active account", and three of those four
/// clauses are removed by what this does not carry and does not do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListedFeed {
    pub account: PubKey,
    /// When this account asked to be listed. **Not when it last posted**,
    /// which is the field SIP-88's census objection is actually about.
    pub listed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub now: u64,
    pub rows: Vec<ListedFeed>,
}

impl Listing {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.rows.len() * 40);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.rows.len() as u16).to_be_bytes());
        for r in &self.rows {
            out.extend_from_slice(r.account.as_bytes());
            out.extend_from_slice(&r.listed_at.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Listing> {
        if b.len() < 10 {
            return Err(Error::Malformed("feed listing is truncated".into()));
        }
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap());
        if count > MAX_LISTING {
            return Err(Error::Malformed(format!(
                "feed listing carries {count} rows, limit is {MAX_LISTING}"
            )));
        }
        let want = 10 + count as usize * 40;
        if b.len() != want {
            return Err(Error::Malformed(format!(
                "feed listing is {} bytes, want {want}",
                b.len()
            )));
        }
        let mut rows = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let at = 10 + i * 40;
            rows.push(ListedFeed {
                account: PubKey::new(b[at..at + 32].try_into().unwrap()),
                listed_at: u64::from_be_bytes(b[at + 32..at + 40].try_into().unwrap()),
            });
        }
        Ok(Listing {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            rows,
        })
    }
}

// ---- answers ----------------------------------------------------------

/// What an append was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    pub serial: u64,
    /// The exchange's own observation of arrival. **Retention and
    /// `expires_after` are measured from this and never from `issued_at`** --
    /// a feed is the first artifact here whose only in-log timestamp belongs
    /// to its author, and measured from that an author sets it far ahead and
    /// the post never prunes.
    pub received: u64,
    /// The new head: the next post's `prev`.
    pub head_input: [u8; 32],
    pub now: u64,
}

impl Appended {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(56);
        out.extend_from_slice(&self.serial.to_be_bytes());
        out.extend_from_slice(&self.received.to_be_bytes());
        out.extend_from_slice(&self.head_input);
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Appended> {
        if b.len() != 56 {
            return Err(Error::Malformed(format!(
                "appended is {} bytes, want 56",
                b.len()
            )));
        }
        Ok(Appended {
            serial: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            received: u64::from_be_bytes(b[8..16].try_into().unwrap()),
            head_input: b[16..48].try_into().unwrap(),
            now: u64::from_be_bytes(b[48..56].try_into().unwrap()),
        })
    }
}

/// One stored post, with the exchange's own arrival time beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub received: u64,
    pub post: Post,
}

impl Stored {
    fn write(&self, out: &mut Vec<u8>) {
        let bytes = self.post.encode();
        out.extend_from_slice(&self.received.to_be_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
    }

    fn read(b: &[u8], o: &mut usize) -> Result<Stored> {
        if b.len() < *o + 12 {
            return Err(Error::Malformed("stored post is truncated".into()));
        }
        let received = u64::from_be_bytes(b[*o..*o + 8].try_into().unwrap());
        let len = u32::from_be_bytes(b[*o + 8..*o + 12].try_into().unwrap()) as usize;
        *o += 12;
        if b.len() < *o + len {
            return Err(Error::Malformed("stored post overruns its page".into()));
        }
        let post = Post::decode(&b[*o..*o + len])?;
        *o += len;
        Ok(Stored { received, post })
    }
}

/// A page of a feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// False for a feed that is absent, withheld, or whose owner has blocked
    /// the caller -- one answer for all three.
    pub found: bool,
    pub oldest: u64,
    pub newest: u64,
    pub now: u64,
    pub posts: Vec<Stored>,
}

impl Page {
    /// A feed this caller is told nothing about. Every field but `now` is
    /// zero, so absent, withheld and blocked are byte-identical.
    pub fn none(now: u64) -> Page {
        Page {
            found: false,
            oldest: 0,
            newest: 0,
            now,
            posts: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(27);
        out.push(u8::from(self.found));
        out.extend_from_slice(&self.oldest.to_be_bytes());
        out.extend_from_slice(&self.newest.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.posts.len() as u16).to_be_bytes());
        for p in &self.posts {
            p.write(&mut out);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Page> {
        if b.len() < 27 {
            return Err(Error::Malformed("feed page is truncated".into()));
        }
        let count = u16::from_be_bytes(b[25..27].try_into().unwrap());
        if count > MAX_PAGE {
            return Err(Error::Malformed(format!(
                "feed page holds {count} posts, limit is {MAX_PAGE}"
            )));
        }
        let mut o = 27;
        let mut posts = Vec::with_capacity(count as usize);
        for _ in 0..count {
            posts.push(Stored::read(b, &mut o)?);
        }
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "feed page has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Page {
            found: b[0] != 0,
            oldest: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            newest: u64::from_be_bytes(b[9..17].try_into().unwrap()),
            now: u64::from_be_bytes(b[17..25].try_into().unwrap()),
            posts,
        })
    }
}

/// A succession seam: from this time, the feed's posts are the predecessor's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seam {
    pub at: u64,
    pub from: PubKey,
}

/// Where a feed has got to, and what its policy is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headed {
    pub found: bool,
    pub oldest: u64,
    pub newest: u64,
    pub head_input: [u8; 32],
    pub posts: u32,
    pub bytes: u64,
    pub retention_secs: u32,
    pub max_posts: u32,
    pub now: u64,
    /// SIP-90: this account asks to be findable in this exchange's
    /// directory. Read back so an author can see what they set.
    pub listed: bool,
    /// SIP-88 §Succession, newest last. Always empty until succession is
    /// built; the field is here so that building it is not a wire change.
    pub seams: Vec<Seam>,
}

impl Headed {
    pub fn none(now: u64) -> Headed {
        Headed {
            found: false,
            oldest: 0,
            newest: 0,
            head_input: [0; 32],
            posts: 0,
            bytes: 0,
            retention_secs: 0,
            max_posts: 0,
            now,
            listed: false,
            seams: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADED_FIXED + self.seams.len() * 40);
        out.push(u8::from(self.found));
        out.extend_from_slice(&self.oldest.to_be_bytes());
        out.extend_from_slice(&self.newest.to_be_bytes());
        out.extend_from_slice(&self.head_input);
        out.extend_from_slice(&self.posts.to_be_bytes());
        out.extend_from_slice(&self.bytes.to_be_bytes());
        out.extend_from_slice(&self.retention_secs.to_be_bytes());
        out.extend_from_slice(&self.max_posts.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out.push(u8::from(self.listed));
        out.push(self.seams.len() as u8);
        for s in &self.seams {
            out.extend_from_slice(&s.at.to_be_bytes());
            out.extend_from_slice(s.from.as_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Headed> {
        if b.len() < HEADED_FIXED {
            return Err(Error::Malformed("feed head is truncated".into()));
        }
        let seams = b[HEADED_FIXED - 1];
        if seams > MAX_SEAMS {
            return Err(Error::Malformed(format!(
                "feed head carries {seams} seams, limit is {MAX_SEAMS}"
            )));
        }
        let want = HEADED_FIXED + seams as usize * 40;
        if b.len() != want {
            return Err(Error::Malformed(format!(
                "feed head is {} bytes, want {want}",
                b.len()
            )));
        }
        let mut out = Vec::with_capacity(seams as usize);
        for i in 0..seams as usize {
            let at = HEADED_FIXED + i * 40;
            out.push(Seam {
                at: u64::from_be_bytes(b[at..at + 8].try_into().unwrap()),
                from: PubKey::new(b[at + 8..at + 40].try_into().unwrap()),
            });
        }
        Ok(Headed {
            found: b[0] != 0,
            oldest: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            newest: u64::from_be_bytes(b[9..17].try_into().unwrap()),
            head_input: b[17..49].try_into().unwrap(),
            posts: u32::from_be_bytes(b[49..53].try_into().unwrap()),
            bytes: u64::from_be_bytes(b[53..61].try_into().unwrap()),
            retention_secs: u32::from_be_bytes(b[61..65].try_into().unwrap()),
            max_posts: u32::from_be_bytes(b[65..69].try_into().unwrap()),
            now: u64::from_be_bytes(b[69..77].try_into().unwrap()),
            listed: b[77] != 0,
            seams: out,
        })
    }
}

/// One row of a [`Moved`] answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    /// Which row of the request this answers.
    pub index: u16,
    pub state: u8,
    pub source: u8,
    pub oldest: u64,
    pub newest: u64,
    /// The head, or -- for `STATE_ELSEWHERE` and `STATE_SUCCEEDED` -- the key
    /// to go to next.
    pub head_input: [u8; 32],
}

/// Which of the feeds asked about have moved.
///
/// **Only the rows that are not unchanged are carried.** `index` names a row's
/// place in the request, so a five-hundred-feed poll where nothing happened is
/// twelve bytes rather than twenty kilobytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub now: u64,
    pub asked: u16,
    pub rows: Vec<Row>,
}

impl Moved {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.rows.len() * 52);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&self.asked.to_be_bytes());
        out.extend_from_slice(&(self.rows.len() as u16).to_be_bytes());
        for r in &self.rows {
            out.extend_from_slice(&r.index.to_be_bytes());
            out.push(r.state);
            out.push(r.source);
            out.extend_from_slice(&r.oldest.to_be_bytes());
            out.extend_from_slice(&r.newest.to_be_bytes());
            out.extend_from_slice(&r.head_input);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Moved> {
        if b.len() < 12 {
            return Err(Error::Malformed("feed moved is truncated".into()));
        }
        let count = u16::from_be_bytes(b[10..12].try_into().unwrap());
        if count > MAX_SINCE {
            return Err(Error::Malformed(format!(
                "feed moved carries {count} rows, limit is {MAX_SINCE}"
            )));
        }
        let want = 12 + count as usize * 52;
        if b.len() != want {
            return Err(Error::Malformed(format!(
                "feed moved is {} bytes, want {want}",
                b.len()
            )));
        }
        let mut rows = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let at = 12 + i * 52;
            rows.push(Row {
                index: u16::from_be_bytes(b[at..at + 2].try_into().unwrap()),
                state: b[at + 2],
                source: b[at + 3],
                oldest: u64::from_be_bytes(b[at + 4..at + 12].try_into().unwrap()),
                newest: u64::from_be_bytes(b[at + 12..at + 20].try_into().unwrap()),
                head_input: b[at + 20..at + 52].try_into().unwrap(),
            });
        }
        Ok(Moved {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            asked: u16::from_be_bytes(b[8..10].try_into().unwrap()),
            rows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn key(b: u8) -> PubKey {
        PubKey::new(SigningKey::from_bytes(&seed(b)).verifying_key().to_bytes())
    }

    fn a_post(serial: u64, prev: [u8; 32]) -> Post {
        Post::sign(
            &seed(1),
            &key(9),
            serial,
            &prev,
            1_700_000_000 + serial,
            0,
            b"hello".to_vec(),
        )
    }

    #[test]
    fn the_signing_input_is_forty_four_bytes() {
        // The doc says 44 and SIP-88 says 44; a reader who trusts either
        // should be able to trust both.
        let p = a_post(1, crate::entry_sig::GENESIS);
        assert_eq!(p.terms().input().len(), 44);
        assert_eq!(FEED_CONTEXT.len(), 12);
    }

    #[test]
    fn the_header_is_one_hundred_and_fifty_three_bytes() {
        let p = a_post(1, crate::entry_sig::GENESIS);
        assert_eq!(POST_HEADER, 153);
        assert_eq!(p.encode().len(), POST_HEADER + 5 + 64);
    }

    #[test]
    fn a_post_round_trips_and_verifies() {
        let p = a_post(1, crate::entry_sig::GENESIS);
        let back = Post::decode(&p.encode()).unwrap();
        assert_eq!(back, p);
        assert!(back.verify(), "a post did not verify after a round trip");
        assert!(back.body_matches());
    }

    #[test]
    fn every_signed_field_is_covered() {
        // Each field on its own. Varying two at once would let a construction
        // that omitted one of them still pass.
        let p = a_post(7, [3; 32]);
        /// One field's name and a change to it, for the loop below.
        type Mutation = (&'static str, fn(&mut Post));

        let mutate: [Mutation; 8] = [
            ("account", |p| p.account = key(8)),
            ("device", |p| p.device = key(7)),
            ("serial", |p| p.serial += 1),
            ("prev", |p| p.prev = [4; 32]),
            ("issued_at", |p| p.issued_at += 1),
            ("expires_after", |p| p.expires_after += 1),
            ("flags", |p| p.flags = 1),
            ("body_hash", |p| p.body_hash = [5; 32]),
        ];
        for (what, f) in mutate {
            let mut t = p.clone();
            f(&mut t);
            assert!(!t.verify(), "a signature survived a changed {what}");
        }
        assert!(p.verify(), "the control failed: the post never verified");
    }

    #[test]
    fn a_tombstone_still_verifies_with_its_body_gone() {
        // The whole reason `body_hash` is a field rather than only a term:
        // an exchange that cleared it would make every withdrawn post read as
        // a forgery.
        let p = a_post(2, [1; 32]);
        let t = p.tombstone();
        assert!(t.withdrawn());
        assert!(t.verify(), "a tombstone read as forged");
        assert!(t.body_matches(), "an empty body is the tombstone's own");
        assert_eq!(t.link(), p.link(), "withdrawing broke the chain");
    }

    #[test]
    fn the_chain_link_is_sip_31s() {
        // Not a restatement of the definition: it is the claim that this
        // crate has one primitive rather than two that can drift, which is
        // what SIP-34 insists on for the entry hash.
        let p = a_post(1, crate::entry_sig::GENESIS);
        assert_eq!(
            p.link(),
            crate::entry_sig::link(&p.terms().input_hashed(&p.body_hash))
        );
    }

    #[test]
    fn a_damaged_body_is_not_a_forged_signature() {
        // Two different facts. Collapsing them would report corruption as an
        // accusation against the author.
        let mut p = a_post(1, crate::entry_sig::GENESIS);
        p.body = b"tampered".to_vec();
        assert!(p.verify(), "the signature covers the hash, not the bytes");
        assert!(!p.body_matches(), "the damage was not noticed");
    }

    #[test]
    fn requests_round_trip() {
        let p = a_post(1, crate::entry_sig::GENESIS);
        assert_eq!(
            Append::decode(&Append { post: p.clone() }.encode()).unwrap(),
            Append { post: p }
        );
        let r = Read {
            account: key(9),
            since: 4,
            limit: 20,
            dir: DIR_BACKWARD,
        };
        assert_eq!(Read::decode(&r.encode()).unwrap(), r);
        let w = Withdraw {
            account: key(9),
            serial: 3,
        };
        assert_eq!(Withdraw::decode(&w.encode()).unwrap(), w);
        let s = Since {
            feeds: vec![(key(9), 1), (key(8), 0)],
        };
        assert_eq!(Since::decode(&s.encode()).unwrap(), s);
        let h = Head { account: key(9) };
        assert_eq!(Head::decode(&h.encode()).unwrap(), h);
        let st = Set {
            listed: true,
            retention_secs: 86400,
            max_posts: 100,
        };
        assert_eq!(Set::decode(&st.encode()).unwrap(), st);
    }

    #[test]
    fn answers_round_trip() {
        let a = Appended {
            serial: 2,
            received: 1_700_000_100,
            head_input: [7; 32],
            now: 1_700_000_101,
        };
        assert_eq!(Appended::decode(&a.encode()).unwrap(), a);

        let page = Page {
            found: true,
            oldest: 1,
            newest: 2,
            now: 1_700_000_200,
            posts: vec![
                Stored {
                    received: 1_700_000_001,
                    post: a_post(1, crate::entry_sig::GENESIS),
                },
                Stored {
                    received: 1_700_000_002,
                    post: a_post(2, [9; 32]),
                },
            ],
        };
        assert_eq!(Page::decode(&page.encode()).unwrap(), page);

        let headed = Headed {
            listed: false,
            found: true,
            oldest: 1,
            newest: 9,
            head_input: [2; 32],
            posts: 9,
            bytes: 900,
            retention_secs: DEFAULT_RETENTION,
            max_posts: MAX_POSTS,
            now: 1_700_000_300,
            seams: vec![Seam {
                at: 1_600_000_000,
                from: key(5),
            }],
        };
        assert_eq!(Headed::decode(&headed.encode()).unwrap(), headed);

        let moved = Moved {
            now: 1_700_000_400,
            asked: 3,
            rows: vec![Row {
                index: 2,
                state: STATE_MOVED,
                source: FROM_HOME,
                oldest: 1,
                newest: 5,
                head_input: [6; 32],
            }],
        };
        assert_eq!(Moved::decode(&moved.encode()).unwrap(), moved);
    }

    #[test]
    fn absent_and_withheld_are_byte_identical() {
        // SIP-88 §What identifies a feed: answering "exists but hidden" would
        // itself be the disclosure that hiding was meant to prevent.
        let now = 1_700_000_000;
        assert_eq!(Page::none(now).encode(), Page::none(now).encode());
        assert_eq!(Headed::none(now).encode(), Headed::none(now).encode());
        assert!(!Page::none(now).found);
        assert!(!Headed::none(now).found);
    }

    #[test]
    fn malformed_is_an_error() {
        assert!(Post::decode(&[]).is_err());
        assert!(Read::decode(&[TYPE_READ]).is_err());
        assert!(Head::decode(&[TYPE_HEAD, 0]).is_err());

        // A body length that overruns the buffer.
        let mut p = a_post(1, crate::entry_sig::GENESIS).encode();
        p[149..153].copy_from_slice(&9999u32.to_be_bytes());
        assert!(Post::decode(&p).is_err(), "an overrun was accepted");

        // Trailing bytes are corruption, not forward compatibility.
        let mut ok = a_post(1, crate::entry_sig::GENESIS).encode();
        ok.push(0);
        assert!(Post::decode(&ok).is_err(), "trailing bytes were accepted");

        // An unknown paging direction is an operand, and there is nothing to
        // skip -- so it is an error, unlike an unknown part kind.
        let mut r = Read {
            account: key(9),
            since: 0,
            limit: 1,
            dir: DIR_FORWARD,
        }
        .encode();
        r[43] = 0x7f;
        assert!(Read::decode(&r).is_err(), "an unknown dir was accepted");
    }

    #[test]
    fn a_page_refuses_more_posts_than_it_may_hold() {
        let mut b = Page {
            found: true,
            oldest: 1,
            newest: 1,
            now: 1,
            posts: Vec::new(),
        }
        .encode();
        b[25..27].copy_from_slice(&(MAX_PAGE + 1).to_be_bytes());
        assert!(Page::decode(&b).is_err());
    }

    #[test]
    fn a_since_refuses_more_feeds_than_it_may_ask_about() {
        let mut b = Since { feeds: Vec::new() }.encode();
        b[1..3].copy_from_slice(&(MAX_SINCE + 1).to_be_bytes());
        assert!(Since::decode(&b).is_err());
    }
}
