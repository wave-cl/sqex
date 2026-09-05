//! Why a request was refused, as a value rather than a document.
//!
//! Every refusal used to be prose the caller had to search. Two shapes were in
//! use: `{"error": "not_an_admin"}` as JSON, and a bare `text/plain` line for a
//! request that failed to decode. A client wanting to act on a refusal — and
//! three places in `sqex-chat` did — had no choice but to match a substring
//! against the whole body:
//!
//! ```text
//! if code == 403 && said.contains("not_an_admin") { … }
//! ```
//!
//! That is correct only while no code is a substring of another **and** no
//! free-text detail ever contains one. The first held by luck of the
//! vocabulary; the second was never true in principle, because a decode error's
//! text was concatenated into the same string being searched. Neither was
//! enforced anywhere, and nothing would have reported the day one stopped
//! holding: the client would simply have taken the wrong branch.
//!
//! # The numbers are permanent
//!
//! A [`Code`]'s `u16` is written down here and **MUST NOT** be reused for a
//! different meaning. A client older than the exchange holds the old mapping,
//! so renumbering does not produce an error — it produces a confident wrong
//! answer, which is the failure this module exists to remove. Retire a number
//! rather than recycle it.
//!
//! [`Code::Unknown`] is what makes that survivable in the other direction: an
//! exchange newer than its client sends a code the client has never heard of,
//! and the client keeps the number and can say so, instead of guessing.

use sqnr_core::{Error, Result};

/// The longest detail carried. It is a diagnostic, not a payload — enough for a
/// decode error to say what it wanted and what it got.
pub const MAX_DETAIL: usize = 512;

/// A refusal with no detail is four bytes.
pub const HEADER: usize = 4;

/// Why a request was refused.
///
/// One code per distinct reason, shared across the modules that raise it:
/// `bad_signature` means the same thing whether a channel entry or a prekey
/// carried it, so both map here rather than each owning a private spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    // Transport and framing.
    Malformed,
    NotFound,
    BodyTooLarge,
    NoIdentity,
    UnsupportedVersion,
    TooManyStreams,
    NotWhitelisted,

    // SIP-20 credentials.
    WrongAccount,
    Expired,
    NotYetValid,
    WrongScope,
    BadSignature,

    // SIP-22 device registry.
    NotAuthorised,
    AlreadyClaimed,
    Revoked,
    SeniorDevice,
    NoSuchDevice,
    TooManyDevices,
    RateLimited,

    // SIP-16 channels.
    NoSuchChannel,
    NotAMember,
    NotAnAdmin,
    NotPublic,
    NotPrivate,
    ChannelFull,
    TooManyChannels,
    WrongEpoch,
    DirectMessage,
    NoPrekey,
    NoSuchEntry,
    SystemEntry,
    InviteQuota,
    BadRetention,
    LastAdmin,
    BrokenChain,
    UsedInstance,
    /// SIP-34: a receipted request to an exchange that issues no receipts.
    NoReceipts,
    /// SIP-35: this channel already has as many replicas as it may.
    TooManyReplicas,
    /// SIP-35: a write to a channel this exchange only replicates. The detail
    /// carries the origin's key, which is where the write belongs.
    Replicated,
    /// SIP-35: a read of a replicated channel whose membership the replica
    /// cannot derive. The detail carries the origin's key.
    Underived,
    /// SIP-35: this exchange holds two receipts for one position from the
    /// channel's origin, and will present neither branch as the conversation.
    Equivocated,
    /// SIP-28: more endpoints than an identity may publish.
    TooManyEndpoints,

    // SIP-18 blobs.
    NoSuchUpload,
    NoSuchBlob,
    BadChunk,
    TooManyUploads,
    BlobQuota,
    BlobChannelQuota,

    // SIP-23 prekeys.
    ReusedId,
    PoolFull,
    ClearQuota,

    // SIP-21 profiles and blocking.
    TooManyBlocked,
    NotYours,
    StaleSerial,

    // SIP-5 mailbox.
    RecipientFull,
    RecipientQuota,

    // SIP-12 sessions.
    NoSession,
    Backpressure,

    // SIP-13 rooms.
    RoomFull,

    Storage,

    /// A code this build does not know. Carries the number as received, so it
    /// can be reported rather than guessed at.
    Unknown(u16),
}

impl Code {
    /// The wire number. Permanent — see the module note.
    pub fn to_u16(self) -> u16 {
        match self {
            Code::Malformed => 1,
            Code::NotFound => 2,
            Code::BodyTooLarge => 3,
            Code::NoIdentity => 4,
            Code::UnsupportedVersion => 5,
            Code::TooManyStreams => 6,
            Code::NotWhitelisted => 54,

            Code::WrongAccount => 7,
            Code::Expired => 8,
            Code::NotYetValid => 9,
            Code::WrongScope => 10,
            Code::BadSignature => 11,

            Code::NotAuthorised => 12,
            Code::AlreadyClaimed => 13,
            Code::Revoked => 14,
            Code::SeniorDevice => 15,
            Code::NoSuchDevice => 16,
            Code::TooManyDevices => 17,
            Code::RateLimited => 18,

            Code::NoSuchChannel => 19,
            Code::NotAMember => 20,
            Code::NotAnAdmin => 21,
            Code::NotPublic => 22,
            Code::NotPrivate => 23,
            Code::ChannelFull => 24,
            Code::TooManyChannels => 25,
            Code::WrongEpoch => 26,
            Code::DirectMessage => 27,
            Code::NoPrekey => 28,
            Code::NoSuchEntry => 29,
            Code::SystemEntry => 30,
            Code::InviteQuota => 31,
            Code::BadRetention => 32,
            Code::LastAdmin => 33,
            Code::BrokenChain => 34,
            Code::UsedInstance => 35,
            Code::NoReceipts => 55,
            Code::TooManyReplicas => 56,
            Code::Replicated => 57,
            Code::Underived => 58,
            Code::Equivocated => 59,
            Code::TooManyEndpoints => 60,

            Code::NoSuchUpload => 36,
            Code::NoSuchBlob => 37,
            Code::BadChunk => 38,
            Code::TooManyUploads => 39,
            Code::BlobQuota => 40,
            Code::BlobChannelQuota => 41,

            Code::ReusedId => 42,
            Code::PoolFull => 43,
            Code::ClearQuota => 44,

            Code::TooManyBlocked => 45,
            Code::NotYours => 46,
            Code::StaleSerial => 47,

            Code::RecipientFull => 48,
            Code::RecipientQuota => 49,

            Code::NoSession => 50,
            Code::Backpressure => 51,

            Code::RoomFull => 52,

            Code::Storage => 53,

            Code::Unknown(v) => v,
        }
    }

    /// The reverse. An unrecognised number is kept rather than mapped onto
    /// something familiar — a wrong-but-known code reads as fact.
    pub fn from_u16(v: u16) -> Code {
        match v {
            1 => Code::Malformed,
            2 => Code::NotFound,
            3 => Code::BodyTooLarge,
            4 => Code::NoIdentity,
            5 => Code::UnsupportedVersion,
            6 => Code::TooManyStreams,
            54 => Code::NotWhitelisted,

            7 => Code::WrongAccount,
            8 => Code::Expired,
            9 => Code::NotYetValid,
            10 => Code::WrongScope,
            11 => Code::BadSignature,

            12 => Code::NotAuthorised,
            13 => Code::AlreadyClaimed,
            14 => Code::Revoked,
            15 => Code::SeniorDevice,
            16 => Code::NoSuchDevice,
            17 => Code::TooManyDevices,
            18 => Code::RateLimited,

            19 => Code::NoSuchChannel,
            20 => Code::NotAMember,
            21 => Code::NotAnAdmin,
            22 => Code::NotPublic,
            23 => Code::NotPrivate,
            24 => Code::ChannelFull,
            25 => Code::TooManyChannels,
            26 => Code::WrongEpoch,
            27 => Code::DirectMessage,
            28 => Code::NoPrekey,
            29 => Code::NoSuchEntry,
            30 => Code::SystemEntry,
            31 => Code::InviteQuota,
            32 => Code::BadRetention,
            33 => Code::LastAdmin,
            34 => Code::BrokenChain,
            35 => Code::UsedInstance,
            55 => Code::NoReceipts,
            56 => Code::TooManyReplicas,
            57 => Code::Replicated,
            58 => Code::Underived,
            59 => Code::Equivocated,
            60 => Code::TooManyEndpoints,

            36 => Code::NoSuchUpload,
            37 => Code::NoSuchBlob,
            38 => Code::BadChunk,
            39 => Code::TooManyUploads,
            40 => Code::BlobQuota,
            41 => Code::BlobChannelQuota,

            42 => Code::ReusedId,
            43 => Code::PoolFull,
            44 => Code::ClearQuota,

            45 => Code::TooManyBlocked,
            46 => Code::NotYours,
            47 => Code::StaleSerial,

            48 => Code::RecipientFull,
            49 => Code::RecipientQuota,

            50 => Code::NoSession,
            51 => Code::Backpressure,

            52 => Code::RoomFull,

            53 => Code::Storage,

            other => Code::Unknown(other),
        }
    }

    /// The word for logs and for a person reading a message. Display only —
    /// nothing decides anything on this string, which is the point.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Malformed => "malformed",
            Code::NotFound => "not_found",
            Code::BodyTooLarge => "body_too_large",
            Code::NoIdentity => "no_identity",
            Code::UnsupportedVersion => "unsupported_version",
            Code::TooManyStreams => "too_many_streams",
            Code::NotWhitelisted => "not_whitelisted",

            Code::WrongAccount => "wrong_account",
            Code::Expired => "expired",
            Code::NotYetValid => "not_yet_valid",
            Code::WrongScope => "wrong_scope",
            Code::BadSignature => "bad_signature",

            Code::NotAuthorised => "not_authorised",
            Code::AlreadyClaimed => "already_claimed",
            Code::Revoked => "revoked",
            Code::SeniorDevice => "senior_device",
            Code::NoSuchDevice => "no_such_device",
            Code::TooManyDevices => "too_many_devices",
            Code::RateLimited => "rate_limited",

            Code::NoSuchChannel => "no_such_channel",
            Code::NotAMember => "not_a_member",
            Code::NotAnAdmin => "not_an_admin",
            Code::NotPublic => "not_public",
            Code::NotPrivate => "not_private",
            Code::ChannelFull => "channel_full",
            Code::TooManyChannels => "too_many_channels",
            Code::WrongEpoch => "wrong_epoch",
            Code::DirectMessage => "direct_message",
            Code::NoPrekey => "no_prekey",
            Code::NoSuchEntry => "no_such_entry",
            Code::SystemEntry => "system_entry",
            Code::InviteQuota => "invite_quota",
            Code::BadRetention => "bad_retention",
            Code::LastAdmin => "last_admin",
            Code::BrokenChain => "broken_chain",
            Code::UsedInstance => "used_instance",
            Code::NoReceipts => "no_receipts",
            Code::TooManyReplicas => "too_many_replicas",
            Code::Replicated => "replicated",
            Code::Underived => "underived",
            Code::Equivocated => "equivocated",
            Code::TooManyEndpoints => "too_many_endpoints",

            Code::NoSuchUpload => "no_such_upload",
            Code::NoSuchBlob => "no_such_blob",
            Code::BadChunk => "bad_chunk",
            Code::TooManyUploads => "too_many_uploads",
            Code::BlobQuota => "blob_quota",
            Code::BlobChannelQuota => "blob_channel_quota",

            Code::ReusedId => "reused_id",
            Code::PoolFull => "pool_full",
            Code::ClearQuota => "clear_quota",

            Code::TooManyBlocked => "too_many_blocked",
            Code::NotYours => "not_yours",
            Code::StaleSerial => "stale_serial",

            Code::RecipientFull => "recipient_full",
            Code::RecipientQuota => "recipient_quota",

            Code::NoSession => "no_session",
            Code::Backpressure => "backpressure",

            Code::RoomFull => "room_full",

            Code::Storage => "storage",

            Code::Unknown(_) => "unknown",
        }
    }

    /// Every code this build knows, for tests and for anything enumerating the
    /// vocabulary. `Unknown` is not in it: it is a hole, not a reason.
    pub const ALL: &'static [Code] = &[
        Code::Malformed,
        Code::NotFound,
        Code::BodyTooLarge,
        Code::NoIdentity,
        Code::UnsupportedVersion,
        Code::TooManyStreams,
        Code::NotWhitelisted,
        Code::WrongAccount,
        Code::Expired,
        Code::NotYetValid,
        Code::WrongScope,
        Code::BadSignature,
        Code::NotAuthorised,
        Code::AlreadyClaimed,
        Code::Revoked,
        Code::SeniorDevice,
        Code::NoSuchDevice,
        Code::TooManyDevices,
        Code::RateLimited,
        Code::NoSuchChannel,
        Code::NotAMember,
        Code::NotAnAdmin,
        Code::NotPublic,
        Code::NotPrivate,
        Code::ChannelFull,
        Code::TooManyChannels,
        Code::WrongEpoch,
        Code::DirectMessage,
        Code::NoPrekey,
        Code::NoSuchEntry,
        Code::SystemEntry,
        Code::InviteQuota,
        Code::BadRetention,
        Code::LastAdmin,
        Code::BrokenChain,
        Code::UsedInstance,
        Code::NoReceipts,
        Code::TooManyReplicas,
        Code::Replicated,
        Code::Underived,
        Code::Equivocated,
        Code::TooManyEndpoints,
        Code::NoSuchUpload,
        Code::NoSuchBlob,
        Code::BadChunk,
        Code::TooManyUploads,
        Code::BlobQuota,
        Code::BlobChannelQuota,
        Code::ReusedId,
        Code::PoolFull,
        Code::ClearQuota,
        Code::TooManyBlocked,
        Code::NotYours,
        Code::StaleSerial,
        Code::RecipientFull,
        Code::RecipientQuota,
        Code::NoSession,
        Code::Backpressure,
        Code::RoomFull,
        Code::Storage,
    ];
}

/// A refusal, whole.
///
/// `detail` is free text and is **never** consulted to decide anything. It says
/// why a request would not decode, or which limit was reached; a caller acting
/// on a refusal reads `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: Code,
    pub detail: Option<String>,
}

impl Refusal {
    /// A refusal with nothing to add.
    pub fn new(code: Code) -> Refusal {
        Refusal { code, detail: None }
    }

    /// A refusal carrying a diagnostic.
    ///
    /// An empty detail normalises to `None`: an empty string and no string say
    /// the same nothing, and letting both exist would put a distinction on the
    /// wire that no reader could act on.
    pub fn detailed(code: Code, detail: impl Into<String>) -> Refusal {
        let d: String = detail.into();
        Refusal {
            code,
            detail: if d.is_empty() { None } else { Some(d) },
        }
    }

    /// `code | detail_len | detail`
    pub fn encode(&self) -> Vec<u8> {
        let detail = self.detail.as_deref().map(clamp).unwrap_or("");
        let mut out = Vec::with_capacity(HEADER + detail.len());
        out.extend_from_slice(&self.code.to_u16().to_be_bytes());
        out.extend_from_slice(&(detail.len() as u16).to_be_bytes());
        out.extend_from_slice(detail.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Refusal> {
        if b.len() < HEADER {
            return Err(Error::Malformed(format!(
                "refusal is {} bytes, want at least {HEADER}",
                b.len()
            )));
        }
        let code = Code::from_u16(u16::from_be_bytes([b[0], b[1]]));
        let len = u16::from_be_bytes([b[2], b[3]]) as usize;
        if b.len() != HEADER + len {
            return Err(Error::Malformed(format!(
                "refusal says {len} bytes of detail but carries {}",
                b.len() - HEADER
            )));
        }
        let detail = if len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&b[HEADER..])
                    .map_err(|e| Error::Malformed(format!("detail is not UTF-8: {e}")))?
                    .to_string(),
            )
        };
        Ok(Refusal { code, detail })
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.code, &self.detail) {
            (Code::Unknown(v), Some(d)) => write!(f, "unknown refusal {v}: {d}"),
            (Code::Unknown(v), None) => write!(f, "unknown refusal {v}"),
            (c, Some(d)) => write!(f, "{}: {d}", c.as_str()),
            (c, None) => write!(f, "{}", c.as_str()),
        }
    }
}

/// Truncate to [`MAX_DETAIL`] on a character boundary, so a long decode error
/// cannot make a refusal larger than the request that caused it.
fn clamp(d: &str) -> &str {
    if d.len() <= MAX_DETAIL {
        return d;
    }
    let mut end = MAX_DETAIL;
    while !d.is_char_boundary(end) {
        end -= 1;
    }
    &d[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_round_trips_with_and_without_detail() {
        let bare = Refusal::new(Code::NotAnAdmin);
        assert_eq!(bare.encode().len(), HEADER);
        assert_eq!(Refusal::decode(&bare.encode()).unwrap(), bare);

        let with = Refusal::detailed(Code::Malformed, "request is 12 bytes, want 33");
        assert_eq!(Refusal::decode(&with.encode()).unwrap(), with);
    }

    /// An empty detail is the same nothing as no detail, and says so on the
    /// wire — otherwise a length-prefixed field carries a distinction that
    /// decodes back to something a reader cannot use.
    #[test]
    fn an_empty_detail_is_no_detail() {
        let empty = Refusal::detailed(Code::Storage, "");
        assert_eq!(empty.detail, None);
        assert_eq!(empty.encode(), Refusal::new(Code::Storage).encode());
    }

    /// The forward-compatibility claim: an exchange newer than this build sends
    /// a number we have never seen, and we keep it rather than resolving it to
    /// something familiar.
    #[test]
    fn an_unknown_code_keeps_its_number() {
        let raw = Refusal {
            code: Code::Unknown(4242),
            detail: None,
        }
        .encode();
        let back = Refusal::decode(&raw).unwrap();
        assert_eq!(back.code, Code::Unknown(4242));
        assert_eq!(back.code.to_u16(), 4242);
        assert!(back.to_string().contains("4242"));
    }

    /// Numbers and words are two representations of one fact, so neither may
    /// collide: two codes sharing a number would decode to the wrong one, and
    /// two sharing a word would be indistinguishable in a log.
    #[test]
    fn codes_words_and_numbers_are_all_distinct() {
        let mut numbers: Vec<u16> = Code::ALL.iter().map(|c| c.to_u16()).collect();
        let n = numbers.len();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), n, "two codes share a number");

        let mut words: Vec<&str> = Code::ALL.iter().map(|c| c.as_str()).collect();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), n, "two codes share a word");
    }

    /// Every known number survives the trip, and none of them lands in
    /// `Unknown` — which is what would happen if `from_u16` fell behind
    /// `to_u16` after a code was added to one and not the other.
    #[test]
    fn every_code_round_trips_through_its_number() {
        for &c in Code::ALL {
            let back = Code::from_u16(c.to_u16());
            assert_eq!(back, c, "{} did not survive its number", c.as_str());
            assert!(
                !matches!(back, Code::Unknown(_)),
                "{} is missing from from_u16",
                c.as_str()
            );
        }
    }

    #[test]
    fn a_truncated_or_overlong_body_is_refused() {
        assert!(
            Refusal::decode(&[0, 21, 0]).is_err(),
            "3 bytes is too short"
        );
        // Says 5 bytes of detail, carries 2.
        assert!(Refusal::decode(&[0, 21, 0, 5, b'h', b'i']).is_err());
        // Says 0, carries 2.
        assert!(Refusal::decode(&[0, 21, 0, 0, b'h', b'i']).is_err());
    }

    #[test]
    fn a_long_detail_is_clamped_on_a_character_boundary() {
        let long = "é".repeat(MAX_DETAIL);
        let r = Refusal::detailed(Code::Malformed, long);
        let bytes = r.encode();
        assert!(bytes.len() <= HEADER + MAX_DETAIL);
        // The point of clamping on a boundary: it still decodes as UTF-8.
        let back = Refusal::decode(&bytes).unwrap();
        assert!(back.detail.unwrap().starts_with('é'));
    }
}
