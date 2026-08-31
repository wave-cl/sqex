//! What can go wrong finding an exchange, kept apart because the differences
//! matter to whoever reads them.
//!
//! "No record" and "the zone is not signed" are the two most easily confused,
//! and they have completely different fixes: publish something, versus sign the
//! zone. A single "lookup failed" would send an operator looking in the wrong
//! place, which is why they are separate variants rather than one string.

use sqnr_core::PubKey;

use crate::record::Invalid;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Nothing conforming at `_sqex.<domain>`. The domain may be fine; it just
    /// does not advertise an exchange.
    ///
    /// `negative_ttl` is set when the answer was a signed proof of absence
    /// rather than simply nothing — see the note on the message below, because
    /// that case has a trap in it.
    NotPublished {
        domain: String,
        name: String,
        negative_ttl: Option<u32>,
    },
    /// Records are there, and the zone is not signed. A different problem from
    /// having none, and refused rather than accepted — "unsigned" is a valid
    /// DNSSEC answer and would otherwise sail straight through.
    Unsigned { domain: String, unproven: usize },
    /// A record that claimed to be ours and was not usable.
    Malformed { domain: String, why: Invalid },
    /// The published key is not the pinned one. The refusal SIP-33 exists for.
    Changed {
        domain: String,
        pinned: PubKey,
        offered: Vec<PubKey>,
    },
    /// DNS did not answer, or answered with a broken signature.
    Resolve(String),
    /// The pin store could not be read or written.
    Store(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The trap: a validating client sets CD (checking-disabled) so it
            // can check signatures itself, and resolvers cache CD answers in a
            // slot of their own. A record published *after* something first
            // asked for it is therefore invisible here for the rest of the
            // negative TTL — while `dig`, which does not set CD, cheerfully
            // shows it. Somebody debugging that with dig concludes the record
            // is fine and the client is broken, and both are true.
            Error::NotPublished {
                domain,
                name,
                negative_ttl: Some(ttl),
            } => write!(
                f,
                "{domain} publishes no exchange: {name} is proven absent (a signed \
                 non-existence proof, cached for another {ttl}s).\n\
                 If it was published recently this is a stale negative and will clear \
                 on its own — dig will already show the record, because dig does not \
                 set the checking-disabled bit that validating clients do, and \
                 resolvers cache those answers separately."
            ),
            Error::NotPublished { domain, name, .. } => write!(
                f,
                "{domain} publishes no exchange: there is no {name} TXT record. \
                 Ask whoever runs it for an address and key, or have them publish one (SIP-33)"
            ),
            Error::Unsigned { domain, unproven } => write!(
                f,
                "{domain} answered, but the answer is not signed (DNSSEC proof was not Secure \
                 for {unproven} record(s)). Discovery takes a key from DNS, so an unsigned zone \
                 is refused — sign the zone, or configure the address and key directly"
            ),
            Error::Malformed { domain, why } => write!(
                f,
                "{domain} publishes an sqex record that cannot be used: {why}"
            ),
            Error::Changed {
                domain,
                pinned,
                offered,
            } => write!(
                f,
                "{}",
                crate::known::changed_message(domain, pinned, offered)
            ),
            Error::Resolve(e) => write!(f, "{e}"),
            Error::Store(e) => write!(f, "the known-servers file could not be used: {e}"),
        }
    }
}

impl std::error::Error for Error {}
