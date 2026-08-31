//! The validating `TXT` lookup.
//!
//! Validation happens **here**, not in whatever answered. The resolvers in
//! `/etc/resolv.conf` are used as transport and the signatures are checked
//! locally against the root anchor, so a resolver that lies — or a network
//! tampering on the way to one — is caught either way. The AD bit is a claim by
//! the resolver about work it says it did, and the path to the resolver is not
//! protected; it is not consulted.
//!
//! There is no feature flag turning this off. For `sqns://` addresses DNSSEC is
//! defence in depth for a pointer and dropping it merely weakens them; here the
//! record *is* the identity, so a build that could not validate would not be
//! doing discovery, it would be trusting its resolver.
//!
//! This is the second implementation of these sixty lines in the family — the
//! first is `sqns-client`'s `dns.rs`, which solves the same problem for
//! `sqns://`. Copied rather than depended on while sqns's future is undecided.
//! If both survive, they belong in `sqnr` as one.

use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use tokio::sync::OnceCell;

use crate::error::{Error, Result};
use crate::record::{self, Parsed, Record};

/// Building a resolver reads the system configuration and sets up a cache, so
/// it is done once and shared.
static RESOLVER: OnceCell<TokioResolver> = OnceCell::const_new();

async fn resolver() -> Result<&'static TokioResolver> {
    RESOLVER
        .get_or_try_init(|| async {
            let mut builder = Resolver::builder_tokio()
                .map_err(|e| Error::Resolve(format!("cannot read the system DNS configuration: {e}")))?;
            // No trust anchor is set, so hickory's built-in root anchor is used:
            // the chain is checked here rather than taken on trust from whoever
            // answered.
            builder.options_mut().validate = true;
            builder
                .build()
                .map_err(|e| Error::Resolve(format!("cannot build a validating resolver: {e}")))
        })
        .await
}

/// Every conforming record published for `domain`, in the order DNS gave them.
///
/// Records that are not ours are skipped in silence. Records that are ours and
/// malformed are an error: a domain that meant to publish one and got it wrong
/// should hear about it rather than look like a domain that published nothing.
pub async fn lookup(domain: &str) -> Result<Vec<Record>> {
    let name = record::query_name(domain);
    // `lookup_txt` reports against the name it queried, because a caller may
    // hand it any name. Here the user asked about a domain, so the domain is
    // what the message should name.
    let texts = lookup_txt(&name).await.map_err(|e| match e {
        Error::NotPublished { negative_ttl, .. } => Error::NotPublished {
            domain: domain.to_string(),
            name: name.clone(),
            negative_ttl,
        },
        Error::Unsigned { unproven, .. } => Error::Unsigned {
            domain: domain.to_string(),
            unproven,
        },
        other => other,
    })?;

    let mut ours = Vec::new();
    for text in &texts {
        match record::parse(text) {
            Parsed::Ours(r) => ours.push(r),
            Parsed::Foreign => {}
            Parsed::Broken(why) => {
                return Err(Error::Malformed {
                    domain: domain.to_string(),
                    why,
                });
            }
        }
    }

    if ours.is_empty() {
        return Err(Error::NotPublished {
            domain: domain.to_string(),
            name,
            negative_ttl: None,
        });
    }
    Ok(ours)
}

/// Every **Secure** `TXT` string published at `name`, one entry per record.
///
/// Split out from [`lookup`] so the `Proof::Secure` filter can be exercised
/// against a name that actually has records in an unsigned zone. Pointing a test
/// at `_sqex.<unsigned domain>` proves nothing: there is no record there, so the
/// lookup ends at "not published" without the filter ever running, and the test
/// passes whether the filter exists or not.
pub async fn lookup_txt(name: &str) -> Result<Vec<String>> {
    let resolver = resolver().await?;

    let answer = resolver
        .lookup(name, RecordType::TXT)
        .await
        .map_err(|e| {
            if !e.is_no_records_found() {
                return Error::Resolve(format!(
                    "looking up {name} failed: {e}. A bogus signature means the answer was \
                     tampered with; a resolver that strips DNSSEC records looks the same from \
                     here."
                ));
            }
            // The SOA that came back with the negative answer carries how long
            // a resolver may go on serving it. That matters: a record published
            // *after* something asked for it stays invisible for the rest of
            // this window, and only to clients that validate. See `Error`.
            let negative_ttl = e.into_soa().map(|soa| soa.ttl);
            Error::NotPublished {
                domain: name.to_string(),
                name: name.to_string(),
                negative_ttl,
            }
        })?;

    // An unsigned zone is a perfectly valid DNSSEC outcome — Insecure, not an
    // error — so it has to be refused explicitly rather than relied on to fail
    // above. This is the whole reason the lookup is done this way, and it is the
    // one branch that silently becomes a no-op if the filter is ever dropped.
    let mut secure = Vec::new();
    let mut unproven = 0usize;
    for rr in answer.answers() {
        if rr.record_type() != RecordType::TXT {
            continue;
        }
        if rr.proof != Proof::Secure {
            unproven += 1;
            continue;
        }
        if let RData::TXT(txt) = &rr.data {
            secure.push(record::join(&txt.txt_data));
        }
    }

    if secure.is_empty() {
        if unproven > 0 {
            return Err(Error::Unsigned {
                domain: name.to_string(),
                unproven,
            });
        }
        return Err(Error::NotPublished {
            domain: name.to_string(),
            name: name.to_string(),
            negative_ttl: None,
        });
    }
    if unproven > 0 {
        tracing::warn!(name, unproven, "ignoring TXT answers without a DNSSEC proof");
    }
    Ok(secure)
}

