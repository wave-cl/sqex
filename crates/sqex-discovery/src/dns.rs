//! The validating `TXT` lookup.
//!
//! Validation happens **here**, not in whatever answered. The resolvers in
//! `/etc/resolv.conf` are used as transport and the signatures are checked
//! locally against the root anchor, so a resolver that lies — or a network
//! tampering on the way to one — is caught either way. The AD bit is a claim by
//! the resolver about work it says it did, and the path to the resolver is not
//! protected; it is not consulted.
//!
//! # A resolver that strips the proof
//!
//! Some resolvers hand back the answer without the records that prove it:
//! `systemd-resolved`'s stub at 127.0.0.53 with DNSSEC off, and the forwarder
//! in most home routers, drop RRSIG and DS on the way through. To a validator
//! that looks exactly like an unsigned zone, and on a Linux desktop it refused
//! squic.org — a signed zone — with "the answer is not signed". So when the
//! system resolvers cannot carry a proof, the same lookup is made through
//! public resolvers that do (Cloudflare, Quad9, Google), **as transport only**:
//! the chain is still checked here against the root anchor, and nothing they
//! say is taken on trust, so this changes what is reachable and not what is
//! believed.
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
use crate::record::{self, Handover, Parsed, Record};

/// Building a resolver reads the system configuration and sets up a cache, so
/// it is done once and shared.
static RESOLVER: OnceCell<TokioResolver> = OnceCell::const_new();

/// The public resolvers, built once, for when the system's strip the proof.
static PUBLIC: OnceCell<TokioResolver> = OnceCell::const_new();

async fn resolver() -> Result<&'static TokioResolver> {
    RESOLVER
        .get_or_try_init(|| async {
            let mut builder = Resolver::builder_tokio().map_err(|e| {
                Error::Resolve(format!("cannot read the system DNS configuration: {e}"))
            })?;
            // No trust anchor is set, so hickory's built-in root anchor is used:
            // the chain is checked here rather than taken on trust from whoever
            // answered.
            builder.options_mut().validate = true;
            room_for_a_key_rollover(builder.options_mut());
            builder
                .build()
                .map_err(|e| Error::Resolve(format!("cannot build a validating resolver: {e}")))
        })
        .await
}

/// A UDP answer that is larger than the size we advertised must not be cut
/// off at the size we advertised.
///
/// hickory advertises 1232 bytes of EDNS payload and — this is the part
/// that matters — reads the datagram into a buffer of exactly that size.
/// Every resolver tried (the ISP's, the router's, Cloudflare, Google)
/// ignores the advertised size for a large DNSKEY RRset and sends the whole
/// thing, and hickory then decodes a packet with its last record cut in
/// half: "incorrect rdata length", the server marked as failed, and the
/// zone reported as *unsigned*. On 2026-09-17 Identity Digital rolled the
/// KSK of every TLD it runs, `.org` and `.exchange` among them, which put a
/// fifth key in each DNSKEY RRset and the signed answer over 1232 bytes —
/// and discovery of both exchanges stopped at once, from every network,
/// while `dig` reported the chain Secure. Four kilobytes is the size these
/// resolvers actually send up to; TCP is tried after that, not instead of
/// it, so the common case stays one datagram each way.
///
/// **One server at a time.** A network that clamps DNS over UDP at 1232
/// bytes whatever the client advertises -- Hetzner's, where both exchanges
/// live, does -- answers the DNSKEY query truncated, and hickory retries
/// over TCP. But it asks its servers in parallel, and the retry is
/// abandoned the moment a *second* server's truncated datagram lands ("UDP
/// already disabled, giving up"), which with two servers in the pool is
/// every time: the same zone that `dig +tcp` calls Secure came back
/// "DNSSEC validation failed" from every resolver, public ones included,
/// on 2026-09-18, and discovery from both exchanges was dead. With the
/// pool asked one server at a time the retry completes. The cost is the
/// latency of a failed first server, which is not the common case.
fn room_for_a_key_rollover(opts: &mut hickory_resolver::config::ResolverOpts) {
    opts.edns_payload_len = 4096;
    opts.try_tcp_on_error = true;
    opts.num_concurrent_reqs = 1;
}

/// Resolvers that carry DNSSEC records intact, as transport for a lookup the
/// system's could not carry. Validating, like the other: what they answer is
/// checked, not believed.
async fn public_resolver() -> Result<&'static TokioResolver> {
    use hickory_resolver::config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    PUBLIC
        .get_or_try_init(|| async {
            let mut servers = Vec::new();
            for group in [&CLOUDFLARE, &QUAD9, &GOOGLE] {
                servers.extend(ResolverConfig::udp_and_tcp(group).into_parts().2);
            }
            let config = ResolverConfig::from_parts(None, Vec::new(), servers);
            let mut builder =
                Resolver::builder_with_config(config, TokioRuntimeProvider::default());
            builder.options_mut().validate = true;
            room_for_a_key_rollover(builder.options_mut());
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
/// Everything a domain publishes at `_sqex`: its SIP-33 records and any SIP-40
/// handovers that verified for this domain.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Published {
    pub records: Vec<Record>,
    /// Signature-checked against `domain`. A handover that did not verify is
    /// not here, and was not reported: SIP-40 says a bad one is somebody
    /// else's record.
    pub handovers: Vec<Handover>,
}

impl Published {
    /// The keys the domain currently publishes, in record order.
    pub fn offered(&self) -> Vec<sqnr_core::PubKey> {
        self.records.iter().map(|r| r.key).collect()
    }
}

pub async fn lookup(domain: &str) -> Result<Published> {
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
    let mut handovers = Vec::new();
    for text in &texts {
        match record::parse(text) {
            Parsed::Ours(r) => ours.push(r),
            Parsed::Handover(h) => {
                // The one check the parser could not make. A failure is
                // logged and dropped, never surfaced: the record is foreign
                // by SIP-40's definition once its signature does not hold.
                if h.verify(domain) {
                    handovers.push(h);
                } else {
                    tracing::debug!(domain, from = %h.from, to = %h.to, "handover did not verify; ignored");
                }
            }
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
    Ok(Published {
        records: ours,
        handovers,
    })
}

/// Every **Secure** `TXT` string published at `name`, one entry per record.
///
/// Split out from [`lookup`] so the `Proof::Secure` filter can be exercised
/// against a name that actually has records in an unsigned zone. Pointing a test
/// at `_sqex.<unsigned domain>` proves nothing: there is no record there, so the
/// lookup ends at "not published" without the filter ever running, and the test
/// passes whether the filter exists or not.
pub async fn lookup_txt(name: &str) -> Result<Vec<String>> {
    // A system with no resolver configuration at all -- Android has no
    // `/etc/resolv.conf`, and nothing else hickory knows to read -- cannot
    // build the first resolver, let alone get an answer out of it. That is
    // the same situation as a system resolver that cannot do the lookup,
    // and takes the same road: the public resolvers, as transport only, with
    // every answer still validated here.
    let system = match resolver().await {
        Ok(system) => system,
        Err(why) => {
            tracing::info!(name, %why, "no system resolver; asking public resolvers");
            return lookup_txt_via(public_resolver().await?, name).await;
        }
    };
    lookup_txt_falling_back(system, public_resolver, name).await
}

/// [`lookup_txt`] with the two resolvers as arguments: the system's, and a
/// way to get the public ones only when they are needed. Public so a test
/// can stand a resolver that carries no proof in for the system's.
pub async fn lookup_txt_falling_back<F, Fut>(
    system: &TokioResolver,
    public: F,
    name: &str,
) -> Result<Vec<String>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<&'static TokioResolver>>,
{
    match lookup_txt_via(system, name).await {
        // Only the outcomes a proof-stripping resolver produces: a signed
        // zone that came back without its signatures, or a lookup the
        // system resolver could not do at all. "Not published" is an answer
        // and is kept; the public resolvers would say the same.
        Err(Error::Unsigned { .. }) | Err(Error::Resolve(_)) => {
            tracing::info!(
                name,
                "the system resolver returned no DNSSEC proof; asking public resolvers"
            );
            lookup_txt_via(public().await?, name).await
        }
        done => done,
    }
}

/// The public resolvers, for a test of the fallback.
pub async fn public_resolvers() -> Result<&'static TokioResolver> {
    public_resolver().await
}

/// A resolver over the public servers that **does not validate**, so every
/// answer comes back without a proof -- which is what a proof-stripping
/// system resolver looks like from here. For tests.
pub fn resolver_without_proofs() -> Result<TokioResolver> {
    use hickory_resolver::config::{CLOUDFLARE, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    let config = ResolverConfig::udp_and_tcp(&CLOUDFLARE);
    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().validate = false;
    builder
        .build()
        .map_err(|e| Error::Resolve(format!("cannot build a resolver: {e}")))
}

async fn lookup_txt_via(resolver: &TokioResolver, name: &str) -> Result<Vec<String>> {
    let answer = resolver.lookup(name, RecordType::TXT).await.map_err(|e| {
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
        tracing::warn!(
            name,
            unproven,
            "ignoring TXT answers without a DNSSEC proof"
        );
    }
    Ok(secure)
}

#[cfg(test)]
mod oversize_tests {
    //! A resolver that answers with more than it was told it may send.
    //!
    //! What every resolver tried did on 2026-09-17 for a DNSKEY RRset with a
    //! fifth key in it — see `room_for_a_key_rollover`. Stood in for here by
    //! a socket that answers any question with an unsigned TXT RRset of
    //! 1,500 bytes, so the outcome that proves the datagram was read whole
    //! is *Unsigned* (every record seen, none proven), and the outcome of a
    //! datagram cut at 1232 is a decode failure reported as *Resolve*.

    use super::*;
    use hickory_resolver::config::{NameServerConfig, ResolverConfig};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::proto::op::{Message, MessageType, OpCode};
    use hickory_resolver::proto::rr::rdata::TXT;
    use hickory_resolver::proto::rr::{Name, Record};

    /// Answers every query with `records` TXT records of a hundred bytes.
    async fn oversize_server(records: usize) -> std::net::SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let Ok(query) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let mut reply =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                reply.metadata.recursion_available = true;
                for q in &query.queries {
                    reply.add_query(q.clone());
                }
                let name: Name = "_sqex.big.test.".parse().unwrap();
                for i in 0..records {
                    let text = format!("v=sqex1; k={:0>90}", i);
                    reply.add_answer(Record::from_rdata(
                        name.clone(),
                        300,
                        RData::TXT(TXT::new(vec![text])),
                    ));
                }
                let bytes = reply.to_vec().unwrap();
                assert!(
                    bytes.len() > 1232,
                    "the answer must be oversize to test anything"
                );
                let _ = socket.send_to(&bytes, from).await;
            }
        });
        addr
    }

    fn resolver_at(addr: std::net::SocketAddr, with_room: bool) -> TokioResolver {
        let mut server = NameServerConfig::udp(addr.ip());
        for c in &mut server.connections {
            c.port = addr.port();
        }
        let config = ResolverConfig::from_parts(None, Vec::new(), vec![server]);
        let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().validate = false;
        builder.options_mut().attempts = 0;
        if with_room {
            room_for_a_key_rollover(builder.options_mut());
            // Not for this test: the fake speaks no TCP, and a fallback to
            // it would hang rather than say what UDP made of the answer.
            builder.options_mut().try_tcp_on_error = false;
        }
        builder.build().unwrap()
    }

    #[tokio::test]
    async fn an_answer_larger_than_advertised_is_read_whole() {
        let addr = oversize_server(14).await;
        let resolver = resolver_at(addr, true);
        let err = lookup_txt_via(&resolver, "_sqex.big.test.")
            .await
            .expect_err("unsigned records are refused");
        assert!(
            matches!(err, Error::Unsigned { unproven: 14, .. }),
            "every record should have been read and found unproven: {err:?}"
        );
    }

    /// The negative control, and the record of why the room is needed: at
    /// hickory's default the same answer is cut at 1232 bytes and the cut
    /// record fails to decode. Should this start passing, hickory has
    /// changed how it reads a datagram and `room_for_a_key_rollover` can go.
    #[tokio::test]
    async fn at_the_default_size_the_same_answer_is_cut_and_fails_to_decode() {
        let addr = oversize_server(14).await;
        let resolver = resolver_at(addr, false);
        let err = lookup_txt_via(&resolver, "_sqex.big.test.")
            .await
            .expect_err("a cut datagram cannot decode");
        assert!(
            matches!(err, Error::Resolve(_)),
            "wanted the decode failure, got {err:?}"
        );
    }
}
