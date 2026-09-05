//! SIP-28 public key resolution: where a key can be reached, on the exchange's
//! word.
//!
//! **The exchange is trusted for availability and privacy, not for
//! authenticity**, and that boundary is the central claim of the SIP rather
//! than a caveat on it. A consumer resolving `K` connects to the address it is
//! given and sQUIC pins `K` in the handshake, so an exchange that returned an
//! attacker's address achieves nothing — the attacker cannot complete the
//! handshake. What a dishonest exchange can do is *deny*: wrong or absent
//! endpoints mean the consumer does not connect, which is a denial of service
//! and not a compromise. And it learns who asks about whom.
//!
//! Nothing here is signed. That is a choice to keep one mechanism rather than
//! two: the handshake has already established which key is speaking, and a
//! second scheme layered over it would need its own format, its own
//! verification path and its own bugs.
//!
//! # What this gives up
//!
//! Gathered in one place because each is a property the retired `sqns` had and
//! this does not: replication between exchanges, upstream recursion, offline
//! verification, long-lived caching, and **authenticated retirement**. The last
//! is the sharpest — see [`Successor`].

use sqnr_core::{Error, PubKey, Result};

pub const TYPE_PUBLISH: u8 = 0x10;
pub const TYPE_RESOLVE: u8 = 0x11;
pub const TYPE_SUCCESSOR: u8 = 0x12;

/// Capabilities one identity may publish alongside its endpoints (SIP-26).
///
/// Small on purpose. Advertising capability advertises attack surface — a
/// version string tells an attacker which vulnerabilities apply — and an
/// exchange makes that queryable for every identity at once, which a
/// distributed set of signed records does not.
pub const MAX_CAPABILITIES: usize = 8;
/// Bytes one capability string may occupy.
pub const MAX_CAPABILITY: usize = 64;

/// Endpoints one identity may publish.
///
/// Bounded because publication is self-asserted: an identity may name any
/// address, including one it does not control. A consumer pins the key on
/// connecting, so pointing at a third party produces failed handshakes there
/// rather than misdirection — but an identity with many consumers could still
/// aim traffic at a victim, and a small cap is most of the answer.
pub const MAX_ENDPOINTS: usize = 8;
/// Bytes a DNS name may occupy.
pub const MAX_HOST: usize = 253;
/// The longest a publication may claim to be good for.
pub const MAX_TTL: u32 = 3600;

pub const KIND_DNS: u8 = 0;
pub const KIND_IPV4: u8 = 4;
pub const KIND_IPV6: u8 = 6;

/// One place a service says it can be reached.
///
/// The shape is `sqns`'s, which was proven before that service was retired and
/// is kept rather than reinvented: lower `priority` is tried first, and
/// `weight` distributes load among equal priorities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub kind: u8,
    /// Four bytes for IPv4, sixteen for IPv6, a UTF-8 name for DNS.
    pub host: Vec<u8>,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

impl Endpoint {
    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        if self.kind == KIND_DNS {
            out.push(self.host.len() as u8);
        }
        out.extend_from_slice(&self.host);
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.priority.to_be_bytes());
        out.extend_from_slice(&self.weight.to_be_bytes());
    }

    fn read(b: &[u8], o: &mut usize) -> Result<Endpoint> {
        if b.len() < *o + 1 {
            return Err(Error::Malformed("endpoint is truncated".into()));
        }
        let kind = b[*o];
        *o += 1;
        let len = match kind {
            KIND_IPV4 => 4,
            KIND_IPV6 => 16,
            KIND_DNS => {
                if b.len() < *o + 1 {
                    return Err(Error::Malformed("endpoint name is truncated".into()));
                }
                let n = b[*o] as usize;
                *o += 1;
                if n > MAX_HOST {
                    return Err(Error::Malformed(format!(
                        "endpoint name is {n} bytes, limit is {MAX_HOST}"
                    )));
                }
                n
            }
            other => {
                return Err(Error::Malformed(format!("unknown endpoint kind {other}")));
            }
        };
        if b.len() < *o + len + 6 {
            return Err(Error::Malformed("endpoint is truncated".into()));
        }
        let host = b[*o..*o + len].to_vec();
        // A name that is not text is not a name. Checked here rather than at
        // use, so a resolver never hands a caller bytes it cannot look up.
        if kind == KIND_DNS && std::str::from_utf8(&host).is_err() {
            return Err(Error::Malformed("endpoint name is not UTF-8".into()));
        }
        let at = *o + len;
        *o = at + 6;
        Ok(Endpoint {
            kind,
            host,
            port: u16::from_be_bytes(b[at..at + 2].try_into().unwrap()),
            priority: u16::from_be_bytes(b[at + 2..at + 4].try_into().unwrap()),
            weight: u16::from_be_bytes(b[at + 4..at + 6].try_into().unwrap()),
        })
    }
}

/// Publish this identity's endpoints, and what it speaks.
///
/// **The whole set is replaced.** There is no partial update, and that is
/// deliberate: partial updates require reconciliation, and reconciliation
/// between an unsigned publisher and a trusting store is where stale addresses
/// live forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub ttl_secs: u32,
    pub endpoints: Vec<Endpoint>,
    /// SIP-26: what this identity offers — an ALPN, a service name, a version.
    ///
    /// **Here rather than anywhere else because it has the same provenance as
    /// the address it accompanies**, and splitting them across two mechanisms
    /// would be the odd choice. SIP-26 spent most of its length arguing the
    /// opposite, correctly, while resolution lived in a signed record: a signed
    /// capability is replicated, cached, and still readable when the service is
    /// down, and an exchange's answer is none of those. Once the address itself
    /// became unsigned and transport-authenticated, that argument applied to
    /// both halves or neither.
    ///
    /// The test that survives, and that every proposed field should meet:
    /// **why can this not simply be published as part of the endpoint set?** A
    /// field that needs different durability, a different signer or a different
    /// lifetime does not belong here. Readiness is the example that fails it —
    /// SIP-4's beacon flags already carry that, and it changes faster than a
    /// publication.
    pub capabilities: Vec<String>,
}

impl Publish {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6);
        out.push(TYPE_PUBLISH);
        out.extend_from_slice(&self.ttl_secs.to_be_bytes());
        out.push(self.endpoints.len() as u8);
        for e in &self.endpoints {
            e.write(&mut out);
        }
        out.push(self.capabilities.len() as u8);
        for c in &self.capabilities {
            out.push(c.len() as u8);
            out.extend_from_slice(c.as_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Publish> {
        if b.len() < 6 {
            return Err(Error::Malformed("publish is truncated".into()));
        }
        if b[0] != TYPE_PUBLISH {
            return Err(Error::Malformed(format!("not a publish (type {:#x})", b[0])));
        }
        let count = b[5] as usize;
        if count > MAX_ENDPOINTS {
            return Err(Error::Malformed(format!(
                "publish carries {count} endpoints, limit is {MAX_ENDPOINTS}"
            )));
        }
        let mut o = 6;
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            endpoints.push(Endpoint::read(b, &mut o)?);
        }
        let capabilities = read_capabilities(b, &mut o)?;
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "publish has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Publish {
            capabilities,
            // Clamped rather than refused, the way SIP-16 clamps a fetch's
            // wait: a publisher asking to be believed for longer than this
            // exchange will believe anybody is not making an error.
            ttl_secs: u32::from_be_bytes(b[1..5].try_into().unwrap()).min(MAX_TTL),
            endpoints,
        })
    }
}

/// Read a capability list, which `Publish` and `Resolved` share.
fn read_capabilities(b: &[u8], o: &mut usize) -> Result<Vec<String>> {
    if b.len() < *o + 1 {
        return Err(Error::Malformed("capabilities are truncated".into()));
    }
    let count = b[*o] as usize;
    *o += 1;
    if count > MAX_CAPABILITIES {
        return Err(Error::Malformed(format!(
            "publish carries {count} capabilities, limit is {MAX_CAPABILITIES}"
        )));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if b.len() < *o + 1 {
            return Err(Error::Malformed("capability is truncated".into()));
        }
        let len = b[*o] as usize;
        *o += 1;
        if len > MAX_CAPABILITY {
            return Err(Error::Malformed(format!(
                "capability is {len} bytes, limit is {MAX_CAPABILITY}"
            )));
        }
        if b.len() < *o + len {
            return Err(Error::Malformed("capability is truncated".into()));
        }
        out.push(
            std::str::from_utf8(&b[*o..*o + len])
                .map_err(|_| Error::Malformed("capability is not UTF-8".into()))?
                .to_string(),
        );
        *o += len;
    }
    Ok(out)
}

/// Ask where a key can be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolve {
    pub key: PubKey,
}

/// Bytes a `Resolve` occupies.
pub const RESOLVE_LEN: usize = 1 + 32;

impl Resolve {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESOLVE_LEN);
        out.push(TYPE_RESOLVE);
        out.extend_from_slice(self.key.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Resolve> {
        if b.len() != RESOLVE_LEN {
            return Err(Error::Malformed(format!(
                "resolve is {} bytes, want {RESOLVE_LEN}",
                b.len()
            )));
        }
        if b[0] != TYPE_RESOLVE {
            return Err(Error::Malformed(format!("not a resolve (type {:#x})", b[0])));
        }
        Ok(Resolve {
            key: PubKey::new(b[1..33].try_into().unwrap()),
        })
    }
}

/// The answer, with its provenance.
///
/// **The provenance is not decoration.** A consumer that cannot see when an
/// answer was published, when it expires and when the service was last seen
/// cannot judge it — a bare list of addresses would make the exchange's
/// confidence invisible and its errors indistinguishable from silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub found: bool,
    pub endpoints: Vec<Endpoint>,
    pub published_at: u64,
    pub expires_at: u64,
    /// The SIP-4 beacon observation, or zero for an identity that does not
    /// beat. **This is the question a signed record structurally cannot
    /// answer**: not where a service claims to be, but that somebody saw it
    /// there recently.
    pub last_seen: u64,
    /// The exchange's own clock. Staleness is computed against the observer's
    /// clock and not the consumer's, for the reason SIP-4 gives.
    pub now: u64,
    /// SIP-26: what the identity said it speaks, with the same provenance and
    /// the same expiry as the endpoints beside it.
    pub capabilities: Vec<String>,
}

impl Resolved {
    /// Nothing published, said in the same shape as an answer.
    pub fn none(now: u64) -> Resolved {
        Resolved {
            found: false,
            endpoints: Vec::new(),
            published_at: 0,
            expires_at: 0,
            last_seen: 0,
            now,
            capabilities: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34);
        out.push(u8::from(self.found));
        out.push(self.endpoints.len() as u8);
        for e in &self.endpoints {
            e.write(&mut out);
        }
        out.extend_from_slice(&self.published_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.last_seen.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out.push(self.capabilities.len() as u8);
        for c in &self.capabilities {
            out.push(c.len() as u8);
            out.extend_from_slice(c.as_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Resolved> {
        if b.len() < 2 {
            return Err(Error::Malformed("resolved is truncated".into()));
        }
        let count = b[1] as usize;
        if count > MAX_ENDPOINTS {
            return Err(Error::Malformed(format!(
                "resolved carries {count} endpoints, limit is {MAX_ENDPOINTS}"
            )));
        }
        let mut o = 2;
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            endpoints.push(Endpoint::read(b, &mut o)?);
        }
        if b.len() < o + 32 {
            return Err(Error::Malformed("resolved is truncated".into()));
        }
        let at = |i: usize| u64::from_be_bytes(b[o + i..o + i + 8].try_into().unwrap());
        let (published_at, expires_at, last_seen, now) = (at(0), at(8), at(16), at(24));
        o += 32;
        let capabilities = read_capabilities(b, &mut o)?;
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "resolved has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Resolved {
            found: b[0] != 0,
            endpoints,
            published_at,
            expires_at,
            last_seen,
            now,
            capabilities,
        })
    }
}

/// A pointer to where this identity has moved.
///
/// **Materially weaker than a signed retirement, and the difference must not be
/// glossed.** A signed supersession is made by an identity key held offline, so
/// a stolen service key cannot retire itself or forward callers anywhere. This
/// pointer is authenticated by the connection, which means whoever holds the
/// key can set it — and after a theft, that is the attacker.
///
/// So an exchange cannot express *this key was stolen, use this one instead*,
/// which is the case rotation exists for. It can express *I am moving*, and
/// only while the mover is still in control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Successor {
    pub successor: PubKey,
    pub reason: String,
}

/// Bytes a successor's reason may occupy.
pub const MAX_REASON: usize = 128;

impl Successor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34 + self.reason.len());
        out.push(TYPE_SUCCESSOR);
        out.extend_from_slice(self.successor.as_bytes());
        out.push(self.reason.len() as u8);
        out.extend_from_slice(self.reason.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Successor> {
        if b.len() < 34 {
            return Err(Error::Malformed("successor is truncated".into()));
        }
        if b[0] != TYPE_SUCCESSOR {
            return Err(Error::Malformed(format!(
                "not a successor (type {:#x})",
                b[0]
            )));
        }
        let len = b[33] as usize;
        if len > MAX_REASON {
            return Err(Error::Malformed(format!(
                "reason is {len} bytes, limit is {MAX_REASON}"
            )));
        }
        if b.len() != 34 + len {
            return Err(Error::Malformed("successor length disagrees".into()));
        }
        Ok(Successor {
            successor: PubKey::new(b[1..33].try_into().unwrap()),
            reason: std::str::from_utf8(&b[34..34 + len])
                .map_err(|_| Error::Malformed("reason is not UTF-8".into()))?
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> Endpoint {
        Endpoint {
            kind: KIND_IPV4,
            host: vec![198, 51, 100, 7],
            port,
            priority: 10,
            weight: 5,
        }
    }

    fn named(host: &str) -> Endpoint {
        Endpoint {
            kind: KIND_DNS,
            host: host.as_bytes().to_vec(),
            port: 443,
            priority: 0,
            weight: 0,
        }
    }

    #[test]
    fn every_endpoint_kind_round_trips() {
        let v6 = Endpoint {
            kind: KIND_IPV6,
            host: vec![0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 5400,
            priority: 1,
            weight: 2,
        };
        let p = Publish {
            ttl_secs: 300,
            capabilities: vec![],
            endpoints: vec![v4(443), v6, named("ex.squic.org")],
        };
        assert_eq!(Publish::decode(&p.encode()).unwrap(), p);
        // Trailing bytes are refused here as everywhere else in this stack.
        let mut extra = p.encode();
        extra.push(0);
        assert!(Publish::decode(&extra).is_err());
    }

    /// A TTL longer than this exchange will believe anybody is clamped rather
    /// than refused: a publisher asking for a week is not making an error.
    #[test]
    fn a_long_ttl_is_clamped_and_not_refused() {
        let p = Publish {
            ttl_secs: u32::MAX,
            capabilities: vec![],
            endpoints: vec![v4(443)],
        };
        assert_eq!(Publish::decode(&p.encode()).unwrap().ttl_secs, MAX_TTL);
    }

    /// **Publication is self-asserted**, so the count is capped: an identity
    /// with many consumers could otherwise aim traffic at a victim, and a
    /// consumer pinning the key turns that into failed handshakes there rather
    /// than misdirection — but the volume is still worth bounding.
    #[test]
    fn more_endpoints_than_the_cap_is_refused() {
        let p = Publish {
            ttl_secs: 60,
            capabilities: vec![],
            endpoints: (0..=MAX_ENDPOINTS).map(|i| v4(i as u16)).collect(),
        };
        assert!(Publish::decode(&p.encode()).is_err());
        let ok = Publish {
            ttl_secs: 60,
            capabilities: vec![],
            endpoints: (0..MAX_ENDPOINTS).map(|i| v4(i as u16)).collect(),
        };
        assert_eq!(Publish::decode(&ok.encode()).unwrap(), ok);
    }

    /// A name that is not text is not a name, and is refused at the boundary
    /// rather than handed to a caller that cannot look it up.
    #[test]
    fn a_name_that_is_not_utf8_is_refused() {
        let bad = Publish {
            ttl_secs: 60,
            capabilities: vec![],
            endpoints: vec![Endpoint {
                kind: KIND_DNS,
                host: vec![0xff, 0xfe],
                port: 443,
                priority: 0,
                weight: 0,
            }],
        };
        assert!(Publish::decode(&bad.encode()).is_err());
        // And an over-long one, which a length byte alone would let through.
        let long = Publish {
            ttl_secs: 60,
            capabilities: vec![],
            endpoints: vec![named(&"a".repeat(MAX_HOST + 1))],
        };
        assert!(Publish::decode(&long.encode()).is_err());
    }

    #[test]
    fn an_unknown_endpoint_kind_is_refused_rather_than_skipped() {
        // Not the SIP-19 ignore rule: an endpoint of an unknown kind has an
        // unknown *length*, so a reader cannot skip it and keep parsing. The
        // difference is why this refuses where a body type would not.
        let mut bytes = Publish {
            ttl_secs: 60,
            capabilities: vec![],
            endpoints: vec![v4(443)],
        }
        .encode();
        bytes[6] = 9;
        assert!(Publish::decode(&bytes).is_err());
    }

    /// SIP-26: capability travels with the address, expires with it, and has
    /// the same provenance. Anything that wants a different lifetime, signer or
    /// durability fails the test the SIP leaves behind and does not belong.
    #[test]
    fn capability_rides_with_the_endpoints_it_describes() {
        let p = Publish {
            ttl_secs: 300,
            capabilities: vec!["sqssh/1".into(), "h3".into()],
            endpoints: vec![v4(443)],
        };
        assert_eq!(Publish::decode(&p.encode()).unwrap(), p);

        // And it is optional: an identity may say where it is without saying
        // what it speaks, which is what every publisher did before SIP-26.
        let bare = Publish {
            ttl_secs: 300,
            capabilities: vec![],
            endpoints: vec![v4(443)],
        };
        assert_eq!(Publish::decode(&bare.encode()).unwrap(), bare);
    }

    #[test]
    fn capability_is_bounded_in_count_and_in_length() {
        let many = Publish {
            ttl_secs: 60,
            capabilities: (0..=MAX_CAPABILITIES).map(|i| format!("s/{i}")).collect(),
            endpoints: vec![],
        };
        assert!(Publish::decode(&many.encode()).is_err());
        let long = Publish {
            ttl_secs: 60,
            capabilities: vec!["x".repeat(MAX_CAPABILITY + 1)],
            endpoints: vec![],
        };
        assert!(Publish::decode(&long.encode()).is_err());
    }

    #[test]
    fn a_capability_that_is_not_text_is_refused() {
        let mut bytes = Publish {
            ttl_secs: 60,
            capabilities: vec!["ok".into()],
            endpoints: vec![],
        }
        .encode();
        let at = bytes.len() - 2;
        bytes[at] = 0xff;
        bytes[at + 1] = 0xfe;
        assert!(Publish::decode(&bytes).is_err());
    }

    #[test]
    fn a_resolution_carries_its_provenance() {
        let r = Resolved {
            found: true,
            endpoints: vec![v4(443), named("ex.squic.org")],
            published_at: 1_700_000_000,
            expires_at: 1_700_000_300,
            last_seen: 1_700_000_290,
            now: 1_700_000_295,
            capabilities: vec!["sqssh/1".into(), "sqex-chat/2".into()],
        };
        assert_eq!(Resolved::decode(&r.encode()).unwrap(), r);
        let none = Resolved::none(1_700_000_000);
        assert_eq!(Resolved::decode(&none.encode()).unwrap(), none);
        assert!(!none.found);
        // Absence is a shape, not an error: a consumer reads `found` rather
        // than distinguishing an empty body from a refusal.
        assert_eq!(none.last_seen, 0);
    }

    #[test]
    fn a_successor_round_trips_and_bounds_its_reason() {
        let s = Successor {
            successor: PubKey::new([4; 32]),
            reason: "moving to new hardware".into(),
        };
        assert_eq!(Successor::decode(&s.encode()).unwrap(), s);
        let long = Successor {
            successor: PubKey::new([4; 32]),
            reason: "x".repeat(MAX_REASON + 1),
        };
        assert!(Successor::decode(&long.encode()).is_err());
        assert!(Successor::decode(&s.encode()[..20]).is_err());
    }

    /// The three type bytes are distinct, and each decoder refuses the others.
    /// A publish read as a resolve would be an identity publishing somebody
    /// else's address by accident.
    #[test]
    fn each_type_refuses_the_others() {
        let p = Publish { ttl_secs: 60, endpoints: vec![v4(443)], capabilities: vec![] }.encode();
        let r = Resolve { key: PubKey::new([1; 32]) }.encode();
        let s = Successor { successor: PubKey::new([2; 32]), reason: String::new() }.encode();
        assert!(Resolve::decode(&p).is_err());
        assert!(Publish::decode(&r).is_err());
        assert!(Successor::decode(&r).is_err());
        assert!(Resolve::decode(&s).is_err());
    }
}
