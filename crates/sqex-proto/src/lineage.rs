//! SIP-40 §Lineage: an exchange's earlier keys.
//!
//! An exchange keeps every SIP-40 handover it signed and serves the chain
//! -- its lineage -- to anyone who asks. A verifier holding the current
//! key checks the chain back from it and verifies receipts and signatures
//! under every key in it. The link is the SIP-40 record in fixed fields;
//! the signing input is SIP-40's, byte for byte.

use ed25519_dalek::{Signature, Verifier};
use sqnr_core::{Error, PubKey, Result};

/// Links a lineage may carry.
pub const MAX_LINEAGE: usize = 16;

/// SIP-40's domain-separation prefix for a handover's signing input.
const HANDOVER_PREFIX: &[u8; 16] = b"sqex-handover-v1";

/// One handover: `from` said its successor is `to`, for `domain`.
///
/// `| dom_len: u8 | domain | from[32] | to[32] | until: u64 | sig[64] |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Lowercased, no trailing dot -- the domain the signature is bound to.
    pub domain: String,
    pub from: PubKey,
    pub to: PubKey,
    pub until: u64,
    pub sig: [u8; 64],
}

impl Link {
    /// SIP-40 §The handover record: prefix, the domain with its length,
    /// both keys, the expiry.
    pub fn signing_input(domain: &str, from: &PubKey, to: &PubKey, until: u64) -> Vec<u8> {
        let domain = canonical(domain);
        let mut out = Vec::with_capacity(16 + 1 + domain.len() + 64 + 8);
        out.extend_from_slice(HANDOVER_PREFIX);
        out.push(domain.len() as u8);
        out.extend_from_slice(domain.as_bytes());
        out.extend_from_slice(from.as_bytes());
        out.extend_from_slice(to.as_bytes());
        out.extend_from_slice(&until.to_be_bytes());
        out
    }

    /// Whether `from` really signed this, for the link's own domain.
    pub fn verify(&self) -> bool {
        let Ok(vk) = self.from.verifying_key() else {
            return false;
        };
        let input = Self::signing_input(&self.domain, &self.from, &self.to, self.until);
        vk.verify(&input, &Signature::from_bytes(&self.sig)).is_ok()
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let d = canonical(&self.domain);
        let d = d.as_bytes();
        let n = d.len().min(255);
        out.push(n as u8);
        out.extend_from_slice(&d[..n]);
        out.extend_from_slice(self.from.as_bytes());
        out.extend_from_slice(self.to.as_bytes());
        out.extend_from_slice(&self.until.to_be_bytes());
        out.extend_from_slice(&self.sig);
    }

    /// Decode one link at the front of `b`; returns it and the rest.
    fn decode_front(b: &[u8]) -> Result<(Link, &[u8])> {
        let short = || Error::Malformed("lineage link cut short".into());
        let n = *b.first().ok_or_else(short)? as usize;
        let domain = b.get(1..1 + n).ok_or_else(short)?;
        let at = 1 + n;
        let from = PubKey::new(b.get(at..at + 32).ok_or_else(short)?.try_into().unwrap());
        let to = PubKey::new(
            b.get(at + 32..at + 64)
                .ok_or_else(short)?
                .try_into()
                .unwrap(),
        );
        let until = u64::from_be_bytes(
            b.get(at + 64..at + 72)
                .ok_or_else(short)?
                .try_into()
                .unwrap(),
        );
        let sig: [u8; 64] = b
            .get(at + 72..at + 136)
            .ok_or_else(short)?
            .try_into()
            .unwrap();
        Ok((
            Link {
                domain: String::from_utf8(domain.to_vec())
                    .map_err(|_| Error::Malformed("lineage domain is not UTF-8".into()))?,
                from,
                to,
                until,
                sig,
            },
            &b[at + 136..],
        ))
    }
}

/// `GET /exchange/lineage`: `| count: u8 | count × Link |`, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lineage {
    pub links: Vec<Link>,
}

/// Why a lineage was not accepted. Never a fault in the verifier's own
/// state: SIP-40's rule for a bad handover, kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    /// A link's signature does not verify under its `from`.
    BadSignature(usize),
    /// A link's `to` is not the next link's `from`, or a `from` repeats.
    Broken(usize),
    /// The last link's `to` is not the key the verifier holds.
    NotThisKey,
    /// A link is for a domain other than the one the key is held for.
    OtherDomain(usize),
    TooLong,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejected::BadSignature(i) => write!(f, "link {i} is not signed by its from key"),
            Rejected::Broken(i) => write!(f, "link {i} does not follow the one before it"),
            Rejected::NotThisKey => write!(f, "the chain does not end at this exchange's key"),
            Rejected::OtherDomain(i) => write!(f, "link {i} is for another domain"),
            Rejected::TooLong => write!(f, "more than {MAX_LINEAGE} links"),
        }
    }
}

impl Lineage {
    pub fn encode(&self) -> Vec<u8> {
        let n = self.links.len().min(MAX_LINEAGE);
        let mut out = Vec::with_capacity(1 + n * 200);
        out.push(n as u8);
        for l in &self.links[..n] {
            l.encode_into(&mut out);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Lineage> {
        let n = *b
            .first()
            .ok_or_else(|| Error::Malformed("lineage cut short".into()))? as usize;
        if n > MAX_LINEAGE {
            return Err(Error::Malformed(format!(
                "a lineage has at most {MAX_LINEAGE} links, not {n}"
            )));
        }
        let mut rest = &b[1..];
        let mut links = Vec::with_capacity(n);
        for _ in 0..n {
            let (l, r) = Link::decode_front(rest)?;
            links.push(l);
            rest = r;
        }
        if !rest.is_empty() {
            return Err(Error::Malformed("trailing bytes after a lineage".into()));
        }
        Ok(Lineage { links })
    }

    /// SIP-40 §Verifying a lineage, the four rules; `until` is not one of
    /// them. Returns the predecessors, **newest first**. An empty lineage
    /// is accepted and yields none.
    pub fn predecessors_for(
        &self,
        current: &PubKey,
        domain: Option<&str>,
    ) -> std::result::Result<Vec<PubKey>, Rejected> {
        if self.links.len() > MAX_LINEAGE {
            return Err(Rejected::TooLong);
        }
        let domain = domain.map(canonical);
        for (i, l) in self.links.iter().enumerate() {
            if let Some(d) = &domain
                && canonical(&l.domain) != *d
            {
                return Err(Rejected::OtherDomain(i));
            }
            if !l.verify() {
                return Err(Rejected::BadSignature(i));
            }
            if i > 0 && self.links[i - 1].to != l.from {
                return Err(Rejected::Broken(i));
            }
            if self.links[..i].iter().any(|e| e.from == l.from) {
                return Err(Rejected::Broken(i));
            }
        }
        if let Some(last) = self.links.last()
            && last.to != *current
        {
            return Err(Rejected::NotThisKey);
        }
        Ok(self.links.iter().rev().map(|l| l.from).collect())
    }
}

/// The domain as it is signed: lowercased, no trailing dot.
pub fn canonical(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(b: u8) -> (SigningKey, PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        let pk = PubKey::new(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn link(from: &SigningKey, to: &PubKey, domain: &str) -> Link {
        let f = PubKey::new(from.verifying_key().to_bytes());
        let until = 1_800_000_000;
        let sig = from
            .sign(&Link::signing_input(domain, &f, to, until))
            .to_bytes();
        Link {
            domain: domain.into(),
            from: f,
            to: *to,
            until,
            sig,
        }
    }

    #[test]
    fn a_lineage_round_trips_and_verifies_back_from_the_current_key() {
        let (a, pa) = key(1);
        let (b, pb) = key(2);
        let (_, pc) = key(3);
        let l = Lineage {
            links: vec![link(&a, &pb, "x.test"), link(&b, &pc, "X.test.")],
        };
        let again = Lineage::decode(&l.encode()).unwrap();
        assert_eq!(
            again.links[1].domain, "x.test",
            "the domain is canonical on the wire"
        );
        assert_eq!(
            again.predecessors_for(&pc, Some("x.test")).unwrap(),
            vec![pb, pa],
            "newest first"
        );
        assert_eq!(again.predecessors_for(&pc, None).unwrap(), vec![pb, pa]);
        assert_eq!(
            Lineage::default().predecessors_for(&pc, None).unwrap(),
            Vec::<PubKey>::new()
        );
    }

    #[test]
    fn each_rule_rejects_the_whole_chain() {
        let (a, pa) = key(1);
        let (b, pb) = key(2);
        let (_, pc) = key(3);
        let (_, pd) = key(4);
        let good = || vec![link(&a, &pb, "x.test"), link(&b, &pc, "x.test")];

        let mut forged = good();
        forged[0].sig[5] ^= 1;
        assert_eq!(
            Lineage { links: forged }.predecessors_for(&pc, None),
            Err(Rejected::BadSignature(0))
        );

        let broken = vec![link(&a, &pb, "x.test"), link(&a, &pc, "x.test")];
        assert_eq!(
            Lineage { links: broken }.predecessors_for(&pc, None),
            Err(Rejected::Broken(1))
        );

        assert_eq!(
            Lineage { links: good() }.predecessors_for(&pd, None),
            Err(Rejected::NotThisKey)
        );

        assert_eq!(
            Lineage { links: good() }.predecessors_for(&pc, Some("y.test")),
            Err(Rejected::OtherDomain(0))
        );
        // A stolen retired key signs a link to a thief's key: inert unless
        // the verifier already holds the thief's key.
        let thief = vec![link(&a, &pd, "x.test")];
        assert_eq!(
            Lineage { links: thief }.predecessors_for(&pc, None),
            Err(Rejected::NotThisKey)
        );
        let _ = pa;
    }

    #[test]
    fn a_lineage_over_the_limit_is_refused_on_the_wire() {
        let mut b = vec![(MAX_LINEAGE + 1) as u8];
        b.extend_from_slice(&[0u8; 300]);
        assert!(Lineage::decode(&b).is_err());
        assert!(Lineage::decode(&[1, 0]).is_err(), "a cut-short link");
    }
}
