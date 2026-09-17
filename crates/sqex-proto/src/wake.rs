//! SIP-45: a wake for a device that cannot hold a stream.
//!
//! A device leaves an endpoint -- an HTTPS address served by a push
//! distributor of its own choosing -- and the exchange posts a content-free
//! wake to it when an event would have gone on a stream the device is not
//! holding. The body is a constant: the distributor is a third party the
//! exchange did not choose, and the wake is all it may learn.

use sqnr_core::{Error, PubKey, Result};

pub const TYPE_REGISTER: u8 = 0x01;
pub const TYPE_FORGET: u8 = 0x02;

/// Bytes an endpoint may occupy.
pub const MAX_ENDPOINT: usize = 512;
/// The longest a registration lasts; a device re-registers when it connects.
pub const MAX_TTL: u32 = 30 * 24 * 60 * 60;
/// Wakes to one device are at least this far apart while it stays away.
pub const WAKE_MIN_SECS: u64 = 30;
/// What is posted. Nothing else, ever.
pub const WAKE_BODY: &[u8] = b"wake";
/// How long a wake may take before it is given up on.
pub const WAKE_TIMEOUT_SECS: u64 = 5;

/// `POST /wake/register`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub ttl: u32,
    pub endpoint: String,
}

impl Register {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + self.endpoint.len());
        out.push(TYPE_REGISTER);
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.extend_from_slice(&(self.endpoint.len() as u16).to_be_bytes());
        out.extend_from_slice(self.endpoint.as_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Register> {
        if b.len() < 7 || b[0] != TYPE_REGISTER {
            return Err(Error::Malformed("not a wake registration".into()));
        }
        let ttl = u32::from_be_bytes(b[1..5].try_into().unwrap());
        let len = u16::from_be_bytes([b[5], b[6]]) as usize;
        if b.len() != 7 + len {
            return Err(Error::Malformed("wake registration cut short".into()));
        }
        if len > MAX_ENDPOINT {
            return Err(Error::Malformed(format!(
                "endpoint is {len} bytes, limit is {MAX_ENDPOINT}"
            )));
        }
        let endpoint = std::str::from_utf8(&b[7..])
            .map_err(|_| Error::Malformed("endpoint is not UTF-8".into()))?
            .to_string();
        if ttl == 0 || ttl > MAX_TTL {
            return Err(Error::Malformed(format!(
                "ttl is {ttl}, want 1..={MAX_TTL}"
            )));
        }
        Ok(Register { ttl, endpoint })
    }
}

/// Whether an endpoint is one an exchange may post to: absolute `https://`,
/// or `http://` to loopback where the exchange allows that for tests. No
/// credentials in it, no fragment; the rest is the distributor's business.
pub fn acceptable(endpoint: &str, allow_loopback_http: bool) -> bool {
    if endpoint.len() > MAX_ENDPOINT || endpoint.contains('@') || endpoint.contains('#') {
        return false;
    }
    if let Some(rest) = endpoint.strip_prefix("https://") {
        return !rest.is_empty() && !rest.starts_with('/');
    }
    if allow_loopback_http && let Some(rest) = endpoint.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        return host == "127.0.0.1" || host == "localhost" || host == "[::1]";
    }
    false
}

/// `POST /wake/forget`: the type byte alone.
pub fn forget() -> Vec<u8> {
    vec![TYPE_FORGET]
}

pub fn is_forget(b: &[u8]) -> bool {
    b == [TYPE_FORGET]
}

/// Who a wake is for, once the exchange has decided one is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    pub device: PubKey,
    pub endpoint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registration_round_trips_and_is_bounded() {
        let r = Register {
            ttl: 3600,
            endpoint: "https://push.example/up/abc".into(),
        };
        assert_eq!(Register::decode(&r.encode()).unwrap(), r);
        let long = Register {
            ttl: 1,
            endpoint: "https://".to_string() + &"x".repeat(MAX_ENDPOINT),
        };
        assert!(Register::decode(&long.encode()).is_err());
        let forever = Register {
            ttl: MAX_TTL + 1,
            endpoint: "https://a/b".into(),
        };
        assert!(Register::decode(&forever.encode()).is_err());
        assert!(is_forget(&forget()));
        assert!(!is_forget(&r.encode()));
    }

    /// Only https, or http to loopback when allowed; never credentials, a
    /// fragment, or a bare scheme.
    #[test]
    fn an_endpoint_is_an_https_address_and_nothing_stranger() {
        assert!(acceptable("https://ntfy.sh/abc", false));
        assert!(!acceptable("http://ntfy.sh/abc", false));
        assert!(!acceptable("http://127.0.0.1:8080/x", false));
        assert!(acceptable("http://127.0.0.1:8080/x", true));
        assert!(acceptable("http://localhost/x", true));
        assert!(!acceptable("http://10.0.0.1/x", true));
        assert!(!acceptable("https://user:pw@host/x", true));
        assert!(!acceptable("https://host/x#frag", true));
        assert!(!acceptable("https://", true));
        assert!(!acceptable("ftp://host/x", true));
    }
}
