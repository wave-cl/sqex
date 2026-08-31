//! SIP-33: finding an exchange by name.
//!
//! A domain publishes a DNSSEC-signed `TXT` record at `_sqex.<domain>` naming
//! its exchange's key; ordinary `A`/`AAAA` records give the address. A client
//! holding nothing but the domain can then reach it.
//!
//! The key obtained this way is a **bootstrap, not an authority**. It is taken
//! on first contact, pinned, and a later change is refused rather than followed.
//! DNSSEC decides who answers the first question; the pin decides every question
//! after it — which bounds a registrar or DNS compromise to clients that have
//! never connected, instead of every connection forever.

pub mod dns;
pub mod error;
pub mod known;
pub mod record;
pub mod target;

pub use error::{Error, Result};
pub use known::{Decision, Known};
pub use target::{Layer, Target};
pub use record::{DEFAULT_PORT, Invalid, LABEL, Parsed, Record, VERSION};

/// Where one rung of the ladder came from, so a caller can say what it did and
/// decide how long to wait on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// An address this client reached before. Costs no DNS at all, and is worth
    /// only a short wait: if the server has moved, every second spent here is
    /// spent before anything can work.
    Remembered,
    /// The `h=` host from the last record, resolved now. Catches a server that
    /// changed address but not name — the common case — without a full lookup.
    Host,
    /// A fresh DNSSEC lookup. The last rung, and the only one that can find a
    /// server whose record now names a different host.
    Discovered,
}

/// One address worth trying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub addr: std::net::SocketAddr,
    pub source: Source,
    /// The host this address came from, for the store.
    pub host: Option<String>,
}

/// What a domain turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The key to pin, per SIP-9.
    pub key: sqnr_core::PubKey,
    /// `host:port` to dial. The host is the record's `h`, or the domain itself.
    pub address: String,
    /// True when this was a first contact and the key has just been pinned —
    /// the caller should say so, because a trust decision was made for the user.
    pub newly_pinned: bool,
}

/// Find `domain`'s exchange, reconciling against the pin store.
///
/// The whole of SIP-33's client side: a validated lookup, then the pin.
pub async fn discover(domain: &str) -> Result<Found> {
    let path = known::path();
    let mut store = Known::load(&path).map_err(Error::Store)?;
    let records = dns::lookup(domain).await?;

    let offered: Vec<_> = records.iter().map(|r| r.key).collect();
    let decision = known::decide(&offered, store.lookup(domain))
        .expect("lookup returns no empty set");

    let (key, newly_pinned) = match decision {
        Decision::Pinned(k) => (k, false),
        Decision::FirstContact(k) => {
            store.add(
                domain,
                k,
                &format!("discovered {}", today()),
            );
            store.save(&path).map_err(Error::Store)?;
            (k, true)
        }
        Decision::Changed { pinned, offered } => {
            return Err(Error::Changed {
                domain: domain.to_string(),
                pinned,
                offered,
            });
        }
    };

    // The record naming the key we settled on decides the address: with several
    // published, they may point at different hosts.
    let chosen = records
        .iter()
        .find(|r| r.key == key)
        .expect("the key came from these records");
    let host = chosen.host.as_deref().unwrap_or(domain);
    Ok(Found {
        key,
        address: format!("{host}:{}", chosen.port),
        newly_pinned,
    })
}

/// Addresses to try for a domain, cheapest and most likely first.
///
/// Three rungs, in the order a client should climb them:
///
/// 1. **Remembered** — where it answered last. No DNS, works when DNS does not.
/// 2. **Host** — the `h=` from the record we already have, resolved now.
///    Finds a server that changed address but kept its name.
/// 3. **Discovered** — a fresh DNSSEC lookup, which is the only rung that finds
///    a server whose record now names somewhere else.
///
/// Only the last rung is reached when the earlier ones fail, so a client with a
/// good cache does no DNS work at all. The key never comes from the cache: rungs
/// 1 and 2 are usable only because a pin already exists, and rung 3 reconciles
/// against it exactly as [`discover`] does.
///
/// Trying a remembered address first is safe because an address is not identity.
/// A stale or hostile one costs a failed handshake — SIP-9 refuses any server
/// that cannot prove the pinned key — so the worst case is the delay, which is
/// why a caller should give the early rungs a short deadline and not the full
/// connect budget.
pub async fn candidates(domain: &str) -> Result<(sqnr_core::PubKey, Vec<Candidate>, bool)> {
    let path = known::path();
    let store = Known::load(&path).map_err(Error::Store)?;
    let held = store.get(domain).cloned();

    let mut out = Vec::new();
    if let Some(e) = &held {
        for addr in &e.addrs {
            out.push(Candidate {
                addr: *addr,
                source: Source::Remembered,
                host: e.host.clone(),
            });
        }
        if let Some(host) = &e.host {
            let port = e.addrs.first().map(|a| a.port()).unwrap_or(DEFAULT_PORT);
            for addr in resolve_host(host, port).await {
                if !out.iter().any(|c| c.addr == addr) {
                    out.push(Candidate {
                        addr,
                        source: Source::Host,
                        host: Some(host.clone()),
                    });
                }
            }
        }
    }

    // Rung three. Always consulted, because the key has to be reconciled and a
    // record may name somewhere new — but its addresses go last, behind
    // everything already known to have worked.
    let found = discover(domain).await?;
    let host = found.address.rsplit_once(':').map(|(h, _)| h.to_string());
    let port = found
        .address
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    if let Some(h) = &host {
        for addr in resolve_host(h, port).await {
            if !out.iter().any(|c| c.addr == addr) {
                out.push(Candidate {
                    addr,
                    source: Source::Discovered,
                    host: host.clone(),
                });
            }
        }
    }

    if out.is_empty() {
        return Err(Error::Resolve(format!(
            "{domain} publishes an exchange at {}, which resolves to no addresses",
            found.address
        )));
    }
    Ok((found.key, out, found.newly_pinned))
}

/// Note where a domain actually answered, so the next start begins there.
pub fn remember(domain: &str, host: Option<&str>, addr: std::net::SocketAddr) -> Result<()> {
    let path = known::path();
    let mut store = Known::load(&path).map_err(Error::Store)?;
    store.remember(domain, host, addr);
    store.save(&path).map_err(Error::Store)
}

async fn resolve_host(host: &str, port: u16) -> Vec<std::net::SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![std::net::SocketAddr::new(ip, port)];
    }
    match tokio::net::lookup_host((host, port)).await {
        Ok(it) => it.collect(),
        Err(e) => {
            tracing::debug!(host, %e, "cannot resolve");
            Vec::new()
        }
    }
}

/// `YYYY-MM-DD`, for the comment written beside a new pin.
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    // Civil-from-days, Howard Hinnant's algorithm.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_date_is_a_date() {
        let d = super::today();
        assert_eq!(d.len(), 10, "{d}");
        assert!(d.starts_with("20"), "{d}");
        let parts: Vec<_> = d.split('-').collect();
        assert_eq!(parts.len(), 3);
        let m: u32 = parts[1].parse().unwrap();
        let day: u32 = parts[2].parse().unwrap();
        assert!((1..=12).contains(&m), "month {m}");
        assert!((1..=31).contains(&day), "day {day}");
    }
}
