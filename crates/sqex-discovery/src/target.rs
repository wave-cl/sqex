//! Deciding what a caller actually asked for.
//!
//! There are two different requests and they used to share a flag:
//!
//! - **Discover** a domain — look it up over DNSSEC, pin what it publishes,
//!   connect. The key comes from DNS and nowhere else.
//! - **Dial** a literal address with a key already in hand.
//!
//! While one `--server` meant both, which one you got depended on whether a
//! *different* flag was set, and that flag could come from a different layer. A
//! `--server` on the command line would pair with a `server_key` from the config
//! — a key belonging to another exchange entirely — and the result was a
//! handshake failure against a server that was perfectly healthy. Nothing in the
//! message could point at the cause, because nothing in the code knew the two
//! halves had come from different places.
//!
//! So the two are separate flags now, and an address never pairs with a key from
//! another layer: whichever layer supplies the address supplies the key.

use sqnr_core::PubKey;

use crate::error::{Error, Result};

/// What to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A domain publishing an exchange. The key comes from its record.
    Discover(String),
    /// A literal address and the key to expect there.
    Direct { address: String, key: PubKey },
}

/// One layer's opinion: an address to discover, an address to dial, and a key.
#[derive(Debug, Default, Clone)]
pub struct Layer {
    /// A domain to discover.
    pub server: Option<String>,
    /// A literal `host:port` to dial.
    pub host: Option<String>,
    /// The key that goes with `host`.
    pub key: Option<String>,
}

impl Layer {
    fn is_empty(&self) -> bool {
        self.server.is_none() && self.host.is_none() && self.key.is_none()
    }
}

/// Resolve the first layer that says anything, and take everything from it.
///
/// Layers are given most-specific first — command line, environment, config.
/// A layer that mentions a server at all decides; later layers are not consulted
/// for the missing halves, which is the whole point.
pub fn resolve(layers: &[Layer]) -> Result<Target> {
    for layer in layers {
        if layer.is_empty() {
            continue;
        }
        return decide(layer);
    }
    Err(Error::Usage(
        "no server: pass --server <domain> to discover one, or --server-host \
         <host:port> with --server-key. SQEX_SERVER / SQEX_SERVER_HOST and \
         ~/.sqnr/config work the same way"
            .into(),
    ))
}

fn decide(layer: &Layer) -> Result<Target> {
    match (&layer.server, &layer.host, &layer.key) {
        // A literal address with its key. The ordinary explicit case.
        (None, Some(host), Some(key)) => Ok(Target::Direct {
            address: host.clone(),
            key: parse_key(key)?,
        }),
        // An address with no key. Nothing can supply it: discovery works on a
        // domain, and this is a place to dial.
        (None, Some(host), None) => Err(Error::Usage(format!(
            "--server-host {host} needs --server-key. If {host} is a domain that \
             publishes its own key, use --server {host} instead and it will be \
             discovered"
        ))),
        // A domain to discover.
        (Some(domain), None, None) => Ok(Target::Discover(domain.clone())),
        // A domain *and* a key. The key would be ignored, which is worse than
        // refusing: somebody who passed it believes it is being checked.
        (Some(domain), None, Some(_)) => Err(Error::Usage(format!(
            "--server {domain} discovers its key over DNSSEC, so --server-key \
             would be ignored. Drop it, or use --server-host to dial an address \
             with a key you name"
        ))),
        (Some(_), Some(_), _) => Err(Error::Usage(
            "--server and --server-host are two ways of saying where to go; give one".into(),
        )),
        (None, None, Some(_)) => Err(Error::Usage(
            "--server-key names a key but no server. Add --server-host <host:port>".into(),
        )),
        (None, None, None) => unreachable!("an empty layer is skipped"),
    }
}

fn parse_key(key: &str) -> Result<PubKey> {
    key.trim()
        .parse()
        .map_err(|e| Error::Usage(format!("bad server key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "2j68p8rZKXE6W1f6LerRGB2SPTH8JkbfMmZRFTzcLKyW";

    fn domain(d: &str) -> Layer {
        Layer {
            server: Some(d.into()),
            ..Default::default()
        }
    }
    fn direct(h: &str, k: &str) -> Layer {
        Layer {
            host: Some(h.into()),
            key: Some(k.into()),
            ..Default::default()
        }
    }

    #[test]
    fn a_domain_is_discovered() {
        assert_eq!(
            resolve(&[domain("squic.org")]).unwrap(),
            Target::Discover("squic.org".into())
        );
    }

    #[test]
    fn an_address_with_a_key_is_dialled() {
        match resolve(&[direct("127.0.0.1:5400", K)]).unwrap() {
            Target::Direct { address, key } => {
                assert_eq!(address, "127.0.0.1:5400");
                assert_eq!(key.to_string(), K);
            }
            other => panic!("{other:?}"),
        }
    }

    /// The bug this module exists for. A `--server` on the command line must not
    /// pick up a `server_key` from the config: that key is another exchange's,
    /// and pairing them fails a handshake against a healthy server with nothing
    /// in the message to say why.
    #[test]
    fn a_command_line_domain_does_not_inherit_a_config_key() {
        let layers = [domain("squic.org"), direct("127.0.0.1:5400", K)];
        assert_eq!(
            resolve(&layers).unwrap(),
            Target::Discover("squic.org".into()),
            "the config layer must not be consulted once the command line has spoken"
        );
    }

    /// And the reverse: an explicit address does not fall through to a domain
    /// configured elsewhere.
    #[test]
    fn an_explicit_address_does_not_fall_through_to_a_configured_domain() {
        let layers = [direct("127.0.0.1:5400", K), domain("squic.org")];
        assert!(matches!(
            resolve(&layers).unwrap(),
            Target::Direct { .. }
        ));
    }

    #[test]
    fn a_later_layer_is_used_when_the_earlier_ones_are_silent() {
        let layers = [Layer::default(), Layer::default(), domain("squic.org")];
        assert_eq!(
            resolve(&layers).unwrap(),
            Target::Discover("squic.org".into())
        );
    }

    /// Refused rather than ignored: somebody who passes a key believes it is
    /// being checked, and silently discarding it is the failure they would never
    /// find.
    #[test]
    fn a_domain_with_a_key_is_refused_not_quietly_ignored() {
        let layer = Layer {
            server: Some("squic.org".into()),
            key: Some(K.into()),
            ..Default::default()
        };
        let e = resolve(&[layer]).unwrap_err().to_string();
        assert!(e.contains("would be ignored"), "{e}");
    }

    #[test]
    fn an_address_without_a_key_says_what_to_do() {
        let layer = Layer {
            host: Some("squic.org".into()),
            ..Default::default()
        };
        let e = resolve(&[layer]).unwrap_err().to_string();
        assert!(e.contains("--server-key"), "{e}");
        assert!(e.contains("--server squic.org"), "should point at discovery: {e}");
    }

    #[test]
    fn saying_nothing_at_all_explains_both_ways() {
        let e = resolve(&[Layer::default()]).unwrap_err().to_string();
        assert!(e.contains("--server "), "{e}");
        assert!(e.contains("--server-host"), "{e}");
    }

    #[test]
    fn a_bad_key_is_reported_as_one() {
        let e = resolve(&[direct("127.0.0.1:5400", "not-base58-!!")])
            .unwrap_err()
            .to_string();
        assert!(e.contains("bad server key"), "{e}");
    }
}
