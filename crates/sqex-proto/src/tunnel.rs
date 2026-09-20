//! SIP-85: a connection carried by the home.
//!
//! A member asks its home exchange to carry a transport connection to another
//! exchange: the home opens a UDP socket towards the target and copies packets
//! between that socket and a stream the member holds, reading none of them.
//! The member then runs its ordinary sQUIC dialler against a local socket the
//! [`Carrier`] pumps into the stream, so the far exchange authenticates the
//! member (SIP-3), the member pins the far exchange (SIP-9), cookies (SIP-7)
//! and the whitelist (SIP-8) work as they would directly -- and the far
//! exchange sees the home's address, never the member's.
//!
//! The wire is three frames on one bidirectional stream under the
//! `sqex-tunnel` ALPN: [`Open`] from the member, [`Opened`] from the home,
//! then [`packet`]s both ways. Carriage is a stream rather than QUIC
//! datagrams: an sQUIC Initial plus its trailer does not fit a DATAGRAM frame
//! on a path below ~1350 bytes, and what a tunnel carries in this revision is
//! control traffic (SIP-85 §Rationale).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use sqnr_core::{Error, Result};
use squic::Config as SquicConfig;
use tokio::net::UdpSocket;

/// ALPN of a tunnel connection, beside the exchange's `h3` and SIP-39's
/// `sqex-relay`; a home that does not carry connections does not offer it.
pub const ALPN: &[u8] = b"sqex-tunnel";

pub const TYPE_OPEN: u8 = 0x01;

/// `Opened.status`: packets may follow.
pub const STATUS_OPEN: u8 = 0;
/// The member may not have a tunnel from this home. Uniform for a
/// non-member, whatever the target (SIP-85 §Opening a tunnel).
pub const STATUS_REFUSED: u8 = 1;
/// The domain did not resolve to an exchange (SIP-33).
pub const STATUS_NO_ADDRESS: u8 = 2;
/// The domain resolved to an exchange whose key is not the one named.
pub const STATUS_WRONG_KEY: u8 = 3;
/// Reserved: a name discovery found that is not an exchange's.
pub const STATUS_NOT_AN_EXCHANGE: u8 = 4;
/// As many tunnels as SIP-85 §Limits allows, open or opened lately.
pub const STATUS_OVER_LIMIT: u8 = 5;

/// Longest `Packet.bytes` either side may send. sQUIC never sends a datagram
/// this large; one that is ends the tunnel.
pub const MAX_PACKET: usize = 1500;

/// SIP-85 §Limits: a tunnel idle in both directions this long is closed.
pub const IDLE_SECS: u64 = 60;

/// Longest a domain in `Open` may be: one length byte.
pub const MAX_DOMAIN: usize = 255;

/// The first bytes of a tunnel stream: the key the member will pin at the
/// target, and the name it found the target by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub key: [u8; 32],
    pub domain: String,
}

impl Open {
    pub fn encode(&self) -> Vec<u8> {
        let d = self.domain.as_bytes();
        let mut out = Vec::with_capacity(34 + d.len());
        out.push(TYPE_OPEN);
        out.extend_from_slice(&self.key);
        out.push(d.len() as u8);
        out.extend_from_slice(d);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Open> {
        if b.len() < 34 {
            return Err(Error::Malformed("tunnel open truncated".into()));
        }
        if b[0] != TYPE_OPEN {
            return Err(Error::Malformed(format!("tunnel open type {:#04x}", b[0])));
        }
        let key: [u8; 32] = b[1..33].try_into().expect("32 bytes");
        let n = b[33] as usize;
        let rest = &b[34..];
        if rest.len() != n {
            return Err(Error::Malformed(format!(
                "tunnel open domain: {n} declared, {} present",
                rest.len()
            )));
        }
        let domain = std::str::from_utf8(rest)
            .map_err(|_| Error::Malformed("tunnel open domain is not UTF-8".into()))?
            .to_string();
        if domain.is_empty() {
            return Err(Error::Malformed("tunnel open domain is empty".into()));
        }
        Ok(Open { key, domain })
    }

    /// Longest an encoded `Open` can be, for the reader's bound.
    pub const MAX: usize = 34 + MAX_DOMAIN;
}

/// The home's one answer to an `Open`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    pub status: u8,
    /// 4 or 6, the family the home's socket was bound in; 0 unless open.
    pub family: u8,
}

impl Opened {
    pub fn encode(&self) -> [u8; 2] {
        [self.status, self.family]
    }

    pub fn decode(b: &[u8]) -> Result<Opened> {
        match b {
            [status, family] => Ok(Opened {
                status: *status,
                family: *family,
            }),
            _ => Err(Error::Malformed(format!(
                "tunnel opened wants 2 bytes, got {}",
                b.len()
            ))),
        }
    }

    /// What a status means, for a client's error.
    pub fn describe(status: u8) -> &'static str {
        match status {
            STATUS_OPEN => "open",
            STATUS_REFUSED => "refused: this home does not carry connections for this identity",
            STATUS_NO_ADDRESS => "the home found no exchange at that domain",
            STATUS_WRONG_KEY => "the home found an exchange at that domain under a different key",
            STATUS_NOT_AN_EXCHANGE => "the home found that name, and it is not an exchange's",
            STATUS_OVER_LIMIT => "over the home's tunnel limit; try later",
            _ => "unknown status",
        }
    }
}

/// One datagram on the stream: `len: u16 | bytes`.
pub fn packet(bytes: &[u8]) -> Vec<u8> {
    debug_assert!(bytes.len() <= MAX_PACKET);
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Read one packet off a stream: `None` at a clean end, an error for a
/// packet over [`MAX_PACKET`] or a cut-short one.
pub async fn read_packet(recv: &mut quinn::RecvStream) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match recv.read_exact(&mut len).await {
        Ok(()) => {}
        // A clean finish, or a stream and connection that are simply gone:
        // the tunnel ended, and nobody framed anything wrongly.
        Err(quinn::ReadExactError::FinishedEarly(0)) | Err(quinn::ReadExactError::ReadError(_)) => {
            return Ok(None);
        }
        Err(e) => return Err(Error::Malformed(format!("tunnel packet: {e}"))),
    }
    let n = u16::from_be_bytes(len) as usize;
    if n > MAX_PACKET {
        return Err(Error::Malformed(format!(
            "tunnel packet of {n} bytes, over {MAX_PACKET}"
        )));
    }
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body)
        .await
        .map_err(|e| Error::Malformed(format!("tunnel packet body: {e}")))?;
    Ok(Some(body))
}

/// Read the `Open` a member sends first: type, key, and a domain of the
/// declared length -- no more, so trailing bytes are refused as SIP-34 would.
pub async fn read_open(recv: &mut quinn::RecvStream) -> Result<Open> {
    let mut head = [0u8; 34];
    recv.read_exact(&mut head)
        .await
        .map_err(|e| Error::Malformed(format!("tunnel open: {e}")))?;
    let n = head[33] as usize;
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body)
        .await
        .map_err(|e| Error::Malformed(format!("tunnel open domain: {e}")))?;
    let mut all = head.to_vec();
    all.extend_from_slice(&body);
    Open::decode(&all)
}

/// The two directions' byte counts, and whether the pump is still running.
#[derive(Debug, Default)]
pub struct Meter {
    /// Bytes the member sent towards the target.
    pub up: AtomicU64,
    /// Bytes the target sent towards the member.
    pub down: AtomicU64,
    /// Packets from a second local sender, dropped: somebody dialled this
    /// carrier's socket twice.
    pub stray: AtomicU64,
    pub closed: AtomicBool,
}

/// The member's end of a tunnel: a connection to the home under [`ALPN`], one
/// stream, and a local UDP socket the member's own dialler talks to.
///
/// Dial the target with `local_addr()` as the address and the target's key
/// as the pin; the packets go up the stream, out of the home's socket, and
/// back. Dropping the carrier closes the connection and with it the tunnel.
///
/// **One connection per carrier.** The home copies bytes and cannot tell two
/// inner connections apart, and neither can this end: replies come down one
/// stream with nothing to route them by but the port that last sent. So the
/// pump binds itself to the **first** dialler it hears from and drops packets
/// from any other; a client that redials opens a fresh carrier (and closes
/// this one) rather than dialling this socket again. Sigil once did the
/// latter -- a second endpoint through the same pump while the first still
/// retransmitted -- and every connection through the tunnel saw seconds of
/// delay and died within a minute, for as long as the app ran.
pub struct Carrier {
    _conn: quinn::Connection,
    local: SocketAddr,
    family: u8,
    meter: Arc<Meter>,
    pumps: Vec<tokio::task::JoinHandle<()>>,
}

impl Carrier {
    /// Ask `home` to carry a connection to the exchange at `domain`, whose
    /// key the member already holds as `target`.
    ///
    /// A home that does not offer the ALPN fails the handshake, which is
    /// reported as "does not carry connections"; any other status is the
    /// home's answer, described.
    pub async fn open(
        home: SocketAddr,
        home_key: &[u8; 32],
        seed: &[u8; 32],
        target: &[u8; 32],
        domain: &str,
    ) -> std::result::Result<Carrier, String> {
        if domain.len() > MAX_DOMAIN || domain.is_empty() {
            return Err(format!("tunnel: domain {domain:?} cannot be named"));
        }
        let conn = squic::dial(
            home,
            home_key,
            SquicConfig {
                alpn_protocols: vec![ALPN.to_vec()],
                keep_alive: Some(Duration::from_secs(15)),
                handshake_timeout: Some(Duration::from_secs(5)),
                client_key: Some(hex::encode(seed)),
                advertise_identity: true,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| {
            let text = e.to_string();
            if text.contains("protocol") || text.contains("alpn") || text.contains("ALPN") {
                format!("{home} does not carry connections (SIP-85): {text}")
            } else {
                format!("tunnel dial {home}: {text}")
            }
        })?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("tunnel stream: {e}"))?;
        send.write_all(
            &Open {
                key: *target,
                domain: domain.to_string(),
            }
            .encode(),
        )
        .await
        .map_err(|e| format!("tunnel open: {e}"))?;
        let mut answer = [0u8; 2];
        recv.read_exact(&mut answer)
            .await
            .map_err(|e| format!("tunnel: the home closed without answering: {e}"))?;
        let opened = Opened::decode(&answer).map_err(|e| e.to_string())?;
        if opened.status != STATUS_OPEN {
            return Err(format!(
                "tunnel to {domain} via {home}: {}",
                Opened::describe(opened.status)
            ));
        }
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("tunnel local socket: {e}"))?;
        let local = socket.local_addr().map_err(|e| e.to_string())?;
        let socket = Arc::new(socket);
        let meter = Arc::new(Meter::default());

        // The dialler's own port is learned from its first packet and every
        // packet from the target goes back to it. **Pinned**: a packet from
        // any other port is a second connection trying to share the tunnel,
        // which cannot work (see the type's doc), and is dropped and counted
        // rather than allowed to hijack the replies.
        let dialler: Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
            Arc::new(tokio::sync::Mutex::new(None));

        let up = {
            let socket = Arc::clone(&socket);
            let dialler = Arc::clone(&dialler);
            let meter = Arc::clone(&meter);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                        break;
                    };
                    if n > MAX_PACKET {
                        continue;
                    }
                    {
                        let mut pinned = dialler.lock().await;
                        match *pinned {
                            None => *pinned = Some(from),
                            Some(first) if first != from => {
                                meter.stray.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            Some(_) => {}
                        }
                    }
                    if send.write_all(&packet(&buf[..n])).await.is_err() {
                        break;
                    }
                    meter.up.fetch_add(n as u64, Ordering::Relaxed);
                }
                meter.closed.store(true, Ordering::Relaxed);
            })
        };
        let down = {
            let socket = Arc::clone(&socket);
            let meter = Arc::clone(&meter);
            tokio::spawn(async move {
                while let Ok(Some(bytes)) = read_packet(&mut recv).await {
                    let Some(to) = *dialler.lock().await else {
                        continue; // nothing has dialled yet; nowhere to deliver
                    };
                    if socket.send_to(&bytes, to).await.is_err() {
                        break;
                    }
                    meter.down.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                }
                meter.closed.store(true, Ordering::Relaxed);
            })
        };
        Ok(Carrier {
            _conn: conn,
            local,
            family: opened.family,
            meter,
            pumps: vec![up, down],
        })
    }

    /// Where the member's dialler sends: a loopback socket this carrier pumps.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The family the home reached the target over, 4 or 6.
    pub fn family(&self) -> u8 {
        self.family
    }

    /// Whether the tunnel has ended -- the home closed it, or the connection
    /// to the home is gone. A dial to `local_addr()` then reaches nothing.
    pub fn closed(&self) -> bool {
        self.meter.closed.load(Ordering::Relaxed)
    }

    /// End the tunnel now: the connection to the home is closed and the
    /// pumps stop, so `closed()` says so at once. What a client does when
    /// it means to start over rather than wait for the home to notice.
    pub fn close(&self) {
        self._conn.close(0u32.into(), b"");
        for p in &self.pumps {
            p.abort();
        }
        self.meter.closed.store(true, Ordering::Relaxed);
    }

    /// Packets dropped because they came from a second local sender -- a
    /// client that dialled this socket again instead of opening a fresh
    /// carrier. Anything but zero is that bug.
    pub fn stray(&self) -> u64 {
        self.meter.stray.load(Ordering::Relaxed)
    }

    /// Bytes carried so far, `(up, down)`.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.meter.up.load(Ordering::Relaxed),
            self.meter.down.load(Ordering::Relaxed),
        )
    }
}

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (up, down) = self.bytes();
        f.debug_struct("Carrier")
            .field("local", &self.local)
            .field("family", &self.family)
            .field("up", &up)
            .field("down", &down)
            .field("closed", &self.closed())
            .finish()
    }
}

impl Drop for Carrier {
    fn drop(&mut self) {
        for p in &self.pumps {
            p.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_round_trips() {
        let o = Open {
            key: [7u8; 32],
            domain: "trunk.exchange".into(),
        };
        assert_eq!(Open::decode(&o.encode()).unwrap(), o);
    }

    #[test]
    fn open_refuses_trailing_bytes_and_a_short_domain() {
        let mut b = Open {
            key: [1u8; 32],
            domain: "x.test".into(),
        }
        .encode();
        b.push(b'!');
        assert!(Open::decode(&b).is_err(), "a trailing byte is refused");
        b.truncate(b.len() - 3);
        assert!(Open::decode(&b).is_err(), "a domain cut short is refused");
        assert!(
            Open::decode(
                &Open {
                    key: [1u8; 32],
                    domain: String::new()
                }
                .encode()
            )
            .is_err(),
            "an empty domain names nothing"
        );
    }

    #[test]
    fn opened_is_two_bytes() {
        let o = Opened {
            status: STATUS_WRONG_KEY,
            family: 0,
        };
        assert_eq!(Opened::decode(&o.encode()).unwrap(), o);
        assert!(Opened::decode(&[0]).is_err());
        assert!(Opened::decode(&[0, 4, 0]).is_err());
    }

    #[test]
    fn packet_is_length_prefixed() {
        let p = packet(&[1, 2, 3]);
        assert_eq!(p, vec![0, 3, 1, 2, 3]);
    }

    #[test]
    fn decoders_reject_garbage_without_panicking() {
        for len in 0..40usize {
            let junk = vec![0xffu8; len];
            let _ = Open::decode(&junk);
            let _ = Opened::decode(&junk);
        }
    }
}
