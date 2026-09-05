//! A small HTTP/3-over-sQUIC client, for callers that cannot use `sqnr::Client`.
//!
//! **Why this exists.** `sqnr::Client` does all of this and more, and it links
//! `openpgp-card` and `card-backend-pcsc` unconditionally for a YubiKey — which
//! a *server* never touches, so depending on it from `sqexd` would put
//! libpcsclite on the deployment path in exchange for nothing. It also binds an
//! ephemeral local port with no way to choose one, which SIP-25's hole punching
//! cannot work without: the address an exchange observes has to be the mapping
//! the peer connection will use, and that means both leaving from the same port.
//!
//! So the eighty lines those two callers need live here. It is deliberately not
//! general: one method, a path and bytes in, a status and bytes out.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Buf;
use squic::Config as SquicConfig;

/// One HTTP/3-over-sQUIC connection.
pub struct H3Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    drive: tokio::task::JoinHandle<()>,
}

/// **Dropping the client stops its driver, and therefore releases its socket.**
///
/// A `JoinHandle` that is dropped *detaches* its task rather than cancelling
/// it, so without this the driver went on holding the connection — and the UDP
/// port — after the caller had let go. Harmless for a replica, which drops one
/// only when it is finished with the whole process; fatal for SIP-25, where the
/// entire point is to hand that port straight to a peer connection, and where
/// the symptom was `Address already in use`.
impl Drop for H3Client {
    fn drop(&mut self) {
        self.drive.abort();
    }
}

impl H3Client {
    /// Dial `addr`, pinning the peer's Ed25519 key and advertising our own.
    ///
    /// **Both keys matter and neither is optional.** The pin is what makes a
    /// SIP-34 receipt checkable: SIP-35 says a replica must obtain the origin's
    /// key independently and must not accept it on the origin's say-so, and
    /// pinning it here is where that is enforced. Advertising ours is what lets
    /// the other end apply its own whitelist — a peering connection is an
    /// ordinary SIP-3 identity, and for an exchange that identity is its SIP-9
    /// key.
    pub async fn connect(
        addr: SocketAddr,
        peer_pub: &[u8; 32],
        seed: &[u8; 32],
    ) -> Result<H3Client, String> {
        Self::connect_from(addr, peer_pub, seed, None).await
    }

    /// The same, leaving from a local address of the caller's choosing.
    ///
    /// **For SIP-25 and nothing else.** The address an exchange observes is the
    /// NAT mapping this socket made, and a peer can only be reached through
    /// that mapping — so the connection that gets introduced and the connection
    /// that punches have to leave from one port. `None` binds an ephemeral one,
    /// which is what every other caller wants.
    pub async fn connect_from(
        addr: SocketAddr,
        peer_pub: &[u8; 32],
        seed: &[u8; 32],
        local_bind: Option<SocketAddr>,
    ) -> Result<H3Client, String> {
        let conn = squic::dial(
            addr,
            peer_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                // A replication link is long-lived and mostly idle between
                // pulls, so it is kept alive rather than redialled — a fresh
                // handshake per pull would cost more than the pull. It is also
                // what holds a punched NAT mapping open.
                keep_alive: Some(Duration::from_secs(15)),
                handshake_timeout: Some(Duration::from_secs(5)),
                client_key: Some(hex::encode(seed)),
                advertise_identity: true,
                local_bind,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| format!("connect: {e}"))?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| format!("h3 setup: {e}"))?;
        let drive = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Ok(H3Client { send, drive })
    }

    /// One request, one response, fully read.
    ///
    /// Bounded by what the peer sends: every SIP-35 response has a limit in the
    /// document and a decoder that refuses more.
    pub async fn post(&mut self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), String> {
        let req = http::Request::builder()
            .method("POST")
            .uri(format!("https://sqex{path}"))
            .body(())
            .map_err(|e| e.to_string())?;
        let mut stream = self.send.send_request(req).await.map_err(|e| e.to_string())?;
        if !body.is_empty() {
            stream
                .send_data(bytes::Bytes::from(body))
                .await
                .map_err(|e| e.to_string())?;
        }
        // Our half closes here: the peer reads a bounded body to its end before
        // answering, so a request that never finished sending is never read.
        stream.finish().await.map_err(|e| e.to_string())?;
        let resp = stream.recv_response().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let mut out = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
            while chunk.remaining() > 0 {
                let n = chunk.chunk().len();
                out.extend_from_slice(chunk.chunk());
                chunk.advance(n);
            }
        }
        Ok((status, out))
    }
}
