//! The outbound half of SIP-35: one exchange dialling another.
//!
//! **Why this exists rather than reusing `sqnr::Client`.** That client does
//! exactly this and more, and it is already a dev-dependency here — but it also
//! links `openpgp-card` and `card-backend-pcsc` unconditionally, for a YubiKey
//! the *server* never touches. Depending on it at runtime would put libpcsclite
//! into every `sqexd` build and every cross-build of one, which is a system
//! library on the deployment path in exchange for nothing. So the eighty lines
//! a replica actually needs live here, on the `squic` and `h3` this crate
//! already has.
//!
//! It is deliberately not general. There is one method, it takes a path and
//! bytes and returns a status and bytes, and a replica needs nothing else.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Buf;
use squic::Config as SquicConfig;

/// One HTTP/3-over-sQUIC connection to a peer exchange.
pub struct PeerClient {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _drive: tokio::task::JoinHandle<()>,
}

impl PeerClient {
    /// Dial `addr`, pinning the peer's Ed25519 key and advertising our own.
    ///
    /// **Both keys matter and neither is optional.** The pin is what makes the
    /// receipts checkable: SIP-35 says a replica must obtain the origin's key
    /// independently and must not accept it on the origin's say-so, and pinning
    /// it here is where that is enforced. Advertising ours is what lets the
    /// origin apply its own whitelist — a peering connection is an ordinary
    /// SIP-3 identity, and for an exchange that identity is its SIP-9 key.
    pub async fn connect(
        addr: SocketAddr,
        peer_pub: &[u8; 32],
        seed: &[u8; 32],
    ) -> Result<PeerClient, String> {
        let conn = squic::dial(
            addr,
            peer_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                // A replication link is long-lived and mostly idle between
                // pulls, so it is kept alive rather than redialled — a fresh
                // handshake per pull would cost more than the pull.
                keep_alive: Some(Duration::from_secs(15)),
                handshake_timeout: Some(Duration::from_secs(5)),
                client_key: Some(hex::encode(seed)),
                advertise_identity: true,
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
        Ok(PeerClient {
            send,
            _drive: drive,
        })
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
