//! A minimal HTTP/3-over-sQUIC client for talking to sqexd.

use std::net::SocketAddr;

use bytes::Buf;
use squic::Config as SquicConfig;

/// One HTTP/3 connection to a sqex server, reused across requests.
pub struct Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _drive: tokio::task::JoinHandle<()>,
}

impl Client {
    /// Dial `addr`, pinning the server's Ed25519 key. The transport key is
    /// ephemeral: admin authority is the command signature, not the connection.
    pub async fn connect(addr: SocketAddr, server_pub: &[u8; 32]) -> Result<Client, String> {
        let conn = squic::dial(
            addr,
            server_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
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
        Ok(Client {
            send,
            _drive: drive,
        })
    }

    pub async fn get(&mut self, path: &str) -> Result<(u16, Vec<u8>), String> {
        self.request("GET", path, None).await
    }

    pub async fn post(&mut self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>), String> {
        self.request("POST", path, Some(body)).await
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String> {
        let req = http::Request::builder()
            .method(method)
            .uri(format!("https://sqex{path}"))
            .body(())
            .map_err(|e| e.to_string())?;
        let mut stream = self
            .send
            .send_request(req)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(b) = body {
            stream
                .send_data(bytes::Bytes::from(b))
                .await
                .map_err(|e| e.to_string())?;
        }
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
