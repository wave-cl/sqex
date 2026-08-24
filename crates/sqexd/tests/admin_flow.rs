//! End-to-end: drive the signed admin-command flow over real HTTP/3 with a
//! software signer, and prove whitelist enforcement, non-admin rejection,
//! replay rejection, and persistence across a restart.

use std::net::SocketAddr;

use bytes::Buf;
use ed25519_dalek::SigningKey;
use sqex_core::PubKey;
use sqex_core::protocol::{Action, Command, SignedCommand, SoftwareSigner};
use sqexd::config::FileConfig;
use squic::Config as SquicConfig;

/// Spawn a server on an ephemeral port; return (addr, server pubkey bytes, task).
async fn spawn_server(
    config_toml: &str,
    config_path: std::path::PathBuf,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let file: FileConfig = toml::from_str(config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, Some(config_path), signing_key)
        .await
        .unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    let handle = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, handle)
}

/// A tiny HTTP/3 client over squic that reuses one connection.
struct Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _drive: tokio::task::JoinHandle<()>,
}

impl Client {
    async fn connect(addr: SocketAddr, server_pub: &[u8; 32], client_seed: &[u8; 32]) -> Client {
        let conn = squic::dial(
            addr,
            server_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                client_key: Some(hex::encode(client_seed)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Client {
            send,
            _drive: drive,
        }
    }

    async fn get(&mut self, path: &str) -> (u16, Vec<u8>) {
        self.request("GET", path, None).await
    }

    async fn post(&mut self, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
        self.request("POST", path, Some(body)).await
    }

    async fn request(&mut self, method: &str, path: &str, body: Option<Vec<u8>>) -> (u16, Vec<u8>) {
        let req = http::Request::builder()
            .method(method)
            .uri(format!("https://sqex{path}"))
            .body(())
            .unwrap();
        let mut stream = self.send.send_request(req).await.unwrap();
        if let Some(b) = body {
            stream.send_data(bytes::Bytes::from(b)).await.unwrap();
        }
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        let status = resp.status().as_u16();
        let mut out = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            while chunk.remaining() > 0 {
                let n = chunk.chunk().len();
                out.extend_from_slice(chunk.chunk());
                chunk.advance(n);
            }
        }
        (status, out)
    }

    /// Run one admin action: fetch a challenge, sign, POST. Returns (status, body).
    async fn admin(
        &mut self,
        action: Action,
        server_pub: &PubKey,
        signer: &SoftwareSigner,
    ) -> (u16, Vec<u8>) {
        let (cs, nonce_bytes) = self.get("/admin/challenge").await;
        assert_eq!(cs, 200, "challenge should be issued");
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);
        let cmd = Command {
            action,
            nonce,
            server: *server_pub,
        };
        let signed = SignedCommand::create(cmd, signer);
        self.post("/admin/command", signed.encode()).await
    }
}

#[tokio::test]
async fn full_admin_flow() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("host_key");
    let state_path = dir.path().join("sqex.state");

    // Server identity.
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();

    // Admin identity (goes in config); a non-admin identity for rejection test.
    let admin_sk = SigningKey::from_bytes(&[7u8; 32]);
    let admin_pub = PubKey::new(admin_sk.verifying_key().to_bytes());
    let admin_signer = SoftwareSigner::new(admin_sk);
    let outsider = SoftwareSigner::new(SigningKey::from_bytes(&[8u8; 32]));

    // Client transport identity (what the whitelist will gate on).
    let client_seed = [42u8; 32];
    let client_pub = PubKey::new(
        SigningKey::from_bytes(&client_seed)
            .verifying_key()
            .to_bytes(),
    );

    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = [{:?}]\n",
        key_path.to_string_lossy(),
        state_path.to_string_lossy(),
        admin_pub.to_base58(),
    );
    let config_path = dir.path().join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let (addr, server_pub_bytes, handle) = spawn_server(&config_toml, config_path.clone()).await;
    let server_pub = PubKey::new(server_pub_bytes);

    let mut client = Client::connect(addr, &server_pub_bytes, &client_seed).await;

    // Public endpoints.
    let (s, _) = client.get("/health").await;
    assert_eq!(s, 200, "health is public");
    let (s, _) = client.get("/exchange/ping").await;
    assert_eq!(s, 200, "ping allowed while whitelist disabled");

    // Enable the whitelist (admin, signed).
    let (s, body) = client
        .admin(Action::WhitelistEnable, &server_pub, &admin_signer)
        .await;
    assert_eq!(
        s,
        200,
        "admin enable accepted: {}",
        String::from_utf8_lossy(&body)
    );

    // Now the (non-whitelisted) client is refused on the protected endpoint.
    let (s, _) = client.get("/exchange/ping").await;
    assert_eq!(s, 403, "ping refused: whitelist on, client not listed");

    // Add the client's identity, then it is allowed again.
    let (s, _) = client
        .admin(Action::WhitelistAdd(client_pub), &server_pub, &admin_signer)
        .await;
    assert_eq!(s, 200, "admin add accepted");
    let (s, _) = client.get("/exchange/ping").await;
    assert_eq!(s, 200, "ping allowed after the client's key is whitelisted");

    // A non-admin signer is rejected.
    let (s, _) = client
        .admin(Action::WhitelistDisable, &server_pub, &outsider)
        .await;
    assert_eq!(s, 403, "outsider is not an admin");

    // Replay: reuse a consumed nonce.
    let (cs, nonce_bytes) = client.get("/admin/challenge").await;
    assert_eq!(cs, 200);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let cmd = Command {
        action: Action::Status,
        nonce,
        server: server_pub,
    };
    let signed = SignedCommand::create(cmd, &admin_signer);
    let (s, _) = client.post("/admin/command", signed.encode()).await;
    assert_eq!(s, 200, "first use of the nonce works");
    let (s, _) = client.post("/admin/command", signed.encode()).await;
    assert_eq!(s, 401, "second use of the same nonce is refused");

    // Persistence across a restart: stop the server, start a fresh one on the
    // same state file, and confirm the whitelist survived.
    handle.abort();
    let _ = handle.await;
    let (addr2, server_pub2, handle2) = spawn_server(&config_toml, config_path).await;
    let mut client2 = Client::connect(addr2, &server_pub2, &client_seed).await;
    let (s, body) = client2.get("/status").await;
    assert_eq!(s, 200);
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["whitelist_enabled"], true, "enabled state persisted");
    assert_eq!(status["whitelist_count"], 1, "one key persisted");
    handle2.abort();
}
