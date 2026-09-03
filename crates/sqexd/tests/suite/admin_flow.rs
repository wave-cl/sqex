//! End-to-end over real HTTP/3 with a software signer: whitelist enforcement,
//! non-admin rejection, replay rejection, batch atomicity, summary-binding, and
//! persistence across a restart. Drives the raw transaction protocol with an
//! inline client (the sqnr-library path is covered in `sqnr_flow.rs`).

use std::net::SocketAddr;

use bytes::Buf;
use ed25519_dalek::SigningKey;
use sqex_proto::Op;
use sqexd::config::FileConfig;
use sqnr_core::{Operation, PubKey, SignedTransaction, SoftwareSigner, Transaction};
use squic::Config as SquicConfig;

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

    /// Fetch a challenge and POST a transaction of `ops` signed by `signer`.
    async fn tx(
        &mut self,
        ops: Vec<Operation>,
        server_pub: &PubKey,
        signer: &SoftwareSigner,
    ) -> (u16, Vec<u8>) {
        let (cs, nonce_bytes) = self.get("/admin/challenge").await;
        assert_eq!(cs, 200, "challenge should be issued");
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);
        let txn = Transaction {
            server: *server_pub,
            nonce,
            ops,
        };
        let signed = SignedTransaction::create(txn, signer);
        self.post("/admin/command", signed.encode()).await
    }

    /// Convenience: a one-op transaction.
    async fn admin(
        &mut self,
        op: Op,
        server_pub: &PubKey,
        signer: &SoftwareSigner,
    ) -> (u16, Vec<u8>) {
        self.tx(vec![op.to_operation()], server_pub, signer).await
    }

    async fn whitelist_enabled(&mut self) -> bool {
        let (_s, body) = self.get("/status").await;
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        v["whitelist_enabled"].as_bool().unwrap_or(false)
    }
}

#[tokio::test]
async fn full_admin_flow() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("host_key");
    let state_path = dir.path().join("sqex.state");

    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();

    let admin_sk = SigningKey::from_bytes(&[7u8; 32]);
    let admin_pub = PubKey::new(admin_sk.verifying_key().to_bytes());
    let admin_signer = SoftwareSigner::new(admin_sk);
    let outsider = SoftwareSigner::new(SigningKey::from_bytes(&[8u8; 32]));

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
    assert_eq!(client.get("/health").await.0, 200, "health is public");
    assert_eq!(
        client.get("/exchange/ping").await.0,
        200,
        "ping allowed while whitelist disabled"
    );

    // A summary that does not match its payload is rejected (context binding).
    let (s, _) = client
        .tx(
            vec![Operation {
                summary: "Do something harmless".into(),
                detail: vec![],
                payload: Op::WhitelistEnable.payload(),
            }],
            &server_pub,
            &admin_signer,
        )
        .await;
    assert_eq!(s, 400, "summary/payload mismatch refused");
    assert!(!client.whitelist_enabled().await, "and nothing was applied");

    // A batch containing a bad op applies NONE of it (atomicity): enable first,
    // then an undecodable payload.
    let (s, _) = client
        .tx(
            vec![
                Op::WhitelistEnable.to_operation(),
                Operation {
                    summary: "bogus".into(),
                    detail: vec![],
                    payload: vec![0xFF],
                },
            ],
            &server_pub,
            &admin_signer,
        )
        .await;
    assert_eq!(s, 400, "batch with a bad op is refused");
    assert!(
        !client.whitelist_enabled().await,
        "the good op in the bad batch was not applied"
    );

    // Enable the whitelist (admin, signed).
    let (s, body) = client
        .admin(Op::WhitelistEnable, &server_pub, &admin_signer)
        .await;
    assert_eq!(s, 200, "admin enable: {}", String::from_utf8_lossy(&body));

    // Non-whitelisted client now refused on the protected endpoint.
    assert_eq!(
        client.get("/exchange/ping").await.0,
        403,
        "ping refused: whitelist on, client not listed"
    );

    // A batch: add the client key AND read the list in one signed transaction.
    let (s, body) = client
        .tx(
            vec![
                Op::WhitelistAdd {
                    key: client_pub,
                    label: Some("test-peer".into()),
                }
                .to_operation(),
                Op::WhitelistList.to_operation(),
            ],
            &server_pub,
            &admin_signer,
        )
        .await;
    assert_eq!(s, 200, "batch add+list accepted");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let listed = &v["results"][1];
    assert_eq!(listed["enabled"], true);
    let entry = listed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key"].as_str() == Some(&client_pub.to_base58()))
        .expect("the added key is in the returned list");
    // Provenance was recorded: the label the operator gave and the signing admin.
    assert_eq!(entry["label"].as_str(), Some("test-peer"));
    assert_eq!(entry["added_by"].as_str(), Some(admin_pub.to_base58().as_str()));
    assert_eq!(
        client.get("/exchange/ping").await.0,
        200,
        "ping allowed after the client's key is whitelisted"
    );

    // A non-admin signer is rejected.
    let (outsider_status, outsider_body) = client
        .admin(Op::WhitelistDisable, &server_pub, &outsider)
        .await;
    assert_eq!(outsider_status, 403, "outsider is not an admin");

    // **This route still answers JSON, and this assertion is why.** Every other
    // refusal on this exchange is a binary `Refusal` now. `/admin/command` is
    // read by `sqnr::flow::sign_and_submit`, an external crate pinned by tag,
    // which parses the body with `from_slice(..).unwrap_or(Null)` and then
    // takes `error` and `detail` out of it. Converting this route would not
    // fail there — it would quietly become a refusal with no reason. Asserting
    // on the parsed fields rather than the raw bytes so that a change of
    // wording stays free and a change of *format* does not.
    let refusal: serde_json::Value = serde_json::from_slice(&outsider_body)
        .expect("/admin/command must answer JSON — see sqnr::flow::sign_and_submit");
    assert_eq!(refusal["error"].as_str(), Some("not_admin"));
    assert!(
        refusal["detail"].is_string(),
        "sqnr reads `detail` as a string"
    );

    // Replay: reuse a consumed nonce.
    let (cs, nonce_bytes) = client.get("/admin/challenge").await;
    assert_eq!(cs, 200);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let txn = Transaction {
        server: server_pub,
        nonce,
        ops: vec![Op::Status.to_operation()],
    };
    let signed = SignedTransaction::create(txn, &admin_signer);
    assert_eq!(
        client.post("/admin/command", signed.encode()).await.0,
        200,
        "first use of the nonce works"
    );
    assert_eq!(
        client.post("/admin/command", signed.encode()).await.0,
        401,
        "second use of the same nonce is refused"
    );

    // Persistence across a restart.
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

/// `/status` reports what sQUIC accepts and what is actually arriving.
///
/// This is the number the SIP-29 retirement decision turns on. Retiring an
/// envelope version that clients still send locks them out in silence — a
/// refused envelope is dropped with no reply, so neither end logs anything —
/// and until this was surfaced the only way to answer "is anything still on
/// v2" was to retire it and see who complained.
///
/// The test pins both halves against a server configured to accept exactly
/// one version, so the reported set is the configured one and not sQUIC's
/// three-version default, and the count is non-zero because this test's own
/// handshake put it there.
#[tokio::test]
async fn status_reports_accepted_and_arriving_envelope_versions() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let client_seed = [7u8; 32];

    // Accept v3 only — the same posture ex runs. A server left on the default
    // would report all three, and the assertion below could not then tell the
    // configured set apart from the default one.
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\naccepted_envelope_versions = [3]\n",
        key_path.to_string_lossy(),
    );
    let config_path = dir.path().join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let (addr, server_pub, handle) = spawn_server(&config_toml, config_path).await;
    let mut client = Client::connect(addr, &server_pub, &client_seed).await;

    let (code, body) = client.get("/status").await;
    assert_eq!(code, 200);
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let transport = &status["transport"];

    assert_eq!(
        transport["accepted_envelope_versions"],
        serde_json::json!([3]),
        "the configured set is reported, not squic's default"
    );

    // This client's own Initial. The client defaults to v3, so the count lands
    // on v3 and the other versions stay at zero — which is exactly the reading
    // that would justify retiring them.
    let arriving = transport["initials_by_envelope_version"]
        .as_object()
        .expect("initials are reported per version");
    assert!(
        arriving["3"].as_u64().unwrap_or(0) >= 1,
        "this test's own handshake is counted on v3, got {arriving:?}"
    );
    assert_eq!(arriving["1"].as_u64(), Some(0), "nothing arrived on v1");
    assert_eq!(arriving["2"].as_u64(), Some(0), "nothing arrived on v2");

    // The cookie defence is idle on a server nobody is flooding.
    assert_eq!(transport["under_load"], false);

    handle.abort();
}
