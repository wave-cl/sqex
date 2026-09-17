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
        Client::try_connect(addr, server_pub, client_seed)
            .await
            .expect("the exchange answers this key")
    }

    /// A dial that may be dropped at the door: the silent server answers a
    /// key it will not have with nothing, so this gives up after a while
    /// rather than for ever.
    async fn try_connect(
        addr: SocketAddr,
        server_pub: &[u8; 32],
        client_seed: &[u8; 32],
    ) -> Option<Client> {
        let dial = squic::dial(
            addr,
            server_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                client_key: Some(hex::encode(client_seed)),
                // SIP-3: named, so the chat routes know who is asking. The
                // whitelist decides on the transport key either way.
                advertise_identity: true,
                ..Default::default()
            },
        );
        let conn = tokio::time::timeout(std::time::Duration::from_secs(4), dial)
            .await
            .ok()?
            .ok()?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Some(Client {
            send,
            _drive: drive,
        })
    }

    /// A GET on a connection that may have been closed under it.
    async fn try_get(&mut self, path: &str) -> Option<(u16, Vec<u8>)> {
        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://sqex{path}"))
            .body(())
            .unwrap();
        let mut stream = self.send.send_request(req).await.ok()?;
        stream.finish().await.ok()?;
        let resp = stream.recv_response().await.ok()?;
        Some((resp.status().as_u16(), Vec::new()))
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
    // The administrator's own connection, as an administrator has: signing
    // is by key, but with the list on the transport the *connection* has to
    // be one the exchange will keep, and an admin's is.
    let mut admin = Client::connect(addr, &server_pub_bytes, &[7u8; 32]).await;

    // Public endpoints.
    assert_eq!(client.get("/health").await.0, 200, "health is public");
    assert_eq!(
        client.get("/exchange/ping").await.0,
        200,
        "ping allowed while whitelist disabled"
    );

    // A summary that does not match its payload is rejected (context binding).
    let (s, _) = admin
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
    assert!(!admin.whitelist_enabled().await, "and nothing was applied");

    // A batch containing a bad op applies NONE of it (atomicity): enable first,
    // then an undecodable payload.
    let (s, _) = admin
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
        !admin.whitelist_enabled().await,
        "the good op in the bad batch was not applied"
    );

    // Enable the whitelist (admin, signed).
    let (s, body) = admin
        .admin(Op::WhitelistEnable, &server_pub, &admin_signer)
        .await;
    assert_eq!(s, 200, "admin enable: {}", String::from_utf8_lossy(&body));

    // **The list is on the transport.** The unlisted client's connection is
    // closed under it, and a fresh dial with the same key is dropped at the
    // door -- the silent server, nothing answers -- while the administrator,
    // whose key is allowed through with the list, goes on being served.
    // Refused at once by the route gate, or closed a moment later; either
    // way, never served -- and after the moment, closed.
    match client.try_get("/exchange/ping").await {
        None => {}
        Some((status, _)) => assert_eq!(status, 403, "served after the list went on"),
    }
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert!(
        client.try_get("/health").await.is_none(),
        "an unlisted peer's connection survived the list being enabled"
    );
    assert!(
        Client::try_connect(addr, &server_pub_bytes, &client_seed)
            .await
            .is_none(),
        "an unlisted key was given a connection with the list on"
    );
    assert_eq!(
        admin.get("/exchange/ping").await.0,
        200,
        "the administrator is allowed through with the list"
    );
    assert_eq!(admin.get("/health").await.0, 200);
    // A batch: add the client key AND read the list in one signed transaction.
    let (s, body) = admin
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
    assert_eq!(
        entry["added_by"].as_str(),
        Some(admin_pub.to_base58().as_str())
    );
    // Listed, the client is let in again -- a new connection; the old one
    // was closed -- and the routes answer it as a client.
    let mut client = Client::try_connect(addr, &server_pub_bytes, &client_seed)
        .await
        .expect("a listed key is given a connection");
    assert_eq!(
        client.get("/exchange/ping").await.0,
        200,
        "ping allowed after the client's key is whitelisted"
    );
    assert_ne!(
        client.post("/channel/list", vec![]).await.0,
        403,
        "a listed peer is not refused as unlisted"
    );

    // **Removed while connected: gone.** The transport only decides at the
    // door, so the exchange closes what it let in; a request racing the
    // close is refused by the route gate instead. Either way, not served.
    let (s, _) = admin
        .admin(Op::WhitelistRemove(client_pub), &server_pub, &admin_signer)
        .await;
    assert_eq!(s, 200);
    match client.try_get("/exchange/ping").await {
        None => {}
        Some((status, _)) => assert_eq!(status, 403, "served after removal"),
    }
    assert!(
        Client::try_connect(addr, &server_pub_bytes, &client_seed)
            .await
            .is_none(),
        "a removed key was given a connection"
    );
    // And back on, for the rest of the flow.
    let (s, _) = admin
        .admin(
            Op::WhitelistAdd {
                key: client_pub,
                label: None,
            },
            &server_pub,
            &admin_signer,
        )
        .await;
    assert_eq!(s, 200);
    let mut client = Client::connect(addr, &server_pub_bytes, &client_seed).await;

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

/// SIP-47: a registered device of an admitted account is admitted, for as
/// long as the registration stands. The phone's key is on no list; the
/// account registers it and it is let in; revoked, or its credential run
/// out, it is closed and refused at the door like any stranger.
#[tokio::test]
async fn a_registered_device_of_a_listed_account_is_let_in_until_it_is_not() {
    use sqex_proto::credential::{Credential, SCOPE_CHAT};
    use sqex_proto::device::{Register, Revoke};

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let admin_sk = SigningKey::from_bytes(&[17u8; 32]);
    let admin_pub = PubKey::new(admin_sk.verifying_key().to_bytes());
    let admin_signer = SoftwareSigner::new(admin_sk);
    let account_seed = [52u8; 32];
    let account_pub = PubKey::new(
        SigningKey::from_bytes(&account_seed)
            .verifying_key()
            .to_bytes(),
    );
    let phone_seed = [53u8; 32];
    let phone_pub = PubKey::new(
        SigningKey::from_bytes(&phone_seed)
            .verifying_key()
            .to_bytes(),
    );
    let brief_seed = [54u8; 32];
    let brief_pub = PubKey::new(
        SigningKey::from_bytes(&brief_seed)
            .verifying_key()
            .to_bytes(),
    );

    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = [{:?}]\n",
        key_path.to_string_lossy(),
        dir.path().join("sqex.state").to_string_lossy(),
        admin_pub.to_base58(),
    );
    let config_path = dir.path().join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();
    let (addr, server_pub_bytes, _handle) = spawn_server(&config_toml, config_path).await;
    let server_pub = PubKey::new(server_pub_bytes);
    let mut admin = Client::connect(addr, &server_pub_bytes, &[17u8; 32]).await;
    let (s, _) = admin
        .admin(Op::WhitelistEnable, &server_pub, &admin_signer)
        .await;
    assert_eq!(s, 200);
    let (s, _) = admin
        .admin(
            Op::WhitelistAdd {
                key: account_pub,
                label: None,
            },
            &server_pub,
            &admin_signer,
        )
        .await;
    assert_eq!(s, 200);

    // The account is in; its phone, on no list, is not.
    let mut account = Client::try_connect(addr, &server_pub_bytes, &account_seed)
        .await
        .expect("the listed account is let in");
    assert!(
        Client::try_connect(addr, &server_pub_bytes, &phone_seed)
            .await
            .is_none(),
        "an unregistered device was let in"
    );

    // Registered by the account (SIP-22), the phone is admitted -- and is
    // not on the list, which is the account's alone.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The account is its own first device (SIP-22: a sibling registers
    // the next, and an unregistered account is nobody's sibling).
    let own =
        Credential::issue(&account_seed, &account_pub, SCOPE_CHAT, now - 1, now + 3600).unwrap();
    let (s, body) = account
        .post("/device/register", Register { credential: own }.encode())
        .await;
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&body));
    let credential =
        Credential::issue(&account_seed, &phone_pub, SCOPE_CHAT, now - 1, now + 3600).unwrap();
    let (s, body) = account
        .post("/device/register", Register { credential }.encode())
        .await;
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&body));
    let mut phone = Client::try_connect(addr, &server_pub_bytes, &phone_seed)
        .await
        .expect("a registered device is let in");
    assert_eq!(phone.get("/exchange/ping").await.0, 200);
    let (s, body) = admin
        .admin(Op::WhitelistList, &server_pub, &admin_signer)
        .await;
    assert_eq!(s, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["results"][0]["keys"].as_array().map(Vec::len),
        Some(1),
        "the device was listed beside the account: {v}"
    );

    // A second device, on a credential about to run out.
    let credential =
        Credential::issue(&account_seed, &brief_pub, SCOPE_CHAT, now - 1, now + 2).unwrap();
    let (s, _) = account
        .post("/device/register", Register { credential }.encode())
        .await;
    assert_eq!(s, 200);
    let mut brief = Client::try_connect(addr, &server_pub_bytes, &brief_seed)
        .await
        .expect("a briefly registered device is let in");
    assert_eq!(brief.get("/exchange/ping").await.0, 200);
    // Whole seconds: a credential good through `now + 2` is good at
    // `now + 2`, so wait past the next second boundary after it.
    tokio::time::sleep(std::time::Duration::from_millis(3500)).await;

    // Revoked, the phone's connection is closed and its key refused; and
    // the door, re-derived, no longer rests on a credential that has run
    // out. (The sweeper would find that by itself within its minute; the
    // revoke is what makes it prompt here.)
    let (s, body) = account
        .post(
            "/device/revoke",
            Revoke {
                device: phone_pub,
                revocation: None,
            }
            .encode(),
        )
        .await;
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&body));
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert!(
        phone.try_get("/health").await.is_none(),
        "a revoked device's connection survived"
    );
    assert!(
        Client::try_connect(addr, &server_pub_bytes, &phone_seed)
            .await
            .is_none(),
        "a revoked device was let back in"
    );
    assert!(
        brief.try_get("/health").await.is_none(),
        "a device whose credential ran out kept its connection"
    );
    assert!(
        Client::try_connect(addr, &server_pub_bytes, &brief_seed)
            .await
            .is_none(),
        "a device whose credential ran out was let back in"
    );
    assert_eq!(
        account.get("/exchange/ping").await.0,
        200,
        "the account itself is unaffected"
    );
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

    // Named explicitly rather than left unset, so the assertion below can tell
    // the configured set apart from squic's default. They happen to be the same
    // list today — v4 is the only version implemented — which is precisely why
    // naming it is what makes the assertion mean anything.
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\naccepted_envelope_versions = [4]\n",
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
        serde_json::json!([4]),
        "the configured set is reported, not squic's default"
    );

    // This client's own Initial, counted against the version it was sent under.
    let arriving = transport["initials_by_envelope_version"]
        .as_object()
        .expect("initials are reported per version");
    assert!(
        arriving["4"].as_u64().unwrap_or(0) >= 1,
        "this test's own handshake is counted on v4, got {arriving:?}"
    );
    assert_eq!(
        arriving.len(),
        1,
        "one version is implemented, so one is reported, got {arriving:?}"
    );

    // The cookie defence is idle on a server nobody is flooding.
    assert_eq!(transport["under_load"], false);

    handle.abort();
}

/// The trap the v4 cut walked past, now closed at the transport and pinned
/// here so it stays closed.
///
/// It used to be that a server told to accept an envelope version this build
/// does not implement **started perfectly happily and then accepted nothing** —
/// no error, no log line and no reply, because a refused envelope is dropped in
/// silence by design (SIP-6). The operator saw a healthy process and a dead
/// port. ex was configured `accepted_envelope_versions = [3]` right up to the
/// cut, which is exactly that state under a v4 binary.
///
/// squic v0.24.1 refuses to bind on such a set, so the failure is now loud and
/// arrives before the socket exists. This test asserts the loudness: that
/// `bind` fails, and that the error says which versions were the problem rather
/// than surfacing as some unrelated I/O complaint.
#[tokio::test]
async fn a_retired_accepted_version_is_refused_at_bind() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();

    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\naccepted_envelope_versions = [3]\n",
        key_path.to_string_lossy(),
    );
    let config_path = dir.path().join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();

    let err = match sqexd::bind(config, Some(config_path), signing_key).await {
        Ok(_) => panic!("sqexd bound on an envelope version it cannot parse"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("accepted_envelope_versions"),
        "bind failed for the wrong reason: {err}"
    );
}
