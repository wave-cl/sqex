//! SIP-38 names, end to end over real HTTP/3 against a live sqexd.
//!
//! The wire and the store are unit-tested elsewhere; what these exercise is the
//! composition — a real exchange, a real connection carrying an identity, and
//! the registration-mode policy that decides who may bind a name. Open mode
//! (self-claim), closed mode (administrator assignment only), and the public
//! resolve/reverse lookups that both share.

use std::net::SocketAddr;

use bytes::Buf;
use ed25519_dalek::SigningKey;
use sqex_proto::Op;
use sqex_proto::name::{
    CLAIM_AT_CAPACITY, CLAIM_CLOSED, CLAIM_GRANTED, CLAIM_TAKEN, Claim, ClaimAck, Names,
    Resolve as NameResolve, Resolved, Reverse,
};
use sqexd::config::FileConfig;
use sqnr_core::{PubKey, SignedTransaction, SoftwareSigner, Transaction};
use squic::Config as SquicConfig;

async fn spawn_server(
    mode: &str,
    admin: Option<&PubKey>,
    max_names: Option<u64>,
) -> (SocketAddr, [u8; 32], tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let admins = match admin {
        Some(a) => format!("admins = [\"{}\"]\n", a.to_base58()),
        None => "admins = []\n".to_string(),
    };
    let cap = max_names
        .map(|n| format!("max_names = {n}\n"))
        .unwrap_or_default();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\n\
         welcome_channel = \"\"\nname_registration = \"{mode}\"\n\
         max_names_per_account = 2\nname_lease_secs = 100000\n{cap}{admins}",
        key_path.to_string_lossy(),
        dir.path().join("sqex.state").to_string_lossy(),
    );
    let config_path = dir.path().join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, Some(config_path), signing_key)
        .await
        .unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, dir)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

/// A one-connection HTTP/3 client that carries a fixed identity.
struct Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _drive: tokio::task::JoinHandle<()>,
}

impl Client {
    async fn connect(addr: SocketAddr, server_pub: &[u8; 32], seed: &[u8; 32]) -> Client {
        let conn = squic::dial(
            addr,
            server_pub,
            SquicConfig {
                alpn_protocols: vec![b"h3".to_vec()],
                client_key: Some(hex::encode(seed)),
                // SIP-3: carry the Ed25519 identity in the Initial, so the
                // exchange resolves the caller to an account. Without it the
                // name routes see no identity and refuse.
                advertise_identity: true,
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

    async fn tx(&mut self, op: Op, server_pub: &PubKey, signer: &SoftwareSigner) -> (u16, Vec<u8>) {
        let (cs, nonce_bytes) = self.get("/admin/challenge").await;
        assert_eq!(cs, 200);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);
        let txn = Transaction {
            server: *server_pub,
            nonce,
            ops: vec![op.to_operation()],
        };
        let signed = SignedTransaction::create(txn, signer);
        self.post("/admin/command", signed.encode()).await
    }

    async fn claim(&mut self, name: &str) -> ClaimAck {
        let (code, body) = self
            .post("/name/claim", Claim { name: name.into() }.encode())
            .await;
        assert_eq!(code, 200, "claim should answer 200");
        ClaimAck::decode(&body).unwrap()
    }

    async fn resolve(&mut self, name: &str) -> Resolved {
        let (code, body) = self
            .post("/name/resolve", NameResolve { name: name.into() }.encode())
            .await;
        assert_eq!(code, 200, "resolve should answer 200");
        Resolved::decode(&body).unwrap()
    }

    async fn reverse(&mut self, account: PubKey) -> Names {
        let (code, body) = self
            .post("/name/reverse", Reverse { account }.encode())
            .await;
        assert_eq!(code, 200, "reverse should answer 200");
        Names::decode(&body).unwrap()
    }
}

/// Open registration: an account claims a free name, it resolves to that
/// account, and reverse lists it. A second account cannot take it; releasing it
/// frees it for anyone.
#[tokio::test]
async fn open_registration_claim_resolve_release() {
    let (a_seed, a) = identity(1);
    let (b_seed, b) = identity(2);
    let (addr, server_pub, _dir) = spawn_server("open", None, None).await;

    let mut alice = Client::connect(addr, &server_pub, &a_seed).await;
    let mut bob = Client::connect(addr, &server_pub, &b_seed).await;

    // A claims a name; it resolves to A and is not stale.
    assert_eq!(alice.claim("colin").await.outcome, CLAIM_GRANTED);
    let r = alice.resolve("colin").await;
    assert!(r.found && !r.stale);
    assert_eq!(r.account, a);
    assert_ne!(r.expires_at, 0, "an open claim carries a lease");

    // Case folds: the same name in any case is the same binding.
    assert_eq!(bob.resolve("COLIN").await.account, a);

    // Reverse lists A's names, and B holds none.
    assert_eq!(alice.reverse(a).await.names, vec!["colin".to_string()]);
    assert!(bob.reverse(b).await.names.is_empty());

    // B cannot take a live name; the owner re-claiming is idempotent.
    assert_eq!(bob.claim("colin").await.outcome, CLAIM_TAKEN);
    assert_eq!(alice.claim("colin").await.outcome, CLAIM_GRANTED);

    // The per-account cap (2) is enforced against self-claims.
    assert_eq!(alice.claim("c").await.outcome, CLAIM_GRANTED);
    assert_eq!(alice.claim("colin2").await.outcome, CLAIM_AT_CAPACITY);

    // A releases the name; it is then free for B.
    let (code, _) = alice
        .post(
            "/name/release",
            sqex_proto::name::Release {
                name: "colin".into(),
            }
            .encode(),
        )
        .await;
    assert_eq!(code, 200);
    assert!(!alice.resolve("colin").await.found);
    assert_eq!(bob.claim("colin").await.outcome, CLAIM_GRANTED);
    assert_eq!(bob.resolve("colin").await.account, b);
}

/// Closed registration: self-claim is refused, but an administrator's SIP-10
/// assignment binds a name — and that binding does not expire and is not capped.
#[tokio::test]
async fn closed_registration_is_administrator_only() {
    let admin_sk = SigningKey::from_bytes(&[9u8; 32]);
    let admin_pub = PubKey::new(admin_sk.verifying_key().to_bytes());
    let admin_signer = SoftwareSigner::new(admin_sk);

    let (a_seed, a) = identity(1);
    let (addr, server_pub, _dir) = spawn_server("closed", Some(&admin_pub), None).await;
    let server_pub_key = PubKey::new(server_pub);

    let mut alice = Client::connect(addr, &server_pub, &a_seed).await;

    // Self-claim is refused in closed mode — but the route still answers, with
    // the outcome in its own vocabulary, because the namespace is public.
    assert_eq!(alice.claim("colin").await.outcome, CLAIM_CLOSED);
    assert!(!alice.resolve("colin").await.found);

    // The administrator assigns it to A with a signed transaction.
    let (code, body) = alice
        .tx(
            Op::NameAssign {
                name: "colin".into(),
                account: a,
            },
            &server_pub_key,
            &admin_signer,
        )
        .await;
    assert_eq!(code, 200, "admin assign should succeed");
    assert!(String::from_utf8_lossy(&body).contains("colin"));

    // It resolves to A, with no lease (an administrator's assignment does not
    // expire), and reverse finds it.
    let r = alice.resolve("colin").await;
    assert!(r.found && !r.stale);
    assert_eq!(r.account, a);
    assert_eq!(r.expires_at, 0, "an admin assignment does not expire");
    assert_eq!(alice.reverse(a).await.names, vec!["colin".to_string()]);

    // NameList reports it, and NameRelease frees it.
    let (code, body) = alice.tx(Op::NameList, &server_pub_key, &admin_signer).await;
    assert_eq!(code, 200);
    assert!(String::from_utf8_lossy(&body).contains("colin"));

    let (code, _) = alice
        .tx(
            Op::NameRelease("colin".into()),
            &server_pub_key,
            &admin_signer,
        )
        .await;
    assert_eq!(code, 200);
    assert!(!alice.resolve("colin").await.found);
}

/// With the route off, even resolution is refused — the feature is not offered.
#[tokio::test]
async fn off_mode_does_not_offer_the_route() {
    let (a_seed, _a) = identity(1);
    let (addr, server_pub, _dir) = spawn_server("off", None, None).await;
    let mut alice = Client::connect(addr, &server_pub, &a_seed).await;
    let (code, _) = alice
        .post(
            "/name/resolve",
            NameResolve {
                name: "colin".into(),
            }
            .encode(),
        )
        .await;
    assert_eq!(code, 404, "the name route is not offered when off");
}

/// Security pass: the global `max_names` cap bounds the whole directory, so a
/// mint-flood (distinct identities each with room under the per-account cap)
/// cannot fill it past the operator's limit. The third distinct account is
/// refused with `CLAIM_FULL`; releasing frees a slot.
#[tokio::test]
async fn global_cap_bounds_a_mint_flood() {
    use sqex_proto::name::CLAIM_FULL;
    let (addr, server_pub, _dir) = spawn_server("open", None, Some(2)).await;

    let mut clients = Vec::new();
    for i in 1..=3u8 {
        let (seed, _) = identity(i);
        clients.push(Client::connect(addr, &server_pub, &seed).await);
    }
    assert_eq!(clients[0].claim("one").await.outcome, CLAIM_GRANTED);
    assert_eq!(clients[1].claim("two").await.outcome, CLAIM_GRANTED);
    // Directory full: a fresh identity is refused despite its own empty quota.
    assert_eq!(clients[2].claim("three").await.outcome, CLAIM_FULL);
    // Freeing a slot lets the flood's next identity in.
    let (code, _) = clients[0]
        .post(
            "/name/release",
            sqex_proto::name::Release { name: "one".into() }.encode(),
        )
        .await;
    assert_eq!(code, 200);
    assert_eq!(clients[2].claim("three").await.outcome, CLAIM_GRANTED);
}
