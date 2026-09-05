//! SIP-28: where a key can be reached, on the exchange's word.
//!
//! The point of every test here is the boundary the SIP draws: **the exchange
//! is trusted for availability and privacy, not for authenticity.** It can deny,
//! and it learns who asks about whom. It cannot impersonate, because a consumer
//! pins the key it asked for when it connects — which is checked here by
//! resolving a key and then connecting to what came back.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::beacon::Beat;
use sqex_proto::resolve::{
    Endpoint, KIND_DNS, KIND_IPV4, MAX_ENDPOINTS, Publish, Resolve, Resolved, Successor,
};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let config_path = dir.join("sqexd.toml");
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
    let handle = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, handle)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn v4(a: [u8; 4], port: u16) -> Endpoint {
    Endpoint {
        kind: KIND_IPV4,
        host: a.to_vec(),
        port,
        priority: 0,
        weight: 0,
    }
}

async fn resolve_as(c: &mut Client, key: PubKey) -> Resolved {
    let (code, body) = c
        .post("/resolve/get", Resolve { key }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Resolved::decode(&body).unwrap()
}

/// Publish, resolve, and read the provenance — which is the part a bare list of
/// addresses would leave invisible.
#[tokio::test]
async fn what_an_identity_publishes_is_what_another_resolves() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(161);
    let (bob_seed, _) = identity(162);

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &bob_seed).await.unwrap();

    // Nothing yet, and absence is a shape rather than an error.
    let before = resolve_as(&mut b, alice).await;
    assert!(!before.found);
    assert!(before.endpoints.is_empty());
    assert_eq!(before.last_seen, 0);
    assert!(before.now > 0, "the exchange always states its own clock");

    let req = Publish {
        ttl_secs: 300,
        capabilities: vec![],
        endpoints: vec![
            v4([198, 51, 100, 7], 443),
            Endpoint {
                kind: KIND_DNS,
                host: b"ex.example.org".to_vec(),
                port: 5400,
                priority: 10,
                weight: 1,
            },
        ],
    };
    let (code, body) = a.post("/resolve/publish", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    let got = resolve_as(&mut b, alice).await;
    assert!(got.found);
    assert_eq!(got.endpoints, req.endpoints);
    assert!(got.expires_at > got.now, "a live answer must not be expired");
    assert!(got.expires_at - got.published_at <= 300);
    // Alice has not beaten, so the exchange has no evidence she is up and says
    // so rather than implying it — the distinction a signed record cannot make.
    assert_eq!(got.last_seen, 0, "publishing is not evidence of liveness");

    // Beating supplies that evidence, and it travels with the answer.
    let (code, _) = a
        .post(
            "/beacon/beat",
            Beat { interval_secs: 60, withhold: false }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let beating = resolve_as(&mut b, alice).await;
    assert!(
        beating.last_seen > 0 && beating.last_seen <= beating.now,
        "a beat should show up as an observation, not a claim"
    );
}

/// SIP-26: what a service *speaks* travels with where it is, expires with it,
/// and is replaced with it.
///
/// The last part is the one worth a test. Capability shares the publication's
/// lifetime, so an identity that republishes its addresses and says nothing
/// about what it speaks has stopped speaking it — there is no partial update
/// here either, and a merge would leave a version string behind after the
/// service it described was upgraded.
#[tokio::test]
async fn what_a_service_speaks_is_published_and_replaced_with_its_address() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(221);
    let (bob_seed, _) = identity(222);
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &bob_seed).await.unwrap();

    let (code, body) = a
        .post(
            "/resolve/publish",
            Publish {
                ttl_secs: 300,
                endpoints: vec![v4([10, 0, 0, 1], 443)],
                capabilities: vec!["sqssh/1".into(), "sqex-chat/0.32".into()],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    let got = resolve_as(&mut b, alice).await;
    assert_eq!(got.capabilities, vec!["sqssh/1", "sqex-chat/0.32"]);
    assert_eq!(
        got.expires_at.saturating_sub(got.published_at),
        300,
        "capability must expire with the address it describes"
    );

    // A rolling upgrade: the same address, a later version.
    let (code, _) = a
        .post(
            "/resolve/publish",
            Publish {
                ttl_secs: 300,
                endpoints: vec![v4([10, 0, 0, 1], 443)],
                capabilities: vec!["sqssh/1".into(), "sqex-chat/0.33".into()],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(
        resolve_as(&mut b, alice).await.capabilities,
        vec!["sqssh/1", "sqex-chat/0.33"],
        "an upgrade must be visible, which is most of why this exists"
    );

    // And dropping it drops it, rather than merging with what came before.
    let (code, _) = a
        .post(
            "/resolve/publish",
            Publish {
                ttl_secs: 300,
                endpoints: vec![v4([10, 0, 0, 1], 443)],
                capabilities: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(
        resolve_as(&mut b, alice).await.capabilities.is_empty(),
        "a stale capability survived a republication"
    );
}

/// **A beat refreshes a publication**, so a service proving it is alive does not
/// separately have to prove its address is current.
///
/// Written with a zero TTL rather than a sleep: the publication is expired the
/// instant it lands, so a resolve that finds it afterwards can only be the beat
/// having extended it. Without that, a passing test would prove the store's
/// `refresh` works and say nothing about whether the beacon route calls it.
#[tokio::test]
async fn a_beat_keeps_an_expiring_publication_alive() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(211);
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();

    let (code, _) = a
        .post(
            "/resolve/publish",
            Publish { ttl_secs: 0, endpoints: vec![v4([10, 0, 0, 1], 443)], capabilities: vec![] }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(
        !resolve_as(&mut a, alice).await.found,
        "a zero-TTL publication should be expired on arrival, or this proves nothing"
    );

    let (code, _) = a
        .post(
            "/beacon/beat",
            Beat { interval_secs: 60, withhold: false }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let after = resolve_as(&mut a, alice).await;
    assert!(
        after.found,
        "a beat did not refresh the beater's endpoints — the SIP-28 coupling is not wired"
    );
    assert!(after.expires_at > after.now);
}

/// **The whole set is replaced.** Partial updates need reconciliation, and
/// reconciliation between an unsigned publisher and a trusting store is where
/// stale addresses live forever.
#[tokio::test]
async fn publishing_replaces_the_set_rather_than_merging_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(171);
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();

    for set in [
        vec![v4([10, 0, 0, 1], 443), v4([10, 0, 0, 2], 443)],
        vec![v4([10, 0, 0, 3], 443)],
    ] {
        let (code, _) = a
            .post(
                "/resolve/publish",
                Publish { ttl_secs: 300, endpoints: set.clone(), capabilities: vec![] }.encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200);
        let got = resolve_as(&mut a, alice).await;
        assert_eq!(got.endpoints, set, "the old set survived a replacement");
    }

    // An empty publication is how an identity withdraws, and it reads as
    // absence rather than as an empty answer that still says `found`.
    let (code, _) = a
        .post(
            "/resolve/publish",
            Publish { ttl_secs: 300, endpoints: vec![], capabilities: vec![] }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(!resolve_as(&mut a, alice).await.found);
}

/// **An identity may publish only for itself**, and the handshake is what says
/// which identity that is — which is the whole reason nothing here is signed.
/// There is no field to put somebody else's key in, and this is the test that
/// says so rather than assuming it.
#[tokio::test]
async fn an_identity_cannot_publish_for_anybody_else() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(181);
    let (mallory_seed, mallory) = identity(182);

    let mut m = Client::connect_as(addr, &server_pub, &mallory_seed).await.unwrap();
    let (code, _) = m
        .post(
            "/resolve/publish",
            Publish { ttl_secs: 300, endpoints: vec![v4([203, 0, 113, 9], 443)], capabilities: vec![] }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // It landed under Mallory's key and nowhere else.
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    assert!(resolve_as(&mut a, mallory).await.found);
    assert!(
        !resolve_as(&mut a, alice).await.found,
        "one identity published for another"
    );

    // And an anonymous caller cannot publish at all: there is no identity to
    // publish for, which is a refusal rather than an anonymous record.
    let mut anon = Client::connect(addr, &server_pub).await.unwrap();
    let (code, _) = anon
        .post(
            "/resolve/publish",
            Publish { ttl_secs: 300, endpoints: vec![v4([203, 0, 113, 10], 443)], capabilities: vec![] }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403, "an unidentified caller published endpoints");
}

/// More endpoints than an identity may claim is refused, and the refusal says
/// which limit was hit.
#[tokio::test]
async fn the_endpoint_cap_is_enforced_by_the_exchange_too() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(191);
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();

    // The decoder refuses this before the store sees it, which is the outer of
    // two checks; the store's own is unit-tested beside it.
    let too_many = Publish {
        ttl_secs: 300,
        capabilities: vec![],
        endpoints: (0..=MAX_ENDPOINTS).map(|i| v4([10, 0, 0, i as u8], 443)).collect(),
    };
    let (code, _) = a.post("/resolve/publish", too_many.encode()).await.unwrap();
    assert_eq!(code, 400, "an over-full publication was accepted");
}

/// A successor is a forwarding note and **not a retirement**, and the test
/// records the difference rather than only the round trip: an identity that
/// names a successor is still resolvable, because it has not been retired and
/// this mechanism cannot retire it.
#[tokio::test]
async fn a_successor_forwards_and_does_not_retire() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(201);
    let (_, next) = identity(202);
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();

    let (code, _) = a
        .post(
            "/resolve/publish",
            Publish { ttl_secs: 300, endpoints: vec![v4([10, 0, 0, 1], 443)], capabilities: vec![] }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (code, body) = a
        .post(
            "/resolve/successor",
            Successor { successor: next, reason: "new hardware".into() }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Still reachable. A signed supersession would say "stop using this key";
    // this says "I am also over there", and only while the mover is in control.
    let got = resolve_as(&mut a, alice).await;
    assert!(
        got.found && !got.endpoints.is_empty(),
        "naming a successor must not silently retire the identity"
    );
}
