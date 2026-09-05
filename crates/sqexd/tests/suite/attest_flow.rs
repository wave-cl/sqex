//! SIP-27: what one identity says about another, over the wire.
//!
//! The exchange holds these and is not an authority over them. Every test here
//! is about that line: it checks a signature and refuses what does not verify;
//! it cannot check whether a claim is true, does not rank issuers, and reports
//! no number that means anything.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::attest::{
    Attestation, CLAIM_KNOWN_AS, CLAIM_OPERATES, CLAIM_REVOKES, Held, Query,
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

fn who(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn read(c: &mut Client, subject: PubKey, issuer: Option<PubKey>) -> Held {
    let (code, body) = c
        .post("/attest/read", Query { subject, issuer }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Held::decode(&body).unwrap()
}

/// **Anybody may lodge one**, because it carries its own proof — so who handed
/// it over establishes nothing, and requiring the issuer would mean an issuer
/// who has gone away can never be quoted again.
#[tokio::test]
async fn a_signed_statement_can_be_lodged_by_anyone_and_read_by_anyone() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = who(31);
    let (_, bob) = who(32);
    let (carol_seed, _) = who(33);

    let a = Attestation::sign(
        &alice_seed,
        &bob,
        CLAIM_OPERATES,
        b"ex.squic.org".to_vec(),
        now() - 1,
        now() + 3600,
    );

    // Carol lodges Alice's statement about Bob. Neither the subject nor the
    // issuer is on the connection.
    let mut c = Client::connect_as(addr, &server_pub, &carol_seed).await.unwrap();
    let (code, body) = c.post("/attest/lodge", a.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // And an anonymous reader can see it, because an attestation is meant to
    // travel.
    let mut anon = Client::connect(addr, &server_pub).await.unwrap();
    let held = read(&mut anon, bob, None).await;
    assert_eq!(held.attestations, vec![a.clone()]);
    // Verified by the reader, not taken from the exchange.
    assert_eq!(held.attestations[0].verify(held.now), Ok(()));
    assert_eq!(held.attestations[0].issuer, alice);
}

/// The exchange checks the signature and refuses what does not verify — the one
/// thing it *can* check. It cannot check whether a claim is true.
#[tokio::test]
async fn a_statement_nobody_signed_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = who(41);
    let (_, bob) = who(42);
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();

    let mut forged = Attestation::sign(
        &alice_seed,
        &bob,
        CLAIM_KNOWN_AS,
        b"Bob".to_vec(),
        now() - 1,
        now() + 3600,
    );
    forged.body = b"Somebody Else".to_vec();
    let (code, _) = a.post("/attest/lodge", forged.encode()).await.unwrap();
    assert_eq!(code, 401, "an unsigned claim was stored");

    // An identity vouching for itself establishes nothing, and without the rule
    // anybody could fill their own record.
    let (_, alice) = who(41);
    let selfie = Attestation::sign(
        &alice_seed,
        &alice,
        CLAIM_KNOWN_AS,
        b"trustworthy".to_vec(),
        now() - 1,
        now() + 3600,
    );
    let (code, _) = a.post("/attest/lodge", selfie.encode()).await.unwrap();
    assert_eq!(code, 401, "an identity vouched for itself");

    assert!(read(&mut a, bob, None).await.attestations.is_empty());
}

/// **Only attestations from issuers a consumer already trusts carry weight.**
/// The filter is what makes that expressible, and it is the ordinary case
/// rather than a refinement: a count measures how many keys somebody made.
#[tokio::test]
async fn a_reader_can_ask_about_one_issuer_and_ignore_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob) = who(52);
    let mut c = Client::connect(addr, &server_pub).await.unwrap();

    // A sybil: many identities, all vouching for Bob, all worthless together.
    let mut trusted = None;
    for i in 0..5u8 {
        let (seed, key) = who(160 + i);
        if i == 0 {
            trusted = Some(key);
        }
        let a = Attestation::sign(
            &seed,
            &bob,
            CLAIM_KNOWN_AS,
            format!("Bob {i}").into_bytes(),
            now() - 1,
            now() + 3600,
        );
        let (code, _) = c.post("/attest/lodge", a.encode()).await.unwrap();
        assert_eq!(code, 200);
    }
    let trusted = trusted.unwrap();

    let all = read(&mut c, bob, None).await;
    assert_eq!(all.attestations.len(), 5, "the exchange holds what it was given");

    let filtered = read(&mut c, bob, Some(trusted)).await;
    assert_eq!(filtered.attestations.len(), 1);
    assert_eq!(filtered.attestations[0].issuer, trusted);
    assert_eq!(filtered.attestations[0].body, b"Bob 0");
}

/// A withdrawal is a signed statement by the same issuer, and **only by that
/// issuer** — otherwise withdrawing would be a way to silence somebody.
///
/// It is kept rather than erased, so a reader arriving later sees that the
/// issuer withdrew rather than that the claim was never made.
#[tokio::test]
async fn only_the_issuer_can_withdraw_and_the_withdrawal_is_visible() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = who(61);
    let (mallory_seed, _) = who(62);
    let (_, bob) = who(63);
    let mut c = Client::connect(addr, &server_pub).await.unwrap();

    let a = Attestation::sign(
        &alice_seed,
        &bob,
        CLAIM_OPERATES,
        b"ex.example.org".to_vec(),
        now() - 1,
        now() + 3600,
    );
    let (code, _) = c.post("/attest/lodge", a.encode()).await.unwrap();
    assert_eq!(code, 200);

    // Mallory tries to withdraw Alice's statement.
    let theirs = Attestation::sign(
        &mallory_seed,
        &bob,
        CLAIM_REVOKES,
        a.digest().to_vec(),
        now() - 1,
        now() + 3600,
    );
    let (code, _) = c.post("/attest/lodge", theirs.encode()).await.unwrap();
    assert_eq!(code, 404, "somebody else withdrew a statement they did not make");
    assert_eq!(
        read(&mut c, bob, Some(alice)).await.attestations.len(),
        1,
        "the statement was removed by a stranger"
    );

    // Alice withdraws her own.
    let mine = Attestation::sign(
        &alice_seed,
        &bob,
        CLAIM_REVOKES,
        a.digest().to_vec(),
        now() - 1,
        now() + 3600,
    );
    let (code, body) = c.post("/attest/lodge", mine.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    let after = read(&mut c, bob, Some(alice)).await;
    assert!(
        !after.attestations.iter().any(|x| x.claim == CLAIM_OPERATES),
        "the withdrawn statement is still being served"
    );
    assert!(
        after.attestations.iter().any(|x| x.claim == CLAIM_REVOKES),
        "a reader arriving now cannot tell a withdrawal from a claim never made"
    );

    // A withdrawal naming nothing this exchange holds is refused, because it is
    // indistinguishable from one naming something the reader has not seen.
    let (code, _) = c
        .post(
            "/attest/lodge",
            Attestation::sign(
                &alice_seed,
                &bob,
                CLAIM_REVOKES,
                [9u8; 32].to_vec(),
                now() - 1,
                now() + 3600,
            )
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 404);
}

/// Lodging the same statement twice changes nothing, so a replay cannot inflate
/// a record — which matters exactly because a count is not evidence.
#[tokio::test]
async fn a_replayed_statement_does_not_accumulate() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = who(71);
    let (_, bob) = who(72);
    let mut c = Client::connect(addr, &server_pub).await.unwrap();

    let a = Attestation::sign(
        &alice_seed,
        &bob,
        CLAIM_KNOWN_AS,
        b"Bob".to_vec(),
        now() - 1,
        now() + 3600,
    );
    for _ in 0..5 {
        let (code, _) = c.post("/attest/lodge", a.encode()).await.unwrap();
        assert_eq!(code, 200);
    }
    assert_eq!(read(&mut c, bob, None).await.attestations.len(), 1);
}

/// An expired statement is not served. **Expiry is the only guarantee this
/// design offers**, since a withdrawal is a statement a reader may never see.
#[tokio::test]
async fn an_expired_statement_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = who(81);
    let (_, bob) = who(82);
    let mut c = Client::connect(addr, &server_pub).await.unwrap();

    // Lodged while valid, with a window that closes a second later.
    let a = Attestation::sign(
        &alice_seed,
        &bob,
        CLAIM_KNOWN_AS,
        b"Bob".to_vec(),
        now() - 2,
        now() + 1,
    );
    let (code, _) = c.post("/attest/lodge", a.encode()).await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(read(&mut c, bob, None).await.attestations.len(), 1);

    // One whose window has already closed is refused outright rather than
    // stored and filtered later.
    let stale = Attestation::sign(
        &alice_seed,
        &bob,
        CLAIM_KNOWN_AS,
        b"Bob, once".to_vec(),
        now() - 100,
        now() - 50,
    );
    let (code, _) = c.post("/attest/lodge", stale.encode()).await.unwrap();
    assert_eq!(code, 401, "an expired statement was accepted");
}
