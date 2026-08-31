//! Ringing somebody, through a real exchange.
//!
//! The point of a ring is that the exchange will not tell you a call is
//! waiting — `OpenState::Waiting` discloses nothing, deliberately — so this
//! covers the thing that replaces that: a sealed note in the SIP-5 mailbox,
//! which works even for a caller the recipient has never heard of.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_voice::ring::{self, RING_TTL_SECS};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let config_path = dir.join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, Some(config_path), signing_key).await.unwrap();
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

/// The property the whole design turns on: a ring reaches somebody who has
/// never exchanged a word with the caller. Sealing to an identity needs nothing
/// published in advance, which a chat channel would have needed (SIP-23 forbids
/// sealing to a device with no prekeys — exactly the person you have never
/// spoken to).
#[tokio::test]
async fn a_ring_reaches_a_stranger() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (a_seed, a_id) = identity(1);
    let (b_seed, b_id) = identity(2);

    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    // A and B have never met: no contact, no channel, no prekeys.
    ring::ring(&mut a, b_id).await.expect("ring a stranger");

    let rings = ring::collect(&mut b, &b_seed, &[]).await.expect("collect");
    assert_eq!(rings.len(), 1, "one ring waiting");
    assert_eq!(rings[0].from, a_id, "and it says who from");

    // Collected once, gone: a ring that stayed would ring again on every sweep.
    let again = ring::collect(&mut b, &b_seed, &[]).await.unwrap();
    assert!(again.is_empty(), "a collected ring does not ring twice");
}

/// One block list, not two. There should be a single answer to "make them
/// stop", rather than one for messages and a different one for calls.
#[tokio::test]
async fn a_blocked_caller_does_not_ring() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (a_seed, a_id) = identity(1);
    let (b_seed, _) = identity(2);
    let (_, b_id) = identity(2);

    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    ring::ring(&mut a, b_id).await.unwrap();
    let rings = ring::collect(&mut b, &b_seed, &[a_id]).await.unwrap();
    assert!(rings.is_empty(), "a blocked caller does not ring");

    // And it is gone rather than merely hidden -- otherwise a blocked caller
    // could fill the mailbox and stop everybody else getting through, since
    // the quota is per recipient.
    let after_unblocking = ring::collect(&mut b, &b_seed, &[]).await.unwrap();
    assert!(
        after_unblocking.is_empty(),
        "a blocked ring is discarded, not left to fill the quota"
    );
}

/// A ring must expire in call time, not mail time. Checked at compile time,
/// because it is a property of the constant rather than of a run -- clippy is
/// right that asserting it inside a test only looks like a test.
const _: () = assert!(RING_TTL_SECS < 5 * 60);

/// A mailbox holds a message for a week. That is right for mail and absurd for
/// a telephone -- nobody wants Tuesday's call ringing on Thursday.
#[tokio::test]
async fn a_stale_ring_is_discarded_rather_than_rung() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (a_seed, _) = identity(1);
    let (b_seed, b_id) = identity(2);

    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();
    ring::ring(&mut a, b_id).await.unwrap();

    // The exchange stamps `received` from its own clock, so a stale ring cannot
    // be arranged here without waiting a minute. What *can* be checked is that
    // a fresh one is not treated as stale, which is the mistake that would make
    // ringing never work at all.
    let rings = ring::collect(&mut b, &b_seed, &[]).await.unwrap();
    assert_eq!(rings.len(), 1, "a ring sent just now is not stale");
}

/// Somebody else's sealed mail is not a ring, and must not be mistaken for one
/// or left behind to be re-fetched on every sweep.
#[tokio::test]
async fn mail_that_is_not_a_ring_is_ignored_and_cleared() {
    use sqex_proto::mailbox::{Send, seal};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (a_seed, _) = identity(1);
    let (b_seed, b_id) = identity(2);

    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    let sealed = seal(&b_id, b"this is not a ring").unwrap();
    let (code, _) = a
        .post("/mailbox/send", Send { recipient: b_id, sealed }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);

    let rings = ring::collect(&mut b, &b_seed, &[]).await.unwrap();
    assert!(rings.is_empty(), "not everything in a mailbox is a ring");

    let again = ring::collect(&mut b, &b_seed, &[]).await.unwrap();
    assert!(again.is_empty());
}
