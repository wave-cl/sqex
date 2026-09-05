//! SIP-36: ringing every one of somebody's devices, and stopping them all.
//!
//! The document exists for two delivery rules and they are what is checked
//! here. Everything else it defines — the invitation, the record, the media —
//! is SIP-19, SIP-16 and SIP-13 doing what they already did.
//!
//! **These tests are untestable with one device per account.** SIP-22 makes an
//! account with no registered device its own device, so a single-client test
//! cannot tell "delivered per device" from "delivered per account": both hand
//! the signal to the one connection there is. Every test below links a second
//! device first, and the pair only start to differ from there.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{Entries, Fetch, SignalOut, Visibility};
use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqex_proto::device::Register;
use sqex_proto::message::{RING_ACCEPTED, RING_RINGING, SIGNAL_CALL_STATE, SIGNAL_TYPING, Signal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Link `device` to `account`, so that the two keys actually differ and the
/// per-device rules have something to be per.
async fn enrol(c: &mut Client, account_seed: &[u8; 32], device: &PubKey) {
    let n = now();
    let credential = Credential::issue(account_seed, device, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let (code, body) = c
        .post("/device/register", Register { credential }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn ring(c: &mut Client, channel: [u8; 32], device: PubKey, target: u64, state: u8) {
    let body = Signal::CallState {
        target,
        state,
        device,
    }
    .encode();
    let (code, said) = c
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind: SIGNAL_CALL_STATE,
                body,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&said));
}

/// What this connection collects. A fetch drains signals for the caller, and
/// SIP-36 changes who "the caller" means for one kind.
async fn collect(c: &mut Client, channel: [u8; 32]) -> Vec<Signalled> {
    let req = Fetch {
        channel,
        since: u64::MAX - 1,
        wait_secs: 0,
        receipts: false,
    };
    let (code, body) = c.post("/channel/fetch", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Entries::decode(&body, false).unwrap().signals
}

use sqex_proto::channel::Signalled;

/// **Rule 1: a ring reaches every one of a person's devices.**
///
/// SIP-22 gives somebody up to eight; a signal delivered at most once per
/// account rings one of their phones and leaves the rest silent, and no
/// client-side arrangement can recover a message the exchange handed
/// elsewhere.
///
/// The control is in the same test: a typing signal, sent the same way over the
/// same two connections, is still delivered once — because SIP-36 says an
/// exchange MUST NOT apply these rules to kind 0x01, and a change that leaked
/// into typing would be a change to SIP-16.
#[tokio::test]
async fn a_ring_reaches_every_device_and_typing_still_reaches_one() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(61);
    let (phone_seed, phone) = identity(62);
    let (laptop_seed, laptop) = identity(63);
    let (caller_seed, caller_key) = identity(64);
    let channel = [61u8; 32];

    // Alice's two devices, both linked to her account.
    let mut a1 = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    let mut a2 = Client::connect_as(addr, &server_pub, &laptop_seed)
        .await
        .unwrap();
    enrol(&mut a1, &alice_seed, &phone).await;
    enrol(&mut a2, &alice_seed, &laptop).await;

    // And somebody to call her.
    let mut b = Client::connect_as(addr, &server_pub, &caller_seed)
        .await
        .unwrap();
    let bs = Signer::new(caller_seed, caller_key, server_pub);
    let mut bchain = Chain::default();
    let req = bs.create_chained(
        &mut bchain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![],
    );
    let (code, body) = b.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Alice joins from one device; the account is what is a member.
    let joining = Signer::new(phone_seed, phone, server_pub)
        .for_account(alice)
        .action_outside(
            channel,
            instance_for(channel, 0),
            sqex_proto::channel::EVENT_JOINED,
            &alice,
            &[],
            0,
            sqex_proto::entry_sig::GENESIS,
        );
    let (code, body) = a1
        .post(
            "/channel/join",
            sqex_proto::channel::ByChannelSigned {
                channel,
                action: joining,
            }
            .encode(sqex_proto::channel::TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    ring(&mut b, channel, caller_key, 1, RING_RINGING).await;

    let on_phone = collect(&mut a1, channel).await;
    let on_laptop = collect(&mut a2, channel).await;
    assert_eq!(on_phone.len(), 1, "the phone did not ring");
    assert_eq!(on_laptop.len(), 1, "the laptop did not ring");
    assert_eq!(on_phone[0].kind, SIGNAL_CALL_STATE);
    assert_eq!(on_laptop[0].kind, SIGNAL_CALL_STATE);

    // Each device collects it once and no more.
    assert!(collect(&mut a1, channel).await.is_empty());

    // The control. Typing is unchanged: one of the two connections gets it,
    // and the other does not.
    let (code, _) = b
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind: SIGNAL_TYPING,
                body: Signal::Typing(true).encode(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let typed = collect(&mut a1, channel).await.len() + collect(&mut a2, channel).await.len();
    assert_eq!(typed, 1, "typing must stay at most once per account");
}

/// **Rule 2: the ring goes back to the sender's own other devices, and never
/// to the device that sent it.**
///
/// This is how the others stop when one answers. It is a deliberate exception
/// to SIP-30's rule that an account is not told about its own actions, and that
/// rule's justification is what shows it to be an exception rather than a
/// contradiction: a client does not need telling that its own keyboard is in
/// use, and a device very much does need telling that its user answered
/// somewhere else.
#[tokio::test]
async fn accepting_on_one_device_reaches_the_others_and_not_itself() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(71);
    let (phone_seed, phone) = identity(72);
    let (laptop_seed, laptop) = identity(73);
    let channel = [71u8; 32];

    let mut a1 = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    let mut a2 = Client::connect_as(addr, &server_pub, &laptop_seed)
        .await
        .unwrap();
    enrol(&mut a1, &alice_seed, &phone).await;
    enrol(&mut a2, &alice_seed, &laptop).await;

    let s = Signer::new(phone_seed, phone, server_pub).for_account(alice);
    let mut chain = Chain::default();
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![],
    );
    let (code, body) = a1.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // The phone answers.
    ring(&mut a1, channel, phone, 1, RING_ACCEPTED).await;

    let on_laptop = collect(&mut a2, channel).await;
    assert_eq!(
        on_laptop.len(),
        1,
        "the sibling device was not told to stop"
    );
    assert_eq!(on_laptop[0].kind, SIGNAL_CALL_STATE);
    assert_eq!(
        on_laptop[0].account, alice,
        "the exchange reports the account it observed"
    );

    let back_on_phone = collect(&mut a1, channel).await;
    assert!(
        back_on_phone.is_empty(),
        "the device that answered must not be told it answered"
    );
}

/// The exclusion is on the device the **exchange observed**, not on the one the
/// signal's body names.
///
/// A client naming a sibling's key could otherwise suppress that sibling's
/// ring, which is exactly the class of claim SIP-16 says is not a fact: an
/// entry's device is "the exchange's observation of the connection that
/// posted". The body's field stays, because the recipients need to know which
/// device this is about; it just decides nothing about routing.
#[tokio::test]
async fn the_device_a_signal_names_does_not_decide_where_it_goes() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(81);
    let (phone_seed, phone) = identity(82);
    let (laptop_seed, laptop) = identity(83);
    let channel = [81u8; 32];

    let mut a1 = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    let mut a2 = Client::connect_as(addr, &server_pub, &laptop_seed)
        .await
        .unwrap();
    enrol(&mut a1, &alice_seed, &phone).await;
    enrol(&mut a2, &alice_seed, &laptop).await;

    let s = Signer::new(phone_seed, phone, server_pub).for_account(alice);
    let mut chain = Chain::default();
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![],
    );
    let (code, _) = a1.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200);

    // The phone signals, but names the laptop — the suppression attempt.
    ring(&mut a1, channel, laptop, 1, RING_ACCEPTED).await;

    let on_laptop = collect(&mut a2, channel).await;
    assert_eq!(
        on_laptop.len(),
        1,
        "a device named in somebody else's signal must still be reached"
    );
    assert!(
        collect(&mut a1, channel).await.is_empty(),
        "the sending device is still the one excluded"
    );
}
