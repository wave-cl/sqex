//! SIP-51: waking a device for a sibling's session.
//!
//! A SIP-12 open discloses nothing about a pending open -- deliberately, so
//! that an open cannot be used to test whether a key is present. This is the
//! one exception: between two devices of the same account the disclosure is
//! empty, because the registry already lists them both and the account signed
//! both credentials. The tests below are that bound as much as they are the
//! feature; a stranger's open must stay as silent as it was.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqex_proto::device::Register as RegisterDevice;
use sqex_proto::events::{Event as WireEvent, Framer, Subscribe};
use sqex_proto::session::Open;
use sqex_proto::wake::{Register as RegisterWake, WAKE_BODY};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::wake_flow::{Distributor, distributor, wakes_within};

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         wake_loopback = true\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, None, signing_key).await.unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
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

/// An account signs a credential for a device, and that device registers it.
async fn enrol(c: &mut Client, account_seed: &[u8; 32], device: &PubKey) {
    let n = now();
    let credential = Credential::issue(account_seed, device, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let (code, body) = c
        .post("/device/register", RegisterDevice { credential }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn open_toward(c: &mut Client, peer: PubKey, ephemeral: [u8; 32]) {
    let (code, body) = c
        .post("/session/open", Open { peer, ephemeral }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

/// The device keys named in every `Sibling` event a stream carries within
/// `secs`, however many arrive. Not "the first one": a test that stops at one
/// cannot tell one event from three, and "once per open" is the rule most of
/// this file is about.
async fn siblings_named(stream: &mut sqnr::Stream, secs: u64) -> Vec<PubKey> {
    let mut framer = Framer::new();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(secs), async {
        while let Ok(Some(chunk)) = stream.next().await {
            for e in framer.feed(&chunk).unwrap() {
                if let WireEvent::Sibling { device } = e {
                    out.push(device);
                }
            }
        }
    })
    .await;
    out
}

/// A stream held by `seed`, as its own device.
///
/// Its **registration must already stand**: a subscription is filed under the
/// account the connecting key resolved to at the moment it opened, and a
/// device that enrols afterwards holds a stream filed under itself. Nothing
/// addressed to the account -- this event included -- reaches it until it
/// subscribes again.
async fn listening(
    addr: SocketAddr,
    server_pub: [u8; 32],
    seed: &[u8; 32],
) -> (Client, sqnr::Stream) {
    let c = Client::connect_as(addr, &server_pub, seed).await.unwrap();
    let stream = c
        .stream(
            "POST",
            "/events",
            Subscribe {
                version: sqex_proto::events::VERSION,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);
    (c, stream)
}

/// A desktop opens toward the phone, and the phone -- listening -- is told
/// which of its siblings wants it. A stranger doing the same is not announced,
/// and that is the control the feature is bounded by.
#[tokio::test]
async fn a_sibling_is_named_and_a_stranger_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (account_seed, _account) = identity(51);
    let (desk_seed, desk) = identity(52);
    let (phone_seed, phone) = identity(53);
    let (bob_seed, _bob) = identity(54);

    let mut d = Client::connect_as(addr, &server_pub, &desk_seed)
        .await
        .unwrap();
    enrol(&mut d, &account_seed, &desk).await;
    let mut p = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    enrol(&mut p, &account_seed, &phone).await;
    drop(p);
    let (_p, mut stream) = listening(addr, server_pub, &phone_seed).await;

    // A stranger first, so a `Sibling` that arrives later cannot be his.
    //
    // This half of the bound holds even with the sibling check taken out,
    // because a stream is filed under the account and an outsider's event
    // would be published under his own. Worth asserting anyway -- it is the
    // property, not the mechanism -- but the wake is the path with nothing
    // structural behind it, and `a_strangers_open_wakes_nobody` is where the
    // check is actually measured.
    let mut b = Client::connect_as(addr, &server_pub, &bob_seed)
        .await
        .unwrap();
    open_toward(&mut b, phone, [64u8; 32]).await;
    assert!(
        siblings_named(&mut stream, 1).await.is_empty(),
        "an open from outside the account was announced -- SIP-12's silence is broken for every key"
    );

    open_toward(&mut d, phone, [52u8; 32]).await;
    assert_eq!(
        siblings_named(&mut stream, 5).await,
        vec![desk],
        "the phone was not told which sibling wants it"
    );
}

/// A desktop renews its open every few seconds. The phone hears about it
/// once. An open carrying a *new* ephemeral is a new open -- the client
/// restarted -- and is announced again.
#[tokio::test]
async fn a_renewed_open_is_announced_once_and_a_restarted_one_again() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (account_seed, _account) = identity(61);
    let (desk_seed, desk) = identity(62);
    let (phone_seed, phone) = identity(63);

    let mut d = Client::connect_as(addr, &server_pub, &desk_seed)
        .await
        .unwrap();
    enrol(&mut d, &account_seed, &desk).await;
    let mut p = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    enrol(&mut p, &account_seed, &phone).await;
    drop(p);
    let (_p, mut stream) = listening(addr, server_pub, &phone_seed).await;

    for _ in 0..3 {
        open_toward(&mut d, phone, [62u8; 32]).await;
    }
    assert_eq!(
        siblings_named(&mut stream, 2).await,
        vec![desk],
        "a renewed open woke the phone again -- a desktop renewing every ten seconds would never let it sleep"
    );

    open_toward(&mut d, phone, [99u8; 32]).await;
    assert_eq!(
        siblings_named(&mut stream, 5).await,
        vec![desk],
        "an open with a fresh ephemeral -- a restarted client -- was taken for a renewal"
    );
}

/// The phone is asleep: no stream, a wake registration. It is woken for the
/// event, and its sibling the desktop -- registered too -- is not, because
/// the session is not with the desktop.
#[tokio::test]
async fn the_named_device_is_woken_and_its_siblings_are_not() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (account_seed, _account) = identity(71);
    let (desk_seed, desk) = identity(72);
    let (phone_seed, phone) = identity(73);

    let mut d = Client::connect_as(addr, &server_pub, &desk_seed)
        .await
        .unwrap();
    enrol(&mut d, &account_seed, &desk).await;
    let mut p = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    enrol(&mut p, &account_seed, &phone).await;

    let to_phone = distributor(200).await;
    let to_desk = distributor(200).await;
    register(&mut p, &to_phone).await;
    register(&mut d, &to_desk).await;

    open_toward(&mut d, phone, [72u8; 32]).await;
    assert!(
        wakes_within(&to_phone, 1, 5).await,
        "the phone was not woken for its sibling's open"
    );
    assert!(
        !wakes_within(&to_desk, 1, 1).await,
        "the opener's own device was woken -- the event went to the account, not the device"
    );
    assert_eq!(
        to_phone.bodies(),
        vec![WAKE_BODY.to_vec()],
        "the wake said something, or arrived twice"
    );
}

/// An account key and a device registered to it are siblings: SIP-51 names
/// that case, and a desktop still running as the account itself is the
/// commonest way to meet it.
#[tokio::test]
async fn an_account_and_its_own_device_are_siblings() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (account_seed, account) = identity(81);
    let (phone_seed, phone) = identity(82);

    let mut a = Client::connect_as(addr, &server_pub, &account_seed)
        .await
        .unwrap();
    let mut p = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    enrol(&mut p, &account_seed, &phone).await;
    drop(p);
    let (_p, mut stream) = listening(addr, server_pub, &phone_seed).await;

    open_toward(&mut a, phone, [81u8; 32]).await;
    assert_eq!(
        siblings_named(&mut stream, 5).await,
        vec![account],
        "the account opening toward its own device was not announced"
    );
    drop(a);
}

async fn register(c: &mut Client, d: &Distributor) {
    let (code, body) = c
        .post(
            "/wake/register",
            RegisterWake {
                ttl: 3600,
                quiet: false,
                endpoint: d.url.clone(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

/// The bound itself. A stranger opens toward a sleeping phone; nothing is
/// posted to it.
///
/// This is the test the feature has to survive. The wake goes to the device by
/// key -- it does not pass through the account, and so nothing but the sibling
/// check stands between an `Open` and somebody else's phone buzzing. Without
/// it, an `Open` is a presence probe with a notification attached: exactly what
/// SIP-12 refuses to be, and the reason it discloses nothing about a pending
/// open in the first place.
#[tokio::test]
async fn a_strangers_open_wakes_nobody() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (account_seed, _account) = identity(91);
    let (phone_seed, phone) = identity(92);
    let (bob_seed, _bob) = identity(93);

    let mut p = Client::connect_as(addr, &server_pub, &phone_seed)
        .await
        .unwrap();
    enrol(&mut p, &account_seed, &phone).await;
    let to_phone = distributor(200).await;
    register(&mut p, &to_phone).await;
    // Asleep: registered, holding no stream.
    drop(p);

    let mut b = Client::connect_as(addr, &server_pub, &bob_seed)
        .await
        .unwrap();
    open_toward(&mut b, phone, [93u8; 32]).await;
    assert!(
        !wakes_within(&to_phone, 1, 3).await,
        "a stranger's open woke the phone -- an `Open` is now a presence probe that buzzes"
    );

    // And the same phone, woken by its own account, proves the registration
    // was live and this test was pointed at something.
    let mut a = Client::connect_as(addr, &server_pub, &account_seed)
        .await
        .unwrap();
    open_toward(&mut a, phone, [91u8; 32]).await;
    assert!(
        wakes_within(&to_phone, 1, 5).await,
        "nothing woke the phone at all -- the endpoint was dead and the assertion above was empty"
    );
}
