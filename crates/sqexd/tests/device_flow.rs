//! End-to-end for SIP-20 credentials and SIP-22's registry over real HTTP/3.
//!
//! The case these exist for is a person with two clients, and the case they are
//! judged by is a stolen one.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{Create, Entries, Fetch, Visibility};
use sqex_proto::credential::{Credential, Revocation, SCOPE_CHAT};
use sqex_proto::device::{Devices, ListDevices, Register, Revoke};
use sqex_proto::refusal::{Code, Refusal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

mod common;
use common::{Chain, Signer, instance_for};

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

fn keys(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn connect(addr: SocketAddr, pubkey: [u8; 32], seed: [u8; 32]) -> Client {
    Client::connect_as(addr, &pubkey, &seed).await.unwrap()
}

/// An account signs a credential for a device, and that device registers
/// itself. The account never connects — it may be a key that cannot.
async fn enrol(
    c: &mut Client,
    account_seed: &[u8; 32],
    device: &PubKey,
    lifetime: u64,
) -> u16 {
    let n = now();
    let credential =
        Credential::issue(account_seed, device, SCOPE_CHAT, n - 1, n + lifetime).unwrap();
    let (code, _) = c
        .post("/device/register", Register { credential }.encode())
        .await
        .unwrap();
    code
}

async fn devices_of(c: &mut Client, account: &PubKey) -> Devices {
    let (code, body) = c
        .post("/device/list", ListDevices { account: *account }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Devices::decode(&body).unwrap()
}

fn public(signer: &Signer, channel: [u8; 32]) -> Create {
    signer.create(channel, instance_for(channel, 0), Visibility::Public, 3600, "shared", vec![])
}

/// Where a creator's chain stands after SIP-32's `created` event.
///
/// The create spends position 0, so anything the creator signs next follows on
/// from it — starting again from zero would be a fork.
fn created_head(signer: &Signer, channel: [u8; 32]) -> [u8; 32] {
    let mut chain = Chain::default();
    let _ = signer.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "shared",
        vec![],
    );
    chain.head
}

#[tokio::test]
async fn one_person_two_devices_share_a_membership() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, account) = keys(21);
    let (desktop_seed, desktop) = keys(22);
    let (phone_seed, phone) = keys(23);
    let channel = [1u8; 32];

    let mut d = connect(addr, pubkey, desktop_seed).await;
    let mut p = connect(addr, pubkey, phone_seed).await;
    assert_eq!(enrol(&mut d, &account_seed, &desktop, 3600).await, 200);
    // The phone is enrolled by the desktop, before it has ever connected —
    // which is what removes the need for any route to be reachable by a peer
    // the exchange will not otherwise serve.
    assert_eq!(enrol(&mut d, &account_seed, &phone, 3600).await, 200);

    let listed = devices_of(&mut d, &account).await;
    assert_eq!(listed.devices.len(), 2);

    // The desktop joins; the phone is in the channel without doing anything,
    // because membership is the account's.
    // Two devices of one account, and the SIP-31 signature is the device's
    // while the entry's account is the account's. This is the case where the
    // two keys actually differ — SIP-22 makes an account with no registered
    // device its own device, and every device-versus-account rule is untestable
    // until somebody links a second client.
    let desk = Signer::new(desktop_seed, desktop, pubkey).for_account(account);
    let hand = Signer::new(phone_seed, phone, pubkey).for_account(account);

    let (code, body) = d.post("/channel/create", public(&desk, channel).encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // A chain each: the position is per device, so both start at zero and
    // neither treads on the other.
    // The desktop created the channel, so SIP-32's `created` already took its
    // position 0. The phone created nothing and starts at 0 — which is the
    // point: the chains are per device.
    let mut desk_chain = Chain { seq: 1, head: created_head(&desk, channel) };
    let mut hand_chain = Chain::default();
    let post = |signer: &Signer, chain: &mut Chain, body: &[u8], seq: u64| {
        signer
            .post_chained(chain, channel, instance_for(channel, 0), 0, seq, body.to_vec())
            .encode()
    };
    assert_eq!(
        d.post("/channel/post", post(&desk, &mut desk_chain, b"from the desktop", 0)).await.unwrap().0,
        200
    );
    assert_eq!(
        p.post("/channel/post", post(&hand, &mut hand_chain, b"from the phone", 0)).await.unwrap().0,
        200
    );

    let (_, body) = p
        .post("/channel/fetch", Fetch { channel, since: 0, wait_secs: 0 }.encode())
        .await
        .unwrap();
    let seen = Entries::decode(&body).unwrap();
    // Three: SIP-32's `created`, then a message from each client.
    assert_eq!(seen.entries.len(), 3);

    // Both messages are attributed to the person and distinguished by client.
    let said: Vec<_> = seen
        .entries
        .iter()
        .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .collect();
    assert_eq!(said.len(), 2);
    assert!(said.iter().all(|e| e.account == account));
    assert_eq!(said[0].device, desktop);
    assert_eq!(said[1].device, phone);
    // Both counted from zero and did not collide, which is the whole reason
    // the subkey is per device.
    assert!(seen.entries.iter().all(|e| e.msg_seq == 0));
}

#[tokio::test]
async fn a_revoked_device_cannot_re_register_with_the_credential_it_still_holds() {
    // The case the registry exists for. Everything needed to register is in
    // the stolen phone's storage, so a revocation that only deleted a mapping
    // would be undone by one request from whoever has the hardware.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, account) = keys(31);
    let (desktop_seed, desktop) = keys(32);
    let (phone_seed, phone) = keys(33);

    let mut d = connect(addr, pubkey, desktop_seed).await;
    let mut p = connect(addr, pubkey, phone_seed).await;
    assert_eq!(enrol(&mut d, &account_seed, &desktop, 3600).await, 200);
    assert_eq!(enrol(&mut d, &account_seed, &phone, 3600).await, 200);

    // The phone is lost. The desktop, registered first, may revoke it.
    let (code, _) = d
        .post("/device/revoke", Revoke { device: phone, revocation: None }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(devices_of(&mut d, &account).await.devices.len(), 1);

    // The thief replays the credential that is sitting on the device.
    let n = now();
    let stolen = Credential::issue(&account_seed, &phone, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let (code, body) = p
        .post("/device/register", Register { credential: stolen }.encode())
        .await
        .unwrap();
    assert_eq!(code, 409, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::Revoked);
    assert_eq!(devices_of(&mut d, &account).await.devices.len(), 1);

    // A found phone comes back — but only with a credential the ACCOUNT signed
    // after the revocation, which is the one thing not on the phone. It has to
    // be dated later than the revocation and not later than now, so wait for
    // the clock to move.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let later = now();
    let fresh = Credential::issue(&account_seed, &phone, SCOPE_CHAT, later, later + 7200).unwrap();
    let (code, _) = p
        .post("/device/register", Register { credential: fresh }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(devices_of(&mut d, &account).await.devices.len(), 2);
}

#[tokio::test]
async fn a_junior_device_cannot_evict_its_senior() {
    // Otherwise somebody who steals a freshly linked laptop uses it to remove
    // the phone that would have removed it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, _) = keys(41);
    let (first_seed, first) = keys(42);
    let (second_seed, second) = keys(43);

    let mut a = connect(addr, pubkey, first_seed).await;
    let mut b = connect(addr, pubkey, second_seed).await;
    assert_eq!(enrol(&mut a, &account_seed, &first, 3600).await, 200);
    // A second later, so the ordering is unambiguous.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(enrol(&mut a, &account_seed, &second, 3600).await, 200);

    let (code, _) = b
        .post("/device/revoke", Revoke { device: first, revocation: None }.encode())
        .await
        .unwrap();
    assert_eq!(code, 403, "the newer device may not evict the older");

    // It may always sign itself out.
    let (code, _) = b
        .post("/device/revoke", Revoke { device: second, revocation: None }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
}

#[tokio::test]
async fn a_device_belongs_to_exactly_one_account() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (one_seed, _) = keys(51);
    let (two_seed, _) = keys(52);
    let (device_seed, device) = keys(53);

    let mut c = connect(addr, pubkey, device_seed).await;
    assert_eq!(enrol(&mut c, &one_seed, &device, 3600).await, 200);
    // A second account cannot claim it: a connection carrying that key would
    // otherwise have no defined answer to whose client it is.
    assert_eq!(enrol(&mut c, &two_seed, &device, 3600).await, 409);
}

#[tokio::test]
async fn a_credential_for_another_service_is_not_a_chat_device() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, _) = keys(61);
    let (device_seed, device) = keys(62);
    let mut c = connect(addr, pubkey, device_seed).await;

    let n = now();
    let wrong = Credential::issue(&account_seed, &device, "sqex-admin", n - 1, n + 3600).unwrap();
    let (code, body) = c
        .post("/device/register", Register { credential: wrong }.encode())
        .await
        .unwrap();
    assert_eq!(code, 401);
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::WrongScope);
}

#[tokio::test]
async fn a_stranger_cannot_enrol_a_device_onto_an_account() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, _) = keys(71);
    let (mine_seed, mine) = keys(72);
    let (other_seed, _) = keys(73);

    let mut m = connect(addr, pubkey, mine_seed).await;
    let mut o = connect(addr, pubkey, other_seed).await;
    assert_eq!(enrol(&mut m, &account_seed, &mine, 3600).await, 200);

    // A credential names `mine`, and somebody else presents it. The caller is
    // neither the delegate nor a device of that account.
    let n = now();
    let c = Credential::issue(&account_seed, &mine, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let (code, _) = o
        .post("/device/register", Register { credential: c }.encode())
        .await
        .unwrap();
    assert_eq!(code, 403);
}

#[tokio::test]
async fn an_expired_credential_stops_resolving() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, account) = keys(81);
    let (device_seed, device) = keys(82);
    let mut c = connect(addr, pubkey, device_seed).await;

    // Valid for one second.
    assert_eq!(enrol(&mut c, &account_seed, &device, 1).await, 200);
    assert_eq!(devices_of(&mut c, &account).await.devices.len(), 1);

    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    // A registration expires with its credential; there is no second lifetime
    // that could disagree with it.
    assert!(devices_of(&mut c, &account).await.devices.is_empty());
}

#[tokio::test]
async fn an_account_with_no_registered_devices_is_its_own_device() {
    // The ordinary single-client case, which must not require anybody to have
    // understood any of this.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alone_seed, alone) = keys(91);
    let channel = [9u8; 32];
    let mut c = connect(addr, pubkey, alone_seed).await;

    assert!(devices_of(&mut c, &alone).await.devices.is_empty());
    let solo = Signer::new(alone_seed, alone, pubkey);
    assert_eq!(c.post("/channel/create", public(&solo, channel).encode()).await.unwrap().0, 200);
    let (code, _) = c
        .post(
            "/channel/post",
            // Position 1: the create's `created` event took 0.
            solo.post_chained(
                &mut Chain { seq: 1, head: created_head(&solo, channel) },
                channel,
                instance_for(channel, 0),
                0,
                0,
                b"hello".to_vec(),
            )
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let (_, body) = c
        .post("/channel/fetch", Fetch { channel, since: 0, wait_secs: 0 }.encode())
        .await
        .unwrap();
    let seen = Entries::decode(&body).unwrap();
    // Entry 0 is SIP-32's `created`, which the exchange wrote and so carries
    // zeroes; the message is the member entry after it.
    let said = seen
        .entries
        .iter()
        .find(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .expect("no member entry");
    assert_eq!(said.account, alone);
    assert_eq!(said.device, alone, "its own device");
}

#[tokio::test]
async fn the_registry_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (account_seed, account) = keys(101);
    let (device_seed, device) = keys(102);

    let (addr, pubkey, first) = server_in(dir.path()).await;
    {
        let mut c = connect(addr, pubkey, device_seed).await;
        assert_eq!(enrol(&mut c, &account_seed, &device, 3600).await, 200);
    }
    first.abort();
    let _ = first.await;

    let (addr, pubkey, _second) = server_in(dir.path()).await;
    let mut c = connect(addr, pubkey, device_seed).await;
    // A device should not have to re-register because a server bounced.
    assert_eq!(devices_of(&mut c, &account).await.devices.len(), 1);
}

#[tokio::test]
async fn an_admission_request_answers_identically_whatever_it_decides() {
    // The rule the rest of SIP-24 exists to protect. This is the one route a
    // peer the exchange will not otherwise serve can reach, so a reply that
    // varied would let anybody probe which accounts a deployment admits.
    use sqex_proto::device::AdmissionRequest;

    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, _) = keys(151);
    let (device_seed, device) = keys(152);
    let (other_seed, _) = keys(153);
    let mut c = connect(addr, pubkey, device_seed).await;

    let n = now();
    let good = Credential::issue(&account_seed, &device, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let mut forged = good.clone();
    forged.signature[0] ^= 1;
    // A credential naming somebody else's device: forwarding one you found.
    let (_, elsewhere) = keys(154);
    let not_mine =
        Credential::issue(&account_seed, &elsewhere, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    // An account the exchange has never heard of.
    let (_, unknown_device) = keys(155);
    let unknown =
        Credential::issue(&other_seed, &unknown_device, SCOPE_CHAT, n - 1, n + 3600).unwrap();

    let mut lengths = Vec::new();
    for credential in [good.clone(), forged, not_mine, unknown] {
        let (code, body) = c
            .post(
                "/admission/request",
                AdmissionRequest {
                    credential,
                    label: "a laptop".into(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "every well-formed request is acknowledged");
        lengths.push(body.len());
    }
    assert!(
        lengths.windows(2).all(|w| w[0] == w[1]),
        "the reply must not vary with what the exchange decided: {lengths:?}"
    );

    // Asking again after being queued is also just an acknowledgement.
    let (code, _) = c
        .post(
            "/admission/request",
            AdmissionRequest {
                credential: good,
                label: "a laptop".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
}

#[tokio::test]
async fn a_malformed_request_is_still_a_malformed_request() {
    // "I do not know this" and "this is broken" are different facts, and the
    // constant reply covers the first, not the second.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (device_seed, _) = keys(161);
    let mut c = connect(addr, pubkey, device_seed).await;

    let (code, _) = c.post("/admission/request", vec![0x04, 0, 0]).await.unwrap();
    assert_eq!(code, 400);
}

#[tokio::test]
async fn the_account_may_revoke_a_device_it_never_registered_beside() {
    // SIP-22's Security considerations name the account key as the recovery
    // when somebody has lost their oldest device, and until this rule nothing
    // in its Specification granted it. Every path refused the account:
    // not_authorised while unregistered, and Senior if it registered itself
    // afterwards, being by then the junior of its own devices.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, account) = keys(51);
    let (laptop_seed, laptop) = keys(52);

    let mut l = connect(addr, pubkey, laptop_seed).await;
    assert_eq!(enrol(&mut l, &account_seed, &laptop, 3600).await, 200);
    assert_eq!(devices_of(&mut l, &account).await.devices.len(), 1);

    // The account has no device row of its own, and revokes anyway.
    let mut a = connect(addr, pubkey, account_seed).await;
    let (code, body) = a
        .post("/device/revoke", Revoke { device: laptop, revocation: None }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(devices_of(&mut a, &account).await.devices.is_empty());
}

#[tokio::test]
async fn the_account_is_exempt_from_seniority_and_nobody_else_is() {
    // The exemption is for the account a device belongs to. It must not have
    // widened the door for anyone else.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, account) = keys(61);
    let (first_seed, first) = keys(62);
    let (stranger_seed, stranger) = keys(63);

    let mut f = connect(addr, pubkey, first_seed).await;
    assert_eq!(enrol(&mut f, &account_seed, &first, 3600).await, 200);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    // The account registers itself last, so it is the junior of the two.
    let mut a = connect(addr, pubkey, account_seed).await;
    assert_eq!(enrol(&mut a, &account_seed, &account, 3600).await, 200);

    // A stranger with its own account cannot touch somebody else's device.
    let mut s = connect(addr, pubkey, stranger_seed).await;
    assert_eq!(enrol(&mut s, &stranger_seed, &stranger, 3600).await, 200);
    let (code, _) = s
        .post("/device/revoke", Revoke { device: first, revocation: None }.encode())
        .await
        .unwrap();
    assert_eq!(code, 403, "a stranger revoked another account's device");

    // The account may, junior though it is.
    let (code, body) = a
        .post("/device/revoke", Revoke { device: first, revocation: None }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

/// **SIP-32: the registry keeps the credential it verified.**
///
/// Until it did, SIP-31's second step — binding the device that signed an entry
/// to the account the entry names — could not be performed by anybody at all.
/// The exchange checked once at registration and answered afterwards with its
/// own summary, so every signature rested on its memory of having checked.
#[tokio::test]
async fn a_listing_carries_the_credential_it_rests_on() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, account) = keys(31);
    let (laptop_seed, laptop) = keys(32);

    // The device registers itself with the credential its account signed, which
    // is the branch SIP-22 exists for: an account key may be in hardware and a
    // hardware key cannot be a transport key at all.
    let mut d = connect(addr, pubkey, laptop_seed).await;
    assert_eq!(enrol(&mut d, &account_seed, &laptop, 3600).await, 200);

    let listed = devices_of(&mut d, &account).await;
    let row = listed
        .devices
        .iter()
        .find(|x| x.device == laptop)
        .expect("the laptop is not listed");

    let cred = row
        .credential
        .as_ref()
        .expect("the registry produced no credential, so nobody can check the binding");

    // Verified here, against the account key alone — the exchange is not
    // consulted and its mapping is not taken on trust. The clock is the real
    // one: `enrol` issues against wall time, and a synthetic `now` would report
    // a perfectly good credential as not yet valid.
    assert_eq!(cred.delegate, laptop);
    assert_eq!(cred.verify(&account, SCOPE_CHAT, now()), Ok(()));

    // And it is not evidence about anybody else.
    let (_, stranger) = keys(33);
    assert!(cred.verify(&stranger, SCOPE_CHAT, now()).is_err());
}

/// **SIP-32: an attested revocation carries its own authority.**
///
/// The account's signed withdrawal needs no registration behind it and no
/// seniority, because it is the same authority that signed the credential. A
/// stranger's signature over the same fields is not evidence about this account.
#[tokio::test]
async fn an_attested_revocation_stands_on_the_account_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, account) = keys(41);
    let (laptop_seed, laptop) = keys(42);
    let (stranger_seed, _) = keys(43);

    let mut d = connect(addr, pubkey, laptop_seed).await;
    assert_eq!(enrol(&mut d, &account_seed, &laptop, 3600).await, 200);

    let now = 1_000_000u64;

    // Signed by somebody else's account over the right device: refused.
    let forged = Revoke {
        device: laptop,
        revocation: Some(Revocation::issue(&stranger_seed, &laptop, now)),
    };
    let (code, body) = d.post("/device/revoke", forged.encode()).await.unwrap();
    assert_ne!(
        code, 200,
        "a stranger's signature withdrew somebody else's device: {}",
        common::said(&body)
    );
    assert_eq!(devices_of(&mut d, &account).await.devices.len(), 1);

    // The account's own withdrawal.
    let attested = Revocation::issue(&account_seed, &laptop, now);
    let (code, body) = d
        .post(
            "/device/revoke",
            Revoke { device: laptop, revocation: Some(attested) }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(devices_of(&mut d, &account).await.devices.is_empty());

    // The artifact is repeatable: verified against the account key with no
    // reference to the exchange that stored it.
    assert_eq!(attested.verify(&account, now + 1, 60), Ok(()));
}

/// A revocation naming one device cannot retire another, however well signed.
#[tokio::test]
async fn a_revocation_is_evidence_about_the_device_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (account_seed, account) = keys(51);
    let (laptop_seed, laptop) = keys(52);
    let (_, phone) = keys(53);

    let mut d = connect(addr, pubkey, laptop_seed).await;
    assert_eq!(enrol(&mut d, &account_seed, &laptop, 3600).await, 200);
    assert_eq!(enrol(&mut d, &account_seed, &phone, 3600).await, 200);

    // Refused at the decoder: a request whose artifact speaks about a different
    // device is malformed rather than merely unauthorised.
    let crossed = Revoke {
        device: laptop,
        revocation: Some(Revocation::issue(&account_seed, &phone, 1_000_000)),
    };
    let (code, _) = d.post("/device/revoke", crossed.encode()).await.unwrap();
    assert_ne!(code, 200, "a revocation retired a device it did not name");
    assert_eq!(devices_of(&mut d, &account).await.devices.len(), 2);
}
