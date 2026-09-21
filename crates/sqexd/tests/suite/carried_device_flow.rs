//! SIP-58: an account whose key never connects -- a token that only signs
//! -- issues a credential offline; an administrator carries it; the device
//! is registered, admitted under the whitelist (SIP-47), and signs for the
//! account. A revocation carried the same way ends it.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::Op;
use sqex_proto::credential::{Credential, Revocation, SCOPE_CHAT};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::{PubKey, SignedTransaction, SoftwareSigner, Transaction};

async fn exchange_in(dir: &std::path::Path, admin: PubKey) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = [\"{admin}\"]\n\
         welcome_channel = \"\"\n",
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

pub(crate) async fn admin(
    addr: SocketAddr,
    server_pub: [u8; 32],
    admin_seed: [u8; 32],
    ops: Vec<Op>,
) -> serde_json::Value {
    let mut c = Client::connect_as(addr, &server_pub, &admin_seed)
        .await
        .unwrap();
    let (cs, nonce_bytes) = c.get("/admin/challenge").await.unwrap();
    assert_eq!(cs, 200);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let txn = Transaction {
        server: PubKey::new(server_pub),
        nonce,
        ops: ops.into_iter().map(|o| o.to_operation()).collect(),
    };
    let signer = SoftwareSigner::new(SigningKey::from_bytes(&admin_seed));
    let (code, body) = c
        .post(
            "/admin/command",
            SignedTransaction::create(txn, &signer).encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

/// A dial that may be dropped at the door.
async fn try_connect(addr: SocketAddr, server_pub: [u8; 32], seed: [u8; 32]) -> Option<Client> {
    tokio::time::timeout(
        std::time::Duration::from_secs(4),
        Client::connect_as(addr, &server_pub, &seed),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
}

#[tokio::test]
async fn an_administrator_carries_a_credential_the_account_signed_offline() {
    let dir = tempfile::tempdir().unwrap();
    let (admin_seed, admin_key) = identity(61);
    let (addr, server_pub) = exchange_in(dir.path(), admin_key).await;

    // The account: a signer that never becomes a transport key and never
    // connects. Its device: an ordinary software identity.
    let token = SoftwareSigner::new(SigningKey::from_bytes(&[62u8; 32]));
    let account = PubKey::new(sqnr_core::Signer::public(&token));
    let (device_seed, device) = identity(63);

    // The whitelist is on, with the account listed; its device is not.
    let v = admin(
        addr,
        server_pub,
        admin_seed,
        vec![
            Op::WhitelistEnable,
            Op::WhitelistAdd {
                key: account,
                label: Some("token".into()),
            },
        ],
    )
    .await;
    assert_eq!(v["results"][0]["ok"], true);
    assert!(
        try_connect(addr, server_pub, device_seed).await.is_none(),
        "an unregistered device got in"
    );

    // Offline: the token signs a credential for the device.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let credential =
        Credential::issue_with(&token, &device, SCOPE_CHAT, now - 60, now + 3600).unwrap();
    assert!(credential.verify(&account, SCOPE_CHAT, now).is_ok());
    // Round-trips through the wire the administrator carries it on.
    let op = Op::DeviceRegister(credential.clone());
    assert_eq!(Op::decode(&op.payload()).unwrap(), op);

    // Not from a stranger's signature: an administrator cannot invent one.
    let forged = Credential::issue_with(
        &SoftwareSigner::new(SigningKey::from_bytes(&[64u8; 32])),
        &device,
        SCOPE_CHAT,
        now - 60,
        now + 3600,
    )
    .unwrap();
    let mut forged = forged;
    forged.account = account;
    let v = admin(
        addr,
        server_pub,
        admin_seed,
        vec![Op::DeviceRegister(forged)],
    )
    .await;
    assert_eq!(
        v["results"][0]["ok"], false,
        "a credential the account did not sign was taken"
    );

    // Carried: registered, and admitted because the account is listed.
    let v = admin(
        addr,
        server_pub,
        admin_seed,
        vec![Op::DeviceRegister(credential)],
    )
    .await;
    assert_eq!(v["results"][0]["ok"], true, "{v}");
    let mut d = try_connect(addr, server_pub, device_seed)
        .await
        .expect("a registered device of a listed account is let in");
    // And the exchange knows whose it is.
    let (code, body) = d
        .post(
            "/device/list",
            sqex_proto::device::ListDevices { account }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let listed = sqex_proto::device::Devices::decode(&body).unwrap();
    assert!(listed.devices.iter().any(|x| x.device == device));

    // Revoked offline, carried the same way: gone, and out.
    let revocation = Revocation::issue_with(&token, &device, now);
    let v = admin(
        addr,
        server_pub,
        admin_seed,
        vec![Op::DeviceRevoke(revocation)],
    )
    .await;
    assert_eq!(v["results"][0]["ok"], true, "{v}");
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert!(
        try_connect(addr, server_pub, device_seed).await.is_none(),
        "a revoked device was let back in"
    );
}
