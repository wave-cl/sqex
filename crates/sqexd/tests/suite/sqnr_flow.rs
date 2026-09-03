//! End-to-end through the *real* sqnr code path: `sqnr::Client` +
//! `sqnr::flow::sign_and_submit` + `sqnr::Backend::software` driving a signed
//! transaction against a live sqexd. This is what the sqex CLI runs, minus the
//! terminal prompt. Also proves batch application (multiple ops, one signature).

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::Op;
use sqexd::config::FileConfig;
use sqnr::signer::Backend;
use sqnr::{Client, flow};
use sqnr_core::{PubKey, Transaction};

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

#[tokio::test]
async fn cli_flow_signs_a_batch() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("host_key");
    let state_path = dir.path().join("sqex.state");

    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();

    let admin_sk = SigningKey::from_bytes(&[7u8; 32]);
    let admin_pub = PubKey::new(admin_sk.verifying_key().to_bytes());

    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = [{:?}]\n",
        key_path.to_string_lossy(),
        state_path.to_string_lossy(),
        admin_pub.to_base58(),
    );
    let config_path = dir.path().join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let (addr, server_pub_bytes, handle) = spawn_server(&config_toml, config_path).await;
    let server = PubKey::new(server_pub_bytes);

    let mut client = Client::connect(addr, &server_pub_bytes).await.unwrap();
    let admin = Backend::software(sqnr_core::SoftwareSigner::new(admin_sk));
    let no_review = |_: &Transaction| {};
    let no_touch = || {};

    // One signed transaction that enables the whitelist AND adds a peer.
    let peer = PubKey::new(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
    let v = flow::sign_and_submit(
        &mut client,
        &admin,
        server,
        vec![
            Op::WhitelistEnable.to_operation(),
            Op::WhitelistAdd {
                key: peer,
                label: Some("device-1".into()),
            }
            .to_operation(),
        ],
        &no_review,
        &no_touch,
    )
    .await
    .expect("batch accepted");
    assert_eq!(v["results"][0]["enabled"], true, "enable applied");
    assert_eq!(v["results"][1]["changed"], true, "add applied");

    // Read it back with a separate signed transaction.
    let v = flow::sign_and_submit(
        &mut client,
        &admin,
        server,
        vec![Op::WhitelistList.to_operation()],
        &no_review,
        &no_touch,
    )
    .await
    .expect("list accepted");
    let listed = &v["results"][0];
    assert_eq!(listed["enabled"], true);
    let entry = listed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key"].as_str() == Some(&peer.to_base58()))
        .expect("both ops in the batch took effect");
    assert_eq!(entry["label"].as_str(), Some("device-1"), "label recorded");

    // A non-admin backend is refused.
    let outsider = Backend::software(sqnr_core::SoftwareSigner::new(SigningKey::from_bytes(&[8u8; 32])));
    let err = flow::sign_and_submit(
        &mut client,
        &outsider,
        server,
        vec![Op::WhitelistDisable.to_operation()],
        &no_review,
        &no_touch,
    )
    .await;
    assert!(err.is_err(), "outsider is not an authorized admin");

    handle.abort();
}
