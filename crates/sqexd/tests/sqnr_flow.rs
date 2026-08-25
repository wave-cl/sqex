//! End-to-end through the *real* sqnr code path: `sqnr::Client` +
//! `sqnr::flow::run_once` + `sqnr::Backend::software` driving signed admin
//! commands against a live sqexd. This is what the `sqnr` CLI runs, minus the
//! terminal passphrase prompt — proof the signer/client/flow apply correctly
//! against the server.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqexd::config::FileConfig;
use sqnr::signer::Backend;
use sqnr::{Client, flow};
use sqnr_core::PubKey;
use sqnr_core::protocol::{Action, SoftwareSigner};

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
async fn cli_flow_signs_and_applies() {
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
    let admin = Backend::software(SoftwareSigner::new(admin_sk));
    let no_touch = || {};

    // Enable the whitelist, then read it back — both signed by the software admin.
    flow::run_once(&mut client, &admin, server, Action::WhitelistEnable, &no_touch)
        .await
        .expect("enable accepted");
    let listed = flow::run_once(&mut client, &admin, server, Action::WhitelistList, &no_touch)
        .await
        .expect("list accepted");
    assert_eq!(listed["enabled"], true, "whitelist reports enabled");

    // Add a peer key and confirm it appears in the list.
    let peer = PubKey::new(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
    flow::run_once(
        &mut client,
        &admin,
        server,
        Action::WhitelistAdd(peer),
        &no_touch,
    )
    .await
    .expect("add accepted");
    let listed = flow::run_once(&mut client, &admin, server, Action::WhitelistList, &no_touch)
        .await
        .expect("list accepted");
    let keys = listed["keys"].as_array().unwrap();
    assert!(
        keys.iter().any(|k| k.as_str() == Some(&peer.to_base58())),
        "added peer is present in the whitelist"
    );

    // A non-admin backend is refused by the server.
    let outsider = Backend::software(SoftwareSigner::new(SigningKey::from_bytes(&[8u8; 32])));
    let err = flow::run_once(
        &mut client,
        &outsider,
        server,
        Action::WhitelistDisable,
        &no_touch,
    )
    .await;
    assert!(err.is_err(), "outsider is not an authorized admin");

    handle.abort();
}
