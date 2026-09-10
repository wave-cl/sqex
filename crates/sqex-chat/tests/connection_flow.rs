//! The connection a `Chat` holds, handed to somebody else.
//!
//! An exchange fans a relayed datagram out to *every* connection an identity
//! holds, so a program that dials once for chat and again for a call has every
//! audio frame written to a connection where nothing reads it. `connection()`
//! is what lets the second dial not happen: a handle on the one already open.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

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

async fn chat_at(addr: SocketAddr, server_pub: [u8; 32], b: u8, store_path: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.top_up_prekeys().await.unwrap();
    chat
}

/// How many connections the exchange has accepted since it started.
///
/// Read **through the handle under test**, deliberately: a probe of its own
/// would open a connection and so change the number it was asking about.
async fn accepted(client: &sqnr::Client) -> u64 {
    let (code, body) = client.requests().get("/status").await.unwrap();
    assert_eq!(code, 200);
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    json["connections"].as_u64().unwrap()
}

/// A handle costs no connection, and the exchange never sees a second one.
#[tokio::test]
async fn a_handle_is_the_same_connection_and_not_another() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 31, &dir.path().join("a.db")).await;

    let first = alice.connection().expect("a live connection to share");
    let before = accepted(&first).await;

    // Another part of the program asking for the same exchange as the same
    // identity. If this dialled, the exchange would say so.
    let second = alice.connection().expect("a second handle");
    let after = accepted(&second).await;
    assert_eq!(
        before, after,
        "taking a handle opened a connection; it is supposed to be the one \
         already open"
    );

    // And it works: not a handle on something dead.
    let (code, _) = second.requests().get("/status").await.unwrap();
    assert_eq!(code, 200);

    // Dropping handles does not take the connection with them. This is the
    // part that would bite: a call ends, its handle goes, and the chat client
    // would find itself offline for no reason a person could see.
    drop(first);
    drop(second);
    let (_, bob_key) = identity(32);
    let channel = alice.open_dm(&bob_key).await.unwrap();
    let mut timeline = Timeline::new();
    alice
        .poll(&channel, &mut timeline, 0)
        .await
        .expect("the chat client should still have its connection");
}
