//! SIP-52: a catch-up is the routes it composes, byte for byte -- and a
//! client that catches up holds what a client that polled holds.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::catchup::{
    Catchup, CaughtUp, MAX_CATCHUP_BYTES, Named, STATUS_ABSENT, STATUS_DEFERRED, STATUS_OK,
};
use sqex_proto::channel::Fetch;
use sqex_proto::channel_key::Get;
use sqex_proto::prekey::Counts;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32]) {
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
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn chat_at(addr: SocketAddr, server_pub: [u8; 32], b: u8, store: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.top_up_prekeys().await.unwrap();
    chat
}

async fn raw(client: &mut Client, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
    client.post(path, body).await.unwrap()
}

fn named(channel: [u8; 32], since: u64) -> Named {
    Named {
        channel,
        since,
        since_epoch: 0,
    }
}

#[tokio::test]
async fn a_catchup_is_fetch_and_get_byte_for_byte_and_the_rest_is_mine_and_count() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;

    let channel = alice.open_dm(&bob_key).await.unwrap();
    for text in ["one", "two", "three"] {
        alice.send(&channel, text).await.unwrap();
    }
    bob.open_dm(&alice_key).await.unwrap();

    // The routes, asked by hand on bob's own connection.
    let mut client = bob.connection().expect("bob is connected");
    let (code, fetched) = raw(
        &mut client,
        "/channel/fetch",
        Fetch {
            channel,
            since: 0,
            wait_secs: 0,
            receipts: false,
        }
        .encode(),
    )
    .await;
    assert_eq!(code, 200);
    let (code, got) = raw(
        &mut client,
        "/channel/key/get",
        Get {
            channel,
            since_epoch: 0,
        }
        .encode(),
    )
    .await;
    assert_eq!(code, 200);
    let (code, counted) = raw(&mut client, "/prekey/count", vec![0x03]).await;
    assert_eq!(code, 200);
    let counts = Counts::decode(&counted).unwrap();

    // The catch-up, naming the one channel.
    let (code, body) = raw(
        &mut client,
        "/channel/catchup",
        Catchup {
            budget: MAX_CATCHUP_BYTES,
            named: vec![named(channel, 0)],
        }
        .encode(),
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let answer = CaughtUp::decode(&body).unwrap();
    assert_eq!(answer.caught.len(), 1);
    let c = &answer.caught[0];
    assert_eq!(c.status, STATUS_OK);
    assert!(!c.more);
    // `now` differs by the second; everything else is the route's bytes.
    assert_eq!(
        c.fetched[8..],
        fetched[8..],
        "fetched is not what fetch said"
    );
    assert_eq!(c.got[8..], got[8..], "got is not what key/get said");
    assert_eq!(answer.prekeys, counts.one_time);
    assert!(answer.unnamed.is_empty(), "the one channel was named");

    // Naming nothing: the unnamed list is `mine`.
    let (code, body) = raw(
        &mut client,
        "/channel/catchup",
        Catchup {
            budget: MAX_CATCHUP_BYTES,
            named: vec![],
        }
        .encode(),
    )
    .await;
    assert_eq!(code, 200);
    let answer = CaughtUp::decode(&body).unwrap();
    let mine: Vec<[u8; 32]> = bob
        .mine()
        .await
        .unwrap()
        .iter()
        .map(|m| m.channel)
        .collect();
    let unnamed: Vec<[u8; 32]> = answer.unnamed.iter().map(|u| u.channel).collect();
    assert_eq!(unnamed, mine);
    assert!(unnamed.contains(&channel));

    // A budget too small for the first entry: what fit (nothing) with
    // `more`, and every channel after it deferred rather than described.
    let (code, body) = raw(
        &mut client,
        "/channel/catchup",
        Catchup {
            budget: 1,
            named: vec![named(channel, 0), named([9; 32], 0)],
        }
        .encode(),
    )
    .await;
    assert_eq!(code, 200);
    let answer = CaughtUp::decode(&body).unwrap();
    assert_eq!(answer.caught[0].status, STATUS_OK);
    assert!(answer.caught[0].more);
    let cut = sqex_proto::channel::Entries::decode(&answer.caught[0].fetched, false).unwrap();
    assert!(cut.entries.is_empty(), "nothing fit in one byte");
    assert_eq!(answer.caught[1].status, STATUS_DEFERRED);
    assert!(answer.caught[1].more);
    assert!(answer.caught[1].fetched.is_empty() && answer.caught[1].got.is_empty());

    // Somebody else naming the conversation, and naming nothing at all: one
    // answer, the same bytes but for the channel.
    let carol = chat_at(addr, server_pub, 3, &dir.path().join("c.db")).await;
    let mut stranger = carol.connection().unwrap();
    let (code, body) = raw(
        &mut stranger,
        "/channel/catchup",
        Catchup {
            budget: MAX_CATCHUP_BYTES,
            named: vec![named(channel, 0), named([7; 32], 0)],
        }
        .encode(),
    )
    .await;
    assert_eq!(code, 200);
    let answer = CaughtUp::decode(&body).unwrap();
    for c in &answer.caught {
        assert_eq!(c.status, STATUS_ABSENT);
        assert!(!c.more && c.fetched.is_empty() && c.got.is_empty());
    }

    // No identity, no answer.
    let mut anon = Client::connect(addr, &server_pub).await.unwrap();
    let (code, _) = raw(
        &mut anon,
        "/channel/catchup",
        Catchup {
            budget: 1,
            named: vec![],
        }
        .encode(),
    )
    .await;
    assert_eq!(code, 403);
}

#[tokio::test]
async fn a_client_that_caught_up_holds_what_one_that_polled_holds() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;

    let channel = alice.open_dm(&bob_key).await.unwrap();
    for text in ["one", "two", "three"] {
        alice.send(&channel, text).await.unwrap();
    }
    // Bob has not opened the conversation: the epoch key alice sealed to him
    // is still waiting at the exchange, and the catch-up is what brings it.

    // Named by hand: the store records a direct message once something has
    // been absorbed into it, which is what a catch-up is about to do. A
    // client that has held the channel names it from the store (below).
    let answer = bob
        .catchup(&[named(channel, 0)], MAX_CATCHUP_BYTES)
        .await
        .unwrap();
    let caught = answer
        .caught
        .into_iter()
        .find(|c| c.channel == channel)
        .expect("the DM was answered");
    assert_eq!(caught.status, STATUS_OK);
    assert!(
        caught.keys_opened >= 1,
        "the epoch key rode along and was opened"
    );
    let mut timeline = bob.history(&channel, &[alice_key, bob_key]).unwrap();
    bob.absorb(&mut timeline, caught.fetched.expect("entries"))
        .await
        .unwrap();
    let said: Vec<String> = timeline
        .messages()
        .filter_map(|m| m.post.body_text().map(str::to_string))
        .collect();
    assert_eq!(said, ["one", "two", "three"]);

    // Caught up: the cursor moved, so the next catch-up carries no entries
    // and opens no keys. Named from the store this time: the store lists
    // what a client recorded there, which the TUI and sigil both do once
    // they know a conversation, and this test now does the same.
    bob.store()
        .put_channel(&channel, false, Some(false), "alice", &[alice_key, bob_key])
        .unwrap();
    let named = bob.named_for_catchup().unwrap();
    assert!(
        named.iter().any(|n| n.channel == channel),
        "the DM is held now"
    );
    let again = bob.catchup(&named, MAX_CATCHUP_BYTES).await.unwrap();
    let c = again.caught.iter().find(|c| c.channel == channel).unwrap();
    assert_eq!(c.keys_opened, 0);
    let mut after = bob.history(&channel, &[alice_key, bob_key]).unwrap();
    let before = after.messages().count();
    bob.absorb(
        &mut after,
        again
            .caught
            .into_iter()
            .find(|c| c.channel == channel)
            .unwrap()
            .fetched
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(after.messages().count(), before, "nothing new to absorb");

    // And the disc agrees with a client that polled.
    let held: Vec<String> = bob
        .history(&channel, &[alice_key, bob_key])
        .unwrap()
        .messages()
        .filter_map(|m| m.post.body_text().map(str::to_string))
        .collect();
    assert_eq!(held, ["one", "two", "three"]);

    // A route that is not there answers not_found, which the client reports
    // as `NoChatHere` -- the shape a caller falls back on for an exchange
    // from before SIP-52.
    let mut client = bob.connection().unwrap();
    let (code, _) = raw(&mut client, "/channel/catchup-not-here", vec![0x01]).await;
    assert_eq!(code, 404);
}
