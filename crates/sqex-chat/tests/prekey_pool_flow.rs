//! SIP-23 §Publishing after a refusal (2026-09-22): a pool that cannot run
//! away. An exchange that refuses to serve the account is answered before
//! anything is minted, and what it refused is dropped; a pool many times
//! its own size -- the shape a store was left in by the first version,
//! which minted on every start and never heard the refusal -- is cleared
//! and started again.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::{Chat, ChatError};
use sqex_chat::store::Store;
use sqex_proto::prekey::{POOL, Pool};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn exchange_in(dir: &Path, domain: &str) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind_with(
        config,
        None,
        signing_key,
        sqexd::relay::Find::Fixed(Default::default()),
    )
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
    chat.set_domain(Some("e.test".into()));
    chat
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An exchange that says the account moved (SIP-59) is asked before anything
/// is minted: the store's pool does not grow by a single row, and what the
/// exchange refuses is gone. The control is the first version: sixty-five
/// rows per call, for ever.
#[tokio::test]
async fn a_moved_account_mints_nothing_and_drops_what_the_exchange_refuses() {
    let e_dir = tempfile::tempdir().unwrap();
    let f_dir = tempfile::tempdir().unwrap();
    let (e_addr, e_pub) = exchange_in(e_dir.path(), "e.test").await;
    let (f_addr, f_pub) = exchange_in(f_dir.path(), "f.test").await;
    let (seed, _carol) = identity(0x91);
    let store = f_dir.path().join("carol-f.db");

    // The account leaves F for E before this client ever published a pool
    // at F -- the shape the runaway had: F holds nothing for it, and every
    // start asks F for a count of zero.
    let mut at_f = chat_at(f_addr, f_pub, 0x91, &store).await;
    at_f.present_move(&sqex_proto::home::Moving {
        mv: sqex_proto::home::Move::sign(&seed, &PubKey::new(e_pub), now()),
        domain: "e.test".into(),
        origins: vec![],
    })
    .await
    .unwrap();
    drop(at_f);
    let _ = e_addr;

    // Every start at F from now on: told, and the pool untouched or smaller.
    for round in 0..3 {
        let mut at_f = chat_at(f_addr, f_pub, 0x91, &store).await;
        let err = at_f.top_up_prekeys().await.unwrap_err();
        assert!(matches!(err, ChatError::Moved(..)), "round {round}: {err}");
        let held = at_f.store().one_time_held().unwrap();
        assert_eq!(
            held, 0,
            "round {round}: the store keeps prekeys the exchange refuses ({held})"
        );
    }

    // And a pool F did take, left behind by the move: dropped on the first
    // start that is told, since F serves none of it any more.
    let (seed2, _) = identity(0x94);
    let store2 = f_dir.path().join("erin-f.db");
    let mut erin = chat_at(f_addr, f_pub, 0x94, &store2).await;
    erin.top_up_prekeys().await.unwrap();
    assert_eq!(erin.store().one_time_held().unwrap(), POOL as u64);
    erin.present_move(&sqex_proto::home::Moving {
        mv: sqex_proto::home::Move::sign(&seed2, &PubKey::new(e_pub), now()),
        domain: "e.test".into(),
        origins: vec![],
    })
    .await
    .unwrap();
    drop(erin);
    let mut erin = chat_at(f_addr, f_pub, 0x94, &store2).await;
    assert!(matches!(
        erin.top_up_prekeys().await.unwrap_err(),
        ChatError::Moved(..)
    ));
    assert_eq!(
        erin.wiped_prekeys(),
        POOL as u64,
        "the pool F no longer serves was kept"
    );
    assert_eq!(erin.store().one_time_held().unwrap(), 0);
}

/// A pool that ran away before the rule -- hundreds of unspent rows the
/// exchange may or may not hold -- is cleared at the exchange and locally,
/// and the client starts again with one pool's worth, above every id the
/// exchange has seen.
#[tokio::test]
async fn a_runaway_pool_is_cleared_and_started_again() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = exchange_in(dir.path(), "e.test").await;
    let (seed, _) = identity(0x92);
    let store_path = dir.path().join("dave.db");

    // The shape the first version left: a thousand "published" rows.
    let mut runaway = Pool::new(&seed);
    let minted = runaway.mint_one_time(1000);
    runaway.mark_published(minted.iter().map(|p| p.id));
    let last_id = minted.last().unwrap().id;
    let mut store = Store::open(&seed, Some(&store_path)).unwrap();
    store.scope_to(&PubKey::new(server_pub)).unwrap();
    store.save_pool(&runaway).unwrap();
    assert_eq!(store.one_time_held().unwrap(), 1000);
    drop(store);

    let mut chat = chat_at(addr, server_pub, 0x92, &store_path).await;
    chat.top_up_prekeys().await.unwrap();
    assert_eq!(chat.wiped_prekeys(), 1000, "the runaway pool was kept");
    assert_eq!(
        chat.store().one_time_held().unwrap(),
        POOL as u64,
        "not one pool's worth after the heal"
    );
    // The new ids sit above the old ones, published, and the exchange holds
    // exactly them.
    let pool = chat.store().pool(&seed).unwrap();
    assert_eq!(pool.unpublished_count(), 0);
    assert_eq!(pool.published_left(), POOL);
    let counts = chat.prekeys_served().await.unwrap();
    assert_eq!(counts.one_time, POOL, "the exchange holds a different pool");
    assert!(
        counts.fallback_id > last_id,
        "the new ids are not above the old"
    );

    // A second start finds a healthy pool and leaves it alone.
    let mut again = chat_at(addr, server_pub, 0x92, &store_path).await;
    again.top_up_prekeys().await.unwrap();
    assert_eq!(again.wiped_prekeys(), 0);
    assert_eq!(again.store().one_time_held().unwrap(), POOL as u64);
}

/// What the store remembers about a publish that never happened: an
/// unpublished id survives a save and a load, and is offered again.
#[test]
fn an_unpublished_prekey_survives_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let (seed, _) = identity(0x93);
    let mut store = Store::open(&seed, Some(&dir.path().join("x.db"))).unwrap();
    store.scope_to(&PubKey::new([7u8; 32])).unwrap();
    let mut pool = Pool::new(&seed);
    let minted = pool.mint_one_time(3);
    pool.mark_published([minted[0].id]);
    store.save_pool(&pool).unwrap();
    let back = store.pool(&seed).unwrap();
    assert_eq!(back.one_time_left(), 3);
    assert_eq!(back.unpublished_count(), 2);
    assert_eq!(back.published_left(), 1);
    let again: Vec<u32> = back.unpublished_prekeys().iter().map(|p| p.id).collect();
    assert_eq!(again, vec![minted[1].id, minted[2].id]);
    // The same public key as first minted: the secret is what was kept.
    assert_eq!(back.unpublished_prekeys()[0].public, minted[1].public);
}
