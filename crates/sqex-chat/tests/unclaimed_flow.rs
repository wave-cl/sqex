//! SIP-60 §When a client presents a Move unasked (2026-09-21): a new store
//! presents no Move by itself. The first "this is my home" is the person's
//! -- `Chat::claim_home` -- and until then a client pointed anywhere is a
//! visitor there: a probe with the wrong `--server` moved live accounts
//! before this.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::{Chat, HomeSaid};
use sqex_chat::store::Store;
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
    let bound = sqexd::bind_with(config, None, signing_key, sqexd::relay::Find::Fixed(Default::default()))
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

async fn open_at(addr: SocketAddr, server_pub: [u8; 32], domain: &str, b: u8, store: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.set_domain(Some(domain.to_string()));
    chat.top_up_prekeys().await.unwrap();
    chat
}

#[tokio::test]
async fn a_new_store_presents_no_move_until_the_person_claims() {
    let e_dir = tempfile::tempdir().unwrap();
    let f_dir = tempfile::tempdir().unwrap();
    let (e_addr, e_pub) = exchange_in(e_dir.path(), "e.test").await;
    let (f_addr, f_pub) = exchange_in(f_dir.path(), "f.test").await;
    let (_, carol) = identity(81);

    // A fresh store at E, which has never heard of Carol: nothing presented,
    // and E still has no home on record for her. (The control: with the
    // first Move presented on connect, `since` here is the Move's time.)
    let store_e = e_dir.path().join("carol-e.db");
    let mut at_e = open_at(e_addr, e_pub, "e.test", 81, &store_e).await;
    assert_eq!(at_e.ensure_home().await.unwrap(), HomeSaid::Unclaimed);
    assert_eq!(at_e.ensure_home().await.unwrap(), HomeSaid::Unclaimed, "asked twice, still nothing");
    let said = at_e.account_home(&carol).await.unwrap();
    assert_eq!(said.since, 0, "a Move was presented for a new store: {said:?}");

    // The person claims: presented, on record, and the store is no longer new.
    assert_eq!(at_e.claim_home().await.unwrap(), HomeSaid::Presented);
    let said = at_e.account_home(&carol).await.unwrap();
    assert_eq!((said.home, said.since != 0), (PubKey::new(e_pub), true));
    assert_eq!(at_e.ensure_home().await.unwrap(), HomeSaid::OnRecord);
    assert_eq!(at_e.claim_home().await.unwrap(), HomeSaid::OnRecord, "a second claim is a no-op");

    // A second fresh store for the same account, pointed at F -- the probe
    // shape. F has no record either; the store says nothing, and F stays
    // ignorant. (F is not asked about E: the residue rule in SIP-60 §The
    // residue of a Move by accident is for the claim made there by mistake.)
    let store_f = f_dir.path().join("carol-f.db");
    let mut at_f = open_at(f_addr, f_pub, "f.test", 81, &store_f).await;
    assert_eq!(at_f.ensure_home().await.unwrap(), HomeSaid::Unclaimed);
    assert_eq!(at_f.account_home(&carol).await.unwrap().since, 0);

    // The E store, pointed at F, is a visitor: filed under E, it is `move`'s
    // job, and a claim there is refused in those words.
    drop(at_e);
    let (seed, _) = identity(81);
    let client = Client::connect_as(f_addr, &f_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(&store_e)).unwrap();
    let mut e_store_at_f = Chat::new(client, seed, carol, PubKey::new(f_pub), store);
    e_store_at_f.set_domain(Some("f.test".into()));
    assert!(matches!(
        e_store_at_f.ensure_home().await.unwrap(),
        HomeSaid::Visitor { home, .. } if home == PubKey::new(e_pub)
    ));
    let refused = e_store_at_f.claim_home().await.unwrap_err().to_string();
    assert!(refused.contains("moving it is `move`"), "{refused}");
    assert_eq!(e_store_at_f.account_home(&carol).await.unwrap().since, 0, "the refusal moved her");
}
