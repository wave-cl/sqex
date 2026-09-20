//! SIP-60 §A direct message opened twice: a direct message opened twice, seen from the clients. Bob at B
//! opened it at his own exchange without locating Alice, as a client from
//! before SIP-60 does; Alice, the lower key, opened it at her home A. Once A
//! learns of B's copy and B folds it, Bob's client finds the conversation
//! under the same identifier with another incarnation: what he read of the
//! stray is kept as an earlier copy, what follows is the conversation, and
//! he writes into it through B.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::home::Moving;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn exchange_in(
    dir: &Path,
    listen: SocketAddr,
    domain: &str,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32]) {
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let key_path = dir.join("host_key");
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\nreplication_peers = [{list}]\n\
         seed_relay_peers = [{list}]\nhome_secs = 1\n",
        listen.to_string(),
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let map = found
        .iter()
        .map(|(d, k, a)| ((*d).to_string(), (*k, *a)))
        .collect();
    let bound = sqexd::bind_with(config, None, signing_key, sqexd::relay::Find::Fixed(map))
        .await
        .unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
}

fn key_in(dir: &Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    PubKey::new(vk.to_bytes())
}

fn free_port() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn chat_at(
    addr: SocketAddr,
    server_pub: [u8; 32],
    domain: &str,
    b: u8,
    store_path: &Path,
) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.set_domain(Some(domain.to_string()));
    chat.top_up_prekeys().await.unwrap();
    chat.ensure_home().await.unwrap();
    chat
}

fn said(timeline: &Timeline) -> Vec<String> {
    timeline
        .messages()
        .filter(|m| m.is_visible())
        .filter_map(|m| m.post.body_text().map(|t| t.to_string()))
        .collect()
}

async fn until(chat: &mut Chat, channel: &[u8; 32], t: &mut Timeline, want: &[&str]) -> bool {
    let mut last = String::new();
    for _ in 0..80 {
        match chat.poll(channel, t, 0).await {
            Ok(got) => {
                if said(&got.timeline) == want {
                    return true;
                }
                last = format!(
                    "{:?} forged {:?} unreadable {:?} no_key {:?} lost {} restarted {}",
                    said(&got.timeline),
                    t.forged(),
                    got.unreadable,
                    got.no_key,
                    got.lost,
                    got.restarted
                );
            }
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    eprintln!("wanted {want:?}, last saw {last}");
    false
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn a_folded_direct_message_keeps_what_was_read_and_continues() {
    // Alice holds the lower key.
    let (mut a, mut b) = (75u8, 76u8);
    if identity(a).1.as_bytes() > identity(b).1.as_bytes() {
        std::mem::swap(&mut a, &mut b);
    }
    let (_, alice) = identity(a);
    let (_, bob) = identity(b);

    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_key = key_in(a_dir.path());
    let b_key = key_in(b_dir.path());
    let (a_at, b_at) = (free_port(), free_port());
    let (a_addr, a_pub) = exchange_in(
        a_dir.path(),
        a_at,
        "a.test",
        &[b_key],
        &[("b.test", b_key, b_at)],
    )
    .await;
    let (b_addr, b_pub) = exchange_in(
        b_dir.path(),
        b_at,
        "b.test",
        &[a_key],
        &[("a.test", a_key, a_at)],
    )
    .await;

    // Before the two exchanges federated, Alice had connected to B as well
    // and left prekeys there -- which is how a stray with anything in it
    // came to be: Bob could seal to her.
    let alice_at_b = chat_at(b_addr, b_pub, "b.test", a, &b_dir.path().join("alice.db")).await;
    drop(alice_at_b);
    let mut bob_at_b = chat_at(b_addr, b_pub, "b.test", b, &b_dir.path().join("bob.db")).await;
    let mut alice_at_a = chat_at(a_addr, a_pub, "a.test", a, &a_dir.path().join("alice.db")).await;

    // Bob opens the message at B without locating Alice, and writes twice:
    // the shape a client from before SIP-60 left behind.
    let dm = bob_at_b.open_dm(&alice).await.unwrap();
    bob_at_b.send(&dm, "stray one").await.unwrap();
    bob_at_b.send(&dm, "stray two").await.unwrap();
    let mut tb = Timeline::new();
    assert!(until(&mut bob_at_b, &dm, &mut tb, &["stray one", "stray two"]).await);
    let stray_home = bob_at_b.home(&dm).await.unwrap();
    assert_eq!(stray_home.origin, b_key);

    // Alice locates Bob -- so A proxies his prekeys -- and opens the message
    // at her own home, being the lower key. Two channels, one identifier.
    let found = alice_at_a.locate(&format!("{bob}@b.test")).await.unwrap();
    assert_eq!(found.home, b_key);
    assert_eq!(alice_at_a.open_dm(&bob).await.unwrap(), dm);
    alice_at_a.send(&dm, "conv one").await.unwrap();
    let mut ta = Timeline::new();
    assert!(until(&mut alice_at_a, &dm, &mut ta, &["conv one"]).await);

    // A learns of B's copy: Alice says where she lives and hints at B. A
    // asks B what she is in there, finds the identifier it holds, and tells
    // B, which folds its copy.
    let mv = alice_at_a.sign_move(&a_key).unwrap();
    let mv = sqex_proto::home::Move::sign(&identity(a).0, &a_key, mv.issued.max(now()) + 1);
    alice_at_a
        .present_move(&Moving {
            mv,
            domain: "a.test".into(),
            origins: vec![(b_key, "b.test".into())],
        })
        .await
        .unwrap();

    // Bob's client finds the conversation under the same identifier: what
    // he read of the stray is an earlier copy, and what follows is Alice's.
    assert!(until(&mut bob_at_b, &dm, &mut tb, &["conv one"]).await);
    assert!(tb.forged().is_empty(), "{:?}", tb.forged());
    let earlier = bob_at_b.earlier(&dm, &[alice, bob]).unwrap();
    assert_eq!(
        earlier.len(),
        1,
        "the stray was not kept as an earlier copy"
    );
    assert_eq!(said(&earlier[0]), ["stray one", "stray two"]);
    assert_eq!(bob_at_b.home(&dm).await.unwrap().origin, a_key);
    // And the log itself is still at B for either of them to read.
    let folded = bob_at_b.folded_entries(&dm).await.unwrap();
    assert!(
        folded.is_some_and(|f| f
            .entries
            .iter()
            .any(|e| e.kind == sqex_proto::channel::KIND_MEMBER)),
        "B does not serve the folded log"
    );

    // He writes into the conversation through B; Alice reads it at A.
    bob_at_b.send(&dm, "bob through b").await.unwrap();
    assert!(
        until(
            &mut alice_at_a,
            &dm,
            &mut ta,
            &["conv one", "bob through b"]
        )
        .await
    );
    assert!(ta.forged().is_empty(), "{:?}", ta.forged());
    assert!(until(&mut bob_at_b, &dm, &mut tb, &["conv one", "bob through b"]).await);
    // Nothing of Alice's is an earlier copy: her channel was the conversation.
    assert!(alice_at_a.earlier(&dm, &[alice, bob]).unwrap().is_empty());

    // Opening it again from Bob's side goes where it lives, and makes no
    // second stray: the identifier at B is the copy.
    assert_eq!(bob_at_b.open_dm(&alice).await.unwrap(), dm);
    assert_eq!(bob_at_b.home(&dm).await.unwrap().origin, a_key);
}
