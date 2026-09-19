//! SIP-64: an exchange's earlier keys. An origin rotates its key; a home
//! that meets it afterwards on an account's word alone holds only the new
//! key, and everything receipted under the old one is repudiated there --
//! until the origin serves its lineage, which the home verifies back from
//! the key it holds and reads the past under.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use sqex_discovery::Handover;
use sqex_proto::channel::{ByChannel, Entries, Fetch, Invitee, Role, TYPE_INFO, Visibility};
use sqex_proto::channel_key::{
    ChannelKey, Get as KeyGet, Got, Put as KeyPut, seal_envelope, sign_envelope,
};
use sqex_proto::home::{Move, Moving};
use sqex_proto::lineage::Lineage;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

/// An exchange in `dir` under whatever `host_key` is there, open to any
/// peer, finding `found` without DNS. Returns the task so the exchange can
/// be stopped and started again under another key.
async fn exchange_in(
    dir: &Path,
    listen: SocketAddr,
    domain: &str,
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        key_in(dir);
    }
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
         home_secs = 1\nlineage_retry_secs = 1\n",
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
    let task = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, task)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

/// Write a fresh exchange key into `dir`, returning it and its seed.
fn key_in(dir: &Path) -> (PubKey, [u8; 32]) {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let seed = server_sk.to_bytes();
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    (PubKey::new(vk.to_bytes()), seed)
}

fn free_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The SIP-40 record `from` signs for `to`, as `sqexd handover` prints it.
fn handover(from_seed: &[u8; 32], to: &PubKey, domain: &str) -> Handover {
    let sk = SigningKey::from_bytes(from_seed);
    let from = PubKey::new(sk.verifying_key().to_bytes());
    let until = now() + 86_400;
    let sig = sk
        .sign(&Handover::signing_input(domain, &from, to, until))
        .to_bytes();
    Handover {
        from,
        to: *to,
        until,
        sig,
    }
}

async fn texts(c: &mut Client, channel: [u8; 32]) -> Vec<String> {
    let (code, body) = c
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since: 0,
                wait_secs: 0,
                receipts: true,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Entries::decode(&body, true)
        .unwrap()
        .entries
        .iter()
        .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .map(|e| String::from_utf8_lossy(&e.body).into_owned())
        .collect()
}

/// What the channel shows at `c` once `ok` holds, or after `rounds` looks.
async fn watch<F: Fn(&[String]) -> bool>(
    c: &mut Client,
    channel: [u8; 32],
    rounds: usize,
    ok: F,
) -> Vec<String> {
    let mut last = Vec::new();
    for _ in 0..rounds {
        let (code, _) = c
            .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
            .await
            .unwrap();
        if code == 200 {
            last = texts(c, channel).await;
            if ok(&last) {
                return last;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    last
}

/// Stop the exchange and bring it up again under whatever `host_key` is
/// in `dir` now. The old listener's socket is held by tasks that outlive
/// the accept loop, so the new one takes a fresh port.
async fn restart(
    dir: &Path,
    task: tokio::task::JoinHandle<()>,
) -> (SocketAddr, PubKey, tokio::task::JoinHandle<()>) {
    task.abort();
    let _ = task.await;
    let (addr, pub_bytes, task) =
        exchange_in(dir, "127.0.0.1:0".parse().unwrap(), "x.test", &[]).await;
    (addr, PubKey::new(pub_bytes), task)
}

/// X rotates from A to B. A home H that meets X afterwards, on Alice's
/// Move alone, holds B and nothing older: what A receipted is repudiated
/// there. X's operator then adds the handover A signed to its lineage
/// file; H asks again on the repudiation, verifies the chain back from B,
/// and reads the past. A second home meeting X after that reads it on
/// first contact.
#[tokio::test]
async fn a_home_learned_by_hint_reads_what_the_origin_receipted_under_an_earlier_key() {
    let x_dir = tempfile::tempdir().unwrap();
    let (a_key, a_seed) = key_in(x_dir.path());
    let (x_at, _, x_task) =
        exchange_in(x_dir.path(), "127.0.0.1:0".parse().unwrap(), "x.test", &[]).await;

    // Under A: Alice and Bob in a public group with a post from each.
    let (alice_seed, alice) = identity(241);
    let (bob_seed, bob) = identity(242);
    let channel = [241u8; 32];
    {
        let mut al = Client::connect_as(x_at, a_key.as_bytes(), &alice_seed)
            .await
            .unwrap();
        let sa = Signer::new(alice_seed, alice, *a_key.as_bytes());
        let mut ca = Chain::default();
        let req = sa.create_chained(
            &mut ca,
            channel,
            instance_for(channel, 0),
            Visibility::Private,
            3600,
            "lineage",
            vec![Invitee {
                account: bob,
                role: Role::Member,
            }],
        );
        let (code, body) = al.post("/channel/create", req.encode()).await.unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
        let info = sa.info(&mut al, channel).await;
        // A key envelope for Bob (a private channel posts under epoch 1), signed -- as SIP-32 has it -- over the
        // place it was published to, which names A.
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let prekey_public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let envelope = sign_envelope(
            &alice_seed,
            &a_key,
            &info.instance,
            &channel,
            1,
            seal_envelope(&bob, 7, &prekey_public, 1, &[ChannelKey::generate()]).unwrap(),
        );
        let rot = sa.action_chained(
            &mut ca,
            channel,
            info.instance,
            sqex_proto::channel::EVENT_ROTATED,
            &alice,
            &1u32.to_be_bytes(),
        );
        let (code, body) = al
            .post(
                "/channel/key/put",
                KeyPut {
                    channel,
                    epoch: 1,
                    envelopes: vec![envelope],
                    action: Some(rot),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
        let post = sa.post_chained(&mut ca, channel, info.instance, 1, 0, b"under a".to_vec());
        assert_eq!(
            al.post("/channel/post", post.encode()).await.unwrap().0,
            200
        );
        let mut bo = Client::connect_as(x_at, a_key.as_bytes(), &bob_seed)
            .await
            .unwrap();
        let sb = Signer::new(bob_seed, bob, *a_key.as_bytes());
        let mut cb = Chain::default();
        let info = sb.info(&mut bo, channel).await;
        let post = sb.post_chained(
            &mut cb,
            channel,
            info.instance,
            1,
            0,
            b"also under a".to_vec(),
        );
        assert_eq!(
            bo.post("/channel/post", post.encode()).await.unwrap().0,
            200
        );
    }

    // X rotates to B and comes up with no lineage: SIP-40 as it stood.
    let (b_key, _) = key_in(x_dir.path());
    let (x_at, up, _x_task) = restart(x_dir.path(), x_task).await;
    assert_eq!(up, b_key);
    let mut al = Client::connect_as(x_at, b_key.as_bytes(), &alice_seed)
        .await
        .unwrap();
    let (code, body) = al.post("/exchange/lineage", Vec::new()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(Lineage::decode(&body).unwrap().links.is_empty());

    // H meets X now, holding B alone, on Alice's Move -- and reads nothing
    // of what A receipted.
    let h_dir = tempfile::tempdir().unwrap();
    let (h_addr, h_pub, _h_task) = exchange_in(
        h_dir.path(),
        free_port(),
        "h.test",
        &[("x.test", b_key, x_at)],
    )
    .await;
    let h_key = PubKey::new(h_pub);
    let mut at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = at_h
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &h_key, now()),
                domain: "h.test".into(),
                origins: vec![(b_key, "x.test".into())],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let got = watch(&mut at_h, channel, 20, |t| !t.is_empty()).await;
    assert!(
        got.is_empty(),
        "a home holding only B read entries receipted under A: {got:?}"
    );

    // The operator adds the handover A signed. X re-reads the file when
    // asked; H's next pull is refused as before, and on that it asks the
    // lineage again, learns A, and reads.
    std::fs::write(
        x_dir.path().join("lineage"),
        format!("x.test {}\n", handover(&a_seed, &b_key, "x.test").render()),
    )
    .unwrap();
    let (code, body) = al.post("/exchange/lineage", Vec::new()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        Lineage::decode(&body)
            .unwrap()
            .predecessors_for(&b_key, Some("x.test"))
            .unwrap(),
        vec![a_key]
    );
    assert_eq!(
        watch(&mut at_h, channel, 80, |t| t.len() == 2).await,
        ["under a", "also under a"],
        "the entries receipted under A did not verify at a home holding B"
    );

    // A file gone wrong keeps the last good lineage served.
    std::fs::write(x_dir.path().join("lineage"), "x.test v=sqex1; k=nonsense\n").unwrap();
    let (code, body) = al.post("/exchange/lineage", Vec::new()).await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(Lineage::decode(&body).unwrap().links.len(), 1);

    // A second home meets X with the lineage already served: first
    // contact, and the past reads at once.
    let g_dir = tempfile::tempdir().unwrap();
    let (g_addr, g_pub, _g_task) = exchange_in(
        g_dir.path(),
        free_port(),
        "g.test",
        &[("x.test", b_key, x_at)],
    )
    .await;
    let g_key = PubKey::new(g_pub);
    let mut at_g = Client::connect_as(g_addr, &g_pub, &bob_seed).await.unwrap();
    let (code, body) = at_g
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&bob_seed, &g_key, now()),
                domain: "g.test".into(),
                origins: vec![(b_key, "x.test".into())],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        watch(&mut at_g, channel, 80, |t| t.len() == 2).await,
        ["under a", "also under a"]
    );
    // The key envelope Alice published under A verifies at G under A as
    // the entries do: Bob asks G for his key and is given it. Live, a copy
    // that checked envelopes under the current key alone refused every
    // envelope from before its origin's rotation, on every pull, forever.
    let mut got = Got {
        now: 0,
        envelopes: vec![],
    };
    for _ in 0..40 {
        let (code, body) = at_g
            .post(
                "/channel/key/get",
                KeyGet {
                    channel,
                    since_epoch: 0,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
        got = Got::decode(&body).unwrap();
        if !got.envelopes.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert_eq!(
        got.envelopes.len(),
        1,
        "the envelope published under A did not verify at a home holding B"
    );
    assert_eq!(got.envelopes[0].publisher, alice);
}

/// A lineage file whose chain does not end at the daemon's own key is
/// refused at start, and a link signed for another domain with it.
#[tokio::test]
async fn the_daemon_refuses_a_lineage_that_is_not_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let (_, a_seed) = key_in(dir.path());
    let (_, other) = identity(243);
    let (own, _) = key_in(dir.path());
    std::fs::write(
        dir.path().join("lineage"),
        format!("x.test {}\n", handover(&a_seed, &other, "x.test").render()),
    )
    .unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n",
        dir.path().join("host_key").to_string_lossy(),
        dir.path().join("sqex.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let err = sqexd::bind(config.clone(), None, signing_key.clone())
        .await
        .err()
        .expect("a lineage ending at another key was served");
    assert!(err.to_string().contains("does not end"), "{err}");

    // The right key, the wrong domain in the file: not signed for it.
    std::fs::write(
        dir.path().join("lineage"),
        format!("y.test {}\n", handover(&a_seed, &own, "x.test").render()),
    )
    .unwrap();
    let err = sqexd::bind(config, None, signing_key)
        .await
        .err()
        .expect("a link signed for another domain was served");
    assert!(err.to_string().contains("not signed"), "{err}");
}
