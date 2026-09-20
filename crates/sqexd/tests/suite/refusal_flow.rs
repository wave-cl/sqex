//! SIP-35 §An origin that does not answer: a refusal a peer can act on. Y's peering-write limit is one an
//! hour; X, the home of Alice and Bob, carries Alice's Move and is refused
//! Bob's with `rate_limited`. X holds its writes to Y, records the refusal
//! where `/status` shows it, and when Bob's create is carried to Y and
//! refused for want of his Move, Bob is answered `origin_refused` -- the
//! origin answered -- and not `origin_away`.

use std::net::SocketAddr;
use std::path::Path;

use sqex_proto::channel::{CreateAt, Invitee, Role, Visibility};
use sqex_proto::home::{Hint, Hinted};
use sqex_proto::refusal::{Code, Refusal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};
use crate::reaching_flow::{exchange_in, free_port, i_live_here, identity, key_in};

/// An open exchange whose peering-write limit is `n` an hour.
async fn origin_with_limit(
    dir: &Path,
    listen: SocketAddr,
    domain: &str,
    found: &[(&str, PubKey, SocketAddr)],
    n: u32,
) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
         open_calls = true\nseed_relay_peers = []\nhome_secs = 1\n\n[limits]\npeering = [{n}, 3600]\n",
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

#[tokio::test]
async fn a_limit_at_the_origin_holds_the_home_off_and_is_passed_on() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let x_key = key_in(x_dir.path());
    let y_key = key_in(y_dir.path());
    let (x_at, y_at) = (free_port(), free_port());
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        &[y_key],
        &[("y.test", y_key, y_at)],
    )
    .await;
    let (_y_addr, y_pub) =
        origin_with_limit(y_dir.path(), y_at, "y.test", &[("x.test", x_key, x_at)], 1).await;
    assert_eq!((PubKey::new(x_pub), PubKey::new(y_pub)), (x_key, y_key));

    // Alice and Bob live at X and both hint Y. X carries Alice's Move --
    // Y's one write of the hour -- and is refused Bob's.
    let (alice_seed, alice) = identity(251);
    let (bob_seed, bob) = identity(252);
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let mut bob_at_x = Client::connect_as(x_addr, &x_pub, &bob_seed).await.unwrap();
    i_live_here(&mut alice_at_x, &alice_seed, x_key, "x.test").await;
    let (code, body) = alice_at_x
        .post(
            "/account/hint",
            Hint {
                origin: y_key,
                domain: "y.test".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(Hinted::decode(&body).unwrap().pulling);
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    i_live_here(&mut bob_at_x, &bob_seed, x_key, "x.test").await;
    let (code, _) = bob_at_x
        .post(
            "/account/hint",
            Hint {
                origin: y_key,
                domain: "y.test".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // X's status shows what Y refused, and the hold in force.
    let mut refused = None;
    for _ in 0..40 {
        let (code, body) = alice_at_x.get("/status").await.unwrap();
        assert_eq!(code, 200);
        let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let row = status["origins"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["key"] == y_key.to_string()).cloned());
        if let Some(r) = row
            && !r["last_refused"].is_null()
        {
            refused = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let row = refused.expect("X never recorded Y's refusal");
    assert_eq!(row["last_refused"]["code"], 429, "{row}");
    assert_eq!(row["last_refused"]["path"], "/peer/moved", "{row}");
    assert!(
        row["last_refused"]["wait"].as_u64().unwrap_or(0) > 0,
        "{row}"
    );
    assert!(
        row["held_until"].as_u64().is_some(),
        "no hold in force: {row}"
    );

    // Bob's create, carried to Y: Y holds no Move for him and refuses; Bob
    // is told the origin refused, not that it was away.
    let sb = Signer::new(bob_seed, bob, y_pub);
    let channel = [252u8; 32];
    let req = sb.create_chained(
        &mut Chain::default(),
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "refused",
        vec![Invitee {
            account: alice,
            role: Role::Member,
        }],
    );
    let (code, body) = bob_at_x
        .post(
            "/channel/create_at",
            CreateAt {
                origin: y_key,
                create: req.encode(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 502, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::OriginRefused);
}
