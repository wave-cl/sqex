//! SIP-80: an origin that cannot be found. A home whose account hinted at
//! an origin nothing resolves backs off from it -- one cycle, two, four
//! -- instead of trying every cycle forever, lists it in `/status` as
//! unfound with the count and the next try, and, once the origin comes
//! up, finds it on the next attempt and clears the record.

use sqex_proto::home::{Move, Moving};
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::reaching_flow::{exchange_in, free_port, identity, key_in};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn origin_row(c: &mut Client, key: &PubKey) -> Option<serde_json::Value> {
    let (code, body) = c.get("/status").await.unwrap();
    assert_eq!(code, 200);
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    status["origins"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["key"] == key.to_string()).cloned())
}

async fn move_hinting(
    c: &mut Client,
    seed: &[u8; 32],
    home: &PubKey,
    origins: Vec<(PubKey, String)>,
) {
    let (code, body) = c
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(seed, home, now()),
                domain: "h.test".into(),
                origins,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

#[tokio::test]
async fn an_origin_with_no_address_is_tried_less_and_less() {
    let h_dir = tempfile::tempdir().unwrap();
    let (h_addr, h_pub) = exchange_in(h_dir.path(), free_port(), "h.test", &[], &[]).await;
    let h_key = PubKey::new(h_pub);
    let (alice_seed, _alice) = identity(81);
    // A key nothing knows, under a domain nothing resolves: SIP-60's
    // reach has nowhere to look.
    let (_, ghost) = identity(82);
    let mut alice = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    move_hinting(
        &mut alice,
        &alice_seed,
        &h_key,
        vec![(ghost, "ghost.test".into())],
    )
    .await;

    // Listed at once, as hinted, before any attempt: the row an operator
    // needed for an origin that never answered.
    let row = origin_row(&mut alice, &ghost)
        .await
        .expect("a hinted origin is not listed");
    assert_eq!(row["domain"], "ghost.test");
    assert!(row["reached"].is_null());

    // Eight seconds of a one-second cycle: attempts at 0, 1, 3 and 7 with
    // the hold doubling, eight or nine without it.
    while started.elapsed() < std::time::Duration::from_secs(8) {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let row = origin_row(&mut alice, &ghost).await.unwrap();
    let tries = row["unfound"]["tries"].as_u64().unwrap_or(0);
    assert!(
        (3..=5).contains(&tries),
        "the home tried an origin with no address {tries} times in eight seconds: {row}"
    );
    assert_eq!(row["unfound"]["why"], "no_address", "{row}");
    assert!(
        row["unfound"]["next_in"].as_u64().unwrap_or(0) >= 1,
        "{row}"
    );
    assert!(
        row["unfound"]["since"].as_u64().unwrap_or(0) >= now() - 10,
        "{row}"
    );

    // The hint withdrawn -- a Move with no origins -- the row goes with
    // it: nothing will try the origin again, so nothing would clear it.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    move_hinting(&mut alice, &alice_seed, &h_key, vec![]).await;
    let mut gone = false;
    for _ in 0..40 {
        if origin_row(&mut alice, &ghost).await.is_none() {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert!(
        gone,
        "an unfound origin nobody hints at any more stayed listed"
    );
}

#[tokio::test]
async fn an_origin_that_comes_up_is_found_on_the_next_try_and_cleared() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let x_key = key_in(x_dir.path());
    let x_at = free_port();
    // H knows where X will be; X is not there yet.
    let (h_addr, h_pub) = exchange_in(
        h_dir.path(),
        free_port(),
        "h.test",
        &[],
        &[("x.test", x_key, x_at)],
    )
    .await;
    let h_key = PubKey::new(h_pub);
    let (alice_seed, _alice) = identity(83);
    let mut alice = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    move_hinting(
        &mut alice,
        &alice_seed,
        &h_key,
        vec![(x_key, "x.test".into())],
    )
    .await;

    // Missed twice: unreachable, and held.
    let mut row = None;
    for _ in 0..120 {
        let r = origin_row(&mut alice, &x_key).await;
        if let Some(r) = r
            && r["unfound"]["tries"].as_u64().unwrap_or(0) >= 2
        {
            row = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let row = row.expect("H never recorded X as unfound");
    assert_eq!(row["unfound"]["why"], "unreachable", "{row}");
    assert!(row["reached"].is_null(), "{row}");

    // X comes up where H expected it. The next attempt finds it; the
    // record is cleared and the origin reads as reached.
    let (x_addr, _) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        &[],
        &[("h.test", h_key, h_addr)],
    )
    .await;
    assert_eq!(x_addr, x_at);
    let mut found = None;
    for _ in 0..160 {
        let r = origin_row(&mut alice, &x_key).await;
        if let Some(r) = r
            && r["unfound"].is_null()
            && !r["reached"].is_null()
        {
            found = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let row = found.expect("H never found X after it came up");
    assert!(row["reached"].as_u64().unwrap_or(999) < 30, "{row}");
}

/// SIP-80 for a configured origin: a `[[replicate]]` origin that takes no
/// connection is held off like a hinted one, and listed the same way.
#[tokio::test]
async fn a_configured_origin_that_cannot_be_reached_is_held_off() {
    use sqexd::config::FileConfig;
    let dir = tempfile::tempdir().unwrap();
    let dead_dir = tempfile::tempdir().unwrap();
    let dead_key = key_in(dead_dir.path());
    let dead_at = free_port();
    let key_path = dir.path().join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n\n[[replicate]]\norigin = {:?}\naddr = {:?}\n\
         channels = [{:?}]\ninterval_secs = 1\ndomain = \"dead.test\"\n",
        key_path.to_string_lossy(),
        dir.path().join("sqex.state").to_string_lossy(),
        dead_key.to_string(),
        dead_at.to_string(),
        bs58::encode([7u8; 32]).into_string(),
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
    let (seed, _) = identity(84);
    let mut c = Client::connect_as(addr, &server_pub, &seed).await.unwrap();

    // Three misses in, the row says unreachable and the next try is further
    // off than the interval -- the hold is four seconds by then, and a poll
    // catches it with at least two left. Without the hold there is no row
    // at all: the loop never said what it could not reach.
    let mut row = None;
    for _ in 0..240 {
        if let Some(r) = origin_row(&mut c, &dead_key).await
            && r["unfound"]["tries"].as_u64().unwrap_or(0) >= 3
        {
            row = Some(r);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let row = row.expect("the replica never recorded its origin as unfound");
    assert_eq!(row["unfound"]["why"], "unreachable", "{row}");
    assert!(
        row["unfound"]["next_in"].as_u64().unwrap_or(0) >= 2,
        "the third miss did not double the hold: {row}"
    );
    assert_eq!(row["domain"], "dead.test", "{row}");
}
