//! SIP-35 §What a copy tells its members: an exchange that stores entries it
//! pulled tells its present members as it would of an entry it ordered --
//! the SIP-30 event on their streams, and the SIP-45 wake to their devices
//! that are not listening. Alice lives at H and reads Carol's room at X
//! through H's copy; her phone is registered at H and nowhere else. Carol
//! posts at X; H pulls; the phone is woken and Alice's stream at H says
//! the room moved.

use sqex_proto::events::{Event as WireEvent, Framer, Subscribe};
use sqnr::Client;

use crate::backup_home_flow::{exchange_in, free_port, identity, key_in};
use crate::wake_flow::{distributor, wakes_within};
use crate::wakes_home_flow::{enrol, move_to, register_wake, room_and_post};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Whether `stream` carries a `Channel` event for `channel` within `secs`.
async fn channel_moved(stream: &mut sqnr::Stream, channel: [u8; 32], secs: u64) -> bool {
    let mut framer = Framer::new();
    let read = async {
        loop {
            let Ok(Some(chunk)) = stream.next().await else {
                return false;
            };
            for e in framer.feed(&chunk).unwrap() {
                if let WireEvent::Channel { channel: c, .. } = e
                    && c == channel
                {
                    return true;
                }
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(secs), read)
        .await
        .unwrap_or(false)
}

#[tokio::test]
async fn a_copy_tells_its_members_of_what_it_pulls() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (h_key, _) = key_in(h_dir.path());
    let (x_at, h_at) = (free_port(), free_port());
    let (alice_seed, alice) = identity(111);
    let (phone_seed, phone) = identity(112);
    let (carol_seed, carol) = identity(113);
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        "",
        &[("h.test", h_key, h_at)],
        1,
        "wake_loopback = true",
    )
    .await;
    let (h_addr, h_pub) = exchange_in(
        h_dir.path(),
        h_at,
        "h.test",
        "",
        &[("x.test", x_key, x_addr)],
        1,
        "wake_loopback = true",
    )
    .await;
    let pushes = distributor(200).await;

    // Alice lives at H, reading through it what X orders; told at X too,
    // so X serves her as away and tells H of what she is put into.
    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_h,
        &alice_seed,
        &h_key,
        "h.test",
        vec![(x_key, "x.test".into())],
        now(),
    )
    .await;
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    // A later `issued`: X may already have learned the first from H, and
    // the same Move presented twice is a stale one.
    move_to(
        &mut alice_at_x,
        &alice_seed,
        &h_key,
        "h.test",
        vec![],
        now() + 2,
    )
    .await;

    // Her phone is registered at H, and nowhere else: only the copy can
    // wake it.
    let mut phone_at_h = Client::connect_as(h_addr, &h_pub, &phone_seed)
        .await
        .unwrap();
    enrol(&mut phone_at_h, &alice_seed, &phone).await;
    assert_eq!(register_wake(&mut phone_at_h, &pushes).await, 200);
    drop(phone_at_h);

    // And her other device holds an event stream at H.
    let mut stream = alice_at_h
        .stream(
            "POST",
            "/events",
            Subscribe {
                version: sqex_proto::events::VERSION,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);

    // Carol's room at X, with Alice in it, and a post. X tells H of the
    // invitation; H pulls the room; what it stored is what it tells of.
    let mut carol_at_x = Client::connect_as(x_addr, &x_pub, &carol_seed)
        .await
        .unwrap();
    let room = [111u8; 32];
    room_and_post(
        &mut carol_at_x,
        carol_seed,
        carol,
        x_pub,
        alice,
        room,
        b"at x",
    )
    .await;

    assert!(
        wakes_within(&pushes, 1, 10).await,
        "the phone was not woken by the copy for what it pulled"
    );
    assert!(
        channel_moved(&mut stream, room, 10).await,
        "the stream at the copy did not say the room moved"
    );
    let _ = phone;
}
