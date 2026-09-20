//! SIP-68 §Collecting wakes: wakes follow the account home. Alice's phone left an endpoint
//! at X; Alice moves to H. H copies the registration, so a post at H for
//! Alice wakes the phone; X keeps its own and goes on waking for a post
//! at X. A registration the phone made at H after the Move stands over
//! the copied one, and an endpoint H's own policy refuses is not held.

use std::net::SocketAddr;

use sqex_proto::channel::{Invitee, Role, Visibility};
use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqex_proto::device::Register as DeviceRegister;
use sqex_proto::home::{Move, Moving};
use sqex_proto::peer::{PullWakes, Wakes};
use sqex_proto::wake::Register;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::backup_home_flow::{exchange_in, free_port, identity, key_in, seed_in};
use crate::common;
use crate::common::{Chain, Signer, instance_for};
use crate::wake_flow::{Distributor, distributor, wakes_within};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn enrol(c: &mut Client, account_seed: &[u8; 32], device: &PubKey) {
    let n = now();
    let credential = Credential::issue(account_seed, device, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let (code, body) = c
        .post("/device/register", DeviceRegister { credential }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn register_wake(c: &mut Client, d: &Distributor) -> u16 {
    let (code, _) = c
        .post(
            "/wake/register",
            Register {
                ttl: 3600,
                endpoint: d.url.clone(),
            }
            .encode(),
        )
        .await
        .unwrap();
    code
}

async fn move_to(
    c: &mut Client,
    seed: &[u8; 32],
    home: &PubKey,
    domain: &str,
    origins: Vec<(PubKey, String)>,
    issued: u64,
) {
    let (code, body) = c
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(seed, home, issued),
                domain: domain.into(),
                origins,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

/// A public room by `owner` with `member` in it, and one post -- the
/// event that wakes `member`'s devices at this exchange.
async fn room_and_post(
    c: &mut Client,
    owner_seed: [u8; 32],
    owner: PubKey,
    server_pub: [u8; 32],
    member: PubKey,
    channel: [u8; 32],
    text: &[u8],
) {
    let s = Signer::new(owner_seed, owner, server_pub);
    let mut chain = Chain::default();
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "wake",
        vec![Invitee {
            account: member,
            role: Role::Member,
        }],
    );
    let (code, body) = c.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let info = s.info(c, channel).await;
    let post = s.post_chained(&mut chain, channel, info.instance, 0, 0, text.to_vec());
    let (code, body) = c.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn wakes_as_home(
    x_addr: SocketAddr,
    x_pub: [u8; 32],
    h_seed: &[u8; 32],
    account: &PubKey,
) -> Wakes {
    let mut as_h = Client::connect_as(x_addr, &x_pub, h_seed).await.unwrap();
    let (code, body) = as_h
        .post("/peer/wakes", PullWakes { account: *account }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Wakes::decode(&body).unwrap()
}

#[tokio::test]
async fn a_wake_registered_before_a_move_is_copied_to_the_new_home() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (h_key, _) = key_in(h_dir.path());
    let (x_at, h_at) = (free_port(), free_port());
    let (alice_seed, alice) = identity(101);
    let (phone_seed, phone) = identity(102);
    let (bob_seed, bob) = identity(103);
    let (carol_seed, carol) = identity(104);
    let (stranger_seed, _) = identity(105);
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

    // Alice lives at X; her phone registers there and leaves an endpoint.
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_x,
        &alice_seed,
        &x_key,
        "x.test",
        vec![],
        now(),
    )
    .await;
    let mut phone_at_x = Client::connect_as(x_addr, &x_pub, &phone_seed)
        .await
        .unwrap();
    enrol(&mut phone_at_x, &alice_seed, &phone).await;
    assert_eq!(register_wake(&mut phone_at_x, &pushes).await, 200);
    drop(phone_at_x);

    // A stranger is refused the registrations.
    let mut s = Client::connect_as(x_addr, &x_pub, &stranger_seed)
        .await
        .unwrap();
    let (code, _) = s
        .post("/peer/wakes", PullWakes { account: alice }.encode())
        .await
        .unwrap();
    assert_eq!(
        code, 404,
        "somebody other than the home was given the registrations"
    );

    // Alice moves to H, naming X. H copies the registration.
    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_h,
        &alice_seed,
        &h_key,
        "h.test",
        vec![(x_key, "x.test".into())],
        now() + 1,
    )
    .await;
    // Told at X too, as a client's move does, so X serves her as away.
    move_to(
        &mut alice_at_x,
        &alice_seed,
        &h_key,
        "h.test",
        vec![],
        now() + 1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

    // Something for Alice arrives at H: Bob's room there. The phone is
    // woken from H, though it never connected there.
    let mut bob_at_h = Client::connect_as(h_addr, &h_pub, &bob_seed).await.unwrap();
    room_and_post(
        &mut bob_at_h,
        bob_seed,
        bob,
        h_pub,
        alice,
        [101u8; 32],
        b"at h",
    )
    .await;
    assert!(
        wakes_within(&pushes, 1, 8).await,
        "the phone was not woken from the new home"
    );

    // X kept its own: something for Alice at X still wakes the phone.
    let mut carol_at_x = Client::connect_as(x_addr, &x_pub, &carol_seed)
        .await
        .unwrap();
    room_and_post(
        &mut carol_at_x,
        carol_seed,
        carol,
        x_pub,
        alice,
        [102u8; 32],
        b"at x",
    )
    .await;
    assert!(
        wakes_within(&pushes, 2, 8).await,
        "the former home stopped waking for a channel it orders"
    );
    let still = wakes_as_home(x_addr, x_pub, &seed_in(h_dir.path()), &alice).await;
    assert_eq!(still.rows.len(), 1, "X's registration was taken");
    assert_eq!(still.rows[0].device, phone);
}

#[tokio::test]
async fn a_registration_the_device_made_at_the_home_stands() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (h_key, _) = key_in(h_dir.path());
    let (x_at, h_at) = (free_port(), free_port());
    let (alice_seed, alice) = identity(106);
    let (bob_seed, bob) = identity(107);
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
    let old = distributor(200).await;
    let new = distributor(200).await;

    // Alice, her own device, registered at X to `old`...
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_x,
        &alice_seed,
        &x_key,
        "x.test",
        vec![],
        now(),
    )
    .await;
    assert_eq!(register_wake(&mut alice_at_x, &old).await, 200);
    // ...and at H to `new`, before her Move is presented there.
    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    assert_eq!(register_wake(&mut alice_at_h, &new).await, 200);
    move_to(
        &mut alice_at_h,
        &alice_seed,
        &h_key,
        "h.test",
        vec![(x_key, "x.test".into())],
        now() + 1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

    let mut bob_at_h = Client::connect_as(h_addr, &h_pub, &bob_seed).await.unwrap();
    room_and_post(
        &mut bob_at_h,
        bob_seed,
        bob,
        h_pub,
        alice,
        [106u8; 32],
        b"at h",
    )
    .await;
    assert!(
        wakes_within(&new, 1, 8).await,
        "her own registration at H did not wake her"
    );
    assert!(
        !wakes_within(&old, 1, 3).await,
        "the copied registration replaced her own"
    );
}

#[tokio::test]
async fn an_endpoint_the_home_would_not_post_to_is_not_held() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (h_key, _) = key_in(h_dir.path());
    let (x_at, h_at) = (free_port(), free_port());
    let (alice_seed, alice) = identity(108);
    let (bob_seed, bob) = identity(109);
    // X admits loopback http; H does not.
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
        "",
    )
    .await;
    let pushes = distributor(200).await;
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_x,
        &alice_seed,
        &x_key,
        "x.test",
        vec![],
        now(),
    )
    .await;
    assert_eq!(register_wake(&mut alice_at_x, &pushes).await, 200);
    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_h,
        &alice_seed,
        &h_key,
        "h.test",
        vec![(x_key, "x.test".into())],
        now() + 1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;

    let mut bob_at_h = Client::connect_as(h_addr, &h_pub, &bob_seed).await.unwrap();
    room_and_post(
        &mut bob_at_h,
        bob_seed,
        bob,
        h_pub,
        alice,
        [108u8; 32],
        b"at h",
    )
    .await;
    assert!(
        !wakes_within(&pushes, 1, 3).await,
        "H posted to an endpoint its policy refuses"
    );
    // X still answers it; nothing was taken.
    let still = wakes_as_home(x_addr, x_pub, &seed_in(h_dir.path()), &alice).await;
    assert_eq!(still.rows.len(), 1);
}
