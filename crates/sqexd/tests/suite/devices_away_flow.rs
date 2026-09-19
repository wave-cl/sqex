//! SIP-81: devices of an account that moved. Alice registered a phone and
//! a laptop at X, then moved to H, where she revoked the phone and linked
//! a tablet. X still holds phone and laptop in its own registry; asked
//! for Alice's devices, it answers what H lists -- laptop and tablet --
//! and its own stale pair only when H cannot be asked.

use std::net::SocketAddr;

use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqex_proto::device::{Devices, ListDevices, Register, Revoke};
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

/// A device registers itself with a credential the account signed.
async fn enrol(c: &mut Client, account_seed: &[u8; 32], device: &PubKey) {
    let n = now();
    let credential = Credential::issue(account_seed, device, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let (code, body) = c
        .post("/device/register", Register { credential }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn listed(c: &mut Client, account: &PubKey) -> Vec<PubKey> {
    let (code, body) = c
        .post("/device/list", ListDevices { account: *account }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let mut out: Vec<PubKey> = Devices::decode(&body)
        .unwrap()
        .devices
        .into_iter()
        .map(|d| d.device)
        .collect();
    out.sort_by_key(|k| k.to_string());
    out
}

async fn move_to(c: &mut Client, seed: &[u8; 32], home: &PubKey, domain: &str, issued: u64) {
    let (code, body) = c
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(seed, home, issued),
                domain: domain.into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

fn sorted(mut v: Vec<PubKey>) -> Vec<PubKey> {
    v.sort_by_key(|k| k.to_string());
    v
}

#[tokio::test]
async fn a_former_home_lists_the_devices_the_home_lists() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_at, h_at): (SocketAddr, SocketAddr) = (free_port(), free_port());
    let x_key = key_in(x_dir.path());
    let h_key = key_in(h_dir.path());
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        &[],
        &[("h.test", h_key, h_at)],
    )
    .await;
    let (h_addr, h_pub) = exchange_in(
        h_dir.path(),
        h_at,
        "h.test",
        &[],
        &[("x.test", x_key, x_addr)],
    )
    .await;
    let (alice_seed, alice) = identity(91);
    let (phone_seed, phone) = identity(92);
    let (laptop_seed, laptop) = identity(93);
    let (tablet_seed, tablet) = identity(94);
    let (bob_seed, _bob) = identity(95);

    // At X: Alice's phone and laptop register.
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    move_to(&mut alice_at_x, &alice_seed, &x_key, "x.test", now()).await;
    let mut phone_at_x = Client::connect_as(x_addr, &x_pub, &phone_seed)
        .await
        .unwrap();
    enrol(&mut phone_at_x, &alice_seed, &phone).await;
    let mut laptop_at_x = Client::connect_as(x_addr, &x_pub, &laptop_seed)
        .await
        .unwrap();
    enrol(&mut laptop_at_x, &alice_seed, &laptop).await;
    let mut bob_at_x = Client::connect_as(x_addr, &x_pub, &bob_seed).await.unwrap();
    assert_eq!(
        listed(&mut bob_at_x, &alice).await,
        sorted(vec![phone, laptop])
    );

    // Alice moves to H; the laptop and a new tablet register there, and
    // the phone, lost, is revoked there.
    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    move_to(&mut alice_at_h, &alice_seed, &h_key, "h.test", now() + 1).await;
    // X learns of the Move as SIP-59 has it learn: the account tells it.
    move_to(&mut alice_at_x, &alice_seed, &h_key, "h.test", now() + 1).await;
    let mut laptop_at_h = Client::connect_as(h_addr, &h_pub, &laptop_seed)
        .await
        .unwrap();
    enrol(&mut laptop_at_h, &alice_seed, &laptop).await;
    let mut tablet_at_h = Client::connect_as(h_addr, &h_pub, &tablet_seed)
        .await
        .unwrap();
    enrol(&mut tablet_at_h, &alice_seed, &tablet).await;
    let (code, body) = alice_at_h
        .post(
            "/device/revoke",
            Revoke {
                device: phone,
                revocation: None,
            }
            .encode(),
        )
        .await
        .unwrap();
    // The phone never registered at H: revoking it there is a no-op or a
    // refusal, and either way H's list is laptop and tablet.
    let _ = (code, body);
    assert_eq!(
        listed(&mut alice_at_h, &alice).await,
        sorted(vec![laptop, tablet])
    );

    // Bob, at X, asks for Alice's devices and is told what H lists, not
    // the phone in a drawer. X's own registry still has the phone.
    assert_eq!(
        listed(&mut bob_at_x, &alice).await,
        sorted(vec![laptop, tablet]),
        "a former home listed the devices the account had when it left"
    );
    let _ = tablet_seed;
}

#[tokio::test]
async fn a_former_home_that_cannot_ask_the_home_answers_its_own_registry() {
    let x_dir = tempfile::tempdir().unwrap();
    let ghost_dir = tempfile::tempdir().unwrap();
    let x_at = free_port();
    let ghost_key = key_in(ghost_dir.path());
    // X knows where Carol's home would be; nothing listens there.
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        &[],
        &[("g.test", ghost_key, free_port())],
    )
    .await;
    let x_key = key_in(x_dir.path());
    let (carol_seed, carol) = identity(96);
    let (watch_seed, watch) = identity(97);
    let mut carol_at_x = Client::connect_as(x_addr, &x_pub, &carol_seed)
        .await
        .unwrap();
    move_to(&mut carol_at_x, &carol_seed, &x_key, "x.test", now()).await;
    let mut watch_at_x = Client::connect_as(x_addr, &x_pub, &watch_seed)
        .await
        .unwrap();
    enrol(&mut watch_at_x, &carol_seed, &watch).await;
    // Carol tells X she now lives at G, which cannot be reached.
    move_to(
        &mut carol_at_x,
        &carol_seed,
        &ghost_key,
        "g.test",
        now() + 1,
    )
    .await;
    // X answers what it held when she left, rather than nothing or a
    // refusal: reading goes on through an outage.
    assert_eq!(listed(&mut watch_at_x, &carol).await, vec![watch]);
}
