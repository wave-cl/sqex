//! SIP-76: a member tells its own home. B cannot find A (its finder does
//! not know `a.test`), so SIP-60's telling from B to A never lands. A
//! direct message Alice opens at B through A still reaches A, because A
//! hinted itself on the create it carried; a group Bob makes at B with
//! Alice in it reaches A once Alice hints A at B by hand; and a device of
//! an account not homed here is told its hint pulled nothing.

use sqex_proto::channel::{
    ByChannel, CreateAt, Invitee, Role, TYPE_INFO, Visibility, direct_message_id,
};
use sqex_proto::home::{Hint, Hinted};
use sqex_proto::locate::{Locate, Located};
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};
use crate::reaching_flow::{exchange_in, free_port, i_live_here, identity, key_in, until};

async fn hint(c: &mut Client, origin: PubKey, domain: &str) -> Hinted {
    let (code, body) = c
        .post(
            "/account/hint",
            Hint {
                origin,
                domain: domain.into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Hinted::decode(&body).unwrap()
}

#[tokio::test]
async fn a_home_that_cannot_be_told_hints_itself_and_is_hinted() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_key = key_in(a_dir.path());
    let b_key = key_in(b_dir.path());
    let (a_at, b_at) = (free_port(), free_port());
    // A finds B; B finds nobody.
    let (a_addr, a_pub) = exchange_in(
        a_dir.path(),
        a_at,
        "a.test",
        &[b_key],
        &[("b.test", b_key, b_at)],
    )
    .await;
    let (b_addr, b_pub) = exchange_in(b_dir.path(), b_at, "b.test", &[a_key], &[]).await;
    assert_eq!((PubKey::new(a_pub), PubKey::new(b_pub)), (a_key, b_key));

    // Bob, the lower key, lives at B; Alice at A.
    let (mut alice_seed, mut alice) = identity(241);
    let (mut bob_seed, mut bob) = identity(242);
    if alice.as_bytes() < bob.as_bytes() {
        std::mem::swap(&mut alice_seed, &mut bob_seed);
        std::mem::swap(&mut alice, &mut bob);
    }
    let dm = direct_message_id(&alice, &bob);
    let mut bob_at_b = Client::connect_as(b_addr, &b_pub, &bob_seed).await.unwrap();
    i_live_here(&mut bob_at_b, &bob_seed, b_key, "b.test").await;
    let mut alice_at_a = Client::connect_as(a_addr, &a_pub, &alice_seed)
        .await
        .unwrap();
    i_live_here(&mut alice_at_a, &alice_seed, a_key, "a.test").await;
    let (code, body) = alice_at_a
        .post(
            "/account/locate",
            Locate {
                target: format!("{bob}@b.test"),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(Located::decode(&body).unwrap().home, b_key);

    // The direct message, created at B through A. B cannot tell A; A
    // hints itself, and the copy comes.
    let sa = Signer::new(alice_seed, alice, b_pub);
    let mut ca = Chain::default();
    let req = sa.create_chained(
        &mut ca,
        dm,
        instance_for(dm, 0),
        Visibility::Public,
        3600,
        "",
        vec![Invitee {
            account: bob,
            role: Role::Member,
        }],
    );
    let (code, body) = alice_at_a
        .post(
            "/channel/create_at",
            CreateAt {
                origin: b_key,
                create: req.encode(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let sb = Signer::new(bob_seed, bob, b_pub);
    let mut cb = Chain::default();
    let info = sb.info(&mut bob_at_b, dm).await;
    let post = sb.post_chained(&mut cb, dm, info.instance, 0, 0, b"hi from b".to_vec());
    assert_eq!(
        bob_at_b
            .post("/channel/post", post.encode())
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(
        until(&mut alice_at_a, dm, |t| t == ["hi from b"]).await,
        ["hi from b"]
    );

    // Carol, a device of an account not homed here, is told her hint
    // pulled nothing, and nothing is recorded for her.
    let (carol_seed, carol) = identity(243);
    let mut carol_at_a = Client::connect_as(a_addr, &a_pub, &carol_seed)
        .await
        .unwrap();
    let h = hint(&mut carol_at_a, b_key, "b.test").await;
    assert!(
        !h.pulling,
        "A took a hint for an account it is not the home of"
    );

    // Then she says A is her home. A group Bob makes at B with her in it:
    // nothing tells A, and A has no hint for her. Her client hints A at B
    // by hand, and A pulls it.
    i_live_here(&mut carol_at_a, &carol_seed, a_key, "a.test").await;
    let group = [242u8; 32];
    let req = sb.create_chained(
        &mut Chain::default(),
        group,
        instance_for(group, 0),
        Visibility::Public,
        3600,
        "untold",
        vec![Invitee {
            account: carol,
            role: Role::Member,
        }],
    );
    let (code, body) = bob_at_b
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let (code, _) = carol_at_a
        .post(
            "/channel/info",
            ByChannel { channel: group }.encode(TYPE_INFO),
        )
        .await
        .unwrap();
    assert_ne!(code, 200, "A learned of the group with nobody telling it");
    let h = hint(&mut carol_at_a, b_key, "b.test").await;
    assert!(h.pulling, "A did not take Carol's hint");
    let mut seen = false;
    for _ in 0..80 {
        let (code, _) = carol_at_a
            .post(
                "/channel/info",
                ByChannel { channel: group }.encode(TYPE_INFO),
            )
            .await
            .unwrap();
        if code == 200 {
            seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    assert!(seen, "A never pulled the group after the hint");
}
