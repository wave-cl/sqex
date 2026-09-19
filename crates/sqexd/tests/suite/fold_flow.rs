//! SIP-71: a direct message opened twice. Alice, the lower key, opened it
//! at her home A; Bob opened it at his exchange B, as a client from before
//! SIP-60 does. A learns of B's copy, tells B, and B folds it: the log is
//! kept for the two of them, the identifier points at A, and once Bob says
//! B is his home, B pulls the conversation and he reads and writes it there.

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByChannel, Entries, Invitee, Role, TYPE_FOLDED, TYPE_HOME, TYPE_INFO, Visibility,
    direct_message_id,
};
use sqex_proto::home::{Move, Moving};
use sqex_proto::peer::{PeerFolded, PeerMoved};
use sqex_proto::refusal::{Code, Refusal};
use sqnr::Client;
use sqnr_core::PubKey;

use crate::blob_flow::{seal_file, upload};
use crate::common;
use crate::common::{Chain, Signer, instance_for};
use crate::reaching_flow::{i_live_here, identity, now, pair, until};

/// Whether `c` can fetch the first chunk of `blob` here.
async fn can_fetch(c: &mut Client, blob: [u8; 32]) -> bool {
    let (code, body) = c
        .post(
            "/blob/get",
            sqex_proto::blob_store::GetChunk { blob, index: 0 }.encode(),
        )
        .await
        .unwrap();
    code == 200 && sqex_proto::blob_store::Chunk::decode(&body).unwrap().found
}

/// The folded log's member texts, as `/channel/folded` answers them.
async fn folded_texts(c: &mut Client, channel: [u8; 32]) -> (u16, Vec<String>) {
    let (code, body) = c
        .post("/channel/folded", ByChannel { channel }.encode(TYPE_FOLDED))
        .await
        .unwrap();
    if code != 200 {
        return (code, Vec::new());
    }
    let entries = Entries::decode(&body, false).unwrap();
    (
        code,
        entries
            .entries
            .iter()
            .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
            .map(|e| String::from_utf8_lossy(&e.body).into_owned())
            .collect(),
    )
}

#[tokio::test]
async fn a_stray_direct_message_is_folded_into_the_conversation() {
    let p = pair().await;
    let (a_addr, a_pub, b_addr, b_pub) = (p.a_addr, p.a_pub, p.b_addr, p.b_pub);
    let (a_key, b_key) = (PubKey::new(a_pub), PubKey::new(b_pub));

    // Alice holds the lower key, so the conversation is the one at her home.
    let (mut alice_seed, mut alice) = identity(71);
    let (mut bob_seed, mut bob) = identity(72);
    if bob.as_bytes() < alice.as_bytes() {
        std::mem::swap(&mut alice_seed, &mut bob_seed);
        std::mem::swap(&mut alice, &mut bob);
    }
    assert!(alice.as_bytes() < bob.as_bytes());
    let dm = direct_message_id(&alice, &bob);
    let (_, carol) = identity(73);
    let (carol_seed, _) = identity(73);

    // Bob opens it at B, his own exchange, without locating Alice.
    let mut bob_at_b = Client::connect_as(b_addr, &b_pub, &bob_seed).await.unwrap();
    let sb = Signer::new(bob_seed, bob, b_pub);
    let mut cb = Chain::default();
    let req = sb.create_chained(
        &mut cb,
        dm,
        instance_for(dm, 1),
        Visibility::Public,
        3600,
        "",
        vec![Invitee {
            account: alice,
            role: Role::Admin,
        }],
    );
    let (code, body) = bob_at_b
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let stray = sb.info(&mut bob_at_b, dm).await;
    let post = sb.post_chained(&mut cb, dm, stray.instance, 0, 0, b"stray one".to_vec());
    assert_eq!(
        bob_at_b
            .post("/channel/post", post.encode())
            .await
            .unwrap()
            .0,
        200
    );

    // Alice opens it at A, her home.
    let mut alice_at_a = Client::connect_as(a_addr, &a_pub, &alice_seed)
        .await
        .unwrap();
    let sa = Signer::new(alice_seed, alice, a_pub);
    let mut ca = Chain::default();
    let req = sa.create_chained(
        &mut ca,
        dm,
        instance_for(dm, 2),
        Visibility::Public,
        3600,
        "",
        vec![Invitee {
            account: bob,
            role: Role::Admin,
        }],
    );
    let (code, body) = alice_at_a
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let conv = sa.info(&mut alice_at_a, dm).await;
    assert_ne!(conv.instance, stray.instance);
    let post = sa.post_chained(&mut ca, dm, conv.instance, 0, 0, b"conv one".to_vec());
    assert_eq!(
        alice_at_a
            .post("/channel/post", post.encode())
            .await
            .unwrap()
            .0,
        200
    );

    // Controls, driven by hand as A over the peering link. Without Alice's
    // Move at B naming A, the telling is refused (uniformly, 404); so is
    // one that names the wrong lower key, or B's own instance; and a 409
    // says nothing is held under the identifier at all.
    let a_seed = SigningKey::from_bytes(
        &hex::decode(
            std::fs::read_to_string(p._dirs.0.path().join("host_key"))
                .unwrap()
                .trim(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    )
    .to_bytes();
    let mut a_at_b = Client::connect_as(b_addr, &b_pub, &a_seed).await.unwrap();
    let tell = PeerFolded {
        channel: dm,
        first: alice,
        instance: conv.instance,
        domain: "a.test".into(),
    };
    let (code, _) = a_at_b.post("/peer/folded", tell.encode()).await.unwrap();
    assert_eq!(code, 404, "a fold was taken without the lower key's Move");
    let (code, _) = a_at_b
        .post(
            "/peer/moved",
            PeerMoved {
                mv: Move::sign(&alice_seed, &a_key, now()),
                domain: "a.test".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    // SIP-75: a file in the stray, attached to it.
    let (_, sealed, blob) = seal_file(b"a photograph in the stray", 4096);
    assert!(upload(&mut bob_at_b, dm, &sealed, blob, 25, 0).await);
    assert!(can_fetch(&mut bob_at_b, blob).await);
    let (code, _) = a_at_b
        .post(
            "/peer/folded",
            PeerFolded {
                first: bob,
                ..tell.clone()
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 404, "a fold was taken naming the higher key as first");
    let (code, _) = a_at_b
        .post(
            "/peer/folded",
            PeerFolded {
                instance: stray.instance,
                ..tell.clone()
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 404, "a fold was taken naming B's own incarnation");
    let (code, _) = a_at_b
        .post(
            "/peer/folded",
            PeerFolded {
                channel: [71u8; 32],
                ..tell.clone()
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 409, "a fold of nothing was not 409");
    let (code, _) = bob_at_b
        .post("/channel/info", ByChannel { channel: dm }.encode(TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(code, 200, "a refused fold changed something");

    // The real thing: Alice says A is her home and hints at B. A asks B what
    // she is in there, finds the identifier it orders, and tells B.
    let (code, body) = alice_at_a
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &a_key, now() + 1),
                domain: "a.test".into(),
                origins: vec![(b_key, "b.test".into())],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let mut folded = false;
    for _ in 0..80 {
        let (code, _) = bob_at_b
            .post("/channel/info", ByChannel { channel: dm }.encode(TYPE_INFO))
            .await
            .unwrap();
        if code != 200 {
            folded = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    assert!(folded, "B never folded the stray");

    // While the record stands: the identifier points at A, to the pair and
    // nobody else; a create by Bob is sent there; the folded log reads to
    // both of them and to nobody else.
    let (code, body) = bob_at_b
        .post("/channel/home", ByChannel { channel: dm }.encode(TYPE_HOME))
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let home = sqex_proto::channel::Home::decode(&body).unwrap();
    assert_eq!((home.origin, home.domain.as_str()), (a_key, "a.test"));
    let mut carol_at_b = Client::connect_as(b_addr, &b_pub, &carol_seed)
        .await
        .unwrap();
    let (code, _) = carol_at_b
        .post("/channel/home", ByChannel { channel: dm }.encode(TYPE_HOME))
        .await
        .unwrap();
    assert_ne!(code, 200, "a fold record was disclosed to a third party");
    let _ = carol;

    let req = sb.create_chained(
        &mut Chain::default(),
        dm,
        instance_for(dm, 3),
        Visibility::Public,
        3600,
        "",
        vec![Invitee {
            account: alice,
            role: Role::Admin,
        }],
    );
    let (code, body) = bob_at_b
        .post("/channel/create", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 421, "{}", common::said(&body));
    let refusal = Refusal::decode(&body).unwrap();
    assert_eq!(refusal.code, Code::Replicated);
    let detail = refusal.detail.unwrap_or_default();
    assert!(
        detail.contains(&a_key.to_string()),
        "the refusal did not name A: {detail}"
    );

    assert_eq!(
        folded_texts(&mut bob_at_b, dm).await,
        (200, vec!["stray one".to_string()])
    );
    let mut alice_at_b = Client::connect_as(b_addr, &b_pub, &alice_seed)
        .await
        .unwrap();
    assert_eq!(
        folded_texts(&mut alice_at_b, dm).await,
        (200, vec!["stray one".to_string()])
    );
    assert_eq!(folded_texts(&mut carol_at_b, dm).await.0, 404);
    assert_eq!(
        folded_texts(&mut alice_at_a, dm).await.0,
        404,
        "A answered a folded log it never had"
    );
    // SIP-75: the stray's file is kept with its log, for the pair and
    // nobody else.
    assert!(
        can_fetch(&mut bob_at_b, blob).await,
        "the stray's file went with the channel"
    );
    assert!(
        can_fetch(&mut alice_at_b, blob).await,
        "the file is not served to the other member"
    );
    assert!(
        !can_fetch(&mut carol_at_b, blob).await,
        "the file is served to a third party"
    );

    // Bob says B is his home. The fold left A as an origin hint for him,
    // so B pulls the conversation and he reads it there, under A's
    // incarnation, and writes through B.
    i_live_here(&mut bob_at_b, &bob_seed, b_key, "b.test").await;
    assert_eq!(
        until(&mut bob_at_b, dm, |t| t == ["conv one"]).await,
        ["conv one"]
    );
    let info = sb.info(&mut bob_at_b, dm).await;
    assert_eq!(
        info.instance, conv.instance,
        "B serves something other than A's conversation"
    );
    let sb_at_a = Signer::new(bob_seed, bob, a_pub);
    let mut cb2 = Chain::default();
    let post = sb_at_a.post_chained(&mut cb2, dm, conv.instance, 0, 0, b"bob through b".to_vec());
    let (code, body) = bob_at_b.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        until(&mut alice_at_a, dm, |t| t.len() == 2).await,
        ["conv one", "bob through b"]
    );
    assert_eq!(until(&mut bob_at_b, dm, |t| t.len() == 2).await.len(), 2);
    // The folded log is still there to read.
    assert_eq!(
        folded_texts(&mut bob_at_b, dm).await,
        (200, vec!["stray one".to_string()])
    );
}
