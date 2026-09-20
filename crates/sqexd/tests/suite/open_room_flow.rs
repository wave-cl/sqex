//! SIP-65 §The member's word: a room shared across two exchanges that list nobody, on a
//! member's word. Alice at X and Bob at Y share a private channel (the
//! consent SIP-65 reads); Alice joins a room at X naming Y with her word,
//! Bob joins at Y and, on seeing her homed at X, names X with his; each
//! sees the other, and the pair's bridge comes up over the unlisted link.
//! Carol, who shares nothing private with Bob, is not seen on her own
//! word; a plain shared join naming a stranger is refused; a word signed
//! for another exchange is malformed.

use sqex_proto::room::{HomedMember, JoinShared, JoinSharedWord, RoomId};
use sqex_proto::session::{CallAck, CallOpen, CallState, Open, OpenAck, OpenState, RoomWord};
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::open_calls_flow::{identity, now, pair};

/// Join with words for each exchange named, answered with homes.
async fn join_word(
    c: &mut Client,
    seed: &[u8; 32],
    room: &RoomId,
    me: &PubKey,
    share: &[(PubKey, &str)],
) -> (u16, Vec<HomedMember>) {
    let req = JoinSharedWord {
        handle: room.handle(),
        proof: room.proof(me),
        share: share
            .iter()
            .map(|(k, d)| {
                (
                    *k,
                    (*d).to_string(),
                    RoomWord::sign(seed, &room.handle(), k, now(), None),
                )
            })
            .collect(),
    };
    let (code, body) = c.post("/room/join", req.encode()).await.unwrap();
    if code != 200 {
        return (code, Vec::new());
    }
    (
        code,
        sqex_proto::room::Homed::decode(&body).unwrap().members,
    )
}

/// Join again until the roster shows `who` at `home`, re-joining every
/// pass as a client's heartbeat does; a share goes every `SHARE_SECS`.
async fn until_seen(
    c: &mut Client,
    seed: &[u8; 32],
    room: &RoomId,
    me: &PubKey,
    share: &[(PubKey, &str)],
    who: &PubKey,
    home: &PubKey,
) -> Option<Vec<HomedMember>> {
    for _ in 0..160 {
        let (code, members) = join_word(c, seed, room, me, share).await;
        assert_eq!(code, 200);
        if members
            .iter()
            .any(|m| m.identity == *who && m.home == *home)
        {
            return Some(members);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test]
async fn a_room_is_shared_across_two_exchanges_that_list_nobody() {
    let p = pair(true, false, 231, 232).await;
    let (x_key, y_key) = (PubKey::new(p.x_pub), PubKey::new(p.y_pub));
    let (alice_seed, alice, bob_seed, bob) = (p.alice_seed, p.alice, p.bob_seed, p.bob);
    let (carol_seed, carol) = identity(233);
    let mut a = Client::connect_as(p.x_addr, &p.x_pub, &alice_seed)
        .await
        .unwrap();
    let mut b = Client::connect_as(p.y_addr, &p.y_pub, &bob_seed)
        .await
        .unwrap();
    let mut c = Client::connect_as(p.x_addr, &p.x_pub, &carol_seed)
        .await
        .unwrap();
    let room = RoomId::generate();

    // Controls. A plain shared join naming a stranger is refused as SIP-39 §Sharing on the relay link
    // refuses it; a word signed for the wrong exchange is malformed and
    // nothing is joined.
    let (code, body) = a
        .post(
            "/room/join",
            JoinShared::new(&room, &alice, vec![y_key]).encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403, "{}", common::said(&body));
    let wrong = JoinSharedWord {
        handle: room.handle(),
        proof: room.proof(&alice),
        share: vec![(
            y_key,
            "y.test".into(),
            RoomWord::sign(&alice_seed, &room.handle(), &x_key, now(), None),
        )],
    };
    let (code, body) = a.post("/room/join", wrong.encode()).await.unwrap();
    assert_eq!(code, 400, "{}", common::said(&body));

    // Carol first: she is in the room at X and asks for Y on her own
    // word, and she shares nothing private with Bob. Bob, in the room
    // at Y, never sees her.
    let (code, _) = join_word(&mut c, &carol_seed, &room, &carol, &[(y_key, "y.test")]).await;
    assert_eq!(code, 200);
    let (code, members) = join_word(&mut b, &bob_seed, &room, &bob, &[]).await;
    assert_eq!(code, 200);
    assert!(members.is_empty());
    assert!(
        until_seen(&mut b, &bob_seed, &room, &bob, &[], &carol, &x_key)
            .await
            .is_none(),
        "Carol was admitted on her own word"
    );
    // Alice joins naming Y. Her word stands -- she and Bob share a
    // private channel -- and X's roster comes over: Alice, and Carol
    // beside her, because a share is the room as X has it.
    let (code, members) = join_word(&mut a, &alice_seed, &room, &alice, &[(y_key, "y.test")]).await;
    assert_eq!(code, 200);
    assert!(members.iter().all(|m| m.identity == carol));
    let seen = until_seen(&mut b, &bob_seed, &room, &bob, &[], &alice, &x_key)
        .await
        .expect("Bob never saw Alice at X");
    assert!(seen.iter().any(|m| m.identity == carol && m.home == x_key));
    // Nothing comes back to X until Bob names it: a share back over an
    // unlisted link needs a word of Bob's.
    let (_, members) = join_word(&mut a, &alice_seed, &room, &alice, &[(y_key, "y.test")]).await;
    assert!(
        !members.iter().any(|m| m.identity == bob),
        "Y shared back without a word"
    );
    // Bob names X, as a client does on seeing a member homed there; the
    // domain may be empty, since Y already holds the link.
    let alice_names = [(y_key, "y.test")];
    let bob_names = [(x_key, "")];
    let seen = until_seen(
        &mut a,
        &alice_seed,
        &room,
        &alice,
        &alice_names,
        &bob,
        &y_key,
    );
    let named = async {
        let mut last = Vec::new();
        for _ in 0..20 {
            let (code, members) = join_word(&mut b, &bob_seed, &room, &bob, &bob_names).await;
            assert_eq!(code, 200);
            last = members;
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        last
    };
    let (seen, _) = tokio::join!(seen, named);
    let seen = seen.expect("Alice never saw Bob at Y");
    assert_eq!(seen.iter().filter(|m| m.identity == bob).count(), 1);

    // The pair: the lower places the bridge naming the higher's home by
    // key, the higher opens toward the lower; over a link nobody listed,
    // honoured because the share that named the caller was admitted.
    let (lower, higher, lower_c, higher_c, higher_home) = if alice.as_bytes() < bob.as_bytes() {
        (alice, bob, &mut a, &mut b, y_key)
    } else {
        (bob, alice, &mut b, &mut a, x_key)
    };
    let eph_l = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_h = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pub_l = x25519_dalek::PublicKey::from(&eph_l).to_bytes();
    let pub_h = x25519_dalek::PublicKey::from(&eph_h).to_bytes();
    let ack = OpenAck::decode(
        &higher_c
            .post(
                "/session/open",
                Open {
                    peer: lower,
                    ephemeral: pub_h,
                }
                .encode(),
            )
            .await
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(ack.state, OpenState::Waiting);
    let mut established = None;
    for _ in 0..100 {
        let (code, body) = lower_c
            .post(
                "/session/call",
                CallOpen {
                    ephemeral: pub_l,
                    target: format!("{higher}@{higher_home}"),
                    word: None,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
        let ack = CallAck::decode(&body).unwrap();
        match ack.state {
            CallState::Ringing => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            CallState::Established => {
                established = Some(ack);
                break;
            }
            CallState::Rejected => panic!("the bridge was refused: reason {}", ack.reason),
        }
    }
    let ack = established.expect("the bridge never came up");
    assert_eq!(ack.peer, higher);
    assert_eq!(ack.peer_ephemeral, pub_h);
}
