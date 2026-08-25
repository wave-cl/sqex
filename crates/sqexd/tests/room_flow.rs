//! End-to-end for SIP-13 rooms over real HTTP/3.
//!
//! A room is a roster and the exchange is deliberately ignorant of it: it is
//! given a handle rather than the secret, and proofs it cannot check. These
//! tests hold it to both halves of that — that it does its job, and that it
//! could not cheat at it if it wanted to.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::room::{Join, Leave, MAX_MEMBERS, RoomId, Roster};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn bare_server(
    dir: &std::path::Path,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let config_path = dir.join("sqexd.toml");
    std::fs::write(&config_path, &config_toml).unwrap();
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let bound = sqexd::bind(config, Some(config_path), signing_key)
        .await
        .unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    let handle = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, handle)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn join(client: &mut Client, room: &RoomId, me: PubKey) -> Roster {
    let (code, body) = client
        .post("/room/join", Join::new(room, &me).encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    Roster::decode(&body).unwrap()
}

fn names(roster: &Roster) -> Vec<[u8; 32]> {
    roster.members.iter().map(|m| *m.identity.as_bytes()).collect()
}

#[tokio::test]
async fn everyone_in_a_room_finds_everyone_else() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;
    let room = RoomId::generate();

    let (a_seed, a_id) = identity(21);
    let (b_seed, b_id) = identity(22);
    let (c_seed, c_id) = identity(23);
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();
    let mut c = Client::connect_as(addr, &server_pub, &c_seed).await.unwrap();

    assert!(join(&mut a, &room, a_id).await.members.is_empty(), "first in is alone");
    assert_eq!(names(&join(&mut b, &room, b_id).await), vec![*a_id.as_bytes()]);
    join(&mut c, &room, c_id).await;

    // Everyone's roster is everyone else, in the same order for all of them.
    let from_a = join(&mut a, &room, a_id).await;
    let from_b = join(&mut b, &room, b_id).await;
    assert_eq!(from_a.members.len(), 2);
    assert_eq!(from_b.members.len(), 2);
    let mut expect_for_a = vec![*b_id.as_bytes(), *c_id.as_bytes()];
    expect_for_a.sort();
    assert_eq!(names(&from_a), expect_for_a);
    assert!(!names(&from_a).contains(a_id.as_bytes()), "never yourself");

    // And every relayed proof verifies under the room secret each holds.
    for m in &from_a.members {
        assert!(room.verify(&m.identity, &m.proof), "a real member's proof");
    }
}

/// The test that earns the design: the exchange can add a member to a roster —
/// it has to be able to, it stores the roster — but it cannot make one that
/// passes a member's check, because checking needs the secret it was never given.
#[tokio::test]
async fn an_identity_that_cannot_prove_the_secret_is_rejected_by_the_members() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;
    let room = RoomId::generate();

    let (a_seed, a_id) = identity(31);
    let (eve_seed, eve_id) = identity(32);
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut eve = Client::connect_as(addr, &server_pub, &eve_seed).await.unwrap();

    join(&mut a, &room, a_id).await;

    // Eve knows the handle — she saw it go past, or the exchange is hers — but
    // not the secret, so the best she can do is make a proof up.
    let (code, body) = eve
        .post(
            "/room/join",
            Join { handle: room.handle(), proof: [0x5a; 32] }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "the exchange cannot tell, and does not pretend to");
    let _ = Roster::decode(&body).unwrap();

    // A sees her in the roster, and throws her out on her proof.
    let roster = join(&mut a, &room, a_id).await;
    assert_eq!(names(&roster), vec![*eve_id.as_bytes()], "she is listed");
    assert!(
        !room.verify(&roster.members[0].identity, &roster.members[0].proof),
        "and rejected by the only party that can check"
    );
}

/// Knowing a handle is not knowing a room: the handle is a one-way function of
/// the secret, so relaying a room never teaches the exchange how to be in one.
#[tokio::test]
async fn the_secret_never_reaches_the_exchange() {
    let room = RoomId::generate();
    let (_, me) = identity(41);
    let body = Join::new(&room, &me).encode();
    let secret = room.to_base58();
    let secret_bytes = bs58::decode(&secret).into_vec().unwrap();

    assert!(
        !body.windows(32).any(|w| w == secret_bytes.as_slice()),
        "the room secret was on the wire"
    );
    assert!(
        body.windows(32).any(|w| w == room.handle()),
        "the handle is what goes instead"
    );
    // And a handle cannot be turned back into a room to join.
    assert_ne!(room.handle(), secret_bytes.as_slice());
}

#[tokio::test]
async fn a_room_holds_only_so_many_and_refuses_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;
    let room = RoomId::generate();

    let mut clients = Vec::new();
    for i in 0..MAX_MEMBERS as u8 {
        let (seed, id) = identity(50 + i);
        let mut c = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
        join(&mut c, &room, id).await;
        clients.push((c, id));
    }

    let (late_seed, late_id) = identity(90);
    let mut late = Client::connect_as(addr, &server_pub, &late_seed).await.unwrap();
    let (code, body) = late
        .post("/room/join", Join::new(&room, &late_id).encode())
        .await
        .unwrap();
    assert_eq!(code, 507, "{}", String::from_utf8_lossy(&body));
    assert!(String::from_utf8_lossy(&body).contains("full"));

    // Nobody was evicted to make space, and the room still works.
    let (first, first_id) = &mut clients[0];
    let roster = join(first, &room, *first_id).await;
    assert_eq!(roster.members.len(), MAX_MEMBERS - 1);
    assert!(
        !names(&roster).contains(late_id.as_bytes()),
        "the refused join left no trace"
    );
}

#[tokio::test]
async fn leaving_is_immediate_and_the_others_see_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;
    let room = RoomId::generate();

    let (a_seed, a_id) = identity(61);
    let (b_seed, b_id) = identity(62);
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();
    join(&mut a, &room, a_id).await;
    join(&mut b, &room, b_id).await;

    let (code, body) = b
        .post("/room/leave", Leave { handle: room.handle() }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(String::from_utf8_lossy(&body).contains("true"));

    assert!(join(&mut a, &room, a_id).await.members.is_empty(), "b is gone");

    // Leaving a room you are not in is not an error; it is just nothing.
    let (code, body) = b
        .post("/room/leave", Leave { handle: room.handle() }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(String::from_utf8_lossy(&body).contains("false"));
}

#[tokio::test]
async fn two_rooms_on_one_exchange_know_nothing_of_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;
    let (one, two) = (RoomId::generate(), RoomId::generate());

    let (a_seed, a_id) = identity(71);
    let (b_seed, b_id) = identity(72);
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &b_seed).await.unwrap();

    join(&mut a, &one, a_id).await;
    assert!(
        join(&mut b, &two, b_id).await.members.is_empty(),
        "a different secret is a different room, on the same exchange"
    );
    assert!(join(&mut a, &one, a_id).await.members.is_empty());
}

/// A room belongs to identities, and an anonymous connection has none. Same
/// rule as the beacon, the mailbox and sessions.
#[tokio::test]
async fn an_anonymous_connection_has_no_room() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;
    let room = RoomId::generate();
    let (_, someone) = identity(81);

    let mut anon = Client::connect(addr, &server_pub).await.unwrap();
    let (code, _) = anon
        .post("/room/join", Join::new(&room, &someone).encode())
        .await
        .unwrap();
    assert_eq!(code, 403);

    let (code, _) = anon
        .post("/room/leave", Leave { handle: room.handle() }.encode())
        .await
        .unwrap();
    assert_eq!(code, 403);
}

#[tokio::test]
async fn a_malformed_join_is_refused_without_disturbing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = bare_server(dir.path()).await;
    let room = RoomId::generate();

    let (a_seed, a_id) = identity(85);
    let mut a = Client::connect_as(addr, &server_pub, &a_seed).await.unwrap();
    join(&mut a, &room, a_id).await;

    for body in [vec![], vec![0x01], vec![0xff; 65]] {
        let (code, _) = a.post("/room/join", body).await.unwrap();
        assert_eq!(code, 400);
    }
    assert!(
        join(&mut a, &room, a_id).await.members.is_empty(),
        "still in the room, still alone"
    );
}
