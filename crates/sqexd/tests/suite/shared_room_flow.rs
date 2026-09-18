//! SIP-49: a room spans two peered exchanges. A member at each joins at
//! its own, names the other, and the rosters cross the relay link with each
//! member's home; the pair then meets through a bridge nobody rang for.

use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use sqex_proto::room::{Homed, Join, JoinShared, RoomId, Roster};
use sqex_proto::session::{CallAck, CallOpen, CallState, Open, OpenAck, OpenState};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::{PubKey, SignedTransaction, SoftwareSigner, Transaction};

async fn relay_server(
    dir: &std::path::Path,
    host_key: &SigningKey,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
    admin: PubKey,
) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    std::fs::write(&key_path, hex::encode(host_key.to_bytes())).unwrap();
    let listed = peers
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = [\"{admin}\"]\n\
         seed_relay_peers = [{listed}]\n",
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
    let handle = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, handle)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

/// Label a peer with its domain, as an operator does with `sqex admin peer
/// add --label`: it is how an exchange turns a peer's key into somewhere to
/// dial when it has no link up yet.
async fn label_peer(
    addr: SocketAddr,
    server_pub: [u8; 32],
    admin_seed: [u8; 32],
    key: PubKey,
    label: &str,
) {
    let mut c = Client::connect_as(addr, &server_pub, &admin_seed)
        .await
        .unwrap();
    let (cs, nonce_bytes) = c.get("/admin/challenge").await.unwrap();
    assert_eq!(cs, 200);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let txn = Transaction {
        server: PubKey::new(server_pub),
        nonce,
        ops: vec![
            sqex_proto::Op::PeerAdd {
                key,
                label: Some(label.into()),
            }
            .to_operation(),
        ],
    };
    let signer = SoftwareSigner::new(SigningKey::from_bytes(&admin_seed));
    let (code, body) = c
        .post(
            "/admin/command",
            SignedTransaction::create(txn, &signer).encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
}

async fn join_shared(
    c: &mut Client,
    room: &RoomId,
    me: &PubKey,
    share: Vec<PubKey>,
) -> (u16, Vec<u8>) {
    c.post("/room/join", JoinShared::new(room, me, share).encode())
        .await
        .unwrap()
}

async fn homed(c: &mut Client, room: &RoomId, me: &PubKey, share: Vec<PubKey>) -> Homed {
    let (code, body) = join_shared(c, room, me, share).await;
    assert_eq!(code, 200, "{}", crate::common::said(&body));
    Homed::decode(&body).unwrap()
}

/// Poll until the roster with homes shows `who` at `home`, or give up.
async fn until_seen(
    c: &mut Client,
    room: &RoomId,
    me: &PubKey,
    share: Vec<PubKey>,
    who: &PubKey,
    home: &PubKey,
) -> Option<Homed> {
    for _ in 0..60 {
        let h = homed(c, room, me, share.clone()).await;
        if h.members
            .iter()
            .any(|m| m.identity == *who && m.home == *home)
        {
            return Some(h);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test]
async fn a_room_spans_two_exchanges_and_the_pair_meets_without_a_ring() {
    let dir_x = tempfile::tempdir().unwrap();
    let dir_y = tempfile::tempdir().unwrap();
    let (xk, x_pub) = identity(210);
    let (yk, y_pub) = identity(211);
    let (x_key, y_key) = (SigningKey::from_bytes(&xk), SigningKey::from_bytes(&yk));
    let (admin_seed, admin) = identity(212);

    // Y first, then X told where Y is. Y is never told where X is: the
    // link X brings up is the one Y shares back over, as a link is
    // bidirectional once up.
    let (y_addr, y_server_pub, _y_h) =
        relay_server(dir_y.path(), &y_key, &[x_pub], &[], admin).await;
    // X's peer entry for Y is added by the administrator with Y's domain as
    // its label, as an operator does: a seeded entry has no label, and the
    // label is what turns a home key from a roster into somewhere to dial.
    let (x_addr, x_server_pub, _x_h) = relay_server(
        dir_x.path(),
        &x_key,
        &[],
        &[("y.test", y_pub, y_addr)],
        admin,
    )
    .await;
    label_peer(x_addr, x_server_pub, admin_seed, y_pub, "y.test").await;

    let (a_seed, alice) = identity(213);
    let (b_seed, bob) = identity(214);
    let mut a = Client::connect_as(x_addr, &x_server_pub, &a_seed)
        .await
        .unwrap();
    let mut b = Client::connect_as(y_addr, &y_server_pub, &b_seed)
        .await
        .unwrap();
    let room = RoomId::new([77u8; 32]);

    // A share naming a stranger is refused.
    let (_, stranger) = identity(219);
    let (code, _) = join_shared(&mut b, &room, &bob, vec![stranger]).await;
    assert_eq!(code, 403, "a share to a stranger was accepted");

    // Alice joins at X and names Y; Bob joins at Y and names nobody.
    let h = homed(&mut a, &room, &alice, vec![y_pub]).await;
    assert!(h.members.is_empty(), "alice is alone so far");
    let seen = until_seen(&mut b, &room, &bob, vec![], &alice, &x_pub)
        .await
        .expect("bob never saw alice, homed at X");
    assert_eq!(seen.members.len(), 1);
    assert!(
        room.verify(&alice, &seen.members[0].proof),
        "alice's proof did not cross intact"
    );
    // Reciprocal: X is told by Y, without bob naming anybody.
    let seen = until_seen(&mut a, &room, &alice, vec![y_pub], &bob, &y_pub)
        .await
        .expect("alice never saw bob, homed at Y");
    assert_eq!(seen.members.len(), 1);

    // A plain join still answers the old way: the local members only.
    let (code, body) = a
        .post("/room/join", Join::new(&room, &alice).encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(
        Roster::decode(&body).unwrap().members.is_empty(),
        "a plain join saw across the link"
    );

    // The pair: the lower places the bridge at its exchange naming the
    // higher's home by key; the higher opens toward the lower as for
    // anybody local. Nobody has an event stream open, so nothing could
    // have rung.
    let (lower, higher, lower_c, higher_c, higher_home) = if alice.as_bytes() < bob.as_bytes() {
        (alice, bob, &mut a, &mut b, y_pub)
    } else {
        (bob, alice, &mut b, &mut a, x_pub)
    };
    let eph_l = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_h = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pub_l = x25519_dalek::PublicKey::from(&eph_l).to_bytes();
    let pub_h = x25519_dalek::PublicKey::from(&eph_h).to_bytes();
    let target = format!("{higher}@{higher_home}");
    // The higher opens first this time: the invite must find the open waiting.
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
                    target: target.clone(),
                    word: None,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200);
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
    assert_eq!(ack.peer, higher, "the bridge answered as somebody else");
    assert_eq!(ack.peer_ephemeral, pub_h);
    // And the higher's open, polled again, is established with the lower's ephemeral.
    let ack_h = OpenAck::decode(
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
    assert_eq!(ack_h.state, OpenState::Established);
    assert_eq!(ack_h.peer_ephemeral, pub_l);

    // Bob leaves at Y; Alice's roster loses him within a share, not a TTL.
    // (Alice keeps naming Y, as a member at a copy keeps naming the origin.)
    let (code, _) = b
        .post(
            "/room/leave",
            sqex_proto::room::Leave {
                handle: room.handle(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let mut gone = false;
    for _ in 0..50 {
        let h = homed(&mut a, &room, &alice, vec![y_pub]).await;
        if h.members.is_empty() {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(gone, "bob's leave never crossed");
}
