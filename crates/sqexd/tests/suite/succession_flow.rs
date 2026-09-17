//! SIP-44: an account is carried to its successor -- by the will it signed,
//! or by a quorum of the guardians it named -- and everything it held
//! follows: devices, names, memberships, and the log's own record of it.
//!
//! The controls are the point. A will presented by anyone but the successor
//! proves nothing; a successor that is already an account cannot be
//! succeeded into; one guardian is not a quorum; and a succession happens
//! once.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByChannelSigned, EVENT_SUCCEEDED, Entries, Fetch, KIND_SYSTEM, Mine, Mines, Role, System,
    TYPE_JOIN, Visibility,
};
use sqex_proto::name::{Claim as NameClaim, ClaimAck, Resolve as NameResolve, Resolved};
use sqex_proto::refusal::{Code, Refusal};
use sqex_proto::succession::{Claim, Policy, Proof, Succeeded, Vouch, Will, ask};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

/// An exchange with open name registration and, optionally, a replication
/// peer.
async fn server_in(dir: &Path, peers: &[PubKey]) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nname_registration = \"open\"\nname_lease_secs = 100000\n\
         replication_peers = [{list}]\n",
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
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn connect(addr: SocketAddr, server_pub: &[u8; 32], seed: &[u8; 32]) -> Client {
    Client::connect_as(addr, server_pub, seed).await.unwrap()
}

async fn mine(c: &mut Client) -> Result<Mines, Refusal> {
    let (code, body) = c
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    if code == 200 {
        Ok(Mines::decode(&body).unwrap())
    } else {
        Err(Refusal::decode(&body).unwrap())
    }
}

async fn resolve(c: &mut Client, name: &str) -> Resolved {
    let (code, body) = c
        .post("/name/resolve", NameResolve { name: name.into() }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    Resolved::decode(&body).unwrap()
}

/// A room made by Alice, with Bob in it and a name on Alice.
async fn a_life(
    addr: SocketAddr,
    server_pub: [u8; 32],
    alice_seed: [u8; 32],
    alice: PubKey,
    bob_seed: [u8; 32],
    bob: PubKey,
    channel: [u8; 32],
) -> Client {
    let mut a = connect(addr, &server_pub, &alice_seed).await;
    let s = Signer::new(alice_seed, alice, server_pub);
    let mut chain = Chain::default();
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "the room",
        vec![],
    );
    let (code, body) = a.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let info = s.info(&mut a, channel).await;
    let req = s.post_chained(&mut chain, channel, info.instance, 0, 0, b"before".to_vec());
    let (code, _) = a.post("/channel/post", req.encode()).await.unwrap();
    assert_eq!(code, 200);
    let (code, body) = a
        .post(
            "/name/claim",
            NameClaim {
                name: "alice".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(ClaimAck::decode(&body).unwrap().outcome, 0);

    let mut b = connect(addr, &server_pub, &bob_seed).await;
    let joining = Signer::new(bob_seed, bob, server_pub).action_outside(
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_JOINED,
        &bob,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, _) = b
        .post(
            "/channel/join",
            ByChannelSigned {
                channel,
                action: joining,
            }
            .encode(TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    a
}

async fn fetch_all(c: &mut Client, channel: [u8; 32]) -> Result<Entries, Refusal> {
    let (code, body) = c
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since: 0,
                wait_secs: 0,
                receipts: false,
            }
            .encode(),
        )
        .await
        .unwrap();
    if code == 200 {
        Ok(Entries::decode(&body, false).unwrap())
    } else {
        Err(Refusal::decode(&body).unwrap())
    }
}

#[tokio::test]
async fn an_account_is_carried_to_its_successor_by_its_will() {
    let dir = tempfile::tempdir().unwrap();
    let (replica_sk, replica_pub) = squic::generate_keypair();
    let replica_key = PubKey::new(replica_pub);
    let (addr, server_pub) = server_in(dir.path(), &[replica_key]).await;
    let (alice_seed, alice) = identity(171);
    let (bob_seed, bob) = identity(172);
    let (carol_seed, carol) = identity(173);
    let (dave_seed, _dave) = identity(174);
    let channel = [171u8; 32];
    let mut a = a_life(addr, server_pub, alice_seed, alice, bob_seed, bob, channel).await;

    // Alice authorises a copy, while she is still Alice.
    {
        let s = Signer::new(alice_seed, alice, server_pub);
        let info = s.info(&mut a, channel).await;
        let action = s.action_at(
            &info,
            channel,
            sqex_proto::channel::EVENT_REPLICATE,
            &replica_key,
            &[],
        );
        let (code, _) = a
            .post(
                "/channel/replicate",
                sqex_proto::channel::ByAccount {
                    channel,
                    account: replica_key,
                    action,
                }
                .encode(sqex_proto::channel::TYPE_REPLICATE),
            )
            .await
            .unwrap();
        assert_eq!(code, 200);
    }

    // Alice, while she can, names Carol's key. Bob, who holds the will,
    // cannot present it: a will says who may act, and he is not it.
    let will = Will::sign(&alice_seed, &carol, 1000);
    let claim = Claim {
        proof: Proof::Will(will),
    };
    let mut b = connect(addr, &server_pub, &bob_seed).await;
    let (code, _) = b.post("/account/succeed", claim.encode()).await.unwrap();
    assert_ne!(code, 200, "somebody else presented the will");

    // Carol presents it, and the account is hers.
    let mut c = connect(addr, &server_pub, &carol_seed).await;
    let (code, body) = c.post("/account/succeed", claim.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Alice's key is nobody's client now, and is told where it went.
    match mine(&mut a).await {
        Err(r) => {
            assert_eq!(r.code, Code::Succeeded);
            assert_eq!(r.detail.as_deref(), Some(carol.to_string().as_str()));
        }
        Ok(m) => panic!("the old key still acts: {m:?}"),
    }
    // Carol holds the room with Alice's role, and Alice's name.
    let hers = mine(&mut c).await.unwrap();
    let seat = hers
        .channels
        .iter()
        .find(|m| m.channel == channel)
        .expect("the successor is not in the room");
    assert_eq!(seat.role, Role::Admin);
    assert_eq!(resolve(&mut c, "alice").await.account, carol);
    // The log says so, under Alice's own signature, for anybody to check.
    let entries = fetch_all(&mut c, channel).await.unwrap();
    let said = entries
        .entries
        .iter()
        .filter(|e| e.kind == KIND_SYSTEM)
        .filter_map(|e| System::decode(&e.body).ok().flatten())
        .find(|s| s.event == EVENT_SUCCEEDED)
        .expect("no succession entry in the log");
    assert_eq!(said.actor, alice);
    assert_eq!(said.subject, carol);
    assert!(sqex_proto::succession::entry_verifies(
        &said.actor,
        &said.subject,
        said.chain_seq,
        &said.sig
    ));
    // Bob sees Carol where Alice was.
    let seen = Signer::new(bob_seed, bob, server_pub)
        .info(&mut b, channel)
        .await;
    assert!(
        seen.members
            .iter()
            .any(|m| m.account == carol && m.role == Role::Admin)
    );
    assert!(!seen.members.iter().any(|m| m.account == alice));
    // And the record is served, proof and all.
    let (code, body) = c.post("/account/succession", ask(&alice)).await.unwrap();
    assert_eq!(code, 200);
    let record = Succeeded::decode(&body).unwrap();
    assert_eq!(record.successor, carol);
    assert!(record.proof.proves(&carol));

    // A copy seats Carol on the strength of the entry alone: the will's
    // signature is in it, and a bare store with no way to ask anybody
    // derives the same roster the origin holds.
    {
        use sqex_proto::h3::H3Client;
        let mut peer = H3Client::connect(addr, &server_pub, &replica_sk.to_bytes())
            .await
            .unwrap();
        let (code, body) = peer
            .post(
                "/peer/pull",
                sqex_proto::peer::Pull {
                    channel,
                    since: 0,
                    max: 64,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(
            code, 200,
            "the replica is not served: it was never authorised"
        );
        let pulled = sqex_proto::peer::Pulled::decode(&body).unwrap();
        let bare = sqexd::channel::Channels::open(None, replica_key, None).unwrap();
        let took =
            sqexd::replica::take(&bare, &PubKey::new(server_pub), &channel, &pulled, &|_| {
                None
            });
        assert!(took.refused.is_empty(), "{took:?}");
        assert!(bare.fetch(&carol, &carol, &channel, 0, false).is_ok());
        let roster = bare.info(&carol, &carol, &channel, None).unwrap();
        assert!(
            roster
                .members
                .iter()
                .any(|m| m.account == carol && m.role == Role::Admin)
        );
        assert!(!roster.members.iter().any(|m| m.account == alice));

        // Control: an origin that invented the succession -- the same entry
        // with a signature Alice never made -- moves nobody at the copy. A
        // system entry's hash is the origin's word, so the receipt still
        // stands; the will's signature is what the copy checks.
        let mut forged = pulled.clone();
        let entry = forged
            .entries
            .iter_mut()
            .find(|e| {
                e.kind == KIND_SYSTEM
                    && System::decode(&e.body)
                        .ok()
                        .flatten()
                        .is_some_and(|s| s.event == EVENT_SUCCEEDED)
            })
            .unwrap();
        let mut sys = System::decode(&entry.body).unwrap().unwrap();
        sys.sig[0] ^= 0xff;
        entry.body = sys.encode();
        let duped = sqexd::channel::Channels::open(None, replica_key, None).unwrap();
        sqexd::replica::take(&duped, &PubKey::new(server_pub), &channel, &forged, &|_| {
            None
        });
        let roster = duped.info(&alice, &alice, &channel, None).unwrap();
        assert!(
            roster.members.iter().any(|m| m.account == alice),
            "the copy took the origin's word"
        );
        assert!(!roster.members.iter().any(|m| m.account == carol));
    }

    // Once, ever: a second will for Alice -- naming Dave -- is refused even
    // when Dave presents it, and Carol cannot be succeeded into again.
    let again = Claim {
        proof: Proof::Will(Will::sign(&alice_seed, &_dave, 2000)),
    };
    let mut d = connect(addr, &server_pub, &dave_seed).await;
    let (code, _) = d.post("/account/succeed", again.encode()).await.unwrap();
    assert_ne!(code, 200, "an account was succeeded twice");
    // A successor that is already an account -- Bob has a name -- is not a
    // fresh key.
    let (code, body) = b
        .post("/name/claim", NameClaim { name: "bob".into() }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let into_bob = Claim {
        proof: Proof::Will(Will::sign(&dave_seed, &bob, 3000)),
    };
    let (code, _) = b.post("/account/succeed", into_bob.encode()).await.unwrap();
    assert_ne!(code, 200, "an account was merged into another");
}

#[tokio::test]
async fn guardians_carry_an_account_as_a_quorum_and_a_replica_follows() {
    use sqex_proto::h3::H3Client;
    use sqexd::replica::{Origin, pull_once};

    let dir = tempfile::tempdir().unwrap();
    let replica_dir = tempfile::tempdir().unwrap();
    let (replica_sk, replica_pub) = squic::generate_keypair();
    std::fs::write(
        replica_dir.path().join("host_key"),
        hex::encode(replica_sk.to_bytes()),
    )
    .unwrap();
    let replica_key = PubKey::new(replica_pub);
    let (addr, server_pub) = server_in(dir.path(), &[replica_key]).await;
    let origin = PubKey::new(server_pub);
    let (alice_seed, alice) = identity(181);
    let (bob_seed, bob) = identity(182);
    let (carol_seed, carol) = identity(183);
    let (g1_seed, g1) = identity(184);
    let (g2_seed, g2) = identity(185);
    let (g3_seed, g3) = identity(186);
    let channel = [181u8; 32];
    let mut a = a_life(addr, server_pub, alice_seed, alice, bob_seed, bob, channel).await;

    // Alice names three guardians, two of whom suffice, and lodges it.
    let policy = Policy::sign(&alice_seed, 2, &[g1, g2, g3], 500).unwrap();
    let (code, _) = a.post("/account/lodge", policy.encode()).await.unwrap();
    assert_eq!(code, 200);
    // Bob cannot lodge a policy for Alice.
    let mut b = connect(addr, &server_pub, &bob_seed).await;
    let (code, _) = b.post("/account/lodge", policy.encode()).await.unwrap();
    assert_ne!(code, 200);
    // The replica is authorised and pulls what there is so far.
    let s = Signer::new(alice_seed, alice, server_pub);
    let info = s.info(&mut a, channel).await;
    let action = s.action_at(
        &info,
        channel,
        sqex_proto::channel::EVENT_REPLICATE,
        &replica_key,
        &[],
    );
    let (code, _) = a
        .post(
            "/channel/replicate",
            sqex_proto::channel::ByAccount {
                channel,
                account: replica_key,
                action,
            }
            .encode(sqex_proto::channel::TYPE_REPLICATE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let replica = {
        let config_toml = format!(
            "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
             welcome_channel = \"\"\n",
            replica_dir.path().join("host_key").to_string_lossy(),
            replica_dir.path().join("replica.state").to_string_lossy(),
        );
        let file: FileConfig = toml::from_str(&config_toml).unwrap();
        let config = file.resolve().unwrap();
        let (signing_key, _pub) =
            squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
        sqexd::bind(config, None, signing_key).await.unwrap().server
    };
    let mut peer = H3Client::connect(addr, &server_pub, &replica_sk.to_bytes())
        .await
        .unwrap();
    let spec = Origin {
        key: origin,
        addr,
        channels: vec![channel],
        interval: std::time::Duration::from_secs(1),
        predecessors: Vec::new(),
    };
    pull_once(&mut peer, &replica, &spec).await.unwrap();
    assert!(
        replica
            .channels()
            .fetch(&alice, &alice, &channel, 0, false)
            .is_ok()
    );

    // Alice's key is gone. Carol asks the exchange for the policy, gathers
    // her vouches, and presents them. One is not enough.
    let mut c = connect(addr, &server_pub, &carol_seed).await;
    let (code, body) = c.post("/account/lodged", ask(&alice)).await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(Policy::decode(&body).unwrap(), policy);
    let v1 = Vouch::sign(&g1_seed, &alice, &carol, 600);
    let v3 = Vouch::sign(&g3_seed, &alice, &carol, 601);
    let one = Claim {
        proof: Proof::Guardians {
            policy: policy.clone(),
            vouches: vec![v1],
        },
    };
    let (code, _) = c.post("/account/succeed", one.encode()).await.unwrap();
    assert_ne!(code, 200, "one guardian moved the account");
    let _ = g2_seed;
    let two = Claim {
        proof: Proof::Guardians {
            policy: policy.clone(),
            vouches: vec![v1, v3],
        },
    };
    let (code, body) = c.post("/account/succeed", two.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(
        mine(&mut c)
            .await
            .unwrap()
            .channels
            .iter()
            .any(|m| m.channel == channel && m.role == Role::Admin)
    );
    assert_eq!(resolve(&mut c, "alice").await.account, carol);

    // The entry carries the policy's signature, which is not a will's; the
    // replica settles it against the origin's record and seats Carol.
    pull_once(&mut peer, &replica, &spec).await.unwrap();
    let store = replica.channels();
    assert!(
        store.fetch(&carol, &carol, &channel, 0, false).is_ok(),
        "the replica did not seat the successor"
    );
    let roster = store.info(&carol, &carol, &channel, None).unwrap();
    assert!(
        roster
            .members
            .iter()
            .any(|m| m.account == carol && m.role == Role::Admin)
    );
    assert!(!roster.members.iter().any(|m| m.account == alice));
}
