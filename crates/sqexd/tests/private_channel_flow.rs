//! End-to-end for a private channel: SIP-16 membership, SIP-17 keys, SIP-23
//! prekeys, over real HTTP/3.
//!
//! The exchange never sees a channel key or a plaintext here. Every seal and
//! open in this file is done by the test acting as a client, which is the point
//! — if any of it could be done by the server, the design would be wrong.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    Ack, ByChannel, Create, Entries, Fetch, Invitee, Role, TYPE_INVITE, TYPE_REMOVE,
    Visibility,
};
use sqex_proto::channel::Posted;
use sqex_proto::channel_key::{
    Absent, ChannelKey, Envelope, Get as KeyGet, Got, Put as KeyPut, PutAck, TYPE_MISSING,
    open_envelope, seal_envelope, sign_envelope,
};
use sqex_proto::message::{Body, Part, Post as SipPost};
use sqex_proto::prekey::{Pool, Prekey, Publish, Take, Taken};
use sqex_proto::timeline::{Received, Timeline, Verdict};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

mod common;
use common::{Chain, Signer, instance_for};
use sqex_proto::channel::{Action, ByChannelSigned, EVENT_ADDED, EVENT_CREATED, EVENT_JOINED, EVENT_LEFT, EVENT_REMOVED, EVENT_ROTATED};

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
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

/// One person's client: an identity, and the prekey secrets it must destroy.
///
/// The secrets live in SIP-23's `Pool` rather than a bare map, so that the
/// receiver rules — spend a one-time key once, refuse a replay, keep a
/// fallback until it is replaced — are the ones the shipped type enforces and
/// not ones this file re-implements more leniently.
struct Peer {
    seed: [u8; 32],
    key: PubKey,
    client: Client,
    pool: Pool,
    /// What signs this peer's entries and membership actions (SIP-31).
    signer: Signer,
}

impl Peer {
    async fn new(addr: SocketAddr, server_pub: [u8; 32], b: u8) -> Peer {
        let sk = SigningKey::from_bytes(&[b; 32]);
        let seed = sk.to_bytes();
        Peer {
            seed,
            key: PubKey::new(sk.verifying_key().to_bytes()),
            client: Client::connect_as(addr, &server_pub, &seed).await.unwrap(),
            pool: Pool::new(&seed),
            signer: Signer::new(seed, PubKey::new(sk.verifying_key().to_bytes()), server_pub),
        }
    }

    /// Mint and publish some one-time prekeys, keeping the secrets.
    async fn publish_prekeys(&mut self, n: u16) {
        let prekeys = self.pool.mint_one_time(n);
        let (code, _) = self
            .client
            .post("/prekey/publish", Publish { prekeys }.encode())
            .await
            .unwrap();
        assert_eq!(code, 200);
    }

    /// Take a prekey for somebody else, verifying it ourselves — the exchange
    /// is the party this signature exists to constrain.
    async fn take_prekey_for(&mut self, them: PubKey) -> Prekey {
        let (code, body) = self
            .client
            .post("/prekey/take", Take { device: them }.encode())
            .await
            .unwrap();
        assert_eq!(code, 200);
        let taken = Taken::decode(&body).unwrap();
        assert!(taken.found, "no prekey published, so nothing may be sealed");
        let p = taken.prekey.unwrap();
        p.verify(&them).expect("prekey must verify under its device");
        p
    }

    /// Collect envelopes and open them, destroying each prekey secret on use.
    async fn collect_keys(&mut self, channel: [u8; 32]) -> Vec<(u32, ChannelKey)> {
        let (code, body) = self
            .client
            .post(
                "/channel/key/get",
                KeyGet {
                    channel,
                    since_epoch: 0,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
        let got = Got::decode(&body).unwrap();
        let mut out = Vec::new();
        for env in got.envelopes {
            // The pool spends the secret here. Deleting is the mechanism: a
            // client that keeps these has the wire format and none of the
            // property.
            let secret = self
                .pool
                .take(env.prekey_id)
                .expect("an envelope naming a prekey we never had, or already spent");
            let keys = open_envelope(&self.seed, &secret, &env).unwrap();
            for (i, k) in keys.into_iter().enumerate() {
                out.push((env.from_epoch + i as u32, k));
            }
        }
        out
    }
}

/// Sign an envelope as `s`'s device published it (SIP-32).
///
/// The exchange verifies this, so a test that seals without signing is one that
/// publishes a key nobody put their name to.
fn published(s: &Signer, channel: [u8; 32], epoch: u32, e: Envelope) -> Envelope {
    sign_envelope(
        &s.seed,
        &s.exchange,
        &instance_for(channel, 0),
        &channel,
        epoch,
        e,
    )
}

/// The signature for minting `epoch`, which is a rotation and therefore writes
/// a system entry. Minting the *first* epoch is a rotation from 0 and needs one
/// just the same: there is no unsigned way to key a channel.
fn rotation(signer: &Signer, chain: &mut Chain, channel: [u8; 32], epoch: u32) -> Action {
    let account = signer.account;
    signer.action_chained(
        chain,
        channel,
        instance_for(channel, 0),
        EVENT_ROTATED,
        &account,
        &epoch.to_be_bytes(),
    )
}

fn private(
    signer: &Signer,
    chain: &mut Chain,
    channel: [u8; 32],
    instance: [u8; 32],
    invites: Vec<Invitee>,
) -> Create {
    signer.create_chained(
        chain,
        channel,
        instance,
        Visibility::Private,
        3600,
        "",
        invites,
    )
}

#[tokio::test]
async fn two_people_hold_a_private_conversation_the_exchange_cannot_read() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 21).await;
    let mut alice_chain = Chain::default();
    let mut bob = Peer::new(addr, pubkey, 22).await;
    let _bob_chain = Chain::default();
    let channel = [1u8; 32];

    alice.publish_prekeys(4).await;
    bob.publish_prekeys(4).await;

    // Alice creates the channel with Bob already in it.
    let (code, _) = alice
        .client
        .post(
            "/channel/create",
            private(
                &alice.signer,
                &mut alice_chain,
                channel,
                instance_for(channel, 0),
                vec![Invitee {
                    account: bob.key,
                    role: Role::Member,
                }],
            )
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // Nothing can be posted yet: a private channel is created with no epoch,
    // and there is no window in which an entry could be stored unsealed.
    // Signed at the position Alice stands at, and not advancing past it: this
    // post is meant to be refused, and a refused post spends nothing.
    let req = alice.signer.post_probe(&alice_chain, channel, instance_for(channel, 0), 0, 0, b"too early".to_vec());
    let (code, _) = alice
        .client
        .post("/channel/post", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 409, "a private channel must refuse an unsealed entry");

    // Alice mints epoch 1 and seals it to every member, herself included.
    let epoch1 = ChannelKey::generate();
    let mut envelopes = Vec::new();
    for who in [alice.key, bob.key] {
        let p = alice.take_prekey_for(who).await;
        envelopes.push(published(&alice.signer, channel, 1, seal_envelope(&who, p.id, &p.public, 1, &[epoch1]).unwrap()));
    }
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 1);
    let (code, body) = alice
        .client
        .post(
            "/channel/key/put",
            KeyPut {
                channel,
                epoch: 1,
                envelopes,
                action: Some(rot),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let ack = PutAck::decode(&body).unwrap();
    assert!(ack.accepted && ack.epoch == 1);

    // Alice seals an entry under her own device subkey and posts the
    // ciphertext. The exchange sees bytes it cannot open.
    let plaintext = b"the exchange cannot read this";
    let sealed = epoch1.seal(&channel, 1, &alice.key, 0, plaintext).unwrap();
    let req = alice.signer.post_chained(&mut alice_chain, channel, instance_for(channel, 0), 1, 0, sealed.clone());
    let (code, body) = alice
        .client
        .post("/channel/post", req.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));

    // Bob collects the key and reads it.
    let keys = bob.collect_keys(channel).await;
    assert_eq!(keys.len(), 1);
    let (epoch, bobs_key) = keys[0];
    assert_eq!(epoch, 1);

    let (_, body) = bob
        .client
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since: 0,
                wait_secs: 0,
            }
            .encode(),
        )
        .await
        .unwrap();
    let entries = Entries::decode(&body).unwrap();
    // Creating with an invitee and minting an epoch are both recorded, so the
    // log holds the exchange's entries as well as the one message.
    let mine: Vec<_> = entries
        .entries
        .iter()
        .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .collect();
    assert_eq!(mine.len(), 1);
    let e = mine[0];
    let opened = bobs_key
        .open(&channel, e.epoch, &e.device, e.msg_seq, &e.body)
        .unwrap();
    assert_eq!(opened, plaintext);

    // What the exchange stored is not the plaintext.
    assert_ne!(e.body, plaintext.to_vec());
}

#[tokio::test]
async fn a_removed_member_is_refused_and_the_next_epoch_is_not_theirs() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 31).await;
    let mut alice_chain = Chain::default();
    let mut bob = Peer::new(addr, pubkey, 32).await;
    let _bob_chain = Chain::default();
    let channel = [2u8; 32];

    alice.publish_prekeys(6).await;
    bob.publish_prekeys(6).await;

    alice
        .client
        .post("/channel/create", private(&alice.signer, &mut alice_chain, channel, instance_for(channel, 0), vec![]).encode())
        .await
        .unwrap();
    let invite = |c: [u8; 32], who: PubKey| {
        let mut b = vec![TYPE_INVITE];
        b.extend_from_slice(&c);
        b.extend_from_slice(who.as_bytes());
        b.push(Role::Member as u8);
        b
    };
    let mut invited = invite(channel, bob.key);
    alice
        .signer
        .action_chained(&mut alice_chain, channel, instance_for(channel, 0), EVENT_ADDED, &bob.key, &[Role::Member as u8])
        .write(&mut invited);
    let (code, _) = alice
        .client
        .post("/channel/invite", invited)
        .await
        .unwrap();
    assert_eq!(code, 200);

    // Epoch 1 to both.
    let epoch1 = ChannelKey::generate();
    let mut envelopes = Vec::new();
    for who in [alice.key, bob.key] {
        let p = alice.take_prekey_for(who).await;
        envelopes.push(published(&alice.signer, channel, 1, seal_envelope(&who, p.id, &p.public, 1, &[epoch1]).unwrap()));
    }
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 1);
    alice
        .client
        .post(
            "/channel/key/put",
            KeyPut { channel, epoch: 1, envelopes, action: Some(rot) }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(bob.collect_keys(channel).await.len(), 1);

    // Remove Bob, then rotate. The exchange cannot enforce the rotation and
    // does not pretend to; it is the client's requirement.
    let mut rm = vec![TYPE_REMOVE];
    rm.extend_from_slice(&channel);
    rm.extend_from_slice(bob.key.as_bytes());
    alice
        .signer
        .action_chained(&mut alice_chain, channel, instance_for(channel, 0), EVENT_REMOVED, &bob.key, &[])
        .write(&mut rm);
    let (code, _) = alice.client.post("/channel/remove", rm).await.unwrap();
    assert_eq!(code, 200);

    // Delivery stops at once.
    let (code, _) = bob
        .client
        .post(
            "/channel/fetch",
            Fetch { channel, since: 0, wait_secs: 0 }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403);

    let epoch2 = ChannelKey::generate();
    let p = alice.take_prekey_for(alice.key).await;
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 2);
    let (code, body) = alice
        .client
        .post(
            "/channel/key/put",
            KeyPut {
                channel,
                epoch: 2,
                envelopes: vec![published(&alice.signer, channel, 2, seal_envelope(&alice.key, p.id, &p.public, 2, &[epoch2]).unwrap())],
                action: Some(rot),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(PutAck::decode(&body).unwrap().epoch, 2);

    // Bob was never sealed epoch 2, and cannot collect it.
    let (code, _) = bob
        .client
        .post(
            "/channel/key/get",
            KeyGet { channel, since_epoch: 0 }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 403);
}

#[tokio::test]
async fn an_envelope_is_served_only_to_the_recipient_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 41).await;
    let mut alice_chain = Chain::default();
    let mut bob = Peer::new(addr, pubkey, 42).await;
    let _bob_chain = Chain::default();
    let channel = [3u8; 32];

    alice.publish_prekeys(4).await;
    bob.publish_prekeys(4).await;
    alice
        .client
        .post(
            "/channel/create",
            private(&alice.signer, &mut alice_chain, channel, instance_for(channel, 0), vec![Invitee { account: bob.key, role: Role::Member }]).encode(),
        )
        .await
        .unwrap();

    // Seal epoch 1 to Alice only.
    let epoch1 = ChannelKey::generate();
    let p = alice.take_prekey_for(alice.key).await;
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 1);
    alice
        .client
        .post(
            "/channel/key/put",
            KeyPut {
                channel,
                epoch: 1,
                envelopes: vec![published(&alice.signer, channel, 1, seal_envelope(&alice.key, p.id, &p.public, 1, &[epoch1]).unwrap())],
                action: Some(rot),
            }
            .encode(),
        )
        .await
        .unwrap();

    // Bob is a member and gets nothing, because nothing was addressed to him.
    let (code, body) = bob
        .client
        .post("/channel/key/get", KeyGet { channel, since_epoch: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(Got::decode(&body).unwrap().envelopes.is_empty());

    // And `Missing` says so, which is how somebody finds out.
    let (code, body) = alice
        .client
        .post(
            "/channel/key/missing",
            ByChannel { channel }.encode(TYPE_MISSING),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let absent = Absent::decode(&body).unwrap();
    assert_eq!(absent.epoch, 1);
    assert_eq!(absent.devices.len(), 1);
    assert_eq!(absent.devices[0].account, bob.key);
    assert!(absent.devices[0].has_prekeys, "Bob is waiting on an admin");
}

#[tokio::test]
async fn a_private_channel_refuses_a_join_and_hides_from_a_stranger() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 51).await;
    let mut alice_chain = Chain::default();
    let mut mallory = Peer::new(addr, pubkey, 52).await;
    let _mallory_chain = Chain::default();
    let channel = [4u8; 32];

    alice
        .client
        .post("/channel/create", private(&alice.signer, &mut alice_chain, channel, instance_for(channel, 0), vec![]).encode())
        .await
        .unwrap();

    // Membership comes only from an invitation. An identifier is not a way in.
    let (code, _) = mallory
        .client
        .post(
            "/channel/join",
            ByChannelSigned {
                channel,
                // Never verified: a private channel refuses the join outright,
                // which is what stops an identifier being a way in.
                action: Action { chain_seq: 0, prev: [0; 32], sig: [0; 64] },
            }
            .encode(sqex_proto::channel::TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 403);

    let (code, _) = mallory
        .client
        .post("/channel/key/get", KeyGet { channel, since_epoch: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 403);
}

#[tokio::test]
async fn a_direct_message_cannot_gain_a_third_party() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 61).await;
    let mut alice_chain = Chain::default();
    let bob = Peer::new(addr, pubkey, 62).await;
    let carol = Peer::new(addr, pubkey, 63).await;

    // The identifier is derived from the two accounts, so both ends compute it
    // without having spoken.
    let dm = sqex_proto::channel::direct_message_id(&alice.key, &bob.key);
    let (code, _) = alice
        .client
        .post(
            "/channel/create",
            private(&alice.signer, &mut alice_chain, dm, instance_for(dm, 0), vec![Invitee { account: bob.key, role: Role::Admin }]).encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // A channel is a direct message exactly when its identifier is the
    // derivation over its two members, recomputed rather than recorded.
    let mut b = vec![TYPE_INVITE];
    b.extend_from_slice(&dm);
    b.extend_from_slice(carol.key.as_bytes());
    b.push(Role::Member as u8);
    // Signed at Alice's current position without advancing it: the invite is
    // meant to be refused, and a refused request spends no chain position.
    let mut probe = Chain { seq: alice_chain.seq, head: alice_chain.head };
    alice
        .signer
        .action_chained(&mut probe, dm, instance_for(dm, 0), EVENT_ADDED, &carol.key, &[Role::Member as u8])
        .write(&mut b);
    let (code, body) = alice.client.post("/channel/invite", b).await.unwrap();
    assert_eq!(code, 409, "{}", String::from_utf8_lossy(&body));

    // Nor may either party eject the other; leaving is the way out.
    let mut rm = vec![TYPE_REMOVE];
    rm.extend_from_slice(&dm);
    rm.extend_from_slice(bob.key.as_bytes());
    // Refused, so it spends nothing: signed at Alice's current position with a
    // scratch chain rather than her own.
    let mut probe = Chain { seq: alice_chain.seq, head: alice_chain.head };
    alice
        .signer
        .action_chained(&mut probe, dm, instance_for(dm, 0), EVENT_REMOVED, &bob.key, &[])
        .write(&mut rm);
    let (code, _) = alice.client.post("/channel/remove", rm).await.unwrap();
    assert_eq!(code, 409);
}

#[tokio::test]
async fn an_envelope_cannot_be_published_twice_for_one_epoch() {
    // What settles the direct-message creation race: both ends mint epoch 1,
    // one Put wins, and the loser is told which epoch stands.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 71).await;
    let mut alice_chain = Chain::default();
    let channel = [5u8; 32];

    alice.publish_prekeys(4).await;
    alice
        .client
        .post("/channel/create", private(&alice.signer, &mut alice_chain, channel, instance_for(channel, 0), vec![]).encode())
        .await
        .unwrap();

    // A detached copy, so the closure does not hold a borrow of `alice` across
    // the calls that need it mutably.
    let signer = alice.signer;
    let seal_one = move |p: &Prekey, k: ChannelKey, who: &PubKey| -> Envelope {
        published(&signer, channel, 1, seal_envelope(who, p.id, &p.public, 1, &[k]).unwrap())
    };
    let p1 = alice.take_prekey_for(alice.key).await;
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 1);
    let (code, body) = alice
        .client
        .post(
            "/channel/key/put",
            KeyPut {
                channel,
                epoch: 1,
                envelopes: vec![seal_one(&p1, ChannelKey::generate(), &alice.key)],
                action: Some(rot),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(PutAck::decode(&body).unwrap().accepted);

    let p2 = alice.take_prekey_for(alice.key).await;
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 1);
    let (code, body) = alice
        .client
        .post(
            "/channel/key/put",
            KeyPut {
                channel,
                epoch: 1,
                envelopes: vec![seal_one(&p2, ChannelKey::generate(), &alice.key)],
                action: Some(rot),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let ack = PutAck::decode(&body).unwrap();
    assert!(!ack.accepted, "a second envelope for one epoch must not land");
    assert_eq!(ack.epoch, 1, "and the caller is told which epoch stands");
}

#[tokio::test]
async fn a_public_channel_has_no_keys_to_distribute() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 81).await;
    let mut alice_chain = Chain::default();
    let channel = [6u8; 32];
    alice.publish_prekeys(2).await;

    // Built public rather than built private and flipped: SIP-32's `created`
    // action commits to the visibility and the name, so mutating them after
    // signing leaves a signature for a channel nobody asked for.
    let req = alice.signer.create_chained(
        &mut alice_chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "open",
        vec![],
    );
    let (code, body) = alice.client.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));

    let p = alice.take_prekey_for(alice.key).await;
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 1);
    let (code, _) = alice
        .client
        .post(
            "/channel/key/put",
            KeyPut {
                channel,
                epoch: 1,
                envelopes: vec![
                    published(
                        &alice.signer,
                        channel,
                        1,
                        seal_envelope(&alice.key, p.id, &p.public, 1, &[ChannelKey::generate()])
                            .unwrap(),
                    ),
                ],
                action: Some(rot),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 409, "a public channel seals nothing");
}

#[tokio::test]
async fn an_ack_is_still_an_ack() {
    // The shared reply shape, so a client can tell a refusal from a success
    // without guessing at content types.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 91).await;
    let mut alice_chain = Chain::default();
    let channel = [7u8; 32];
    alice
        .client
        .post("/channel/create", private(&alice.signer, &mut alice_chain, channel, instance_for(channel, 0), vec![]).encode())
        .await
        .unwrap();
    let leaving = {
        let acct = alice.signer.account;
        alice.signer.action_chained(&mut alice_chain, channel, instance_for(channel, 0), EVENT_LEFT, &acct, &[])
    };
    let (code, body) = alice
        .client
        .post(
            "/channel/leave",
            ByChannelSigned { channel, action: leaving }
                .encode(sqex_proto::channel::TYPE_LEAVE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(Ack::decode(&body).is_ok());
}

/// Fold a fetched, decrypted channel into what a person would see.
fn timeline_of(entries: &[sqex_proto::channel::Entry], key: &ChannelKey, channel: [u8; 32], admins: &[PubKey]) -> Timeline {
    let received: Vec<Received> = entries
        .iter()
        .map(|e| Received {
            seq: e.seq,
            account: e.account,
            posted: e.posted,
            kind: e.kind,
            tombstone: false,
            body: key
                .open(&channel, e.epoch, &e.device, e.msg_seq, &e.body)
                .ok()
                .and_then(|plain| Body::decode(&plain).ok().flatten()),
            verdict: Verdict::Valid,
        })
        .collect();
    Timeline::fold(&received, admins)
}

#[tokio::test]
async fn a_real_conversation_renders_end_to_end() {
    // Everything above the byte level, through a live exchange that can read
    // none of it: text, a reply, a reaction, an edit and a redaction.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 101).await;
    let mut alice_chain = Chain::default();
    let mut bob = Peer::new(addr, pubkey, 102).await;
    let mut bob_chain = Chain::default();
    let channel = [8u8; 32];

    alice.publish_prekeys(4).await;
    bob.publish_prekeys(4).await;
    alice
        .client
        .post(
            "/channel/create",
            private(&alice.signer, &mut alice_chain, channel, instance_for(channel, 0), vec![Invitee { account: bob.key, role: Role::Member }]).encode(),
        )
        .await
        .unwrap();

    let epoch1 = ChannelKey::generate();
    let mut envelopes = Vec::new();
    for who in [alice.key, bob.key] {
        let p = alice.take_prekey_for(who).await;
        envelopes.push(published(&alice.signer, channel, 1, seal_envelope(&who, p.id, &p.public, 1, &[epoch1]).unwrap()));
    }
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 1);
    alice
        .client
        .post("/channel/key/put", KeyPut { channel, epoch: 1, envelopes, action: Some(rot) }.encode())
        .await
        .unwrap();
    assert_eq!(bob.collect_keys(channel).await.len(), 1);

    // Each side seals under its own device subkey and counts its own messages.
    let mut alice_seq = 0u64;
    let mut bob_seq = 0u64;
    // The chain advances per device, and is the same one the create and the
    // rotation already moved — starting again from zero here would be a fork.
    let send = |signer: &Signer, chain: &mut Chain, body: Body, seq: &mut u64| {
        let sealed = epoch1
            .seal(&channel, 1, &signer.device, *seq, &body.encode())
            .unwrap();
        let post = signer.post_chained(
            chain,
            channel,
            instance_for(channel, 0),
            1,
            *seq,
            sealed,
        );
        *seq += 1;
        post.encode()
    };

    // Sequence numbers are the exchange's, and the exchange's own entries share
    // the space, so a client works from what it was told rather than counting.
    let a1 = send(&alice.signer, &mut alice_chain, Body::Post(SipPost::text("has anyone seen the report")), &mut alice_seq);
    let (code, body) = alice.client.post("/channel/post", a1).await.unwrap();
    assert_eq!(code, 200);
    let question = Posted::decode(&body).unwrap().seq;

    let b1 = send(
        &bob.signer,
        &mut bob_chain,
        Body::Post(SipPost {
            parts: vec![
                Part::Reply(question),
                Part::Text("I have it here".into()),
                Part::Mention(alice.key),
            ],
            unknown: 0,
        }),
        &mut bob_seq,
    );
    let (_, body) = bob.client.post("/channel/post", b1).await.unwrap();
    let reply = Posted::decode(&body).unwrap().seq;

    let a2 = send(
        &alice.signer,
        &mut alice_chain,
        Body::Reaction { target: reply, add: true, emoji: "🙏".into() },
        &mut alice_seq,
    );
    assert_eq!(alice.client.post("/channel/post", a2).await.unwrap().0, 200);

    let b2 = send(
        &bob.signer,
        &mut bob_chain,
        Body::Edit { target: reply, post: SipPost::text("I have it here — sending now") },
        &mut bob_seq,
    );
    assert_eq!(bob.client.post("/channel/post", b2).await.unwrap().0, 200);

    let a3 = send(&alice.signer, &mut alice_chain, Body::Post(SipPost::text("ignore that")), &mut alice_seq);
    let (_, body) = alice.client.post("/channel/post", a3).await.unwrap();
    let regretted = Posted::decode(&body).unwrap().seq;
    let a4 = send(&alice.signer, &mut alice_chain, Body::Redact { target: regretted }, &mut alice_seq);
    assert_eq!(alice.client.post("/channel/post", a4).await.unwrap().0, 200);

    // Bob fetches the lot and folds it.
    let (code, body) = bob
        .client
        .post("/channel/fetch", Fetch { channel, since: 0, wait_secs: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let entries = Entries::decode(&body).unwrap();
    assert_eq!(
        entries
            .entries
            .iter()
            .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
            .count(),
        6
    );

    let t = timeline_of(&entries.entries, &epoch1, channel, &[alice.key]);
    let shown: Vec<&sqex_proto::timeline::Message> = t.messages().collect();
    assert_eq!(shown.len(), 3, "three posts; the rest act on them");

    assert_eq!(shown[0].post.body_text(), Some("has anyone seen the report"));
    assert!(shown[0].reactions.is_empty());

    // Alice thanked Bob's reply, and Bob then edited it. The reply target
    // survives the fold, so a client can still draw the thread.
    assert_eq!(shown[1].post.body_text(), Some("I have it here — sending now"));
    assert_eq!(shown[1].reactions["🙏"], vec![alice.key]);
    assert!(shown[1].edited.is_some());

    // Alice redacted her own, and it shows as a gap rather than vanishing.
    assert!(!shown[2].is_visible());
    assert_eq!(t.unreadable(), &[] as &[u64]);
}

#[tokio::test]
async fn a_forged_edit_is_ignored_by_the_reader_because_the_exchange_cannot_check_it() {
    // The exchange sees ciphertext, so it cannot tell that this edit came from
    // somebody other than the author. It accepts the entry, as it must. The
    // reader is what refuses it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 111).await;
    let mut alice_chain = Chain::default();
    let mut bob = Peer::new(addr, pubkey, 112).await;
    let mut bob_chain = Chain::default();
    let channel = [9u8; 32];

    alice.publish_prekeys(4).await;
    bob.publish_prekeys(4).await;
    alice
        .client
        .post(
            "/channel/create",
            private(&alice.signer, &mut alice_chain, channel, instance_for(channel, 0), vec![Invitee { account: bob.key, role: Role::Member }]).encode(),
        )
        .await
        .unwrap();
    let epoch1 = ChannelKey::generate();
    let mut envelopes = Vec::new();
    for who in [alice.key, bob.key] {
        let p = alice.take_prekey_for(who).await;
        envelopes.push(published(&alice.signer, channel, 1, seal_envelope(&who, p.id, &p.public, 1, &[epoch1]).unwrap()));
    }
    let rot = rotation(&alice.signer, &mut alice_chain, channel, 1);
    alice
        .client
        .post("/channel/key/put", KeyPut { channel, epoch: 1, envelopes, action: Some(rot) }.encode())
        .await
        .unwrap();
    bob.collect_keys(channel).await;

    // Each side signs as itself. SIP-31 does not touch what this test is
    // about: Bob can still seal a well-formed edit of Alice's message and post
    // it under his own name, and it is the *reader* that refuses it, because
    // the edit's account is not the target's.
    let seal = |signer: &Signer, chain: &mut Chain, body: Body, seq: u64| {
        let sealed = epoch1
            .seal(&channel, 1, &signer.device, seq, &body.encode())
            .unwrap();
        signer
            .post_chained(chain, channel, instance_for(channel, 0), 1, seq, sealed)
            .encode()
    };

    let a = seal(&alice.signer, &mut alice_chain, Body::Post(SipPost::text("what I actually said")), 0);
    let (code, body) = alice.client.post("/channel/post", a).await.unwrap();
    assert_eq!(code, 200);
    let target = Posted::decode(&body).unwrap().seq;

    // Bob is a member, so he holds the channel key and can seal a well-formed
    // edit of somebody else's message. The exchange takes it.
    let forged = seal(
        &bob.signer,
        &mut bob_chain,
        Body::Edit { target, post: SipPost::text("what Bob wishes I had said") },
        0,
    );
    assert_eq!(
        bob.client.post("/channel/post", forged).await.unwrap().0,
        200,
        "the exchange cannot read it, so it must accept it"
    );

    let (_, body) = alice
        .client
        .post("/channel/fetch", Fetch { channel, since: 0, wait_secs: 0 }.encode())
        .await
        .unwrap();
    let entries = Entries::decode(&body).unwrap();
    assert_eq!(
        entries
            .entries
            .iter()
            .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
            .count(),
        2,
        "both entries are stored"
    );

    let t = timeline_of(&entries.entries, &epoch1, channel, &[alice.key]);
    let m = t.get(target).unwrap();
    assert_eq!(
        m.post.body_text(),
        Some("what I actually said"),
        "the reader refuses what the exchange could not"
    );
    assert_eq!(m.edited, None);
}

#[tokio::test]
async fn a_removal_leaves_a_record_of_who_did_it() {
    // The reason system entries exist. Without them a member simply vanishes
    // from the roster and nothing says why or at whose hand.
    use sqex_proto::channel::{EVENT_ADDED, EVENT_REMOVED, KIND_SYSTEM, System};

    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 121).await;
    let mut alice_chain = Chain::default();
    let bob = Peer::new(addr, pubkey, 122).await;
    let channel = [30u8; 32];

    alice
        .client
        .post(
            "/channel/create",
            private(&alice.signer, &mut alice_chain, channel, instance_for(channel, 0), vec![Invitee { account: bob.key, role: Role::Member }]).encode(),
        )
        .await
        .unwrap();

    let mut rm = vec![TYPE_REMOVE];
    rm.extend_from_slice(&channel);
    rm.extend_from_slice(bob.key.as_bytes());
    alice
        .signer
        .action_chained(&mut alice_chain, channel, instance_for(channel, 0), EVENT_REMOVED, &bob.key, &[])
        .write(&mut rm);
    assert_eq!(alice.client.post("/channel/remove", rm).await.unwrap().0, 200);

    let (_, body) = alice
        .client
        .post("/channel/fetch", Fetch { channel, since: 0, wait_secs: 0 }.encode())
        .await
        .unwrap();
    let seen = Entries::decode(&body).unwrap();
    let events: Vec<System> = seen
        .entries
        .iter()
        .filter(|e| e.kind == KIND_SYSTEM)
        .filter_map(|e| System::decode(&e.body).ok().flatten())
        .collect();

    assert_eq!(events.len(), 3, "created, added at creation, then removed");
    assert_eq!(events[0].event, EVENT_CREATED);
    assert_eq!(events[1].event, EVENT_ADDED);
    assert_eq!(events[1].subject, bob.key);
    assert_eq!(events[2].event, EVENT_REMOVED);
    assert_eq!(events[1].subject, bob.key);
    assert_eq!(events[1].actor, alice.key, "and by whom");

    // The exchange wrote these, so they carry no member's name as author.
    let system = seen.entries.iter().find(|e| e.kind == KIND_SYSTEM).unwrap();
    assert_eq!(system.account, PubKey::new([0; 32]));
    assert_eq!(system.epoch, 0);
}

#[tokio::test]
async fn a_squatter_cannot_deny_two_people_a_direct_message() {
    // A direct-message identifier is a hash of two public keys, so anybody can
    // compute it. Without a rule, one request from a stranger would sit in that
    // channel forever and deny two people the ability to ever talk.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 131).await;
    let mut alice_chain = Chain::default();
    let bob = Peer::new(addr, pubkey, 132).await;
    let mut mallory = Peer::new(addr, pubkey, 133).await;
    let mut mallory_chain = Chain::default();

    let dm = sqex_proto::channel::direct_message_id(&alice.key, &bob.key);

    // Mallory gets there first, knowing nothing but two public keys — and
    // signs its own create, because SIP-32's `created` names its actor.
    let squat = private(&mallory.signer, &mut mallory_chain, dm, instance_for(dm, 0), vec![]);
    let (code, body) = mallory.client.post("/channel/create", squat.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));

    // Alice claims it by showing it is the derivation over herself and Bob,
    // which nobody but those two can do. The squatter's channel is discarded.
    //
    // A **new** incarnation: the squatter's is retired, and reusing it would
    // let the entries signed under it be replayed into the channel Alice is
    // building. The exchange refuses a repeat, which is what this line would
    // otherwise trip over.
    let (code, body) = alice
        .client
        .post(
            "/channel/create",
            private(&alice.signer, &mut alice_chain, dm, instance_for(dm, 1), vec![Invitee { account: bob.key, role: Role::Admin }]).encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));

    let (code, body) = alice
        .client
        .post("/channel/info", ByChannel { channel: dm }.encode(sqex_proto::channel::TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(code, 200);
    let info = sqex_proto::channel::ChannelInfo::decode(&body).unwrap();
    let members: Vec<PubKey> = info.members.iter().map(|m| m.account).collect();
    assert!(members.contains(&alice.key) && members.contains(&bob.key));
    assert!(!members.contains(&mallory.key), "the squatter has no claim");

    // And Mallory cannot take it back, having none.
    let (code, _) = mallory
        .client
        .post("/channel/create", private(&alice.signer, &mut alice_chain, dm, instance_for(dm, 0), vec![]).encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (_, body) = alice
        .client
        .post("/channel/info", ByChannel { channel: dm }.encode(sqex_proto::channel::TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(
        sqex_proto::channel::ChannelInfo::decode(&body).unwrap().members.len(),
        2
    );
}

#[tokio::test]
async fn a_party_who_left_a_direct_message_may_return_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let mut alice = Peer::new(addr, pubkey, 141).await;
    let mut alice_chain = Chain::default();
    let bob = Peer::new(addr, pubkey, 142).await;
    let dm = sqex_proto::channel::direct_message_id(&alice.key, &bob.key);

    alice
        .client
        .post(
            "/channel/create",
            private(&alice.signer, &mut alice_chain, dm, instance_for(dm, 0), vec![Invitee { account: bob.key, role: Role::Admin }]).encode(),
        )
        .await
        .unwrap();

    let leaving = {
        let acct = alice.signer.account;
        alice.signer.action_chained(&mut alice_chain, dm, instance_for(dm, 0), EVENT_LEFT, &acct, &[])
    };
    let (code, _) = alice
        .client
        .post(
            "/channel/leave",
            ByChannelSigned { channel: dm, action: leaving }
                .encode(sqex_proto::channel::TYPE_LEAVE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    // Bob keeps the conversation; leaving must not delete the other person's
    // copy of it.
    assert_eq!(
        alice
            .client
            .post("/channel/info", ByChannel { channel: dm }.encode(sqex_proto::channel::TYPE_INFO))
            .await
            .unwrap()
            .0,
        403,
        "she is no longer a member"
    );

    // Returning is a create, permitted because the derivation proves she is
    // one of the two the channel is named after.
    //
    // It names the incarnation that stands rather than proposing one, and it
    // signs a `joined` rather than an `added` — that is the event the exchange
    // writes for a return. A real client learns both from the first create,
    // which is answered `created: 0` with the incarnation and changes nothing.
    let mut back = private(&alice.signer, &mut Chain::default(), dm, instance_for(dm, 0), vec![Invitee {
        account: bob.key,
        role: Role::Admin,
    }]);
    let me = alice.signer.account;
    back.actions = vec![alice.signer.action_chained(
        &mut alice_chain,
        dm,
        instance_for(dm, 0),
        EVENT_JOINED,
        &me,
        &[],
    )];
    let (code, body) = alice
        .client
        .post("/channel/create", back.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let (code, body) = alice
        .client
        .post("/channel/info", ByChannel { channel: dm }.encode(sqex_proto::channel::TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        sqex_proto::channel::ChannelInfo::decode(&body).unwrap().members.len(),
        2
    );
}
