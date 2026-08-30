//! SIP-31: what a signature on a channel entry actually buys.
//!
//! Every test here fails against the code that preceded this SIP, and most of
//! them could not be written at all before it — there was nothing to forge.
//!
//! The through-line: an entry's author used to be the exchange's observation of
//! a connection, which SIP-16 says plainly is not a cryptographic fact. These
//! check that it now is, and that the three things which stop a signature
//! travelling — the exchange it was made against, the channel incarnation, and
//! the account it names — each actually stop it.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByChannel, Entries, Fetch, Invitee, Post, Role, TYPE_INFO, Visibility, direct_message_id,
};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

mod common;
use common::{Chain, Signer, instance_for};

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n",
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

async fn connect(addr: SocketAddr, server_pub: [u8; 32], seed: [u8; 32]) -> Client {
    Client::connect_as(addr, &server_pub, &seed).await.unwrap()
}

fn signer(server_pub: [u8; 32], b: u8) -> Signer {
    let (seed, key) = identity(b);
    Signer::new(seed, key, server_pub)
}

/// A public channel `b` creates, with nothing in it.
async fn a_room(c: &mut Client, s: &Signer, channel: [u8; 32]) {
    let (code, body) = c
        .post(
            "/channel/create",
            s.create(channel, instance_for(channel, 0), Visibility::Public, 3600, "room", vec![])
                .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
}

/// **The forgery this SIP exists to stop.**
///
/// Before it, an entry's author was whatever the exchange observed on the
/// connection, so the only thing standing between a member and a message
/// attributed to somebody else was the exchange declining to write the wrong
/// device into the header. Nothing about the entry itself said who wrote it.
///
/// Here Mallory signs an entry naming Alice's account and device — the header
/// he wishes the exchange would stamp — and presents it on his own connection.
/// The exchange rebuilds the terms from what it actually sees and the signature
/// does not verify under it.
#[tokio::test]
async fn an_entry_signed_by_one_device_and_claimed_by_another_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(11);
    let (mallory_seed, _) = identity(12);
    let channel = [1u8; 32];

    let mut a = connect(addr, server_pub, alice_seed).await;
    let mut m = connect(addr, server_pub, mallory_seed).await;
    a_room(&mut a, &signer(server_pub, 11), channel).await;

    // Mallory joins, so membership is not what refuses him.
    let joining = signer(server_pub, 12).action_outside(
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_JOINED,
        &identity(12).1,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, _) = m
        .post(
            "/channel/join",
            sqex_proto::channel::ByChannelSigned { channel, action: joining }
                .encode(sqex_proto::channel::TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "membership must not be what refuses the forgery");

    // Signed by Mallory's key over terms that name Alice.
    let as_alice = Signer {
        seed: mallory_seed,
        account: alice,
        device: alice,
        exchange: PubKey::new(server_pub),
    };
    let forged = as_alice.post_chained(
        &mut Chain { seq: 1, head: [0; 32] },
        channel,
        instance_for(channel, 0),
        0,
        0,
        b"alice would never say this".to_vec(),
    );
    let (code, body) = m.post("/channel/post", forged.encode()).await.unwrap();
    assert_eq!(
        code, 401,
        "an entry claiming another account was stored: {}",
        String::from_utf8_lossy(&body)
    );
}

/// **Cross-exchange replay**, and the reason the exchange's own key is in the
/// signing input.
///
/// A direct message's identifier is derived from its two accounts (SIP-16), so
/// the same conversation between the same two people has byte-identical channel
/// bytes on every exchange that has ever existed. Without the origin bound into
/// the signature, an entry lifts out of one and into another's copy of it and
/// verifies there — which is precisely what SIP-10 binds `transaction.server`
/// against, and says so.
#[tokio::test]
async fn an_entry_signed_against_one_exchange_is_refused_by_another() {
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();
    let (addr_a, pub_a, _h1) = server_in(one.path()).await;
    let (addr_b, pub_b, _h2) = server_in(two.path()).await;
    assert_ne!(pub_a, pub_b, "two exchanges must not share a key");

    let (alice_seed, alice) = identity(21);
    let (_, bob) = identity(22);
    let channel = direct_message_id(&alice, &bob);

    // The same channel identifier on both, which is the whole hazard.
    let mut a1 = connect(addr_a, pub_a, alice_seed).await;
    let mut a2 = connect(addr_b, pub_b, alice_seed).await;
    for (c, key) in [(&mut a1, pub_a), (&mut a2, pub_b)] {
        let (code, _) = c
            .post(
                "/channel/create",
                signer(key, 21)
                    .create(
                        channel,
                        instance_for(channel, 0),
                        Visibility::Public,
                        3600,
                        "",
                        vec![],
                    )
                    .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200);
    }

    // Signed for exchange A, accepted there.
    let signed = signer(pub_a, 21).post_chained(
        &mut Chain::default(),
        channel,
        instance_for(channel, 0),
        0,
        0,
        b"for one exchange only".to_vec(),
    );
    assert_eq!(
        a1.post("/channel/post", signed.encode()).await.unwrap().0,
        200,
        "the honest case must work, or this test proves nothing"
    );

    // The same bytes, at exchange B.
    let (code, body) = a2.post("/channel/post", signed.encode()).await.unwrap();
    assert_eq!(
        code, 401,
        "an entry lifted between exchanges verified: {}",
        String::from_utf8_lossy(&body)
    );
}

/// **Cross-incarnation replay**, and the reason a channel carries an instance.
///
/// SIP-16 describes a destroyed direct message being recreated under the same
/// derived identifier with its numbering restarted, and says an exchange cannot
/// avoid the situation in general. Without an incarnation marker in the
/// signature, every entry of the first one replays into the second, where the
/// channel, the epoch and the empty chain all agree with it.
#[tokio::test]
async fn an_entry_from_a_previous_incarnation_is_refused_by_the_next() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(31);
    let (bob_seed, bob) = identity(32);
    let channel = direct_message_id(&alice, &bob);

    let mut a = connect(addr, server_pub, alice_seed).await;
    let mut b = connect(addr, server_pub, bob_seed).await;

    let first = instance_for(channel, 0);
    let (code, _) = a
        .post(
            "/channel/create",
            signer(server_pub, 31)
                .create(channel, first, Visibility::Public, 3600, "", vec![])
                .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let said = signer(server_pub, 31).post_chained(
        &mut Chain::default(),
        channel,
        first,
        0,
        0,
        b"said in the first one".to_vec(),
    );
    assert_eq!(a.post("/channel/post", said.encode()).await.unwrap().0, 200);

    // Alice closes it and rebuilds under the same identifier — which she cannot
    // avoid, because it is the derivation over the two of them.
    let (code, _) = a
        .post(
            "/channel/close",
            ByChannel { channel }.encode(sqex_proto::channel::TYPE_CLOSE),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let second = instance_for(channel, 1);
    let (code, _) = a
        .post(
            "/channel/create",
            signer(server_pub, 31)
                .create(channel, second, Visibility::Public, 3600, "", vec![])
                .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // The old entry, verbatim, into the new incarnation.
    let (code, body) = a.post("/channel/post", said.encode()).await.unwrap();
    assert_eq!(
        code, 401,
        "an entry from a previous incarnation was accepted: {}",
        String::from_utf8_lossy(&body)
    );
    let _ = &mut b;
}

/// The exchange refuses an incarnation an identifier has already used.
///
/// Without this the marker is only as good as every client's randomness, and a
/// client that reused one deliberately would re-admit the entries signed under
/// it.
#[tokio::test]
async fn an_incarnation_cannot_be_used_twice_for_one_identifier() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(41);
    let (_, bob) = identity(42);
    let channel = direct_message_id(&alice, &bob);
    let mut a = connect(addr, server_pub, alice_seed).await;

    let once = instance_for(channel, 0);
    let build = |i: [u8; 32]| {
        signer(server_pub, 41)
            .create(channel, i, Visibility::Public, 3600, "", vec![])
            .encode()
    };
    assert_eq!(a.post("/channel/create", build(once)).await.unwrap().0, 200);
    assert_eq!(
        a.post(
            "/channel/close",
            ByChannel { channel }.encode(sqex_proto::channel::TYPE_CLOSE)
        )
        .await
        .unwrap()
        .0,
        200
    );

    let (code, body) = a.post("/channel/create", build(once)).await.unwrap();
    assert_eq!(
        code, 409,
        "an identifier reused an incarnation: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(String::from_utf8_lossy(&body).contains("used_instance"));

    // A fresh one is fine, which is what makes the refusal a rule and not a
    // ban on rebuilding a conversation.
    assert_eq!(
        a.post("/channel/create", build(instance_for(channel, 1)))
            .await
            .unwrap()
            .0,
        200
    );
}

/// A chain position may not be reused, and may not be skipped.
///
/// The first is a fork and cannot happen without a device signing twice or
/// somebody replaying. The second is what an exchange dropping an entry would
/// leave behind, and refusing it here is what makes the omission visible rather
/// than silent.
#[tokio::test]
async fn a_chain_position_is_neither_reused_nor_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(51);
    let channel = [5u8; 32];
    let mut a = connect(addr, server_pub, alice_seed).await;
    a_room(&mut a, &signer(server_pub, 51), channel).await;

    let s = signer(server_pub, 51);
    let mut chain = Chain::default();
    let first = s.post_chained(&mut chain, channel, instance_for(channel, 0), 0, 0, b"one".to_vec());
    assert_eq!(a.post("/channel/post", first.encode()).await.unwrap().0, 200);

    // The same position again.
    let repeat = s.post_chained(
        &mut Chain::default(),
        channel,
        instance_for(channel, 0),
        0,
        1,
        b"again".to_vec(),
    );
    let (code, body) = a.post("/channel/post", repeat.encode()).await.unwrap();
    assert_eq!(code, 409, "{}", String::from_utf8_lossy(&body));
    assert!(String::from_utf8_lossy(&body).contains("broken_chain"));

    // A position skipped over.
    let ahead = s.post_chained(
        &mut Chain { seq: chain.seq + 3, head: chain.head },
        channel,
        instance_for(channel, 0),
        0,
        2,
        b"ahead".to_vec(),
    );
    let (code, body) = a.post("/channel/post", ahead.encode()).await.unwrap();
    assert_eq!(code, 409, "{}", String::from_utf8_lossy(&body));

    // And the next position, in order, still works.
    let second = s.post_chained(&mut chain, channel, instance_for(channel, 0), 0, 3, b"two".to_vec());
    assert_eq!(a.post("/channel/post", second.encode()).await.unwrap().0, 200);
}

/// A redaction keeps the signature, and it still verifies.
///
/// The commitment is to `SHA-256(body)` rather than to the body precisely so a
/// tombstone survives with its signature intact and the device's chain runs
/// through it unbroken. Clearing the signature instead would make every deleted
/// message read as a forgery.
#[tokio::test]
async fn a_tombstone_keeps_a_signature_that_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(61);
    let channel = [6u8; 32];
    let mut a = connect(addr, server_pub, alice_seed).await;
    a_room(&mut a, &signer(server_pub, 61), channel).await;

    let s = signer(server_pub, 61);
    let mut chain = Chain::default();
    let said = s.post_chained(&mut chain, channel, instance_for(channel, 0), 0, 0, b"regret".to_vec());
    let (_, body) = a.post("/channel/post", said.encode()).await.unwrap();
    let seq = sqex_proto::channel::Posted::decode(&body).unwrap().seq;

    let (code, _) = a
        .post(
            "/channel/redact",
            sqex_proto::channel::ByTarget { channel, target: seq }
                .encode(sqex_proto::channel::TYPE_REDACT),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let (_, body) = a
        .post("/channel/fetch", Fetch { channel, since: 0, wait_secs: 0 }.encode())
        .await
        .unwrap();
    let seen = Entries::decode(&body).unwrap();
    let tomb = seen.entries.iter().find(|e| e.seq == seq).expect("the tombstone is gone");
    assert!(tomb.body.is_empty(), "the body survived the redaction");
    assert_ne!(tomb.sig, [0u8; 64], "the signature was cleared with the body");

    let terms = sqex_proto::entry_sig::EntryTerms {
        place: sqex_proto::entry_sig::Place {
            exchange: PubKey::new(server_pub),
            instance: instance_for(channel, 0),
            channel,
        },
        account: tomb.account,
        device: tomb.device,
        epoch: tomb.epoch,
        msg_seq: tomb.msg_seq,
        expires_after: tomb.expires_after,
        chain_seq: tomb.chain_seq,
        prev: tomb.prev,
        body: &[],
    };
    assert!(
        sqex_proto::entry_sig::verify_entry_hashed(&terms, &tomb.body_hash, &tomb.sig),
        "a tombstone's signature no longer verifies, so every deletion reads as a forgery"
    );

    // And the chain runs through it: the next entry follows on.
    let next = s.post_chained(&mut chain, channel, instance_for(channel, 0), 0, 1, b"after".to_vec());
    assert_eq!(a.post("/channel/post", next.encode()).await.unwrap().0, 200);
}

/// An entry with no signature at all is refused.
///
/// There is no unsigned member entry in a conforming exchange. The reference
/// deployment was wiped rather than migrated so that this could be a rule
/// rather than a default, and a test pins it so nobody reintroduces tolerance
/// for one later as a convenience.
#[tokio::test]
async fn an_unsigned_entry_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(71);
    let channel = [7u8; 32];
    let mut a = connect(addr, server_pub, alice_seed).await;
    a_room(&mut a, &signer(server_pub, 71), channel).await;

    let bare = Post {
        channel,
        epoch: 0,
        msg_seq: 0,
        expires_after: 0,
        chain_seq: 0,
        prev: [0; 32],
        sig: [0; 64],
        body: b"nobody vouched for this".to_vec(),
    };
    let (code, body) = a.post("/channel/post", bare.encode()).await.unwrap();
    assert_eq!(
        code, 401,
        "an unsigned entry was stored: {}",
        String::from_utf8_lossy(&body)
    );
}

/// A membership event nobody signed for cannot be written.
///
/// This is what makes a replica able to answer "was this account a member when
/// this entry was signed" from the log rather than from its peer's word.
#[tokio::test]
async fn a_membership_event_needs_the_actors_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(81);
    let (_, bob) = identity(82);
    let channel = [8u8; 32];
    let mut a = connect(addr, server_pub, alice_seed).await;
    a_room(&mut a, &signer(server_pub, 81), channel).await;

    // An invite carrying a signature made by somebody else's key.
    let impostor = Signer {
        seed: identity(83).0,
        account: identity(81).1,
        device: identity(81).1,
        exchange: PubKey::new(server_pub),
    };
    let action = impostor.action_outside(
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_ADDED,
        &bob,
        &[Role::Member as u8],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, body) = a
        .post(
            "/channel/invite",
            sqex_proto::channel::Invite { channel, account: bob, role: Role::Member, action }
                .encode(),
        )
        .await
        .unwrap();
    assert_eq!(
        code, 401,
        "a membership change went in under a signature nobody made: {}",
        String::from_utf8_lossy(&body)
    );

    // Nobody was added.
    let (_, body) = a
        .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(
        sqex_proto::channel::ChannelInfo::decode(&body).unwrap().members.len(),
        1
    );
}

/// **The degenerate case, made non-degenerate.**
///
/// SIP-22 makes an account with no registered device *its own* device, so the
/// account key and the device key are the same 32 bytes and every rule that
/// distinguishes them is untestable. That is exactly how SIP-17's per-device
/// sealing went unimplemented for a whole release line. Here two devices of one
/// account each sign their own entries, keep their own chains, and are recorded
/// under one account.
#[tokio::test]
async fn two_devices_of_one_account_sign_separately_and_chain_separately() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (account_seed, account) = identity(91);
    let (desk_seed, desk_key) = identity(92);
    let (hand_seed, hand_key) = identity(93);
    let channel = [9u8; 32];

    let mut desk = connect(addr, server_pub, desk_seed).await;
    let mut hand = connect(addr, server_pub, hand_seed).await;

    // Link both to the account.
    for (c, device) in [(&mut desk, desk_key), (&mut hand, hand_key)] {
        let cred = sqex_proto::credential::Credential::issue(
            &account_seed,
            &device,
            sqex_proto::credential::SCOPE_CHAT,
            0,
            u64::MAX / 2,
        )
        .unwrap();
        let (code, _) = c
            .post(
                "/device/register",
                sqex_proto::device::Register { credential: cred }.encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "linking a device failed");
    }

    let d = Signer::new(desk_seed, desk_key, server_pub).for_account(account);
    let h = Signer::new(hand_seed, hand_key, server_pub).for_account(account);
    a_room(&mut desk, &d, channel).await;

    // Two chains, both starting at zero, neither treading on the other.
    let mut dc = Chain::default();
    let mut hc = Chain::default();
    let one = d.post_chained(&mut dc, channel, instance_for(channel, 0), 0, 0, b"desk".to_vec());
    let two = h.post_chained(&mut hc, channel, instance_for(channel, 0), 0, 0, b"phone".to_vec());
    assert_eq!(desk.post("/channel/post", one.encode()).await.unwrap().0, 200);
    assert_eq!(hand.post("/channel/post", two.encode()).await.unwrap().0, 200);

    let (_, body) = desk
        .post("/channel/fetch", Fetch { channel, since: 0, wait_secs: 0 }.encode())
        .await
        .unwrap();
    let seen = Entries::decode(&body).unwrap();
    let mine: Vec<_> = seen
        .entries
        .iter()
        .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .collect();
    assert_eq!(mine.len(), 2);
    for e in &mine {
        assert_eq!(e.account, account, "the account is the person, not the client");
    }
    assert_ne!(mine[0].device, mine[1].device, "two clients, two devices");
    assert_eq!(mine[0].chain_seq, 0);
    assert_eq!(mine[1].chain_seq, 0, "each device keeps its own chain");

    // And a device may not sign for the other's position.
    let crossed = d.post_chained(&mut hc, channel, instance_for(channel, 0), 0, 1, b"no".to_vec());
    let (code, _) = hand.post("/channel/post", crossed.encode()).await.unwrap();
    assert_eq!(code, 401, "one device's signature stood for another's entry");
    let _ = Invitee { account, role: Role::Member };
}
