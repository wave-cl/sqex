//! SIP-87 agreed channel keys, through real clients and a real exchange.
//!
//! The unit tests in `sqex_proto::agreement` prove the key schedule agrees with
//! itself. These prove the thing that cannot be proved from one side: that a
//! commit posted by one client is read by another off the log, that the envelope
//! sealed beside it derives the same key, and — the control SIP-87 asks for by
//! name — that a device restored behind the channel **refuses** rather than
//! deriving nonsense.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::{Chat, ChatError};
use sqex_chat::store::Store;
use sqex_proto::agreement::Refused;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn chat_at(addr: SocketAddr, server_pub: [u8; 32], b: u8, store_path: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.top_up_prekeys().await.unwrap();
    chat
}

/// Read everything waiting: the entries first and the envelopes after, which is
/// SIP-87's order and not an accident of this helper. A device must read the
/// commit before opening the envelope, and the entries are where the commit is.
async fn catch_up(chat: &mut Chat, channel: &[u8; 32], timeline: &mut Timeline) {
    for _ in 0..3 {
        chat.poll(channel, timeline, 0).await.unwrap();
        chat.collect_keys(channel).await.unwrap();
    }
    chat.poll(channel, timeline, 0).await.unwrap();
}

#[tokio::test]
async fn every_member_derives_the_same_key_and_nobody_chose_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, bob_key) = identity(2);

    let channel = alice
        .create_agreed_group("the agreed one", &[bob_key])
        .await
        .unwrap();

    // Two commits, and the second is the one bob is in: a channel is keyed
    // before anybody is admitted to it, so that no welcome is ever published at
    // an epoch whose log holds no commit to recognise it by. Each is an entry
    // in the log rather than anything the exchange minted.
    assert_eq!(alice.info(&channel).await.unwrap().epoch, 2);

    alice.send(&channel, "keyed by all of us").await.unwrap();

    let mut bobs = Timeline::new();
    catch_up(&mut bob, &channel, &mut bobs).await;
    assert_eq!(
        bobs.messages().next().and_then(|m| m.post.body_text()),
        Some("keyed by all of us"),
        "bob did not get epoch 1's key"
    );
    // And he holds the *chain*, not merely the key.
    //
    // Asserted separately because the two come apart, and the way they come
    // apart is worth knowing: a `Welcome`'s slots are laid out so that slot `i`
    // is the key for `from_epoch + i`, which means a reader that took it for an
    // ordinary SIP-17 envelope would store the right key for the right epoch and
    // a junk one for the slot the chain sits in. Harmless, and it would leave
    // this device unable to derive a single epoch after this one — so reading one
    // message is not evidence that any of SIP-87 ran.
    assert_eq!(
        bob.agreed_epoch(&channel).unwrap(),
        Some(2),
        "bob read the epoch without being welcomed into the chain behind it"
    );

    // And bob can post under it, which is the other half: a key he could read
    // with and not write with would be half derived.
    bob.send(&channel, "and by me").await.unwrap();
    let mut alices = Timeline::new();
    catch_up(&mut alice, &channel, &mut alices).await;
    assert!(
        alices
            .messages()
            .any(|m| m.post.body_text() == Some("and by me")),
        "alice could not read what bob sealed under the agreed key"
    );
}

#[tokio::test]
async fn an_addition_is_in_the_log_before_the_key_it_is_for_exists() {
    // SIP-87's first claim: under SIP-17 the key exists as soon as the admin
    // generates it and the envelopes are the only trace. Here the epoch key does
    // not exist until a commit naming the member set is in the log, signed, and
    // read by the members.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("carol.db")).await;
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(3);

    let channel = alice
        .create_agreed_group("before and after", &[bob_key])
        .await
        .unwrap();
    alice.send(&channel, "said before carol").await.unwrap();

    let mut bobs = Timeline::new();
    catch_up(&mut bob, &channel, &mut bobs).await;

    alice.commit(&channel, &[carol_key], &[]).await.unwrap();
    alice.send(&channel, "said after carol").await.unwrap();

    // Bob reads the commit as a commit: a member's signed statement of who the
    // next epoch is for, in the same sequence space as the messages.
    catch_up(&mut bob, &channel, &mut bobs).await;
    let added = bobs
        .commits()
        .find(|c| c.commit.adds.contains(&carol_key))
        .expect("bob never read the commit that admitted carol");
    assert_eq!(added.commit.adds, vec![carol_key]);
    assert_eq!(added.account, identity(1).1, "the committer is attributed");
    assert!(
        added.posted > 0,
        "a commit a client cannot date cannot be shown as 'X added Y at 14:02'"
    );

    // And carol reads from her own epoch forward and no further back, which is
    // the retroactive addition SIP-87 says stops being possible.
    let mut carols = Timeline::new();
    catch_up(&mut carol, &channel, &mut carols).await;
    let said: Vec<String> = carols
        .messages()
        .filter_map(|m| m.post.body_text().map(str::to_string))
        .collect();
    assert!(
        said.iter().any(|t| t == "said after carol"),
        "carol could not read the epoch she was admitted at: {said:?}"
    );
    assert!(
        !said.iter().any(|t| t == "said before carol"),
        "carol reached an epoch before her own: {said:?}"
    );
}

#[tokio::test]
async fn a_device_two_epochs_behind_refuses_rather_than_deriving_nonsense() {
    // SIP-87 §Reference implementation asks for exactly this control: "a device
    // restored two epochs behind, handed a commit secret, must refuse rather
    // than derive nonsense."
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let bob_db = dir.path().join("bob.db");
    let mut bob = chat_at(addr, server_pub, 2, &bob_db).await;
    let (_, bob_key) = identity(2);
    let (_, carol_key) = identity(3);
    let (_, dave_key) = identity(4);

    let channel = alice
        .create_agreed_group("the restore", &[bob_key])
        .await
        .unwrap();
    let mut bobs = Timeline::new();
    catch_up(&mut bob, &channel, &mut bobs).await;
    assert_eq!(
        bob.agreed_epoch(&channel).unwrap().unwrap(),
        2,
        "bob must be in before there is a backup worth restoring"
    );

    // The backup, taken while bob stands at the epoch he was admitted at.
    // Copied rather than
    // reopened: a restore is a file from before, and reopening the live one
    // would test nothing.
    drop(bob);
    let backup = dir.path().join("bob-behind.db");
    std::fs::copy(&bob_db, &backup).unwrap();

    // The channel goes on without him. Two commits, so the secret he is handed
    // is for an epoch two above the chain he holds.
    alice.commit(&channel, &[carol_key], &[]).await.unwrap();
    alice.commit(&channel, &[dave_key], &[]).await.unwrap();
    assert_eq!(alice.info(&channel).await.unwrap().epoch, 4);
    alice
        .send(&channel, "said while bob was away")
        .await
        .unwrap();

    // **And the epoch between is withheld**, which is what makes this the case
    // SIP-87 asks about rather than a restore that simply catches up.
    //
    // Worth being exact about, because it is a finding. A backup holds the
    // SIP-23 prekey secrets it was taken with, so a restored device can usually
    // open every envelope published since and walk its chain forward one commit
    // at a time — the feared failure does not arise. It arises when an epoch's
    // secret never reaches the device at all, and SIP-87 names the party who can
    // arrange that: "the exchange can still withhold", and withholding a commit
    // "stops a member posting" rather than merely hiding a message. So the
    // envelope for the epoch between is deleted from the exchange's own store,
    // which is the one place it lives.
    let db = rusqlite::Connection::open(dir.path().join("channels.db")).unwrap();
    let gone = db
        .execute(
            "DELETE FROM envelope WHERE channel = ?1 AND recipient = ?2 AND epoch = 3",
            rusqlite::params![&channel[..], bob_key.as_bytes()],
        )
        .unwrap();
    assert_eq!(gone, 1, "there was no envelope for bob to withhold");
    drop(db);

    let mut restored = chat_at(addr, server_pub, 2, &backup).await;
    let mut theirs = Timeline::new();
    catch_up(&mut restored, &channel, &mut theirs).await;

    // Refused, and said so. Not "derived something": the chain has not moved,
    // there is no key for the epoch it was handed, and what it could not do is
    // named.
    assert_eq!(
        restored.refusal(&channel),
        Some(Refused::WrongEpoch { held: 2, commit: 4 }),
        "a device two epochs behind did not refuse the commit secret it was sent"
    );
    assert_eq!(
        restored.agreed_epoch(&channel).unwrap().unwrap(),
        2,
        "the chain moved on a commit it could not derive"
    );
    let said: Vec<String> = theirs
        .messages()
        .filter_map(|m| m.post.body_text().map(str::to_string))
        .collect();
    assert!(
        !said.iter().any(|t| t == "said while bob was away"),
        "a refused derivation still produced a readable epoch: {said:?}"
    );

    // And the way back is the one SIP-87 names: admitted again by a commit,
    // which is visible to the whole channel.
    alice.commit(&channel, &[bob_key], &[]).await.unwrap();
    alice.send(&channel, "and bob is back").await.unwrap();
    catch_up(&mut restored, &channel, &mut theirs).await;
    assert!(
        theirs
            .messages()
            .any(|m| m.post.body_text() == Some("and bob is back")),
        "a re-admitted device could not read the epoch that admitted it"
    );
    assert_eq!(
        restored.refusal(&channel),
        None,
        "the refusal was not cleared"
    );
}

#[tokio::test]
async fn an_ordinary_member_cannot_commit_merely_because_it_wants_to() {
    // The finding this implementation produced, asserted so that it cannot
    // regress into either story being half true.
    //
    // SIP-87 §Why any member may commit says an ordinary member's commit is one
    // with no adds and no removes, "a rekey and nothing else". SIP-17 §Put says a
    // non-admin publishing MUST use the current epoch, with one exception — a
    // member who revoked one of its own devices since the epoch was minted — and
    // SIP-17's own amendment for SIP-87 says "Nothing in this document changes".
    // So post-compromise security is reachable exactly where SIP-17 already put
    // it, by revoking the suspected device first, and a scheduled member rekey
    // is not reachable at all.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, bob_key) = identity(2);

    let channel = alice
        .create_agreed_group("who may commit", &[bob_key])
        .await
        .unwrap();
    let mut bobs = Timeline::new();
    catch_up(&mut bob, &channel, &mut bobs).await;

    let refused = bob.commit(&channel, &[], &[]).await;
    assert!(
        matches!(refused, Err(ChatError::NotAnAdmin)),
        "an ordinary member's rekey was accepted, which SIP-17 §Put forbids: {refused:?}"
    );
    // And the channel is where it was: a refused commit leaves no half-keyed
    // epoch behind.
    assert_eq!(alice.info(&channel).await.unwrap().epoch, 2);
    assert_eq!(bob.agreed_epoch(&channel).unwrap().unwrap(), 2);
}

#[tokio::test]
async fn a_commit_cannot_be_made_on_an_admin_keyed_channel() {
    // SIP-17, amended for SIP-87: a channel is agreed or admin-keyed from its
    // first commit and MUST NOT mix the two, because a client deriving the
    // current epoch has to know which rule produced it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let _ = &mut bob;

    let channel = alice
        .create_group("the admin-keyed one", &[bob_key])
        .await
        .unwrap();
    assert!(
        matches!(
            alice.commit(&channel, &[], &[]).await,
            Err(ChatError::NotAgreed)
        ),
        "a commit was made on a channel whose key an admin minted"
    );
}

#[tokio::test]
async fn a_member_whose_chain_is_behind_cannot_commit_at_all() {
    // The control on the transcript, and it turned out to be stronger than the
    // one that was wanted. Two members must not both be accepted at one epoch;
    // what this asserts is that a member whose chain is behind cannot *build* a
    // commit, let alone publish one — it refuses before anything reaches the
    // exchange, because the epoch it would create is not the one after the chain
    // it holds and the transcript it would state is not the one that stands.
    //
    // So the divergent chain the race is feared for cannot be minted by a stale
    // member at all, and the only parties who can race are two members both up
    // to date — where SIP-17's own rule arbitrates, one envelope per recipient
    // per epoch, with the loser told which epoch stands.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, bob_key) = identity(2);

    let channel = alice
        .create_agreed_group("two committers", &[bob_key])
        .await
        .unwrap();
    // Both admins, so SIP-17 §Put lets either advance the epoch: what stops bob
    // below is SIP-87 and not a role.
    alice
        .grant(&channel, &bob_key, sqex_proto::channel::Role::Admin)
        .await
        .unwrap();
    let mut bobs = Timeline::new();
    catch_up(&mut bob, &channel, &mut bobs).await;
    assert_eq!(bob.agreed_epoch(&channel).unwrap(), Some(2));

    alice.commit(&channel, &[], &[]).await.unwrap();
    assert_eq!(alice.info(&channel).await.unwrap().epoch, 3);

    // Bob has not read the commit yet, and tries to commit himself.
    let refused = bob.commit(&channel, &[], &[]).await;
    assert_eq!(
        refused.err().map(|e| e.to_string()),
        Some(
            "this device's chain stands at epoch 2 and the commit creates 4: \
             it must be admitted again by a commit"
                .to_string()
        ),
        "a member two epochs out committed anyway"
    );
    // And nothing of it reached the exchange: no epoch, no envelopes, no entry.
    assert_eq!(
        alice.info(&channel).await.unwrap().epoch,
        3,
        "a refused commit moved the channel"
    );

    // Caught up, he may commit, and the chain is one chain.
    catch_up(&mut bob, &channel, &mut bobs).await;
    assert_eq!(bob.agreed_epoch(&channel).unwrap(), Some(3));
    assert_eq!(bob.commit(&channel, &[], &[]).await.unwrap(), 4);
    bob.send(&channel, "under the epoch bob made")
        .await
        .unwrap();
    let mut alices = Timeline::new();
    catch_up(&mut alice, &channel, &mut alices).await;
    assert_eq!(alice.agreed_epoch(&channel).unwrap(), Some(4));
    assert!(
        alices
            .messages()
            .any(|m| m.post.body_text() == Some("under the epoch bob made")),
        "alice could not read the epoch bob committed"
    );
    // One commit per epoch, counted off the store rather than off this poll's
    // fold: a poll folds from the cursor, and alice's was already above her own
    // first commit. `history` is what a client draws the conversation from, and
    // rebuilding it is how a commit survives a restart.
    let whole = alice.history(&channel, &[identity(1).1, bob_key]).unwrap();
    assert_eq!(
        whole.commits().map(|c| c.commit.epoch).collect::<Vec<_>>(),
        vec![1, 2, 3, 4],
        "the log does not hold one commit per epoch"
    );
}

#[tokio::test]
async fn nobody_is_welcomed_at_the_first_commit() {
    // **The window between a commit's envelopes and its entry**, closed by
    // construction rather than by timing.
    //
    // SIP-87 cannot avoid the ordering: the exchange takes a post only at the
    // epoch in force, so the envelopes that create an epoch go up before the
    // entry explaining them. In between, a device reading the channel for the
    // first time has read the whole log, finds no commit anywhere in it, and
    // has nothing to tell SIP-17's kind from this one. Take the `Welcome` for a
    // SIP-17 key and the SIP-23 prekey is spent, the chain inside it thrown
    // away — and the failure hides, because the slot layout leaves such a
    // device holding the right key for the epoch it was admitted at. It reads
    // that one epoch and derives nothing after it. That is how this was found:
    // a sigil session read one message and then quietly stopped.
    //
    // So the first commit admits nobody. Every `Welcome` is then for an epoch
    // of two or more, by which time the log holds the first commit and the
    // question is settled however the timing falls. This asserts that shape;
    // `sigil`'s `an_agreed_group_draws_who_the_key_is_for` drives the race
    // itself, and failed against this file before the rule was added.
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice
        .create_agreed_group("keyed before anybody is let in", &[bob_key])
        .await
        .unwrap();

    let whole = alice.history(&channel, &[alice_key, bob_key]).unwrap();
    let admitting = whole
        .commits()
        .find(|c| c.commit.adds.contains(&bob_key))
        .expect("alice should hold the commit that admitted bob");
    assert!(
        admitting.commit.epoch >= 2,
        "a welcome at the first commit would reach a device with no commit in \
         its log to recognise it by: epoch {}",
        admitting.commit.epoch
    );
    // And the commit it is safe by is really there, earlier in the log, naming
    // nobody.
    let first = whole
        .commits()
        .find(|c| c.commit.epoch == 1)
        .expect("the channel is keyed by a commit before anybody is admitted");
    assert!(
        first.seq < admitting.seq,
        "the keying commit must be in the log before the one that admits"
    );
    assert!(
        first.commit.adds.is_empty() && first.commit.removes.is_empty(),
        "and must admit nobody: {:?}",
        first.commit.adds
    );

    // The invitee still ends up in, which is the point of the extra epoch
    // being cheap rather than free.
    let mut bobs = Timeline::new();
    catch_up(&mut bob, &channel, &mut bobs).await;
    assert_eq!(
        bob.agreed_epoch(&channel).unwrap(),
        Some(admitting.commit.epoch),
        "the invitee is welcomed at the commit that admitted it"
    );
    alice
        .send(&channel, "in at the second epoch")
        .await
        .unwrap();
    catch_up(&mut bob, &channel, &mut bobs).await;
    assert!(
        bobs.messages()
            .any(|m| m.post.body_text() == Some("in at the second epoch")),
        "and reads under the key it derived: {:?}",
        bobs.messages()
            .filter_map(|m| m.post.body_text())
            .collect::<Vec<_>>()
    );
}
