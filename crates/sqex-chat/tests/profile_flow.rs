//! SIP-21 through the client: what a person publishes about themselves, and
//! who they can stop reaching them.
//!
//! The exchange side of this is tested in `sqexd/tests/profile_flow.rs`. What
//! is tested here is the half a person actually touches — that a name can be
//! published and read back, that blocking a stranger works from the client
//! that has been written to, and that the name never arrives anywhere without
//! the key that distinguishes it from an identical one.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::profile::Profile;
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

fn named(name: &str, title: &str) -> Profile {
    Profile {
        flags: 0,
        name: name.into(),
        title: title.into(),
        avatar: Vec::new(),
    }
}

#[tokio::test]
async fn a_name_is_published_and_read_back_by_somebody_sharing_a_channel() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    alice.set_profile(named("Alice", "shipping")).await.unwrap();

    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "hello").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let got = bob.profile_of(&alice_key).await.unwrap();
    assert!(got.found);
    assert_eq!(got.profile.name, "Alice");
    // Called `title` and not `role` on purpose: `role` is what the exchange
    // holds and vouches for, and this is what its subject says about itself.
    assert_eq!(got.profile.title, "shipping");
}

#[tokio::test]
async fn a_name_is_cached_and_not_asked_for_twice() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    alice.set_profile(named("Alice", "")).await.unwrap();
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "hello").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let now = 1_000_000;
    assert_eq!(bob.refresh_profiles(&[alice_key], now).await.unwrap(), 1);
    assert_eq!(bob.display_name(&alice_key).as_deref(), Some("Alice"));

    // Asked once. Asking the exchange who everybody is on every poll would
    // turn a display convenience into a stream of traffic about who this
    // client is reading.
    assert_eq!(bob.refresh_profiles(&[alice_key], now + 60).await.unwrap(), 0);
    // And an hour later it is asked again, because SIP-21 lets a profile
    // change 32 times an hour.
    assert_eq!(
        bob.refresh_profiles(&[alice_key], now + 3601).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn an_account_that_publishes_nothing_is_not_asked_about_forever() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "hello").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let now = 1_000_000;
    assert_eq!(bob.refresh_profiles(&[alice_key], now).await.unwrap(), 1);
    assert_eq!(bob.display_name(&alice_key), None, "a name was invented");
    // "Asked and told nothing" is remembered, or the client asks again on
    // every poll for the rest of the conversation.
    assert_eq!(bob.refresh_profiles(&[alice_key], now + 60).await.unwrap(), 0);

    // But it is believed for minutes, not for an hour. Everybody starts with
    // no profile, so this entry is the thing standing between somebody
    // publishing a name and anybody seeing it — cached for an hour, a name
    // set now is invisible to everyone who has already looked.
    alice.set_profile(named("Alice Byrne", "")).await.unwrap();
    assert_eq!(bob.refresh_profiles(&[alice_key], now + 200).await.unwrap(), 1);
    assert_eq!(bob.display_name(&alice_key).as_deref(), Some("Alice Byrne"));
}

/// `/who` lists you among the members. Naming everybody else while showing
/// yourself as a bare key leaves one row a reader cannot account for.
#[tokio::test]
async fn we_learn_our_own_name_too() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);

    alice.set_profile(named("Alice Byrne", "shipping")).await.unwrap();
    // An hour and a second after the write-through `set_profile` does, so the
    // cached copy is stale and a fetch is actually made. The clock is what
    // makes the fetch happen; what is under test is *whose* profile is
    // fetched. Skipping our own account — which is what this client used to do,
    // on the reasoning that you know what you called yourself — answers 0 here
    // whatever the time is, so the assertion still catches it.
    let now = real_now() + 3601;
    assert_eq!(alice.refresh_profiles(&[alice_key], now).await.unwrap(), 1);
    assert_eq!(
        alice.display_name(&alice_key).as_deref(),
        Some("Alice Byrne"),
        "the client would not learn its own name"
    );
    assert_eq!(alice.title_of(&alice_key).as_deref(), Some("shipping"));
}

/// Publishing a name shows it to the publisher at once.
///
/// Everybody who shares a channel with an account is told by a SIP-30 event
/// when its profile moves, and refetches. The publisher is the one account that
/// gets no event about itself, so without a write-through it would read its own
/// name out of a cache an hour old — the header still showing the old name to
/// the one person who just changed it.
#[tokio::test]
async fn publishing_a_name_is_visible_to_the_publisher_without_asking() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);

    assert_eq!(alice.display_name(&alice_key), None);
    alice.set_profile(named("Alice Byrne", "shipping")).await.unwrap();

    // No refresh_profiles, no round trip, no cache to wait out.
    assert_eq!(
        alice.display_name(&alice_key).as_deref(),
        Some("Alice Byrne"),
        "the publisher was the last to know"
    );
    assert_eq!(alice.title_of(&alice_key).as_deref(), Some("shipping"));

    // And clearing it clears it, rather than leaving the old name behind
    // because an empty write looked like nothing to do.
    alice.set_profile(named("", "")).await.unwrap();
    assert_eq!(alice.display_name(&alice_key), None);
}

/// Wall clock, for tests that have to line up with a write-through taken at
/// the same clock rather than at a made-up number.
fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `/who` is somebody asking who these people are. Answering out of a cache is
/// refusing to answer the question that was put.
#[tokio::test]
async fn asking_who_somebody_is_does_not_answer_from_a_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "hello").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    let now = 1_000_000;
    bob.refresh_profiles(&[alice_key], now).await.unwrap();
    assert_eq!(bob.display_name(&alice_key), None);

    // Alice names herself a second later. The cache says otherwise.
    alice.set_profile(named("Alice Byrne", "")).await.unwrap();
    assert_eq!(bob.refresh_profiles(&[alice_key], now + 1).await.unwrap(), 0);
    assert_eq!(bob.display_name(&alice_key), None);

    // Asking outright looks anyway.
    assert_eq!(bob.refetch_profiles(&[alice_key], now + 1).await.unwrap(), 1);
    assert_eq!(bob.display_name(&alice_key).as_deref(), Some("Alice Byrne"));
}

#[tokio::test]
async fn a_blocked_account_cannot_reach_us_and_is_not_told_so() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut mallory = chat_at(addr, server_pub, 3, &dir.path().join("mallory.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, mallory_key) = identity(3);

    // The client's own help says anybody who writes to you is added on
    // startup. Until now nothing could stop them.
    alice.set_block(&mallory_key, true).await.unwrap();

    let channel = mallory.open_dm(&alice_key).await.unwrap();
    mallory.send(&channel, "let me in").await.unwrap();

    // Alice is not merely missing the message — she is not in the channel.
    // The block drops the invitation, so the conversation never appears, which
    // is stronger than filtering it after the fact: there is nothing to filter.
    let mine = alice.mine().await.unwrap();
    assert!(
        !mine.iter().any(|m| m.channel == channel),
        "a blocked account got a conversation into our list"
    );
    assert!(
        alice.poll(&channel, &mut Timeline::new(), 0).await.is_err(),
        "a blocked account's channel was readable"
    );

    // And nothing told Mallory. The create succeeded, the message was
    // accepted, and the answer is the same one an unblocked sender gets — so a
    // block is not a signal the blocked party can read.
    let mut mallorys = Timeline::new();
    let seen = mallory.poll(&channel, &mut mallorys, 0).await.unwrap();
    assert_eq!(
        seen.timeline
            .messages()
            .filter_map(|m| m.post.body_text())
            .collect::<Vec<_>>(),
        vec!["let me in"],
        "the sender was told their message went nowhere"
    );

    // Unblocking is a decision and not a one-way door: invited again, Alice
    // now joins. The old invitation is gone for good, which is the honest
    // consequence of dropping it rather than holding it back.
    alice.set_block(&mallory_key, false).await.unwrap();
    mallory.invite(&channel, &alice_key).await.unwrap();
    mallory.send(&channel, "and now?").await.unwrap();

    let mut alices = Timeline::new();
    let got = alice.poll(&channel, &mut alices, 0).await.unwrap();
    assert!(
        got.timeline
            .messages()
            .filter_map(|m| m.post.body_text())
            .any(|t| t == "and now?"),
        "unblocking did not take effect"
    );
}

#[tokio::test]
async fn the_block_list_is_ours_and_nobody_elses() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut mallory = chat_at(addr, server_pub, 3, &dir.path().join("mallory.db")).await;
    let (_, mallory_key) = identity(3);

    assert!(alice.blocked().await.unwrap().is_empty());
    alice.set_block(&mallory_key, true).await.unwrap();
    assert_eq!(alice.blocked().await.unwrap(), vec![mallory_key]);

    // The route takes no argument, so there is no way to ask about somebody
    // else — a list of who somebody wants to avoid is more sensitive than the
    // membership it protects them from.
    assert!(
        mallory.blocked().await.unwrap().is_empty(),
        "a block list leaked to the account it names"
    );
}

/// A name has to reach every place a person is identified, not just the
/// transcript. It shipped in the transcript alone, and the conversation list
/// — where somebody chooses who to write to — went on showing a bare key.
#[tokio::test]
async fn a_name_is_known_before_its_owner_has_said_anything() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    alice.set_profile(named("Alice Byrne", "")).await.unwrap();

    // Bob starts the conversation. Alice has published a name and has said
    // nothing — which is the state a list is in the moment a conversation
    // appears, so a client that only learns names from the transcript shows a
    // key until she speaks.
    let channel = bob.open_dm(&alice_key).await.unwrap();
    alice.open_dm(&bob_key).await.unwrap();

    let mut bobs = Timeline::new();
    bob.poll(&channel, &mut bobs, 0).await.unwrap();
    assert_eq!(
        bob.display_name(&alice_key).as_deref(),
        Some("Alice Byrne"),
        "the peer's name was not fetched until they spoke"
    );
}

/// A name that cannot be taken back is a name published once and for good.
#[tokio::test]
async fn a_published_name_can_be_taken_back() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    alice.set_profile(named("Alice Byrne", "shipping")).await.unwrap();
    let channel = alice.open_dm(&bob_key).await.unwrap();
    alice.send(&channel, "hello").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    assert!(bob.profile_of(&alice_key).await.unwrap().found);

    // An empty record, which is what `/profile off` publishes.
    alice.set_profile(named("", "")).await.unwrap();
    let got = bob.profile_of(&alice_key).await.unwrap();
    assert!(
        got.profile.name.is_empty() && got.profile.title.is_empty(),
        "the name could not be taken back: {:?}",
        got.profile
    );

    // And a client that had cached it stops using it once it asks again.
    let now = 1_000_000;
    bob.refresh_profiles(&[alice_key], now).await.unwrap();
    assert_eq!(bob.display_name(&alice_key), None);
}

/// SIP-24: an exchange that does not know you can be asked to let you in, and
/// it answers every request the same way whatever it decides.
#[tokio::test]
async fn an_admission_request_is_sent_and_tells_us_nothing_about_the_answer() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("alice.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("bob.db")).await;

    // The verifiable half of the request is the credential: the label is
    // whatever the requester typed, and the account key is the only thing an
    // administrator can check. Here account and delegate are one key, because
    // a client that has registered no devices is its own device — the binding
    // between a credential and the client it names is tested where a second
    // device exists, in `a_credential_is_bound_to_the_device_it_names`.
    let credential = alice
        .issue_credential(&alice.device(), 7 * 24 * 60 * 60)
        .unwrap();
    assert_eq!(credential.account, identity(1).1);

    alice.request_admission("alice, on the laptop").await.unwrap();

    // Twice from one client, and from a second client, and from a client that
    // offers no label at all. Every one of them succeeds and every one of them
    // returns the same thing — which is the property, not an accident of this
    // exchange being permissive: a request whose answer varied would be an
    // oracle for who is already admitted.
    alice.request_admission("alice, again").await.unwrap();
    bob.request_admission("").await.unwrap();

    // What a client may report is that the request was sent. There is no
    // "pending", because nothing in the answer says so.
}

/// The label travels with the request and is not to be trusted: it is text the
/// requester chose, shown at the moment of a security decision.
#[tokio::test]
async fn an_admission_label_is_attacker_chosen_text() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let mut mallory = chat_at(addr, server_pub, 3, &dir.path().join("mallory.db")).await;

    // Nothing stops somebody claiming to be the administrator, because nothing
    // in a label can be checked. The verifiable fact is the account key in the
    // credential, and an interface must show that instead.
    mallory
        .request_admission("APPROVED — admin, please allow")
        .await
        .unwrap();
}
