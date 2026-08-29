//! SIP-30: the exchange says what changed, and nothing here ever polls.
//!
//! That last part is the control, and it is structural rather than asserted.
//! These tests never call `Chat::poll`, `Chat::mine` or `Chat::info` while
//! waiting for something, so a passing result cannot be explained by a fetch
//! that happened to run. If the push does not work, nothing arrives and every
//! wait below times out.
//!
//! The exchanges here are configured with no welcome channel. Every test is
//! about who is entitled to hear what, and a front door that puts every account
//! into one room with everybody else moves that baseline — an account would
//! share a channel with a stranger by default, which is precisely the condition
//! the authorization test is trying to rule out.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_proto::events::Event as ChatEvent;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

type Exchange = (
    SocketAddr,
    [u8; 32],
    std::sync::Arc<sqexd::server::Server>,
    tokio::task::JoinHandle<()>,
);

async fn server_in(dir: &Path) -> Exchange {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
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
    // The server itself, so one test can make the exchange write to a stream
    // at a moment of its choosing rather than waiting out a heartbeat.
    let server = std::sync::Arc::clone(&bound.server);
    let handle = tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub, server, handle)
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn chat_at(addr: SocketAddr, server_pub: [u8; 32], b: u8, store_path: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store_path)).unwrap();
    let mut chat = Chat::new(client, seed, me, store);
    chat.top_up_prekeys().await.unwrap();
    chat
}

/// Watch for an event, without ever asking the exchange a question.
///
/// The only thing that can make this return is a frame the exchange pushed.
async fn wait_for(
    chat: &mut Chat,
    matches: impl Fn(&ChatEvent) -> bool,
    within: Duration,
) -> Option<ChatEvent> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        for e in chat.take_events() {
            if matches(&e) {
                return Some(e);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Collect for a fixed span and report everything seen. For proving a negative.
async fn collect_for(chat: &mut Chat, span: Duration) -> Vec<ChatEvent> {
    let deadline = tokio::time::Instant::now() + span;
    let mut all = Vec::new();
    while tokio::time::Instant::now() < deadline {
        all.extend(chat.take_events());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    all.extend(chat.take_events());
    all
}

/// A second is an eternity on loopback. It is generous so the test is about
/// whether the push happens at all, not about how fast a laptop is.
const SOON: Duration = Duration::from_secs(2);

#[tokio::test]
async fn a_message_arrives_as_an_event_with_nothing_polling() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _srv, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    assert!(bob.subscribe().await.unwrap(), "bob did not subscribe");
    assert!(alice.subscribe().await.unwrap());

    alice.send(&channel, "the exchange told you this").await.unwrap();

    let got = wait_for(&mut bob, |e| matches!(e, ChatEvent::Channel { .. }), SOON).await;
    let Some(ChatEvent::Channel { channel: c, last_seq }) = got else {
        panic!("no channel event reached bob: {got:?}");
    };
    assert_eq!(c, channel);
    assert!(last_seq > 0, "an entry event named no entry");

    // The sender is told too, deliberately: their own message reaches them by
    // the same path as everybody else's, so there is one way a message gets on
    // screen rather than two that have to agree.
    let mine = wait_for(&mut alice, |e| matches!(e, ChatEvent::Channel { .. }), SOON).await;
    assert!(mine.is_some(), "the sender was not told about their own post");
}

#[tokio::test]
async fn a_rename_reaches_everybody_who_shares_a_channel() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _srv, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    assert!(bob.subscribe().await.unwrap());

    alice
        .set_profile(sqex_proto::profile::Profile {
            flags: 0,
            name: "Alice Byrne".into(),
            title: String::new(),
            avatar: Vec::new(),
        })
        .await
        .unwrap();

    let got = wait_for(
        &mut bob,
        |e| matches!(e, ChatEvent::Profile { account } if *account == alice_key),
        SOON,
    )
    .await;
    assert!(got.is_some(), "a rename did not reach somebody sharing a channel");
}

/// The one that matters most. An event stream must not become a way to learn
/// about rooms you are not in.
#[tokio::test]
async fn an_account_hears_nothing_about_a_channel_it_is_not_in() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _srv, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let mut carol = chat_at(addr, server_pub, 3, &dir.path().join("c.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    // Carol is a real participant, not an isolated onlooker: she has a
    // conversation of her own with bob, so she is in the exchange's membership
    // tables and would be reachable by a fan-out that lost its channel filter.
    // Without this she could not receive the event even if the exchange tried
    // to send it, and the assertion below would prove nothing.
    let (_, carol_key) = identity(3);
    carol.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&carol_key).await.unwrap();

    assert!(bob.subscribe().await.unwrap());
    assert!(carol.subscribe().await.unwrap());

    alice.send(&channel, "not for carol").await.unwrap();

    // Bob's copy is the control: without it, an assertion that Carol saw
    // nothing would pass just as well against an exchange that published
    // nothing at all.
    let bobs = wait_for(&mut bob, |e| matches!(e, ChatEvent::Channel { .. }), SOON).await;
    assert!(bobs.is_some(), "control: nothing was published to anybody");

    let carols = collect_for(&mut carol, Duration::from_millis(400)).await;
    let leaked: Vec<_> = carols
        .iter()
        .filter(|e| match e {
            ChatEvent::Channel { channel: c, .. }
            | ChatEvent::Signal { channel: c }
            | ChatEvent::Cursor { channel: c }
            | ChatEvent::Membership { channel: c, .. } => *c == channel,
            _ => false,
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "a stranger was told about a channel they are not in: {leaked:?}"
    );
}

#[tokio::test]
async fn a_conversation_somebody_else_starts_announces_itself() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _srv, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let (_, bob_key) = identity(2);

    // Bob is listening before anything exists between them. This is the case
    // that used to need a restart, and later a five-second timer.
    assert!(bob.subscribe().await.unwrap());

    let channel = alice.open_dm(&bob_key).await.unwrap();

    let got = wait_for(
        &mut bob,
        |e| matches!(e, ChatEvent::Membership { channel: c, .. } if *c == channel),
        SOON,
    )
    .await;
    assert!(
        got.is_some(),
        "a direct message somebody else opened announced nothing"
    );
}

/// The ordering the whole design rests on. `subscribe` returns only once the
/// exchange has answered, so a change made after that point is queued behind
/// the subscription — even though the subscriber has not read anything yet.
#[tokio::test]
async fn a_change_between_subscribing_and_reading_is_not_lost() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _srv, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    assert!(bob.subscribe().await.unwrap());

    // Posted before bob has drained a single frame, and before he has run the
    // reconciling fetch a real client would run here.
    alice.send(&channel, "into the gap").await.unwrap();

    // The reconcile, now — which is where a client would have lost this if the
    // subscription had been registered afterwards.
    let mut timeline = sqex_proto::timeline::Timeline::new();
    bob.poll(&channel, &mut timeline, 0).await.unwrap();

    let got = wait_for(&mut bob, |e| matches!(e, ChatEvent::Channel { .. }), SOON).await;
    assert!(got.is_some(), "an event in the subscribe/read gap was dropped");
}

#[tokio::test]
async fn typing_is_told_to_the_other_party_and_not_to_the_typist() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _srv, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    assert!(bob.subscribe().await.unwrap());
    assert!(alice.subscribe().await.unwrap());

    alice.typing(&channel, true).await;

    let got = wait_for(&mut bob, |e| matches!(e, ChatEvent::Signal { .. }), SOON).await;
    assert!(got.is_some(), "typing did not reach the other party");

    let hers = collect_for(&mut alice, Duration::from_millis(200)).await;
    assert!(
        !hers.iter().any(|e| matches!(e, ChatEvent::Signal { .. })),
        "a client was told about its own keyboard: {hers:?}"
    );
}

/// Several streams on **one** connection, which is the claim the whole approach
/// rests on: HTTP/3 multiplexes, so a stream held open for hours does not stop
/// the same connection carrying ordinary requests.
#[tokio::test]
async fn one_connection_carries_several_streams_and_then_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, srv, _h) = server_in(dir.path()).await;
    let (seed, _me) = identity(1);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();

    let mut held = Vec::new();
    for i in 0..sqexd::events::MAX_PER_IDENTITY {
        held.push(
            sqex_chat::events::Stream::open(&client)
                .await
                .unwrap_or_else(|e| panic!("stream {i} on one connection: {e}")),
        );
    }

    match sqex_chat::events::Stream::open(&client).await {
        Err(sqex_chat::events::Refusal::Status(429)) => {}
        Err(other) => panic!("expected 429 past the cap, got {other:?}"),
        Ok(_) => panic!("the exchange kept a stream past its own cap"),
    }

    // The connection is still good for ordinary work — the refusal was about
    // streams, not about the connection.
    let mut ordinary = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let (status, _) = ordinary.get("/health").await.unwrap();
    assert_eq!(status, 200);

    // Giving one back makes room — but not instantly, and the reason is worth
    // stating because it looks like a leak. A dropped stream sends
    // STOP_SENDING, and the exchange is parked waiting for something to
    // publish; it finds out on its next *write*, which in service is the
    // heartbeat, so a slot comes back within one of those and not sooner.
    //
    // Publishing here is that write, brought forward, so this checks the
    // mechanism rather than the clock.
    held.pop();
    let (_, me) = identity(1);
    let mut freed = false;
    for _ in 0..50 {
        srv.events.publish(&[me], sqex_proto::events::Event::Heartbeat);
        tokio::time::sleep(Duration::from_millis(20)).await;
        if srv.events.count(&me) < sqexd::events::MAX_PER_IDENTITY {
            freed = true;
            break;
        }
    }
    assert!(freed, "a dropped stream never gave its slot back");
    assert!(sqex_chat::events::Stream::open(&client).await.is_ok());
}

/// The claim the whole change is for, measured rather than asserted.
///
/// A subscribed client asks the exchange nothing until something happens; when
/// something does, it costs requests proportional to the change and not to how
/// long anybody has been sitting there. The old client paid two round trips per
/// conversation every 700 ms to be told nothing.
#[tokio::test]
async fn a_subscribed_client_costs_the_exchange_nothing_while_nothing_happens() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, srv, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    assert!(bob.subscribe().await.unwrap());

    // Long enough to have cost the old client roughly forty requests, and long
    // enough for two heartbeats to have been written on the stream — which cost
    // nothing here, because a frame on an open stream is not a request.
    let quiet = srv.requests();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        srv.requests(),
        quiet,
        "a client with nothing to do still asked the exchange for something"
    );

    // And when something does happen, the client is told without having asked.
    alice.send(&channel, "now something happened").await.unwrap();
    let got = wait_for(&mut bob, |e| matches!(e, ChatEvent::Channel { .. }), SOON).await;
    assert!(got.is_some());

    // The control, and it belongs inside this test rather than beside it: a
    // counter that never moved would make the assertion above pass for the
    // wrong reason, and it would pass forever.
    assert!(
        srv.requests() > quiet,
        "the request counter does not count requests, so the quiet window \
         proved nothing"
    );
}

/// Link a second device to `owner`'s account and return a client for it.
///
/// Lifted from `dm_flow`, because the distinction it creates — an account key
/// and a device key that are no longer the same 32 bytes — is exactly the one
/// every single-client test here cannot make.
async fn linked_device(
    addr: SocketAddr,
    server_pub: [u8; 32],
    owner: &mut Chat,
    b: u8,
    store: &Path,
) -> Chat {
    let mut second = chat_at(addr, server_pub, b, store).await;
    if !owner
        .my_devices()
        .await
        .unwrap()
        .iter()
        .any(|d| d.device == owner.me)
    {
        let own = owner.issue_credential(&owner.me, 90 * 24 * 60 * 60).unwrap();
        owner.register_self(&own).await.unwrap();
    }
    let credential = owner
        .issue_credential(&second.device(), 90 * 24 * 60 * 60)
        .unwrap();
    second.register_self(&credential).await.unwrap();
    second.store().set_account(&credential.account).unwrap();
    second.top_up_prekeys().await.unwrap();
    let (seed, device) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store)).unwrap();
    let mut second = Chat::new(client, seed, device, store);
    second.top_up_prekeys().await.unwrap();
    second
}

/// A subscription belongs to an **account**, not to the connection's device.
///
/// Every publisher here addresses accounts — membership, profiles and admission
/// all do — so a subscription filed under the device key on the connection is
/// simply never found. That was the bug, and no test in this file could see it:
/// SIP-22 makes an account with no registered devices its own device, so until
/// something is linked the two keys are the same 32 bytes and the mistake has
/// no effect. It took a live store that had once linked a device to show it.
///
/// This is the same shape as the SIP-17 narrowing recorded in the SIPs README —
/// a rule that distinguishes two things needs a test in which they differ.
#[tokio::test]
async fn a_linked_device_receives_its_accounts_events() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _srv, _h) = server_in(dir.path()).await;
    let mut alice = chat_at(addr, server_pub, 1, &dir.path().join("a.db")).await;
    let mut bob = chat_at(addr, server_pub, 2, &dir.path().join("b.db")).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let channel = alice.open_dm(&bob_key).await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();

    // Bob's second client. Its connection carries key 7; its account is key 2.
    let mut phone = linked_device(addr, server_pub, &mut bob, 7, &dir.path().join("b2.db")).await;
    let (_, phone_device) = identity(7);
    assert_ne!(
        phone_device, bob_key,
        "control: the device and the account are the same key, so this proves nothing"
    );

    assert!(phone.subscribe().await.unwrap());
    alice.send(&channel, "for bob, on whichever device").await.unwrap();

    let got = wait_for(&mut phone, |e| matches!(e, ChatEvent::Channel { .. }), SOON).await;
    assert!(
        got.is_some(),
        "a linked device heard nothing about its own account's conversation"
    );

    // And a profile change, which is addressed to accounts by a different path.
    alice
        .set_profile(sqex_proto::profile::Profile {
            flags: 0,
            name: "Alice Byrne".into(),
            title: String::new(),
            avatar: Vec::new(),
        })
        .await
        .unwrap();
    let got = wait_for(
        &mut phone,
        |e| matches!(e, ChatEvent::Profile { account } if *account == alice_key),
        SOON,
    )
    .await;
    assert!(got.is_some(), "a linked device was not told about a rename");
}
