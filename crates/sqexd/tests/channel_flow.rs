//! End-to-end for SIP-16 channels over real HTTP/3.
//!
//! The slice these cover is public channels carrying text: no devices, no
//! envelopes, no blobs. That is deliberate — a public entry is unsealed, so
//! this exercises the parts every other chat SIP rests on (ordering,
//! membership, persistence, pruning, the long poll) without waiting on the
//! parts most likely to change.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByChannel, ByTarget, ChannelInfo, Create, Cursor, EVENT_JOINED, Entries, Fetch,
    KIND_MEMBER, KIND_SYSTEM, List, Listing, MIN_RETENTION, Mark, Marks, Post, Posted, Role,
    SignalOut, System, TYPE_CLOSE, TYPE_CURSORS, TYPE_INFO, TYPE_JOIN, TYPE_LEAVE, TYPE_REDACT,
    Visibility,
};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
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

async fn as_identity(addr: SocketAddr, server_pub: [u8; 32], seed: [u8; 32]) -> Client {
    Client::connect_as(addr, &server_pub, &seed).await.unwrap()
}

fn public(channel: [u8; 32], name: &str) -> Create {
    Create {
        channel,
        visibility: Visibility::Public,
        retention_secs: 3600,
        max_entries: 0,
        name: name.into(),
        topic: String::new(),
        invites: vec![],
    }
}

async fn create(client: &mut Client, req: &Create) -> u16 {
    let (code, _) = client.post("/channel/create", req.encode()).await.unwrap();
    code
}

async fn join(client: &mut Client, channel: [u8; 32]) -> u16 {
    let (code, _) = client
        .post("/channel/join", ByChannel { channel }.encode(TYPE_JOIN))
        .await
        .unwrap();
    code
}

async fn post(client: &mut Client, channel: [u8; 32], text: &[u8]) -> (u16, Vec<u8>) {
    client
        .post(
            "/channel/post",
            Post {
                channel,
                epoch: 0,
                msg_seq: 0,
                expires_after: 0,
                body: text.to_vec(),
            }
            .encode(),
        )
        .await
        .unwrap()
}

async fn fetch(client: &mut Client, channel: [u8; 32], since: u64, wait: u16) -> (u16, Vec<u8>) {
    client
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since,
                wait_secs: wait,
            }
            .encode(),
        )
        .await
        .unwrap()
}

async fn info(client: &mut Client, channel: [u8; 32]) -> (u16, Vec<u8>) {
    client
        .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
        .await
        .unwrap()
}

/// The entries a member posted, which is what a client shows as messages.
/// The exchange's own entries share the sequence space and are folded into the
/// timeline separately.
fn messages(e: &Entries) -> Vec<&sqex_proto::channel::Entry> {
    e.entries.iter().filter(|x| x.kind == KIND_MEMBER).collect()
}

fn bodies(e: &Entries) -> Vec<Vec<u8>> {
    messages(e).iter().map(|x| x.body.clone()).collect()
}

/// The exchange's own entries: who did what to whom.
fn events(e: &Entries) -> Vec<System> {
    e.entries
        .iter()
        .filter(|x| x.kind == KIND_SYSTEM)
        .filter_map(|x| System::decode(&x.body).ok().flatten())
        .collect()
}

#[tokio::test]
async fn two_members_hold_a_conversation_in_one_order() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(21);
    let (bob_seed, _bob) = identity(22);
    let channel = [1u8; 32];

    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create(&mut a, &public(channel, "planning")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    for text in [&b"one"[..], b"two", b"three"] {
        assert_eq!(post(&mut a, channel, text).await.0, 200);
    }
    assert_eq!(post(&mut b, channel, b"four").await.0, 200);

    // The order is the exchange's, and it is the same order for everybody.
    let (code, body) = fetch(&mut b, channel, 0, 0).await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let seen = Entries::decode(&body).unwrap();
    assert_eq!(
        bodies(&seen),
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec(), b"four".to_vec()]
    );
    // Bob's join is entry 1, so the messages start at 2 — the exchange's own
    // entries share the sequence space, which is what makes interleaving free.
    assert_eq!(
        messages(&seen).iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![2, 3, 4, 5]
    );
    assert_eq!(events(&seen).len(), 1);
    assert_eq!(events(&seen)[0].event, EVENT_JOINED);

    let (_, body) = fetch(&mut a, channel, 0, 0).await;
    assert_eq!(bodies(&Entries::decode(&body).unwrap()), bodies(&seen));

    // The creator is an admin and the joiner is not.
    let (_, body) = info(&mut a, channel).await;
    let seen = ChannelInfo::decode(&body).unwrap();
    assert_eq!(seen.members.len(), 2);
    let mine = seen.members.iter().find(|m| m.account == alice).unwrap();
    assert_eq!(mine.role, Role::Admin);
}

#[tokio::test]
async fn a_stranger_cannot_read_a_channel_it_has_not_joined() {
    // The load-bearing row of SIP-16's authorization table. A channel
    // identifier is not a way in.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(31);
    let (mallory_seed, _) = identity(32);
    let channel = [2u8; 32];

    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut m = as_identity(addr, pubkey, mallory_seed).await;

    assert_eq!(create(&mut a, &public(channel, "members only")).await, 200);
    assert_eq!(post(&mut a, channel, b"secret enough").await.0, 200);

    assert_eq!(fetch(&mut m, channel, 0, 0).await.0, 403);
    assert_eq!(post(&mut m, channel, b"hello").await.0, 403);
    assert_eq!(info(&mut m, channel).await.0, 403);

    // Joining is what changes it, and a public channel lets anyone.
    assert_eq!(join(&mut m, channel).await, 200);
    let (code, body) = fetch(&mut m, channel, 0, 0).await;
    assert_eq!(code, 200);
    assert_eq!(bodies(&Entries::decode(&body).unwrap()), vec![b"secret enough".to_vec()]);
}

#[tokio::test]
async fn a_parked_fetch_is_answered_by_a_post() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(41);
    let (bob_seed, _) = identity(42);
    let channel = [3u8; 32];

    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;
    assert_eq!(create(&mut a, &public(channel, "waiting")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    // Bob's join is itself an entry, so catch up first: a fetch only parks
    // when there is genuinely nothing waiting.
    let (_, body) = fetch(&mut b, channel, 0, 0).await;
    let caught_up = Entries::decode(&body).unwrap().last;

    let waiter = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let (code, body) = fetch(&mut b, channel, caught_up, 20).await;
        (code, body, started.elapsed())
    });

    // Long enough that the fetch is certainly parked rather than answered by
    // the first read.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(post(&mut a, channel, b"woken").await.0, 200);

    let (code, body, elapsed) = waiter.await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(bodies(&Entries::decode(&body).unwrap()), vec![b"woken".to_vec()]);
    // Answered by the post, not by the timeout.
    assert!(elapsed < std::time::Duration::from_secs(5), "waited {elapsed:?}");
}

#[tokio::test]
async fn a_fetch_with_nothing_to_say_returns_empty_rather_than_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(51);
    let channel = [4u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    assert_eq!(create(&mut a, &public(channel, "quiet")).await, 200);

    let started = std::time::Instant::now();
    let (code, body) = fetch(&mut a, channel, 0, 1).await;
    assert_eq!(code, 200);
    assert!(Entries::decode(&body).unwrap().entries.is_empty());
    assert!(started.elapsed() >= std::time::Duration::from_millis(900));
}

#[tokio::test]
async fn the_log_survives_a_restart() {
    // The claim that separates this service from every other one in the
    // daemon. If it fails, the service is not the service.
    let dir = tempfile::tempdir().unwrap();
    let (alice_seed, _) = identity(61);
    let channel = [5u8; 32];

    let (addr, pubkey, first) = server_in(dir.path()).await;
    {
        let mut a = as_identity(addr, pubkey, alice_seed).await;
        assert_eq!(create(&mut a, &public(channel, "durable")).await, 200);
        assert_eq!(post(&mut a, channel, b"before the restart").await.0, 200);
    }
    first.abort();
    let _ = first.await;

    let (addr, pubkey, _second) = server_in(dir.path()).await;
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let (code, body) = fetch(&mut a, channel, 0, 0).await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let seen = Entries::decode(&body).unwrap();
    assert_eq!(bodies(&seen), vec![b"before the restart".to_vec()]);

    // And the sequence continues rather than starting again, because next_seq
    // is stored rather than derived from what survives.
    let (_, body) = post(&mut a, channel, b"after").await;
    assert_eq!(Posted::decode(&body).unwrap().seq, 2);
}

#[tokio::test]
async fn retention_by_count_drops_the_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(71);
    let channel = [6u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    let mut req = public(channel, "short memory");
    req.max_entries = 3;
    assert_eq!(create(&mut a, &req).await, 200);

    for i in 0..6u8 {
        assert_eq!(post(&mut a, channel, &[b'a' + i]).await.0, 200);
    }
    let (_, body) = fetch(&mut a, channel, 0, 0).await;
    let seen = Entries::decode(&body).unwrap();
    assert_eq!(bodies(&seen), vec![vec![b'd'], vec![b'e'], vec![b'f']]);

    // A client that was away longer than the window must be able to tell it
    // has a gap, which is what `first` is for.
    assert_eq!(seen.first, 4);
    assert_eq!(seen.last, 6);
}

#[tokio::test]
async fn a_public_channel_outlives_its_membership_and_a_private_one_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(81);
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    let open = [7u8; 32];
    let shut = [8u8; 32];
    assert_eq!(create(&mut a, &public(open, "a place")).await, 200);
    let mut priv_req = public(shut, "");
    priv_req.channel = shut;
    priv_req.visibility = Visibility::Private;
    assert_eq!(create(&mut a, &priv_req).await, 200);

    let leave = |c: [u8; 32]| ByChannel { channel: c }.encode(TYPE_LEAVE);
    assert_eq!(a.post("/channel/leave", leave(open)).await.unwrap().0, 200);
    assert_eq!(a.post("/channel/leave", leave(shut)).await.unwrap().0, 200);

    // The public room is still there and its admin, who is no longer a member,
    // can still see it and close it.
    let (code, body) = info(&mut a, open).await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    assert!(ChannelInfo::decode(&body).unwrap().members.is_empty());

    // The private one went with its last member.
    assert_eq!(info(&mut a, shut).await.0, 404);

    let (code, _) = a
        .post("/channel/close", ByChannel { channel: open }.encode(TYPE_CLOSE))
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(info(&mut a, open).await.0, 404);
}

#[tokio::test]
async fn the_directory_lists_public_channels_only() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(91);
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    assert_eq!(create(&mut a, &public([10u8; 32], "rust talk")).await, 200);
    assert_eq!(create(&mut a, &public([11u8; 32], "garden talk")).await, 200);
    let mut hidden = public([12u8; 32], "should not appear");
    hidden.visibility = Visibility::Private;
    assert_eq!(create(&mut a, &hidden).await, 200);

    let (code, body) = a
        .post(
            "/channel/list",
            List {
                offset: 0,
                query: String::new(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let listing = Listing::decode(&body).unwrap();
    assert_eq!(listing.total, 2);
    let names: Vec<&str> = listing.channels.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"rust talk") && names.contains(&"garden talk"));
    assert!(!names.contains(&"should not appear"));

    // A private channel's name is not stored at the exchange at all, so it
    // cannot leak through a query that happens to match it.
    let (_, body) = a
        .post(
            "/channel/list",
            List {
                offset: 0,
                query: "should".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(Listing::decode(&body).unwrap().total, 0);
}

#[tokio::test]
async fn retention_outside_the_permitted_range_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(101);
    let mut a = as_identity(addr, pubkey, alice_seed).await;

    let mut too_short = public([13u8; 32], "blink");
    too_short.retention_secs = MIN_RETENTION - 1;
    assert_eq!(create(&mut a, &too_short).await, 409);
}

#[tokio::test]
async fn an_anonymous_connection_has_no_membership() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(111);
    let channel = [14u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    assert_eq!(create(&mut a, &public(channel, "named callers only")).await, 200);

    // Client::connect does not advertise an identity (SIP-3 is opt-in), and
    // every channel route refuses a connection carrying none.
    let mut anon = Client::connect(addr, &pubkey).await.unwrap();
    assert_eq!(fetch(&mut anon, channel, 0, 0).await.0, 403);
    assert_eq!(join(&mut anon, channel).await, 403);
}

async fn cursor(client: &mut Client, channel: [u8; 32], read: u64, receipts: bool) -> u16 {
    let (code, _) = client
        .post(
            "/channel/cursor",
            Cursor {
                channel,
                read,
                receipts,
            }
            .encode(),
        )
        .await
        .unwrap();
    code
}

async fn marks(client: &mut Client, channel: [u8; 32]) -> Marks {
    let (code, body) = client
        .post("/channel/cursors", ByChannel { channel }.encode(TYPE_CURSORS))
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    Marks::decode(&body).unwrap()
}

fn mark_of(m: &Marks, who: &PubKey) -> Mark {
    *m.marks.iter().find(|x| &x.account == who).unwrap()
}

#[tokio::test]
async fn delivery_is_observed_and_reading_is_asserted() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(121);
    let (bob_seed, bob) = identity(122);
    let channel = [20u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create(&mut a, &public(channel, "receipts")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);
    for t in [&b"one"[..], b"two", b"three"] {
        assert_eq!(post(&mut a, channel, t).await.0, 200);
    }

    // Bob collects everything. He never says so — asking for what comes after 0
    // and being handed three entries is the exchange watching him do it.
    let (_, body) = fetch(&mut b, channel, 0, 0).await;
    let seen = Entries::decode(&body).unwrap();
    assert_eq!(messages(&seen).len(), 3);
    // Four entries in all: Bob's join, then three messages.
    assert_eq!(seen.entries.len(), 4);
    let last = seen.last;

    let m = marks(&mut b, channel).await;
    assert_eq!(mark_of(&m, &bob).delivered, last);
    assert_eq!(mark_of(&m, &bob).read, 0, "collected is not read");

    assert_eq!(cursor(&mut b, channel, 2, true).await, 200);
    let m = marks(&mut a, channel).await;
    assert_eq!(mark_of(&m, &bob).read, 2);
    let delivered = mark_of(&m, &bob).delivered;

    // A mark cannot run ahead of what was delivered: a client may not claim to
    // have read further than it collected.
    assert_eq!(cursor(&mut b, channel, 99, true).await, 200);
    assert_eq!(mark_of(&marks(&mut a, channel).await, &bob).read, delivered);

    // Nor backwards.
    assert_eq!(cursor(&mut b, channel, 1, true).await, 200);
    assert_eq!(mark_of(&marks(&mut a, channel).await, &bob).read, delivered);
    assert_eq!(mark_of(&marks(&mut a, channel).await, &alice).delivered, 0);
}

#[tokio::test]
async fn opting_out_of_receipts_withholds_others_reading_but_not_their_delivery() {
    // The reciprocity is enforced at the exchange rather than left to a client
    // that might simply not honour it — which is what stops somebody taking
    // the signal without giving it.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(131);
    let (bob_seed, _bob) = identity(132);
    let channel = [21u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create(&mut a, &public(channel, "quiet reader")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);
    assert_eq!(post(&mut a, channel, b"hello").await.0, 200);

    let (_, body) = fetch(&mut a, channel, 0, 0).await;
    let last = Entries::decode(&body).unwrap().last;
    assert_eq!(cursor(&mut a, channel, last, true).await, 200);

    // Bob reads, and opts out.
    fetch(&mut b, channel, 0, 0).await;
    assert_eq!(cursor(&mut b, channel, last, false).await, 200);

    let seen = marks(&mut b, channel).await;
    assert_eq!(mark_of(&seen, &alice).read, 0, "he gave nothing, he sees nothing");
    assert!(mark_of(&seen, &alice).delivered > 0, "delivery is never withheld");

    // Alice still gave hers, so she still sees his.
    assert!(mark_of(&marks(&mut a, channel).await, &alice).read > 0);
}

#[tokio::test]
async fn a_redaction_leaves_a_tombstone_and_a_stranger_cannot_make_one() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(141);
    let (bob_seed, _) = identity(142);
    let channel = [22u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create(&mut a, &public(channel, "regrets")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);
    let (_, body) = post(&mut b, channel, b"said too much").await;
    let bobs = Posted::decode(&body).unwrap().seq;

    let redact = |c: [u8; 32], t: u64| ByTarget { channel: c, target: t }.encode(TYPE_REDACT);

    // Neither a stranger to the entry nor a plain member may redact it.
    let (mallory_seed, _) = identity(143);
    let mut m = as_identity(addr, pubkey, mallory_seed).await;
    assert_eq!(join(&mut m, channel).await, 200);
    let (code, _) = m.post("/channel/redact", redact(channel, bobs)).await.unwrap();
    assert_eq!(code, 403);

    // Nor may an admin reach the exchange's own record of who did what: an
    // audit trail its subject can erase is not one.
    let (code, _) = a.post("/channel/redact", redact(channel, 1)).await.unwrap();
    assert_eq!(code, 409, "a system entry is never redactable");

    // Its author may.
    let (code, _) = b.post("/channel/redact", redact(channel, bobs)).await.unwrap();
    assert_eq!(code, 200);

    // The entry survives as a gap, which is the record.
    let (_, body) = fetch(&mut a, channel, 0, 0).await;
    let seen = Entries::decode(&body).unwrap();
    let mine: Vec<_> = messages(&seen).into_iter().filter(|e| e.seq == bobs).collect();
    assert_eq!(mine.len(), 1, "the entry is still there");
    assert!(mine[0].body.is_empty(), "and its body is not");

    // An admin may redact somebody else's, which is the moderation path.
    let (_, body) = post(&mut b, channel, b"again").await;
    let again = Posted::decode(&body).unwrap().seq;
    let (code, _) = a.post("/channel/redact", redact(channel, again)).await.unwrap();
    assert_eq!(code, 200);

    let (code, _) = a.post("/channel/redact", redact(channel, 99)).await.unwrap();
    assert_eq!(code, 404, "nothing to redact");
}

#[tokio::test]
async fn a_signal_reaches_the_others_once_and_is_never_stored() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = identity(151);
    let (bob_seed, _) = identity(152);
    let channel = [23u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;

    assert_eq!(create(&mut a, &public(channel, "typing")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    let (code, _) = a
        .post(
            "/channel/signal",
            SignalOut {
                channel,
                kind: 0x01,
                body: vec![1],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let (_, body) = fetch(&mut b, channel, 0, 0).await;
    let seen = Entries::decode(&body).unwrap();
    assert_eq!(seen.signals.len(), 1);
    assert_eq!(seen.signals[0].account, alice);
    assert_eq!(seen.signals[0].kind, 0x01);
    assert!(messages(&seen).is_empty(), "a signal is not an entry");

    // Delivered at most once, and it left nothing behind.
    let (_, body) = fetch(&mut b, channel, 0, 0).await;
    assert!(Entries::decode(&body).unwrap().signals.is_empty());

    // The sender does not receive their own.
    let (_, body) = fetch(&mut a, channel, 0, 0).await;
    assert!(Entries::decode(&body).unwrap().signals.is_empty());
}

#[tokio::test]
async fn a_parked_fetch_is_answered_by_a_signal_too() {
    // SIP-16: a held request returns as soon as an entry is accepted *or* a
    // signal arrives for the caller.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(161);
    let (bob_seed, _) = identity(162);
    let channel = [24u8; 32];
    let mut a = as_identity(addr, pubkey, alice_seed).await;
    let mut b = as_identity(addr, pubkey, bob_seed).await;
    assert_eq!(create(&mut a, &public(channel, "waiting")).await, 200);
    assert_eq!(join(&mut b, channel).await, 200);

    let (_, body) = fetch(&mut b, channel, 0, 0).await;
    let caught_up = Entries::decode(&body).unwrap().last;

    let waiter = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let (code, body) = fetch(&mut b, channel, caught_up, 20).await;
        (code, body, started.elapsed())
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    a.post(
        "/channel/signal",
        SignalOut {
            channel,
            kind: 0x01,
            body: vec![1],
        }
        .encode(),
    )
    .await
    .unwrap();

    let (code, body, elapsed) = waiter.await.unwrap();
    assert_eq!(code, 200);
    assert_eq!(Entries::decode(&body).unwrap().signals.len(), 1);
    assert!(elapsed < std::time::Duration::from_secs(5), "waited {elapsed:?}");
}
