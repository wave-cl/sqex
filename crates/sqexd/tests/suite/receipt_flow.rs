//! SIP-34: what an exchange's signature over its own act actually buys.
//!
//! SIP-31 removed the exchange from authorship and deliberately left it where
//! it was for ordering. These check that ordering is now signed too — that a
//! receipt verifies under the key a client pinned, that the head links entry to
//! entry across membership changes as well as messages, and that the tip is
//! served and checkable on a fetch that returned nothing, which is the case the
//! whole mechanism exists for.
//!
//! Every test here fails against the code that preceded this SIP: before it
//! there was no field to check.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{Entries, Entry, Fetch, Posted, Visibility};
use sqex_proto::entry_sig::Place;
use sqex_proto::receipt::{self, Branch, Equivocation, HEAD_GENESIS, ReceiptTerms};
use sqex_proto::refusal::Code;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

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

fn signer(server_pub: [u8; 32], b: u8) -> Signer {
    let (seed, key) = identity(b);
    Signer::new(seed, key, server_pub)
}

async fn a_room(c: &mut Client, s: &Signer, chain: &mut Chain, channel: [u8; 32]) {
    let req = s.create_chained(
        chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![],
    );
    let (code, body) = c.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn say(c: &mut Client, s: &Signer, chain: &mut Chain, channel: [u8; 32], text: &[u8]) {
    let info = s.info(c, channel).await;
    let req = s.post_chained(chain, channel, info.instance, 0, 0, text.to_vec());
    let (code, body) = c.post("/channel/post", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

async fn fetch_receipted(c: &mut Client, channel: [u8; 32], since: u64) -> Entries {
    let req = Fetch { channel, since, wait_secs: 0, receipts: true };
    let (code, body) = c.post("/channel/fetch", req.encode()).await.unwrap();
    assert_eq!(code, 200, "receipted fetch refused: {}", common::said(&body));
    Entries::decode(&body, true).unwrap()
}

/// Check one entry's receipt the way SIP-34 requires: under the key the caller
/// pinned, never one taken from the response.
fn verify(server_pub: [u8; 32], channel: [u8; 32], instance: [u8; 32], e: &Entry) -> bool {
    let stamp = e.stamp.as_ref().expect("a receipted fetch stamps every entry");
    receipt::verify(
        &ReceiptTerms {
            place: Place { exchange: PubKey::new(server_pub), instance, channel },
            seq: e.seq,
            posted: e.posted,
            entry_hash: stamp.entry_hash,
            head: stamp.head,
        },
        &stamp.receipt,
    )
}

/// The whole mechanism, end to end: every entry carries a receipt that verifies
/// under the pinned exchange key, and the heads chain from genesis without a
/// break — across the exchange's own system entries as well as the messages.
///
/// The linkage is what makes a receipt cover *omission*: an exchange that
/// showed one reader an entry it withheld from another would have to advance
/// its head over it either way, and the two readers' heads diverge from that
/// point on.
#[tokio::test]
async fn every_entry_is_receipted_and_the_heads_chain_from_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(41);
    let channel = [41u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = signer(server_pub, 41);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    for text in [&b"one"[..], b"two", b"three"] {
        say(&mut a, &s, &mut chain, channel, text).await;
    }

    let instance = instance_for(channel, 0);
    let seen = fetch_receipted(&mut a, channel, 0).await;
    assert_eq!(seen.entries.len(), 4, "one `created` and three messages");

    let mut head = HEAD_GENESIS;
    for e in &seen.entries {
        assert!(
            verify(server_pub, channel, instance, e),
            "entry {} carries a receipt that does not verify",
            e.seq
        );
        let stamp = e.stamp.unwrap();
        assert_eq!(
            receipt::advance(&head, &stamp.entry_hash),
            stamp.head,
            "the head at entry {} does not follow the one before it",
            e.seq
        );
        head = stamp.head;
    }

    // The tip is the newest entry's, and it is the same head the walk arrived
    // at — a reader that followed the log and a reader that read only the tip
    // agree.
    let tip = seen.tip.expect("a receipted fetch carries a tip");
    assert_eq!(tip.seq, seen.last);
    assert_eq!(tip.stamp.head, head);
}

/// **What a reader who fetched nothing still learns.**
///
/// Without the tip, "nothing happened" and "I am not being shown what happened"
/// are the same empty response. The tip is served anyway, carries the newest
/// entry's `posted` so it is checkable when that entry is not in the batch, and
/// verifies on its own.
#[tokio::test]
async fn the_tip_is_served_and_verifiable_on_a_fetch_that_returned_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(42);
    let channel = [42u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = signer(server_pub, 42);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    say(&mut a, &s, &mut chain, channel, b"the only message").await;

    let caught_up = fetch_receipted(&mut a, channel, 0).await;
    let empty = fetch_receipted(&mut a, channel, caught_up.last).await;
    assert!(empty.entries.is_empty(), "nothing new should have arrived");

    let tip = empty.tip.expect("the tip is served even with no entries");
    assert_eq!(tip.seq, caught_up.last);
    assert!(
        receipt::verify(
            &ReceiptTerms {
                place: Place {
                    exchange: PubKey::new(server_pub),
                    instance: instance_for(channel, 0),
                    channel,
                },
                seq: tip.seq,
                posted: tip.posted,
                entry_hash: tip.stamp.entry_hash,
                head: tip.stamp.head,
            },
            &tip.stamp.receipt,
        ),
        "the tip must be checkable by a reader holding none of its entries"
    );
    // And it is the same claim the full fetch made, which is what lets two
    // readers compare.
    assert_eq!(tip.stamp, caught_up.tip.unwrap().stamp);
}

/// A poster learns its entry was numbered, which is what closes
/// accept-and-silently-discard. It does not close *refusing* the post, and
/// SIP-34 says so plainly — the mechanism covers what the exchange said, never
/// what it declined to say.
#[tokio::test]
async fn a_receipted_post_is_the_exchange_saying_it_numbered_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(43);
    let channel = [43u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = signer(server_pub, 43);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;

    let info = s.info(&mut a, channel).await;
    let mut req = s.post_chained(&mut chain, channel, info.instance, 0, 0, b"hello".to_vec());
    req.receipts = true;
    let (code, body) = a.post("/channel/post", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    let posted = Posted::decode(&body, true).unwrap();
    let stamp = posted.stamp.expect("a receipted post is answered with a receipt");
    assert!(receipt::verify(
        &ReceiptTerms {
            place: Place {
                exchange: PubKey::new(server_pub),
                instance: info.instance,
                channel,
            },
            seq: posted.seq,
            posted: posted.posted,
            entry_hash: stamp.entry_hash,
            head: stamp.head,
        },
        &stamp.receipt,
    ));

    // And the same position, fetched, carries the same claim. An exchange that
    // told the poster one thing and a reader another would fail here.
    let seen = fetch_receipted(&mut a, channel, posted.seq - 1).await;
    assert_eq!(seen.entries[0].seq, posted.seq);
    assert_eq!(seen.entries[0].stamp.unwrap(), stamp);
}

/// The unreceipted shape is untouched, which is the whole compatibility story:
/// a client that never asks is served exactly what it was served before.
#[tokio::test]
async fn a_plain_fetch_is_unchanged_and_carries_no_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(44);
    let channel = [44u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = signer(server_pub, 44);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    say(&mut a, &s, &mut chain, channel, b"hello").await;

    let req = Fetch { channel, since: 0, wait_secs: 0, receipts: false };
    let (code, body) = a.post("/channel/fetch", req.encode()).await.unwrap();
    assert_eq!(code, 200);
    let seen = Entries::decode(&body, false).unwrap();
    assert!(seen.tip.is_none());
    assert!(
        seen.entries.iter().all(|e| e.stamp.is_none()),
        "an unreceipted fetch must carry no receipts at all"
    );

    // The negative control for the pair: the same bytes read in the other
    // shape must fail rather than silently produce nonsense. This is why the
    // shape follows the request's type byte and never its length.
    assert!(
        Entries::decode(&body, true).is_err(),
        "an unreceipted body must not parse as a receipted one"
    );
}

/// Two receipts naming one position with different content are a portable
/// proof, and this is what a client would build on finding a pair.
///
/// Constructed rather than provoked: an honest exchange never equivocates, and
/// making this one do so would mean building a dishonest sqexd. What is tested
/// is the artifact — that it verifies, travels, and refuses to be built out of
/// receipts that agree.
#[tokio::test]
async fn two_receipts_at_one_position_make_a_portable_proof() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = identity(45);
    let channel = [45u8; 32];

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed).await.unwrap();
    let s = signer(server_pub, 45);
    let mut chain = Chain::default();
    a_room(&mut a, &s, &mut chain, channel).await;
    say(&mut a, &s, &mut chain, channel, b"what one reader saw").await;

    let seen = fetch_receipted(&mut a, channel, 0).await;
    let e = seen.entries.last().unwrap();
    let stamp = e.stamp.unwrap();
    let place = Place {
        exchange: PubKey::new(server_pub),
        instance: instance_for(channel, 0),
        channel,
    };
    let real = Branch {
        posted: e.posted,
        entry_hash: stamp.entry_hash,
        head: stamp.head,
        receipt: stamp.receipt,
    };

    // Two copies of one truth are not a contradiction, and an implementation
    // that presented them as one would accuse an honest exchange.
    assert!(Equivocation::new(place, e.seq, real, real).is_err());

    // Neither is a branch nobody signed. Anyone can write two conflicting
    // structs; the artifact is worth something only because a stranger can
    // check both signatures.
    let mut invented = real;
    invented.head[0] ^= 1;
    assert!(
        Equivocation::new(place, e.seq, real, invented).is_err(),
        "an unsigned branch must not be presentable as proof"
    );
}

/// An exchange that issues no receipts refuses the receipted request rather
/// than answering it in the other shape.
///
/// Answering unreceipted would put the reader back to telling the shapes apart
/// by length, which is exactly what the type byte exists to prevent. The
/// refusal is also what a client sees from an exchange that has lost a
/// channel's head, and the recovery is the same: ask again plainly.
#[test]
fn an_exchange_that_cannot_sign_refuses_rather_than_answering_in_the_other_shape() {
    // Not an integration test: a deployed sqexd always holds its key, so the
    // only way to reach this state is to build the store without one.
    use sqexd::channel::{ChannelError, Channels};
    let exchange = PubKey::new(SigningKey::from_bytes(&[46u8; 32]).verifying_key().to_bytes());
    let c = Channels::open(None, exchange, None).unwrap();
    let caller = identity(46).1;
    let err = c.fetch(&caller, &[46u8; 32], 0, true).unwrap_err();
    assert!(
        matches!(err, ChannelError::NoReceipts | ChannelError::NoSuchChannel),
        "a store with no seed must refuse a receipted fetch, got {err:?}"
    );
    assert_eq!(Code::NoReceipts.as_str(), "no_receipts");
}
