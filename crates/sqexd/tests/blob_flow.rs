//! End-to-end for SIP-18 blobs over real HTTP/3.
//!
//! Every seal and open here is done by the test acting as a client. The
//! exchange stores chunks it cannot read, verifies a name it cannot invert,
//! and serves bytes to people it checks the membership of — and that is the
//! whole of its job.

use std::net::SocketAddr;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::SigningKey;
use sqex_proto::blob::{Attachment, KIND_IMAGE};
use sqex_proto::blob_store::{
    Begin, ByBlob, ByChannelBlob, ByUpload, Begun, Chunk, Commit, Committed, GetChunk, Headed,
    Limits, PutChunk, TYPE_ABORT, TYPE_ATTACH, TYPE_DETACH, TYPE_HEAD, blob_id, chunk_nonce,
};
use sqex_proto::channel::{ByChannel, Create, TYPE_CLOSE, TYPE_JOIN, Visibility};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

mod common;
use common::{Signer, instance_for};
use sqex_proto::channel::{ByChannelSigned, EVENT_JOINED};
use sqex_proto::entry_sig::GENESIS;

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

/// What signs for identity `b` against this exchange (SIP-31).
fn signer(pubkey: [u8; 32], b: u8) -> Signer {
    let sk = SigningKey::from_bytes(&[b; 32]);
    Signer::new(sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()), pubkey)
}

async fn client_for(addr: SocketAddr, pubkey: [u8; 32], b: u8) -> (Client, PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    let seed = sk.to_bytes();
    (
        Client::connect_as(addr, &pubkey, &seed).await.unwrap(),
        PubKey::new(sk.verifying_key().to_bytes()),
    )
}

fn public(signer: &Signer, channel: [u8; 32], name: &str) -> Create {
    signer.create(channel, instance_for(channel, 0), Visibility::Public, 3600, name, vec![])
}

/// Seal a file the way a client must: one key, one nonce per chunk, and the
/// name over the ciphertext.
fn seal_file(plaintext: &[u8], chunk: usize) -> ([u8; 32], Vec<Vec<u8>>, [u8; 32]) {
    let key = [0x5a; 32];
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let sealed: Vec<Vec<u8>> = plaintext
        .chunks(chunk)
        .enumerate()
        .map(|(i, c)| {
            cipher
                .encrypt(Nonce::from_slice(&chunk_nonce(i as u32)), c)
                .unwrap()
        })
        .collect();
    let id = blob_id(&sealed);
    (key, sealed, id)
}

fn open_file(key: &[u8; 32], sealed: &[Vec<u8>]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    sealed
        .iter()
        .enumerate()
        .flat_map(|(i, c)| {
            cipher
                .decrypt(Nonce::from_slice(&chunk_nonce(i as u32)), c.as_slice())
                .unwrap()
        })
        .collect()
}

/// Upload a sealed file and commit it, returning whether the exchange accepted.
async fn upload(
    c: &mut Client,
    channel: [u8; 32],
    sealed: &[Vec<u8>],
    id: [u8; 32],
    size: u64,
    expires_after: u32,
) -> bool {
    let (code, body) = c
        .post(
            "/blob/begin",
            Begin {
                channel,
                size,
                chunks: sealed.len() as u32,
                expires_after,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let up = Begun::decode(&body).unwrap().upload;

    for (i, s) in sealed.iter().enumerate() {
        let (code, _) = c
            .post(
                "/blob/put",
                PutChunk {
                    upload: up,
                    index: i as u32,
                    sealed: s.clone(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 200);
    }
    let (code, body) = c
        .post("/blob/commit", Commit { upload: up, blob: id }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Committed::decode(&body).unwrap().stored
}

async fn fetch_all(c: &mut Client, id: [u8; 32], chunks: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for i in 0..chunks {
        let (code, body) = c
            .post("/blob/get", GetChunk { blob: id, index: i }.encode())
            .await
            .unwrap();
        assert_eq!(code, 200);
        let c = Chunk::decode(&body).unwrap();
        assert!(c.found, "chunk {i} missing");
        out.push(c.sealed);
    }
    out
}

#[tokio::test]
async fn a_file_survives_the_round_trip_and_the_exchange_never_sees_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, pubkey, 21).await;
    let (mut bob, _) = client_for(addr, pubkey, 22).await;
    let channel = [1u8; 32];

    let (code, body) = alice
        .post("/channel/create", public(&signer(pubkey, 21), channel, "pictures").encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "create: {}", common::said(&body));
    let joining = signer(pubkey, 22).action_outside(
        channel,
        instance_for(channel, 0),
        EVENT_JOINED,
        &signer(pubkey, 22).account,
        &[],
        0,
        GENESIS,
    );
    bob.post(
        "/channel/join",
        ByChannelSigned { channel, action: joining }.encode(TYPE_JOIN),
    )
        .await
        .unwrap();

    // Something big enough to be several chunks, at a chunk size the exchange
    // told us it would take.
    let (code, body) = alice.post("/blob/limits", vec![0x09]).await.unwrap();
    assert_eq!(code, 200);
    let limits = Limits::decode(&body).unwrap();
    let chunk = (limits.chunk as usize).min(64 * 1024);

    let original: Vec<u8> = (0..chunk * 3 + 17).map(|i| (i % 251) as u8).collect();
    let (key, sealed, id) = seal_file(&original, chunk);
    assert!(sealed.len() >= 4);

    assert!(upload(&mut alice, channel, &sealed, id, original.len() as u64, 0).await);

    // Bob fetches and reassembles with the key that would have arrived inside
    // the message.
    let got = fetch_all(&mut bob, id, sealed.len() as u32).await;
    assert_eq!(open_file(&key, &got), original);

    // The exchange stored the ciphertext, not the file.
    assert_ne!(got[0], original[..chunk].to_vec());

    let (_, body) = bob
        .post("/blob/head", ByBlob { blob: id }.encode(TYPE_HEAD))
        .await
        .unwrap();
    let head = Headed::decode(&body).unwrap();
    assert!(head.found);
    assert_eq!(head.size, original.len() as u64);
    assert_eq!(head.chunks, sealed.len() as u32);
}

#[tokio::test]
async fn a_commit_that_does_not_hash_to_its_name_is_refused() {
    // The exchange cannot read a byte of this and can still tell it is being
    // told the truth about it — which is why the name is over the ciphertext.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, pubkey, 31).await;
    let channel = [2u8; 32];
    alice
        .post("/channel/create", public(&signer(pubkey, 31), channel, "pictures").encode())
        .await
        .unwrap();

    let (_, sealed, id) = seal_file(b"the real bytes", 1024);
    let mut wrong = id;
    wrong[0] ^= 1;
    assert!(!upload(&mut alice, channel, &sealed, wrong, 14, 0).await);

    // And nothing was stored under either name.
    let (_, body) = alice
        .post("/blob/head", ByBlob { blob: id }.encode(TYPE_HEAD))
        .await
        .unwrap();
    assert!(!Headed::decode(&body).unwrap().found);
}

#[tokio::test]
async fn an_upload_missing_a_chunk_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, pubkey, 41).await;
    let channel = [3u8; 32];
    alice
        .post("/channel/create", public(&signer(pubkey, 41), channel, "pictures").encode())
        .await
        .unwrap();

    let (_, sealed, id) = seal_file(&vec![7u8; 4096], 1024);
    let (_, body) = alice
        .post(
            "/blob/begin",
            Begin {
                channel,
                size: 4096,
                chunks: sealed.len() as u32,
                expires_after: 0,
            }
            .encode(),
        )
        .await
        .unwrap();
    let up = Begun::decode(&body).unwrap().upload;

    // Everything but the last.
    for (i, s) in sealed.iter().enumerate().take(sealed.len() - 1) {
        alice
            .post(
                "/blob/put",
                PutChunk { upload: up, index: i as u32, sealed: s.clone() }.encode(),
            )
            .await
            .unwrap();
    }
    let (_, body) = alice
        .post("/blob/commit", Commit { upload: up, blob: id }.encode())
        .await
        .unwrap();
    assert!(!Committed::decode(&body).unwrap().stored);
}

#[tokio::test]
async fn a_stranger_cannot_fetch_a_blob_and_absence_looks_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, pubkey, 51).await;
    let (mut mallory, _) = client_for(addr, pubkey, 52).await;
    let channel = [4u8; 32];

    // A private channel, so membership is the only way in.
    //
    // Built private rather than built public and flipped: SIP-32's `created`
    // action commits to the visibility, so mutating it afterwards leaves a
    // signature for a channel that was never asked for — which the exchange
    // refuses, and which is the whole point of the commitment.
    let req = signer(pubkey, 51).create(
        channel,
        instance_for(channel, 0),
        Visibility::Private,
        3600,
        "",
        vec![],
    );
    alice.post("/channel/create", req.encode()).await.unwrap();

    let (_, sealed, id) = seal_file(b"not for you", 1024);
    assert!(upload(&mut alice, channel, &sealed, id, 11, 0).await);

    let (code, body) = mallory
        .post("/blob/get", GetChunk { blob: id, index: 0 }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    let c = Chunk::decode(&body).unwrap();
    assert!(!c.found, "a stranger is told the same thing as about nothing");

    let (_, body) = mallory
        .post("/blob/head", ByBlob { blob: id }.encode(TYPE_HEAD))
        .await
        .unwrap();
    assert!(!Headed::decode(&body).unwrap().found);
}

#[tokio::test]
async fn forwarding_costs_the_reference_and_not_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, pubkey, 61).await;
    let first = [5u8; 32];
    let second = [6u8; 32];
    alice
        .post("/channel/create", public(&signer(pubkey, 61), first, "one").encode())
        .await
        .unwrap();
    alice
        .post("/channel/create", public(&signer(pubkey, 61), second, "two").encode())
        .await
        .unwrap();

    let (_, sealed, id) = seal_file(b"shared", 1024);
    assert!(upload(&mut alice, first, &sealed, id, 6, 0).await);

    let (code, _) = alice
        .post(
            "/blob/attach",
            ByChannelBlob { channel: second, blob: id, expires_after: 0 }.encode(TYPE_ATTACH),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // Closing the first channel must not take the photograph out of the
    // second: a blob dies with its last attachment, not with one channel.
    let (code, _) = alice
        .post("/channel/close", ByChannel { channel: first }.encode(TYPE_CLOSE))
        .await
        .unwrap();
    assert_eq!(code, 200);

    let (_, body) = alice
        .post("/blob/head", ByBlob { blob: id }.encode(TYPE_HEAD))
        .await
        .unwrap();
    assert!(Headed::decode(&body).unwrap().found, "still attached elsewhere");

    // Detaching the last one deletes it.
    let (code, _) = alice
        .post(
            "/blob/detach",
            ByChannelBlob { channel: second, blob: id, expires_after: 0 }.encode(TYPE_DETACH),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (_, body) = alice
        .post("/blob/head", ByBlob { blob: id }.encode(TYPE_HEAD))
        .await
        .unwrap();
    assert!(!Headed::decode(&body).unwrap().found, "the last attachment took it");
}

#[tokio::test]
async fn an_aborted_upload_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, pubkey, 71).await;
    let channel = [7u8; 32];
    alice
        .post("/channel/create", public(&signer(pubkey, 71), channel, "x").encode())
        .await
        .unwrap();

    let (_, sealed, id) = seal_file(b"abandoned", 1024);
    let (_, body) = alice
        .post(
            "/blob/begin",
            Begin { channel, size: 9, chunks: 1, expires_after: 0 }.encode(),
        )
        .await
        .unwrap();
    let up = Begun::decode(&body).unwrap().upload;
    alice
        .post(
            "/blob/put",
            PutChunk { upload: up, index: 0, sealed: sealed[0].clone() }.encode(),
        )
        .await
        .unwrap();

    let (code, _) = alice
        .post("/blob/abort", ByUpload { upload: up }.encode(TYPE_ABORT))
        .await
        .unwrap();
    assert_eq!(code, 200);

    // The upload is gone, so committing it is not a thing that can happen.
    let (code, _) = alice
        .post("/blob/commit", Commit { upload: up, blob: id }.encode())
        .await
        .unwrap();
    assert_eq!(code, 404);
}

#[tokio::test]
async fn a_chunk_outside_the_reservation_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, pubkey, 81).await;
    let channel = [8u8; 32];
    alice
        .post("/channel/create", public(&signer(pubkey, 81), channel, "x").encode())
        .await
        .unwrap();

    let (_, body) = alice
        .post(
            "/blob/begin",
            Begin { channel, size: 10, chunks: 2, expires_after: 0 }.encode(),
        )
        .await
        .unwrap();
    let up = Begun::decode(&body).unwrap().upload;
    let (code, _) = alice
        .post(
            "/blob/put",
            PutChunk { upload: up, index: 5, sealed: vec![0; 32] }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 409);
}

#[tokio::test]
async fn an_attachment_reference_describes_what_was_uploaded() {
    // The two halves meeting: what SIP-18 stores, and what SIP-19 carries.
    let dir = tempfile::tempdir().unwrap();
    let (addr, pubkey, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, pubkey, 91).await;
    let channel = [9u8; 32];
    alice
        .post("/channel/create", public(&signer(pubkey, 91), channel, "x").encode())
        .await
        .unwrap();

    let original = vec![3u8; 5000];
    let (key, sealed, id) = seal_file(&original, 2048);
    assert!(upload(&mut alice, channel, &sealed, id, original.len() as u64, 0).await);

    let reference = Attachment {
        kind: KIND_IMAGE,
        blob: id,
        key,
        size: original.len() as u64,
        chunks: sealed.len() as u32,
        mime: "image/png".into(),
        meta: {
            let mut m = 64u16.to_be_bytes().to_vec();
            m.extend_from_slice(&64u16.to_be_bytes());
            m
        },
        preview: vec![1; 32],
    };

    // A reader takes the reference, fetches by its name, and opens with its
    // key — never having asked the exchange for anything but bytes.
    let got = fetch_all(&mut alice, reference.blob, reference.chunks).await;
    assert_eq!(open_file(&reference.key, &got), original);
    assert_eq!(reference.dimensions(), Some((64, 64)));
}

#[tokio::test]
async fn the_last_member_leaving_takes_the_blobs_with_them() {
    // Found by tidying up a development server and counting: one blob, no
    // attachments. Three of destroy's four callers gathered the attached
    // blobs and collected them afterwards, and `leave` did not — so the last
    // member walking out of a private channel orphaned its files for good.
    // The collection lives inside `destroy` now, because a rule every caller
    // must remember is a rule one of them will not.
    use sqex_proto::channel::{EVENT_LEFT, Invitee, Role, TYPE_LEAVE};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (mut alice, alice_key) = client_for(addr, server_pub, 1).await;
    let (mut bob, bob_key) = client_for(addr, server_pub, 2).await;

    let channel = [0x71; 32];
    let (code, _) = alice
        .post(
            "/channel/create",
            signer(server_pub, 1)
                .create(
                    channel,
                    instance_for(channel, 0),
                    Visibility::Private,
                    3600,
                    "",
                    vec![Invitee {
                        account: bob_key,
                        role: Role::Member,
                    }],
                )
                .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let (_, sealed, id) = seal_file(b"a file nobody will want afterwards", sqex_proto::blob_store::CHUNK);
    assert!(upload(&mut alice, channel, &sealed, id, 34, 0).await);

    let held = |label: &str| {
        let db = rusqlite::Connection::open(dir.path().join("channels.db")).unwrap();
        let blobs: i64 = db
            .query_row("SELECT COUNT(*) FROM blob", [], |r| r.get(0))
            .unwrap();
        let chunks: i64 = db
            .query_row("SELECT COUNT(*) FROM blob_chunk", [], |r| r.get(0))
            .unwrap();
        println!("{label}: {blobs} blob(s), {chunks} chunk(s)");
        (blobs, chunks)
    };
    assert_eq!(held("uploaded").0, 1);

    // Both leave. The channel is destroyed with the last of them.
    for (c, b) in [(&mut bob, 2u8), (&mut alice, 1u8)] {
        let who = signer(server_pub, b);
        // Asked rather than assumed: Alice's create already spent a position
        // for Bob's `added`, so she is not where Bob is, and both are still
        // members here so `Info` will answer.
        let account = who.account;
        let action = who.action(c, channel, EVENT_LEFT, &account, &[]).await;
        let (code, body) = c
            .post(
                "/channel/leave",
                ByChannelSigned { channel, action }.encode(TYPE_LEAVE),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
    }

    assert_eq!(
        held("after everyone left"),
        (0, 0),
        "the blob outlived the channel that held it"
    );
    let _ = alice_key;
}

#[tokio::test]
async fn a_blob_attached_twice_survives_one_channel_ending() {
    // The other half of the same rule, and the reason destroy collects rather
    // than deletes: forwarding costs the reference and not the file, so a
    // photograph in two conversations does not go when one of them does.
    use sqex_proto::blob_store::{ByChannelBlob, TYPE_ATTACH};
    use sqex_proto::channel::{ByChannel, TYPE_LEAVE};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (mut alice, _) = client_for(addr, server_pub, 1).await;

    let first = [0x81; 32];
    let second = [0x82; 32];
    for c in [first, second] {
        let (code, _) = alice
            .post("/channel/create", public(&signer(server_pub, 1), c, "room").encode())
            .await
            .unwrap();
        assert_eq!(code, 200);
    }
    let (_, sealed, id) = seal_file(b"forwarded", sqex_proto::blob_store::CHUNK);
    assert!(upload(&mut alice, first, &sealed, id, 9, 0).await);
    let (code, _) = alice
        .post(
            "/blob/attach",
            ByChannelBlob {
                channel: second,
                blob: id,
                expires_after: 0,
            }
            .encode(TYPE_ATTACH),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    // The first channel ends. The blob is still in the second.
    alice
        .post("/channel/leave", ByChannel { channel: first }.encode(TYPE_LEAVE))
        .await
        .unwrap();
    let db = rusqlite::Connection::open(dir.path().join("channels.db")).unwrap();
    let blobs: i64 = db
        .query_row("SELECT COUNT(*) FROM blob", [], |r| r.get(0))
        .unwrap();
    assert_eq!(blobs, 1, "a blob attached elsewhere was collected anyway");
}
