//! SIP-48: an account keeps a sealed backup at the exchange -- segments as
//! SIP-18 blobs held by the account, named by a manifest whose generation
//! must advance -- readable by its own devices and by its SIP-44 successor,
//! and by nobody else.

use std::net::SocketAddr;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::SigningKey;
use sqex_proto::backup::{
    Held, KIND_HELD, KIND_HISTORY, Manifest, Plain, Segment, ask, drop_all, open,
};
use sqex_proto::blob_store::{
    Begin, Begun, Chunk, Commit, Committed, GetChunk, PutChunk, blob_id, chunk_nonce,
};
use sqex_proto::channel::Visibility;
use sqex_proto::refusal::{Code, Refusal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Signer, instance_for};

async fn server_in(dir: &Path, extra: &str) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n{extra}\n",
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

fn seal(plaintext: &[u8], key: &[u8; 32]) -> (Vec<Vec<u8>>, [u8; 32]) {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    let sealed: Vec<Vec<u8>> = plaintext
        .chunks(1024)
        .enumerate()
        .map(|(i, c)| {
            cipher
                .encrypt(Nonce::from_slice(&chunk_nonce(i as u32)), c)
                .unwrap()
        })
        .collect();
    let id = blob_id(&sealed);
    (sealed, id)
}

/// Upload sealed chunks held by `holder` -- a channel, or the account itself.
async fn upload(
    c: &mut Client,
    holder: [u8; 32],
    sealed: &[Vec<u8>],
    id: [u8; 32],
    size: u64,
) -> u16 {
    let (code, body) = c
        .post(
            "/blob/begin",
            Begin {
                channel: holder,
                size,
                chunks: sealed.len() as u32,
                expires_after: 0,
            }
            .encode(),
        )
        .await
        .unwrap();
    if code != 200 {
        return code;
    }
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
        .post(
            "/blob/commit",
            Commit {
                upload: up,
                blob: id,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(Committed::decode(&body).unwrap().stored);
    200
}

async fn chunk(c: &mut Client, id: [u8; 32], index: u32) -> Option<Vec<u8>> {
    let (code, body) = c
        .post("/blob/get", GetChunk { blob: id, index }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    let ch = Chunk::decode(&body).unwrap();
    ch.found.then_some(ch.sealed)
}

fn code_of(body: &[u8]) -> (Code, String) {
    let r = Refusal::decode(body).unwrap();
    (r.code, r.detail.unwrap_or_default())
}

#[tokio::test]
async fn a_backup_is_held_for_the_account_and_read_by_nobody_else() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path(), "backup_quota = 8192").await;
    let alice_seed = [201u8; 32];
    let alice = PubKey::new(
        SigningKey::from_bytes(&alice_seed)
            .verifying_key()
            .to_bytes(),
    );
    let bob_seed = [202u8; 32];
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed)
        .await
        .unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &bob_seed)
        .await
        .unwrap();
    let backup_key = [77u8; 32];

    // A segment, held by the account: uploaded with the account as holder.
    let seg_key = [1u8; 32];
    let (sealed, seg) = seal(b"history of a channel, sealed", &seg_key);
    assert_eq!(
        upload(&mut a, *alice.as_bytes(), &sealed, seg, 28).await,
        200,
        "the account could not hold a segment"
    );
    // Not anybody else's account.
    let (other_sealed, other) = seal(b"not mine", &seg_key);
    assert_ne!(
        upload(&mut b, *alice.as_bytes(), &other_sealed, other, 8).await,
        200,
        "bob uploaded into alice's backup"
    );

    // Nothing yet: generation 0, and the quota all the same.
    let (code, body) = a.post("/backup/read", ask(&alice)).await.unwrap();
    assert_eq!(code, 200);
    let none = Held::decode(&body).unwrap();
    assert!(!none.is_some());
    assert_eq!((none.quota, none.used), (8192, 28));

    // The first manifest names the segment.
    let plain = Plain {
        written: 1,
        segments: vec![Segment {
            kind: KIND_HISTORY,
            blob: seg,
            key: seg_key,
            channel: [9; 32],
            first: 1,
            last: 12,
        }],
    };
    let m1 = Manifest::make(&alice_seed, &backup_key, &alice, 1, &plain).unwrap();
    let (code, body) = a.post("/backup/write", m1.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Read back: verifies as alice's device, opens with the key, counts the
    // segment against the quota.
    let (code, body) = a.post("/backup/read", ask(&alice)).await.unwrap();
    assert_eq!(code, 200);
    let held = Held::decode(&body).unwrap();
    assert_eq!(held.generation, 1);
    assert_eq!(held.device, alice);
    assert_eq!(held.quota, 8192);
    assert_eq!(held.used, 28);
    assert!(held.manifest().verifies(&alice, &alice));
    assert_eq!(open(&backup_key, &alice, 1, &held.sealed).unwrap(), plain);
    assert!(open(&[78u8; 32], &alice, 1, &held.sealed).is_err());
    assert_eq!(
        chunk(&mut a, seg, 0).await.as_deref(),
        Some(sealed[0].as_slice()),
        "the account could not fetch its own segment"
    );

    // Bob: neither the manifest nor the segment.
    let (code, _) = b.post("/backup/read", ask(&alice)).await.unwrap();
    assert_eq!(code, 403, "a stranger read alice's manifest");
    assert!(
        chunk(&mut b, seg, 0).await.is_none(),
        "a stranger fetched a segment"
    );

    // A stale generation is refused and says where the exchange got to.
    let m_stale = Manifest::make(&alice_seed, &backup_key, &alice, 1, &plain).unwrap();
    let (code, body) = a.post("/backup/write", m_stale.encode()).await.unwrap();
    assert_eq!(code, 409);
    assert_eq!(code_of(&body), (Code::StaleGeneration, "1".into()));

    // A manifest naming a blob the account cannot fetch is refused.
    let mut bad = plain.clone();
    bad.segments.push(Segment {
        kind: KIND_HELD,
        blob: [0xee; 32],
        key: [0; 32],
        channel: [0; 32],
        first: 0,
        last: 0,
    });
    let m_bad = Manifest::make(&alice_seed, &backup_key, &alice, 2, &bad).unwrap();
    let (code, body) = a.post("/backup/write", m_bad.encode()).await.unwrap();
    assert_eq!(code, 409);
    assert_eq!(code_of(&body).0, Code::NotHeld);

    // The quota: 8 KiB, 28 bytes used; a 9 KiB segment is refused.
    let big = vec![0u8; 9 * 1024];
    let (big_sealed, big_id) = seal(&big, &seg_key);
    let (code, body) = a
        .post(
            "/blob/begin",
            Begin {
                channel: *alice.as_bytes(),
                size: big.len() as u64,
                chunks: big_sealed.len() as u32,
                expires_after: 0,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 507, "{}", common::said(&body));
    assert_eq!(code_of(&body).0, Code::BlobQuota);
    let _ = big_id;

    // A held blob: a picture alice posted in a channel outlives the channel's
    // window while her manifest names it. Alice makes a room and uploads a
    // blob into it; her next manifest holds it and drops the old segment.
    let s = Signer::new(alice_seed, alice, server_pub);
    let room = [203u8; 32];
    let create = s.create(
        room,
        instance_for(room, 0),
        Visibility::Public,
        3600,
        "room",
        vec![],
    );
    let (code, _) = a.post("/channel/create", create.encode()).await.unwrap();
    assert_eq!(code, 200);
    let pic_key = [2u8; 32];
    let (pic_sealed, pic) = seal(b"a picture", &pic_key);
    assert_eq!(upload(&mut a, room, &pic_sealed, pic, 9).await, 200);
    let plain2 = Plain {
        written: 2,
        segments: vec![Segment {
            kind: KIND_HELD,
            blob: pic,
            key: pic_key,
            channel: room,
            first: 0,
            last: 0,
        }],
    };
    let m2 = Manifest::make(&alice_seed, &backup_key, &alice, 2, &plain2).unwrap();
    let (code, body) = a.post("/backup/write", m2.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    // The old segment was released: gone from the exchange.
    assert!(
        chunk(&mut a, seg, 0).await.is_none(),
        "a released segment survived"
    );
    let (_, body) = a.post("/backup/read", ask(&alice)).await.unwrap();
    let held = Held::decode(&body).unwrap();
    assert_eq!(held.generation, 2);
    assert_eq!(held.used, 9, "the held picture counts against the quota");

    // Dropped: nothing to read, the picture still in its room.
    let (code, _) = a.post("/backup/drop", drop_all()).await.unwrap();
    assert_eq!(code, 200);
    let (_, body) = a.post("/backup/read", ask(&alice)).await.unwrap();
    let none = Held::decode(&body).unwrap();
    assert!(!none.is_some(), "dropped, and still held");
    assert_eq!(none.used, 0);
    assert!(
        chunk(&mut a, pic, 0).await.is_some(),
        "dropping the backup took the room's picture"
    );
}

/// SIP-44: the successor reads the predecessor's backup, and only the
/// successor.
#[tokio::test]
async fn a_successor_reads_what_its_predecessor_kept() {
    use sqex_proto::succession::{Claim, Proof, Will};

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path(), "").await;
    let old_seed = [204u8; 32];
    let old = PubKey::new(SigningKey::from_bytes(&old_seed).verifying_key().to_bytes());
    let new_seed = [205u8; 32];
    let new = PubKey::new(SigningKey::from_bytes(&new_seed).verifying_key().to_bytes());
    let mut o = Client::connect_as(addr, &server_pub, &old_seed)
        .await
        .unwrap();
    let mut n = Client::connect_as(addr, &server_pub, &new_seed)
        .await
        .unwrap();
    let backup_key = [88u8; 32];

    let (sealed, seg) = seal(b"what the old key kept", &[3u8; 32]);
    assert_eq!(upload(&mut o, *old.as_bytes(), &sealed, seg, 21).await, 200);
    let plain = Plain {
        written: 1,
        segments: vec![Segment {
            kind: KIND_HISTORY,
            blob: seg,
            key: [3u8; 32],
            channel: [1; 32],
            first: 1,
            last: 3,
        }],
    };
    let m = Manifest::make(&old_seed, &backup_key, &old, 1, &plain).unwrap();
    let (code, _) = o.post("/backup/write", m.encode()).await.unwrap();
    assert_eq!(code, 200);

    // Before the succession, the new key is a stranger to it.
    let (code, _) = n.post("/backup/read", ask(&old)).await.unwrap();
    assert_eq!(code, 403);
    assert!(chunk(&mut n, seg, 0).await.is_none());

    // The old key's will names the new one; the new one claims.
    let will = Will::sign(&old_seed, &new, 1_700_000_000);
    let claim = Claim {
        proof: Proof::Will(will),
    };
    let (code, body) = n.post("/account/succeed", claim.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Now the manifest opens for the successor, who fetches the segment.
    let (code, body) = n.post("/backup/read", ask(&old)).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let held = Held::decode(&body).unwrap();
    assert!(held.manifest().verifies(&old, &old));
    assert_eq!(open(&backup_key, &old, 1, &held.sealed).unwrap(), plain);
    assert_eq!(
        chunk(&mut n, seg, 0).await.as_deref(),
        Some(sealed[0].as_slice())
    );
}
