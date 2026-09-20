//! SIP-59 §Collecting the backup: a backup follows the account home. What Alice wrote at X before
//! she moved to H is collected by H -- the manifest as X held it and every
//! blob it names, over the peering link, once -- and read at H exactly as
//! it was; X releases its copy. A backup Alice writes at H after the Move
//! stands, and X's is released unread. A backup H has no quota for is left
//! at X. A stranger and a configured acts-for peer are refused.

use std::net::SocketAddr;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::SigningKey;
use sqex_proto::backup::{Held, KIND_HISTORY, Manifest, Plain, Segment, ask};
use sqex_proto::blob_store::{
    Begin, Begun, Chunk, Commit, Committed, GetChunk, PutChunk, blob_id, chunk_nonce,
};
use sqex_proto::home::{Move, Moving};
use sqex_proto::peer::{BLOB_LIST, PullBackup, PullBackupBlob, TookBackup};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;

/// An exchange peering openly, finding `found` without DNS, with `peers`
/// listed, a home cycle of `home_secs`, and `extra` config appended.
pub(crate) async fn exchange_in(
    dir: &Path,
    listen: SocketAddr,
    domain: &str,
    peers: &str,
    found: &[(&str, PubKey, SocketAddr)],
    home_secs: u64,
    extra: &str,
) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        key_in(dir);
    }
    let config_toml = format!(
        "listen = {:?}\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\ndomain = {domain:?}\nopen_peering = true\n\
         replication_peers = [{peers}]\nhome_secs = {home_secs}\n{extra}\n",
        listen.to_string(),
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    let file: FileConfig = toml::from_str(&config_toml).unwrap();
    let config = file.resolve().unwrap();
    let (signing_key, _pub) =
        squic::load_keypair(&std::fs::read_to_string(&config.key_file).unwrap()).unwrap();
    let map = found
        .iter()
        .map(|(d, k, a)| ((*d).to_string(), (*k, *a)))
        .collect();
    let bound = sqexd::bind_with(config, None, signing_key, sqexd::relay::Find::Fixed(map))
        .await
        .unwrap();
    let addr = bound.local_addr;
    let server_pub = bound.public_key.to_bytes();
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
}

pub(crate) fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

pub(crate) fn key_in(dir: &Path) -> (PubKey, [u8; 32]) {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let seed = server_sk.to_bytes();
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    (PubKey::new(vk.to_bytes()), seed)
}

pub(crate) fn seed_in(dir: &Path) -> [u8; 32] {
    let bytes = std::fs::read_to_string(dir.join("host_key")).unwrap();
    let (sk, _) = squic::load_keypair(&bytes).unwrap();
    sk.to_bytes()
}

pub(crate) fn free_port() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

/// Upload sealed chunks held by the account itself (SIP-48).
async fn upload(c: &mut Client, holder: [u8; 32], sealed: &[Vec<u8>], id: [u8; 32], size: u64) {
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
}

/// Write a one-segment backup for `account` at the exchange `c` is at.
async fn write_backup(
    c: &mut Client,
    seed: &[u8; 32],
    account: &PubKey,
    backup_key: &[u8; 32],
    text: &[u8],
    generation: u64,
) -> (Manifest, [u8; 32], Vec<Vec<u8>>) {
    let seg_key = [1u8; 32];
    let (sealed, seg) = seal(text, &seg_key);
    upload(c, *account.as_bytes(), &sealed, seg, text.len() as u64).await;
    let plain = Plain {
        written: generation,
        segments: vec![Segment {
            kind: KIND_HISTORY,
            blob: seg,
            key: seg_key,
            channel: [9; 32],
            first: 1,
            last: 12,
        }],
    };
    let m = Manifest::make(seed, backup_key, account, generation, &plain).unwrap();
    let (code, body) = c.post("/backup/write", m.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    (m, seg, sealed)
}

async fn held(c: &mut Client, account: &PubKey) -> Held {
    let (code, body) = c.post("/backup/read", ask(account)).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Held::decode(&body).unwrap()
}

async fn chunk_at(c: &mut Client, id: [u8; 32], index: u32) -> Option<Vec<u8>> {
    let (code, body) = c
        .post("/blob/get", GetChunk { blob: id, index }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    let ch = Chunk::decode(&body).unwrap();
    ch.found.then_some(ch.sealed)
}

async fn move_to(
    c: &mut Client,
    seed: &[u8; 32],
    home: &PubKey,
    domain: &str,
    origins: Vec<(PubKey, String)>,
    issued: u64,
) {
    let (code, body) = c
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(seed, home, issued),
                domain: domain.into(),
                origins,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
}

/// Wait until `account`'s backup at `c` reaches `generation`, or give up.
async fn wait_for_generation(c: &mut Client, account: &PubKey, generation: u64) -> Held {
    let mut h = held(c, account).await;
    for _ in 0..80 {
        if h.generation == generation {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        h = held(c, account).await;
    }
    h
}

#[tokio::test]
async fn a_backup_written_before_a_move_is_collected_by_the_new_home() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (h_key, _) = key_in(h_dir.path());
    let (x_at, h_at) = (free_port(), free_port());
    let (alice_seed, alice) = identity(51);
    let (stranger_seed, stranger) = identity(53);
    // X lists the stranger as acting for Alice: an operator's word, which
    // confers no backup.
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        &format!("{{ key = \"{stranger}\", for = [\"{alice}\"] }}"),
        &[("h.test", h_key, h_at)],
        1,
        "",
    )
    .await;
    let (h_addr, h_pub) = exchange_in(
        h_dir.path(),
        h_at,
        "h.test",
        "",
        &[("x.test", x_key, x_addr)],
        1,
        "",
    )
    .await;

    // Alice lives at X and writes her backup there.
    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_x,
        &alice_seed,
        &x_key,
        "x.test",
        vec![],
        now(),
    )
    .await;
    let backup_key = [77u8; 32];
    let (m, seg, sealed) = write_backup(
        &mut alice_at_x,
        &alice_seed,
        &alice,
        &backup_key,
        b"history of a channel, sealed at x",
        1,
    )
    .await;
    let at_x = held(&mut alice_at_x, &alice).await;
    assert_eq!(at_x.generation, 1);

    // Strangers, listed or not, are refused the backup, its blobs and the
    // release: only her home collects it.
    for seed in [stranger_seed, identity(54).0] {
        let mut s = Client::connect_as(x_addr, &x_pub, &seed).await.unwrap();
        let (code, _) = s
            .post("/peer/backup", PullBackup { account: alice }.encode())
            .await
            .unwrap();
        assert_eq!(
            code, 404,
            "somebody other than the home was given the backup"
        );
        let (code, _) = s
            .post(
                "/peer/backup/blob",
                PullBackupBlob {
                    account: alice,
                    blob: seg,
                    chunk: BLOB_LIST,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(code, 404, "somebody other than the home was given a blob");
        let (code, _) = s
            .post(
                "/peer/backup/took",
                TookBackup {
                    account: alice,
                    generation: 1,
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(
            code, 404,
            "somebody other than the home released the backup"
        );
    }
    assert_eq!(held(&mut alice_at_x, &alice).await.generation, 1);

    // Alice moves to H, naming X as an origin. H carries the Move, and
    // collects her backup.
    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_h,
        &alice_seed,
        &h_key,
        "h.test",
        vec![(x_key, "x.test".into())],
        now() + 1,
    )
    .await;
    let at_h = wait_for_generation(&mut alice_at_h, &alice, 1).await;
    assert_eq!(at_h.generation, 1, "the backup did not follow Alice home");
    assert_eq!(at_h.device, alice, "the writing device, as X reported it");
    assert_eq!(
        at_h.written, at_x.written,
        "when the device wrote, as X reported it"
    );
    assert_eq!(at_h.blobs, vec![seg]);
    assert_eq!(at_h.sealed, m.sealed, "the sealed manifest, unchanged");
    assert_eq!(at_h.sig, m.sig, "the device's signature, unchanged");
    assert_eq!(at_h.used, 33, "the segment counts against her quota at H");
    // The segment's bytes are at H, served to her as her own.
    assert_eq!(
        chunk_at(&mut alice_at_h, seg, 0).await,
        Some(sealed[0].clone())
    );
    assert_eq!(chunk_at(&mut alice_at_h, seg, 1).await, None);

    // X released its copy: nothing held, and the segment gone with it.
    let mut released = held(&mut alice_at_x, &alice).await;
    for _ in 0..40 {
        if released.generation == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        released = held(&mut alice_at_x, &alice).await;
    }
    assert_eq!(released.generation, 0, "X kept a copy nobody reads");
    assert_eq!(released.used, 0, "X kept the segment");
    assert_eq!(chunk_at(&mut alice_at_x, seg, 0).await, None);

    // Another cycle stores nothing twice: H still serves generation 1, and
    // her next write must exceed it, as SIP-48 requires.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert_eq!(held(&mut alice_at_h, &alice).await.generation, 1);
    let stale = Manifest::make(
        &alice_seed,
        &backup_key,
        &alice,
        1,
        &Plain {
            written: 2,
            segments: vec![],
        },
    )
    .unwrap();
    let (code, _) = alice_at_h
        .post("/backup/write", stale.encode())
        .await
        .unwrap();
    assert_eq!(
        code, 409,
        "generation 1 was accepted over the collected generation 1"
    );
    let (m2, ..) = write_backup(
        &mut alice_at_h,
        &alice_seed,
        &alice,
        &backup_key,
        b"written at h",
        2,
    )
    .await;
    let at_h = held(&mut alice_at_h, &alice).await;
    assert_eq!((at_h.generation, at_h.sealed), (2, m2.sealed));
    assert_eq!(
        at_h.used, 12,
        "the collected segment was not released by the manifest that omits it"
    );

    // The home's own pull, by hand: X answers nothing held now.
    let mut as_h = Client::connect_as(x_addr, &x_pub, &seed_in(h_dir.path()))
        .await
        .unwrap();
    let (code, body) = as_h
        .post("/peer/backup", PullBackup { account: alice }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(!Held::decode(&body).unwrap().is_some());
}

#[tokio::test]
async fn a_backup_written_at_the_new_home_stands_over_the_former_homes() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (h_key, _) = key_in(h_dir.path());
    let (x_at, h_at) = (free_port(), free_port());
    let (alice_seed, alice) = identity(55);
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        "",
        &[("h.test", h_key, h_at)],
        1,
        "",
    )
    .await;
    // H's cycle is slow enough that Alice's own write lands first.
    let (h_addr, h_pub) = exchange_in(
        h_dir.path(),
        h_at,
        "h.test",
        "",
        &[("x.test", x_key, x_addr)],
        3,
        "",
    )
    .await;

    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_x,
        &alice_seed,
        &x_key,
        "x.test",
        vec![],
        now(),
    )
    .await;
    let backup_key = [78u8; 32];
    write_backup(
        &mut alice_at_x,
        &alice_seed,
        &alice,
        &backup_key,
        b"old, at x, generation thirty-seven",
        37,
    )
    .await;

    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_h,
        &alice_seed,
        &h_key,
        "h.test",
        vec![(x_key, "x.test".into())],
        now() + 1,
    )
    .await;
    // Written at H after the Move, from generation 0 there: the newer
    // state by her own act, whatever the number says.
    let (mine, ..) = write_backup(
        &mut alice_at_h,
        &alice_seed,
        &alice,
        &backup_key,
        b"new, at h",
        1,
    )
    .await;

    // X's copy is released without being read; H's stands.
    let mut released = held(&mut alice_at_x, &alice).await;
    for _ in 0..80 {
        if released.generation == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        released = held(&mut alice_at_x, &alice).await;
    }
    assert_eq!(
        released.generation, 0,
        "X kept a copy the account had superseded"
    );
    let at_h = held(&mut alice_at_h, &alice).await;
    assert_eq!(
        (at_h.generation, at_h.sealed.clone()),
        (1, mine.sealed),
        "H replaced her newest backup with an older one"
    );
    assert_eq!(at_h.used, 9, "H holds blobs it did not need");
}

#[tokio::test]
async fn a_backup_over_the_homes_quota_stays_at_the_former_home() {
    let x_dir = tempfile::tempdir().unwrap();
    let h_dir = tempfile::tempdir().unwrap();
    let (x_key, _) = key_in(x_dir.path());
    let (h_key, _) = key_in(h_dir.path());
    let (x_at, h_at) = (free_port(), free_port());
    let (alice_seed, alice) = identity(56);
    let (x_addr, x_pub) = exchange_in(
        x_dir.path(),
        x_at,
        "x.test",
        "",
        &[("h.test", h_key, h_at)],
        1,
        "",
    )
    .await;
    let (h_addr, h_pub) = exchange_in(
        h_dir.path(),
        h_at,
        "h.test",
        "",
        &[("x.test", x_key, x_addr)],
        1,
        "backup_quota = 16",
    )
    .await;

    let mut alice_at_x = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_x,
        &alice_seed,
        &x_key,
        "x.test",
        vec![],
        now(),
    )
    .await;
    let backup_key = [79u8; 32];
    write_backup(
        &mut alice_at_x,
        &alice_seed,
        &alice,
        &backup_key,
        b"thirty-three bytes, over the quota",
        1,
    )
    .await;

    let mut alice_at_h = Client::connect_as(h_addr, &h_pub, &alice_seed)
        .await
        .unwrap();
    move_to(
        &mut alice_at_h,
        &alice_seed,
        &h_key,
        "h.test",
        vec![(x_key, "x.test".into())],
        now() + 1,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
    // Not collected, not released: readable at X as before, nothing at H.
    let at_x = held(&mut alice_at_x, &alice).await;
    assert_eq!(
        (at_x.generation, at_x.used),
        (1, 34),
        "X released a backup H never stored"
    );
    let at_h = held(&mut alice_at_h, &alice).await;
    assert_eq!(
        (at_h.generation, at_h.used),
        (0, 0),
        "H kept what it could not hold"
    );
}
