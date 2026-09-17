//! SIP-62: an account hands itself over to a new key while it still holds
//! the old one. Its device -- itself, device-less -- follows under the new
//! key's credential, so the same connection acts for the successor from
//! the next request; its name and its seat in the room follow as SIP-44
//! moves them; its home record is re-keyed with the signature cleared and
//! the successor is asked to sign again; and the new key may hand over
//! once more. The controls: a stranger cannot present it, a successor that
//! is an account already cannot be handed into, a credential the new key
//! did not sign refuses the whole thing, and a key is succeeded once.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{
    ByChannel, ByChannelSigned, EVENT_SUCCEEDED, Entries, Fetch, KIND_SYSTEM, Mine, Mines, System,
    TYPE_INFO, TYPE_JOIN, Visibility,
};
use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqex_proto::device::{Devices, ListDevices};
use sqex_proto::home::{Homed, Move, Moving};
use sqex_proto::name::{Claim as NameClaim, ClaimAck, Resolve as NameResolve, Resolved};
use sqex_proto::refusal::{Code, Refusal};
use sqex_proto::succession::{Handover, Succeeded, Will, ask};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

async fn server_in(dir: &Path, peers: &[PubKey]) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nname_registration = \"open\"\nname_lease_secs = 100000\n\
         replication_peers = [{list}]\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
    );
    serve(dir, &config_toml).await
}

async fn replica_in(
    dir: &Path,
    origin: PubKey,
    origin_addr: SocketAddr,
    channel: [u8; 32],
) -> (SocketAddr, [u8; 32]) {
    let key_path = dir.join("host_key");
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\n\n[[replicate]]\norigin = {:?}\naddr = {:?}\n\
         channels = [{:?}]\ninterval_secs = 1\ndomain = \"x.test\"\n",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
        origin.to_string(),
        origin_addr.to_string(),
        bs58::encode(channel).into_string(),
    );
    serve(dir, &config_toml).await
}

async fn serve(dir: &Path, config_toml: &str) -> (SocketAddr, [u8; 32]) {
    let config_path = dir.join("sqexd.toml");
    std::fs::write(&config_path, config_toml).unwrap();
    let file: FileConfig = toml::from_str(config_toml).unwrap();
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

fn key_in(dir: &Path) -> PubKey {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    PubKey::new(vk.to_bytes())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn connect(addr: SocketAddr, server_pub: &[u8; 32], seed: &[u8; 32]) -> Client {
    Client::connect_as(addr, server_pub, seed).await.unwrap()
}

async fn mine(c: &mut Client) -> Result<Mines, Refusal> {
    let (code, body) = c
        .post("/channel/mine", Mine { offset: 0 }.encode())
        .await
        .unwrap();
    if code == 200 {
        Ok(Mines::decode(&body).unwrap())
    } else {
        Err(Refusal::decode(&body).unwrap())
    }
}

async fn resolve(c: &mut Client, name: &str) -> Resolved {
    let (code, body) = c
        .post("/name/resolve", NameResolve { name: name.into() }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    Resolved::decode(&body).unwrap()
}

async fn devices_of(c: &mut Client, account: &PubKey) -> Vec<PubKey> {
    let (code, body) = c
        .post("/device/list", ListDevices { account: *account }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    Devices::decode(&body)
        .unwrap()
        .devices
        .iter()
        .map(|d| d.device)
        .collect()
}

async fn home_of(c: &mut Client, account: &PubKey) -> Option<Homed> {
    let (code, body) = c
        .post("/account/home", account.as_bytes().to_vec())
        .await
        .unwrap();
    (code == 200).then(|| Homed::decode(&body).unwrap())
}

async fn present(c: &mut Client, h: &Handover) -> (u16, Vec<u8>) {
    c.post("/account/handover", h.encode()).await.unwrap()
}

fn handover(old_seed: &[u8; 32], new_seed: &[u8; 32], devices: &[PubKey]) -> Handover {
    let new = PubKey::new(SigningKey::from_bytes(new_seed).verifying_key().to_bytes());
    let will = Will::sign(old_seed, &new, now());
    let credentials = devices
        .iter()
        .map(|d| Credential::issue(new_seed, d, SCOPE_CHAT, now() - 60, now() + 86_400).unwrap())
        .collect();
    Handover { will, credentials }
}

async fn fetch_all(c: &mut Client, channel: [u8; 32]) -> Result<Entries, Refusal> {
    let (code, body) = c
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since: 0,
                wait_secs: 0,
                receipts: false,
            }
            .encode(),
        )
        .await
        .unwrap();
    if code == 200 {
        Ok(Entries::decode(&body, false).unwrap())
    } else {
        Err(Refusal::decode(&body).unwrap())
    }
}

/// A room made by Alice, replicated to `replica` where given, with Bob in
/// it, a name on Alice, and Alice's Move saying this exchange is home.
#[allow(clippy::too_many_arguments)]
async fn a_life(
    addr: SocketAddr,
    server_pub: [u8; 32],
    alice_seed: [u8; 32],
    alice: PubKey,
    bob_seed: [u8; 32],
    bob: PubKey,
    channel: [u8; 32],
    replica: Option<PubKey>,
) -> (Client, Chain) {
    let mut a = connect(addr, &server_pub, &alice_seed).await;
    let s = Signer::new(alice_seed, alice, server_pub);
    let mut chain = Chain::default();
    let req = s.create_chained(
        &mut chain,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "the room",
        vec![],
    );
    let (code, body) = a.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    if let Some(r) = replica {
        let action = s.action_chained(
            &mut chain,
            channel,
            instance_for(channel, 0),
            sqex_proto::channel::EVENT_REPLICATE,
            &r,
            &[],
        );
        let (code, body) = a
            .post(
                "/channel/replicate",
                sqex_proto::channel::ByAccount {
                    channel,
                    account: r,
                    action,
                }
                .encode(sqex_proto::channel::TYPE_REPLICATE),
            )
            .await
            .unwrap();
        assert_eq!(code, 200, "{}", common::said(&body));
    }
    let info = s.info(&mut a, channel).await;
    let req = s.post_chained(&mut chain, channel, info.instance, 0, 0, b"before".to_vec());
    assert_eq!(a.post("/channel/post", req.encode()).await.unwrap().0, 200);
    let (code, body) = a
        .post(
            "/name/claim",
            NameClaim {
                name: "alice".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(ClaimAck::decode(&body).unwrap().outcome, 0);
    let (code, _) = a
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &PubKey::new(server_pub), now()),
                domain: "x.test".into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);

    let mut b = connect(addr, &server_pub, &bob_seed).await;
    let joining = Signer::new(bob_seed, bob, server_pub).action_outside(
        channel,
        instance_for(channel, 0),
        sqex_proto::channel::EVENT_JOINED,
        &bob,
        &[],
        0,
        sqex_proto::entry_sig::GENESIS,
    );
    let (code, _) = b
        .post(
            "/channel/join",
            ByChannelSigned {
                channel,
                action: joining,
            }
            .encode(TYPE_JOIN),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    (a, chain)
}

#[tokio::test]
async fn an_account_hands_itself_over_and_its_device_name_seat_and_home_follow() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub) = server_in(dir.path(), &[]).await;
    let here = PubKey::new(server_pub);
    let (alice_seed, alice) = identity(91);
    let (bob_seed, bob) = identity(92);
    let (new_seed, new) = identity(93);
    let (third_seed, third) = identity(94);
    let (stranger_seed, _) = identity(95);
    let channel = [91u8; 32];
    let (mut a, mut chain) = a_life(
        addr, server_pub, alice_seed, alice, bob_seed, bob, channel, None,
    )
    .await;

    // Controls. A stranger presenting Alice's handover is refused; a
    // credential the new key did not sign refuses the whole thing; a
    // successor that is already an account cannot be handed into.
    let h = handover(&alice_seed, &new_seed, &[alice]);
    let mut stranger = connect(addr, &server_pub, &stranger_seed).await;
    let (code, body) = present(&mut stranger, &h).await;
    assert_eq!(code, 403, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::NotYours);
    let mut forged = h.clone();
    forged.credentials[0] =
        Credential::issue(&third_seed, &alice, SCOPE_CHAT, now() - 60, now() + 100).unwrap();
    let (code, _) = present(&mut a, &forged).await;
    assert_eq!(
        code, 403,
        "a credential the successor did not sign got through"
    );
    let mut b = connect(addr, &server_pub, &bob_seed).await;
    let into_bob = handover(&alice_seed, &bob_seed, &[alice]);
    let (code, _) = present(&mut a, &into_bob).await;
    assert_eq!(code, 403, "an account was handed into another account");
    // Nothing above changed anything.
    assert_eq!(resolve(&mut b, "alice").await.account, alice);
    assert_eq!(home_of(&mut a, &alice).await.unwrap().home, here);

    // The handover, by Alice herself, keeping herself as a device.
    let (code, body) = present(&mut a, &h).await;
    assert_eq!(code, 200, "{}", common::said(&body));

    // The same connection acts for the successor now: its channels are the
    // successor's, and it is listed as the successor's device.
    let mines = mine(&mut a).await.unwrap();
    assert_eq!(mines.channels.len(), 1);
    assert_eq!(devices_of(&mut b, &new).await, vec![alice]);
    assert!(devices_of(&mut b, &alice).await.is_empty());
    // Name, seat, record.
    assert_eq!(resolve(&mut b, "alice").await.account, new);
    let entries = fetch_all(&mut b, channel).await.unwrap();
    let moved = entries
        .entries
        .iter()
        .filter(|e| e.kind == KIND_SYSTEM)
        .filter_map(|e| System::decode(&e.body).ok().flatten())
        .find(|s| s.event == EVENT_SUCCEEDED)
        .expect("no succeeded entry in the room");
    assert_eq!((moved.actor, moved.subject), (alice, new));
    let (code, body) = b.post("/account/succession", ask(&alice)).await.unwrap();
    assert_eq!(code, 200);
    let record = Succeeded::decode(&body).unwrap();
    assert_eq!(record.successor, new);
    assert!(record.proof.proves(&new));
    // The home record followed with its signature cleared: it still says
    // where the account lives, and asks for a fresh Move.
    let followed = home_of(&mut a, &new).await.unwrap();
    assert_eq!((followed.home, followed.since), (here, 0));
    assert!(home_of(&mut a, &alice).await.is_none());
    // Which the new key signs, and then it is whole.
    let (code, _) = a
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&new_seed, &here, now()),
                domain: "x.test".into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "a fresh Move was refused as stale");
    assert_ne!(home_of(&mut a, &new).await.unwrap().since, 0);

    // The device posts on, as the successor, on its own chain.
    let s = Signer::new(alice_seed, alice, server_pub).for_account(new);
    let info = s.info(&mut a, channel).await;
    let post = s.post_chained(&mut chain, channel, info.instance, 0, 1, b"after".to_vec());
    let (code, body) = a.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));

    // Once per key: Alice's key cannot hand over again; the new key can.
    let again = handover(&alice_seed, &third_seed, &[alice]);
    let (code, _) = present(&mut a, &again).await;
    assert_eq!(code, 403, "a key was succeeded twice");
    let onward = handover(&new_seed, &third_seed, &[alice]);
    let (code, body) = present(&mut a, &onward).await;
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(resolve(&mut b, "alice").await.account, third);
    assert_eq!(devices_of(&mut b, &third).await, vec![alice]);
    let (code, _) = a
        .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
        .await
        .unwrap();
    assert_eq!(code, 200, "the device lost the room on the second handover");
}

/// A copy of the room follows the handover from the log: the seat moves,
/// and what the copy held of the account under SIP-59 -- a Move naming
/// the origin as its home, so the copy served it as away -- follows the
/// key.
#[tokio::test]
async fn a_copy_follows_a_handover_from_the_log() {
    let x_dir = tempfile::tempdir().unwrap();
    let y_dir = tempfile::tempdir().unwrap();
    let y_key = key_in(y_dir.path());
    let (x_addr, x_pub) = server_in(x_dir.path(), &[y_key]).await;
    let x_key = PubKey::new(x_pub);
    let (alice_seed, alice) = identity(96);
    let (bob_seed, bob) = identity(97);
    let (new_seed, new) = identity(98);
    let channel = [96u8; 32];
    let (mut a, mut chain) = a_life(
        x_addr,
        x_pub,
        alice_seed,
        alice,
        bob_seed,
        bob,
        channel,
        Some(y_key),
    )
    .await;
    let (y_addr, y_pub) = replica_in(y_dir.path(), x_key, x_addr, channel).await;
    let mut at_y = connect(y_addr, &y_pub, &bob_seed).await;
    for _ in 0..50 {
        if fetch_all(&mut at_y, channel).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    // Y also holds Alice's Move, carried there by hand: she lives at X.
    let (code, _) = at_y
        .post(
            "/account/move",
            Moving {
                mv: Move::sign(&alice_seed, &x_key, now()),
                domain: "x.test".into(),
                origins: vec![],
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(home_of(&mut at_y, &alice).await.unwrap().home, x_key);

    let h = handover(&alice_seed, &new_seed, &[alice]);
    let (code, body) = present(&mut a, &h).await;
    assert_eq!(code, 200, "{}", common::said(&body));

    // The copy pulls the entry, verifies the will inside it, moves the
    // seat, and re-keys the Move it held.
    let mut followed = false;
    for _ in 0..50 {
        if let Some(h) = home_of(&mut at_y, &new).await
            && h.home == x_key
        {
            followed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        followed,
        "the copy did not re-key the account's home record"
    );
    assert_eq!(home_of(&mut at_y, &new).await.unwrap().since, 0);
    assert!(home_of(&mut at_y, &alice).await.is_none());
    let entries = fetch_all(&mut at_y, channel).await.unwrap();
    assert!(
        entries
            .entries
            .iter()
            .filter(|e| e.kind == KIND_SYSTEM)
            .filter_map(|e| System::decode(&e.body).ok().flatten())
            .any(|s| s.event == EVENT_SUCCEEDED && s.subject == new),
        "the copy holds no succeeded entry"
    );

    // The old key is a device of the new one now; what it posts as the
    // successor reaches the copy, bound to the account through the
    // origin's registry.
    let s = Signer::new(alice_seed, alice, x_pub).for_account(new);
    let info = s.info(&mut a, channel).await;
    let post = s.post_chained(
        &mut chain,
        channel,
        info.instance,
        0,
        1,
        b"as the new key".to_vec(),
    );
    let (code, body) = a.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let mut seen = false;
    for _ in 0..50 {
        let texts: Vec<String> = fetch_all(&mut at_y, channel)
            .await
            .unwrap()
            .entries
            .iter()
            .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
            .map(|e| String::from_utf8_lossy(&e.body).into_owned())
            .collect();
        if texts == ["before", "as the new key"] {
            seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(seen, "the copy refused the successor's post");
}
