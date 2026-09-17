//! SIP-59: an account moves home. Alice signs that B is her home, presents
//! it at B only; B carries it to X, pulls her private group from there, and
//! carries her posts back. A device she registers only at B posts through
//! B with its credential carried, and X registers it. At X, everything
//! that was the key's answers `moved`; a Move back reopens it.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_proto::channel::{ByChannel, Entries, Fetch, Invitee, Role, TYPE_INFO, Visibility};
use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqex_proto::device::{Devices, ListDevices, Register as DeviceRegister};
use sqex_proto::home::{Homed, Move, Moved, Moving};
use sqex_proto::mailbox::{self, Send as MailSend};
use sqex_proto::peer::{Carried, Forward, Forwarded, Mine, PullMine};
use sqex_proto::refusal::{Code, Refusal};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;
use crate::common::{Chain, Signer, instance_for};

/// An exchange whose peer list holds `peers`, with a finder that knows
/// `found`, pulling for its homed accounts every second.
async fn exchange_in(
    dir: &Path,
    peers: &[PubKey],
    found: &[(&str, PubKey, SocketAddr)],
) -> (SocketAddr, [u8; 32]) {
    let list = peers
        .iter()
        .map(|p| format!("{:?}", p.to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let key_path = dir.join("host_key");
    if !key_path.exists() {
        let (server_sk, _) = squic::generate_keypair();
        std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    }
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n\
         welcome_channel = \"\"\nreplication_peers = [{list}]\nhome_secs = 1\n\
         wake_loopback = true\n",
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

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

/// Write an exchange's host key ahead of starting it, so another exchange
/// can list it; returns the key and its seed (to act as the exchange).
fn key_in(dir: &Path) -> (PubKey, [u8; 32]) {
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(dir.join("host_key"), hex::encode(server_sk.to_bytes())).unwrap();
    let vk = ed25519_dalek::SigningKey::from_bytes(&server_sk.to_bytes()).verifying_key();
    (PubKey::new(vk.to_bytes()), server_sk.to_bytes())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn texts(c: &mut Client, channel: [u8; 32]) -> Vec<String> {
    let (code, body) = c
        .post(
            "/channel/fetch",
            Fetch {
                channel,
                since: 0,
                wait_secs: 0,
                receipts: true,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    Entries::decode(&body, true)
        .unwrap()
        .entries
        .iter()
        .filter(|e| e.kind == sqex_proto::channel::KIND_MEMBER)
        .map(|e| String::from_utf8_lossy(&e.body).into_owned())
        .collect()
}

async fn until<F: Fn(&[String]) -> bool>(c: &mut Client, channel: [u8; 32], ok: F) -> Vec<String> {
    for _ in 0..80 {
        let (code, _) = c
            .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
            .await
            .unwrap();
        if code == 200 {
            let t = texts(c, channel).await;
            if ok(&t) {
                return t;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
    panic!("the channel never showed what was expected");
}

async fn home_of(c: &mut Client, account: &PubKey) -> (u16, Option<Homed>) {
    let (code, body) = c
        .post("/account/home", account.as_bytes().to_vec())
        .await
        .unwrap();
    (code, (code == 200).then(|| Homed::decode(&body).unwrap()))
}

async fn present(c: &mut Client, moving: &Moving) -> (u16, Vec<u8>) {
    c.post("/account/move", moving.encode()).await.unwrap()
}

/// Alice and Bob in a group at X, with two messages in it. Public, so the
/// bodies read here without SIP-17's epoch machinery; the gate under test
/// does not care -- a peer pulls a public channel by the same rule -- and
/// the sealed case is `sqex-chat`'s `moving_flow`.
async fn group_at_x(
    x_addr: SocketAddr,
    x_pub: [u8; 32],
    alice_seed: [u8; 32],
    alice: PubKey,
    bob_seed: [u8; 32],
    bob: PubKey,
    channel: [u8; 32],
) -> (Client, Chain, Client, Chain) {
    let mut a = Client::connect_as(x_addr, &x_pub, &alice_seed)
        .await
        .unwrap();
    let sa = Signer::new(alice_seed, alice, x_pub);
    let mut ca = Chain::default();
    let req = sa.create_chained(
        &mut ca,
        channel,
        instance_for(channel, 0),
        Visibility::Public,
        3600,
        "room",
        vec![Invitee {
            account: bob,
            role: Role::Member,
        }],
    );
    let (code, body) = a.post("/channel/create", req.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let info = sa.info(&mut a, channel).await;
    let post = sa.post_chained(&mut ca, channel, info.instance, 0, 0, b"hello".to_vec());
    assert_eq!(a.post("/channel/post", post.encode()).await.unwrap().0, 200);

    let mut b = Client::connect_as(x_addr, &x_pub, &bob_seed).await.unwrap();
    let sb = Signer::new(bob_seed, bob, x_pub);
    let mut cb = Chain::default();
    let info = sb.info(&mut b, channel).await;
    let post = sb.post_chained(&mut cb, channel, info.instance, 0, 0, b"hi".to_vec());
    assert_eq!(b.post("/channel/post", post.encode()).await.unwrap().0, 200);
    (a, ca, b, cb)
}

/// Alice presents a Move at B only. B carries it to X and pulls her group;
/// she reads it at B and posts through B; Bob at X reads her post.
#[tokio::test]
async fn an_account_moves_and_its_private_group_follows() {
    let x_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let (b_key, b_seed) = key_in(b_dir.path());
    let (x_addr, x_pub) = exchange_in(x_dir.path(), &[b_key], &[]).await;
    let x_key = PubKey::new(x_pub);
    let (b_addr, b_pub) = exchange_in(b_dir.path(), &[x_key], &[("x.test", x_key, x_addr)]).await;
    assert_eq!(PubKey::new(b_pub), b_key);

    let (alice_seed, alice) = identity(231);
    let (bob_seed, bob) = identity(232);
    let channel = [231u8; 32];
    let (mut a, mut ca, mut b, _cb) =
        group_at_x(x_addr, x_pub, alice_seed, alice, bob_seed, bob, channel).await;
    assert_eq!(texts(&mut a, channel).await, ["hello", "hi"]);

    // Before any move X says Alice lives here, and B -- acting as itself
    // -- is refused her channels as any stranger is.
    let (code, homed) = home_of(&mut a, &alice).await;
    assert_eq!(code, 200);
    assert_eq!(homed.unwrap().home, x_key);
    let mut as_b = Client::connect_as(x_addr, &x_pub, &b_seed).await.unwrap();
    let (code, _) = as_b
        .post("/peer/mine", PullMine { account: alice }.encode())
        .await
        .unwrap();
    assert_eq!(code, 404, "a peer that is nobody's home was answered");
    let (code, _) = as_b
        .post(
            "/peer/pull",
            sqex_proto::peer::Pull {
                channel,
                since: 0,
                max: 10,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 404, "a peer that is nobody's home pulled a group");

    // The move, presented at B and nowhere else.
    let mv = Move::sign(&alice_seed, &b_key, now());
    let mut at_b = Client::connect_as(b_addr, &b_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = present(
        &mut at_b,
        &Moving {
            mv,
            domain: "b.test".into(),
            origins: vec![(x_key, "x.test".into())],
        },
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));
    assert!(Moved::decode(&body).unwrap().peered);

    // B pulled the group from X, under the Move it carried there.
    let got = until(&mut at_b, channel, |t| t.len() == 2).await;
    assert_eq!(got, ["hello", "hi"]);
    let (code, body) = as_b
        .post("/peer/mine", PullMine { account: alice }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(Mine::decode(&body).unwrap().channels, vec![channel]);
    let (_, homed) = home_of(&mut a, &alice).await;
    let homed = homed.unwrap();
    assert_eq!((homed.home, homed.domain.as_str()), (b_key, "b.test"));
    let (_, homed) = home_of(&mut at_b, &alice).await;
    assert_eq!(homed.unwrap().home, b_key);
    // Bob was never moved: X still says he is here, and B knows nothing.
    let (_, homed) = home_of(&mut a, &bob).await;
    assert_eq!(homed.unwrap().home, x_key);
    assert_eq!(home_of(&mut at_b, &bob).await.0, 404);

    // Alice posts at B, signing under X as SIP-43 has her; B carries it
    // and Bob reads it at X.
    let sa = Signer::new(alice_seed, alice, x_pub);
    let info = sa.info(&mut at_b, channel).await;
    let post = sa.post_chained(&mut ca, channel, info.instance, 0, 1, b"from b".to_vec());
    let (code, body) = at_b.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        until(&mut b, channel, |t| t.len() == 3).await,
        ["hello", "hi", "from b"]
    );
    assert_eq!(
        until(&mut at_b, channel, |t| t.len() == 3).await,
        ["hello", "hi", "from b"]
    );
}

/// A device Alice registers only at B posts through B; B carries its
/// credential and X registers it. Unwrapped, the same forward for a device
/// X never saw is refused.
#[tokio::test]
async fn a_device_the_origin_never_saw_is_carried_with_its_credential() {
    let x_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let (b_key, b_seed) = key_in(b_dir.path());
    let (x_addr, x_pub) = exchange_in(x_dir.path(), &[b_key], &[]).await;
    let x_key = PubKey::new(x_pub);
    let (b_addr, b_pub) = exchange_in(b_dir.path(), &[x_key], &[("x.test", x_key, x_addr)]).await;

    let (alice_seed, alice) = identity(233);
    let (bob_seed, bob) = identity(234);
    let (phone_seed, phone) = identity(235);
    let (laptop_seed, laptop) = identity(236);
    let channel = [233u8; 32];
    let (mut a, _ca, mut b, _cb) =
        group_at_x(x_addr, x_pub, alice_seed, alice, bob_seed, bob, channel).await;

    let mv = Move::sign(&alice_seed, &b_key, now());
    let mut at_b = Client::connect_as(b_addr, &b_pub, &alice_seed)
        .await
        .unwrap();
    let (code, _) = present(
        &mut at_b,
        &Moving {
            mv,
            domain: "b.test".into(),
            origins: vec![(x_key, "x.test".into())],
        },
    )
    .await;
    assert_eq!(code, 200);
    until(&mut at_b, channel, |t| t.len() == 2).await;

    // The phone registers at B and only at B.
    let n = now();
    let mut p = Client::connect_as(b_addr, &b_pub, &phone_seed)
        .await
        .unwrap();
    let credential = Credential::issue(&alice_seed, &phone, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let (code, _) = p
        .post("/device/register", DeviceRegister { credential }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (code, body) = a
        .post("/device/list", ListDevices { account: alice }.encode())
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert!(
        Devices::decode(&body).unwrap().devices.is_empty(),
        "X knew the phone before anything was carried"
    );

    // The phone posts at B. The forward reaches X wrapped, X registers the
    // phone from the credential and orders the post.
    let sp = Signer::new(phone_seed, phone, x_pub).for_account(alice);
    let mut cp = Chain::default();
    let info = sp.info(&mut p, channel).await;
    let post = sp.post_chained(
        &mut cp,
        channel,
        info.instance,
        0,
        0,
        b"from the phone".to_vec(),
    );
    let (code, body) = p.post("/channel/post", post.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    assert_eq!(
        until(&mut b, channel, |t| t.len() == 3).await,
        ["hello", "hi", "from the phone"]
    );
    // And the copy at B takes it back: SIP-31's step 2 at a copy asks the
    // origin's registry by the *account* the entry names, which is where
    // a linked device is listed. (Asked by the device key, it found
    // nothing, and every linked device's entry was refused at copies.)
    assert_eq!(
        until(&mut at_b, channel, |t| t.len() == 3).await,
        ["hello", "hi", "from the phone"]
    );
    let (_, body) = a
        .post("/device/list", ListDevices { account: alice }.encode())
        .await
        .unwrap();
    let listed = Devices::decode(&body).unwrap().devices;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].device, phone);
    assert!(listed[0].credential.is_some());

    // Control, at the wire: B's own forward for a laptop X never saw.
    // Bare, X resolves the laptop to nobody and refuses; wrapped in the
    // laptop's credential, X takes it.
    let mut as_b = Client::connect_as(x_addr, &x_pub, &b_seed).await.unwrap();
    let sl = Signer::new(laptop_seed, laptop, x_pub).for_account(alice);
    let mut cl = Chain::default();
    let post = sl.post_chained(
        &mut cl,
        channel,
        instance_for(channel, 0),
        0,
        0,
        b"laptop".to_vec(),
    );
    let bare = Forward {
        device: laptop,
        post: post.clone(),
    };
    let (code, body) = as_b.post("/peer/forward", bare.encode()).await.unwrap();
    let taken = code == 200
        && Forwarded::decode(&body)
            .map(|f| f.status == 200)
            .unwrap_or(false);
    assert!(!taken, "a bare forward for an unknown device was ordered");
    let credential = Credential::issue(&alice_seed, &laptop, SCOPE_CHAT, n - 1, n + 3600).unwrap();
    let wrapped = Carried {
        credential,
        inner: bare.encode(),
    };
    let (code, body) = as_b.post("/peer/forward", wrapped.encode()).await.unwrap();
    assert_eq!(code, 200, "{}", common::said(&body));
    let forwarded = Forwarded::decode(&body).unwrap();
    assert_eq!(forwarded.status, 200, "{}", common::said(&forwarded.body));
    assert_eq!(
        until(&mut b, channel, |t| t.len() == 4).await,
        ["hello", "hi", "from the phone", "laptop"]
    );
    // A credential naming a different device than the forward's is not
    // evidence about the forward's device.
    let mut cl2 = Chain { ..cl };
    let post = sl.post_chained(
        &mut cl2,
        channel,
        instance_for(channel, 0),
        0,
        1,
        b"again".to_vec(),
    );
    let wrong = Carried {
        credential: Credential::issue(&alice_seed, &phone, SCOPE_CHAT, n - 1, n + 3600).unwrap(),
        inner: Forward {
            device: laptop,
            post,
        }
        .encode(),
    };
    let (code, _) = as_b.post("/peer/forward", wrong.encode()).await.unwrap();
    assert_eq!(
        code, 404,
        "a forward carried under another device's credential got through"
    );
}

/// At a former home, the key's services answer `moved` naming the home; a
/// stale or forged Move changes nothing; a Move back reopens everything.
#[tokio::test]
async fn a_former_home_hands_off_the_keys_services_and_a_move_back_reopens_them() {
    let x_dir = tempfile::tempdir().unwrap();
    let (_, b_key) = identity(240);
    let (x_addr, x_pub) = exchange_in(x_dir.path(), &[b_key], &[]).await;
    let x_key = PubKey::new(x_pub);
    let (alice_seed, alice) = identity(241);
    let (bob_seed, bob) = identity(242);
    let (nobody_seed, nobody) = identity(243);
    let channel = [241u8; 32];
    let (mut a, _ca, mut b, _cb) =
        group_at_x(x_addr, x_pub, alice_seed, alice, bob_seed, bob, channel).await;

    // An account X knows nothing of has no home here.
    assert_eq!(home_of(&mut a, &nobody).await.0, 404);

    let issued = now();
    let mv = Move::sign(&alice_seed, &b_key, issued);
    let (code, body) = present(
        &mut a,
        &Moving {
            mv,
            domain: "b.test".into(),
            origins: vec![],
        },
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let moved = Moved::decode(&body).unwrap();
    assert!(moved.peered, "B is on X's peer list and X said it is not");

    let expect_moved = |code: u16, body: &[u8], what: &str| {
        assert_eq!(code, 403, "{what}: {}", common::said(body));
        let r = Refusal::decode(body).unwrap();
        assert_eq!(r.code, Code::Moved, "{what}");
        assert_eq!(
            r.detail.as_deref(),
            Some(format!("{b_key} b.test").as_str()),
            "{what}"
        );
    };
    // A sender's routes name the home.
    let sealed = mailbox::seal(&alice, b"for alice").unwrap();
    let (code, body) = b
        .post(
            "/mailbox/send",
            MailSend {
                recipient: alice,
                sealed: sealed.clone(),
            }
            .encode(),
        )
        .await
        .unwrap();
    expect_moved(code, &body, "mailbox send");
    // SIP-60: a prekey is not refused but taken at the home and handed on;
    // here the home is not running, so the answer is "none", and never a
    // prekey from a pool at the wrong exchange.
    let (code, body) = b
        .post(
            "/prekey/take",
            sqex_proto::prekey::Take { device: alice }.encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 404, "prekey take: {}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::NoPrekey);
    let (code, body) = b
        .post(
            "/resolve/get",
            sqex_proto::resolve::Resolve { key: alice }.encode(),
        )
        .await
        .unwrap();
    expect_moved(code, &body, "resolve get");
    // And the account's own writes here.
    let (code, body) = a
        .post(
            "/wake/register",
            sqex_proto::wake::Register {
                ttl: 3600,
                endpoint: "http://127.0.0.1:1/up".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    expect_moved(code, &body, "wake register");
    // But not Bob's: he never moved.
    let (code, _) = a
        .post(
            "/mailbox/send",
            MailSend {
                recipient: bob,
                sealed: mailbox::seal(&bob, b"for bob").unwrap(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    // And her channel is still served to her here.
    assert_eq!(texts(&mut a, channel).await, ["hello", "hi"]);

    // Stale: not later than the one on record. Forged: does not verify.
    let stale = Move::sign(&alice_seed, &x_key, issued);
    let (code, body) = present(
        &mut a,
        &Moving {
            mv: stale,
            domain: String::new(),
            origins: vec![],
        },
    )
    .await;
    assert_eq!(code, 409, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::StaleGeneration);
    let mut forged = Move::sign(&nobody_seed, &x_key, issued + 5);
    forged.account = alice;
    let (code, body) = present(
        &mut a,
        &Moving {
            mv: forged,
            domain: String::new(),
            origins: vec![],
        },
    )
    .await;
    assert_eq!(code, 403, "{}", common::said(&body));
    assert_eq!(Refusal::decode(&body).unwrap().code, Code::BadSignature);
    let (_, homed) = home_of(&mut a, &alice).await;
    assert_eq!(
        homed.unwrap().home,
        b_key,
        "a refused Move changed the record"
    );

    // Back, by a later Move naming X; presented by Bob, who carries it,
    // because who carries a Move is not what makes it good.
    let back = Move::sign(&alice_seed, &x_key, issued + 1);
    let (code, body) = present(
        &mut b,
        &Moving {
            mv: back,
            domain: String::new(),
            origins: vec![],
        },
    )
    .await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let (_, homed) = home_of(&mut a, &alice).await;
    let homed = homed.unwrap();
    assert_eq!((homed.home, homed.since), (x_key, issued + 1));
    let (code, _) = b
        .post(
            "/mailbox/send",
            MailSend {
                recipient: alice,
                sealed,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200, "a mailbox that should have reopened did not");
    let (code, _) = a
        .post(
            "/wake/register",
            sqex_proto::wake::Register {
                ttl: 3600,
                endpoint: "http://127.0.0.1:1/up".into(),
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
}
