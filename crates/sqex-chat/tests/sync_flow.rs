//! SIP-42: two devices of one account hand each other the history they hold,
//! through a real exchange that relays the session and cannot read it.
//!
//! The controls are the point. A sibling is the wire and nothing more: the
//! importing device keeps what verifies by the entries' own signatures and
//! the exchange's receipts, and refuses what does not, however honestly it
//! was handed over -- and a stranger, a forged credential, or a device the
//! account revoked never gets past `Hello`.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use sqex_chat::client::Chat;
use sqex_chat::store::Store;
use sqex_chat::sync::{Link, Message, Phase, Relayed, Sync};
use sqex_proto::channel::Entry;
use sqex_proto::session::Session;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;
use x25519_dalek::StaticSecret;

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
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

fn said(timeline: &Timeline) -> Vec<String> {
    timeline
        .messages()
        .filter(|m| m.is_visible())
        .filter_map(|m| m.post.body_text().map(|t| t.to_string()))
        .collect()
}

/// Link a second device to `owner`'s account, as `dm_flow` does; the
/// owner registers itself first so it is not sealed out of its own account.
async fn link_device(
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
        let own = owner
            .issue_credential(&owner.me, 90 * 24 * 60 * 60)
            .unwrap();
        owner.register_self(&own).await.unwrap();
    }
    let credential = owner
        .issue_credential(&second.device(), 90 * 24 * 60 * 60)
        .unwrap();
    second.register_self(&credential).await.unwrap();
    second.top_up_prekeys().await.unwrap();
    let client = Client::connect_as(addr, &server_pub, &identity(b).0)
        .await
        .unwrap();
    let store = Store::open(&identity(b).0, Some(store)).unwrap();
    let mut second = Chat::new(
        client,
        identity(b).0,
        identity(b).1,
        PubKey::new(server_pub),
        store,
    );
    second.top_up_prekeys().await.unwrap();
    second
}

/// A session loop is a spawned task, so what it awaits must be `Send`.
/// `Chat` is not `Sync`, and a future holding `&Chat` across an await is
/// exactly what sigil's loop cannot hold. Checked here, where the
/// signature lives, rather than found in the consumer.
fn assert_send<T: Send>(t: T) -> T {
    t
}

/// Both devices open toward each other until the exchange has them met.
async fn meet(a: &Chat, b: &Chat) -> ((Relayed, Session), (Relayed, Session)) {
    let ea = StaticSecret::random_from_rng(rand_core::OsRng);
    let eb = StaticSecret::random_from_rng(rand_core::OsRng);
    for _ in 0..100 {
        let ra = assert_send(a.meet_sibling(&ea, &b.device())).await.unwrap();
        let rb = b.meet_sibling(&eb, &a.device()).await.unwrap();
        if let (Some(x), Some(y)) = (ra, rb) {
            return (x, y);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the two devices never met");
}

/// Run both sides step by step until neither has anything left to do.
async fn run_both(a: &mut Chat, b: &mut Chat) -> (Sync, Sync) {
    let ((mut la, sa), (mut lb, sb)) = meet(a, b).await;
    let mut xa = Sync::new(sa, b.device());
    let mut xb = Sync::new(sb, a.device());
    let over = |p: Phase| matches!(p, Phase::Finished | Phase::Failed);
    // As a client would: step while there is something to do, close the
    // session once this side is done, and take the link ending as the end.
    for _ in 0..2000 {
        if !over(xa.phase()) && !assert_send(xa.step(a, &mut la)).await.unwrap_or(false) {
            la.close().await;
        }
        if !over(xb.phase()) && !xb.step(b, &mut lb).await.unwrap_or(false) {
            lb.close().await;
        }
        if over(xa.phase()) && over(xb.phase()) {
            return (xa, xb);
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!(
        "the sync did not finish: {:?} / {:?}",
        xa.phase(),
        xb.phase()
    );
}

/// A phone that has read a conversation, and a laptop just linked to the
/// same account with nothing on it.
async fn phone_and_laptop(dir: &Path) -> (SocketAddr, [u8; 32], Chat, Chat, Chat, [u8; 32]) {
    let (addr, server_pub, _h) = server_in(dir).await;
    std::mem::forget(_h);
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);
    let mut bob = chat_at(addr, server_pub, 2, &dir.join("bob.db")).await;
    let mut phone = chat_at(addr, server_pub, 1, &dir.join("phone.db")).await;

    let channel = phone.open_dm(&bob_key).await.unwrap();
    phone.send(&channel, "one").await.unwrap();
    bob.open_dm(&alice_key).await.unwrap();
    bob.send(&channel, "two").await.unwrap();
    phone.send(&channel, "three").await.unwrap();
    let mut t = Timeline::new();
    let got = phone.poll(&channel, &mut t, 0).await.unwrap();
    assert_eq!(said(&got.timeline), vec!["one", "two", "three"]);
    assert!(
        phone.store().entry_count(&channel).unwrap() >= 3,
        "the phone kept no signed entries to hand on"
    );

    let laptop = link_device(addr, server_pub, &mut phone, 7, &dir.join("laptop.db")).await;
    assert_eq!(laptop.store().entry_count(&channel).unwrap(), 0);
    (addr, server_pub, phone, laptop, bob, channel)
}

#[tokio::test]
async fn a_new_device_gets_the_history_its_sibling_holds() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, mut phone, mut laptop, _bob, channel) = phone_and_laptop(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    // The exchange forgets all but its newest entry, and the laptop reads
    // that one from it: the top of the channel and nothing below. What
    // follows can only have come from the phone.
    phone
        .set_retention(&channel, sqex_proto::channel::MIN_RETENTION, 1)
        .await
        .unwrap();
    let mut t = Timeline::new();
    let _ = laptop.poll(&channel, &mut t, 0).await;
    let mut t = Timeline::new();
    let _ = phone.poll(&channel, &mut t, 0).await;
    assert_eq!(
        laptop.store().highest_entry(&channel).unwrap(),
        phone.store().highest_entry(&channel).unwrap()
    );
    assert_eq!(laptop.store().entry_count(&channel).unwrap(), 1);
    let cursor = laptop.store().cursor(&channel).unwrap();

    // Nobody resealed to the laptop: the key comes with the history.
    let (xp, xl) = run_both(&mut phone, &mut laptop).await;
    assert_eq!(xp.phase(), Phase::Finished, "{:?}", xp.why);
    assert_eq!(xl.phase(), Phase::Finished, "{:?}", xl.why);
    assert!(xl.progress.entries_in >= 3, "{:?}", xl.progress);
    assert_eq!(xl.progress.messages_in, 3, "{:?}", xl.progress);
    assert!(xl.progress.keys_in >= 1, "{:?}", xl.progress);
    assert_eq!(xp.progress.entries_in, 0, "the phone had nothing to learn");
    // Served from the bottom, since the laptop's copy started above the
    // phone's: the one entry it already held went over and was not kept
    // twice.
    assert_eq!(xp.progress.entries_out, xl.progress.entries_in + 1);

    // The laptop holds the signed entries, the key, and can read the
    // conversation from its own store -- which the exchange no longer has.
    assert_eq!(
        laptop.store().entry_count(&channel).unwrap(),
        phone.store().entry_count(&channel).unwrap()
    );
    assert!(!laptop.store().keys_of(&channel).unwrap().is_empty());
    let history = laptop.history(&channel, &[alice_key, bob_key]).unwrap();
    assert_eq!(said(&history), vec!["one", "two", "three"]);

    // And the cursor did not move: the sibling is not the exchange.
    assert_eq!(laptop.store().cursor(&channel).unwrap(), cursor);

    // A second sync has nothing to carry.
    let (xp, xl) = run_both(&mut phone, &mut laptop).await;
    assert_eq!((xp.phase(), xl.phase()), (Phase::Finished, Phase::Finished));
    assert_eq!(xl.progress.entries_in, 0);
    assert_eq!(xp.progress.entries_out, 0);
}

#[tokio::test]
async fn history_flows_both_ways_and_a_sync_can_be_resumed() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, mut phone, mut laptop, mut bob, channel) = phone_and_laptop(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    // Get the laptop going, then let it read further than the phone.
    run_both(&mut phone, &mut laptop).await;
    bob.send(&channel, "four").await.unwrap();
    let mut t = Timeline::new();
    laptop.poll(&channel, &mut t, 0).await.unwrap();
    assert!(
        laptop.store().highest_entry(&channel).unwrap()
            > phone.store().highest_entry(&channel).unwrap()
    );

    // This time the phone is the one that learns.
    let (xp, xl) = run_both(&mut phone, &mut laptop).await;
    assert_eq!((xp.phase(), xl.phase()), (Phase::Finished, Phase::Finished));
    assert_eq!(
        xp.progress.entries_in, 1,
        "{:?} / laptop {:?}",
        xp.progress, xl.progress
    );
    assert_eq!(xl.progress.entries_in, 0);
    let history = phone.history(&channel, &[alice_key, bob_key]).unwrap();
    assert_eq!(said(&history), vec!["one", "two", "three", "four"]);
}

#[tokio::test]
async fn a_file_travels_with_the_message_that_names_it() {
    use sqex_proto::message::{Part, Post as SipPost};
    let dir = tempfile::tempdir().unwrap();
    let (_, _, mut phone, mut laptop, _bob, channel) = phone_and_laptop(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, bob_key) = identity(2);

    let path = dir.path().join("notes.md");
    let secret: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &secret).unwrap();
    let limits = phone.blob_limits().await.unwrap();
    let prepared = phone.prepare_file(&path, limits.chunk as usize).unwrap();
    let attachment = phone.upload(&channel, &prepared).await.unwrap();
    let blob = attachment.blob;
    let mut post = SipPost::text("the notes");
    post.parts.push(Part::Attachment(attachment));
    phone.send_post(&channel, post).await.unwrap();
    let mut t = Timeline::new();
    phone.poll(&channel, &mut t, 0).await.unwrap();
    assert!(phone.store().has_blob(&blob).unwrap());

    let (_, xl) = run_both(&mut phone, &mut laptop).await;
    assert_eq!(xl.phase(), Phase::Finished, "{:?}", xl.why);
    assert_eq!(xl.progress.blobs_in, 1, "{:?}", xl.progress);
    assert!(laptop.store().has_blob(&blob).unwrap());
    let history = laptop.history(&channel, &[alice_key, bob_key]).unwrap();
    let last = history.messages().last().unwrap();
    assert_eq!(last.post.body_text(), Some("the notes"));
    let a = last.post.attachments().next().unwrap();
    // Opened from the local copy alone.
    assert_eq!(laptop.download(a).await.unwrap(), secret);
}

#[tokio::test]
async fn a_revoked_device_is_not_a_sibling_any_more() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, mut phone, mut laptop, _bob, channel) = phone_and_laptop(dir.path()).await;
    phone.revoke_device(&laptop.device()).await.unwrap();

    let (xp, xl) = run_both(&mut phone, &mut laptop).await;
    assert_eq!(xp.phase(), Phase::Failed);
    assert!(
        xp.why.as_deref().unwrap_or("").contains("no longer lists"),
        "{:?}",
        xp.why
    );
    assert_eq!(xl.phase(), Phase::Failed, "{:?}", xl.why);
    assert_eq!(laptop.store().entry_count(&channel).unwrap(), 0);
    assert!(laptop.store().keys_of(&channel).unwrap().is_empty());
}

/// An in-memory link: what one side sends the other receives, sealed as
/// [`Sync`] sealed it. For driving one side by hand.
type Frames = Arc<Mutex<VecDeque<(u64, Vec<u8>)>>>;

#[derive(Clone, Default)]
struct Pipe {
    to_them: Frames,
    from_them: Frames,
}

impl Pipe {
    fn pair() -> (Pipe, Pipe) {
        let a = Pipe::default();
        let b = Pipe {
            to_them: a.from_them.clone(),
            from_them: a.to_them.clone(),
        };
        (a, b)
    }
}

impl Link for Pipe {
    async fn send(&mut self, seq: u64, sealed: &[u8]) -> Result<bool, sqex_chat::ChatError> {
        self.to_them
            .lock()
            .unwrap()
            .push_back((seq, sealed.to_vec()));
        Ok(true)
    }
    async fn recv(&mut self) -> Result<Vec<(u64, Vec<u8>)>, sqex_chat::ChatError> {
        Ok(self.from_them.lock().unwrap().drain(..).collect())
    }
}

/// The far side, driven by hand: a courier holding a session key.
struct Courier {
    session: Session,
    pipe: Pipe,
    seq: u64,
    inbox: Vec<u8>,
}

impl Courier {
    fn say(&mut self, m: &Message) {
        let body = m.encode();
        let mut stream = (body.len() as u32).to_be_bytes().to_vec();
        stream.extend_from_slice(&body);
        for piece in stream.chunks(32 * 1024 - 64) {
            let sealed = self.session.seal(self.seq, piece).unwrap();
            self.pipe
                .to_them
                .lock()
                .unwrap()
                .push_back((self.seq, sealed));
            self.seq += 1;
        }
    }
    fn heard(&mut self) -> Vec<Message> {
        let frames: Vec<_> = self.pipe.from_them.lock().unwrap().drain(..).collect();
        for (seq, sealed) in frames {
            self.inbox
                .extend_from_slice(&self.session.open(seq, &sealed).unwrap());
        }
        let mut out = Vec::new();
        while self.inbox.len() >= 4 {
            let len = u32::from_be_bytes(self.inbox[..4].try_into().unwrap()) as usize;
            if self.inbox.len() < 4 + len {
                break;
            }
            let rest = self.inbox.split_off(4 + len);
            let body = std::mem::replace(&mut self.inbox, rest);
            out.push(Message::decode(&body[4..]).unwrap());
        }
        out
    }
}

/// Two session keys for a pair of identities, as the exchange would have
/// them derive, without an exchange.
fn sessions(a: u8, b: u8) -> (Session, Session) {
    let ea = StaticSecret::random_from_rng(rand_core::OsRng);
    let eb = StaticSecret::random_from_rng(rand_core::OsRng);
    let pa = x25519_dalek::PublicKey::from(&ea).to_bytes();
    let pb = x25519_dalek::PublicKey::from(&eb).to_bytes();
    let sa = Session::derive(&identity(a).0, &ea, &identity(b).1, &pb).unwrap();
    let sb = Session::derive(&identity(b).0, &eb, &identity(a).1, &pa).unwrap();
    (sa, sb)
}

/// Step the laptop's side until it settles, feeding the courier's answers.
async fn drive<F: FnMut(&mut Courier, Vec<Message>)>(
    laptop: &mut Chat,
    x: &mut Sync,
    pipe: &mut Pipe,
    courier: &mut Courier,
    mut answer: F,
) {
    for _ in 0..50 {
        let more = x.step(laptop, pipe).await.unwrap();
        let heard = courier.heard();
        answer(courier, heard);
        if !more {
            return;
        }
    }
    panic!("did not settle: {:?} {:?}", x.phase(), x.why);
}

#[tokio::test]
async fn a_tampered_entry_is_refused_and_the_rest_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, phone, mut laptop, _bob, channel) = phone_and_laptop(dir.path()).await;
    let (_, alice_key) = identity(1);

    // The courier is the phone's key -- the account itself, which needs no
    // credential -- holding the phone's real entries and key, and it alters
    // one entry's body on the way.
    let (s_phone, s_laptop) = sessions(1, 7);
    let (mut pipe_laptop, pipe_phone) = Pipe::pair();
    let mut courier = Courier {
        session: s_phone,
        pipe: pipe_phone,
        seq: 0,
        inbox: Vec::new(),
    };
    let raw = phone.store().entries_after(&channel, 0, 256).unwrap();
    let mut entries: Vec<Entry> = raw
        .iter()
        .map(|(_, b)| Entry::read_receipted(b, &mut 0).unwrap())
        .collect();
    let total = entries.len();
    assert!(total >= 3);
    let victim = entries
        .iter_mut()
        .find(|e| e.kind == 1 && !e.body.is_empty())
        .unwrap();
    victim.body[0] ^= 0xff;
    let instance = phone.store().incarnation(&channel).unwrap().unwrap();
    let keys: Vec<(u32, [u8; 32])> = phone
        .store()
        .keys_of(&channel)
        .unwrap()
        .into_iter()
        .map(|(e, k)| (e, *k.as_bytes()))
        .collect();

    let mut x = Sync::new(s_laptop, alice_key);
    drive(
        &mut laptop,
        &mut x,
        &mut pipe_laptop,
        &mut courier,
        |c, heard| {
            for m in heard {
                match m {
                    Message::Hello { .. } => {
                        c.say(&Message::Hello {
                            account: alice_key,
                            credential: None,
                        });
                        c.say(&Message::Have(vec![sqex_chat::sync::Held {
                            channel,
                            instance,
                            first: 1,
                            last: total as u64,
                            epochs: keys.len() as u16,
                        }]));
                    }
                    Message::Have(_) => c.say(&Message::Want(vec![])),
                    Message::Want(w) => {
                        assert_eq!(w.len(), 1, "the laptop wanted {w:?}");
                        c.say(&Message::Keys {
                            channel,
                            keys: keys.clone(),
                        });
                        c.say(&Message::Entries {
                            channel,
                            instance,
                            entries: entries.clone(),
                        });
                        c.say(&Message::Done);
                    }
                    _ => {}
                }
            }
        },
    )
    .await;
    assert_eq!(x.phase(), Phase::Finished, "{:?}", x.why);
    assert_eq!(x.progress.entries_in, total - 1, "{:?}", x.progress);
    assert_eq!(
        laptop.store().entry_count(&channel).unwrap() as usize,
        total - 1,
        "the altered entry was kept"
    );
}

#[tokio::test]
async fn an_entry_without_the_exchanges_receipt_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, phone, mut laptop, _bob, channel) = phone_and_laptop(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (s_phone, s_laptop) = sessions(1, 7);
    let (mut pipe_laptop, pipe_phone) = Pipe::pair();
    let mut courier = Courier {
        session: s_phone,
        pipe: pipe_phone,
        seq: 0,
        inbox: Vec::new(),
    };
    let raw = phone.store().entries_after(&channel, 0, 256).unwrap();
    let mut entries: Vec<Entry> = raw
        .iter()
        .map(|(_, b)| Entry::read_receipted(b, &mut 0).unwrap())
        .collect();
    let total = entries.len();
    // Well-signed by their authors; the exchange's word forged on one. (An
    // entry with no receipt at all has no wire form here: `Entries` carries
    // SIP-35's receipted entry, so it cannot even be offered.)
    if let Some(stamp) = entries[1].stamp.as_mut() {
        stamp.receipt[0] ^= 0xff;
    }
    let instance = phone.store().incarnation(&channel).unwrap().unwrap();
    let mut x = Sync::new(s_laptop, alice_key);
    drive(
        &mut laptop,
        &mut x,
        &mut pipe_laptop,
        &mut courier,
        |c, heard| {
            for m in heard {
                match m {
                    Message::Hello { .. } => {
                        c.say(&Message::Hello {
                            account: alice_key,
                            credential: None,
                        });
                        c.say(&Message::Have(vec![sqex_chat::sync::Held {
                            channel,
                            instance,
                            first: 1,
                            last: total as u64,
                            epochs: 0,
                        }]));
                    }
                    Message::Have(_) => c.say(&Message::Want(vec![])),
                    Message::Want(_) => {
                        c.say(&Message::Entries {
                            channel,
                            instance,
                            entries: entries.clone(),
                        });
                        c.say(&Message::Done);
                    }
                    _ => {}
                }
            }
        },
    )
    .await;
    assert_eq!(x.phase(), Phase::Finished, "{:?}", x.why);
    assert_eq!(x.progress.entries_in, total - 1, "{:?}", x.progress);
    assert_eq!(
        laptop.store().entry_count(&channel).unwrap() as usize,
        total - 1
    );
}

#[tokio::test]
async fn nobody_but_a_sibling_gets_past_hello() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, mut phone, _laptop, _bob, _channel) = phone_and_laptop(dir.path()).await;
    let (_, alice_key) = identity(1);
    let (_, carol_key) = identity(3);
    let carol_seed = identity(3).0;

    // Three ways in, each refused before a `Have` is sent.
    let attempts: Vec<(&str, Message, &str)> = vec![
        (
            "another account",
            Message::Hello {
                account: carol_key,
                credential: None,
            },
            "not this account",
        ),
        (
            "our account, no credential, not the account key",
            Message::Hello {
                account: alice_key,
                credential: None,
            },
            "not the account itself",
        ),
        (
            "our account, a credential carol signed herself",
            Message::Hello {
                account: alice_key,
                credential: Some({
                    let mut c = sqex_proto::credential::Credential::issue(
                        &carol_seed,
                        &carol_key,
                        sqex_proto::credential::SCOPE_CHAT,
                        0,
                        u64::MAX / 2,
                    )
                    .unwrap();
                    c.account = alice_key;
                    c
                }),
            },
            "does not verify",
        ),
    ];
    for (what, hello, expect) in attempts {
        let (s_carol, s_phone) = sessions(3, 1);
        let (mut pipe_phone, pipe_carol) = Pipe::pair();
        let mut courier = Courier {
            session: s_carol,
            pipe: pipe_carol,
            seq: 0,
            inbox: Vec::new(),
        };
        let mut x = Sync::new(s_phone, carol_key);
        let mut have_seen = false;
        drive(
            &mut phone,
            &mut x,
            &mut pipe_phone,
            &mut courier,
            |c, heard| {
                for m in heard {
                    match m {
                        Message::Hello { .. } => c.say(&hello),
                        Message::Have(_) => have_seen = true,
                        _ => {}
                    }
                }
            },
        )
        .await;
        assert_eq!(x.phase(), Phase::Failed, "{what}: {:?}", x.why);
        assert!(
            x.why.as_deref().unwrap().contains(expect),
            "{what}: {:?}",
            x.why
        );
        assert!(!have_seen, "{what}: the phone said what it holds");
    }
}
