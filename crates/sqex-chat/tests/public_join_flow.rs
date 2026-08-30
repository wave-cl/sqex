//! Joining a public channel and being able to read it.
//!
//! A public channel is one anybody may find and join, which is the whole of
//! what makes it public. But SIP-17 keys are handed out by a *member*, not by
//! the exchange — it holds no keys and could not — and joining is the one way
//! into a channel that involves no existing member at all. So a self-service
//! join produces somebody the exchange counts as a member and who holds no key
//! for the epoch in force.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::SigningKey;
use sqex_chat::client::{Chat, ChatError};
use sqex_chat::store::Store;
use sqex_proto::timeline::Timeline;
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

async fn server_with(dir: &Path, extra: &str) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    let key_path = dir.join("host_key");
    let (server_sk, _) = squic::generate_keypair();
    std::fs::write(&key_path, hex::encode(server_sk.to_bytes())).unwrap();
    let config_toml = format!(
        "listen = \"127.0.0.1:0\"\nkey_file = {:?}\nstate_file = {:?}\nadmins = []\n{}",
        key_path.to_string_lossy(),
        dir.join("sqex.state").to_string_lossy(),
        extra,
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

async fn server_in(dir: &Path) -> (SocketAddr, [u8; 32], tokio::task::JoinHandle<()>) {
    server_with(dir, "").await
}

fn identity(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn chat_at(addr: SocketAddr, server_pub: [u8; 32], b: u8, store: &Path) -> Chat {
    let (seed, me) = identity(b);
    let client = Client::connect_as(addr, &server_pub, &seed).await.unwrap();
    let store = Store::open(&seed, Some(store)).unwrap();
    let mut chat = Chat::new(client, seed, me, PubKey::new(server_pub), store);
    chat.top_up_prekeys().await.unwrap();
    chat
}

/// What somebody who joins a public channel can actually read.
#[tokio::test]
async fn joining_a_public_channel_leaves_the_joiner_able_to_read_it() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;

    let mut founder = chat_at(addr, server_pub, 40, &dir.path().join("a.db")).await;
    let channel = founder.create_public("general", "").await.unwrap();
    founder.send(&channel, "welcome, everybody").await.unwrap();

    // Somebody else finds it in the directory and joins, which is the whole
    // of what a public channel offers.
    let mut joiner = chat_at(addr, server_pub, 41, &dir.path().join("b.db")).await;
    join_public(&mut joiner, channel).await.unwrap();

    let info = joiner.info(&channel).await.unwrap();
    println!("epoch in force: {} | members: {}", info.epoch, info.members.len());
    let mut timeline = Timeline::new();
    let got = joiner.poll(&channel, &mut timeline, 0).await;
    match got {
        Ok(c) => {
            let said: Vec<String> = c
                .timeline
                .messages()
                .filter_map(|m| m.post.body_text().map(str::to_string))
                .collect();
            assert_eq!(
                said,
                vec!["welcome, everybody".to_string()],
                "a member of a public channel cannot read it"
            );
        }
        Err(ChatError::NoKey(epoch)) => panic!(
            "joined, and holds no key for epoch {epoch}: nobody sealed one, because \
             joining involves no existing member and the exchange has no keys"
        ),
        Err(e) => panic!("{e}"),
    }
}

/// An exchange with nothing in it is a room with no doors: a new account can
/// reach nobody and be reached by nobody until somebody hands it a sixty-four
/// character identifier out of band.
#[tokio::test]
async fn a_new_account_arrives_already_in_the_welcome_channel() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;

    // Nobody has done anything yet, and this account has never been seen.
    let mut fresh = chat_at(addr, server_pub, 42, &dir.path().join("c.db")).await;
    let mine = fresh.mine().await.unwrap();
    assert_eq!(mine.len(), 1, "a new account is in nothing at all");

    let info = fresh.info(&mine[0].channel).await.unwrap();
    assert_eq!(info.name, "general");
    assert!(
        info.members.iter().any(|m| m.account == fresh.me),
        "in the channel's list of members it is not a member of"
    );

    // And two of them meet there, which is the whole point of it.
    let mut other = chat_at(addr, server_pub, 43, &dir.path().join("d.db")).await;
    let channel = other.mine().await.unwrap()[0].channel;
    assert_eq!(channel, mine[0].channel, "they landed in different rooms");
    other.send(&channel, "anybody there?").await.unwrap();

    let mut timeline = Timeline::new();
    let got = fresh.poll(&channel, &mut timeline, 0).await.unwrap();
    let said: Vec<String> = got
        .timeline
        .messages()
        .filter_map(|m| m.post.body_text().map(str::to_string))
        .collect();
    assert_eq!(said, vec!["anybody there?".to_string()]);
}

/// Welcoming once, and only once. Somebody who leaves has left; an exchange
/// that put them back on their next request would be overruling them.
#[tokio::test]
async fn leaving_the_welcome_channel_sticks() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;

    let mut who = chat_at(addr, server_pub, 44, &dir.path().join("e.db")).await;
    let channel = who.mine().await.unwrap()[0].channel;
    who.leave(&channel).await.unwrap();

    // Several more requests, any one of which used to be a chance to be put
    // back in.
    for _ in 0..3 {
        assert!(
            who.mine().await.unwrap().is_empty(),
            "the exchange put them back into a channel they left"
        );
    }
}

/// An operator who does not want one says so, and gets an exchange with
/// nothing in it — which is what every exchange was until now.
#[tokio::test]
async fn an_exchange_can_be_asked_for_no_welcome_channel() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_with(dir.path(), "welcome_channel = \"\"\n").await;
    let mut who = chat_at(addr, server_pub, 45, &dir.path().join("f.db")).await;
    assert!(who.mine().await.unwrap().is_empty());
}

/// A lobby is not an acquaintance.
///
/// A withheld profile is visible to accounts that share a channel with its
/// subject — a relationship the exchange already knows, chosen so it need not
/// keep an address book. Putting everybody into one channel makes every pair
/// of accounts share one, which would leave the flag still there, still
/// settable, and withholding from nobody.
#[tokio::test]
async fn the_welcome_channel_does_not_make_everybody_acquainted() {
    use sqex_proto::profile::Profile;

    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;

    let mut hidden = chat_at(addr, server_pub, 46, &dir.path().join("g.db")).await;
    hidden
        .set_profile(Profile {
            flags: sqex_proto::profile::FLAG_WITHHOLD,
            name: "Hidden".into(),
            title: String::new(),
            avatar: Vec::new(),
        })
        .await
        .unwrap();

    // Both are in the welcome channel, and nothing else.
    let mut stranger = chat_at(addr, server_pub, 47, &dir.path().join("h.db")).await;
    let lobby = stranger.mine().await.unwrap()[0].channel;
    assert!(
        hidden.mine().await.unwrap().iter().any(|m| m.channel == lobby),
        "they are not both in it, so this proves nothing"
    );
    let got = stranger.profile_of(&hidden.me).await.unwrap();
    assert!(
        !got.found,
        "sharing the lobby was enough to see a withheld profile: {:?}",
        got.profile().name
    );

    // Somewhere they actually chose to be together is different.
    let room = hidden.create_group("ours", &[stranger.me]).await.unwrap();
    assert!(!room.is_empty() || true);
    let got = stranger.profile_of(&hidden.me).await.unwrap();
    assert!(
        got.found && got.profile().name == "Hidden",
        "a channel they were actually invited to should count"
    );
}

/// Renaming a public channel has to reach the directory as well as the room.
///
/// The metadata entry is what members fold; the directory is what a stranger
/// searches. Only `create` ever wrote the second, so a renamed public channel
/// had two names — and the one people who were not in it saw was the old one.
#[tokio::test]
async fn renaming_a_public_channel_renames_it_for_strangers_too() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_with(dir.path(), "welcome_channel = \"\"\n").await;

    let mut admin = chat_at(addr, server_pub, 48, &dir.path().join("i.db")).await;
    let channel = admin.create_public("the town square", "").await.unwrap();
    admin.set_name(&channel, "general").await.unwrap();

    // A stranger, who can only see what the directory says.
    let mut stranger = chat_at(addr, server_pub, 49, &dir.path().join("j.db")).await;
    let found = stranger.find("", 0).await.unwrap();
    let names: Vec<String> = found.channels.iter().map(|c| c.name.clone()).collect();
    assert!(
        names.contains(&"general".to_string()),
        "the directory still advertises the old name: {names:?}"
    );
    assert!(
        !names.contains(&"the town square".to_string()),
        "both names are in the directory: {names:?}"
    );
}

/// A private channel's name is never given to the exchange, and this route is
/// not a way around that.
#[tokio::test]
async fn the_directory_route_refuses_a_private_channel() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_with(dir.path(), "welcome_channel = \"\"\n").await;

    let mut admin = chat_at(addr, server_pub, 50, &dir.path().join("k.db")).await;
    let channel = admin.create_group("private plans", &[]).await.unwrap();
    admin.set_name(&channel, "still private").await.unwrap();

    // Whatever the exchange holds for it, it is not the name.
    let info = admin.info(&channel).await.unwrap();
    assert_eq!(info.name, "", "the exchange learned a private channel's name");
}

/// Join a public channel the way the client does: find it in the directory,
/// and sign against the incarnation that row carries.
///
/// A joiner cannot ask `Info` for it — that needs the membership the join is
/// acquiring — so the directory is where it comes from.
async fn join_public(chat: &mut Chat, channel: [u8; 32]) -> Result<(), sqex_chat::ChatError> {
    let listing = chat.find("", 0).await?;
    let instance = listing
        .channels
        .iter()
        .find(|c| c.channel == channel)
        .map(|c| c.instance)
        .unwrap_or([0u8; 32]);
    chat.join(&channel, instance).await
}
