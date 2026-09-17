//! Play a scripted group conversation between several identities.
//!
//!     cargo run -p sqex-chat --example thread -- --server trunk.exchange \
//!         --name "release check" -i ~/.sqnr/identity-2 -i ~/.sqnr/identity-3 \
//!         < script.txt
//!
//! The first identity creates a private group and invites the rest. Then the
//! script, one entry per line, each posted by the identity at that index
//! (0-based, in `-i` order):
//!
//!     0 say Anybody seen the build?
//!     1 reply 1 Green since lunch.
//!     2 react 2 🎉
//!
//! `reply N` and `react N` name the Nth *line of the script* that said
//! something (1-based), not a sequence number: the exchange assigns those,
//! and a script that guessed them would target the wrong entry after the
//! first invitation or key. Each identity polls the channel before it posts,
//! so it holds the epoch key and sees what it is answering.
//!
//! Plaintext identities only; nothing here asks for a passphrase. The stores
//! are the real ones under `~/.sqex/chat`, so afterwards every identity has
//! the conversation in its own history, as if it had been there — and each
//! store's lock is taken first, so an identity a running client holds at
//! this exchange is refused rather than raced for its counter.

use std::io::Read;

use clap::Parser;
use sqex_chat::client::Chat;
use sqex_chat::store::{self, Lock, Store, store_path};
use sqex_proto::timeline::Timeline;
use sqnr::{Client, identity};
use sqnr_core::{PubKey, Signer};

#[derive(Parser)]
struct Cli {
    /// A domain that publishes an exchange (SIP-33).
    #[arg(long)]
    server: String,
    /// The group's name, sealed to its members.
    #[arg(long)]
    name: String,
    /// Identity files, in the order the script indexes them. An identity
    /// whose account lives at another exchange (SIP-59) connects there:
    /// write it `path@domain`, and it reaches the group as a copy carried
    /// between the two (SIP-60).
    #[arg(short, long = "identity", required = true)]
    identities: Vec<String>,
}

enum Line {
    Say(usize, String),
    Reply(usize, usize, String),
    React(usize, usize, String),
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn open(server_domain: &str, path: &std::path::Path) -> Result<(Chat, PubKey, Lock), String> {
    if identity::is_encrypted(path)? {
        return Err(format!(
            "{} is passphrase-protected; this example only opens plaintext identities",
            path.display()
        ));
    }
    let signer = identity::load(path, None)?;
    let seed = signer.seed();
    let me = PubKey::new(signer.public());
    let (server, candidates, _pin) = sqex_discovery::candidates(server_domain)
        .await
        .map_err(|e| e.to_string())?;
    let mut client = None;
    let mut last = String::new();
    for c in &candidates {
        match Client::connect_as(c.addr, server.as_bytes(), &seed).await {
            Ok(k) => {
                client = Some((k, c.addr));
                break;
            }
            Err(e) => last = format!("{}: {e}", c.addr),
        }
    }
    let (client, addr) =
        client.ok_or_else(|| format!("could not reach {server_domain}: {last}"))?;
    let store_at = store_path(&me).map_err(|e| e.to_string())?;
    // The same lock the interface takes: what it protects is the SIP-17
    // counter, and a sigil holding this identity at this exchange would be
    // counting with it. Refused rather than raced.
    let lock = store::lock(&store_at, &server).map_err(|e| format!("{me}: {e}"))?;
    let store = Store::open(&seed, Some(&store_at)).map_err(|e| e.to_string())?;
    let mut chat = Chat::new(client, seed, me, server, store);
    chat.set_domain(Some(server_domain.to_string()));
    chat.dials(addr, *server.as_bytes());
    chat.top_up_prekeys()
        .await
        .map_err(|e| format!("{me}: publishing prekeys: {e}"))?;
    Ok((chat, me, lock))
}

fn parse(text: &str) -> Result<Vec<Line>, String> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        let bad = || format!("line {}: cannot read {raw:?}", n + 1);
        let mut words = raw.splitn(3, ' ');
        let who: usize = words.next().and_then(|w| w.parse().ok()).ok_or_else(bad)?;
        let verb = words.next().ok_or_else(bad)?;
        let rest = words.next().unwrap_or("").to_string();
        let line = match verb {
            "say" => Line::Say(who, rest),
            "reply" | "react" => {
                let (target, text) = rest.split_once(' ').ok_or_else(bad)?;
                let target: usize = target.parse().map_err(|_| bad())?;
                if verb == "reply" {
                    Line::Reply(who, target, text.to_string())
                } else {
                    Line::React(who, target, text.to_string())
                }
            }
            _ => return Err(bad()),
        };
        out.push(line);
    }
    Ok(out)
}

async fn run(cli: Cli) -> Result<(), String> {
    let mut script = String::new();
    std::io::stdin()
        .lock()
        .read_to_string(&mut script)
        .map_err(|e| e.to_string())?;
    let lines = parse(&script)?;

    let mut chats = Vec::new();
    let mut keys = Vec::new();
    let mut locks = Vec::new();
    for spec in &cli.identities {
        let (path, at) = match spec.rsplit_once('@') {
            Some((p, d)) if !d.contains('/') => (p, d),
            _ => (spec.as_str(), cli.server.as_str()),
        };
        let path = std::path::Path::new(path);
        let (chat, me, lock) = open(at, path).await?;
        println!("{me}  {} at {at}", path.display());
        chats.push(chat);
        keys.push(me);
        locks.push(lock);
    }
    for l in &lines {
        let who = match l {
            Line::Say(w, _) | Line::Reply(w, _, _) | Line::React(w, _, _) => *w,
        };
        if who >= chats.len() {
            return Err(format!(
                "the script names identity {who}, and there are {}",
                chats.len()
            ));
        }
    }

    let channel = chats[0]
        .create_group(&cli.name, &keys[1..])
        .await
        .map_err(|e| format!("creating the group: {e}"))?;
    println!(
        "group {:?} is {}",
        cli.name,
        bs58::encode(channel).into_string()
    );

    // Every identity reads the channel once, so the invitations land and
    // each holds the epoch key before anyone speaks.
    let mut timelines: Vec<Timeline> = (0..chats.len()).map(|_| Timeline::new()).collect();
    for (i, chat) in chats.iter_mut().enumerate() {
        chat.poll(&channel, &mut timelines[i], 0)
            .await
            .map_err(|e| format!("{}: first read: {e}", keys[i]))?;
    }

    // The exchange's sequence number of each script line that said
    // something, by its 1-based place among them.
    let mut seqs: Vec<u64> = Vec::new();
    let target_of = |seqs: &Vec<u64>, n: usize| -> Result<u64, String> {
        seqs.get(n.wrapping_sub(1))
            .copied()
            .ok_or_else(|| format!("no message {n} yet to point at"))
    };
    for l in &lines {
        let who = match l {
            Line::Say(w, _) | Line::Reply(w, _, _) | Line::React(w, _, _) => *w,
        };
        let chat = &mut chats[who];
        chat.poll(&channel, &mut timelines[who], 0)
            .await
            .map_err(|e| format!("{}: reading: {e}", keys[who]))?;
        match l {
            Line::Say(_, text) => {
                let posted = chat
                    .send(&channel, text)
                    .await
                    .map_err(|e| format!("{}: saying: {e}", keys[who]))?;
                seqs.push(posted.seq);
                println!("{}  #{} {who} says {text:?}", posted.seq, seqs.len());
            }
            Line::Reply(_, n, text) => {
                let target = target_of(&seqs, *n)?;
                let posted = chat
                    .reply(&channel, target, text)
                    .await
                    .map_err(|e| format!("{}: replying: {e}", keys[who]))?;
                seqs.push(posted.seq);
                println!(
                    "{}  #{} {who} replies to #{n} (seq {target}) {text:?}",
                    posted.seq,
                    seqs.len()
                );
            }
            Line::React(_, n, emoji) => {
                let target = target_of(&seqs, *n)?;
                let posted = chat
                    .react(&channel, target, emoji, true)
                    .await
                    .map_err(|e| format!("{}: reacting: {e}", keys[who]))?;
                println!(
                    "{}  {who} reacts {emoji} to #{n} (seq {target})",
                    posted.seq
                );
            }
        }
    }
    println!("{} entries posted", lines.len());
    Ok(())
}
