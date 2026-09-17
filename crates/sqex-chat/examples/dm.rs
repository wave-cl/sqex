//! Send one direct message from the command line, without the interface.
//!
//!     cargo run -p sqex-chat --example dm -- \
//!         --server trunk.exchange -i ~/.sqnr/identity-2 --to a "hello"
//!
//! `--to` is a SIP-38 name at the exchange or a base58 key. The recipient's
//! profile name is printed before anything is sent, so what the name resolves
//! to is on the screen beside what was said to it. Everything else is what
//! `sqex-chat` does on startup: discover the exchange, connect as the
//! identity, take the store's lock, open the store, publish prekeys, open
//! the direct message, post. The store is the real one under `~/.sqex/chat`,
//! so the message is in the identity's own history afterwards, as it would
//! be had it been typed — and an identity a running client already holds at
//! this exchange is refused, as a second `sqex-chat` would be.

use clap::Parser;
use sqex_chat::client::Chat;
use sqex_chat::store::{self, Store, store_path};
use sqnr::{Client, identity};
use sqnr_core::{PubKey, Signer};

#[derive(Parser)]
struct Cli {
    /// A domain that publishes an exchange (SIP-33).
    #[arg(long)]
    server: String,
    /// Identity file. Must be plaintext: nothing here asks for a passphrase.
    #[arg(short, long)]
    identity: std::path::PathBuf,
    /// Who to write to: a name at the exchange, or a key.
    #[arg(long)]
    to: String,
    /// What to say. Leave it out to only print who `--to` is.
    text: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    if identity::is_encrypted(&cli.identity)? {
        return Err(format!(
            "{} is passphrase-protected; this example only opens plaintext identities",
            cli.identity.display()
        ));
    }
    let signer = identity::load(&cli.identity, None)?;
    let seed = signer.seed();
    let me = PubKey::new(signer.public());

    let (server, candidates, _pin) = sqex_discovery::candidates(&cli.server)
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
    let (client, addr) = client.ok_or_else(|| format!("could not reach {}: {last}", cli.server))?;

    let path = store_path(&me).map_err(|e| e.to_string())?;
    // The same lock the interface takes: what it protects is the SIP-17
    // counter, and a sigil holding this identity at this exchange would be
    // counting with it. Refused rather than raced.
    let _lock = store::lock(&path, &server).map_err(|e| e.to_string())?;
    let store = Store::open(&seed, Some(&path)).map_err(|e| e.to_string())?;
    let mut chat = Chat::new(client, seed, me, server, store);
    chat.set_domain(Some(cli.server.clone()));
    chat.dials(addr, *server.as_bytes());
    chat.top_up_prekeys()
        .await
        .map_err(|e| format!("publishing prekeys: {e}"))?;

    let them: PubKey = match cli.to.parse() {
        Ok(key) => key,
        Err(_) => chat
            .resolve_name(&cli.to)
            .await
            .map_err(|e| format!("resolving {}: {e}", cli.to))?,
    };
    if them == me {
        return Err("that is your own key".into());
    }
    let got = chat
        .profile_of(&them)
        .await
        .map_err(|e| format!("reading their profile: {e}"))?;
    let profile = got.profile();
    let called = if profile.name.is_empty() {
        "(no profile name)".to_string()
    } else {
        profile.name.clone()
    };
    let Some(text) = cli.text else {
        println!("{them} is {called} at {}", cli.server);
        return Ok(());
    };

    let channel = chat
        .open_dm(&them)
        .await
        .map_err(|e| format!("opening the direct message: {e}"))?;
    let posted = chat
        .send(&channel, &text)
        .await
        .map_err(|e| format!("sending: {e}"))?;
    println!(
        "{me} → {them} ({called}) at {}: seq {} {:?}",
        cli.server, posted.seq, text
    );
    Ok(())
}
