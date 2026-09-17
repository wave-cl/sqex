//! Publish this identity's profile — its display name and title — at an
//! exchange, without the interface.
//!
//!     cargo run -p sqex-chat --example profile -- \
//!         --server trunk.exchange -i ~/.sqnr/identity-2 --name "Alice Wren" --title "does the builds"
//!
//! A display name is a claim, not a credential: readers see the key beside
//! it. Leave `--name` empty to withdraw the profile. Plaintext identities
//! only; it never asks for a passphrase.

use clap::Parser;
use sqex_chat::client::Chat;
use sqex_chat::store::{Store, store_path};
use sqex_proto::profile::Profile;
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
    /// The display name. Empty withdraws the profile.
    #[arg(long, default_value = "")]
    name: String,
    /// A line about yourself. Carries no authority; an exchange never reads it.
    #[arg(long, default_value = "")]
    title: String,
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
    // No lock and no prekeys: this is a one-shot like `sqex-chat add`, and
    // publishing a profile touches neither the SIP-17 counter nor the pool,
    // which are what the lock and the top-up are for. It runs beside a
    // client holding this identity, which is the ordinary time to change a
    // name.
    let store = Store::open(&seed, Some(&path)).map_err(|e| e.to_string())?;
    let mut chat = Chat::new(client, seed, me, server, store);
    chat.set_domain(Some(cli.server.clone()));
    chat.dials(addr, *server.as_bytes());

    let before = chat
        .profile_of(&me)
        .await
        .map(|g| g.profile().name)
        .unwrap_or_default();
    chat.set_profile(Profile {
        flags: 0,
        name: cli.name.clone(),
        title: cli.title.clone(),
        avatar: Vec::new(),
    })
    .await
    .map_err(|e| format!("publishing the profile: {e}"))?;
    let after = chat
        .profile_of(&me)
        .await
        .map_err(|e| format!("reading it back: {e}"))?
        .profile();
    println!(
        "{me} at {}: {:?} → {:?} ({:?})",
        cli.server, before, after.name, after.title
    );
    Ok(())
}
