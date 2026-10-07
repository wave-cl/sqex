//! `sqex-feed` — SIP-88 feeds from the command line.
//!
//! Publish to your own feed, follow other people's, and read a timeline
//! across everything you follow.
//!
//! # Why this is its own command, and why it does not take the store's lock
//!
//! A feed is not a conversation, which is SIP-88's whole argument, and it
//! shows in what this program needs: no sealing, no epochs, no prekeys, no
//! membership. `sqex-chat` takes an exclusive lock on the store because two
//! *interactive* clients would each have their own idea of the next SIP-17
//! counter — and **a feed never seals**, so this touches the one thing that
//! lock exists to protect exactly never. Every command here is one shot, and
//! SQLite's own locking is enough for that.
//!
//! So this runs beside a live `sqex-chat` or Sigil on the same identity, on
//! the same store, which is the point: a person should be able to publish
//! without closing the client they are talking to people in.
//!
//! # What it does not do
//!
//! It does not hold a connection, watch for anything, or notify. A feed has no
//! push, which SIP-88 settled and did not hide, and this is the shape that
//! admits it: you ask, it answers, it exits.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sqex_chat::client::{Chat, ChatError};
use sqex_chat::feed::Cited;
use sqex_chat::store::{Store, store_path};
use sqex_proto::feed::{self, Headed, Page};
use sqex_proto::message::{Body, Part, Post};
use sqnr::{Client, config::Config, identity};
use sqnr_core::{PubKey, Signer};

#[derive(Parser)]
#[command(
    name = "sqex-feed",
    about = "Publish to your feed, follow others, read a timeline.",
    long_about = "SIP-88 feeds. Your feed is your account: there is nothing to \
create and nobody to admit, and anybody holding your key can read it. Who you \
follow is this client's own list, and no exchange is told it."
)]
struct Cli {
    /// A domain that publishes an exchange (SIP-33). Its key is discovered over
    /// DNSSEC and pinned on first contact.
    #[arg(long, global = true)]
    server: Option<String>,
    /// A literal address, host:port. Needs --server-key.
    #[arg(long, global = true)]
    server_host: Option<String>,
    /// The exchange's base58 public key, with --server-host.
    #[arg(long, global = true)]
    server_key: Option<String>,
    /// Identity file. Default ~/.sqnr/identity.
    #[arg(short, long, global = true)]
    identity: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Command,
}

/// Anywhere a person names somebody, a base58 account key or a SIP-38
/// `name@domain` will do. A handle is resolved through the exchange, so it
/// needs a connection where a key does not.
#[derive(Subcommand)]
enum Command {
    /// Publish to your own feed.
    Publish {
        /// What to say. Omitted, it is read from standard input.
        text: Option<String>,
        /// Quote a post in somebody's feed (SIP-89): `--quoting <who> <serial>`.
        #[arg(long, num_args = 2, value_names = ["WHO", "SERIAL"])]
        quoting: Option<Vec<String>>,
    },
    /// Read somebody's feed, newest first. Yours by default.
    Read {
        who: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u16,
    },
    /// Follow somebody's feed. Local: no exchange is told.
    Follow { who: String },
    /// Stop following. Also local.
    Unfollow { who: String },
    /// Who you follow, and where you have read each to.
    Following,
    /// What has been said in the feeds you follow since you last read them.
    ///
    /// One request for every feed you follow rather than one each, which is the
    /// reason SIP-88 carries `/feed/since` at all.
    Timeline {
        /// Mark everything shown as read.
        #[arg(long)]
        mark: bool,
    },
    /// Withdraw one of your own posts.
    ///
    /// **This does not take it back.** It stops this exchange serving the body
    /// and leaves a tombstone where the post was. It reaches no reader who
    /// already has it, no copy, and no screenshot.
    Withdraw { serial: u64 },
    /// Where your feed has got to, and what its retention policy is.
    Head,
    /// Set your feed's retention policy: how long posts are kept, and how many.
    ///
    /// `/feed/set` writes the policy **whole**, so giving one of these keeps
    /// the other as it stands rather than zeroing it. An exchange refuses a
    /// value outside SIP-88's bounds; it does not quietly clamp one.
    Policy {
        /// Seconds. At least an hour, at most a year.
        #[arg(long)]
        retention: Option<u32>,
        /// At most this many posts.
        #[arg(long)]
        max_posts: Option<u32>,
    },
}

fn main() {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(run(cli)) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let cfg = Config::load();
    let (seed, me) = load_identity(&cli, &cfg)?;
    let path = store_path(&me).map_err(|e| e.to_string())?;
    let store = Store::open(&seed, Some(&path)).map_err(|e| e.to_string())?;

    // Curating your own list touches nothing but this store, so it is answered
    // before anything is dialled: `follow` works while the exchange is down,
    // which is when somebody is most likely to be fiddling with it.
    //
    // A handle cannot be answered here, because resolving `name@domain` *is* a
    // request. Those fall through to the connected path below rather than
    // being refused, so the two spellings mean the same thing everywhere.
    match &cli.cmd {
        Command::Following => {
            let follows = store.follows().map_err(|e| e.to_string())?;
            if follows.is_empty() {
                println!("following nobody yet — sqex-feed follow <who>");
            }
            for (account, serial) in follows {
                println!("{account}  read to {serial}");
            }
            return Ok(());
        }
        Command::Follow { who } => {
            if let Some(account) = as_key(who) {
                store.follow(&account, now()).map_err(|e| e.to_string())?;
                println!("following {account}");
                return Ok(());
            }
        }
        Command::Unfollow { who } => {
            if let Some(account) = as_key(who) {
                store.unfollow(&account).map_err(|e| e.to_string())?;
                println!("no longer following {account}");
                return Ok(());
            }
        }
        _ => {}
    }

    // Resolved once. Discovery is a DNSSEC lookup and carries a notice a
    // person should see exactly as many times as it happened.
    let (addr, server, domain) = resolve_endpoint(&cli, &cfg).await?;
    let client = Client::connect_as(addr, server.as_bytes(), &seed)
        .await
        .map_err(|e| e.to_string())?;
    let mut chat = Chat::new(client, seed, me, server, store);
    // So a handle naming this exchange is resolved here and one naming another
    // is located, rather than both being asked of whoever answered.
    chat.set_domain(domain);

    match cli.cmd {
        Command::Publish { text, quoting } => publish(&mut chat, text, quoting).await?,
        Command::Read { who, limit } => {
            let account = match who {
                Some(w) => whose(&mut chat, &w).await?,
                None => chat.me,
            };
            let page = chat
                .read_feed(&account, 0, limit)
                .await
                .map_err(|e| e.to_string())?;
            // Absent, withheld and blocked are one answer by design, so this
            // says what it knows and does not guess which of the three.
            if !page.found {
                println!("nothing to read there");
                return Ok(());
            }
            show(&mut chat, &page).await;
        }
        Command::Follow { who } => {
            let account = whose(&mut chat, &who).await?;
            chat.follow(&account).map_err(|e| e.to_string())?;
            println!("following {account}");
        }
        Command::Unfollow { who } => {
            let account = whose(&mut chat, &who).await?;
            chat.unfollow(&account).map_err(|e| e.to_string())?;
            println!("no longer following {account}");
        }
        Command::Timeline { mark } => timeline(&mut chat, mark).await?,
        Command::Withdraw { serial } => {
            chat.withdraw(serial).await.map_err(|e| e.to_string())?;
            println!(
                "withdrawn at {serial}. This exchange will stop serving the body; \
                 anybody who already read it still has it."
            );
        }
        Command::Head => {
            let h = chat.feed_head().await.map_err(|e| e.to_string())?;
            if !h.found {
                println!("you have published nothing yet");
                return Ok(());
            }
            println!("serials {}..{}", h.oldest, h.newest);
            println!("{} posts, {} bytes", h.posts, h.bytes);
            println!("{}", policy_line(&h));
        }
        Command::Policy {
            retention,
            max_posts,
        } => {
            if retention.is_none() && max_posts.is_none() {
                return Err("say --retention, or --max-posts, or both".into());
            }
            // The route writes the policy whole, so the half that was not
            // asked about has to come from somewhere. It comes from what
            // holds -- and from SIP-88's own defaults for a feed that does not
            // exist yet, which is not the same as zero: zero is refused.
            let held = chat.feed_head().await.map_err(|e| e.to_string())?;
            let (was_retention, was_max) = if held.found {
                (held.retention_secs, held.max_posts)
            } else {
                (feed::DEFAULT_RETENTION, feed::MAX_POSTS)
            };
            chat.set_feed(
                retention.unwrap_or(was_retention),
                max_posts.unwrap_or(was_max),
            )
            .await
            .map_err(|e| e.to_string())?;
            // Read back rather than reported from the request. **This is not
            // observable today** -- an exchange refuses a value outside
            // SIP-88's bounds instead of clamping it, so the two always agree,
            // and `feed_cli.rs` says so rather than claiming a control it has
            // not got. It is here because `/feed/set` answers with an `Ack` and
            // not with the resulting policy, so a read is the only way a
            // client can ever learn the outcome, and the day a bound moves or
            // an exchange starts clamping, this prints what holds.
            let now = chat.feed_head().await.map_err(|e| e.to_string())?;
            println!("{}", policy_line(&now));
        }
        // Answered above, before anything was dialled.
        Command::Following => unreachable!("answered offline"),
    }
    Ok(())
}

async fn publish(
    chat: &mut Chat,
    text: Option<String>,
    quoting: Option<Vec<String>>,
) -> Result<(), String> {
    let words = match text {
        Some(t) => t,
        None => {
            use std::io::Read as _;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| e.to_string())?;
            buf.trim_end().to_string()
        }
    };
    let mut post = Post::text(&words);
    if let Some(q) = quoting {
        // clap guarantees two values, so this indexes what it was given.
        let account = whose(chat, &q[0]).await?;
        let serial: u64 = q[1]
            .trim()
            .parse()
            .map_err(|_| format!("{:?} is not a serial", q[1]))?;
        // A pointer and never a copy (SIP-89), so withdrawing the original
        // reaches this quote too. Nothing the quoter says about the quoted
        // post is carried: there is no field for it, deliberately.
        post.parts.push(Part::Quote(account, serial));
    }
    let at = chat
        .publish(&Body::Post(post))
        .await
        .map_err(|e| e.to_string())?;
    println!("published at {}", at.serial);
    Ok(())
}

async fn timeline(chat: &mut Chat, mark: bool) -> Result<(), String> {
    let caught = chat.feeds_since().await.map_err(|e| e.to_string())?;
    // Said first, and plainly. A feed whose home could not be asked is not a
    // feed that said nothing, and a reader not told the difference has a
    // timeline that quietly stops filling.
    for account in &caught.unasked {
        eprintln!("could not ask about {account}");
    }
    for account in &caught.gone {
        eprintln!("{account}: nothing to read — no feed, or not for us");
    }
    for s in &caught.reset {
        eprintln!(
            "{}: this exchange reports serial {} where we hold {} — it is behind, or wrong",
            s.account, s.newest, s.held
        );
    }
    for s in &caught.truncated {
        eprintln!(
            "{}: its oldest is now {}, past the {} we hold — there is a gap nothing will close",
            s.account, s.oldest, s.held
        );
    }
    if caught.moved.is_empty() {
        println!("nothing new");
        return Ok(());
    }
    for s in caught.moved {
        // One failure is one feed's, not the timeline's: the rest still print.
        let page = match chat.read_feed_after(&s.account, s.held, 20).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: {e}", s.account);
                continue;
            }
        };
        println!("— {} ({} new) —", s.account, s.behind());
        show(chat, &page).await;
        if mark {
            // What was shown, not what was reported as the head: a page is
            // capped and marking past it would skip the remainder silently.
            chat.read_to(&s.account, highest(&page))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// One line for a feed's retention policy, printed by `head` and by `policy`
/// so the two cannot drift into saying it differently.
fn policy_line(h: &Headed) -> String {
    format!(
        "kept {} seconds, at most {} posts",
        h.retention_secs, h.max_posts
    )
}

/// The highest serial actually in a page, which is what a cursor may advance to.
fn highest(page: &Page) -> u64 {
    page.posts.iter().map(|s| s.post.serial).max().unwrap_or(0)
}

/// Print a page, oldest first, resolving any citation it carries.
///
/// A quote is **not** rendered from anything the quoter said about the post
/// they named, because there is no such field: the citation is a key and a
/// serial, and what is shown is what came back and verified. Where it will not
/// resolve, that is said rather than guessed at — SIP-89 is explicit that a
/// citation rendered before verification is a smear primitive.
async fn show(chat: &mut Chat, page: &Page) {
    let mut posts: Vec<_> = page.posts.iter().collect();
    posts.sort_by_key(|s| s.post.serial);
    for s in posts {
        if s.post.withdrawn() {
            println!("  {:>6}  (withdrawn by its author)", s.post.serial);
            continue;
        }
        let shown = match Body::decode(&s.post.body) {
            Ok(Some(Body::Post(p))) => p,
            // A body this version cannot read is not a damaged one, and saying
            // so is the difference between "upgrade" and "something is wrong".
            _ => {
                println!("  {:>6}  (nothing this version can show)", s.post.serial);
                continue;
            }
        };
        println!(
            "  {:>6}  {}",
            s.post.serial,
            shown.body_text().unwrap_or("")
        );
        if let Some((who, serial)) = shown.quoted() {
            println!("          > {}", cited(chat, who, serial).await);
        }
    }
}

async fn cited(chat: &mut Chat, who: PubKey, serial: u64) -> String {
    match chat.resolve_quote(&who, serial).await {
        Cited::Got(q) => match Body::decode(&q.post.body) {
            Ok(Some(Body::Post(orig))) => {
                format!("{who} {serial}: {}", orig.body_text().unwrap_or(""))
            }
            _ => format!("{who} {serial}: (nothing this version can show)"),
        },
        Cited::Withdrawn => format!("{who} {serial}: withdrawn by its author"),
        Cited::Evicted => format!("{who} {serial}: no longer held"),
        Cited::NoFeed => format!("{who}: nothing to read there"),
        Cited::Forged => format!("{who} {serial}: did not verify — not shown"),
        Cited::Unresolved => format!("{who} {serial}: could not be reached"),
    }
}

/// A base58 account key, if that is what this is. `None` for anything else,
/// including a SIP-38 handle, which needs the exchange to answer.
fn as_key(typed: &str) -> Option<PubKey> {
    typed.trim().parse().ok()
}

/// Whoever a person named: a key, or a SIP-38 handle resolved through the
/// exchange.
///
/// The same shape as `sqex-chat`'s own, and for the same reason: a handle
/// naming a *different* exchange is **located** through this one rather than
/// resolved against the wrong one, which would silently answer with whoever
/// happens to hold that name here.
async fn whose(chat: &mut Chat, typed: &str) -> Result<PubKey, String> {
    let typed = typed.trim();
    if let Some((label, domain)) = typed.rsplit_once('@')
        && !label.is_empty()
        && !domain.is_empty()
        && chat.domain() != Some(domain)
    {
        return chat
            .locate(typed)
            .await
            .map(|l| l.account)
            .map_err(|e: ChatError| e.to_string());
    }
    match sqex_proto::name::classify(typed).map_err(|e| e.to_string())? {
        sqex_proto::name::Target::Key(k) => Ok(k),
        sqex_proto::name::Target::Named { name, .. } => {
            chat.resolve_name(&name).await.map_err(|e| e.to_string())
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn identity_path(cli: &Cli, cfg: &Config) -> Result<PathBuf, String> {
    if let Some(p) = &cli.identity {
        return Ok(p.clone());
    }
    if let Some(p) = &cfg.identity {
        return Ok(p.clone());
    }
    identity::default_identity_path()
}

fn load_identity(cli: &Cli, cfg: &Config) -> Result<([u8; 32], PubKey), String> {
    let path = identity_path(cli, cfg)?;
    let signer = if identity::is_encrypted(&path)? {
        let pass = rpassword::prompt_password(format!("Passphrase for {}: ", path.display()))
            .map_err(|e| {
                format!(
                    "{} is passphrase-protected and there is no terminal to ask on ({e}) — \
                     run this from a terminal, or point --identity at an unencrypted one",
                    path.display()
                )
            })?;
        identity::load(&path, Some(&pass))?
    } else {
        identity::load(&path, None)?
    };
    Ok((signer.seed(), PubKey::new(signer.public())))
}

/// An environment variable's value, or None if unset or empty.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// The layers a caller can speak through, most specific first. Resolution
/// itself lives in `sqex_discovery::target`, shared with the other clients,
/// because three copies of it is what produced two bugs in a day.
fn layers(cli: &Cli, cfg: &Config) -> Vec<sqex_discovery::Layer> {
    let mut layers = vec![
        sqex_discovery::Layer {
            server: cli.server.clone(),
            host: cli.server_host.clone(),
            key: cli.server_key.clone(),
        },
        sqex_discovery::Layer {
            server: env_nonempty("SQEX_SERVER"),
            host: env_nonempty("SQEX_SERVER_HOST"),
            key: env_nonempty("SQEX_SERVER_KEY"),
        },
        // SIP-59: where this identity's account lives, as a move or a claim
        // recorded it beside the identity. Above the config, which is one
        // pointer for every identity; below anything said for this run.
        {
            let home = identity_path(cli, cfg)
                .ok()
                .and_then(|id| sqex_proto::home_file::load(&id))
                .unwrap_or_default();
            sqex_discovery::Layer::for_home(home.domain, home.key)
        },
        // The config is `sqnr`'s type and has no `server_host`, so the pairing
        // rule is read off the two fields it does have.
        match (&cfg.server, &cfg.server_key) {
            (Some(s), Some(k)) => sqex_discovery::Layer {
                host: Some(s.clone()),
                key: Some(k.clone()),
                ..Default::default()
            },
            (Some(s), None) => sqex_discovery::Layer {
                server: Some(s.clone()),
                ..Default::default()
            },
            _ => sqex_discovery::Layer::default(),
        },
    ];
    // Lowest priority: this identity's primary handle domain (SIP-38), so a
    // claimed name *is* the default exchange and no pointer is needed. Reading
    // the sidecar is a cleartext file read — no passphrase.
    if let Ok(id) = identity_path(cli, cfg)
        && let Some(domain) = sqex_proto::handles::primary_domain(&id)
    {
        layers.push(sqex_discovery::Layer {
            server: Some(domain),
            ..Default::default()
        });
    }
    layers
}

/// The address, the key to pin, and -- when the exchange was reached by SIP-33
/// discovery rather than a literal host and key -- the domain it answered
/// under, which is what a SIP-38 handle is judged against.
async fn resolve_endpoint(
    cli: &Cli,
    cfg: &Config,
) -> Result<(SocketAddr, PubKey, Option<String>), String> {
    match sqex_discovery::target::resolve(&layers(cli, cfg)).map_err(|e| e.to_string())? {
        sqex_discovery::Target::Direct { address, key } => {
            Ok((sqex_discovery::resolve_addr(&address)?, key, None))
        }
        sqex_discovery::Target::Discover(domain) => {
            let found = sqex_discovery::discover(&domain)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(notice) = found.notice(&domain) {
                eprintln!("{notice}");
            }
            Ok((
                sqex_discovery::resolve_addr(&found.address)?,
                found.key,
                Some(domain),
            ))
        }
    }
}
