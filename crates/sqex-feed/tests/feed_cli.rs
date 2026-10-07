//! `sqex-feed` driven as a person drives it: the real binary, a real exchange,
//! and nothing of this test visible to either.
//!
//! The client library already has `feed_flow.rs`, which proves the protocol.
//! What is only provable here is the binary's own glue, and one claim in
//! particular that the library cannot make: **curating your own list needs no
//! exchange.** `follow` short-circuits before anything is dialled, and the
//! control for that is the same command spelled as a SIP-38 handle, which
//! cannot short-circuit because resolving a handle *is* a request.
//!
//! Every child runs with `HOME` pointed into a temporary directory, so the
//! store and the identity it opens are this test's and never the person's.
//! That is the production path exactly — `store_path` and
//! `default_identity_path` are both under the home directory — and not a seam
//! cut for the tests.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Output;

use ed25519_dalek::SigningKey;
use sqexd::config::FileConfig;
use sqnr_core::PubKey;

async fn server_in(dir: &Path) -> (SocketAddr, PubKey) {
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
    let server_pub = PubKey::new(bound.public_key.to_bytes());
    tokio::spawn(async move {
        let _ = sqexd::serve(bound).await;
    });
    (addr, server_pub)
}

/// A plaintext identity file, the form `sqnr keygen --plaintext` writes: a
/// header naming the form, the base58 seed, and the base58 public key.
fn identity_file(dir: &Path, b: u8) -> (PathBuf, PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    let public = PubKey::new(sk.verifying_key().to_bytes());
    let path = dir.join(format!("identity-{b}"));
    std::fs::write(
        &path,
        format!(
            "SQNR-ED25519-PRIVATE-KEY\n{}\n{}\n",
            bs58::encode(sk.to_bytes()).into_string(),
            public.to_base58()
        ),
    )
    .unwrap();
    (path, public)
}

/// One person: a home of their own, and an identity in it.
struct Who {
    home: PathBuf,
    identity: PathBuf,
    account: PubKey,
}

fn who(dir: &Path, b: u8) -> Who {
    let home = dir.join(format!("home-{b}"));
    std::fs::create_dir_all(&home).unwrap();
    let (identity, account) = identity_file(&home, b);
    Who {
        home,
        identity,
        account,
    }
}

impl Who {
    /// Run the real binary, against `at`, as this person.
    async fn run(&self, at: Option<(SocketAddr, PubKey)>, args: &[&str]) -> Output {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_sqex-feed"));
        cmd.env("HOME", &self.home)
            // Cleared so an exchange named in the environment of whoever runs
            // the suite cannot be the one a test talks to.
            .env_remove("SQEX_SERVER")
            .env_remove("SQEX_SERVER_HOST")
            .env_remove("SQEX_SERVER_KEY")
            .arg("--identity")
            .arg(&self.identity);
        if let Some((addr, key)) = at {
            cmd.arg("--server-host")
                .arg(addr.to_string())
                .arg("--server-key")
                .arg(key.to_base58());
        }
        cmd.args(args);
        cmd.output().await.unwrap()
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// An address nothing answers on, for proving a command did not need one.
fn nowhere() -> (SocketAddr, PubKey) {
    ("127.0.0.1:1".parse().unwrap(), PubKey::new([9u8; 32]))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_published_through_the_binary_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let at = server_in(dir.path()).await;
    let alice = who(dir.path(), 1);

    let published = alice.run(Some(at), &["publish", "the first thing"]).await;
    assert!(
        published.status.success(),
        "publish failed: {}",
        err(&published)
    );
    assert_eq!(out(&published).trim(), "published at 1");

    let read = alice.run(Some(at), &["read"]).await;
    assert!(read.status.success(), "read failed: {}", err(&read));
    assert!(
        out(&read).contains("the first thing"),
        "read showed {:?}",
        out(&read)
    );

    // Anybody holding the key can read it. There is nobody to admit and
    // nothing to join, which is the whole of SIP-88's access model.
    let bob = who(dir.path(), 2);
    let theirs = bob
        .run(Some(at), &["read", &alice.account.to_base58()])
        .await;
    assert!(theirs.status.success(), "read failed: {}", err(&theirs));
    assert!(
        out(&theirs).contains("the first thing"),
        "a published feed is readable by anybody: {:?}",
        out(&theirs)
    );

    // **The control.** A feed nobody has published to is not an error and not
    // an empty list of posts: absent, withheld and blocked are one answer by
    // design, and the binary must not invent which of the three it met. This
    // also shows the assertion above is reading alice's feed and not any feed.
    let empty = alice
        .run(Some(at), &["read", &bob.account.to_base58()])
        .await;
    assert!(empty.status.success(), "read failed: {}", err(&empty));
    assert_eq!(out(&empty).trim(), "nothing to read there");
}

#[tokio::test(flavor = "multi_thread")]
async fn following_a_key_needs_no_exchange() {
    let dir = tempfile::tempdir().unwrap();
    let bob = who(dir.path(), 3);
    let alice = who(dir.path(), 4);
    let key = alice.account.to_base58();

    // Nothing is listening on the address given, and this still works, because
    // following is this client's own list and no exchange is told it.
    let followed = bob.run(Some(nowhere()), &["follow", &key]).await;
    assert!(
        followed.status.success(),
        "follow needed the exchange: {}",
        err(&followed)
    );
    let listed = bob.run(Some(nowhere()), &["following"]).await;
    assert!(
        out(&listed).contains(&key),
        "following did not list them: {:?}",
        out(&listed)
    );

    // **The control.** The same command against the same dead address, spelled
    // as a handle instead of a key, must fail -- otherwise this test would
    // pass for a binary that never dialled at all, and would be proving
    // nothing about the short-circuit.
    let by_handle = bob
        .run(Some(nowhere()), &["follow", "alice@example.test"])
        .await;
    assert!(
        !by_handle.status.success(),
        "a handle cannot be resolved with the exchange down, but it succeeded: {:?}",
        out(&by_handle)
    );

    // And the other half of the control: a command that is *not* list
    // curation fails against the same address, so the success above is about
    // this command and not about this address being reachable after all.
    let published = bob.run(Some(nowhere()), &["publish", "anything"]).await;
    assert!(!published.status.success(), "the dead address answered");

    let unfollowed = bob.run(Some(nowhere()), &["unfollow", &key]).await;
    assert!(unfollowed.status.success(), "{}", err(&unfollowed));
    assert!(out(&bob.run(Some(nowhere()), &["following"]).await).contains("following nobody yet"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_timeline_shows_what_a_followed_feed_said_once_it_is_marked() {
    let dir = tempfile::tempdir().unwrap();
    let at = server_in(dir.path()).await;
    let alice = who(dir.path(), 5);
    let bob = who(dir.path(), 6);

    // The control, before anything is published: following somebody silent
    // reads as nothing new, so what the next assertion sees came from the post.
    assert!(
        bob.run(Some(at), &["follow", &alice.account.to_base58()])
            .await
            .status
            .success()
    );
    let quiet = bob.run(Some(at), &["timeline"]).await;
    assert_eq!(out(&quiet).trim(), "nothing new", "stderr: {}", err(&quiet));

    assert!(
        alice
            .run(Some(at), &["publish", "something to say"])
            .await
            .status
            .success()
    );

    let seen = bob.run(Some(at), &["timeline"]).await;
    assert!(
        out(&seen).contains("something to say"),
        "timeline showed {:?} (stderr {:?})",
        out(&seen),
        err(&seen)
    );

    // Unmarked, it is still unread: a timeline that forgot where it was would
    // be indistinguishable from one that marked everything it drew.
    assert!(
        out(&bob.run(Some(at), &["timeline"]).await).contains("something to say"),
        "an unmarked timeline must still be unread"
    );

    assert!(out(&bob.run(Some(at), &["timeline", "--mark"]).await).contains("something to say"));
    assert_eq!(
        out(&bob.run(Some(at), &["timeline"]).await).trim(),
        "nothing new",
        "marking did not move the cursor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_quote_is_shown_as_the_post_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let at = server_in(dir.path()).await;
    let alice = who(dir.path(), 7);
    let bob = who(dir.path(), 8);

    assert!(
        alice
            .run(Some(at), &["publish", "the original"])
            .await
            .status
            .success()
    );
    let quoted = bob
        .run(
            Some(at),
            &[
                "publish",
                "worth reading",
                "--quoting",
                &alice.account.to_base58(),
                "1",
            ],
        )
        .await;
    assert!(quoted.status.success(), "quoting failed: {}", err(&quoted));

    let read = bob.run(Some(at), &["read", &bob.account.to_base58()]).await;
    let shown = out(&read);
    assert!(shown.contains("worth reading"), "showed {shown:?}");
    assert!(
        shown.contains("the original"),
        "the citation did not resolve: {shown:?}"
    );

    // Withdrawn, the citation says so rather than resolving to a body that is
    // no longer served -- the pointer reaches the withdrawal, which is the
    // whole reason SIP-89 carries a pointer and not a copy.
    assert!(
        alice
            .run(Some(at), &["withdraw", "1"])
            .await
            .status
            .success()
    );
    let after = out(&bob.run(Some(at), &["read", &bob.account.to_base58()]).await);
    assert!(
        after.contains("withdrawn by its author"),
        "after withdrawal: {after:?}"
    );
    assert!(
        !after.contains("the original"),
        "a withdrawn body was still shown: {after:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_is_written_whole_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let at = server_in(dir.path()).await;
    let alice = who(dir.path(), 9);

    assert!(
        alice
            .run(Some(at), &["publish", "to have a feed at all"])
            .await
            .status
            .success()
    );
    let before = out(&alice.run(Some(at), &["head"]).await);
    let held = before.lines().last().unwrap().trim().to_string();

    // Half a policy. `/feed/set` writes it whole, so the half not asked about
    // has to be carried -- and the control for that is the number that was
    // never mentioned still being there afterwards.
    let set = alice.run(Some(at), &["policy", "--max-posts", "500"]).await;
    assert!(set.status.success(), "policy failed: {}", err(&set));
    let said = out(&set).trim().to_string();
    assert!(said.contains("at most 500 posts"), "policy said {said:?}");
    assert_ne!(said, held, "nothing changed");
    assert!(
        said.contains(held.split_whitespace().nth(1).unwrap()),
        "the retention nobody mentioned was not carried: {held:?} -> {said:?}"
    );

    // `policy` and `head` agree to the character, because one function writes
    // the line.
    //
    // Note what this does **not** prove: that `policy` prints a read-back
    // rather than the values it sent. While the exchange refuses an
    // out-of-bounds policy instead of clamping it, the two are always equal,
    // so no test here can tell them apart -- a mutation that printed the
    // request passes this file. The read-back is there because `/feed/set`
    // answers with an `Ack`, so a read is the only way to learn the outcome;
    // it is not a claim this suite makes good on.
    let head = out(&alice.run(Some(at), &["head"]).await);
    assert!(head.contains("serials 1..1"), "head said {head:?}");
    assert_eq!(
        said,
        head.lines().last().unwrap().trim(),
        "policy and head disagree about what holds"
    );

    // **The control.** An exchange refuses a value outside SIP-88's bounds
    // rather than clamping it, so this must fail -- and the policy that held
    // before must still hold afterwards.
    let refused = alice
        .run(Some(at), &["policy", "--max-posts", "4000000000"])
        .await;
    assert!(
        !refused.status.success(),
        "an impossible policy was accepted: {:?}",
        out(&refused)
    );
    assert_eq!(
        out(&alice.run(Some(at), &["head"]).await)
            .lines()
            .last()
            .unwrap()
            .trim(),
        said,
        "a refused policy changed what holds"
    );

    // And neither half given is not a no-op write of what already holds: it is
    // a person who meant to say something, and is told so.
    let nothing = alice.run(Some(at), &["policy"]).await;
    assert!(!nothing.status.success(), "an empty policy was accepted");
}
