//! SIP-25: the half that exists — coordination, and the consent rule it turns
//! on.
//!
//! **Address disclosure is the entire mechanism, so consent is not a detail.**
//! Every test here is about what is *not* said before both sides have asked,
//! and about the address being the one the exchange observed rather than one a
//! caller supplied.
//!
//! Nothing here punches. `squic::dial` binds a fresh ephemeral port, so a peer
//! cannot dial from the address named in an introduction, and reusing that
//! mapping is the whole mechanism — see SIP-25's reference-implementation note.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sqex_proto::rendezvous::{INTRODUCED_LEN, Introduce, Introduced, START_LEAD_SECS};
use sqexd::config::FileConfig;
use sqnr::Client;
use sqnr_core::PubKey;

use crate::common;

/// Retry a `squic` bind that is refused because the port is still held, for
/// up to ten seconds.
///
/// Dropping an `H3Client` aborts its driver, which is what actually releases
/// the socket, and the OS does not hand the port back synchronously. The test
/// below used to pause a fixed 200ms and then bind once -- a guess at how long
/// a release takes. With the ephemeral range under pressure it was not enough:
/// *both* ports were still held, Alice's `listen` failed with `AddrInUse`, and
/// Bob's `dial` from his own port failed the same way.
///
/// So this waits for the port rather than for a duration. **Bounded on
/// purpose:** a port genuinely held by something that is not going to let go
/// still fails the test, with the error it failed with, rather than hanging
/// until the suite times out. Any error that is not `AddrInUse` fails at once
/// -- a wrong key or an unparseable version is not something waiting fixes.
macro_rules! once_the_port_is_free {
    ($what:expr, $call:expr) => {
        once_the_port_is_free!($what, $call, Duration::from_secs(10))
    };
    ($what:expr, $call:expr, $within:expr) => {{
        let deadline = tokio::time::Instant::now() + $within;
        loop {
            match $call.await {
                Ok(bound) => break bound,
                Err(squic::Error::Io(e))
                    if e.kind() == std::io::ErrorKind::AddrInUse
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => panic!("{}: {:?}", $what, e),
            }
        }
    }};
}

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

fn who(b: u8) -> ([u8; 32], PubKey) {
    let sk = SigningKey::from_bytes(&[b; 32]);
    (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
}

async fn ask(c: &mut Client, peer: PubKey, wait_secs: u16) -> (u16, Vec<u8>) {
    c.post(
        "/rendezvous/introduce",
        Introduce {
            peer,
            wait_secs,
            family_aware: true,
        }
        .encode(),
    )
    .await
    .unwrap()
}

/// **Neither side learns anything until both have asked**, and the answer that
/// says so is the same length as the one that does not — so even the size of
/// the reply discloses nothing.
#[tokio::test]
async fn one_side_asking_discloses_nothing_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = who(11);
    let (_, bob) = who(12);

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed)
        .await
        .unwrap();
    let (code, body) = ask(&mut a, bob, 0).await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let got = Introduced::decode(&body).unwrap();
    assert!(!got.is_ready());
    assert!(
        got.addr.is_none(),
        "an address was disclosed to one side alone"
    );
    assert_eq!(got.start_at, 0);
    assert!(got.now > 0, "the exchange always states its own clock");
    assert_eq!(
        body.len(),
        INTRODUCED_LEN,
        "a waiting answer must not be distinguishable by its length"
    );

    // Asking repeatedly changes nothing. A caller that could learn "they have
    // not asked yet" versus "there is no such identity" would be probing.
    for _ in 0..3 {
        let (_, body) = ask(&mut a, bob, 0).await;
        assert!(!Introduced::decode(&body).unwrap().is_ready());
    }
}

/// When both have asked, each is told the other's **observed** address and both
/// are told the same moment to begin.
#[tokio::test]
async fn both_asking_completes_the_pair_with_one_start_for_both() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = who(21);
    let (bob_seed, bob) = who(22);

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed)
        .await
        .unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &bob_seed)
        .await
        .unwrap();

    let (_, first) = ask(&mut a, bob, 0).await;
    assert!(!Introduced::decode(&first).unwrap().is_ready());

    let (code, body) = ask(&mut b, alice, 0).await;
    assert_eq!(code, 200, "{}", common::said(&body));
    let for_bob = Introduced::decode(&body).unwrap();
    assert!(
        for_bob.is_ready(),
        "the second ask did not complete the pair"
    );
    let alice_at = for_bob.addr.expect("no address for the peer");

    // **More than a second later**, deliberately. Alice's answer must carry the
    // moment computed when the pair completed, not the moment she asked again —
    // without this delay both compute the same `now + lead` by coincidence, and
    // the assertion below would pass against an implementation where each side
    // made up its own start.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    // Alice asks again and is told about Bob.
    let (_, body) = ask(&mut a, bob, 0).await;
    let for_alice = Introduced::decode(&body).unwrap();
    assert!(for_alice.is_ready());
    let bob_at = for_alice.addr.expect("no address for the peer");

    // Both are loopback, and both are the addresses the exchange saw — the
    // ports differ because they are two different connections.
    assert!(alice_at.ip().is_loopback() && bob_at.ip().is_loopback());
    assert_ne!(alice_at.port(), bob_at.port());

    // **One start for both.** A second caller told a later moment than the
    // first was given would defeat the whole point of coordinating.
    assert_eq!(
        for_alice.start_at, for_bob.start_at,
        "the two sides were told different moments to begin"
    );
    // The nominated moment is in the future **when the pair completes**, which
    // is Bob's answer. Checking it against Alice's `now` instead failed 3 runs
    // in 12: her answer is collected after the 1.2s sleep above, leaving a
    // nominal margin of START_LEAD_SECS - 1.2s = 0.8s, and since these
    // timestamps are whole seconds that margin is zero whenever the pair
    // happens to complete late within a second. The design never promised the
    // start stays in the future however long a peer waits before collecting --
    // only that both are told the same one, which the assertion above checks
    // and the sleep makes meaningful.
    assert_eq!(
        for_bob.start_at,
        for_bob.now + START_LEAD_SECS,
        "the pair was not given the lead the protocol specifies"
    );
}

/// The first party to ask **waits** for the second, and both are answered
/// within a wake-up of each other. Polling would have worked and would have put
/// the two answers as far apart as the poll interval, which is the one thing a
/// coordinated start cannot afford.
#[tokio::test]
async fn the_first_to_ask_waits_and_is_woken_by_the_second() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = who(31);
    let (bob_seed, bob) = who(32);

    let mut a = Client::connect_as(addr, &server_pub, &alice_seed)
        .await
        .unwrap();
    let mut b = Client::connect_as(addr, &server_pub, &bob_seed)
        .await
        .unwrap();

    let waiting = tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let (_, body) = ask(&mut a, bob, 10).await;
        (Introduced::decode(&body).unwrap(), started.elapsed())
    });

    // Long enough that the answer cannot be the request racing ahead of the
    // wait, short enough that a ten second timeout is not what ends it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (_, body) = ask(&mut b, alice, 0).await;
    assert!(Introduced::decode(&body).unwrap().is_ready());

    let (got, waited) = waiting.await.unwrap();
    assert!(got.is_ready(), "the waiting side was not woken: {got:?}");
    assert!(
        waited < Duration::from_secs(5),
        "the waiting side was not woken by the second ask, it timed out: {waited:?}"
    );
    assert!(
        waited >= Duration::from_millis(250),
        "the answer arrived before the other side asked, so nothing was coordinated"
    );
}

/// A request that nobody answers ends in silence rather than in an address.
#[tokio::test]
async fn a_wait_that_nobody_joins_ends_saying_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, _) = who(41);
    let (_, nobody) = who(42);
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed)
        .await
        .unwrap();

    let started = tokio::time::Instant::now();
    let (code, body) = ask(&mut a, nobody, 1).await;
    assert_eq!(code, 200);
    let got = Introduced::decode(&body).unwrap();
    assert!(!got.is_ready());
    assert!(got.addr.is_none());
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "the wait returned early, so it was not waiting"
    );
}

/// **An identity cannot ask to meet itself**, which would introduce a caller to
/// its own address for no purpose — the degenerate case a rule keyed on a pair
/// has to exclude on purpose.
#[tokio::test]
async fn an_identity_cannot_introduce_itself_to_itself() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (alice_seed, alice) = who(51);
    let mut a = Client::connect_as(addr, &server_pub, &alice_seed)
        .await
        .unwrap();

    let (code, body) = ask(&mut a, alice, 0).await;
    assert_eq!(code, 200);
    assert!(
        !Introduced::decode(&body).unwrap().is_ready(),
        "an identity was introduced to itself"
    );
}

/// An unidentified caller has no identity to pair, and is refused rather than
/// given an anonymous introduction.
#[tokio::test]
async fn an_unidentified_caller_cannot_ask() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;
    let (_, bob) = who(61);
    let mut anon = Client::connect(addr, &server_pub).await.unwrap();
    let (code, _) = ask(&mut anon, bob, 0).await;
    assert_eq!(code, 403);
}

/// **Two peers introduce themselves and then connect directly**, with the
/// exchange out of the path.
///
/// This is what SIP-25 is for, and it is as far as a test on one machine can
/// go: on loopback there is no NAT, so what this proves is that the coordination
/// produces a usable address and that a peer can dial from the port the exchange
/// observed. Whether that survives a real NAT is a question for two peers behind
/// two of them — see SIP-25, which stays Draft for exactly that reason.
///
/// What it does prove, and what nothing else did: the address an exchange hands
/// over is one a peer can actually reach, and `local_bind` makes the connection
/// leave from the port that was introduced rather than a fresh one.
#[tokio::test]
async fn two_peers_introduced_by_an_exchange_connect_directly() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, server_pub, _h) = server_in(dir.path()).await;

    // Each peer picks a port and uses it for *both* connections: the one the
    // exchange observes and the one the other peer dials. That is the whole
    // mechanism — an exchange that observed a different socket would be
    // describing a mapping nothing else can use.
    //
    // **Both probes are held at once.** Taken one at a time -- bind, read the
    // port, drop, repeat -- the second `bind(:0)` is free to hand back the
    // port the first just released, and the test would put Alice and Bob on
    // one socket while asserting about two.
    let (alice_port, bob_port) = {
        let alices = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bobs = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        (alices.local_addr().unwrap(), bobs.local_addr().unwrap())
    };
    assert_ne!(alice_port, bob_port, "both peers were given one port");
    let (alice_seed, alice) = who(71);
    let (bob_seed, bob) = who(72);

    let a =
        sqex_proto::h3::H3Client::connect_from(addr, &server_pub, &alice_seed, Some(alice_port))
            .await
            .unwrap();
    let b = sqex_proto::h3::H3Client::connect_from(addr, &server_pub, &bob_seed, Some(bob_port))
        .await
        .unwrap();

    let (code, _) = a
        .post(
            "/rendezvous/introduce",
            Introduce {
                peer: bob,
                wait_secs: 0,
                family_aware: true,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let (code, body) = b
        .post(
            "/rendezvous/introduce",
            Introduce {
                peer: alice,
                wait_secs: 0,
                family_aware: true,
            }
            .encode(),
        )
        .await
        .unwrap();
    assert_eq!(code, 200);
    let for_bob = Introduced::decode(&body).unwrap();
    assert!(for_bob.is_ready());

    // **The address the exchange observed is the port Alice chose.** Without
    // that, everything below would be dialling somewhere nobody is listening.
    let alice_seen = for_bob.addr.unwrap();
    assert_eq!(
        alice_seen.port(),
        alice_port.port(),
        "the exchange observed a different mapping from the one that will be used"
    );

    // Alice listens on hers, Bob dials it from his — the tiebreak the CLI uses,
    // fixed here so the test does not depend on which key sorts lower.
    // Both exchange connections go and the ports come free, but not at once:
    // see `once_the_port_is_free`, which is what each bind below goes through
    // instead of the fixed pauses this test used to take on faith.
    drop((a, b));

    let (bound, is_bound) = tokio::sync::oneshot::channel();
    let listening = tokio::spawn(async move {
        let key = ed25519_dalek::SigningKey::from_bytes(&alice_seed);
        let config = squic::Config {
            punch: vec![bob_port],
            ..Default::default()
        };
        let listener = once_the_port_is_free!(
            "alice could not listen on the port she was introduced at",
            squic::listen(alice_port, &key, config.clone())
        );
        // Bob dials once she is actually bound. The second fixed pause was
        // the same guess pointing the other way, and it cannot stand next to
        // a bind that now waits: his five-second handshake timeout would run
        // out while she was still waiting for her port.
        bound.send(()).expect("nobody is waiting for alice");
        let incoming = listener.accept().await.expect("nobody arrived");
        incoming.await.map(|c| c.remote_address())
    });
    is_bound.await.expect("alice's listener never came up");

    let bobs = squic::Config {
        local_bind: Some(bob_port),
        punch: vec![alice_seen],
        client_key: Some(hex::encode(bob_seed)),
        advertise_identity: true,
        handshake_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };
    let conn = once_the_port_is_free!(
        "bob could not reach alice at the address the exchange gave him",
        squic::dial(alice_seen, alice.as_bytes(), bobs.clone())
    );
    assert_eq!(conn.remote_address(), alice_seen);

    let seen_by_alice = listening.await.unwrap().unwrap();
    assert_eq!(
        seen_by_alice.port(),
        bob_port.port(),
        "bob arrived from a port other than the one he was introduced at"
    );
    conn.close(0u32.into(), b"done");
}

/// The control for `once_the_port_is_free`: a port held by something that
/// never lets go must still fail the test.
///
/// Without this the retry is indistinguishable from `expect` on a port that
/// happened to be free -- it would wait out its bound and then report the
/// same `AddrInUse` the old code reported immediately, which is the point,
/// but nothing here would have proved it rather than hanging or passing. A
/// short bound keeps it cheap; the mechanism is the same at ten seconds.
#[tokio::test]
// Pinned to the *reason*, not the site: `expected` on the message prefix
// alone would be satisfied by a bad key or an unparseable version failing at
// the same call, and the control would pass while proving nothing about a
// held port. `AddrInUse` is the normalised kind, so this reads the same on
// the Linux runner, where the raw errno is 98 rather than 48.
#[should_panic(expected = "kind: AddrInUse")]
async fn a_port_that_never_frees_still_fails_the_bind() {
    let hog = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let held = hog.local_addr().unwrap();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let config = squic::Config::default();
    let _listener = once_the_port_is_free!(
        "a port nothing is going to give back",
        squic::listen(held, &key, config.clone()),
        Duration::from_millis(300)
    );
    // `hog` is still bound here: dropping it earlier would let the retry
    // succeed and the control would prove the opposite of what it claims.
    drop(hog);
}
