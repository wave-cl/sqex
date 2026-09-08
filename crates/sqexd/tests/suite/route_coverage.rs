//! Every route the exchange serves, and what can reach it.
//!
//! `/channel/redact` was implemented here when the channel work landed and no
//! client could call it — no command, no library method, no test outside this
//! directory. It went unnoticed for as long as it did because every other test
//! in the workspace starts from a caller, and a route with no caller is
//! invisible to all of them. Nothing was broken; there was simply nothing
//! pointing at it.
//!
//! So this test starts from the other end. It reads the dispatch table out of
//! `server.rs` and checks it against the list below, which names for each route
//! the thing that reaches it. Adding a route without adding a caller now fails
//! here, and the failure says which route and that somebody has to decide.
//!
//! The list is not verified — it cannot be, across crates — so it is a claim,
//! not a proof. What is verified is that a claim exists for every route and
//! that no claim outlives its route.
//!
//! Each route carries a second claim: **who may reach it**. An audit of all
//! eighty found a route that ended anybody's call, a route whose comment
//! asserted a membership check the code did not make, and a blob path that
//! widened its own audience — each one a route somebody served without writing
//! down who it was for. An audit finds those once. This makes the next one fail
//! the build, and pins the handful of facts about the surface that would
//! otherwise have to be rediscovered by reading eighty handlers.

/// What reaches a route. The payload is where to look, so a failure here points
/// at something rather than only asserting.
#[derive(Debug, PartialEq, Eq)]
enum By {
    /// A method on `sqex_chat::client::Chat`, or a command in its TUI.
    Chat(&'static str),
    /// A subcommand of the `sqex` CLI.
    Cli(&'static str),
    /// sqex-voice.
    Voice(&'static str),
    /// The sqnr admin CLI, over the signed-command protocol.
    Sqnr(&'static str),
    /// Another exchange, over SIP-35 replication. Not a person's client at all,
    /// which is why it is its own kind rather than filed under one.
    Peer(&'static str),
    /// Liveness, answered to anything that connects. No client owns it.
    Probe,
    /// Served and reachable from nothing. Every one of these is a decision
    /// somebody has to make: wire it up, or delete the route.
    ///
    /// Unused, which is the point — there are none. It stays because it is the
    /// word for the next route somebody serves before anything can call it,
    /// and having to invent that word again is how the gap gets glossed over.
    #[allow(dead_code)]
    Unreachable(&'static str),
}

use By::*;

/// **Who may reach a route**, as a claim this file makes about each one.
///
/// The same device as [`By`], pointed at a different question. `By` asks
/// whether anything calls a route; this asks who is allowed to. Neither is
/// verified — a test cannot read an authorization out of a handler — so both
/// are claims. What is verified is that a claim exists for every route and that
/// no claim outlives its route, which is what makes adding a route without
/// deciding who may reach it fail here rather than in production.
///
/// It exists because an audit of all eighty found a route that ended anybody's
/// call, a route whose comment claimed a membership check the code did not
/// make, and a blob path that widened its own audience. Each was a route
/// somebody wrote without writing down who it was for. A one-time audit finds
/// those once; this makes the next one fail the build.
#[derive(Debug, PartialEq, Eq)]
enum Who {
    /// Anyone who can reach the exchange, identified or not.
    Anyone,
    /// Any advertised identity, with no further test. The caller is named but
    /// nothing about them is required.
    Identity,
    /// The connection's own account or device, and no other. The request names
    /// no subject, or names one that must equal the caller.
    SelfOnly,
    /// A present member of the named channel (`role_of`).
    Member,
    /// An admin of the named channel (`is_admin`), or the owner of the thing.
    ChannelAdmin,
    /// The exchange's administrator, proved by signature rather than by
    /// connection. **Not** a channel admin: SIP-24 and SIP-38 both warn that
    /// conflating them would let anybody who made a chat room grant transport
    /// access or hand out names.
    ExchangeAdmin,
    /// A SIP-35 replication peer on the operator's list, *and* a per-channel
    /// authorisation signed into the log by a channel admin.
    ReplicationPeer,
    /// A party to the named session or bridge.
    SessionParty,
    /// The managed whitelist (SIP-8). Exactly one route uses it, which is worth
    /// knowing: enabling the whitelist does not restrict the chat surface.
    Whitelisted,
    /// Holding a secret is the whole authorization. SIP-13 rooms: the exchange
    /// is never given the room secret and cannot check membership, so anyone
    /// with the handle is a member. Deliberate, and the only entry here that
    /// is not a check the exchange performs.
    Capability,
}

use Who::*;

/// The dispatch table, mirrored. Order is `server.rs`'s own.
const ROUTES: &[(&str, &str, By, Who)] = &[
    ("GET", "/health", Probe, Anyone),
    ("GET", "/status", Cli("sqex status"), Anyone),
    (
        "GET",
        "/admin/challenge",
        Sqnr("challenge/response auth"),
        Anyone,
    ),
    (
        "POST",
        "/admin/command",
        Sqnr("signed transactions"),
        ExchangeAdmin,
    ),
    ("POST", "/beacon/beat", Cli("sqex beacon"), Identity),
    ("POST", "/beacon/read", Cli("sqex beacon read"), Anyone),
    // SIP-25 rendezvous. Coordination only: nothing punches yet, and the
    // command says so rather than implying a connection was made.
    ("POST", "/rendezvous/introduce", Cli("sqex meet"), Identity),
    // SIP-27 attestation.
    (
        "POST",
        "/attest/lodge",
        Cli("sqex attest say, sqex attest withdraw"),
        Anyone,
    ),
    ("POST", "/attest/read", Cli("sqex attest read"), Anyone),
    // SIP-28 resolution.
    (
        "POST",
        "/resolve/publish",
        Cli("sqex resolve publish"),
        SelfOnly,
    ),
    ("POST", "/resolve/get", Cli("sqex resolve get"), Identity),
    (
        "POST",
        "/resolve/successor",
        Cli("sqex resolve moved"),
        SelfOnly,
    ),
    (
        "POST",
        "/admission/request",
        Chat("sqex-chat admit"),
        Identity,
    ),
    ("POST", "/profile/put", Chat("/profile"), SelfOnly),
    (
        "POST",
        "/profile/get",
        Chat("Chat::refresh_profiles"),
        Identity,
    ),
    ("POST", "/block/set", Chat("/block, /unblock"), SelfOnly),
    ("POST", "/block/list", Chat("/blocked"), SelfOnly),
    (
        "POST",
        "/device/register",
        Chat("Chat::register_self"),
        SelfOnly,
    ),
    (
        "POST",
        "/device/revoke",
        Chat("Chat::revoke_device"),
        SelfOnly,
    ),
    ("POST", "/device/list", Chat("Chat::my_devices"), Anyone),
    // SIP-38 names.
    ("POST", "/name/claim", Cli("sqex name claim"), SelfOnly),
    ("POST", "/name/release", Cli("sqex name release"), SelfOnly),
    ("POST", "/name/resolve", Cli("sqex name resolve"), Anyone),
    ("POST", "/name/reverse", Cli("sqex name reverse"), Anyone),
    ("POST", "/blob/limits", Chat("Chat::send_file"), Anyone),
    ("POST", "/blob/begin", Chat("Chat::send_file"), Member),
    ("POST", "/blob/put", Chat("Chat::send_file"), SelfOnly),
    ("POST", "/blob/commit", Chat("Chat::send_file"), SelfOnly),
    (
        "POST",
        "/blob/abort",
        Chat("Chat::send_file, on failure"),
        SelfOnly,
    ),
    ("POST", "/blob/head", Chat("Chat::fetch_file"), Member),
    ("POST", "/blob/get", Chat("Chat::fetch_file"), Member),
    ("POST", "/blob/attach", Chat("/forward"), Member),
    (
        "POST",
        "/blob/detach",
        Chat("Chat::redact, via Chat::detach"),
        ChannelAdmin,
    ),
    (
        "POST",
        "/prekey/publish",
        Chat("Chat::top_up_prekeys"),
        SelfOnly,
    ),
    ("POST", "/prekey/take", Chat("Chat::ensure_epoch"), Identity),
    (
        "POST",
        "/prekey/count",
        Chat("Chat::top_up_prekeys"),
        SelfOnly,
    ),
    (
        "POST",
        "/prekey/clear",
        Chat("Chat::top_up_prekeys, after a lost store"),
        SelfOnly,
    ),
    (
        "POST",
        "/channel/create",
        Chat("/new, /public, open_dm"),
        Identity,
    ),
    ("POST", "/channel/join", Chat("/join"), Identity),
    ("POST", "/channel/leave", Chat("/leave"), Member),
    ("POST", "/channel/post", Chat("Chat::send_body"), Member),
    ("POST", "/channel/info", Chat("Chat::info"), Member),
    ("POST", "/channel/retain", Chat("/retain"), ChannelAdmin),
    // `/name` and `/topic` on a public channel: the sealed entry members fold
    // goes to `/channel/post`, and this is the directory copy strangers search.
    ("POST", "/channel/directory", Chat("/name"), ChannelAdmin),
    ("POST", "/channel/close", Chat("/close yes"), ChannelAdmin),
    ("POST", "/channel/mine", Chat("Chat::mine"), SelfOnly),
    ("POST", "/channel/list", Chat("/find"), Anyone),
    ("POST", "/channel/invite", Chat("/invite"), ChannelAdmin),
    ("POST", "/channel/remove", Chat("/kick"), ChannelAdmin),
    // SIP-35. The peering routes are called by another exchange rather than by
    // a person, which is what `Peer` says: the caller is `sqexd::replica`,
    // driven from `replicate` entries in the config.
    (
        "POST",
        "/channel/replicate",
        Chat("/replicate"),
        ChannelAdmin,
    ),
    (
        "POST",
        "/channel/unreplicate",
        Chat("/unreplicate"),
        ChannelAdmin,
    ),
    (
        "POST",
        "/peer/hello",
        Peer("replica::pull_once"),
        ReplicationPeer,
    ),
    (
        "POST",
        "/peer/pull",
        Peer("replica::pull_once"),
        ReplicationPeer,
    ),
    (
        "POST",
        "/peer/envelopes",
        Peer("replica::pull_envelopes"),
        ReplicationPeer,
    ),
    (
        "POST",
        "/peer/blobs",
        Peer("replica::pull_blobs"),
        ReplicationPeer,
    ),
    (
        "POST",
        "/peer/records",
        Peer("replica::pull_profiles"),
        ReplicationPeer,
    ),
    // Reached when a fetch is refused with `equivocated`: the client asks for
    // the evidence rather than reporting a bare refusal.
    (
        "POST",
        "/channel/equivocation",
        Chat("Chat::poll, on an equivocated refusal"),
        Member,
    ),
    (
        "POST",
        "/channel/key/put",
        Chat("Chat::ensure_epoch"),
        Member,
    ),
    (
        "POST",
        "/channel/key/get",
        Chat("Chat::collect_keys"),
        Member,
    ),
    (
        "POST",
        "/channel/key/missing",
        Chat("Chat::stranded"),
        Member,
    ),
    ("POST", "/channel/cursor", Chat("Chat::mark_read"), Member),
    ("POST", "/channel/cursors", Chat("/read"), Member),
    ("POST", "/channel/redact", Chat("/redact"), ChannelAdmin),
    ("POST", "/channel/signal", Chat("Chat::typing"), Member),
    ("POST", "/channel/fetch", Chat("Chat::poll"), Member),
    // Not in the dispatch match: an event stream has no body to return, so
    // it is answered in `handle_stream` before `route` is reached. `served()`
    // scans for that shape too, or this route would be invisible here — which
    // is the exact failure this file exists to prevent.
    ("POST", "/events", Chat("Chat::subscribe"), SelfOnly),
    ("POST", "/room/join", Voice("sqex-voice rooms"), Capability),
    ("POST", "/room/leave", Voice("sqex-voice rooms"), Capability),
    ("POST", "/mailbox/send", Cli("sqex mail send"), Identity),
    ("POST", "/mailbox/list", Cli("sqex mail list"), SelfOnly),
    ("POST", "/mailbox/fetch", Cli("sqex mail fetch"), SelfOnly),
    ("POST", "/mailbox/delete", Cli("sqex mail delete"), SelfOnly),
    ("POST", "/mailbox/status", Cli("sqex mail status"), SelfOnly),
    ("POST", "/session/open", Cli("sqex session"), Identity),
    ("POST", "/session/send", Cli("sqex session"), SessionParty),
    ("POST", "/session/recv", Cli("sqex session"), SessionParty),
    ("POST", "/session/close", Cli("sqex session"), SessionParty),
    ("POST", "/session/call", Voice("sqex-voice call"), Identity),
    (
        "POST",
        "/session/decline",
        Voice("sqex-voice answer --decline"),
        SessionParty,
    ),
    ("GET", "/exchange/ping", Probe, Whitelisted),
];

/// Pull the dispatch arms out of `server.rs`.
///
/// Scanning the whole file would catch any tuple that looks like an arm, so the
/// scan is bounded to the match itself: from `match (method, path) {` to the
/// wildcard that ends it.
fn served() -> Vec<(String, String)> {
    // Relative to this file, which lives in tests/suite/ — two levels down
    // from the crate root, not one. Moving this file changes this path.
    let src = include_str!("../../src/server.rs");
    let start = src
        .find("match (method, path) {")
        .expect("the dispatch match moved or was renamed");
    let end = src[start..]
        .find("_ => refuse(404,")
        .expect("the dispatch match lost its wildcard arm")
        + start;
    let body = &src[start..end];

    let mut out = Vec::new();
    for method in ["GET", "POST"] {
        let needle = format!("(\"{method}\", \"");
        let mut from = 0;
        while let Some(i) = body[from..].find(&needle) {
            let open = from + i + needle.len();
            let close = open + body[open..].find('"').expect("unterminated route path");
            out.push((method.to_string(), body[open..close].to_string()));
            from = close;
        }
    }
    out.extend(handled_early(src));
    out.sort();
    out.dedup();
    out
}

/// Routes answered before the dispatch match is reached.
///
/// `/events` is one: it holds its response stream open and writes to it for
/// hours, so it cannot go through a `route` that returns a finished body. That
/// put it outside the scan this file was built on, and a route this test cannot
/// see is precisely the thing it exists to catch — so the scan follows.
///
/// Matched on the full `method == http::Method::X && path == "..."` shape
/// rather than on `path ==` alone, because `handle_stream` also compares the
/// path to pick a body limit, and a body limit is not a route.
fn handled_early(src: &str) -> Vec<(String, String)> {
    let start = src
        .find("async fn handle_stream(")
        .expect("handle_stream moved or was renamed");
    let end = src[start..]
        .find("/// Pure-ish routing")
        .expect("handle_stream lost the routing doc comment that ends it")
        + start;
    let body = &src[start..end];

    let mut out = Vec::new();
    for method in ["GET", "POST"] {
        let needle = format!("method == http::Method::{method} && path == \"");
        let mut from = 0;
        while let Some(i) = body[from..].find(&needle) {
            let open = from + i + needle.len();
            let close = open + body[open..].find('"').expect("unterminated route path");
            out.push((method.to_string(), body[open..close].to_string()));
            from = close;
        }
    }
    out
}

#[test]
fn every_route_names_something_that_reaches_it() {
    let mut served = served();
    let mut listed: Vec<(String, String)> = ROUTES
        .iter()
        .map(|(m, p, _, _)| (m.to_string(), p.to_string()))
        .collect();
    served.sort();
    listed.sort();

    let missing: Vec<_> = served.iter().filter(|r| !listed.contains(r)).collect();
    assert!(
        missing.is_empty(),
        "these routes are served and nothing above says what reaches them.\n\
         Add each to ROUTES with the caller, or Unreachable(\"why\") if there \
         is none yet:\n{missing:#?}"
    );

    let stale: Vec<_> = listed.iter().filter(|r| !served.contains(r)).collect();
    assert!(
        stale.is_empty(),
        "these are listed above and no longer served — the route was renamed \
         or removed:\n{stale:#?}"
    );
}

/// The gaps, named. This fails when one is closed, which is the point: closing
/// a gap should require saying so here, and the list reaching empty is what
/// "the whole API is reachable" means in practice.
#[test]
fn the_unreachable_routes_are_the_ones_we_know_about() {
    let open: Vec<&str> = ROUTES
        .iter()
        .filter(|(_, _, by, _)| matches!(by, Unreachable(_)))
        .map(|(_, p, _, _)| *p)
        .collect();

    // Empty, and the assertion below is what keeps it that way: a route added
    // with nothing able to call it fails here until somebody decides which.
    let expected: Vec<&str> = vec![];

    let mut open_sorted = open.clone();
    open_sorted.sort();
    assert_eq!(
        open_sorted, expected,
        "the set of routes no client can reach has changed. If one was wired \
         up, mark it here and remove it from `expected`; if a new one appeared, \
         it needs a client."
    );
}

/// The invariants worth pinning about who may reach what.
///
/// Not "every route has a `Who`" — the type guarantees that. These are the
/// facts about the shape of the surface that would be surprising to lose, and
/// each one is a sentence somebody would otherwise have to rediscover by
/// reading eighty handlers.
#[test]
fn the_authorization_surface_holds_its_shape() {
    let who = |path: &str| {
        &ROUTES
            .iter()
            .find(|(_, p, _, _)| *p == path)
            .unwrap_or_else(|| panic!("{path} is not in the table"))
            .3
    };

    // Replication is peer-gated on every one of its routes, with no exception
    // for the handshake: SIP-35 requires an origin to answer every peering
    // route identically to a caller not on its list.
    for (_, path, _, w) in ROUTES.iter().filter(|(_, p, _, _)| p.starts_with("/peer/")) {
        assert_eq!(w, &ReplicationPeer, "{path} must be peer-gated");
    }

    // The directory is the only channel route open to anybody, and it can be
    // because its SQL is hard-filtered to public channels. Every other
    // `/channel/` route names an id, and an id is not an authorization.
    for (_, path, _, w) in ROUTES
        .iter()
        .filter(|(_, p, _, _)| p.starts_with("/channel/"))
    {
        if *path == "/channel/list" {
            assert_eq!(w, &Anyone, "the directory is public by construction");
        } else {
            assert_ne!(w, &Anyone, "{path} names a channel id and must not be open");
        }
    }

    // Exactly one route is gated by the managed whitelist, and an operator who
    // runs `sqex admin whitelist enable` believing it restricts the chat
    // surface is mistaken. If that ever stops being true, this fails and
    // somebody gets to say so out loud.
    let whitelisted: Vec<&str> = ROUTES
        .iter()
        .filter(|(_, _, _, w)| *w == Whitelisted)
        .map(|(_, p, _, _)| *p)
        .collect();
    assert_eq!(
        whitelisted,
        vec!["/exchange/ping"],
        "the whitelist gates one route; enabling it does not restrict the exchange"
    );

    // Holding a secret is the whole authorization in exactly one place. SIP-13
    // is explicit that the exchange is never given a room secret and so cannot
    // check membership; anywhere else, that would be a gap rather than a design.
    let capability: Vec<&str> = ROUTES
        .iter()
        .filter(|(_, _, _, w)| *w == Capability)
        .map(|(_, p, _, _)| *p)
        .collect();
    assert_eq!(capability, vec!["/room/join", "/room/leave"]);

    // The two admin kinds are not the same kind, and SIP-24 and SIP-38 both
    // warn what conflating them would cost: anybody who made a chat room could
    // grant transport access, or hand out names in the domain.
    assert_eq!(who("/admin/command"), &ExchangeAdmin);
    assert_eq!(who("/channel/invite"), &ChannelAdmin);

    // Reads of a channel take membership, including the key routes — closing
    // the existence oracle on `fetch` and leaving `/channel/key/get` open would
    // not have closed it.
    for path in [
        "/channel/fetch",
        "/channel/info",
        "/channel/key/get",
        "/channel/cursors",
        "/channel/equivocation",
    ] {
        assert_eq!(who(path), &Member, "{path} is a read of a channel");
    }
}
