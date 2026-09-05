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

/// The dispatch table, mirrored. Order is `server.rs`'s own.
const ROUTES: &[(&str, &str, By)] = &[
    ("GET", "/health", Probe),
    ("GET", "/status", Cli("sqex status")),
    ("GET", "/admin/challenge", Sqnr("challenge/response auth")),
    ("POST", "/admin/command", Sqnr("signed transactions")),
    ("POST", "/beacon/beat", Cli("sqex beacon")),
    ("POST", "/beacon/read", Cli("sqex beacon read")),
    ("POST", "/admission/request", Chat("sqex-chat admit")),
    ("POST", "/profile/put", Chat("/profile")),
    ("POST", "/profile/get", Chat("Chat::refresh_profiles")),
    ("POST", "/block/set", Chat("/block, /unblock")),
    ("POST", "/block/list", Chat("/blocked")),
    ("POST", "/device/register", Chat("Chat::register_self")),
    ("POST", "/device/revoke", Chat("Chat::revoke_device")),
    ("POST", "/device/list", Chat("Chat::my_devices")),
    ("POST", "/blob/limits", Chat("Chat::send_file")),
    ("POST", "/blob/begin", Chat("Chat::send_file")),
    ("POST", "/blob/put", Chat("Chat::send_file")),
    ("POST", "/blob/commit", Chat("Chat::send_file")),
    ("POST", "/blob/abort", Chat("Chat::send_file, on failure")),
    ("POST", "/blob/head", Chat("Chat::fetch_file")),
    ("POST", "/blob/get", Chat("Chat::fetch_file")),
    ("POST", "/blob/attach", Chat("/forward")),
    ("POST", "/blob/detach", Chat("Chat::redact, via Chat::detach")),
    ("POST", "/prekey/publish", Chat("Chat::top_up_prekeys")),
    ("POST", "/prekey/take", Chat("Chat::ensure_epoch")),
    ("POST", "/prekey/count", Chat("Chat::top_up_prekeys")),
    ("POST", "/prekey/clear", Chat("Chat::top_up_prekeys, after a lost store")),
    ("POST", "/channel/create", Chat("/new, /public, open_dm")),
    ("POST", "/channel/join", Chat("/join")),
    ("POST", "/channel/leave", Chat("/leave")),
    ("POST", "/channel/post", Chat("Chat::send_body")),
    ("POST", "/channel/info", Chat("Chat::info")),
    ("POST", "/channel/retain", Chat("/retain")),
    // `/name` and `/topic` on a public channel: the sealed entry members fold
    // goes to `/channel/post`, and this is the directory copy strangers search.
    ("POST", "/channel/directory", Chat("/name")),
    ("POST", "/channel/close", Chat("/close yes")),
    ("POST", "/channel/mine", Chat("Chat::mine")),
    ("POST", "/channel/list", Chat("/find")),
    ("POST", "/channel/invite", Chat("/invite")),
    ("POST", "/channel/remove", Chat("/kick")),
    // SIP-35. The peering routes are called by another exchange rather than by
    // a person, which is what `Peer` says: the caller is `sqexd::replica`,
    // driven from `replicate` entries in the config.
    ("POST", "/channel/replicate", Chat("/replicate")),
    ("POST", "/channel/unreplicate", Chat("/unreplicate")),
    ("POST", "/peer/hello", Peer("replica::pull_once")),
    ("POST", "/peer/pull", Peer("replica::pull_once")),
    ("POST", "/peer/envelopes", Peer("replica::pull_envelopes")),
    ("POST", "/peer/blobs", Peer("replica::pull_blobs")),
    ("POST", "/peer/records", Peer("replica::pull_profiles")),
    // Reached when a fetch is refused with `equivocated`: the client asks for
    // the evidence rather than reporting a bare refusal.
    ("POST", "/channel/equivocation", Chat("Chat::poll, on an equivocated refusal")),
    ("POST", "/channel/key/put", Chat("Chat::ensure_epoch")),
    ("POST", "/channel/key/get", Chat("Chat::collect_keys")),
    ("POST", "/channel/key/missing", Chat("Chat::stranded")),
    ("POST", "/channel/cursor", Chat("Chat::mark_read")),
    ("POST", "/channel/cursors", Chat("/read")),
    ("POST", "/channel/redact", Chat("/redact")),
    ("POST", "/channel/signal", Chat("Chat::typing")),
    ("POST", "/channel/fetch", Chat("Chat::poll")),
    // Not in the dispatch match: an event stream has no body to return, so
    // it is answered in `handle_stream` before `route` is reached. `served()`
    // scans for that shape too, or this route would be invisible here — which
    // is the exact failure this file exists to prevent.
    ("POST", "/events", Chat("Chat::subscribe")),
    ("POST", "/room/join", Voice("sqex-voice rooms")),
    ("POST", "/room/leave", Voice("sqex-voice rooms")),
    ("POST", "/mailbox/send", Cli("sqex mail send")),
    ("POST", "/mailbox/list", Cli("sqex mail list")),
    ("POST", "/mailbox/fetch", Cli("sqex mail fetch")),
    ("POST", "/mailbox/delete", Cli("sqex mail delete")),
    ("POST", "/mailbox/status", Cli("sqex mail status")),
    ("POST", "/session/open", Cli("sqex session")),
    ("POST", "/session/send", Cli("sqex session")),
    ("POST", "/session/recv", Cli("sqex session")),
    ("POST", "/session/close", Cli("sqex session")),
    ("GET", "/exchange/ping", Probe),
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
        .map(|(m, p, _)| (m.to_string(), p.to_string()))
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
        .filter(|(_, _, by)| matches!(by, Unreachable(_)))
        .map(|(_, p, _)| *p)
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
