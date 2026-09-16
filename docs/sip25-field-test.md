# SIP-25 field test — the two-homes runbook

SIP-25 (rendezvous & introduction) is implemented and its coordination is
loopback-tested, but the spec keeps it **Draft** deliberately: the property that
matters — that a direct connection survives real NAT — "cannot be demonstrated
from a desk." Loopback has no NAT; a public cloud host has no NAT. The only
evidence that promotes SIP-25 is running `sqex meet` between **two residential
networks**. This is that procedure.

## What you need
- The exchange reachable by both parties. `ex.squic.org` (UDP/443) works.
- Two people (or two networks), each on ordinary home broadband — **not** the
  same LAN, and not a VPN/cloud host (those have no NAT to traverse, so a success
  proves nothing). Ideally test a few network pairs; CGNAT and symmetric NAT are
  the cases that break it.
- `sqex` built and each party's identity keypair (`~/.sqnr/…`).

## The run
Both parties, at roughly the same time (the exchange coordinates the exact
moment, but both must be waiting):

```sh
# Party A meets B's identity; B meets A's. wait_secs is how long each long-polls.
sqex --server ex.squic.org meet <peer-pubkey> --wait 30
```

- Neither side learns anything until **both** have asked — that's the consent
  rule; a one-sided `meet` just waits and then reports nothing.
- When both are waiting, the exchange tells each the other's *observed* address
  and a shared start time; both drop the exchange connection, reuse that local
  port, punch, and (lower key dials / higher key listens) connect directly. The
  listener admits only the peer it was introduced to, and once connected the
  two agree a SIP-12 key over the connection, so `meet` proves the whole of
  what a call needs and not only the hole.

### With audio

The same flow carries a call. Both parties:

```sh
sqex-voice call <peer-pubkey> --direct --seconds 20
```

`connected directly to <addr> (SIP-25)` means the call is going between the
two homes; `relayed by the exchange: …` means the introduction was made and the
punch failed (or the peer never asked), and the call went through the exchange
as SIP-12 always has. Either way there is audio: the fallback is the point.

### In sigil

A direct-message call in sigil does this by default. Place a call, answer it,
and read the call bar: **direct** or **via exchange** (hover the second for
why). The setting is in the Desktop pane — "Connect calls directly when
possible" — and it discloses your address to the other person, which is what
the introduction is.

## Reading the result
- **Success:** a direct sQUIC connection establishes between the two homes with
  no relay — this is the evidence SIP-25 needs. Record both NAT types.
- **`unreachable`:** the punch did not open a path. Expected on **symmetric NAT**
  and most **CGNAT** (the mapping is per-destination, so the port the exchange
  observed is not the one the peer can reach). This is a known limit, not a bug —
  the fallback is the SIP-12 relay, and the message says so.
- Capture: each side's NAT type (full-cone / restricted / port-restricted /
  symmetric / CGNAT), success or failure, and the observed vs actual ports.

## A partial test that does NOT count
Running `meet` between a NATed laptop and a public host (e.g. a cloud VM, or two
processes on one machine) proves the coordination and port-reuse mechanics over
the real internet, but **not** NAT traversal — one or both sides have no NAT.
Useful as a smoke test of the plumbing; it is not the promotion evidence.

## Promotion
Per `sips/sip-0025.md`, SIP-25 moves from Draft once direct connection is shown
to survive real NAT across a representative set of home networks. Until then it
stays Draft, and SIP-12 relay remains the documented fallback for the cases
punching cannot reach.
