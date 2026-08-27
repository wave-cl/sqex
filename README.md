# sqex — the sQUIC exchange

sqex is a service that identities already authenticated by their sQUIC
connection can use without signing anything further. It speaks **HTTP/3 over
sQUIC**, and the connection's verified Ed25519 identity (SIP-3) is the caller —
there is no login, no session token and no account to create.

On that foundation it runs several services: a liveness beacon, a
store-and-forward mailbox, relayed sessions with real-time voice, rooms, and an
**end-to-end encrypted chat stack**. Administrators manage the connection
whitelist with **Ed25519-signed commands**, ready for a YubiKey.

## Install

Clients (`sqex`, `sqex-chat`) and the server (`sqexd`):

```
curl -fsSL https://raw.githubusercontent.com/wave-cl/sqex/main/install.sh | sh
```

Set up a server (Linux, root — installs and starts `sqexd` under systemd):

```
curl -fsSL https://raw.githubusercontent.com/wave-cl/sqex/main/install.sh | sh -s -- --server
```

You also need a signing identity for admin commands — install
[sqnr](https://github.com/wave-cl/sqnr) and run `sqnr keygen`, or use a YubiKey.

## Pointing the CLI at a server

`sqex` resolves the server address and pinned key with the precedence
**flag > environment > `~/.sqnr/config`**:

```
sqex --server host:5400 --server-key <b58> status   # flags
SQEX_SERVER=host:5400 SQEX_SERVER_KEY=<b58> sqex status   # environment
# or set server / server_key in ~/.sqnr/config and just: sqex status
```

`SQEXD_LOG` sets the server's log filter (`RUST_LOG`-style; default `info`).

## Services

| Service | SIP | Client |
|---|---|---|
| Signed administration | [10](https://github.com/wave-cl/sips/blob/main/sip-0010.md) | `sqex admin` |
| Liveness beacon | [4](https://github.com/wave-cl/sips/blob/main/sip-0004.md) | `sqex beacon` |
| Store-and-forward mailbox | [5](https://github.com/wave-cl/sips/blob/main/sip-0005.md) | `sqex mail` |
| Relayed session | [12](https://github.com/wave-cl/sips/blob/main/sip-0012.md) | `sqex session talk` |
| Rooms and voice | [13](https://github.com/wave-cl/sips/blob/main/sip-0013.md), [15](https://github.com/wave-cl/sips/blob/main/sip-0015.md) | `sqex-voice call`, `sqex-voice room` |
| Chat: messages, groups, public channels, files | [16–24](https://github.com/wave-cl/sips/blob/main/sip-0016.md) | `sqex-chat` |

## Chat

Nine SIPs, 40 routes: channels with a durable ordered log, per-epoch channel
keys, chunked blobs, message structure, portable delegation credentials,
profiles and blocking, a device registry, X3DH prekeys, and admission requests.

What the exchange can see is ordering, membership and retention. What it cannot
see is a channel key, a message, a file, or a private channel's name — those are
sealed by the members, and `sqexd` has no module that would open them. Forward
secrecy comes from single-use prekeys: a device publishes them in advance, the
exchange serves each once, and the sender's envelope carries a fresh key at both
ends, so a stored pile of envelopes does not become readable when an identity
key later turns up.

Two rules the exchange is structurally unable to check are implemented in
`sqex-proto` as types a client uses rather than as advice, and `sqex-chat`
calls both:

- `channel_key::Replay` refuses an entry whose `(device, epoch, msg_seq)` has
  been seen before.
- `prekey::Pool` owns a device's prekey secrets and the id counter, spends a
  one-time secret exactly once, and refuses an envelope naming one already
  spent — which is how a recipient notices an exchange serving the same prekey
  twice.

The client for it is `sqex-chat` — direct messages, private groups, public
channels and files, in a terminal, across as many of your own clients as you
care to link.

```
sqex-chat whoami             # your identity, to give to somebody
sqex-chat add <their-key>    # somebody you want to write to first
sqex-chat                    # the conversations
sqex-chat device link <key>  # authorise another of your own clients
```

Inside: `/public <name>` makes a channel anybody may find, `/find [query]`
searches the directory and `/join <n>` enters one by number. `/new <name>` makes
a private group instead, `/invite` and `/kick` change who is in it, `/rotate`
hands everyone a new key, `/who` lists the members, `/file` and `/save` move
files, and `^N` adds a contact.

A private group's name is a sealed entry, so the exchange never learns what it
is called. A public channel's is not, and cannot be: the directory is how
somebody finds a room nobody told them about. Public rows carry a yellow `#`,
because "anybody can read this" is the one thing worth seeing before you type.

`/kick` rotates, and that is not optional: the exchange refuses a removed member
further entries, but they keep every key they were ever given, so without a new
epoch they could still read what follows from the exchange's own copy. `/rotate`
is also the way to re-key somebody who cannot open what they were sent — an
envelope is one per recipient per epoch and the exchange will not replace it, so
re-inviting them does nothing.

### The client keeps the keys, and has to

This is the part of the design that surprises people, so it is worth stating
before somebody loses a conversation to it.

An epoch key reaches a device inside an envelope sealed against a **single-use**
prekey, and opening that envelope spends the prekey. Ask the exchange for the
same envelope tomorrow and it will hand over the same bytes to no effect,
because the secret that opened them is gone. That is the forward secrecy
working exactly as intended, and it means the copy `sqex-chat` writes to
`~/.sqex/chat` is the only copy that will exist — unless you have made another
one, which is what linking a second client is.

**That is the closest thing to a backup this design offers, and it is worth
knowing before you need it.** A linked client holds its own copy of every epoch
key its siblings have handed it, so losing one machine stops being losing the
conversation. Nothing else recovers it: an exchange refuses a second envelope
for a recipient at an epoch, so a client that lost its store cannot simply be
sent the key again — the remedy is `/rotate`, which hands out the *next* epoch
and never a past one.

So losing that directory loses the conversations in it, permanently, for
everybody including you. The store is SQLite with every secret sealed under a
key derived from your identity seed — per row rather than by encrypting the
file, so the schema stays legible while holding no key material. Deriving from
the seed is also why **a YubiKey identity cannot use `sqex-chat`**: a card never
releases its seed, which is the same reason `sqex mail` and `sqex session`
refuse one.

Two things soften that, and neither recovers a message. The exchange returns the
**message counter** — kept per device per epoch, independently of pruning,
precisely so a client that lost the number resumes rather than guesses, since
reusing one would cost the confidentiality of two messages. And SIP-23's
`Clear` lets a device discard the prekeys the exchange is still serving on its
behalf, whose secrets went with the store; without it, peers keep sealing to
keys that will never open and two such clients rotate past each other
indefinitely.

So a client that loses its store keeps its identity and its conversations, and
loses their history. `sqex-chat` says so where it happened — a line in the
transcript, once, rather than a permanent count of failures in the status bar,
because the one is history and the other is a fault to chase.

### Who can find you

A direct message's identifier is derived from the two account keys, so starting
one needs nothing from the exchange. **Being found used to.** A private channel
is invisible to the directory under any query by design, and every other
operation takes its 32-byte identifier as input — so an invitation reached an
account with no way to discover it had happened.

SIP-16's `Mine` closes that: it answers *"which channels am I in"*, about the
caller and nobody else, and `sqex-chat` asks on startup. Somebody who writes to
you first is found and added without your knowing them in advance, and a group
you are invited to appears without anybody sending you its identifier.

A **public** channel is the opposite case and needs none of that: it is in the
directory, `/find` searches it by name and topic, and joining is one request
with nothing granted to you. Private channels never appear there under any
query, which is the rule that stops an identifier being a way in.

For a direct message the identifier is a hash and cannot be run backwards, so
the other party comes from the member list the exchange enforces — and is then
checked by re-deriving the identifier from it. A channel that does not hash
back is not a direct message with that person, whatever the exchange said.

## How admin commands work

Admins sign **transactions** — an ordered batch of operations — with
[sqnr](https://github.com/wave-cl/sqnr), the generic signer. sqex only supplies
the command vocabulary (`sqex-proto`); the signer never parses a payload.

1. `GET /admin/challenge` → the server returns a single-use 32-byte nonce.
2. The client builds one or more ops (each an opaque payload + a human summary),
   assembles `Transaction { server, nonce, ops }`, and signs its hash
   (`sqnr-tx-v1`) once with the admin Ed25519 key.
3. `POST /admin/command` with `{ transaction, admin_pubkey, signature }`.
4. The server checks, in order: the nonce is one it issued and has not used; the
   transaction names this server; the signature verifies under `admin_pubkey`;
   `admin_pubkey` is in the configured admin list; and every op decodes with a
   summary matching what it will do. Only then does it apply the batch
   **atomically** (all ops, or none).

Ops: enable/disable the whitelist, add/remove a peer key, list it, read status,
reload the admin list, read the audit tail, and list, admit and deny pending
SIP-24 admission requests. Every mutation is recorded to a
persisted audit log (who, what, when).

The three admission ops are in the vocabulary and executed by the server, but
`sqex admin` does not expose them yet: it covers `whitelist`, `audit` and
`reload-admins`. Deciding on a request today means building the op through
`sqex-proto`.

## Why signed commands

sQUIC proves a caller's key during the handshake, so a service need not
re-authenticate the connection. But some authority cannot ride on the
connection at all: a **YubiKey** signs with an Ed25519 key and never releases
the seed, and sQUIC's transport identity needs that seed to derive its X25519
key. So an administrator authenticated by a YubiKey cannot be recognised by the
transport `peer_key`.

sqex therefore takes authority from an **application-layer Ed25519 signature on
the command itself**, verified against a list of admin public keys in the config
file — independent of the connection's transport key. A software signer and a
YubiKey are interchangeable behind one trait, so the protocol is hardware-ready
from the start.

## Whitelist enforcement

The managed whitelist is sqex's own connection ACL, but it is enforced at the
HTTP/3 layer using the transport's verified peer key (SIP-2 `peer_key`), **not**
as sQUIC's transport whitelist. Gating the transport would drop the admin
surface the moment the whitelist was enabled, since YubiKey admins have no
stable transport key. So sQUIC accepts anyone holding the server key, and sqex
answers `403` on protected endpoints for a peer whose key is not whitelisted.
Admin commands are signature-gated and always reachable.

Which routes are protected is an operator's policy, and today only
`/exchange/ping` is — it is there to demonstrate the mechanism. The chat routes
are open to any advertised identity. SIP-24 covers the case where they should
not be, and the queue and the admin ops for it are implemented; wiring
enforcement onto a chosen set of routes is not.

## Storage

With `state_file` set, `sqexd` keeps the whitelist and audit log in that file
and puts four SQLite databases beside it: `channels.db`, `devices.db`,
`profiles.db` and `prekeys.db`. SQLite is bundled (no system library), and the
channel log runs in WAL mode with `synchronous = FULL` — this is the service
that promised to remember, so an entry is on the disk before the exchange says
it accepted it.

`prekeys.db` is there because of a bug worth knowing about if you are building
something similar. Prekeys were held in memory on the argument that one
outliving the device that made it is a key whose secret is gone. But a server
bounce does not restart its clients, and a client whose own pool looks healthy
has no reason to publish again — so restarting the exchange quietly made every
registered device unsealable-to, and no channel key could reach anybody. A
client now asks what the exchange holds rather than trusting its own count.

Omit `state_file` and everything is in memory and lost on restart, which is what
the tests use.

## Layout

- `sqex-proto` — every wire format, and the client-side logic for the ones the
  exchange must not be able to perform: sealing, opening, the prekey pool, the
  replay check, the timeline reader.
- `sqexd` — the HTTP/3 server: whitelist store, audit log, transaction
  execution, and the beacon, mailbox, session, room, channel, blob, device,
  prekey, profile and admission services.
- `sqex-cli` — the `sqex` command-line tool (signs via sqnr).
- `sqex-voice` — calls and rooms: capture, Opus, relay, mix, play.
- `sqex-chat` — the terminal chat client, and the client-side key store the
  chat stack needs and the exchange cannot provide.
- `sqex-admin` — the desktop GUI (YubiKey), parked.

## Running

```
sqexd keygen                 # writes an identity key on first run
sqexd --config etc/sqexd.toml
sqexd --show-pubkey          # the key clients pin
```

Built on [squic](https://github.com/wave-cl/squic-rust). Design proposals live
in [sips](https://github.com/wave-cl/sips).
