# sqex — the sQUIC exchange

sqex is a service that identities already authenticated by their sQUIC
connection can use without signing anything further. It speaks **HTTP/3 over
sQUIC** and, as its first capability, lets administrators manage its connection
whitelist by **Ed25519-signed commands** — ready for a YubiKey.

## Install

Admin client (`sqex`, and `sqexd`):

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

## Why

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
reload the admin list, and read the audit tail. Every mutation is recorded to a
persisted audit log (who, what, when).

## Whitelist enforcement

The managed whitelist is sqex's own connection ACL, but it is enforced at the
HTTP/3 layer using the transport's verified peer key (SIP-2 `peer_key`), **not**
as sQUIC's transport whitelist. Gating the transport would drop the admin
surface the moment the whitelist was enabled, since YubiKey admins have no
stable transport key. So sQUIC accepts anyone holding the server key, and sqex
answers `403` on protected endpoints for a peer whose key is not whitelisted.
Admin commands are signature-gated and always reachable.

## Layout

- `sqex-proto` — the admin command vocabulary: opaque op payloads + human
  summaries, over [sqnr](https://github.com/wave-cl/sqnr) transactions.
- `sqexd` — the HTTP/3 server, whitelist store, audit log, transaction execution.
- `sqex-cli` — the `sqex` command-line admin tool (signs via sqnr).
- `sqex-admin` — the desktop GUI (YubiKey), parked.

## Running

```
sqexd keygen                 # writes an identity key on first run
sqexd --config etc/sqexd.toml
sqexd --show-pubkey          # the key clients pin
```

Built on [squic](https://github.com/wave-cl/squic-rust). Design proposals live
in [sips](https://github.com/wave-cl/sips).
