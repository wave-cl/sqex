# sqex — the sQUIC exchange

sqex is a service that identities already authenticated by their sQUIC
connection can use without signing anything further. It speaks **HTTP/3 over
sQUIC** and, as its first capability, lets administrators manage its connection
whitelist by **Ed25519-signed commands** — ready for a YubiKey.

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

Every command is replay-protected by challenge-response and bound to this
server:

1. `GET /admin/challenge` → the server returns a single-use 32-byte nonce.
2. The admin signs the canonical bytes of `{ action, nonce, server_pubkey }`
   with their Ed25519 key (domain-separated by `sqex-admin-v1`).
3. `POST /admin/command` with `{ command, admin_pubkey, signature }`.
4. The server checks, in order: the nonce is one it issued and has not used;
   the command names this server; the signature verifies under `admin_pubkey`;
   and `admin_pubkey` is in the configured admin list. Only then does it act.

Actions: enable/disable the whitelist, add/remove a peer key, list it, read
status, reload the admin list, and read the audit tail. Every mutation is
recorded to a persisted audit log (who, what, when).

## Whitelist enforcement

The managed whitelist is sqex's own connection ACL, but it is enforced at the
HTTP/3 layer using the transport's verified peer key (SIP-2 `peer_key`), **not**
as sQUIC's transport whitelist. Gating the transport would drop the admin
surface the moment the whitelist was enabled, since YubiKey admins have no
stable transport key. So sQUIC accepts anyone holding the server key, and sqex
answers `403` on protected endpoints for a peer whose key is not whitelisted.
Admin commands are signature-gated and always reachable.

## Layout

- `sqex-core` — keys and the signed admin-command protocol (no networking).
- `sqexd` — the HTTP/3 server, whitelist store, audit log, command execution.
- `sqex-admin` — the desktop admin app (YubiKey), under construction.

## Running

```
sqexd keygen                 # writes an identity key on first run
sqexd --config etc/sqexd.toml
sqexd --show-pubkey          # the key clients pin
```

Built on [squic](https://github.com/wave-cl/squic-rust). Design proposals live
in [sips](https://github.com/wave-cl/sips).
