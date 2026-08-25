#!/usr/bin/env bash
# sqex-first-time-setup.sh
#
# Authorize a YubiKey as a sqex admin and turn on the whitelist, end to end.
# Targets the LOCAL dev case: it stands up a sqexd on this machine that trusts
# your card. For a REMOTE server, see "Remote server" at the bottom.
#
# Requires `sqnr`, `sqex`, and `sqexd` on PATH. Get them there with, e.g.:
#     export PATH="$PWD/sqnr/target/debug:$PWD/sqex/target/debug:$PATH"
# `ykman` is optional (only to set the touch policy).
#
# You will be prompted for the YubiKey PIN (and, for touch policy, the admin
# PIN) by the tools themselves. This script never sees or stores them.
set -euo pipefail

# --- edit these ------------------------------------------------------------
LISTEN="127.0.0.1:5400"                       # where the local sqexd listens
SQEX_HOME="${SQEX_HOME:-$HOME/.sqex-dev}"     # local server key/state/config
# ---------------------------------------------------------------------------
CONFIG="$SQEX_HOME/sqexd.toml"
KEY_FILE="$SQEX_HOME/host.key"
STATE_FILE="$SQEX_HOME/sqex.state"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1 (not on PATH)"; exit 1; }; }
need sqnr; need sqex; need sqexd
mkdir -p "$SQEX_HOME"

echo "==> 1. Checking the YubiKey has an Ed25519 Authentication key"
if ! ADMIN=$(sqnr --yubikey pubkey 2>/dev/null); then
  cat <<'EOF'
    No Ed25519 auth key found on the card.

    Provision it ONCE — this GENERATES a new key on the card's Authentication
    slot and OVERWRITES anything already there, so do it deliberately. From the
    sqex tree:

        cargo run --bin yubikey_spike -- --provision

    Then re-run this script.
EOF
  exit 1
fi
echo "    admin key: $ADMIN"

echo "==> 2. Requiring a touch per signature (optional; prompts for the admin PIN)"
if command -v ykman >/dev/null 2>&1; then
  ykman openpgp keys set-touch aut on \
    || echo "    (skipped — set later: ykman openpgp keys set-touch aut on)"
else
  echo "    ykman not found; set later: ykman openpgp keys set-touch aut on"
fi

echo "==> 3. Writing the local sqexd config with your card as an admin"
cat > "$CONFIG" <<EOF
listen = "$LISTEN"
key_file = "$KEY_FILE"
state_file = "$STATE_FILE"
admins = ["$ADMIN"]
seed_whitelist = []
challenge_ttl_secs = 30
EOF
echo "    wrote $CONFIG"

echo "==> 4. Server key (generated on first run)"
SERVER_KEY=$(sqexd --config "$CONFIG" --show-pubkey 2>/dev/null)
echo "    server key: $SERVER_KEY"

echo "==> 5. Saving connection defaults to ~/.sqnr/config (so sqex needs no flags)"
mkdir -p "$HOME/.sqnr"; chmod 700 "$HOME/.sqnr"
cat > "$HOME/.sqnr/config" <<EOF
server = "$LISTEN"
server_key = "$SERVER_KEY"
EOF

echo "==> 6. Starting sqexd in the background"
sqexd --config "$CONFIG" >"$SQEX_HOME/sqexd.log" 2>&1 &
SQEXD_PID=$!
sleep 1
# Fail loudly if it didn't come up (most often: something else already on
# $LISTEN). Otherwise step 7 would hit the wrong server and time out.
if ! kill -0 "$SQEXD_PID" 2>/dev/null; then
    echo "    sqexd failed to start — last log lines:"
    tail -3 "$SQEX_HOME/sqexd.log" | sed 's/^/      /'
    echo "    Is another sqexd already on $LISTEN? Stop it (e.g. pkill sqexd)"
    echo "    or change LISTEN at the top of this script, then re-run."
    exit 1
fi
echo "    sqexd pid $SQEXD_PID (log: $SQEX_HOME/sqexd.log)"

echo "==> 7. Enabling the whitelist (enter your PIN, then touch the key)"
sqex --yubikey admin whitelist enable

cat <<EOF

Done. sqexd is running (pid $SQEXD_PID) at $LISTEN, trusting your YubiKey.

Try:
    sqex status                                         # public, no card
    sqex --yubikey admin whitelist list                 # PIN + touch
    sqex --yubikey admin whitelist add <peer-base58>    # add a peer
    sqex --yubikey admin audit -n 20

Stop the server:  kill $SQEXD_PID

Remote server: skip steps 3-6. Instead, give the "admin key" from step 1 to
whoever runs the server so they add it to their sqexd `admins`, set
server/server_key for that host in ~/.sqnr/config, and run step 7's command.
EOF
