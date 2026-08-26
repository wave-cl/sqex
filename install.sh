#!/bin/sh
set -e

REPO="wave-cl/sqex"
INSTALL_DIR="${SQEX_INSTALL_DIR:-}"
SERVER_MODE=false

for arg in "$@"; do
    case "$arg" in
        --server) SERVER_MODE=true ;;
    esac
done

info() { printf "  \033[1m%s\033[0m\n" "$1"; }
warn() { printf "  \033[33mwarning:\033[0m %s\n" "$1" >&2; }
err()  { printf "  \033[31merror:\033[0m %s\n" "$1" >&2; exit 1; }

# The unprivileged account sqexd runs as. It binds a port, reads its key and
# config, and writes one state snapshot — nothing that needs root.
SQEX_USER="sqex"
SQEX_GROUP="sqex"
SQEX_ID=5400

ensure_sqex_user() {
    command -v useradd >/dev/null 2>&1 ||
        err "useradd not found; create the $SQEX_USER user yourself and re-run"

    if getent group "$SQEX_GROUP" >/dev/null 2>&1; then
        info "Group $SQEX_GROUP exists (gid $(getent group "$SQEX_GROUP" | cut -d: -f3))"
    elif getent group "$SQEX_ID" >/dev/null 2>&1; then
        warn "gid $SQEX_ID is taken by $(getent group "$SQEX_ID" | cut -d: -f1); creating $SQEX_GROUP with an automatic gid"
        groupadd --system "$SQEX_GROUP"
    else
        groupadd --system --gid "$SQEX_ID" "$SQEX_GROUP"
        info "Created group $SQEX_GROUP (gid $SQEX_ID)"
    fi

    if getent passwd "$SQEX_USER" >/dev/null 2>&1; then
        info "User $SQEX_USER exists (uid $(getent passwd "$SQEX_USER" | cut -d: -f3))"
        return 0
    fi

    NOLOGIN=/bin/false
    if [ -x /usr/sbin/nologin ]; then NOLOGIN=/usr/sbin/nologin
    elif [ -x /sbin/nologin ]; then NOLOGIN=/sbin/nologin
    fi

    if getent passwd "$SQEX_ID" >/dev/null 2>&1; then
        warn "uid $SQEX_ID is taken by $(getent passwd "$SQEX_ID" | cut -d: -f1); creating $SQEX_USER with an automatic uid"
        useradd --system --gid "$SQEX_GROUP" --home-dir /var/lib/sqex \
            --no-create-home --shell "$NOLOGIN" "$SQEX_USER"
    else
        useradd --system --uid "$SQEX_ID" --gid "$SQEX_GROUP" --home-dir /var/lib/sqex \
            --no-create-home --shell "$NOLOGIN" "$SQEX_USER"
        info "Created user $SQEX_USER (uid $SQEX_ID)"
    fi
}

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)  OS_NAME="linux" ;;
    Darwin) OS_NAME="darwin" ;;
    *)      err "unsupported OS: $OS" ;;
esac

case "$ARCH" in
    x86_64|amd64)  TARGET="x86_64-linux-gnu" ;;
    aarch64|arm64) TARGET="aarch64-linux-gnu" ;;
    *)             err "unsupported architecture: $ARCH" ;;
esac

if [ "$OS_NAME" = "darwin" ]; then
    case "$ARCH" in
        x86_64|amd64)  TARGET="x86_64-apple-darwin" ;;
        aarch64|arm64) TARGET="aarch64-apple-darwin" ;;
    esac
fi

# The sqex CLI links libpcsclite (via sqnr, for the YubiKey), which is awkward to
# cross-build for Linux/aarch64; releases cover Linux x86_64 and both macOS
# arches. On aarch64 Linux, build from source.
if [ "$OS_NAME" = "linux" ] && [ "$TARGET" = "aarch64-linux-gnu" ]; then
    err "no prebuilt sqex for aarch64 Linux — build from source: cargo install --git https://github.com/$REPO sqexd sqex-cli sqex-chat"
fi

if [ -n "$INSTALL_DIR" ]; then
    BIN_DIR="$INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO- "$1"; }
else
    err "curl or wget required"
fi

info "Fetching latest release..."
LATEST=$(fetch "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
[ -z "$LATEST" ] && err "could not determine latest version"
info "Latest version: $LATEST"

URL="https://github.com/$REPO/releases/download/$LATEST/sqex-${LATEST}-${TARGET}.tar.gz"
info "Downloading sqex $LATEST for $TARGET..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

fetch "$URL" > "$TMPDIR/sqex.tar.gz" || err "download failed — no release for $TARGET?"

info "Installing to $BIN_DIR..."
mkdir -p "$BIN_DIR"
tar -xzf "$TMPDIR/sqex.tar.gz" -C "$BIN_DIR"

if ! "$BIN_DIR/sqex" --version >/dev/null 2>&1; then
    err "installation failed — sqex not executable"
fi

VERSION=$("$BIN_DIR/sqex" --version 2>&1 || echo "unknown")
info "Installed: $VERSION"

# PATH setup for non-root installs
if [ "$BIN_DIR" = "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            SHELL_NAME=$(basename "$SHELL" 2>/dev/null || echo "unknown")
            case "$SHELL_NAME" in
                bash) RC="$HOME/.bashrc"; echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"; info "Added ~/.local/bin to PATH in $RC" ;;
                zsh)  RC="$HOME/.zshrc";  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC"; info "Added ~/.local/bin to PATH in $RC" ;;
                fish) RC="$HOME/.config/fish/config.fish"; mkdir -p "$(dirname "$RC")"; echo 'fish_add_path ~/.local/bin' >> "$RC"; info "Added ~/.local/bin to PATH in $RC" ;;
                *)    info "Add $BIN_DIR to your PATH" ;;
            esac
            info "Restart your shell or run: export PATH=\"$BIN_DIR:\$PATH\""
            ;;
    esac
fi

if [ "$SERVER_MODE" = true ]; then
    info "Setting up the sqexd server..."

    [ "$(id -u)" -ne 0 ] && err "--server requires root"
    [ "$OS_NAME" != "linux" ] && err "--server is only supported on Linux"

    ensure_sqex_user

    mkdir -p /etc/sqex
    chown root:root /etc/sqex
    chmod 755 /etc/sqex
    mkdir -p /var/lib/sqex

    if [ -f /etc/sqex/sqexd.key ]; then
        info "Server key already exists, keeping it"
    else
        info "Generating the server key..."
        "$BIN_DIR/sqexd" keygen -f /etc/sqex/sqexd.key >/dev/null
        info "Server key generated"
    fi

    chown "$SQEX_USER:$SQEX_GROUP" /etc/sqex/sqexd.key
    chmod 600 /etc/sqex/sqexd.key
    chown "$SQEX_USER:$SQEX_GROUP" /var/lib/sqex
    chmod 700 /var/lib/sqex

    if [ -f /etc/sqex/sqexd.toml ]; then
        info "Config already exists, skipping"
    else
        info "Writing default config to /etc/sqex/sqexd.toml..."
        cat > /etc/sqex/sqexd.toml << 'CONF'
# sqexd configuration. See the README for every option.

listen = "[::]:5400"
key_file = "/etc/sqex/sqexd.key"
state_file = "/var/lib/sqex/sqex.state"

# Base58 Ed25519 admin keys, authorised to sign management transactions.
# Add your key (sqnr pubkey, or sqnr --yubikey pubkey) and restart, or once one
# admin exists, add more with: sqex --yubikey admin reload-admins after editing here.
admins = []

# Keys seeded into the managed whitelist on first run (base58 Ed25519).
seed_whitelist = []

challenge_ttl_secs = 30
CONF
        chmod 644 /etc/sqex/sqexd.toml
    fi

    if command -v systemctl >/dev/null 2>&1; then
        info "Installing the systemd service..."
        cat > /etc/systemd/system/sqexd.service << 'SVC'
[Unit]
Description=sqex exchange server daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sqexd --config /etc/sqex/sqexd.toml
Restart=on-failure
RestartSec=2

User=sqex
Group=sqex
StateDirectory=sqex
StateDirectoryMode=0700

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
UMask=0077
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RestrictRealtime=yes
ProtectHostname=yes
ProtectClock=yes
ProtectProc=invisible
ProcSubset=pid
# AF_UNIX and AF_NETLINK are deliberate: glibc reaches for both when resolving
# a hostname.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
SVC
        chmod 644 /etc/systemd/system/sqexd.service
        systemctl daemon-reload
        systemctl enable sqexd

        if systemctl is-active sqexd >/dev/null 2>&1; then
            info "Restarting sqexd..."
            systemctl restart sqexd
        else
            info "Starting sqexd..."
            systemctl start sqexd
        fi

        sleep 1
        if systemctl is-active sqexd >/dev/null 2>&1; then
            info "sqexd is running"
        else
            err "sqexd failed to start — check: journalctl -u sqexd"
        fi
    else
        info "systemd not found — skipping service installation"
        info "Start manually: sqexd --config /etc/sqex/sqexd.toml"
    fi

    PUBKEY=$("$BIN_DIR/sqexd" --config /etc/sqex/sqexd.toml --show-pubkey 2>/dev/null)
    HOSTNAME="$(curl -4 -fsSL -m 3 https://api.ipify.org 2>/dev/null || curl -4 -fsSL -m 3 https://ifconfig.me 2>/dev/null || hostname -f 2>/dev/null || hostname)"
    printf "\n"
    info "Server public key:"
    printf "  %s\n\n" "$PUBKEY"
    info "Next steps:"
    printf "  1. Authorise an admin: add your key to admins in /etc/sqex/sqexd.toml\n"
    printf "        (get it with: sqnr pubkey   or   sqnr --yubikey pubkey)\n"
    printf "     then: systemctl restart sqexd\n"
    printf "  2. On a client, set ~/.sqnr/config:\n"
    printf "        server = \"%s:5400\"\n" "$HOSTNAME"
    printf "        server_key = \"%s\"\n\n" "$PUBKEY"
    info "Then: sqex status   and   sqex --yubikey admin whitelist enable"
    printf "\n"
else
    printf "\n"
    info "Getting started (admin client):"
    printf "  1. Point at a server in ~/.sqnr/config:\n"
    printf "        server = \"host:5400\"\n"
    printf "        server_key = \"<base58 server pubkey>\"\n"
    printf "  2. sqex status                                   # public, no signing\n"
    printf "     sqex --yubikey admin whitelist enable         # PIN + touch\n"
    printf "     sqex --yubikey admin whitelist add <peer>     # authorise a peer\n\n"
    info "You need a signing identity — install sqnr and run 'sqnr keygen' (or use --yubikey):"
    printf "  curl -fsSL https://raw.githubusercontent.com/wave-cl/sqnr/main/install.sh | sh\n\n"
    info "Set up a server:"
    printf "  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sh -s -- --server\n\n" "$REPO"
fi
