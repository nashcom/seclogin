#!/bin/bash
# Install seclogin_ed25519 public key in seclogin authorized_keys with ForceCommand
# Run this on the auth server after create_auth_key.sh
# Usage: sudo ./install_auth_key.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

AUTH_KEY_PUB="${AUTH_KEY_FILE}.pub"
AUTHORIZED_KEYS="${AUTH_HOME}/.ssh/authorized_keys"

error()
{
    echo "ERROR: $*" >&2
    exit 1
}

header()
{
    echo
    echo "------------------------------------------------------------"
    echo " $*"
    echo "------------------------------------------------------------"
    echo
}

if [ "$(id -u)" -ne 0 ]; then
    error "Run as root (sudo $0)"
fi

if [ ! -f "$AUTH_KEY_PUB" ]; then
    error "$AUTH_KEY_PUB not found. Run sudo $SCRIPT_DIR/create_auth_key.sh first."
fi

PUBKEY=$(cat "$AUTH_KEY_PUB")
ENTRY="command=\"${INSTALL_DIR}/${BIN} --verify\",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ${PUBKEY}"

header "Installing to $AUTHORIZED_KEYS"

mkdir -p "$(dirname "$AUTHORIZED_KEYS")"
chmod 700 "$(dirname "$AUTHORIZED_KEYS")"

if grep -qF "$PUBKEY" "$AUTHORIZED_KEYS" 2>/dev/null; then
    echo "Key already present — skipping"
else
    echo "$ENTRY" >> "$AUTHORIZED_KEYS"
    chown "$AUTH_USER:$AUTH_USER" "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
    echo "Added."
fi

header "Installed entry"

grep -F "$PUBKEY" "$AUTHORIZED_KEYS"

header "Done"
