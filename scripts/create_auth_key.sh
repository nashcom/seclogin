#!/bin/bash
# Generate the Ed25519 SSH keypair for seclogin remote verification
# Keypair lives in /etc/seclogin/ alongside all other seclogin files
# Run this on the auth server
# Usage: sudo ./create_auth_key.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

AUTH_KEY_PRIV="$AUTH_KEY_FILE"
AUTH_KEY_PUB="${AUTH_KEY_FILE}.pub"

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

if ! getent passwd "$AUTH_USER" > /dev/null 2>&1; then
    error "User '$AUTH_USER' not found — run sudo $SCRIPT_DIR/create_seclogin_user.sh first"
fi

# ensure config directory exists
mkdir -p "$SECLOGIN_DIR"
chown "root:$ADMIN_GROUP" "$SECLOGIN_DIR"
chmod 750 "$SECLOGIN_DIR"

if [ -f "$AUTH_KEY_PRIV" ]; then
    echo "Keypair already exists — skipping generation"
else
    header "Generating Ed25519 keypair"

    ssh-keygen -t ed25519 -f "$AUTH_KEY_PRIV" -N "" -C "seclogin-auth"

    chown "root:$ADMIN_GROUP" "$AUTH_KEY_PRIV" "$AUTH_KEY_PUB"
    chmod 640 "$AUTH_KEY_PRIV"
    chmod 644 "$AUTH_KEY_PUB"
fi

header "Done"

echo "Private key: $AUTH_KEY_PRIV"
echo "Public key:  $AUTH_KEY_PUB"
echo "Fingerprint: $(ssh-keygen -l -f $AUTH_KEY_PUB)"
echo ""
