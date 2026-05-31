#!/bin/bash
# Establish SSH trust with the auth server — populates /etc/seclogin/known_hosts
# Run this on each target server after copying the auth key
# Usage: sudo ./trust_auth_server.sh
#
# Reads auth_server from /etc/seclogin/seclogin.conf and connects once.
# Verify the fingerprint against the auth server's output, type yes, then Ctrl+C.
# The host key is written directly to /etc/seclogin/known_hosts.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

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

# Read auth_server from config
AUTH_SERVER=$(grep -i "^auth_server=" "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
if [ -z "$AUTH_SERVER" ]; then
    error "auth_server not found in $CONFIG_FILE — configure remote verify mode first"
fi

AUTH_HOST=$(echo "$AUTH_SERVER" | cut -d@ -f2)

# Ensure /etc/seclogin/ directory exists with correct permissions
if [ ! -d "$SECLOGIN_DIR" ]; then
    mkdir -p "$SECLOGIN_DIR"
    chown "root:$ADMIN_GROUP" "$SECLOGIN_DIR"
    chmod 750 "$SECLOGIN_DIR"
fi

# Create known_hosts file with correct permissions if missing
if [ ! -f "$SECLOGIN_DIR/known_hosts" ]; then
    touch "$SECLOGIN_DIR/known_hosts"
    chown "root:$ADMIN_GROUP" "$SECLOGIN_DIR/known_hosts"
    chmod 640 "$SECLOGIN_DIR/known_hosts"
    echo "  Created: $SECLOGIN_DIR/known_hosts"
fi

# Check auth key exists
if [ ! -f "$AUTH_KEY_FILE" ]; then
    error "$AUTH_KEY_FILE not found — copy it from the auth server first"
fi

header "Auth server host key fingerprints for $AUTH_HOST"

echo "  Connecting to $AUTH_SERVER to display fingerprints..."
echo "  Compare these with the fingerprints shown by setup_auth_server.sh."
echo ""

# Show fingerprints by attempting a scan (output only — not yet trusted)
ssh-keyscan "$AUTH_HOST" 2>/dev/null | ssh-keygen -l -f - 2>/dev/null || true

header "Establishing trust"

echo "  Connecting to $AUTH_SERVER..."
echo "  Verify the fingerprint above, type yes to accept, then Ctrl+C."
echo ""

ssh \
    -o UserKnownHostsFile="$SECLOGIN_DIR/known_hosts" \
    -o StrictHostKeyChecking=ask \
    -i "$AUTH_KEY_FILE" \
    "$AUTH_SERVER" || true

echo ""
if grep -q "$AUTH_HOST" "$SECLOGIN_DIR/known_hosts" 2>/dev/null || \
   [ -s "$SECLOGIN_DIR/known_hosts" ]; then
    echo "  Host key saved to $SECLOGIN_DIR/known_hosts"
    echo ""
    echo "  Verify with:"
    echo "    ssh-keygen -F $AUTH_HOST -f $SECLOGIN_DIR/known_hosts"
else
    echo "  WARNING: $SECLOGIN_DIR/known_hosts appears empty — was the fingerprint accepted?"
fi
echo ""
