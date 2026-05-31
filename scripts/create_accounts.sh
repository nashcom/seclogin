#!/bin/bash
# Create the seclogin group and sysadmin user — run on every server (client and auth server)
#
# Creates:
#   seclogin group  — owns the binary and config; controls who can run seclogin
#   sysadmin user   — system administrator, member of seclogin group
#
# On auth server: run this before setup_auth_server.sh if sysadmin does not yet exist
# On client:      run this before installing the binary
#
# Usage: sudo ./create_accounts.sh

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

# ---------------------------------------------------------------------------
# seclogin group — owns the binary and config on every machine
# ---------------------------------------------------------------------------

header "Creating group: $ADMIN_GROUP"

if getent group "$ADMIN_GROUP" > /dev/null 2>&1; then
    echo "Group '$ADMIN_GROUP' already exists (GID $(getent group $ADMIN_GROUP | cut -d: -f3)) — skipping"
else
    groupadd "$ADMIN_GROUP"
    echo "Group '$ADMIN_GROUP' created (GID $(getent group $ADMIN_GROUP | cut -d: -f3))"
fi

# ---------------------------------------------------------------------------
# sysadmin user — member of seclogin group, gets access to seclogin binary
# ---------------------------------------------------------------------------

header "Creating user: $ADMIN_USER"

if getent passwd "$ADMIN_USER" > /dev/null 2>&1; then
    echo "User '$ADMIN_USER' already exists (UID $(id -u $ADMIN_USER)) — skipping"
else
    useradd \
        --home-dir "$ADMIN_HOME" \
        --create-home \
        --shell "$ADMIN_SHELL" \
        --comment "System Administrator" \
        "$ADMIN_USER"
    echo "User '$ADMIN_USER' created (UID $(id -u $ADMIN_USER))"
fi

# Ensure sysadmin is in the seclogin group
if ! id -nG "$ADMIN_USER" | grep -qw "$ADMIN_GROUP"; then
    usermod -aG "$ADMIN_GROUP" "$ADMIN_USER"
    echo "Added '$ADMIN_USER' to group '$ADMIN_GROUP'"
else
    echo "User '$ADMIN_USER' already in group '$ADMIN_GROUP'"
fi

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

header "Result"

echo "  Group:  $(getent group $ADMIN_GROUP)"
echo "  User:   $(id $ADMIN_USER)"
echo
