#!/bin/bash
# Create the dedicated seclogin user on the auth server
# This user runs seclogin --verify via ForceCommand — no interactive login needed
# Must be run before create_totp.sh and create_auth_key.sh
# Usage: sudo ./create_seclogin_user.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

VERIFY_SECRET_FILE="$SECLOGIN_DIR/totp_verify.secret"

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

header "Creating seclogin user"

if getent group "$AUTH_USER" > /dev/null 2>&1; then
    echo "Group '$AUTH_USER' already exists — skipping"
else
    groupadd "$AUTH_USER"
    echo "Group '$AUTH_USER' created (GID $(getent group $AUTH_USER | cut -d: -f3))"
fi

if getent passwd "$AUTH_USER" > /dev/null 2>&1; then
    echo "User '$AUTH_USER' already exists — skipping"
else
    useradd \
        --gid "$AUTH_USER" \
        --home-dir "$AUTH_HOME" \
        --create-home \
        --shell /bin/sh \
        --comment "seclogin remote verification" \
        "$AUTH_USER"
    echo "User '$AUTH_USER' created (UID $(id -u $AUTH_USER))"
fi

# seclogin user must be in the admin group to read /etc/seclogin.conf (root:sysadmin 0640)
if ! id -nG "$AUTH_USER" | grep -qw "$ADMIN_GROUP"; then
    usermod -aG "$ADMIN_GROUP" "$AUTH_USER"
    echo "Added '$AUTH_USER' to group '$ADMIN_GROUP'"
else
    echo "User '$AUTH_USER' already in group '$ADMIN_GROUP'"
fi

mkdir -p "$AUTH_HOME/.ssh"
chown "$AUTH_USER:$AUTH_USER" "$AUTH_HOME" "$AUTH_HOME/.ssh"
chmod 755 "$AUTH_HOME"
chmod 700 "$AUTH_HOME/.ssh"

# Verify secret is created directly by setup_auth_server.sh via create_totp.sh
# (with secret_file=/etc/seclogin-verify.secret) — /etc/seclogin.secret is not
# needed on the auth server and should not be created here
if [ -f "$VERIFY_SECRET_FILE" ]; then
    echo "Verify secret exists: $(ls -lh $VERIFY_SECRET_FILE | awk '{print $1, $3, $4}')"
else
    echo "Note: verify secret not found — run setup_auth_server.sh to generate it"
fi

header "Done"

echo "User:   $(id $AUTH_USER)"
echo "Home:   $AUTH_HOME"
echo "Shell:  $(getent passwd $AUTH_USER | cut -d: -f7)"
echo "Groups: $(id -nG $AUTH_USER)"
echo ""
echo ""
