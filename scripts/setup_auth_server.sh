#!/bin/bash
# Set up seclogin auth server — run once on the auth server
# Steps: seclogin user → TOTP verify secret → SSH keypair → binary (no SUID) → ForceCommand → host key trust
# Note: run create_accounts.sh first if sysadmin user does not yet exist on this server
# Usage: sudo ./setup_auth_server.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

AUTH_KEY_PRIV="$AUTH_KEY_FILE"   # /etc/seclogin/seclogin_ed25519

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

info()
{
    echo "  - $*"
}

ask()
{
    printf "  %s [y/N] " "$*"
    read -r answer
    [ "${answer,,}" = "y" ]
}

if [ "$(id -u)" -ne 0 ]; then
    error "Run as root (sudo $0)"
fi

HOSTNAME=$(hostname -f 2>/dev/null || hostname)

header "seclogin auth server setup — $HOSTNAME"

# ---------------------------------------------------------------------------
# Step 1: seclogin user
# ---------------------------------------------------------------------------

header "Step 1: seclogin user"

if getent passwd "$AUTH_USER" > /dev/null 2>&1; then
    info "User '$AUTH_USER' already exists — skipping creation"
else
    "$SCRIPT_DIR/create_seclogin_user.sh"
fi

# seclogin's primary group IS the seclogin group — no extra membership needed

# ---------------------------------------------------------------------------
# Step 2: TOTP secret
# ---------------------------------------------------------------------------

header "Step 2: TOTP secret"

if [ -f "$SECLOGIN_DIR/totp_verify.secret" ]; then
    info "Verify secret exists: $(ls -lh $SECLOGIN_DIR/totp_verify.secret | awk '{print $1, $3, $4}')"
elif [ -f "$SECLOGIN_DIR/totp.secret" ]; then
    info "totp.secret found — copying to totp_verify.secret (same secret, same authenticator enrollment)"
    cp "$SECLOGIN_DIR/totp.secret" "$SECLOGIN_DIR/totp_verify.secret"
    chown "root:$AUTH_USER" "$SECLOGIN_DIR/totp_verify.secret"
    chmod 640 "$SECLOGIN_DIR/totp_verify.secret"
    info "Verify secret: $(ls -lh $SECLOGIN_DIR/totp_verify.secret | awk '{print $1, $3, $4}')"
else
    info "Generating new TOTP verify secret: $SECLOGIN_DIR/totp_verify.secret"
    "$SCRIPT_DIR/create_totp.sh" SHA256 "$ADMIN_USER" "$SECLOGIN_DIR/totp_verify.secret"
    chown "root:$AUTH_USER" "$SECLOGIN_DIR/totp_verify.secret"
    chmod 640 "$SECLOGIN_DIR/totp_verify.secret"
    info "Verify secret: $(ls -lh $SECLOGIN_DIR/totp_verify.secret | awk '{print $1, $3, $4}')"
fi

# Auth server config must be readable by the seclogin user (after seteuid drop in --verify)
chown "root:$AUTH_USER" "$CONFIG_FILE"
chmod 640 "$CONFIG_FILE"
info "Config permissions set for auth server: $(ls -lh $CONFIG_FILE | awk '{print $1, $3, $4}')"

# ---------------------------------------------------------------------------
# Step 3: SSH keypair
# ---------------------------------------------------------------------------

header "Step 3: SSH keypair for target servers"

if [ -f "$AUTH_KEY_PRIV" ]; then
    info "Keypair already exists: $AUTH_KEY_PRIV"
else
    "$SCRIPT_DIR/create_auth_key.sh"
fi

# Key lives in $AUTH_KEY_FILE — readable by sysadmin (seclogin group, 640)
# Target admins SCP directly from $AUTH_KEY_FILE — no copy to sysadmin home needed
info "Auth key: $AUTH_KEY_FILE ($(ls -lh $AUTH_KEY_FILE | awk '{print $1, $3, $4}'))"

# ---------------------------------------------------------------------------
# Step 4: Install binary (no SUID — auth server never needs root)
# ---------------------------------------------------------------------------

header "Step 4: Install binary (root:$AUTH_USER $AUTH_MODE — no SUID)"

if [ ! -f "$INSTALL_DIR/$BIN" ]; then
    error "Binary not found at $INSTALL_DIR/$BIN — build first with ./build_alpine.sh, then copy here"
fi

chown "root:$AUTH_USER" "$INSTALL_DIR/$BIN"
chmod "$AUTH_MODE" "$INSTALL_DIR/$BIN"
info "$(ls -lh $INSTALL_DIR/$BIN)"

# ---------------------------------------------------------------------------
# Step 5: ForceCommand in authorized_keys
# ---------------------------------------------------------------------------

header "Step 5: ForceCommand in $AUTH_USER authorized_keys"

"$SCRIPT_DIR/install_auth_key.sh"

# ---------------------------------------------------------------------------
# Step 6: Host key trust
# ---------------------------------------------------------------------------

header "Step 6: Host key trust"

echo ""
echo "  seclogin needs to trust this server's SSH host key."
echo "  The safest way is to connect once manually and verify the fingerprint."
echo ""
echo "  This server's host key fingerprints:"
echo ""
for key in /etc/ssh/ssh_host_*_key.pub; do
    [ -f "$key" ] || continue
    ssh-keygen -l -f "$key" 2>/dev/null && echo ""
done

echo "  Run this on each target server to populate $SECLOGIN_DIR/known_hosts:"
echo ""
echo "    mkdir -p $SECLOGIN_DIR"
echo "    touch $SECLOGIN_DIR/known_hosts"
echo "    chown root:${ADMIN_GROUP} $SECLOGIN_DIR/known_hosts"
echo "    chmod 640 $SECLOGIN_DIR/known_hosts"
echo "    ssh -o UserKnownHostsFile=$SECLOGIN_DIR/known_hosts \\"
echo "        -i ${AUTH_KEY_FILE} \\"
echo "        ${AUTH_USER}@${HOSTNAME}"
echo ""
echo "  Verify the fingerprint matches above, type yes, then Ctrl+C."
echo "  The host key is written directly to $SECLOGIN_DIR/known_hosts."
echo ""

# ---------------------------------------------------------------------------
# Step 7: Summary and target server config
# ---------------------------------------------------------------------------

header "Step 7: Auth server setup complete"

echo "  Auth server: ${AUTH_USER}@${HOSTNAME}"
echo "  Keypair:     $AUTH_KEY_PRIV"
echo ""
echo "  Run this to show target server deployment instructions:"
echo "    sudo $SCRIPT_DIR/show_target_config.sh"
echo ""
