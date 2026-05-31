#!/bin/bash
# Generate a TOTP secret, display QR code, and install to a secret file + /etc/seclogin.conf
# Usage: sudo ./create_totp.sh [SHA256|SHA1] [account] [secret_file]
#
#   secret_file defaults to $SECLOGIN_DIR/totp.secret (client/local mode)
#   For auth server use $SECLOGIN_DIR/totp_verify.secret:
#     sudo ./create_totp.sh SHA256 sysadmin $SECLOGIN_DIR/totp_verify.secret

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root (sudo $0)" >&2
    exit 1
fi

ALGO="${1:-SHA256}"
ALGO="${ALGO^^}"   # normalise to uppercase
ACCOUNT="${2:-$ADMIN_USER}"
SECRET_FILE="${3:-$SECLOGIN_DIR/totp.secret}"

# ensure config directory exists with correct permissions
mkdir -p "$SECLOGIN_DIR"
chown "root:$ADMIN_GROUP" "$SECLOGIN_DIR"
chmod 750 "$SECLOGIN_DIR"

case "$ALGO" in
    SHA256|SHA1) ;;
    *) echo "ERROR: Invalid algorithm '$ALGO' — use SHA256 or SHA1" >&2; exit 1 ;;
esac

if [ -f "$SECRET_FILE" ]; then
    echo "Secret already exists, showing existing configuration..."
    echo "To re-provision with a different algorithm, remove $SECRET_FILE first."
    exec "$SCRIPT_DIR/show_totp_qr.sh" "$ACCOUNT"
fi

# /dev/urandom -> base32 produces a valid TOTP secret (A-Z, 2-7 only)
SECRET=$(head -c 20 /dev/urandom | base32 | tr -d '=')

URI="otpauth://totp/${ISSUER}:${ACCOUNT}?secret=${SECRET}&issuer=${ISSUER}&algorithm=${ALGO}&digits=6&period=30"

delim()
{
    echo "------------------------------------------------------------"
}

header()
{
    echo
    delim
    echo " $*"
    delim
    echo
}

header "Installing secret to $SECRET_FILE (root:root 0600)"

# Root-shell mode reads the secret as euid=root, so it must be owner-readable
# ONLY — a group-readable secret could be read by seclogin-group members, who
# could then compute codes and bypass the TOTP factor. The binary enforces this
# (open_secret rejects group-read when euid=0).
#
# Gate mode (euid=seclogin) and the auth-server verify secret legitimately need
# group read: for those, after running this script set
#   chown root:$ADMIN_GROUP $SECRET_FILE && chmod 640 $SECRET_FILE
# (setup_auth_server.sh does this automatically for the verify secret.)
echo "$SECRET" > "$SECRET_FILE"
chown "root:root" "$SECRET_FILE"
chmod 600 "$SECRET_FILE"
echo "Done"

header "Installing config to $CONFIG_FILE (root:$ADMIN_GROUP, 0640)"

cat > "$CONFIG_FILE" <<EOF
# seclogin configuration — $CONFIG_FILE
# owner: root:$ADMIN_GROUP  mode: 0640
# All runtime files: $SECLOGIN_DIR/

# HMAC digest algorithm: SHA256 (recommended) or SHA1 (legacy)
algorithm=$ALGO

# Path to TOTP secret file (default: $SECLOGIN_DIR/totp.secret)
# secret_file=$SECLOGIN_DIR/totp.secret

# Path to Domino notes.ini — shown in banner if file exists (optional)
notes_ini=/local/notesdata/notes.ini

# Remote verification — uncomment to use instead of local TOTP
# auth_server=authsrv.example.com
# auth_key=$SECLOGIN_DIR/seclogin_ed25519
# known_hosts=$SECLOGIN_DIR/known_hosts

# IP access control — IPv4 and IPv6 CIDR supported (multiple entries allowed)
# deny= rules are checked first; allow= rules define a whitelist
# If no allow= rules exist, all IPs not denied are permitted
# If allow= rules exist, only matching IPs may authenticate
# Console access (no SSH) is always permitted regardless of rules
#
# Examples:
# allow=192.168.1.0/24
# allow=10.0.0.0/8
# allow=::1
# allow=2001:db8::/32
# deny=192.168.1.100

EOF

chown "root:$ADMIN_GROUP" "$CONFIG_FILE"
chmod 640 "$CONFIG_FILE"
echo "Done"

header "TOTP Secret (base32)"
echo "$SECRET"

header "Current TOTP Code"
if [ "${ALGO^^}" = "SHA1" ]; then
    oathtool --totp -b "$SECRET"
else
    oathtool --totp=sha256 -b "$SECRET"
fi

header "QR Code (Terminal)"
qrencode -t ANSIUTF8 "$URI"

header "QR Code PNG"
PNG_FILE="totp-${ACCOUNT}.png"
qrencode -o "$PNG_FILE" "$URI"
echo "$PNG_FILE"

header "OTPAuth URI"
echo "$URI"
echo

echo "Scan the QR code with your TOTP app (Google Authenticator, Aegis, etc.)"
echo "Then verify with: sudo $SCRIPT_DIR/get_code.sh"
echo
