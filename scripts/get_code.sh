#!/bin/bash
# Print the current TOTP code from the seclogin secret file
# Auto-detects which secret file is present; accepts optional override
#
# Usage: sudo ./get_code.sh [secret_file]
#   sudo ./get_code.sh                              — auto-detect
#   sudo ./get_code.sh $SECLOGIN_DIR/totp.secret         — client/local mode
#   sudo ./get_code.sh $SECLOGIN_DIR/totp_verify.secret  — auth server mode

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

LOCAL_SECRET="$SECLOGIN_DIR/totp.secret"
VERIFY_SECRET="$SECLOGIN_DIR/totp_verify.secret"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root (sudo $0)" >&2
    exit 1
fi

# Resolve secret file — explicit arg, else auto-detect
if [ -n "$1" ]; then
    SECRET_FILE="$1"
elif [ -f "$LOCAL_SECRET" ]; then
    SECRET_FILE="$LOCAL_SECRET"
    # warn when both files exist — combined server, specify explicitly if needed
    if [ -f "$VERIFY_SECRET" ]; then
        echo "NOTE: both $LOCAL_SECRET and $VERIFY_SECRET exist" >&2
        echo "      using $LOCAL_SECRET — pass path explicitly to choose:" >&2
        echo "      sudo $0 $VERIFY_SECRET" >&2
    fi
elif [ -f "$VERIFY_SECRET" ]; then
    SECRET_FILE="$VERIFY_SECRET"
else
    echo "ERROR: No secret file found ($LOCAL_SECRET or $VERIFY_SECRET)" >&2
    echo "       Run sudo ./create_totp.sh to generate one." >&2
    exit 1
fi

if [ ! -f "$SECRET_FILE" ]; then
    echo "ERROR: $SECRET_FILE not found." >&2
    exit 1
fi

# Check permissions — expected depends on which file it is
PERMS=$(stat -c "%a" "$SECRET_FILE")
OWNER=$(stat -c "%U:%G" "$SECRET_FILE")

# both totp.secret and totp_verify.secret use root:seclogin 0640
# the seclogin group is restricted (sysadmin + seclogin service account only)
# seclogin user has no interactive login — ForceCommand only
# group-read is acceptable: protects against outsiders, not against the controlled group
EXP_OWNER="root:$ADMIN_GROUP"
EXP_PERMS="640"

if [ "$PERMS" != "$EXP_PERMS" ] || [ "$OWNER" != "$EXP_OWNER" ]; then
    echo "WARNING: $SECRET_FILE has wrong permissions or ownership" >&2
    echo "  Found:    $OWNER $PERMS" >&2
    echo "  Expected: $EXP_OWNER $EXP_PERMS" >&2
    echo "  Fix:      sudo chown $EXP_OWNER $SECRET_FILE && sudo chmod $EXP_PERMS $SECRET_FILE" >&2
fi

SECRET=$(cat "$SECRET_FILE")
ALGO=$(grep -i "^algorithm=" "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
ALGO="${ALGO:-SHA256}"

echo "Secret: $SECRET_FILE"
echo
if [ "${ALGO^^}" = "SHA1" ]; then
    oathtool --totp -b "$SECRET"
else
    oathtool --totp=sha256 -b "$SECRET"
fi
echo
