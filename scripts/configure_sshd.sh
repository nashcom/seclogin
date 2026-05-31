#!/bin/bash
# Configure sshd settings required and recommended for seclogin
#
# Global settings:
#   LogLevel VERBOSE          — logs SSH key fingerprint, correlates with seclogin syslog
#   PermitRootLogin no        — no direct root SSH access
#
# Per-user settings (Match User sysadmin):
#   AuthenticationMethods publickey,password  — requires SSH key AND password
#   PasswordAuthentication yes                — needed for the password factor
#
# Security chain: SSH key + password (sshd) + TOTP (seclogin) = 3 factors
#
# Usage: sudo ./configure_sshd.sh [--check]
#   --check  show current status without making changes

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_MARKER="# seclogin configuration"

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

check_setting()
{
    local key="$1"
    local expected="$2"
    local current

    current=$(sshd -T 2>/dev/null | grep -i "^${key} " | awk '{print $2}')

    if [ -z "$current" ]; then
        echo "  $key: not set"
        return 1
    elif [ "${current,,}" = "${expected,,}" ]; then
        echo "  $key: $current ✓"
        return 0
    else
        echo "  $key: $current (expected: $expected)"
        return 1
    fi
}

if [ "$(id -u)" -ne 0 ] && [ "${1}" != "--check" ]; then
    error "Run as root (sudo $0)"
fi

header "Current sshd settings"

check_setting "loglevel"       "VERBOSE" || NEED_UPDATE=1
check_setting "permitrootlogin" "no"     || NEED_UPDATE=1
check_setting "pubkeyauthentication" "yes"

echo ""
echo "  Per-user (Match User $ADMIN_USER):"
if grep -q "AuthenticationMethods publickey,password" "$SSHD_CONFIG" 2>/dev/null; then
    echo "  AuthenticationMethods: publickey,password ✓"
else
    echo "  AuthenticationMethods: not set (expected: publickey,password)"
    NEED_UPDATE=1
fi

if [ "${1}" = "--check" ]; then
    echo
    echo "Run 'sudo $0' to apply missing settings."
    exit 0
fi

if [ -z "$NEED_UPDATE" ]; then
    echo
    echo "All required settings already configured."
else
    header "Updating $SSHD_CONFIG"

    # remove any previous seclogin block
    if grep -q "$SSHD_MARKER" "$SSHD_CONFIG"; then
        sed -i "/$SSHD_MARKER/,/# end seclogin/d" "$SSHD_CONFIG"
    fi

    cat >> "$SSHD_CONFIG" <<EOF

$SSHD_MARKER
LogLevel VERBOSE
PermitRootLogin no

Match User $ADMIN_USER
    AuthenticationMethods publickey,password
    PasswordAuthentication yes
# end seclogin
EOF

    echo "Settings added."
fi

header "Validating sshd config"

if sshd -t; then
    echo "Config valid."
else
    error "sshd config validation failed — check $SSHD_CONFIG manually"
fi

header "Reloading sshd"

systemctl reload sshd
echo "Done."

echo
echo "Security chain for $ADMIN_USER:"
echo "  1. SSH key            (who you are)"
echo "  2. SSH password       (what you know)"
echo "  3. TOTP via seclogin (second factor)"
echo
echo "Make sure $ADMIN_USER has a password set: sudo passwd $ADMIN_USER"
echo
