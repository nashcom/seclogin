#!/bin/bash
# Display QR code and current TOTP code for an existing secret
# Usage: sudo ./show_totp_qr.sh [account]
# Algorithm is read from /etc/seclogin.conf automatically

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root (sudo $0)" >&2
    exit 1
fi

ACCOUNT="${1:-$ADMIN_USER}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: $CONFIG_FILE not found. Run sudo ./create_totp.sh first." >&2
    exit 1
fi

SECRET_FILE=$(grep -i "^secret_file=" "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
SECRET_FILE="${SECRET_FILE:-$SECLOGIN_DIR/totp.secret}"

if [ ! -f "$SECRET_FILE" ]; then
    echo "ERROR: $SECRET_FILE not found. Run sudo $SCRIPT_DIR/create_totp.sh first." >&2
    exit 1
fi

SECRET=$(cat "$SECRET_FILE")
ALGO=$(grep -i "^algorithm=" "$CONFIG_FILE" | head -1 | cut -d= -f2-)
ALGO="${ALGO:-SHA256}"

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
