#!/bin/bash
# Print the config and commands needed to set up a target server
# Run this on the auth server after setup_auth_server.sh
# Usage: sudo ./show_target_config.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

AUTH_KEY_PRIV="$AUTH_KEY_FILE"

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

if [ ! -f "$AUTH_KEY_PRIV" ]; then
    error "$AUTH_KEY_PRIV not found. Run sudo $SCRIPT_DIR/setup_auth_server.sh first."
fi

HOSTNAME=$(hostname -f 2>/dev/null || hostname)

header "Deploy on each target server — run these commands on the target as root"

echo "# 0. Create seclogin group and sysadmin user (skip if already exists):"
echo "groupadd ${ADMIN_GROUP}"
echo "useradd --gid ${ADMIN_GROUP} --home-dir ${ADMIN_HOME} --create-home --shell ${ADMIN_SHELL} ${ADMIN_USER}"
echo ""
echo "# 1. Create seclogin config directory:"
echo "mkdir -p ${SECLOGIN_DIR}"
echo "chown root:${ADMIN_GROUP} ${SECLOGIN_DIR}"
echo "chmod 750 ${SECLOGIN_DIR}"
echo ""
echo "# 2. Install seclogin binary from auth server:"
echo "scp ${ADMIN_USER}@${HOSTNAME}:${INSTALL_DIR}/${BIN} /tmp/${BIN}"
echo "install -o root -g ${ADMIN_GROUP} -m ${MODE} /tmp/${BIN} ${INSTALL_DIR}/${BIN}"
echo "rm /tmp/${BIN}"
echo ""
echo "# 3. Copy SSH auth key from auth server:"
echo "scp ${ADMIN_USER}@${HOSTNAME}:${AUTH_KEY_FILE} ${AUTH_KEY_FILE}"
echo "chown root:${ADMIN_GROUP} ${AUTH_KEY_FILE}"
echo "chmod 640 ${AUTH_KEY_FILE}"
echo ""
echo "# 4. Trust the auth server host key:"
echo "sudo ./trust_auth_server.sh"
echo "#    Reads auth_server from $CONFIG_FILE, connects once, verify fingerprint then Ctrl+C"
echo ""
echo "# 5. Write ${CONFIG_FILE}:"
echo "cat > ${CONFIG_FILE} << 'EOF'"
echo "# seclogin configuration — target server"
echo "algorithm=SHA256"
echo "auth_server=${AUTH_USER}@${HOSTNAME}"
echo "auth_key=${AUTH_KEY_FILE}"
echo ""
echo "# Optional: show Domino server name in privilege banner"
echo "# notes_ini=/local/notesdata/notes.ini"
echo "EOF"
echo "chown root:${ADMIN_GROUP} ${CONFIG_FILE}"
echo "chmod 640 ${CONFIG_FILE}"
echo ""
echo "# 6. Test:"
echo "su - ${ADMIN_USER}"
echo "seclogin"
echo ""
