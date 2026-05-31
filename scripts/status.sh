#!/bin/bash
# seclogin status and cleanup
# Auto-detects role: auth server (seclogin user exists), client (SUID binary), or both
#
# Usage:
#   sudo ./status.sh            — show status
#   sudo ./status.sh --delete   — show status, confirm, then remove everything

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/config"

VERIFY_SECRET="$SECLOGIN_DIR/totp_verify.secret"
KNOWN_HOSTS="$SECLOGIN_DIR/known_hosts"
DEBUG_LOG="/var/log/seclogin-debug.log"
AUTH_KEY_PRIV="$AUTH_KEY_FILE"
AUTH_KEY_PUB="${AUTH_KEY_FILE}.pub"
AUTH_KEYS="${AUTH_HOME}/.ssh/authorized_keys"

fDelete=0
[ "${1}" = "--delete" ] && fDelete=1

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { printf "  ${GREEN}✓${NC}  %s\n" "$*"; }
warn() { printf "  ${YELLOW}!${NC}  %s\n" "$*"; }
miss() { printf "  ${RED}-${NC}  %s\n" "$*"; }
exp()  { printf "  ${CYAN}>${NC}  %s\n" "$*"; }   # expected — same column width as ok/warn
note() { printf "      %s\n" "$*"; }

header()
{
    echo
    echo "------------------------------------------------------------"
    echo " $*"
    echo "------------------------------------------------------------"
}

# ---------------------------------------------------------------------------
# Status functions
# ---------------------------------------------------------------------------

check_file()
{
    local path="$1" exp_owner="$2" exp_mode="$3"

    if [ ! -e "$path" ]; then
        miss "$(printf '%-38s  %s' "(not found)" "$path")"
        return
    fi

    local owner mode perm
    owner=$(stat -c "%U:%G" "$path")
    mode=$(stat -c "%a"  "$path")
    perm=$(stat -c "%A"  "$path")

    if [ "$owner" = "$exp_owner" ] && [ "$mode" = "$exp_mode" ]; then
        ok "$(printf '%-4s  %-10s  %-20s  %s' "$mode" "$perm" "$owner" "$path")"
    else
        warn "$(printf '%-4s  %-10s  %-20s  %s' "$mode" "$perm" "$owner" "$path")"
        exp "$(printf '%-4s  %-10s  %-20s' "$exp_mode" "" "$exp_owner")"
        echo
    fi
}

check_user()
{
    local user="$1"
    if getent passwd "$user" > /dev/null 2>&1; then
        ok "$(printf '%-8s  %-16s  uid=%-6s  groups=%s' "user" "$user" "$(id -u $user)" "$(id -nG $user | tr ' ' ',')")"
    else
        miss "$(printf '%-8s  %-16s  (not found)' "user" "$user")"
    fi
}

check_group()
{
    local grp="$1"
    if getent group "$grp" > /dev/null 2>&1; then
        local gid members
        gid=$(getent group "$grp" | cut -d: -f3)
        members=$(getent group "$grp" | cut -d: -f4)
        ok "$(printf '%-8s  %-16s  gid=%-6s  members=%s' "group" "$grp" "$gid" "${members:-(none)}")"
    else
        miss "$(printf '%-8s  %-16s  (not found)' "group" "$grp")"
    fi
}

check_in_group()
{
    local user="$1" grp="$2"
    if id -nG "$user" 2>/dev/null | grep -qw "$grp"; then
        ok "$(printf '%-8s  %-16s  in group %s' "member" "$user" "$grp")"
    else
        warn "$(printf '%-8s  %-16s  NOT in group %s' "member" "$user" "$grp")"
        echo
    fi
}

check_forcecommand()
{
    if [ -f "$AUTH_KEYS" ]; then
        local n
        n=$(grep -c "ForceCommand" "$AUTH_KEYS" 2>/dev/null; true); n="${n:-0}"
        ok "$(printf '%-4s  %-10s  %-20s  %s  (%s ForceCommand entries)' "" "" "" "$AUTH_KEYS" "$n")"
    else
        miss "$(printf '%-38s  %s' "(not found)" "$AUTH_KEYS")"
    fi
}

# ---------------------------------------------------------------------------
# Delete functions
# ---------------------------------------------------------------------------

delete_file()
{
    local path="$1"
    if [ -e "$path" ]; then
        rm -rf "$path"
        echo "  removed: $path"
    fi
}

delete_user()
{
    local user="$1"
    if getent passwd "$user" > /dev/null 2>&1; then
        userdel -r "$user" 2>/dev/null && echo "  removed user+home: $user"
    fi
}

delete_group()
{
    local grp="$1"
    if getent group "$grp" > /dev/null 2>&1; then
        local members
        members=$(getent group "$grp" | cut -d: -f4)
        if [ -z "$members" ]; then
            groupdel "$grp" 2>/dev/null && echo "  removed group: $grp"
        else
            warn "group $grp still has members: $members — skipped"
            note "remove manually: sudo groupdel $grp"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Action dispatcher — same items, different action
# ---------------------------------------------------------------------------

ACTION=status   # "status" or "delete"

item_file()     { [ "$ACTION" = delete ] && delete_file "$1"  || check_file "$@"; }
item_user()     { [ "$ACTION" = delete ] && delete_user "$1"  || check_user "$1"; }
item_group()    { [ "$ACTION" = delete ] && delete_group "$1" || check_group "$1"; }
item_in_group() { [ "$ACTION" = delete ] && true              || check_in_group "$@"; }
item_forcecommand() { [ "$ACTION" = delete ] && delete_file "$AUTH_KEYS" || check_forcecommand; }

# ---------------------------------------------------------------------------
# Item definitions — the single source of truth for what seclogin owns
# ---------------------------------------------------------------------------

process_items()
{
    header "Config directory"
    if [ -d "$SECLOGIN_DIR" ]; then
        item_file "$SECLOGIN_DIR" "root:$ADMIN_GROUP" "750"
    else
        miss "$(printf '%-38s  %s' "(not found)" "$SECLOGIN_DIR")"
    fi

    header "Binary"
    if [ "$fClient" -eq 1 ] && [ "$fAuthServer" -eq 1 ]; then
        item_file "$INSTALL_DIR/$BIN" "root:$ADMIN_GROUP" "4750"
        note "SUID — loopback/test mode (production: split auth server and client)"
    elif [ "$fClient" -eq 1 ]; then
        item_file "$INSTALL_DIR/$BIN" "root:$ADMIN_GROUP" "4750"
        note "SUID root — client mode"
    elif [ "$fAuthServer" -eq 1 ]; then
        item_file "$INSTALL_DIR/$BIN" "root:$AUTH_USER"   "750"
        note "no SUID — auth server mode"
    else
        miss "$INSTALL_DIR/$BIN  (not installed)"
    fi

    # seclogin-gate: SUID to seclogin user — login shell gate for non-admin users
    if [ -f "$INSTALL_DIR/$BIN_GATE" ]; then
        item_file "$INSTALL_DIR/$BIN_GATE" "$AUTH_USER:$AUTH_USER" "$MODE_GATE"
        note "SUID $AUTH_USER — gate mode (TOTP gate for login shells)"
    else
        miss "$(printf '%-4s  %-10s  %-20s  %s' "????" "----------" "(not installed)" "$INSTALL_DIR/$BIN_GATE")"
    fi

    if [ "$fClient" -eq 1 ]; then
        header "Client config"
        item_file "$CONFIG_FILE"                       "root:$ADMIN_GROUP" "640"
        # root-shell mode reads the secret as euid=root and the binary rejects a
        # group-readable secret — so the client secret is owner-only root:root 0600.
        # (Gate-mode deployments that share this file need root:seclogin 0640 instead.)
        item_file "$SECLOGIN_DIR/totp.secret"          "root:root"         "600"
        item_file "$KNOWN_HOSTS"                       "root:$ADMIN_GROUP" "640"
        item_file "$AUTH_KEY_PRIV"                     "root:$ADMIN_GROUP" "640"
    fi

    if [ "$fAuthServer" -eq 1 ]; then
        header "Auth server config"
        item_file "$CONFIG_FILE"   "root:$ADMIN_GROUP" "640"
        item_file "$VERIFY_SECRET" "root:$ADMIN_GROUP" "640"
    fi

    if [ -f "$DEBUG_LOG" ]; then
        header "Debug log"
        local logperm logowner
        logperm=$(stat -c "%A" "$DEBUG_LOG")
        logowner=$(stat -c "%U:%G" "$DEBUG_LOG")
        logmode=$(stat -c "%a" "$DEBUG_LOG")
        ok "$(printf '%-4s  %-10s  %-20s  %s  (%s lines)' "$logmode" "$logperm" "$logowner" "$DEBUG_LOG" "$(wc -l < $DEBUG_LOG; true)")"
    fi

    header "Users and groups"
    item_group "$ADMIN_GROUP"
    item_user  "$ADMIN_USER"
    item_in_group "$ADMIN_USER" "$ADMIN_GROUP"
    if [ "$fAuthServer" -eq 1 ]; then
        item_user "$AUTH_USER"
    fi

    header "SSH keys"
    if [ "$fAuthServer" -eq 1 ]; then
        item_file "$AUTH_KEY_PRIV" "root:$ADMIN_GROUP" "640"
        item_file "$AUTH_KEY_PUB"  "root:$ADMIN_GROUP" "644"
        item_forcecommand
    fi

    echo
}

# ---------------------------------------------------------------------------
# Detect roles
# ---------------------------------------------------------------------------

fAuthServer=0
fClient=0

getent passwd "$AUTH_USER" > /dev/null 2>&1 && fAuthServer=1
[ -f "$VERIFY_SECRET" ]                         && fAuthServer=1   # partial setup

if [ -f "$INSTALL_DIR/$BIN" ]; then
    binmode=$(stat -c "%a" "$INSTALL_DIR/$BIN")
    case "$binmode" in
        4750|4755) fClient=1 ;;      # SUID — client mode (4755 = old/legacy install)
        750|0750)  fAuthServer=1 ;;  # no SUID — auth server mode
    esac
fi

# show client section if totp.secret exists — even without binary (partial setup)
[ -f "$SECLOGIN_DIR/totp.secret" ]              && fClient=1

HOSTNAME=$(hostname -f 2>/dev/null || hostname)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

header "seclogin status — $HOSTNAME"
echo
printf "  Role: "
if   [ "$fAuthServer" -eq 1 ] && [ "$fClient" -eq 1 ]; then
    printf "${YELLOW}auth server + client (loopback/test only)${NC}\n"
elif [ "$fAuthServer" -eq 1 ]; then
    printf "${CYAN}auth server${NC}\n"
elif [ "$fClient" -eq 1 ]; then
    printf "${CYAN}client${NC}\n"
else
    printf "${RED}not configured${NC}\n"
fi

ACTION=status
process_items

if [ "$fDelete" -eq 0 ]; then
    echo "  Run 'sudo $0 --delete' to remove all seclogin files and users."
    echo
    exit 0
fi

# Delete: confirm then act
echo
printf "  ${RED}WARNING: This will remove all seclogin configuration listed above.${NC}\n"
printf "  Sysadmin user will NOT be removed.\n"
echo
printf "  Continue? [y/N] "
read -r answer
[ "${answer,,}" != "y" ] && echo "Aborted." && exit 0

echo
ACTION=delete
process_items
echo
echo "  Done. Sysadmin user preserved."
echo
