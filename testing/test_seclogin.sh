#!/bin/bash
# Rootshell test suite — runs inside the Alpine build container
# Tests local TOTP mode and remote verify mode via loopback SSH on port 2222
#
# Usage (inside container): ./testing/test_seclogin.sh [--quick]
# Usage (via build_alpine.sh): ./build_alpine.sh test
#
#   --quick   skip delay-heavy tests (invalid code, nonce expiry) — runs in ~5s
#   (no arg)  full test suite — runs in ~27s

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

QUICK=0
[ "${1}" = "--quick" ] && QUICK=1

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ADMIN_USER=sysadmin
ADMIN_GROUP=seclogin
ADMIN_UID=2000
ADMIN_GID=2001          # seclogin group owns binary/config — same GID as AUTH_GID
ADMIN_HOME=/home/sysadmin
AUTH_USER=seclogin
AUTH_UID=2001
AUTH_GID=2001
AUTH_HOME=/home/seclogin
SSH_PORT=2222
BIN=/usr/local/bin/seclogin

# Fixed test secret — SHA256 TOTP
TEST_SECRET="JBSWY3DPEHPK3PXP"
TEST_PASS="testpass"
NONCE_MAX_AGE=10       # must match NONCE_MAX_AGE in seclogin.c
AUTH_FAIL_DELAY=5      # must match AUTH_FAIL_DELAY in seclogin.c
TEST_DELAY=12          # delay injected to force nonce expiry (> NONCE_MAX_AGE)

# expect timeouts
TIMEOUT_NORMAL=8                                           # normal auth + SSH overhead
TIMEOUT_EXPIRY=$((TEST_DELAY + AUTH_FAIL_DELAY + 5))       # 22s — nonce expiry (test_delay blocks before response)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

nPass=0
nFail=0
nSkip=0
nTest=0

# Arrays to collect test results for summary table
aTestNames=()
aTestResults=()
szCurrentTest=""

# Section header — for setup/teardown blocks
header()
{
    echo
    echo "------------------------------------------------------------"
    echo " $*"
    echo "------------------------------------------------------------"
    echo
}

# Test case header — auto-numbered, used for every test
test_case()
{
    nTest=$((nTest + 1))
    szCurrentTest="$*"
    aTestNames+=("$*")
    aTestResults+=("?")     # placeholder until pass/fail/skip
    echo
    echo "------------------------------------------------------------"
    echo -e " Test ${nTest}: $*"
    echo "------------------------------------------------------------"
}

# Info line — describes what a test or setup step does
info()
{
    echo -e "  ${CYAN}-${NC} $*"
}

pass()
{
    echo
    echo -e "  ${GREEN}[PASS]${NC} $*"
    nPass=$((nPass + 1))
    aTestResults[$((nTest - 1))]="PASS"
}

fail()
{
    echo
    echo -e "  ${RED}[FAIL]${NC} $*"
    nFail=$((nFail + 1))
    aTestResults[$((nTest - 1))]="FAIL"
}

skip()
{
    echo
    echo -e "  ${YELLOW}[SKIP]${NC} $*"
    nSkip=$((nSkip + 1))
    aTestResults[$((nTest - 1))]="SKIP"
}

get_code()
{
    $OATHTOOL --totp=sha256 -b "$TEST_SECRET"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

header "Installing test dependencies"

info "openssh         — sshd for loopback test sessions"
info "oath-toolkit    — oathtool to generate TOTP codes"
info "expect          — drives interactive passcode prompt"
apk add --quiet openssh oath-toolkit-oathtool expect bash dos2unix
info "Done."

header "Setting up test environment"

mkdir -p /var/log

info "Creating seclogin group (gid=$AUTH_GID) — owns binary/config; both users are members"
addgroup -g "$AUTH_GID" "$ADMIN_GROUP"

info "Creating admin user '$ADMIN_USER' (uid=$ADMIN_UID) — member of $ADMIN_GROUP"
adduser -D -u "$ADMIN_UID" -G "$ADMIN_GROUP" \
        -h "$ADMIN_HOME" -s /bin/bash "$ADMIN_USER"
echo "${ADMIN_USER}:${TEST_PASS}" | chpasswd
echo "  User: $(id $ADMIN_USER)"

info "Creating auth user '$AUTH_USER' (uid=$AUTH_UID) — dedicated for remote verify ForceCommand"
adduser -D -u "$AUTH_UID" -G "$AUTH_USER" \
        -h "$AUTH_HOME" -s /bin/sh "$AUTH_USER"
echo "${AUTH_USER}:${TEST_PASS}" | chpasswd   # unlock account — sshd rejects locked accounts even for key auth
mkdir -p "$AUTH_HOME/.ssh"
chown "$AUTH_USER:$AUTH_USER" "$AUTH_HOME" "$AUTH_HOME/.ssh"
chmod 755 "$AUTH_HOME"
chmod 700 "$AUTH_HOME/.ssh"
echo "  User: $(id $AUTH_USER)"

info "Installing binary: root:$ADMIN_GROUP 4750 (SUID)"
info "NOTE: production auth server uses 0750 (no SUID); here we use 4750 for the loopback"
info "test only. run_verify_mode() calls seteuid(getuid()) immediately, so --verify"
info "behaves as unprivileged even when the binary has the SUID bit set."
install -o root -g "$ADMIN_GROUP" -m 4750 "$ROOT_DIR/seclogin" "$BIN"
ls -lh "$BIN"

info "Creating /etc/seclogin config directory"
mkdir -p /etc/seclogin
chown "root:$ADMIN_GROUP" /etc/seclogin
chmod 750 /etc/seclogin

info "Provisioning TOTP secret: /etc/seclogin/totp.secret (root:root 0600)"
info "Root-shell mode reads it as euid=root — owner-readable only, so seclogin"
info "group members cannot read the secret directly. The binary enforces this."
echo "$TEST_SECRET" > /etc/seclogin/totp.secret
chown "root:root" /etc/seclogin/totp.secret
chmod 600 /etc/seclogin/totp.secret

info "Writing config: /etc/seclogin/seclogin.conf (root:$ADMIN_GROUP 0640)"
info "Config readable by seclogin group — needed by gate mode (euid=seclogin); contains no secrets"
cat > /etc/seclogin/seclogin.conf << EOF
algorithm=SHA256
debug=1
EOF
chown "root:$ADMIN_GROUP" /etc/seclogin/seclogin.conf
chmod 640 /etc/seclogin/seclogin.conf

info "Generating SSH host keys for sshd"
ssh-keygen -A -q

info "Generating ED25519 keypair for $ADMIN_USER login"
mkdir -p "$ADMIN_HOME/.ssh"
ssh-keygen -t ed25519 -f "$ADMIN_HOME/.ssh/id_ed25519" -N "" -q
cat "$ADMIN_HOME/.ssh/id_ed25519.pub" > "$ADMIN_HOME/.ssh/authorized_keys"
chown -R "$ADMIN_USER:$ADMIN_GROUP" "$ADMIN_HOME/.ssh"
chmod 700 "$ADMIN_HOME/.ssh"
chmod 600 "$ADMIN_HOME/.ssh/authorized_keys" "$ADMIN_HOME/.ssh/id_ed25519"

info "Configuring sshd on port $SSH_PORT (key auth only)"

# Fix home directory permissions — sshd StrictModes requires these
chmod 755 "$ADMIN_HOME"
chown "$ADMIN_USER:$ADMIN_GROUP" "$ADMIN_HOME"

cat > /etc/ssh/sshd_config << EOF
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
StrictModes no
LogLevel VERBOSE
EOF

info "Starting sshd and waiting for it to be ready"
/usr/sbin/sshd -E /tmp/sshd.log
for i in $(seq 1 10); do
    nc -z localhost "$SSH_PORT" 2>/dev/null && break
    sleep 1
done

info "Accepting localhost host key into /root/.ssh/known_hosts"
mkdir -p /root/.ssh
chmod 700 /root/.ssh
ssh-keyscan -p "$SSH_PORT" localhost >> /root/.ssh/known_hosts 2>/dev/null

OATHTOOL=$(command -v oathtool)
if [ -z "$OATHTOOL" ]; then
    echo "ERROR: oathtool not found" >&2
    exit 1
fi

info "Setup complete."

# ---------------------------------------------------------------------------
# SSH helper — runs a command over SSH as sysadmin
# ---------------------------------------------------------------------------

SSH="ssh -t -p $SSH_PORT -i $ADMIN_HOME/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o BatchMode=yes ${ADMIN_USER}@localhost"

# Verify SSH connectivity before running tests
if ! $SSH "true" > /dev/null 2>&1; then
    echo "ERROR: SSH connectivity check failed" >&2
    echo "--- .ssh permissions ---" >&2
    ls -la "$ADMIN_HOME/" >&2
    ls -la "$ADMIN_HOME/.ssh/" >&2
    echo "--- authorized_keys content ---" >&2
    cat "$ADMIN_HOME/.ssh/authorized_keys" >&2
    echo "--- sshd log ---" >&2
    cat /tmp/sshd.log >&2
    exit 1
fi
info "SSH connectivity verified."

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_case "binary permissions"

if [ -u "$BIN" ] && [ -x "$BIN" ]; then
    pass "SUID bit set, binary executable: $(ls -lh $BIN | awk '{print $1, $3, $4}')"
else
    fail "SUID bit or execute permission missing: $(ls -lh $BIN | awk '{print $1, $3, $4}')"
fi

echo
info "seclogin verifies its own SUID bit and ownership at startup."
info "If the binary is not root-owned SUID it refuses to run."

# ---------------------------------------------------------------------------

test_case "valid TOTP code → root shell"

CODE=$(get_code)

result=$(expect -c "
    log_user 0
    set timeout $TIMEOUT_NORMAL
    spawn $SSH seclogin
    expect \"Passcode:\"
    send \"${CODE}\r\"
    expect {
        \"PRIVILEGED ROOT SESSION\" { exit 0 }
        \"Authentication failed\"   { exit 1 }
        timeout                    { exit 2 }
    }
"; echo $?)

case "$result" in
    0) pass "Valid code accepted — root shell granted" ;;
    1) fail "Valid code rejected — authentication failed" ;;
    2) fail "Timeout waiting for response" ;;
    *) fail "Unexpected result: $result" ;;
esac

echo
info "SSH in as $ADMIN_USER, run seclogin, feed the current TOTP code ($CODE)."
info "Expecting: privilege banner (PRIVILEGED ROOT SESSION)."

# ---------------------------------------------------------------------------

test_case "invalid TOTP code → authentication failed"

if [ "$QUICK" -eq 1 ]; then
    skip "Skipped in quick mode"
else
    result=$(expect -c "
        log_user 0
        set timeout $TIMEOUT_NORMAL
        spawn $SSH seclogin
        expect \"Passcode:\"
        send \"000000\r\"
        expect {
            \"Authentication failed\"   { exit 0 }
            \"PRIVILEGED ROOT SESSION\" { exit 1 }
            timeout                    { exit 2 }
        }
    "; echo $?)

    case "$result" in
        0) pass "Invalid code rejected — authentication failed" ;;
        1) fail "Invalid code accepted — root shell granted (bad!)" ;;
        2) fail "Timeout waiting for response" ;;
        *) fail "Unexpected result: $result" ;;
    esac

    echo
    info "Send wrong code (000000) — expecting: Authentication failed."
    info "A ${AUTH_FAIL_DELAY}s delay is enforced server-side after rejection."
fi

# ---------------------------------------------------------------------------

test_case "wrong binary permissions → rejected"

chmod 0755 "$BIN"    # remove SUID

result=$(expect -c "
    log_user 0
    set timeout $TIMEOUT_NORMAL
    spawn $SSH seclogin
    expect {
        \"binary check failed\"     { exit 0 }
        \"Passcode:\"               { exit 1 }
        timeout                    { exit 2 }
    }
"; echo $?)

chmod 4750 "$BIN"    # restore

case "$result" in
    0) pass "Non-SUID binary rejected at startup" ;;
    1) fail "Non-SUID binary was not rejected" ;;
    2) fail "Timeout waiting for response" ;;
    *) fail "Unexpected result: $result" ;;
esac

echo
info "Temporarily remove the SUID bit — seclogin checks its own binary"
info "at startup and refuses to run if the permissions are wrong."

# ---------------------------------------------------------------------------

test_case "missing config file → still works (defaults)"

mv /etc/seclogin/seclogin.conf /etc/seclogin/seclogin.conf.bak

CODE=$(get_code)

result=$(expect -c "
    log_user 0
    set timeout $TIMEOUT_NORMAL
    spawn $SSH seclogin
    expect \"Passcode:\"
    send \"${CODE}\r\"
    expect {
        \"PRIVILEGED ROOT SESSION\" { exit 0 }
        \"Authentication failed\"   { exit 1 }
        timeout                    { exit 2 }
    }
"; echo $?)

mv /etc/seclogin/seclogin.conf.bak /etc/seclogin/seclogin.conf

case "$result" in
    0) pass "Works with no config file (defaults applied)" ;;
    1) fail "Failed with no config file" ;;
    2) fail "Timeout" ;;
    *) fail "Unexpected result: $result" ;;
esac

echo
info "All config keys have sensible defaults — /etc/seclogin/seclogin.conf is optional."
info "Authentication still works using /etc/seclogin/totp.secret with defaults."

# ---------------------------------------------------------------------------

test_case "secret file wrong permissions → rejected"

chmod 0644 /etc/seclogin/totp.secret    # make world-readable (root:root) — must be rejected

result=$(expect -c "
    log_user 0
    set timeout $TIMEOUT_NORMAL
    spawn $SSH seclogin
    expect \"Passcode:\"
    send \"000000\r\"
    expect {
        \"Secret file\"            { exit 0 }
        \"PRIVILEGED ROOT SESSION\" { exit 1 }
        timeout                   { exit 2 }
    }
"; echo $?)

chmod 0600 /etc/seclogin/totp.secret    # restore (root:root 0600)

case "$result" in
    0) pass "World-readable secret file rejected" ;;
    1) fail "World-readable secret file was not rejected" ;;
    2) fail "Timeout waiting for response" ;;
    *) fail "Unexpected result: $result" ;;
esac

echo
info "Secret file must not be world-accessible — checked after passcode entry, rejected if world-readable."

# ---------------------------------------------------------------------------

test_case "allow= rule permits matching IP"

# add allow rule for loopback — connection comes from ::1
cat >> /etc/seclogin/seclogin.conf << EOF
allow=::1
allow=127.0.0.1
EOF

CODE=$(get_code)

result=$(expect -c "
    log_user 0
    set timeout $TIMEOUT_NORMAL
    spawn $SSH seclogin
    expect \"Passcode:\"
    send \"${CODE}\r\"
    expect {
        \"PRIVILEGED ROOT SESSION\" { exit 0 }
        \"Authentication failed\"   { exit 1 }
        \"Access denied\"           { exit 3 }
        timeout                    { exit 2 }
    }
"; echo $?)

# remove ACL entries
sed -i '/^allow=/d' /etc/seclogin/seclogin.conf

case "$result" in
    0) pass "Loopback IP permitted by allow= rule" ;;
    3) fail "Loopback IP denied — allow= rule not matching" ;;
    1) fail "Authentication failed" ;;
    2) fail "Timeout" ;;
    *) fail "Unexpected result: $result" ;;
esac

echo
info "allow=::1 and allow=127.0.0.1 permit loopback connections."

# ---------------------------------------------------------------------------

test_case "deny= rule blocks matching IP"

# deny loopback — connection comes from ::1 or 127.0.0.1
cat >> /etc/seclogin/seclogin.conf << EOF
deny=::1
deny=127.0.0.1
EOF

result=$(expect -c "
    log_user 0
    set timeout $TIMEOUT_NORMAL
    spawn $SSH seclogin
    expect {
        \"Access denied\"           { exit 0 }
        \"Passcode:\"               { exit 1 }
        timeout                    { exit 2 }
    }
"; echo $?)

# remove ACL entries
sed -i '/^deny=/d' /etc/seclogin/seclogin.conf

case "$result" in
    0) pass "Loopback IP blocked by deny= rule" ;;
    1) fail "deny= rule did not block the connection — passcode prompt shown" ;;
    2) fail "Timeout" ;;
    *) fail "Unexpected result: $result" ;;
esac

echo
info "deny=::1 and deny=127.0.0.1 block loopback connections before any prompt."

# ---------------------------------------------------------------------------
# Remote verify mode setup
# ---------------------------------------------------------------------------

header "Setting up remote verify mode"

info "In remote verify mode the TOTP secret stays on the auth server only."
info "Target servers hold no secret — a compromised target exposes nothing."
info "The target SSH's to the auth server using a dedicated keypair."
info "ForceCommand ensures the auth server only runs 'seclogin --verify'."
echo ""
info "In this loopback test auth server and target are the same machine."

# Generate auth keypair — stored in sysadmin home (used by seclogin binary to connect out)
AUTH_KEY="/etc/seclogin/seclogin_ed25519"
info "Generating auth keypair: $AUTH_KEY"
ssh-keygen -t ed25519 -f "$AUTH_KEY" -N "" -q
chown "root:$ADMIN_GROUP" "$AUTH_KEY" "${AUTH_KEY}.pub"
chmod 640 "$AUTH_KEY"
chmod 644 "${AUTH_KEY}.pub"

info "Installing public key with ForceCommand in $AUTH_USER authorized_keys"
info "ForceCommand=seclogin --verify ensures only verification runs over this key"
echo "command=\"$BIN --verify\",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding $(cat ${AUTH_KEY}.pub)" \
    >> "$AUTH_HOME/.ssh/authorized_keys"
chown "$AUTH_USER:$AUTH_USER" "$AUTH_HOME/.ssh/authorized_keys"
chmod 600 "$AUTH_HOME/.ssh/authorized_keys"

info "Creating verify secret: /etc/seclogin/totp_verify.secret (root:$AUTH_USER 0640)"
info "seclogin --verify reads this file — separate from the local SUID secret"
cp /etc/seclogin/totp.secret /etc/seclogin/totp_verify.secret
chown "root:$AUTH_USER" /etc/seclogin/totp_verify.secret
chmod 640 /etc/seclogin/totp_verify.secret

info "Adding SSH client config for $ADMIN_USER — maps localhost to port $SSH_PORT"
info "seclogin's SSH child runs as $ADMIN_USER and uses ~/.ssh/config"
cat > "$ADMIN_HOME/.ssh/config" << EOF
Host localhost
    Port $SSH_PORT
    StrictHostKeyChecking no
EOF
chown "$ADMIN_USER:$ADMIN_GROUP" "$ADMIN_HOME/.ssh/config"
chmod 600 "$ADMIN_HOME/.ssh/config"

info "Populating /etc/seclogin/known_hosts with localhost host key"
ssh-keyscan -p "$SSH_PORT" localhost >> /etc/seclogin/known_hosts 2>/dev/null
chmod 644 /etc/seclogin/known_hosts

info "Switching /etc/seclogin/seclogin.conf to remote verify mode (root:$AUTH_USER 0640)"
info "Auth server: seclogin user reads config after seteuid drop — needs group read access"
cat > /etc/seclogin/seclogin.conf << EOF
auth_server=${AUTH_USER}@localhost
auth_key=${AUTH_KEY}
debug=1
EOF
chown "root:$AUTH_USER" /etc/seclogin/seclogin.conf
chmod 640 /etc/seclogin/seclogin.conf

info "Remote verify mode configured."

# Verify auth server SSH connectivity before remote tests
info "Checking $AUTH_USER user exists:"
id "$AUTH_USER" || echo "  ERROR: user not found"
grep "^$AUTH_USER" /etc/passwd || echo "  ERROR: not in /etc/passwd"

info "Checking authorized_keys for $AUTH_USER:"
ls -la "$AUTH_HOME/.ssh/" || echo "  ERROR: .ssh missing"
cat "$AUTH_HOME/.ssh/authorized_keys" || echo "  ERROR: no authorized_keys"

info "Checking seclogin.conf:"
cat /etc/seclogin/seclogin.conf

info "Checking verify secret file:"
ls -lh /etc/seclogin/totp_verify.secret || echo "  ERROR: /etc/seclogin/totp_verify.secret missing"

info "Testing SSH connection to ${AUTH_USER}@localhost as ${ADMIN_USER}"
su -s /bin/sh "$ADMIN_USER" -c "ssh -v -p $SSH_PORT -i $AUTH_KEY -o StrictHostKeyChecking=no -o BatchMode=yes ${AUTH_USER}@localhost echo ok" 2>&1 || true

# ---------------------------------------------------------------------------

test_case "remote verify — valid code → root shell"

CODE=$(get_code)

result=$(expect -c "
    log_user 0
    set timeout $TIMEOUT_NORMAL
    spawn $SSH seclogin
    expect \"Passcode:\"
    send \"${CODE}\r\"
    expect {
        \"PRIVILEGED ROOT SESSION\" { exit 0 }
        \"Authentication failed\"   { exit 1 }
        timeout                    { exit 2 }
    }
"; echo $?)

case "$result" in
    0) pass "Valid code accepted via remote verify — root shell granted" ;;
    1) fail "Valid code rejected via remote verify" ;;
    2) fail "Timeout waiting for response" ;;
    *) fail "Unexpected result: $result" ;;
esac

echo
info "Target SSHs to auth server, exchanges nonce+HMAC, gets 'ok' ($CODE)."
info "Auth server validates TOTP and logs approval with client IP and nonce age."

# ---------------------------------------------------------------------------

test_case "remote verify — invalid code → authentication failed"

if [ "$QUICK" -eq 1 ]; then
    skip "Skipped in quick mode"
else
    result=$(expect -c "
        log_user 0
        set timeout $TIMEOUT_NORMAL
        spawn $SSH seclogin
        expect \"Passcode:\"
        send \"000000\r\"
        expect {
            \"Authentication failed\"   { exit 0 }
            \"PRIVILEGED ROOT SESSION\" { exit 1 }
            timeout                    { exit 2 }
        }
    "; echo $?)

    case "$result" in
        0) pass "Invalid code rejected via remote verify" ;;
        1) fail "Invalid code accepted via remote verify (bad!)" ;;
        2) fail "Timeout" ;;
        *) fail "Unexpected result: $result" ;;
    esac

    echo
    info "Auth server returns 'fail' — a ${AUTH_FAIL_DELAY}s delay is enforced server-side."
    info "Limits brute force to ~1 attempt per ${AUTH_FAIL_DELAY}s per connection."
fi

# ---------------------------------------------------------------------------

test_case "remote verify — nonce expiry"

if [ "$QUICK" -eq 1 ]; then
    skip "Skipped in quick mode (${TEST_DELAY}s delay)"
else
    cat >> /etc/seclogin/seclogin.conf << EOF
test_delay=$TEST_DELAY
EOF

    CODE=$(get_code)

    result=$(expect -c "
        log_user 0
        set timeout $TIMEOUT_EXPIRY
        spawn $SSH seclogin
        expect \"Passcode:\"
        send \"${CODE}\r\"
        expect {
            \"Authentication failed\"   { exit 0 }
            \"PRIVILEGED ROOT SESSION\" { exit 1 }
            timeout                    { exit 2 }
        }
    "; echo $?)

    sed -i '/^debug=/d; /^test_delay=/d' /etc/seclogin/seclogin.conf
    rm -f /var/log/seclogin-debug.log

    case "$result" in
        0) pass "Expired nonce rejected via remote verify (age > ${NONCE_MAX_AGE}s)" ;;
        1) fail "Expired nonce accepted via remote verify (bad!)" ;;
        2) fail "Timeout" ;;
        *) fail "Unexpected result: $result" ;;
    esac

    echo
    info "Auth server embeds timestamp in nonce — test_delay=$TEST_DELAY forces age past ${NONCE_MAX_AGE}s."
    info "No clock skew: generation and validation both happen on the auth server."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

header "Summary"

for i in $(seq 0 $((nTest - 1))); do
    szName="${aTestNames[$i]}"
    szResult="${aTestResults[$i]}"
    case "$szResult" in
        PASS) echo -e "  ${GREEN}[PASS]${NC}  Test $((i+1)): $szName" ;;
        FAIL) echo -e "  ${RED}[FAIL]${NC}  Test $((i+1)): $szName" ;;
        SKIP) echo -e "  ${YELLOW}[SKIP]${NC}  Test $((i+1)): $szName" ;;
        *)    echo -e "         Test $((i+1)): $szName" ;;
    esac
done

if [ "$nFail" -eq 0 ]; then
    echo
    echo -e "  ${GREEN}All tests passed.${NC}"
    echo
else

    header "Debug Log"

    echo -e "  ${RED}${nFail} test(s) failed.${NC}"

    if [ -f /var/log/seclogin-debug.log ]; then
        header "seclogin debug log"
        cat /var/log/seclogin-debug.log
    fi

    if [ -f /tmp/sshd.log ]; then
        header "sshd log"
        grep -v "^debug" /tmp/sshd.log
    fi
fi

header "Results"

echo -e "  ${GREEN}[PASS]${NC}  $(printf '%3d' $nPass)"
echo -e "  ${RED}[FAIL]${NC}  $(printf '%3d' $nFail)"
echo -e "  ${YELLOW}[SKIP]${NC}  $(printf '%3d' $nSkip)"
printf "  Runtime %3ds\n" "${SECONDS:-0}"
echo
