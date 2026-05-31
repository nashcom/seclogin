# SECLogin — Secure Enforced Login

SECLogin adds authentication, authorization, auditing, and controlled privilege
elevation on top of SSH and existing Linux infrastructure.

A hardened TOTP authentication gate for SSH sessions and privileged shell access.
Designed for servers where you control who can SSH in and want a second factor
before granting a root shell. The user must already be strongly authenticated
via SSH key and password before `seclogin` is reachable.

> **SECLogin is not a replacement for sudo.**
>
> `sudo` is *command authorization* — it grants specific users the right to run
> specific commands. `seclogin` is *privileged session elevation* — it opens a
> full interactive root shell after multi-factor authentication. These are
> different security models serving different purposes. Use `sudo` for
> controlled, auditable command delegation. Use `seclogin` for trusted
> sysadmins who need an interactive root session and require a second factor
> to reach it. They complement each other; neither replaces the other.

**This is a tool for interactive user sessions only.** A real TTY is required
by design — piped input, scripting, and automation are explicitly rejected.
For non-interactive or scripted root access, use `sudo` with appropriate
sudoers rules instead.

---

## Overview

`seclogin` is a small, statically linked C binary that:

1. Validates its own binary integrity (SUID bit, root ownership, no world/group write)
2. Requires an interactive SSH session with a real TTY
3. Checks IP access control rules (optional `allow=` / `deny=` in config)
4. Optionally prompts for a reason before authentication
5. Prompts for a TOTP passcode (RFC 6238, SHA256 by default)
6. Drops supplementary groups, sets UID/GID to root
7. Launches a clean, sanitized `bash` root shell

Authentication attempts are logged to syslog (`LOG_AUTH`) in structured
`key=value` format for easy grepping and SIEM integration.

### Threat model

- The invoking user is already trusted and SSH-authenticated
- `seclogin` is the second factor: TOTP prevents unauthorized use if the SSH key is compromised
- Only members of the `seclogin` group can execute the binary
- On auth servers the binary has no SUID bit — verify mode never needs root

### Three modes

| Mode | Binary | Ownership | Use when |
|---|---|---|---|
| **Local TOTP** | `seclogin` | `root:seclogin 4750` | Simple deployments — secret on each server |
| **Remote verification** | `seclogin` | Client: `4750` / Auth server: `0750` | Multiple servers, centralised secret |
| **Gate mode** | `seclogin-gate` | `seclogin:seclogin 4750` | TOTP gate for any user's login shell |

Mode is auto-detected at runtime from `geteuid()`:
- `euid = 0` → root shell mode
- `euid ≠ 0` → gate mode (same binary, different SUID owner)

---

## Quick start

### Local TOTP mode

```bash
# 1. Edit config (ADMIN_USER, ADMIN_HOME, ISSUER)
vi config

# 2. Install dependencies
sudo ./install_deps.sh

# 3. Create seclogin group and sysadmin user
sudo ./create_accounts.sh

# 4. Configure sshd (LogLevel VERBOSE + key+password auth)
sudo ./configure_sshd.sh
sudo passwd sysadmin

# 5. Add SSH public key for sysadmin
sudo mkdir -p /home/sysadmin/.ssh
sudo install -o sysadmin -m 600 /dev/stdin /home/sysadmin/.ssh/authorized_keys
# paste public key, Ctrl+D

# 6. Build and install binary
./build_alpine.sh
sudo ./build_alpine.sh install

# 7. Generate TOTP secret and scan QR code
sudo ./create_totp.sh

# 8. Test
ssh sysadmin@<server>
seclogin
```

### Remote verification mode

```bash
# On the auth server:
sudo ./create_accounts.sh          # seclogin group + sysadmin user
sudo ./setup_auth_server.sh        # seclogin user, verify secret, keypair, ForceCommand, binary

# Run on the auth server to print per-target instructions:
sudo ./show_target_config.sh

# On each target server (paste the printed commands):
#   0. create accounts
#   1. install SUID binary from auth server
#   2. copy SSH private key from auth server
#   3. trust auth server host key into /etc/seclogin_known_hosts
#   4. write /etc/seclogin.conf
```

---

## Requirements

**Target host:**
- Linux with `/proc` filesystem
- `bash`
- OpenSSL (runtime, for dynamic build only)
- `seclogin` group and admin user (see [Accounts](#accounts))

**Build host:**
- Docker (for Alpine static build — recommended)
- `gcc`, `make`, `libssl-dev` (for dynamic build only)

**Provisioning tools (host):**
- `oathtool` — generate and verify TOTP codes
- `qrencode` — generate QR codes for authenticator app enrollment

```bash
sudo ./install_deps.sh
```

---

## Accounts

`seclogin` uses two accounts with clearly separated roles:

| Account | Role | Exists on |
|---|---|---|
| `sysadmin` | Admin user who runs `seclogin` | All servers |
| `seclogin` | Runs `seclogin --verify` via ForceCommand | Auth server only |
| `seclogin` group | Owns binary + config; controls who can execute | All servers |

```bash
sudo ./create_accounts.sh          # creates seclogin group + sysadmin user (any server)
sudo ./create_seclogin_user.sh     # creates seclogin user (auth server only)
```

**Why two accounts?**
`sysadmin` is a full admin who needs a root shell. `seclogin` is a service account
with no login shell that exists only to run `seclogin --verify` over SSH — it never
gets an interactive session. The `seclogin` group controls execute permission on the
binary (`4750` — group execute only).

---

## Customisation

All site-specific settings live in **`config`**. Edit this file before
running any other script.

```bash
# TOTP issuer name shown in authenticator apps
ISSUER=seclogin

# seclogin group owns the binary and config — controls who can run seclogin
ADMIN_GROUP=seclogin
ADMIN_USER=sysadmin
ADMIN_HOME=/home/sysadmin
ADMIN_SHELL=/bin/bash

# Config and install paths
CONFIG_FILE=/etc/seclogin.conf
INSTALL_DIR=/usr/local/bin
BIN=seclogin
MODE=4750       # client/target: SUID root
AUTH_MODE=0750  # auth server:   no SUID

# Dedicated user on the auth server for remote verification (ForceCommand)
AUTH_USER=seclogin
AUTH_HOME=/home/seclogin
```

### Domino / HCL Notes integration

On Domino servers `seclogin` reads the server name from `notes.ini` and
displays it in the privilege banner. Configurable via `/etc/seclogin.conf`:

```ini
notes_ini=/local/notesdata/notes.ini
```

If the file does not exist the Domino Server line is simply not shown —
safe to deploy on non-Domino servers without any changes.

---

## File permissions

The permission model separates reading from executing:

| File | Client / Target | Auth server |
|---|---|---|
| `/usr/local/bin/seclogin` | `root:seclogin 4750` SUID | `root:seclogin 0750` no SUID |
| `/etc/seclogin.conf` | `root:root 0600` | `root:seclogin 0640` |
| `/etc/seclogin.secret` | `root:root 0600` | not created |
| `/etc/seclogin-verify.secret` | not needed | `root:seclogin 0640` |
| `/etc/seclogin_known_hosts` | `root:root 0644` | — |

**Client:** sysadmin is in the `seclogin` group → can execute the SUID binary.
Config and secret are `root:root 0600` — sysadmin cannot read them directly.
The SUID binary reads them as root.

**Auth server:** seclogin user is in the `seclogin` group → can read config and
verify secret (`0640`). Binary has no SUID bit — verify mode runs entirely
unprivileged. `seclogin --verify` drops SUID euid immediately via `seteuid(getuid())`.

---

## Build

### Static build — Alpine container (recommended)

Produces a fully static binary with no runtime dependencies. Immune to
`LD_PRELOAD` attacks.

```bash
./build_alpine.sh           # compile only
./build_alpine.sh install   # compile + install to host (requires root)
./build_alpine.sh test      # run test suite (~26s)
./build_alpine.sh test --quick   # quick tests, skip delay-heavy (~5s)
./build_alpine.sh all       # compile + full test suite
./build_alpine.sh rebuild   # force rebuild of Docker image, then compile
```

On first run the script builds a `seclogin-build` Docker image with all
compile-time and test dependencies. Subsequent runs reuse the cached image.

### Dynamic build — host toolchain

```bash
make
```

---

## Local TOTP mode

The TOTP secret is stored on each server. Simple to deploy — no additional
infrastructure required.

### Setup

```bash
# 1. Create seclogin group and sysadmin user
sudo ./create_accounts.sh

# 2. Configure sshd
sudo ./configure_sshd.sh
sudo passwd sysadmin

# 3. Add SSH public key for sysadmin
sudo mkdir -p /home/sysadmin/.ssh
sudo install -o sysadmin -m 600 /dev/stdin /home/sysadmin/.ssh/authorized_keys

# 4. Build and install binary (SUID, client mode)
./build_alpine.sh
sudo ./build_alpine.sh install

# 5. Provision TOTP secret
sudo ./create_totp.sh           # SHA256 (default)
sudo ./create_totp.sh SHA1      # for Microsoft Authenticator
```

### Authenticator app compatibility

| App | SHA1 | SHA256 |
|---|---|---|
| Google Authenticator | ✓ | ✓ |
| Aegis (Android) | ✓ | ✓ |
| andOTP | ✓ | ✓ |
| YubiKey Authenticator | ✓ | ✓ |
| Microsoft Authenticator | ✓ | ✗ — silently falls back to SHA1 |

SHA256 is the default. Use `SHA1` only if your app does not support SHA256.

### Configuration — `/etc/seclogin.conf`

```
owner: root:root  mode: 0600
```

```ini
# seclogin configuration - local TOTP mode
algorithm=SHA256

# secret_file=/etc/seclogin.secret        (default)
# notes_ini=/local/notesdata/notes.ini
# reason=0                                (0=disabled 1=optional 2=required)
# allow=192.168.1.0/24
# deny=192.168.1.100
```

### Configuration keys

| Key | Values | Default | Description |
|---|---|---|---|
| `algorithm` | `SHA256`, `SHA1` | `SHA256` | HMAC digest algorithm |
| `secret_file` | file path | `/etc/seclogin.secret` | Path to TOTP secret file |
| `notes_ini` | file path | `/local/notesdata/notes.ini` | Path to Domino notes.ini (optional) |
| `reason` | `0`, `1`, `2` | `0` | Reason prompt: 0=disabled, 1=optional, 2=required |
| `allow` | CIDR | — | Allow rule (multiple entries supported) |
| `deny` | CIDR | — | Deny rule — checked before allow (multiple entries supported) |
| `debug` | `1` | disabled | Write trace log to `/var/log/seclogin-debug.log` |

### Utility scripts

| Script | Description |
|---|---|
| `sudo ./create_totp.sh [SHA256\|SHA1] [account] [secret_file]` | Generate secret and config |
| `sudo ./show_totp_qr.sh [account]` | Re-display QR code for re-enrollment |
| `sudo ./get_code.sh [secret_file]` | Print the current TOTP code (auto-detects secret file) |

---

## Reason feature

seclogin can prompt the user for a reason before authentication. The reason is
logged in syslog and — in remote verification mode — sent to the auth server.

Configure in `/etc/seclogin.conf`:

```ini
reason=0    # disabled (default)
reason=1    # ask for a reason — user may leave it blank
reason=2    # require a reason — empty reason is rejected
```

Example session with `reason=2`:

```
  Reason: deploying hotfix to prod

  Passcode:
```

The reason appears in the syslog entry:

```
seclogin: auth=success target=root uid=1001 src=192.168.1.50 port=38824 reason="deploying hotfix to prod"
```

---

## IP access control

seclogin supports per-server IP whitelisting and blacklisting via `allow=` and
`deny=` entries in `/etc/seclogin.conf`. Both IPv4 and IPv6 CIDR notation are
supported. IPv4-mapped IPv6 addresses (e.g. `::ffff:192.168.1.1`) are matched
transparently against IPv4 rules.

```ini
# Allow only specific networks
allow=192.168.1.0/24
allow=10.0.0.0/8
allow=::1

# Block a specific host within an allowed range
deny=192.168.1.100

# IPv6 range
allow=2001:db8::/32
```

### Evaluation order

1. **deny= rules checked first** — match → reject immediately, no prompt shown
2. **allow= rules checked next** — match → proceed to authentication
3. **No allow= rules** — allow all not explicitly denied (deny-only mode)
4. **Allow rules exist, no match** → reject
5. **No rules at all** → allow all (backward compatible default)
6. **Console access** (no SSH) → always allow regardless of rules

### Syslog on rejection

```
seclogin: auth=denied target=root uid=1001 src=192.168.1.100 port=38824 msg="IP access denied"
```

---

## Usage

Connect via SSH as the admin user, then run:

```
seclogin
```

You will see:

```
  We trust you have received the usual lecture from the local
  System Administrator. It usually boils down to these three things:

    1.  Respect the privacy of others.
    2.  Think before you type.
    3.  With great power comes great responsibility.

  Reason: <optional, if configured>

  Passcode:
```

Enter the current 6-digit code from your authenticator app. On success the
screen clears and the privileged banner appears:

```
--------------------------------------
  PRIVILEGED ROOT SESSION
  This session is logged.

  Host:   myserver
  Domino: earth/NotesLab
--------------------------------------

[root@myserver ~]#
```

The shell is `bash` with `--noprofile --norc -p`. No startup files are sourced.
The environment contains only: `PATH`, `TERM`, `LANG`, `HOME`, `PS1`.

---

## Remote HMAC verification mode

Remote verification moves the TOTP secret off target servers entirely.
Only the auth server holds the secret — a compromised target server
exposes nothing sensitive.

### How it works

```
Local (target server)                  Remote (auth server, ForceCommand)
────────────────────────────────────────────────────────────────────────
seclogin collects user code
fork unprivileged child
  │
  │── ssh seclogin@authsrv ──────────►│  seclogin --verify (no SUID, unprivileged)
  │                                    │── generate remote_nonce
  │                                    │   = timestamp(4) || random(12)
  │◄── remote_nonce ───────────────────│
  │                                    │
  │  compute HMAC(remote_nonce,        │
  │               user_code)           │
  │                                    │
  │── local_nonce + HMAC + reason ────►│
  │                                    │── check nonce age ≤ 10s
  │                                    │── validate TOTP window
  │                                    │── log result + reason
  │◄── ok / fail ──────────────────────│   (fail adds 5s delay)
  │                                    │
child reports result to parent
if ok → privilege elevation
```

The `ok / fail` response is authenticated by the SSH transport. `local_nonce`
is a correlation ID matching the target server log entry to the auth server log.
The network call runs entirely **before** privilege elevation — the SUID binary
never touches the network.

**Auth server binary has no SUID.** `seclogin --verify` calls `seteuid(getuid())`
immediately — it runs entirely as the `seclogin` service account.

**Nonce timestamping:** `remote_nonce` embeds a unix timestamp in its first 4
bytes. Generation and validation both happen on the auth server — zero clock skew.
The auth server rejects nonces older than 10 seconds.

**Brute force mitigation:** failed verifications incur a 5-second delay.
As this delay is per process, we recommend additionally rate-limiting
connections at the host layer with Fail2Ban or CrowdSec on the auth server.

### Why this is stronger than local TOTP

| | Local TOTP | Remote verification |
|---|---|---|
| Secret location | every target server | auth server only |
| Target server compromise | exposes TOTP secret | exposes nothing |
| Replay protection | 30s TOTP time window | nonce expires after 10s |
| Brute force rate limit | sshd connection overhead | 5s delay per failed attempt |
| Audit trail | local syslog only | centralised on auth server |

### Auth server setup

```bash
# On the auth server — run once:
sudo ./create_accounts.sh          # seclogin group + sysadmin user
sudo ./setup_auth_server.sh        # all remaining steps (see below)

# Print per-target deployment instructions:
sudo ./show_target_config.sh
```

`setup_auth_server.sh` performs these steps:
1. Create `seclogin` user (no login shell, ForceCommand account)
2. Generate TOTP verify secret → `/etc/seclogin-verify.secret` (`root:seclogin 0640`)
3. Generate SSH keypair (`seclogin_ed25519`) + copy to sysadmin home for distribution
4. Install binary without SUID (`root:seclogin 0750`)
5. Install ForceCommand in seclogin's `authorized_keys`
6. Show host key fingerprints for manual trust on target servers

**Note:** `/etc/seclogin.secret` is **not** created on the auth server.
The verify secret (`/etc/seclogin-verify.secret`) is generated directly.

### Target server setup

Follow the printed output of `show_target_config.sh`:

```bash
# 0. Create seclogin group and sysadmin user
sudo groupadd seclogin
sudo useradd --gid seclogin --home-dir /home/sysadmin --create-home --shell /bin/bash sysadmin

# 1. Install SUID binary from auth server
scp sysadmin@authsrv:/usr/local/bin/seclogin /tmp/seclogin
sudo install -o root -g seclogin -m 4750 /tmp/seclogin /usr/local/bin/seclogin

# 2. Copy SSH private key from auth server (connect as sysadmin — seclogin has ForceCommand)
mkdir -p /home/sysadmin/.ssh
scp sysadmin@authsrv:~/.ssh/seclogin_ed25519 /home/sysadmin/.ssh/seclogin_ed25519
chmod 600 /home/sysadmin/.ssh/seclogin_ed25519

# 3. Trust the auth server host key into /etc/seclogin_known_hosts
touch /etc/seclogin_known_hosts
chmod 644 /etc/seclogin_known_hosts
ssh -o UserKnownHostsFile=/etc/seclogin_known_hosts \
    -i /home/sysadmin/.ssh/seclogin_ed25519 \
    seclogin@authsrv
# Verify fingerprint matches output of setup_auth_server.sh, type yes, Ctrl+C

# 4. Write /etc/seclogin.conf
cat > /etc/seclogin.conf << 'EOF'
algorithm=SHA256
auth_server=seclogin@authsrv.example.com
auth_key=/home/sysadmin/.ssh/seclogin_ed25519
# notes_ini=/local/notesdata/notes.ini
EOF
sudo chown root:root /etc/seclogin.conf
sudo chmod 600 /etc/seclogin.conf
```

No secret file on target servers — `/etc/seclogin.secret` does not exist.

### Host key trust — `/etc/seclogin_known_hosts`

seclogin uses a dedicated system-wide known_hosts file (`/etc/seclogin_known_hosts`)
rather than a per-user `~/.ssh/known_hosts`. This means:

- One file per target server, shared by all users who run `seclogin`
- Adding new admin users requires no per-user SSH setup
- Explicit, auditable list of trusted auth servers on each machine
- Path is configurable via `known_hosts=` in `/etc/seclogin.conf`

Populate it once per target server with the ssh command shown above (no `ssh-keyscan` —
the fingerprint must be manually verified against the auth server output).

### Remote verification configuration

| Key | Values | Default | Description |
|---|---|---|---|
| `auth_server` | `user@host` | — | Auth server — enables remote mode when set |
| `auth_key` | file path | — | SSH private key for connecting to auth server |
| `known_hosts` | file path | `/etc/seclogin_known_hosts` | Known hosts file for auth server verification |
| `notes_ini` | file path | `/local/notesdata/notes.ini` | Domino notes.ini (optional) |
| `reason` | `0`, `1`, `2` | `0` | Reason prompt mode |
| `allow` / `deny` | CIDR | — | IP access control rules |
| `debug` | `1` | disabled | Write trace log to `/var/log/seclogin-debug.log` |

---

## Gate mode — TOTP gate for login shells

Gate mode turns `seclogin-gate` into a TOTP-gated login shell launcher for
any user — not just sysadmin. After successful TOTP authentication the user
gets their own login shell. No root access is granted.

**Typical uses:**
- TOTP-protected SSH login for the `notes` user on a Domino server
- Second factor for any service account that needs interactive access
- `authorized_keys` ForceCommand that enforces TOTP before the user's shell

### How it works

The binary is the same source code as `seclogin`. The mode is detected at
runtime from `geteuid()`:
- SUID owner is `root` → `euid=0` → root shell mode
- SUID owner is `seclogin` → `euid=seclogin` → gate mode

```
/usr/local/bin/seclogin       root:seclogin    4750  ← root shell for sysadmin
/usr/local/bin/seclogin-gate  seclogin:seclogin 4750  ← login gate for any user
```

### After successful TOTP

1. `initgroups()` — restore the user's supplementary groups
2. `setresgid(gid, gid, gid)` — drop to user's GID
3. `setresuid(uid, uid, uid)` — drop SUID, fully become the invoking user
4. `execve(pw_shell, ["-shell"], env)` — exec login shell from `/etc/passwd`

`SSH_ORIGINAL_COMMAND` is intentionally ignored — only login shells are exec'd.

### Installation

```bash
# Install gate mode binary (SUID to seclogin user, not root)
sudo install -o seclogin -g seclogin -m 4750 seclogin /usr/local/bin/seclogin-gate
```

### Use as login shell

```bash
# Set seclogin-gate as login shell for the notes user
sudo usermod -s /usr/local/bin/seclogin-gate notes
```

### Use as authorized_keys ForceCommand

```
command="/usr/local/bin/seclogin-gate",no-pty,no-port-forwarding ssh-ed25519 AAAA...
```

### Syslog

Gate mode uses the same `key=value` format with `target=<username>`:

```
seclogin: auth=success target=notes uid=1005 src=192.168.1.50 port=38824
seclogin: auth=failed  target=notes uid=1005 src=192.168.1.50 port=38824
```

---

## Logging and audit trail

seclogin logs events to syslog (`LOG_AUTH`) in `key=value` format.
SSH authentication events are logged by sshd. The two are correlated by
client IP and port.

### Log format

All log entries use consistent structured fields:

```
auth=       success | failed | approved | denied | error
target=     root
uid=        real UID of the invoking user
src=        client IP address
port=       client port
reason=     reason text (when configured and provided)
msg=        error description (on failure/error entries)
```

### Log examples

**Successful privilege escalation:**
```
seclogin: auth=success target=root uid=1001 src=192.168.1.50 port=38824
seclogin: auth=success target=root uid=1001 src=192.168.1.50 port=38824 reason="deploying hotfix"
```

**Failed authentication:**
```
seclogin: auth=failed target=root uid=1001 src=192.168.1.50 port=38824
seclogin: auth=failed target=root uid=1001 src=192.168.1.50 port=38824 msg="invalid passcode length"
```

**IP access denied:**
```
seclogin: auth=denied target=root uid=1001 src=10.0.0.99 port=22345 msg="IP access denied"
```

**Remote verification — auth server:**
```
seclogin --verify: auth=approved uid=2000 src=10.0.0.5 port=52318 age=3s nonce=6a1c0dff... reason="hotfix"
seclogin --verify: auth=denied   uid=2000 src=10.0.0.5 port=52318 age=3s nonce=6a1c0dff...
seclogin --verify: auth=error    uid=2000 src=10.0.0.5 port=52318 msg="nonce expired" age=14s nonce=...
```

### Grep patterns

```bash
journalctl | grep 'auth=success'    # successful root shells granted
journalctl | grep 'auth=failed'     # failed authentication attempts
journalctl | grep 'auth=denied'     # IP-blocked or verify-denied
journalctl | grep 'auth=approved'   # remote verify approvals
journalctl | grep 'auth=error'      # protocol / nonce errors
journalctl | grep 'src=10.0.0.5'    # all events from a specific IP
```

### Security chain

seclogin is the third factor. The sysadmin user should authenticate with all three:

```
1. SSH key      — who you are
2. SSH password — what you know
3. TOTP         — seclogin passcode (what you have)
```

Configure sshd for key + password:
```bash
sudo ./configure_sshd.sh
```

### Viewing logs

```bash
sudo ./show_syslog.sh               # last 20 entries
sudo ./show_syslog.sh -f            # follow live
sudo ./show_syslog.sh --since today # today's entries
sudo journalctl SYSLOG_FACILITY=10  # all auth events (sshd + seclogin)
```

---

## Status and cleanup

```bash
sudo ./status.sh            # show installed files, permissions, users
sudo ./status.sh --delete   # show status then remove everything (sysadmin preserved)
```

`status.sh` auto-detects the server role (auth server / client / both) from what
is installed and shows the appropriate expectations for each file.

Example output:

```
------------------------------------------------------------
 seclogin status — myserver.example.com
------------------------------------------------------------

  Role: client

------------------------------------------------------------
 Binary
------------------------------------------------------------
  ✓  4750  -rwsr-x---  root:seclogin         /usr/local/bin/seclogin

------------------------------------------------------------
 Client config
------------------------------------------------------------
  ✓  600   -rw-------  root:root             /etc/seclogin.conf
  ✓  600   -rw-------  root:root             /etc/seclogin.secret
  !  644   -rw-r--r--  root:sysadmin         /etc/seclogin_known_hosts
  >  644               root:root
```

---

## Testing

The test suite runs entirely inside the `seclogin-build` Docker container —
no changes to the host system. It sets up a loopback sshd on port 2222,
provisions a known test secret, and exercises seclogin end-to-end via
`expect`-driven SSH sessions.

```bash
./build_alpine.sh test           # full suite — ~26s
./build_alpine.sh test --quick   # quick mode — ~5s, skips delay tests
```

### What is tested

| Test | Mode | Description |
|---|---|---|
| Binary permissions | — | SUID bit set, owned `root:seclogin` |
| Valid TOTP code | Local | Correct code grants root shell |
| Invalid TOTP code | Local | Wrong code rejected + 5s delay enforced |
| Wrong binary permissions | Local | Non-SUID binary rejected at startup |
| Missing config file | Local | Defaults applied, auth still works |
| Secret wrong permissions | Local | World-readable secret rejected |
| allow= rule | Local | Matching IP permitted before prompt |
| deny= rule | Local | Blocked IP rejected before prompt |
| Remote valid code | Remote | Correct code approved via auth server |
| Remote invalid code | Remote | Wrong code denied + 5s delay enforced |
| Remote nonce expiry | Remote | `test_delay=12` forces nonce past 10s limit |

`--quick` skips the three delay-heavy tests (invalid code ×2, nonce expiry),
reducing runtime from ~26s to ~5s.

---

## SSH certificate authentication

seclogin is explicitly designed to work with SSH certificate-based authentication,
though it works equally well with traditional `authorized_keys`. SSH certificates are
not required — but when used together, they form a particularly powerful and clean
access control model.

### Why SSH certificates fit this design

Traditional SSH key auth requires maintaining `authorized_keys` on every server.
With SSH certificates, a single Certificate Authority (CA) signs user public keys.
Servers trust the CA — not individual keys. This eliminates per-server key management
entirely and adds powerful access control through certificate principals and expiry.

Combined with seclogin, the full authentication chain becomes:

```
1. SSH certificate   — who you are, which accounts you may reach, until when
2. seclogin TOTP     — proof of presence (second factor)
3. Shell or root     — what you can do (gate mode or privilege escalation)
```

Each layer enforces a different aspect of access control. A compromised SSH key
is limited by the certificate's principals and expiry. A stolen TOTP secret is
useless without the SSH key. Neither alone grants access.

### Setting up an SSH CA

```bash
# Generate the CA key — keep this extremely secure
ssh-keygen -t ed25519 -f /etc/ssh/seclogin_ca -C "seclogin CA"

# Configure sshd on each server to trust the CA
echo "TrustedUserCAKeys /etc/ssh/seclogin_ca.pub" >> /etc/ssh/sshd_config
systemctl reload sshd
```

The CA private key (`seclogin_ca`) should be kept offline or in a hardware security
module. Only the public key (`seclogin_ca.pub`) is distributed to servers.

### Signing user keys with principal restrictions

A certificate's **principals** field controls which accounts the holder may log in to.
This is where the power of the model lies — the CA decides, at signing time, exactly
which accounts on which servers a user can reach.

```bash
# Sign sysadmin's key — can only log in as 'sysadmin' account
ssh-keygen -s /etc/ssh/seclogin_ca \
    -I "alice-sysadmin" \
    -n sysadmin \
    -V +365d \
    alice_id_ed25519.pub

# Sign notes user's key — restricted to 'notes' account only
ssh-keygen -s /etc/ssh/seclogin_ca \
    -I "alice-notes" \
    -n notes \
    -V +90d \
    alice_id_ed25519.pub

# Sign with multiple principals — sysadmin and notes on specific servers
ssh-keygen -s /etc/ssh/seclogin_ca \
    -I "alice-prod" \
    -n "sysadmin,notes" \
    -O source-address=192.168.1.0/24 \
    -V +30d \
    alice_id_ed25519.pub
```

| Option | Meaning |
|---|---|
| `-I` | Certificate identity (shown in logs) |
| `-n` | Principals — which accounts this cert may log in to |
| `-V +365d` | Valid for 365 days from now |
| `-O source-address=` | Restrict to source IP range |

### Integration with seclogin

**Standard login (`sysadmin` account):**
The sysadmin certificate has principal `sysadmin`. The user SSHs in, runs `seclogin`
for TOTP, and gets a root shell. The certificate controls access to the `sysadmin`
account; seclogin adds the TOTP second factor before privilege escalation.

**Gate mode (`seclogin-gate` for other accounts):**
The `notes` certificate has principal `notes`. The user SSHs directly to the `notes`
account — `seclogin-gate` is the login shell, prompting for TOTP before the session
starts. The certificate restricts which account is reached; `seclogin-gate` ensures
TOTP is required regardless.

```
                  CA signs cert          cert has principal=notes
Alice's key  ─────────────────────►  cert ──────────────────────► notes@server
                                                                       │
                                                             seclogin-gate prompts
                                                             for TOTP before shell
```

**Without SSH certificates:** seclogin works normally with traditional `authorized_keys`.
The certificate layer is optional — seclogin's TOTP gate works the same either way.
SSH certificates simply add centralized key management and principal-based restrictions
on top.

### Certificate principals and seclogin accounts

A recommended mapping:

| Certificate principal | Account | seclogin binary | Result |
|---|---|---|---|
| `sysadmin` | sysadmin | `seclogin` (4750 SUID root) | Root shell after TOTP |
| `notes` | notes | `seclogin-gate` (6755 login shell) | Notes shell after TOTP |
| `backup` | backup | `seclogin-gate` | Backup shell after TOTP |

Each user gets a separate signed certificate per role. Certificates expire
automatically. Revoking access means not renewing the certificate — no server-side
changes needed.

### Certificate revocation

SSH supports a `RevokedKeys` file or KRL (Key Revocation List) in `sshd_config`:

```bash
# Revoke a specific certificate immediately
ssh-keygen -k -f /etc/ssh/revoked_keys -z 1 alice_id_ed25519-cert.pub

# sshd_config
RevokedKeys /etc/ssh/revoked_keys
```

This provides immediate revocation without waiting for certificate expiry.

### Summary

| Feature | Without certs | With SSH certificates |
|---|---|---|
| Key management | Per-server `authorized_keys` | Single CA, no per-server setup |
| Account restrictions | Per-key `authorized_keys` entry | Certificate principal field |
| Access expiry | Manual key removal | Certificate `-V` expiry |
| Revocation | Remove from `authorized_keys` | KRL or non-renewal |
| Audit identity | Key fingerprint | Certificate identity (`-I`) |
| seclogin TOTP | Required | Required (unchanged) |

seclogin's TOTP requirement is orthogonal to certificate authentication —
it applies regardless of how the SSH session was established.

---

## Security design

| Measure | Detail |
|---|---|
| `root:seclogin 4750` | Only `seclogin` group members can execute the SUID binary |
| No SUID on auth server | Auth server binary is `0750` — verify mode runs unprivileged |
| `seteuid(getuid())` in verify | Drops SUID euid immediately — verify mode runs as `seclogin` user |
| Binary self-check | Verifies root ownership, SUID bit, no world/group write |
| TTY required | `isatty()` on stdin and stdout — blocks non-interactive use |
| SSH env checks | `SSH_CONNECTION` / `SSH_TTY` — defense-in-depth (forgeable, documented) |
| IP access control | `allow=` / `deny=` CIDR rules checked before any UI is shown |
| Config security | Checks root ownership, no world access, regular file, no symlinks |
| Secret security | `root:root 0600` — readable only by SUID binary (`euid=root`) |
| Verify secret | `root:seclogin 0640` — readable only by `seclogin` user after `seteuid` drop |
| `seclogin_known_hosts` | System-wide known_hosts for auth server — no per-user setup needed |
| TOTP-SHA256 | RFC 6238 via OpenSSL HMAC — no external TOTP library |
| Constant-time compare | `CRYPTO_memcmp()` for TOTP and HMAC comparison — no timing leak |
| Timestamped nonce | `remote_nonce` = 4-byte timestamp + 12-byte random; expires after 10s |
| Brute force delay | 5-second sleep before `fail` response in `--verify` mode |
| `prctl(PR_SET_DUMPABLE, 0)` | Disables core dumps and `/proc/PID/mem` access |
| `setgroups(0, NULL)` | Drops all supplementary groups before privilege transition |
| `setgid(0)` before `setuid(0)` | Correct privilege escalation order |
| `umask(077)` | Set at start and after `setuid` — no inherited umask survives |
| Privilege boundary | All file I/O, NSS lookups and string parsing done before `setuid` |
| Environment sanitization | `clearenv()` then explicit allowlist: `PATH`, `TERM`, `LANG`, `HOME`, `PS1` |
| `TERM` / `LANG` validation | Content-validated before passing to child process |
| `close_fds()` | Enumerates `/proc/self/fd` — closes all FDs > 2 before exec |
| `O_NOFOLLOW` on config/secrets | Prevents symlink attacks |
| `bash -p` | Privileged mode — disables `$BASH_ENV` and function import |
| Static binary (Alpine build) | No dynamic linker — `LD_PRELOAD` has no attack surface |
| Full RELRO + PIE | `-Wl,-z,relro,-z,now` + `-fPIE -pie` — GOT read-only, ASLR enabled |
| Structured syslog | `key=value` format — grep-friendly, SIEM-ready |

---

## File overview

### Source and build

| File | Purpose |
|---|---|
| `seclogin.c` | Main source |
| `Makefile` | Dynamic build (host toolchain) |
| `Makefile.alpine` | Static build (Alpine container) |
| `Dockerfile.build` | Alpine build image definition |
| `build_alpine.sh` | Build, test, and install via Docker (installs both `seclogin` and `seclogin-gate`) |

### Configuration

| File | Purpose |
|---|---|
| `config` | Site-specific settings sourced by all scripts |

### Setup scripts

| Script | Run on | Purpose |
|---|---|---|
| `install_deps.sh` | Any | Install `oathtool` and `qrencode` |
| `create_accounts.sh` | Any | Create `seclogin` group and `sysadmin` user |
| `configure_sshd.sh` | Any | Configure sshd (LogLevel VERBOSE, key+password auth) |
| `setup_auth_server.sh` | Auth server | Full auth server setup (orchestrates scripts below) |
| `create_seclogin_user.sh` | Auth server | Create `seclogin` service account |
| `create_totp.sh` | Auth server / client | Generate TOTP secret and config |
| `create_auth_key.sh` | Auth server | Generate SSH keypair for target servers |
| `install_auth_key.sh` | Auth server | Install public key with ForceCommand |
| `show_target_config.sh` | Auth server | Print per-target deployment instructions |

### Operational scripts

| Script | Purpose |
|---|---|
| `status.sh` | Show installed files and permissions; `--delete` to remove everything |
| `get_code.sh` | Print current TOTP code (auto-detects secret file) |
| `show_totp_qr.sh` | Re-display QR code for re-enrollment |
| `show_syslog.sh` | Show seclogin syslog entries (passes args to journalctl) |
| `show_syslog.sh -f` | Follow seclogin log live |

### Testing

| File | Purpose |
|---|---|
| `testing/test_seclogin.sh` | End-to-end test suite — runs inside Alpine container |

### Snippets

| File | Purpose |
|---|---|
| `notes_bashrc_snippet` | `.bashrc` snippet showing Domino server name in prompt |
