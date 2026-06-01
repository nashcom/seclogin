# Changelog

## [1.1.1] - 2026-06-02

### Fixed
- Gate mode recovery code verification now works correctly
  - Recovery files moved to `/etc/seclogin/recovery/` (`root:seclogin 770`) so
    gate mode (`euid=seclogin`) can atomically rewrite `recovery.conf` via `rename()`
  - `recovery.conf` and `recovery.lock` changed to `root:seclogin 660`
  - `check_file_safety` accepts files owned by root or current euid (seclogin)
  - `check_file_safety` allows group-writable files (world-write still rejected)
- Debug log (`/var/log/seclogin-debug.log`) changed to `root:seclogin 660`
  so gate mode can write debug entries
- Debug log open failure now logs a clear actionable message when file is missing

---

## [1.1.0] - 2026-06-01

### Added
- Recovery code module (`scratchcodes.c` / `scratchcodes.h`)
  - Single-use emergency codes replacing TOTP when authenticator is unavailable
  - SSH key authentication still required - recovery codes replace TOTP only
  - PBKDF2-HMAC-SHA512 (250,000 iterations, 16-byte random salt, 64-byte hash)
  - Format: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (120-bit entropy, unambiguous alphabet)
  - Atomic file rewrite with `fsync` + `rename` + parent dir `fsync`
  - Advisory `flock` around read/verify/rewrite - race-free single-use enforcement
  - File safety check: rejects symlinks, non-root ownership, group/other-writable
  - Parameters stored per entry (`pbkdf2_sha512:iter:salt:hash`) for forward compatibility
  - Return codes: `RECOVERY_OK` / `RECOVERY_DENIED` / `RECOVERY_ERROR`
  - Dedicated subdirectory `/etc/seclogin/recovery/` (`root:seclogin 770`) -
    group-writable so gate mode (euid=seclogin) can atomically rewrite recovery.conf;
    parent `/etc/seclogin/` stays 750
- `seclogin-recovery` admin binary (`root:root 0700`)
  - `generate` - generate 5 codes, print plaintext once, store hashed
  - `list`     - show remaining code count
  - `verify`   - verify and consume one code
  - `test`     - self-test suite (code format, hash/verify, file safety, round-trip)
- Recovery code auth path in `authenticate_totp()`
  - Input length 29 routes to recovery path; length 6 routes to existing TOTP path
  - Success logged at `LOG_CRIT` with `method=recovery-code` and `remaining=N`
  - Failure logged at `LOG_WARNING` with same delay as TOTP mismatch
  - Works in both local TOTP and remote HMAC verification mode by design
- Scripts moved to `scripts/` subdirectory
- `scripts/config` - shared configuration for all shell scripts

### Security
- Recovery code verification isolated in non-SUID binary (`seclogin-recovery`)
- SUID binary (`seclogin`) contains only `recovery_verify` and its dependencies -
  admin functions (`recovery_generate`, `recovery_list`) are dead-code eliminated
- Test added to assert admin symbols are absent from the SUID binary
- Test added to verify `recovery.conf` has correct owner and permissions

---

## [1.0.0] - 2026-05-31

### Added
- SUID root shell with TOTP second-factor authentication (SHA256/SHA1, RFC 6238)
- Gate mode (`seclogin-gate`) - TOTP gate for login shells, drops SUID after auth
- Remote HMAC verification mode (`--verify`) via SSH ForceCommand
  - TOTP secret stays on auth server only - compromised target exposes nothing
  - Nonce: 4-byte timestamp + 12-byte random, 10-second expiry, no clock skew
- IP access control (`allow=` / `deny=` CIDR, IPv4/IPv6)
- Optional reason logging (`reason=0/1/2`)
- Domino banner (reads `notes.ini` for server name)
- Static Alpine build (~4.7 MB), LD_PRELOAD immune
- Full test suite (11 tests, local + remote verify + IP ACL)
- Setup scripts: `create_accounts.sh`, `setup_auth_server.sh`, `create_totp.sh`,
  `status.sh`, `get_code.sh`, `trust_auth_server.sh`

### Security
- `prctl(PR_SET_DUMPABLE, 0)` - no core dumps containing secrets
- `setgroups(0, NULL)` before privilege operations
- SSH child drops to real UID before `execve` - prevents caller-controlled `~/.ssh/config`
- Secret file rejected if group-readable in root mode
- `O_NOFOLLOW` + `S_ISREG` on `notes.ini` path - symlink/FIFO hardening
- `valid_reason()` rejects `"` and `\` - syslog field injection prevention
- `CRYPTO_memcmp()` for constant-time comparisons
- Full RELRO + PIE + dead code elimination
