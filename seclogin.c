/*
    Hardened minimal SUID root shell launcher

    PURPOSE:
        Interactive second-factor authentication for trusted sysadmin users.
        The user must already be authenticated via SSH key + password before
        invoking this binary. It is NOT intended for scripting, automation,
        or non-interactive use — a real TTY is required by design.

    Build:
        gcc -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 seclogin.c -o seclogin

    Install:
        sudo chown root:sysadmin seclogin
        sudo chmod 4750 seclogin

    Notes:
        - Intended only for trusted sysadmin accounts on interactive SSH sessions
        - TOTP-SHA256 authentication via OpenSSL (RFC 6238, Google Authenticator compatible)
        - Environment is sanitized before execve via explicit env array
        - Requires interactive TTY — stdin/stdout must be a real terminal, not a pipe
        - SSH_CONNECTION/SSH_TTY are checked as defense-in-depth (forgeable by caller)
        - Supplementary groups are dropped via setgroups(0, NULL) before setgid/setuid
        - FDs closed via /proc/self/fd enumeration (avoids O(_SC_OPEN_MAX) loop)
        - Authentication attempts logged to syslog(LOG_AUTH)
        - Remote HMAC verification mode via --verify (ForceCommand on auth server)
*/


#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

#include <stdint.h>
#include <syslog.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <stdarg.h>

#include <arpa/inet.h>
#include <sys/file.h>

#include "scratchcodes.h"
#include <netinet/in.h>


/* version — set at build time via -DSECLOGIN_VERSION="x.y.z"
 * falls back to "dev" for local builds without a tag           */
#ifndef SECLOGIN_VERSION
#define SECLOGIN_VERSION    "dev"
#endif

#define SAFE_PATH           "/usr/sbin:/usr/bin:/sbin:/bin"
#define SECLOGIN_DIR        "/etc/seclogin"
#define ROOTSHELL_CONFIG    "/etc/seclogin/seclogin.conf"
#define ROOTSHELL_SECRET    "/etc/seclogin/totp.secret"
#define VERIFY_SECRET       "/etc/seclogin/totp_verify.secret"
#define SECLOGIN_KNOWN_HOSTS "/etc/seclogin/known_hosts"
#define SECLOGIN_AUTH_KEY   "/etc/seclogin/seclogin_ed25519"
#define AUTH_USER_DEFAULT   "seclogin"
#define ACL_MAX             32    /* max allow= / deny= entries in config */
#define ACL_ENTRY_MAX       64    /* max length of a single CIDR entry    */
#define TOTP_STEP           30
#define TOTP_DIGITS         6
#define TOTP_WINDOW         1
#define NOTES_INI_DEFAULT   "/local/notesdata/notes.ini"
#define NOTES_INI_MAX_LINE  256
#define REASON_MAX          200   /* max reason string length */

/* nonce: 16 bytes = 4-byte big-endian unix timestamp + 12-byte random
 * auth server embeds timestamp on generation and validates age on receipt —
 * zero clock skew since both happen on the same machine.
 * NONCE_MAX_AGE limits replay window independently of the 30s TOTP interval. */

#define NONCE_BYTES        16
#define NONCE_HEX          (NONCE_BYTES * 2 + 1)   /* 33 */
#define NONCE_TS_BYTES      4                        /* first 4 bytes = big-endian unix timestamp */
#define NONCE_RAND_BYTES   (NONCE_BYTES - NONCE_TS_BYTES)   /* 12 bytes random */
#define NONCE_MAX_AGE      10                        /* max nonce age in seconds */
#define AUTH_FAIL_DELAY    5                        /* seconds to sleep before fail response */
#define HMAC256_BYTES      32
#define HMAC256_HEX        (HMAC256_BYTES * 2 + 1) /* 65 */

#define DEBUG_LOG_FILE     "/var/log/seclogin-debug.log"


/* --------------------------------------------------------------------------
 * Debug logging
 * Enabled by debug=1 in /etc/seclogin.conf.
 * All entries written to DEBUG_LOG_FILE with PID prefix.
 * Never log secrets, TOTP codes, or HMAC values.
 * -------------------------------------------------------------------------- */

static int g_fDebug = 0;

/* config cache — loaded once by main() before any mode dispatch;
 * all read_config_value() / read_config_all() calls use this buffer directly.
 * statically allocated: no malloc(), no heap, zero-initialised (BSS)         */
#define CONFIG_BUF_MAX  8192

static char g_szLine[] = "------------------------------------------";
static char g_szConfigBuf[CONFIG_BUF_MAX] = {0};
static int  g_nConfigLoaded               = 0;    /* 0=not loaded, 1=loaded */

static void debug_log(const char *pszFmt, ...)
{
    FILE        *pFile      = NULL;
    struct stat  st         = {0};
    time_t       tNow       = 0;
    struct tm    tmNow      = {0};
    char         szTime[32] = {0};
    int          fdLog      = -1;
    va_list      ap;

    if (!g_fDebug)
        return;

    /* O_NOFOLLOW: reject symlinks; O_CREAT with 0660: root:seclogin rw-rw---- */
    fdLog = open(DEBUG_LOG_FILE, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0660);
    if (fdLog < 0)
    {
        if (errno == ENOENT || errno == EACCES)
            syslog(LOG_AUTH | LOG_WARNING,
                   "seclogin: debug log %s not available"
                   " — run seclogin once as root to create it",
                   DEBUG_LOG_FILE);
        else
            syslog(LOG_AUTH | LOG_ERR,
                   "seclogin: debug_log: cannot open %s: %m", DEBUG_LOG_FILE);
        return;
    }

    /* Set root:seclogin ownership when running as root so gate mode can write */
    if (geteuid() == 0)
    {
        struct group *pGrp = getgrnam("seclogin");
        if (fchown(fdLog, 0, pGrp ? pGrp->gr_gid : 0) != 0)
            syslog(LOG_AUTH | LOG_WARNING, "seclogin: debug_log: fchown failed: %m");
        if (fchmod(fdLog, 0660) != 0)
            syslog(LOG_AUTH | LOG_WARNING, "seclogin: debug_log: fchmod failed: %m");
    }

    /* validate the opened file: must be a regular root-owned file,
     * world-write rejected; group-write allowed (seclogin group is trusted) */
    if (fstat(fdLog, &st) != 0          ||
        !S_ISREG(st.st_mode)            ||
        st.st_uid != 0                  ||
        (st.st_mode & S_IWOTH))
    {
        syslog(LOG_AUTH | LOG_ERR,
               "seclogin: debug_log: %s failed safety check (uid=%d mode=%o)",
               DEBUG_LOG_FILE, (int) st.st_uid, (unsigned) st.st_mode);
        close(fdLog);
        return;
    }

    pFile = fdopen(fdLog, "a");
    if (!pFile)
    {
        syslog(LOG_AUTH | LOG_ERR, "seclogin: debug_log: fdopen failed: %m");
        close(fdLog);
        return;
    }

    /* unbuffered: each write goes directly to the kernel —
     * logs survive a crash inside vfprintf before fclose */
    setvbuf(pFile, NULL, _IONBF, 0);

    tNow = time(NULL);
    gmtime_r(&tNow, &tmNow);
    strftime(szTime, sizeof(szTime), "%Y-%m-%dT%H:%M:%SZ", &tmNow);

    fprintf(pFile, "[%d] %s ", (int) getpid(), szTime);

    va_start(ap, pszFmt);
    vfprintf(pFile, pszFmt, ap);
    va_end(ap);

    fputc('\n', pFile);
    fclose(pFile);
}


static void debug_ids(int ConsoleOnly)
{
    uid_t nRuid = 0, nEuid = 0, nSuid = 0;
    gid_t nRgid = 0, nEgid = 0, nSgid = 0;

    if (!g_fDebug && !ConsoleOnly)
        return;

    getresuid(&nRuid, &nEuid, &nSuid);
    getresgid(&nRgid, &nEgid, &nSgid);

    fprintf(stderr, "\n  [debug] ruid=%d euid=%d suid=%d  rgid=%d egid=%d sgid=%d\n",
            (int) nRuid, (int) nEuid, (int) nSuid,
            (int) nRgid, (int) nEgid, (int) nSgid);

    if (ConsoleOnly)
        return;

    debug_log("ruid=%d euid=%d suid=%d  rgid=%d egid=%d sgid=%d",
              (int) nRuid, (int) nEuid, (int) nSuid,
              (int) nRgid, (int) nEgid, (int) nSgid);
}

static void clear_screen(void)
{
    /* skip in debug mode — preserves terminal output for inspection */
    if (g_fDebug)
        return;

    /* clear screen, home cursor, reset all terminal attributes */
    fprintf(stderr, "\033[2J\033[H\033[0m");
}


static void print_top_banner(void)
{
    fprintf(stderr,
        "\n"
        "  SECLogin " SECLOGIN_VERSION " - Secure Enforced Login\n"
        "  %s\n", g_szLine);
}


static void err_msg(const char *pszFmt, ...)
{
    va_list ap;
    va_start(ap, pszFmt);
    vfprintf(stderr, pszFmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}


static int validate_binary(void)
{
    struct stat st = {0};

    if (stat("/proc/self/exe", &st) != 0)
    {
        perror("stat");
        return -1;
    }

    if (!S_ISREG(st.st_mode))
    {
        err_msg("Executable is not a regular file");
        return -1;
    }

    /* in root shell mode  euid=0        → binary must be owned by root
     * in gate mode        euid=seclogin → binary must be owned by seclogin
     * in both cases the SUID owner must match the current effective user     */
    if (st.st_uid != geteuid())
    {
        err_msg("Executable owner does not match effective user (uid=%d, euid=%d)",
                (int) st.st_uid, (int) geteuid());
        return -1;
    }

    if (!(st.st_mode & S_ISUID))
    {
        err_msg("SUID bit missing");
        return -1;
    }

    if (st.st_mode & S_IWOTH)
    {
        err_msg("Executable is world writable");
        return -1;
    }

    if (st.st_mode & S_IWGRP)
    {
        err_msg("Executable is group writable");
        return -1;
    }

    return 0;
}


static int valid_term(const char *pszTerm)
{
    const unsigned char *p = NULL;

    if (!pszTerm || !*pszTerm)
        return 0;

    if (strlen(pszTerm) > 64)
        return 0;

    for (p = (const unsigned char *) pszTerm; *p; p++)
    {
        if (!(isalnum(*p) || *p == '-' || *p == '_'))
            return 0;
    }

    return 1;
}


/* hex strings: validates exact length and character set */
static int valid_hex_str(const char *pszHex, size_t cbExpected)
{
    size_t i = 0;

    if (!pszHex)
        return 0;

    if (strlen(pszHex) != cbExpected)
        return 0;

    for (i = 0; i < cbExpected; i++)
    {
        if (!isxdigit((unsigned char) pszHex[i]))
            return 0;
    }

    return 1;
}


/* locale identifiers: ll_CC.charset[@modifier] — allow alnum, _ . - @ */
static int valid_lang(const char *pszLang)
{
    const unsigned char *p = NULL;

    if (!pszLang || !*pszLang)
        return 0;

    if (strlen(pszLang) > 64)
        return 0;

    for (p = (const unsigned char *) pszLang; *p; p++)
    {
        if (!(isalnum(*p) || *p == '_' || *p == '.' || *p == '-' || *p == '@'))
            return 0;
    }

    return 1;
}


/* reason string: printable ASCII only, no newlines, max REASON_MAX chars */
static int valid_reason(const char *pszReason)
{
    const unsigned char *p = NULL;

    if (!pszReason)
        return 0;

    if (strlen(pszReason) > REASON_MAX)
        return 0;

    for (p = (const unsigned char *) pszReason; *p; p++)
    {
        if (*p < 0x20 || *p > 0x7e)   /* printable ASCII only */
            return 0;

        /* reject characters that would break the quoted syslog field
         * reason="..." — prevents audit-log field injection by the caller */
        if (*p == '"' || *p == '\\')
            return 0;
    }

    return 1;
}


static void sanitize_environment(void)
{
    const char *pszTerm = NULL;
    const char *pszLang = NULL;

    pszTerm = getenv("TERM");
    pszLang = getenv("LANG");

    clearenv();

    setenv("PATH", SAFE_PATH, 1);

    if (valid_term(pszTerm))
        setenv("TERM", pszTerm, 1);
    else
        setenv("TERM", "dumb", 1);

    if (valid_lang(pszLang))
        setenv("LANG", pszLang, 1);
    else
        setenv("LANG", "C", 1);
}


static void close_fds(void)
{
    DIR           *d      = NULL;
    struct dirent *ent    = NULL;
    int            fdDir  = -1;
    int            fd     = -1;
    long           nMaxFd = 0;

    d = opendir("/proc/self/fd");

    if (d)
    {
        fdDir = dirfd(d);

        while ((ent = readdir(d)) != NULL)
        {
            char *pszEnd = NULL;
            long  nVal   = 0;

            nVal = strtol(ent->d_name, &pszEnd, 10);

            if (*pszEnd != '\0')
                continue;

            fd = (int) nVal;

            if (fd > 2 && fd != fdDir)
                close(fd);
        }

        closedir(d);
    }
    else
    {
        /* fallback if /proc is unavailable */
        nMaxFd = sysconf(_SC_OPEN_MAX);

        if (nMaxFd < 0)
            nMaxFd = 1024;

        for (fd = 3; fd < nMaxFd; fd++)
            close(fd);
    }
}


static int validate_session(void)
{
    struct stat st = {0};

    /* SUID must be active — euid must differ from ruid
     * root mode: euid=0, ruid=sysadmin
     * gate mode: euid=seclogin, ruid=invoking user                */
    if (geteuid() == getuid())
    {
        err_msg("SUID not active — check binary ownership and permissions");
        return -1;
    }

    if (getuid() == 0)
    {
        err_msg("Direct root execution not allowed");
        return -1;
    }

    if (!isatty(STDIN_FILENO))
    {
        err_msg("Interactive TTY required");
        return -1;
    }

    if (!isatty(STDOUT_FILENO))
    {
        err_msg("Interactive TTY required");
        return -1;
    }

    /* SSH_CONNECTION and SSH_TTY are caller-supplied env vars and can be forged
       by any member of the sysadmin group running the binary locally.
       These checks are defense-in-depth only; real protection is the TOTP step. */
    if (!getenv("SSH_CONNECTION"))
    {
        err_msg("SSH session required");
        return -1;
    }

    if (!getenv("SSH_TTY"))
    {
        err_msg("SSH TTY required");
        return -1;
    }

    if (fstat(STDIN_FILENO, &st) != 0)
    {
        perror("fstat");
        return -1;
    }

    if (!S_ISCHR(st.st_mode))
    {
        err_msg("Invalid terminal device");
        return -1;
    }

    return 0;
}


/* opens and security-checks ROOTSHELL_CONFIG; returns fd or -1 */
static int open_config(void)
{
    struct stat  st = {0};
    int          fd = -1;

    fd = open(ROOTSHELL_CONFIG, O_RDONLY | O_NOFOLLOW);

    if (fd < 0)
    {
        err_msg("Cannot open config file: %s", ROOTSHELL_CONFIG);
        debug_ids(1);
        return -1;
    }

    if (fstat(fd, &st) != 0)
    {
        close(fd);
        err_msg("Cannot stat config file");
        debug_ids(1);
        return -1;
    }

    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        err_msg("Config file is not a regular file");
        return -1;
    }

    if (st.st_uid != 0)
    {
        close(fd);
        err_msg("Config file not owned by root (uid=%d)", (int) st.st_uid);
        return -1;
    }

    /* no world access; group-read (0640) is fine — config contains no secrets */
    if (st.st_mode & (S_IROTH | S_IWOTH | S_IXOTH))
    {
        close(fd);
        err_msg("Config file must not be world-accessible (found %04o)",
                (unsigned int)(st.st_mode & 0777));
        return -1;
    }

    if (st.st_mode & (S_IWGRP | S_IXGRP))
    {
        close(fd);
        err_msg("Config file must not be group-writable (found %04o)",
                (unsigned int)(st.st_mode & 0777));
        return -1;
    }

    return fd;
}


/* load config into memory — called once by main() before mode dispatch */
static int load_config(void)
{
    FILE  *f  = NULL;
    int    fd = -1;
    size_t n  = 0;

    fd = open_config();
    if (fd < 0)
        return -1;

    f = fdopen(fd, "r");
    if (!f)
    {
        close(fd);
        return -1;
    }

    memset(g_szConfigBuf, 0, sizeof(g_szConfigBuf));
    n = fread(g_szConfigBuf, 1, CONFIG_BUF_MAX - 1, f);
    g_szConfigBuf[n] = '\0';
    fclose(f);

    g_nConfigLoaded = 1;
    debug_log("config: loaded %zu bytes", n);
    return 0;
}

/* advance *pp to the next line in the config buffer, copying it into pszLine;
 * strips trailing \r — returns 0 while lines remain, -1 at end of buffer    */
static int next_config_line(const char **pp, char *pszLine, size_t cbLine)
{
    const char *p   = *pp;
    const char *end = NULL;
    size_t      n   = 0;

    if (!p || !*p) return -1;

    end = strchr(p, '\n');
    n   = end ? (size_t)(end - p) : strlen(p);
    if (n >= cbLine) n = cbLine - 1;

    memcpy(pszLine, p, n);
    while (n > 0 && pszLine[n-1] == '\r') n--;
    pszLine[n] = '\0';

    *pp = end ? end + 1 : p + strlen(p);
    return 0;
}

/* opens the TOTP secret file with context-appropriate permission checks:
   - SUID mode (euid=0):   requires root:root 0600 — secret unreadable by anyone else
   - verify mode (euid!=0): allows root:group 0640 — sysadmin needs to read it     */

/* reads a key=value from config into pszBuf; returns length or -1 */
static int read_config_value(const char *pszKey, char *pszBuf, size_t cbBuf)
{
    const char *p    = g_szConfigBuf;
    char        szLine[256];
    size_t      cbKey = strlen(pszKey);

    if (!g_nConfigLoaded)
        return -1;

    p = g_szConfigBuf;
    while (next_config_line(&p, szLine, sizeof(szLine)) == 0)
    {
        if (szLine[0] == '#' || szLine[0] == '\0')
            continue;

        if (strncasecmp(szLine, pszKey, cbKey) == 0 && szLine[cbKey] == '=')
        {
            char  *pszVal = szLine + cbKey + 1;
            size_t cbLen  = strlen(pszVal);

            while (cbLen > 0 && (pszVal[cbLen-1] == ' '))
                pszVal[--cbLen] = '\0';

            snprintf(pszBuf, cbBuf, "%s", pszVal);
            return (int) strlen(pszBuf);
        }
    }

    return -1;
}


/* reads ALL values for pszKey from config into ppszOut[0..nMax-1]
 * returns count of entries found (0 = no rules = allow all)       */
static int read_config_all(const char *pszKey,
                           char        ppszOut[][ACL_ENTRY_MAX],
                           int         nMax)
{
    const char *p    = g_szConfigBuf;
    char        szLine[256];
    size_t      cbKey = strlen(pszKey);
    int         nFound = 0;

    if (!g_nConfigLoaded)
        return 0;

    p = g_szConfigBuf;
    while (next_config_line(&p, szLine, sizeof(szLine)) == 0 && nFound < nMax)
    {
        if (szLine[0] == '#' || szLine[0] == '\0')
            continue;

        if (strncasecmp(szLine, pszKey, cbKey) == 0 && szLine[cbKey] == '=')
        {
            char  *pszVal = szLine + cbKey + 1;
            size_t cbLen  = strlen(pszVal);

            while (cbLen > 0 && pszVal[cbLen-1] == ' ')
                pszVal[--cbLen] = '\0';

            if (cbLen > 0 && cbLen < ACL_ENTRY_MAX)
            {
                snprintf(ppszOut[nFound], ACL_ENTRY_MAX, "%s", pszVal);
                nFound++;
            }
        }
    }

    return nFound;
}


/* pszConfigKey  — config key to look up (e.g. "secret_file" or "verify_secret_file")
 * pszDefault    — path used when the config key is absent                            */
static int open_secret(const char *pszConfigKey, const char *pszDefault)
{
    struct stat  st                 = {0};
    int          fd                 = -1;
    mode_t       modePerms          = 0;
    char         szSecretFile[256]  = {0};

    if (read_config_value(pszConfigKey, szSecretFile, sizeof(szSecretFile)) <= 0)
        snprintf(szSecretFile, sizeof(szSecretFile), "%s", pszDefault);

    fd = open(szSecretFile, O_RDONLY | O_NOFOLLOW);

    if (fd < 0)
    {
        err_msg("Cannot open secret file: %s", szSecretFile);
        return -1;
    }

    if (fstat(fd, &st) != 0)
    {
        close(fd);
        err_msg("Cannot stat secret file");
        return -1;
    }

    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        err_msg("Secret file is not a regular file");
        return -1;
    }

    if (st.st_uid != 0)
    {
        close(fd);
        err_msg("Secret file not owned by root (uid=%d)", (int) st.st_uid);
        return -1;
    }

    modePerms = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);

    /* no world access, no group write — applies to all modes
     * 0600 (root-only) and 0640 (group-readable) are both valid:
     *   totp.secret:        root:seclogin 0640 — readable by root mode (euid=0) and gate mode (egid=seclogin)
     *   totp_verify.secret: root:seclogin 0640 — readable by verify mode (euid=seclogin) on auth server */
    if (st.st_mode & (S_IROTH | S_IWOTH | S_IXOTH))
    {
        close(fd);
        err_msg("Secret file must not be world-accessible (found %04o)",
                (unsigned int) modePerms);
        return -1;
    }

    if (st.st_mode & (S_IWGRP | S_IXGRP))
    {
        close(fd);
        err_msg("Secret file must not be group-writable (found %04o)",
                (unsigned int) modePerms);
        return -1;
    }

    /* root-shell mode (euid=0): the secret must be readable by root ONLY.
     * A group-readable secret could be read directly by seclogin-group members,
     * who could then compute valid codes and bypass the TOTP second factor.
     * Gate and verify modes run with euid!=0 and legitimately need group read
     * (0640), so this stricter check applies to root-shell mode only. */
    if (geteuid() == 0 && (st.st_mode & S_IRGRP))
    {
        close(fd);
        err_msg("Secret file must be owner-readable only in root mode (found %04o)",
                (unsigned int) modePerms);
        return -1;
    }

    return fd;
}


/* reads the TOTP secret from a file into pszBuf; returns length or -1 */
static int read_secret_from(const char *pszConfigKey, const char *pszDefault,
                            char *pszBuf, size_t cbBuf)
{
    FILE   *f     = NULL;
    int     fd    = -1;
    size_t  cbLen = 0;

    fd = open_secret(pszConfigKey, pszDefault);

    if (fd < 0)
        return -1;

    f = fdopen(fd, "r");

    if (!f)
    {
        close(fd);
        err_msg("Cannot read secret file");
        return -1;
    }

    if (!fgets(pszBuf, (int) cbBuf, f))
    {
        fclose(f);
        err_msg("Secret file is empty");
        return -1;
    }

    fclose(f);

    cbLen = strlen(pszBuf);
    while (cbLen > 0 && (pszBuf[cbLen-1] == '\n' || pszBuf[cbLen-1] == '\r' || pszBuf[cbLen-1] == ' '))
        pszBuf[--cbLen] = '\0';

    if (cbLen == 0)
    {
        err_msg("Secret file is empty");
        return -1;
    }

    return (int) cbLen;
}


/* local SUID mode: uses secret_file= / /etc/seclogin.secret (root:root 0600) */
static int read_secret(char *pszBuf, size_t cbBuf)
{
    return read_secret_from("secret_file", ROOTSHELL_SECRET, pszBuf, cbBuf);
}


/* --verify mode: uses verify_secret_file= / /etc/seclogin/totp_verify.secret (root:seclogin 0640) */
static int read_verify_secret(char *pszBuf, size_t cbBuf)
{
    return read_secret_from("verify_secret_file", VERIFY_SECRET, pszBuf, cbBuf);
}


static int get_notes_ini_value(const char *pszKey, char *pszBuf, size_t cbBuf)
{
    FILE  *f                        = NULL;
    char   szLine[NOTES_INI_MAX_LINE]    = {0};
    char   szNotesIni[NOTES_INI_MAX_LINE] = {0};
    size_t cbKey                    = 0;

    /* path is configurable via seclogin.conf notes_ini= key */
    if (read_config_value("notes_ini", szNotesIni, sizeof(szNotesIni)) <= 0)
        snprintf(szNotesIni, sizeof(szNotesIni), "%s", NOTES_INI_DEFAULT);

    /* notes.ini lives in the Domino data dir, owned by the unprivileged notes
     * user — in root-shell mode this is opened while euid=0. Harden the open:
     *   O_NOFOLLOW  — refuse a symlink swapped in for notes.ini (no redirect to
     *                 root-only files such as /etc/shadow)
     *   O_NONBLOCK  — never block if notes.ini is replaced by a FIFO (DoS)
     *   S_ISREG     — reject FIFOs, devices and other non-regular files */
    {
        int         fd = -1;
        struct stat st = {0};

        fd = open(szNotesIni, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        if (fd < 0)
            return 0;

        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
        {
            close(fd);
            return 0;
        }

        f = fdopen(fd, "r");
        if (!f)
        {
            close(fd);
            return 0;
        }
    }

    cbKey = strlen(pszKey);

    while (fgets(szLine, sizeof(szLine), f))
    {
        if (strncasecmp(szLine, pszKey, cbKey) == 0 && szLine[cbKey] == '=')
        {
            char  *pszVal = szLine + cbKey + 1;
            size_t cbLen  = strlen(pszVal);

            while (cbLen > 0 && (pszVal[cbLen-1] == '\n' || pszVal[cbLen-1] == '\r'))
                pszVal[--cbLen] = '\0';

            snprintf(pszBuf, cbBuf, "%s", pszVal);
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}


/* converts "CN=earth/O=NotesLab" to abbreviated "earth/NotesLab" */
static const char *abbrev_notes_name(const char *pszCanonical, char *pszBuf, size_t cbBuf)
{
    const char *pszSrc;
    char       *pszDst;
    char       *pszEnd;

    if (!strchr(pszCanonical, '='))
        return pszCanonical;

    pszSrc = pszCanonical;
    pszDst = pszBuf;
    pszEnd = pszBuf + cbBuf - 1;

    while (*pszSrc && pszDst < pszEnd)
    {
        /* skip up to and including the '=' of each component */
        const char *pszEq = strchr(pszSrc, '=');

        if (!pszEq)
            break;

        pszSrc = pszEq + 1;

        /* copy value until next '/' or end */
        while (*pszSrc && *pszSrc != '/' && pszDst < pszEnd)
            *pszDst++ = *pszSrc++;

        if (*pszSrc == '/')
        {
            if (pszDst < pszEnd)
                *pszDst++ = '/';
            pszSrc++;
        }
    }

    *pszDst = '\0';

    return pszBuf;
}


static int base32_decode(const char *pszSrc, unsigned char *pbDst, size_t cbDst)
{
    size_t       cbSrc = strlen(pszSrc);
    size_t       i     = 0;
    unsigned int nBuf  = 0;
    int          nBits = 0;
    size_t       cbOut = 0;

    for (i = 0; i < cbSrc; i++)
    {
        char ch  = pszSrc[i];
        int  nVal = 0;

        if (ch == '=' || ch == ' ' || ch == '\t')
            continue;

        if (ch >= 'A' && ch <= 'Z')      nVal = ch - 'A';
        else if (ch >= 'a' && ch <= 'z') nVal = ch - 'a';
        else if (ch >= '2' && ch <= '7') nVal = ch - '2' + 26;
        else return -1;

        nBuf   = (nBuf << 5) | (unsigned int) nVal;
        nBits += 5;

        if (nBits >= 8)
        {
            if (cbOut >= cbDst)
                return -1;

            pbDst[cbOut++] = (unsigned char) (nBuf >> (nBits - 8));
            nBits -= 8;
        }
    }

    return (int) cbOut;
}


static void hex_encode(const unsigned char *pbSrc, size_t cbSrc,
                       char *pszDst, size_t cbDst)
{
    static const char szHex[] = "0123456789abcdef";
    size_t i = 0;

    for (i = 0; i < cbSrc && (i * 2 + 2) < cbDst; i++)
    {
        pszDst[i * 2]     = szHex[pbSrc[i] >> 4];
        pszDst[i * 2 + 1] = szHex[pbSrc[i] & 0x0f];
    }
    pszDst[i * 2] = '\0';
}


static int hex_decode(const char *pszSrc, unsigned char *pbDst, size_t cbDst)
{
    size_t cbSrc = strlen(pszSrc);
    size_t i     = 0;

    if (cbSrc % 2 != 0)    return -1;
    if (cbSrc / 2 > cbDst) return -1;

    for (i = 0; i < cbSrc; i += 2)
    {
        unsigned int nHi = 0, nLo = 0;
        char         chHi = pszSrc[i];
        char         chLo = pszSrc[i + 1];

        if      (chHi >= '0' && chHi <= '9') nHi = (unsigned int)(chHi - '0');
        else if (chHi >= 'a' && chHi <= 'f') nHi = (unsigned int)(chHi - 'a' + 10);
        else if (chHi >= 'A' && chHi <= 'F') nHi = (unsigned int)(chHi - 'A' + 10);
        else return -1;

        if      (chLo >= '0' && chLo <= '9') nLo = (unsigned int)(chLo - '0');
        else if (chLo >= 'a' && chLo <= 'f') nLo = (unsigned int)(chLo - 'a' + 10);
        else if (chLo >= 'A' && chLo <= 'F') nLo = (unsigned int)(chLo - 'A' + 10);
        else return -1;

        pbDst[i / 2] = (unsigned char)((nHi << 4) | nLo);
    }

    return (int)(cbSrc / 2);
}


static int generate_nonce(char *pszHex, size_t cbHex)
{
    unsigned char abNonce[NONCE_BYTES] = {0};
    uint32_t      uTs                  = 0;
    int           fd                   = -1;
    ssize_t       cbRead               = 0;

    if (cbHex < NONCE_HEX)
        return -1;

    /* first 4 bytes: big-endian unix timestamp — allows age check without clock skew */
    uTs = (uint32_t) time(NULL);
    abNonce[0] = (uTs >> 24) & 0xFF;
    abNonce[1] = (uTs >> 16) & 0xFF;
    abNonce[2] = (uTs >>  8) & 0xFF;
    abNonce[3] =  uTs        & 0xFF;

    /* remaining 12 bytes: random — loop to handle EINTR and short reads */
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    {
        size_t  cbFill = NONCE_RAND_BYTES;
        unsigned char *pbFill = abNonce + NONCE_TS_BYTES;

        while (cbFill > 0)
        {
            cbRead = read(fd, pbFill, cbFill);

            if (cbRead < 0)
            {
                if (errno == EINTR)
                    continue;
                close(fd);
                return -1;
            }

            if (cbRead == 0)
            {
                close(fd);
                return -1;
            }

            pbFill += cbRead;
            cbFill -= (size_t) cbRead;
        }
    }

    close(fd);

    hex_encode(abNonce, sizeof(abNonce), pszHex, cbHex);
    explicit_bzero(abNonce, sizeof(abNonce));
    return 0;
}


/* HMAC-SHA256(key=nonce_bytes, data=code_string) → hex string */
static int compute_verify_hmac(const char *pszNonceHex, const char *pszCode,
                               char *pszHmacHex, size_t cbHmacHex)
{
    unsigned char abNonce[NONCE_BYTES]  = {0};
    unsigned char abHmac[HMAC256_BYTES] = {0};
    unsigned int  cbHmac = sizeof(abHmac);

    if (cbHmacHex < HMAC256_HEX)
        return -1;

    if (hex_decode(pszNonceHex, abNonce, sizeof(abNonce)) != NONCE_BYTES)
        return -1;

    if (!HMAC(EVP_sha256(), abNonce, sizeof(abNonce),
              (const unsigned char *) pszCode, strlen(pszCode),
              abHmac, &cbHmac))
    {
        explicit_bzero(abNonce, sizeof(abNonce));
        return -1;
    }

    explicit_bzero(abNonce, sizeof(abNonce));
    hex_encode(abHmac, cbHmac, pszHmacHex, cbHmacHex);
    explicit_bzero(abHmac, sizeof(abHmac));
    return 0;
}


/* generates TOTP code string for a given time step into szCode */
static int totp_generate(const unsigned char *pbSecret, size_t cbSecret,
                         const EVP_MD *pMd,
                         time_t now, int nStepOffset,
                         char *pszCode, size_t cbCode)
{
    uint64_t      T                 = 0;
    unsigned char abMsg[8]          = {0};
    unsigned char abDigest[32]      = {0};
    unsigned int  cbDigest          = sizeof(abDigest);
    unsigned int  nOffset           = 0;
    unsigned long ulOtp             = 0;
    int           i                 = 0;

    if (cbCode < TOTP_DIGITS + 1)
        return -1;

    T = (uint64_t)(now / TOTP_STEP) + (int64_t) nStepOffset;

    for (i = 7; i >= 0; i--)
    {
        abMsg[i] = T & 0xff;
        T >>= 8;
    }

    if (!HMAC(pMd, pbSecret, (int) cbSecret,
              abMsg, sizeof(abMsg), abDigest, &cbDigest))
        return -1;

    nOffset = abDigest[cbDigest - 1] & 0x0f;

    ulOtp = ((unsigned long)(abDigest[nOffset]     & 0x7f) << 24)
          | ((unsigned long)(abDigest[nOffset + 1] & 0xff) << 16)
          | ((unsigned long)(abDigest[nOffset + 2] & 0xff) <<  8)
          |  (unsigned long)(abDigest[nOffset + 3] & 0xff);

    ulOtp %= 1000000UL;

    snprintf(pszCode, cbCode, "%06lu", ulOtp);
    return 0;
}


/* returns 0 if pszCode matches the TOTP value for the given time step offset */
static int totp_validate(const unsigned char *pbSecret, size_t cbSecret,
                         const EVP_MD *pMd,
                         time_t now, int nStepOffset, const char *pszCode)
{
    char szExpected[TOTP_DIGITS + 1] = {0};

    if (totp_generate(pbSecret, cbSecret, pMd, now, nStepOffset,
                      szExpected, sizeof(szExpected)) != 0)
        return -1;

    return CRYPTO_memcmp(szExpected, pszCode, TOTP_DIGITS);
}


/* ---------------------------------------------------------------------------
 * IP access control — allow= / deny= entries in seclogin.conf
 *
 * Config syntax (multiple entries supported):
 *   allow=192.168.1.0/24       — allow IPv4 range
 *   allow=10.0.0.0/8           — allow IPv4 range
 *   allow=::1                  — allow IPv6 address
 *   allow=2001:db8::/32        — allow IPv6 range
 *   deny=192.168.1.100         — deny specific host (checked before allow)
 *
 * Evaluation order:
 *   1. deny= rules checked first — match → reject immediately
 *   2. allow= rules checked next — match → proceed to authentication
 *   3. No allow= rules           → allow all (deny-only mode)
 *   4. Allow rules exist, no match → reject
 *   5. No rules at all           → allow all (backward compatible)
 *   6. No SSH (console access)   → always allow
 *
 * Both IPv4 and IPv6 CIDR notation supported.
 * IPv4-mapped IPv6 (::ffff:x.x.x.x) matched transparently against IPv4 rules.
 * --------------------------------------------------------------------------- */

/* compare first nPrefix bits of two IPv6 addresses */

static int ip6_prefix_match(const struct in6_addr *pA, const struct in6_addr *pB, int nPrefix)
{
    int     nBytes = nPrefix / 8;
    int     nBits  = nPrefix % 8;
    uint8_t mask   = 0;

    if ( (NULL == pA) || (NULL == pB) )
        return 0;

    if (nPrefix < 0 || nPrefix > 128) return 0;

    if (nBytes > 0 && memcmp(pA->s6_addr, pB->s6_addr, (size_t) nBytes) != 0)
        return 0;

    if (nBits == 0)
        return 1;

    mask = (uint8_t)(0xffu << (8 - nBits));
    return (pA->s6_addr[nBytes] & mask) == (pB->s6_addr[nBytes] & mask);
}


/* returns 1 if pszIp matches CIDR rule pszCidr, 0 otherwise
 * all matching is done in IPv6 address space:
 *   - IPv4 addresses and rules are mapped to ::ffff:x.x.x.x (prefix += 96)
 *   - pure IPv6 addresses and rules are compared directly              */

static int ip_matches_cidr(const char *pszIp, const char *pszCidr)
{
    char            szNet[64]  = {0};
    char           *pszSlash   = NULL;
    int             nPrefix    = -1;
    struct in6_addr addrIp     = {0};
    struct in6_addr addrNet    = {0};
    struct in_addr  addr4      = {0};

    if (!pszIp || !*pszIp || !pszCidr || !*pszCidr) return 0;

    /* split rule on '/' to get network and prefix */
    snprintf(szNet, sizeof(szNet), "%s", pszCidr);
    pszSlash = strchr(szNet, '/');
    if (pszSlash)
    {
        *pszSlash = '\0';
        nPrefix = atoi(pszSlash + 1);
    }

    /* normalize connecting IP into IPv6 address space */
    memset(&addrIp, 0, sizeof(addrIp));
    if (inet_pton(AF_INET, pszIp, &addr4) == 1)
    {
        /* IPv4 → ::ffff:x.x.x.x */
        addrIp.s6_addr[10] = 0xff;
        addrIp.s6_addr[11] = 0xff;
        memcpy(&addrIp.s6_addr[12], &addr4, 4);
    }
    else if (inet_pton(AF_INET6, pszIp, &addrIp) == 1)
    {
        /* already in IPv6 form (includes ::ffff:x.x.x.x if sent as IPv6) */
    }
    else return 0;  /* unparseable connecting IP */

    /* normalize rule network into IPv6 address space */
    memset(&addrNet, 0, sizeof(addrNet));
    if (inet_pton(AF_INET, szNet, &addr4) == 1)
    {
        /* IPv4 rule → ::ffff:x.x.x.x, shift prefix into IPv6 space */
        addrNet.s6_addr[10] = 0xff;
        addrNet.s6_addr[11] = 0xff;
        memcpy(&addrNet.s6_addr[12], &addr4, 4);
        nPrefix = (nPrefix < 0) ? 128 : (nPrefix + 96);
        if (nPrefix > 128) return 0;
    }
    else if (inet_pton(AF_INET6, szNet, &addrNet) == 1)
    {
        if (nPrefix < 0) nPrefix = 128;
        if (nPrefix > 128) return 0;
    }
    else return 0;  /* unparseable rule */

    return ip6_prefix_match(&addrIp, &addrNet, nPrefix);
}


/* returns 0 if pszIp is permitted by the configured ACL, -1 if denied
 * pszIp is the raw client IP (without port or src= prefix)           */

static int check_ip_access(const char *pszIp)
{
    char aszDeny [ACL_MAX][ACL_ENTRY_MAX];
    char aszAllow[ACL_MAX][ACL_ENTRY_MAX];
    int  nDeny  = 0;
    int  nAllow = 0;
    int  i      = 0;

    memset(aszDeny,  0, sizeof(aszDeny));
    memset(aszAllow, 0, sizeof(aszAllow));

    /* no SSH connection (console access) — always allow */
    if (!pszIp || !*pszIp) return 0;

    nDeny  = read_config_all("deny",  aszDeny,  ACL_MAX);
    nAllow = read_config_all("allow", aszAllow, ACL_MAX);

    /* no rules configured — allow all (backward compatible) */
    if (nDeny == 0 && nAllow == 0) return 0;

    /* deny rules take priority — checked first */
    for (i = 0; i < nDeny; i++)
    {
        if (ip_matches_cidr(pszIp, aszDeny[i]))
        {
            debug_log("ip_access: denied by rule deny=%s ip=%s", aszDeny[i], pszIp);
            return -1;
        }
    }

    /* no allow rules — allow all not explicitly denied */
    if (nAllow == 0) return 0;

    /* allow rules present — IP must match at least one */
    for (i = 0; i < nAllow; i++)
    {
        if (ip_matches_cidr(pszIp, aszAllow[i]))
        {
            debug_log("ip_access: allowed by rule allow=%s ip=%s", aszAllow[i], pszIp);
            return 0;
        }
    }

    /* allow rules exist but none matched */
    debug_log("ip_access: denied — no allow rule matched ip=%s", pszIp);
    return -1;
}


/* --verify mode: runs on auth server via ForceCommand, validates TOTP remotely */

static int run_verify_mode(void)
{
    char          szRemoteNonce[NONCE_HEX]                 = {0};
    char          szLocalNonce[NONCE_HEX]                  = {0};
    char          szReceivedHmac[HMAC256_HEX]              = {0};
    char          szLine[NONCE_HEX + 1 + HMAC256_HEX + 1 + REASON_MAX + 4] = {0};
    char          szReason[REASON_MAX + 1]                 = {0};
    char          szSecretB32[128]                         = {0};
    char          szAlgorithm[16]                          = {0};
    char          szClientIp[48]                           = {0};
    char          szClientPort[16]                         = {0};
    char          szClientSrc[80]                          = {0};
    unsigned char abSecretBin[64]                          = {0};
    int           cbSecret                              = 0;
    int           nStep                                 = 0;
    int           fMatched                              = 0;
    time_t        tAge                                  = -1;
    uid_t         nUid                                  = 0;
    const EVP_MD *pMd                                   = NULL;
    const char   *pszConn                               = NULL;

    if (getuid() == 0)
    {
        err_msg("verify mode must not run as root");
        return 1;
    }

    /* drop SUID euid immediately — verify mode needs no elevated privileges;
     * the real user (seclogin) has group access to the verify secret (0640) */
    if (seteuid(getuid()) != 0)
    {
        err_msg("seteuid failed");
        return 1;
    }

    /* identify this process as verify mode in syslog — cleaner than "seclogin --verify:" */
    openlog("seclogin-srv", LOG_PID, LOG_AUTH);

    /* config already loaded and debug set by main() */
    nUid    = getuid();
    szClientIp[0]   = '\0';
    szClientPort[0] = '\0';

    /* SSH_CONNECTION="client_ip client_port server_ip server_port"
     * gives us the target server's IP — which server is requesting verification */
    pszConn = getenv("SSH_CONNECTION");
    if (pszConn)
        sscanf(pszConn, "%47s %15s", szClientIp, szClientPort);

    if (*szClientIp && *szClientPort)
        snprintf(szClientSrc, sizeof(szClientSrc), "src=%s port=%s", szClientIp, szClientPort);
    else if (*szClientIp)
        snprintf(szClientSrc, sizeof(szClientSrc), "src=%s", szClientIp);
    else
        snprintf(szClientSrc, sizeof(szClientSrc), "src=unknown");

    debug_log("--verify: client %s", szClientSrc);

    /* check IP access control (allow=/deny= in config) */
    if (check_ip_access(szClientIp) != 0)
    {
        syslog(LOG_AUTH | LOG_WARNING,
               "auth=denied uid=%d %s msg=\"IP access denied\"",
               (int) nUid, szClientSrc);
        return 1;
    }

    /* generate and send remote nonce to local side */
    if (generate_nonce(szRemoteNonce, sizeof(szRemoteNonce)) != 0)
    {
        err_msg("nonce generation failed");
        return 1;
    }

    debug_log("--verify: nonce generated remote_nonce=%s", szRemoteNonce);

    printf("%s\n", szRemoteNonce);
    fflush(stdout);

    /* read response: "local_nonce hmac_hex" */
    if (!fgets(szLine, sizeof(szLine), stdin))
    {
        syslog(LOG_AUTH | LOG_WARNING,
               "auth=error uid=%d %s msg=\"no response received\"",
               (int) nUid, szClientSrc);
        debug_log("--verify: no response received");
        return 1;
    }

    szLine[strcspn(szLine, "\r\n")] = '\0';

    /* parse: "local_nonce hmac [reason]" — reason is everything after the two hex tokens */
    sscanf(szLine, "%32s %64s", szLocalNonce, szReceivedHmac);

    /* validate exact lengths and hex-only content before any further processing */
    if (!valid_hex_str(szLocalNonce,   NONCE_BYTES * 2)   ||
        !valid_hex_str(szReceivedHmac, HMAC256_BYTES * 2))
    {
        syslog(LOG_AUTH | LOG_WARNING,
               "auth=error uid=%d %s msg=\"invalid response format\"",
               (int) nUid, szClientSrc);
        return 1;
    }

    /* extract reason: skip past nonce and hmac tokens to the remainder of the line */
    {
        const char *p = szLine;
        /* skip nonce */
        while (*p && !isspace((unsigned char)*p)) p++;
        while (*p &&  isspace((unsigned char)*p)) p++;
        /* skip hmac */
        while (*p && !isspace((unsigned char)*p)) p++;
        while (*p &&  isspace((unsigned char)*p)) p++;
        /* rest is reason — already stripped of \r\n by earlier strcspn */
        if (*p && strlen(p) <= REASON_MAX)
        {
            snprintf(szReason, sizeof(szReason), "%s", p);
            if (!valid_reason(szReason))
                szReason[0] = '\0';
        }
    }

    debug_log("--verify: reason=\"%s\"", szReason);

    /* validate nonce age — timestamp embedded in first 4 bytes by generate_nonce()
     * both generation and validation happen on the auth server: zero clock skew */
    {
        unsigned char abNonce[NONCE_BYTES] = {0};
        uint32_t      uNonceTs             = 0;
        time_t        tNow                 = time(NULL);

        if (hex_decode(szRemoteNonce, abNonce, sizeof(abNonce)) != NONCE_BYTES)
        {
            syslog(LOG_AUTH | LOG_WARNING,
                   "auth=error uid=%d %s msg=\"malformed nonce\"",
                   (int) nUid, szClientSrc);
            return 1;
        }

        uNonceTs = ((uint32_t) abNonce[0] << 24) |
                   ((uint32_t) abNonce[1] << 16) |
                   ((uint32_t) abNonce[2] <<  8) |
                    (uint32_t) abNonce[3];

        tAge = tNow - (time_t) uNonceTs;

        explicit_bzero(abNonce, sizeof(abNonce));

        debug_log("--verify: nonce age=%lds limit=%ds", (long) tAge, NONCE_MAX_AGE);

        if (tAge < 0 || tAge > NONCE_MAX_AGE)
        {
            syslog(LOG_AUTH | LOG_WARNING,
                   "auth=error uid=%d %s age=%lds nonce=%s msg=\"nonce expired\"",
                   (int) nUid, szClientSrc,
                   (long) tAge, szLocalNonce);
            debug_log("--verify: nonce expired, rejecting");
            sleep(AUTH_FAIL_DELAY);
            printf("fail\n");
            fflush(stdout);
            return 1;
        }
    }

    /* read TOTP secret from verify-specific file (root:seclogin 0640) */
    if (read_verify_secret(szSecretB32, sizeof(szSecretB32)) < 0)
        return 1;

    if (read_config_value("algorithm", szAlgorithm, sizeof(szAlgorithm)) < 0)
        snprintf(szAlgorithm, sizeof(szAlgorithm), "SHA256");

    pMd = (strcasecmp(szAlgorithm, "SHA1") == 0) ? EVP_sha1() : EVP_sha256();

    cbSecret = base32_decode(szSecretB32, abSecretBin, sizeof(abSecretBin));
    explicit_bzero(szSecretB32, sizeof(szSecretB32));

    if (cbSecret <= 0)
    {
        err_msg("invalid secret");
        return 1;
    }

    debug_log("--verify: checking TOTP window [-%d..+%d] algorithm=%s",
              TOTP_WINDOW, TOTP_WINDOW, szAlgorithm);

    /* check TOTP window — generate each expected code, compute expected HMAC, compare */
    for (nStep = -TOTP_WINDOW; nStep <= TOTP_WINDOW && !fMatched; nStep++)
    {
        char szExpectedCode[TOTP_DIGITS + 1] = {0};
        char szExpectedHmac[HMAC256_HEX]    = {0};

        if (totp_generate(abSecretBin, (size_t) cbSecret, pMd,
                          time(NULL), nStep,
                          szExpectedCode, sizeof(szExpectedCode)) != 0)
            continue;

        if (compute_verify_hmac(szRemoteNonce, szExpectedCode,
                                szExpectedHmac, sizeof(szExpectedHmac)) != 0)
            continue;

        if (strlen(szReceivedHmac) == HMAC256_BYTES * 2 &&
            CRYPTO_memcmp(szExpectedHmac, szReceivedHmac, HMAC256_BYTES * 2) == 0)
        {
            fMatched = 1;
        }

        debug_log("--verify: step=%d match=%d", nStep, fMatched);

        explicit_bzero(szExpectedCode, sizeof(szExpectedCode));
        explicit_bzero(szExpectedHmac, sizeof(szExpectedHmac));
    }

    explicit_bzero(abSecretBin, sizeof(abSecretBin));

    if (fMatched)
    {
        if (*szReason)
            syslog(LOG_AUTH | LOG_NOTICE,
                   "auth=approved uid=%d %s age=%lds nonce=%s reason=\"%s\"",
                   (int) nUid, szClientSrc,
                   (long) tAge, szLocalNonce, szReason);
        else
            syslog(LOG_AUTH | LOG_NOTICE,
                   "auth=approved uid=%d %s age=%lds nonce=%s",
                   (int) nUid, szClientSrc,
                   (long) tAge, szLocalNonce);
        debug_log("--verify: approved");
        printf("ok\n");
        fflush(stdout);
        return 0;
    }
    else
    {
        if (*szReason)
            syslog(LOG_AUTH | LOG_WARNING,
                   "auth=denied uid=%d %s age=%lds nonce=%s msg=\"TOTP mismatch\" reason=\"%s\"",
                   (int) nUid, szClientSrc,
                   (long) tAge, szLocalNonce, szReason);
        else
            syslog(LOG_AUTH | LOG_WARNING,
                   "auth=denied uid=%d %s age=%lds nonce=%s msg=\"TOTP mismatch\"",
                   (int) nUid, szClientSrc,
                   (long) tAge, szLocalNonce);
        debug_log("--verify: denied, sleeping %ds", AUTH_FAIL_DELAY);
        printf("fail\n");
        fflush(stdout);
        sleep(AUTH_FAIL_DELAY);
        return 1;
    }
}


/* runs as unprivileged child: forks ssh to auth server, exchanges nonces,
   sends HMAC of remote_nonce+code, returns 0 on approval               */

static int remote_verify(const char *pszCode, const char *pszReason)
{
    char    szAuthServer[256]                        = {0};
    char    szAuthKey[256]                           = {0};
    char    szKnownHosts[256]                        = {0};
    char    szLocalNonce[NONCE_HEX]                  = {0};
    char    szRemoteNonce[NONCE_HEX + 4]             = {0};
    char    szHmac[HMAC256_HEX]                      = {0};
    char    szPayload[NONCE_HEX + 1 + HMAC256_HEX + 1 + REASON_MAX + 4] = {0};
    char    szResult[16]                             = {0};
    int     pipeIn[2]                                = {-1, -1};
    int     pipeOut[2]                               = {-1, -1};
    pid_t   pid                                      = -1;
    int     nResult                                  = -1;
    FILE   *fIn                                      = NULL;
    FILE   *fOut                                     = NULL;

    if (read_config_value("auth_server", szAuthServer, sizeof(szAuthServer)) < 0)
    {
        err_msg("no auth_server configured");
        return -1;
    }

    /* default to seclogin@ if no user specified — e.g. "localhost" → "seclogin@localhost" */
    if (!strchr(szAuthServer, '@'))
    {
        char szTmp[256] = {0};
        snprintf(szTmp, sizeof(szTmp), "%s@%s", AUTH_USER_DEFAULT, szAuthServer);
        snprintf(szAuthServer, sizeof(szAuthServer), "%s", szTmp);
        debug_log("remote_verify: no user in auth_server — defaulting to %s", szAuthServer);
    }

    if (read_config_value("auth_key", szAuthKey, sizeof(szAuthKey)) <= 0)
        snprintf(szAuthKey, sizeof(szAuthKey), "%s", SECLOGIN_AUTH_KEY);

    if (read_config_value("known_hosts", szKnownHosts, sizeof(szKnownHosts)) <= 0)
        snprintf(szKnownHosts, sizeof(szKnownHosts), "%s", SECLOGIN_KNOWN_HOSTS);

    if (generate_nonce(szLocalNonce, sizeof(szLocalNonce)) != 0)
    {
        err_msg("nonce generation failed");
        return -1;
    }

    debug_log("remote_verify: connecting to auth_server=%s key=%s known_hosts=%s uid=%d local_nonce=%s",
              szAuthServer, szAuthKey, szKnownHosts, (int) getuid(), szLocalNonce);

    if (pipe(pipeIn) != 0 || pipe(pipeOut) != 0)
    {
        perror("pipe");
        return -1;
    }

    pid = fork();

    if (pid < 0)
    {
        perror("fork");
        return -1;
    }

    if (pid == 0)
    {
        /* child: execs ssh — stderr stays connected to terminal */
        static char szKnownHostsOpt[300];
        static char szSshHome[128];
        char       *apszEnv[3];
        struct passwd *pwReal = NULL;

        /* Drop the SUID privilege BEFORE exec'ing ssh.
         * In root-shell mode the parent runs as euid=0; without this drop ssh
         * would run with effective root and honor a caller-controlled
         * ~/.ssh/config (ProxyCommand / LocalCommand / Match exec) — arbitrary
         * command execution as root, bypassing TOTP entirely. ssh needs no
         * elevated privilege here: the auth key is group-readable by the real
         * user. Drop fully and irreversibly (gid before uid).
         * Done before prctl(PR_SET_PDEATHSIG) below so the death signal — which
         * the kernel clears across a credential change — survives. */
        if (geteuid() == 0)
        {
            if (setgid(getgid()) != 0)
                _exit(1);
            if (setuid(getuid()) != 0)
                _exit(1);
        }

        pwReal = getpwuid(getuid());

        /* szKnownHosts resolved in parent before fork */
        snprintf(szKnownHostsOpt, sizeof(szKnownHostsOpt), "UserKnownHostsFile=%s", szKnownHosts);

        apszEnv[0] = (char *) "PATH=" SAFE_PATH;
        apszEnv[1] = NULL;
        apszEnv[2] = NULL;

        /* pass real user's HOME so SSH can read ~/.ssh/config (e.g. Port override);
         * known_hosts path is explicit via UserKnownHostsFile — not affected by HOME */
        if (pwReal && pwReal->pw_dir && *pwReal->pw_dir)
        {
            snprintf(szSshHome, sizeof(szSshHome), "HOME=%s", pwReal->pw_dir);
            apszEnv[1] = szSshHome;
        }

        const char *apszArgs[] =
        {
            "ssh",
            "-i",  szAuthKey,
            "-o",  "StrictHostKeyChecking=yes",
            "-o",  szKnownHostsOpt,
            "-o",  "BatchMode=yes",
            "-o",  "ConnectTimeout=10",
            "-o",  "PasswordAuthentication=no",
            "-o",  "PubkeyAuthentication=yes",
            "-T",
            szAuthServer,
            NULL
        };

        /* if the parent (seclogin) is killed while we are running, kill this
         * SSH child too — prevents orphaned connections to the auth server */
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        dup2(pipeIn[0],  STDIN_FILENO);
        dup2(pipeOut[1], STDOUT_FILENO);

        close(pipeIn[0]);  close(pipeIn[1]);
        close(pipeOut[0]); close(pipeOut[1]);

        execve("/usr/bin/ssh", (char *const *) apszArgs, apszEnv);
        _exit(1);
    }

    /* parent: close unused pipe ends */
    close(pipeIn[0]);
    close(pipeOut[1]);

    fOut = fdopen(pipeIn[1],  "w");
    fIn  = fdopen(pipeOut[0], "r");

    if (!fOut || !fIn)
    {
        perror("fdopen");
        kill(pid, SIGTERM);
        goto cleanup;
    }

    /* read remote nonce */
    if (!fgets(szRemoteNonce, sizeof(szRemoteNonce), fIn))
    {
        err_msg("no nonce received from auth server");
        goto cleanup;
    }

    szRemoteNonce[strcspn(szRemoteNonce, "\r\n")] = '\0';

    debug_log("remote_verify: received remote_nonce=%s", szRemoteNonce);

    if (strlen(szRemoteNonce) != NONCE_BYTES * 2)
    {
        err_msg("invalid nonce from auth server");
        goto cleanup;
    }

    /* test_delay: inject artificial delay to test nonce expiry — debug mode only */
    if (g_fDebug)
    {
        char szDelay[16] = {0};

        if (read_config_value("test_delay", szDelay, sizeof(szDelay)) > 0)
        {
            int nDelay = 0;
            nDelay = atoi(szDelay);

            if (nDelay > 0)
            {
                debug_log("remote_verify: test_delay=%ds (testing nonce expiry)", nDelay);
                sleep((unsigned int) nDelay);
            }
        }
    }

    /* compute HMAC(remote_nonce, user_code) and send with local nonce */
    if (compute_verify_hmac(szRemoteNonce, pszCode, szHmac, sizeof(szHmac)) != 0)
    {
        err_msg("HMAC computation failed");
        goto cleanup;
    }

    /* send single line: "local_nonce hmac [reason]"
     * reason is last — no newlines allowed (valid_reason enforces this,
     * but strip defensively before appending)                           */
    if (pszReason && *pszReason)
    {
        char szSafeReason[REASON_MAX + 1] = {0};
        snprintf(szSafeReason, sizeof(szSafeReason), "%s", pszReason);
        szSafeReason[strcspn(szSafeReason, "\r\n")] = '\0';
        snprintf(szPayload, sizeof(szPayload), "%s %s %s", szLocalNonce, szHmac, szSafeReason);
    }
    else
    {
        snprintf(szPayload, sizeof(szPayload), "%s %s", szLocalNonce, szHmac);
    }

    fprintf(fOut, "%s\n", szPayload);
    fflush(fOut);
    fclose(fOut);
    fOut = NULL;

    explicit_bzero(szHmac, sizeof(szHmac));

    /* read approved/denied */
    if (!fgets(szResult, sizeof(szResult), fIn))
    {
        err_msg("no result from auth server");
        goto cleanup;
    }

    szResult[strcspn(szResult, "\r\n")] = '\0';

    nResult = (strcmp(szResult, "ok") == 0) ? 0 : 1;

    debug_log("remote_verify: result=%s nResult=%d", szResult, nResult);

cleanup:
    if (fOut) fclose(fOut);
    if (fIn)  fclose(fIn);

    waitpid(pid, NULL, 0);

    explicit_bzero(szLocalNonce,  sizeof(szLocalNonce));
    explicit_bzero(szRemoteNonce, sizeof(szRemoteNonce));

    return nResult;
}


static void print_banner(const char *pszTitle, const char *pszHost, const char *pszUser, const char *pszDomino)
{
    fprintf(stderr,
        "\n\n"
        "  %s\n\n"
        "  This session is logged.\n"
        "\n"
        "  Host   :  %s\n",
        pszTitle ? pszTitle : "",
        pszHost  ? pszHost  : "");

    if (pszUser && pszUser)
        fprintf(stderr, "  User   :  %s\n", pszUser);

    if (pszDomino && *pszDomino)
        fprintf(stderr, "  Domino :  %s\n", pszDomino);

    fprintf(stderr, "  %s\n\n\n", g_szLine);
}


static void auth_error(const char *pszMsg)
{
    clear_screen();
    print_top_banner();
    fprintf(stderr, "\n  %s\n\n", pszMsg);
}


/* verify the required secret file is accessible before showing any UI
 * in local TOTP mode: opens and validates the secret file, then closes it
 * in remote verify mode: no local secret needed — returns 0 immediately    */
static int check_secret_access(void)
{
    char szAuthServer[256] = {0};
    int  fdSecret          = -1;

    /* remote verify mode — no local secret needed */
    if (read_config_value("auth_server", szAuthServer, sizeof(szAuthServer)) > 0)
        return 0;

    /* local mode — open_secret() validates permissions and ownership
     * totp.secret (root:seclogin 0640) readable by root mode (euid=0) and gate mode (egid=seclogin) */
    fdSecret = open_secret("secret_file", ROOTSHELL_SECRET);
    if (fdSecret < 0)
        return -1;

    close(fdSecret);
    return 0;
}


static int authenticate_totp(const char *pszClientIp, char *pszReason, size_t cbReason,
                             const char *pszTarget)
{
    char   szCode[CODE_STR_LEN + 2] = {0};  /* large enough for TOTP (6) or recovery code (29) + newline + NUL */
    char   szReasonMode[8]     = {0};
    size_t cbLen               = 0;
    size_t i                   = 0;
    int    nReasonMode         = 0;

    debug_ids(0);

    /* read reason= config: 0=disabled 1=optional 2=required */
    if (read_config_value("reason", szReasonMode, sizeof(szReasonMode)) > 0)
        nReasonMode = atoi(szReasonMode);

    if (nReasonMode >= 1)
    {
        fprintf(stderr, "\n\n  Reason: ");

        if (!fgets(pszReason, (int) cbReason, stdin))
        {
            fprintf(stderr, "\nInput error\n");
            return -1;
        }

        /* strip trailing newline/whitespace */
        cbLen = strlen(pszReason);
        while (cbLen > 0 && (pszReason[cbLen-1] == '\n' || pszReason[cbLen-1] == '\r' ||
                              pszReason[cbLen-1] == ' '))
            pszReason[--cbLen] = '\0';

        if (!valid_reason(pszReason))
        {
            /* strip invalid chars silently — log what we got */
            pszReason[0] = '\0';
        }

        if (nReasonMode >= 2 && pszReason[0] == '\0')
        {
            auth_error("Reason required");
            return -1;
        }
    }

    fprintf(stderr, "\n\n  Passcode:  ");

    if (!fgets(szCode, sizeof(szCode), stdin))
    {
        fprintf(stderr, "\nInput error\n");
        return -1;
    }

    cbLen = strlen(szCode);

    debug_log("authenticate_totp: raw input len=%zu buf_size=%zu",
              cbLen, sizeof(szCode));

    if (cbLen > 0 && szCode[cbLen - 1] == '\n')
        szCode[cbLen - 1] = '\0';

    cbLen = strlen(szCode);

    debug_log("authenticate_totp: stripped len=%zu", cbLen);

    /* --- recovery code path (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX = 29 chars) --- */
    if (cbLen == CODE_STR_LEN - 1)
    {
        debug_log("authenticate_totp: recovery code path len=%zu", cbLen);

        int nRemaining = 0;
        int nRet = recovery_verify(szCode, &nRemaining);
        explicit_bzero(szCode, sizeof(szCode));

        if (nRet == RECOVERY_OK)
        {
            syslog(LOG_AUTH | LOG_CRIT,
                   "seclogin: auth=success method=recovery-code target=%s uid=%d %s remaining=%d",
                   pszTarget, (int) getuid(),
                   pszClientIp ? pszClientIp : "src=unknown",
                   nRemaining);
            return 0;
        }

        auth_error("Authentication failed");
        syslog(LOG_AUTH | LOG_WARNING,
               "seclogin: auth=failed method=recovery-code target=%s uid=%d %s",
               pszTarget, (int) getuid(),
               pszClientIp ? pszClientIp : "src=unknown");
        debug_log("authenticate_totp: recovery code rejected ret=%d", nRet);
        sleep(AUTH_FAIL_DELAY);
        return -1;
    }

    /* --- TOTP path --- */
    if (cbLen != 6)
    {
        auth_error("Authentication failed");
        syslog(LOG_AUTH | LOG_WARNING,
               "seclogin: auth=failed target=%s uid=%d %s msg=\"invalid passcode length=%zu\"",
               pszTarget, (int) getuid(),
               pszClientIp ? pszClientIp : "src=unknown",
               cbLen);
        debug_log("authenticate_totp: rejected len=%zu expected 6", cbLen);
        explicit_bzero(szCode, sizeof(szCode));
        sleep(AUTH_FAIL_DELAY);
        return -1;
    }

    for (i = 0; i < cbLen; i++)
    {
        if (!isdigit((unsigned char) szCode[i]))
        {
            auth_error("Authentication failed");
            syslog(LOG_AUTH | LOG_WARNING,
                   "seclogin: auth=failed target=%s uid=%d %s msg=\"invalid passcode format\"",
                   pszTarget, (int) getuid(),
                   pszClientIp ? pszClientIp : "src=unknown");
            explicit_bzero(szCode, sizeof(szCode));
            sleep(AUTH_FAIL_DELAY);
            return -1;
        }
    }

    {
        char szAuthServer[256] = {0};
        int  fMatched          = 0;

        if (read_config_value("auth_server", szAuthServer, sizeof(szAuthServer)) > 0)
        {
            /* --- remote verification via SSH --- */
            int nRc = 0;
            nRc = remote_verify(szCode, pszReason);
            explicit_bzero(szCode, sizeof(szCode));

            if (nRc == 0)
            {
                fMatched = 1;
            }
        }
        else
        {
            /* --- local TOTP verification --- */
            char          szSecretB32[128]  = {0};
            char          szAlgorithm[16]   = {0};
            unsigned char abSecretBin[64]   = {0};
            int           cbSecret          = 0;
            int           nStep             = 0;
            const EVP_MD *pMd               = NULL;

            if (read_secret(szSecretB32, sizeof(szSecretB32)) < 0)
            {
                explicit_bzero(szCode, sizeof(szCode));
                return -1;
            }

            if (read_config_value("algorithm", szAlgorithm, sizeof(szAlgorithm)) < 0)
                snprintf(szAlgorithm, sizeof(szAlgorithm), "SHA256");

            pMd = (strcasecmp(szAlgorithm, "SHA1") == 0) ? EVP_sha1() : EVP_sha256();

            cbSecret = base32_decode(szSecretB32, abSecretBin, sizeof(abSecretBin));
            explicit_bzero(szSecretB32, sizeof(szSecretB32));

            if (cbSecret <= 0)
            {
                explicit_bzero(szCode, sizeof(szCode));
                err_msg("Invalid TOTP secret");
                return -1;
            }

            /* check T-1, T, T+1 to allow for clock skew */
            for (nStep = -TOTP_WINDOW; nStep <= TOTP_WINDOW; nStep++)
            {
                if (totp_validate(abSecretBin, (size_t) cbSecret,
                                  pMd, time(NULL), nStep, szCode) == 0)
                {
                    fMatched = 1;
                    break;
                }
            }

            explicit_bzero(abSecretBin, sizeof(abSecretBin));
            explicit_bzero(szCode, sizeof(szCode));
        }

        if (!fMatched)
        {
            auth_error("Authentication failed");
            if (pszReason && *pszReason)
                syslog(LOG_AUTH | LOG_WARNING,
                       "seclogin: auth=failed target=%s uid=%d %s reason=\"%s\"",
                       pszTarget, (int) getuid(),
                       pszClientIp ? pszClientIp : "src=unknown",
                       pszReason);
            else
                syslog(LOG_AUTH | LOG_WARNING,
                       "seclogin: auth=failed target=%s uid=%d %s",
                       pszTarget, (int) getuid(),
                       pszClientIp ? pszClientIp : "src=unknown");
            sleep(AUTH_FAIL_DELAY);
            return -1;
        }
    }

    return 0;
}


/* ---------------------------------------------------------------------------
 * Gate mode — TOTP gate for login shells
 *
 * Triggered when euid != 0 (binary installed as seclogin:seclogin 4750).
 * After successful TOTP authentication, drops SUID privilege completely
 * and executes the invoking user's login shell. No root access is granted.
 *
 * Usage:
 *   Install as /usr/local/bin/seclogin-user  owned seclogin:seclogin 4750
 *   Set as login shell in /etc/passwd, or use as ForceCommand in authorized_keys
 *
 * After authentication:
 *   - setresgid()    — drop effective/saved GID to real GID
 *   - setresuid()    — set real/effective/saved UID to user's UID (drops SUID)
 *   - execve shell   — exec the user's login shell from /etc/passwd
 *
 * Only login shells are exec'd — SSH_ORIGINAL_COMMAND is intentionally ignored.
 * --------------------------------------------------------------------------- */
static int run_gate_mode(void)
{
    char        szClientIp[64]          = {0};
    char        szRawIp[48]             = {0};
    char        szReason[REASON_MAX+1]  = {0};
    char        szHostname[HOST_NAME_MAX+1]    = {0};
    char        szUsername[64]              = {0};
    char        szDominoServer[NOTES_INI_MAX_LINE] = {0};
    char        szDominoCn[NOTES_INI_MAX_LINE]     = {0};
    uid_t       nRuid                   = 0;
    gid_t       nRgid                   = 0;
    const char *pszShell                = "/bin/sh";
    static char szShellArg[PATH_MAX+4]  = {0};
    static char szHomeBuf[256]          = {0};
    static char szPs1Buf[HOST_NAME_MAX+64] = {0};
    static char szTermBuf[80]           = {0};
    struct passwd *pw                   = NULL;
    char       *pEnv[6]                 = {0};
    const char *pszTerm                 = NULL;

    /* config loaded, debug set, binary/session validated, prctl done by main() */
    debug_ids(0);

    nRuid = getuid();
    nRgid = getgid();

    /* gather client IP before clearenv() */
    {
        const char *pszConn = getenv("SSH_CONNECTION");

        if (pszConn)
        {
            char szIp[48] = {0}, szPort[16] = {0};
            sscanf(pszConn, "%47s %15s", szIp, szPort);
            snprintf(szRawIp, sizeof(szRawIp), "%s", szIp);
            if (*szIp && *szPort)
                snprintf(szClientIp, sizeof(szClientIp), "src=%s port=%s", szIp, szPort);
            else if (*szIp)
                snprintf(szClientIp, sizeof(szClientIp), "src=%s", szIp);
        }
    }

    sanitize_environment();

    debug_log("gate_mode: entered uid=%d euid=%d gid=%d",
              (int) nRuid, (int) geteuid(), (int) nRgid);
    debug_log("gate_mode: client %s", szClientIp[0] ? szClientIp : "src=unknown");

    /* look up invoking user before privilege drop */
    pw = getpwuid(nRuid);
    if (!pw)
    {
        err_msg("Cannot look up user uid=%d", (int) nRuid);
        return 1;
    }

    snprintf(szUsername, sizeof(szUsername), "%s", pw->pw_name);
    pszShell = pw->pw_shell;

    if (!pszShell || !*pszShell)
        pszShell = "/bin/sh";

    debug_log("gate_mode: user=%s shell=%s home=%s",
              szUsername, pszShell, pw->pw_dir ? pw->pw_dir : "(none)");

    gethostname(szHostname, sizeof(szHostname) - 1);

    /* IP access control */
    if (check_ip_access(szRawIp) != 0)
    {
        syslog(LOG_AUTH | LOG_WARNING,
               "seclogin: auth=denied target=%s uid=%d %s msg=\"IP access denied\"",
               szUsername, (int) nRuid,
               szClientIp[0] ? szClientIp : "src=unknown");
        err_msg("Access denied");
        return 1;
    }

    /* verify secret is accessible before showing any UI */
    if (check_secret_access() != 0)
        return 1;

    /* TOTP authentication */
    clear_screen();
    print_top_banner();

    fprintf(stderr,
        "\n  We trust you have received the usual lecture from the local\n"
        "  System Administrator. It usually boils down to these three things:\n"
        "\n"
        "    1.  Respect the privacy of others.\n"
        "    2.  Think before you type.\n"
        "    3.  With great power comes great responsibility.\n");

    if (authenticate_totp(szClientIp, szReason, sizeof(szReason), szUsername) != 0)
        return 1;

    /* log success */
    if (szReason[0])
        syslog(LOG_AUTH | LOG_NOTICE,
               "seclogin: auth=success target=%s uid=%d %s reason=\"%s\"",
               szUsername, (int) nRuid,
               szClientIp[0] ? szClientIp : "src=unknown", szReason);
    else
        syslog(LOG_AUTH | LOG_NOTICE,
               "seclogin: auth=success target=%s uid=%d %s",
               szUsername, (int) nRuid,
               szClientIp[0] ? szClientIp : "src=unknown");

    /* drop SUID+SGID privilege back to invoking user
     * supplementary groups are unchanged — already set from the user's login session
     * initgroups() is not needed (and not permitted without root)                   */
    debug_log("gate_mode: dropping privilege to uid=%d gid=%d user=%s",
              (int) nRuid, (int) nRgid, szUsername);

    /* mask signals during privilege drop — a signal arriving between setresgid and
     * setresuid would leave the process with inconsistent uid/gid state            */
    {
        sigset_t mask, oldmask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGHUP);
        sigprocmask(SIG_BLOCK, &mask, &oldmask);

        if (setresgid(nRgid, nRgid, nRgid) != 0)
        {
            perror("setresgid");
            return 1;
        }

        if (setresuid(nRuid, nRuid, nRuid) != 0)
        {
            perror("setresuid");
            return 1;
        }

        /* restore signal mask — privilege drop complete */
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
    }

    /* read Domino CN after privilege drop — notes.ini is readable as the real user */
    szDominoServer[0] = '\0';
    szDominoCn[0]     = '\0';
    if (!get_notes_ini_value("ServerName", szDominoServer, sizeof(szDominoServer)))
        get_notes_ini_value("MailServer", szDominoServer, sizeof(szDominoServer));
    if (*szDominoServer)
    {
        const char *pszCn = abbrev_notes_name(szDominoServer, szDominoCn, sizeof(szDominoCn));
        if (pszCn != szDominoCn)
            snprintf(szDominoCn, sizeof(szDominoCn), "%s", pszCn);
    }

    closelog();   /* clean shutdown before execve — close_fds() would force-close it anyway */
    close_fds();

    /* build login shell banner */
    clear_screen();

    {
        char szTitle[128] = {0};
        snprintf(szTitle, sizeof(szTitle), "Authenticated session");
        print_banner(szTitle, szHostname, szUsername, szDominoCn[0] ? szDominoCn : NULL);
    }

    /* exec login shell — argv[0] prefixed with '-' signals a login shell */
    snprintf(szShellArg, sizeof(szShellArg), "-%s",
             strrchr(pszShell, '/') ? strrchr(pszShell, '/') + 1 : pszShell);

    snprintf(szHomeBuf,  sizeof(szHomeBuf),  "HOME=%s",  pw->pw_dir  ? pw->pw_dir  : "/");
    snprintf(szPs1Buf,   sizeof(szPs1Buf),   "PS1=[%s@%s \\W]\\$ ", szUsername, szHostname);

    pszTerm = getenv("TERM");
    if (pszTerm && valid_term(pszTerm))
        snprintf(szTermBuf, sizeof(szTermBuf), "TERM=%s", pszTerm);
    else
        snprintf(szTermBuf, sizeof(szTermBuf), "TERM=vt100");

    pEnv[0] = (char *) "PATH=/usr/local/bin:/usr/bin:/bin";
    pEnv[1] = szHomeBuf;
    pEnv[2] = szTermBuf;
    pEnv[3] = szPs1Buf;
    pEnv[4] = NULL;

    umask(022);

    debug_log("gate_mode: exec shell=%s argv0=%s", pszShell, szShellArg);
    debug_ids(0);

    execve(pszShell, (char *const[]){ szShellArg, NULL }, pEnv);

    perror("execve");
    return 1;
}


int main(int argc, char *argv[])
{
    const char *pszTerm = NULL;

    /* common setup — runs once before dispatching to any mode */
    signal(SIGPIPE, SIG_IGN);
    umask(077);
    openlog("seclogin", LOG_PID, LOG_AUTH);

    /* load config into memory once — all modes use the cached buffer
     * debug= is read here so logging is active for every subsequent step */
    if (load_config() < 0)
    {
        syslog(LOG_AUTH | LOG_ERR,
               "seclogin: auth=error uid=%d msg=\"cannot read config: %s\"",
               (int) getuid(), ROOTSHELL_CONFIG);
        err_msg("Cannot read config — aborting");
        return 1;
    }
    {
        char szDebug[8] = {0};
        if (read_config_value("debug", szDebug, sizeof(szDebug)) > 0 && szDebug[0] == '1')
            g_fDebug = 1;
    }
    debug_ids(0);

    /* --verify mode: no SUID, no validate_binary/session — runs as seclogin user */
    if (argc == 2 && strcmp(argv[1], "--verify") == 0)
        return run_verify_mode();

    /* SUID modes (root shell + gate) require binary and session validation */
    if (validate_binary() != 0)
        return 1;

    if (validate_session() != 0)
        return 1;

    /* disable core dumps — secrets appear during auth */
    prctl(PR_SET_DUMPABLE, 0);

    /* gate mode: euid != 0 — binary is SUID to seclogin user, not root */
    if (geteuid() != 0)
        return run_gate_mode();

    /* root shell mode */
    char *const args[] =
    {
        "bash",
        "--noprofile",
        "--norc",
        "-p",
        NULL
    };

    char *pEnv[7] = {0};
    char        szHostname[HOST_NAME_MAX + 1]      = {0};
    char        szDominoServer[NOTES_INI_MAX_LINE]  = {0};
    char        szDominoCn[NOTES_INI_MAX_LINE]      = {0};
    char        szClientIp[64]                      = {0};
    char        szRawIp[48]                         = {0};   /* raw IP for ACL check */
    char        szReason[REASON_MAX + 1]            = {0};
    static char szTermBuf[80]                       = {0};
    static char szPs1Buf[HOST_NAME_MAX + 64]        = {0};
    static char szHomeBuf[80]                       = {0};
    const char *pszHome                             = NULL;
    const char *pszTarget                           = "root"; /* syslog target field */

    /* ------------------------------------------------------------------ */
    /* Gather all informational data before privilege elevation.           */
    /* File I/O, NSS lookups and string parsing belong here, not after     */
    /* setuid. Goal: complexity before root, simplicity after root.        */
    /* ------------------------------------------------------------------ */

    /* save client IP:port before clearenv() wipes the environment
       SSH authentication (key fingerprint) is logged by sshd (LogLevel VERBOSE)
       seclogin logs only the privilege escalation event; client port correlates
       the two log entries reliably                                                */
    {
        const char *pszConn = getenv("SSH_CONNECTION");

        szClientIp[0] = '\0';

        if (pszConn)
        {
            /* format: "client_ip client_port server_ip server_port" */
            char   szIp[48]   = {0};
            char   szPort[16] = {0};

            szIp[0]   = '\0';
            szPort[0] = '\0';

            sscanf(pszConn, "%47s %15s", szIp, szPort);

            snprintf(szRawIp, sizeof(szRawIp), "%s", szIp);   /* raw IP for ACL */

            if (*szIp && *szPort)
                snprintf(szClientIp, sizeof(szClientIp), "src=%s port=%s", szIp, szPort);
            else if (*szIp)
                snprintf(szClientIp, sizeof(szClientIp), "src=%s", szIp);
        }
    }

    /* sanitize first so getenv("TERM") below returns the validated value */
    sanitize_environment();

    /* check IP access control (allow=/deny= in config) before showing any UI */
    if (check_ip_access(szRawIp) != 0)
    {
        syslog(LOG_AUTH | LOG_WARNING,
               "seclogin: auth=denied target=%s uid=%d %s msg=\"IP access denied\"",
               pszTarget, (int) getuid(),
               szClientIp[0] ? szClientIp : "src=unknown");
        err_msg("Access denied");
        return 1;
    }

    /* verify secret is accessible before showing any UI */
    if (check_secret_access() != 0)
        return 1;

    /* resolve root's home — NSS may open files/sockets, must be before close_fds() */
    {
        struct passwd *pw = getpwuid(0);

        if (pw && pw->pw_dir && *pw->pw_dir)
            pszHome = pw->pw_dir;
        else
            pszHome = "/root";
    }

    if (gethostname(szHostname, sizeof(szHostname)) != 0)
        szHostname[0] = '\0';
    szHostname[sizeof(szHostname) - 1] = '\0';

    szDominoServer[0] = '\0';
    szDominoCn[0]     = '\0';

    if (!get_notes_ini_value("ServerName", szDominoServer, sizeof(szDominoServer)))
        get_notes_ini_value("MailServer", szDominoServer, sizeof(szDominoServer));

    if (*szDominoServer)
    {
        const char *pszCn = abbrev_notes_name(szDominoServer, szDominoCn, sizeof(szDominoCn));

        if (pszCn != szDominoCn)
            snprintf(szDominoCn, sizeof(szDominoCn), "%s", pszCn);
    }

    pszTerm = getenv("TERM");

    pEnv[0] = (char *) "PATH=" SAFE_PATH;

    if (pszTerm)
    {
        snprintf(szTermBuf, sizeof(szTermBuf), "TERM=%s", pszTerm);
        pEnv[1] = szTermBuf;
    }
    else
    {
        pEnv[1] = (char *) "TERM=dumb";
    }

    snprintf(szHomeBuf, sizeof(szHomeBuf), "HOME=%s", pszHome);
    snprintf(szPs1Buf,  sizeof(szPs1Buf),  "PS1=[root@%s \\W]# ", szHostname);

    pEnv[2] = (char *) "LANG=C";
    pEnv[3] = szHomeBuf;
    pEnv[4] = szPs1Buf;
    pEnv[5] = NULL;

    /* ------------------------------------------------------------------ */
    /* Authentication and privilege transition.                            */
    /* From here: no file parsing, no NSS, no complexity.                 */
    /* ------------------------------------------------------------------ */

    clear_screen();
    print_top_banner();

    fprintf(stderr,
        "\n  We trust you have received the usual lecture from the local\n"
        "  System Administrator. It usually boils down to these three things:\n"
        "\n"
        "    1.  Respect the privacy of others.\n"
        "    2.  Think before you type.\n"
        "    3.  With great power comes great responsibility.\n");

    if (authenticate_totp(szClientIp, szReason, sizeof(szReason), pszTarget) != 0)
        return 1;

    closelog();   /* clean shutdown before execve — close_fds() would force-close it anyway */
    close_fds();

    if (szReason[0])
        syslog(LOG_AUTH | LOG_NOTICE,
               "seclogin: auth=success target=%s uid=%d %s reason=\"%s\"",
               pszTarget, (int) getuid(),
               szClientIp[0] ? szClientIp : "src=unknown",
               szReason);
    else
        syslog(LOG_AUTH | LOG_NOTICE,
               "seclogin: auth=success target=%s uid=%d %s",
               pszTarget, (int) getuid(),
               szClientIp[0] ? szClientIp : "src=unknown");

    /* mask signals during privilege escalation — a signal between setgid and setuid
     * would leave the process with root GID but non-root UID (inconsistent state)  */
    {
        sigset_t mask, oldmask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGHUP);
        sigprocmask(SIG_BLOCK, &mask, &oldmask);

        if (setgroups(0, NULL) != 0)
        {
            perror("setgroups");
            return 1;
        }

        if (setgid(0) != 0)
        {
            perror("setgid");
            return 1;
        }

        if (setuid(0) != 0)
        {
            perror("setuid");
            return 1;
        }

        /* restore signal mask — privilege escalation complete */
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
    }

    /* ------------------------------------------------------------------ */
    /* Post-elevation: print pre-prepared strings only, then exec.        */
    /* ------------------------------------------------------------------ */

    umask(077);

    clear_screen();
    print_banner("\033[1;31mPRIVILEGED ROOT SESSION\033[0m", szHostname, "root", szDominoCn);

    if (chdir(pszHome) != 0)
        perror("chdir");

    execve("/bin/bash", args, pEnv);

    perror("execve");

    return 1;
}
