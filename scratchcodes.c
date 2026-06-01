/*
    seclogin Recovery Code Module

    Implements emergency single-use recovery codes as a TOTP replacement.
    SSH key authentication is still required -- recovery codes replace TOTP only.

    Build (standalone test):
        see Makefile

    Integration:
        Add scratchcodes.c to seclogin's build, #include "scratchcodes.h",
        wire recovery_generate/list/verify into seclogin.c's argument dispatch.
*/

#include "scratchcodes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <grp.h>
#include <sys/file.h>

/* --- constants ---------------------------------------------------- */

#define CODE_GROUPS         6
#define CODE_GROUP_LEN      4
#define CODE_RAW_BYTES      15      /* 120 bits; 24 chars x 5 bits */

#define MAX_CODES_FILE      CODE_COUNT  /* must match generated count */
#define PBKDF2_ITER         250000
#define SALT_BYTES          16
#define HASH_BYTES          64

#define SALT_B64_MAX        32
#define HASH_B64_MAX        96
#define LINE_BUF            256

/* Uppercase alphanumeric, visually unambiguous (no 0/O, 1/I).
 * 32 entries = 2^5 -> 5 bits per char, no modulo bias. */
static const char g_szAlphabet[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

/* --- base64 (via OpenSSL) ----------------------------------------- */

int b64_encode(const unsigned char *pbSrc, int nSrcLen, char *pszDst, int nDstMax)
{
    int nLen = EVP_EncodeBlock((unsigned char *)pszDst, pbSrc, nSrcLen);
    if (nLen >= nDstMax) return -1;
    return nLen;
}

int b64_decode(const char *pszSrc, unsigned char *pbDst, int nDstMax)
{
    /* EVP_DecodeBlock pads output to a multiple of 3; count trailing '=' to
     * determine actual byte count. */
    int nLen = (int)strlen(pszSrc);

    /* strip trailing newline/whitespace */
    while (nLen > 0 && (pszSrc[nLen-1] == '\n' || pszSrc[nLen-1] == '\r' || pszSrc[nLen-1] == ' '))
        nLen--;

    int nPad = 0;
    if (nLen > 0 && pszSrc[nLen-1] == '=') nPad++;
    if (nLen > 1 && pszSrc[nLen-2] == '=') nPad++;

    /* EVP_DecodeBlock requires a non-const, NUL-terminated input */
    char szTmp[HASH_B64_MAX + 4] = {0};
    if (nLen >= (int)sizeof(szTmp)) return -1;
    memcpy(szTmp, pszSrc, (size_t)nLen);
    szTmp[nLen] = '\0';

    int nDecoded = EVP_DecodeBlock(pbDst, (unsigned char *)szTmp, nLen);
    if (nDecoded < 0) return -1;
    nDecoded -= nPad;
    if (nDecoded > nDstMax) return -1;
    return nDecoded;
}

/* --- code generation ---------------------------------------------- */

int generate_code(char *pszBuf)
{
    unsigned char abRaw[CODE_RAW_BYTES] = {0};
    if (RAND_bytes(abRaw, CODE_RAW_BYTES) != 1)
        return -1;

    int nPos = 0, nByteIdx = 0, nBitBuf = 0, nBitsLeft = 0;

    for (int g = 0; g < CODE_GROUPS; g++) {
        if (g > 0) pszBuf[nPos++] = '-';
        for (int c = 0; c < CODE_GROUP_LEN; c++) {
            while (nBitsLeft < 5 && nByteIdx < CODE_RAW_BYTES) {
                nBitBuf = (nBitBuf << 8) | abRaw[nByteIdx++];
                nBitsLeft += 8;
            }
            nBitsLeft -= 5;
            pszBuf[nPos++] = g_szAlphabet[(nBitBuf >> nBitsLeft) & 0x1f];
        }
    }
    pszBuf[nPos] = '\0';

    OPENSSL_cleanse(abRaw, sizeof(abRaw));
    return 0;
}

/* --- hashing ------------------------------------------------------ */

int hash_code(const char *pszCode, char *pszOut, int nOutMax)
{
    unsigned char abSalt[SALT_BYTES]  = {0};
    unsigned char abHash[HASH_BYTES]  = {0};
    char szSaltB64[SALT_B64_MAX]      = {0};
    char szHashB64[HASH_B64_MAX]      = {0};

    if (RAND_bytes(abSalt, SALT_BYTES) != 1)
        return -1;

    if (!PKCS5_PBKDF2_HMAC(pszCode, (int)strlen(pszCode),
                            abSalt, SALT_BYTES, PBKDF2_ITER,
                            EVP_sha512(), HASH_BYTES, abHash))
        return -1;

    b64_encode(abSalt, SALT_BYTES, szSaltB64, SALT_B64_MAX);
    b64_encode(abHash, HASH_BYTES, szHashB64, HASH_B64_MAX);

    int nLen = snprintf(pszOut, (size_t)nOutMax, "pbkdf2_sha512:%d:%s:%s\n",
                        PBKDF2_ITER, szSaltB64, szHashB64);

    OPENSSL_cleanse(abHash, sizeof(abHash));
    return (nLen > 0 && nLen < nOutMax) ? 0 : -1;
}

/* Verify code against one stored line.
 * Returns 1 = match, 0 = no match, -1 = parse/crypto error. */
int verify_line(const char *pszCode, const char *pszLine)
{
    char szTmp[LINE_BUF] = {0};
    strncpy(szTmp, pszLine, LINE_BUF - 1);
    szTmp[LINE_BUF - 1] = '\0';

    char *pszNl = strchr(szTmp, '\n');
    if (pszNl) *pszNl = '\0';

    char *pszScheme = strtok(szTmp, ":");
    char *pszIterS  = strtok(NULL,  ":");
    char *pszSaltS  = strtok(NULL,  ":");
    char *pszHashS  = strtok(NULL,  ":");

    if (!pszScheme || !pszIterS || !pszSaltS || !pszHashS) return -1;
    if (strcmp(pszScheme, "pbkdf2_sha512") != 0)            return -1;

    int nIter = atoi(pszIterS);
    if (nIter <= 0) return -1;

    unsigned char abSalt[SALT_BYTES + 4]     = {0};
    unsigned char abStored[HASH_BYTES + 4]   = {0};
    unsigned char abComputed[HASH_BYTES]     = {0};

    int nSaltLen = b64_decode(pszSaltS, abSalt,    SALT_BYTES);
    int nHashLen = b64_decode(pszHashS, abStored,  HASH_BYTES);
    if (nSaltLen != SALT_BYTES || nHashLen != HASH_BYTES) return -1;

    if (!PKCS5_PBKDF2_HMAC(pszCode, (int)strlen(pszCode),
                            abSalt, SALT_BYTES, nIter,
                            EVP_sha512(), HASH_BYTES, abComputed))
        return -1;

    int bMatch = (CRYPTO_memcmp(abComputed, abStored, HASH_BYTES) == 0);
    OPENSSL_cleanse(abComputed, sizeof(abComputed));
    return bMatch;
}

/* --- file I/O ----------------------------------------------------- */

/* Create /etc/seclogin/recovery/ (root:seclogin 770) and set correct
 * ownership/permissions on recovery.conf and recovery.lock.
 * Called only from recovery_generate which runs as root.
 *
 * The directory is group-writable so gate mode (euid=seclogin, egid=seclogin)
 * can atomically rewrite recovery.conf via rename(). The parent /etc/seclogin/
 * stays 750 — only this subdirectory is writable by the seclogin group. */
static void set_recovery_file_perms(void)
{
    struct group *pGrp = getgrnam("seclogin");
    gid_t nGid = pGrp ? pGrp->gr_gid : 0;

    /* Create recovery subdirectory if needed */
    if (mkdir(RECOVERY_DIR, 0770) != 0 && errno != EEXIST)
    {
        syslog(LOG_AUTH | LOG_ERR, "recovery: mkdir %s failed: %m", RECOVERY_DIR);
        return;
    }
    if (chown(RECOVERY_DIR, 0, nGid) != 0)
        syslog(LOG_AUTH | LOG_ERR, "recovery: chown %s failed: %m", RECOVERY_DIR);
    chmod(RECOVERY_DIR, 0770);

    /* recovery.conf */
    if (chown(RECOVERY_FILE, 0, nGid) != 0)
        syslog(LOG_AUTH | LOG_ERR, "recovery: chown %s failed: %m", RECOVERY_FILE);
    chmod(RECOVERY_FILE, 0660);

    /* Pre-create lock file so gate mode can open it O_RDONLY for flock */
    int nFd = open(RECOVERY_LOCK_FILE, O_WRONLY | O_CREAT | O_NOFOLLOW, 0660);
    if (nFd >= 0)
    {
        if (chown(RECOVERY_LOCK_FILE, 0, nGid) != 0)
            syslog(LOG_AUTH | LOG_ERR, "recovery: chown %s failed: %m", RECOVERY_LOCK_FILE);
        chmod(RECOVERY_LOCK_FILE, 0660);
        close(nFd);
    }
    else
    {
        syslog(LOG_AUTH | LOG_ERR, "recovery: create lock file failed: %m");
    }
}

/* Verify recovery file is safe to read: owned by root or current euid
 * (seclogin in gate mode), not a symlink, not writable by group or other.
 * Both root and the seclogin SUID owner are trusted writers. */
int check_file_safety(const char *pszPath)
{
    struct stat st;
    if (lstat(pszPath, &st) != 0)                              return -1;
    if (S_ISLNK(st.st_mode))                                   return -1;
    if (st.st_uid != 0 && st.st_uid != geteuid())              return -1;
    if (st.st_mode & S_IWOTH)                                  return -1;
    return 0;
}

static int count_codes(const char *pszPath)
{
    FILE *f = fopen(pszPath, "r");
    if (!f) return 0;
    char szLine[LINE_BUF] = {0};
    int nCount = 0;
    while (fgets(szLine, LINE_BUF, f))
        if (szLine[0] != '#' && szLine[0] != '\n' && szLine[0] != '\r') nCount++;
    fclose(f);
    return nCount;
}

static int write_recovery_file(const char *pszPath, const char *pszTmpPath,
                                char aszLines[][LINE_BUF], int nLines)
{
    int fd = open(pszTmpPath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;

    for (int i = 0; i < nLines; i++) {
        size_t nLen = strlen(aszLines[i]);
        if (write(fd, aszLines[i], nLen) != (ssize_t)nLen) {
            close(fd); unlink(pszTmpPath); return -1;
        }
    }

    if (fsync(fd) != 0) { close(fd); unlink(pszTmpPath); return -1; }
    close(fd);

    if (rename(pszTmpPath, pszPath) != 0) { unlink(pszTmpPath); return -1; }

    /* fsync parent dir (the recovery subdirectory) to persist the rename */
    int nDirFd = open(RECOVERY_DIR, O_RDONLY | O_DIRECTORY);
    if (nDirFd >= 0) { fsync(nDirFd); close(nDirFd); }

    return 0;
}

/* --- public API --------------------------------------------------- */

int recovery_generate(void)
{
    char aszCodes[CODE_COUNT][CODE_STR_LEN]  = {{0}};
    char aszHashed[CODE_COUNT][LINE_BUF]     = {{0}};

    for (int i = 0; i < CODE_COUNT; i++) {
        if (generate_code(aszCodes[i]) != 0) {
            fprintf(stderr, "recovery_generate: RAND_bytes failed\n");
            return -1;
        }
        if (hash_code(aszCodes[i], aszHashed[i], LINE_BUF) != 0) {
            fprintf(stderr, "recovery_generate: hash failed\n");
            return -1;
        }
    }

    /* Create recovery subdirectory before writing — must exist before write_recovery_file */
    set_recovery_file_perms();

    if (write_recovery_file(RECOVERY_FILE, RECOVERY_FILE_TMP,
                             aszHashed, CODE_COUNT) != 0) {
        fprintf(stderr, "recovery_generate: write failed: %s\n", strerror(errno));
        return -1;
    }
    /* Re-apply perms after write to ensure recovery.conf has correct ownership */
    set_recovery_file_perms();

    printf("\nStore these recovery codes securely.\n");
    printf("Each code can only be used once.\n");
    printf("Previous recovery codes are now invalid.\n\n");
    for (int i = 0; i < CODE_COUNT; i++)
        printf("  %s\n", aszCodes[i]);
    printf("\n");

    for (int i = 0; i < CODE_COUNT; i++)
        OPENSSL_cleanse(aszCodes[i], CODE_STR_LEN);

    openlog("seclogin", LOG_PID, LOG_AUTH);
    syslog(LOG_NOTICE, "recovery codes regenerated");
    closelog();
    return 0;
}

int recovery_list(void)
{
    int nCount = count_codes(RECOVERY_FILE);
    printf("\nRemaining: %d\n\n", nCount);
    return 0;
}

int recovery_verify(const char *pszCode, int *pnRemaining)
{
    openlog("seclogin", LOG_PID, LOG_AUTH);

    syslog(LOG_AUTH | LOG_DEBUG,
           "recovery_verify: uid=%d euid=%d gid=%d egid=%d",
           (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid());

    /* log directory and file permissions to diagnose access issues */
    {
        struct stat stDir = {0}, stFile = {0};
        if (stat(RECOVERY_DIR, &stDir) == 0)
            syslog(LOG_AUTH | LOG_DEBUG,
                   "recovery_verify: dir uid=%d gid=%d mode=%o",
                   (int)stDir.st_uid, (int)stDir.st_gid, (unsigned)(stDir.st_mode & 07777));
        else
            syslog(LOG_AUTH | LOG_DEBUG, "recovery_verify: stat dir failed: %m");

        if (stat(RECOVERY_FILE, &stFile) == 0)
            syslog(LOG_AUTH | LOG_DEBUG,
                   "recovery_verify: file uid=%d gid=%d mode=%o",
                   (int)stFile.st_uid, (int)stFile.st_gid, (unsigned)(stFile.st_mode & 07777));
        else
            syslog(LOG_AUTH | LOG_DEBUG, "recovery_verify: stat file failed: %m");
    }

    if (check_file_safety(RECOVERY_FILE) != 0)
    {
        syslog(LOG_AUTH | LOG_ERR,
               "recovery_verify: file safety check failed for %s: %m", RECOVERY_FILE);
        closelog();
        return RECOVERY_ERROR;
    }

    /* Lock file must be pre-created by recovery_generate (root).
     * Gate mode has no dir-write permission so cannot create it. */
    int nLockFd = open(RECOVERY_LOCK_FILE, O_RDONLY | O_NOFOLLOW);
    if (nLockFd < 0)
    {
        syslog(LOG_AUTH | LOG_ERR,
               "recovery_verify: cannot open lock file %s: %m", RECOVERY_LOCK_FILE);
        closelog();
        return RECOVERY_ERROR;
    }

    if (flock(nLockFd, LOCK_EX) != 0)
    {
        syslog(LOG_AUTH | LOG_ERR, "recovery_verify: flock failed: %m");
        close(nLockFd);
        closelog();
        return RECOVERY_ERROR;
    }

    FILE *f = fopen(RECOVERY_FILE, "r");
    if (!f)
    {
        syslog(LOG_AUTH | LOG_ERR,
               "recovery_verify: cannot open %s: %m", RECOVERY_FILE);
        flock(nLockFd, LOCK_UN);
        close(nLockFd);
        closelog();
        return RECOVERY_ERROR;
    }

    char aszLines[MAX_CODES_FILE][LINE_BUF] = {{0}};
    int nLines = 0, nMatchIdx = -1;
    char szLine[LINE_BUF] = {0};

    while (fgets(szLine, LINE_BUF, f) && nLines < MAX_CODES_FILE)
    {
        if (szLine[0] == '#' || szLine[0] == '\n' || szLine[0] == '\r') continue;
        if (nMatchIdx < 0)
        {
            int ret = verify_line(pszCode, szLine);
            if (ret == 1) { nMatchIdx = nLines; continue; }
        }
        size_t nLen = strlen(szLine);
        memcpy(aszLines[nLines], szLine, nLen + 1);
        nLines++;
    }
    fclose(f);

    if (nMatchIdx < 0)
    {
        syslog(LOG_AUTH | LOG_DEBUG,
               "recovery_verify: no matching code found (lines_read=%d)", nLines);
        flock(nLockFd, LOCK_UN);
        close(nLockFd);
        closelog();
        return RECOVERY_DENIED;
    }

    if (write_recovery_file(RECOVERY_FILE, RECOVERY_FILE_TMP,
                             aszLines, nLines) != 0)
    {
        syslog(LOG_AUTH | LOG_ERR,
               "recovery_verify: file rewrite failed path=%s tmp=%s uid=%d euid=%d: %m",
               RECOVERY_FILE, RECOVERY_FILE_TMP, (int)getuid(), (int)geteuid());
        flock(nLockFd, LOCK_UN);
        close(nLockFd);
        closelog();
        return RECOVERY_ERROR;
    }
    /* chmod only — cannot chown in gate mode (euid=seclogin, not root).
     * File ownership stays as euid of the writer; check_file_safety accepts
     * both root and seclogin as trusted owners. */
    chmod(RECOVERY_FILE, 0660);

    flock(nLockFd, LOCK_UN);
    close(nLockFd);
    closelog();

    if (pnRemaining)
        *pnRemaining = nLines;

    return RECOVERY_OK;
}
