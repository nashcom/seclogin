/*
    Recovery code module -- test harness + CLI

    Usage:
        scratchcodes generate          generate 5 new codes
        scratchcodes list              show remaining count
        scratchcodes verify <code>     verify + consume a code
        scratchcodes test              run self-tests
*/

#include "scratchcodes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/crypto.h>

/* --- self-tests --------------------------------------------------- */

static int nPassCount = 0, nFailCount = 0;

#define CHECK(desc, expr) do { \
    int _r = (expr); \
    if (_r) { printf("  PASS  %s\n", desc); nPassCount++; } \
    else    { printf("  FAIL  %s\n", desc); nFailCount++; } \
} while(0)

static const char g_szAlphabet[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

static int count_dashes(const char *psz)
{
    int nCount = 0;
    for (; *psz; psz++)
        if (*psz == '-') nCount++;
    return nCount;
}

static int all_valid_chars(const char *psz)
{
    for (; *psz; psz++) {
        if (*psz == '-') continue;
        int bFound = 0;
        for (int j = 0; g_szAlphabet[j]; j++)
            if (*psz == g_szAlphabet[j]) { bFound = 1; break; }
        if (!bFound) return 0;
    }
    return 1;
}

static int file_line_count(void)
{
    FILE *f = fopen(RECOVERY_FILE, "r");
    int nCount = 0;
    char szBuf[256] = {0};
    if (f) {
        while (fgets(szBuf, 256, f))
            if (szBuf[0] != '#' && szBuf[0] != '\n' && szBuf[0] != '\r') nCount++;
        fclose(f);
    }
    return nCount;
}

static int run_tests(void)
{
    printf("=== scratchcodes self-test ===\n\n");

    /* -- code generation -- */
    printf("-- code generation --\n");
    char szCode[CODE_STR_LEN] = {0};
    CHECK("generate_code returns 0",    generate_code(szCode) == 0);
    CHECK("code length == 29",          (int)strlen(szCode) == CODE_STR_LEN - 1);
    CHECK("5 dashes present",           count_dashes(szCode) == 5);
    CHECK("all chars valid",            all_valid_chars(szCode));
    printf("  sample: %s\n\n", szCode);

    /* -- hash + verify -- */
    printf("-- hash + verify --\n");
    char szLine[256] = {0};
    CHECK("hash_code returns 0",        hash_code(szCode, szLine, 256) == 0);
    CHECK("line starts with scheme",    strncmp(szLine, "pbkdf2_sha512:", 14) == 0);
    CHECK("verify correct code -> 1",   verify_line(szCode, szLine) == 1);

    char szBad[CODE_STR_LEN] = {0};
    memcpy(szBad, szCode, CODE_STR_LEN);
    szBad[0] = (szBad[0] == 'A') ? 'B' : 'A';
    CHECK("verify wrong code -> 0",     verify_line(szBad, szLine) == 0);

    char szCorrupt[256] = {0};
    memcpy(szCorrupt, szLine, strlen(szLine) + 1);
    szCorrupt[20] ^= 0x01;
    CHECK("verify corrupt line -> <=0", verify_line(szCode, szCorrupt) <= 0);

    /* -- verify_line: malformed input -- */
    printf("\n-- verify_line malformed input --\n");
    CHECK("missing fields -> -1",  verify_line(szCode, "notavalidline\n") == -1);
    CHECK("wrong scheme -> -1",    verify_line(szCode, "md5:1000:AAAA:BBBB\n") == -1);
    CHECK("zero iterations -> -1", verify_line(szCode, "pbkdf2_sha512:0:AAAA:BBBB\n") == -1);
    CHECK("empty string -> -1",    verify_line(szCode, "\n") == -1);

    /* -- file safety checks -- */
    printf("\n-- file safety --\n");

    CHECK("missing file -> -1", check_file_safety("/tmp/scratchcodes_noexist_test") == -1);

    /* group-writable file */
    {
        const char *pszTmp = "/tmp/scratchcodes_gwtest";
        FILE *fTmp = fopen(pszTmp, "w");
        if (fTmp)
        {
            fputs("x\n", fTmp);
            fclose(fTmp);
        }
        chmod(pszTmp, 0660);
        CHECK("group-writable file -> -1", check_file_safety(pszTmp) == -1);
        unlink(pszTmp);
    }

    /* other-writable file */
    {
        const char *pszTmp = "/tmp/scratchcodes_owtest";
        FILE *fTmp = fopen(pszTmp, "w");
        if (fTmp)
        {
            fputs("x\n", fTmp);
            fclose(fTmp);
        }
        chmod(pszTmp, 0606);
        CHECK("other-writable file -> -1", check_file_safety(pszTmp) == -1);
        unlink(pszTmp);
    }

    /* symlink */
    {
        const char *pszTarget = "/tmp/scratchcodes_symtarget";
        const char *pszLink   = "/tmp/scratchcodes_symlink";
        FILE *fTmp = fopen(pszTarget, "w");
        if (fTmp)
        {
            fputs("x\n", fTmp);
            fclose(fTmp);
        }
        unlink(pszLink);
        if (symlink(pszTarget, pszLink) != 0)
            printf("  NOTE: symlink creation failed, skipping\n");
        CHECK("symlink -> -1", check_file_safety(pszLink) == -1);
        unlink(pszLink);
        unlink(pszTarget);
    }

    /* -- recovery_verify on missing file -- */
    printf("\n-- recovery_verify edge cases --\n");
    unlink(RECOVERY_FILE);
    CHECK("verify with missing file -> RECOVERY_ERROR",
          recovery_verify("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", NULL) == RECOVERY_ERROR);

    /* -- live file: generate -- */
    printf("\n-- live file test (writes to %s) --\n", RECOVERY_FILE);
    CHECK("recovery_generate returns 0",      recovery_generate() == 0);
    CHECK("5 entries in file after generate", file_line_count() == CODE_COUNT);

    /* -- verify round-trip --
     * Generate a single known code, write it as the only entry, then verify. */
    printf("\n-- verify round-trip --\n");
    char szKnown[CODE_STR_LEN] = {0};
    CHECK("generate known code", generate_code(szKnown) == 0);

    char szHLine[256] = {0};
    CHECK("hash known code", hash_code(szKnown, szHLine, 256) == 0);

    FILE *fApp = fopen(RECOVERY_FILE, "w");
    if (fApp)
    {
        fputs(szHLine, fApp);
        fclose(fApp);
    }

    int nBefore = file_line_count();

    int nRemaining = 0;
    int ret = recovery_verify(szKnown, &nRemaining);
    CHECK("verify known code -> RECOVERY_OK",      ret == RECOVERY_OK);
    CHECK("one entry consumed from file",          file_line_count() == nBefore - 1);
    CHECK("remaining count == 0",                 nRemaining == 0);

    int ret2 = recovery_verify(szKnown, NULL);
    CHECK("same code rejected -> RECOVERY_DENIED", ret2 == RECOVERY_DENIED);

    printf("\n=== %d passed, %d failed ===\n", nPassCount, nFailCount);
    return nFailCount ? 1 : 0;
}

/* --- main --------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "\nUsage: %s generate|list|verify <code>|test\n\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "test") == 0)
        return run_tests();

    if (strcmp(argv[1], "generate") == 0)
        return recovery_generate();

    if (strcmp(argv[1], "list") == 0)
        return recovery_list();

    if (strcmp(argv[1], "verify") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "\nUsage: %s verify <code>\n\n", argv[0]);
            return 1;
        }
        const char *pszSrc = getenv("SSH_CONNECTION");
        char szSrcIp[64] = "-";
        if (pszSrc)
        {
            strncpy(szSrcIp, pszSrc, 63);
            szSrcIp[63] = '\0';
            char *pszSp = strchr(szSrcIp, ' ');
            if (pszSp)
                *pszSp = '\0';
        }
        int nRemaining = 0;
        int ret = recovery_verify(argv[2], &nRemaining);
        if (ret == RECOVERY_OK)
            printf("\nRecovery code accepted. Remaining: %d\n\n", nRemaining);
        else if (ret == RECOVERY_DENIED)
            printf("\nRecovery code rejected.\n\n");
        return ret;
    }

    fprintf(stderr, "\nUnknown command: %s\n\n", argv[1]);
    return 1;
}
