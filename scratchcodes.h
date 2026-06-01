#ifndef SCRATCHCODES_H
#define SCRATCHCODES_H

/* Recovery code module for seclogin.
 * File: /etc/seclogin/recovery.conf  owner: root:seclogin  mode: 0640 */

#define RECOVERY_FILE       "/etc/seclogin/recovery.conf"
#define RECOVERY_FILE_TMP   "/etc/seclogin/recovery.conf.tmp"
#define RECOVERY_LOCK_FILE  "/etc/seclogin/recovery.lock"

#define CODE_COUNT          5
/* "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX\0" = 6*4 + 5 dashes + NUL */
#define CODE_STR_LEN        30

/* --- return codes ------------------------------------------------- */

#define RECOVERY_OK         0   /* code accepted and consumed       */
#define RECOVERY_DENIED     1   /* code not found / already used    */
#define RECOVERY_ERROR     -1   /* system or internal error         */

/* --- public API --------------------------------------------------- */

/* Generate CODE_COUNT new codes, print plaintext once, store hashed. */
int recovery_generate(void);

/* Print count of remaining codes. */
int recovery_list(void);

/* Verify and consume one recovery code.
 * On RECOVERY_OK, *pnRemaining is set to the number of codes left (may be NULL).
 * Returns: RECOVERY_OK / RECOVERY_DENIED / RECOVERY_ERROR. */
int recovery_verify(const char *pszCode, int *pnRemaining);

/* --- internal functions (exposed for unit testing) ---------------- */

int generate_code(char *pszBuf);    /* pszBuf must be CODE_STR_LEN bytes */
int hash_code(const char *pszCode, char *pszOut, int nOutMax);
int verify_line(const char *pszCode, const char *pszLine);
int b64_encode(const unsigned char *pbSrc, int nSrcLen, char *pszDst, int nDstMax);
int b64_decode(const char *pszSrc, unsigned char *pbDst, int nDstMax);
int check_file_safety(const char *pszPath);

#endif /* SCRATCHCODES_H */
