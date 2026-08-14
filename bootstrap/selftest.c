/*
 * selftest.c — bootstrap.c self-test / parity vector emitter.
 *
 * Usage:
 *   ./bootstrap_selftest              # random EMSK, prints fingerprints
 *   ./bootstrap_selftest <emsk-hex>   # deterministic vectors for interop check
 *
 * With an EMSK hex argument it prints hex of USRK, DSRK, OSCORE master
 * secret/salt and the UE-side sender/recipient keys + common IV, so
 * bootstrap_interop.py can assert the C and Python schedules are identical.
 */
#include "bootstrap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

static void put_hex(const char *name, const uint8_t *b, size_t n)
{
    printf("%s=", name);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    uint8_t emsk[BK_EMSK_LEN];
    if (argc > 1) {
        size_t hexlen = strlen(argv[1]);
        if (hexlen != BK_EMSK_LEN * 2) {
            fprintf(stderr, "emsk hex must be %d chars\n", BK_EMSK_LEN * 2);
            return 1;
        }
        if (sodium_hex2bin(emsk, sizeof(emsk), argv[1], hexlen, NULL, NULL, NULL) != 0) {
            fprintf(stderr, "bad emsk hex\n");
            return 1;
        }
    } else {
        randombytes_buf(emsk, sizeof(emsk));
    }

    uint8_t usrk[BK_USRK_LEN], dsrk[BK_DSRK_LEN];
    bk_derive_usrk(emsk, sizeof(emsk), BK_USRK_KEY_LABEL, usrk, sizeof(usrk));
    bk_derive_dsrk(usrk, sizeof(usrk), BK_DSRK_DOMAIN_LABEL, dsrk, sizeof(dsrk));

    uint8_t ms[BK_OSCORE_MS_LEN], salt[BK_OSCORE_SALT_LEN];
    bk_derive_oscore_master_secret(dsrk, sizeof(dsrk), ms);
    bk_derive_oscore_master_salt(dsrk, sizeof(dsrk), salt);

    bk_oscore_ctx ue, as;
    bk_derive_oscore_context(ms, salt, /*sender*/1, /*recipient*/0, &ue);
    bk_derive_oscore_context(ms, salt, /*sender*/0, /*recipient*/1, &as);

    /* correctness: UE sender key == AS recipient key, and vice versa */
    int ok = (memcmp(ue.sender_key, as.recipient_key, BK_OSCORE_KEY_LEN) == 0)
          && (memcmp(ue.recipient_key, as.sender_key, BK_OSCORE_KEY_LEN) == 0)
          && (memcmp(ue.common_iv, as.common_iv, BK_OSCORE_IV_LEN) == 0);

    if (argc > 1) {
        put_hex("USRK", usrk, sizeof(usrk));
        put_hex("DSRK", dsrk, sizeof(dsrk));
        put_hex("OSCORE_MS", ms, sizeof(ms));
        put_hex("OSCORE_SALT", salt, sizeof(salt));
        put_hex("UE_SENDER_KEY", ue.sender_key, BK_OSCORE_KEY_LEN);
        put_hex("UE_RECIPIENT_KEY", ue.recipient_key, BK_OSCORE_KEY_LEN);
        put_hex("COMMON_IV", ue.common_iv, BK_OSCORE_IV_LEN);
    } else {
        char fp[17];
        bk_fingerprint(usrk, sizeof(usrk), fp); printf("USRK  fp: %s\n", fp);
        bk_fingerprint(dsrk, sizeof(dsrk), fp); printf("DSRK  fp: %s\n", fp);
        bk_fingerprint(ms, sizeof(ms), fp);     printf("OSCORE master secret fp: %s\n", fp);
    }
    printf("context correspondence: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
