/*
 * xwing_kat.c — X-Wing known-answer test against the test vectors of
 * draft-connolly-cfrg-xwing-kem-09, Appendix C: GenerateKeyPairDerand(seed)
 * must give pk, EncapsulateDerand(pk, eseed) must give (ct, ss), and
 * Decapsulate(ct, sk) must give ss.
 */
#include "edhoc4.h"
#include "xwing_kat_vectors.h"
#include <stdio.h>
#include <string.h>
#include <sodium.h>

int main(void)
{
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
    int n = (int)(sizeof(XWING_KAT) / sizeof(XWING_KAT[0])), fail = 0;
    for (int i = 0; i < n; i++) {
        const xwing_kat *v = &XWING_KAT[i];
        uint8_t pk[E4_XWING_PK], ct[E4_XWING_CT], ss_e[E4_XWING_SS], ss_d[E4_XWING_SS];
        int rc = edhoc4_xwing_selftest_kat(v->seed, v->eseed, pk, ct, ss_e, ss_d);
        int ok_pk = memcmp(pk, v->pk, sizeof(pk)) == 0;
        int ok_ct = memcmp(ct, v->ct, sizeof(ct)) == 0;
        int ok_se = memcmp(ss_e, v->ss, sizeof(ss_e)) == 0;
        int ok_sd = memcmp(ss_d, v->ss, sizeof(ss_d)) == 0;
        int ok = rc == E4_OK && ok_pk && ok_ct && ok_se && ok_sd;
        printf("  vector %d: pk %s, ct %s, ss(encaps) %s, ss(decaps) %s -> %s\n", i + 1,
               ok_pk ? "ok" : "BAD", ok_ct ? "ok" : "BAD", ok_se ? "ok" : "BAD",
               ok_sd ? "ok" : "BAD", ok ? "PASS" : "FAIL");
        fail |= !ok;
    }
    printf("RESULT: %s (%d X-Wing test vectors)\n", fail ? "FAIL" : "PASS", n);
    return fail;
}
