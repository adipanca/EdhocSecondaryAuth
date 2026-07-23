/*
 * selftest.c — In-process EAP-EDHOC method 4 (SIGMA XWING) handshake test.
 *
 * Runs the full initiator<->responder exchange (message_1..4) using the shared
 * edhoc4 core and checks that both parties derive identical MSK/EMSK. This is
 * the same core linked by FreeRADIUS and UERANSIM, so a PASS here means the two
 * live peers share a byte-identical crypto/serialization implementation.
 */
#include "edhoc4.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>

static int hexdump_eq(const char *label, const uint8_t *a, const uint8_t *b, size_t n)
{
    int eq = (memcmp(a, b, n) == 0);
    printf("  %-6s : %s (", label, eq ? "MATCH" : "MISMATCH");
    for (size_t i = 0; i < 8 && i < n; i++) printf("%02x", a[i]);
    printf("...)\n");
    return eq;
}

int main(void)
{
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    printf("[edhoc4 selftest] method 4 SIGMA XWING (X25519+ML-KEM-768 / ML-DSA-44)\n");

    /* provision long-term credentials */
    edhoc4_creds ue, aaa;
    uint8_t idI[E4_ID_CRED] = { 0x00, 0x00, 0x01 };
    uint8_t idR[E4_ID_CRED] = { 0x00, 0x00, 0x02 };
    if (edhoc4_gen_creds(&ue, idI) != E4_OK) { fprintf(stderr, "gen UE creds failed\n"); return 1; }
    if (edhoc4_gen_creds(&aaa, idR) != E4_OK) { fprintf(stderr, "gen AAA creds failed\n"); return 1; }
    printf("  provisioned UE + DN-AAA XWING + ML-DSA-44 credentials\n");

    edhoc4_ctx I, R;
    edhoc4_init_initiator(&I, &ue, aaa.kem_pk);
    edhoc4_init_responder(&R, &aaa, ue.kem_pk);

    uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    size_t n1, n2, n3, n4;
    int rc;

    rc = edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1);
    if (rc != E4_OK) { fprintf(stderr, "msg1: %s\n", edhoc4_strerror(rc)); return 1; }
    printf("  message_1 : %zu bytes\n", n1);

    rc = edhoc4_r_handle_msg1(&R, m1, n1, m2, sizeof(m2), &n2);
    if (rc != E4_OK) { fprintf(stderr, "handle msg1 / build msg2: %s\n", edhoc4_strerror(rc)); return 1; }
    printf("  message_2 : %zu bytes\n", n2);

    rc = edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3);
    if (rc != E4_OK) { fprintf(stderr, "handle msg2 / build msg3: %s\n", edhoc4_strerror(rc)); return 1; }
    printf("  message_3 : %zu bytes\n", n3);

    rc = edhoc4_r_handle_msg3(&R, m3, n3, m4, sizeof(m4), &n4);
    if (rc != E4_OK) { fprintf(stderr, "handle msg3 / build msg4: %s\n", edhoc4_strerror(rc)); return 1; }
    printf("  message_4 : %zu bytes\n", n4);

    rc = edhoc4_i_handle_msg4(&I, m4, n4);
    if (rc != E4_OK) { fprintf(stderr, "handle msg4: %s\n", edhoc4_strerror(rc)); return 1; }

    printf("[key confirmation]\n");
    int ok = 1;
    ok &= hexdump_eq("MSK",  I.msk,  R.msk,  E4_MSK_LEN);
    ok &= hexdump_eq("EMSK", I.emsk, R.emsk, E4_EMSK_LEN);
    ok &= hexdump_eq("TH4",  I.th4,  R.th4,  E4_HASH_LEN);
    /* ratchet keys: each side learned the other's next static public key */
    ok &= (memcmp(I.new_pk, R.peer_new_pk, E4_XWING_PK) == 0);   /* NpkA */
    ok &= (memcmp(R.new_pk, I.peer_new_pk, E4_XWING_PK) == 0);   /* NpkB */
    printf("  ratchet: NpkA %s, NpkB %s\n",
           memcmp(I.new_pk, R.peer_new_pk, E4_XWING_PK) == 0 ? "ok" : "BAD",
           memcmp(R.new_pk, I.peer_new_pk, E4_XWING_PK) == 0 ? "ok" : "BAD");

    if (!ok || !I.done || !R.done) {
        printf("\nRESULT: FAIL\n");
        return 1;
    }
    printf("\nRESULT: PASS — both peers derived identical MSK/EMSK\n");
    return 0;
}
