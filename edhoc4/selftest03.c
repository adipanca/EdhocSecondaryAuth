/*
 * selftest03.c — in-process initiator<->responder handshake test for the
 * classical EAP-EDHOC methods 0..3 (edhoc03 core). Verifies both peers derive
 * the same MSK/EMSK and reports the on-wire message sizes.
 */
#include "edhoc03.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>

static int run_method(int method)
{
    edhoc03_creds ue, srv;
    uint8_t id_ue[E3_ID_CRED]  = { 0x00, 0x00, 0x01 };
    uint8_t id_srv[E3_ID_CRED] = { 0x00, 0x00, 0x02 };
    edhoc03_gen_creds(&ue, id_ue);
    edhoc03_gen_creds(&srv, id_srv);

    edhoc03_peer ue_pub, srv_pub;
    memcpy(ue_pub.sig_vk, ue.sig_vk, E3_ED_PK);
    memcpy(ue_pub.dh_pk, ue.dh_pk, E3_X_PK);
    memcpy(srv_pub.sig_vk, srv.sig_vk, E3_ED_PK);
    memcpy(srv_pub.dh_pk, srv.dh_pk, E3_X_PK);

    edhoc03_ctx ictx, rctx;
    edhoc03_init_initiator(&ictx, method, &ue, &srv_pub);
    edhoc03_init_responder(&rctx, &srv, &ue_pub);

    uint8_t m1[E3_MAX_MSG], m2[E3_MAX_MSG], m3[E3_MAX_MSG], m4[E3_MAX_MSG];
    size_t n1, n2, n3, n4;
    int rc;

    rc = edhoc03_i_make_msg1(&ictx, m1, sizeof(m1), &n1);
    if (rc != E3_OK) { printf("  m1 fail: %s\n", edhoc03_strerror(rc)); return 1; }

    rc = edhoc03_r_handle_msg1(&rctx, m1, n1, m2, sizeof(m2), &n2);
    if (rc != E3_OK) { printf("  m2 fail: %s\n", edhoc03_strerror(rc)); return 1; }

    rc = edhoc03_i_handle_msg2(&ictx, m2, n2, m3, sizeof(m3), &n3);
    if (rc != E3_OK) { printf("  m3 fail: %s\n", edhoc03_strerror(rc)); return 1; }

    rc = edhoc03_r_handle_msg3(&rctx, m3, n3, m4, sizeof(m4), &n4);
    if (rc != E3_OK) { printf("  r_msg3 fail: %s\n", edhoc03_strerror(rc)); return 1; }

    rc = edhoc03_i_handle_msg4(&ictx, m4, n4);
    if (rc != E3_OK) { printf("  i_msg4 fail: %s\n", edhoc03_strerror(rc)); return 1; }

    if (!ictx.done || !rctx.done) { printf("  not done\n"); return 1; }
    if (sodium_memcmp(ictx.msk, rctx.msk, E3_MSK_LEN) != 0) { printf("  MSK mismatch\n"); return 1; }
    if (sodium_memcmp(ictx.emsk, rctx.emsk, E3_EMSK_LEN) != 0) { printf("  EMSK mismatch\n"); return 1; }

    printf("  method %d PASS  sizes: msg1=%zu msg2=%zu msg3=%zu msg4=%zu (MSK/EMSK match)\n",
           method, n1, n2, n3, n4);
    return 0;
}

int main(void)
{
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
    int fails = 0;
    printf("edhoc03 selftest (classical methods 0..3)\n");
    for (int m = 0; m <= 3; m++)
        fails += run_method(m);
    printf(fails ? "FAILED (%d)\n" : "ALL PASS\n", fails);
    return fails ? 1 : 0;
}
