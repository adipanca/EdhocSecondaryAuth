/*
 * selftest.c — In-process EAP-EDHOC method 4 v3 handshake test
 * (no ephemeral X-Wing; forward secrecy from one-time rotated static keys;
 * next keys in EAD_1 / EAD_2).
 *
 * Runs FIVE consecutive sessions per UE between two UEs and the DN-AAA:
 *   - the next responder key the UE receives equals the one the DN-AAA made;
 *   - each session: message_1..4, MSK/EMSK must match on both sides;
 *   - after each session both sides call edhoc4_commit(): the next session
 *     must use the rotated keys, and the old secret keys must be erased;
 *   - the responder resolves pk_A / VK_I from ID_CRED_I through a lookup
 *     callback (per-UE record), as in a multi-UE deployment;
 *   - two UEs: the DN-AAA picks the per-UE record (its one-time sk_B) from
 *     the EAP identity of the session (RADIUS User-Name), before EDHOC;
 *   - a stale-key check: re-running with the erased pre-rotation key fails.
 */
#include "edhoc4.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>

/* DN-AAA per-UE record: (own one-time X-Wing key for this UE, ID_CRED_I,
 * current pk_A, VK_I) */
typedef struct {
    char eap_identity[32];
    edhoc4_creds server;
    uint8_t id[E4_ID_CRED];
    uint8_t pk_a[E4_XWING_PK];
    uint8_t vk_i[E4_MLDSA_PK];
} ue_record;

static int lookup(const uint8_t id[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                  uint8_t vk_i[E4_MLDSA_PK], void *arg)
{
    ue_record *r = (ue_record *)arg;
    if (memcmp(id, r->id, E4_ID_CRED) != 0) return -1;
    memcpy(pk_a, r->pk_a, E4_XWING_PK);
    memcpy(vk_i, r->vk_i, E4_MLDSA_PK);
    return 0;
}

#define NUE 2
static ue_record db[NUE];

/* DN-AAA: select the per-UE record from the EAP identity of the session */
static ue_record *select_record(const char *eap_identity)
{
    for (int i = 0; i < NUE; i++)
        if (strcmp(eap_identity, db[i].eap_identity) == 0) return &db[i];
    return NULL;
}

static int run_session(int n, edhoc4_creds *ue, uint8_t ue_peer_pk[E4_XWING_PK],
                       int verbose)
{
    edhoc4_ctx I, R;
    uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    size_t n1, n2, n3, n4;
    int rc;

    char ident[32];
    snprintf(ident, sizeof(ident), "ue%02x@dn.example", ue->id_cred[2]);
    ue_record *rec = select_record(ident);      /* from EAP-Response/Identity */
    edhoc4_init_initiator(&I, ue, ue_peer_pk);
    if ((rc = edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1)) != E4_OK) return rc;
    if (!rec) return E4_ERR_PEER;
    edhoc4_creds *aaa = &rec->server;
    edhoc4_init_responder(&R, aaa, rec->pk_a);
    edhoc4_set_lookup(&R, lookup, rec);
    if ((rc = edhoc4_r_handle_msg1(&R, m1, n1, m2, sizeof(m2), &n2)) != E4_OK) return rc;
    if ((rc = edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3)) != E4_OK) return rc;
    if ((rc = edhoc4_r_handle_msg3(&R, m3, n3, m4, sizeof(m4), &n4)) != E4_OK) return rc;
    if ((rc = edhoc4_i_handle_msg4(&I, m4, n4)) != E4_OK) return rc;

    if (verbose)
        printf("  message_1 : %zu bytes\n  message_2 : %zu bytes\n"
               "  message_3 : %zu bytes\n  message_4 : %zu bytes\n"
               "  total     : %zu bytes\n", n1, n2, n3, n4, n1 + n2 + n3 + n4);

    int ok = memcmp(I.msk, R.msk, E4_MSK_LEN) == 0 &&
             memcmp(I.emsk, R.emsk, E4_EMSK_LEN) == 0 && I.done && R.done &&
             memcmp(I.peer_new_pk, R.new_pk, E4_XWING_PK) == 0 &&
             memcmp(R.peer_new_pk, I.new_pk, E4_XWING_PK) == 0;
    printf("  UE %02x run %d: MSK/EMSK/next keys %s\n", ue->id_cred[2], n, ok ? "MATCH" : "MISMATCH");
    if (!ok) return E4_ERR_MAC;

    /* rotate: UE installs NskA/NpkA and NpkB; DN-AAA installs NskB/NpkB and
     * the UE's next pk_A in the per-UE record; both erase the old sk. */
    uint8_t old_ue_sk[E4_XWING_SK];
    memcpy(old_ue_sk, ue->kem_sk, E4_XWING_SK);
    if ((rc = edhoc4_commit(&I, ue, ue_peer_pk)) != E4_OK) return rc;
    if ((rc = edhoc4_commit(&R, aaa, rec->pk_a)) != E4_OK) return rc;
    int rotated = memcmp(old_ue_sk, ue->kem_sk, E4_XWING_SK) != 0 &&
                  memcmp(ue->kem_pk, rec->pk_a, E4_XWING_PK) == 0 &&
                  memcmp(aaa->kem_pk, ue_peer_pk, E4_XWING_PK) == 0;
    sodium_memzero(old_ue_sk, sizeof(old_ue_sk));
    printf("  UE %02x run %d: rotation committed, old sk erased: %s\n", ue->id_cred[2], n,
           rotated ? "ok" : "BAD");
    return rotated ? E4_OK : E4_ERR_STATE;
}

int main(void)
{
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
    printf("[edhoc4 selftest v3] X-Wing + ML-DSA-44, rotation keys in EAD_1/EAD_2\n");

    edhoc4_creds ue[NUE];
    uint8_t ue_peer_pk[NUE][E4_XWING_PK];        /* each UE's copy of its pk_B */
    for (int i = 0; i < NUE; i++) {
        uint8_t idI[E4_ID_CRED] = { 0x00, 0x00, (uint8_t)(0x01 + i) };
        uint8_t idR[E4_ID_CRED] = { 0x00, 0x00, 0x02 };
        if (edhoc4_gen_creds(&ue[i], idI) != E4_OK ||
            edhoc4_gen_creds(&db[i].server, idR) != E4_OK) {
            fprintf(stderr, "credential generation failed\n"); return 1;
        }
        /* one ML-DSA-44 key for the DN-AAA, one X-Wing key per UE record */
        if (i > 0) {
            memcpy(db[i].server.sig_sk, db[0].server.sig_sk, E4_MLDSA_SK);
            memcpy(db[i].server.sig_vk, db[0].server.sig_vk, E4_MLDSA_PK);
        }
        memcpy(ue_peer_pk[i], db[i].server.kem_pk, E4_XWING_PK);
        memcpy(db[i].id, idI, E4_ID_CRED);
        snprintf(db[i].eap_identity, sizeof(db[i].eap_identity), "ue%02x@dn.example", idI[2]);
        memcpy(db[i].pk_a, ue[i].kem_pk, E4_XWING_PK);
        memcpy(db[i].vk_i, ue[i].sig_vk, E4_MLDSA_PK);
    }
    edhoc4_creds ue0_before = ue[0];             /* snapshot to test stale keys */

    for (int n = 1; n <= 5; n++)
        for (int i = 0; i < NUE; i++) {
            int rc = run_session(n, &ue[i], ue_peer_pk[i], n == 1 && i == 0);
            if (rc != E4_OK) {
                printf("\nRESULT: FAIL at UE %d run %d: %s\n", i, n, edhoc4_strerror(rc));
                return 1;
            }
        }

    /* stale-key check: UE 0 still holding its pre-rotation (erased) key pair
     * and the old pk_B must not complete a handshake. */
    edhoc4_ctx I, R;
    uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG];
    size_t n1, n2, n3;
    edhoc4_init_initiator(&I, &ue0_before, ue0_before.kem_pk /* placeholder */);
    memcpy(I.peer_kem_pk, db[0].server.kem_pk, E4_XWING_PK);   /* even with the current pk_B */
    int rc = edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1);
    ue_record *rec = (rc == E4_OK) ? select_record("ue01@dn.example") : NULL;
    if (rec) {
        edhoc4_init_responder(&R, &rec->server, rec->pk_a);
        edhoc4_set_lookup(&R, lookup, rec);
        rc = edhoc4_r_handle_msg1(&R, m1, n1, m2, sizeof(m2), &n2);
        if (rc == E4_OK) rc = edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3);
    } else rc = E4_ERR_PEER;
    printf("  stale pre-rotation key of UE 01: %s (%s)\n",
           rc == E4_OK ? "ACCEPTED (BAD)" : "rejected", edhoc4_strerror(rc));
    sodium_memzero(&ue0_before, sizeof(ue0_before));
    if (rc == E4_OK) { printf("\nRESULT: FAIL\n"); return 1; }

    printf("\nRESULT: PASS — 2 UEs x 5 runs, identical MSK/EMSK and next keys, per-UE keys rotated every run\n");
    return 0;
}
