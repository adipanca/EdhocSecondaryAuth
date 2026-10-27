/*
 * dbtest.c — file-backed rotation test for the DN-AAA record store
 * (edhoc4_db.c) and the UE-side atomic persistence, without radiusd.
 *
 *   edhoc4_dbtest [workdir]
 *
 * Provisions two UEs with ./edhoc4_keygen, then checks:
 *   - consecutive sessions succeed and rotate ue.creds / server.creds on disk;
 *   - a lost message_4 is recovered through prev/ (grace key);
 *   - a stale pre-rotation UE key is rejected once prev/ is erased;
 *   - an unknown EAP identity is resolved by trial decapsulation.
 */
#include "edhoc4.h"
#include "edhoc4_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

static char root[512], db[600];

static void digest(const char *p, uint8_t h[32])
{
    static uint8_t buf[16384];
    FILE *f = fopen(p, "rb");
    size_t n = f ? fread(buf, 1, sizeof(buf), f) : 0;
    if (f) fclose(f);
    crypto_hash_sha256(h, buf, n);
}

/* one EAP-EDHOC run; UE files under <root>/ue/<ue_id>/, the DN-AAA picks the
 * record from `eap_identity`. drop_m4: message_4 never reaches the UE. */
static int session(const char *ue_id, const char *eap_identity, int drop_m4, int *used_prev)
{
    char cp[700], pp[700];
    edhoc4_creds ue; uint8_t srv_pk[E4_XWING_PK];
    edhoc4_ctx I, R; edhoc4_db_rec rec;
    static uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    size_t n1, n2, n3, n4;
    uint8_t msk_r[E4_MSK_LEN];
    int rc;

    snprintf(cp, sizeof(cp), "%s/ue/%s/ue.creds", root, ue_id);
    snprintf(pp, sizeof(pp), "%s/ue/%s/server.pub", root, ue_id);
    if (edhoc4_creds_load(cp, &ue) || edhoc4_pub_load(pp, srv_pk)) return E4_ERR_ARG;

    edhoc4_init_initiator(&I, &ue, srv_pk);
    if ((rc = edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1)) != E4_OK) return rc;
    memset(&rec, 0, sizeof(rec));
    if ((rc = edhoc4_db_handle_msg1(db, eap_identity, &R, &rec, m1, n1, m2, sizeof(m2), &n2)) != E4_OK) return rc;
    if (used_prev) *used_prev = rec.used_prev;
    if ((rc = edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3)) != E4_OK) return rc;
    if ((rc = edhoc4_r_handle_msg3(&R, m3, n3, m4, sizeof(m4), &n4)) != E4_OK) return rc;

    memcpy(msk_r, R.msk, E4_MSK_LEN);                /* export, then commit */
    if ((rc = edhoc4_db_commit(&R, &rec)) != E4_OK) return rc;
    edhoc4_db_rec_wipe(&rec);
    if (drop_m4) { edhoc4_ctx_wipe(&I); return E4_OK; }

    if ((rc = edhoc4_i_handle_msg4(&I, m4, n4)) != E4_OK) return rc;
    if (sodium_memcmp(msk_r, I.msk, E4_MSK_LEN) != 0) return E4_ERR_MAC;
    if ((rc = edhoc4_commit(&I, &ue, srv_pk)) != E4_OK) return rc;
    if ((rc = edhoc4_creds_save_atomic(cp, &ue)) != E4_OK) return rc;
    return edhoc4_pub_save_atomic_raw(pp, srv_pk);
}

static int fails;
static void check(int ok, const char *what)
{
    printf("  %-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

int main(int argc, char **argv)
{
    char cmd[1200], p_ue[700], p_srv[700];
    uint8_t h_ue[3][32], h_srv[3][32];
    int used_prev = -1;

    if (sodium_init() < 0) return 1;
    snprintf(root, sizeof(root), "%s", argc > 1 ? argv[1] : "dbtest.tmp");
    snprintf(db, sizeof(db), "%s/edhoc_db", root);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s' && ./edhoc4_keygen '%s' ue-a ue-b >/dev/null", root, root);
    if (system(cmd) != 0) { fprintf(stderr, "provisioning failed\n"); return 1; }
    snprintf(p_ue, sizeof(p_ue), "%s/ue/ue-a/ue.creds", root);
    snprintf(p_srv, sizeof(p_srv), "%s/edhoc_db/ue-a/server.creds", root);

    printf("[edhoc4 dbtest] per-UE record store, rotation persistence\n");
    for (int i = 0; i < 3; i++) {
        digest(p_ue, h_ue[i]); digest(p_srv, h_srv[i]);
        char what[80];
        snprintf(what, sizeof(what), "ue-a session %d", i + 1);
        check(session("ue-a", "ue-a", 0, NULL) == E4_OK, what);
    }
    check(memcmp(h_ue[0], h_ue[1], 32) && memcmp(h_ue[1], h_ue[2], 32),
          "ue.creds changes every session");
    check(memcmp(h_srv[0], h_srv[1], 32) && memcmp(h_srv[1], h_srv[2], 32),
          "edhoc_db/ue-a/server.creds changes every session");
    check(session("ue-b", "ue-b", 0, NULL) == E4_OK, "ue-b session (independent record)");

    /* lost message_4 -> next session through prev/ */
    check(session("ue-a", "ue-a", 1, NULL) == E4_OK, "ue-a session, message_4 dropped");
    check(session("ue-a", "ue-a", 0, &used_prev) == E4_OK && used_prev == 1,
          "next session recovers through prev/ (grace key)");
    check(session("ue-a", "ue-a", 0, &used_prev) == E4_OK && used_prev == 0,
          "following session uses the active record");

    /* stale key: keep a copy, rotate twice (prev/ erased), restore it */
    char stale_cmd[1600];
    snprintf(stale_cmd, sizeof(stale_cmd), "cp -r '%s/ue/ue-a' '%s/stale'", root, root);
    if (system(stale_cmd) != 0) return 1;
    check(session("ue-a", "ue-a", 0, NULL) == E4_OK, "ue-a session (stale copy taken before)");
    check(session("ue-a", "ue-a", 0, NULL) == E4_OK, "ue-a session (prev/ erased)");
    snprintf(stale_cmd, sizeof(stale_cmd), "rm -rf '%s/ue/ue-a' && mv '%s/stale' '%s/ue/ue-a'", root, root, root);
    if (system(stale_cmd) != 0) return 1;
    int rc = session("ue-a", "ue-a", 0, NULL);
    printf("    stale key -> %s\n", edhoc4_strerror(rc));
    check(rc != E4_OK, "stale pre-rotation UE key rejected");

    /* unknown identity -> trial decapsulation */
    check(session("ue-b", "anonymous", 0, NULL) == E4_OK, "unknown identity: trial decapsulation finds ue-b");
    check(session("ue-b", "ue-b", 0, NULL) == E4_OK, "ue-b session after trial");

    printf("\nRESULT: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
