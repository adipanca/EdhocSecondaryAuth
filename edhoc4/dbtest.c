/*
 * dbtest.c — file-level tests of the method-4 key records (final v3
 * protocol): the DN-AAA store (edhoc4_db_*) and the UE's CUR/NEXT record
 * (edhoc4_ue_*), with failure injection, without radiusd.
 *
 *   1. 2 UEs x 5 sessions: MSK/EMSK match; after the commit + erasure the
 *      DN-AAA file holds one sk_B only, after the promotion the UE file
 *      holds no old sk_A (the old key bytes are absent from the files).
 *   2. failure injection, each followed by a normal session that must
 *      complete without re-provisioning:
 *        message_3 dropped          NEXT rejected -> fallback to CUR, NEXT replaced
 *        message_4 dropped          NEXT succeeds
 *        EAP-Success dropped        normal (the UE promoted after message_4)
 *        UE stopped after message_3 NEXT succeeds, or fallback if not committed
 *        DN-AAA stopped after commit, before message_4: NEXT succeeds
 *        forged EAP-Failure after message_1 while the DN-AAA committed NEXT:
 *                                   fallback to CUR is rejected, NEXT is kept,
 *                                   the next session on NEXT succeeds
 *        timeout after message_1    no fallback; the next session uses NEXT
 *   3. an unknown identity is rejected.
 */
#define _DEFAULT_SOURCE
#include "edhoc4.h"
#include "edhoc4_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sodium.h>

#define ROOT "dbtest.tmp"
#define DB   ROOT "/edhoc_db"

static int fails;

static void check(int ok, const char *what)
{
    printf("  %-66s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

static void mkdirs(const char *p)
{
    char t[512];
    snprintf(t, sizeof(t), "%s", p);
    for (char *s = t + 1; *s; s++)
        if (*s == '/') { *s = 0; mkdir(t, 0700); *s = '/'; }
    mkdir(t, 0700);
}

static void write_raw(const char *dir, const char *name, const void *b, size_t n)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (f) { fwrite(b, 1, n, f); fclose(f); }
}

static void ue_path(const char *id, char *p, size_t cap) { snprintf(p, cap, ROOT "/ue/%s/ue.rec", id); }
static void dn_path(const char *id, char *p, size_t cap) { snprintf(p, cap, DB "/%s/rec.bin", id); }

static void provision(const char *id, uint8_t idx, const edhoc4_creds *dn_sig)
{
    edhoc4_creds srv, ue;
    uint8_t id_srv[E4_ID_CRED] = { 0, 0, 2 }, id_ue[E4_ID_CRED] = { 0, 0, idx };
    char d[512], p[512];
    edhoc4_gen_creds(&srv, id_srv);
    memcpy(srv.sig_sk, dn_sig->sig_sk, E4_MLDSA_SK);
    memcpy(srv.sig_vk, dn_sig->sig_vk, E4_MLDSA_PK);
    edhoc4_gen_creds(&ue, id_ue);
    snprintf(d, sizeof(d), DB "/%s", id); mkdirs(d);
    dn_path(id, p, sizeof(p));
    edhoc4_rec_create(p, &srv, ue.kem_pk);
    write_raw(d, "ue.vk", ue.sig_vk, E4_MLDSA_PK);
    write_raw(d, "id_cred", ue.id_cred, E4_ID_CRED);
    snprintf(d, sizeof(d), ROOT "/ue/%s", id); mkdirs(d);
    ue_path(id, p, sizeof(p));
    edhoc4_rec_create(p, &ue, srv.kem_pk);
}

/* does the file contain these bytes anywhere? */
static int file_has(const char *path, const uint8_t *needle, size_t n)
{
    static uint8_t buf[1 << 16];
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    for (size_t i = 0; i + n <= len; i++)
        if (memcmp(buf + i, needle, n) == 0) return 1;
    return 0;
}

static int valid_slots(const char *path)
{
    edhoc4_creds c; edhoc4_rec_info info;
    if (edhoc4_rec_load(path, -1, &c, NULL, &info) != E4_OK) return 0;
    sodium_memzero(&c, sizeof(c));
    return info.valid[0] + info.valid[1];
}

enum fault { F_NONE, F_DROP_M3, F_DROP_M4, F_DROP_SUCCESS, F_UE_STOP_M3_LOST,
             F_UE_STOP_M3_DONE, F_DN_STOP_COMMIT, F_FORGED_FAILURE, F_TIMEOUT };

typedef struct {
    int ok;            /* message_4 verified, MSK/EMSK match */
    int fallback;      /* retried on CUR after an explicit EAP-Failure */
    int rejected;      /* every attempt got an explicit EAP-Failure */
    int used_next;
} result;

/* One session of UE `id`; `fault` disturbs it at the given point. An
 * explicit EAP-Failure before message_2 on NEXT triggers one retry on CUR
 * (NEXT kept); a timeout does not. */
static int session(const char *id, enum fault fault, result *res)
{
    char up[512];
    edhoc4_ue_state st;
    edhoc4_ctx I, R;
    edhoc4_db_rec rec;
    static uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    size_t n1, n2, n3, n4;
    int rc, attempt = 0;

    memset(res, 0, sizeof(*res));
    ue_path(id, up, sizeof(up));
    if ((rc = edhoc4_ue_load(up, &st)) != E4_OK) return rc;
    res->used_next = st.using_next;
    for (;;) {
        edhoc4_init_initiator(&I, &st.self, st.peer_pk);
        if ((rc = edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1)) != E4_OK) return rc;
        if (attempt == 0 && fault == F_TIMEOUT) {          /* no answer at all */
            edhoc4_ctx_wipe(&I); edhoc4_ue_state_wipe(&st);
            return E4_OK;
        }
        if (attempt == 0 && fault == F_FORGED_FAILURE)
            rc = E4_ERR_AEAD;                              /* attacker's EAP-Failure */
        else
            rc = edhoc4_db_handle_msg1(DB, id, &R, &rec, m1, n1, m2, sizeof(m2), &n2);
        if (rc == E4_OK) break;
        edhoc4_ctx_wipe(&I);
        if (st.using_next && attempt == 0) {               /* explicit EAP-Failure on NEXT */
            if ((rc = edhoc4_ue_fallback(up, &st)) != E4_OK) return rc;
            res->fallback = 1;
            attempt++;
            continue;
        }
        res->rejected = 1;                                 /* keep both slots */
        edhoc4_ue_state_wipe(&st);
        return E4_OK;
    }

    if ((rc = edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3)) != E4_OK) return rc;
    /* write-ahead: NEXT is durable before message_3 leaves */
    if ((rc = edhoc4_ue_store_next(up, &st, &I)) != E4_OK) return rc;
    if (fault == F_DROP_M3 || fault == F_UE_STOP_M3_LOST) {
        edhoc4_ctx_wipe(&I); edhoc4_ctx_wipe(&R); edhoc4_db_rec_wipe(&rec); edhoc4_ue_state_wipe(&st);
        return E4_OK;
    }

    if ((rc = edhoc4_r_handle_msg3(&R, m3, n3, m4, sizeof(m4), &n4)) != E4_OK) return rc;
    int keys_match = memcmp(I.msk, R.msk, E4_MSK_LEN) == 0 &&
                     memcmp(I.emsk, R.emsk, E4_EMSK_LEN) == 0;
    if ((rc = edhoc4_db_commit(&R, &rec)) != E4_OK) return rc;
    if (fault == F_DN_STOP_COMMIT) {
        /* DN-AAA dies before message_4 and before the erasure; its next
         * message_1 for this UE erases the old sk_B */
        edhoc4_ctx_wipe(&I); edhoc4_db_rec_wipe(&rec); edhoc4_ue_state_wipe(&st);
        return E4_OK;
    }
    edhoc4_db_erase_old(&rec);                    /* after message_4 is sent */
    edhoc4_db_rec_wipe(&rec);
    if (fault == F_DROP_M4 || fault == F_UE_STOP_M3_DONE) {
        edhoc4_ctx_wipe(&I); edhoc4_ue_state_wipe(&st);
        return E4_OK;
    }

    if ((rc = edhoc4_i_handle_msg4(&I, m4, n4)) != E4_OK) return rc;
    if ((rc = edhoc4_ue_promote(up, &st)) != E4_OK) return rc;   /* after message_4 */
    edhoc4_ctx_wipe(&I);
    edhoc4_ue_state_wipe(&st);
    /* F_DROP_SUCCESS: the UE verified message_4 and promoted; losing the
     * EAP-Success afterwards changes no key state */
    res->ok = keys_match;
    return E4_OK;
}

/* a normal session that checks the erasure of the keys it replaced */
static int normal_session(const char *id, int *fallback)
{
    char up[512], dp[512];
    edhoc4_creds dn_old, ue_cur, ue_other;
    edhoc4_rec_info info;
    result r;
    ue_path(id, up, sizeof(up));
    dn_path(id, dp, sizeof(dp));
    edhoc4_rec_load(dp, -1, &dn_old, NULL, NULL);
    /* every UE key on file before the session (CUR, NEXT) must be gone after */
    edhoc4_rec_load(up, -1, &ue_cur, NULL, &info);
    int two = info.valid[1 - info.active];
    if (two) edhoc4_rec_load(up, 1 - info.active, &ue_other, NULL, NULL);
    int rc = session(id, F_NONE, &r);
    if (fallback) *fallback = r.fallback;
    int ok = rc == E4_OK && r.ok &&
             valid_slots(dp) == 1 && valid_slots(up) == 1 &&
             !file_has(dp, dn_old.kem_sk, 64) &&
             !file_has(up, ue_cur.kem_sk, 64) &&
             (!two || !file_has(up, ue_other.kem_sk, 64));
    sodium_memzero(&dn_old, sizeof(dn_old));
    sodium_memzero(&ue_cur, sizeof(ue_cur));
    sodium_memzero(&ue_other, sizeof(ue_other));
    return ok;
}

static int ue_has_next(const char *id)
{
    char up[512];
    edhoc4_ue_state st;
    ue_path(id, up, sizeof(up));
    if (edhoc4_ue_load(up, &st) != E4_OK) return -1;
    int n = st.using_next;
    edhoc4_ue_state_wipe(&st);
    return n;
}

int main(void)
{
    if (sodium_init() < 0) return 1;
    if (system("rm -rf " ROOT) != 0) return 1;
    edhoc4_creds dn_sig;
    uint8_t id_srv[E4_ID_CRED] = { 0, 0, 2 };
    edhoc4_gen_creds(&dn_sig, id_srv);
    provision("ue-a", 1, &dn_sig);
    provision("ue-b", 2, &dn_sig);
    printf("[edhoc4 dbtest v3 final] record by EAP identity, CUR/NEXT, no grace key\n");

    /* ---- 1. 2 UEs x 5 sessions ---- */
    int ok_all = 1;
    for (int n = 0; n < 5; n++)
        for (int u = 0; u < 2; u++)
            ok_all &= normal_session(u ? "ue-b" : "ue-a", NULL);
    check(ok_all, "2 UEs x 5 sessions: keys match, one sk_B / no old sk_A on file");

    /* ---- 2. failure injection: fault, then one normal session ---- */
    static const struct { enum fault f; const char *name; int want_next, want_fb; } cases[] = {
        { F_DROP_M3,         "message_3 dropped",                 1, 1 },
        { F_DROP_M4,         "message_4 dropped",                 1, 0 },
        { F_DROP_SUCCESS,    "EAP-Success dropped",               0, 0 },
        { F_UE_STOP_M3_LOST, "UE stopped after message_3 (lost)", 1, 1 },
        { F_UE_STOP_M3_DONE, "UE stopped after message_3 (rcvd)", 1, 0 },
        { F_DN_STOP_COMMIT,  "DN-AAA stopped after commit",       1, 0 },
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        result r;
        char what[128];
        int rc = session("ue-a", cases[k].f, &r);
        int next_ok = ue_has_next("ue-a") == cases[k].want_next;
        int fb = -1;
        int next = normal_session("ue-a", &fb);
        snprintf(what, sizeof(what), "%s: next session ok, fallback=%d", cases[k].name, fb);
        check(rc == E4_OK && next_ok && next && fb == cases[k].want_fb, what);
    }

    /* forged EAP-Failure: bring the UE to NEXT with the DN-AAA committed
     * (message_4 lost), then forge a Failure on the NEXT attempt */
    {
        result r0, r1;
        int fb = -1;
        session("ue-a", F_DROP_M4, &r0);
        int rc = session("ue-a", F_FORGED_FAILURE, &r1);
        int kept = ue_has_next("ue-a") == 1;
        int next = normal_session("ue-a", &fb);
        check(rc == E4_OK && r1.fallback && r1.rejected && kept && next && fb == 0,
              "forged EAP-Failure: CUR rejected, NEXT kept, then NEXT ok");
    }
    /* timeout after message_1: no fallback, the next session uses NEXT */
    {
        result r0, r1;
        int fb = -1;
        session("ue-a", F_DROP_M4, &r0);
        int rc = session("ue-a", F_TIMEOUT, &r1);
        int kept = ue_has_next("ue-a") == 1;
        int next = normal_session("ue-a", &fb);
        check(rc == E4_OK && !r1.fallback && kept && next && fb == 0,
              "timeout after message_1: no fallback, then NEXT ok");
    }

    /* ---- 3. unknown identity ---- */
    edhoc4_ctx R; edhoc4_db_rec rec;
    uint8_t m2[E4_MAX_MSG], junk[64] = { 0 };
    size_t n2;
    check(edhoc4_db_handle_msg1(DB, "nobody", &R, &rec, junk, sizeof(junk), m2, sizeof(m2), &n2) == E4_ERR_PEER,
          "unknown identity rejected (before any KEM)");
    check(edhoc4_db_handle_msg1(DB, "../ue-a", &R, &rec, junk, sizeof(junk), m2, sizeof(m2), &n2) == E4_ERR_PEER,
          "path-like identity rejected");

    sodium_memzero(&dn_sig, sizeof(dn_sig));
    printf("\nRESULT: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
