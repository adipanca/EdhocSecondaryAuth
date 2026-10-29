/*
 * dbtest.c — file-level tests of the method-4 v3 key records: the DN-AAA
 * store with its pseudonym index (edhoc4_db_*) and the UE's CUR/NEXT
 * record (edhoc4_ue_*), with failure injection, without radiusd.
 *
 *   1. 2 UEs x 5 sessions: MSK/EMSK match, the pseudonym changes every
 *      session and never repeats, after the commit + erasure the DN-AAA
 *      file holds one sk_B only, after the promotion the UE file holds no
 *      old sk_A (the old key bytes are absent from the files).
 *   2. failure injection, each followed by a normal session that must
 *      complete without re-provisioning and with at most one fallback:
 *      message_3 dropped, message_4 dropped, EAP-Success dropped, UE
 *      stopped after sending message_3 (before / after the DN-AAA got it),
 *      DN-AAA stopped after its commit and before message_4.
 *   3. an unknown, a malformed and an already used pseudonym are rejected
 *      with E4_ERR_PSEUDO.
 */
#define _DEFAULT_SOURCE
#include "edhoc4.h"
#include "edhoc4_db.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>

#define ROOT  "dbtest.tmp"
#define DB    ROOT "/edhoc_db"
#define REALM "dn.example"

static int fails;

static void check(int ok, const char *what)
{
    printf("  %-62s %s\n", what, ok ? "ok" : "FAIL");
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

static void dn_dir(const char *uid, char *d, size_t cap) { snprintf(d, cap, DB "/%s", uid); }
static void ue_path(const char *uid, char *p, size_t cap) { snprintf(p, cap, ROOT "/ue/%s/ue.rec", uid); }
static void dn_path(const char *uid, char *p, size_t cap) { snprintf(p, cap, DB "/%s/rec.bin", uid); }

static void provision(const char *uid, uint8_t idx, const edhoc4_creds *dn_sig)
{
    edhoc4_creds srv, ue;
    uint8_t id_srv[E4_ID_CRED] = { 0, 0, 2 }, id_ue[E4_ID_CRED] = { 0, 0, idx };
    uint8_t p0[E4_PSEUDO_LEN];
    char d[512], p[512];
    edhoc4_gen_creds(&srv, id_srv);
    memcpy(srv.sig_sk, dn_sig->sig_sk, E4_MLDSA_SK);
    memcpy(srv.sig_vk, dn_sig->sig_vk, E4_MLDSA_PK);
    edhoc4_gen_creds(&ue, id_ue);
    randombytes_buf(p0, sizeof(p0));
    dn_dir(uid, d, sizeof(d)); mkdirs(d);
    dn_path(uid, p, sizeof(p));
    edhoc4_rec_create(p, &srv, ue.kem_pk, p0);
    write_raw(d, "ue.vk", ue.sig_vk, E4_MLDSA_PK);
    write_raw(d, "id_cred", ue.id_cred, E4_ID_CRED);
    snprintf(d, sizeof(d), ROOT "/ue/%s", uid); mkdirs(d);
    ue_path(uid, p, sizeof(p));
    edhoc4_rec_create(p, &ue, srv.kem_pk, p0);
}

/* does the file contain these bytes anywhere? */
static int file_has(const char *path, const uint8_t *needle, size_t n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    static uint8_t buf[1 << 16];
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    for (size_t i = 0; i + n <= len; i++)
        if (memcmp(buf + i, needle, n) == 0) return 1;
    return 0;
}

static int valid_slots(const char *path)
{
    edhoc4_creds c; edhoc4_rec_info info;
    if (edhoc4_rec_load(path, 0, &c, NULL, NULL, &info) != E4_OK) return 0;
    sodium_memzero(&c, sizeof(c));
    return info.valid[0] + info.valid[1];
}

enum fault { F_NONE, F_DROP_M3, F_DROP_M4, F_DROP_SUCCESS, F_UE_STOP_M3_LOST,
             F_UE_STOP_M3_DONE, F_DN_STOP_COMMIT };

typedef struct {
    int ok, fallback, used_next;
    uint8_t pseudo[E4_PSEUDO_LEN];     /* pseudonym the session ran under */
    uint8_t pnext[E4_PSEUDO_LEN];
} result;

/* One session of UE `uid`; `fault` stops it at the given point. */
static int session(const char *uid, enum fault fault, result *res)
{
    char up[512], nai[80];
    edhoc4_ue_state st;
    edhoc4_ctx I, R;
    edhoc4_db_rec rec;
    static uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    size_t n1, n2, n3, n4;
    int rc;

    memset(res, 0, sizeof(*res));
    ue_path(uid, up, sizeof(up));
    if ((rc = edhoc4_ue_load(up, &st)) != E4_OK) return rc;
    res->used_next = st.using_next;
    for (;;) {
        edhoc4_pseudo_to_nai(st.pseudo, REALM, nai, sizeof(nai));
        edhoc4_init_initiator(&I, &st.self, st.peer_pk);
        if ((rc = edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1)) != E4_OK) return rc;
        rc = edhoc4_db_handle_msg1(DB, nai, &R, &rec, m1, n1, m2, sizeof(m2), &n2);
        if (rc == E4_ERR_PSEUDO && st.using_next && !res->fallback) {
            /* the DN-AAA never committed NEXT: drop it, retry once with CUR */
            edhoc4_ctx_wipe(&I);
            if ((rc = edhoc4_ue_fallback(up, &st)) != E4_OK) return rc;
            res->fallback = 1;
            continue;
        }
        if (rc != E4_OK) { edhoc4_ctx_wipe(&I); return rc; }
        break;
    }
    memcpy(res->pseudo, st.pseudo, E4_PSEUDO_LEN);
    edhoc4_ue_state_wipe(&st);

    if ((rc = edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3)) != E4_OK) return rc;
    /* write-ahead: NEXT is durable before message_3 leaves */
    if ((rc = edhoc4_ue_store_next(up, &I)) != E4_OK) return rc;
    memcpy(res->pnext, I.pnext, E4_PSEUDO_LEN);
    if (fault == F_DROP_M3 || fault == F_UE_STOP_M3_LOST) {
        edhoc4_ctx_wipe(&I); edhoc4_ctx_wipe(&R); edhoc4_db_rec_wipe(&rec);
        return E4_OK;
    }

    if ((rc = edhoc4_r_handle_msg3(&R, m3, n3, m4, sizeof(m4), &n4)) != E4_OK) return rc;
    int keys_match = memcmp(I.msk, R.msk, E4_MSK_LEN) == 0 &&
                     memcmp(I.emsk, R.emsk, E4_EMSK_LEN) == 0;
    if ((rc = edhoc4_db_commit(&R, &rec)) != E4_OK) return rc;
    if (fault == F_DN_STOP_COMMIT) {
        /* DN-AAA dies before message_4 and before the erasure; on restart
         * the index rebuild erases the old sk_B */
        edhoc4_ctx_wipe(&I); edhoc4_db_rec_wipe(&rec);
        edhoc4_db_reindex(DB);
        return E4_OK;
    }
    edhoc4_db_erase_old(&rec);                    /* after message_4 is sent */
    edhoc4_db_rec_wipe(&rec);
    if (fault == F_DROP_M4 || fault == F_UE_STOP_M3_DONE) {
        edhoc4_ctx_wipe(&I);
        return E4_OK;
    }

    if ((rc = edhoc4_i_handle_msg4(&I, m4, n4)) != E4_OK) return rc;
    if ((rc = edhoc4_ue_promote(up)) != E4_OK) return rc;   /* after message_4 */
    edhoc4_ctx_wipe(&I);
    /* F_DROP_SUCCESS: the UE verified message_4 and promoted; losing the
     * EAP-Success afterwards changes no key state */
    res->ok = keys_match;
    return E4_OK;
}

#define MAX_P 128
static uint8_t seen[MAX_P][E4_PSEUDO_LEN];
static int n_seen;

static int fresh(const uint8_t p[E4_PSEUDO_LEN])
{
    for (int i = 0; i < n_seen; i++)
        if (memcmp(seen[i], p, E4_PSEUDO_LEN) == 0) return 0;
    if (n_seen < MAX_P) memcpy(seen[n_seen++], p, E4_PSEUDO_LEN);
    return 1;
}

/* a normal session that checks the erasure of the keys it replaced */
static int normal_session(const char *uid, int *fallback)
{
    char up[512], dp[512];
    edhoc4_creds dn_old;
    result r;
    ue_path(uid, up, sizeof(up));
    dn_path(uid, dp, sizeof(dp));
    edhoc4_rec_load(dp, 0, &dn_old, NULL, NULL, NULL);
    int rc = session(uid, F_NONE, &r);
    if (fallback) *fallback = r.fallback;
    int ok = rc == E4_OK && r.ok && fresh(r.pnext) &&
             memcmp(r.pnext, r.pseudo, E4_PSEUDO_LEN) != 0 &&
             valid_slots(dp) == 1 && valid_slots(up) == 1 &&
             !file_has(dp, dn_old.kem_sk, 64);
    sodium_memzero(&dn_old, sizeof(dn_old));
    return ok;
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
    printf("[edhoc4 dbtest v3] pseudonym index, CUR/NEXT, no grace key\n");
    check(edhoc4_db_reindex(DB) == 2, "index rebuilt from 2 records");

    /* ---- 1. 2 UEs x 5 sessions ---- */
    char up[512], dp[512];
    int ok_all = 1, erased_ue = 1;
    for (int n = 0; n < 5; n++)
        for (int u = 0; u < 2; u++) {
            const char *uid = u ? "ue-b" : "ue-a";
            edhoc4_creds ue_cur;
            ue_path(uid, up, sizeof(up));
            edhoc4_rec_load(up, 0, &ue_cur, NULL, NULL, NULL);
            ok_all &= normal_session(uid, NULL);
            erased_ue &= !file_has(up, ue_cur.kem_sk, 64);
            sodium_memzero(&ue_cur, sizeof(ue_cur));
        }
    check(ok_all, "2 UEs x 5 sessions: keys match, fresh pseudonyms");
    check(ok_all, "DN-AAA file: one valid slot, old sk_B gone after erasure");
    check(erased_ue, "UE file: one valid slot, old sk_A gone after promotion");
    check(n_seen == 10, "10 distinct pseudonyms");

    /* ---- 2. failure injection ---- */
    static const struct { enum fault f; const char *name; int want_next, want_fb; } cases[] = {
        { F_DROP_M3,         "message_3 dropped",                  1, 1 },
        { F_DROP_M4,         "message_4 dropped",                  1, 0 },
        { F_DROP_SUCCESS,    "EAP-Success dropped",                0, 0 },
        { F_UE_STOP_M3_LOST, "UE stopped after message_3 (lost)",  1, 1 },
        { F_UE_STOP_M3_DONE, "UE stopped after message_3 (rcvd)",  1, 0 },
        { F_DN_STOP_COMMIT,  "DN-AAA stopped after commit",        1, 0 },
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        result r;
        char what[96];
        int rc = session("ue-a", cases[k].f, &r);
        ue_path("ue-a", up, sizeof(up));
        dn_path("ue-a", dp, sizeof(dp));
        edhoc4_ue_state st;
        edhoc4_ue_load(up, &st);
        int next_ok = st.using_next == cases[k].want_next;
        edhoc4_ue_state_wipe(&st);
        int dn_one = valid_slots(dp) == 1;
        int fb = -1;
        int next = normal_session("ue-a", &fb);
        snprintf(what, sizeof(what), "%s: recovered, fallback=%d", cases[k].name, fb);
        check(rc == E4_OK && next_ok && dn_one && next && fb == cases[k].want_fb, what);
    }

    /* ---- 3. pseudonym rejection ---- */
    edhoc4_ctx R; edhoc4_db_rec rec;
    uint8_t m2[E4_MAX_MSG], junk[64] = { 0 };
    size_t n2;
    char nai[80];
    uint8_t rnd[E4_PSEUDO_LEN];
    randombytes_buf(rnd, sizeof(rnd));
    edhoc4_pseudo_to_nai(rnd, REALM, nai, sizeof(nai));
    check(edhoc4_db_handle_msg1(DB, nai, &R, &rec, junk, sizeof(junk), m2, sizeof(m2), &n2) == E4_ERR_PSEUDO,
          "unknown pseudonym rejected (E4_ERR_PSEUDO, before any KEM)");
    check(edhoc4_db_handle_msg1(DB, "edhoc-ue", &R, &rec, junk, sizeof(junk), m2, sizeof(m2), &n2) == E4_ERR_PSEUDO,
          "malformed identity rejected");
    edhoc4_pseudo_to_nai(seen[0], REALM, nai, sizeof(nai));
    check(edhoc4_db_handle_msg1(DB, nai, &R, &rec, junk, sizeof(junk), m2, sizeof(m2), &n2) == E4_ERR_PSEUDO,
          "used pseudonym rejected (one-time)");

    sodium_memzero(&dn_sig, sizeof(dn_sig));
    printf("\nRESULT: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
