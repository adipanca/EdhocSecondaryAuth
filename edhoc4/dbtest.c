/*
 * dbtest.c — file-level tests of the method-4 key records (protocol v4):
 * the DN-AAA store with its KeyID index (edhoc4_db_*) and the UE's CUR/NEXT
 * record (edhoc4_ue_*), with failure injection, without radiusd. Built
 * with -DE4_TEST_HOOKS (see Makefile).
 *
 *   1. 2 UEs x 5 sessions: MSK/EMSK match, the DN-AAA picks the UE's own
 *      record by KeyID_B; after commit + erasure the DN-AAA file holds one
 *      sk_B and the index exactly the KeyID of the new pk_B, after the
 *      promotion the UE file holds no old sk_A.
 *   2. KeyID / message_1 checks:
 *        KeyID_B with one bit flipped, a forged index entry pointing to the
 *        same record                              E4_ERR_KEYID, no decaps
 *        KeyID_B != SHA-256(pk_B) (edhoc4 core)   E4_ERR_KEYID, no decaps
 *        ct_B with one bit flipped                E4_ERR_AEAD (AAD_1, TH_1)
 *        KeyID_B and ct_B of another session      rejected
 *        ciphertext with one bit flipped          E4_ERR_AEAD
 *        unknown KeyID_B                          E4_ERR_PEER, no decaps
 *        message_1 vector                         layout, 2390 B, edhoc_sizes.py
 *   3. failure injection, each followed by a normal session that must
 *      complete without re-provisioning:
 *        message_3 dropped          NEXT (H(Npk_B)) unknown -> EAP-Failure ->
 *                                   fallback to CUR (H(pk_B)) -> success
 *        message_4 dropped          H(Npk_B) already indexed -> NEXT succeeds
 *        EAP-Success dropped        normal (the UE promoted after message_4)
 *        UE stopped after message_3 NEXT succeeds, or fallback if not committed
 *        DN-AAA stopped after commit, before erase_old: both KeyIDs found;
 *                                   the next message_1 cleans the older one
 *        forged EAP-Failure after message_1 while the DN-AAA committed NEXT:
 *                                   fallback to CUR is rejected, NEXT is kept,
 *                                   the next session on NEXT succeeds
 *        timeout after message_1    no fallback; the next session uses NEXT
 *   4. 100 UEs, all with the anonymous identity: two interleaved rounds and
 *      one parallel round (one thread per UE); every session must select
 *      the UE's own record (0 mix-ups) and end with matching keys.
 */
#define _DEFAULT_SOURCE
#include "edhoc4.h"
#include "edhoc4_db.h"

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sodium.h>

#define ROOT "dbtest.tmp"
#define DB   ROOT "/edhoc_db"
#define N_MANY 100

extern unsigned long edhoc4_test_decaps_calls;

static int fails;

static void check(int ok, const char *what)
{
    printf("  %-70s %s\n", what, ok ? "ok" : "FAIL");
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

static void provision(const char *id, unsigned idx, const edhoc4_creds *dn_sig)
{
    edhoc4_creds srv, ue;
    uint8_t id_srv[E4_ID_CRED] = { 0, 0, 2 };
    uint8_t id_ue[E4_ID_CRED] = { 0, (uint8_t)(idx >> 8), (uint8_t)idx };
    uint8_t kid[E4_KEYID_LEN];
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
    edhoc4_keyid(srv.kem_pk, kid);
    edhoc4_db_index_put(DB, kid, id);
    snprintf(d, sizeof(d), ROOT "/ue/%s", id); mkdirs(d);
    ue_path(id, p, sizeof(p));
    edhoc4_rec_create(p, &ue, srv.kem_pk);
    sodium_memzero(&srv, sizeof(srv));
    sodium_memzero(&ue, sizeof(ue));
}

/* does the file contain these bytes anywhere? */
static int file_has(const char *path, const uint8_t *needle, size_t n)
{
    static __thread uint8_t buf[1 << 16];
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
    edhoc4_rec_info info;
    if (edhoc4_rec_load(path, -1, NULL, NULL, &info) != E4_OK) return 0;
    return info.valid[0] + info.valid[1];
}

/* KeyID of slot `slot` (-1: newest) of the DN-AAA record of `id` */
static int dn_kid(const char *id, int slot, uint8_t kid[E4_KEYID_LEN])
{
    char p[512];
    edhoc4_creds c;
    dn_path(id, p, sizeof(p));
    if (edhoc4_rec_load(p, slot, &c, NULL, NULL) != E4_OK) return -1;
    edhoc4_keyid(c.kem_pk, kid);
    sodium_memzero(&c, sizeof(c));
    return 0;
}

/* number of index entries that name `id` */
static int index_entries(const char *id)
{
    DIR *d = opendir(DB "/kid");
    struct dirent *de;
    int n = 0;
    if (!d) return -1;
    while ((de = readdir(d)) != NULL) {
        char p[700], buf[256];
        if (de->d_name[0] == '.') continue;
        snprintf(p, sizeof(p), DB "/kid/%s", de->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        size_t k = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[k] = 0;
        n += strcmp(buf, id) == 0;
    }
    closedir(d);
    return n;
}

/* the index names `id` for `kid` */
static int indexed(const uint8_t kid[E4_KEYID_LEN], const char *id)
{
    char got[256];
    return edhoc4_db_index_get(DB, kid, got, sizeof(got)) == E4_OK && strcmp(got, id) == 0;
}

enum fault { F_NONE, F_DROP_M3, F_DROP_M4, F_DROP_SUCCESS, F_UE_STOP_M3_LOST,
             F_UE_STOP_M3_DONE, F_DN_STOP_COMMIT, F_FORGED_FAILURE, F_TIMEOUT };

typedef struct {
    int ok;            /* message_4 verified, MSK/EMSK match */
    int fallback;      /* retried on CUR after an explicit EAP-Failure */
    int rejected;      /* every attempt got an explicit EAP-Failure */
    int used_next;
    int first_rc;      /* DN-AAA result of the first message_1 */
    char rec_id[256];  /* record the DN-AAA selected by KeyID_B */
} result;

/* One session of UE `id`; `fault` disturbs it at the given point. An
 * explicit EAP-Failure before message_2 on NEXT triggers one retry on CUR
 * (NEXT kept); a timeout does not. The DN-AAA sees no identity: it finds
 * the record by KeyID_B. */
static int session(const char *id, enum fault fault, result *res)
{
    char up[512];
    edhoc4_ue_state st;
    edhoc4_ctx I, R;
    edhoc4_db_rec rec;
    uint8_t *m = malloc(4 * E4_MAX_MSG);
    size_t n1, n2, n3, n4;
    int rc, attempt = 0;

    memset(res, 0, sizeof(*res));
    if (!m) return E4_ERR_BUF;
    uint8_t *m1 = m, *m2 = m + E4_MAX_MSG, *m3 = m + 2 * E4_MAX_MSG, *m4 = m + 3 * E4_MAX_MSG;
    ue_path(id, up, sizeof(up));
    if ((rc = edhoc4_ue_load(up, &st)) != E4_OK) goto out;
    res->used_next = st.using_next;
    for (;;) {
        edhoc4_init_initiator(&I, &st.self, st.peer_pk);
        if ((rc = edhoc4_i_make_msg1(&I, m1, E4_MAX_MSG, &n1)) != E4_OK) goto out;
        if (attempt == 0 && fault == F_TIMEOUT) {          /* no answer at all */
            edhoc4_ctx_wipe(&I); edhoc4_ue_state_wipe(&st);
            rc = E4_OK; goto out;
        }
        if (attempt == 0 && fault == F_FORGED_FAILURE)
            rc = E4_ERR_AEAD;                              /* attacker's EAP-Failure */
        else
            rc = edhoc4_db_handle_msg1(DB, &R, &rec, m1, n1, m2, E4_MAX_MSG, &n2);
        if (attempt == 0) res->first_rc = rc;
        if (rc == E4_OK) break;
        edhoc4_ctx_wipe(&I);
        if (st.using_next && attempt == 0) {               /* explicit EAP-Failure on NEXT */
            if ((rc = edhoc4_ue_fallback(up, &st)) != E4_OK) goto out;
            res->fallback = 1;
            attempt++;
            continue;
        }
        res->rejected = 1;                                 /* keep both slots */
        edhoc4_ue_state_wipe(&st);
        rc = E4_OK; goto out;
    }
    snprintf(res->rec_id, sizeof(res->rec_id), "%s", rec.id);

    if ((rc = edhoc4_i_handle_msg2(&I, m2, n2, m3, E4_MAX_MSG, &n3)) != E4_OK) goto out;
    /* write-ahead: NEXT is durable before message_3 leaves */
    if ((rc = edhoc4_ue_store_next(up, &st, &I)) != E4_OK) goto out;
    if (fault == F_DROP_M3 || fault == F_UE_STOP_M3_LOST) {
        edhoc4_ctx_wipe(&I); edhoc4_ctx_wipe(&R); edhoc4_db_rec_wipe(&rec); edhoc4_ue_state_wipe(&st);
        rc = E4_OK; goto out;
    }

    if ((rc = edhoc4_r_handle_msg3(&R, m3, n3, m4, E4_MAX_MSG, &n4)) != E4_OK) goto out;
    int keys_match = memcmp(I.msk, R.msk, E4_MSK_LEN) == 0 &&
                     memcmp(I.emsk, R.emsk, E4_EMSK_LEN) == 0;
    if ((rc = edhoc4_db_commit(&R, &rec)) != E4_OK) goto out;
    if (fault == F_DN_STOP_COMMIT) {
        /* DN-AAA dies before message_4 and before the erasure; the next
         * message_1 naming the new key erases the old sk_B and its KeyID */
        edhoc4_ctx_wipe(&I); edhoc4_db_rec_wipe(&rec); edhoc4_ue_state_wipe(&st);
        rc = E4_OK; goto out;
    }
    edhoc4_db_erase_old(&rec);                    /* after message_4 is sent */
    edhoc4_db_rec_wipe(&rec);
    if (fault == F_DROP_M4 || fault == F_UE_STOP_M3_DONE) {
        edhoc4_ctx_wipe(&I); edhoc4_ue_state_wipe(&st);
        rc = E4_OK; goto out;
    }

    if ((rc = edhoc4_i_handle_msg4(&I, m4, n4)) != E4_OK) goto out;
    if ((rc = edhoc4_ue_promote(up, &st)) != E4_OK) goto out;   /* after message_4 */
    edhoc4_ctx_wipe(&I);
    edhoc4_ue_state_wipe(&st);
    /* F_DROP_SUCCESS: the UE verified message_4 and promoted; losing the
     * EAP-Success afterwards changes no key state */
    res->ok = keys_match;
    rc = E4_OK;
out:
    free(m);
    return rc;
}

/* a normal session that checks the record choice, the erasure of the keys
 * it replaced and the index (exactly the KeyID of the new pk_B) */
static int normal_session(const char *id, int *fallback)
{
    char up[512], dp[512];
    edhoc4_creds dn_old, ue_cur, ue_other;
    edhoc4_rec_info info;
    uint8_t new_kid[E4_KEYID_LEN];
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
    int ok = rc == E4_OK && r.ok && strcmp(r.rec_id, id) == 0 &&
             valid_slots(dp) == 1 && valid_slots(up) == 1 &&
             !file_has(dp, dn_old.kem_sk, 64) &&
             !file_has(up, ue_cur.kem_sk, 64) &&
             (!two || !file_has(up, ue_other.kem_sk, 64)) &&
             dn_kid(id, -1, new_kid) == 0 && indexed(new_kid, id) && index_entries(id) == 1;
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

/* message_1 of UE `id` on its current slot */
static int make_msg1(const char *id, uint8_t *m1, size_t *n1)
{
    char up[512];
    edhoc4_ue_state st;
    edhoc4_ctx I;
    ue_path(id, up, sizeof(up));
    if (edhoc4_ue_load(up, &st) != E4_OK) return -1;
    edhoc4_init_initiator(&I, &st.self, st.peer_pk);
    int rc = edhoc4_i_make_msg1(&I, m1, E4_MAX_MSG, n1);
    edhoc4_ctx_wipe(&I);
    edhoc4_ue_state_wipe(&st);
    return rc;
}

/* ---- 100 anonymous UEs ---- */
typedef struct { char id[32]; int ok; } many_arg;

static void *many_main(void *arg)
{
    many_arg *a = arg;
    result r;
    a->ok = session(a->id, F_NONE, &r) == E4_OK && r.ok && strcmp(r.rec_id, a->id) == 0;
    return NULL;
}

int main(void)
{
    static uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3_buf[E4_MAX_MSG], m4_buf[E4_MAX_MSG];
    size_t n1, n2;
    edhoc4_ctx R;
    edhoc4_db_rec rec;

    if (sodium_init() < 0) return 1;
    if (system("rm -rf " ROOT) != 0) return 1;
    edhoc4_creds dn_sig;
    uint8_t id_srv[E4_ID_CRED] = { 0, 0, 2 };
    edhoc4_gen_creds(&dn_sig, id_srv);
    provision("ue-a", 1, &dn_sig);
    provision("ue-b", 2, &dn_sig);
    printf("[edhoc4 dbtest v4] record by KeyID_B = H(pk_B), AAD_1, anonymous identity, CUR/NEXT, no grace key\n");

    /* ---- 1. 2 UEs x 5 sessions ---- */
    int ok_all = 1;
    for (int n = 0; n < 5; n++)
        for (int u = 0; u < 2; u++)
            ok_all &= normal_session(u ? "ue-b" : "ue-a", NULL);
    check(ok_all, "2 UEs x 5 sessions: own record by KeyID, keys match, index = new KeyID only");

    /* ---- 2. KeyID / message_1 checks ---- */
    {
        char p[512], got[256];
        unsigned long d0;
        int rc;

        /* message_1 vector: layout and size, against edhoc_sizes.py */
        edhoc4_ue_state st;
        ue_path("ue-a", p, sizeof(p));
        edhoc4_ue_load(p, &st);
        uint8_t kid_a[E4_KEYID_LEN];
        edhoc4_keyid(st.peer_pk, kid_a);
        edhoc4_ue_state_wipe(&st);
        make_msg1("ue-a", m1, &n1);
        long model = -1;
        FILE *mf = popen("python3 ../benchmark/edhoc_sizes.py | sed -n 's/^method 4 .*msg1=\\([0-9]*\\).*/\\1/p'", "r");
        if (mf) { if (fscanf(mf, "%ld", &model) != 1) model = -1; pclose(mf); }
        check(n1 == 2390 && (long)n1 == model && memcmp(m1, kid_a, E4_KEYID_LEN) == 0,
              "message_1 vector: KeyID_B first, 2390 B == edhoc_sizes.py");

        /* KeyID_B with one bit flipped; a forged index entry names the record */
        uint8_t forged[E4_KEYID_LEN];
        memcpy(forged, m1, E4_KEYID_LEN);
        forged[0] ^= 1;
        edhoc4_db_index_put(DB, forged, "ue-a");
        memcpy(m3_buf, m1, n1);
        m3_buf[0] ^= 1;
        d0 = edhoc4_test_decaps_calls;
        rc = edhoc4_db_handle_msg1(DB, &R, &rec, m3_buf, n1, m2, sizeof(m2), &n2);
        int removed = edhoc4_db_index_get(DB, forged, got, sizeof(got)) == E4_ERR_PEER;
        check(rc == E4_ERR_KEYID && edhoc4_test_decaps_calls == d0 && removed,
              "KeyID_B 1 bit flipped, forged index: E4_ERR_KEYID, no decaps, removed");

        /* the record's pk_B does not hash to KeyID_B (core check, no KEM) */
        edhoc4_creds b_srv;
        uint8_t b_ue_pk[E4_XWING_PK];
        dn_path("ue-b", p, sizeof(p));
        edhoc4_rec_load(p, -1, &b_srv, b_ue_pk, NULL);
        d0 = edhoc4_test_decaps_calls;
        edhoc4_init_responder(&R, &b_srv, b_ue_pk);
        rc = edhoc4_r_handle_msg1(&R, m1, n1, m2, sizeof(m2), &n2);
        edhoc4_ctx_wipe(&R);
        sodium_memzero(&b_srv, sizeof(b_srv));
        check(rc == E4_ERR_KEYID && edhoc4_test_decaps_calls == d0,
              "KeyID_B != SHA-256(pk_B) of the record: E4_ERR_KEYID, no decaps");

        /* ct_B with one bit flipped */
        memcpy(m3_buf, m1, n1);
        m3_buf[E4_KEYID_LEN + 100] ^= 1;
        rc = edhoc4_db_handle_msg1(DB, &R, &rec, m3_buf, n1, m2, sizeof(m2), &n2);
        check(rc == E4_ERR_AEAD, "ct_B 1 bit flipped: E4_ERR_AEAD");

        /* ciphertext with one bit flipped */
        memcpy(m3_buf, m1, n1);
        m3_buf[n1 - 1] ^= 1;
        rc = edhoc4_db_handle_msg1(DB, &R, &rec, m3_buf, n1, m2, sizeof(m2), &n2);
        check(rc == E4_ERR_AEAD, "ciphertext 1 bit flipped: E4_ERR_AEAD");

        /* KeyID_B + ct_B of another session: of the same UE, then of another
         * UE (a valid (KeyID, ct) pair, the rest of this session) */
        size_t n_o;
        make_msg1("ue-a", m4_buf, &n_o);
        memcpy(m3_buf, m1, n1);
        memcpy(m3_buf, m4_buf, E4_KEYID_LEN + E4_XWING_CT);
        rc = edhoc4_db_handle_msg1(DB, &R, &rec, m3_buf, n1, m2, sizeof(m2), &n2);
        int rc2;
        make_msg1("ue-b", m4_buf, &n_o);
        memcpy(m3_buf, m1, n1);
        memcpy(m3_buf, m4_buf, E4_KEYID_LEN + E4_XWING_CT);
        rc2 = edhoc4_db_handle_msg1(DB, &R, &rec, m3_buf, n1, m2, sizeof(m2), &n2);
        check(rc == E4_ERR_AEAD && rc2 == E4_ERR_AEAD,
              "KeyID_B and ct_B of another session (same UE, other UE): rejected");

        /* unknown KeyID */
        memcpy(m3_buf, m1, n1);
        m3_buf[0] ^= 0xff;
        d0 = edhoc4_test_decaps_calls;
        rc = edhoc4_db_handle_msg1(DB, &R, &rec, m3_buf, n1, m2, sizeof(m2), &n2);
        check(rc == E4_ERR_PEER && edhoc4_test_decaps_calls == d0, "unknown KeyID_B: E4_ERR_PEER, no decaps");
        uint8_t junk[64] = { 0 };
        check(edhoc4_db_handle_msg1(DB, &R, &rec, junk, sizeof(junk), m2, sizeof(m2), &n2) == E4_ERR_PARSE,
              "short message_1: rejected before the index");
        check(normal_session("ue-a", NULL), "ue-a still works after the tampering tests");
    }

    /* ---- 3. failure injection: fault, then one normal session ---- */
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
        char what[160];
        uint8_t kid_old[E4_KEYID_LEN], kid_new[E4_KEYID_LEN];
        dn_kid("ue-a", -1, kid_old);
        int rc = session("ue-a", cases[k].f, &r);
        int next_ok = ue_has_next("ue-a") == cases[k].want_next;
        int extra = 1;
        if (cases[k].f == F_DN_STOP_COMMIT) {
            /* both slots and both KeyIDs present until the next message_1 */
            char dp[512];
            dn_path("ue-a", dp, sizeof(dp));
            extra = valid_slots(dp) == 2 && dn_kid("ue-a", -1, kid_new) == 0 &&
                    indexed(kid_old, "ue-a") && indexed(kid_new, "ue-a");
        }
        if (cases[k].f == F_DROP_M3)        /* the UE's NEXT KeyID is unknown */
            extra = index_entries("ue-a") == 1 && indexed(kid_old, "ue-a");
        int fb = -1;
        int next = normal_session("ue-a", &fb);
        if (cases[k].f == F_DN_STOP_COMMIT) extra &= !indexed(kid_old, "ue-a");
        snprintf(what, sizeof(what), "%s: next session ok, fallback=%d", cases[k].name, fb);
        check(rc == E4_OK && next_ok && next && extra && fb == cases[k].want_fb, what);
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

    /* ---- 4. 100 anonymous UEs ---- */
    {
        static many_arg args[N_MANY];
        pthread_t th[N_MANY];
        for (int i = 0; i < N_MANY; i++) {
            snprintf(args[i].id, sizeof(args[i].id), "u%03d", i);
            provision(args[i].id, 100 + i, &dn_sig);
        }
        int ok = 1;
        for (int round = 0; round < 2; round++)
            for (int i = 0; i < N_MANY; i++) {
                many_main(&args[i]);
                ok &= args[i].ok;
            }
        check(ok, "100 anonymous UEs, 2 interleaved rounds: own record, keys match");
        for (int i = 0; i < N_MANY; i++) pthread_create(&th[i], NULL, many_main, &args[i]);
        ok = 1;
        for (int i = 0; i < N_MANY; i++) { pthread_join(th[i], NULL); ok &= args[i].ok; }
        int idx_ok = 1;
        for (int i = 0; i < N_MANY; i++) idx_ok &= index_entries(args[i].id) == 1;
        check(ok && idx_ok, "100 anonymous UEs in parallel: 0 mix-ups, one index entry each");
    }

    sodium_memzero(&dn_sig, sizeof(dn_sig));
    printf("\nRESULT: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
