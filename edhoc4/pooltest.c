/*
 * pooltest.c — tests of the next-key pool (xwing_next_keygen = pregen | inline),
 * in process. Built with -DE4_TEST_HOOKS (see Makefile):
 *
 *   edhoc4_pooltest [N_seq] [N_par]      defaults 1000 and 100
 *
 *   1. N_seq handshakes in a row, pregen (pool 64, refill thread woken after
 *      each commit): every Npk_A and Npk_B unique, pool misses reported
 *   2. failed run: Message2 dropped, the UE ctx wiped; Nsk_A of that run is
 *      zero in the ctx and in the freed pool slot, the retry announces a new
 *      Npk_A and completes
 *   3. N_par handshakes in parallel threads against one pool of 64: no key
 *      taken twice, pool misses reported
 *   4. pool size 0: every take falls back to inline KeyGen, handshake OK
 *   5. restart: pool cleared and configured again, handshake OK, new keys
 *   6. inline mode: no key taken from the pool, handshake OK
 *
 * One process holds both parties here, so UE and DN-AAA share one pool; the
 * live tests (benchmark/pool_tests.sh) run them in separate processes.
 */
#define _GNU_SOURCE
#include "edhoc4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sodium.h>

int edhoc4_test_pool_free_slots_zero(void);
int edhoc4_test_crash_point, edhoc4_test_in_commit;   /* dbtest hooks, unused here */

static edhoc4_creds g_ue, g_aaa;
static uint8_t g_id[E4_ID_CRED] = { 0, 0, 1 };
static int g_fail;

#define CHECK(c, ...) do { if (!(c)) { printf("FAIL: " __VA_ARGS__); printf("\n"); g_fail = 1; } } while (0)

static int lookup(const uint8_t id[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                  uint8_t vk_i[E4_MLDSA_PK], void *arg)
{
    const edhoc4_creds *ue = arg;
    if (memcmp(id, g_id, E4_ID_CRED) != 0) return -1;
    memcpy(pk_a, ue->kem_pk, E4_XWING_PK);
    memcpy(vk_i, ue->sig_vk, E4_MLDSA_PK);
    return 0;
}

/* one handshake between ue and aaa (no commit); returns Npk_A and Npk_B
 * as SHA-256 fingerprints */
static int handshake(const edhoc4_creds *ue, const edhoc4_creds *aaa,
                     uint8_t fa[32], uint8_t fb[32])
{
    static __thread uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    edhoc4_ctx *I = malloc(sizeof(*I)), *R = malloc(sizeof(*R));
    size_t n1, n2, n3, n4;
    int rc = -1;
    if (!I || !R) goto out;
    edhoc4_init_initiator(I, ue, aaa->kem_pk);
    edhoc4_init_responder(R, aaa, ue->kem_pk);
    edhoc4_set_lookup(R, lookup, (void *)ue);
    if (edhoc4_i_make_msg1(I, m1, sizeof(m1), &n1)) goto out;
    if (edhoc4_r_handle_msg1(R, m1, n1, m2, sizeof(m2), &n2)) goto out;
    if (edhoc4_i_handle_msg2(I, m2, n2, m3, sizeof(m3), &n3)) goto out;
    if (edhoc4_r_handle_msg3(R, m3, n3, m4, sizeof(m4), &n4)) goto out;
    if (edhoc4_i_handle_msg4(I, m4, n4)) goto out;
    if (memcmp(I->msk, R->msk, E4_MSK_LEN) != 0) goto out;
    if (memcmp(I->peer_new_pk, R->new_pk, E4_XWING_PK) != 0) goto out;
    if (memcmp(R->peer_new_pk, I->new_pk, E4_XWING_PK) != 0) goto out;
    crypto_hash_sha256(fa, I->new_pk, E4_XWING_PK);
    crypto_hash_sha256(fb, R->new_pk, E4_XWING_PK);
    rc = 0;
out:
    edhoc4_ctx_wipe(I);
    edhoc4_ctx_wipe(R);
    free(I);
    free(R);
    return rc;
}

static int cmp32(const void *a, const void *b) { return memcmp(a, b, 32); }

static int count_dups(uint8_t (*fp)[32], int n)
{
    qsort(fp, n, 32, cmp32);
    int d = 0;
    for (int i = 1; i < n; i++) d += memcmp(fp[i - 1], fp[i], 32) == 0;
    return d;
}

static void stats_line(const char *tag)
{
    edhoc4_pool_stats_t st;
    edhoc4_pool_stats(&st);
    printf("  [%s] mode=%s size=%d n=%d locked=%d taken=%lu pool_miss=%lu inline=%lu"
           " refilled=%lu refill_cpu_per_key_us=%.1f\n", tag,
           edhoc4_next_keygen_name(st.mode), st.size, st.n, st.locked, st.taken, st.miss,
           st.inline_gen, st.refilled,
           st.refilled ? st.refill_cpu_ns / 1e3 / st.refilled : 0.0);
}

/* ---- 3. parallel ---- */
typedef struct { edhoc4_creds ue; uint8_t fa[32], fb[32]; int rc; } par_arg;

static pthread_barrier_t g_bar;

static void *par_main(void *p)
{
    par_arg *a = p;
    pthread_barrier_wait(&g_bar);
    a->rc = handshake(&a->ue, &g_aaa, a->fa, a->fb);
    return NULL;
}

int main(int argc, char **argv)
{
    int n_seq = argc > 1 ? atoi(argv[1]) : 1000;
    int n_par = argc > 2 ? atoi(argv[2]) : 100;
    uint8_t idR[E4_ID_CRED] = { 0, 0, 2 };
    if (n_seq < 1 || n_par < 1 || sodium_init() < 0) return 2;
    if (edhoc4_gen_creds(&g_ue, g_id) || edhoc4_gen_creds(&g_aaa, idR)) return 2;

    /* 1. sequential, pregen */
    {
        uint8_t (*fa)[32] = malloc((size_t)n_seq * 32), (*fb)[32] = malloc((size_t)n_seq * 32);
        uint8_t (*all)[32] = malloc((size_t)n_seq * 64);
        if (!fa || !fb || !all) return 2;
        edhoc4_pool_config(E4_NEXT_KEYGEN_PREGEN, 64);
        edhoc4_pool_fill(64);
        int bad = 0;
        for (int k = 0; k < n_seq; k++) {
            bad += handshake(&g_ue, &g_aaa, fa[k], fb[k]) != 0;
            edhoc4_pool_refill_async();          /* "after commit" */
        }
        memcpy(all, fa, (size_t)n_seq * 32);
        memcpy(all + n_seq, fb, (size_t)n_seq * 32);
        int da = count_dups(fa, n_seq), db = count_dups(fb, n_seq), dall = count_dups(all, 2 * n_seq);
        edhoc4_pool_stats_t st;
        edhoc4_pool_stats(&st);
        printf("1. %d sequential handshakes (pregen, pool 64): failed=%d dup Npk_A=%d dup Npk_B=%d"
               " dup across both=%d pool_miss=%lu\n", n_seq, bad, da, db, dall, st.miss);
        stats_line("seq");
        CHECK(bad == 0 && da == 0 && db == 0 && dall == 0, "sequential uniqueness");
        free(fa); free(fb); free(all);
    }

    /* 2. failed run (Message2 dropped) and retry */
    {
        static uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG];
        static const uint8_t zero_sk[E4_XWING_SK];
        size_t n1, n2;
        uint8_t old_fp[32], new_fp[32], fb[32];
        edhoc4_ctx *I = malloc(sizeof(*I)), *R = malloc(sizeof(*R));
        if (!I || !R) return 2;
        edhoc4_pool_config(E4_NEXT_KEYGEN_PREGEN, 2);   /* no refill thread wake-ups below */
        edhoc4_pool_fill(2);
        edhoc4_init_initiator(I, &g_ue, g_aaa.kem_pk);
        edhoc4_init_responder(R, &g_aaa, g_ue.kem_pk);
        edhoc4_set_lookup(R, lookup, &g_ue);
        int ok = edhoc4_i_make_msg1(I, m1, sizeof(m1), &n1) == E4_OK
                 && edhoc4_r_handle_msg1(R, m1, n1, m2, sizeof(m2), &n2) == E4_OK;
        crypto_hash_sha256(old_fp, I->new_pk, E4_XWING_PK);
        int slots_zero = edhoc4_test_pool_free_slots_zero();
        /* Message2 is lost: the UE abandons the run */
        edhoc4_ctx_wipe(I);
        edhoc4_ctx_wipe(R);
        int sk_zero = sodium_memcmp(I->new_sk, zero_sk, E4_XWING_SK) == 0;
        free(I); free(R);
        edhoc4_pool_fill(2);
        int retry = handshake(&g_ue, &g_aaa, new_fp, fb);
        int fresh = memcmp(old_fp, new_fp, 32) != 0;
        printf("2. Message2 dropped: run1 ok to Message2=%d, Nsk_A zero in wiped ctx=%d,"
               " taken pool slots zero=%d, retry ok=%d, retry Npk_A new=%d\n",
               ok, sk_zero, slots_zero, retry == 0, fresh);
        CHECK(ok && sk_zero && slots_zero && retry == 0 && fresh, "failed run");
    }

    /* 3. parallel */
    {
        par_arg *a = calloc((size_t)n_par, sizeof(*a));
        pthread_t *t = calloc((size_t)n_par, sizeof(*t));
        uint8_t (*all)[32] = malloc((size_t)n_par * 64);
        if (!a || !t || !all) return 2;
        for (int k = 0; k < n_par; k++) a[k].ue = g_ue;     /* one UE key, distinct runs */
        edhoc4_pool_config(E4_NEXT_KEYGEN_PREGEN, 64);
        edhoc4_pool_fill(64);
        edhoc4_pool_stats_t s0;
        edhoc4_pool_stats(&s0);
        pthread_barrier_init(&g_bar, NULL, (unsigned)n_par);
        for (int k = 0; k < n_par; k++) pthread_create(&t[k], NULL, par_main, &a[k]);
        int bad = 0;
        for (int k = 0; k < n_par; k++) { pthread_join(t[k], NULL); bad += a[k].rc != 0; }
        for (int k = 0; k < n_par; k++) {
            memcpy(all[2 * k], a[k].fa, 32);
            memcpy(all[2 * k + 1], a[k].fb, 32);
        }
        int d = count_dups(all, 2 * n_par);
        edhoc4_pool_stats_t s1;
        edhoc4_pool_stats(&s1);
        printf("3. %d parallel handshakes (pool 64, both parties take from it): failed=%d"
               " keys taken twice=%d taken=%lu pool_miss=%lu\n", n_par, bad, d,
               s1.taken - s0.taken, s1.miss - s0.miss);
        CHECK(bad == 0 && d == 0, "parallel uniqueness");
        free(a); free(t); free(all);
    }

    /* 4. pool size 0 */
    {
        uint8_t fa[32], fb[32];
        edhoc4_pool_config(E4_NEXT_KEYGEN_PREGEN, 0);
        edhoc4_pool_stats_t s0, s1;
        edhoc4_pool_stats(&s0);
        int rc = handshake(&g_ue, &g_aaa, fa, fb);
        edhoc4_pool_stats(&s1);
        printf("4. pool size 0: handshake ok=%d, pool_miss +%lu (fallback inline KeyGen)\n",
               rc == 0, s1.miss - s0.miss);
        CHECK(rc == 0 && s1.miss - s0.miss == 2, "pool size 0");
    }

    /* 5. restart */
    {
        uint8_t fa1[32], fb1[32], fa2[32], fb2[32];
        edhoc4_pool_config(E4_NEXT_KEYGEN_PREGEN, 4);
        edhoc4_pool_fill(4);
        int rc1 = handshake(&g_ue, &g_aaa, fa1, fb1);
        edhoc4_pool_clear();
        int cleared = edhoc4_test_pool_free_slots_zero();
        edhoc4_pool_config(E4_NEXT_KEYGEN_PREGEN, 4);
        edhoc4_pool_fill(4);
        edhoc4_pool_stats_t st;
        edhoc4_pool_stats(&st);
        int rc2 = handshake(&g_ue, &g_aaa, fa2, fb2);
        int fresh = memcmp(fa1, fa2, 32) && memcmp(fb1, fb2, 32);
        printf("5. restart: before ok=%d, pool wiped=%d, rebuilt n=%d, after ok=%d, new keys=%d\n",
               rc1 == 0, cleared, st.n, rc2 == 0, fresh);
        CHECK(rc1 == 0 && cleared && st.n == 4 && rc2 == 0 && fresh, "restart");
    }

    /* 6. inline */
    {
        uint8_t fa[32], fb[32];
        edhoc4_pool_config(E4_NEXT_KEYGEN_INLINE, 64);
        edhoc4_pool_stats_t s0, s1;
        edhoc4_pool_stats(&s0);
        int rc = handshake(&g_ue, &g_aaa, fa, fb);
        edhoc4_pool_stats(&s1);
        printf("6. inline: handshake ok=%d, taken +%lu, inline KeyGen +%lu, pool size=%d\n",
               rc == 0, s1.taken - s0.taken, s1.inline_gen - s0.inline_gen, s1.size);
        CHECK(rc == 0 && s1.taken == s0.taken && s1.inline_gen - s0.inline_gen == 2 && s1.size == 0,
              "inline");
    }

    printf("%s\n", g_fail ? "pooltest: FAIL" : "pooltest: PASS");
    return g_fail;
}
