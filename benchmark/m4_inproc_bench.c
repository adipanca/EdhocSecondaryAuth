/*
 * m4_inproc_bench.c — method 4 handshake computation per side, in process
 * (no RADIUS transport, no key storage): wall-clock time of each party's
 * message processing over N handshakes, with key rotation after each one.
 *
 *   m4_inproc_bench [--iters N] [--pool] [--csv F --label L]
 *
 * By default the next one-time key pair (EAD3/EAD4) is generated inside the
 * handshake, as the live UE and DN-AAA do; with --pool it is generated
 * between handshakes with edhoc4_pool_fill() (optional precompute). Build
 * with -DNO_POOL_API to link against an edhoc4 core without the pool.
 */
#define _POSIX_C_SOURCE 199309L
#include "edhoc4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

static uint8_t g_pk_a[E4_XWING_PK], g_vk_i[E4_MLDSA_PK], g_id[E4_ID_CRED];

static int lookup(const uint8_t id[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                  uint8_t vk_i[E4_MLDSA_PK], void *arg)
{
    (void)arg;
    if (memcmp(id, g_id, E4_ID_CRED) != 0) return -1;
    memcpy(pk_a, g_pk_a, E4_XWING_PK);
    memcpy(vk_i, g_vk_i, E4_MLDSA_PK);
    return 0;
}

static double now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    int iters = 2000, pool = 0;
    const char *csv = NULL, *label = "m4";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pool")) pool = 1;
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv = argv[++i];
        else if (!strcmp(argv[i], "--label") && i + 1 < argc) label = argv[++i];
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
#ifdef NO_POOL_API
    pool = 0;
#endif
    if (iters < 1 || sodium_init() < 0) return 1;

    edhoc4_creds ue, aaa;
    uint8_t idI[E4_ID_CRED] = { 0, 0, 1 }, idR[E4_ID_CRED] = { 0, 0, 2 };
    uint8_t ue_peer[E4_XWING_PK];
    if (edhoc4_gen_creds(&ue, idI) != E4_OK || edhoc4_gen_creds(&aaa, idR) != E4_OK) return 1;
    memcpy(ue_peer, aaa.kem_pk, E4_XWING_PK);
    memcpy(g_pk_a, ue.kem_pk, E4_XWING_PK);
    memcpy(g_vk_i, ue.sig_vk, E4_MLDSA_PK);
    memcpy(g_id, idI, E4_ID_CRED);

    double *ti = malloc(iters * sizeof(double)), *tr = malloc(iters * sizeof(double));
    static uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    if (!ti || !tr) return 1;

    for (int k = -50; k < iters; k++) {          /* 50 warm-up handshakes */
#ifndef NO_POOL_API
        if (pool) edhoc4_pool_fill(2);           /* both parties' next keys */
#endif
        edhoc4_ctx I, R;
        size_t n1, n2, n3, n4;
        double t, ci = 0, cr = 0;
        edhoc4_init_initiator(&I, &ue, ue_peer);
        edhoc4_init_responder(&R, &aaa, g_pk_a);
        edhoc4_set_lookup(&R, lookup, NULL);
        t = now_us(); if (edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1)) return 3; ci += now_us() - t;
        t = now_us(); if (edhoc4_r_handle_msg1(&R, m1, n1, m2, sizeof(m2), &n2)) return 3; cr += now_us() - t;
        t = now_us(); if (edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3)) return 3; ci += now_us() - t;
        t = now_us(); if (edhoc4_r_handle_msg3(&R, m3, n3, m4, sizeof(m4), &n4)) return 3; cr += now_us() - t;
        t = now_us(); if (edhoc4_i_handle_msg4(&I, m4, n4)) return 3; ci += now_us() - t;
        if (memcmp(I.msk, R.msk, E4_MSK_LEN) != 0) return 4;
        if (edhoc4_commit(&I, &ue, ue_peer) || edhoc4_commit(&R, &aaa, g_pk_a)) return 5;
        if (k >= 0) { ti[k] = ci; tr[k] = cr; }
    }

    double si = 0, sr = 0;
    for (int k = 0; k < iters; k++) { si += ti[k]; sr += tr[k]; }
    qsort(ti, iters, sizeof(double), cmp_d);
    qsort(tr, iters, sizeof(double), cmp_d);
    printf("[%s] N=%d initiator mean %.1f median %.1f us | responder mean %.1f median %.1f us"
           " | total mean %.1f us\n", label, iters, si / iters, ti[iters / 2],
           sr / iters, tr[iters / 2], (si + sr) / iters);
    if (csv) {
        FILE *f = fopen(csv, "a");
        if (!f) return 1;
        fseek(f, 0, SEEK_END);
        if (ftell(f) == 0)
            fprintf(f, "label,iters,initiator_mean_us,initiator_median_us,"
                       "responder_mean_us,responder_median_us,total_mean_us\n");
        fprintf(f, "%s,%d,%.1f,%.1f,%.1f,%.1f,%.1f\n", label, iters, si / iters,
                ti[iters / 2], sr / iters, tr[iters / 2], (si + sr) / iters);
        fclose(f);
    }
    free(ti);
    free(tr);
    return 0;
}
