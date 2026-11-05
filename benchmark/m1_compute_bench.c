/*
 * m1_compute_bench.c — computation of Message1 alone, per variant, in process:
 * edhoc4_i_make_msg1 at the UE (with the EAD_1 key generation, as live) and
 * edhoc4_r_open_msg1 at the DN-AAA (KeyID check, Decaps, TH_1, AEAD, parse; no
 * record lookup, no Message2). The variants take turns within every iteration,
 * so slow drift of the machine reaches all of them alike.
 *
 *   m1_compute_bench [--iters N] [--csv F]      one row per variant, median us
 */
#define _POSIX_C_SOURCE 199309L
#include "edhoc4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#define NV 4

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

static double pct(double *v, int n, double p)
{
    return v[(int)(p * (n - 1) + 0.5)];
}

int main(int argc, char **argv)
{
    int iters = 10000;
    const char *csv = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv = argv[++i];
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
    if (sodium_init() < 0) return 1;

    static edhoc4_creds ue, aaa;
    const uint8_t idI[E4_ID_CRED] = { 0, 0, 1 }, idR[E4_ID_CRED] = { 0, 0, 2 };
    if (edhoc4_gen_creds(&ue, idI) != E4_OK || edhoc4_gen_creds(&aaa, idR) != E4_OK) return 1;

    double *ti[NV], *tr[NV];
    for (int v = 0; v < NV; v++) {
        ti[v] = malloc(sizeof(double) * iters);
        tr[v] = malloc(sizeof(double) * iters);
        if (!ti[v] || !tr[v]) return 1;
    }
    static edhoc4_ctx I, R;
    static uint8_t m1[E4_MAX_MSG];
    size_t n1;
    for (int it = 0; it < iters; it++) {
        for (int k = 0; k < NV; k++) {
            int v = (it + k) % NV;
            edhoc4_set_variant(v);
            edhoc4_init_initiator(&I, &ue, aaa.kem_pk);
            edhoc4_init_responder(&R, &aaa, ue.kem_pk);
            double t0 = now_us();
            if (edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1) != E4_OK) return 3;
            double t1 = now_us();
            if (edhoc4_r_open_msg1(&R, m1, n1) != E4_OK) return 3;
            double t2 = now_us();
            ti[v][it] = t1 - t0;
            tr[v][it] = t2 - t1;
        }
    }
    FILE *f = csv ? fopen(csv, "w") : stdout;
    if (!f) return 1;
    fprintf(f, "variant,iters,msg1_bytes,ue_median_us,ue_p95_us,dn_median_us,dn_p95_us\n");
    for (int v = 0; v < NV; v++) {
        edhoc4_set_variant(v);
        qsort(ti[v], iters, sizeof(double), cmp_d);
        qsort(tr[v], iters, sizeof(double), cmp_d);
        fprintf(f, "%s,%d,%zu,%.1f,%.1f,%.1f,%.1f\n", edhoc4_variant_name(v), iters, edhoc4_msg1_len(),
                pct(ti[v], iters, 0.5), pct(ti[v], iters, 0.95), pct(tr[v], iters, 0.5), pct(tr[v], iters, 0.95));
    }
    if (csv) fclose(f);
    return 0;
}
