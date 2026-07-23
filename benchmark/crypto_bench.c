/*
 * crypto_bench.c — Real cryptographic micro-benchmark for EAP-EDHOC methods 0..4.
 *
 * Library usage matches spesifikasi.md exactly:
 *   - libsodium : X25519 (keygen + scalar-mult/DH), Ed25519 (keygen/sign/verify),
 *                 SHA-256, HKDF (built on libsodium HMAC-SHA256, RFC 5869).
 *   - mbedTLS   : AES-128-GCM (EDHOC AEAD).
 *   - PQClean   : ML-KEM-768 and ML-DSA-44 (clean reference implementation).
 *
 * Outputs CSV files into the directory given as argv[1]:
 *   crypto-primitives.csv : per-operation latency distribution (ns).
 *   crypto-breakdown.csv  : per-method/role breakdown (Keygen, Scalar mult,
 *                           Encaps, Decaps, Signature, Verify) + handshake totals.
 *   handshake-compute.csv : per-method total compute time.
 *
 * EDHOC method matrix (per spesifikasi.md / mermaid.md):
 *   0  SIG(Ed25519)        / SIG(Ed25519)
 *   1  SIG(Ed25519)        / MAC(static-DH X25519)
 *   2  MAC(static-DH X25519)/ SIG(Ed25519)
 *   3  MAC(static-DH X25519)/ MAC(static-DH X25519)
 *   4  SIGMA XWING (Initiator: SIGMA, Responder: SIGMA)
 *      key establishment : XWING KEM = X25519 + ML-KEM-768 hybrid
 *      authentication    : ML-DSA-44 signatures on BOTH sides (+ MAC)
 *      XWING op decomposition:
 *        KeyGen = x25519_keygen + mlkem_keygen
 *        Encaps = x25519_keygen + x25519_dh + mlkem_encaps
 *        Decaps = x25519_dh + mlkem_decaps
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#include <sodium.h>
#include <mbedtls/gcm.h>

/* ---- PQClean prototypes (clean reference, namespaced symbols) ---- */
#define MLKEM768_PK 1184
#define MLKEM768_SK 2400
#define MLKEM768_CT 1088
#define MLKEM768_SS 32
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define MLDSA44_PK 1312
#define MLDSA44_SK 2560
#define MLDSA44_SIG 2420
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *pk);

/* -------- timing helpers -------- */

static long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int cmp_ll(const void *a, const void *b)
{
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x > y) - (x < y);
}

typedef struct {
    const char *name;
    const char *lib;
    double mean_ns;
    double median_ns;
    double p95_ns;
    double p99_ns;
    double stddev_ns;
    long long min_ns;
    long long max_ns;
    int iters;
} op_stat_t;

#define MAX_OPS 24
static op_stat_t g_ops[MAX_OPS];
static int g_nops = 0;

static double lookup_mean(const char *name)
{
    for (int i = 0; i < g_nops; i++)
        if (strcmp(g_ops[i].name, name) == 0)
            return g_ops[i].mean_ns;
    return 0.0;
}

typedef void (*bench_fn)(void *ctx);

static void bench_op(const char *name, const char *lib,
                     bench_fn fn, void *ctx, int iters)
{
    long long *samples = malloc(sizeof(long long) * iters);
    if (!samples) { fprintf(stderr, "OOM\n"); exit(1); }

    for (int i = 0; i < 50 && i < iters; i++) fn(ctx);

    for (int i = 0; i < iters; i++) {
        long long t0 = now_ns();
        fn(ctx);
        long long t1 = now_ns();
        samples[i] = t1 - t0;
    }

    qsort(samples, iters, sizeof(long long), cmp_ll);

    double sum = 0.0;
    for (int i = 0; i < iters; i++) sum += (double)samples[i];
    double mean = sum / iters;

    double var = 0.0;
    for (int i = 0; i < iters; i++) {
        double d = (double)samples[i] - mean;
        var += d * d;
    }
    var /= iters;

    op_stat_t *o = &g_ops[g_nops++];
    o->name = name;
    o->lib = lib;
    o->mean_ns = mean;
    o->median_ns = (double)samples[iters / 2];
    o->p95_ns = (double)samples[(int)(iters * 0.95)];
    o->p99_ns = (double)samples[(int)(iters * 0.99)];
    o->stddev_ns = sqrt(var);
    o->min_ns = samples[0];
    o->max_ns = samples[iters - 1];
    o->iters = iters;

    free(samples);
    fprintf(stderr, "  %-22s %-9s mean=%9.1f ns  median=%9.1f ns\n",
            name, lib, mean, o->median_ns);
}

/* -------- HKDF-SHA256 (RFC 5869) on top of libsodium HMAC-SHA256 -------- */

static void hkdf_sha256(const unsigned char *salt, size_t salt_len,
                        const unsigned char *ikm, size_t ikm_len,
                        const unsigned char *info, size_t info_len,
                        unsigned char *okm, size_t okm_len)
{
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;

    /* HKDF-Extract */
    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);

    /* HKDF-Expand */
    unsigned char t[crypto_auth_hmacsha256_BYTES];
    size_t done = 0, tlen = 0;
    unsigned char ctr = 1;
    while (done < okm_len) {
        crypto_auth_hmacsha256_init(&st, prk, sizeof(prk));
        if (tlen) crypto_auth_hmacsha256_update(&st, t, tlen);
        crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &ctr, 1);
        crypto_auth_hmacsha256_final(&st, t);
        tlen = sizeof(t);
        size_t n = (okm_len - done < tlen) ? okm_len - done : tlen;
        memcpy(okm + done, t, n);
        done += n;
        ctr++;
    }
}

/* -------- primitive contexts -------- */

typedef struct {
    unsigned char pk[crypto_scalarmult_BYTES];
    unsigned char sk[crypto_scalarmult_SCALARBYTES];
    unsigned char peer_pk[crypto_scalarmult_BYTES];
    unsigned char shared[crypto_scalarmult_BYTES];
} x25519_ctx_t;

static void op_x25519_keygen(void *c)
{
    x25519_ctx_t *x = c;
    randombytes_buf(x->sk, sizeof(x->sk));
    crypto_scalarmult_base(x->pk, x->sk);
}

static void op_x25519_dh(void *c)
{
    x25519_ctx_t *x = c;
    if (crypto_scalarmult(x->shared, x->sk, x->peer_pk) != 0) {
        fprintf(stderr, "x25519 dh failed!\n");
        exit(1);
    }
}

typedef struct {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char msg[32];
    unsigned char sig[crypto_sign_BYTES];
} ed25519_ctx_t;

static void op_ed25519_keygen(void *c)
{
    ed25519_ctx_t *e = c;
    crypto_sign_keypair(e->pk, e->sk);
}

static void op_ed25519_sign(void *c)
{
    ed25519_ctx_t *e = c;
    unsigned long long siglen;
    crypto_sign_detached(e->sig, &siglen, e->msg, sizeof(e->msg), e->sk);
}

static void op_ed25519_verify(void *c)
{
    ed25519_ctx_t *e = c;
    if (crypto_sign_verify_detached(e->sig, e->msg, sizeof(e->msg), e->pk) != 0) {
        fprintf(stderr, "ed25519 verify failed!\n");
        exit(1);
    }
}

/* SHA-256 (libsodium) */
typedef struct { unsigned char in[64], out[crypto_hash_sha256_BYTES]; } sha_ctx_t;
static void op_sha256(void *c)
{
    sha_ctx_t *s = c;
    crypto_hash_sha256(s->out, s->in, sizeof(s->in));
}

/* HKDF-SHA256 (libsodium HMAC) */
typedef struct {
    unsigned char salt[32], ikm[32], info[16], okm[32];
} hkdf_ctx_t;
static void op_hkdf(void *c)
{
    hkdf_ctx_t *h = c;
    hkdf_sha256(h->salt, sizeof(h->salt), h->ikm, sizeof(h->ikm),
                h->info, sizeof(h->info), h->okm, sizeof(h->okm));
}

/* AES-128-GCM (mbedTLS) */
typedef struct {
    mbedtls_gcm_context gcm;
    unsigned char iv[12], aad[8], in[64], out[64], tag[16];
} aesgcm_ctx_t;
static void op_aes128gcm(void *c)
{
    aesgcm_ctx_t *a = c;
    if (mbedtls_gcm_crypt_and_tag(&a->gcm, MBEDTLS_GCM_ENCRYPT, sizeof(a->in),
            a->iv, sizeof(a->iv), a->aad, sizeof(a->aad),
            a->in, a->out, sizeof(a->tag), a->tag) != 0) {
        fprintf(stderr, "aes-128-gcm failed!\n");
        exit(1);
    }
}

/* ML-KEM-768 (PQClean) */
typedef struct {
    unsigned char pk[MLKEM768_PK], sk[MLKEM768_SK], ct[MLKEM768_CT];
    unsigned char ss_e[MLKEM768_SS], ss_d[MLKEM768_SS];
} mlkem_ctx_t;
static void op_mlkem_keygen(void *c)
{
    mlkem_ctx_t *m = c;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(m->pk, m->sk);
}
static void op_mlkem_encaps(void *c)
{
    mlkem_ctx_t *m = c;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(m->ct, m->ss_e, m->pk);
}
static void op_mlkem_decaps(void *c)
{
    mlkem_ctx_t *m = c;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(m->ss_d, m->ct, m->sk);
}

/* ML-DSA-44 (PQClean) */
typedef struct {
    unsigned char pk[MLDSA44_PK], sk[MLDSA44_SK], sig[MLDSA44_SIG];
    unsigned char msg[32];
    size_t siglen;
} mldsa_ctx_t;
static void op_mldsa_keygen(void *c)
{
    mldsa_ctx_t *d = c;
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(d->pk, d->sk);
}
static void op_mldsa_sign(void *c)
{
    mldsa_ctx_t *d = c;
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(d->sig, &d->siglen,
            d->msg, sizeof(d->msg), d->sk);
}
static void op_mldsa_verify(void *c)
{
    mldsa_ctx_t *d = c;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(d->sig, d->siglen,
            d->msg, sizeof(d->msg), d->pk) != 0) {
        fprintf(stderr, "ml-dsa-44 verify failed!\n");
        exit(1);
    }
}

/* -------- per-method breakdown model -------- */

typedef struct {
    int x25519_keygen;
    int x25519_dh;
    int ed25519_sign;
    int ed25519_verify;
    int mlkem_keygen;
    int mlkem_encaps;
    int mlkem_decaps;
    int mldsa_sign;
    int mldsa_verify;
} opcount_t;

typedef struct {
    int method;
    const char *profile;
    opcount_t initiator;
    opcount_t responder;
} method_def_t;

static const method_def_t METHODS[] = {
    { 0, "SIG/SIG Ed25519",            {1,1,1,1,0,0,0,0,0}, {1,1,1,1,0,0,0,0,0} },
    { 1, "SIG-Ed25519 / MAC-X25519",   {1,1,1,0,0,0,0,0,0}, {1,2,0,1,0,0,0,0,0} },
    { 2, "MAC-X25519 / SIG-Ed25519",   {1,2,0,1,0,0,0,0,0}, {1,1,1,0,0,0,0,0,0} },
    { 3, "MAC/MAC static-DH X25519",   {1,2,0,0,0,0,0,0,0}, {1,2,0,0,0,0,0,0,0} },
    /* method 4: SIGMA XWING — X25519+ML-KEM-768 hybrid KEM + ML-DSA-44 sig.
     * XWING KeyGen=xkg+mkg, Encaps=xkg+xdh+me, Decaps=xdh+md.
     * Initiator: KeyGen(pkX)+Encaps(pkB)+Decaps(cte)+Decaps(ctA)+KeyGen(NpkA)
     *            + ML-DSA verify(sigma_R) + ML-DSA sign(sigma_I).
     * Responder: Decaps(ctB)+Encaps(pkX)+Encaps(pkA)+KeyGen(NpkB)
     *            + ML-DSA sign(sigma_R) + ML-DSA verify(sigma_I). */
    { 4, "SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768)",
                                       {3,3,0,0,2,1,2,1,1}, {3,3,0,0,1,2,1,1,1} },
};
static const int N_METHODS = (int)(sizeof(METHODS) / sizeof(METHODS[0]));

static double role_total(const opcount_t *o)
{
    return o->x25519_keygen * lookup_mean("Keygen_X25519")
         + o->x25519_dh     * lookup_mean("ScalarMult_X25519")
         + o->ed25519_sign  * lookup_mean("Signature_Ed25519")
         + o->ed25519_verify* lookup_mean("Verify_Ed25519")
         + o->mlkem_keygen  * lookup_mean("Keygen_MLKEM768")
         + o->mlkem_encaps  * lookup_mean("Encaps_MLKEM768")
         + o->mlkem_decaps  * lookup_mean("Decaps_MLKEM768")
         + o->mldsa_sign    * lookup_mean("Signature_MLDSA44")
         + o->mldsa_verify  * lookup_mean("Verify_MLDSA44");
}

static void write_breakdown_rows(FILE *f, int method, const char *profile,
                                 const char *role, const opcount_t *o)
{
    struct { const char *op; int cnt; const char *prim; } rows[] = {
        { "Keygen",     o->x25519_keygen + o->mlkem_keygen, "X25519/ML-KEM-768" },
        { "ScalarMult", o->x25519_dh,    "X25519" },
        { "Encaps",     o->mlkem_encaps, "ML-KEM-768" },
        { "Decaps",     o->mlkem_decaps, "ML-KEM-768" },
        { "Signature",  o->ed25519_sign + o->mldsa_sign, "Ed25519/ML-DSA-44" },
        { "Verify",     o->ed25519_verify + o->mldsa_verify, "Ed25519/ML-DSA-44" },
    };
    double contrib[6];
    contrib[0] = o->x25519_keygen * lookup_mean("Keygen_X25519")
               + o->mlkem_keygen  * lookup_mean("Keygen_MLKEM768");
    contrib[1] = o->x25519_dh     * lookup_mean("ScalarMult_X25519");
    contrib[2] = o->mlkem_encaps  * lookup_mean("Encaps_MLKEM768");
    contrib[3] = o->mlkem_decaps  * lookup_mean("Decaps_MLKEM768");
    contrib[4] = o->ed25519_sign  * lookup_mean("Signature_Ed25519")
               + o->mldsa_sign    * lookup_mean("Signature_MLDSA44");
    contrib[5] = o->ed25519_verify* lookup_mean("Verify_Ed25519")
               + o->mldsa_verify  * lookup_mean("Verify_MLDSA44");

    for (int i = 0; i < 6; i++) {
        fprintf(f, "%d,%s,%s,%s,%s,%d,%.1f\n",
                method, profile, role, rows[i].op, rows[i].prim,
                rows[i].cnt, contrib[i]);
    }
}

int main(int argc, char **argv)
{
    const char *outdir = (argc > 1) ? argv[1] : ".";
    int iters = (argc > 2) ? atoi(argv[2]) : 2000;
    if (iters < 200) iters = 200;

    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    fprintf(stderr, "[crypto_bench] iterations/op = %d\n", iters);
    fprintf(stderr, "[crypto_bench] libs: libsodium (X25519/Ed25519/SHA-256/HKDF), "
                    "mbedTLS (AES-128-GCM), PQClean (ML-KEM-768/ML-DSA-44)\n");

    /* ---- libsodium: X25519 ---- */
    x25519_ctx_t xc;
    op_x25519_keygen(&xc);
    memcpy(xc.peer_pk, xc.pk, sizeof(xc.peer_pk));
    bench_op("Keygen_X25519",     "libsodium", op_x25519_keygen, &xc, iters);
    bench_op("ScalarMult_X25519", "libsodium", op_x25519_dh,     &xc, iters);

    /* ---- libsodium: Ed25519 ---- */
    ed25519_ctx_t ec;
    memset(ec.msg, 0xA5, sizeof(ec.msg));
    op_ed25519_keygen(&ec);
    op_ed25519_sign(&ec);
    bench_op("Keygen_Ed25519",    "libsodium", op_ed25519_keygen, &ec, iters);
    bench_op("Signature_Ed25519", "libsodium", op_ed25519_sign,   &ec, iters);
    bench_op("Verify_Ed25519",    "libsodium", op_ed25519_verify, &ec, iters);

    /* ---- libsodium: SHA-256 + HKDF ---- */
    sha_ctx_t sc;
    memset(sc.in, 0x5A, sizeof(sc.in));
    bench_op("SHA256",            "libsodium", op_sha256, &sc, iters);

    hkdf_ctx_t hc;
    memset(&hc, 0x33, sizeof(hc));
    bench_op("HKDF_SHA256",       "libsodium", op_hkdf, &hc, iters);

    /* ---- mbedTLS: AES-128-GCM ---- */
    aesgcm_ctx_t ac;
    mbedtls_gcm_init(&ac.gcm);
    unsigned char aes_key[16];
    randombytes_buf(aes_key, sizeof(aes_key));
    if (mbedtls_gcm_setkey(&ac.gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 128) != 0) {
        fprintf(stderr, "gcm setkey failed\n"); return 1;
    }
    memset(ac.iv, 0x01, sizeof(ac.iv));
    memset(ac.aad, 0x02, sizeof(ac.aad));
    memset(ac.in, 0x03, sizeof(ac.in));
    bench_op("AES128GCM",         "mbedTLS",   op_aes128gcm, &ac, iters);
    mbedtls_gcm_free(&ac.gcm);

    /* ---- PQClean: ML-KEM-768 ---- */
    mlkem_ctx_t mc;
    op_mlkem_keygen(&mc);
    op_mlkem_encaps(&mc);
    bench_op("Keygen_MLKEM768",   "PQClean",   op_mlkem_keygen, &mc, iters);
    bench_op("Encaps_MLKEM768",   "PQClean",   op_mlkem_encaps, &mc, iters);
    bench_op("Decaps_MLKEM768",   "PQClean",   op_mlkem_decaps, &mc, iters);

    /* ---- PQClean: ML-DSA-44 ---- */
    mldsa_ctx_t dc;
    memset(dc.msg, 0x7E, sizeof(dc.msg));
    op_mldsa_keygen(&dc);
    op_mldsa_sign(&dc);
    bench_op("Keygen_MLDSA44",    "PQClean",   op_mldsa_keygen, &dc, iters);
    bench_op("Signature_MLDSA44", "PQClean",   op_mldsa_sign,   &dc, iters);
    bench_op("Verify_MLDSA44",    "PQClean",   op_mldsa_verify, &dc, iters);

    /* ---- write primitives CSV ---- */
    char path[1024];
    snprintf(path, sizeof(path), "%s/crypto-primitives.csv", outdir);
    FILE *fp = fopen(path, "w");
    if (!fp) { perror("fopen primitives"); return 1; }
    fprintf(fp, "operation,library,iterations,mean_ns,median_ns,p95_ns,p99_ns,stddev_ns,min_ns,max_ns\n");
    for (int i = 0; i < g_nops; i++) {
        op_stat_t *o = &g_ops[i];
        fprintf(fp, "%s,%s,%d,%.1f,%.1f,%.1f,%.1f,%.1f,%lld,%lld\n",
                o->name, o->lib, o->iters, o->mean_ns, o->median_ns,
                o->p95_ns, o->p99_ns, o->stddev_ns, o->min_ns, o->max_ns);
    }
    fclose(fp);
    fprintf(stderr, "[crypto_bench] wrote %s\n", path);

    /* ---- write breakdown CSV ---- */
    snprintf(path, sizeof(path), "%s/crypto-breakdown.csv", outdir);
    FILE *fb = fopen(path, "w");
    if (!fb) { perror("fopen breakdown"); return 1; }
    fprintf(fb, "method,profile,role,operation,primitive,op_count,compute_ns\n");
    for (int i = 0; i < N_METHODS; i++) {
        write_breakdown_rows(fb, METHODS[i].method, METHODS[i].profile,
                             "initiator", &METHODS[i].initiator);
        write_breakdown_rows(fb, METHODS[i].method, METHODS[i].profile,
                             "responder", &METHODS[i].responder);
    }
    fclose(fb);
    fprintf(stderr, "[crypto_bench] wrote %s\n", path);

    /* ---- write handshake totals CSV ---- */
    snprintf(path, sizeof(path), "%s/handshake-compute.csv", outdir);
    FILE *fh = fopen(path, "w");
    if (!fh) { perror("fopen handshake"); return 1; }
    fprintf(fh, "method,profile,initiator_compute_us,responder_compute_us,total_compute_us\n");
    for (int i = 0; i < N_METHODS; i++) {
        double ini = role_total(&METHODS[i].initiator) / 1000.0;
        double res = role_total(&METHODS[i].responder) / 1000.0;
        fprintf(fh, "%d,%s,%.3f,%.3f,%.3f\n",
                METHODS[i].method, METHODS[i].profile, ini, res, ini + res);
    }
    fclose(fh);
    fprintf(stderr, "[crypto_bench] wrote %s\n", path);

    return 0;
}
