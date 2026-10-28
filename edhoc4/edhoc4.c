/*
 * edhoc4.c — Shared EAP-EDHOC method 4 (SIGMA XWING) core, revision "no-eph":
 * no ephemeral X-Wing key pair; forward secrecy from one-time static keys.
 * See edhoc4.h and mermaid.md §5.
 */
#define _POSIX_C_SOURCE 200809L
#include "edhoc4.h"

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sodium.h>
#include <mbedtls/gcm.h>

/* ---- PQClean (clean reference, namespaced) ---- */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk,
        const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss,
        const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *pk);

/* PQClean common/fips202.c (linked into libedhoc4.a) */
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

/* XWingLabel, hex 5c2e2f2f5e5c (draft-connolly-cfrg-xwing-kem-09, Sec. 5.3) */
static const uint8_t XWING_LABEL[6] = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };

/* ======================================================================== */
/* Crypto helpers                                                            */
/* ======================================================================== */

static void sha256(uint8_t out[32], const uint8_t *in, size_t len)
{
    crypto_hash_sha256(out, in, len);
}

/* SHA-256 over a list of segments */
static void sha256_cat(uint8_t out[32], const uint8_t *const *segs,
                       const size_t *lens, int n)
{
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    for (int i = 0; i < n; i++)
        crypto_hash_sha256_update(&st, segs[i], lens[i]);
    crypto_hash_sha256_final(&st, out);
}

/* HKDF-Extract (RFC 5869) over libsodium HMAC-SHA256 */
static void hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[32])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);
}

/* HKDF-Expand (RFC 5869) */
static void hkdf_expand(const uint8_t prk[32],
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    uint8_t t[32];
    size_t done = 0, tlen = 0;
    uint8_t ctr = 1;
    while (done < okm_len) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, 32);
        if (tlen) crypto_auth_hmacsha256_update(&st, t, tlen);
        crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &ctr, 1);
        crypto_auth_hmacsha256_final(&st, t);
        tlen = 32;
        size_t n = (okm_len - done < tlen) ? (okm_len - done) : tlen;
        memcpy(okm + done, t, n);
        done += n;
        ctr++;
    }
    sodium_memzero(t, sizeof(t));
}

/* Derive AEAD key||nonce from (prk, th) */
static void derive_k(const uint8_t prk[32], const uint8_t th[32],
                     uint8_t key[E4_AEAD_KEY], uint8_t nonce[E4_AEAD_NONCE])
{
    uint8_t info[32 + 5];
    memcpy(info, th, 32);
    memcpy(info + 32, "E4KEY", 5);
    uint8_t okm[E4_AEAD_KEY + E4_AEAD_NONCE];
    hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm));
    memcpy(key, okm, E4_AEAD_KEY);
    memcpy(nonce, okm + E4_AEAD_KEY, E4_AEAD_NONCE);
    sodium_memzero(okm, sizeof(okm));
}

/* AES-128-GCM (mbedTLS), 16-byte tag, AAD = TH_x (32 B).  ct = C || tag. */
static int gcm_seal(const uint8_t key[E4_AEAD_KEY], const uint8_t nonce[E4_AEAD_NONCE],
                    const uint8_t aad[32], const uint8_t *pt, size_t pt_len, uint8_t *ct)
{
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 8 * E4_AEAD_KEY);
    if (rc == 0)
        rc = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, pt_len, nonce, E4_AEAD_NONCE,
                                       aad, 32, pt, ct, E4_AEAD_TAG, ct + pt_len);
    mbedtls_gcm_free(&g);
    return rc;
}

static int gcm_open(const uint8_t key[E4_AEAD_KEY], const uint8_t nonce[E4_AEAD_NONCE],
                    const uint8_t aad[32], const uint8_t *ct, size_t ct_len, uint8_t *pt)
{
    size_t n = ct_len - E4_AEAD_TAG;
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 8 * E4_AEAD_KEY);
    if (rc == 0)
        rc = mbedtls_gcm_auth_decrypt(&g, n, nonce, E4_AEAD_NONCE, aad, 32,
                                      ct + n, E4_AEAD_TAG, ct, pt);
    mbedtls_gcm_free(&g);
    if (rc != 0) sodium_memzero(pt, n);
    return rc;
}

static int aead_seal(const uint8_t prk[32], const uint8_t th[32],
                     const uint8_t *pt, size_t pt_len,
                     uint8_t *ct, size_t *ct_len)
{
    uint8_t key[E4_AEAD_KEY], nonce[E4_AEAD_NONCE];
    derive_k(prk, th, key, nonce);
    int rc = gcm_seal(key, nonce, th, pt, pt_len, ct);
    sodium_memzero(key, sizeof(key));
    if (rc != 0) return E4_ERR_AEAD;
    *ct_len = pt_len + E4_AEAD_TAG;
    return E4_OK;
}

static int aead_open(const uint8_t prk[32], const uint8_t th[32],
                     const uint8_t *ct, size_t ct_len,
                     uint8_t *pt, size_t *pt_len)
{
    uint8_t key[E4_AEAD_KEY], nonce[E4_AEAD_NONCE];
    derive_k(prk, th, key, nonce);
    if (ct_len < E4_AEAD_TAG) { sodium_memzero(key, sizeof(key)); return E4_ERR_AEAD; }
    int rc = gcm_open(key, nonce, th, ct, ct_len, pt);
    sodium_memzero(key, sizeof(key));
    if (rc != 0) return E4_ERR_AEAD;
    *pt_len = ct_len - E4_AEAD_TAG;
    return E4_OK;
}

/* MAC_x = HKDF-Expand(prk, th || id_cred || ead, E4_MAC_LEN) */
static void compute_mac(const uint8_t prk[32], const uint8_t th[32],
                        const uint8_t id_cred[E4_ID_CRED],
                        const uint8_t *ead, size_t ead_len,
                        uint8_t mac[E4_MAC_LEN])
{
    uint8_t info[32 + E4_ID_CRED + E4_XWING_PK];
    size_t off = 0;
    memcpy(info + off, th, 32); off += 32;
    memcpy(info + off, id_cred, E4_ID_CRED); off += E4_ID_CRED;
    if (ead_len) { memcpy(info + off, ead, ead_len); off += ead_len; }
    hkdf_expand(prk, info, off, mac, E4_MAC_LEN);
}

/* signature message = th || id_cred || mac */
static size_t sig_message(uint8_t *buf, const uint8_t th[32],
                          const uint8_t id_cred[E4_ID_CRED],
                          const uint8_t mac[E4_MAC_LEN])
{
    size_t off = 0;
    memcpy(buf + off, th, 32); off += 32;
    memcpy(buf + off, id_cred, E4_ID_CRED); off += E4_ID_CRED;
    memcpy(buf + off, mac, E4_MAC_LEN); off += E4_MAC_LEN;
    return off;
}

/* ---- X-Wing hybrid KEM (ML-KEM-768 + X25519) ----
 * draft-connolly-cfrg-xwing-kem-09: pk = pk_M || pk_X, ct = ct_M || ct_X,
 * ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel). The 32-byte
 * seed is expanded with SHAKE256 into (d, z, sk_X); sk holds the expanded
 * key (sk_M || sk_X), as Sec. 5.5.1 permits for a key that stays local, and
 * the decapsulator takes pk_X from its own pk instead of recomputing it. */

/* GenerateKeyPairDerand(seed), keeping the expanded decapsulation key */
static int xwing_keypair_derand(uint8_t pk[E4_XWING_PK], uint8_t sk[E4_XWING_SK],
                                const uint8_t seed[32])
{
    uint8_t expanded[96];
    shake256(expanded, sizeof(expanded), seed, 32);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, expanded);  /* d || z */
    memcpy(sk + E4_MLKEM_SK, expanded + 64, E4_X25519_SK);
    int rc = crypto_scalarmult_base(pk + E4_MLKEM_PK, sk + E4_MLKEM_SK) == 0
             ? E4_OK : E4_ERR_KEM;
    sodium_memzero(expanded, sizeof(expanded));
    return rc;
}

static int xwing_keypair(uint8_t pk[E4_XWING_PK], uint8_t sk[E4_XWING_SK])
{
    uint8_t seed[32];
    randombytes_buf(seed, sizeof(seed));
    int rc = xwing_keypair_derand(pk, sk, seed);
    sodium_memzero(seed, sizeof(seed));
    return rc;
}

static void xwing_combine(uint8_t ss[32], const uint8_t ss_m[32],
                          const uint8_t ss_x[32], const uint8_t ct_x[32],
                          const uint8_t pk_x[32])
{
    uint8_t buf[32 * 4 + sizeof(XWING_LABEL)];
    memcpy(buf, ss_m, 32);
    memcpy(buf + 32, ss_x, 32);
    memcpy(buf + 64, ct_x, 32);
    memcpy(buf + 96, pk_x, 32);
    memcpy(buf + 128, XWING_LABEL, sizeof(XWING_LABEL));
    sha3_256(ss, buf, sizeof(buf));
    sodium_memzero(buf, sizeof(buf));
}

/* EncapsulateDerand(pk, eseed): eseed = ML-KEM coins (32) || ek_X (32) */
static int xwing_encaps_derand(uint8_t ct[E4_XWING_CT], uint8_t ss[E4_XWING_SS],
                               const uint8_t pk[E4_XWING_PK], const uint8_t eseed[64])
{
    const uint8_t *pk_x = pk + E4_MLKEM_PK;
    uint8_t *ct_x = ct + E4_MLKEM_CT;
    uint8_t ss_m[32], ss_x[32];
    int rc = E4_ERR_KEM;
    if (crypto_scalarmult_base(ct_x, eseed + 32) != 0) goto out;      /* ct_X = g^e */
    if (crypto_scalarmult(ss_x, eseed + 32, pk_x) != 0) goto out;
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss_m, pk, eseed);
    xwing_combine(ss, ss_m, ss_x, ct_x, pk_x);
    rc = E4_OK;
out:
    sodium_memzero(ss_x, sizeof(ss_x));
    sodium_memzero(ss_m, sizeof(ss_m));
    return rc;
}

static int xwing_encaps(uint8_t ct[E4_XWING_CT], uint8_t ss[E4_XWING_SS],
                        const uint8_t pk[E4_XWING_PK])
{
    uint8_t eseed[64];
    randombytes_buf(eseed, sizeof(eseed));
    int rc = xwing_encaps_derand(ct, ss, pk, eseed);
    sodium_memzero(eseed, sizeof(eseed));
    return rc;
}

/* sk is the expanded key, pk the party's own X-Wing public key */
static int xwing_decaps(uint8_t ss[E4_XWING_SS], const uint8_t ct[E4_XWING_CT],
                        const uint8_t sk[E4_XWING_SK], const uint8_t pk[E4_XWING_PK])
{
    uint8_t ss_m[32], ss_x[32];
    const uint8_t *ct_x = ct + E4_MLKEM_CT;
    int rc = E4_ERR_KEM;
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_m, ct, sk) != 0) goto out;
    if (crypto_scalarmult(ss_x, sk + E4_MLKEM_SK, ct_x) != 0) goto out;
    xwing_combine(ss, ss_m, ss_x, ct_x, pk + E4_MLKEM_PK);
    rc = E4_OK;
out:
    sodium_memzero(ss_x, sizeof(ss_x));
    sodium_memzero(ss_m, sizeof(ss_m));
    return rc;
}

int edhoc4_xwing_selftest_kat(const uint8_t seed[32], const uint8_t eseed[64],
                              uint8_t pk[E4_XWING_PK], uint8_t ct[E4_XWING_CT],
                              uint8_t ss_enc[E4_XWING_SS], uint8_t ss_dec[E4_XWING_SS])
{
    uint8_t sk[E4_XWING_SK];
    int rc = xwing_keypair_derand(pk, sk, seed);
    if (rc == E4_OK) rc = xwing_encaps_derand(ct, ss_enc, pk, eseed);
    if (rc == E4_OK) rc = xwing_decaps(ss_dec, ct, sk, pk);
    sodium_memzero(sk, sizeof(sk));
    return rc;
}

/* ---- optional rotation-key pool (off unless filled or started) ----
 * The next one-time key pair does not depend on the session, so a deployment
 * may generate it before the handshake that announces it. Taken keys are
 * wiped from the pool; an empty pool (the default) generates inline. */
typedef struct {
    uint8_t pk[E4_XWING_PK];
    uint8_t sk[E4_XWING_SK];
} pool_key;

static pool_key        pool_keys[E4_POOL_MAX];
static int             pool_n, pool_target, pool_thread_on;
static unsigned long   pool_miss;
static pthread_mutex_t pool_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  pool_cv = PTHREAD_COND_INITIALIZER;

static int pool_clamp(int n)
{
    return n < 0 ? 0 : (n > E4_POOL_MAX ? E4_POOL_MAX : n);
}

/* generate one key outside the lock, then store it if there is room */
static int pool_add_one(void)
{
    pool_key k;
    if (xwing_keypair(k.pk, k.sk) != E4_OK) return E4_ERR_KEM;
    pthread_mutex_lock(&pool_mu);
    if (pool_n < E4_POOL_MAX) pool_keys[pool_n++] = k;
    pthread_mutex_unlock(&pool_mu);
    sodium_memzero(&k, sizeof(k));
    return E4_OK;
}

int edhoc4_pool_fill(int n)
{
    n = pool_clamp(n);
    for (;;) {
        pthread_mutex_lock(&pool_mu);
        int have = pool_n;
        pthread_mutex_unlock(&pool_mu);
        if (have >= n) return E4_OK;
        if (pool_add_one() != E4_OK) return E4_ERR_KEM;
    }
}

static void *pool_main(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&pool_mu);
        while (pool_n >= pool_target) pthread_cond_wait(&pool_cv, &pool_mu);
        pthread_mutex_unlock(&pool_mu);
        pool_add_one();
    }
    return NULL;
}

int edhoc4_pool_start(int n)
{
    pthread_mutex_lock(&pool_mu);
    pool_target = pool_clamp(n);
    pthread_cond_signal(&pool_cv);
    pthread_mutex_unlock(&pool_mu);
    return E4_OK;
}

unsigned long edhoc4_pool_misses(void)
{
    pthread_mutex_lock(&pool_mu);
    unsigned long m = pool_miss;
    pthread_mutex_unlock(&pool_mu);
    return m;
}

/* The refill thread starts on the first take, i.e. in the process that
 * serves handshakes (after any daemon fork). */
static int next_keypair(uint8_t pk[E4_XWING_PK], uint8_t sk[E4_XWING_SK])
{
    pthread_mutex_lock(&pool_mu);
    if (pool_target > 0 && !pool_thread_on) {
        pthread_t t;
        if (pthread_create(&t, NULL, pool_main, NULL) == 0) {
            pthread_detach(t);
            pool_thread_on = 1;
        }
    }
    if (pool_n > 0) {
        pool_key *k = &pool_keys[--pool_n];
        memcpy(pk, k->pk, E4_XWING_PK);
        memcpy(sk, k->sk, E4_XWING_SK);
        sodium_memzero(k, sizeof(*k));
        pthread_cond_signal(&pool_cv);
        pthread_mutex_unlock(&pool_mu);
        return E4_OK;
    }
    pool_miss++;
    pthread_mutex_unlock(&pool_mu);
    return xwing_keypair(pk, sk);
}

/* ======================================================================== */
/* Key-schedule + exporter                                                   */
/* ======================================================================== */

static void derive_prk_out_and_msk(edhoc4_ctx *ctx)
{
    hkdf_expand(ctx->prk4e3m, ctx->th4, 32, ctx->prk_out, E4_PRK_LEN);
    hkdf_expand(ctx->prk_out, (const uint8_t *)"EDHOC-EAP-MSK", 13,
                ctx->msk, E4_MSK_LEN);
    hkdf_expand(ctx->prk_out, (const uint8_t *)"EDHOC-EAP-EMSK", 14,
                ctx->emsk, E4_EMSK_LEN);
    ctx->done = 1;
}

/* ======================================================================== */
/* Credentials + context init                                                */
/* ======================================================================== */

int edhoc4_gen_creds(edhoc4_creds *c, const uint8_t id_cred[E4_ID_CRED])
{
    if (!c) return E4_ERR_ARG;
    if (sodium_init() < 0) return E4_ERR_ARG;
    memset(c, 0, sizeof(*c));
    if (xwing_keypair(c->kem_pk, c->kem_sk) != E4_OK) return E4_ERR_KEM;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(c->sig_vk, c->sig_sk) != 0)
        return E4_ERR_SIG;
    if (id_cred) memcpy(c->id_cred, id_cred, E4_ID_CRED);
    return E4_OK;
}

int edhoc4_creds_save(const char *path, const edhoc4_creds *c)
{
    if (!path || !c) return E4_ERR_ARG;
    FILE *f = fopen(path, "wb");
    if (!f) return E4_ERR_ARG;
    size_t n = fwrite(c, 1, sizeof(*c), f);
    fclose(f);
    return (n == sizeof(*c)) ? E4_OK : E4_ERR_ARG;
}

int edhoc4_creds_load(const char *path, edhoc4_creds *c)
{
    if (!path || !c) return E4_ERR_ARG;
    FILE *f = fopen(path, "rb");
    if (!f) return E4_ERR_ARG;
    size_t n = fread(c, 1, sizeof(*c), f);
    fclose(f);
    return (n == sizeof(*c)) ? E4_OK : E4_ERR_PARSE;
}

int edhoc4_pub_save(const char *path, const edhoc4_creds *c)
{
    if (!path || !c) return E4_ERR_ARG;
    FILE *f = fopen(path, "wb");
    if (!f) return E4_ERR_ARG;
    size_t n = fwrite(c->kem_pk, 1, E4_XWING_PK, f);
    fclose(f);
    return (n == E4_XWING_PK) ? E4_OK : E4_ERR_ARG;
}

int edhoc4_pub_load(const char *path, uint8_t peer_kem_pk[E4_XWING_PK])
{
    if (!path || !peer_kem_pk) return E4_ERR_ARG;
    FILE *f = fopen(path, "rb");
    if (!f) return E4_ERR_ARG;
    size_t n = fread(peer_kem_pk, 1, E4_XWING_PK, f);
    fclose(f);
    return (n == E4_XWING_PK) ? E4_OK : E4_ERR_PARSE;
}

/* Write buf to path.tmp, fsync, then rename over path, so a crash never
 * leaves a half-written key file (the old or the new one survives). */
static int save_atomic(const char *path, const void *buf, size_t len)
{
    char tmp[4096];
    if (!path || !buf) return E4_ERR_ARG;
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= sizeof(tmp)) return E4_ERR_ARG;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return E4_ERR_ARG;
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);
        if (n <= 0) { close(fd); unlink(tmp); return E4_ERR_ARG; }
        off += (size_t)n;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return E4_ERR_ARG; }
    if (close(fd) != 0) { unlink(tmp); return E4_ERR_ARG; }
    if (rename(tmp, path) != 0) { unlink(tmp); return E4_ERR_ARG; }
    return E4_OK;
}

int edhoc4_creds_save_atomic(const char *path, const edhoc4_creds *c)
{
    if (!c) return E4_ERR_ARG;
    return save_atomic(path, c, sizeof(*c));
}

int edhoc4_pub_save_atomic_raw(const char *path, const uint8_t pk[E4_XWING_PK])
{
    if (!pk) return E4_ERR_ARG;
    return save_atomic(path, pk, E4_XWING_PK);
}

/* ---- two-slot key record ----
 * block 0 (4096 B): magic "E4R2", version, slot size, payload length
 * slot i at REC_HDR + i * REC_SLOT: u64 seq, u32 len, u32 0,
 *     payload = creds || peer pk, tag = SHA-256(seq..payload)
 * Slots are page-aligned so a torn write stays within one slot. Native
 * byte order: the file never leaves the host that wrote it. */
#define REC_HDR      4096
#define REC_SLOT_HDR 16
#define REC_SLOT     ((REC_SLOT_HDR + E4_REC_PAYLOAD + 32 + 4095) / 4096 * 4096)
#define REC_SIZE     (REC_HDR + 2 * REC_SLOT)

typedef struct {
    uint8_t magic[4];
    uint32_t version, slot_size, payload_len;
} rec_header;

static uint8_t *rec_slot_build(uint64_t seq, const edhoc4_creds *self,
                               const uint8_t peer_pk[E4_XWING_PK], uint8_t *buf)
{
    uint32_t len = (uint32_t)E4_REC_PAYLOAD, z = 0;
    memset(buf, 0, REC_SLOT);
    memcpy(buf, &seq, 8);
    memcpy(buf + 8, &len, 4);
    memcpy(buf + 12, &z, 4);
    memcpy(buf + REC_SLOT_HDR, self, sizeof(*self));
    memcpy(buf + REC_SLOT_HDR + sizeof(*self), peer_pk, E4_XWING_PK);
    crypto_hash_sha256(buf + REC_SLOT_HDR + E4_REC_PAYLOAD, buf, REC_SLOT_HDR + E4_REC_PAYLOAD);
    return buf;
}

static int rec_slot_ok(const uint8_t *buf, uint64_t *seq)
{
    uint8_t tag[32];
    uint32_t len;
    memcpy(seq, buf, 8);
    memcpy(&len, buf + 8, 4);
    if (*seq == 0 || len != E4_REC_PAYLOAD) return 0;
    crypto_hash_sha256(tag, buf, REC_SLOT_HDR + E4_REC_PAYLOAD);
    return sodium_memcmp(tag, buf + REC_SLOT_HDR + E4_REC_PAYLOAD, 32) == 0;
}

static int rec_pwrite(int fd, const void *buf, size_t len, off_t off)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = pwrite(fd, p, len, off);
        if (n <= 0) return -1;
        p += n; len -= (size_t)n; off += n;
    }
    return 0;
}

/* open the record, check the header and read both slots into slots[2] */
static int rec_open(const char *path, int flags, uint8_t (*slots)[REC_SLOT],
                    edhoc4_rec_info *info)
{
    rec_header h;
    int fd = open(path, flags);
    if (fd < 0) return -1;
    if (pread(fd, &h, sizeof(h), 0) != (ssize_t)sizeof(h) || memcmp(h.magic, "E4R2", 4) != 0 ||
        h.version != 1 || h.slot_size != REC_SLOT || h.payload_len != E4_REC_PAYLOAD) {
        close(fd);
        return -1;
    }
    info->active = -1;
    for (int i = 0; i < 2; i++) {
        info->seq[i] = 0;
        info->valid[i] = pread(fd, slots[i], REC_SLOT, REC_HDR + (off_t)i * REC_SLOT) == REC_SLOT &&
                         rec_slot_ok(slots[i], &info->seq[i]);
        if (info->valid[i] && (info->active < 0 || info->seq[i] > info->seq[info->active]))
            info->active = i;
    }
    return fd;
}

int edhoc4_rec_create(const char *path, const edhoc4_creds *self,
                      const uint8_t peer_pk[E4_XWING_PK])
{
    static uint8_t zero[REC_SIZE];
    static uint8_t slot[REC_SLOT];
    rec_header h = { { 'E', '4', 'R', '2' }, 1, REC_SLOT, (uint32_t)E4_REC_PAYLOAD };
    if (!path || !self || !peer_pk) return E4_ERR_ARG;
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return E4_ERR_ARG;
    /* write every block once, so later overwrites need no extent change */
    int rc = (posix_fallocate(fd, 0, REC_SIZE) == 0 && rec_pwrite(fd, zero, REC_SIZE, 0) == 0 &&
              rec_pwrite(fd, &h, sizeof(h), 0) == 0 &&
              rec_pwrite(fd, rec_slot_build(1, self, peer_pk, slot), REC_SLOT, REC_HDR) == 0 &&
              fsync(fd) == 0) ? E4_OK : E4_ERR_ARG;
    sodium_memzero(slot, sizeof(slot));
    close(fd);
    return rc;
}

int edhoc4_rec_load(const char *path, int prev, edhoc4_creds *self,
                    uint8_t peer_pk[E4_XWING_PK], edhoc4_rec_info *info)
{
    static __thread uint8_t slots[2][REC_SLOT];
    edhoc4_rec_info tmp;
    if (!path || !self || !peer_pk) return E4_ERR_ARG;
    if (!info) info = &tmp;
    int fd = rec_open(path, O_RDONLY, slots, info);
    if (fd < 0) return E4_ERR_ARG;
    close(fd);
    int rc = E4_ERR_PARSE;
    int i = info->active < 0 ? -1 : (prev ? 1 - info->active : info->active);
    if (i >= 0 && info->valid[i]) {
        memcpy(self, slots[i] + REC_SLOT_HDR, sizeof(*self));
        memcpy(peer_pk, slots[i] + REC_SLOT_HDR + sizeof(*self), E4_XWING_PK);
        rc = E4_OK;
    }
    sodium_memzero(slots, sizeof(slots));
    return rc;
}

int edhoc4_rec_commit(const char *path, const edhoc4_creds *self,
                      const uint8_t peer_pk[E4_XWING_PK], int keep_prev)
{
    static __thread uint8_t slots[2][REC_SLOT];
    edhoc4_rec_info info;
    if (!path || !self || !peer_pk) return E4_ERR_ARG;
    int fd = rec_open(path, O_RDWR, slots, &info);
    if (fd < 0) return E4_ERR_ARG;
    int rc = E4_ERR_STATE;
    if (info.active >= 0) {
        int w = 1 - info.active;
        rc = (rec_pwrite(fd, rec_slot_build(info.seq[info.active] + 1, self, peer_pk, slots[w]),
                         REC_SLOT, REC_HDR + (off_t)w * REC_SLOT) == 0 &&
              fdatasync(fd) == 0) ? E4_OK : E4_ERR_ARG;
        if (rc == E4_OK && !keep_prev) {
            memset(slots[0], 0, REC_SLOT);
            rec_pwrite(fd, slots[0], REC_SLOT, REC_HDR + (off_t)info.active * REC_SLOT);
        }
    }
    sodium_memzero(slots, sizeof(slots));
    close(fd);
    return rc;
}

int edhoc4_rec_erase_prev(const char *path)
{
    static __thread uint8_t slots[2][REC_SLOT];
    edhoc4_rec_info info;
    int fd = rec_open(path, O_RDWR, slots, &info);
    if (fd < 0) return E4_ERR_ARG;
    int rc = E4_OK;
    if (info.active >= 0 && info.valid[1 - info.active]) {
        memset(slots[0], 0, REC_SLOT);
        rc = rec_pwrite(fd, slots[0], REC_SLOT, REC_HDR + (off_t)(1 - info.active) * REC_SLOT) == 0
             ? E4_OK : E4_ERR_ARG;
    }
    sodium_memzero(slots, sizeof(slots));
    close(fd);
    return rc;
}

int edhoc4_rec_promote_prev(const char *path)
{
    static __thread uint8_t slots[2][REC_SLOT];
    edhoc4_rec_info info;
    int fd = rec_open(path, O_RDWR, slots, &info);
    if (fd < 0) return E4_ERR_ARG;
    int rc = E4_ERR_STATE;
    if (info.active >= 0 && info.valid[1 - info.active]) {
        int a = info.active, p = 1 - a;
        uint64_t seq = info.seq[a] + 1;
        /* same payload as prev, new seq and tag, written over the unused
         * rotated record in the active slot */
        memcpy(slots[a], slots[p], REC_SLOT);
        memcpy(slots[a], &seq, 8);
        crypto_hash_sha256(slots[a] + REC_SLOT_HDR + E4_REC_PAYLOAD, slots[a], REC_SLOT_HDR + E4_REC_PAYLOAD);
        rc = (rec_pwrite(fd, slots[a], REC_SLOT, REC_HDR + (off_t)a * REC_SLOT) == 0 &&
              fdatasync(fd) == 0) ? E4_OK : E4_ERR_ARG;
    }
    sodium_memzero(slots, sizeof(slots));
    close(fd);
    return rc;
}

void edhoc4_init_initiator(edhoc4_ctx *ctx, const edhoc4_creds *self,
                           const uint8_t peer_kem_pk[E4_XWING_PK])
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->role = 1;
    ctx->self = *self;
    memcpy(ctx->peer_kem_pk, peer_kem_pk, E4_XWING_PK);
    ctx->c_i[0] = 0x10;
}

void edhoc4_init_responder(edhoc4_ctx *ctx, const edhoc4_creds *self,
                           const uint8_t peer_kem_pk[E4_XWING_PK])
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->role = 0;
    ctx->self = *self;
    memcpy(ctx->peer_kem_pk, peer_kem_pk, E4_XWING_PK);
    ctx->c_r[0] = 0x20;
}

/* ======================================================================== */
/* Revised protocol (v2): NO ephemeral X-Wing key pair.                      */
/*   - message_1 carries only ct_B (encapsulation to the responder's         */
/*     one-time static key pk_B); pk_X is gone.                              */
/*   - message_2 carries ct_A in the clear, in the place of ct_e.            */
/*   - PRK_2e = Extract(TH_2, ss_A); PRK_3e2m = Extract(PRK_2e, ss_B);       */
/*     PRK_4e3m = PRK_3e2m (ss_A is already in the schedule).                */
/*   - Forward secrecy comes from per-session rotation of pk_A / pk_B and    */
/*     erasure of the old secret keys (edhoc4_*_commit, edhoc4_ctx_wipe).    */
/* ======================================================================== */

/* ======================================================================== */
/* Message 1  (initiator -> responder)                                       */
/*   layout: ctB[1120] || AEAD(K1, PT1)                                      */
/*   PT1 = method(1) || C_I(1) || ID_CRED_I(3)                               */
/* ======================================================================== */

int edhoc4_i_make_msg1(edhoc4_ctx *ctx, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx->role != 1) return E4_ERR_STATE;

    uint8_t ct_b[E4_XWING_CT];
    if (xwing_encaps(ct_b, ctx->ss_b, ctx->peer_kem_pk) != E4_OK) return E4_ERR_KEM;

    /* TH1 = H(ctB) */
    sha256(ctx->th1, ct_b, E4_XWING_CT);

    /* PRK1e = HKDF-Extract(TH1, ss_b) */
    hkdf_extract(ctx->th1, 32, ctx->ss_b, E4_XWING_SS, ctx->prk1e);

    /* ID_CRED_I is needed by the responder to look up pk_A before message_2 */
    uint8_t pt1[2 + E4_ID_CRED];
    pt1[0] = E4_METHOD;
    pt1[1] = ctx->c_i[0];
    memcpy(pt1 + 2, ctx->self.id_cred, E4_ID_CRED);
    uint8_t ct1[sizeof(pt1) + E4_AEAD_TAG];
    size_t ct1_len = 0;
    if (aead_seal(ctx->prk1e, ctx->th1, pt1, sizeof(pt1), ct1, &ct1_len) != E4_OK)
        return E4_ERR_AEAD;

    size_t need = E4_XWING_CT + ct1_len;
    if (need > out_cap) return E4_ERR_BUF;
    size_t off = 0;
    memcpy(out + off, ct_b, E4_XWING_CT); off += E4_XWING_CT;
    memcpy(out + off, ct1, ct1_len); off += ct1_len;
    *out_len = off;

    /* keep H(message_1) for TH2 computation on msg2 */
    sha256(ctx->h_msg1, out, off);
    return E4_OK;
}

/* ======================================================================== */
/* Message 1 handling + Message 2  (responder)                               */
/*   msg2 = ctA[1120] || AEAD(K2, PT2)                                       */
/*   PT2 = C_R[1] || ID_CRED_R[3] || VK_R[1312] || MAC2[8] || sigma_R[2420]  */
/* ======================================================================== */

int edhoc4_r_handle_msg1(edhoc4_ctx *ctx, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx->role != 0) return E4_ERR_STATE;
    size_t min1 = E4_XWING_CT + 2 + E4_ID_CRED + E4_AEAD_TAG;
    if (in_len < min1) return E4_ERR_PARSE;

    const uint8_t *ct_b = in;
    const uint8_t *ct1  = in + E4_XWING_CT;
    size_t ct1_len = in_len - E4_XWING_CT;

    /* ss_b = Decaps(ctB, own static sk_B) */
    if (xwing_decaps(ctx->ss_b, ct_b, ctx->self.kem_sk, ctx->self.kem_pk) != E4_OK) return E4_ERR_KEM;

    /* TH1 = H(ctB); PRK1e; decrypt PT1 */
    sha256(ctx->th1, ct_b, E4_XWING_CT);
    hkdf_extract(ctx->th1, 32, ctx->ss_b, E4_XWING_SS, ctx->prk1e);

    uint8_t pt1[64]; size_t pt1_len = 0;
    if (aead_open(ctx->prk1e, ctx->th1, ct1, ct1_len, pt1, &pt1_len) != E4_OK)
        return E4_ERR_AEAD;
    if (pt1_len != 2 + E4_ID_CRED || pt1[0] != E4_METHOD) return E4_ERR_PARSE;
    ctx->c_i[0] = pt1[1];
    memcpy(ctx->peer_id_cred, pt1 + 2, E4_ID_CRED);

    /* (pk_A, VK_I) = Lookup(ID_CRED_I); falls back to the preloaded key */
    if (ctx->lookup &&
        ctx->lookup(ctx->peer_id_cred, ctx->peer_kem_pk, ctx->peer_sig_vk,
                    ctx->lookup_arg) != 0)
        return E4_ERR_PEER;

    /* H(message_1) */
    uint8_t h_msg1[32];
    sha256(h_msg1, in, in_len);

    /* (ssA, ctA) = Encaps(pkA = initiator one-time static key) */
    if (xwing_encaps(ctx->ct_a, ctx->ss_a, ctx->peer_kem_pk) != E4_OK) return E4_ERR_KEM;

    /* TH2 = H(H(msg1) || ctA || C_R) */
    const uint8_t *s2[3] = { h_msg1, ctx->ct_a, ctx->c_r };
    const size_t l2[3] = { 32, E4_XWING_CT, E4_CONN_ID };
    sha256_cat(ctx->th2, s2, l2, 3);

    /* PRK2e = Extract(TH2, ssA); PRK3e2m = Extract(PRK2e, ss_b) */
    hkdf_extract(ctx->th2, 32, ctx->ss_a, E4_XWING_SS, ctx->prk2e);
    hkdf_extract(ctx->prk2e, 32, ctx->ss_b, E4_XWING_SS, ctx->prk3e2m);

    /* MAC2 + sigma_R */
    uint8_t mac2[E4_MAC_LEN];
    compute_mac(ctx->prk3e2m, ctx->th2, ctx->self.id_cred, NULL, 0, mac2);

    uint8_t sigmsg[32 + E4_ID_CRED + E4_MAC_LEN];
    size_t sigmsg_len = sig_message(sigmsg, ctx->th2, ctx->self.id_cred, mac2);
    uint8_t sig_r[E4_MLDSA_SIG]; size_t sig_r_len = 0;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig_r, &sig_r_len,
            sigmsg, sigmsg_len, ctx->self.sig_sk) != 0) return E4_ERR_SIG;
    if (sig_r_len != E4_MLDSA_SIG) return E4_ERR_SIG;

    /* PT2 = C_R || ID_CRED_R || VK_R || MAC2 || sigma_R   (ctA moved out) */
    uint8_t pt2[E4_CONN_ID + E4_ID_CRED + E4_MLDSA_PK + E4_MAC_LEN + E4_MLDSA_SIG];
    size_t o = 0;
    memcpy(pt2 + o, ctx->c_r, E4_CONN_ID); o += E4_CONN_ID;
    memcpy(pt2 + o, ctx->self.id_cred, E4_ID_CRED); o += E4_ID_CRED;
    memcpy(pt2 + o, ctx->self.sig_vk, E4_MLDSA_PK); o += E4_MLDSA_PK;
    memcpy(pt2 + o, mac2, E4_MAC_LEN); o += E4_MAC_LEN;
    memcpy(pt2 + o, sig_r, E4_MLDSA_SIG); o += E4_MLDSA_SIG;

    /* TH3 = H(TH2 || PT2) */
    const uint8_t *s3[2] = { ctx->th2, pt2 };
    const size_t l3[2] = { 32, o };
    sha256_cat(ctx->th3, s3, l3, 2);

    /* K2 seal */
    uint8_t ct2[sizeof(pt2) + E4_AEAD_TAG]; size_t ct2_len = 0;
    if (aead_seal(ctx->prk2e, ctx->th2, pt2, o, ct2, &ct2_len) != E4_OK)
        return E4_ERR_AEAD;

    size_t need = E4_XWING_CT + ct2_len;
    if (need > out_cap) return E4_ERR_BUF;
    size_t off = 0;
    memcpy(out + off, ctx->ct_a, E4_XWING_CT); off += E4_XWING_CT;
    memcpy(out + off, ct2, ct2_len); off += ct2_len;
    *out_len = off;
    return E4_OK;
}

/* ======================================================================== */
/* Message 2 handling + Message 3  (initiator)                               */
/*   msg3 = AEAD(K3, PT3)                                                     */
/*   PT3 = ID_CRED_I || EAD3(NpkA) || MAC3 || VK_I || sigma_I                */
/* ======================================================================== */

int edhoc4_i_handle_msg2(edhoc4_ctx *ctx, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx->role != 1) return E4_ERR_STATE;
    if (in_len < E4_XWING_CT + E4_AEAD_TAG) return E4_ERR_PARSE;

    memcpy(ctx->ct_a, in, E4_XWING_CT);
    const uint8_t *ct2 = in + E4_XWING_CT;
    size_t ct2_len = in_len - E4_XWING_CT;

    /* ssA = Decaps(ctA, own one-time static sk_A)  (moved up) */
    if (xwing_decaps(ctx->ss_a, ctx->ct_a, ctx->self.kem_sk, ctx->self.kem_pk) != E4_OK) return E4_ERR_KEM;

    /* TH2 = H(H(msg1) || ctA || C_R) */
    ctx->c_r[0] = 0x20;               /* responder connection id (fixed)      */
    const uint8_t *s2[3] = { ctx->h_msg1, ctx->ct_a, ctx->c_r };
    const size_t l2[3] = { 32, E4_XWING_CT, E4_CONN_ID };
    sha256_cat(ctx->th2, s2, l2, 3);

    hkdf_extract(ctx->th2, 32, ctx->ss_a, E4_XWING_SS, ctx->prk2e);

    /* decrypt PT2 */
    uint8_t pt2[E4_CONN_ID + E4_ID_CRED + E4_MLDSA_PK + E4_MAC_LEN + E4_MLDSA_SIG + 16];
    size_t pt2_len = 0;
    if (aead_open(ctx->prk2e, ctx->th2, ct2, ct2_len, pt2, &pt2_len) != E4_OK)
        return E4_ERR_AEAD;
    size_t exp2 = E4_CONN_ID + E4_ID_CRED + E4_MLDSA_PK + E4_MAC_LEN + E4_MLDSA_SIG;
    if (pt2_len != exp2) return E4_ERR_PARSE;

    size_t o = 0;
    memcpy(ctx->c_r, pt2 + o, E4_CONN_ID); o += E4_CONN_ID;
    memcpy(ctx->peer_id_cred, pt2 + o, E4_ID_CRED); o += E4_ID_CRED;
    memcpy(ctx->peer_sig_vk, pt2 + o, E4_MLDSA_PK); o += E4_MLDSA_PK;
    const uint8_t *mac2 = pt2 + o; o += E4_MAC_LEN;
    const uint8_t *sig_r = pt2 + o; o += E4_MLDSA_SIG;

    /* PRK3e2m = Extract(PRK2e, ss_b) */
    hkdf_extract(ctx->prk2e, 32, ctx->ss_b, E4_XWING_SS, ctx->prk3e2m);

    /* verify MAC2 */
    uint8_t mac2_c[E4_MAC_LEN];
    compute_mac(ctx->prk3e2m, ctx->th2, ctx->peer_id_cred, NULL, 0, mac2_c);
    if (sodium_memcmp(mac2_c, mac2, E4_MAC_LEN) != 0) return E4_ERR_MAC;

    /* verify sigma_R */
    uint8_t sigmsg[32 + E4_ID_CRED + E4_MAC_LEN];
    size_t sigmsg_len = sig_message(sigmsg, ctx->th2, ctx->peer_id_cred, mac2_c);
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig_r, E4_MLDSA_SIG,
            sigmsg, sigmsg_len, ctx->peer_sig_vk) != 0) return E4_ERR_SIG;

    /* TH3 = H(TH2 || PT2) */
    const uint8_t *s3[2] = { ctx->th2, pt2 };
    const size_t l3[2] = { 32, pt2_len };
    sha256_cat(ctx->th3, s3, l3, 2);

    /* PRK4e3m = PRK3e2m  (ss_A already entered at PRK2e) */
    memcpy(ctx->prk4e3m, ctx->prk3e2m, E4_PRK_LEN);

    /* EAD3 = NpkA (fresh one-time static XWING keypair for the next session) */
    if (next_keypair(ctx->new_pk, ctx->new_sk) != E4_OK) return E4_ERR_KEM;

    /* MAC3 + sigma_I (EAD3 bound in MAC) */
    uint8_t mac3[E4_MAC_LEN];
    compute_mac(ctx->prk4e3m, ctx->th3, ctx->self.id_cred,
                ctx->new_pk, E4_XWING_PK, mac3);
    uint8_t sigmsg3[32 + E4_ID_CRED + E4_MAC_LEN];
    size_t sigmsg3_len = sig_message(sigmsg3, ctx->th3, ctx->self.id_cred, mac3);
    uint8_t sig_i[E4_MLDSA_SIG]; size_t sig_i_len = 0;
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig_i, &sig_i_len,
            sigmsg3, sigmsg3_len, ctx->self.sig_sk) != 0) return E4_ERR_SIG;

    /* PT3 = ID_CRED_I || EAD3 || MAC3 || VK_I || sigma_I */
    uint8_t pt3[E4_ID_CRED + E4_XWING_PK + E4_MAC_LEN + E4_MLDSA_PK + E4_MLDSA_SIG];
    size_t p = 0;
    memcpy(pt3 + p, ctx->self.id_cred, E4_ID_CRED); p += E4_ID_CRED;
    memcpy(pt3 + p, ctx->new_pk, E4_XWING_PK); p += E4_XWING_PK;
    memcpy(pt3 + p, mac3, E4_MAC_LEN); p += E4_MAC_LEN;
    memcpy(pt3 + p, ctx->self.sig_vk, E4_MLDSA_PK); p += E4_MLDSA_PK;
    memcpy(pt3 + p, sig_i, E4_MLDSA_SIG); p += E4_MLDSA_SIG;

    /* TH4 = H(TH3 || PT3) */
    const uint8_t *s4[2] = { ctx->th3, pt3 };
    const size_t l4[2] = { 32, p };
    sha256_cat(ctx->th4, s4, l4, 2);

    /* seal msg3 with K3 (PRK3e2m, TH3) */
    uint8_t ct3[sizeof(pt3) + E4_AEAD_TAG]; size_t ct3_len = 0;
    if (aead_seal(ctx->prk3e2m, ctx->th3, pt3, p, ct3, &ct3_len) != E4_OK)
        return E4_ERR_AEAD;
    if (ct3_len > out_cap) return E4_ERR_BUF;
    memcpy(out, ct3, ct3_len);
    *out_len = ct3_len;

    derive_prk_out_and_msk(ctx);
    ctx->done = 0;   /* not fully done until msg4 processed (pkB rotation)  */
    return E4_OK;
}

/* ======================================================================== */
/* Message 3 handling + Message 4  (responder)                               */
/*   msg4 = AEAD(K4, EAD4=NpkB[1216])                                         */
/* ======================================================================== */

int edhoc4_r_handle_msg3(edhoc4_ctx *ctx, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx->role != 0) return E4_ERR_STATE;

    /* PRK4e3m = PRK3e2m */
    memcpy(ctx->prk4e3m, ctx->prk3e2m, E4_PRK_LEN);

    uint8_t pt3[E4_ID_CRED + E4_XWING_PK + E4_MAC_LEN + E4_MLDSA_PK + E4_MLDSA_SIG + 16];
    size_t pt3_len = 0;
    if (aead_open(ctx->prk3e2m, ctx->th3, in, in_len, pt3, &pt3_len) != E4_OK)
        return E4_ERR_AEAD;
    size_t exp3 = E4_ID_CRED + E4_XWING_PK + E4_MAC_LEN + E4_MLDSA_PK + E4_MLDSA_SIG;
    if (pt3_len != exp3) return E4_ERR_PARSE;

    size_t o = 0;
    uint8_t id_i[E4_ID_CRED];
    memcpy(id_i, pt3 + o, E4_ID_CRED); o += E4_ID_CRED;
    if (sodium_memcmp(id_i, ctx->peer_id_cred, E4_ID_CRED) != 0) return E4_ERR_PEER;
    memcpy(ctx->peer_new_pk, pt3 + o, E4_XWING_PK); o += E4_XWING_PK;
    const uint8_t *mac3 = pt3 + o; o += E4_MAC_LEN;
    uint8_t vk_i[E4_MLDSA_PK];
    memcpy(vk_i, pt3 + o, E4_MLDSA_PK); o += E4_MLDSA_PK;
    const uint8_t *sig_i = pt3 + o; o += E4_MLDSA_SIG;
    /* VK_I must match the provisioned one when a lookup is configured */
    if (ctx->lookup && sodium_memcmp(vk_i, ctx->peer_sig_vk, E4_MLDSA_PK) != 0)
        return E4_ERR_PEER;
    memcpy(ctx->peer_sig_vk, vk_i, E4_MLDSA_PK);

    uint8_t mac3_c[E4_MAC_LEN];
    compute_mac(ctx->prk4e3m, ctx->th3, ctx->peer_id_cred,
                ctx->peer_new_pk, E4_XWING_PK, mac3_c);
    if (sodium_memcmp(mac3_c, mac3, E4_MAC_LEN) != 0) return E4_ERR_MAC;

    uint8_t sigmsg3[32 + E4_ID_CRED + E4_MAC_LEN];
    size_t sigmsg3_len = sig_message(sigmsg3, ctx->th3, ctx->peer_id_cred, mac3_c);
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig_i, E4_MLDSA_SIG,
            sigmsg3, sigmsg3_len, ctx->peer_sig_vk) != 0) return E4_ERR_SIG;

    const uint8_t *s4[2] = { ctx->th3, pt3 };
    const size_t l4[2] = { 32, pt3_len };
    sha256_cat(ctx->th4, s4, l4, 2);

    derive_prk_out_and_msk(ctx);

    /* EAD4 = NpkB (fresh one-time static XWING keypair for the next session) */
    if (next_keypair(ctx->new_pk, ctx->new_sk) != E4_OK) return E4_ERR_KEM;

    uint8_t ct4[E4_XWING_PK + E4_AEAD_TAG]; size_t ct4_len = 0;
    if (aead_seal(ctx->prk4e3m, ctx->th4, ctx->new_pk, E4_XWING_PK, ct4, &ct4_len) != E4_OK)
        return E4_ERR_AEAD;
    if (ct4_len > out_cap) return E4_ERR_BUF;
    memcpy(out, ct4, ct4_len);
    *out_len = ct4_len;
    return E4_OK;
}

int edhoc4_i_handle_msg4(edhoc4_ctx *ctx, const uint8_t *in, size_t in_len)
{
    if (ctx->role != 1) return E4_ERR_STATE;
    uint8_t pt4[E4_XWING_PK + 16]; size_t pt4_len = 0;
    if (aead_open(ctx->prk4e3m, ctx->th4, in, in_len, pt4, &pt4_len) != E4_OK)
        return E4_ERR_AEAD;
    if (pt4_len != E4_XWING_PK) return E4_ERR_PARSE;
    memcpy(ctx->peer_new_pk, pt4, E4_XWING_PK);   /* next responder pk_B */
    ctx->done = 1;
    return E4_OK;
}

/* ======================================================================== */
/* Rotation commit + erasure (forward secrecy now depends on these)          */
/* ======================================================================== */

/* Install the next-session keys into *creds / *peer_pk and erase the old
 * one-time secret key. Call only after the handshake succeeded:
 *   initiator: after edhoc4_i_handle_msg4 (ctx->done == 1)
 *   responder: after edhoc4_r_handle_msg3 (ctx->done == 1)
 * The caller must then persist *creds and *peer_pk (the per-UE record on the
 * responder side) and overwrite the old files. */
int edhoc4_commit(edhoc4_ctx *ctx, edhoc4_creds *creds,
                  uint8_t peer_pk[E4_XWING_PK])
{
    if (!ctx || !creds || !peer_pk || !ctx->done) return E4_ERR_STATE;
    sodium_memzero(creds->kem_sk, E4_XWING_SK);          /* erase old sk      */
    memcpy(creds->kem_sk, ctx->new_sk, E4_XWING_SK);
    memcpy(creds->kem_pk, ctx->new_pk, E4_XWING_PK);
    memcpy(peer_pk, ctx->peer_new_pk, E4_XWING_PK);      /* peer's next pk    */
    edhoc4_ctx_wipe(ctx);
    return E4_OK;
}

/* Erase every secret held in the session context (old sk copy, shared
 * secrets, PRKs, MSK/EMSK). Export MSK/EMSK before calling this. */
void edhoc4_ctx_wipe(edhoc4_ctx *ctx)
{
    if (ctx) sodium_memzero(ctx, sizeof(*ctx));
}

void edhoc4_set_lookup(edhoc4_ctx *ctx, edhoc4_lookup_fn fn, void *arg)
{
    ctx->lookup = fn;
    ctx->lookup_arg = arg;
}

const char *edhoc4_strerror(int rc)
{
    switch (rc) {
    case E4_OK:        return "ok";
    case E4_ERR_ARG:   return "invalid argument";
    case E4_ERR_BUF:   return "buffer too small";
    case E4_ERR_PARSE: return "malformed message";
    case E4_ERR_KEM:   return "KEM failure";
    case E4_ERR_AEAD:  return "AEAD auth failure";
    case E4_ERR_MAC:   return "MAC mismatch";
    case E4_ERR_SIG:   return "signature verify failed";
    case E4_ERR_STATE: return "wrong role/state";
    case E4_ERR_PEER:  return "unknown or mismatching peer";
    default:           return "unknown error";
    }
}
