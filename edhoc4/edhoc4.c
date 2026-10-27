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
#include <sodium.h>
#include <mbedtls/gcm.h>

/* ---- PQClean (clean reference, namespaced) ---- */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *pk);

static const char XWING_LABEL[] = "XWING-combiner-v1";

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

/* ---- XWING hybrid KEM (X25519 || ML-KEM-768) ---- */

static int xwing_keypair(uint8_t pk[E4_XWING_PK], uint8_t sk[E4_XWING_SK])
{
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) != 0)
        return E4_ERR_KEM;
    uint8_t *sk_x = sk + E4_MLKEM_SK;
    uint8_t *pk_x = pk + E4_MLKEM_PK;
    randombytes_buf(sk_x, E4_X25519_SK);
    crypto_scalarmult_base(pk_x, sk_x);
    return E4_OK;
}

static void xwing_combine(uint8_t ss[32], const uint8_t ss_m[32],
                          const uint8_t ss_x[32], const uint8_t ct_x[32],
                          const uint8_t pk_x[32])
{
    const uint8_t *segs[5] = { ss_m, ss_x, ct_x, pk_x, (const uint8_t *)XWING_LABEL };
    const size_t lens[5] = { 32, 32, 32, 32, sizeof(XWING_LABEL) - 1 };
    sha256_cat(ss, segs, lens, 5);
}

static int xwing_encaps(uint8_t ct[E4_XWING_CT], uint8_t ss[E4_XWING_SS],
                        const uint8_t pk[E4_XWING_PK])
{
    uint8_t ss_m[32];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss_m, pk) != 0)
        return E4_ERR_KEM;
    const uint8_t *pk_x = pk + E4_MLKEM_PK;
    uint8_t *ct_x = ct + E4_MLKEM_CT;
    uint8_t e_sk[E4_X25519_SK], ss_x[32];
    randombytes_buf(e_sk, sizeof(e_sk));
    crypto_scalarmult_base(ct_x, e_sk);          /* ct_x = g^e            */
    if (crypto_scalarmult(ss_x, e_sk, pk_x) != 0) {
        sodium_memzero(e_sk, sizeof(e_sk));
        return E4_ERR_KEM;
    }
    xwing_combine(ss, ss_m, ss_x, ct_x, pk_x);
    sodium_memzero(e_sk, sizeof(e_sk));
    sodium_memzero(ss_x, sizeof(ss_x));
    sodium_memzero(ss_m, sizeof(ss_m));
    return E4_OK;
}

static int xwing_decaps(uint8_t ss[E4_XWING_SS], const uint8_t ct[E4_XWING_CT],
                        const uint8_t sk[E4_XWING_SK])
{
    uint8_t ss_m[32];
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_m, ct, sk) != 0)
        return E4_ERR_KEM;
    const uint8_t *sk_x = sk + E4_MLKEM_SK;
    const uint8_t *ct_x = ct + E4_MLKEM_CT;
    uint8_t ss_x[32], pk_x[32];
    crypto_scalarmult_base(pk_x, sk_x);          /* own static x25519 pub */
    if (crypto_scalarmult(ss_x, sk_x, ct_x) != 0)
        return E4_ERR_KEM;
    xwing_combine(ss, ss_m, ss_x, ct_x, pk_x);
    sodium_memzero(ss_x, sizeof(ss_x));
    sodium_memzero(ss_m, sizeof(ss_m));
    return E4_OK;
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
    if (xwing_decaps(ctx->ss_b, ct_b, ctx->self.kem_sk) != E4_OK) return E4_ERR_KEM;

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
    if (xwing_decaps(ctx->ss_a, ctx->ct_a, ctx->self.kem_sk) != E4_OK) return E4_ERR_KEM;

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
    if (xwing_keypair(ctx->new_pk, ctx->new_sk) != E4_OK) return E4_ERR_KEM;

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
    if (xwing_keypair(ctx->new_pk, ctx->new_sk) != E4_OK) return E4_ERR_KEM;

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
