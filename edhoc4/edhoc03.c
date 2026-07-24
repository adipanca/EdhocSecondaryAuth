/*
 * edhoc03.c — Shared EAP-EDHOC methods 0..3 core (classical suite).
 * See edhoc03.h and mermaid.md §1-4.
 *
 * Self-consistent binary profile (mirrors edhoc4.c's construction):
 *   message_1 = method(1) || G_X(32) || C_I(1)
 *   message_2 = G_Y(32) || AEAD(K2, PT2)
 *       PT2 (R=SIG)  = ID_CRED_R(3) || VK_R(32) || sigma_R(64)
 *       PT2 (R=STAT) = ID_CRED_R(3) || DHpk_R(32) || MAC2(8)
 *   message_3 = AEAD(K3, PT3)
 *       PT3 (I=SIG)  = ID_CRED_I(3) || VK_I(32) || sigma_I(64)
 *       PT3 (I=STAT) = ID_CRED_I(3) || DHpk_I(32) || MAC3(8)
 *   message_4 = empty (EAP-Success)
 */
#include "edhoc03.h"

#include <string.h>
#include <stdio.h>
#include <sodium.h>

/* ======================================================================== */
/* Crypto helpers (same construction as edhoc4.c)                            */
/* ======================================================================== */

static void e3_sha256(uint8_t out[32], const uint8_t *in, size_t len)
{
    crypto_hash_sha256(out, in, len);
}

static void e3_sha256_cat(uint8_t out[32], const uint8_t *const *segs,
                          const size_t *lens, int n)
{
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    for (int i = 0; i < n; i++)
        crypto_hash_sha256_update(&st, segs[i], lens[i]);
    crypto_hash_sha256_final(&st, out);
}

static void e3_hkdf_extract(const uint8_t *salt, size_t salt_len,
                            const uint8_t *ikm, size_t ikm_len, uint8_t prk[32])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);
}

static void e3_hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                           size_t info_len, uint8_t *okm, size_t okm_len)
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

static void e3_derive_k(const uint8_t prk[32], const uint8_t th[32],
                        uint8_t key[E3_AEAD_KEY], uint8_t nonce[E3_AEAD_NONCE])
{
    uint8_t info[32 + 5];
    memcpy(info, th, 32);
    memcpy(info + 32, "E3KEY", 5);
    uint8_t okm[E3_AEAD_KEY + E3_AEAD_NONCE];
    e3_hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm));
    memcpy(key, okm, E3_AEAD_KEY);
    memcpy(nonce, okm + E3_AEAD_KEY, E3_AEAD_NONCE);
    sodium_memzero(okm, sizeof(okm));
}

static int e3_aead_seal(const uint8_t prk[32], const uint8_t th[32],
                        const uint8_t *pt, size_t pt_len, uint8_t *ct, size_t *ct_len)
{
    uint8_t key[E3_AEAD_KEY], nonce[E3_AEAD_NONCE];
    e3_derive_k(prk, th, key, nonce);
    unsigned long long clen = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        ct, &clen, pt, pt_len, th, 32, NULL, nonce, key);
    sodium_memzero(key, sizeof(key));
    if (rc != 0) return E3_ERR_AEAD;
    *ct_len = (size_t)clen;
    return E3_OK;
}

static int e3_aead_open(const uint8_t prk[32], const uint8_t th[32],
                        const uint8_t *ct, size_t ct_len, uint8_t *pt, size_t *pt_len)
{
    uint8_t key[E3_AEAD_KEY], nonce[E3_AEAD_NONCE];
    e3_derive_k(prk, th, key, nonce);
    unsigned long long mlen = 0;
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        pt, &mlen, NULL, ct, ct_len, th, 32, nonce, key);
    sodium_memzero(key, sizeof(key));
    if (rc != 0) return E3_ERR_AEAD;
    *pt_len = (size_t)mlen;
    return E3_OK;
}

/* MAC_x = HKDF-Expand(prk, th || id_cred || cred_pub, MAC_LEN) */
static void e3_compute_mac(const uint8_t prk[32], const uint8_t th[32],
                           const uint8_t id_cred[E3_ID_CRED],
                           const uint8_t cred_pub[E3_X_PK], uint8_t mac[E3_MAC_LEN])
{
    uint8_t info[32 + E3_ID_CRED + E3_X_PK];
    size_t off = 0;
    memcpy(info + off, th, 32); off += 32;
    memcpy(info + off, id_cred, E3_ID_CRED); off += E3_ID_CRED;
    memcpy(info + off, cred_pub, E3_X_PK); off += E3_X_PK;
    e3_hkdf_expand(prk, info, off, mac, E3_MAC_LEN);
}

/* signature message = th || id_cred || mac */
static size_t e3_sig_message(uint8_t *buf, const uint8_t th[32],
                             const uint8_t id_cred[E3_ID_CRED], const uint8_t mac[E3_MAC_LEN])
{
    size_t off = 0;
    memcpy(buf + off, th, 32); off += 32;
    memcpy(buf + off, id_cred, E3_ID_CRED); off += E3_ID_CRED;
    memcpy(buf + off, mac, E3_MAC_LEN); off += E3_MAC_LEN;
    return off;
}

/* ======================================================================== */
/* Method auth-mode table                                                    */
/* ======================================================================== */

int edhoc03_method_valid(int method) { return method >= 0 && method <= 3; }

static int method_init_auth(int m) { return (m == 0 || m == 1) ? E3_AUTH_SIG : E3_AUTH_STAT; }
static int method_resp_auth(int m) { return (m == 0 || m == 2) ? E3_AUTH_SIG : E3_AUTH_STAT; }

/* ======================================================================== */
/* Key-schedule + exporter (identical labels to edhoc4)                      */
/* ======================================================================== */

static void e3_derive_msk(edhoc03_ctx *ctx)
{
    e3_hkdf_expand(ctx->prk4e3m, ctx->th4, 32, ctx->prk_out, E3_PRK_LEN);
    e3_hkdf_expand(ctx->prk_out, (const uint8_t *)"EDHOC-EAP-MSK", 13, ctx->msk, E3_MSK_LEN);
    e3_hkdf_expand(ctx->prk_out, (const uint8_t *)"EDHOC-EAP-EMSK", 14, ctx->emsk, E3_EMSK_LEN);
    ctx->done = 1;
}

/* ======================================================================== */
/* Credentials                                                               */
/* ======================================================================== */

int edhoc03_gen_creds(edhoc03_creds *c, const uint8_t id_cred[E3_ID_CRED])
{
    if (!c) return E3_ERR_ARG;
    if (sodium_init() < 0) return E3_ERR_ARG;
    memset(c, 0, sizeof(*c));
    crypto_sign_keypair(c->sig_vk, c->sig_sk);
    randombytes_buf(c->dh_sk, sizeof(c->dh_sk));
    crypto_scalarmult_base(c->dh_pk, c->dh_sk);
    if (id_cred) memcpy(c->id_cred, id_cred, E3_ID_CRED);
    return E3_OK;
}

int edhoc03_creds_save(const char *path, const edhoc03_creds *c)
{
    if (!path || !c) return E3_ERR_ARG;
    FILE *f = fopen(path, "wb");
    if (!f) return E3_ERR_ARG;
    size_t n = fwrite(c, 1, sizeof(*c), f);
    fclose(f);
    return (n == sizeof(*c)) ? E3_OK : E3_ERR_ARG;
}

int edhoc03_creds_load(const char *path, edhoc03_creds *c)
{
    if (!path || !c) return E3_ERR_ARG;
    FILE *f = fopen(path, "rb");
    if (!f) return E3_ERR_ARG;
    size_t n = fread(c, 1, sizeof(*c), f);
    fclose(f);
    return (n == sizeof(*c)) ? E3_OK : E3_ERR_PARSE;
}

int edhoc03_pub_save(const char *path, const edhoc03_creds *c)
{
    if (!path || !c) return E3_ERR_ARG;
    edhoc03_peer p;
    memcpy(p.sig_vk, c->sig_vk, E3_ED_PK);
    memcpy(p.dh_pk, c->dh_pk, E3_X_PK);
    FILE *f = fopen(path, "wb");
    if (!f) return E3_ERR_ARG;
    size_t n = fwrite(&p, 1, sizeof(p), f);
    fclose(f);
    return (n == sizeof(p)) ? E3_OK : E3_ERR_ARG;
}

int edhoc03_pub_load(const char *path, edhoc03_peer *peer)
{
    if (!path || !peer) return E3_ERR_ARG;
    FILE *f = fopen(path, "rb");
    if (!f) return E3_ERR_ARG;
    size_t n = fread(peer, 1, sizeof(*peer), f);
    fclose(f);
    return (n == sizeof(*peer)) ? E3_OK : E3_ERR_PARSE;
}

/* ======================================================================== */
/* Context init                                                              */
/* ======================================================================== */

void edhoc03_init_initiator(edhoc03_ctx *ctx, int method,
                            const edhoc03_creds *self, const edhoc03_peer *peer)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->role = 1;
    ctx->method = method;
    ctx->self_auth = method_init_auth(method);
    ctx->peer_auth = method_resp_auth(method);
    ctx->self = *self;
    ctx->peer = *peer;
    ctx->c_i[0] = 0x10;
    ctx->c_r[0] = 0x20;
}

void edhoc03_init_responder(edhoc03_ctx *ctx,
                            const edhoc03_creds *self, const edhoc03_peer *peer)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->role = 0;
    ctx->self = *self;
    ctx->peer = *peer;
    ctx->c_i[0] = 0x10;
    ctx->c_r[0] = 0x20;
    /* method learned from message_1 */
}

/* ======================================================================== */
/* Message 1 (initiator -> responder)                                        */
/* ======================================================================== */

int edhoc03_i_make_msg1(edhoc03_ctx *ctx, uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx->role != 1) return E3_ERR_STATE;
    if (!edhoc03_method_valid(ctx->method)) return E3_ERR_ARG;

    randombytes_buf(ctx->eph_sk, sizeof(ctx->eph_sk));
    crypto_scalarmult_base(ctx->eph_pk, ctx->eph_sk);      /* G_X */

    size_t need = 1 + E3_X_PK + E3_CONN_ID;
    if (need > out_cap) return E3_ERR_BUF;
    size_t off = 0;
    out[off++] = (uint8_t)ctx->method;
    memcpy(out + off, ctx->eph_pk, E3_X_PK); off += E3_X_PK;
    out[off++] = ctx->c_i[0];
    *out_len = off;

    e3_sha256(ctx->h_msg1, out, off);
    return E3_OK;
}

/* ======================================================================== */
/* Message 1 handling + Message 2 (responder)                                */
/* ======================================================================== */

int edhoc03_r_handle_msg1(edhoc03_ctx *ctx, const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx->role != 0) return E3_ERR_STATE;
    if (in_len != 1 + E3_X_PK + E3_CONN_ID) return E3_ERR_PARSE;

    int method = in[0];
    if (!edhoc03_method_valid(method)) return E3_ERR_PARSE;
    ctx->method = method;
    ctx->self_auth = method_resp_auth(method);
    ctx->peer_auth = method_init_auth(method);

    memcpy(ctx->peer_eph_pk, in + 1, E3_X_PK);             /* G_X */
    ctx->c_i[0] = in[1 + E3_X_PK];

    e3_sha256(ctx->h_msg1, in, in_len);

    /* ephemeral keypair G_Y, ss_e = ECDH(y, G_X) */
    randombytes_buf(ctx->eph_sk, sizeof(ctx->eph_sk));
    crypto_scalarmult_base(ctx->eph_pk, ctx->eph_sk);      /* G_Y */
    if (crypto_scalarmult(ctx->ss_e, ctx->eph_sk, ctx->peer_eph_pk) != 0)
        return E3_ERR_DH;

    /* TH2 = H(G_Y || H(msg1) || C_R) */
    const uint8_t *s2[3] = { ctx->eph_pk, ctx->h_msg1, ctx->c_r };
    const size_t l2[3] = { E3_X_PK, E3_HASH_LEN, E3_CONN_ID };
    e3_sha256_cat(ctx->th2, s2, l2, 3);

    e3_hkdf_extract(ctx->th2, 32, ctx->ss_e, E3_X_SS, ctx->prk2e);

    /* PT2 + PRK3e2m depending on responder auth */
    uint8_t pt2[E3_ID_CRED + E3_X_PK + E3_ED_SIG];
    size_t pt2_len = 0;

    if (ctx->self_auth == E3_AUTH_STAT) {
        /* G_RX = ECDH(static dh_sk_R, G_X) */
        uint8_t g_rx[E3_X_SS];
        if (crypto_scalarmult(g_rx, ctx->self.dh_sk, ctx->peer_eph_pk) != 0)
            return E3_ERR_DH;
        e3_hkdf_extract(ctx->prk2e, 32, g_rx, E3_X_SS, ctx->prk3e2m);
        sodium_memzero(g_rx, sizeof(g_rx));

        uint8_t mac2[E3_MAC_LEN];
        e3_compute_mac(ctx->prk3e2m, ctx->th2, ctx->self.id_cred, ctx->self.dh_pk, mac2);

        size_t o = 0;
        memcpy(pt2 + o, ctx->self.id_cred, E3_ID_CRED); o += E3_ID_CRED;
        memcpy(pt2 + o, ctx->self.dh_pk, E3_X_PK); o += E3_X_PK;
        memcpy(pt2 + o, mac2, E3_MAC_LEN); o += E3_MAC_LEN;
        pt2_len = o;
    } else {
        /* SIG: PRK3e2m = PRK2e */
        memcpy(ctx->prk3e2m, ctx->prk2e, E3_PRK_LEN);

        uint8_t mac2[E3_MAC_LEN];
        e3_compute_mac(ctx->prk3e2m, ctx->th2, ctx->self.id_cred, ctx->self.sig_vk, mac2);

        uint8_t sigmsg[32 + E3_ID_CRED + E3_MAC_LEN];
        size_t sigmsg_len = e3_sig_message(sigmsg, ctx->th2, ctx->self.id_cred, mac2);
        uint8_t sig_r[E3_ED_SIG];
        if (crypto_sign_detached(sig_r, NULL, sigmsg, sigmsg_len, ctx->self.sig_sk) != 0)
            return E3_ERR_SIG;

        size_t o = 0;
        memcpy(pt2 + o, ctx->self.id_cred, E3_ID_CRED); o += E3_ID_CRED;
        memcpy(pt2 + o, ctx->self.sig_vk, E3_ED_PK); o += E3_ED_PK;
        memcpy(pt2 + o, sig_r, E3_ED_SIG); o += E3_ED_SIG;
        pt2_len = o;
    }

    /* TH3 = H(TH2 || PT2) */
    const uint8_t *s3[2] = { ctx->th2, pt2 };
    const size_t l3[2] = { 32, pt2_len };
    e3_sha256_cat(ctx->th3, s3, l3, 2);

    /* seal PT2 with K2 = (PRK2e, TH2) */
    uint8_t ct2[sizeof(pt2) + E3_AEAD_TAG];
    size_t ct2_len = 0;
    if (e3_aead_seal(ctx->prk2e, ctx->th2, pt2, pt2_len, ct2, &ct2_len) != E3_OK)
        return E3_ERR_AEAD;

    size_t need = E3_X_PK + ct2_len;
    if (need > out_cap) return E3_ERR_BUF;
    size_t off = 0;
    memcpy(out + off, ctx->eph_pk, E3_X_PK); off += E3_X_PK;   /* G_Y */
    memcpy(out + off, ct2, ct2_len); off += ct2_len;
    *out_len = off;
    return E3_OK;
}

/* ======================================================================== */
/* Message 2 handling + Message 3 (initiator)                                */
/* ======================================================================== */

int edhoc03_i_handle_msg2(edhoc03_ctx *ctx, const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx->role != 1) return E3_ERR_STATE;
    if (in_len < E3_X_PK + E3_AEAD_TAG) return E3_ERR_PARSE;

    memcpy(ctx->peer_eph_pk, in, E3_X_PK);                 /* G_Y */
    const uint8_t *ct2 = in + E3_X_PK;
    size_t ct2_len = in_len - E3_X_PK;

    /* ss_e = ECDH(x, G_Y) */
    if (crypto_scalarmult(ctx->ss_e, ctx->eph_sk, ctx->peer_eph_pk) != 0)
        return E3_ERR_DH;

    /* TH2 = H(G_Y || H(msg1) || C_R) */
    const uint8_t *s2[3] = { ctx->peer_eph_pk, ctx->h_msg1, ctx->c_r };
    const size_t l2[3] = { E3_X_PK, E3_HASH_LEN, E3_CONN_ID };
    e3_sha256_cat(ctx->th2, s2, l2, 3);

    e3_hkdf_extract(ctx->th2, 32, ctx->ss_e, E3_X_SS, ctx->prk2e);

    uint8_t pt2[E3_ID_CRED + E3_X_PK + E3_ED_SIG + 16];
    size_t pt2_len = 0;
    if (e3_aead_open(ctx->prk2e, ctx->th2, ct2, ct2_len, pt2, &pt2_len) != E3_OK)
        return E3_ERR_AEAD;

    /* parse + verify responder auth */
    if (ctx->peer_auth == E3_AUTH_STAT) {
        if (pt2_len != E3_ID_CRED + E3_X_PK + E3_MAC_LEN) return E3_ERR_PARSE;
        size_t o = 0;
        memcpy(ctx->peer_id_cred, pt2 + o, E3_ID_CRED); o += E3_ID_CRED;
        const uint8_t *dh_pk_r = pt2 + o; o += E3_X_PK;
        const uint8_t *mac2 = pt2 + o; o += E3_MAC_LEN;

        /* pin: responder static key must match provisioned peer key */
        if (sodium_memcmp(dh_pk_r, ctx->peer.dh_pk, E3_X_PK) != 0) return E3_ERR_MAC;

        /* G_RX = ECDH(x, dh_pk_R) */
        uint8_t g_rx[E3_X_SS];
        if (crypto_scalarmult(g_rx, ctx->eph_sk, dh_pk_r) != 0) return E3_ERR_DH;
        e3_hkdf_extract(ctx->prk2e, 32, g_rx, E3_X_SS, ctx->prk3e2m);
        sodium_memzero(g_rx, sizeof(g_rx));

        uint8_t mac2_c[E3_MAC_LEN];
        e3_compute_mac(ctx->prk3e2m, ctx->th2, ctx->peer_id_cred, dh_pk_r, mac2_c);
        if (sodium_memcmp(mac2_c, mac2, E3_MAC_LEN) != 0) return E3_ERR_MAC;
    } else {
        if (pt2_len != E3_ID_CRED + E3_ED_PK + E3_ED_SIG) return E3_ERR_PARSE;
        size_t o = 0;
        memcpy(ctx->peer_id_cred, pt2 + o, E3_ID_CRED); o += E3_ID_CRED;
        const uint8_t *vk_r = pt2 + o; o += E3_ED_PK;
        const uint8_t *sig_r = pt2 + o; o += E3_ED_SIG;

        if (sodium_memcmp(vk_r, ctx->peer.sig_vk, E3_ED_PK) != 0) return E3_ERR_SIG;

        memcpy(ctx->prk3e2m, ctx->prk2e, E3_PRK_LEN);
        uint8_t mac2_c[E3_MAC_LEN];
        e3_compute_mac(ctx->prk3e2m, ctx->th2, ctx->peer_id_cred, vk_r, mac2_c);

        uint8_t sigmsg[32 + E3_ID_CRED + E3_MAC_LEN];
        size_t sigmsg_len = e3_sig_message(sigmsg, ctx->th2, ctx->peer_id_cred, mac2_c);
        if (crypto_sign_verify_detached(sig_r, sigmsg, sigmsg_len, vk_r) != 0)
            return E3_ERR_SIG;
    }

    /* TH3 = H(TH2 || PT2) */
    const uint8_t *s3[2] = { ctx->th2, pt2 };
    const size_t l3[2] = { 32, pt2_len };
    e3_sha256_cat(ctx->th3, s3, l3, 2);

    /* build PT3 depending on initiator auth */
    uint8_t pt3[E3_ID_CRED + E3_X_PK + E3_ED_SIG];
    size_t pt3_len = 0;

    if (ctx->self_auth == E3_AUTH_STAT) {
        /* G_IY = ECDH(static dh_sk_I, G_Y) */
        uint8_t g_iy[E3_X_SS];
        if (crypto_scalarmult(g_iy, ctx->self.dh_sk, ctx->peer_eph_pk) != 0)
            return E3_ERR_DH;
        e3_hkdf_extract(ctx->prk3e2m, 32, g_iy, E3_X_SS, ctx->prk4e3m);
        sodium_memzero(g_iy, sizeof(g_iy));

        uint8_t mac3[E3_MAC_LEN];
        e3_compute_mac(ctx->prk4e3m, ctx->th3, ctx->self.id_cred, ctx->self.dh_pk, mac3);

        size_t o = 0;
        memcpy(pt3 + o, ctx->self.id_cred, E3_ID_CRED); o += E3_ID_CRED;
        memcpy(pt3 + o, ctx->self.dh_pk, E3_X_PK); o += E3_X_PK;
        memcpy(pt3 + o, mac3, E3_MAC_LEN); o += E3_MAC_LEN;
        pt3_len = o;
    } else {
        memcpy(ctx->prk4e3m, ctx->prk3e2m, E3_PRK_LEN);

        uint8_t mac3[E3_MAC_LEN];
        e3_compute_mac(ctx->prk4e3m, ctx->th3, ctx->self.id_cred, ctx->self.sig_vk, mac3);

        uint8_t sigmsg[32 + E3_ID_CRED + E3_MAC_LEN];
        size_t sigmsg_len = e3_sig_message(sigmsg, ctx->th3, ctx->self.id_cred, mac3);
        uint8_t sig_i[E3_ED_SIG];
        if (crypto_sign_detached(sig_i, NULL, sigmsg, sigmsg_len, ctx->self.sig_sk) != 0)
            return E3_ERR_SIG;

        size_t o = 0;
        memcpy(pt3 + o, ctx->self.id_cred, E3_ID_CRED); o += E3_ID_CRED;
        memcpy(pt3 + o, ctx->self.sig_vk, E3_ED_PK); o += E3_ED_PK;
        memcpy(pt3 + o, sig_i, E3_ED_SIG); o += E3_ED_SIG;
        pt3_len = o;
    }

    /* TH4 = H(TH3 || PT3) */
    const uint8_t *s4[2] = { ctx->th3, pt3 };
    const size_t l4[2] = { 32, pt3_len };
    e3_sha256_cat(ctx->th4, s4, l4, 2);

    /* seal PT3 with K3 = (PRK3e2m, TH3) */
    uint8_t ct3[sizeof(pt3) + E3_AEAD_TAG];
    size_t ct3_len = 0;
    if (e3_aead_seal(ctx->prk3e2m, ctx->th3, pt3, pt3_len, ct3, &ct3_len) != E3_OK)
        return E3_ERR_AEAD;
    if (ct3_len > out_cap) return E3_ERR_BUF;
    memcpy(out, ct3, ct3_len);
    *out_len = ct3_len;

    e3_derive_msk(ctx);
    return E3_OK;
}

/* ======================================================================== */
/* Message 3 handling + Message 4 (responder)                                */
/* ======================================================================== */

int edhoc03_r_handle_msg3(edhoc03_ctx *ctx, const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (ctx->role != 0) return E3_ERR_STATE;

    uint8_t pt3[E3_ID_CRED + E3_X_PK + E3_ED_SIG + 16];
    size_t pt3_len = 0;
    if (e3_aead_open(ctx->prk3e2m, ctx->th3, in, in_len, pt3, &pt3_len) != E3_OK)
        return E3_ERR_AEAD;

    if (ctx->peer_auth == E3_AUTH_STAT) {
        if (pt3_len != E3_ID_CRED + E3_X_PK + E3_MAC_LEN) return E3_ERR_PARSE;
        size_t o = 0;
        memcpy(ctx->peer_id_cred, pt3 + o, E3_ID_CRED); o += E3_ID_CRED;
        const uint8_t *dh_pk_i = pt3 + o; o += E3_X_PK;
        const uint8_t *mac3 = pt3 + o; o += E3_MAC_LEN;

        if (sodium_memcmp(dh_pk_i, ctx->peer.dh_pk, E3_X_PK) != 0) return E3_ERR_MAC;

        /* G_IY = ECDH(y, dh_pk_I) */
        uint8_t g_iy[E3_X_SS];
        if (crypto_scalarmult(g_iy, ctx->eph_sk, dh_pk_i) != 0) return E3_ERR_DH;
        e3_hkdf_extract(ctx->prk3e2m, 32, g_iy, E3_X_SS, ctx->prk4e3m);
        sodium_memzero(g_iy, sizeof(g_iy));

        uint8_t mac3_c[E3_MAC_LEN];
        e3_compute_mac(ctx->prk4e3m, ctx->th3, ctx->peer_id_cred, dh_pk_i, mac3_c);
        if (sodium_memcmp(mac3_c, mac3, E3_MAC_LEN) != 0) return E3_ERR_MAC;
    } else {
        if (pt3_len != E3_ID_CRED + E3_ED_PK + E3_ED_SIG) return E3_ERR_PARSE;
        size_t o = 0;
        memcpy(ctx->peer_id_cred, pt3 + o, E3_ID_CRED); o += E3_ID_CRED;
        const uint8_t *vk_i = pt3 + o; o += E3_ED_PK;
        const uint8_t *sig_i = pt3 + o; o += E3_ED_SIG;

        if (sodium_memcmp(vk_i, ctx->peer.sig_vk, E3_ED_PK) != 0) return E3_ERR_SIG;

        memcpy(ctx->prk4e3m, ctx->prk3e2m, E3_PRK_LEN);
        uint8_t mac3_c[E3_MAC_LEN];
        e3_compute_mac(ctx->prk4e3m, ctx->th3, ctx->peer_id_cred, vk_i, mac3_c);

        uint8_t sigmsg[32 + E3_ID_CRED + E3_MAC_LEN];
        size_t sigmsg_len = e3_sig_message(sigmsg, ctx->th3, ctx->peer_id_cred, mac3_c);
        if (crypto_sign_verify_detached(sig_i, sigmsg, sigmsg_len, vk_i) != 0)
            return E3_ERR_SIG;
    }

    /* TH4 = H(TH3 || PT3) */
    const uint8_t *s4[2] = { ctx->th3, pt3 };
    const size_t l4[2] = { 32, pt3_len };
    e3_sha256_cat(ctx->th4, s4, l4, 2);

    e3_derive_msk(ctx);

    /* message_4 is empty (EAP-Success) */
    (void)out; (void)out_cap;
    *out_len = 0;
    return E3_OK;
}

int edhoc03_i_handle_msg4(edhoc03_ctx *ctx, const uint8_t *in, size_t in_len)
{
    if (ctx->role != 1) return E3_ERR_STATE;
    (void)in;
    if (in_len != 0) return E3_ERR_PARSE;   /* classical msg4 carries no payload */
    ctx->done = 1;
    return E3_OK;
}

const char *edhoc03_strerror(int rc)
{
    switch (rc) {
    case E3_OK:        return "ok";
    case E3_ERR_ARG:   return "invalid argument";
    case E3_ERR_BUF:   return "buffer too small";
    case E3_ERR_PARSE: return "malformed message";
    case E3_ERR_DH:    return "X25519 failure";
    case E3_ERR_AEAD:  return "AEAD auth failure";
    case E3_ERR_MAC:   return "MAC mismatch";
    case E3_ERR_SIG:   return "signature verify failed";
    case E3_ERR_STATE: return "wrong role/state";
    default:           return "unknown error";
    }
}
