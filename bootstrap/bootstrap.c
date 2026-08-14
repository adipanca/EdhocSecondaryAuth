/*
 * bootstrap.c — Key Bootstrapping key schedule (C parity of keyschedule.py).
 *
 * Uses libsodium HMAC-SHA256 / SHA-256, exactly like edhoc4.c, so it links into
 * the same FreeRADIUS/UERANSIM builds. Build with the provided Makefile (needs
 * libsodium dev headers, same dependency as libedhoc4).
 */
#include "bootstrap.h"

#include <string.h>
#include <sodium.h>

/* ---- HKDF-SHA256 (RFC 5869), identical to edhoc4.c ---- */
static void hmac(const uint8_t *key, size_t key_len,
                 const uint8_t *const *segs, const size_t *lens, int n,
                 uint8_t out[32])
{
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    for (int i = 0; i < n; i++)
        crypto_auth_hmacsha256_update(&st, segs[i], lens[i]);
    crypto_auth_hmacsha256_final(&st, out);
}

static void hkdf_expand(const uint8_t *prk, size_t prk_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    uint8_t t[32];
    size_t done = 0, tlen = 0;
    uint8_t ctr = 1;
    while (done < okm_len) {
        const uint8_t *segs[3];
        size_t lens[3];
        int n = 0;
        if (tlen) { segs[n] = t; lens[n] = tlen; n++; }
        segs[n] = info; lens[n] = info_len; n++;
        segs[n] = &ctr; lens[n] = 1; n++;
        hmac(prk, prk_len, segs, lens, n, t);
        tlen = 32;
        size_t take = (okm_len - done < tlen) ? (okm_len - done) : tlen;
        memcpy(okm + done, t, take);
        done += take;
        ctr++;
    }
    sodium_memzero(t, sizeof(t));
}

static void hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len, uint8_t prk[32])
{
    const uint8_t *segs[1] = { ikm };
    const size_t lens[1] = { ikm_len };
    hmac(salt, salt_len, segs, lens, 1, prk);
}

/* ---- RFC 5295 §3.1 PRF+ (default HMAC-SHA256) ---- */
static int rfc5295_prf_plus(const uint8_t *key, size_t key_len,
                            const char *label,
                            uint8_t *out, size_t out_len)
{
    /* S = label | 0x00 | (no optional data) | length(2, big-endian) */
    size_t label_len = strlen(label);
    size_t s_len = label_len + 1 + 2;
    uint8_t s[256];
    if (s_len > sizeof(s) || out_len > 0xFFFF) return BK_ERR_ARG;
    memcpy(s, label, label_len);
    s[label_len] = 0x00;
    s[label_len + 1] = (uint8_t)((out_len >> 8) & 0xff);
    s[label_len + 2] = (uint8_t)(out_len & 0xff);

    uint8_t t[32];
    size_t done = 0, tlen = 0;
    uint8_t ctr = 1;
    while (done < out_len) {
        const uint8_t *segs[3];
        size_t lens[3];
        int n = 0;
        if (tlen) { segs[n] = t; lens[n] = tlen; n++; }
        segs[n] = s; lens[n] = s_len; n++;
        segs[n] = &ctr; lens[n] = 1; n++;
        hmac(key, key_len, segs, lens, n, t);
        tlen = 32;
        size_t take = (out_len - done < tlen) ? (out_len - done) : tlen;
        memcpy(out + done, t, take);
        done += take;
        ctr++;
    }
    sodium_memzero(t, sizeof(t));
    return BK_OK;
}

int bk_derive_usrk(const uint8_t *emsk, size_t emsk_len, const char *key_label,
                   uint8_t *usrk, size_t usrk_len)
{
    if (!emsk || emsk_len < 32 || !usrk) return BK_ERR_ARG;
    if (!key_label) key_label = BK_USRK_KEY_LABEL;
    return rfc5295_prf_plus(emsk, emsk_len, key_label, usrk, usrk_len);
}

int bk_derive_dsrk(const uint8_t *parent, size_t parent_len,
                   const char *domain_label, uint8_t *dsrk, size_t dsrk_len)
{
    if (!parent || parent_len < 32 || !dsrk) return BK_ERR_ARG;
    if (!domain_label) domain_label = BK_DSRK_DOMAIN_LABEL;
    return rfc5295_prf_plus(parent, parent_len, domain_label, dsrk, dsrk_len);
}

int bk_derive_oscore_master_secret(const uint8_t *dsrk, size_t dsrk_len,
                                   uint8_t ms[BK_OSCORE_MS_LEN])
{
    static const char *L = "OSCORE Master Secret";
    if (!dsrk || dsrk_len < 32) return BK_ERR_ARG;
    hkdf_expand(dsrk, dsrk_len, (const uint8_t *)L, strlen(L),
                ms, BK_OSCORE_MS_LEN);
    return BK_OK;
}

int bk_derive_oscore_master_salt(const uint8_t *dsrk, size_t dsrk_len,
                                 uint8_t salt[BK_OSCORE_SALT_LEN])
{
    static const char *L = "OSCORE Master Salt";
    if (!dsrk || dsrk_len < 32) return BK_ERR_ARG;
    hkdf_expand(dsrk, dsrk_len, (const uint8_t *)L, strlen(L),
                salt, BK_OSCORE_SALT_LEN);
    return BK_OK;
}

/* RFC 8613 §3.2.1 info = [ id, id_context(h''), alg, type, L ] as CBOR. */
static size_t oscore_info(uint8_t *buf, const uint8_t *id, size_t id_len,
                          const char *type_str, int length)
{
    size_t off = 0;
    buf[off++] = 0x85;                       /* array(5) */
    buf[off++] = (uint8_t)(0x40 | id_len);   /* bstr id  */
    memcpy(buf + off, id, id_len); off += id_len;
    buf[off++] = 0x40;                       /* bstr id_context = h'' */
    buf[off++] = (uint8_t)BK_OSCORE_AEAD_ALG; /* uint alg (10 < 24) */
    size_t tl = strlen(type_str);
    buf[off++] = (uint8_t)(0x60 | tl);       /* tstr type */
    memcpy(buf + off, type_str, tl); off += tl;
    buf[off++] = (uint8_t)length;            /* uint L (<24) */
    return off;
}

int bk_derive_oscore_context(const uint8_t ms[BK_OSCORE_MS_LEN],
                             const uint8_t salt[BK_OSCORE_SALT_LEN],
                             uint8_t sender_id, uint8_t recipient_id,
                             bk_oscore_ctx *ctx)
{
    if (!ms || !salt || !ctx) return BK_ERR_ARG;
    uint8_t prk[32];
    hkdf_extract(salt, BK_OSCORE_SALT_LEN, ms, BK_OSCORE_MS_LEN, prk);

    uint8_t info[64];
    size_t n;

    n = oscore_info(info, &sender_id, 1, "Key", BK_OSCORE_KEY_LEN);
    hkdf_expand(prk, 32, info, n, ctx->sender_key, BK_OSCORE_KEY_LEN);

    n = oscore_info(info, &recipient_id, 1, "Key", BK_OSCORE_KEY_LEN);
    hkdf_expand(prk, 32, info, n, ctx->recipient_key, BK_OSCORE_KEY_LEN);

    n = oscore_info(info, NULL, 0, "IV", BK_OSCORE_IV_LEN);
    hkdf_expand(prk, 32, info, n, ctx->common_iv, BK_OSCORE_IV_LEN);

    memcpy(ctx->master_secret, ms, BK_OSCORE_MS_LEN);
    memcpy(ctx->master_salt, salt, BK_OSCORE_SALT_LEN);
    ctx->sender_id = sender_id;
    ctx->recipient_id = recipient_id;
    sodium_memzero(prk, sizeof(prk));
    return BK_OK;
}

int bk_oscore_ctx_from_dsrk(const uint8_t *dsrk, size_t dsrk_len,
                            uint8_t sender_id, uint8_t recipient_id,
                            bk_oscore_ctx *ctx)
{
    uint8_t ms[BK_OSCORE_MS_LEN], salt[BK_OSCORE_SALT_LEN];
    int rc = bk_derive_oscore_master_secret(dsrk, dsrk_len, ms);
    if (rc != BK_OK) return rc;
    rc = bk_derive_oscore_master_salt(dsrk, dsrk_len, salt);
    if (rc != BK_OK) return rc;
    return bk_derive_oscore_context(ms, salt, sender_id, recipient_id, ctx);
}

int bk_fingerprint(const uint8_t *key, size_t key_len, char out[17])
{
    if (!key || !out) return BK_ERR_ARG;
    static const char pfx[] = "bootstrap-fp|";
    crypto_hash_sha256_state st;
    uint8_t h[32];
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const uint8_t *)pfx, sizeof(pfx) - 1);
    crypto_hash_sha256_update(&st, key, key_len);
    crypto_hash_sha256_final(&st, h);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[2 * i] = hex[h[i] >> 4];
        out[2 * i + 1] = hex[h[i] & 0xf];
    }
    out[16] = '\0';
    return BK_OK;
}
