/*
 * bootstrap.h — Key Bootstrapping key schedule (C parity module).
 *
 * Byte-for-byte identical derivation to bootstrap/keyschedule.py, meant to be
 * linked into the FreeRADIUS responder (rlm_eap_edhoc, C) and the UERANSIM
 * initiator (C++, via extern "C") so that the C side of each peer can bootstrap
 * application keys straight from the EAP-EDHOC EMSK (edhoc4_ctx.emsk) without
 * shelling out to Python.
 *
 * Chain (see bootstrappingkey.md §1 and keyschedule.py):
 *   EMSK --RFC5295 §3.2--> USRK --RFC5295--> DSRK
 *   DSRK --> OSCORE Master Secret / Master Salt
 *   (Master Secret, Master Salt) --RFC8613 §3.2.1--> Sender/Recipient key + IV
 *
 * All KDFs are HKDF-SHA256 (RFC 5869) over libsodium HMAC-SHA256, exactly like
 * edhoc4.c, so values chain cleanly from the handshake output.
 */
#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BK_EMSK_LEN            64
#define BK_USRK_LEN            64
#define BK_DSRK_LEN            64

#define BK_OSCORE_MS_LEN       16   /* OSCORE Master Secret */
#define BK_OSCORE_SALT_LEN      8   /* OSCORE Master Salt   */
#define BK_OSCORE_KEY_LEN      16   /* AES-CCM-16-64-128 key */
#define BK_OSCORE_IV_LEN       13   /* AEAD nonce length     */
#define BK_OSCORE_AEAD_ALG     10   /* COSE AES-CCM-16-64-128 */

/* Default labels (must match keyschedule.py exactly). */
#define BK_USRK_KEY_LABEL   "usrk@example.org,ekeylabel=EAP-EDHOC"
#define BK_DSRK_DOMAIN_LABEL "dsrk@app-domain.example.org"

typedef struct {
    uint8_t master_secret[BK_OSCORE_MS_LEN];
    uint8_t master_salt[BK_OSCORE_SALT_LEN];
    uint8_t sender_key[BK_OSCORE_KEY_LEN];
    uint8_t recipient_key[BK_OSCORE_KEY_LEN];
    uint8_t common_iv[BK_OSCORE_IV_LEN];
    uint8_t sender_id;
    uint8_t recipient_id;
} bk_oscore_ctx;

/* RFC 5295 §3.2 USRK = KDF(EMSK, label | 0x00 | opt | length). */
int bk_derive_usrk(const uint8_t *emsk, size_t emsk_len,
                   const char *key_label,
                   uint8_t *usrk, size_t usrk_len);

/* RFC 5295 DSRK from a parent key (USRK per bootstrappingkey.md §1.1). */
int bk_derive_dsrk(const uint8_t *parent, size_t parent_len,
                   const char *domain_label,
                   uint8_t *dsrk, size_t dsrk_len);

/* OSCORE Master Secret / Salt from the per-application DSRK. */
int bk_derive_oscore_master_secret(const uint8_t *dsrk, size_t dsrk_len,
                                   uint8_t ms[BK_OSCORE_MS_LEN]);
int bk_derive_oscore_master_salt(const uint8_t *dsrk, size_t dsrk_len,
                                 uint8_t salt[BK_OSCORE_SALT_LEN]);

/* RFC 8613 §3.2.1: derive Sender/Recipient key + Common IV into ctx. */
int bk_derive_oscore_context(const uint8_t ms[BK_OSCORE_MS_LEN],
                             const uint8_t salt[BK_OSCORE_SALT_LEN],
                             uint8_t sender_id, uint8_t recipient_id,
                             bk_oscore_ctx *ctx);

/* Convenience: DSRK -> full OSCORE context. */
int bk_oscore_ctx_from_dsrk(const uint8_t *dsrk, size_t dsrk_len,
                            uint8_t sender_id, uint8_t recipient_id,
                            bk_oscore_ctx *ctx);

/* Test-only fingerprint (first 8 bytes of SHA-256("bootstrap-fp|" | key)),
 * hex into out (>=17 bytes). Matches keyschedule.fingerprint() prefix. */
int bk_fingerprint(const uint8_t *key, size_t key_len, char out[17]);

#define BK_OK          0
#define BK_ERR_ARG    -1
#define BK_ERR_CRYPTO -2

#ifdef __cplusplus
}
#endif

#endif /* BOOTSTRAP_H */
