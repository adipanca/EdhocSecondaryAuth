/*
 * edhoc4.h — Shared EAP-EDHOC method 4 core (SIGMA XWING).
 *
 * Implements the "EAP-EDHOC Hybrid PQC (XWING) — SIGMA" handshake from
 * mermaid.md §5:
 *   - key establishment : XWING hybrid KEM = X25519 (libsodium) + ML-KEM-768
 *                         (PQClean), shared-secret combiner over SHA-256.
 *   - authentication    : ML-DSA-44 signatures on BOTH sides (PQClean) + MAC.
 *   - KDF / AEAD        : HKDF-SHA256 + ChaCha20-Poly1305 (libsodium).
 *
 * The SAME object file is linked by both the FreeRADIUS responder (C) and the
 * UERANSIM initiator (C++, via extern "C"), so the two peers run byte-for-byte
 * identical serialization and crypto — which is what makes them interoperate.
 *
 * This is a self-consistent binary profile (not literal RFC 9528 CBOR): the
 * message contents follow mermaid.md §5 exactly, encoded with simple
 * length-prefixed fields shared by both endpoints.
 */
#ifndef EDHOC4_H
#define EDHOC4_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- primitive sizes ---- */
#define E4_MLKEM_PK   1184
#define E4_MLKEM_SK   2400
#define E4_MLKEM_CT   1088
#define E4_MLKEM_SS   32

#define E4_MLDSA_PK   1312
#define E4_MLDSA_SK   2560
#define E4_MLDSA_SIG  2420

#define E4_X25519_PK  32
#define E4_X25519_SK  32

/* XWING hybrid = ML-KEM-768 || X25519 */
#define E4_XWING_PK   (E4_MLKEM_PK + E4_X25519_PK)   /* 1216 */
#define E4_XWING_SK   (E4_MLKEM_SK + E4_X25519_SK)   /* 2432 */
#define E4_XWING_CT   (E4_MLKEM_CT + E4_X25519_PK)   /* 1120 */
#define E4_XWING_SS   32

#define E4_HASH_LEN   32
#define E4_PRK_LEN    32
#define E4_MAC_LEN    8
#define E4_AEAD_KEY   32
#define E4_AEAD_NONCE 12
#define E4_AEAD_TAG   16

#define E4_CONN_ID    1     /* C_I / C_R length */
#define E4_ID_CRED    3     /* ID_CRED (kid) length */

#define E4_MSK_LEN    64
#define E4_EMSK_LEN   64

/* Generous upper bound for any single EDHOC message buffer. */
#define E4_MAX_MSG    8192

/* Internal EAP-EDHOC fragmentation wrapper used by the NAS/RADIUS transport. */
#define E4_EDHOC_FRAG_WIRE_MAX 1000
#define E4_EDHOC_FRAG_FLAG_LEN  0x80
#define E4_EDHOC_FRAG_FLAG_MORE 0x40
#define E4_EDHOC_FRAG_HDR_LEN   1
#define E4_EDHOC_FRAG_LEN_LEN   2

/* ---- long-term credentials (per party) ---- */
typedef struct {
    uint8_t kem_sk[E4_XWING_SK];   /* own static XWING secret key   */
    uint8_t kem_pk[E4_XWING_PK];   /* own static XWING public key   */
    uint8_t sig_sk[E4_MLDSA_SK];   /* own ML-DSA-44 signing key     */
    uint8_t sig_vk[E4_MLDSA_PK];   /* own ML-DSA-44 verify key (VK) */
    uint8_t id_cred[E4_ID_CRED];   /* ID_CRED identifier            */
} edhoc4_creds;

/* ---- handshake context ---- */
typedef struct {
    int role;                       /* 1 = initiator, 0 = responder */

    edhoc4_creds self;              /* own long-term credentials    */
    uint8_t peer_kem_pk[E4_XWING_PK];   /* peer static XWING pk      */
    uint8_t peer_sig_vk[E4_MLDSA_PK];   /* peer ML-DSA VK            */
    uint8_t peer_id_cred[E4_ID_CRED];

    uint8_t c_i[E4_CONN_ID];
    uint8_t c_r[E4_CONN_ID];

    /* ephemeral XWING keypair (pkX / skX), initiator-generated */
    uint8_t eph_sk[E4_XWING_SK];
    uint8_t eph_pk[E4_XWING_PK];

    /* shared secrets */
    uint8_t ss_b[E4_XWING_SS];      /* encaps/decaps against pkB (responder static) */
    uint8_t ss_e[E4_XWING_SS];      /* encaps/decaps against pkX (ephemeral)        */
    uint8_t ss_a[E4_XWING_SS];      /* encaps/decaps against pkA (initiator static) */

    /* transcript hashes */
    uint8_t th1[E4_HASH_LEN];
    uint8_t th2[E4_HASH_LEN];
    uint8_t th3[E4_HASH_LEN];
    uint8_t th4[E4_HASH_LEN];
    uint8_t h_msg1[E4_HASH_LEN];     /* H(message_1), kept by initiator */

    /* key schedule */
    uint8_t prk1e[E4_PRK_LEN];
    uint8_t prk2e[E4_PRK_LEN];
    uint8_t prk3e2m[E4_PRK_LEN];
    uint8_t prk4e3m[E4_PRK_LEN];
    uint8_t prk_out[E4_PRK_LEN];

    /* ratcheting: freshly generated static XWING keypairs (EAD3 / EAD4) */
    uint8_t new_sk[E4_XWING_SK];    /* own next static sk   */
    uint8_t new_pk[E4_XWING_PK];    /* own next static pk (sent as EAD)   */
    uint8_t peer_new_pk[E4_XWING_PK]; /* peer next static pk (received)   */

    /* saved ciphertext to initiator static (ctA), needed msg2->msg3 */
    uint8_t ct_a[E4_XWING_CT];

    /* outputs */
    uint8_t msk[E4_MSK_LEN];
    uint8_t emsk[E4_EMSK_LEN];
    int done;                       /* 1 once MSK/EMSK are derived  */
} edhoc4_ctx;

/* ---- credential generation (test / provisioning helper) ---- */
int edhoc4_gen_creds(edhoc4_creds *c, const uint8_t id_cred[E4_ID_CRED]);

/* ---- credential persistence (provisioning) ----
 * Full creds (with secret key) are written/read as a fixed-size binary blob.
 * A "public" file carries only the static XWING public key (peer material). */
int edhoc4_creds_save(const char *path, const edhoc4_creds *c);
int edhoc4_creds_load(const char *path, edhoc4_creds *c);
int edhoc4_pub_save(const char *path, const edhoc4_creds *c);
int edhoc4_pub_load(const char *path, uint8_t peer_kem_pk[E4_XWING_PK]);

/* ---- initiator (UE) ---- */
void edhoc4_init_initiator(edhoc4_ctx *ctx, const edhoc4_creds *self,
                           const uint8_t peer_kem_pk[E4_XWING_PK]);

/* build message_1 (also generates ephemeral key + ss_b) */
int edhoc4_i_make_msg1(edhoc4_ctx *ctx, uint8_t *out, size_t out_cap, size_t *out_len);
/* consume message_2, build message_3 */
int edhoc4_i_handle_msg2(edhoc4_ctx *ctx, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);
/* consume message_4 (EAP-Success payload) -> derive MSK/EMSK */
int edhoc4_i_handle_msg4(edhoc4_ctx *ctx, const uint8_t *in, size_t in_len);

/* ---- responder (DN-AAA) ---- */
void edhoc4_init_responder(edhoc4_ctx *ctx, const edhoc4_creds *self,
                           const uint8_t peer_kem_pk[E4_XWING_PK]);

/* consume message_1, build message_2 */
int edhoc4_r_handle_msg1(edhoc4_ctx *ctx, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);
/* consume message_3, build message_4 -> derive MSK/EMSK */
int edhoc4_r_handle_msg3(edhoc4_ctx *ctx, const uint8_t *in, size_t in_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/* returns a static human-readable string for an error code (<0) */
const char *edhoc4_strerror(int rc);

/* error codes */
#define E4_OK                0
#define E4_ERR_ARG          -1
#define E4_ERR_BUF          -2
#define E4_ERR_PARSE        -3
#define E4_ERR_KEM          -4
#define E4_ERR_AEAD         -5
#define E4_ERR_MAC          -6
#define E4_ERR_SIG          -7
#define E4_ERR_STATE        -8

#ifdef __cplusplus
}
#endif

#endif /* EDHOC4_H */
