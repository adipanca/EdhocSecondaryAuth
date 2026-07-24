/*
 * edhoc03.h — Shared EAP-EDHOC methods 0..3 core (classical suite).
 *
 * Companion to edhoc4.h (which implements only method 4, SIGMA XWING PQC).
 * This core implements the four classical EDHOC methods from mermaid.md §1-4:
 *
 *   method 0 : SIG  / SIG   (initiator Ed25519 signature, responder Ed25519)
 *   method 1 : SIG  / STAT  (initiator Ed25519 signature, responder static-DH X25519 MAC)
 *   method 2 : STAT / SIG   (initiator static-DH X25519 MAC, responder Ed25519)
 *   method 3 : STAT / STAT  (both static-DH X25519 MAC)
 *
 * Key establishment : ephemeral X25519 ECDH (G_X / G_Y), libsodium.
 * Authentication    : Ed25519 signature (SIG role) or static-DH X25519 MAC (STAT role).
 * KDF / AEAD        : HKDF-SHA256 + ChaCha20-Poly1305 (libsodium), identical
 *                     construction to the method-4 core so the two share the
 *                     same key-schedule/exporter shape and MSK/EMSK labels.
 *
 * As with edhoc4, this is a *self-consistent binary profile* (not literal
 * RFC 9528 CBOR): both peers run byte-for-byte identical serialization, which
 * is what makes the UERANSIM/harness initiator and the FreeRADIUS responder
 * interoperate.  The classical methods produce small messages (< 200 B) so
 * they never require EAP fragmentation — the deliberate contrast with method 4.
 */
#ifndef EDHOC03_H
#define EDHOC03_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- primitive sizes ---- */
#define E3_X_PK        32     /* X25519 public key  (G_X / G_Y / static)  */
#define E3_X_SK        32     /* X25519 secret key                        */
#define E3_X_SS        32     /* X25519 shared secret                     */
#define E3_ED_PK       32     /* Ed25519 verify key                       */
#define E3_ED_SK       64     /* Ed25519 secret key (libsodium form)      */
#define E3_ED_SIG      64     /* Ed25519 signature                        */

#define E3_HASH_LEN    32
#define E3_PRK_LEN     32
#define E3_MAC_LEN      8
#define E3_AEAD_KEY    32
#define E3_AEAD_NONCE  12
#define E3_AEAD_TAG    16

#define E3_CONN_ID      1
#define E3_ID_CRED      3

#define E3_MSK_LEN     64
#define E3_EMSK_LEN    64

/* Upper bound for any single classical EDHOC message. */
#define E3_MAX_MSG    512

/* auth mode of a peer for a given method */
#define E3_AUTH_SIG    0      /* Ed25519 signature */
#define E3_AUTH_STAT   1      /* static-DH X25519 MAC */

/* ---- credentials ----
 * A single credential set carries BOTH an Ed25519 signing key (used when the
 * peer plays a SIG role) and an X25519 static key (used when it plays a STAT
 * role), so one provisioned file works for every method.
 */
typedef struct {
    uint8_t id_cred[E3_ID_CRED];
    uint8_t sig_sk[E3_ED_SK];     /* Ed25519 secret (SIG role)           */
    uint8_t sig_vk[E3_ED_PK];     /* Ed25519 public                       */
    uint8_t dh_sk[E3_X_SK];       /* X25519 static secret (STAT role)    */
    uint8_t dh_pk[E3_X_PK];       /* X25519 static public                 */
} edhoc03_creds;

/* Peer static-public material (loaded from a .pub file). */
typedef struct {
    uint8_t sig_vk[E3_ED_PK];
    uint8_t dh_pk[E3_X_PK];
} edhoc03_peer;

typedef struct {
    int role;                     /* 1 = initiator, 0 = responder         */
    int method;                   /* 0..3                                  */
    int self_auth;                /* E3_AUTH_SIG / E3_AUTH_STAT for self   */
    int peer_auth;                /* auth mode of the peer                 */

    edhoc03_creds self;
    edhoc03_peer  peer;           /* pinned peer static keys               */

    uint8_t c_i[E3_CONN_ID];
    uint8_t c_r[E3_CONN_ID];

    /* ephemeral X25519 keypair */
    uint8_t eph_sk[E3_X_SK];
    uint8_t eph_pk[E3_X_PK];      /* G_X (initiator) or G_Y (responder)   */
    uint8_t peer_eph_pk[E3_X_PK]; /* G_Y (initiator) or G_X (responder)   */

    uint8_t ss_e[E3_X_SS];        /* G_XY ephemeral shared secret          */

    uint8_t h_msg1[E3_HASH_LEN];  /* H(message_1)                          */
    uint8_t th2[E3_HASH_LEN];
    uint8_t th3[E3_HASH_LEN];
    uint8_t th4[E3_HASH_LEN];

    uint8_t prk2e[E3_PRK_LEN];
    uint8_t prk3e2m[E3_PRK_LEN];
    uint8_t prk4e3m[E3_PRK_LEN];
    uint8_t prk_out[E3_PRK_LEN];

    uint8_t peer_id_cred[E3_ID_CRED];

    uint8_t msk[E3_MSK_LEN];
    uint8_t emsk[E3_EMSK_LEN];
    int done;
} edhoc03_ctx;

/* ---- credential generation / persistence ---- */
int  edhoc03_gen_creds(edhoc03_creds *c, const uint8_t id_cred[E3_ID_CRED]);
int  edhoc03_creds_save(const char *path, const edhoc03_creds *c);
int  edhoc03_creds_load(const char *path, edhoc03_creds *c);
int  edhoc03_pub_save(const char *path, const edhoc03_creds *c);
int  edhoc03_pub_load(const char *path, edhoc03_peer *peer);

/* ---- initiator ---- */
void edhoc03_init_initiator(edhoc03_ctx *ctx, int method,
                            const edhoc03_creds *self, const edhoc03_peer *peer);
int  edhoc03_i_make_msg1(edhoc03_ctx *ctx, uint8_t *out, size_t out_cap, size_t *out_len);
int  edhoc03_i_handle_msg2(edhoc03_ctx *ctx, const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);
/* consume message_4 (empty EAP-Success payload) -> confirm done */
int  edhoc03_i_handle_msg4(edhoc03_ctx *ctx, const uint8_t *in, size_t in_len);

/* ---- responder ---- */
void edhoc03_init_responder(edhoc03_ctx *ctx,
                            const edhoc03_creds *self, const edhoc03_peer *peer);
int  edhoc03_r_handle_msg1(edhoc03_ctx *ctx, const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);
/* consume message_3, build message_4 (empty) -> derive MSK/EMSK */
int  edhoc03_r_handle_msg3(edhoc03_ctx *ctx, const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);

const char *edhoc03_strerror(int rc);

/* returns 0..3 method's initiator/responder auth modes */
int  edhoc03_method_valid(int method);

/* error codes (shared numeric space with edhoc4) */
#define E3_OK          0
#define E3_ERR_ARG    -1
#define E3_ERR_BUF    -2
#define E3_ERR_PARSE  -3
#define E3_ERR_DH     -4
#define E3_ERR_AEAD   -5
#define E3_ERR_MAC    -6
#define E3_ERR_SIG    -7
#define E3_ERR_STATE  -8

#ifdef __cplusplus
}
#endif

#endif /* EDHOC03_H */
