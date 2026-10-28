/*
 * edhoc4.h — Shared EAP-EDHOC method 4 core (SIGMA XWING).
 *
 * Implements the "EAP-EDHOC Hybrid PQC (XWING) — SIGMA" handshake from
 * mermaid.md §5:
 *   - key establishment : X-Wing hybrid KEM = ML-KEM-768 (PQClean) + X25519
 *                         (libsodium), SHA3-256 combiner and SHAKE256 key
 *                         expansion as in draft-connolly-cfrg-xwing-kem-09.
 *   - authentication    : ML-DSA-44 signatures on BOTH sides (PQClean) + MAC.
 *   - KDF / AEAD        : HKDF-SHA256 + AES-128-GCM (mbedTLS).
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
#define E4_AEAD_KEY   16   /* AES-128-GCM */
#define E4_AEAD_NONCE 12
#define E4_AEAD_TAG   16

#define E4_CONN_ID    1     /* C_I / C_R length */
#define E4_ID_CRED    3     /* ID_CRED_I / ID_CRED_R identifier length */
#define E4_METHOD     0x04  /* method byte in PT1 */

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

/* responder-side lookup: ID_CRED_I -> (pk_A, VK_I); return 0 on success */
typedef int (*edhoc4_lookup_fn)(const uint8_t id_cred[E4_ID_CRED],
                                uint8_t pk_a[E4_XWING_PK],
                                uint8_t vk_i[E4_MLDSA_PK], void *arg);

/* ---- handshake context ---- */
typedef struct {
    int role;                       /* 1 = initiator, 0 = responder */

    edhoc4_creds self;              /* own long-term credentials    */
    uint8_t peer_kem_pk[E4_XWING_PK];   /* peer static XWING pk      */
    uint8_t peer_sig_vk[E4_MLDSA_PK];   /* peer ML-DSA VK            */
    uint8_t peer_id_cred[E4_ID_CRED];

    uint8_t c_i[E4_CONN_ID];
    uint8_t c_r[E4_CONN_ID];

    /* shared secrets */
    uint8_t ss_b[E4_XWING_SS];      /* encaps/decaps against pkB (responder static) */
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

    /* responder: optional per-UE key lookup (set after edhoc4_init_responder) */
    edhoc4_lookup_fn lookup;
    void *lookup_arg;
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
/* crash-safe variants used after every rotation: write path.tmp, fsync,
 * rename(path.tmp, path). The _raw form stores a bare peer pk (Npk). */
int edhoc4_creds_save_atomic(const char *path, const edhoc4_creds *c);
int edhoc4_pub_save_atomic_raw(const char *path, const uint8_t pk[E4_XWING_PK]);

/* ---- two-slot key record (rotating state of one party) ----
 * One preallocated file per record: a header block and two fixed-size
 * slots, each holding (own creds, peer's current pk) with a sequence number
 * and a SHA-256 tag. The valid slot with the highest seq is active, the
 * other valid slot is prev (the DN-AAA's grace key). A commit writes the
 * inactive slot and issues ONE fdatasync: the file size never changes, so
 * no rename, directory flush or metadata commit is needed, and a torn write
 * fails its tag and leaves the old slot in force. Overwriting a slot is
 * also how an old key is erased. */
#define E4_REC_PAYLOAD (sizeof(edhoc4_creds) + E4_XWING_PK)

typedef struct {
    int      valid[2];
    uint64_t seq[2];
    int      active;        /* slot index, -1 if no slot is valid */
} edhoc4_rec_info;

/* provisioning: allocate and zero the file, write slot 0 (seq 1), fsync */
int edhoc4_rec_create(const char *path, const edhoc4_creds *self,
                      const uint8_t peer_pk[E4_XWING_PK]);
/* read the active (prev = 0) or the prev (prev = 1) slot; info may be NULL */
int edhoc4_rec_load(const char *path, int prev, edhoc4_creds *self,
                    uint8_t peer_pk[E4_XWING_PK], edhoc4_rec_info *info);
/* write (self, peer_pk) to the inactive slot with seq = active + 1 and
 * fdatasync once. keep_prev = 0 then zeroes the now-previous slot without
 * a flush (UE: it has no use for its old key). */
int edhoc4_rec_commit(const char *path, const edhoc4_creds *self,
                      const uint8_t peer_pk[E4_XWING_PK], int keep_prev);
/* zero the prev slot without a flush; the next commit's fdatasync, which
 * covers the same file, makes it durable */
int edhoc4_rec_erase_prev(const char *path);
/* lost message_4: copy prev over the active slot with a higher seq, flush */
int edhoc4_rec_promote_prev(const char *path);

/* ---- rotation-key pool (optional, off by default) ----
 * By default the EAD3/EAD4 key pair (next session's one-time X-Wing key) is
 * generated inside the handshake. It does not depend on the session, so a
 * deployment may precompute it: the handshake takes a key from this
 * process-wide pool when one is there and generates one inline otherwise.
 * edhoc4_pool_fill(n): top the pool up to n keys now (UE: after its commit).
 * edhoc4_pool_start(n): keep n keys ready with a refill thread, started on
 * the first take (DN-AAA). edhoc4_pool_misses(): keys generated inline. */
#define E4_POOL_MAX 16
int edhoc4_pool_fill(int n);
int edhoc4_pool_start(int n);
unsigned long edhoc4_pool_misses(void);

/* X-Wing known-answer test hook (draft-connolly-cfrg-xwing-kem-09, App. C):
 * GenerateKeyPairDerand(seed), EncapsulateDerand(pk, eseed), Decapsulate */
int edhoc4_xwing_selftest_kat(const uint8_t seed[32], const uint8_t eseed[64],
                              uint8_t pk[E4_XWING_PK], uint8_t ct[E4_XWING_CT],
                              uint8_t ss_enc[E4_XWING_SS], uint8_t ss_dec[E4_XWING_SS]);

/* ---- initiator (UE) ---- */
void edhoc4_init_initiator(edhoc4_ctx *ctx, const edhoc4_creds *self,
                           const uint8_t peer_kem_pk[E4_XWING_PK]);

/* build message_1 (encapsulates to pk_B only; no ephemeral key pair) */
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

/* responder: resolve (pk_A, VK_I) from ID_CRED_I carried in message_1.
 * The caller selects the per-UE record (own one-time sk_B) BEFORE
 * edhoc4_init_responder, from the EAP identity of the session. */
void edhoc4_set_lookup(edhoc4_ctx *ctx, edhoc4_lookup_fn fn, void *arg);

/* after success: install next-session keys, erase the old one-time sk and the
 * whole session context. Export MSK/EMSK first, then persist creds/peer_pk. */
int  edhoc4_commit(edhoc4_ctx *ctx, edhoc4_creds *creds, uint8_t peer_pk[E4_XWING_PK]);
void edhoc4_ctx_wipe(edhoc4_ctx *ctx);

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
#define E4_ERR_PEER         -9

#ifdef __cplusplus
}
#endif

#endif /* EDHOC4_H */
