/*
 * edhoc4_db.h — key records for EAP-EDHOC method 4 (protocol v3).
 *
 * DN-AAA side: one record per UE under <root>/<uid>/ (see keygen.c):
 *   rec.bin  ue.vk  id_cred
 * rec.bin is a two-slot record (edhoc4_rec_*): the newest slot holds
 * (sk_B/pk_B + ML-DSA key, pk_A, P_cur); ue.vk and id_cred do not rotate.
 *
 * The EAP identity (RADIUS User-Name) is a one-time pseudonym NAI
 * p<32 hex>@realm. An in-memory index P -> uid, rebuilt from the records
 * on first use, selects the record; an unknown pseudonym is rejected with
 * E4_ERR_PSEUDO before any KEM operation. There is no grace key:
 *   edhoc4_db_commit     after message_3: (P_next, Nsk_B, Npk_B, pk_A :=
 *                        Npk_A) to the other slot + one fdatasync, index
 *                        P_cur -> P_next (critical path, before message_4);
 *   edhoc4_db_erase_old  after message_4 is sent: zero the slot with the old
 *                        sk_B + fdatasync (off the critical path).
 * A crash between the two leaves both slots valid; the index rebuild then
 * erases the older one.
 *
 * UE side: ue.rec holds CUR (one valid slot) and, between message_3 and the
 * promotion after message_4, NEXT (the newer of two valid slots):
 *   edhoc4_ue_load        NEXT if present, else CUR;
 *   edhoc4_ue_fallback    the DN-AAA rejected NEXT before message_2: drop
 *                         NEXT and reload CUR (one retry);
 *   edhoc4_ue_store_next  after message_2: NEXT = (Nsk_A, Npk_B, P_next)
 *                         + one fdatasync, before message_3 is sent;
 *   edhoc4_ue_promote     after message_4: drop the older slot (old sk_A)
 *                         + fdatasync (off the critical path).
 *
 * All DN-AAA file operations take flock(<record>/.lock); radiusd is
 * multi-threaded and the index is guarded by a mutex.
 */
#ifndef EDHOC4_DB_H
#define EDHOC4_DB_H

#include "edhoc4.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char    uid[256];                  /* internal record id             */
    char    dir[1024];                 /* <root>/<uid>                   */
    edhoc4_creds server;               /* own one-time sk_B/pk_B + ML-DSA */
    uint8_t ue_pub[E4_XWING_PK];       /* pk_A                            */
    uint8_t ue_vk[E4_MLDSA_PK];        /* VK_I                            */
    uint8_t id_cred[E4_ID_CRED];       /* ID_CRED_I                       */
    uint8_t pseudo[E4_PSEUDO_LEN];     /* P_cur                           */
} edhoc4_db_rec;

/* lookup callback for edhoc4_set_lookup(): checks ID_CRED_I == rec->id_cred */
int edhoc4_db_lookup(const uint8_t id_cred[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                     uint8_t vk_i[E4_MLDSA_PK], void *arg);

/* Select the record of the pseudonym NAI `identity` and process message_1.
 * Unknown or malformed pseudonym: E4_ERR_PSEUDO, no KEM operation. On
 * success *ctx holds the responder state and *rec the record to pass to
 * edhoc4_db_commit(). */
int edhoc4_db_handle_msg1(const char *root, const char *identity,
                          edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

/* After edhoc4_r_handle_msg3 succeeded and MSK/EMSK were exported: write
 * the rotated record to the other slot with one fdatasync and move the
 * index to P_next. Wipes *ctx; *rec keeps what edhoc4_db_erase_old needs. */
int edhoc4_db_commit(edhoc4_ctx *ctx, edhoc4_db_rec *rec);

/* After message_4 was sent: zero the slot with the old sk_B + fdatasync.
 * The _async form hands the erasure to a worker thread (radiusd). */
int edhoc4_db_erase_old(const edhoc4_db_rec *rec);
int edhoc4_db_erase_old_async(const edhoc4_db_rec *rec);

/* (Re)build the pseudonym index of `root`; erases older slots left by a
 * crash between commit and erasure. Returns the number of records. */
int edhoc4_db_reindex(const char *root);

void edhoc4_db_rec_wipe(edhoc4_db_rec *rec);

/* ---- UE side ---- */
typedef struct {
    edhoc4_creds self;                 /* own one-time sk_A/pk_A + ML-DSA */
    uint8_t peer_pk[E4_XWING_PK];      /* pk_B                            */
    uint8_t pseudo[E4_PSEUDO_LEN];     /* pseudonym for this session      */
    int     using_next;                /* 1: the session runs on NEXT     */
} edhoc4_ue_state;

int  edhoc4_ue_load(const char *path, edhoc4_ue_state *st);
int  edhoc4_ue_fallback(const char *path, edhoc4_ue_state *st);
int  edhoc4_ue_store_next(const char *path, const edhoc4_ctx *ctx);
int  edhoc4_ue_promote(const char *path);
void edhoc4_ue_state_wipe(edhoc4_ue_state *st);

#ifdef __cplusplus
}
#endif

#endif /* EDHOC4_DB_H */
