/*
 * edhoc4_db.h — key records for EAP-EDHOC method 4 (final v3 protocol).
 *
 * DN-AAA side: one record per UE under <root>/<eap_identity>/ (keygen.c):
 *   rec.bin  ue.vk  id_cred
 * rec.bin is a two-slot record (edhoc4_rec_*): the newest slot holds
 * (sk_B/pk_B + ML-DSA key, pk_A); ue.vk and id_cred do not rotate.
 * The record is selected from the EAP identity (RADIUS User-Name), which
 * arrives before message_1; an unknown identity is rejected. After PT1 is
 * opened, (pk_A, VK_I) = Lookup(ID_CRED_I) must match the record. There is
 * no grace key:
 *   edhoc4_db_commit     after message_3: (Nsk_B, Npk_B, pk_A := Npk_A) to
 *                        the other slot + one fdatasync (critical path,
 *                        before message_4);
 *   edhoc4_db_erase_old  after message_4 is sent: zero the slot with the old
 *                        sk_B + fdatasync (off the critical path; the
 *                        _async form uses a worker thread).
 * A crash between the two leaves both slots valid; the next message_1 of
 * that UE erases the older one.
 *
 * UE side: ue.rec holds CUR and, between message_3 and the promotion after
 * message_4, NEXT = (Nsk_A, Npk_A, Npk_B), the newest valid slot.
 *   edhoc4_ue_load        NEXT if present, else CUR;
 *   edhoc4_ue_fallback    an explicit EAP-Failure after message_1 and before
 *                         message_2 was verified while on NEXT: run on CUR,
 *                         KEEP NEXT (a Failure is unauthenticated and must
 *                         not erase a key); a timeout is no reason;
 *   edhoc4_ue_store_next  after message_2: NEXT into the slot not in use
 *                         (replacing an uncommitted NEXT when on CUR) + one
 *                         fdatasync, before message_3 is sent;
 *   edhoc4_ue_promote     after message_4: zero the slot in use (the old
 *                         sk_A) + fdatasync, off the critical path.
 *
 * All DN-AAA file operations take flock(<record>/.lock); radiusd is
 * multi-threaded.
 */
#ifndef EDHOC4_DB_H
#define EDHOC4_DB_H

#include "edhoc4.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char    dir[1024];                 /* <root>/<identity>              */
    edhoc4_creds server;               /* own one-time sk_B/pk_B + ML-DSA */
    uint8_t ue_pub[E4_XWING_PK];       /* pk_A                            */
    uint8_t ue_vk[E4_MLDSA_PK];        /* VK_I                            */
    uint8_t id_cred[E4_ID_CRED];       /* ID_CRED_I                       */
} edhoc4_db_rec;

/* lookup callback for edhoc4_set_lookup(): checks ID_CRED_I == rec->id_cred */
int edhoc4_db_lookup(const uint8_t id_cred[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                     uint8_t vk_i[E4_MLDSA_PK], void *arg);

/* Select the record of `identity` and process message_1. Unknown identity:
 * E4_ERR_PEER (no KEM operation). On success *ctx holds the responder
 * state and *rec the record to pass to edhoc4_db_commit(). */
int edhoc4_db_handle_msg1(const char *root, const char *identity,
                          edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

/* After edhoc4_r_handle_msg3 succeeded and MSK/EMSK were exported: write
 * the rotated record to the other slot with one fdatasync. Wipes *ctx;
 * *rec keeps what edhoc4_db_erase_old needs. */
int edhoc4_db_commit(edhoc4_ctx *ctx, edhoc4_db_rec *rec);

/* After message_4 was sent: zero the slot with the old sk_B + fdatasync. */
int edhoc4_db_erase_old(const edhoc4_db_rec *rec);
int edhoc4_db_erase_old_async(const edhoc4_db_rec *rec);

void edhoc4_db_rec_wipe(edhoc4_db_rec *rec);

/* ---- UE side ---- */
typedef struct {
    edhoc4_creds self;                 /* own one-time sk_A/pk_A + ML-DSA */
    uint8_t peer_pk[E4_XWING_PK];      /* pk_B                            */
    int     slot;                      /* slot this session runs on       */
    int     using_next;                /* 1: that slot is NEXT            */
    int     has_next;                  /* a NEXT slot exists              */
} edhoc4_ue_state;

int  edhoc4_ue_load(const char *path, edhoc4_ue_state *st);
int  edhoc4_ue_fallback(const char *path, edhoc4_ue_state *st);
int  edhoc4_ue_store_next(const char *path, const edhoc4_ue_state *st, const edhoc4_ctx *ctx);
int  edhoc4_ue_promote(const char *path, const edhoc4_ue_state *st);
void edhoc4_ue_state_wipe(edhoc4_ue_state *st);

#ifdef __cplusplus
}
#endif

#endif /* EDHOC4_DB_H */
