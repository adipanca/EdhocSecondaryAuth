/*
 * edhoc4_db.h — key records for EAP-EDHOC method 4 (protocol v4).
 *
 * DN-AAA side: one record per UE under <root>/<record_id>/ (keygen.c); the
 * record id is internal (e.g. "ue1"), never taken from a network message:
 *   rec.bin  ue.vk  id_cred
 * rec.bin is a two-slot record (edhoc4_rec_*): the newest slot holds
 * (sk_B/pk_B + ML-DSA key, pk_A); ue.vk and id_cred do not rotate.
 *
 * The record is found by KID_B = SHA-256(pk_B), sent in clear at the start
 * of message_1, through the index <root>/kid/<hex(KID_B)> (a small file
 * holding the record id, written via a temporary file + rename + fsync of
 * the directory, under flock(<root>/kid/.lock)). The index is only a hint:
 * the record slot whose SHA-256(pk_B) equals KID_B is used; an entry that
 * names no such slot is stale, removed, and the KID is unknown. An unknown
 * KID is rejected before any KEM operation, so the outer EAP identity can
 * be anonymous. After PT1 is opened, (pk_A, VK_I) = Lookup(ID_CRED_I) must
 * match the record. There is no grace key:
 *   edhoc4_db_commit     after message_3: (Nsk_B, Npk_B, pk_A := Npk_A) to
 *                        the other slot + fdatasync, then the index entry of
 *                        SHA-256(Npk_B); both before message_4;
 *   edhoc4_db_erase_old  after message_4 is sent: zero the slot with the old
 *                        sk_B + fdatasync, then drop the index entry of the
 *                        old KID (off the critical path; _async uses a
 *                        worker thread).
 * A crash between the two leaves both slots and both index entries valid;
 * the next message_1 that names the newer slot erases the older one and
 * its entry. A KID that names the older slot while a newer one exists is
 * refused (the UE wrote NEXT before message_3, so it has the newer key).
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
 * Record file operations take flock(<record>/.lock); index operations
 * flock(<root>/kid/.lock), always after the record lock when both are held.
 * radiusd is multi-threaded.
 */
#ifndef EDHOC4_DB_H
#define EDHOC4_DB_H

#include "edhoc4.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char    root[1024];                /* record database root           */
    char    id[256];                   /* internal record id             */
    char    dir[1300];                 /* <root>/<id>                    */
    int     slot;                      /* slot this session runs on      */
    edhoc4_creds server;               /* own one-time sk_B/pk_B + ML-DSA */
    uint8_t ue_pub[E4_XWING_PK];       /* pk_A                            */
    uint8_t ue_vk[E4_MLDSA_PK];        /* VK_I                            */
    uint8_t id_cred[E4_ID_CRED];       /* ID_CRED_I                       */
} edhoc4_db_rec;

/* lookup callback for edhoc4_set_lookup(): checks ID_CRED_I == rec->id_cred */
int edhoc4_db_lookup(const uint8_t id_cred[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                     uint8_t vk_i[E4_MLDSA_PK], void *arg);

/* Find the record by the clear KID_B of message_1 and process message_1.
 * Unknown or stale KID: E4_ERR_PEER (no KEM operation). On success *ctx
 * holds the responder state and *rec the record (rec->id names it, e.g.
 * for the EMSK export) to pass to edhoc4_db_commit(). */
int edhoc4_db_handle_msg1(const char *root, edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

/* After edhoc4_r_handle_msg3 succeeded and MSK/EMSK were exported: write
 * the rotated record to the other slot (fdatasync), then the index entry
 * of SHA-256(Npk_B). Wipes *ctx; *rec keeps what edhoc4_db_erase_old
 * needs. */
int edhoc4_db_commit(edhoc4_ctx *ctx, edhoc4_db_rec *rec);

/* After message_4 was sent: zero the slot with the old sk_B + fdatasync,
 * then drop the old KID from the index. */
int edhoc4_db_erase_old(const edhoc4_db_rec *rec);
int edhoc4_db_erase_old_async(const edhoc4_db_rec *rec);

void edhoc4_db_rec_wipe(edhoc4_db_rec *rec);

/* KID index <root>/kid/<hex(kid)> -> record id */
int edhoc4_db_index_put(const char *root, const uint8_t kid[E4_KID_LEN], const char *id);
int edhoc4_db_index_get(const char *root, const uint8_t kid[E4_KID_LEN], char *id, size_t cap);
/* remove the entry if it names `id` (any record if id is NULL) */
int edhoc4_db_index_del(const char *root, const uint8_t kid[E4_KID_LEN], const char *id);
/* rebuild the index from the valid slots of every record (provisioning,
 * migration of records named by EAP identity) */
int edhoc4_db_reindex(const char *root);

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
