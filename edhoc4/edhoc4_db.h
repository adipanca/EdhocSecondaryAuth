/*
 * edhoc4_db.h — key records for EAP-EDHOC method 4 (protocol v4).
 *
 * DN-AAA side: one record per UE under <root>/<record_id>/ (keygen.c); the
 * record id is internal (e.g. "ue1"), never taken from a network message:
 *   rec.bin  ue.vk  id_cred
 * rec.bin is a two-slot record (edhoc4_rec_*): the newest slot holds
 * (sk_B/pk_B + ML-DSA key, pk_A); ue.vk and id_cred do not rotate.
 *
 * The record is found by KeyID_B = SHA-256(pk_B), sent in clear at the start
 * of message_1, through an in-memory index KeyID_B -> (record id, slot),
 * protected by a mutex. The slots are the only source of truth: the index is
 * rebuilt from them at start-up (edhoc4_db_index_open) and never written to
 * disk, so the critical path has one flush, as without an index. A record
 * added while the DN-AAA runs needs a restart. Even so the slot is read and
 * KeyID_B == SHA-256(pk_B) is checked (constant time) before any KEM
 * operation. An unknown KeyID costs a table lookup only: no disk access, no
 * KEM operation, so random KeyIDs cannot make the DN-AAA do work. After PT1
 * is opened, (pk_A, VK_I) = Lookup(ID_CRED_I) must match the record. There is
 * no grace key:
 *   edhoc4_db_commit     after message_3: (Nsk_B, Npk_B, pk_A := Npk_A) to
 *                        the other slot + one fdatasync, then the table entry
 *                        of SHA-256(Npk_B); before message_4;
 *   edhoc4_db_erase_old  after message_4 is sent: zero the slot with the old
 *                        sk_B + fdatasync, then drop the old KeyID from the
 *                        table (off the critical path; _async uses a worker
 *                        thread).
 * A crash between the two leaves both slots valid, so the rebuild finds both
 * KeyIDs; the next message_1 that names the newer slot erases the older one
 * and its entry. A KeyID that names the older slot while a newer one exists is
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
 * Record file operations take flock(<record>/.lock); radiusd is
 * multi-threaded, the index has its own mutex.
 */
#ifndef EDHOC4_DB_H
#define EDHOC4_DB_H

#include "edhoc4.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct edhoc4_db_index edhoc4_db_index;

typedef struct {
    edhoc4_db_index *idx;              /* in-memory KeyID index          */
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

/* Find the record by the clear KeyID_B of message_1 and process message_1.
 * Unknown KeyID, or a record that is gone: E4_ERR_PEER; an entry naming a
 * slot whose pk_B does not hash to KeyID_B is removed: E4_ERR_KEYID (both
 * without a KEM operation, both an EAP-Failure). On success *ctx holds the
 * responder state and *rec the record (rec->id names it, e.g. for the EMSK
 * export) to pass to edhoc4_db_commit(). */
int edhoc4_db_handle_msg1(edhoc4_db_index *idx, edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

/* After edhoc4_r_handle_msg3 succeeded and MSK/EMSK were exported: write
 * the rotated record to the other slot (one fdatasync), then the table entry
 * of SHA-256(Npk_B). Wipes *ctx; *rec keeps what edhoc4_db_erase_old
 * needs. */
int edhoc4_db_commit(edhoc4_ctx *ctx, edhoc4_db_rec *rec);

/* After message_4 was sent: zero the slot with the old sk_B + fdatasync,
 * then drop the old KeyID from the table. */
int edhoc4_db_erase_old(const edhoc4_db_rec *rec);
int edhoc4_db_erase_old_async(const edhoc4_db_rec *rec);

void edhoc4_db_rec_wipe(edhoc4_db_rec *rec);

/* In-memory KeyID index. _open scans every <root>/<record_id>/rec.bin and
 * enters each valid slot (after a crash between commit and erase_old, both);
 * *n_records and *n_keys may be NULL. NULL if root cannot be read. */
edhoc4_db_index *edhoc4_db_index_open(const char *root, size_t *n_records, size_t *n_keys);
void edhoc4_db_index_free(edhoc4_db_index *idx);
int edhoc4_db_index_put(edhoc4_db_index *idx, const uint8_t kid[E4_KEYID_LEN], const char *id, int slot);
/* E4_ERR_PEER if unknown; id (cap bytes) and slot may be NULL */
int edhoc4_db_index_get(edhoc4_db_index *idx, const uint8_t kid[E4_KEYID_LEN], char *id, size_t cap, int *slot);
/* remove the entry if it names `id` (any record if id is NULL) */
int edhoc4_db_index_del(edhoc4_db_index *idx, const uint8_t kid[E4_KEYID_LEN], const char *id);
/* entries naming `id` (all entries if id is NULL) */
size_t edhoc4_db_index_count(edhoc4_db_index *idx, const char *id);

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
