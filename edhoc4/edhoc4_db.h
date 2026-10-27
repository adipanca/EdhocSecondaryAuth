/*
 * edhoc4_db.h — DN-AAA per-UE record store for EAP-EDHOC method 4 (no-eph).
 *
 * pk_B is per UE and rotated every session, so the responder keeps one
 * record per UE under <root>/<eap_identity>/ (see keygen.c):
 *   server.creds  ue.pub  ue.vk  id_cred  [prev/server.creds prev/ue.pub]
 *
 * The record is chosen from the EAP identity (RADIUS User-Name), which
 * arrives before message_1, so message_1 carries no key identifier. An
 * unknown identity falls back to trial decapsulation over all records.
 *
 * Grace-key policy for a lost message_4: on commit the active record moves
 * to prev/. If the next message_1 only decrypts under prev/, the UE did not
 * rotate: prev/ is restored as active and the unused rotated record is
 * erased. Once message_1 decrypts under the active record, prev/ is erased
 * (zeroized + unlinked). Forward secrecy of the last session is therefore
 * delayed by one session.
 *
 * All file operations take flock(<record>/.lock); radiusd is multi-threaded.
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
    int     used_prev;                 /* message_1 matched prev/         */
} edhoc4_db_rec;

/* lookup callback for edhoc4_set_lookup(): checks ID_CRED_I == rec->id_cred */
int edhoc4_db_lookup(const uint8_t id_cred[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                     uint8_t vk_i[E4_MLDSA_PK], void *arg);

/* Select the record for `identity` (NULL/unknown -> trial decapsulation over
 * every record in `root`), apply the grace-key policy and process
 * message_1. On success *ctx holds the responder state and *rec the record
 * to pass to edhoc4_db_commit(). */
int edhoc4_db_handle_msg1(const char *root, const char *identity,
                          edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

/* After edhoc4_r_handle_msg3 succeeded and MSK/EMSK were exported: move the
 * active record to prev/, install the rotated keys (edhoc4_commit) and save
 * the new record atomically. Wipes *ctx. */
int edhoc4_db_commit(edhoc4_ctx *ctx, edhoc4_db_rec *rec);

void edhoc4_db_rec_wipe(edhoc4_db_rec *rec);

#ifdef __cplusplus
}
#endif

#endif /* EDHOC4_DB_H */
