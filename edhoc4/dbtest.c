/*
 * dbtest.c — file-backed rotation test for the two-slot key records
 * (edhoc4_rec_*) and the DN-AAA record store (edhoc4_db.c), without radiusd.
 *
 *   edhoc4_dbtest [workdir]
 *
 * Provisions two UEs with ./edhoc4_keygen, then checks:
 *   - 2 UEs x 5 sessions succeed and rewrite ue.rec / rec.bin every session;
 *   - a lost message_4 is recovered through the prev slot (grace key);
 *   - a torn write of the newest slot (UE or DN-AAA) falls back to the old one;
 *   - the prev slot is zero once message_1 proves the UE rotated, and an
 *     erased key no longer appears anywhere in the record file;
 *   - a stale pre-rotation UE key is rejected;
 *   - an unknown EAP identity is resolved by trial decapsulation.
 */
#include "edhoc4.h"
#include "edhoc4_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define REC_HDR  4096
#define REC_SLOT ((16 + E4_REC_PAYLOAD + 32 + 4095) / 4096 * 4096)

static char root[512], db[600];
static uint8_t filebuf[REC_HDR + 2 * REC_SLOT];

static void path_of(char *p, size_t cap, const char *ue_id, int dn)
{
    if (dn) snprintf(p, cap, "%s/edhoc_db/%s/rec.bin", root, ue_id);
    else    snprintf(p, cap, "%s/ue/%s/ue.rec", root, ue_id);
}

static size_t read_all(const char *p)
{
    FILE *f = fopen(p, "rb");
    size_t n = f ? fread(filebuf, 1, sizeof(filebuf), f) : 0;
    if (f) fclose(f);
    return n;
}

static void digest(const char *p, uint8_t h[32])
{
    crypto_hash_sha256(h, filebuf, read_all(p));
}

static int active_slot(const char *p)
{
    edhoc4_creds c; uint8_t pk[E4_XWING_PK]; edhoc4_rec_info info;
    int rc = edhoc4_rec_load(p, 0, &c, pk, &info);
    sodium_memzero(&c, sizeof(c));
    return rc == E4_OK ? info.active : -1;
}

/* flip one payload byte of the newest slot: its tag no longer verifies */
static void tear_newest(const char *p)
{
    int a = active_slot(p);
    FILE *f = fopen(p, "r+b");
    if (!f || a < 0) { if (f) fclose(f); return; }
    long off = REC_HDR + (long)a * REC_SLOT + 16 + 100;
    fseek(f, off, SEEK_SET);
    int c = fgetc(f);
    fseek(f, off, SEEK_SET);
    fputc(c ^ 0xff, f);
    fclose(f);
}

static int slot_is_zero(const char *p, int slot)
{
    read_all(p);
    for (size_t i = 0; i < REC_SLOT; i++)
        if (filebuf[REC_HDR + (size_t)slot * REC_SLOT + i]) return 0;
    return 1;
}

static int file_contains(const char *p, const uint8_t *needle, size_t len)
{
    size_t n = read_all(p);
    for (size_t i = 0; i + len <= n; i++)
        if (memcmp(filebuf + i, needle, len) == 0) return 1;
    return 0;
}

/* one EAP-EDHOC run; UE record under <root>/ue/<ue_id>/, the DN-AAA picks
 * the record from `eap_identity`. drop_m4: message_4 never reaches the UE.
 * stop_after_m1: abort after message_1 (no commit on either side). */
static int session(const char *ue_id, const char *eap_identity, int drop_m4,
                   int stop_after_m1, int *used_prev)
{
    char up[700];
    edhoc4_creds ue; uint8_t srv_pk[E4_XWING_PK];
    edhoc4_ctx I, R; edhoc4_db_rec rec;
    static uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    size_t n1, n2, n3, n4;
    uint8_t msk_r[E4_MSK_LEN];
    int rc;

    path_of(up, sizeof(up), ue_id, 0);
    if (edhoc4_rec_load(up, 0, &ue, srv_pk, NULL) != E4_OK) return E4_ERR_ARG;

    edhoc4_init_initiator(&I, &ue, srv_pk);
    if ((rc = edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1)) != E4_OK) return rc;
    memset(&rec, 0, sizeof(rec));
    if ((rc = edhoc4_db_handle_msg1(db, eap_identity, &R, &rec, m1, n1, m2, sizeof(m2), &n2)) != E4_OK) return rc;
    if (used_prev) *used_prev = rec.used_prev;
    if (stop_after_m1) { edhoc4_ctx_wipe(&I); edhoc4_ctx_wipe(&R); edhoc4_db_rec_wipe(&rec); return E4_OK; }
    if ((rc = edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3)) != E4_OK) return rc;
    if ((rc = edhoc4_r_handle_msg3(&R, m3, n3, m4, sizeof(m4), &n4)) != E4_OK) return rc;

    memcpy(msk_r, R.msk, E4_MSK_LEN);                /* export, then commit */
    if ((rc = edhoc4_db_commit(&R, &rec)) != E4_OK) return rc;
    edhoc4_db_rec_wipe(&rec);
    if (drop_m4) { edhoc4_ctx_wipe(&I); return E4_OK; }

    if ((rc = edhoc4_i_handle_msg4(&I, m4, n4)) != E4_OK) return rc;
    if (sodium_memcmp(msk_r, I.msk, E4_MSK_LEN) != 0) return E4_ERR_MAC;
    /* UE: after EAP-Success, one flush, old key slot zeroed */
    if ((rc = edhoc4_commit(&I, &ue, srv_pk)) != E4_OK) return rc;
    rc = edhoc4_rec_commit(up, &ue, srv_pk, 0);
    sodium_memzero(&ue, sizeof(ue));
    return rc;
}

static int fails;
static void check(int ok, const char *what)
{
    printf("  %-62s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

int main(int argc, char **argv)
{
    char cmd[1200], p_ue[700], p_dn[700], p_dnb[700];
    uint8_t h_ue[6][32], h_dn[6][32];
    int used_prev = -1;

    if (sodium_init() < 0) return 1;
    snprintf(root, sizeof(root), "%s", argc > 1 ? argv[1] : "dbtest.tmp");
    snprintf(db, sizeof(db), "%s/edhoc_db", root);
    snprintf(cmd, sizeof(cmd), "rm -rf '%s' && ./edhoc4_keygen '%s' ue-a ue-b >/dev/null", root, root);
    if (system(cmd) != 0) { fprintf(stderr, "provisioning failed\n"); return 1; }
    path_of(p_ue, sizeof(p_ue), "ue-a", 0);
    path_of(p_dn, sizeof(p_dn), "ue-a", 1);
    path_of(p_dnb, sizeof(p_dnb), "ue-b", 1);

    printf("[edhoc4 dbtest] two-slot key records, rotation persistence\n");
    int ok_a = 1, ok_b = 1, changes = 1;
    for (int i = 0; i < 5; i++) {
        digest(p_ue, h_ue[i]); digest(p_dn, h_dn[i]);
        ok_a &= session("ue-a", "ue-a", 0, 0, &used_prev) == E4_OK && used_prev == 0;
        ok_b &= session("ue-b", "ue-b", 0, 0, &used_prev) == E4_OK && used_prev == 0;
    }
    digest(p_ue, h_ue[5]); digest(p_dn, h_dn[5]);
    for (int i = 0; i < 5; i++)
        changes &= memcmp(h_ue[i], h_ue[i + 1], 32) && memcmp(h_dn[i], h_dn[i + 1], 32);
    check(ok_a, "ue-a: 5 sessions on the active slot");
    check(ok_b, "ue-b: 5 sessions on the active slot (independent record)");
    check(changes, "ue.rec and rec.bin rewritten every session");

    /* erasure: the key active before the last session must be gone from
     * rec.bin once the next message_1 proves the UE rotated */
    edhoc4_creds old; uint8_t old_pk[E4_XWING_PK];
    edhoc4_rec_load(p_dn, 1, &old, old_pk, NULL);         /* grace key now */
    check(file_contains(p_dn, old.kem_sk, 64), "grace key present in rec.bin after commit");
    check(session("ue-a", "ue-a", 0, 1, NULL) == E4_OK, "ue-a message_1 only (no commit)");
    check(slot_is_zero(p_dn, 1 - active_slot(p_dn)), "prev slot is zero once the UE proved rotation");
    check(!file_contains(p_dn, old.kem_sk, 64), "erased grace key no longer in rec.bin");
    sodium_memzero(&old, sizeof(old));
    check(session("ue-a", "ue-a", 0, 0, &used_prev) == E4_OK && used_prev == 0,
          "ue-a session after the aborted one");

    /* lost message_4 -> next session through the prev slot */
    check(session("ue-a", "ue-a", 1, 0, NULL) == E4_OK, "ue-a session, message_4 dropped");
    check(session("ue-a", "ue-a", 0, 0, &used_prev) == E4_OK && used_prev == 1,
          "next session recovers through prev (grace key)");
    check(session("ue-a", "ue-a", 0, 0, &used_prev) == E4_OK && used_prev == 0,
          "following session uses the active slot");

    /* torn write on the UE: crash while its commit writes the inactive slot
     * (before the old slot is zeroed). Replay it on a copy of ue.rec taken
     * before the session: the UE falls back to its old key, which the
     * DN-AAA still holds as prev */
    static uint8_t before[sizeof(filebuf)];
    size_t nb = read_all(p_ue);
    memcpy(before, filebuf, nb);
    int w = 1 - active_slot(p_ue);
    check(session("ue-a", "ue-a", 0, 0, NULL) == E4_OK, "ue-a session (UE commit to be torn)");
    memset(before + REC_HDR + (size_t)w * REC_SLOT, 0xA5, 4096);   /* half-written slot */
    FILE *f = fopen(p_ue, "wb");
    if (!f || fwrite(before, 1, nb, f) != nb) return 1;
    fclose(f);
    check(session("ue-a", "ue-a", 0, 0, &used_prev) == E4_OK && used_prev == 1,
          "UE torn write -> old UE slot, accepted through grace key");
    /* torn write on the DN-AAA after a lost message_4: its newest slot is
     * lost, the old slot matches the UE again */
    check(session("ue-a", "ue-a", 1, 0, NULL) == E4_OK, "ue-a session, message_4 dropped");
    tear_newest(p_dn);
    check(session("ue-a", "ue-a", 0, 0, &used_prev) == E4_OK && used_prev == 0,
          "DN-AAA torn write -> old DN-AAA slot, handshake succeeds");
    check(session("ue-a", "ue-a", 0, 0, &used_prev) == E4_OK && used_prev == 0,
          "following session uses the active slot");

    /* stale key: keep a copy, rotate twice (grace key overwritten), restore it */
    snprintf(cmd, sizeof(cmd), "cp -r '%s/ue/ue-a' '%s/stale'", root, root);
    if (system(cmd) != 0) return 1;
    check(session("ue-a", "ue-a", 0, 0, NULL) == E4_OK, "ue-a session (stale copy taken before)");
    check(session("ue-a", "ue-a", 0, 0, NULL) == E4_OK, "ue-a session (old grace key overwritten)");
    snprintf(cmd, sizeof(cmd), "rm -rf '%s/ue/ue-a' && mv '%s/stale' '%s/ue/ue-a'", root, root, root);
    if (system(cmd) != 0) return 1;
    int rc = session("ue-a", "ue-a", 0, 0, NULL);
    printf("    stale key -> %s\n", edhoc4_strerror(rc));
    check(rc != E4_OK, "stale pre-rotation UE key rejected");

    /* unknown identity -> trial decapsulation */
    check(session("ue-b", "anonymous", 0, 0, NULL) == E4_OK, "unknown identity: trial decapsulation finds ue-b");
    check(session("ue-b", "ue-b", 0, 0, NULL) == E4_OK, "ue-b session after trial");
    check(active_slot(p_dnb) >= 0, "ue-b rec.bin has a valid active slot");

    printf("\nRESULT: %s\n", fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}
