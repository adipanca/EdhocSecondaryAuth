/*
 * keygen.c — provisioning tool for EAP-EDHOC method 4 (protocol v4).
 *
 *   edhoc4_keygen <dir> [record_id ...]         (default record id: edhoc-ue)
 *   edhoc4_keygen --scan <db_root>              time of the DN-AAA index rebuild
 *
 * pk_B is per UE and rotated every session, so the DN-AAA keeps one record
 * per UE under an internal record id, found by KeyID_B = SHA-256(pk_B) from
 * message_1 through an in-memory index the DN-AAA rebuilds from the record
 * slots at start-up (nothing to write here). For each record id:
 *
 *   DN-AAA side  <dir>/edhoc_db/<record_id>/
 *       rec.bin       two-slot record: sk_B/pk_B for this UE + DN-AAA
 *                     ML-DSA key, and pk_A (UE one-time X-Wing key)  [secret]
 *       ue.vk         VK_I  (UE ML-DSA-44 verification key)
 *       id_cred       ID_CRED_I
 *   UE side      <dir>/ue/<identity>/
 *       ue.rec        two-slot record (CUR/NEXT): sk_A/pk_A + UE ML-DSA key,
 *                     and pk_B
 *
 * The DN-AAA ML-DSA key is the same for every UE. The first identity is
 * also written flat as <dir>/{server.creds,server.pub,ue.creds,ue.pub,ue.vk,
 * ue.rec} for single-UE tools. Records of earlier formats are not
 * converted: re-provision. Re-run before every benchmark series to start
 * from a clean state.
 */
#define _POSIX_C_SOURCE 200809L
#include "edhoc4.h"
#include "edhoc4_db.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sodium.h>

static int mkdir_p(const char *path)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    return (mkdir(tmp, 0700) != 0 && errno != EEXIST) ? -1 : 0;
}

static int save_rec(const char *dir, const char *name, const edhoc4_creds *self,
                    const uint8_t peer_pk[E4_XWING_PK])
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    if (edhoc4_rec_create(p, self, peer_pk) != E4_OK) { fprintf(stderr, "write %s failed\n", p); return 1; }
    return 0;
}

static int save_raw(const char *dir, const char *name, const void *buf, size_t len)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (!f) { fprintf(stderr, "write %s failed\n", p); return 1; }
    size_t n = fwrite(buf, 1, len, f);
    fclose(f);
    if (n != len) { fprintf(stderr, "write %s failed\n", p); return 1; }
    return 0;
}

/* DN-AAA record + UE files for one identity */
static int save_record(const char *dn_dir, const char *ue_dir, const edhoc4_creds *server,
                       const edhoc4_creds *ue)
{
    if (mkdir_p(dn_dir) || mkdir_p(ue_dir)) { fprintf(stderr, "mkdir failed\n"); return 1; }
    if (save_rec(dn_dir, "rec.bin", server, ue->kem_pk)) return 1;
    if (save_raw(dn_dir, "ue.vk", ue->sig_vk, E4_MLDSA_PK)) return 1;
    if (save_raw(dn_dir, "id_cred", ue->id_cred, E4_ID_CRED)) return 1;
    if (save_rec(ue_dir, "ue.rec", ue, server->kem_pk)) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--scan")) {
        struct timespec t0, t1;
        size_t nr = 0, nk = 0;
        if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
        clock_gettime(CLOCK_MONOTONIC, &t0);
        edhoc4_db_index *x = edhoc4_db_index_open(argv[2], &nr, &nk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (!x) { fprintf(stderr, "scan %s failed\n", argv[2]); return 1; }
        edhoc4_db_index_free(x);
        printf("%zu record(s), %zu KeyID(s), %.1f ms\n", nr, nk,
               (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6);
        return 0;
    }

    const char *dir = (argc > 1) ? argv[1] : ".";
    static const char *def_ids[] = { "edhoc-ue" };
    const char **ids = (argc > 2) ? (const char **)&argv[2] : def_ids;
    int nids = (argc > 2) ? argc - 2 : 1;
    char dn_dir[512], ue_dir[512];

    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
    if (mkdir_p(dir)) { fprintf(stderr, "mkdir %s failed\n", dir); return 1; }

    /* one DN-AAA ML-DSA key for every UE */
    edhoc4_creds dn_sig;
    uint8_t id_srv[E4_ID_CRED] = { 0x00, 0x00, 0x02 };
    if (edhoc4_gen_creds(&dn_sig, id_srv) != E4_OK) { fprintf(stderr, "gen DN-AAA failed\n"); return 1; }

    for (int i = 0; i < nids; i++) {
        edhoc4_creds server, ue;
        uint8_t id_ue[E4_ID_CRED] = { 0x00, (uint8_t)((i + 1) >> 8), (uint8_t)(i + 1) };

        /* per-UE X-Wing pair for the DN-AAA, shared ML-DSA identity */
        if (edhoc4_gen_creds(&server, id_srv) != E4_OK) { fprintf(stderr, "gen server failed\n"); return 1; }
        memcpy(server.sig_sk, dn_sig.sig_sk, E4_MLDSA_SK);
        memcpy(server.sig_vk, dn_sig.sig_vk, E4_MLDSA_PK);
        if (edhoc4_gen_creds(&ue, id_ue) != E4_OK) { fprintf(stderr, "gen ue failed\n"); return 1; }

        snprintf(dn_dir, sizeof(dn_dir), "%s/edhoc_db/%s", dir, ids[i]);
        snprintf(ue_dir, sizeof(ue_dir), "%s/ue/%s", dir, ids[i]);
        if (save_record(dn_dir, ue_dir, &server, &ue)) return 1;

        if (i == 0) {
            if (save_raw(dir, "server.creds", &server, sizeof(server))) return 1;
            if (save_raw(dir, "server.pub", server.kem_pk, E4_XWING_PK)) return 1;
            if (save_raw(dir, "ue.creds", &ue, sizeof(ue))) return 1;
            if (save_raw(dir, "ue.pub", ue.kem_pk, E4_XWING_PK)) return 1;
            if (save_raw(dir, "ue.vk", ue.sig_vk, E4_MLDSA_PK)) return 1;
            if (save_rec(dir, "ue.rec", &ue, server.kem_pk)) return 1;
        }
        printf("  %-16s DN-AAA %s/  UE %s/\n", ids[i], dn_dir, ue_dir);
        sodium_memzero(&server, sizeof(server));
        sodium_memzero(&ue, sizeof(ue));
    }
    sodium_memzero(&dn_sig, sizeof(dn_sig));

    printf("provisioned %d EDHOC method-4 record(s) in %s/\n", nids, dir);
    return 0;
}
