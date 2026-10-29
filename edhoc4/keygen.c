/*
 * keygen.c — provisioning tool for EAP-EDHOC method 4 (protocol v3).
 *
 *   edhoc4_keygen <dir> [uid ...]      (default uid: edhoc-ue)
 *
 * pk_B is per UE and rotated every session, so the DN-AAA keeps one record
 * per UE under an internal id (uid). The UE presents a one-time pseudonym
 * P as its EAP identity (NAI p<32 hex>@realm); P_0 is provisioned here and
 * every session replaces it with the P_next sent in EAD_2. For each uid:
 *
 *   DN-AAA side  <dir>/edhoc_db/<uid>/
 *       rec.bin       two-slot record: sk_B/pk_B for this UE + DN-AAA
 *                     ML-DSA key, pk_A (UE one-time X-Wing key), P_0 [secret]
 *       ue.vk         VK_I  (UE ML-DSA-44 verification key)
 *       id_cred       ID_CRED_I
 *   UE side      <dir>/ue/<uid>/
 *       ue.rec        two-slot record (CUR/NEXT): sk_A/pk_A + UE ML-DSA key,
 *                     pk_B, P_0
 *
 * The DN-AAA ML-DSA key is the same for every UE. The first uid is also
 * written flat as <dir>/{server.creds,server.pub,ue.creds,ue.pub,ue.vk,
 * ue.rec} for single-UE tools. Records of the earlier layout (no pseudonym)
 * are not converted: re-provision. Re-run before every benchmark series to
 * start from a clean state.
 */
#define _POSIX_C_SOURCE 200809L
#include "edhoc4.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
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
                    const uint8_t peer_pk[E4_XWING_PK], const uint8_t pseudo[E4_PSEUDO_LEN])
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    if (edhoc4_rec_create(p, self, peer_pk, pseudo) != E4_OK) { fprintf(stderr, "write %s failed\n", p); return 1; }
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

/* DN-AAA record + UE files for one uid */
static int save_record(const char *dn_dir, const char *ue_dir, const edhoc4_creds *server,
                       const edhoc4_creds *ue, const uint8_t p0[E4_PSEUDO_LEN])
{
    if (mkdir_p(dn_dir) || mkdir_p(ue_dir)) { fprintf(stderr, "mkdir failed\n"); return 1; }
    if (save_rec(dn_dir, "rec.bin", server, ue->kem_pk, p0)) return 1;
    if (save_raw(dn_dir, "ue.vk", ue->sig_vk, E4_MLDSA_PK)) return 1;
    if (save_raw(dn_dir, "id_cred", ue->id_cred, E4_ID_CRED)) return 1;
    if (save_rec(ue_dir, "ue.rec", ue, server->kem_pk, p0)) return 1;
    return 0;
}

int main(int argc, char **argv)
{
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

        uint8_t p0[E4_PSEUDO_LEN];
        char nai[64];
        randombytes_buf(p0, sizeof(p0));
        edhoc4_pseudo_to_nai(p0, NULL, nai, sizeof(nai));
        snprintf(dn_dir, sizeof(dn_dir), "%s/edhoc_db/%s", dir, ids[i]);
        snprintf(ue_dir, sizeof(ue_dir), "%s/ue/%s", dir, ids[i]);
        if (save_record(dn_dir, ue_dir, &server, &ue, p0)) return 1;

        if (i == 0) {
            if (save_raw(dir, "server.creds", &server, sizeof(server))) return 1;
            if (save_raw(dir, "server.pub", server.kem_pk, E4_XWING_PK)) return 1;
            if (save_raw(dir, "ue.creds", &ue, sizeof(ue))) return 1;
            if (save_raw(dir, "ue.pub", ue.kem_pk, E4_XWING_PK)) return 1;
            if (save_raw(dir, "ue.vk", ue.sig_vk, E4_MLDSA_PK)) return 1;
            if (save_rec(dir, "ue.rec", &ue, server.kem_pk, p0)) return 1;
        }
        printf("  %-16s P_0 %s  DN-AAA %s/  UE %s/\n", ids[i], nai, dn_dir, ue_dir);
        sodium_memzero(&server, sizeof(server));
        sodium_memzero(&ue, sizeof(ue));
    }
    sodium_memzero(&dn_sig, sizeof(dn_sig));

    printf("provisioned %d EDHOC method-4 record(s) in %s/\n", nids, dir);
    return 0;
}
