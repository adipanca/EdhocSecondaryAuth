/*
 * keygen.c — provisioning tool for EAP-EDHOC method 4 (SIGMA XWING, no-eph).
 *
 *   edhoc4_keygen <dir> [eap_identity ...]      (default identity: edhoc-ue)
 *   edhoc4_keygen --migrate <dir>               (one-time: old files -> rec)
 *
 * pk_B is per UE and rotated every session, so the DN-AAA keeps one record
 * per UE, selected by the EAP identity (RADIUS User-Name). For each identity:
 *
 *   DN-AAA side  <dir>/edhoc_db/<identity>/
 *       rec.bin       two-slot record: sk_B/pk_B for this UE + DN-AAA
 *                     ML-DSA key, and pk_A (UE one-time X-Wing key)  [secret]
 *       ue.vk         VK_I  (UE ML-DSA-44 verification key)
 *       id_cred       ID_CRED_I
 *   UE side      <dir>/ue/<identity>/
 *       ue.rec        two-slot record: sk_A/pk_A + UE ML-DSA key, and pk_B
 *
 * The DN-AAA ML-DSA key is the same for every UE. The first identity is
 * also written flat as <dir>/{server.creds,server.pub,ue.creds,ue.pub,ue.vk,
 * ue.rec} for single-UE tools.
 *
 * --migrate converts records written by the earlier layout (server.creds +
 * ue.pub [+ prev/] on the DN-AAA, ue.creds + server.pub on the UE) in place:
 * the active pair becomes slot 0 and the old files are zeroed and removed. Re-run before every benchmark series to start from a
 * clean (non-rotated) state.
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
static int save_record(const char *dn_dir, const char *ue_dir,
                       const edhoc4_creds *server, const edhoc4_creds *ue)
{
    if (mkdir_p(dn_dir) || mkdir_p(ue_dir)) { fprintf(stderr, "mkdir failed\n"); return 1; }
    if (save_rec(dn_dir, "rec.bin", server, ue->kem_pk)) return 1;
    if (save_raw(dn_dir, "ue.vk", ue->sig_vk, E4_MLDSA_PK)) return 1;
    if (save_raw(dn_dir, "id_cred", ue->id_cred, E4_ID_CRED)) return 1;
    if (save_rec(ue_dir, "ue.rec", ue, server->kem_pk)) return 1;
    return 0;
}

/* zero a secret file in place, then remove it */
static void wipe_file(const char *dir, const char *name)
{
    char p[1100];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    if (stat(p, &st) != 0) return;
    FILE *f = fopen(p, "r+b");
    if (f) {
        for (off_t i = 0; i < st.st_size; i++) fputc(0, f);
        fflush(f); fsync(fileno(f)); fclose(f);
    }
    unlink(p);
}

/* old layout -> rec for one directory; returns 1 if converted */
static int migrate_dir(const char *dir, const char *creds_name, const char *pub_name,
                       const char *rec_name)
{
    char cp[1100], pp[1100], rp[1100];
    edhoc4_creds c; uint8_t pk[E4_XWING_PK];
    snprintf(cp, sizeof(cp), "%s/%s", dir, creds_name);
    snprintf(pp, sizeof(pp), "%s/%s", dir, pub_name);
    snprintf(rp, sizeof(rp), "%s/%s", dir, rec_name);
    if (access(rp, F_OK) == 0 || edhoc4_creds_load(cp, &c) != E4_OK || edhoc4_pub_load(pp, pk) != E4_OK)
        return 0;
    int rc = edhoc4_rec_create(rp, &c, pk);
    sodium_memzero(&c, sizeof(c));
    if (rc != E4_OK) { fprintf(stderr, "write %s failed\n", rp); return -1; }
    wipe_file(dir, creds_name);
    wipe_file(dir, pub_name);
    char prev[1100];
    snprintf(prev, sizeof(prev), "%s/prev", dir);   /* old grace key: dropped */
    wipe_file(prev, creds_name);
    wipe_file(prev, pub_name);
    rmdir(prev);
    printf("  migrated %s\n", rp);
    return 1;
}

static int migrate(const char *root)
{
    static const char *sub[2] = { "edhoc_db", "ue" };
    static const char *names[2][3] = { { "server.creds", "ue.pub", "rec.bin" },
                                       { "ue.creds", "server.pub", "ue.rec" } };
    int n = 0;
    for (int k = 0; k < 2; k++) {
        char base[600], d[1100];
        snprintf(base, sizeof(base), "%s/%s", root, sub[k]);
        DIR *dp = opendir(base);
        if (!dp) continue;
        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            if (de->d_name[0] == '.') continue;
            snprintf(d, sizeof(d), "%s/%s", base, de->d_name);
            int r = migrate_dir(d, names[k][0], names[k][1], names[k][2]);
            if (r < 0) { closedir(dp); return 1; }
            n += r;
        }
        closedir(dp);
    }
    printf("migrated %d record(s) in %s/\n", n, root);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 2 && !strcmp(argv[1], "--migrate")) {
        if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
        return migrate(argv[2]);
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
