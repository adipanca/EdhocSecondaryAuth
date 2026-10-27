/*
 * edhoc4_db.c — DN-AAA per-UE record store for EAP-EDHOC method 4 (no-eph).
 * See edhoc4_db.h for the layout and the grace-key policy.
 */
#define _DEFAULT_SOURCE
#include "edhoc4_db.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>

static int read_file(const char *dir, const char *name, void *buf, size_t len)
{
    char p[1200];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}

static void rec_path(const char *dir, char *p, size_t cap)
{
    snprintf(p, cap, "%s/rec.bin", dir);
}

static int lock_rec(const char *dir)
{
    char p[1100];
    snprintf(p, sizeof(p), "%s/.lock", dir);
    int fd = open(p, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX) != 0) { close(fd); return -1; }
    return fd;
}

static void unlock_rec(int fd)
{
    if (fd < 0) return;
    flock(fd, LOCK_UN);
    close(fd);
}

/* load (sk_B/pk_B, pk_A) from the active or the prev slot of rec.bin; ue.vk
 * and id_cred do not rotate and are separate files */
static int load_rec(const char *dir, int prev, edhoc4_db_rec *rec, edhoc4_rec_info *info)
{
    char p[1200];
    snprintf(rec->dir, sizeof(rec->dir), "%s", dir);
    rec->used_prev = prev;
    rec_path(dir, p, sizeof(p));
    if (edhoc4_rec_load(p, prev, &rec->server, rec->ue_pub, info) != E4_OK) return -1;
    if (read_file(dir, "ue.vk", rec->ue_vk, E4_MLDSA_PK)) return -1;
    if (read_file(dir, "id_cred", rec->id_cred, E4_ID_CRED)) return -1;
    return 0;
}

int edhoc4_db_lookup(const uint8_t id_cred[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                     uint8_t vk_i[E4_MLDSA_PK], void *arg)
{
    const edhoc4_db_rec *rec = (const edhoc4_db_rec *)arg;
    if (!rec || sodium_memcmp(id_cred, rec->id_cred, E4_ID_CRED) != 0) return -1;
    memcpy(pk_a, rec->ue_pub, E4_XWING_PK);
    memcpy(vk_i, rec->ue_vk, E4_MLDSA_PK);
    return 0;
}

static int try_msg1(edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    edhoc4_init_responder(ctx, &rec->server, rec->ue_pub);
    edhoc4_set_lookup(ctx, edhoc4_db_lookup, rec);
    int rc = edhoc4_r_handle_msg1(ctx, in, in_len, out, out_cap, out_len);
    if (rc != E4_OK) edhoc4_ctx_wipe(ctx);
    return rc;
}

/* one record: active slot first, then prev (grace key) */
static int handle_one(const char *dir, edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                      const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    char p[1200];
    edhoc4_rec_info info;
    int rc = E4_ERR_PEER;
    int fd = lock_rec(dir);
    if (fd < 0) return E4_ERR_ARG;
    rec_path(dir, p, sizeof(p));

    if (load_rec(dir, 0, rec, &info) == 0) {
        rc = try_msg1(ctx, rec, in, in_len, out, out_cap, out_len);
        if (rc == E4_OK) {
            /* the UE rotated: zero the grace key; no flush here, the
             * commit of this session flushes the same file */
            if (info.valid[1 - info.active]) edhoc4_rec_erase_prev(p);
            unlock_rec(fd);
            return E4_OK;
        }
        if (info.valid[1 - info.active] && load_rec(dir, 1, rec, NULL) == 0) {
            int rc2 = try_msg1(ctx, rec, in, in_len, out, out_cap, out_len);
            if (rc2 == E4_OK) {
                /* message_4 was lost, the UE kept its old key: make prev
                 * active again over the unused rotated record */
                if (edhoc4_rec_promote_prev(p) != E4_OK) {
                    edhoc4_ctx_wipe(ctx);
                    rc2 = E4_ERR_ARG;
                } else {
                    unlock_rec(fd);
                    return E4_OK;
                }
            }
            if (rc == E4_ERR_PEER) rc = rc2;
        }
    }
    unlock_rec(fd);
    edhoc4_db_rec_wipe(rec);
    return rc;
}

static int valid_identity(const char *id)
{
    if (!id || !*id || id[0] == '.' || strlen(id) > 200) return 0;
    for (const char *p = id; *p; p++)
        if (*p == '/' || *p == '\\') return 0;
    return 1;
}

int edhoc4_db_handle_msg1(const char *root, const char *identity,
                          edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    char dir[1024];
    struct stat st;
    if (!root || !ctx || !rec) return E4_ERR_ARG;

    if (valid_identity(identity)) {
        snprintf(dir, sizeof(dir), "%s/%s", root, identity);
        if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode))
            return handle_one(dir, ctx, rec, in, in_len, out, out_cap, out_len);
    }

    /* unknown identity: trial decapsulation over every record */
    DIR *d = opendir(root);
    if (!d) return E4_ERR_ARG;
    int rc = E4_ERR_PEER;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        snprintf(dir, sizeof(dir), "%s/%s", root, de->d_name);
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        rc = handle_one(dir, ctx, rec, in, in_len, out, out_cap, out_len);
        if (rc == E4_OK) break;
    }
    closedir(d);
    return rc;
}

int edhoc4_db_commit(edhoc4_ctx *ctx, edhoc4_db_rec *rec)
{
    char p[1200];
    edhoc4_creds disk;
    uint8_t disk_pk[E4_XWING_PK];
    int rc;

    if (!ctx || !rec || !ctx->done) return E4_ERR_STATE;
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    rec_path(rec->dir, p, sizeof(p));

    /* refuse if another session rotated this record meanwhile */
    if (edhoc4_rec_load(p, 0, &disk, disk_pk, NULL) != E4_OK ||
        sodium_memcmp(disk.kem_pk, rec->server.kem_pk, E4_XWING_PK) != 0) {
        sodium_memzero(&disk, sizeof(disk));
        unlock_rec(fd);
        return E4_ERR_STATE;
    }
    sodium_memzero(&disk, sizeof(disk));

    /* write-ahead: the rotated record is durable (one fdatasync) before
     * message_4 is sent; the current slot stays as the grace key */
    rc = edhoc4_commit(ctx, &rec->server, rec->ue_pub);
    if (rc == E4_OK) rc = edhoc4_rec_commit(p, &rec->server, rec->ue_pub, 1);
    unlock_rec(fd);
    return rc;
}

void edhoc4_db_rec_wipe(edhoc4_db_rec *rec)
{
    if (rec) sodium_memzero(rec, sizeof(*rec));
}
