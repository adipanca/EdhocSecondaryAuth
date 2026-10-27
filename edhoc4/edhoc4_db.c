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

static int exists(const char *dir, const char *name)
{
    char p[1200];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    return stat(p, &st) == 0;
}

/* Overwrite two secret files with zeros in place, flush both, then unlink.
 * The overwrite keeps the file size, so fdatasync is enough to reach the
 * disk (no metadata to commit), and both overwrites go out before the first
 * flush instead of one flush per file. */
static void wipe_files(const char *dir, const char *a, const char *b)
{
    const char *names[2] = { a, b };
    char p[2][1200];
    int fd[2] = { -1, -1 };
    for (int i = 0; i < 2; i++) {
        struct stat st;
        snprintf(p[i], sizeof(p[i]), "%s/%s", dir, names[i]);
        if (stat(p[i], &st) != 0) { p[i][0] = '\0'; continue; }
        fd[i] = open(p[i], O_WRONLY);
        if (fd[i] < 0) continue;
        uint8_t z[512] = {0};
        off_t left = st.st_size;
        while (left > 0) {
            ssize_t n = write(fd[i], z, left < (off_t)sizeof(z) ? (size_t)left : sizeof(z));
            if (n <= 0) break;
            left -= n;
        }
    }
    for (int i = 0; i < 2; i++)
        if (fd[i] >= 0) { fdatasync(fd[i]); close(fd[i]); }
    for (int i = 0; i < 2; i++)
        if (p[i][0]) unlink(p[i]);
}

static void wipe_prev(const char *dir)
{
    char p[1100];
    wipe_files(dir, "prev/server.creds", "prev/ue.pub");
    snprintf(p, sizeof(p), "%s/prev", dir);
    rmdir(p);
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

/* load (server.creds, ue.pub) from <dir> or <dir>/prev; ue.vk and id_cred
 * do not rotate and always come from <dir> */
static int load_rec(const char *dir, int prev, edhoc4_db_rec *rec)
{
    snprintf(rec->dir, sizeof(rec->dir), "%s", dir);
    rec->used_prev = prev;
    if (read_file(dir, prev ? "prev/server.creds" : "server.creds",
                  &rec->server, sizeof(rec->server))) return -1;
    if (read_file(dir, prev ? "prev/ue.pub" : "ue.pub", rec->ue_pub, E4_XWING_PK)) return -1;
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

/* one record: active first, then prev/ (grace key) */
static int handle_one(const char *dir, edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                      const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    int rc = E4_ERR_PEER;
    int fd = lock_rec(dir);
    if (fd < 0) return E4_ERR_ARG;

    if (load_rec(dir, 0, rec) == 0) {
        rc = try_msg1(ctx, rec, in, in_len, out, out_cap, out_len);
        if (rc == E4_OK) {
            /* the UE rotated: the grace key is no longer needed */
            if (exists(dir, "prev")) wipe_prev(dir);
            unlock_rec(fd);
            return E4_OK;
        }
    }
    if (exists(dir, "prev/server.creds") && load_rec(dir, 1, rec) == 0) {
        int rc2 = try_msg1(ctx, rec, in, in_len, out, out_cap, out_len);
        if (rc2 == E4_OK) {
            /* message_4 was lost, the UE kept its old key: restore prev/ as
             * the active record and drop the unused rotated one */
            char a[1200], b[1200];
            wipe_files(dir, "server.creds", "ue.pub");
            snprintf(a, sizeof(a), "%s/prev/server.creds", dir);
            snprintf(b, sizeof(b), "%s/server.creds", dir);
            rename(a, b);
            snprintf(a, sizeof(a), "%s/prev/ue.pub", dir);
            snprintf(b, sizeof(b), "%s/ue.pub", dir);
            rename(a, b);
            snprintf(a, sizeof(a), "%s/prev", dir);
            rmdir(a);
            unlock_rec(fd);
            return E4_OK;
        }
        if (rc == E4_ERR_PEER) rc = rc2;
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
    char a[1200], b[1200];
    edhoc4_creds disk;
    int rc;

    if (!ctx || !rec || !ctx->done) return E4_ERR_STATE;
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;

    /* refuse if another session rotated this record meanwhile */
    if (read_file(rec->dir, "server.creds", &disk, sizeof(disk)) != 0 ||
        sodium_memcmp(disk.kem_pk, rec->server.kem_pk, E4_XWING_PK) != 0) {
        sodium_memzero(&disk, sizeof(disk));
        unlock_rec(fd);
        return E4_ERR_STATE;
    }
    sodium_memzero(&disk, sizeof(disk));

    /* active -> prev/ (grace key until the UE proves it rotated) */
    if (exists(rec->dir, "prev")) wipe_prev(rec->dir);
    snprintf(a, sizeof(a), "%s/prev", rec->dir);
    mkdir(a, 0700);
    snprintf(a, sizeof(a), "%s/server.creds", rec->dir);
    snprintf(b, sizeof(b), "%s/prev/server.creds", rec->dir);
    if (rename(a, b) != 0) { unlock_rec(fd); return E4_ERR_ARG; }
    snprintf(a, sizeof(a), "%s/ue.pub", rec->dir);
    snprintf(b, sizeof(b), "%s/prev/ue.pub", rec->dir);
    if (rename(a, b) != 0) { unlock_rec(fd); return E4_ERR_ARG; }

    rc = edhoc4_commit(ctx, &rec->server, rec->ue_pub);
    if (rc == E4_OK) {
        snprintf(a, sizeof(a), "%s/server.creds", rec->dir);
        rc = edhoc4_creds_save_atomic(a, &rec->server);
    }
    if (rc == E4_OK) {
        snprintf(a, sizeof(a), "%s/ue.pub", rec->dir);
        rc = edhoc4_pub_save_atomic_raw(a, rec->ue_pub);
    }
    unlock_rec(fd);
    return rc;
}

void edhoc4_db_rec_wipe(edhoc4_db_rec *rec)
{
    if (rec) sodium_memzero(rec, sizeof(*rec));
}
