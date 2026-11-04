/*
 * edhoc4_db.c — key records for EAP-EDHOC method 4 (protocol v4).
 * See edhoc4_db.h for the layout, the commit order and the UE slot rules.
 */
#define _DEFAULT_SOURCE
#include "edhoc4_db.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
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

/* ---- KeyID index: <root>/kid/<hex(KeyID_B)> -> record id ---- */

static void kid_hex(const uint8_t kid[E4_KEYID_LEN], char hex[2 * E4_KEYID_LEN + 1])
{
    sodium_bin2hex(hex, 2 * E4_KEYID_LEN + 1, kid, E4_KEYID_LEN);
}

static int fsync_dir(const char *dir)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc;
}

static int lock_index(const char *root)
{
    char p[1200];
    snprintf(p, sizeof(p), "%s/kid", root);
    if (mkdir(p, 0700) != 0 && errno != EEXIST) return -1;
    snprintf(p, sizeof(p), "%s/kid/.lock", root);
    int fd = open(p, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX) != 0) { close(fd); return -1; }
    return fd;
}

/* record ids name a directory under root: no path separators, no dot files */
static int valid_id(const char *id)
{
    if (!id || !*id || id[0] == '.' || strlen(id) > 200) return 0;
    for (const char *p = id; *p; p++)
        if (*p == '/' || *p == '\\' || *p == '\n') return 0;
    return 1;
}

static int index_get_locked(const char *root, const uint8_t kid[E4_KEYID_LEN], char *id, size_t cap)
{
    char hex[2 * E4_KEYID_LEN + 1], p[1300];
    kid_hex(kid, hex);
    snprintf(p, sizeof(p), "%s/kid/%s", root, hex);
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    size_t n = fread(id, 1, cap - 1, f);
    fclose(f);
    id[n] = 0;
    return valid_id(id) ? 0 : -1;
}

static int index_put_locked(const char *root, const uint8_t kid[E4_KEYID_LEN], const char *id)
{
    char hex[2 * E4_KEYID_LEN + 1], p[1300], tmp[1300], dir[1100];
    kid_hex(kid, hex);
    snprintf(dir, sizeof(dir), "%s/kid", root);
    snprintf(p, sizeof(p), "%s/%s", dir, hex);
    snprintf(tmp, sizeof(tmp), "%s/.tmp-%s", dir, hex);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    size_t len = strlen(id);
    int ok = write(fd, id, len) == (ssize_t)len && fdatasync(fd) == 0;
    close(fd);
    if (!ok || rename(tmp, p) != 0) { unlink(tmp); return -1; }
    return fsync_dir(dir);
}

static int index_del_locked(const char *root, const uint8_t kid[E4_KEYID_LEN], const char *id)
{
    char hex[2 * E4_KEYID_LEN + 1], p[1300], cur[256], dir[1100];
    if (id && (index_get_locked(root, kid, cur, sizeof(cur)) != 0 || strcmp(cur, id) != 0))
        return 0;                       /* absent, or names another record */
    kid_hex(kid, hex);
    snprintf(dir, sizeof(dir), "%s/kid", root);
    snprintf(p, sizeof(p), "%s/%s", dir, hex);
    if (unlink(p) != 0) return errno == ENOENT ? 0 : -1;
    return fsync_dir(dir);
}

int edhoc4_db_index_put(const char *root, const uint8_t kid[E4_KEYID_LEN], const char *id)
{
    if (!root || !kid || !valid_id(id)) return E4_ERR_ARG;
    int fd = lock_index(root);
    if (fd < 0) return E4_ERR_ARG;
    int rc = index_put_locked(root, kid, id) == 0 ? E4_OK : E4_ERR_ARG;
    unlock_rec(fd);
    return rc;
}

int edhoc4_db_index_get(const char *root, const uint8_t kid[E4_KEYID_LEN], char *id, size_t cap)
{
    if (!root || !kid || !id || cap < 2) return E4_ERR_ARG;
    int fd = lock_index(root);
    if (fd < 0) return E4_ERR_ARG;
    int rc = index_get_locked(root, kid, id, cap) == 0 ? E4_OK : E4_ERR_PEER;
    unlock_rec(fd);
    return rc;
}

int edhoc4_db_index_del(const char *root, const uint8_t kid[E4_KEYID_LEN], const char *id)
{
    if (!root || !kid) return E4_ERR_ARG;
    int fd = lock_index(root);
    if (fd < 0) return E4_ERR_ARG;
    int rc = index_del_locked(root, kid, id) == 0 ? E4_OK : E4_ERR_ARG;
    unlock_rec(fd);
    return rc;
}

int edhoc4_db_reindex(const char *root)
{
    DIR *d = opendir(root);
    if (!d) return E4_ERR_ARG;
    struct dirent *de;
    int n = 0, rc = E4_OK;
    while ((de = readdir(d)) != NULL) {
        char dir[1300], p[1400];
        struct stat st;
        if (!valid_id(de->d_name) || !strcmp(de->d_name, "kid")) continue;
        snprintf(dir, sizeof(dir), "%s/%s", root, de->d_name);
        rec_path(dir, p, sizeof(p));
        if (stat(p, &st) != 0) continue;
        int fd = lock_rec(dir);
        if (fd < 0) { rc = E4_ERR_ARG; continue; }
        for (int slot = 0; slot < 2; slot++) {
            edhoc4_creds c;
            uint8_t kid[E4_KEYID_LEN];
            if (edhoc4_rec_load(p, slot, &c, NULL, NULL) != E4_OK) continue;
            edhoc4_keyid(c.kem_pk, kid);
            sodium_memzero(&c, sizeof(c));
            if (edhoc4_db_index_put(root, kid, de->d_name) != E4_OK) rc = E4_ERR_ARG;
            else n++;
        }
        unlock_rec(fd);
    }
    closedir(d);
    return rc == E4_OK ? n : rc;
}

/* ---- DN-AAA ---- */

int edhoc4_db_lookup(const uint8_t id_cred[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                     uint8_t vk_i[E4_MLDSA_PK], void *arg)
{
    const edhoc4_db_rec *rec = (const edhoc4_db_rec *)arg;
    if (!rec || sodium_memcmp(id_cred, rec->id_cred, E4_ID_CRED) != 0) return -1;
    memcpy(pk_a, rec->ue_pub, E4_XWING_PK);
    memcpy(vk_i, rec->ue_vk, E4_MLDSA_PK);
    return 0;
}

/* slot of record file p whose SHA-256(pk_B) is kid, -1 if none */
static int slot_of_kid(const char *p, const uint8_t kid[E4_KEYID_LEN])
{
    for (int slot = 0; slot < 2; slot++) {
        edhoc4_creds c;
        uint8_t k[E4_KEYID_LEN];
        if (edhoc4_rec_load(p, slot, &c, NULL, NULL) != E4_OK) continue;
        edhoc4_keyid(c.kem_pk, k);
        sodium_memzero(&c, sizeof(c));
        if (sodium_memcmp(k, kid, E4_KEYID_LEN) == 0) return slot;
    }
    return -1;
}

/* zero slot `slot` of a record and drop its KeyID from the index (record
 * lock held) */
static int erase_slot(const char *root, const char *id, const char *p, int slot)
{
    edhoc4_creds c;
    uint8_t kid[E4_KEYID_LEN];
    if (edhoc4_rec_load(p, slot, &c, NULL, NULL) != E4_OK) return E4_OK;
    edhoc4_keyid(c.kem_pk, kid);
    sodium_memzero(&c, sizeof(c));
    int rc = edhoc4_rec_zero(p, slot, 1);
    if (rc == E4_OK) {
        int ifd = lock_index(root);
        if (ifd >= 0) { index_del_locked(root, kid, id); unlock_rec(ifd); }
    }
    return rc;
}

int edhoc4_db_handle_msg1(const char *root, edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    char p[1400];
    uint8_t kid[E4_KEYID_LEN];
    struct stat st;
    edhoc4_rec_info info;
    if (!root || !ctx || !rec) return E4_ERR_ARG;
    memset(rec, 0, sizeof(*rec));

    /* clear KeyID_B -> record id; unknown: reject before any KEM operation */
    if (edhoc4_r_peek_keyid(in, in_len, kid) != E4_OK) return E4_ERR_PARSE;
    if (edhoc4_db_index_get(root, kid, rec->id, sizeof(rec->id)) != E4_OK) return E4_ERR_PEER;
    snprintf(rec->root, sizeof(rec->root), "%s", root);
    snprintf(rec->dir, sizeof(rec->dir), "%s/%s", root, rec->id);
    if (stat(rec->dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        edhoc4_db_index_del(root, kid, rec->id);          /* stale entry */
        edhoc4_db_rec_wipe(rec);
        return E4_ERR_PEER;
    }

    rec_path(rec->dir, p, sizeof(p));
    int fd = lock_rec(rec->dir);
    if (fd < 0) { edhoc4_db_rec_wipe(rec); return E4_ERR_ARG; }
    int rc = E4_ERR_PEER;
    int slot = slot_of_kid(p, kid);
    if (slot < 0) {
        /* the index named a record without that pk_B: KeyID_B != SHA-256(pk_B);
         * a stale entry, removed, no KEM operation */
        int ifd = lock_index(root);
        if (ifd >= 0) { index_del_locked(root, kid, rec->id); unlock_rec(ifd); }
        rc = E4_ERR_KEYID;
    } else if (edhoc4_rec_load(p, -1, NULL, NULL, &info) == E4_OK && slot == info.active &&
               edhoc4_rec_load(p, slot, &rec->server, rec->ue_pub, NULL) == E4_OK &&
               read_file(rec->dir, "ue.vk", rec->ue_vk, E4_MLDSA_PK) == 0 &&
               read_file(rec->dir, "id_cred", rec->id_cred, E4_ID_CRED) == 0) {
        /* an old sk_B whose erasure did not happen (crash): erase it now */
        if (info.valid[1 - slot]) erase_slot(root, rec->id, p, 1 - slot);
        rec->slot = slot;
        edhoc4_init_responder(ctx, &rec->server, rec->ue_pub);
        edhoc4_set_lookup(ctx, edhoc4_db_lookup, rec);
        rc = edhoc4_r_handle_msg1(ctx, in, in_len, out, out_cap, out_len);
        if (rc != E4_OK) edhoc4_ctx_wipe(ctx);
    }
    /* else: the KeyID names the older slot while a newer one exists; the UE
     * holds the newer key (NEXT was written before message_3) */
    unlock_rec(fd);
    if (rc != E4_OK) edhoc4_db_rec_wipe(rec);
    return rc;
}

int edhoc4_db_commit(edhoc4_ctx *ctx, edhoc4_db_rec *rec)
{
    char p[1400];
    edhoc4_creds disk, next;
    edhoc4_rec_info info;
    uint8_t next_pk[E4_XWING_PK], next_kid[E4_KEYID_LEN];
    int rc;

    if (!ctx || !rec || !ctx->done) return E4_ERR_STATE;
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    rec_path(rec->dir, p, sizeof(p));

    /* refuse if another session rotated this record meanwhile */
    if (edhoc4_rec_load(p, -1, &disk, NULL, &info) != E4_OK || info.active != rec->slot ||
        sodium_memcmp(disk.kem_pk, rec->server.kem_pk, E4_XWING_PK) != 0) {
        sodium_memzero(&disk, sizeof(disk));
        unlock_rec(fd);
        return E4_ERR_STATE;
    }
    sodium_memzero(&disk, sizeof(disk));

    /* write-ahead: (Nsk_B, Npk_B, pk_A := Npk_A) is durable (one fdatasync),
     * then the index names the record by SHA-256(Npk_B); both before
     * message_4. The old slot and its entry are erased later. */
    edhoc4_next_state(ctx, &next, next_pk);
    edhoc4_keyid(next.kem_pk, next_kid);
    rc = edhoc4_rec_write(p, 1 - rec->slot, &next, next_pk);
    sodium_memzero(&next, sizeof(next));
    edhoc4_ctx_wipe(ctx);
    if (rc == E4_OK) {
        int ifd = lock_index(rec->root);
        rc = (ifd >= 0 && index_put_locked(rec->root, next_kid, rec->id) == 0) ? E4_OK : E4_ERR_ARG;
        if (ifd >= 0) unlock_rec(ifd);
    }
    unlock_rec(fd);
    return rc;
}

int edhoc4_db_erase_old(const edhoc4_db_rec *rec)
{
    char p[1400];
    edhoc4_rec_info info;
    if (!rec || !rec->dir[0]) return E4_ERR_ARG;
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    rec_path(rec->dir, p, sizeof(p));
    int rc = edhoc4_rec_load(p, -1, NULL, NULL, &info);
    if (rc == E4_OK && info.valid[1 - info.active])
        rc = erase_slot(rec->root, rec->id, p, 1 - info.active);
    unlock_rec(fd);
    return rc;
}

/* erase worker: one thread, started on first use, so that the fdatasync of
 * the erasure never sits on the path of a reply */
typedef struct erase_job {
    char root[1024];
    char id[256];
    char dir[1300];
    struct erase_job *next;
} erase_job;

static pthread_mutex_t er_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  er_cv = PTHREAD_COND_INITIALIZER;
static erase_job *er_head, **er_tail = &er_head;
static int er_thread_on;

static void *erase_main(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&er_mu);
        while (!er_head) pthread_cond_wait(&er_cv, &er_mu);
        erase_job *j = er_head;
        er_head = j->next;
        if (!er_head) er_tail = &er_head;
        pthread_mutex_unlock(&er_mu);
        edhoc4_db_rec r;
        memset(&r, 0, sizeof(r));
        snprintf(r.root, sizeof(r.root), "%s", j->root);
        snprintf(r.id, sizeof(r.id), "%s", j->id);
        snprintf(r.dir, sizeof(r.dir), "%s", j->dir);
        edhoc4_db_erase_old(&r);
        free(j);
    }
    return NULL;
}

int edhoc4_db_erase_old_async(const edhoc4_db_rec *rec)
{
    if (!rec || !rec->dir[0]) return E4_ERR_ARG;
    erase_job *j = calloc(1, sizeof(*j));
    if (!j) return edhoc4_db_erase_old(rec);
    snprintf(j->root, sizeof(j->root), "%s", rec->root);
    snprintf(j->id, sizeof(j->id), "%s", rec->id);
    snprintf(j->dir, sizeof(j->dir), "%s", rec->dir);
    pthread_mutex_lock(&er_mu);
    if (!er_thread_on) {
        pthread_t t;
        if (pthread_create(&t, NULL, erase_main, NULL) != 0) {
            pthread_mutex_unlock(&er_mu);
            free(j);
            return edhoc4_db_erase_old(rec);
        }
        pthread_detach(t);
        er_thread_on = 1;
    }
    *er_tail = j;
    er_tail = &j->next;
    pthread_cond_signal(&er_cv);
    pthread_mutex_unlock(&er_mu);
    return E4_OK;
}

void edhoc4_db_rec_wipe(edhoc4_db_rec *rec)
{
    if (rec) sodium_memzero(rec, sizeof(*rec));
}

/* ---- UE ---- */

int edhoc4_ue_load(const char *path, edhoc4_ue_state *st)
{
    edhoc4_rec_info info;
    if (!path || !st) return E4_ERR_ARG;
    memset(st, 0, sizeof(*st));
    int rc = edhoc4_rec_load(path, -1, &st->self, st->peer_pk, &info);
    if (rc != E4_OK) return rc;
    st->slot = info.active;
    st->has_next = st->using_next = info.valid[1 - info.active];
    return E4_OK;
}

int edhoc4_ue_fallback(const char *path, edhoc4_ue_state *st)
{
    if (!path || !st || !st->using_next) return E4_ERR_STATE;
    int cur = 1 - st->slot;
    edhoc4_ue_state_wipe(st);
    int rc = edhoc4_rec_load(path, cur, &st->self, st->peer_pk, NULL);
    st->slot = cur;
    st->has_next = 1;          /* NEXT is kept */
    return rc;
}

int edhoc4_ue_store_next(const char *path, const edhoc4_ue_state *st, const edhoc4_ctx *ctx)
{
    edhoc4_creds next;
    uint8_t peer_pk[E4_XWING_PK];
    if (!path || !st || !ctx) return E4_ERR_ARG;
    edhoc4_next_state(ctx, &next, peer_pk);
    int rc = edhoc4_rec_write(path, 1 - st->slot, &next, peer_pk);
    sodium_memzero(&next, sizeof(next));
    return rc;
}

int edhoc4_ue_promote(const char *path, const edhoc4_ue_state *st)
{
    if (!path || !st) return E4_ERR_ARG;
    return edhoc4_rec_zero(path, st->slot, 1);
}

void edhoc4_ue_state_wipe(edhoc4_ue_state *st)
{
    if (st) sodium_memzero(st, sizeof(*st));
}
