/*
 * edhoc4_db.c — key records for EAP-EDHOC method 4 (final v3 protocol).
 * See edhoc4_db.h for the layout, the commit order and the UE slot rules.
 */
#define _DEFAULT_SOURCE
#include "edhoc4_db.h"

#include <dirent.h>
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
    char p[1200];
    struct stat st;
    edhoc4_rec_info info;
    if (!root || !ctx || !rec) return E4_ERR_ARG;
    memset(rec, 0, sizeof(*rec));

    /* unknown identity: reject before any KEM operation */
    if (!valid_identity(identity)) return E4_ERR_PEER;
    snprintf(rec->dir, sizeof(rec->dir), "%s/%s", root, identity);
    if (stat(rec->dir, &st) != 0 || !S_ISDIR(st.st_mode)) return E4_ERR_PEER;

    rec_path(rec->dir, p, sizeof(p));
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    int rc = E4_ERR_PEER;
    if (edhoc4_rec_load(p, -1, &rec->server, rec->ue_pub, &info) == E4_OK &&
        read_file(rec->dir, "ue.vk", rec->ue_vk, E4_MLDSA_PK) == 0 &&
        read_file(rec->dir, "id_cred", rec->id_cred, E4_ID_CRED) == 0) {
        /* an old sk_B whose erasure did not happen (crash): erase it now */
        if (info.valid[1 - info.active]) edhoc4_rec_zero(p, 1 - info.active, 1);
        edhoc4_init_responder(ctx, &rec->server, rec->ue_pub);
        edhoc4_set_lookup(ctx, edhoc4_db_lookup, rec);
        rc = edhoc4_r_handle_msg1(ctx, in, in_len, out, out_cap, out_len);
        if (rc != E4_OK) edhoc4_ctx_wipe(ctx);
    }
    unlock_rec(fd);
    if (rc != E4_OK) edhoc4_db_rec_wipe(rec);
    return rc;
}

int edhoc4_db_commit(edhoc4_ctx *ctx, edhoc4_db_rec *rec)
{
    char p[1200];
    edhoc4_creds disk, next;
    edhoc4_rec_info info;
    uint8_t next_pk[E4_XWING_PK];
    int rc;

    if (!ctx || !rec || !ctx->done) return E4_ERR_STATE;
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    rec_path(rec->dir, p, sizeof(p));

    /* refuse if another session rotated this record meanwhile */
    if (edhoc4_rec_load(p, -1, &disk, NULL, &info) != E4_OK ||
        sodium_memcmp(disk.kem_pk, rec->server.kem_pk, E4_XWING_PK) != 0) {
        sodium_memzero(&disk, sizeof(disk));
        unlock_rec(fd);
        return E4_ERR_STATE;
    }
    sodium_memzero(&disk, sizeof(disk));

    /* write-ahead: (Nsk_B, Npk_B, pk_A := Npk_A) is durable (one fdatasync)
     * before message_4 is sent; the old slot is erased later */
    edhoc4_next_state(ctx, &next, next_pk);
    rc = edhoc4_rec_write(p, 1 - info.active, &next, next_pk);
    sodium_memzero(&next, sizeof(next));
    edhoc4_ctx_wipe(ctx);
    unlock_rec(fd);
    return rc;
}

int edhoc4_db_erase_old(const edhoc4_db_rec *rec)
{
    char p[1200];
    edhoc4_creds c;
    edhoc4_rec_info info;
    if (!rec || !rec->dir[0]) return E4_ERR_ARG;
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    rec_path(rec->dir, p, sizeof(p));
    int rc = edhoc4_rec_load(p, -1, &c, NULL, &info);
    sodium_memzero(&c, sizeof(c));
    if (rc == E4_OK && info.valid[1 - info.active]) rc = edhoc4_rec_zero(p, 1 - info.active, 1);
    unlock_rec(fd);
    return rc;
}

/* erase worker: one thread, started on first use, so that the fdatasync of
 * the erasure never sits on the path of a reply */
typedef struct erase_job {
    char dir[1024];
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
