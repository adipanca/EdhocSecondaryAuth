/*
 * edhoc4_db.c — key records for EAP-EDHOC method 4 (protocol v3).
 * See edhoc4_db.h for the layout, the pseudonym index and the commit order.
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

/* ---- pseudonym index: P -> uid (chained hash table, mutex) ---- */

#define IDX_BUCKETS 1024

typedef struct idx_node {
    uint8_t p[E4_PSEUDO_LEN];
    char uid[256];
    struct idx_node *next;
} idx_node;

static pthread_mutex_t idx_mu = PTHREAD_MUTEX_INITIALIZER;
static idx_node *idx_tab[IDX_BUCKETS];
static char idx_root[1024];
static int idx_built;

static unsigned idx_hash(const uint8_t p[E4_PSEUDO_LEN])
{
    unsigned h;
    memcpy(&h, p, sizeof(h));          /* P is uniformly random */
    return h % IDX_BUCKETS;
}

static void idx_clear(void)
{
    for (int i = 0; i < IDX_BUCKETS; i++) {
        idx_node *n = idx_tab[i];
        while (n) { idx_node *x = n->next; free(n); n = x; }
        idx_tab[i] = NULL;
    }
}

static int idx_put(const uint8_t p[E4_PSEUDO_LEN], const char *uid)
{
    idx_node *n = calloc(1, sizeof(*n));
    if (!n) return -1;
    memcpy(n->p, p, E4_PSEUDO_LEN);
    snprintf(n->uid, sizeof(n->uid), "%s", uid);
    unsigned h = idx_hash(p);
    n->next = idx_tab[h];
    idx_tab[h] = n;
    return 0;
}

static void idx_del(const uint8_t p[E4_PSEUDO_LEN])
{
    idx_node **pp = &idx_tab[idx_hash(p)];
    while (*pp) {
        if (sodium_memcmp((*pp)->p, p, E4_PSEUDO_LEN) == 0) {
            idx_node *x = *pp; *pp = x->next; free(x);
            return;
        }
        pp = &(*pp)->next;
    }
}

static int idx_get(const uint8_t p[E4_PSEUDO_LEN], char *uid, size_t cap)
{
    for (idx_node *n = idx_tab[idx_hash(p)]; n; n = n->next)
        if (sodium_memcmp(n->p, p, E4_PSEUDO_LEN) == 0) {
            snprintf(uid, cap, "%s", n->uid);
            return 0;
        }
    return -1;
}

/* caller holds idx_mu */
static int idx_build(const char *root)
{
    DIR *d = opendir(root);
    if (!d) return -1;
    idx_clear();
    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        char dir[1024], p[1200];
        struct stat st;
        edhoc4_creds c;
        edhoc4_rec_info info;
        uint8_t ps[E4_PSEUDO_LEN];
        if (de->d_name[0] == '.') continue;
        snprintf(dir, sizeof(dir), "%s/%s", root, de->d_name);
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        rec_path(dir, p, sizeof(p));
        int fd = lock_rec(dir);
        if (fd < 0) continue;
        if (edhoc4_rec_load(p, 0, &c, NULL, ps, &info) == E4_OK) {
            /* crash between commit and erasure: the old sk_B goes now */
            if (info.valid[1 - info.active]) edhoc4_rec_drop(p, 1, 1);
            if (idx_put(ps, de->d_name) == 0) count++;
        }
        sodium_memzero(&c, sizeof(c));
        unlock_rec(fd);
    }
    closedir(d);
    snprintf(idx_root, sizeof(idx_root), "%s", root);
    idx_built = 1;
    return count;
}

int edhoc4_db_reindex(const char *root)
{
    if (!root) return -1;
    pthread_mutex_lock(&idx_mu);
    int n = idx_build(root);
    pthread_mutex_unlock(&idx_mu);
    return n;
}

static int idx_lookup(const char *root, const uint8_t p[E4_PSEUDO_LEN], char *uid, size_t cap)
{
    pthread_mutex_lock(&idx_mu);
    int rc = 0;
    if (!idx_built || strcmp(idx_root, root) != 0) rc = idx_build(root) < 0 ? -1 : 0;
    if (rc == 0) rc = idx_get(p, uid, cap);
    pthread_mutex_unlock(&idx_mu);
    return rc;
}

static void idx_move(const uint8_t from[E4_PSEUDO_LEN], const uint8_t to[E4_PSEUDO_LEN],
                     const char *uid)
{
    pthread_mutex_lock(&idx_mu);
    idx_del(from);
    idx_put(to, uid);
    pthread_mutex_unlock(&idx_mu);
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

int edhoc4_db_handle_msg1(const char *root, const char *identity,
                          edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t ps[E4_PSEUDO_LEN];
    char p[1200];
    if (!root || !ctx || !rec) return E4_ERR_ARG;
    memset(rec, 0, sizeof(*rec));

    /* unknown or malformed pseudonym: reject before any KEM operation */
    if (edhoc4_nai_to_pseudo(identity, ps) != E4_OK ||
        idx_lookup(root, ps, rec->uid, sizeof(rec->uid)) != 0)
        return E4_ERR_PSEUDO;

    snprintf(rec->dir, sizeof(rec->dir), "%s/%s", root, rec->uid);
    rec_path(rec->dir, p, sizeof(p));
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    int rc = E4_ERR_PSEUDO;
    edhoc4_rec_info info;
    if (edhoc4_rec_load(p, 0, &rec->server, rec->ue_pub, rec->pseudo, &info) == E4_OK &&
        sodium_memcmp(rec->pseudo, ps, E4_PSEUDO_LEN) == 0 &&
        read_file(rec->dir, "ue.vk", rec->ue_vk, E4_MLDSA_PK) == 0 &&
        read_file(rec->dir, "id_cred", rec->id_cred, E4_ID_CRED) == 0) {
        /* an old sk_B whose erasure did not happen (crash): erase it now */
        if (info.valid[1 - info.active]) edhoc4_rec_drop(p, 1, 1);
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
    uint8_t next_pk[E4_XWING_PK], pnext[E4_PSEUDO_LEN];
    int rc;

    if (!ctx || !rec || !ctx->done) return E4_ERR_STATE;
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    rec_path(rec->dir, p, sizeof(p));

    /* refuse if another session rotated this record meanwhile */
    if (edhoc4_rec_load(p, 0, &disk, NULL, NULL, NULL) != E4_OK ||
        sodium_memcmp(disk.kem_pk, rec->server.kem_pk, E4_XWING_PK) != 0) {
        sodium_memzero(&disk, sizeof(disk));
        unlock_rec(fd);
        return E4_ERR_STATE;
    }
    sodium_memzero(&disk, sizeof(disk));

    /* write-ahead: (P_next, Nsk_B, Npk_B, pk_A := Npk_A) is durable (one
     * fdatasync) before message_4 is sent; the old slot is erased later */
    edhoc4_next_state(ctx, &next, next_pk);
    memcpy(pnext, ctx->pnext, E4_PSEUDO_LEN);
    rc = edhoc4_rec_write_next(p, &next, next_pk, pnext);
    sodium_memzero(&next, sizeof(next));
    edhoc4_ctx_wipe(ctx);
    unlock_rec(fd);
    if (rc == E4_OK) idx_move(rec->pseudo, pnext, rec->uid);
    return rc;
}

int edhoc4_db_erase_old(const edhoc4_db_rec *rec)
{
    char p[1200];
    if (!rec || !rec->dir[0]) return E4_ERR_ARG;
    int fd = lock_rec(rec->dir);
    if (fd < 0) return E4_ERR_ARG;
    rec_path(rec->dir, p, sizeof(p));
    int rc = edhoc4_rec_drop(p, 1, 1);
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

static int ue_read(const char *path, int older, edhoc4_ue_state *st)
{
    return edhoc4_rec_load(path, older, &st->self, st->peer_pk, st->pseudo, NULL);
}

int edhoc4_ue_load(const char *path, edhoc4_ue_state *st)
{
    edhoc4_rec_info info;
    if (!path || !st) return E4_ERR_ARG;
    memset(st, 0, sizeof(*st));
    int rc = edhoc4_rec_load(path, 0, &st->self, st->peer_pk, st->pseudo, &info);
    if (rc == E4_OK) st->using_next = info.valid[1 - info.active];
    return rc;
}

int edhoc4_ue_fallback(const char *path, edhoc4_ue_state *st)
{
    if (!path || !st || !st->using_next) return E4_ERR_STATE;
    int rc = edhoc4_rec_drop(path, 0, 1);
    edhoc4_ue_state_wipe(st);
    if (rc == E4_OK) rc = ue_read(path, 0, st);
    return rc;
}

int edhoc4_ue_store_next(const char *path, const edhoc4_ctx *ctx)
{
    edhoc4_creds next;
    uint8_t peer_pk[E4_XWING_PK];
    if (!path || !ctx) return E4_ERR_ARG;
    edhoc4_next_state(ctx, &next, peer_pk);
    int rc = edhoc4_rec_write_next(path, &next, peer_pk, ctx->pnext);
    sodium_memzero(&next, sizeof(next));
    return rc;
}

int edhoc4_ue_promote(const char *path)
{
    return edhoc4_rec_drop(path, 1, 1);
}

void edhoc4_ue_state_wipe(edhoc4_ue_state *st)
{
    if (st) sodium_memzero(st, sizeof(*st));
}
