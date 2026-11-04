/*
 * edhoc4_db.c — key records for EAP-EDHOC method 4 (protocol v4).
 * See edhoc4_db.h for the layout, the commit order and the UE slot rules.
 */
#define _DEFAULT_SOURCE
#include "edhoc4_db.h"

#include <dirent.h>
#include <errno.h>
#include <signal.h>
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
#ifdef E4_TEST_HOOKS
    extern unsigned long edhoc4_test_rec_locks;
    edhoc4_test_rec_locks++;
#endif
    char p[1400];
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

#ifdef E4_TEST_HOOKS
/* dbtest only (built with -DE4_TEST_HOOKS, never in libedhoc4.a) */
unsigned long edhoc4_test_scan_calls;   /* index rebuilds */
unsigned long edhoc4_test_rec_locks;    /* record files touched */
int edhoc4_test_crash_point;            /* in commit: 1 before the slot write, 4 torn write,
                                           2 written not flushed, 3 after fdatasync */
int edhoc4_test_in_commit;              /* edhoc4_rec_write also serves the UE */
#define E4_TEST_CRASH(n) do { if (edhoc4_test_crash_point == (n)) raise(SIGKILL); } while (0)
#else
#define E4_TEST_CRASH(n) do { } while (0)
#endif

/* ---- in-memory KeyID index: KeyID_B -> (record id, slot) ---- */

typedef struct idx_entry {
    uint8_t kid[E4_KEYID_LEN];
    int     slot;
    char    id[256];
    struct idx_entry *next;
} idx_entry;

struct edhoc4_db_index {
    char   root[1024];
    pthread_mutex_t mu;
    idx_entry **bucket;
    size_t n_bucket, n_entry;
};

/* KeyIDs are SHA-256 outputs and only the DN-AAA inserts them; any bytes do */
static size_t idx_slot(const edhoc4_db_index *x, const uint8_t kid[E4_KEYID_LEN])
{
    uint64_t h;
    memcpy(&h, kid, sizeof(h));
    return (size_t)h & (x->n_bucket - 1);
}

static void idx_grow(edhoc4_db_index *x)
{
    size_t n = x->n_bucket * 2;
    idx_entry **b = calloc(n, sizeof(*b));
    if (!b) return;                     /* longer chains, still correct */
    idx_entry **old = x->bucket;
    size_t old_n = x->n_bucket;
    x->bucket = b;
    x->n_bucket = n;
    for (size_t i = 0; i < old_n; i++)
        for (idx_entry *e = old[i], *nx; e; e = nx) {
            nx = e->next;
            size_t k = idx_slot(x, e->kid);
            e->next = b[k];
            b[k] = e;
        }
    free(old);
}

/* record ids name a directory under root: no path separators, no dot files */
static int valid_id(const char *id)
{
    if (!id || !*id || id[0] == '.' || strlen(id) > 200) return 0;
    for (const char *p = id; *p; p++)
        if (*p == '/' || *p == '\\' || *p == '\n') return 0;
    return 1;
}

int edhoc4_db_index_put(edhoc4_db_index *x, const uint8_t kid[E4_KEYID_LEN], const char *id, int slot)
{
    if (!x || !kid || !valid_id(id)) return E4_ERR_ARG;
    idx_entry *n = calloc(1, sizeof(*n));
    if (!n) return E4_ERR_ARG;
    memcpy(n->kid, kid, E4_KEYID_LEN);
    n->slot = slot;
    snprintf(n->id, sizeof(n->id), "%s", id);
    pthread_mutex_lock(&x->mu);
    size_t k = idx_slot(x, kid);
    for (idx_entry *e = x->bucket[k]; e; e = e->next)
        if (sodium_memcmp(e->kid, kid, E4_KEYID_LEN) == 0) {
            e->slot = slot;
            snprintf(e->id, sizeof(e->id), "%s", id);
            pthread_mutex_unlock(&x->mu);
            free(n);
            return E4_OK;
        }
    n->next = x->bucket[k];
    x->bucket[k] = n;
    if (++x->n_entry > 2 * x->n_bucket) idx_grow(x);
    pthread_mutex_unlock(&x->mu);
    return E4_OK;
}

int edhoc4_db_index_get(edhoc4_db_index *x, const uint8_t kid[E4_KEYID_LEN], char *id, size_t cap, int *slot)
{
    int rc = E4_ERR_PEER;
    if (!x || !kid) return E4_ERR_ARG;
    pthread_mutex_lock(&x->mu);
    for (idx_entry *e = x->bucket[idx_slot(x, kid)]; e; e = e->next)
        if (sodium_memcmp(e->kid, kid, E4_KEYID_LEN) == 0) {
            if (id && cap) snprintf(id, cap, "%s", e->id);
            if (slot) *slot = e->slot;
            rc = E4_OK;
            break;
        }
    pthread_mutex_unlock(&x->mu);
    return rc;
}

int edhoc4_db_index_del(edhoc4_db_index *x, const uint8_t kid[E4_KEYID_LEN], const char *id)
{
    if (!x || !kid) return E4_ERR_ARG;
    pthread_mutex_lock(&x->mu);
    for (idx_entry **pp = &x->bucket[idx_slot(x, kid)]; *pp; pp = &(*pp)->next) {
        idx_entry *e = *pp;
        if (sodium_memcmp(e->kid, kid, E4_KEYID_LEN) != 0) continue;
        if (!id || strcmp(e->id, id) == 0) {
            *pp = e->next;
            x->n_entry--;
            free(e);
        }
        break;
    }
    pthread_mutex_unlock(&x->mu);
    return E4_OK;
}

size_t edhoc4_db_index_count(edhoc4_db_index *x, const char *id)
{
    size_t n = 0;
    if (!x) return 0;
    pthread_mutex_lock(&x->mu);
    for (size_t i = 0; i < x->n_bucket; i++)
        for (idx_entry *e = x->bucket[i]; e; e = e->next)
            if (!id || strcmp(e->id, id) == 0) n++;
    pthread_mutex_unlock(&x->mu);
    return n;
}

void edhoc4_db_index_free(edhoc4_db_index *x)
{
    if (!x) return;
    for (size_t i = 0; i < x->n_bucket; i++)
        for (idx_entry *e = x->bucket[i], *nx; e; e = nx) {
            nx = e->next;
            free(e);
        }
    free(x->bucket);
    pthread_mutex_destroy(&x->mu);
    free(x);
}

edhoc4_db_index *edhoc4_db_index_open(const char *root, size_t *n_records, size_t *n_keys)
{
    DIR *d = root ? opendir(root) : NULL;
    if (!d) return NULL;
    edhoc4_db_index *x = calloc(1, sizeof(*x));
    if (x) x->bucket = calloc(1024, sizeof(*x->bucket));
    if (!x || !x->bucket) { free(x); closedir(d); return NULL; }
    x->n_bucket = 1024;
    pthread_mutex_init(&x->mu, NULL);
    snprintf(x->root, sizeof(x->root), "%s", root);
#ifdef E4_TEST_HOOKS
    edhoc4_test_scan_calls++;
#endif
    size_t nr = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        char dir[1300], p[1400];
        edhoc4_rec_info info;
        if (!valid_id(de->d_name)) continue;
        snprintf(dir, sizeof(dir), "%s/%s", root, de->d_name);
        rec_path(dir, p, sizeof(p));
        if (edhoc4_rec_load(p, -1, NULL, NULL, &info) != E4_OK) continue;
        nr++;
        for (int slot = 0; slot < 2; slot++) {
            edhoc4_creds c;
            uint8_t kid[E4_KEYID_LEN];
            if (!info.valid[slot] || edhoc4_rec_load(p, slot, &c, NULL, NULL) != E4_OK) continue;
            edhoc4_keyid(c.kem_pk, kid);
            sodium_memzero(&c, sizeof(c));
            edhoc4_db_index_put(x, kid, de->d_name, slot);
        }
    }
    closedir(d);
    if (n_records) *n_records = nr;
    if (n_keys) *n_keys = x->n_entry;
    return x;
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

/* zero slot `slot` of a record and drop its KeyID from the table (record
 * lock held) */
static int erase_slot(edhoc4_db_index *idx, const char *id, const char *p, int slot)
{
    edhoc4_creds c;
    uint8_t kid[E4_KEYID_LEN];
    if (edhoc4_rec_load(p, slot, &c, NULL, NULL) != E4_OK) return E4_OK;
    edhoc4_keyid(c.kem_pk, kid);
    sodium_memzero(&c, sizeof(c));
    int rc = edhoc4_rec_zero(p, slot, 1);
    if (rc == E4_OK) edhoc4_db_index_del(idx, kid, id);
    return rc;
}

int edhoc4_db_handle_msg1(edhoc4_db_index *idx, edhoc4_ctx *ctx, edhoc4_db_rec *rec,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    char p[1400];
    uint8_t kid[E4_KEYID_LEN], disk_kid[E4_KEYID_LEN];
    struct stat st;
    edhoc4_rec_info info;
    int slot = -1;
    if (!idx || !ctx || !rec) return E4_ERR_ARG;
    memset(rec, 0, sizeof(*rec));

    /* clear KeyID_B -> (record, slot); unknown: rejected from memory, without
     * touching the disk and before any KEM operation */
    if (edhoc4_r_peek_keyid(in, in_len, kid) != E4_OK) return E4_ERR_PARSE;
    if (edhoc4_db_index_get(idx, kid, rec->id, sizeof(rec->id), &slot) != E4_OK) return E4_ERR_PEER;
    rec->idx = idx;
    snprintf(rec->dir, sizeof(rec->dir), "%s/%s", idx->root, rec->id);
    if (stat(rec->dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        edhoc4_db_index_del(idx, kid, rec->id);           /* stale entry */
        edhoc4_db_rec_wipe(rec);
        return E4_ERR_PEER;
    }

    rec_path(rec->dir, p, sizeof(p));
    int fd = lock_rec(rec->dir);
    if (fd < 0) { edhoc4_db_rec_wipe(rec); return E4_ERR_ARG; }
    int rc = E4_ERR_PEER;
    /* the index is only a hint: the slot must hold the pk_B of this KeyID */
    if (edhoc4_rec_load(p, slot, &rec->server, rec->ue_pub, &info) == E4_OK)
        edhoc4_keyid(rec->server.kem_pk, disk_kid);
    else
        sodium_memzero(disk_kid, sizeof(disk_kid));
    if (sodium_memcmp(disk_kid, kid, E4_KEYID_LEN) != 0) {
        edhoc4_db_index_del(idx, kid, rec->id);
        rc = E4_ERR_KEYID;
    } else if (slot == info.active &&
               read_file(rec->dir, "ue.vk", rec->ue_vk, E4_MLDSA_PK) == 0 &&
               read_file(rec->dir, "id_cred", rec->id_cred, E4_ID_CRED) == 0) {
        /* an old sk_B whose erasure did not happen (crash): erase it now */
        if (info.valid[1 - slot]) erase_slot(idx, rec->id, p, 1 - slot);
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

    /* write-ahead: (Nsk_B, Npk_B, pk_A := Npk_A) is durable with one
     * fdatasync before message_4; the table entry needs no flush, a restart
     * rebuilds it from this slot. The old slot and its entry go later. */
    edhoc4_next_state(ctx, &next, next_pk);
    edhoc4_keyid(next.kem_pk, next_kid);
    E4_TEST_CRASH(1);
#ifdef E4_TEST_HOOKS
    edhoc4_test_in_commit = 1;
#endif
    rc = edhoc4_rec_write(p, 1 - rec->slot, &next, next_pk);
    E4_TEST_CRASH(3);
#ifdef E4_TEST_HOOKS
    edhoc4_test_in_commit = 0;
#endif
    sodium_memzero(&next, sizeof(next));
    edhoc4_ctx_wipe(ctx);
    if (rc == E4_OK) rc = edhoc4_db_index_put(rec->idx, next_kid, rec->id, 1 - rec->slot);
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
        rc = erase_slot(rec->idx, rec->id, p, 1 - info.active);
    unlock_rec(fd);
    return rc;
}

/* erase worker: one thread, started on first use, so that the fdatasync of
 * the erasure never sits on the path of a reply */
typedef struct erase_job {
    edhoc4_db_index *idx;
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
        r.idx = j->idx;
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
    j->idx = rec->idx;
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
