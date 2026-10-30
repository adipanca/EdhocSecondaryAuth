/*
 * Secondary Authentication relay client (SMF -> UPF sidecar).
 *
 * One persistent UDP socket to the UPF relay, registered in the SMF pollset,
 * so a slow or lost DN-AAA reply never blocks the SMF event loop. Every
 * request carries a token (session pool id, per-session sequence number)
 * that the relay echoes; a reply whose token is not the outstanding request
 * of a live session (late reply after a timeout, removed session) is
 * dropped.
 *
 * Relay protocol v2 (big endian):
 *   request : magic 0xE5E5DEAD, version 2, reserved, user_len(1),
 *             state_len(2), eap_len(2), sess_id(4), seq(4),
 *             user, state, eap
 *   reply   : magic 0xE5E5BEEF, version 2, result(1), state_len(2),
 *             eap_len(2), sess_id(4), seq(4), state, eap
 */

#include "radius-client.h"

#include "context.h"
#include "event.h"
#include "timer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define EAP_RELAY_MAGIC_REQ 0xE5E5DEADU
#define EAP_RELAY_MAGIC_RESP 0xE5E5BEEFU
#define EAP_RELAY_VERSION 2U
#define EAP_RELAY_HDR_LEN 18   /* reply: magic(4) ver(1) result(1) lens(4) token(8) */

#define EAP_RELAY_DEFAULT_ADDR "127.0.0.1"
#define EAP_RELAY_DEFAULT_PORT 3870

#define EAP_RELAY_MAX_USER_LEN 255
#define EAP_RELAY_MAX_STATE_LEN 2048
/* EAP-EDHOC method 4 messages are large (message_2 is 6097 B), so the relay
 * carries multi-kilobyte EAP payloads. */
#define EAP_RELAY_MAX_EAP_LEN 8192
#define EAP_RELAY_MAX_PKT 16384

static int g_fd = -1;
static ogs_poll_t *g_poll = NULL;

/* E4_TIMING=1: "[E4T] smf_relay_tx|smf_relay_rx t_us=... sess=<psi> len=..." */
static void e4t(const char *tag, int psi, size_t len)
{
    static int on = -1;
    struct timespec ts;

    if (on < 0) {
        const char *v = getenv("E4_TIMING");
        on = (v && atoi(v) > 0);
    }
    if (!on)
        return;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(stderr, "[E4T] %s t_us=%llu sess=%d len=%zu\n", tag,
            (unsigned long long)ts.tv_sec * 1000000ULL +
            (unsigned long long)(ts.tv_nsec / 1000), psi, len);
}

static uint16_t get_port_from_env(const char *name, uint16_t default_port)
{
    const char *v = getenv(name);
    long p = 0;
    char *end = NULL;

    if (!v || !v[0])
        return default_port;

    p = strtol(v, &end, 10);
    if (!end || *end != '\0' || p < 1 || p > 65535)
        return default_port;

    return (uint16_t)p;
}

static void relay_recv_cb(short when, ogs_socket_t fd, void *data)
{
    uint8_t buf[EAP_RELAY_MAX_PKT];
    ssize_t n;

    (void)when;
    (void)data;

    /* drain everything that is queued */
    while ((n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
        uint32_t v32, sess_id, seq;
        smf_sess_t *sess = NULL;
        smf_event_t *e = NULL;
        ogs_pkbuf_t *pkbuf = NULL;
        int rv;

        if (n < EAP_RELAY_HDR_LEN) {
            ogs_error("EAP relay: short reply (%zd)", n);
            continue;
        }
        memcpy(&v32, buf, 4);
        if (ntohl(v32) != EAP_RELAY_MAGIC_RESP || buf[4] != EAP_RELAY_VERSION) {
            ogs_error("EAP relay: invalid reply header");
            continue;
        }
        memcpy(&v32, buf + 10, 4); sess_id = ntohl(v32);
        memcpy(&v32, buf + 14, 4); seq = ntohl(v32);

        sess = smf_sess_find_by_id((ogs_pool_id_t)sess_id);
        if (!sess || !sess->sec_auth.in_progress ||
                seq != sess->sec_auth.relay_seq) {
            ogs_warn("EAP relay: stale reply dropped (sess %u seq %u)",
                    sess_id, seq);
            continue;
        }
        e4t("smf_relay_rx", sess->psi, (size_t)n);
        ogs_timer_stop(sess->sec_auth.t_relay);
        sess->sec_auth.relay_seq++;      /* a duplicate is stale from now */

        pkbuf = ogs_pkbuf_alloc(NULL, (int)n);
        ogs_assert(pkbuf);
        ogs_pkbuf_put_data(pkbuf, buf, (int)n);

        e = smf_event_new(SMF_EVT_SEC_AUTH_RELAY);
        ogs_assert(e);
        e->sess_id = sess->id;
        e->pkbuf = pkbuf;
        rv = ogs_queue_push(ogs_app()->queue, e);
        if (rv != OGS_OK) {
            ogs_error("ogs_queue_push() failed [%d]", rv);
            ogs_pkbuf_free(pkbuf);
            ogs_event_free(e);
        }
    }
}

static int relay_open(void)
{
    const char *relay_addr = getenv("OPEN5GS_EAP_RELAY_ADDR");
    uint16_t relay_port = get_port_from_env("OPEN5GS_EAP_RELAY_PORT",
            EAP_RELAY_DEFAULT_PORT);
    struct sockaddr_in dst;

    if (g_fd >= 0)
        return OGS_OK;
    if (!relay_addr || !relay_addr[0])
        relay_addr = EAP_RELAY_DEFAULT_ADDR;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(relay_port);
    if (inet_pton(AF_INET, relay_addr, &dst.sin_addr) != 1) {
        ogs_error("EAP relay: invalid relay address [%s]", relay_addr);
        return OGS_ERROR;
    }

    g_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_fd < 0) {
        ogs_error("EAP relay: socket() failed (%d)", errno);
        return OGS_ERROR;
    }
    if (connect(g_fd, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        ogs_error("EAP relay: connect() failed (%d)", errno);
        close(g_fd);
        g_fd = -1;
        return OGS_ERROR;
    }
    g_poll = ogs_pollset_add(ogs_app()->pollset, OGS_POLLIN, g_fd,
            relay_recv_cb, NULL);
    ogs_assert(g_poll);
    ogs_info("EAP relay: persistent socket to %s:%u", relay_addr, relay_port);
    return OGS_OK;
}

void smf_eap_relay_close(void)
{
    if (g_poll) {
        ogs_pollset_remove(g_poll);
        g_poll = NULL;
    }
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
}

int smf_eap_relay_send(smf_sess_t *sess, const uint8_t *eap, size_t eap_len)
{
    uint8_t req[EAP_RELAY_MAX_PKT];
    size_t req_len = 0, uname_len, state_len;
    uint32_t v32;
    uint16_t v16;
    const char *username;

    ogs_assert(sess);
    username = sess->sec_auth.identity ? sess->sec_auth.identity : "";
    uname_len = strlen(username);
    state_len = sess->sec_auth.state_len;

    if (!eap || uname_len > EAP_RELAY_MAX_USER_LEN ||
            state_len > EAP_RELAY_MAX_STATE_LEN ||
            eap_len > EAP_RELAY_MAX_EAP_LEN) {
        ogs_error("EAP relay: invalid or too large payload");
        return OGS_ERROR;
    }
    if (relay_open() != OGS_OK)
        return OGS_ERROR;

    sess->sec_auth.relay_seq++;

    v32 = htonl(EAP_RELAY_MAGIC_REQ);
    memcpy(req + req_len, &v32, 4); req_len += 4;
    req[req_len++] = EAP_RELAY_VERSION;
    req[req_len++] = 0;
    req[req_len++] = (uint8_t)uname_len;
    v16 = htons((uint16_t)state_len);
    memcpy(req + req_len, &v16, 2); req_len += 2;
    v16 = htons((uint16_t)eap_len);
    memcpy(req + req_len, &v16, 2); req_len += 2;
    v32 = htonl((uint32_t)sess->id);
    memcpy(req + req_len, &v32, 4); req_len += 4;
    v32 = htonl(sess->sec_auth.relay_seq);
    memcpy(req + req_len, &v32, 4); req_len += 4;
    memcpy(req + req_len, username, uname_len); req_len += uname_len;
    if (state_len) {
        memcpy(req + req_len, sess->sec_auth.state, state_len);
        req_len += state_len;
    }
    memcpy(req + req_len, eap, eap_len); req_len += eap_len;

    e4t("smf_relay_tx", sess->psi, req_len);
    if (send(g_fd, req, req_len, 0) < 0) {
        ogs_error("EAP relay: send() failed (%d)", errno);
        return OGS_ERROR;
    }
    ogs_timer_start(sess->sec_auth.t_relay,
            ogs_time_from_msec(SMF_EAP_RELAY_TIMEOUT_MSEC));
    return OGS_OK;
}

int smf_eap_relay_parse(ogs_pkbuf_t *pkbuf, uint8_t *result,
        const uint8_t **state, size_t *state_len,
        const uint8_t **eap, size_t *eap_len)
{
    const uint8_t *p;
    uint16_t v16;

    ogs_assert(pkbuf);
    p = pkbuf->data;
    if (pkbuf->len < EAP_RELAY_HDR_LEN)
        return OGS_ERROR;
    *result = p[5];
    memcpy(&v16, p + 6, 2); *state_len = ntohs(v16);
    memcpy(&v16, p + 8, 2); *eap_len = ntohs(v16);
    if ((size_t)pkbuf->len < EAP_RELAY_HDR_LEN + *state_len + *eap_len)
        return OGS_ERROR;
    *state = p + EAP_RELAY_HDR_LEN;
    *eap = p + EAP_RELAY_HDR_LEN + *state_len;
    return OGS_OK;
}
