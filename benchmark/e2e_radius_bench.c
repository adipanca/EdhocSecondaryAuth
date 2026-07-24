/*
 * e2e_radius_bench.c — real end-to-end EAP-EDHOC benchmark harness.
 *
 * Drives a *real* EAP-over-RADIUS handshake against a live FreeRADIUS
 * rlm_eap_edhoc responder (127.0.0.1:1812), for every EDHOC method 0..4:
 *
 *   - Speaks RADIUS (RFC 2865 / 3579): Access-Request with User-Name,
 *     NAS attributes, fragmented EAP-Message and Message-Authenticator
 *     (HMAC-MD5, shared secret); parses Access-Challenge / Accept / Reject
 *     and echoes State.
 *   - Runs the EAP peer state machine (EAP-Response/Identity -> EDHOC-Start
 *     -> message_1/2/3[/4] -> EAP-Success).
 *   - Uses the SAME crypto cores as the responder: edhoc03 (methods 0..3,
 *     classical) and edhoc4 (method 4, SIGMA XWING PQC), and the SAME
 *     1000-byte EAP fragmentation profile.
 *
 * It measures, per handshake: wall-clock duration, RADIUS round-trips,
 * EAP round-trips, per-message byte sizes and EAP fragment counts, plus
 * optional network-loss emulation (drop + retransmit) for the lossy table.
 *
 * This is a benchmark / interoperability harness, not production code.
 */
#define _POSIX_C_SOURCE 200809L

#include "edhoc03.h"
#include "edhoc4.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* ------------------------------------------------------------------ */
/* RADIUS / EAP constants                                             */
/* ------------------------------------------------------------------ */
#define RAD_ACCESS_REQUEST    1
#define RAD_ACCESS_ACCEPT     2
#define RAD_ACCESS_REJECT     3
#define RAD_ACCESS_CHALLENGE 11

#define RAD_ATTR_USER_NAME          1
#define RAD_ATTR_NAS_IP_ADDRESS     4
#define RAD_ATTR_NAS_PORT           5
#define RAD_ATTR_STATE             24
#define RAD_ATTR_EAP_MESSAGE       79
#define RAD_ATTR_MESSAGE_AUTH      80

#define EAP_CODE_REQUEST   1
#define EAP_CODE_RESPONSE  2
#define EAP_CODE_SUCCESS   3
#define EAP_CODE_FAILURE   4

#define EAP_TYPE_IDENTITY  1
#define EAP_TYPE_EDHOC     56

#define RAD_MAX_PKT   4096
#define EAP_CHUNK      253

/* ------------------------------------------------------------------ */
/* configuration                                                      */
/* ------------------------------------------------------------------ */
static const char *g_secret   = "testing123";
static const char *g_server   = "127.0.0.1";
static int         g_port     = 1812;
static const char *g_creddir  = "/usr/local/etc/edhoc";
static const char *g_identity = "edhoc-ue";
static double      g_loss     = 0.0;    /* per-datagram drop probability */
static int         g_verbose  = 0;
static int         g_max_retx = 6;      /* EAP-style retransmit cap (per exchange) */
static double      g_rto_ms   = 40.0;   /* retransmit back-off, matches lossy_bench RTO */

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */
static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1.0e6;
}

static void rand_bytes(uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(rand() & 0xff);
}

/* ------------------------------------------------------------------ */
/* EDHOC engine (initiator) + EAP fragmentation, mirrors the module   */
/* ------------------------------------------------------------------ */
typedef struct {
    int method;        /* 0..4                             */
    int classical;     /* method <= 3                      */

    edhoc03_ctx c3;
    edhoc4_ctx  c4;

    int step;          /* 0 start, 1 sent msg1, 2 sent msg3, 3 done */
    int done;
    int failed;

    /* fragmentation state (same layout as responder session) */
    uint8_t in[E4_MAX_MSG];  size_t in_len, in_pos;
    uint8_t out[E4_MAX_MSG]; size_t out_len, out_pos;

    /* metrics: index 1..4 = message_1..4 */
    size_t msg_bytes[5];
    int    msg_frags[5];
    int    cur_out_msg;   /* which message we are fragmenting out */
    int    cur_in_msg;    /* which message we are reassembling    */

    uint8_t msk[64];
} eng_t;

/* Produce one outbound EAP fragment from eng->out into wire[], return len. */
static size_t eng_send_fragment(eng_t *e, uint8_t *wire)
{
    const size_t first_cap = E4_EDHOC_FRAG_WIRE_MAX - E4_EDHOC_FRAG_HDR_LEN - E4_EDHOC_FRAG_LEN_LEN;
    const size_t next_cap  = E4_EDHOC_FRAG_WIRE_MAX - E4_EDHOC_FRAG_HDR_LEN;
    size_t remaining = e->out_len - e->out_pos;
    size_t frag_cap  = (e->out_pos == 0) ? first_cap : next_cap;
    size_t frag_len  = remaining < frag_cap ? remaining : frag_cap;
    int    add_len   = (e->out_pos == 0 && remaining > frag_len);
    size_t pos = 0;

    wire[pos++] = (remaining > frag_len ? E4_EDHOC_FRAG_FLAG_MORE : 0) |
                  (add_len ? E4_EDHOC_FRAG_FLAG_LEN : 0);
    if (add_len) {
        uint16_t total = htons((uint16_t)e->out_len);
        memcpy(wire + pos, &total, 2);
        pos += 2;
    }
    memcpy(wire + pos, e->out + e->out_pos, frag_len);
    pos += frag_len;
    e->out_pos += frag_len;

    if (e->cur_out_msg >= 1 && e->cur_out_msg <= 4)
        e->msg_frags[e->cur_out_msg]++;

    if (e->out_pos >= e->out_len) { e->out_len = 0; e->out_pos = 0; }
    return pos;
}

/* Load a complete outbound message into eng->out and emit its first fragment. */
static size_t eng_queue_outgoing(eng_t *e, int which, uint8_t *wire)
{
    const size_t first_cap = E4_EDHOC_FRAG_WIRE_MAX - E4_EDHOC_FRAG_HDR_LEN - E4_EDHOC_FRAG_LEN_LEN;
    size_t len = e->out_len;   /* caller placed message in e->out with out_len set */

    e->cur_out_msg = which;
    e->msg_bytes[which] = len;

    if (len <= first_cap) {
        /* single fragment (flag 0x00) */
        wire[0] = 0x00;
        memcpy(wire + 1, e->out, len);
        e->msg_frags[which]++;
        e->out_len = 0; e->out_pos = 0;
        return len + 1;
    }
    e->out_pos = 0;
    return eng_send_fragment(e, wire);
}

/* Consume an inbound EAP fragment; on complete message returns msg/msg_len. */
static int eng_consume(eng_t *e, const uint8_t *in, size_t in_len,
                       const uint8_t **msg, size_t *msg_len, int *need_ack)
{
    uint8_t flags;
    size_t pos = 0;

    *need_ack = 0; *msg = NULL; *msg_len = 0;
    if (!in || in_len == 0) return -3;

    flags = in[pos++];
    if (flags & E4_EDHOC_FRAG_FLAG_LEN) {
        uint16_t total = 0;
        if (in_len < 3) return -3;
        memcpy(&total, in + pos, 2); total = ntohs(total); pos += 2;
        if (total == 0 || total > E4_MAX_MSG) return -2;
        if (!e->in_len) { e->in_len = total; e->in_pos = 0; }
        else if (e->in_len != total) return -3;
    }
    if (in_len < pos) return -3;

    if (e->in_len) {
        size_t payload = in_len - pos;
        if (e->in_pos + payload > e->in_len) return -2;
        memcpy(e->in + e->in_pos, in + pos, payload);
        e->in_pos += payload;
        if (e->cur_in_msg >= 1 && e->cur_in_msg <= 4) e->msg_frags[e->cur_in_msg]++;
        if (flags & E4_EDHOC_FRAG_FLAG_MORE) { *need_ack = 1; return 0; }
        if (e->in_pos != e->in_len) return -3;
        *msg = e->in; *msg_len = e->in_len;
        e->in_len = 0; e->in_pos = 0;
        return 0;
    }

    if (flags & E4_EDHOC_FRAG_FLAG_MORE) return -3;
    *msg = in + pos; *msg_len = in_len - pos;
    if (e->cur_in_msg >= 1 && e->cur_in_msg <= 4 && *msg_len > 0) e->msg_frags[e->cur_in_msg]++;
    return 0;
}

/*
 * React to one inbound EDHOC wire (the EAP-Request type-data).
 * Fills wire[] with the outbound EAP-Response type-data and returns its
 * length; sets *is_final_ack when we sent the closing empty ACK.
 * Returns -1 on protocol error.
 */
static long eng_react(eng_t *e, const uint8_t *in, size_t in_len, uint8_t *wire)
{
    const uint8_t *msg = NULL;
    size_t msg_len = 0;
    int need_ack = 0, rc;
    size_t olen = 0;

    /* Still fragmenting our previous outbound message: server ACKed -> send next. */
    if (e->out_pos < e->out_len) {
        return (long)eng_send_fragment(e, wire);
    }

    rc = eng_consume(e, in, in_len, &msg, &msg_len, &need_ack);
    if (rc != 0) return -1;
    if (need_ack) { wire[0] = 0x00; return 1; }   /* empty ACK */

    switch (e->step) {
    case 0: /* EDHOC-Start (empty msg) -> build message_1 */
        if (e->classical)
            rc = edhoc03_i_make_msg1(&e->c3, e->out, sizeof(e->out), &olen);
        else
            rc = edhoc4_i_make_msg1(&e->c4, e->out, sizeof(e->out), &olen);
        if (rc != 0) return -1;
        e->out_len = olen;
        e->step = 1;
        e->cur_in_msg = 2;   /* next inbound is message_2 */
        return (long)eng_queue_outgoing(e, 1, wire);

    case 1: /* message_2 -> build message_3 */
        e->msg_bytes[2] = msg_len;
        if (e->classical)
            rc = edhoc03_i_handle_msg2(&e->c3, msg, msg_len, e->out, sizeof(e->out), &olen);
        else
            rc = edhoc4_i_handle_msg2(&e->c4, msg, msg_len, e->out, sizeof(e->out), &olen);
        if (rc != 0) return -1;
        e->out_len = olen;
        e->step = 2;
        e->cur_in_msg = 4;   /* method 4: next inbound is message_4 */
        if (e->classical) {
            /* classical derives MSK now; no message_4 follows */
            memcpy(e->msk, e->c3.msk, 64);
        }
        return (long)eng_queue_outgoing(e, 3, wire);

    case 2: /* method 4: message_4 -> finish, then send closing empty ACK */
        e->msg_bytes[4] = msg_len;
        rc = edhoc4_i_handle_msg4(&e->c4, msg, msg_len);
        if (rc != 0) return -1;
        memcpy(e->msk, e->c4.msk, 64);
        e->step = 3;
        wire[0] = 0x00;      /* empty ACK; server replies EAP-Success */
        return 1;

    default:
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/* RADIUS packet assembly / parsing                                   */
/* ------------------------------------------------------------------ */
static void put_attr(uint8_t *buf, size_t *len, uint8_t type,
                     const uint8_t *val, size_t vlen)
{
    buf[(*len)++] = type;
    buf[(*len)++] = (uint8_t)(vlen + 2);
    memcpy(buf + *len, val, vlen);
    *len += vlen;
}

/* Build an Access-Request carrying an EAP packet (may be fragmented into
 * multiple EAP-Message attributes) plus Message-Authenticator + State. */
static size_t build_access_request(uint8_t id, const uint8_t auth[16],
                                   const uint8_t *eap, size_t eap_len,
                                   const uint8_t *state, size_t state_len,
                                   uint8_t *pkt)
{
    uint8_t attrs[RAD_MAX_PKT];
    size_t  alen = 0;
    uint8_t nas_ip[4] = { 127, 0, 0, 1 };
    uint8_t nas_port[4] = { 0, 0, 0, 1 };
    size_t  ma_off_in_attrs;
    uint8_t zero16[16] = {0};

    put_attr(attrs, &alen, RAD_ATTR_USER_NAME,
             (const uint8_t *)g_identity, strlen(g_identity));
    put_attr(attrs, &alen, RAD_ATTR_NAS_IP_ADDRESS, nas_ip, 4);
    put_attr(attrs, &alen, RAD_ATTR_NAS_PORT, nas_port, 4);
    if (state && state_len)
        put_attr(attrs, &alen, RAD_ATTR_STATE, state, state_len);

    /* EAP-Message fragmented into <=253-byte attributes */
    {
        size_t off = 0;
        do {
            size_t chunk = eap_len - off;
            if (chunk > EAP_CHUNK) chunk = EAP_CHUNK;
            put_attr(attrs, &alen, RAD_ATTR_EAP_MESSAGE, eap + off, chunk);
            off += chunk;
        } while (off < eap_len);
    }

    /* Message-Authenticator (16 zero bytes for now) */
    ma_off_in_attrs = alen;
    put_attr(attrs, &alen, RAD_ATTR_MESSAGE_AUTH, zero16, 16);

    /* assemble full packet */
    size_t plen = 20 + alen;
    pkt[0] = RAD_ACCESS_REQUEST;
    pkt[1] = id;
    pkt[2] = (uint8_t)(plen >> 8);
    pkt[3] = (uint8_t)(plen & 0xff);
    memcpy(pkt + 4, auth, 16);
    memcpy(pkt + 20, attrs, alen);

    /* Message-Authenticator = HMAC-MD5(entire packet with MA value zeroed) */
    {
        unsigned int mdlen = 16;
        uint8_t mac[16];
        HMAC(EVP_md5(), g_secret, (int)strlen(g_secret), pkt, plen, mac, &mdlen);
        memcpy(pkt + 20 + ma_off_in_attrs + 2, mac, 16);
    }
    return plen;
}

/* Extract EAP payload (concatenated EAP-Message attrs) + State from a reply. */
static int parse_reply(const uint8_t *pkt, size_t plen, uint8_t *code,
                       uint8_t *eap, size_t *eap_len,
                       uint8_t *state, size_t *state_len)
{
    if (plen < 20) return -1;
    *code = pkt[0];
    *eap_len = 0;
    *state_len = 0;
    size_t pos = 20;
    while (pos + 2 <= plen) {
        uint8_t t = pkt[pos];
        uint8_t l = pkt[pos + 1];
        if (l < 2 || pos + l > plen) break;
        const uint8_t *v = pkt + pos + 2;
        size_t vl = l - 2;
        if (t == RAD_ATTR_EAP_MESSAGE) {
            memcpy(eap + *eap_len, v, vl);
            *eap_len += vl;
        } else if (t == RAD_ATTR_STATE) {
            memcpy(state, v, vl);
            *state_len = vl;
        }
        pos += l;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* UDP send/recv with loss emulation + RADIUS retransmit              */
/* ------------------------------------------------------------------ */
static int g_retx;   /* retransmit counter for the current handshake */

static int rad_exchange(int sock, const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t *resp_len)
{
    const int max_try = g_max_retx + 1;
    for (int t = 0; t < max_try; t++) {
        int drop_out = (g_loss > 0.0) && ((rand() / (double)RAND_MAX) < g_loss);
        if (!drop_out) {
            if (send(sock, req, req_len, 0) < 0) return -1;
        } else {
            g_retx++;
        }

        if (!drop_out) {
            ssize_t n = recv(sock, resp, RAD_MAX_PKT, 0);
            if (n > 0) {
                int drop_in = (g_loss > 0.0) && ((rand() / (double)RAND_MAX) < g_loss);
                if (!drop_in) { *resp_len = (size_t)n; return 0; }
                g_retx++;
            } else {
                g_retx++;   /* timeout */
            }
        }
        /* EAP-style back-off before retransmitting the identical request */
        if (g_rto_ms > 0.0) {
            struct timespec bo = { (time_t)(g_rto_ms / 1000.0),
                                   (long)((g_rto_ms - ((long)(g_rto_ms / 1000.0)) * 1000.0) * 1e6) };
            nanosleep(&bo, NULL);
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* one full handshake                                                 */
/* ------------------------------------------------------------------ */
typedef struct {
    int    ok;
    double duration_ms;
    int    radius_rt;     /* Access-Requests sent           */
    int    eap_rt;        /* EAP-Responses sent             */
    int    access_req, access_chal, access_accept, access_reject;
    int    retx;
    size_t msg_bytes[5];
    int    msg_frags[5];
} result_t;

static int load_creds(eng_t *e)
{
    char p[512];
    if (e->classical) {
        edhoc03_creds self; edhoc03_peer peer;
        snprintf(p, sizeof(p), "%s/ue03.creds", g_creddir);
        if (edhoc03_creds_load(p, &self) != E3_OK) { fprintf(stderr, "load %s failed\n", p); return -1; }
        snprintf(p, sizeof(p), "%s/server03.pub", g_creddir);
        if (edhoc03_pub_load(p, &peer) != E3_OK) { fprintf(stderr, "load %s failed\n", p); return -1; }
        edhoc03_init_initiator(&e->c3, e->method, &self, &peer);
    } else {
        edhoc4_creds self; uint8_t peer_pk[E4_XWING_PK];
        snprintf(p, sizeof(p), "%s/ue.creds", g_creddir);
        if (edhoc4_creds_load(p, &self) != E4_OK) { fprintf(stderr, "load %s failed\n", p); return -1; }
        snprintf(p, sizeof(p), "%s/server.pub", g_creddir);
        if (edhoc4_pub_load(p, peer_pk) != E4_OK) { fprintf(stderr, "load %s failed\n", p); return -1; }
        edhoc4_init_initiator(&e->c4, &self, peer_pk);
    }
    return 0;
}

static int run_handshake(int method, result_t *r)
{
    eng_t e;
    memset(&e, 0, sizeof(e));
    e.method = method;
    e.classical = (method <= 3);
    memset(r, 0, sizeof(*r));

    if (load_creds(&e) != 0) return -1;

    /* UDP socket connected to the RADIUS server, 2s recv timeout */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)g_port);
    inet_pton(AF_INET, g_server, &sa.sin_addr);
    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(sock); return -1; }
    struct timeval tv = { 2, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t rad_id = (uint8_t)(rand() & 0xff);
    uint8_t auth[16];
    uint8_t state[256]; size_t state_len = 0;
    uint8_t eap[RAD_MAX_PKT];   size_t eap_len;
    uint8_t req[RAD_MAX_PKT];   size_t req_len;
    uint8_t resp[RAD_MAX_PKT];  size_t resp_len;
    uint8_t reap[RAD_MAX_PKT];  size_t reap_len;
    uint8_t rstate[256];        size_t rstate_len;
    uint8_t code;

    g_retx = 0;
    double t0 = now_ms();

    /* ---- 1. EAP-Response/Identity ---- */
    eap_len = 0;
    eap[eap_len++] = EAP_CODE_RESPONSE;
    eap[eap_len++] = 1;                       /* EAP id */
    eap[eap_len++] = 0; eap[eap_len++] = 0;   /* length placeholder */
    eap[eap_len++] = EAP_TYPE_IDENTITY;
    memcpy(eap + eap_len, g_identity, strlen(g_identity));
    eap_len += strlen(g_identity);
    eap[2] = (uint8_t)(eap_len >> 8); eap[3] = (uint8_t)(eap_len & 0xff);

    rand_bytes(auth, 16);
    req_len = build_access_request(rad_id, auth, eap, eap_len, NULL, 0, req);
    r->access_req++; r->radius_rt++; r->eap_rt++;
    if (rad_exchange(sock, req, req_len, resp, &resp_len) != 0) { close(sock); return -1; }

    for (;;) {
        if (parse_reply(resp, resp_len, &code, reap, &reap_len, rstate, &rstate_len) != 0) {
            close(sock); return -1;
        }
        if (code == RAD_ACCESS_ACCEPT) { r->access_accept++; e.done = 1; break; }
        if (code == RAD_ACCESS_REJECT) { r->access_reject++; e.failed = 1; break; }
        if (code != RAD_ACCESS_CHALLENGE) { close(sock); return -1; }
        r->access_chal++;

        if (rstate_len) { memcpy(state, rstate, rstate_len); state_len = rstate_len; }

        /* reap holds an EAP-Request; expect EDHOC type */
        if (reap_len < 5 || reap[0] != EAP_CODE_REQUEST) { close(sock); return -1; }
        uint8_t eap_id = reap[1];
        if (reap[4] != EAP_TYPE_EDHOC) { close(sock); return -1; }
        const uint8_t *in = reap + 5;
        size_t in_len = reap_len - 5;

        /* drive EDHOC + fragmentation */
        uint8_t wire[E4_EDHOC_FRAG_WIRE_MAX];
        long wlen = eng_react(&e, in, in_len, wire);
        if (wlen < 0) { close(sock); e.failed = 1; break; }

        /* wrap into EAP-Response(EDHOC) */
        eap_len = 0;
        eap[eap_len++] = EAP_CODE_RESPONSE;
        eap[eap_len++] = eap_id;
        eap[eap_len++] = 0; eap[eap_len++] = 0;
        eap[eap_len++] = EAP_TYPE_EDHOC;
        memcpy(eap + eap_len, wire, (size_t)wlen);
        eap_len += (size_t)wlen;
        eap[2] = (uint8_t)(eap_len >> 8); eap[3] = (uint8_t)(eap_len & 0xff);

        rad_id++;
        rand_bytes(auth, 16);
        req_len = build_access_request(rad_id, auth, eap, eap_len, state, state_len, req);
        r->access_req++; r->radius_rt++; r->eap_rt++;
        if (rad_exchange(sock, req, req_len, resp, &resp_len) != 0) { close(sock); return -1; }
    }

    r->duration_ms = now_ms() - t0;
    r->retx = g_retx;
    close(sock);

    r->ok = (e.done && !e.failed);
    for (int i = 0; i < 5; i++) { r->msg_bytes[i] = e.msg_bytes[i]; r->msg_frags[i] = e.msg_frags[i]; }
    return r->ok ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */
static const char *method_name(int m)
{
    switch (m) {
    case 0: return "SIG/SIG";
    case 1: return "SIG/STAT";
    case 2: return "STAT/SIG";
    case 3: return "STAT/STAT";
    case 4: return "SIGMA-XWING-PQC";
    default: return "?";
    }
}

int main(int argc, char **argv)
{
    int method = -1, iters = 1;
    const char *csv = NULL;
    const char *label = "e2e";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--method") && i + 1 < argc) method = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--iters") && i + 1 < argc) iters = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--server") && i + 1 < argc) g_server = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) g_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--secret") && i + 1 < argc) g_secret = argv[++i];
        else if (!strcmp(argv[i], "--creds-dir") && i + 1 < argc) g_creddir = argv[++i];
        else if (!strcmp(argv[i], "--loss") && i + 1 < argc) g_loss = atof(argv[++i]) / 100.0;
        else if (!strcmp(argv[i], "--max-retx") && i + 1 < argc) g_max_retx = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rto-ms") && i + 1 < argc) g_rto_ms = atof(argv[++i]);
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv = argv[++i];
        else if (!strcmp(argv[i], "--label") && i + 1 < argc) label = argv[++i];
        else if (!strcmp(argv[i], "-v")) g_verbose = 1;
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
    if (method < 0 || method > 4) {
        fprintf(stderr, "usage: %s --method 0..4 [--iters N] [--loss PCT] [--csv F] [--label L]\n", argv[0]);
        return 2;
    }

    srand((unsigned)(time(NULL) ^ getpid()));

    FILE *cf = NULL;
    if (csv) {
        int existed = access(csv, F_OK) == 0;
        cf = fopen(csv, "a");
        if (cf && !existed)
            fprintf(cf, "label,timestamp,method,method_name,iteration,status,duration_ms,"
                        "radius_round_trips,eap_round_trips,access_req,access_challenge,"
                        "access_accept,access_reject,retransmits,loss_pct,"
                        "msg1_bytes,msg2_bytes,msg3_bytes,msg4_bytes,"
                        "msg1_frags,msg2_frags,msg3_frags,msg4_frags\n");
    }

    int pass = 0;
    double sum = 0, best = 1e18, worst = 0;
    for (int it = 1; it <= iters; it++) {
        result_t r;
        int rc = run_handshake(method, &r);

        time_t now = time(NULL);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));

        const char *st = (rc == 0) ? "PASS" : "FAIL";
        if (rc == 0) {
            pass++; sum += r.duration_ms;
            if (r.duration_ms < best) best = r.duration_ms;
            if (r.duration_ms > worst) worst = r.duration_ms;
        }
        printf("[m%d %-16s] iter %2d: %s  %.3f ms  radius_rt=%d eap_rt=%d "
               "req=%d chal=%d accept=%d reject=%d retx=%d "
               "bytes(1..4)=%zu/%zu/%zu/%zu frags=%d/%d/%d/%d\n",
               method, method_name(method), it, st, r.duration_ms,
               r.radius_rt, r.eap_rt, r.access_req, r.access_chal,
               r.access_accept, r.access_reject, r.retx,
               r.msg_bytes[1], r.msg_bytes[2], r.msg_bytes[3], r.msg_bytes[4],
               r.msg_frags[1], r.msg_frags[2], r.msg_frags[3], r.msg_frags[4]);

        if (cf) {
            fprintf(cf, "%s,%s,%d,%s,%d,%s,%.3f,%d,%d,%d,%d,%d,%d,%d,%.1f,"
                        "%zu,%zu,%zu,%zu,%d,%d,%d,%d\n",
                    label, ts, method, method_name(method), it, st, r.duration_ms,
                    r.radius_rt, r.eap_rt, r.access_req, r.access_chal,
                    r.access_accept, r.access_reject, r.retx, g_loss * 100.0,
                    r.msg_bytes[1], r.msg_bytes[2], r.msg_bytes[3], r.msg_bytes[4],
                    r.msg_frags[1], r.msg_frags[2], r.msg_frags[3], r.msg_frags[4]);
        }
    }

    printf("== method %d (%s): %d/%d PASS", method, method_name(method), pass, iters);
    if (pass) printf("  mean=%.3f ms best=%.3f worst=%.3f", sum / pass, best, worst);
    printf(" ==\n");

    if (cf) fclose(cf);
    return (pass == iters) ? 0 : 1;
}
