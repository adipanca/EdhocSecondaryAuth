/*
 * Secondary Authentication relay service (UPF sidecar).
 */

#include "eap-relay.h"

#include "context.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define EAP_RELAY_MAGIC_REQ 0xE5E5DEADU
#define EAP_RELAY_MAGIC_RESP 0xE5E5BEEFU
#define EAP_RELAY_VERSION 1U

#define EAP_RELAY_DEFAULT_ADDR "127.0.0.1"
#define EAP_RELAY_DEFAULT_PORT 3870

#define EAP_RELAY_RESULT_ACCEPT 0
#define EAP_RELAY_RESULT_REJECT 1
#define EAP_RELAY_RESULT_CHALLENGE 2
#define EAP_RELAY_RESULT_ERROR 3

#define RADIUS_CODE_ACCESS_REQUEST 1
#define RADIUS_CODE_ACCESS_ACCEPT 2
#define RADIUS_CODE_ACCESS_REJECT 3
#define RADIUS_CODE_ACCESS_CHALLENGE 11

#define RADIUS_ATTR_USER_NAME 1
#define RADIUS_ATTR_SERVICE_TYPE 6
#define RADIUS_ATTR_STATE 24
#define RADIUS_ATTR_NAS_PORT_TYPE 61
#define RADIUS_ATTR_EAP_MESSAGE 79
#define RADIUS_ATTR_MESSAGE_AUTHENTICATOR 80

#define RADIUS_SERVICE_FRAMED_USER 2
#define RADIUS_NAS_PORT_VIRTUAL 5

#define RADIUS_HEADER_LEN 20
#define RADIUS_MAX_PACKET_LEN 4096
#define RADIUS_MAX_ATTR_VALUE 253

static int g_sock = -1;
static pthread_t g_thread;
static volatile int g_running = 0;
static uint8_t g_radius_identifier = 0;

typedef struct {
    uint32_t state[4];
    uint64_t bit_len;
    uint8_t buffer[64];
    size_t buffer_len;
} md5_ctx_t;

static uint32_t md5_rotl(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32U - n));
}

static uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }
static uint16_t get_port_from_env(const char *name, uint16_t default_port);

static void md5_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a, b, c, d, m[16];
    size_t i;

    for (i = 0; i < 16; ++i) {
        m[i] = (uint32_t)block[i * 4 + 0] |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];

#define MD5_STEP(f, a, b, c, d, x, t, s) \
    do { \
        (a) += f((b), (c), (d)) + (x) + (t); \
        (a) = md5_rotl((a), (s)); \
        (a) += (b); \
    } while (0)

    MD5_STEP(md5_f, a, b, c, d, m[0], 0xd76aa478U, 7);
    MD5_STEP(md5_f, d, a, b, c, m[1], 0xe8c7b756U, 12);
    MD5_STEP(md5_f, c, d, a, b, m[2], 0x242070dbU, 17);
    MD5_STEP(md5_f, b, c, d, a, m[3], 0xc1bdceeeU, 22);
    MD5_STEP(md5_f, a, b, c, d, m[4], 0xf57c0fafU, 7);
    MD5_STEP(md5_f, d, a, b, c, m[5], 0x4787c62aU, 12);
    MD5_STEP(md5_f, c, d, a, b, m[6], 0xa8304613U, 17);
    MD5_STEP(md5_f, b, c, d, a, m[7], 0xfd469501U, 22);
    MD5_STEP(md5_f, a, b, c, d, m[8], 0x698098d8U, 7);
    MD5_STEP(md5_f, d, a, b, c, m[9], 0x8b44f7afU, 12);
    MD5_STEP(md5_f, c, d, a, b, m[10], 0xffff5bb1U, 17);
    MD5_STEP(md5_f, b, c, d, a, m[11], 0x895cd7beU, 22);
    MD5_STEP(md5_f, a, b, c, d, m[12], 0x6b901122U, 7);
    MD5_STEP(md5_f, d, a, b, c, m[13], 0xfd987193U, 12);
    MD5_STEP(md5_f, c, d, a, b, m[14], 0xa679438eU, 17);
    MD5_STEP(md5_f, b, c, d, a, m[15], 0x49b40821U, 22);

    MD5_STEP(md5_g, a, b, c, d, m[1], 0xf61e2562U, 5);
    MD5_STEP(md5_g, d, a, b, c, m[6], 0xc040b340U, 9);
    MD5_STEP(md5_g, c, d, a, b, m[11], 0x265e5a51U, 14);
    MD5_STEP(md5_g, b, c, d, a, m[0], 0xe9b6c7aaU, 20);
    MD5_STEP(md5_g, a, b, c, d, m[5], 0xd62f105dU, 5);
    MD5_STEP(md5_g, d, a, b, c, m[10], 0x02441453U, 9);
    MD5_STEP(md5_g, c, d, a, b, m[15], 0xd8a1e681U, 14);
    MD5_STEP(md5_g, b, c, d, a, m[4], 0xe7d3fbc8U, 20);
    MD5_STEP(md5_g, a, b, c, d, m[9], 0x21e1cde6U, 5);
    MD5_STEP(md5_g, d, a, b, c, m[14], 0xc33707d6U, 9);
    MD5_STEP(md5_g, c, d, a, b, m[3], 0xf4d50d87U, 14);
    MD5_STEP(md5_g, b, c, d, a, m[8], 0x455a14edU, 20);
    MD5_STEP(md5_g, a, b, c, d, m[13], 0xa9e3e905U, 5);
    MD5_STEP(md5_g, d, a, b, c, m[2], 0xfcefa3f8U, 9);
    MD5_STEP(md5_g, c, d, a, b, m[7], 0x676f02d9U, 14);
    MD5_STEP(md5_g, b, c, d, a, m[12], 0x8d2a4c8aU, 20);

    MD5_STEP(md5_h, a, b, c, d, m[5], 0xfffa3942U, 4);
    MD5_STEP(md5_h, d, a, b, c, m[8], 0x8771f681U, 11);
    MD5_STEP(md5_h, c, d, a, b, m[11], 0x6d9d6122U, 16);
    MD5_STEP(md5_h, b, c, d, a, m[14], 0xfde5380cU, 23);
    MD5_STEP(md5_h, a, b, c, d, m[1], 0xa4beea44U, 4);
    MD5_STEP(md5_h, d, a, b, c, m[4], 0x4bdecfa9U, 11);
    MD5_STEP(md5_h, c, d, a, b, m[7], 0xf6bb4b60U, 16);
    MD5_STEP(md5_h, b, c, d, a, m[10], 0xbebfbc70U, 23);
    MD5_STEP(md5_h, a, b, c, d, m[13], 0x289b7ec6U, 4);
    MD5_STEP(md5_h, d, a, b, c, m[0], 0xeaa127faU, 11);
    MD5_STEP(md5_h, c, d, a, b, m[3], 0xd4ef3085U, 16);
    MD5_STEP(md5_h, b, c, d, a, m[6], 0x04881d05U, 23);
    MD5_STEP(md5_h, a, b, c, d, m[9], 0xd9d4d039U, 4);
    MD5_STEP(md5_h, d, a, b, c, m[12], 0xe6db99e5U, 11);
    MD5_STEP(md5_h, c, d, a, b, m[15], 0x1fa27cf8U, 16);
    MD5_STEP(md5_h, b, c, d, a, m[2], 0xc4ac5665U, 23);

    MD5_STEP(md5_i, a, b, c, d, m[0], 0xf4292244U, 6);
    MD5_STEP(md5_i, d, a, b, c, m[7], 0x432aff97U, 10);
    MD5_STEP(md5_i, c, d, a, b, m[14], 0xab9423a7U, 15);
    MD5_STEP(md5_i, b, c, d, a, m[5], 0xfc93a039U, 21);
    MD5_STEP(md5_i, a, b, c, d, m[12], 0x655b59c3U, 6);
    MD5_STEP(md5_i, d, a, b, c, m[3], 0x8f0ccc92U, 10);
    MD5_STEP(md5_i, c, d, a, b, m[10], 0xffeff47dU, 15);
    MD5_STEP(md5_i, b, c, d, a, m[1], 0x85845dd1U, 21);
    MD5_STEP(md5_i, a, b, c, d, m[8], 0x6fa87e4fU, 6);
    MD5_STEP(md5_i, d, a, b, c, m[15], 0xfe2ce6e0U, 10);
    MD5_STEP(md5_i, c, d, a, b, m[6], 0xa3014314U, 15);
    MD5_STEP(md5_i, b, c, d, a, m[13], 0x4e0811a1U, 21);
    MD5_STEP(md5_i, a, b, c, d, m[4], 0xf7537e82U, 6);
    MD5_STEP(md5_i, d, a, b, c, m[11], 0xbd3af235U, 10);
    MD5_STEP(md5_i, c, d, a, b, m[2], 0x2ad7d2bbU, 15);
    MD5_STEP(md5_i, b, c, d, a, m[9], 0xeb86d391U, 21);

#undef MD5_STEP

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

static void md5_init(md5_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xefcdab89U;
    ctx->state[2] = 0x98badcfeU;
    ctx->state[3] = 0x10325476U;
    ctx->bit_len = 0;
    ctx->buffer_len = 0;
}

static void md5_update(md5_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t i;
    size_t space;

    if (!data || len == 0)
        return;

    ctx->bit_len += (uint64_t)len * 8U;

    i = 0;
    if (ctx->buffer_len > 0) {
        space = 64U - ctx->buffer_len;
        if (len < space) {
            memcpy(ctx->buffer + ctx->buffer_len, data, len);
            ctx->buffer_len += len;
            return;
        }

        memcpy(ctx->buffer + ctx->buffer_len, data, space);
        md5_transform(ctx->state, ctx->buffer);
        ctx->buffer_len = 0;
        i += space;
    }

    while (i + 63 < len) {
        md5_transform(ctx->state, data + i);
        i += 64;
    }

    if (i < len) {
        ctx->buffer_len = len - i;
        memcpy(ctx->buffer, data + i, ctx->buffer_len);
    }
}

static void md5_final(md5_ctx_t *ctx, uint8_t out[16])
{
    size_t i;
    size_t pad_len;
    uint8_t pad[128];
    uint8_t len_le[8];
    uint32_t v;
    uint64_t bit_len;

    bit_len = ctx->bit_len;
    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof(pad) - 1);

    for (i = 0; i < 8; ++i) {
        len_le[i] = (uint8_t)((bit_len >> (8U * i)) & 0xffU);
    }

    if (ctx->buffer_len < 56U)
        pad_len = 56U - ctx->buffer_len;
    else
        pad_len = 120U - ctx->buffer_len;

    md5_update(ctx, pad, pad_len);
    ctx->bit_len = bit_len;
    md5_update(ctx, len_le, sizeof(len_le));
    ctx->bit_len = bit_len;
    for (i = 0; i < 4; ++i) {
        v = ctx->state[i];
        out[i * 4 + 0] = (uint8_t)(v & 0xffU);
        out[i * 4 + 1] = (uint8_t)((v >> 8U) & 0xffU);
        out[i * 4 + 2] = (uint8_t)((v >> 16U) & 0xffU);
        out[i * 4 + 3] = (uint8_t)((v >> 24U) & 0xffU);
    }
}

static void md5_hash(const uint8_t *data, size_t len, uint8_t out[16])
{
    md5_ctx_t ctx;

    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, out);
}

static void hmac_md5(const uint8_t *key, size_t key_len,
        const uint8_t *data, size_t data_len, uint8_t out[16])
{
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[16];
    size_t i;
    md5_ctx_t ctx;

    if (key_len > 64U) {
        md5_hash(key, key_len, tk);
        key = tk;
        key_len = sizeof(tk);
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
    for (i = 0; i < key_len; ++i) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    md5_init(&ctx);
    md5_update(&ctx, k_ipad, sizeof(k_ipad));
    md5_update(&ctx, data, data_len);
    md5_final(&ctx, tk);

    md5_init(&ctx);
    md5_update(&ctx, k_opad, sizeof(k_opad));
    md5_update(&ctx, tk, sizeof(tk));
    md5_final(&ctx, out);
}

static void radius_random_bytes(uint8_t *out, size_t len)
{
    static int seeded = 0;
    size_t i;

    if (!seeded) {
        srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
        seeded = 1;
    }

    for (i = 0; i < len; ++i)
        out[i] = (uint8_t)(rand() & 0xff);
}

static int radius_append_attr(uint8_t *buf, size_t cap, size_t *pos,
        uint8_t type, const uint8_t *data, size_t data_len)
{
    size_t chunk;

    while (data_len > 0) {
        chunk = (data_len > RADIUS_MAX_ATTR_VALUE) ? RADIUS_MAX_ATTR_VALUE : data_len;
        if (*pos + 2U + chunk > cap)
            return -1;

        buf[*pos + 0] = type;
        buf[*pos + 1] = (uint8_t)(2U + chunk);
        memcpy(buf + *pos + 2, data, chunk);
        *pos += 2U + chunk;
        data += chunk;
        data_len -= chunk;
    }

    return 0;
}

static int radius_append_u16_attr(uint8_t *buf, size_t cap, size_t *pos,
        uint8_t type, uint16_t value)
{
    uint8_t data[2];
    data[0] = (uint8_t)((value >> 8U) & 0xffU);
    data[1] = (uint8_t)(value & 0xffU);
    return radius_append_attr(buf, cap, pos, type, data, sizeof(data));
}

static int radius_build_request(const char *username,
        const uint8_t *state, size_t state_len,
        const uint8_t *eap, size_t eap_len,
        const uint8_t *secret, size_t secret_len,
        uint8_t *req, size_t req_cap,
        size_t *req_len)
{
    size_t pos = 0;
    size_t username_len;
    size_t ma_pos;
    uint16_t len_be;
    uint8_t auth[16];
    uint8_t digest[16];

    if (!username || !eap || !req || !req_len || !secret)
        return -1;

    username_len = strlen(username);
    if (username_len > RADIUS_MAX_ATTR_VALUE)
        return -1;

    req[pos++] = RADIUS_CODE_ACCESS_REQUEST;
    if (RADIUS_HEADER_LEN + 2U + username_len + 2U + 2U + eap_len + 18U > req_cap)
        return -1;
    req[pos++] = ++g_radius_identifier;
    req[pos++] = 0;
    req[pos++] = 0;

    radius_random_bytes(auth, sizeof(auth));
    memcpy(req + pos, auth, sizeof(auth));
    pos += sizeof(auth);

    if (radius_append_attr(req, req_cap, &pos, RADIUS_ATTR_USER_NAME,
                (const uint8_t *)username, username_len) != 0)
        return -1;

    if (radius_append_u16_attr(req, req_cap, &pos, RADIUS_ATTR_SERVICE_TYPE,
                RADIUS_SERVICE_FRAMED_USER) != 0)
        return -1;

    if (radius_append_u16_attr(req, req_cap, &pos, RADIUS_ATTR_NAS_PORT_TYPE,
                RADIUS_NAS_PORT_VIRTUAL) != 0)
        return -1;

    if (state && state_len > 0) {
        if (radius_append_attr(req, req_cap, &pos, RADIUS_ATTR_STATE, state, state_len) != 0)
            return -1;
    }

    if (radius_append_attr(req, req_cap, &pos, RADIUS_ATTR_EAP_MESSAGE, eap, eap_len) != 0)
        return -1;

    ma_pos = pos + 2U;
    if (pos + 18U > req_cap)
        return -1;
    req[pos++] = RADIUS_ATTR_MESSAGE_AUTHENTICATOR;
    req[pos++] = 18;
    memset(req + pos, 0, 16);
    pos += 16;

    if (pos > RADIUS_MAX_PACKET_LEN)
        return -1;

    len_be = htons((uint16_t)pos);
    memcpy(req + 2, &len_be, sizeof(len_be));

    hmac_md5(secret, secret_len, req, pos, digest);
    memcpy(req + ma_pos, digest, sizeof(digest));

    *req_len = pos;
    return 0;
}

static int radius_parse_response(const uint8_t *resp, size_t resp_len,
        uint8_t *out_result,
        uint8_t *out_state, size_t out_state_cap, size_t *out_state_len,
        uint8_t *out_eap, size_t out_eap_cap, size_t *out_eap_len)
{
    size_t pos = 0;
    size_t state_pos = 0;
    size_t eap_pos = 0;
    uint16_t packet_len = 0;
    uint8_t code;

    if (!resp || resp_len < RADIUS_HEADER_LEN || !out_result || !out_state_len || !out_eap_len)
        return -1;

    code = resp[0];
    packet_len = (uint16_t)(((uint16_t)resp[2] << 8U) | (uint16_t)resp[3]);
    if (packet_len > resp_len || packet_len < RADIUS_HEADER_LEN)
        return -1;

    pos = RADIUS_HEADER_LEN;
    while (pos + 2U <= packet_len) {
        uint8_t type = resp[pos];
        uint8_t alen = resp[pos + 1];
        size_t data_len;

        if (alen < 2U || pos + alen > packet_len)
            return -1;

        data_len = (size_t)alen - 2U;
        if (type == RADIUS_ATTR_STATE) {
            if (state_pos + data_len > out_state_cap)
                return -1;
            if (data_len > 0 && out_state)
                memcpy(out_state + state_pos, resp + pos + 2, data_len);
            state_pos += data_len;
        } else if (type == RADIUS_ATTR_EAP_MESSAGE) {
            if (eap_pos + data_len > out_eap_cap)
                return -1;
            if (data_len > 0 && out_eap)
                memcpy(out_eap + eap_pos, resp + pos + 2, data_len);
            eap_pos += data_len;
        }

        pos += alen;
    }

    *out_state_len = state_pos;
    *out_eap_len = eap_pos;

    if (code == RADIUS_CODE_ACCESS_ACCEPT)
        *out_result = EAP_RELAY_RESULT_ACCEPT;
    else if (code == RADIUS_CODE_ACCESS_REJECT)
        *out_result = EAP_RELAY_RESULT_REJECT;
    else if (code == RADIUS_CODE_ACCESS_CHALLENGE)
        *out_result = EAP_RELAY_RESULT_CHALLENGE;
    else
        return -1;

    return 0;
}

static int radius_verify_response(const uint8_t *req, size_t req_len,
        const uint8_t *resp, size_t resp_len,
        const uint8_t *secret, size_t secret_len)
{
    uint16_t packet_len;
    size_t pos;
    int has_eap = 0;
    int ma_off = -1;
    uint8_t tmp[RADIUS_MAX_PACKET_LEN];
    uint8_t digest[16];
    md5_ctx_t ctx;

    if (!req || !resp || !secret)
        return -1;

    if (req_len < RADIUS_HEADER_LEN || resp_len < RADIUS_HEADER_LEN)
        return -1;

    if (resp[1] != req[1]) {
        ogs_error("radius_verify_response: identifier mismatch (req=%u resp=%u)",
                req[1], resp[1]);
        return -1;
    }

    packet_len = (uint16_t)(((uint16_t)resp[2] << 8U) | (uint16_t)resp[3]);
    if (packet_len < RADIUS_HEADER_LEN || packet_len > resp_len || packet_len > RADIUS_MAX_PACKET_LEN)
        return -1;

    memcpy(tmp, resp, packet_len);
    memcpy(tmp + 4, req + 4, 16);

    pos = RADIUS_HEADER_LEN;
    while (pos + 2U <= packet_len) {
        uint8_t type = tmp[pos];
        uint8_t alen = tmp[pos + 1];

        if (alen < 2U || pos + alen > packet_len)
            return -1;

        if (type == RADIUS_ATTR_EAP_MESSAGE)
            has_eap = 1;

        if (type == RADIUS_ATTR_MESSAGE_AUTHENTICATOR) {
            if (alen != 18U) {
                ogs_error("radius_verify_response: invalid Message-Authenticator length");
                return -1;
            }
            if (ma_off >= 0) {
                ogs_error("radius_verify_response: duplicate Message-Authenticator");
                return -1;
            }
            ma_off = (int)pos + 2;
        }

        pos += alen;
    }

    if (has_eap && ma_off < 0) {
        ogs_error("radius_verify_response: missing Message-Authenticator in EAP response");
        return -1;
    }

    if (ma_off >= 0) {
        uint8_t recv_ma[16];

        memcpy(recv_ma, tmp + ma_off, sizeof(recv_ma));
        memset(tmp + ma_off, 0, sizeof(recv_ma));
        hmac_md5(secret, secret_len, tmp, packet_len, digest);
        if (memcmp(recv_ma, digest, sizeof(recv_ma)) != 0) {
            ogs_error("radius_verify_response: Message-Authenticator verification failed");
            return -1;
        }
        memcpy(tmp + ma_off, recv_ma, sizeof(recv_ma));
    }

    md5_init(&ctx);
    md5_update(&ctx, tmp, packet_len);
    md5_update(&ctx, secret, secret_len);
    md5_final(&ctx, digest);

    if (memcmp(digest, resp + 4, 16) != 0) {
        ogs_error("radius_verify_response: Response Authenticator verification failed");
        return -1;
    }

    return 0;
}

static int radius_exchange(const char *username,
        const uint8_t *state, size_t state_len,
        const uint8_t *eap, size_t eap_len,
        uint8_t *out_result,
        uint8_t *out_state, size_t out_state_cap, size_t *out_state_len,
        uint8_t *out_eap, size_t out_eap_cap, size_t *out_eap_len)
{
    const char *radius_addr;
    const char *secret_env;
    uint16_t radius_port;
    uint8_t req[8192];
    uint8_t resp[8192];
    size_t req_len = 0;
    size_t resp_len = 0;
    ssize_t rcv_len;
    int fd = -1;
    struct sockaddr_in dst;
    struct timeval tv;
    const uint8_t *secret;
    size_t secret_len;

    radius_addr = getenv("OPEN5GS_RADIUS_ADDR");
    if (!radius_addr || !radius_addr[0])
        radius_addr = getenv("OPEN5GS_RADIUS_SERVER");
    if (!radius_addr || !radius_addr[0])
        radius_addr = "127.0.0.1";

    secret_env = getenv("OPEN5GS_RADIUS_SECRET");
    if (!secret_env || !secret_env[0])
        secret_env = "testing123";
    secret = (const uint8_t *)secret_env;
    secret_len = strlen(secret_env);

    radius_port = get_port_from_env("OPEN5GS_RADIUS_PORT", 1812);

    if (radius_build_request(username, state, state_len, eap, eap_len,
                secret, secret_len, req, sizeof(req), &req_len) != 0) {
        ogs_error("radius_exchange: failed to build Access-Request");
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ogs_error("radius_exchange: socket() failed (%d)", errno);
        return -1;
    }

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(radius_port);
    if (inet_pton(AF_INET, radius_addr, &dst.sin_addr) != 1) {
        ogs_error("radius_exchange: invalid RADIUS address [%s]", radius_addr);
        goto done;
    }

    if (sendto(fd, req, req_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        ogs_error("radius_exchange: sendto() failed (%d)", errno);
        goto done;
    }

    rcv_len = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
    if (rcv_len < 0) {
        ogs_error("radius_exchange: recvfrom() failed (%d)", errno);
        goto done;
    }

    resp_len = (size_t)rcv_len;
    if (radius_verify_response(req, req_len, resp, resp_len, secret, secret_len) != 0) {
        ogs_error("radius_exchange: response authentication failed");
        goto done;
    }

    if (radius_parse_response(resp, resp_len, out_result,
                out_state, out_state_cap, out_state_len,
                out_eap, out_eap_cap, out_eap_len) != 0) {
        ogs_error("radius_exchange: invalid response packet");
        goto done;
    }

    close(fd);
    return 0;

done:
    if (fd >= 0)
        close(fd);
    return -1;
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

static void write_response(const uint8_t result,
        const uint8_t *state, uint16_t state_len,
        const uint8_t *eap, uint16_t eap_len,
        uint8_t *out, size_t *out_len)
{
    uint32_t v32 = htonl(EAP_RELAY_MAGIC_RESP);
    uint16_t v16 = 0;
    size_t pos = 0;

    memcpy(out + pos, &v32, sizeof(v32));
    pos += sizeof(v32);

    out[pos++] = EAP_RELAY_VERSION;
    out[pos++] = result;

    v16 = htons(state_len);
    memcpy(out + pos, &v16, sizeof(v16));
    pos += sizeof(v16);

    v16 = htons(eap_len);
    memcpy(out + pos, &v16, sizeof(v16));
    pos += sizeof(v16);

    if (state_len && state) {
        memcpy(out + pos, state, state_len);
        pos += state_len;
    }

    if (eap_len && eap) {
        memcpy(out + pos, eap, eap_len);
        pos += eap_len;
    }

    *out_len = pos;
}

static void process_req(const uint8_t *buf, size_t len,
        uint8_t *resp, size_t *resp_len)
{
    size_t pos = 0;
    uint32_t v32 = 0;
    uint16_t state_len = 0;
    uint16_t eap_len = 0;
    uint8_t version = 0;
    uint8_t uname_len = 0;
    const uint8_t *state = NULL;
    const uint8_t *eap = NULL;
    size_t need = 0;
    char username_buf[256];
    const char *username = NULL;
    uint8_t result = EAP_RELAY_RESULT_ERROR;
    uint8_t radius_state[2048];
    uint8_t radius_eap[8192];
    size_t radius_state_len = 0;
    size_t radius_eap_len = 0;

    if (len < 10) {
        write_response(EAP_RELAY_RESULT_ERROR, NULL, 0, NULL, 0, resp, resp_len);
        return;
    }

    memcpy(&v32, buf + pos, sizeof(v32));
    pos += sizeof(v32);
    if (ntohl(v32) != EAP_RELAY_MAGIC_REQ) {
        write_response(EAP_RELAY_RESULT_ERROR, NULL, 0, NULL, 0, resp, resp_len);
        return;
    }

    version = buf[pos++];
    (void)buf[pos++]; /* reserved */
    uname_len = buf[pos++];

    memcpy(&state_len, buf + pos, sizeof(state_len));
    pos += sizeof(state_len);
    state_len = ntohs(state_len);

    memcpy(&eap_len, buf + pos, sizeof(eap_len));
    pos += sizeof(eap_len);
    eap_len = ntohs(eap_len);

    if (version != EAP_RELAY_VERSION) {
        write_response(EAP_RELAY_RESULT_ERROR, NULL, 0, NULL, 0, resp, resp_len);
        return;
    }

    need = pos + (size_t)uname_len + state_len + eap_len;
    if (len < need) {
        write_response(EAP_RELAY_RESULT_ERROR, NULL, 0, NULL, 0, resp, resp_len);
        return;
    }

    memset(username_buf, 0, sizeof(username_buf));
    memcpy(username_buf, buf + pos, uname_len);
    username = username_buf;
    pos += uname_len;
    state = buf + pos;
    pos += state_len;
    eap = buf + pos;

    if (radius_exchange(username, state, state_len, eap, eap_len,
                &result,
                radius_state, sizeof(radius_state), &radius_state_len,
                radius_eap, sizeof(radius_eap), &radius_eap_len) != 0) {
        write_response(EAP_RELAY_RESULT_ERROR, NULL, 0, NULL, 0, resp, resp_len);
        return;
    }

    if (radius_state_len > 0)
        state = radius_state;
    else
        state = NULL;

    if (radius_eap_len > 0)
        eap = radius_eap;
    else
        eap = NULL;

    write_response(result, state, (uint16_t)radius_state_len, eap, (uint16_t)radius_eap_len, resp, resp_len);
}

static void *relay_main(void *unused)
{
    uint8_t req[8192];
    uint8_t resp[8192];

    (void)unused;

    while (g_running) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(g_sock, req, sizeof(req), 0,
                (struct sockaddr *)&from, &from_len);
        size_t resp_len = 0;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (!g_running)
                break;
            continue;
        }

        process_req(req, (size_t)n, resp, &resp_len);
        if (resp_len > 0) {
            (void)sendto(g_sock, resp, resp_len, 0,
                    (struct sockaddr *)&from, from_len);
        }
    }

    return NULL;
}

int upf_eap_relay_start(void)
{
    struct sockaddr_in addr;
    const char *bind_addr = getenv("OPEN5GS_EAP_RELAY_ADDR");
    uint16_t bind_port = get_port_from_env("OPEN5GS_EAP_RELAY_PORT",
            EAP_RELAY_DEFAULT_PORT);

    if (g_running)
        return OGS_OK;

    if (!bind_addr || !bind_addr[0])
        bind_addr = EAP_RELAY_DEFAULT_ADDR;

    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) {
        ogs_error("upf_eap_relay_start: socket() failed (%d)", errno);
        return OGS_ERROR;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bind_port);
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        ogs_error("upf_eap_relay_start: invalid bind address [%s]", bind_addr);
        close(g_sock);
        g_sock = -1;
        return OGS_ERROR;
    }

    if (bind(g_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ogs_error("upf_eap_relay_start: bind() failed (%d)", errno);
        close(g_sock);
        g_sock = -1;
        return OGS_ERROR;
    }

    g_running = 1;
    if (pthread_create(&g_thread, NULL, relay_main, NULL) != 0) {
        ogs_error("upf_eap_relay_start: pthread_create() failed");
        g_running = 0;
        close(g_sock);
        g_sock = -1;
        return OGS_ERROR;
    }

    ogs_info("UPF EAP relay started on %s:%u", bind_addr, bind_port);
    return OGS_OK;
}

void upf_eap_relay_stop(void)
{
    if (!g_running)
        return;

    g_running = 0;
    if (g_sock >= 0) {
        close(g_sock);
        g_sock = -1;
    }

    (void)pthread_join(g_thread, NULL);
    ogs_info("UPF EAP relay stopped");
}
