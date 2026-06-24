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
#include <sys/socket.h>
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

static int g_sock = -1;
static pthread_t g_thread;
static volatile int g_running = 0;

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

    pos += uname_len; /* username, currently unused in local scaffold */
    state = buf + pos;
    pos += state_len;
    eap = buf + pos;

    /*
     * Scaffold behavior for integration testing:
     * - if EAP Code=2 (Response), return Challenge to continue exchange
     * - if EAP Code=3 (Success), return Accept
     * - if EAP Code=4 (Failure), return Reject
     */
    if (eap_len > 0) {
        switch (eap[0]) {
        case 3:
            write_response(EAP_RELAY_RESULT_ACCEPT,
                    state, state_len, eap, eap_len, resp, resp_len);
            return;
        case 4:
            write_response(EAP_RELAY_RESULT_REJECT,
                    state, state_len, eap, eap_len, resp, resp_len);
            return;
        default:
            write_response(EAP_RELAY_RESULT_CHALLENGE,
                    state, state_len, eap, eap_len, resp, resp_len);
            return;
        }
    }

    write_response(EAP_RELAY_RESULT_ERROR, NULL, 0, NULL, 0, resp, resp_len);
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
