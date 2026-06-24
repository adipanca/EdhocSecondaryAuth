/*
 * Secondary Authentication relay client (SMF -> UPF sidecar).
 */

#include "radius-client.h"

#include "context.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define EAP_RELAY_MAGIC_REQ 0xE5E5DEADU
#define EAP_RELAY_MAGIC_RESP 0xE5E5BEEFU
#define EAP_RELAY_VERSION 1U

#define EAP_RELAY_DEFAULT_ADDR "127.0.0.1"
#define EAP_RELAY_DEFAULT_PORT 3870

#define EAP_RELAY_MAX_USER_LEN 255
#define EAP_RELAY_MAX_STATE_LEN 2048
#define EAP_RELAY_MAX_EAP_LEN 4096

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

int smf_eap_relay_exchange(const char *username,
        const uint8_t *state, size_t state_len,
        const uint8_t *eap, size_t eap_len,
        uint8_t *out_result,
        uint8_t *out_state, size_t out_state_cap, size_t *out_state_len,
        uint8_t *out_eap, size_t out_eap_cap, size_t *out_eap_len)
{
    int fd = -1;
    int rc = OGS_ERROR;
    struct sockaddr_in dst;
    const char *relay_addr = getenv("OPEN5GS_EAP_RELAY_ADDR");
    uint16_t relay_port = get_port_from_env("OPEN5GS_EAP_RELAY_PORT",
            EAP_RELAY_DEFAULT_PORT);
    struct timeval tv;
    uint8_t req[8192];
    size_t req_len = 0;
    uint8_t resp[8192];
    ssize_t rcv_len = 0;
    uint32_t v32 = 0;
    uint16_t v16 = 0;
    size_t pos = 0;
    uint8_t uname_len = 0;
    const uint8_t *uname_ptr = NULL;
    size_t body_need = 0;

    if (!username || !eap || !out_result || !out_state_len || !out_eap_len) {
        ogs_error("smf_eap_relay_exchange: invalid argument");
        return OGS_ERROR;
    }

    if (!relay_addr || !relay_addr[0])
        relay_addr = EAP_RELAY_DEFAULT_ADDR;

    if (strlen(username) > EAP_RELAY_MAX_USER_LEN) {
        ogs_error("smf_eap_relay_exchange: username too large");
        return OGS_ERROR;
    }

    uname_len = (uint8_t)strlen(username);
    uname_ptr = (const uint8_t *)username;
    if (state_len > EAP_RELAY_MAX_STATE_LEN ||
        eap_len > EAP_RELAY_MAX_EAP_LEN) {
        ogs_error("smf_eap_relay_exchange: payload too large");
        return OGS_ERROR;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        ogs_error("smf_eap_relay_exchange: socket() failed (%d)", errno);
        return OGS_ERROR;
    }

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(relay_port);
    if (inet_pton(AF_INET, relay_addr, &dst.sin_addr) != 1) {
        ogs_error("smf_eap_relay_exchange: invalid relay address [%s]", relay_addr);
        goto done;
    }

    v32 = htonl(EAP_RELAY_MAGIC_REQ);
    memcpy(req + req_len, &v32, sizeof(v32));
    req_len += sizeof(v32);

    req[req_len++] = EAP_RELAY_VERSION;
    req[req_len++] = 0;
    req[req_len++] = uname_len;

    v16 = htons((uint16_t)state_len);
    memcpy(req + req_len, &v16, sizeof(v16));
    req_len += sizeof(v16);

    v16 = htons((uint16_t)eap_len);
    memcpy(req + req_len, &v16, sizeof(v16));
    req_len += sizeof(v16);

    if (uname_len) {
        memcpy(req + req_len, uname_ptr, uname_len);
        req_len += uname_len;
    }
    if (state_len) {
        memcpy(req + req_len, state, state_len);
        req_len += state_len;
    }
    if (eap_len) {
        memcpy(req + req_len, eap, eap_len);
        req_len += eap_len;
    }

    if (sendto(fd, req, req_len, 0,
            (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        ogs_error("smf_eap_relay_exchange: sendto() failed (%d)", errno);
        goto done;
    }

    rcv_len = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
    if (rcv_len < 10) {
        ogs_error("smf_eap_relay_exchange: short response (%zd)", rcv_len);
        goto done;
    }

    pos = 0;
    memcpy(&v32, resp + pos, sizeof(v32));
    pos += sizeof(v32);
    if (ntohl(v32) != EAP_RELAY_MAGIC_RESP) {
        ogs_error("smf_eap_relay_exchange: invalid response magic");
        goto done;
    }

    if (resp[pos++] != EAP_RELAY_VERSION) {
        ogs_error("smf_eap_relay_exchange: unsupported response version");
        goto done;
    }

    *out_result = resp[pos++];

    memcpy(&v16, resp + pos, sizeof(v16));
    pos += sizeof(v16);
    *out_state_len = ntohs(v16);

    memcpy(&v16, resp + pos, sizeof(v16));
    pos += sizeof(v16);
    *out_eap_len = ntohs(v16);

    body_need = pos + *out_state_len + *out_eap_len;
    if ((size_t)rcv_len < body_need) {
        ogs_error("smf_eap_relay_exchange: truncated response body");
        goto done;
    }

    if (*out_state_len > out_state_cap || *out_eap_len > out_eap_cap) {
        ogs_error("smf_eap_relay_exchange: output buffer too small");
        goto done;
    }

    if (*out_state_len && out_state)
        memcpy(out_state, resp + pos, *out_state_len);
    pos += *out_state_len;

    if (*out_eap_len && out_eap)
        memcpy(out_eap, resp + pos, *out_eap_len);

    rc = OGS_OK;

done:
    if (fd >= 0)
        close(fd);
    return rc;
}
