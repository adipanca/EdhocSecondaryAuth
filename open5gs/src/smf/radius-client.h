/*
 * Secondary Authentication relay client (SMF -> UPF sidecar).
 */

#ifndef SMF_RADIUS_CLIENT_H
#define SMF_RADIUS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SMF_EAP_RELAY_RESULT_ACCEPT 0
#define SMF_EAP_RELAY_RESULT_REJECT 1
#define SMF_EAP_RELAY_RESULT_CHALLENGE 2
#define SMF_EAP_RELAY_RESULT_ERROR 3

int smf_eap_relay_exchange(const char *username,
        const uint8_t *state, size_t state_len,
        const uint8_t *eap, size_t eap_len,
        uint8_t *out_result,
        uint8_t *out_state, size_t out_state_cap, size_t *out_state_len,
        uint8_t *out_eap, size_t out_eap_cap, size_t *out_eap_len);

#ifdef __cplusplus
}
#endif

#endif /* SMF_RADIUS_CLIENT_H */
