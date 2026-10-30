/*
 * Secondary Authentication relay client (SMF -> UPF sidecar).
 *
 * Non-blocking: one persistent UDP socket to the UPF relay, registered in
 * the SMF pollset. smf_eap_relay_send() returns at once; the reply is
 * delivered to the session FSM as SMF_EVT_SEC_AUTH_RELAY (e->pkbuf holds
 * the reply body, parse it with smf_eap_relay_parse()), and a missing reply
 * as SMF_EVT_5GSM_TIMER / SMF_TIMER_SEC_AUTH_RELAY.
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

/* reply wait in the SMF; the UPF relay waits 2 s for the DN-AAA */
#define SMF_EAP_RELAY_TIMEOUT_MSEC 2500

typedef struct smf_sess_s smf_sess_t;
typedef struct ogs_pkbuf_s ogs_pkbuf_t;

/* send one EAP payload of sess (User-Name = sess->sec_auth.identity, RADIUS
 * State = sess->sec_auth.state) and start sess->sec_auth.t_relay */
int smf_eap_relay_send(smf_sess_t *sess, const uint8_t *eap, size_t eap_len);

/* parse a reply delivered by SMF_EVT_SEC_AUTH_RELAY; the pointers refer
 * into pkbuf */
int smf_eap_relay_parse(ogs_pkbuf_t *pkbuf, uint8_t *result,
        const uint8_t **state, size_t *state_len,
        const uint8_t **eap, size_t *eap_len);

void smf_eap_relay_close(void);

#ifdef __cplusplus
}
#endif

#endif /* SMF_RADIUS_CLIENT_H */
