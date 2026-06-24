/*
 * Secondary Authentication relay service (UPF sidecar).
 */

#ifndef UPF_EAP_RELAY_H
#define UPF_EAP_RELAY_H

#ifdef __cplusplus
extern "C" {
#endif

int upf_eap_relay_start(void);
void upf_eap_relay_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* UPF_EAP_RELAY_H */
