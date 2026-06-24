#pragma once

#define FR_EAP_TYPE_EDHOC 56

typedef struct rlm_eap_edhoc_conf_s {
    const char *server_key_path;
    const char *ue_key_path;
} rlm_eap_edhoc_conf_t;
