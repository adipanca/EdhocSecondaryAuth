#include "rlm_eap_edhoc.h"

/*
 * Minimal placeholder for FreeRADIUS EAP-EDHOC module wiring.
 * The real implementation should parse/compose EAP payload for RFC 9528.
 */
int rlm_eap_edhoc_version(void)
{
    return EAP_TYPE_EDHOC;
}
