#include <freeradius-devel/server/base.h>
#include <freeradius-devel/modules/rlm_eap/types/rlm_eap.h>

#include "rlm_eap_edhoc.h"

static unlang_action_t mod_authenticate(UNUSED rlm_rcode_t *p_result,
                                        UNUSED module_ctx_t const *mctx,
                                        request_t *request)
{
    RDEBUG2("rlm_eap_edhoc: received EAP-EDHOC packet");

    if (!request || !request->packet) {
        return UNLANG_ACTION_FAIL;
    }

    return UNLANG_ACTION_CALCULATE_RESULT;
}

static const module_method_binding_t rlm_eap_edhoc_method[] = {
    { .section = SECTION_NAME("authenticate"), .method = mod_authenticate },
    MODULE_BINDING_TERMINATOR
};

module_rlm_t rlm_eap_edhoc = {
    .magic = RLM_MODULE_INIT,
    .name = "eap_edhoc",
    .type = MODULE_TYPE_THREAD_UNSAFE,
    .method_group = MODULE_METHOD_GROUP_INIT,
    .method_names = rlm_eap_edhoc_method,
};
