
#include "ogs-core.h"
#include "mlkem/mlkem_wrapper.h"
#include "mlkem.h"

bool ogs_mlkem_keygen(uint8_t *pk, uint8_t *sk)
{
    if (!pk || !sk) return false;
    mlkem_keygen(pk, sk);
    return true;
}

bool ogs_mlkem_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    if (!pk || !ct || !ss) return false;
    mlkem_encapsulate(pk, ct, ss);
    return true;
}

bool ogs_mlkem_decapsulate(const uint8_t *ct, const uint8_t *sk, uint8_t *ss)
{
    if (!ct || !sk || !ss) return false;
    mlkem_decapsulate(ct, sk, ss);
    return true;
}
