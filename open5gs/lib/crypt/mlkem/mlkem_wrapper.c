#include "kem.h"
#include "mlkem_wrapper.h"

void mlkem_keygen(uint8_t *pk, uint8_t *sk) {
    crypto_kem_keypair(pk, sk);
}

void mlkem_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss) {
    crypto_kem_enc(ct, ss, pk);
}

void mlkem_decapsulate(const uint8_t *ct, const uint8_t *sk, uint8_t *ss) {
    crypto_kem_dec(ss, ct, sk);
}
