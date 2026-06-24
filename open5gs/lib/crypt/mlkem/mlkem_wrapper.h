#ifndef MLKEM_WRAPPER_H
#define MLKEM_WRAPPER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MLKEM_PUBLIC_KEY_BYTES 1184
#define MLKEM_SECRET_KEY_BYTES 2400
#define MLKEM_CIPHERTEXT_BYTES 1088
#define MLKEM_SHARED_SECRET_BYTES 32

void mlkem_keygen(uint8_t *pk, uint8_t *sk);
void mlkem_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss);
void mlkem_decapsulate(const uint8_t *ct, const uint8_t *sk, uint8_t *ss);

#ifdef __cplusplus
}
#endif

#endif // MLKEM_WRAPPER_H
