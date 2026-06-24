#ifndef OGS_MLKEM_H
#define OGS_MLKEM_H

#include <stdint.h>
#include <stdbool.h>

#define OGS_MLKEM_PUBLIC_KEY_SIZE 1184
#define OGS_MLKEM_SECRET_KEY_SIZE 2400
#define OGS_MLKEM_CIPHERTEXT_SIZE 1088
#define OGS_MLKEM_SHARED_SECRET_SIZE 32

bool ogs_mlkem_keygen(uint8_t *pk, uint8_t *sk);
bool ogs_mlkem_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss);
bool ogs_mlkem_decapsulate(const uint8_t *ct, const uint8_t *sk, uint8_t *ss);

#endif /* OGS_MLKEM_H */
