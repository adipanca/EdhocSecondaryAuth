/*
 * interop_vec.c — cross-implementation interop helper for EAP-EDHOC primitives.
 *
 * Used by interop_check.py to prove that the libsodium/PQClean crypto core
 * interoperates with an independent implementation (OpenSSL via pyca
 * cryptography), the kind of stack a peer EDHOC implementation (e.g. the
 * FreeRADIUS rlm_eap_edhoc responder) would use.
 *
 * Subcommands:
 *   x25519 <peer_pub_in> <my_pub_out> <shared_out>
 *       Generate an X25519 keypair, ECDH with peer_pub, write my_pub + shared.
 *   ed25519_sign <msg_in> <pub_out> <sig_out>
 *       Generate an Ed25519 keypair, sign msg, write pub + signature.
 *   ed25519_verify <msg_in> <pub_in> <sig_in>
 *       Verify an externally produced Ed25519 signature (exit 0 if valid).
 *   mlkem
 *       ML-KEM-768 (PQClean) encaps/decaps round-trip; exit 0 if shared
 *       secrets match.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

/* PQClean ML-KEM-768 (clean reference) */
#define MLKEM768_PK 1184
#define MLKEM768_SK 2400
#define MLKEM768_CT 1088
#define MLKEM768_SS 32
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static int read_file(const char *p, unsigned char *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(p, "rb");
    if (!f) { perror(p); return -1; }
    *len = fread(buf, 1, cap, f);
    fclose(f);
    return 0;
}

static int write_file(const char *p, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(p, "wb");
    if (!f) { perror(p); return -1; }
    fwrite(buf, 1, len, f);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0) return 2;
    if (argc < 2) { fprintf(stderr, "usage: %s <subcommand> ...\n", argv[0]); return 2; }

    if (strcmp(argv[1], "x25519") == 0 && argc == 5) {
        unsigned char peer[32], mypk[32], mysk[32], shared[32];
        size_t n;
        if (read_file(argv[2], peer, sizeof(peer), &n) || n != 32) return 1;
        randombytes_buf(mysk, sizeof(mysk));
        crypto_scalarmult_base(mypk, mysk);
        if (crypto_scalarmult(shared, mysk, peer) != 0) return 1;
        if (write_file(argv[3], mypk, 32)) return 1;
        if (write_file(argv[4], shared, 32)) return 1;
        return 0;
    }

    if (strcmp(argv[1], "ed25519_sign") == 0 && argc == 5) {
        unsigned char msg[4096], pk[crypto_sign_PUBLICKEYBYTES],
                      sk[crypto_sign_SECRETKEYBYTES], sig[crypto_sign_BYTES];
        size_t mlen;
        unsigned long long siglen;
        if (read_file(argv[2], msg, sizeof(msg), &mlen)) return 1;
        crypto_sign_keypair(pk, sk);
        crypto_sign_detached(sig, &siglen, msg, mlen, sk);
        if (write_file(argv[3], pk, sizeof(pk))) return 1;
        if (write_file(argv[4], sig, (size_t)siglen)) return 1;
        return 0;
    }

    if (strcmp(argv[1], "ed25519_verify") == 0 && argc == 5) {
        unsigned char msg[4096], pk[crypto_sign_PUBLICKEYBYTES], sig[crypto_sign_BYTES];
        size_t mlen, plen, slen;
        if (read_file(argv[2], msg, sizeof(msg), &mlen)) return 1;
        if (read_file(argv[3], pk, sizeof(pk), &plen) || plen != sizeof(pk)) return 1;
        if (read_file(argv[4], sig, sizeof(sig), &slen) || slen != sizeof(sig)) return 1;
        return crypto_sign_verify_detached(sig, msg, mlen, pk) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "mlkem") == 0) {
        unsigned char pk[MLKEM768_PK], sk[MLKEM768_SK], ct[MLKEM768_CT];
        unsigned char ss_e[MLKEM768_SS], ss_d[MLKEM768_SS];
        int rc = 1;
        if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) == 0 &&
            PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss_e, pk) == 0 &&
            PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_d, ct, sk) == 0 &&
            memcmp(ss_e, ss_d, MLKEM768_SS) == 0) {
            printf("ml_kem_768 pk=%d sk=%d ct=%d ss=%d\n",
                   MLKEM768_PK, MLKEM768_SK, MLKEM768_CT, MLKEM768_SS);
            rc = 0;
        }
        return rc;
    }

    fprintf(stderr, "unknown subcommand or wrong argc\n");
    return 2;
}
