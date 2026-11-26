/*
 * inline_identity.c — transcript of method-4 handshakes under a
 * deterministic RNG, so that two builds of edhoc4.c can be compared byte for
 * byte (inline_identity.sh: the v5 core before the next-key pool against
 * the current core in inline mode, which is what an unconfigured process
 * runs). Prints one SHA-256 per handshake over message_1..4 || MSK || EMSK
 * || Npk_A || Npk_B, with key rotation (commit) between handshakes.
 * Test only: the RNG here is NOT random.
 */
#include "edhoc4.h"
#include <stdio.h>
#include <string.h>
#include <sodium.h>

static uint8_t g_seed[32];
static uint64_t g_ctr;

static void det_buf(void *buf, size_t n)
{
    uint8_t in[40];
    memcpy(in, g_seed, 32);
    memcpy(in + 32, &g_ctr, 8);
    g_ctr++;
    uint8_t s[32];
    crypto_hash_sha256(s, in, sizeof(in));
    randombytes_buf_deterministic(buf, n, s);
}
static uint32_t det_random(void) { uint32_t r; det_buf(&r, sizeof(r)); return r; }
static const char *det_name(void) { return "deterministic-test"; }
static struct randombytes_implementation det_impl = {
    .implementation_name = det_name, .random = det_random, .buf = det_buf,
};
/* PQClean's randombytes (ML-DSA signing randomness), same stream */
int PQCLEAN_randombytes(uint8_t *out, size_t n) { det_buf(out, n); return 0; }

static edhoc4_creds g_ue;
static uint8_t g_id[E4_ID_CRED] = { 0, 0, 1 };
static int lookup(const uint8_t id[E4_ID_CRED], uint8_t pk_a[E4_XWING_PK],
                  uint8_t vk_i[E4_MLDSA_PK], void *arg)
{
    (void)arg;
    if (memcmp(id, g_id, E4_ID_CRED) != 0) return -1;
    memcpy(pk_a, g_ue.kem_pk, E4_XWING_PK);
    memcpy(vk_i, g_ue.sig_vk, E4_MLDSA_PK);
    return 0;
}

int main(void)
{
    static uint8_t m1[E4_MAX_MSG], m2[E4_MAX_MSG], m3[E4_MAX_MSG], m4[E4_MAX_MSG];
    static edhoc4_ctx I, R;
    edhoc4_creds aaa;
    uint8_t ue_peer[E4_XWING_PK], aaa_peer[E4_XWING_PK], idR[E4_ID_CRED] = { 0, 0, 2 };
    randombytes_set_implementation(&det_impl);
    if (sodium_init() < 0) return 2;
    if (edhoc4_gen_creds(&g_ue, g_id) || edhoc4_gen_creds(&aaa, idR)) return 2;
    memcpy(ue_peer, aaa.kem_pk, E4_XWING_PK);
    memcpy(aaa_peer, g_ue.kem_pk, E4_XWING_PK);
    for (int k = 0; k < 3; k++) {
        size_t n1, n2, n3, n4;
        edhoc4_init_initiator(&I, &g_ue, ue_peer);
        edhoc4_init_responder(&R, &aaa, aaa_peer);
        edhoc4_set_lookup(&R, lookup, NULL);
        if (edhoc4_i_make_msg1(&I, m1, sizeof(m1), &n1) ||
            edhoc4_r_handle_msg1(&R, m1, n1, m2, sizeof(m2), &n2) ||
            edhoc4_i_handle_msg2(&I, m2, n2, m3, sizeof(m3), &n3) ||
            edhoc4_r_handle_msg3(&R, m3, n3, m4, sizeof(m4), &n4) ||
            edhoc4_i_handle_msg4(&I, m4, n4)) { printf("handshake %d failed\n", k); return 1; }
        crypto_hash_sha256_state st;
        uint8_t h[32];
        crypto_hash_sha256_init(&st);
        crypto_hash_sha256_update(&st, m1, n1);
        crypto_hash_sha256_update(&st, m2, n2);
        crypto_hash_sha256_update(&st, m3, n3);
        crypto_hash_sha256_update(&st, m4, n4);
        crypto_hash_sha256_update(&st, I.msk, E4_MSK_LEN);
        crypto_hash_sha256_update(&st, I.emsk, E4_EMSK_LEN);
        crypto_hash_sha256_update(&st, I.new_pk, E4_XWING_PK);
        crypto_hash_sha256_update(&st, R.new_pk, E4_XWING_PK);
        crypto_hash_sha256_final(&st, h);
        printf("handshake %d: %zu/%zu/%zu/%zu B sha256=", k, n1, n2, n3, n4);
        for (int i = 0; i < 32; i++) printf("%02x", h[i]);
        printf("\n");
        if (edhoc4_commit(&I, &g_ue, ue_peer) || edhoc4_commit(&R, &aaa, aaa_peer)) return 1;
    }
    return 0;
}
