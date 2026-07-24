/*
 * keygen03.c — provisioning tool for classical EAP-EDHOC methods 0..3.
 *
 * Emits a matched credential set shared by the two peers:
 *   <dir>/server03.creds  DN-AAA (responder) credentials  [secret]
 *   <dir>/server03.pub    DN-AAA static public keys (Ed25519 vk + X25519 pk)
 *   <dir>/ue03.creds      UE (initiator) credentials       [secret]
 *   <dir>/ue03.pub        UE static public keys
 *
 * FreeRADIUS loads server03.creds + ue03.pub; the harness/UE loads ue03.creds
 * + server03.pub, so both sides pin each other's static keys.
 */
#include "edhoc03.h"

#include <stdio.h>
#include <sodium.h>

static int save_pair(const char *dir, const char *name, const edhoc03_creds *c)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s.creds", dir, name);
    if (edhoc03_creds_save(p, c) != E3_OK) { fprintf(stderr, "write %s failed\n", p); return 1; }
    snprintf(p, sizeof(p), "%s/%s.pub", dir, name);
    if (edhoc03_pub_save(p, c) != E3_OK) { fprintf(stderr, "write %s failed\n", p); return 1; }
    return 0;
}

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    edhoc03_creds server, ue;
    uint8_t id_srv[E3_ID_CRED] = { 0x00, 0x00, 0x02 };  /* DN-AAA */
    uint8_t id_ue[E3_ID_CRED]  = { 0x00, 0x00, 0x01 };  /* UE     */

    if (edhoc03_gen_creds(&server, id_srv) != E3_OK) { fprintf(stderr, "gen server failed\n"); return 1; }
    if (edhoc03_gen_creds(&ue, id_ue) != E3_OK) { fprintf(stderr, "gen ue failed\n"); return 1; }

    if (save_pair(dir, "server03", &server)) return 1;
    if (save_pair(dir, "ue03", &ue)) return 1;

    printf("provisioned classical EDHOC (methods 0-3) credentials in %s/\n", dir);
    return 0;
}
