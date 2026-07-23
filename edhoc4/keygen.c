/*
 * keygen.c — provisioning tool for EAP-EDHOC method 4 (SIGMA XWING).
 *
 * Generates a matched credential set shared by the two live peers:
 *   <dir>/server.creds  full DN-AAA (responder) credentials  [secret]
 *   <dir>/server.pub    DN-AAA static XWING public key
 *   <dir>/ue.creds      full UE (initiator) credentials       [secret]
 *   <dir>/ue.pub        UE static XWING public key
 *
 * FreeRADIUS loads server.creds + ue.pub; UERANSIM loads ue.creds + server.pub.
 * Run once during provisioning so both sides pin each other's static key.
 */
#include "edhoc4.h"

#include <stdio.h>
#include <string.h>
#include <sodium.h>

static int save_pair(const char *dir, const char *name,
                     const edhoc4_creds *c)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s.creds", dir, name);
    if (edhoc4_creds_save(p, c) != E4_OK) { fprintf(stderr, "write %s failed\n", p); return 1; }
    snprintf(p, sizeof(p), "%s/%s.pub", dir, name);
    if (edhoc4_pub_save(p, c) != E4_OK) { fprintf(stderr, "write %s failed\n", p); return 1; }
    return 0;
}

int main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }

    edhoc4_creds server, ue;
    uint8_t id_srv[E4_ID_CRED] = { 0x00, 0x00, 0x02 };  /* DN-AAA */
    uint8_t id_ue[E4_ID_CRED]  = { 0x00, 0x00, 0x01 };  /* UE     */

    if (edhoc4_gen_creds(&server, id_srv) != E4_OK) { fprintf(stderr, "gen server failed\n"); return 1; }
    if (edhoc4_gen_creds(&ue, id_ue) != E4_OK) { fprintf(stderr, "gen ue failed\n"); return 1; }

    if (save_pair(dir, "server", &server)) return 1;
    if (save_pair(dir, "ue", &ue)) return 1;

    printf("provisioned EDHOC method-4 credentials in %s/\n", dir);
    printf("  server.creds (%zu B), server.pub (%d B)\n", sizeof(server), E4_XWING_PK);
    printf("  ue.creds     (%zu B), ue.pub     (%d B)\n", sizeof(ue), E4_XWING_PK);
    return 0;
}
