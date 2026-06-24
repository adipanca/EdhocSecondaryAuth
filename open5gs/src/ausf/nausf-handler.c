/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sbi-path.h"
#include "nnrf-handler.h"
#include "nausf-handler.h"
//tahap-6
#include "nudm-handler.h"
//end


bool ausf_nausf_auth_handle_authenticate(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_authentication_info_t *AuthenticationInfo = NULL;
    char *serving_network_name = NULL;
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    AuthenticationInfo = recvmsg->AuthenticationInfo;
    if (!AuthenticationInfo) {
        ogs_error("[%s] No AuthenticationInfo", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationInfo", ausf_ue->suci, NULL));
        return false;
    }

    serving_network_name = AuthenticationInfo->serving_network_name;
    if (!serving_network_name) {
        ogs_error("[%s] No servingNetworkName", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No servingNetworkName", ausf_ue->suci, NULL));
        return false;
    }

    if (ausf_ue->serving_network_name)
        ogs_free(ausf_ue->serving_network_name);
    ausf_ue->serving_network_name = ogs_strdup(serving_network_name);
    ogs_assert(ausf_ue->serving_network_name);

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_get,
            ausf_ue, stream, AuthenticationInfo->resynchronization_info);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}

//tahap-6
static void print_hex(const char *tag, const uint8_t *buf, int len) {
    char hex[4096] = {0};
    char *p = hex;
    int i;  // ← pindah ke luar loop

    for (i = 0; i < len && i < 1167; i++) {
        p += sprintf(p, "%02X", buf[i]);
        if (i < len - 1)
            *p++ = ' ';
    }

    ogs_info("%s [%d bytes]: %s", tag, len, hex);
}
//end

bool ausf_nausf_auth_handle_authenticate_confirmation(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_info("ConfirmationData SUCCESS ausf_nausf_auth_handle_authenticate_confirmation");
    OpenAPI_confirmation_data_t *ConfirmationData = NULL;
    char *res_star_string = NULL;
    uint8_t res_star[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    ConfirmationData = recvmsg->ConfirmationData;
    if (!ConfirmationData) {
        ogs_error("[%s] No ConfirmationData", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No ConfirmationData", ausf_ue->suci, NULL));
        return false;
    }

    res_star_string = ConfirmationData->res_star;
    if (!res_star_string) {
        ogs_error("[%s] No ConfirmationData.resStar", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No ConfirmationData.resStar", ausf_ue->suci, NULL));
        return false;
    }

    if (ausf_ue->auth_type == OpenAPI_auth_type_EAP_AKA_PRIME) {
        char *eap_payload_b64_string = NULL;
        eap_payload_b64_string = ConfirmationData->eap_payload;
        ogs_info("EAP B64 = [%s]",eap_payload_b64_string);

        if (!eap_payload_b64_string) {
            ogs_error("[%s] No EAP Payload in ConfirmationData", ausf_ue->suci);
            return false;
        }

        // uint8_t decoded_payload[512]; // Ukuran sesuai batas maksimum EAP
        uint8_t decoded_payload[2048]; 
        int decoded_len = ogs_base64_decode(
            (char *)decoded_payload,
            eap_payload_b64_string);

        if (decoded_len <= 0) {
            ogs_error("[%s] Failed to decode Base64 EAP Payload", ausf_ue->suci);
            return false;
        }

        // Simpan hasil decode ke ausf_ue
        ausf_ue->eap_payload = ogs_malloc(decoded_len);
        memcpy(ausf_ue->eap_payload, decoded_payload, decoded_len);
        ausf_ue->eap_payload_len = decoded_len;

        ogs_info("[%s] EAP Payload decoded successfully, length = %d", ausf_ue->suci, decoded_len);
        print_hex("Decoded EAP Payload", ausf_ue->eap_payload, ausf_ue->eap_payload_len);

        

        // print_hex("EAP PAYLOAD = ", ausf_ue->eap_payload, ausf_ue->eap_payload_len);
        EapMessage eap_msg;
        int p = parse_eap_aka_prime(
            &eap_msg,
            ausf_ue->eap_payload, 
            ausf_ue->eap_payload_len
        );

        print_hex("RES = ", eap_msg.attributes.res, eap_msg.attributes.res_len);
        ogs_info("[%d] RES LEN", eap_msg.attributes.res_len);
        print_hex("XRES = ", ausf_ue->xres, OGS_MAX_RES_LEN );
        ogs_info("[%d] XRES LEN", OGS_MAX_RES_LEN);

        print_hex("PUB ECDHE = ", eap_msg.attributes.pub_ecdhe, eap_msg.attributes.pub_ecdhe_len);
        ogs_info("[%d] PUB ECDHE LEN", eap_msg.attributes.pub_ecdhe_len);

        print_hex("PUB HYBRID = ", eap_msg.attributes.pub_hybrid, eap_msg.attributes.pub_hybrid_len);
        ogs_info("[%d] PUB HYBRID LEN", eap_msg.attributes.pub_hybrid_len);
        
        if (p != OGS_OK) {
            ogs_error("[%s] Failed to parse attributes", ausf_ue->suci);
            return false;
        }

        print_hex("After PARSE parse_eap_aka_prime EAP PAYLOAD = ", ausf_ue->eap_payload, ausf_ue->eap_payload_len);
        print_hex("K_aut (from AV)", ausf_ue->k_aut, 32);

        //tahap-9 //Prime-FS
        if (eap_msg.attributes.pub_ecdhe && eap_msg.attributes.pub_ecdhe_len >= 32) {
            ogs_info("Received valid AT_PUB_ECDHE, calculating X25519 shared secret...");
        
            // uint8_t ue_pub_key[36];
            // memcpy(ue_pub_key, eap_msg.attributes.pub_ecdhe, 36);  // Ambil 36-byte public key dari UE

            uint8_t ue_pub_key[32];
            memcpy(ue_pub_key, eap_msg.attributes.pub_ecdhe + 4, 32);  // skip 4-byte reserved

        
            uint8_t shared_secret[32];
        
            print_hex("Private Key OPEN5GS: ", ausf_ue->priv_key, 32);
            print_hex("Public Key OPEN5GS: ", ausf_ue->pub_key.value, 32);

            print_hex("Public Key UERANSIM: ", ue_pub_key, 32);

            // Hitung shared secret menggunakan kunci privat AUSF (yang sudah diklamping sebelumnya)
            curve25519_donna(shared_secret, ausf_ue->priv_key, ue_pub_key);
        
            print_hex("Shared Secret", shared_secret, 32);

            //tanpa imsi- karena di ueransim tanpa imsi-
            const char *supi = ausf_ue->supi;           // "imsi-999700000000001"
            const char *identity = supi + 5;           // skip "imsi-"
            size_t identity_len = strlen(identity);

            ogs_info("SUPI with prefix : %s", supi);
            ogs_info("SUPI for PRF     : %s", identity);
        
            // Di sini kamu bisa langsung panggil fungsi derivasi MK_ECDHE
            // Contoh: derive_mk_ecdhe(ik_prime, ck_prime, shared_secret, supi_string);

            uint8_t ik_prime[16];
            uint8_t ck_prime[16];

            memcpy(ik_prime, ausf_ue->ik_prime, 16);  // ← hanya ambil 16 byte pertama
            memcpy(ck_prime, ausf_ue->ck_prime, 16);

            // Open5GS
            ogs_info("============================== PRINT PARAMETER OPEN5GS ============================= ");
            print_hex("IK'", ik_prime, 16);
            print_hex("CK'", ck_prime, 16);
            print_hex("Shared Secret", shared_secret, 32);
            ogs_info("SUPI for PRF %s",identity);
            ogs_info("============================== PRINT PARAMETER OPEN5GS ============================= ");


            ogs_kdf_prf_prime_fs(
                ik_prime,  // ← 16 byte
                ck_prime,  // ← 16 byte
                shared_secret,      // ← 32 byte
                (const uint8_t *)identity, 
                identity_len,
                ausf_ue->mk_ecdhe); // ← 208 byte output

            print_hex("MK_ECDHE GENERATE FOR PRIME FS =", ausf_ue->mk_ecdhe, 208);

            // K_re    = MK_ECDHE[0..31]       (offset 0, 32 byte)
            memcpy(ausf_ue->k_re, ausf_ue->mk_ecdhe + 0, 32);

            // MSK     = MK_ECDHE[32..95]      (offset 32, 64 byte → RFC says 512 bits = 64 byte)
            memcpy(ausf_ue->msk, ausf_ue->mk_ecdhe + 32, 64);

            // EMSK    = MK_ECDHE[96..159]     (offset 96, 64 byte)
            memcpy(ausf_ue->emsk, ausf_ue->mk_ecdhe + 96, 64);

            // KAUSF   = MK_ECDHE[96..108]    (offset 96, 32 byte)
            memset(ausf_ue->kausf, 0, 32);
            memcpy(ausf_ue->kausf, ausf_ue->mk_ecdhe + 96, 32);

            print_hex("K_RE FOR PRIME FS =", ausf_ue->k_re, 208);
            print_hex("K_AUSF GENERATE FOR PRIME FS =", ausf_ue->kausf, 32);

            //hitung MAC FS
            uint8_t mac_result[16];
            bool mac_ok = CalculateMacForEapAkaPrime(
                ausf_ue->k_aut, 32,
                ausf_ue->eap_payload,
                ausf_ue->eap_payload_len,
                mac_result);

            print_hex("MAC from UE", eap_msg.attributes.mac, 16);
            print_hex("MAC calculated", mac_result, 16);

            if (!mac_ok) {
                ogs_error("Failed to calculate MAC");
                return false;
            }

            if (memcmp(eap_msg.attributes.mac, mac_result, 16) != 0) {
                ogs_error("[%s] MAC FS mismatch ", ausf_ue->suci);
                print_hex("UE MAC FS ", eap_msg.attributes.mac, 16);
                print_hex("AUSF MAC FS ", mac_result, 16);
                ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                return false;
            }

        }
        //end
        //tahap-10 //HPQC
        else if (eap_msg.attributes.pub_hybrid && eap_msg.attributes.pub_hybrid_len >= 1120) {
            ogs_info("Received valid AT_PUB_HYBRID, calculating HPQC shared secret...");

            // Pisahkan ML-KEM ciphertext (ct_M) dan X25519 public key (pub_X25519)
            const uint8_t *ct_m = eap_msg.attributes.pub_hybrid;             // 1088 bytes
            const uint8_t *ue_pub_x25519 = eap_msg.attributes.pub_hybrid + 1088;  // 32 bytes
        
            // Decapsulate ct_M menggunakan ML-KEM private key
            uint8_t shared_secret_m[32];
            ogs_mlkem_decapsulate(ct_m, ausf_ue->mlkem_sk, shared_secret_m);
        
            print_hex("Shared Secret ML-KEM", shared_secret_m, 32);
        
            // Hitung shared secret X25519
            uint8_t shared_secret_x[32];
            curve25519_donna(shared_secret_x, ausf_ue->priv_key, ue_pub_x25519);
        
            print_hex("Shared Secret X25519", shared_secret_x, 32);
        
            // Combine hybrid_shared_secret = ss_M || ss_X25519
            uint8_t hybrid_shared_secret[64];
            memcpy(hybrid_shared_secret, shared_secret_m, 32);
            memcpy(hybrid_shared_secret + 32, shared_secret_x, 32);
        
            print_hex("Hybrid Shared Secret", hybrid_shared_secret, 64);
        
            // SUPI Handling
            const char *supi = ausf_ue->supi;
            const char *identity = supi + 5; // skip "imsi-"
            size_t identity_len = strlen(identity);
        
            ogs_info("SUPI with prefix : %s", supi);
            ogs_info("SUPI for PRF     : %s", identity);
        
            // Derive MK_HYBRID
            uint8_t ik_prime[16];
            uint8_t ck_prime[16];
            memcpy(ik_prime, ausf_ue->ik_prime, 16);
            memcpy(ck_prime, ausf_ue->ck_prime, 16);
        
            ogs_info("============================== PRINT PARAMETER OPEN5GS (HPQC) ============================= ");
            print_hex("IK'", ik_prime, 16);
            print_hex("CK'", ck_prime, 16);
            print_hex("Hybrid Shared Secret", hybrid_shared_secret, 64);
            ogs_info("SUPI for PRF %s", identity);
            ogs_info("============================== PRINT PARAMETER OPEN5GS (HPQC) ============================= ");
        
            ogs_kdf_prf_prime_fs(
                ik_prime,
                ck_prime,
                hybrid_shared_secret, // ← sekarang 64 bytes
                (const uint8_t *)identity,
                identity_len,
                ausf_ue->mk_hybrid); // output 208 bytes
        
            // Derive K_re, MSK, EMSK, KAUSF
            memcpy(ausf_ue->k_re, ausf_ue->mk_hybrid + 0, 32);
            memcpy(ausf_ue->msk, ausf_ue->mk_hybrid + 32, 64);
            memcpy(ausf_ue->emsk, ausf_ue->mk_hybrid + 96, 64);
            memset(ausf_ue->kausf, 0, 32);
            memcpy(ausf_ue->kausf, ausf_ue->mk_hybrid + 96, 32);
        
            print_hex("K_RE FOR HPQC =", ausf_ue->k_re, 32);
            print_hex("MK_ECDHE GENERATE FOR HPQC =", ausf_ue->mk_hybrid, 208);
            print_hex("K_AUSF GENERATE FOR HPQC =", ausf_ue->kausf, 32);
        
            // Hitung MAC
            uint8_t mac_result[16];
            bool mac_ok = CalculateMacForEapAkaPrime(
                ausf_ue->k_aut, 32,
                ausf_ue->eap_payload,
                ausf_ue->eap_payload_len,
                mac_result);
        
            print_hex("MAC from UE", eap_msg.attributes.mac, 16);
            print_hex("MAC calculated", mac_result, 16);
        
            if (!mac_ok) {
                ogs_error("Failed to calculate MAC");
                return false;
            }
        
            if (memcmp(eap_msg.attributes.mac, mac_result, 16) != 0) {
                ogs_error("[%s] MAC HPQC mismatch ", ausf_ue->suci);
                print_hex("UE MAC HPQC ", eap_msg.attributes.mac, 16);
                print_hex("AUSF MAC HPQC ", mac_result, 16);
                ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                return false;
            }
        }
        //end
        else {
            //bukan Prime-FS / HPQC
            //hitung mac
            uint8_t mac_result[16];
            bool mac_ok = CalculateMacForEapAkaPrime(
                ausf_ue->k_aut, 32,
                ausf_ue->eap_payload,
                ausf_ue->eap_payload_len,
                mac_result);

            print_hex("MAC from UE", eap_msg.attributes.mac, 16);
            print_hex("MAC calculated", mac_result, 16);

            if (!mac_ok) {
                ogs_error("Failed to calculate MAC");
                return false;
            }

            if (memcmp(eap_msg.attributes.mac, mac_result, 16) != 0) {
                ogs_error("[%s] MAC mismatch", ausf_ue->suci);
                print_hex("UE MAC", eap_msg.attributes.mac, 16);
                print_hex("AUSF MAC", mac_result, 16);
                ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                return false;
            }
        }
        



        if (memcmp(eap_msg.attributes.res, ausf_ue->xres, eap_msg.attributes.res_len) != 0){

            ogs_log_hexdump(OGS_LOG_WARN, eap_msg.attributes.res, eap_msg.attributes.res_len);
            ogs_log_hexdump(OGS_LOG_WARN, ausf_ue->xres, OGS_MAX_RES_LEN);

            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
            ogs_error("[%s] FAILED to Authentication RES = XRES", ausf_ue->suci);
        } else {
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
            ogs_info("[%s] SUCCESS to Authentication RES = XRES", ausf_ue->suci);

            int payload_len = 0;
            uint8_t *payload = build_eap_success(&payload_len, ausf_ue->eap_identifier);
            ogs_assert(payload);
            
            // Base64 encode
            char encoded[512] = {0};
            if (ogs_base64_encode(encoded, (const char *)payload, payload_len) <= 0) {
                ogs_error("[%s] Failed to Base64 encode EAP-Success", ausf_ue->suci);
                ogs_free(payload);
                return false;
            }
            
            char *payload_b64 = ogs_strdup(encoded);
            ogs_assert(payload_b64);

            //modif disini untuk penambahan pengiriman eap payload

            // Simpan ke ausf_ue agar bisa dikirim di fungsi build_result_confirmation_inform()
            ausf_ue->eap_payload_b64 = payload_b64;
            ausf_ue->auth_type = OpenAPI_auth_type_EAP_AKA_PRIME;

        }

    }else{
        ogs_ascii_to_hex(res_star_string, strlen(res_star_string),
                res_star, sizeof(res_star));

        if (memcmp(res_star, ausf_ue->xres_star, OGS_MAX_RES_LEN) != 0) {
            ogs_log_hexdump(OGS_LOG_WARN, res_star, OGS_MAX_RES_LEN);
            ogs_log_hexdump(OGS_LOG_WARN, ausf_ue->xres_star, OGS_MAX_RES_LEN);

            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
        } else {
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
        }

    }

    r = ausf_sbi_discover_and_send(
        OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
        ausf_nudm_ueau_build_result_confirmation_inform,
        ausf_ue, stream, NULL);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}

bool ausf_nausf_auth_handle_authenticate_delete(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_auth_removal_ind,
            ausf_ue, stream, NULL);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}

//tahap-6
int parse_eap_aka_prime(EapMessage *msg, const uint8_t *eap_payload, 
    size_t length)
{
    ogs_info("Parsing EAP-AKA' payload...");
    ogs_info("EAP Payload Length: %zu", length);
    print_hex("EAP Payload:", eap_payload, length);

    size_t pos = 7;  // Skip 7-byte EAP header (starts from AT_RES)
    msg->attributes.res = NULL;
    msg->attributes.res_len = 0;
    msg->attributes.mac = NULL;
    msg->attributes.mac_len = 0;
    msg->attributes.kdf = NULL;
    msg->attributes.kdf_len = 0;

    //tahap-9 //Prime-FS
    msg->attributes.pub_ecdhe = NULL;
    msg->attributes.pub_ecdhe_len = 0;
    //end

    //tahap-10 //Prime-FS
    msg->attributes.pub_hybrid = NULL;
    msg->attributes.pub_hybrid_len = 0;
    //end

    while (pos < length) {
        uint8_t attribute_type = eap_payload[pos++];

        switch (attribute_type) {
            case 0x03: // AT_RES
                pos += 3;
                msg->attributes.res = (uint8_t *) &eap_payload[pos];
                msg->attributes.res_len = 7;
                pos += 7;
                ogs_info("Parsed AT_RES\n");
                break;

            case 0x0B: // AT_MAC
                pos += 3;
                msg->attributes.mac = (uint8_t *) &eap_payload[pos];
                msg->attributes.mac_len = 13;
                pos += 13;
                ogs_info("Parsed AT_MAC\n");
                break;

            case 0x18: // AT_KDF
                msg->attributes.kdf = (uint8_t *) &eap_payload[pos];
                msg->attributes.kdf_len = 3;
                pos += 3;
                ogs_info("Parsed AT_KDF\n");
                break;

            //tahap-9 //Prime-FS
            case 0x98: // AT_PUB_ECDHE
                pos += 1;
                msg->attributes.pub_ecdhe = (uint8_t *) &eap_payload[pos];
                msg->attributes.pub_ecdhe_len = 36; //+2 length
                pos += 36;
                ogs_info("Parsed AT_PUB_ECDHE\n");
                break;        
            //end

            //tahap-10 //HPQC
            case 0xA0: // AT_PUB_ECDHE
                pos += 2; //kaena length 2
                msg->attributes.pub_hybrid = (uint8_t *) &eap_payload[pos];
                msg->attributes.pub_hybrid_len = 1120; //+2 length
                pos += 1120;
                ogs_info("Parsed AT_PUB_HYBRID\n");
                break;        
            //end

            default:
                ogs_info("Unknown Attribute Type 0x%02X, skipping\n", attribute_type);
                break;
        }
    }

    return 0;
}

//tahap-8
uint8_t *build_eap_success(int *len, uint8_t identifier) {
    uint8_t *payload = ogs_malloc(4);
    ogs_assert(payload);
    
    payload[0] = 0x03;          // Code: EAP-Success
    // payload[1] = identifier;    // Identifier (harus cocok dengan request)
    payload[1] = 0x01;    // Identifier (harus cocok dengan request)
    payload[2] = 0x00;
    payload[3] = 0x04;
    
    *len = 4;
    return payload;
}
//end
//end