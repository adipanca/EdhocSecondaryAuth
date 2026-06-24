/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "nudm-handler.h"

// //tahap-2
static void print_hex(const char *tag, const uint8_t *buf, int len) {
    char hex[512] = {0};
    char *p = hex;
    int i;  // ← pindah ke luar loop

    for (i = 0; i < len && i < 128; i++) {
        p += sprintf(p, "%02X", buf[i]);
        if (i < len - 1)
            *p++ = ' ';
    }

    ogs_info("%s [%d bytes]: %s", tag, len, hex);
}

bool CalculateMacForEapAkaPrime(
    const uint8_t *mk, size_t mk_len,
    const uint8_t *eap_payload, size_t eap_len,
    uint8_t *mac_out)
{
    ogs_assert(mk);
    ogs_assert(eap_payload);
    ogs_assert(mac_out);

    // Batasi panjang maksimal payload
    // if (eap_len > 512) {
    if (eap_len > 2048) {
        ogs_error("EAP payload too large: %zu bytes", eap_len);
        return false;
    }

    // uint8_t payload_copy[512];
    // memcpy(payload_copy, eap_payload, eap_len);

    //pakai ini lebih aman untuk HYBRID
    uint8_t *payload_copy = ogs_malloc(eap_len);
    if (!payload_copy) return false;

    memcpy(payload_copy, eap_payload, eap_len);


    // Cari IEI = 0x0B (AT_MAC)
    int offset = -1;
    int i;
    for (i = 0; i < (int)(eap_len - 2); i++) {
        if (payload_copy[i] == 0x0B) { // AT_MAC
            uint8_t len = payload_copy[i + 1];
            if (len == 5) {  // Panjang harus 5 (20 bytes)
                offset = i;
                break;
            }
        }
    }

    if (offset < 0 || offset + 20 > (int)eap_len) {
        ogs_error("AT_MAC IE not found or invalid (offset=%d, len=%zu)", offset, eap_len);
        return false;
    }

    // Kosongkan field MAC (16 byte) sebelum HMAC
    memset(&payload_copy[offset + 4], 0x00, 16);

    // Hitung HMAC-SHA256 dan ambil 16 byte pertama (truncated)
    uint8_t hmac_result[OGS_SHA256_DIGEST_SIZE];
    ogs_hmac_sha256(mk, mk_len, payload_copy, eap_len, hmac_result, sizeof(hmac_result));

    memcpy(mac_out, hmac_result, 16);

    ogs_free(payload_copy); 

    // Log tambahan
    print_hex("MAC (calculated)", mac_out, 16);
    return true;
}

int build_eap_aka_prime_header(uint8_t *payload, uint8_t code, uint8_t identifier) {
    int offset = 0;

    payload[offset++] = code;         // EAP Code: 1 = Request
    payload[offset++] = identifier;   // EAP Identifier
    payload[offset++] = 0x00;         // EAP Length (MSB, placeholder)
    payload[offset++] = 0x00;         // EAP Length (LSB, placeholder)

    payload[offset++] = 0x32;         // Type = 50 (EAP-AKA')
    payload[offset++] = 0x01;         // Subtype = Challenge
    payload[offset++] = 0x00;         // Reserved
    payload[offset++] = 0x00;

    return offset; // start offset for IEs
}


int add_at_rand(uint8_t *payload, int offset, const uint8_t *rand) {
    payload[offset++] = AT_RAND;
    payload[offset++] = 0x05;
    payload[offset++] = 0x00;
    payload[offset++] = 0x00;
    memcpy(&payload[offset], rand, 16);
    return offset + 16;
}

int add_at_autn(uint8_t *payload, int offset, const uint8_t *autn) {
    payload[offset++] = AT_AUTN;
    payload[offset++] = 0x05;
    payload[offset++] = 0x00;
    payload[offset++] = 0x00;
    memcpy(&payload[offset], autn, 16);
    return offset + 16;
}

int add_at_kdf(uint8_t *payload, int offset, uint16_t kdf_id) {
    payload[offset++] = AT_KDF;
    payload[offset++] = 0x01;
    payload[offset++] = (kdf_id >> 8) & 0xFF;
    payload[offset++] = kdf_id & 0xFF;
    return offset;
}

// tanpa padding 00 00 di akhir agar UERANSIM berhasil PARSE
int add_at_kdf_input(uint8_t *payload, int offset, const char *snn) {
    ogs_assert(payload);
    ogs_assert(snn);

    int snn_len = strlen(snn);

    int attr_len = (2 + snn_len + 3) / 4;  // langsung hitung

    // Safety check
    if (snn_len > 255) {
        ogs_error("SNN length too long: %d", snn_len);
        return offset;
    }

    // IEI
    payload[offset++] = AT_KDF_INPUT;  // 0x17

    // Length in units of 4 bytes
    payload[offset++] = (uint8_t)attr_len;

    // Actual Network Name Length (2 bytes)
    payload[offset++] = (uint8_t)((snn_len >> 8) & 0xFF);
    payload[offset++] = (uint8_t)(snn_len & 0xFF);

    // Network Name (SNN)
    memcpy(&payload[offset], snn, snn_len);
    offset += snn_len;

    return offset;
}


int add_at_mac(uint8_t *payload, int offset, uint8_t **mac_ptr) {
    payload[offset++] = AT_MAC;
    payload[offset++] = 0x05;
    payload[offset++] = 0x00;
    payload[offset++] = 0x00;
    *mac_ptr = &payload[offset];
    memset(*mac_ptr, 0x00, 16);
    return offset + 16;
}

// //end

//tahap-9 //Prime-FS
int add_at_kdf_fs(uint8_t *payload, int offset, uint8_t fs_kdf_id) {
    payload[offset++] = AT_KDF_FS;    // 153
    payload[offset++] = 0x01;         // Length = 1 word (4 bytes)
    payload[offset++] = fs_kdf_id;    // ← ID = 1 (misalnya untuk X25519)
    payload[offset++] = 0x00;         // Padding
    return offset;
}

int add_at_pub_ecdhe(uint8_t *payload, int offset, const uint8_t *pub_key) {
    payload[offset++] = AT_PUB_ECDHE; // 152
    payload[offset++] = 0x09;         // 9 * 4 = 36 bytes
    payload[offset++] = 0x00;         // Reserved
    payload[offset++] = 0x00;
    memcpy(&payload[offset], pub_key, 32);
    return offset + 32;
}
//end

//tahap-10 //HPQC
// int add_at_pub_hybrid(uint8_t *payload, int offset, const uint8_t *mlkem_pub_key, const uint8_t *x25519_pub_key) {
//     payload[offset++] = AT_PUB_HYBRID; // Misal Type ID baru, contoh 160 (nanti final dari IANA)
//     payload[offset++] = 0x131;           // Length dalam unit 4 bytes (48 * 4 = 192 bytes)
//     payload[offset++] = 0x00;           // Reserved
//     payload[offset++] = 0x00;

//     memcpy(&payload[offset], mlkem_pub_key, 1184); // ML-KEM-768 public key
//     offset += 1184;

//     memcpy(&payload[offset], x25519_pub_key, 32);  // X25519 public key
//     offset += 32;

//     return offset;
// }
int add_at_pub_hybrid(uint8_t *payload, int offset, const uint8_t *mlkem_pub_key, const uint8_t *x25519_pub_key) {
    const uint16_t total_length_bytes = 1184 + 32; // ML-KEM + X25519
    const uint16_t attribute_length_in_words = (4 + total_length_bytes) / 4; // Termasuk type(1) + len(2) + reserved(1)

    // AT Header
    payload[offset++] = AT_PUB_HYBRID;              // Type
    payload[offset++] = (attribute_length_in_words >> 8) & 0xFF; // Length high byte (big-endian)
    payload[offset++] = attribute_length_in_words & 0xFF;        // Length low byte (big-endian)
    payload[offset++] = 0x00;                       // Reserved

    // Value
    memcpy(&payload[offset], mlkem_pub_key, 1184);  // ML-KEM-768 Public Key
    offset += 1184;

    memcpy(&payload[offset], x25519_pub_key, 32);   // X25519 Public Key
    offset += 32;

    return offset;
}

//end

static const char *links_member_name(OpenAPI_auth_type_e auth_type)
{
    if (auth_type == OpenAPI_auth_type_5G_AKA ||
        auth_type == OpenAPI_auth_type_EAP_AKA_PRIME) {
        return OGS_SBI_RESOURCE_NAME_5G_AKA;
    } else if (auth_type == OpenAPI_auth_type_EAP_TLS) {
        return OGS_SBI_RESOURCE_NAME_EAP_SESSION;
    }

    ogs_assert_if_reached();
    return NULL;
}

bool ausf_nudm_ueau_handle_get(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;

    char hxres_star_string[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];

    OpenAPI_authentication_info_result_t *AuthenticationInfoResult = NULL;
    OpenAPI_authentication_vector_t *AuthenticationVector = NULL;
    OpenAPI_ue_authentication_ctx_t UeAuthenticationCtx;
    OpenAPI_ue_authentication_ctx_5g_auth_data_t AV5G_AKA;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_links_value_schema_t LinksValueSchemeValue;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    ogs_assert(recvmsg);

    AuthenticationInfoResult = recvmsg->AuthenticationInfoResult;
    if (!AuthenticationInfoResult) {
        ogs_error("[%s] No AuthenticationInfoResult", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationInfoResult", ausf_ue->suci,
                NULL));
        return false;
    }

    /* See TS29.509 6.1.7.3 Application Errors */
    if (AuthenticationInfoResult->auth_type !=
            OpenAPI_auth_type_5G_AKA && AuthenticationInfoResult->auth_type !=
            OpenAPI_auth_type_EAP_AKA_PRIME) {
        ogs_error("[%s] Not supported Auth Method [%d]",
            ausf_ue->suci, AuthenticationInfoResult->auth_type);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_NOT_IMPLEMENTED,
                recvmsg, "Not supported Auth Method", ausf_ue->suci,
                NULL));
        return false;
    }

    AuthenticationVector =
        AuthenticationInfoResult->authentication_vector;
    if (!AuthenticationVector) {
        ogs_error("[%s] No AuthenticationVector", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector", ausf_ue->suci, NULL));
        return false;
    }

    if (AuthenticationVector->av_type != OpenAPI_av_type_5G_HE_AKA && AuthenticationVector->av_type != OpenAPI_av_type_EAP_AKA_PRIME ) {
        ogs_error("[%s] Not supported Auth Method [%d]",
            ausf_ue->suci, AuthenticationVector->av_type);
        /*
        * TS29.509
        * 5.2.2.2.2 5G AKA 
        *
        * On failure or redirection, one of the HTTP status code
        * listed in table 6.1.7.3-1 shall be returned with the message
        * body containing a ProblemDetails structure with the "cause"
        * attribute set to one of the application error listed in
        * Table 6.1.7.3-1.
        * Application Error: AUTHENTICATION_REJECTED
        * HTTP status code: 403 Forbidden 
        * Description: The user cannot be authenticated with this
        * authentication method e.g. only SIM data available 
        */
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_FORBIDDEN,
                recvmsg, "Not supported Auth Method", ausf_ue->suci,
                "AUTHENTICATION_REJECTED"));
        return false;
    }

    if (!AuthenticationVector->rand) {
        ogs_error("[%s] No AuthenticationVector.rand", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.rand", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->xres_star) {
        ogs_error("[%s] No AuthenticationVector.xresStar",
                ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.xresStar", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->autn) {
        ogs_error("[%s] No AuthenticationVector.autn", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.autn", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationVector->kausf) {
        ogs_error("[%s] No AuthenticationVector.kausf", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.kausf", ausf_ue->suci,
                NULL));
        return false;
    }

    if (!AuthenticationInfoResult->supi) {
        ogs_error("[%s] No AuthenticationVector.supi", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationVector.supi", ausf_ue->suci,
                NULL));
        return false;
    }

    /* SUPI */
    if (ausf_ue->supi) {
        ogs_hash_set(ausf_self()->supi_hash,
                ausf_ue->supi, strlen(ausf_ue->supi), NULL);
        ogs_free(ausf_ue->supi);
    }
    ausf_ue->supi = ogs_strdup(AuthenticationInfoResult->supi);
    ogs_assert(ausf_ue->supi);
    ogs_hash_set(ausf_self()->supi_hash,
            ausf_ue->supi, strlen(ausf_ue->supi), ausf_ue);

    ausf_ue->auth_type = AuthenticationInfoResult->auth_type;

    ogs_ascii_to_hex(
        AuthenticationVector->rand,
        strlen(AuthenticationVector->rand),
        ausf_ue->rand, sizeof(ausf_ue->rand));
    ogs_ascii_to_hex(
        AuthenticationVector->xres_star,
        strlen(AuthenticationVector->xres_star),
        ausf_ue->xres_star, sizeof(ausf_ue->xres_star));
    ogs_ascii_to_hex(
        AuthenticationVector->kausf,
        strlen(AuthenticationVector->kausf),
        ausf_ue->kausf, sizeof(ausf_ue->kausf));

    //tahap-2
    if (AuthenticationInfoResult->auth_type == OpenAPI_auth_type_EAP_AKA_PRIME) {
        ogs_info("[%s] Auth Method is EAP_AKA_PRIME", ausf_ue->suci);

        AuthenticationVector = AuthenticationInfoResult->authentication_vector;
        if (!AuthenticationVector || !AuthenticationVector->rand || !AuthenticationVector->autn || !AuthenticationVector->k_aut) {
            ogs_error("[%s] Incomplete EAP-AKA' vector", ausf_ue->suci);
            ogs_assert(true == ogs_sbi_server_send_error(stream,
                OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "Incomplete EAP-AKA' vector", ausf_ue->suci, NULL));
            return false;
        }
    
        // Convert hex strings to binary
        uint8_t xres_bin[OGS_MAX_RES_LEN], rand_bin[OGS_RAND_LEN], autn_bin[OGS_AUTN_LEN], k_aut[32];
        int rand_len = ogs_ascii_to_hex(AuthenticationVector->rand, strlen(AuthenticationVector->rand), rand_bin, sizeof(rand_bin));
        int autn_len = ogs_ascii_to_hex(AuthenticationVector->autn, strlen(AuthenticationVector->autn), autn_bin, sizeof(autn_bin));
        int kaut_len = ogs_ascii_to_hex(AuthenticationVector->k_aut, strlen(AuthenticationVector->k_aut), k_aut, sizeof(k_aut));
        int xres_len = ogs_ascii_to_hex(AuthenticationVector->xres, strlen(AuthenticationVector->xres), xres_bin, sizeof(xres_bin));
    
        //parsing res
        ogs_ascii_to_hex(
            AuthenticationVector->xres,
            strlen(AuthenticationVector->xres),
            ausf_ue->xres, sizeof(ausf_ue->xres));

        //parsing ck_prime
        ogs_ascii_to_hex(
            AuthenticationVector->ck_prime,
            strlen(AuthenticationVector->ck_prime),
            ausf_ue->ck_prime, sizeof(ausf_ue->ck_prime));

        //parsing ik_prime
        ogs_ascii_to_hex(
            AuthenticationVector->ik_prime,
            strlen(AuthenticationVector->ik_prime),
            ausf_ue->ik_prime, sizeof(ausf_ue->ik_prime));
        
        //parsing k_aut
        ogs_ascii_to_hex(
            AuthenticationVector->k_aut,
            strlen(AuthenticationVector->k_aut),
            ausf_ue->k_aut, sizeof(ausf_ue->k_aut));
        
        ausf_ue->xres_len = xres_len;

        //Cek kausf
        print_hex("KAUSF Awal", ausf_ue->kausf, OGS_SHA256_DIGEST_SIZE);  // 32 bytes

        if (rand_len != OGS_RAND_LEN || autn_len != OGS_AUTN_LEN || kaut_len != 32) {
            ogs_error("[%s] Invalid RAND/AUTN/K_AUT length", ausf_ue->suci);
            return false;
        }
    
        print_hex("xres (converted)", xres_bin, xres_len);
        print_hex("RAND (converted)", rand_bin, rand_len);
        print_hex("AUTN (converted)", autn_bin, autn_len);
        print_hex("K_AUT (used for MAC) In AUSF", k_aut, 32);
    
        // Prepare identity and SNN
        const char *supi_str = ausf_ue->supi;
        // const uint8_t *identity = (const uint8_t *)supi_str;
        size_t identity_len = strlen(supi_str);
        const char *snn = ausf_ue->serving_network_name;
    
        ogs_info("SUPI (identity) [%zu bytes]: %s", identity_len, supi_str);
        ogs_info("SNN: %s", snn);

        //tahap-9 //Prime-FS
        print_hex("Private Key In AUSF", ausf_ue->priv_key, 32);
        print_hex("Public Key In AUSF", ausf_ue->pub_key_raw, 32);
        generate_x25519_keypair(ausf_ue->priv_key, ausf_ue->pub_key_raw);
        ausf_ue->pub_key.value = ausf_ue->pub_key_raw;
        ausf_ue->pub_key.len = 32;       
        print_hex("Public Key In AUSF", ausf_ue->pub_key.value, 32); 
        //end

        //tahap-10 //HPQC
        uint8_t mlkem_pk[OGS_MLKEM_PUBLIC_KEY_SIZE];
        uint8_t mlkem_sk[OGS_MLKEM_SECRET_KEY_SIZE];

        if (!ogs_mlkem_keygen(mlkem_pk, mlkem_sk)) {
            ogs_error("Failed to generate ML-KEM keypair");
            return OGS_ERROR;
        }

        /* Simpan sk ke ausf_ue */
        memcpy(ausf_ue->mlkem_sk, mlkem_sk, OGS_MLKEM_SECRET_KEY_SIZE);
        ausf_ue->has_mlkem_sk = true;
        //end
    
        // Build EAP Payload
        // uint8_t eap_payload[512] = {0}; //khusus Prime dan FS
        uint8_t eap_payload[2048] = {0};  // Aman untuk ML-KEM + X25519 + MAC
        uint8_t *mac_ptr = NULL;
        int len = 0;
    
        len = build_eap_aka_prime_header(eap_payload, 0x01, 0x01); // Code=Request, ID=1
        len = add_at_rand(eap_payload, len, rand_bin);
        len = add_at_autn(eap_payload, len, autn_bin);
        len = add_at_kdf(eap_payload, len, 0x0001);
        //tahap-9 //Prime-FS
        len = add_at_kdf_fs(eap_payload, len, 1);                 // Tambahkan ini X25519 → FS-KDF ID = 1 (1 = X25519) untuk Prime FS dan HPQC
        //end
        len = add_at_kdf_input(eap_payload, len, snn);
        //tahap-9 //Prime-FS
        // len = add_at_pub_ecdhe(eap_payload, len, ausf_ue->pub_key.value);     // Tambahkan ini untuk FS
        //end
        //tahap-10 //HPQC
        len = add_at_pub_hybrid(eap_payload, len, mlkem_pk, ausf_ue->pub_key.value); // <-- hybrid PQC FS
        //end
        len = add_at_mac(eap_payload, len, &mac_ptr);

        if (len < 0 || len > sizeof(eap_payload)) {
            ogs_error("EAP payload overflow after AT_PUB_HYBRID");
            return false;
        }        
    
        // Update EAP total length
        eap_payload[2] = (len >> 8) & 0xFF;
        eap_payload[3] = len & 0xFF;
    
        print_hex("EAP Payload Before MAC", eap_payload, len);
    
        // Calculate MAC using K_AUT
        uint8_t mac[16];
        if (!CalculateMacForEapAkaPrime(k_aut, 32, eap_payload, len, mac)) {
            ogs_error("[%s] Failed to calculate MAC", ausf_ue->suci);
            return false;
        }

        ogs_info("Prosess Melewati CalculateMacForEapAkaPrime()");

        if (!mac_ptr) {
            ogs_error("MAC pointer is NULL");
            return false;
        }        
    
        memcpy(mac_ptr, mac, 16);
        ogs_info("AT_MAC pointer offset: %ld", mac_ptr - eap_payload);
    
        print_hex("MAC", mac, 16);
        print_hex("EAP Payload Final", eap_payload, len);
    
        // Encode EAP Payload to Base64
        // char encoded[512] = {0}; //khusus Prime dan FS
        char encoded[4096] = {0};         // Karena Base64 encoding butuh ~1.37x dari biner
        if (ogs_base64_encode(encoded, (const char *)eap_payload, len) <= 0) {
            ogs_error("[%s] Failed to Base64 encode EAP payload", ausf_ue->suci);
            return false;
        }
    
        ogs_info("[%s] EAP Base64 encoded: %s", ausf_ue->suci, encoded);
    
        // Prepare response to AMF
        OpenAPI_links_value_schema_t LinksValueSchemeValue;
        OpenAPI_map_t *LinksValueScheme = NULL;
        OpenAPI_list_t *_links = NULL;
        OpenAPI_ue_authentication_ctx_t UeAuthenticationCtx;
        ogs_sbi_message_t sendmsg;
        ogs_sbi_header_t header;
    
        memset(&LinksValueSchemeValue, 0, sizeof(LinksValueSchemeValue));
        memset(&header, 0, sizeof(header));
    
        header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
        header.api.version = (char *)OGS_SBI_API_V1;
        header.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
        header.resource.component[1] = ausf_ue->ctx_id;
        header.resource.component[2] = (char *)OGS_SBI_RESOURCE_NAME_EAP_SESSION;
    
        LinksValueSchemeValue.href = ogs_sbi_server_uri(server, &header);
        LinksValueScheme = OpenAPI_map_create(ogs_strdup("eap-session"), &LinksValueSchemeValue);
        ogs_assert(LinksValueScheme);
    
        _links = OpenAPI_list_create();
        ogs_assert(_links);
        OpenAPI_list_add(_links, LinksValueScheme);
    
        memset(&UeAuthenticationCtx, 0, sizeof(UeAuthenticationCtx));
        UeAuthenticationCtx.auth_type = OpenAPI_auth_type_EAP_AKA_PRIME;
        UeAuthenticationCtx.eap_payload = ogs_strdup(encoded);
        UeAuthenticationCtx._links = _links;
    
        memset(&sendmsg, 0, sizeof(sendmsg));
        sendmsg.UeAuthenticationCtx = &UeAuthenticationCtx;
    
        memset(&header, 0, sizeof(header));
        header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
        header.api.version = (char *)OGS_SBI_API_V1;
        header.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
        header.resource.component[1] = ausf_ue->ctx_id;
    
        sendmsg.http.location = ogs_sbi_server_uri(server, &header);
        sendmsg.http.content_type = (char *)OGS_SBI_CONTENT_3GPPHAL_TYPE;
    
        ogs_info("[%s] Kirim response ke AMF", ausf_ue->suci);
        response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));
    
        ogs_info("[%s] Berhasil response dan parse ke AMF", ausf_ue->suci);
    
        // Cleanup
        ogs_free(sendmsg.http.location);
        ogs_free(LinksValueSchemeValue.href);
        OpenAPI_list_free(_links);
    
        return true;
    }
    
    //end

    memset(&UeAuthenticationCtx, 0, sizeof(UeAuthenticationCtx));

    UeAuthenticationCtx.auth_type = ausf_ue->auth_type;

    memset(&AV5G_AKA, 0, sizeof(AV5G_AKA));
    AV5G_AKA.rand = AuthenticationVector->rand;
    AV5G_AKA.autn = AuthenticationVector->autn;

    ogs_kdf_hxres_star(ausf_ue->rand, ausf_ue->xres_star,
            ausf_ue->hxres_star);
    ogs_hex_to_ascii(ausf_ue->hxres_star, sizeof(ausf_ue->hxres_star),
            hxres_star_string, sizeof(hxres_star_string));
    AV5G_AKA.hxres_star = hxres_star_string;

    UeAuthenticationCtx._5g_auth_data = &AV5G_AKA;

    memset(&LinksValueSchemeValue, 0, sizeof(LinksValueSchemeValue));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
    header.resource.component[1] = ausf_ue->ctx_id;
    header.resource.component[2] =
            (char *)OGS_SBI_RESOURCE_NAME_5G_AKA_CONFIRMATION;
    LinksValueSchemeValue.href = ogs_sbi_server_uri(server, &header);
    LinksValueScheme = OpenAPI_map_create(
            (char *)links_member_name(UeAuthenticationCtx.auth_type),
            &LinksValueSchemeValue);
    ogs_assert(LinksValueScheme);

    UeAuthenticationCtx._links = OpenAPI_list_create();
    ogs_assert(UeAuthenticationCtx._links);
    OpenAPI_list_add(UeAuthenticationCtx._links, LinksValueScheme);

    memset(&sendmsg, 0, sizeof(sendmsg));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
    header.resource.component[1] = ausf_ue->ctx_id;

    sendmsg.http.location = ogs_sbi_server_uri(server, &header);
    sendmsg.http.content_type = (char *)OGS_SBI_CONTENT_3GPPHAL_TYPE;

    sendmsg.UeAuthenticationCtx = &UeAuthenticationCtx;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_CREATED);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    OpenAPI_list_free(UeAuthenticationCtx._links);
    OpenAPI_map_free(LinksValueScheme);

    ogs_free(LinksValueSchemeValue.href);
    ogs_free(sendmsg.http.location);

    return true;
}

bool ausf_nudm_ueau_handle_auth_removal_ind(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(ausf_ue);
    ogs_assert(stream);

    memset(&sendmsg, 0, sizeof(sendmsg));
    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_NO_CONTENT);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    return true;
}

bool ausf_nudm_ueau_handle_result_confirmation_inform(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_info("[%s] Masuk ke ausf_nudm_ueau_handle_result_confirmation_inform", ausf_ue->suci);
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    char kseaf_string[OGS_KEYSTRLEN(OGS_SHA256_DIGEST_SIZE)];

    OpenAPI_confirmation_data_response_t ConfirmationDataResponse;
    OpenAPI_auth_event_t *AuthEvent = NULL;

    bool rc;
    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(ausf_ue);
    ogs_assert(stream);

    ogs_assert(recvmsg);

    AuthEvent = recvmsg->AuthEvent;
    if (!AuthEvent) {
        ogs_error("[%s] No AuthEvent", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No AuthEvent", ausf_ue->suci, NULL));
        return false;
    }

    if (!recvmsg->http.location) {
        ogs_error("[%s] No Location", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No Location", ausf_ue->suci, NULL));
        return false;
    }

    rc = ogs_sbi_getaddr_from_uri(
            &scheme, &fqdn, &fqdn_port, &addr, &addr6, recvmsg->http.location);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        ogs_error("[%s] Invalid URI [%s]",
                ausf_ue->suci, recvmsg->http.location);

        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "Invalid URI", ausf_ue->suci, NULL));

        return false;
    }

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("[%s] ogs_sbi_client_add()", ausf_ue->suci);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        ogs_assert(client);
    }

    OGS_SBI_SETUP_CLIENT(&ausf_ue->auth_event, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    AUTH_EVENT_STORE(ausf_ue, recvmsg->http.location);

    memset(&ConfirmationDataResponse, 0, sizeof(ConfirmationDataResponse));

    if (AuthEvent->success == true)
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
    else
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;

    ConfirmationDataResponse.auth_result = ausf_ue->auth_result;
    ConfirmationDataResponse.supi = ausf_ue->supi;

    //tahap-6
    if (ausf_ue->auth_type == OpenAPI_auth_type_EAP_AKA_PRIME) {
        ConfirmationDataResponse.eap_payload_b64 = ausf_ue->eap_payload_b64;
    }else{
        ConfirmationDataResponse.eap_payload_b64 = NULL;
    }
    print_hex("KAUSF untuk KSEAF", ausf_ue->kausf, OGS_SHA256_DIGEST_SIZE);  // 32 bytes
    //end

    ogs_info("serving_network_name = %s",ausf_ue->serving_network_name);

    ogs_kdf_kseaf(ausf_ue->serving_network_name,
            ausf_ue->kausf, ausf_ue->kseaf);
    ogs_hex_to_ascii(ausf_ue->kseaf, sizeof(ausf_ue->kseaf),
            kseaf_string, sizeof(kseaf_string));
    ConfirmationDataResponse.kseaf = kseaf_string;


    print_hex("KSEAF", ausf_ue->kseaf, sizeof(ausf_ue->kseaf));

    memset(&sendmsg, 0, sizeof(sendmsg));

    sendmsg.ConfirmationDataResponse = &ConfirmationDataResponse;

    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    return true;
}


