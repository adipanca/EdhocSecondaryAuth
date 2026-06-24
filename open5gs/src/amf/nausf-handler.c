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

#include "nausf-handler.h"
#include "nas-path.h"

//tahap-7
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




// end

int amf_nausf_auth_handle_authenticate(
        amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    int r;
    OpenAPI_ue_authentication_ctx_t *UeAuthenticationCtx = NULL;
    OpenAPI_ue_authentication_ctx_5g_auth_data_t *AV5G_AKA = NULL;
    OpenAPI_links_value_schema_t *LinksValueSchemeValue = NULL;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_lnode_t *node = NULL;

    bool rc;
    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(amf_ue);
    ogs_assert(message);

    if (!message->http.location) {
        ogs_error("[%s] No http.locationxxxx", amf_ue->suci);
        return OGS_ERROR;
    }

    UeAuthenticationCtx = message->UeAuthenticationCtx;
    if (!UeAuthenticationCtx) {
        ogs_error("[%s] No UeAuthenticationCtx", amf_ue->suci);
        return OGS_ERROR;
    }

    //tahap-3
    if (UeAuthenticationCtx->auth_type == OpenAPI_auth_type_EAP_AKA_PRIME) {
//         ogs_info("[%s] Handling EAP-AKA' response from AUSF", amf_ue->suci);

//         if (!UeAuthenticationCtx->eap_payload || !UeAuthenticationCtx->_links) {
//             ogs_error("[%s] EAP-AKA' missing eap_payload or _links", amf_ue->suci);
//             return OGS_ERROR;
//         }

//         amf_ue->auth_type = UeAuthenticationCtx->auth_type;       

//         OpenAPI_list_for_each(UeAuthenticationCtx->_links, node) {
//             LinksValueScheme = node->data;
//             if (LinksValueScheme && strcmp(LinksValueScheme->key, OGS_SBI_RESOURCE_NAME_EAP_SESSION) == 0) {
//                 LinksValueSchemeValue = LinksValueScheme->value;
//                 break;
//             }
//         }

//         if (LinksValueSchemeValue && LinksValueSchemeValue->href) {
// #ifdef STORE_EAP_SESSION
//             STORE_EAP_SESSION(amf_ue, LinksValueSchemeValue->href);
// #else
//             if (amf_ue->eap_session_href) free(amf_ue->eap_session_href);
//             amf_ue->eap_session_href = strdup(LinksValueSchemeValue->href);
// #endif
//         }

//         ogs_info("[%s] EAP-Payload (Base64): %s", amf_ue->suci, UeAuthenticationCtx->eap_payload);
//         ogs_info("[%s] EAP-Payload (HREF): %s", amf_ue->suci, amf_ue->eap_session_href);

//         if (amf_ue->eap_payload) {
//             free(amf_ue->eap_payload);
//             amf_ue->eap_payload = NULL;
//             amf_ue->eap_payload_len = 0;
//         }

//         uint8_t decoded_payload[256] = {0};
//         int decoded_len = ogs_base64_decode_binary(decoded_payload, UeAuthenticationCtx->eap_payload);
//         if (decoded_len <= 0) {
//             ogs_error("[%s] Failed to decode EAP payload from base64", amf_ue->suci);
//             return OGS_ERROR;
//         }

//         amf_ue->eap_payload = ogs_malloc(decoded_len);
//         ogs_assert(amf_ue->eap_payload);
//         memcpy(amf_ue->eap_payload, decoded_payload, decoded_len);
//         amf_ue->eap_payload_len = decoded_len;

//         ogs_info("[%s] Decoded EAP-Payload length = %d", amf_ue->suci, decoded_len);
//         // ogs_log_hexdump_func(OGS_LOG_INFO, OGS_LOG_DOMAIN, amf_ue->eap_payload, amf_ue->eap_payload_len);

//         r = nas_5gs_send_authentication_request(amf_ue);
//         ogs_expect(r == OGS_OK);
//         ogs_assert(r != OGS_ERROR);
//         ogs_info("[%s] sampai sini nas_5gs_send_authentication_request", amf_ue->suci);

//         return OGS_OK;

            ogs_info("[%s] Handling EAP-AKA' response from AUSF", amf_ue->suci);

            if (!UeAuthenticationCtx->eap_payload || !UeAuthenticationCtx->_links) {
                ogs_error("[%s] EAP-AKA' missing eap_payload or _links", amf_ue->suci);
                return OGS_ERROR;
            }

            amf_ue->auth_type = UeAuthenticationCtx->auth_type;

            // Ambil href dari _links
            OpenAPI_list_for_each(UeAuthenticationCtx->_links, node) {
                LinksValueScheme = node->data;
                if (LinksValueScheme && strcmp(LinksValueScheme->key, OGS_SBI_RESOURCE_NAME_EAP_SESSION) == 0) {
                    LinksValueSchemeValue = LinksValueScheme->value;
                    break;
                }
            }

            if (LinksValueSchemeValue && LinksValueSchemeValue->href) {
            #ifdef STORE_EAP_SESSION
                STORE_EAP_SESSION(amf_ue, LinksValueSchemeValue->href);
            #else
                if (amf_ue->eap_session_href) free(amf_ue->eap_session_href);
                amf_ue->eap_session_href = strdup(LinksValueSchemeValue->href);
            #endif
            }

            ogs_info("[%s] EAP-Payload (Base64): %s", amf_ue->suci, UeAuthenticationCtx->eap_payload);
            ogs_info("[%s] EAP-Payload (HREF): %s", amf_ue->suci, amf_ue->eap_session_href);

            // Bersihkan payload sebelumnya
            if (amf_ue->eap_payload) {
                free(amf_ue->eap_payload);
                amf_ue->eap_payload = NULL;
                amf_ue->eap_payload_len = 0;
            }

            // Alokasi buffer secara dinamis berdasarkan panjang yang dibutuhkan
            int decoded_len = ogs_base64_decode_len(UeAuthenticationCtx->eap_payload);
            if (decoded_len <= 0) {
                ogs_error("[%s] Invalid base64 payload", amf_ue->suci);
                return OGS_ERROR;
            }

            amf_ue->eap_payload = ogs_malloc(decoded_len);
            ogs_assert(amf_ue->eap_payload);

            decoded_len = ogs_base64_decode_binary(amf_ue->eap_payload, UeAuthenticationCtx->eap_payload);
            if (decoded_len <= 0) {
                ogs_error("[%s] Failed to decode EAP payload from base64", amf_ue->suci);
                free(amf_ue->eap_payload);
                amf_ue->eap_payload = NULL;
                amf_ue->eap_payload_len = 0;
                return OGS_ERROR;
            }
            amf_ue->eap_payload_len = decoded_len;

            ogs_info("[%s] Decoded EAP-Payload length = %d", amf_ue->suci, decoded_len);
            // ogs_log_hexdump_func(OGS_LOG_INFO, OGS_LOG_DOMAIN, amf_ue->eap_payload, amf_ue->eap_payload_len);

            // Kirim ke NAS
            r = nas_5gs_send_authentication_request(amf_ue);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);

            ogs_info("[%s] sampai sini nas_5gs_send_authentication_request", amf_ue->suci);
            return OGS_OK;

    }
    //end

    if (UeAuthenticationCtx->auth_type != OpenAPI_auth_type_5G_AKA) {
        ogs_error("[%s] Not supported Auth Method [%d]",
            amf_ue->suci, UeAuthenticationCtx->auth_type);
        return OGS_ERROR;
    }

    AV5G_AKA = UeAuthenticationCtx->_5g_auth_data;
    if (!AV5G_AKA) {
        ogs_error("[%s] No Av5gAka", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!AV5G_AKA->rand) {
        ogs_error("[%s] No Av5gAka.rand", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!AV5G_AKA->hxres_star) {
        ogs_error("[%s] No Av5gAka.hxresStar", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!AV5G_AKA->autn) {
        ogs_error("[%s] No Av5gAka.autn", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!UeAuthenticationCtx->_links) {
        ogs_error("[%s] No _links", amf_ue->suci);
        return OGS_ERROR;
    }

    OpenAPI_list_for_each(UeAuthenticationCtx->_links, node) {
        LinksValueScheme = node->data;
        if (LinksValueScheme) {
            if (strcmp(LinksValueScheme->key,
                        OGS_SBI_RESOURCE_NAME_5G_AKA) == 0) {
                LinksValueSchemeValue = LinksValueScheme->value;
                break;
            }
        }
    }

    if (!LinksValueSchemeValue) {
        ogs_error("[%s] No _links.5g-aka", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!LinksValueSchemeValue->href) {
        ogs_error("[%s] No _links.5g-aka.href", amf_ue->suci);
        return OGS_ERROR;
    }

    rc = ogs_sbi_getaddr_from_uri(
            &scheme, &fqdn, &fqdn_port, &addr, &addr6, message->http.location);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        ogs_error("[%s] Invalid URI [%s]",
                amf_ue->suci, message->http.location);
        return OGS_ERROR;
    }

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("[%s] ogs_sbi_client_add()", amf_ue->suci);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            ogs_error("[%s] ogs_sbi_client_add() failed", amf_ue->suci);

            ogs_free(fqdn);
            ogs_freeaddrinfo(addr);
            ogs_freeaddrinfo(addr6);

            return OGS_ERROR;
        }
    }

    OGS_SBI_SETUP_CLIENT(&amf_ue->confirmation_for_5g_aka, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    STORE_5G_AKA_CONFIRMATION(amf_ue, LinksValueSchemeValue->href);

    ogs_ascii_to_hex(AV5G_AKA->rand, strlen(AV5G_AKA->rand),
        amf_ue->rand, sizeof(amf_ue->rand));
    ogs_ascii_to_hex(AV5G_AKA->hxres_star, strlen(AV5G_AKA->hxres_star),
        amf_ue->hxres_star, sizeof(amf_ue->hxres_star));
    ogs_ascii_to_hex(AV5G_AKA->autn, strlen(AV5G_AKA->autn),
        amf_ue->autn, sizeof(amf_ue->autn));

    /* Clear Security Context */
    CLEAR_SECURITY_CONTEXT(amf_ue);

    if (amf_ue->nas.amf.ksi < (OGS_NAS_KSI_NO_KEY_IS_AVAILABLE - 1))
        amf_ue->nas.amf.ksi++;
    else
        amf_ue->nas.amf.ksi = 0;

    amf_ue->nas.ue.ksi = amf_ue->nas.amf.ksi;

    r = nas_5gs_send_authentication_request(amf_ue);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return OGS_OK;
}

int amf_nausf_auth_handle_authenticate_confirmation(
        amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    uint8_t kseaf[OGS_SHA256_DIGEST_SIZE];

    ogs_info("[%s] Masuk pada fungsi ini amf_nausf_auth_handle_authenticate_confirmation OGS_KDF_KAMF", amf_ue->suci);

    OpenAPI_confirmation_data_response_t *ConfirmationDataResponse;

    ogs_assert(amf_ue);
    ogs_assert(message);

    ConfirmationDataResponse = message->ConfirmationDataResponse;
    if (!ConfirmationDataResponse) {
        ogs_error("[%s] No ConfirmationDataResponse", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!ConfirmationDataResponse->supi) {
        ogs_error("[%s] No supi", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!ConfirmationDataResponse->kseaf) {
        ogs_error("[%s] No Kseaf", amf_ue->suci);
        return OGS_ERROR;
    }

    amf_ue->auth_result = ConfirmationDataResponse->auth_result;
    if (amf_ue->auth_result == OpenAPI_auth_result_AUTHENTICATION_SUCCESS) {

        amf_ue_set_supi(amf_ue, ConfirmationDataResponse->supi);
        ogs_ascii_to_hex(ConfirmationDataResponse->kseaf,
                strlen(ConfirmationDataResponse->kseaf), kseaf, sizeof(kseaf));

        ogs_kdf_kamf(amf_ue->supi, amf_ue->abba, amf_ue->abba_len,
                kseaf, amf_ue->kamf);

        //tahap-7
        ogs_info("KAMF input: SUPI=%s", amf_ue->supi);
        print_hex("ABBA", amf_ue->abba, amf_ue->abba_len);
        print_hex("KSEAF", kseaf, 32);
        print_hex("KAMF", amf_ue->kamf, sizeof(amf_ue->kamf));

        if (ConfirmationDataResponse->eap_payload_b64) {


            ogs_info("[%s] EAP-AKA' success, menerima EAP-Success dari AUSF", amf_ue->suci);
            amf_ue->auth_type = OpenAPI_auth_type_EAP_AKA_PRIME;

            // Simpan EAP payload (encoded base64)
            amf_ue->eap_success= ogs_strdup(ConfirmationDataResponse->eap_payload_b64);

            // Kirim NAS Authentication Result (berisi IE EAP 0x78)
            // if (nas_5gs_send_authentication_result(amf_ue) != OGS_OK) {
            //     ogs_error("[%s] Failed to send NAS Authentication Result", amf_ue->suci);
            //     return OGS_ERROR;
            // }
        }
        //end

        return OGS_OK;

    } else {

        ogs_error("[%s] Authentication failed", amf_ue->suci);
        return OGS_ERROR;
    }
}
