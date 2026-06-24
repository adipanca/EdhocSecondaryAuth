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

#ifndef AUSF_NAUSF_HANDLER_H
#define AUSF_NAUSF_HANDLER_H

#include "context.h"


#ifdef __cplusplus
extern "C" {
#endif
//tahap-6
    typedef struct {
        uint8_t *res;
        int res_len;
        uint8_t *mac;
        int mac_len;
        uint8_t *kdf;
        int kdf_len;
        //tahap-9 //Prime-FS
        uint8_t *pub_ecdhe;
        int pub_ecdhe_len;
        //end
        //tahap-10 //HPQC
        uint8_t *pub_hybrid;
        int pub_hybrid_len;
        //end
    } EapAttributes;
    
    typedef struct {
        EapAttributes attributes;
    } EapMessage;

    int parse_eap_aka_prime(EapMessage *msg, const uint8_t *eap_payload, 
        size_t length);

    uint8_t *build_eap_success(int *len, uint8_t identifier);
//end
bool ausf_nausf_auth_handle_authenticate(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool ausf_nausf_auth_handle_authenticate_confirmation(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool ausf_nausf_auth_handle_authenticate_delete(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);

#ifdef __cplusplus
}
#endif

#endif /* AUSF_NAUSF_HANDLER_H */
