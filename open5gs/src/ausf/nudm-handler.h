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

#ifndef AUSF_NUDM_HANDLER_H
#define AUSF_NUDM_HANDLER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

//tahap-9 //Prime-FS
#define AT_KDF_FS       0x99// decimal 153 — Forward Secrecy indicator
#define AT_PUB_ECDHE    0x98 // decimal 152 — 32-byte public key from AUSF
//end

//tahap-10
#define AT_PUB_HYBRID   0xA0 // <-- Public Key Hybrid ML-KEM + X25519
//end

//tahap-2
#define AT_RAND         0x01 //nilai decimal 1
#define AT_AUTN         0x02 //nilai decimal 2
#define AT_MAC          0x0B //nilai decimal 11
#define AT_KDF_INPUT    0x17 //nilai decimal 23
#define AT_KDF          0x18 //nilai decimal 24

bool CalculateMacForEapAkaPrime(
        const uint8_t *mk, size_t mk_len,
        const uint8_t *eap_payload, size_t eap_len,
        uint8_t *mac_out);

int build_eap_aka_prime_header(uint8_t *payload, uint8_t code, uint8_t identifier) ;
int add_at_rand(uint8_t *payload, int offset, const uint8_t *rand);
int add_at_autn(uint8_t *payload, int offset, const uint8_t *autn);
int add_at_kdf(uint8_t *payload, int offset, uint16_t kdf_id);
int add_at_kdf_input(uint8_t *payload, int offset, const char *snn);
int add_at_mac(uint8_t *payload, int offset, uint8_t **mac_ptr);
//end

//tahap-9 //Prime-FS
int add_at_kdf_fs(uint8_t *payload, int offset, uint8_t fs_kdf_id) ;
int add_at_pub_ecdhe(uint8_t *payload, int offset, const uint8_t *pub_key) ;
//end

//tahap-10 //HPQC
int add_at_pub_hybrid(uint8_t *payload, int offset, const uint8_t *mlkem_pub_key, const uint8_t *x25519_pub_key);
//end

bool ausf_nudm_ueau_handle_get(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool ausf_nudm_ueau_handle_result_confirmation_inform(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool ausf_nudm_ueau_handle_auth_removal_ind(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
#ifdef __cplusplus
}
#endif

#endif /* AUSF_NUDM_HANDLER_H */
