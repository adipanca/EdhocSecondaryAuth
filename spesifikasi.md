### EAP Secondary Authentication dengan Open5GS, UERANSIM dan Freeradius
Method	Initiator auth	Responder auth	Profil kripto
0	SIG (Ed25519)	SIG (Ed25519)	
1	SIG (Ed25519)	MAC (static-DH X25519)	
2	MAC (static-DH X25519)	SIG (Ed25519)	
3	MAC (static-DH X25519)	MAC (static-DH X25519)	
4	MAC (static-XWING)	MAC (static-XWING)	XWING (X25519 + ML-KEM-768) hybrid PQC

### gunakan mermaid.md untuk melihat protocol diagram

Komponen
Komponen	Versi	Peran
FreeRADIUS	3.2.6	DN-AAA / EAP server (rlm_eap_edhoc) — responder, persist long-term keys
Open5GS SMF	2.7.2	EAP authenticator (forwards EAP to UPF, tidak ke RADIUS langsung)
Open5GS UPF	2.7.2	N6 RADIUS client ke DN-AAA (TS 23.502 §4.3.2.3)
UERANSIM	3.2.7	UE NAS EAP-EDHOC initiator


### Hanya third-party yang benar-benar dipakai oleh proyek ini:

libsodium
Dipakai untuk: X25519, Ed25519, SHA-256, HKDF.
mbedTLS (libmbedcrypto)
Dipakai untuk: AES-128-GCM.
PQClean
Dipakai untuk: ML-KEM-768 dan ML-DSA-44 (clean reference implementation).

Sesuai TS 23.502 §4.3.2.3 dan TS 33.501 §11.1.2, entitas yang berbicara dengan DN-AAA lewat interface N6 adalah UPF, bukan SMF. Implementasi sekarang mencerminkan pemisahan tersebut:3

              N1 (NAS)         N4 (kontrol)        UDP sidecar         N6 (RADIUS)
   UE ───────────────► SMF ─────────────► SMF ───────────────► UPF ────────────────► DN-AAA
                       │  EAP authenticator          │  eap-relay (port 3870)         │  (FreeRADIUS)
                       │  pass-through               │  radcli RADIUS client          │
                       └─ radius-client.c ──────────► eap-relay.c ──────────────────► rlm_eap_edhoc


### Hop	File	Mekanisme
SMF → UPF	open5gs/src/smf/radius-client.c	UDP sidecar (OPEN5GS_EAP_RELAY_ADDR:PORT, default 127.0.0.1:3870)
UPF listener	open5gs/src/upf/eap-relay.c	pthread UDP server, validasi magic 0xE5E5DEAD
UPF → DN-AAA	open5gs/src/upf/eap-relay.c	radcli rc_auth() ke OPEN5GS_RADIUS_SERVER:PORT (default 127.0.0.1:1812)
DN-AAA	rlm_eap_edhoc	EAP-EDHOC responder


### Wire format SMF↔UPF (UDP private)

REQ  (magic 0xE5E5DEAD): magic | ver=1 | rsvd | uname_len | state_len | eap_len | uname | state | eap
RESP (magic 0xE5E5BEEF): magic | ver=1 | result        | state_len | eap_len | state | eap
                              result: 0=Accept, 1=Reject, 2=Challenge, 3=Error

### Env var konfigurasi
Var	Default	Lokasi	Fungsi
OPEN5GS_EAP_RELAY_ADDR	127.0.0.1	SMF & UPF	Alamat UDP sidecar
OPEN5GS_EAP_RELAY_PORT	3870	SMF & UPF	Port UDP sidecar
OPEN5GS_RADIUS_SERVER	127.0.0.1	UPF only	DN-AAA (FreeRADIUS)
OPEN5GS_RADIUS_PORT	1812	UPF only	Port RADIUS auth
OPEN5GS_RADIUS_SECRET	testing123	UPF only	RADIUS shared secret


### Catatan kepatuhan 3GPP:
Pemisahan SMF/UPF: UPF adalah satu-satunya entitas yang mengirim RADIUS ke DN-AAA, sesuai TS 23.502 §4.3.2.3 figure 4.3.2.3-1 step 5–10.
EAP authenticator di SMF: SMF tetap men-driving state machine EAP (start, retransmit, success/failure) sesuai TS 33.501 §11.1.2.


### Benchmark setiap varian

1. Run benchmark handshake utama dari secondary authentication P2P dan juga uji komputasi breakdown (Keygen, Scalar multiplication, Encaps, Decaps, Signature, Verify)
2. Ukur performa pada jaringan lossy
3. Uji interoperabilitas dengan implementasi EDHOC 
4. pengaruh ukuran paket terhadap MTU dan fragmentasi
5. Generate analisis hasil pengukuran


sebagai bahan referensi untuk kode yang diubah atau ditambahkan: 
### Open5GS Source Code

| No | File | Directory | Status | Keterangan |
|----|------|-----------|--------|------------|
| 1 | `context.h` | `src/smf/` | Modified | Tambah `eap_session` dan `eap_edhoc_session` struct |
| 2 | `gsm-sm.c` | `src/smf/` | Modified | Logic EAP authentication (eap-edhoc + RADIUS) |
| 3 | `gsm-build.c` | `src/smf/` | Modified | Build EAP-edhoc Version Request |
| 4 | `gsm-build.h` | `src/smf/` | Modified | Header untuk EAP message builder |
| 5 | `meson.build` | `src/smf/` | Modified | Tambah radcli + eap-edhoc dependency |
| 6 | `namf-build.h` | `src/smf/` | Modified | Header AMF communication |
| 7 | `namf-handler.c` | `src/smf/` | Modified | Handler untuk AMF messages |
| 8 | `radius-client.c` | `src/smf/` | **New** | RADIUS client implementation |
| 9 | `radius-client.h` | `src/smf/` | **New** | RADIUS client header |
| 10 | `eap-edhoc.c` | `src/smf/` | **New** | EAP-edhoc server implementation |
| 11 | `eap-edhoc.h` | `src/smf/` | **New** | EAP-edhoc header (TLV types, state machine) |
| 12 | `context.h` | `src/amf/` | Modified | AMF context untuk EAP |
| 13 | `gmm-build.c` | `src/amf/` | Modified | Build GMM messages |
| 14 | `gmm-build.h` | `src/amf/` | Modified | GMM builder header |
| 15 | `gmm-handler.c` | `src/amf/` | Modified | GMM message handler |
| 16 | `gmm-handler.h` | `src/amf/` | Modified | GMM handler header |
| 17 | `gmm-sm.c` | `src/amf/` | Modified | GMM state machine |
| 18 | `namf-handler.c` | `src/amf/` | Modified | NAMF handler |
| 19 | `nas-path.c` | `src/amf/` | Modified | NAS message path |
| 20 | `nas-path.h` | `src/amf/` | Modified | NAS path header |
| 21 | `nas-security.c` | `src/amf/` | Modified | NAS security functions |
| 22 | `nausf-build.c` | `src/amf/` | Modified | NAUSF message builder |
| 23 | `nausf-build.h` | `src/amf/` | Modified | NAUSF builder header |
| 24 | `nausf-handler.c` | `src/amf/` | Modified | NAUSF handler |
| 25 | `context.h` | `src/ausf/` | Modified | AUSF context |
| 26 | `nausf-handler.c` | `src/ausf/` | Modified | NAUSF handler |
| 27 | `nausf-handler.h` | `src/ausf/` | Modified | NAUSF handler header |
| 28 | `nudm-handler.c` | `src/ausf/` | Modified | NUDM handler |
| 29 | `nudm-handler.h` | `src/ausf/` | Modified | NUDM handler header |
| 30 | `context.h` | `src/udm/` | Modified | UDM context |
| 31 | `nudr-handler.c` | `src/udm/` | Modified | NUDR handler |

### Open5GS Library (lib/)

| No | File | Directory | Status | Keterangan |
|----|------|-----------|--------|------------|
| 1 | `curve25519-donna.c` | `lib/crypt/` | Modified | Curve25519 implementation |
| 2 | `meson.build` | `lib/crypt/` | Modified | Build config untuk mlkem |
| 3 | `ogs-crypt.h` | `lib/crypt/` | Modified | Crypto header |
| 4 | `ogs-kdf.c` | `lib/crypt/` | Modified | Key derivation functions |
| 5 | `ogs-kdf.h` | `lib/crypt/` | Modified | KDF header |
| 6 | `ogs-sha2-hmac.c` | `lib/crypt/` | Modified | SHA2 HMAC |
| 7 | `mlkem.c` | `lib/crypt/` | **New** | ML-KEM implementation |
| 8 | `mlkem.h` | `lib/crypt/` | **New** | ML-KEM header |
| 9 | `mlkem/` | `lib/crypt/` | **New** | ML-KEM library folder |
| 10 | `auth_type.h` | `lib/sbi/openapi/model/` | Modified | Auth type definitions |
| 11 | `authentication_vector.c` | `lib/sbi/openapi/model/` | Modified | Auth vector |
| 12 | `authentication_vector.h` | `lib/sbi/openapi/model/` | Modified | Auth vector header |
| 13 | `confirmation_data.c` | `lib/sbi/openapi/model/` | Modified | Confirmation data |
| 14 | `confirmation_data.h` | `lib/sbi/openapi/model/` | Modified | Confirmation data header |
| 15 | `confirmation_data_response.c` | `lib/sbi/openapi/model/` | Modified | Confirmation response |
| 16 | `confirmation_data_response.h` | `lib/sbi/openapi/model/` | Modified | Confirmation response header |
| 17 | `ue_authentication_ctx.c` | `lib/sbi/openapi/model/` | Modified | UE auth context |
| 18 | `ue_authentication_ctx.h` | `lib/sbi/openapi/model/` | Modified | UE auth context header |

### Sample FreeRADIUS Configuration

| No | File | Directory | Status | Keterangan |
|----|------|-----------|--------|------------|
| 1 | `README.md` | `sample-freeradius/` | **New** | Dokumentasi konfigurasi |
| 2 | `authorize` | `sample-freeradius/` | **New** | Sample user database |
| 3 | `clients.conf.sample` | `sample-freeradius/` | **New** | Sample RADIUS client config |
| 4 | `radcli-servers` | `sample-freeradius/` | **New** | Sample radcli servers |
| 5 | `radiusclient.conf` | `sample-freeradius/` | **New** | Sample radcli client config |
| 6 | `setup-freeradius.sh` | `sample-freeradius/` | **New** | Script setup FreeRADIUS |



**Location:** `/home/admin-vb/freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/`

| No | File | Full Path | Status | Keterangan |
|----|------|-----------|--------|------------|
| 1 | `rlm_eap_edhoc.c` | `/home/admin-vb/freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/` | **New** | Module utama EAP-edhoc (RFC 9528) - 297 lines |
| 2 | `rlm_eap_edhoc.h` | `/home/admin-vb/freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/` | **New** | Header dengan TLV types dan state machine - 54 lines |
| 3 | `all.mk` | `/home/admin-vb/freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/` | **New** | Build configuration untuk FreeRADIUS v3 |


**Built Artifacts:**
- `/home/admin-vb/freeradius-v3/build/lib/.libs/rlm_eap_edhoc.so`
- `/usr/local/lib/rlm_eap_edhoc.so` (installed)

### FreeRADIUS v3.2.6 Configuration Files Modified

| No | File | Full Path | Status | Keterangan |
|----|------|-----------|--------|------------|
| 1 | `users` | `/usr/local/etc/raddb/users` | **Modified** | Tambah test_user dan imsi-999700000000001 |
| 2 | `dictionary` | `/usr/local/etc/raddb/dictionary` | **Modified** | Tambah `VALUE EAP-Type edhoc misalnya 56` |
| 3 | `eap` | `/usr/local/etc/raddb/mods-available/eap` | **Modified** | Tambah `edhoc {}` section |



### FreeRADIUS v3.2.6 Binary Locations

| Binary | Path | Keterangan |
|--------|------|------------|
| `radiusd` | `/usr/local/sbin/radiusd` | FreeRADIUS daemon |
| `radclient` | `/usr/local/bin/radclient` | RADIUS test client |
| `rlm_eap_edhoc.so` | `/usr/local/lib/rlm_eap_edhoc.so` | EAP-EDHOC module |


### UERANSIM Source Code

| No | File | Directory | Status | Keterangan |
|----|------|-----------|--------|------------|
| 1 | `crypt.cpp` | `src/lib/crypt/` | Modified | Crypto functions |
| 2 | `crypt.hpp` | `src/lib/crypt/` | Modified | Crypto header |
| 3 | `eap.cpp` | `src/lib/nas/` | Modified | EAP message handling |
| 4 | `eap.hpp` | `src/lib/nas/` | Modified | EAP header |
| 5 | `eap_edhoc.cpp` | `src/lib/nas/` | **New** | EAP-edhoc client implementation |
| 6 | `eap_edhoc.hpp` | `src/lib/nas/` | **New** | EAP-edhoc client header |
| 7 | `encode.cpp` | `src/lib/nas/` | Modified | NAS encoding |
| 8 | `ie6.cpp` | `src/lib/nas/` | Modified | NAS IE type 6 |
| 9 | `keys.cpp` | `src/ue/nas/` | Modified | NAS key derivation |
| 10 | `keys.hpp` | `src/ue/nas/` | Modified | NAS keys header |
| 11 | `auth.cpp` | `src/ue/nas/mm/` | Modified | MM authentication |
| 12 | `security.cpp` | `src/ue/nas/mm/` | Modified | MM security |
| 13 | `sm.hpp` | `src/ue/nas/sm/` | Modified | SM state machine header |
| 14 | `transport.cpp` | `src/ue/nas/sm/` | Modified | SM transport (EAP-edhoc) |
| 15 | `usim.hpp` | `src/ue/nas/usim/` | Modified | USIM header |
| 16 | `octet_view.hpp` | `src/utils/` | Modified | Octet view utility |
| 17 | `mlkem/` | `src/ext/` | **New** | ML-KEM library folder |


### File yang dibuat / diubah untuk varian EDHOC

| Komponen | File | Peran |
| --- | --- | --- |
| FreeRADIUS | `freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/rlm_eap_edhoc.{c,h}` | EAP server module (responder), persist long-term keys ke `/tmp/edhoc/{server,ue}_keys.bin` |
| FreeRADIUS | `freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/edhoc.{c,h}` | XWING + HKDF + AES-GCM core (libsodium + PQClean) |
| FreeRADIUS | `…/all.mk` | link `-loqs -lcrypto` |
| FreeRADIUS dict | `share/dictionary.freeradius.internal` | `VALUE EAP-Type EDHOC 56` |
| FreeRADIUS conf | `raddb/mods-available/eap` | `default_eap_type = edhoc; edhoc { }` |
| Open5GS | `open5gs/lib/crypt/edhoc/edhoc.{c,h}` | EDHOC core (mirror) |
| Open5GS SMF | `open5gs/src/smf/gsm-sm.c` | `EAP_TYPE_EDHOC=56` dispatch (passthrough) |
| Open5GS SMF | `open5gs/src/smf/gsm-build.c` | `gsm_build_pdu_session_authentication_command_edhoc()` |
| Open5GS SMF | `open5gs/src/smf/radius-client.c` | EAP-Message dipecah ke chunk 253 B (RFC 3579) |
| UERANSIM UE | `UERANSIM/src/ue/nas/edhoc/edhoc.{c,h}` | EDHOC core (mirror) |
| UERANSIM UE | `UERANSIM/src/ue/nas/edhoc/edhoc_initiator.{hpp,cpp}` | C++ wrapper untuk NAS |
| UERANSIM UE | `UERANSIM/src/ue/nas/sm/transport.cpp` | EAP_EDHOC handler dalam PDU-Session SM, identity = SUPI |
| UERANSIM lib | `UERANSIM/src/lib/nas/eap.{hpp,cpp}` | `class EapEdhoc : public Eap` (type 56) |
| Test harness | `open5gs/run_eap_edhoc_test.sh` | start/stop FR + 5GC + gNB + UE, verifikasi log |


### terakhir buatkan readme.md : 
1. arsitektur software dan struktur direktori
2. algorithm yang digunakan
3. instalasi depedency
4. third party yang digunakan (tidak termasuk library yang tidak digunakan, misalnya hanya sebagai base contoh maka tidak perlu dimasukan)
5. cara clone dan install
6. cara run dan cara run seluruh benchmark

### password bash "admin"