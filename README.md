# Secondary Authentication (Open5GS + UERANSIM + FreeRADIUS)

## 1. Arsitektur Software dan Struktur Direktori

### Arsitektur

Implementasi mengikuti pemisahan peran:

- UE (UERANSIM) sebagai EAP-EDHOC initiator
- SMF (Open5GS) sebagai EAP authenticator (relay ke UPF)
- UPF (Open5GS) sebagai endpoint N6 menuju DN-AAA
- DN-AAA (FreeRADIUS) sebagai EAP responder

Alur:

1. UE mengirim EAP payload di NAS SM `PDU_SESSION_AUTHENTICATION_COMPLETE`
2. SMF mem-forward payload ke sidecar UDP UPF
3. UPF relay memproses payload dan mengembalikan `Accept/Reject/Challenge`
4. SMF melanjutkan state machine NAS sesuai hasil relay

### Struktur Direktori

- `open5gs/src/smf/radius-client.c`
- `open5gs/src/smf/radius-client.h`
- `open5gs/src/upf/eap-relay.c`
- `open5gs/src/upf/eap-relay.h`
- `UERANSIM/src/lib/nas/eap.hpp`
- `UERANSIM/src/lib/nas/eap.cpp`
- `UERANSIM/src/ue/nas/sm/transport.cpp`
- `sample-freeradius/`
- `freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/`

## 2. Algorithm yang Digunakan

### EAP / Secondary Authentication

- EAP Type `56` dipakai untuk EDHOC (`EAP_EDHOC`)
- UE merespon `PDU_SESSION_AUTHENTICATION_COMMAND` dengan `PDU_SESSION_AUTHENTICATION_COMPLETE`
- Payload EAP dibawa apa adanya pada flow EDHOC (passthrough style)

### Sidecar UDP SMF <-> UPF

Wire format private:

- REQ (`0xE5E5DEAD`):
  - `magic | ver | rsvd | uname_len | state_len | eap_len | uname | state | eap`
- RESP (`0xE5E5BEEF`):
  - `magic | ver | result | state_len | eap_len | state | eap`

Result code:

- `0` Accept
- `1` Reject
- `2` Challenge
- `3` Error

## 3. Instalasi Dependency

### Base toolchain

```bash
sudo apt update
sudo apt install -y build-essential cmake meson ninja-build pkg-config git \
  libssl-dev libsctp-dev libyaml-dev libmicrohttpd-dev libmongoc-dev libbson-dev \
  libidn11-dev libnghttp2-dev libgnutls28-dev libtins-dev libcurl4-openssl-dev
```

### Open5GS build deps (tambahan umum)

```bash
sudo apt install -y libgcrypt20-dev libgnutls28-dev libyaml-dev
```

### UERANSIM build deps

```bash
sudo apt install -y libsctp-dev lksctp-tools
```

### FreeRADIUS deps

```bash
sudo apt install -y libtalloc-dev libkqueue-dev libssl-dev
```

### Runtime deps untuk benchmark script

```bash
sudo apt install -y freeradius freeradius-utils mongodb-mongosh
```

## 4. Third Party yang Digunakan

Yang benar-benar dipakai oleh implementasi saat ini:

- Open5GS 2.7.2
- UERANSIM 3.2.7
- FreeRADIUS 3.2.6
- libsodium — X25519, Ed25519, SHA-256, HKDF
- mbedTLS (libmbedcrypto) — AES-128-GCM
- PQClean — ML-KEM-768 dan ML-DSA-44 (clean reference implementation)

Catatan: pada commit ini, modul relay dan flow EAP-EDHOC dasar sudah aktif; integrasi penuh PQ path masih tahap lanjutan.

## 5. Cara Clone dan Install

### Clone

```bash
git clone <repo-anda> EdhocSecondaryAuth
cd EdhocSecondaryAuth
```

### Build Open5GS (workspace-local)

```bash
cd open5gs
meson setup build-ws --prefix=$PWD/install-ws
ninja -C build-ws
ninja -C build-ws install
```

### Build UERANSIM

```bash
cd ../UERANSIM
make
```

### Setup FreeRADIUS sample

```bash
cd ../sample-freeradius
sudo ./setup-freeradius.sh
```

Module skeleton juga sudah ditempatkan di:

- `freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/rlm_eap_edhoc.c`
- `freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/rlm_eap_edhoc.h`
- `freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/all.mk`

### Env var runtime relay

```bash
export OPEN5GS_EAP_RELAY_ADDR=127.0.0.1
export OPEN5GS_EAP_RELAY_PORT=3870
export OPEN5GS_RADIUS_SERVER=127.0.0.1
export OPEN5GS_RADIUS_PORT=1812
export OPEN5GS_RADIUS_SECRET=testing123
```

## 6. Cara Run dan Cara Run Seluruh Benchmark

### Suite benchmark lengkap (5 pengukuran wajib)

Seluruh pengukuran yang diminta spesifikasi.md diotomasi oleh satu perintah di
folder `benchmark/`. Benchmark kripto memakai library nyata sesuai spesifikasi:
libsodium (X25519/Ed25519/SHA-256/HKDF), mbedTLS (AES-128-GCM), dan PQClean
(ML-KEM-768/ML-DSA-44, clean reference).

Prasyarat sekali pasang:

```bash
sudo apt-get install -y libsodium-dev libmbedtls-dev python3-cryptography
# PQClean (ML-KEM-768 + ML-DSA-44) di-clone di ./PQClean; Makefile benchmark
# membangun static lib clean reference-nya secara otomatis.
```

Jalankan semua benchmark:

```bash
cd /home/admin-vb/EdhocSecondaryAuth/benchmark
./run_all_benchmarks.sh                 # tanpa testbed 5G live
RUN_E2E=1 ./run_all_benchmarks.sh       # sekaligus testbed 5G end-to-end
```

Hasil ditulis ke `benchmark-results/`:

| # | Kebutuhan | File hasil |
| --- | --- | --- |
| 1a | Latensi primitif kripto | `crypto-primitives.csv` |
| 1b | Breakdown per method (Keygen, Scalar mult, Encaps, Decaps, Signature, Verify) | `crypto-breakdown.csv`, `handshake-compute.csv` |
| 1c | Handshake P2P end-to-end 5G | `benchmark.csv`, `summary.txt` |
| 2 | Performa jaringan lossy | `lossy-network.csv` |
| 3 | Interoperabilitas dengan implementasi EDHOC | `interop.csv` |
| 4 | Ukuran paket vs MTU/fragmentasi | `mtu-fragmentation.csv` |
| 5 | Analisis terkonsolidasi | `analysis.md` |

Parameter (env var):

- `CRYPTO_ITERS` (default `3000`) — iterasi per operasi primitif
- `LOSSY_TRIALS` (default `120`) — trial per (method, loss-rate)
- `RUN_E2E` (`0`/`1`) — sertakan testbed 5G live
- `ITERATIONS`, `UE_TIMEOUT_SEC` — untuk run e2e

Menjalankan komponen satu per satu:

```bash
cd benchmark
make                                  # build crypto_bench + interop_vec
./crypto_bench    ../benchmark-results 3000
python3 lossy_bench.py        ../benchmark-results
python3 interop_check.py      ../benchmark-results
python3 mtu_fragmentation.py  ../benchmark-results
python3 analyze.py            ../benchmark-results   # regenerasi analysis.md
```

### Testbed 5G end-to-end (handshake P2P, kebutuhan 1c)

```bash
cd /home/admin-vb/EdhocSecondaryAuth/benchmark
./run_all_benchmarks.sh
```

Script ini otomatis: membersihkan proses/port sisa, menyiapkan device `ogstun`,
provisioning subscriber, start FreeRADIUS + 10 NF Open5GS + gNB, lalu menjalankan
UE per iterasi. Output:

- `benchmark-results/benchmark.csv`, `benchmark-results/summary.txt`
- `benchmark-results/analysis-e2e.md`
- `benchmark-results/logs-<timestamp>/` (log per komponen, termasuk relay UPF di port 3870)

### Jalankan komponen 5G manual (opsional)

1. FreeRADIUS

```bash
sudo systemctl restart freeradius
```

2. Open5GS (binary hasil install workspace)

```bash
export LD_LIBRARY_PATH=/home/admin-vb/EdhocSecondaryAuth/open5gs/install-ws/lib/x86_64-linux-gnu
/home/admin-vb/EdhocSecondaryAuth/open5gs/install-ws/bin/open5gs-nrfd
# ... scpd, udrd, udmd, ausfd, nssfd, pcfd, amfd, smfd ...
sudo -E /home/admin-vb/EdhocSecondaryAuth/open5gs/install-ws/bin/open5gs-upfd
```

3. UERANSIM gNB dan UE

```bash
cd UERANSIM
./build/nr-gnb -c config/open5gs-gnb.yaml
./build/nr-ue  -c config/open5gs-ue.yaml
```

### Catatan transparansi hasil

- Benchmark kripto (1a/1b), lossy (2), interop (3), dan MTU (4) adalah pengukuran
  nyata memakai primitif kriptografi sebenarnya — angka langsung masuk akal dan
  reproducible.
- Loss pada benchmark lossy diemulasi di level aplikasi pada socket UDP nyata,
  sehingga tidak mengganggu trafik loopback 5G core.
- Testbed 5G (1c) memvalidasi jalur signaling secondary-authentication
  (UE→AMF→SMF→UPF→FreeRADIUS) sampai PDU session berhasil dan relay UPF aktif di
  port 3870. Handshake EDHOC kripto pada jalur live masih relay/passthrough;
  biaya kriptografinya dikuantifikasi terpisah oleh benchmark 1a/1b.


---

## Catatan Implementasi Saat Ini

Perubahan kode yang sudah ditambahkan:

- Open5GS:
  - client relay SMF (`radius-client.*`)
  - listener relay UPF (`eap-relay.*`)
  - lifecycle UPF start/stop relay
- UERANSIM:
  - dukungan `EAP_EDHOC (56)` di parser/encoder EAP
  - handler SM untuk `PDU_SESSION_AUTHENTICATION_COMMAND/RESULT`
- FreeRADIUS:
  - sample config + skeleton module `rlm_eap_edhoc`

Untuk integrasi produksi penuh, tahap berikutnya adalah menghubungkan relay UPF ke transaksi RADIUS Access-Request/Challenge secara penuh (dengan state dan Message-Authenticator), lalu sinkronisasi state machine SMF.
