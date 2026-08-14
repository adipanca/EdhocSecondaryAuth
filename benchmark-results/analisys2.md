# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)

_Dibuat otomatis oleh benchmark/e2e_analyze.py pada 2026-08-14T10:47:47._

Dokumen ini adalah pasangan **end-to-end** dari `analysis.md`. Setiap angka diperoleh dari handshake EAP-EDHOC **nyata** yang berjalan di atas transport EAP-over-RADIUS (RFC 2865/3579) menuju responder FreeRADIUS `rlm_eap_edhoc` yang hidup di `127.0.0.1:1812`. Tidak ada estimasi/proyeksi: kolom setiap tabel dibuat **identik** dengan `analysis.md` agar perbedaan tiap method dapat dibandingkan langsung antara kedua percobaan.

Setiap method 0..4 diimplementasikan penuh dan interoperable: method 0..3 (klasik: Ed25519 SIG / static-DH X25519 MAC, core `edhoc03`) dan method 4 (SIGMA XWING PQC, core `edhoc4`). Method 0..3 memakai 3 pesan (tanpa message_4), method 4 memakai 4 pesan dengan fragmentasi EAP. Method 5 (EAP-TLS Classic) menjalankan handshake mutual-TLS **nyata** (RFC 5216) melalui OpenSSL (`benchmark/eap_tls_bench.c`) melawan `rlm_eap_tls` yang hidup, dengan negosiasi EAP-Nak dari `edhoc` (default_eap_type) ke tipe TLS (13). Method 6 (EAP-TLS Hybrid PQC) menjalankan handshake mutual-TLS 1.3 **nyata** juga (grup KEM hybrid X25519MLKEM768 + sertifikat ML-DSA-44, via `benchmark/eap_tls_hybrid_bench.c` dan `oqs-provider`) melawan `rlm_eap_tls` yang sama — lihat catatan metodologi di bawah untuk cara pengukurannya.

Method matrix:

| Method | Initiator | Responder | Profil kripto |
| --- | --- | --- | --- |
| 0 | SIG (Ed25519) | SIG (Ed25519) | Ed25519 |
| 1 | SIG (Ed25519) | MAC (static-DH X25519) | Ed25519 + X25519 |
| 2 | MAC (static-DH X25519) | SIG (Ed25519) | X25519 + Ed25519 |
| 3 | MAC (static-DH X25519) | MAC (static-DH X25519) | X25519 |
| 4 | SIGMA (ML-DSA-44) | SIGMA (ML-DSA-44) | XWING (X25519 + ML-KEM-768) + ML-DSA-44 (PQC) |
| 5 | EAP-TLS Classic (mutual, RSA-2048) | EAP-TLS Classic (mutual, RSA-2048) | X25519 ECDHE + RSA-2048 (classical TLS) |
| 6 | EAP-TLS Hybrid PQC (mutual, ML-DSA-44) | EAP-TLS Hybrid PQC (mutual, ML-DSA-44) | X25519MLKEM768 hybrid KEM + ML-DSA-44 (PQC) |

> **Catatan metodologi — bagaimana method 5 dan method 6 diukur:** Method **0-6 seluruhnya** diukur end-to-end secara **live** di atas EAP-over-RADIUS nyata terhadap `rlm_eap_tls`/`rlm_eap_edhoc` yang hidup. Method 5 (klasik, RSA-2048) dan method 6 (hybrid-PQC, ML-DSA-44 + grup KEM X25519MLKEM768) memakai `rlm_eap_tls` yang SAMA, tetapi satu instance `tls {}` hanya bisa memegang satu pasangan sertifikat/grup pada satu waktu — jadi keduanya diukur **berurutan, bukan bersamaan**: `benchmark/switch_tls_config.sh classic|hybrid` menukar `tls-config` yang dipakai lalu me-restart radiusd (untuk method 6, ditambah variabel lingkungan `OPENSSL_CONF`/`OPENSSL_MODULES` yang mengaktifkan `oqs-provider`, lihat `pqc-tls/openssl-hybrid.cnf`). Method 6 memerlukan OpenSSL >= 3.2 untuk sertifikat/tanda tangan ML-DSA-44 di TLS1.3 (`oqs-provider` belum mendukung ini di versi OpenSSL yang lebih lama); lingkungan ini memakai OpenSSL 3.0.13 secara default, sehingga sebuah build OpenSSL 3.2.6 privat (`pqc-tls/openssl32/`) dipakai lewat `LD_LIBRARY_PATH` khusus untuk radiusd dan harness method 6 saja — `rlm_eap_tls`/radiusd sendiri tidak diubah kodenya untuk ini (hanya linking runtime-nya), kecuali satu pengecekan versi OpenSSL di `src/main/version.c` yang direlaksasi agar tidak menolak kombinasi minor-version 3.0/3.2 ini (OpenSSL menjamin stabilitas ABI/API di seluruh seri 3.x). Setiap handshake method 6 diverifikasi (bukan cuma diasumsikan) benar-benar memakai grup `X25519MLKEM768` dan sertifikat `mldsa44` lewat `SSL_get0_group_name()`/`EVP_PKEY_get0_type_name()` — kalau sampai jatuh diam-diam ke classical, harness menandainya FAIL, bukan PASS.

## 1c. Handshake secondary authentication P2P (end-to-end EAP-over-RADIUS)

Jalur live EAP-over-RADIUS (harness UE initiator -> FreeRADIUS `rlm_eap_edhoc` untuk method 0..4, `rlm_eap_tls` untuk method 5 dan 6). 100 iterasi per method, tanpa loss. Method 5 dan 6 diukur berurutan (lihat catatan metodologi di atas), tetapi keduanya live.

Baris perwakilan (satu handshake sukses per method), kolom identik dengan `analysis.md` bagian 1c (`duration_ms` menggantikan `duration_sec`; nilai adalah durasi pertukaran EAP-EDHOC saja, bukan seluruh registrasi 5G):

| Method | timestamp | iteration | status | duration_ms | pdu_success_count |
| --- | --- | --- | --- | --- | --- |
| 0 | 2026-08-14T10:07:07+0900 | 1 | PASS | 2.216 | 1 |
| 1 | 2026-08-14T10:07:08+0900 | 1 | PASS | 1.659 | 1 |
| 2 | 2026-08-14T10:07:08+0900 | 1 | PASS | 1.651 | 1 |
| 3 | 2026-08-14T10:07:08+0900 | 1 | PASS | 1.538 | 1 |
| 4 | 2026-08-14T10:07:08+0900 | 1 | PASS | 6.499 | 1 |
| 5 | 2026-08-14T10:12:21+0900 | 1 | PASS | 5.500 | 1 |
| 6 | 2026-08-14T10:24:07+0900 | 1 | PASS | 14.045 | 1 |

### Ringkasan statistik handshake end-to-end per method

| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 100 | 100.0 | 1.722 | 0.490 | 8.518 | 0.373 | 25.684 | 3 | 3 |
| 1 | SIG/STAT | 100 | 100.0 | 0.907 | 0.885 | 1.158 | 0.669 | 1.659 | 3 | 3 |
| 2 | STAT/SIG | 100 | 100.0 | 0.848 | 0.800 | 1.149 | 0.676 | 1.651 | 3 | 3 |
| 3 | STAT/STAT | 100 | 100.0 | 0.941 | 0.843 | 1.193 | 0.696 | 4.154 | 3 | 3 |
| 4 | SIGMA-XWING-PQC | 100 | 100.0 | 7.742 | 5.898 | 12.408 | 2.882 | 123.607 | 17 | 17 |
| 5 | EAP-TLS-Classic | 100 | 100.0 | 4.282 | 4.101 | 5.501 | 3.625 | 7.041 | 9 | 9 |
| 6 | EAP-TLS-Hybrid-PQC | 100 | 100.0 | 9.455 | 7.790 | 15.751 | 6.825 | 52.758 | 28 | 28 |

- Handshake end-to-end tercepat: **method 2** (STAT/SIG).
- Handshake end-to-end terlambat: **method 6** (EAP-TLS-Hybrid-PQC), karena fragmentasi EAP membutuhkan 28 round-trip RADIUS dibanding 3 untuk method klasik.

> Bagian 1a dan 1b berikut adalah pengukuran primitif/komputasi yang **identik** dengan `analysis.md` (independen terhadap transport), disertakan agar kedua dokumen memiliki kolom yang sama persis.

## 1a. Breakdown komputasi primitif kriptografi

Latensi per operasi primitif (pengukuran nyata, libsodium + mbedTLS + PQClean).

| Operation | Lib | Iter | Mean (ns) | Median (ns) | p95 (ns) | p99 (ns) | Stddev (ns) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Keygen_X25519 | libsodium | 3000 | 24004.0 | 20536.0 | 21961.0 | 111065.0 | 28270.9 |
| ScalarMult_X25519 | libsodium | 3000 | 24888.8 | 21961.0 | 23550.0 | 117989.0 | 16869.7 |
| Keygen_Ed25519 | libsodium | 3000 | 10882.0 | 9464.0 | 10396.0 | 72195.0 | 12332.9 |
| Signature_Ed25519 | libsodium | 3000 | 11225.8 | 9664.0 | 10350.0 | 65055.0 | 16348.0 |
| Verify_Ed25519 | libsodium | 3000 | 29693.1 | 26632.0 | 30303.0 | 107835.0 | 21513.7 |
| SHA256 | libsodium | 3000 | 262.8 | 262.0 | 266.0 | 267.0 | 2.7 |
| HKDF_SHA256 | libsodium | 3000 | 1447.6 | 1117.0 | 1148.0 | 1252.0 | 5968.8 |
| AES128GCM | mbedTLS | 3000 | 254.8 | 228.0 | 230.0 | 231.0 | 1266.2 |
| Keygen_MLKEM768 | PQClean | 3000 | 34582.4 | 30688.0 | 41467.0 | 129760.0 | 19357.5 |
| Encaps_MLKEM768 | PQClean | 3000 | 39528.4 | 33147.0 | 58460.0 | 152274.0 | 47954.9 |
| Decaps_MLKEM768 | PQClean | 3000 | 47707.7 | 42002.0 | 85800.0 | 166671.0 | 34353.1 |
| Keygen_MLDSA44 | PQClean | 3000 | 57264.4 | 49737.0 | 100359.0 | 207756.0 | 39540.4 |
| Signature_MLDSA44 | PQClean | 3000 | 237660.0 | 185264.0 | 583052.0 | 976302.0 | 203541.2 |
| Verify_MLDSA44 | PQClean | 3000 | 62322.5 | 53773.0 | 121024.0 | 196086.0 | 41195.9 |
| Keygen_RSA2048 | pyca/cryptography(OpenSSL) | 30 | 104872119.9 | 97656191.5 | 195124792.8 | 223465944.8 | 52104213.0 |
| Signature_RSA2048 | pyca/cryptography(OpenSSL) | 500 | 394245.6 | 352154.5 | 518293.4 | 888279.2 | 181477.2 |
| Verify_RSA2048 | pyca/cryptography(OpenSSL) | 500 | 20433.3 | 20154.0 | 21038.8 | 27888.4 | 1898.1 |

## 1b. Breakdown komputasi per method (Keygen, Scalar mult, Encaps, Decaps, Signature, Verify)

Kontribusi waktu komputasi tiap operasi dalam satu handshake (initiator = UE, responder = DN-AAA).

| Method | Role | Operation | Primitive | Count | Compute (ns) |
| --- | --- | --- | --- | --- | --- |
| 0 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 0 | initiator | ScalarMult | X25519 | 1 | 24888.8 |
| 0 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 0 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 0 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 11225.8 |
| 0 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 29693.1 |
| 0 | responder | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 0 | responder | ScalarMult | X25519 | 1 | 24888.8 |
| 0 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 0 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 0 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11225.8 |
| 0 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 29693.1 |
| 1 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 1 | initiator | ScalarMult | X25519 | 1 | 24888.8 |
| 1 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 1 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 1 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 11225.8 |
| 1 | initiator | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 1 | responder | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 1 | responder | ScalarMult | X25519 | 2 | 49777.6 |
| 1 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 1 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 1 | responder | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 1 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 29693.1 |
| 2 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 2 | initiator | ScalarMult | X25519 | 2 | 49777.6 |
| 2 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 2 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 2 | initiator | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 2 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 29693.1 |
| 2 | responder | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 2 | responder | ScalarMult | X25519 | 1 | 24888.8 |
| 2 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 2 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 2 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11225.8 |
| 2 | responder | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 3 | initiator | ScalarMult | X25519 | 2 | 49777.6 |
| 3 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 3 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 3 | initiator | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | initiator | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | responder | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 3 | responder | ScalarMult | X25519 | 2 | 49777.6 |
| 3 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 3 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 3 | responder | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | responder | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 4 | initiator | Keygen | X25519/ML-KEM-768 | 5 | 141177.0 |
| 4 | initiator | ScalarMult | X25519 | 3 | 74666.4 |
| 4 | initiator | Encaps | ML-KEM-768 | 1 | 39528.4 |
| 4 | initiator | Decaps | ML-KEM-768 | 2 | 95415.3 |
| 4 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 237660.0 |
| 4 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 62322.5 |
| 4 | responder | Keygen | X25519/ML-KEM-768 | 4 | 106594.5 |
| 4 | responder | ScalarMult | X25519 | 3 | 74666.4 |
| 4 | responder | Encaps | ML-KEM-768 | 2 | 79056.9 |
| 4 | responder | Decaps | ML-KEM-768 | 1 | 47707.7 |
| 4 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 237660.0 |
| 4 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 62322.5 |
| 5 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 5 | initiator | ScalarMult | X25519 | 1 | 24888.8 |
| 5 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 5 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 5 | initiator | Signature | Ed25519/ML-DSA-44/RSA-2048 | 1 | 394245.6 |
| 5 | initiator | Verify | Ed25519/ML-DSA-44/RSA-2048 | 1 | 20433.3 |
| 5 | responder | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 5 | responder | ScalarMult | X25519 | 1 | 24888.8 |
| 5 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Signature | Ed25519/ML-DSA-44/RSA-2048 | 1 | 394245.6 |
| 5 | responder | Verify | Ed25519/ML-DSA-44/RSA-2048 | 1 | 20433.3 |
| 6 | initiator | Keygen | X25519/ML-KEM-768 | 2 | 58586.4 |
| 6 | initiator | ScalarMult | X25519 | 1 | 24888.8 |
| 6 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 6 | initiator | Decaps | ML-KEM-768 | 1 | 47707.7 |
| 6 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 237660.0 |
| 6 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 62322.5 |
| 6 | responder | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 6 | responder | ScalarMult | X25519 | 1 | 24888.8 |
| 6 | responder | Encaps | ML-KEM-768 | 1 | 39528.4 |
| 6 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 6 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 237660.0 |
| 6 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 62322.5 |

### Total komputasi handshake per method

| Method | Profil | Initiator (us) | Responder (us) | Total (us) |
| --- | --- | --- | --- | --- |
| 0 | SIG/SIG Ed25519 | 89.812 | 89.812 | 179.623 |
| 1 | SIG-Ed25519 / MAC-X25519 | 60.119 | 103.475 | 163.593 |
| 2 | MAC-X25519 / SIG-Ed25519 | 103.475 | 60.119 | 163.593 |
| 3 | MAC/MAC static-DH X25519 | 73.782 | 73.782 | 147.563 |
| 4 | SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768) | 650.770 | 608.008 | 1258.778 |
| 5 | EAP-TLS Classic (X25519 ECDHE + RSA-2048, mutual) | 463.572 | 463.572 | 927.143 |
| 6 | EAP-TLS Hybrid PQC (X25519MLKEM768 hybrid KEM, ML-DSA-44 cert) | 431.165 | 388.404 | 819.569 |

- Termurah secara komputasi: **method 3** (MAC/MAC static-DH X25519, 147.563 us).
- Termahal secara komputasi: **method 4** (SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768), 1258.778 us).

> **Peringatan baca:** urutan termurah/termahal di atas HANYA waktu komputasi kripto murni (µs) — TIDAK termasuk round-trip jaringan RADIUS/fragmentasi EAP. Urutan itu BUKAN urutan kecepatan handshake end-to-end nyata. Untuk urutan yang sebenarnya dialami pengguna (termasuk RTT), lihat `analisys2.md` section 1c — di sana method 6 (EAP-TLS Hybrid PQC) adalah yang paling lambat secara live, bukan method 4, justru karena jumlah round-trip fragmentasi EAP-nya yang jauh lebih banyak, sesuatu yang tidak tertangkap oleh tabel compute murni ini.

## 2. Performa pada jaringan lossy (end-to-end EAP-over-RADIUS)

Handshake EAP-EDHOC/EAP-TLS nyata melalui RADIUS dengan retransmisi gaya EAP (RTO 40 ms, maks 6 retransmisi per pertukaran); loss diemulasi di level aplikasi pada tiap datagram UDP nyata. 120 percobaan per sel, semua method (0..6) live.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 1.692 | 4.753 | 0.000 |
| 0 | 1.0 | 100.0 | 3.038 | 3.997 | 0.042 |
| 0 | 5.0 | 100.0 | 16.819 | 84.172 | 0.367 |
| 0 | 10.0 | 100.0 | 32.623 | 131.355 | 0.700 |
| 0 | 20.0 | 99.2 | 77.309 | 213.626 | 1.792 |
| 0 | 30.0 | 94.2 | 130.009 | 294.815 | 2.800 |
| 1 | 0.0 | 100.0 | 0.940 | 1.482 | 0.000 |
| 1 | 1.0 | 100.0 | 3.489 | 42.798 | 0.058 |
| 1 | 5.0 | 100.0 | 19.869 | 87.299 | 0.400 |
| 1 | 10.0 | 100.0 | 34.105 | 90.028 | 0.742 |
| 1 | 20.0 | 100.0 | 80.183 | 221.916 | 1.708 |
| 1 | 30.0 | 97.5 | 123.326 | 290.434 | 2.692 |
| 2 | 0.0 | 100.0 | 0.824 | 1.059 | 0.000 |
| 2 | 1.0 | 100.0 | 4.951 | 43.165 | 0.092 |
| 2 | 5.0 | 100.0 | 13.397 | 51.613 | 0.275 |
| 2 | 10.0 | 100.0 | 27.510 | 97.715 | 0.600 |
| 2 | 20.0 | 100.0 | 88.381 | 233.256 | 1.867 |
| 2 | 30.0 | 100.0 | 130.561 | 312.409 | 2.917 |
| 3 | 0.0 | 100.0 | 0.786 | 1.143 | 0.000 |
| 3 | 1.0 | 100.0 | 3.853 | 41.540 | 0.067 |
| 3 | 5.0 | 100.0 | 14.507 | 48.937 | 0.308 |
| 3 | 10.0 | 100.0 | 37.862 | 122.938 | 0.817 |
| 3 | 20.0 | 99.2 | 81.119 | 214.577 | 1.867 |
| 3 | 30.0 | 99.2 | 137.265 | 336.802 | 3.117 |
| 4 | 0.0 | 100.0 | 6.127 | 9.624 | 0.000 |
| 4 | 1.0 | 100.0 | 20.099 | 90.919 | 0.308 |
| 4 | 5.0 | 100.0 | 93.210 | 235.189 | 1.908 |
| 4 | 10.0 | 100.0 | 172.090 | 317.874 | 3.742 |
| 4 | 20.0 | 97.5 | 454.634 | 766.241 | 9.550 |
| 4 | 30.0 | 86.7 | 768.277 | 1212.616 | 14.542 |
| 5 | 0.0 | 100.0 | 4.441 | 5.242 | 0.000 |
| 5 | 1.0 | 100.0 | 9.791 | 49.993 | 0.117 |
| 5 | 5.0 | 100.0 | 51.110 | 135.392 | 0.875 |
| 5 | 10.0 | 100.0 | 97.618 | 242.142 | 2.033 |
| 5 | 20.0 | 100.0 | 238.939 | 482.221 | 5.025 |
| 5 | 30.0 | 87.5 | 444.280 | 804.189 | 8.233 |
| 6 | 0.0 | 100.0 | 8.112 | 12.103 | 0.000 |
| 6 | 1.0 | 100.0 | 37.871 | 101.879 | 0.600 |
| 6 | 5.0 | 100.0 | 124.426 | 280.081 | 2.608 |
| 6 | 10.0 | 100.0 | 291.985 | 545.642 | 6.283 |
| 6 | 20.0 | 99.2 | 710.622 | 1063.183 | 16.033 |
| 6 | 30.0 | 70.0 | 1131.184 | 1726.407 | 18.233 |

> Bagian 3 (interoperabilitas primitif) identik dengan `analysis.md`.

## 3. Interoperabilitas dengan implementasi EDHOC

Primitif cipher-suite EDHOC divalidasi silang terhadap implementasi independen (pyca/cryptography, backend OpenSSL).

Lolos 11/11 pemeriksaan.

| Pemeriksaan | Hasil | Detail |
| --- | --- | --- |
| X25519_ECDH_libsodium_vs_OpenSSL | PASS | shared secrets match |
| Ed25519_libsodium_sign_OpenSSL_verify | PASS | OpenSSL verified libsodium signature |
| Ed25519_OpenSSL_sign_libsodium_verify | PASS | libsodium verified OpenSSL signature |
| MLKEM768_PQClean_roundtrip | PASS | ml_kem_768 pk=1184 sk=2400 ct=1088 ss=32 |
| size_X25519_public_key | PASS | expected=32 actual=32 |
| size_Ed25519_signature | PASS | expected=64 actual=64 |
| size_MAC_AES_CCM_16_64 | PASS | expected=8 actual=8 |
| size_MLKEM768_encap_key | PASS | expected=1184 actual=1184 |
| size_MLKEM768_ciphertext | PASS | expected=1088 actual=1088 |
| size_MLDSA44_verify_key | PASS | expected=1312 actual=1312 |
| size_MLDSA44_signature | PASS | expected=2420 actual=2420 |

## 4. Pengaruh ukuran paket terhadap MTU dan fragmentasi

Ukuran pesan dan jumlah fragmen EAP untuk method 0..6 di bawah ini adalah **hasil observasi langsung** dari byte yang benar-benar dikirim/diterima harness (bukan perkiraan) — termasuk method 6, yang sekarang live sama seperti method lainnya. `EAP frags` = fragmen EDHOC/TLS yang teramati; `EAP attrs` = atribut EAP-Message 253 B (RFC 3579); `IP frags` dan `>MTU` diturunkan dari byte teramati pada MTU 1500.

| Method | Pesan | Bytes | EAP attrs | EAP frags | IP frags | >MTU | Sumber |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | message_1 | 34 | 1 | 1 | 1 | no | observasi nyata |
| 0 | message_2 | 147 | 1 | 1 | 1 | no | observasi nyata |
| 0 | message_3 | 115 | 1 | 1 | 1 | no | observasi nyata |
| 1 | message_1 | 34 | 1 | 1 | 1 | no | observasi nyata |
| 1 | message_2 | 91 | 1 | 1 | 1 | no | observasi nyata |
| 1 | message_3 | 115 | 1 | 1 | 1 | no | observasi nyata |
| 2 | message_1 | 34 | 1 | 1 | 1 | no | observasi nyata |
| 2 | message_2 | 147 | 1 | 1 | 1 | no | observasi nyata |
| 2 | message_3 | 59 | 1 | 1 | 1 | no | observasi nyata |
| 3 | message_1 | 34 | 1 | 1 | 1 | no | observasi nyata |
| 3 | message_2 | 91 | 1 | 1 | 1 | no | observasi nyata |
| 3 | message_3 | 59 | 1 | 1 | 1 | no | observasi nyata |
| 4 | message_1 | 2354 | 10 | 3 | 2 | yes | observasi nyata |
| 4 | message_2 | 6000 | 24 | 7 | 4 | yes | observasi nyata |
| 4 | message_3 | 4975 | 20 | 5 | 4 | yes | observasi nyata |
| 4 | message_4 | 1232 | 5 | 2 | 1 | no | observasi nyata |
| 5 | message_1 | 289 | 2 | 1 | 1 | no | observasi nyata |
| 5 | message_2 | 2967 | 12 | 3 | 2 | yes | observasi nyata |
| 5 | message_3 | 2703 | 11 | 3 | 2 | yes | observasi nyata |
| 5 | message_4 | 51 | 1 | 1 | 1 | no | observasi nyata |
| 6 | message_1 | 1589 | 7 | 2 | 2 | yes | observasi nyata |
| 6 | message_2 | 12600 | 50 | 13 | 9 | yes | observasi nyata |
| 6 | message_3 | 10983 | 44 | 11 | 8 | yes | observasi nyata |
| 6 | message_4 | 23 | 1 | 1 | 1 | no | observasi nyata |

Pesan yang memerlukan fragmentasi pada method 4 (SIGMA XWING PQC) dan method 6 (EAP-TLS Hybrid PQC) — keduanya observasi nyata: XWING/hybrid-KEM (X25519+ML-KEM-768) menambah ~1.1-1.2 KB per elemen KEM dan tanda tangan ML-DSA-44 menambah ~2.4 KB per pesan, sehingga keduanya memerlukan banyak round-trip fragmentasi EAP sedangkan method 0, 1, 2, 3 dan 5 (klasik) selalu muat dalam sedikit fragmen.

