# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)

_Dibuat otomatis oleh benchmark/e2e_analyze.py pada 2026-08-14T13:59:06._

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
| 5 | EAP-TLS Classic (mutual, Ed25519) | EAP-TLS Classic (mutual, Ed25519) | X25519 ECDHE + Ed25519 (classical TLS) |
| 6 | EAP-TLS Hybrid PQC (mutual, ML-DSA-44) | EAP-TLS Hybrid PQC (mutual, ML-DSA-44) | X25519MLKEM768 hybrid KEM + ML-DSA-44 (PQC) |

> **Catatan metodologi — bagaimana method 5 dan method 6 diukur:** Method **0-6 seluruhnya** diukur end-to-end secara **live** di atas EAP-over-RADIUS nyata terhadap `rlm_eap_tls`/`rlm_eap_edhoc` yang hidup. Method 5 memakai sertifikat **Ed25519** (bukan RSA-2048) supaya perbandingan dengan EDHOC klasik (method 0-3, yang semuanya Ed25519 + X25519) apples-to-apples: algoritma tanda tangan dan grup DH-nya identik, sehingga selisih yang tersisa murni berasal dari framing protokol (TLS record + X.509 vs CBOR EDHOC) dan transport (fragmentasi EAP RFC 5216 vs EDHOC-over-EAP), bukan dari pilihan algoritma kripto. (Sertifikat RSA-2048 asli masih tersimpan di `raddb/certs/rsa2048-backup/` kalau diperlukan sebagai referensi.) Method 5 (klasik, Ed25519) dan method 6 (hybrid-PQC, ML-DSA-44 + grup KEM X25519MLKEM768) memakai `rlm_eap_tls` yang SAMA, tetapi satu instance `tls {}` hanya bisa memegang satu pasangan sertifikat/grup pada satu waktu — jadi keduanya diukur **berurutan, bukan bersamaan**: `benchmark/switch_tls_config.sh classic|hybrid` menukar `tls-config` yang dipakai lalu me-restart radiusd (untuk method 6, ditambah variabel lingkungan `OPENSSL_CONF`/`OPENSSL_MODULES` yang mengaktifkan `oqs-provider`, lihat `pqc-tls/openssl-hybrid.cnf`). Method 6 memerlukan OpenSSL >= 3.2 untuk sertifikat/tanda tangan ML-DSA-44 di TLS1.3 (`oqs-provider` belum mendukung ini di versi OpenSSL yang lebih lama); lingkungan ini memakai OpenSSL 3.0.13 secara default, sehingga sebuah build OpenSSL 3.2.6 privat (`pqc-tls/openssl32/`) dipakai lewat `LD_LIBRARY_PATH` khusus untuk radiusd dan harness method 6 saja — `rlm_eap_tls`/radiusd sendiri tidak diubah kodenya untuk ini (hanya linking runtime-nya), kecuali satu pengecekan versi OpenSSL di `src/main/version.c` yang direlaksasi agar tidak menolak kombinasi minor-version 3.0/3.2 ini (OpenSSL menjamin stabilitas ABI/API di seluruh seri 3.x). Setiap handshake method 6 diverifikasi (bukan cuma diasumsikan) benar-benar memakai grup `X25519MLKEM768` dan sertifikat `mldsa44` lewat `SSL_get0_group_name()`/`EVP_PKEY_get0_type_name()` — kalau sampai jatuh diam-diam ke classical, harness menandainya FAIL, bukan PASS.

## 1c. Handshake secondary authentication P2P (end-to-end EAP-over-RADIUS)

Jalur live EAP-over-RADIUS (harness UE initiator -> FreeRADIUS `rlm_eap_edhoc` untuk method 0..4, `rlm_eap_tls` untuk method 5 dan 6). 100 iterasi per method, tanpa loss. Method 5 dan 6 diukur berurutan (lihat catatan metodologi di atas), tetapi keduanya live.

Baris perwakilan (satu handshake sukses per method), kolom identik dengan `analysis.md` bagian 1c (`duration_ms` menggantikan `duration_sec`; nilai adalah durasi pertukaran EAP-EDHOC saja, bukan seluruh registrasi 5G):

| Method | timestamp | iteration | status | duration_ms | pdu_success_count |
| --- | --- | --- | --- | --- | --- |
| 0 | 2026-08-14T13:39:19+0900 | 1 | PASS | 3.284 | 1 |
| 1 | 2026-08-14T13:39:19+0900 | 1 | PASS | 1.503 | 1 |
| 2 | 2026-08-14T13:39:19+0900 | 1 | PASS | 2.035 | 1 |
| 3 | 2026-08-14T13:39:20+0900 | 1 | PASS | 1.443 | 1 |
| 4 | 2026-08-14T13:39:20+0900 | 1 | PASS | 5.000 | 1 |
| 5 | 2026-08-14T13:48:41+0900 | 1 | PASS | 4.114 | 1 |
| 6 | 2026-08-14T13:53:17+0900 | 1 | PASS | 13.392 | 1 |

### Ringkasan statistik handshake end-to-end per method

| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 100 | 100.0 | 0.960 | 0.890 | 1.281 | 0.674 | 3.284 | 3 | 3 |
| 1 | SIG/STAT | 100 | 100.0 | 0.886 | 0.783 | 1.507 | 0.690 | 2.705 | 3 | 3 |
| 2 | STAT/SIG | 100 | 100.0 | 1.136 | 0.859 | 3.567 | 0.686 | 7.760 | 3 | 3 |
| 3 | STAT/STAT | 100 | 100.0 | 1.007 | 0.841 | 1.819 | 0.696 | 5.007 | 3 | 3 |
| 4 | SIGMA-XWING-PQC | 100 | 100.0 | 5.765 | 5.181 | 9.359 | 4.221 | 15.038 | 17 | 17 |
| 5 | EAP-TLS-Classic | 100 | 100.0 | 3.047 | 2.732 | 4.651 | 2.376 | 10.293 | 6 | 6 |
| 6 | EAP-TLS-Hybrid-PQC | 100 | 100.0 | 8.674 | 7.868 | 14.460 | 6.497 | 20.731 | 28 | 28 |

- Handshake end-to-end tercepat: **method 1** (SIG/STAT).
- Handshake end-to-end terlambat: **method 6** (EAP-TLS-Hybrid-PQC), karena fragmentasi EAP membutuhkan 28 round-trip RADIUS dibanding 3 untuk method klasik.

### Pembagian beban initiator vs responder (live, wall-clock nyata)

Setiap harness (UE/initiator) mengukur, per round-trip RADIUS, waktu yang dihabiskan **menunggu balasan** (`send()` sampai `recv()` kembali) secara terpisah dari waktu yang dihabiskan **mengerjakan sendiri** (membangun paket RADIUS/EAP, HMAC-MD5 Message-Authenticator, dan menjalankan engine EDHOC/TLS-nya sendiri) di antara round-trip. `responder_ms` = total waktu menunggu (mendominasi oleh pemrosesan penuh di sisi FreeRADIUS — parsing, dispatch modul, kripto, serialisasi balasan — karena transit jaringan nyata di loopback nyaris nol); `initiator_ms` = `duration_ms` dikurangi itu, murni kerja lokal UE. Ini pengukuran **live nyata** per handshake, bukan model — berbeda dari section 1b yang cuma menghitung compute kripto murni tanpa overhead RADIUS/TLS-framing sama sekali.

| Method | Profil | Initiator mean (ms) | Responder mean (ms) | Initiator % | Responder % | Total mean (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 0.118 | 0.841 | 12.3% | 87.7% | 0.960 |
| 1 | SIG/STAT | 0.108 | 0.778 | 12.2% | 87.8% | 0.886 |
| 2 | STAT/SIG | 0.145 | 0.990 | 12.8% | 87.2% | 1.136 |
| 3 | STAT/STAT | 0.121 | 0.886 | 12.0% | 88.0% | 1.007 |
| 4 | SIGMA-XWING-PQC | 0.827 | 4.938 | 14.3% | 85.7% | 5.766 |
| 5 | EAP-TLS-Classic | 0.619 | 2.428 | 20.3% | 79.7% | 3.047 |
| 6 | EAP-TLS-Hybrid-PQC | 0.685 | 7.989 | 7.9% | 92.1% | 8.674 |

- Di semua method, beban **responder** (AAA/FreeRADIUS) mendominasi total waktu handshake — wajar, karena responder-lah yang benar-benar memproses paket RADIUS (parsing, dispatch modul, verifikasi kripto) dan initiator cuma menunggu selama itu; porsi initiator yang genuinely CPU-bound (encode paket + panggilan engine lokal) jauh lebih kecil dari total.
- Proporsi responder tertinggi: **method 6** (EAP-TLS-Hybrid-PQC).

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
| Keygen_RSA2048 | pyca/cryptography(OpenSSL) | 30 | 121835084.6 | 112639921.0 | 212098736.2 | 232936779.6 | 55131841.2 |
| Signature_RSA2048 | pyca/cryptography(OpenSSL) | 500 | 442925.7 | 362334.0 | 740862.3 | 1621179.1 | 247948.5 |
| Verify_RSA2048 | pyca/cryptography(OpenSSL) | 500 | 23481.5 | 20138.5 | 30472.5 | 105832.6 | 20127.1 |

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
| 5 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 5 | initiator | ScalarMult | X25519 | 1 | 24888.8 |
| 5 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 5 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 5 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 11225.8 |
| 5 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 29693.1 |
| 5 | responder | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 5 | responder | ScalarMult | X25519 | 1 | 24888.8 |
| 5 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11225.8 |
| 5 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 29693.1 |

### Total komputasi handshake per method

| Method | Profil | Initiator (us) | Responder (us) | Total (us) |
| --- | --- | --- | --- | --- |
| 0 | SIG/SIG Ed25519 | 89.812 | 89.812 | 179.623 |
| 1 | SIG-Ed25519 / MAC-X25519 | 60.119 | 103.475 | 163.593 |
| 2 | MAC-X25519 / SIG-Ed25519 | 103.475 | 60.119 | 163.593 |
| 3 | MAC/MAC static-DH X25519 | 73.782 | 73.782 | 147.563 |
| 4 | SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768) | 650.770 | 608.008 | 1258.778 |
| 6 | EAP-TLS Hybrid PQC (X25519MLKEM768 hybrid KEM, ML-DSA-44 cert) | 431.165 | 388.404 | 819.569 |
| 5 | EAP-TLS Classic (X25519 ECDHE + Ed25519, mutual) | 89.812 | 89.812 | 179.623 |

- Termurah secara komputasi: **method 3** (MAC/MAC static-DH X25519, 147.563 us).
- Termahal secara komputasi: **method 4** (SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768), 1258.778 us).

> **Peringatan baca:** urutan termurah/termahal di atas HANYA waktu komputasi kripto murni (µs) — TIDAK termasuk round-trip jaringan RADIUS/fragmentasi EAP. Urutan itu BUKAN urutan kecepatan handshake end-to-end nyata. Untuk urutan yang sebenarnya dialami pengguna (termasuk RTT), lihat `analisys2.md` section 1c — di sana method 6 (EAP-TLS Hybrid PQC) adalah yang paling lambat secara live, bukan method 4, justru karena jumlah round-trip fragmentasi EAP-nya yang jauh lebih banyak, sesuatu yang tidak tertangkap oleh tabel compute murni ini.

## 2. Performa pada jaringan lossy (end-to-end EAP-over-RADIUS)

Handshake EAP-EDHOC/EAP-TLS nyata melalui RADIUS dengan retransmisi gaya EAP (RTO 40 ms, maks 6 retransmisi per pertukaran); loss diemulasi di level aplikasi pada tiap datagram UDP nyata. 120 percobaan per sel, semua method (0..6) live.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 0.980 | 1.622 | 0.000 |
| 0 | 1.0 | 100.0 | 4.582 | 42.110 | 0.083 |
| 0 | 5.0 | 100.0 | 19.617 | 84.037 | 0.433 |
| 0 | 10.0 | 100.0 | 30.265 | 87.170 | 0.675 |
| 0 | 20.0 | 99.2 | 83.532 | 208.702 | 1.933 |
| 0 | 30.0 | 98.3 | 122.180 | 294.701 | 2.792 |
| 1 | 0.0 | 100.0 | 0.919 | 1.232 | 0.000 |
| 1 | 1.0 | 100.0 | 4.606 | 42.153 | 0.083 |
| 1 | 5.0 | 100.0 | 15.308 | 83.782 | 0.333 |
| 1 | 10.0 | 100.0 | 34.477 | 123.537 | 0.775 |
| 1 | 20.0 | 100.0 | 69.578 | 181.842 | 1.608 |
| 1 | 30.0 | 95.8 | 130.142 | 293.008 | 2.892 |
| 2 | 0.0 | 100.0 | 1.551 | 5.750 | 0.000 |
| 2 | 1.0 | 100.0 | 4.415 | 42.405 | 0.075 |
| 2 | 5.0 | 100.0 | 12.520 | 43.911 | 0.275 |
| 2 | 10.0 | 100.0 | 23.362 | 84.906 | 0.525 |
| 2 | 20.0 | 100.0 | 77.735 | 210.208 | 1.783 |
| 2 | 30.0 | 97.5 | 127.022 | 294.386 | 2.867 |
| 3 | 0.0 | 100.0 | 1.092 | 2.961 | 0.000 |
| 3 | 1.0 | 100.0 | 1.891 | 1.369 | 0.025 |
| 3 | 5.0 | 100.0 | 13.963 | 83.096 | 0.300 |
| 3 | 10.0 | 100.0 | 30.893 | 95.373 | 0.692 |
| 3 | 20.0 | 100.0 | 76.727 | 213.317 | 1.750 |
| 3 | 30.0 | 96.7 | 123.436 | 303.303 | 2.775 |
| 4 | 0.0 | 100.0 | 5.837 | 8.939 | 0.000 |
| 4 | 1.0 | 100.0 | 20.373 | 55.558 | 0.342 |
| 4 | 5.0 | 100.0 | 80.961 | 210.463 | 1.733 |
| 4 | 10.0 | 100.0 | 190.252 | 373.194 | 4.250 |
| 4 | 20.0 | 98.3 | 448.355 | 728.836 | 10.183 |
| 4 | 30.0 | 85.8 | 735.024 | 1148.339 | 14.750 |
| 5 | 0.0 | 100.0 | 3.083 | 4.016 | 0.000 |
| 5 | 1.0 | 100.0 | 8.629 | 46.273 | 0.125 |
| 5 | 5.0 | 100.0 | 29.649 | 95.914 | 0.600 |
| 5 | 10.0 | 100.0 | 68.915 | 208.984 | 1.500 |
| 5 | 20.0 | 99.2 | 127.816 | 276.891 | 2.867 |
| 5 | 30.0 | 94.2 | 249.059 | 518.585 | 5.392 |
| 6 | 0.0 | 100.0 | 8.582 | 12.214 | 0.000 |
| 6 | 1.0 | 100.0 | 34.136 | 98.346 | 0.558 |
| 6 | 5.0 | 100.0 | 139.167 | 308.411 | 2.967 |
| 6 | 10.0 | 100.0 | 294.860 | 554.220 | 6.567 |
| 6 | 20.0 | 96.7 | 669.079 | 1071.006 | 14.642 |
| 6 | 30.0 | 79.2 | 1229.697 | 1942.375 | 22.467 |

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
| 5 | message_2 | 1148 | 5 | 2 | 1 | no | observasi nyata |
| 5 | message_3 | 990 | 4 | 1 | 1 | no | observasi nyata |
| 5 | message_4 | 51 | 1 | 1 | 1 | no | observasi nyata |
| 6 | message_1 | 1589 | 7 | 2 | 2 | yes | observasi nyata |
| 6 | message_2 | 12600 | 50 | 13 | 9 | yes | observasi nyata |
| 6 | message_3 | 10983 | 44 | 11 | 8 | yes | observasi nyata |
| 6 | message_4 | 23 | 1 | 1 | 1 | no | observasi nyata |

Pesan yang memerlukan fragmentasi pada method 4 (SIGMA XWING PQC) dan method 6 (EAP-TLS Hybrid PQC) — keduanya observasi nyata: XWING/hybrid-KEM (X25519+ML-KEM-768) menambah ~1.1-1.2 KB per elemen KEM dan tanda tangan ML-DSA-44 menambah ~2.4 KB per pesan, sehingga keduanya memerlukan banyak round-trip fragmentasi EAP sedangkan method 0, 1, 2, 3 dan 5 (klasik) selalu muat dalam sedikit fragmen.

