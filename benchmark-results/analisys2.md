# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)

_Dibuat otomatis oleh benchmark/e2e_analyze.py pada 2026-07-23T16:22:19._

Dokumen ini adalah pasangan **end-to-end** dari `analysis.md`. Setiap angka diperoleh dari handshake EAP-EDHOC **nyata** yang berjalan di atas transport EAP-over-RADIUS (RFC 2865/3579) menuju responder FreeRADIUS `rlm_eap_edhoc` yang hidup di `127.0.0.1:1812`. Tidak ada estimasi/proyeksi: kolom setiap tabel dibuat **identik** dengan `analysis.md` agar perbedaan tiap method dapat dibandingkan langsung antara kedua percobaan.

Setiap method 0..4 diimplementasikan penuh dan interoperable: method 0..3 (klasik: Ed25519 SIG / static-DH X25519 MAC, core `edhoc03`) dan method 4 (SIGMA XWING PQC, core `edhoc4`). Method 0..3 memakai 3 pesan (tanpa message_4), method 4 memakai 4 pesan dengan fragmentasi EAP.

Method matrix:

| Method | Initiator | Responder | Profil kripto |
| --- | --- | --- | --- |
| 0 | SIG (Ed25519) | SIG (Ed25519) | Ed25519 |
| 1 | SIG (Ed25519) | MAC (static-DH X25519) | Ed25519 + X25519 |
| 2 | MAC (static-DH X25519) | SIG (Ed25519) | X25519 + Ed25519 |
| 3 | MAC (static-DH X25519) | MAC (static-DH X25519) | X25519 |
| 4 | SIGMA (ML-DSA-44) | SIGMA (ML-DSA-44) | XWING (X25519 + ML-KEM-768) + ML-DSA-44 (PQC) |

## 1c. Handshake secondary authentication P2P (end-to-end EAP-over-RADIUS)

Jalur live EAP-over-RADIUS (harness UE initiator -> FreeRADIUS rlm_eap_edhoc responder). 100 iterasi per method, tanpa loss.

Baris perwakilan (satu handshake sukses per method), kolom identik dengan `analysis.md` bagian 1c (`duration_ms` menggantikan `duration_sec`; nilai adalah durasi pertukaran EAP-EDHOC saja, bukan seluruh registrasi 5G):

| Method | timestamp | iteration | status | duration_ms | pdu_success_count |
| --- | --- | --- | --- | --- | --- |
| 0 | 2026-07-23T16:15:24+0900 | 1 | PASS | 2.963 | 1 |
| 1 | 2026-07-23T16:15:25+0900 | 1 | PASS | 1.562 | 1 |
| 2 | 2026-07-23T16:15:25+0900 | 1 | PASS | 1.781 | 1 |
| 3 | 2026-07-23T16:15:25+0900 | 1 | PASS | 1.612 | 1 |
| 4 | 2026-07-23T16:15:25+0900 | 1 | PASS | 10.149 | 1 |

### Ringkasan statistik handshake end-to-end per method

| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 100 | 100.0 | 1.024 | 0.877 | 2.092 | 0.667 | 3.021 | 3 | 3 |
| 1 | SIG/STAT | 100 | 100.0 | 0.970 | 0.895 | 1.569 | 0.678 | 2.140 | 3 | 3 |
| 2 | STAT/SIG | 100 | 100.0 | 0.963 | 0.847 | 1.753 | 0.675 | 3.676 | 3 | 3 |
| 3 | STAT/STAT | 100 | 100.0 | 0.947 | 0.849 | 1.560 | 0.680 | 3.846 | 3 | 3 |
| 4 | SIGMA-XWING-PQC | 100 | 100.0 | 6.971 | 5.919 | 12.106 | 4.209 | 28.392 | 17 | 17 |

- Handshake end-to-end tercepat: **method 3** (STAT/STAT).
- Handshake end-to-end terlambat: **method 4** (SIGMA-XWING-PQC), karena fragmentasi EAP membutuhkan 17 round-trip RADIUS dibanding 3 untuk method klasik.

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

### Total komputasi handshake per method

| Method | Profil | Initiator (us) | Responder (us) | Total (us) |
| --- | --- | --- | --- | --- |
| 0 | SIG/SIG Ed25519 | 89.812 | 89.812 | 179.623 |
| 1 | SIG-Ed25519 / MAC-X25519 | 60.119 | 103.475 | 163.593 |
| 2 | MAC-X25519 / SIG-Ed25519 | 103.475 | 60.119 | 163.593 |
| 3 | MAC/MAC static-DH X25519 | 73.782 | 73.782 | 147.563 |
| 4 | SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768) | 650.770 | 608.008 | 1258.778 |

- Termurah secara komputasi: **method 3** (MAC/MAC static-DH X25519, 147.563 us).
- Termahal secara komputasi: **method 4** (SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768), 1258.778 us).

## 2. Performa pada jaringan lossy (end-to-end EAP-over-RADIUS)

Handshake EAP-EDHOC nyata melalui RADIUS dengan retransmisi gaya EAP (RTO 40 ms, maks 6 retransmisi per pertukaran); loss diemulasi di level aplikasi pada tiap datagram UDP nyata. 120 percobaan per sel.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 0.986 | 1.754 | 0.000 |
| 0 | 1.0 | 100.0 | 3.740 | 19.628 | 0.050 |
| 0 | 5.0 | 100.0 | 15.513 | 47.392 | 0.342 |
| 0 | 10.0 | 100.0 | 25.432 | 88.618 | 0.575 |
| 0 | 20.0 | 100.0 | 64.905 | 171.766 | 1.533 |
| 0 | 30.0 | 99.2 | 122.151 | 294.859 | 2.842 |
| 1 | 0.0 | 100.0 | 0.933 | 1.355 | 0.000 |
| 1 | 1.0 | 100.0 | 3.398 | 41.384 | 0.058 |
| 1 | 5.0 | 100.0 | 19.306 | 86.586 | 0.433 |
| 1 | 10.0 | 100.0 | 39.979 | 127.452 | 0.925 |
| 1 | 20.0 | 99.2 | 67.747 | 173.611 | 1.583 |
| 1 | 30.0 | 96.7 | 132.455 | 338.593 | 3.025 |
| 2 | 0.0 | 100.0 | 0.542 | 0.921 | 0.000 |
| 2 | 1.0 | 100.0 | 4.432 | 41.458 | 0.083 |
| 2 | 5.0 | 100.0 | 13.994 | 45.477 | 0.308 |
| 2 | 10.0 | 100.0 | 31.869 | 124.923 | 0.742 |
| 2 | 20.0 | 99.2 | 73.924 | 246.700 | 1.700 |
| 2 | 30.0 | 98.3 | 130.502 | 298.590 | 3.033 |
| 3 | 0.0 | 100.0 | 1.030 | 1.629 | 0.000 |
| 3 | 1.0 | 100.0 | 3.559 | 41.364 | 0.058 |
| 3 | 5.0 | 100.0 | 16.329 | 48.877 | 0.358 |
| 3 | 10.0 | 100.0 | 28.724 | 85.380 | 0.658 |
| 3 | 20.0 | 100.0 | 68.212 | 178.851 | 1.583 |
| 3 | 30.0 | 98.3 | 115.017 | 257.533 | 2.675 |
| 4 | 0.0 | 100.0 | 6.305 | 8.615 | 0.000 |
| 4 | 1.0 | 100.0 | 17.304 | 51.485 | 0.275 |
| 4 | 5.0 | 100.0 | 87.966 | 175.184 | 1.942 |
| 4 | 10.0 | 100.0 | 169.369 | 333.591 | 3.900 |
| 4 | 20.0 | 100.0 | 409.701 | 666.418 | 9.633 |
| 4 | 30.0 | 89.2 | 694.433 | 1025.383 | 14.700 |

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

## 4. Pengaruh ukuran paket terhadap MTU dan fragmentasi (observasi nyata)

Ukuran pesan dan jumlah fragmen EAP di bawah ini adalah **hasil observasi langsung** dari byte yang benar-benar dikirim harness (bukan perkiraan). `EAP frags` = fragmen EDHOC (wrapper 1000 B) yang teramati; `EAP attrs` = atribut EAP-Message 253 B (RFC 3579); `IP frags` dan `>MTU` diturunkan dari byte teramati pada MTU 1500.

| Method | Pesan | Bytes | EAP attrs | EAP frags | IP frags | >MTU |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | message_1 | 34 | 1 | 1 | 1 | no |
| 0 | message_2 | 147 | 1 | 1 | 1 | no |
| 0 | message_3 | 115 | 1 | 1 | 1 | no |
| 1 | message_1 | 34 | 1 | 1 | 1 | no |
| 1 | message_2 | 91 | 1 | 1 | 1 | no |
| 1 | message_3 | 115 | 1 | 1 | 1 | no |
| 2 | message_1 | 34 | 1 | 1 | 1 | no |
| 2 | message_2 | 147 | 1 | 1 | 1 | no |
| 2 | message_3 | 59 | 1 | 1 | 1 | no |
| 3 | message_1 | 34 | 1 | 1 | 1 | no |
| 3 | message_2 | 91 | 1 | 1 | 1 | no |
| 3 | message_3 | 59 | 1 | 1 | 1 | no |
| 4 | message_1 | 2354 | 10 | 3 | 2 | yes |
| 4 | message_2 | 6000 | 24 | 7 | 4 | yes |
| 4 | message_3 | 4975 | 20 | 5 | 4 | yes |
| 4 | message_4 | 1232 | 5 | 2 | 1 | no |
Pesan yang memerlukan fragmentasi hanya pada method 4 (profil SIGMA XWING PQC): XWING (X25519+ML-KEM-768) menambah ~1.1–1.2 KB per elemen KEM dan tanda tangan ML-DSA-44 menambah ~2.4 KB per pesan, sehingga method 4 memerlukan banyak round-trip fragmentasi EAP sedangkan method 0..3 selalu muat dalam satu fragmen.

