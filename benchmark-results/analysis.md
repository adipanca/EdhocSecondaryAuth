# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication

_Dibuat otomatis oleh benchmark/analyze.py pada 2026-07-22T15:00:45._

Method matrix:

| Method | Initiator | Responder | Profil kripto |
| --- | --- | --- | --- |
| 0 | SIG (Ed25519) | SIG (Ed25519) | Ed25519 |
| 1 | SIG (Ed25519) | MAC (static-DH X25519) | Ed25519 + X25519 |
| 2 | MAC (static-DH X25519) | SIG (Ed25519) | X25519 + Ed25519 |
| 3 | MAC (static-DH X25519) | MAC (static-DH X25519) | X25519 |
| 4 | SIGMA (ML-DSA-44) | SIGMA (ML-DSA-44) | XWING (X25519 + ML-KEM-768) + ML-DSA-44 (PQC) |

## 1c. Handshake secondary authentication P2P (end-to-end 5G)

Jalur live 5G (UERANSIM UE -> AMF -> SMF -> UPF -> FreeRADIUS). PASS 1/1 iterasi.

10 baris terakhir:

| timestamp | iteration | status | duration_sec | pdu_success_count |
| --- | --- | --- | --- | --- |
| 2026-06-24T15:56:00+09:00 | 1 | PASS | 70 | 1 |

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

## 2. Performa pada jaringan lossy

Handshake 3-pesan EDHOC dengan retransmisi gaya EAP; loss diemulasi di level aplikasi pada socket UDP nyata.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 4.106 | 7.765 | 0.0 |
| 0 | 1.0 | 100.0 | 5.201 | 9.091 | 0.025 |
| 0 | 5.0 | 100.0 | 13.157 | 49.04 | 0.217 |
| 0 | 10.0 | 100.0 | 23.287 | 87.732 | 0.458 |
| 0 | 20.0 | 100.0 | 46.019 | 129.674 | 1.008 |
| 0 | 30.0 | 98.3 | 87.946 | 251.013 | 2.125 |
| 1 | 0.0 | 100.0 | 4.087 | 6.92 | 0.0 |
| 1 | 1.0 | 100.0 | 4.617 | 9.215 | 0.017 |
| 1 | 5.0 | 100.0 | 13.327 | 49.955 | 0.217 |
| 1 | 10.0 | 100.0 | 20.173 | 86.357 | 0.4 |
| 1 | 20.0 | 99.2 | 41.703 | 127.133 | 0.983 |
| 1 | 30.0 | 97.5 | 89.136 | 253.769 | 2.192 |
| 2 | 0.0 | 100.0 | 3.985 | 7.705 | 0.0 |
| 2 | 1.0 | 100.0 | 5.677 | 10.843 | 0.033 |
| 2 | 5.0 | 100.0 | 11.71 | 48.884 | 0.175 |
| 2 | 10.0 | 100.0 | 23.559 | 87.02 | 0.467 |
| 2 | 20.0 | 100.0 | 59.001 | 172.586 | 1.325 |
| 2 | 30.0 | 96.7 | 87.371 | 213.198 | 2.233 |
| 3 | 0.0 | 100.0 | 5.406 | 13.495 | 0.0 |
| 3 | 1.0 | 100.0 | 6.624 | 22.546 | 0.042 |
| 3 | 5.0 | 100.0 | 16.682 | 84.607 | 0.283 |
| 3 | 10.0 | 100.0 | 23.679 | 89.051 | 0.467 |
| 3 | 20.0 | 100.0 | 48.883 | 136.174 | 1.083 |
| 3 | 30.0 | 99.2 | 86.065 | 259.877 | 2.008 |
| 4 | 0.0 | 100.0 | 3.366 | 4.807 | 0.0 |
| 4 | 1.0 | 100.0 | 5.127 | 8.253 | 0.025 |
| 4 | 5.0 | 100.0 | 14.297 | 47.853 | 0.242 |
| 4 | 10.0 | 100.0 | 25.407 | 90.185 | 0.517 |
| 4 | 20.0 | 100.0 | 51.347 | 133.888 | 1.133 |
| 4 | 30.0 | 99.2 | 76.473 | 221.57 | 1.775 |

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

Ukuran pesan dihitung dari elemen kripto nyata; fragmentasi EAP (RFC 3579, atribut 253 B) dan IP (MTU 1500) diturunkan darinya.

| Method | Pesan | Bytes | EAP attrs | EAP frags | IP frags | >MTU |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | message_1 | 38 | 1 | 1 | 1 | no |
| 0 | message_2 | 103 | 1 | 1 | 1 | no |
| 0 | message_3 | 77 | 1 | 1 | 1 | no |
| 1 | message_1 | 38 | 1 | 1 | 1 | no |
| 1 | message_2 | 46 | 1 | 1 | 1 | no |
| 1 | message_3 | 77 | 1 | 1 | 1 | no |
| 2 | message_1 | 38 | 1 | 1 | 1 | no |
| 2 | message_2 | 103 | 1 | 1 | 1 | no |
| 2 | message_3 | 20 | 1 | 1 | 1 | no |
| 3 | message_1 | 38 | 1 | 1 | 1 | no |
| 3 | message_2 | 46 | 1 | 1 | 1 | no |
| 3 | message_3 | 20 | 1 | 1 | 1 | no |
| 4 | message_1 | 2355 | 10 | 3 | 2 | yes |
| 4 | message_2 | 5998 | 24 | 6 | 5 | yes |
| 4 | message_3 | 4967 | 20 | 5 | 4 | yes |
| 4 | message_4 | 1227 | 5 | 2 | 1 | no |
Pesan yang memerlukan fragmentasi terdapat pada method 4 (profil SIGMA XWING PQC), karena XWING (X25519+ML-KEM-768) menambah ~1.1–1.2 KB per elemen KEM dan tanda tangan ML-DSA-44 menambah ~2.4 KB per pesan.
