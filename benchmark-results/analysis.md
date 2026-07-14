# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication

_Dibuat otomatis oleh benchmark/analyze.py pada 2026-06-24T16:10:45._

Method matrix:

| Method | Initiator | Responder | Profil kripto |
| --- | --- | --- | --- |
| 0 | SIG (Ed25519) | SIG (Ed25519) | Ed25519 |
| 1 | SIG (Ed25519) | MAC (static-DH X25519) | Ed25519 + X25519 |
| 2 | MAC (static-DH X25519) | SIG (Ed25519) | X25519 + Ed25519 |
| 3 | MAC (static-DH X25519) | MAC (static-DH X25519) | X25519 |
| 4 | MAC (static-XWING) | MAC (static-XWING) | X25519 + ML-KEM-768 (PQC) |

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
| Keygen_X25519 | libsodium | 3000 | 26256.3 | 20547.0 | 32937.0 | 145257.0 | 53926.2 |
| ScalarMult_X25519 | libsodium | 3000 | 26580.8 | 21979.0 | 27060.0 | 135527.0 | 40057.2 |
| Keygen_Ed25519 | libsodium | 3000 | 11820.2 | 9445.0 | 10914.0 | 81875.0 | 24262.3 |
| Signature_Ed25519 | libsodium | 3000 | 11303.6 | 9670.0 | 10232.0 | 58975.0 | 21752.1 |
| Verify_Ed25519 | libsodium | 3000 | 32790.2 | 26192.0 | 40955.0 | 163781.0 | 57709.4 |
| SHA256 | libsodium | 3000 | 261.7 | 261.0 | 265.0 | 265.0 | 4.8 |
| HKDF_SHA256 | libsodium | 3000 | 1139.2 | 1087.0 | 1111.0 | 1144.0 | 1568.2 |
| AES128GCM | mbedTLS | 3000 | 258.7 | 236.0 | 238.0 | 239.0 | 1253.6 |
| Keygen_MLKEM768 | PQClean | 3000 | 33745.9 | 28540.0 | 32462.0 | 129200.0 | 53611.0 |
| Encaps_MLKEM768 | PQClean | 3000 | 34288.0 | 30399.0 | 36607.0 | 128317.0 | 24861.9 |
| Decaps_MLKEM768 | PQClean | 3000 | 42795.0 | 38845.0 | 47108.0 | 137908.0 | 20809.4 |
| Keygen_MLDSA44 | PQClean | 3000 | 55757.8 | 49590.0 | 97237.0 | 181770.0 | 27705.7 |
| Signature_MLDSA44 | PQClean | 3000 | 226232.8 | 178860.0 | 551238.0 | 833738.0 | 160158.7 |
| Verify_MLDSA44 | PQClean | 3000 | 59211.9 | 52996.0 | 100690.0 | 181919.0 | 29391.9 |

## 1b. Breakdown komputasi per method (Keygen, Scalar mult, Encaps, Decaps, Signature, Verify)

Kontribusi waktu komputasi tiap operasi dalam satu handshake (initiator = UE, responder = DN-AAA).

| Method | Role | Operation | Primitive | Count | Compute (ns) |
| --- | --- | --- | --- | --- | --- |
| 0 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 0 | initiator | ScalarMult | X25519 | 1 | 26580.8 |
| 0 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 0 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 0 | initiator | Signature | Ed25519 | 1 | 11303.6 |
| 0 | initiator | Verify | Ed25519 | 1 | 32790.2 |
| 0 | responder | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 0 | responder | ScalarMult | X25519 | 1 | 26580.8 |
| 0 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 0 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 0 | responder | Signature | Ed25519 | 1 | 11303.6 |
| 0 | responder | Verify | Ed25519 | 1 | 32790.2 |
| 1 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 1 | initiator | ScalarMult | X25519 | 1 | 26580.8 |
| 1 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 1 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 1 | initiator | Signature | Ed25519 | 1 | 11303.6 |
| 1 | initiator | Verify | Ed25519 | 0 | 0.0 |
| 1 | responder | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 1 | responder | ScalarMult | X25519 | 2 | 53161.6 |
| 1 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 1 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 1 | responder | Signature | Ed25519 | 0 | 0.0 |
| 1 | responder | Verify | Ed25519 | 1 | 32790.2 |
| 2 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 2 | initiator | ScalarMult | X25519 | 2 | 53161.6 |
| 2 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 2 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 2 | initiator | Signature | Ed25519 | 0 | 0.0 |
| 2 | initiator | Verify | Ed25519 | 1 | 32790.2 |
| 2 | responder | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 2 | responder | ScalarMult | X25519 | 1 | 26580.8 |
| 2 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 2 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 2 | responder | Signature | Ed25519 | 1 | 11303.6 |
| 2 | responder | Verify | Ed25519 | 0 | 0.0 |
| 3 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 3 | initiator | ScalarMult | X25519 | 2 | 53161.6 |
| 3 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 3 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 3 | initiator | Signature | Ed25519 | 0 | 0.0 |
| 3 | initiator | Verify | Ed25519 | 0 | 0.0 |
| 3 | responder | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 3 | responder | ScalarMult | X25519 | 2 | 53161.6 |
| 3 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 3 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 3 | responder | Signature | Ed25519 | 0 | 0.0 |
| 3 | responder | Verify | Ed25519 | 0 | 0.0 |
| 4 | initiator | Keygen | X25519/ML-KEM-768 | 2 | 60002.1 |
| 4 | initiator | ScalarMult | X25519 | 1 | 26580.8 |
| 4 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 4 | initiator | Decaps | ML-KEM-768 | 2 | 85590.0 |
| 4 | initiator | Signature | Ed25519 | 0 | 0.0 |
| 4 | initiator | Verify | Ed25519 | 0 | 0.0 |
| 4 | responder | Keygen | X25519/ML-KEM-768 | 1 | 26256.3 |
| 4 | responder | ScalarMult | X25519 | 2 | 53161.6 |
| 4 | responder | Encaps | ML-KEM-768 | 2 | 68576.0 |
| 4 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 4 | responder | Signature | Ed25519 | 0 | 0.0 |
| 4 | responder | Verify | Ed25519 | 0 | 0.0 |

### Total komputasi handshake per method

| Method | Profil | Initiator (us) | Responder (us) | Total (us) |
| --- | --- | --- | --- | --- |
| 0 | SIG/SIG Ed25519 | 96.931 | 96.931 | 193.862 |
| 1 | SIG-Ed25519 / MAC-X25519 | 64.141 | 112.208 | 176.349 |
| 2 | MAC-X25519 / SIG-Ed25519 | 112.208 | 64.141 | 176.349 |
| 3 | MAC/MAC static-DH X25519 | 79.418 | 79.418 | 158.836 |
| 4 | MAC/MAC XWING (X25519+ML-KEM-768) | 172.173 | 147.994 | 320.167 |

- Termurah secara komputasi: **method 3** (MAC/MAC static-DH X25519, 158.836 us).
- Termahal secara komputasi: **method 4** (MAC/MAC XWING (X25519+ML-KEM-768), 320.167 us).

## 2. Performa pada jaringan lossy

Handshake 3-pesan EDHOC dengan retransmisi gaya EAP; loss diemulasi di level aplikasi pada socket UDP nyata.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 4.208 | 7.459 | 0.0 |
| 0 | 1.0 | 100.0 | 4.908 | 7.748 | 0.025 |
| 0 | 5.0 | 100.0 | 12.833 | 49.953 | 0.217 |
| 0 | 10.0 | 100.0 | 23.074 | 89.068 | 0.458 |
| 0 | 20.0 | 100.0 | 45.519 | 132.566 | 1.008 |
| 0 | 30.0 | 98.3 | 87.296 | 247.334 | 2.125 |
| 1 | 0.0 | 100.0 | 3.739 | 6.02 | 0.0 |
| 1 | 1.0 | 100.0 | 4.301 | 7.002 | 0.017 |
| 1 | 5.0 | 100.0 | 12.839 | 48.139 | 0.217 |
| 1 | 10.0 | 100.0 | 20.589 | 88.456 | 0.4 |
| 1 | 20.0 | 99.2 | 42.749 | 132.883 | 0.983 |
| 1 | 30.0 | 97.5 | 90.728 | 250.75 | 2.233 |
| 2 | 0.0 | 100.0 | 3.877 | 6.511 | 0.0 |
| 2 | 1.0 | 100.0 | 5.22 | 9.353 | 0.033 |
| 2 | 5.0 | 100.0 | 11.327 | 47.495 | 0.175 |
| 2 | 10.0 | 100.0 | 23.603 | 89.8 | 0.458 |
| 2 | 20.0 | 100.0 | 58.025 | 172.08 | 1.308 |
| 2 | 30.0 | 96.7 | 86.977 | 209.756 | 2.242 |
| 3 | 0.0 | 100.0 | 4.607 | 10.111 | 0.0 |
| 3 | 1.0 | 100.0 | 5.757 | 8.837 | 0.042 |
| 3 | 5.0 | 100.0 | 15.348 | 85.315 | 0.283 |
| 3 | 10.0 | 100.0 | 24.548 | 88.91 | 0.483 |
| 3 | 20.0 | 100.0 | 49.749 | 132.091 | 1.092 |
| 3 | 30.0 | 99.2 | 84.382 | 251.145 | 2.0 |
| 4 | 0.0 | 100.0 | 4.264 | 8.932 | 0.0 |
| 4 | 1.0 | 100.0 | 4.4 | 6.177 | 0.025 |
| 4 | 5.0 | 100.0 | 13.98 | 47.993 | 0.25 |
| 4 | 10.0 | 100.0 | 26.286 | 92.837 | 0.525 |
| 4 | 20.0 | 100.0 | 48.919 | 131.362 | 1.092 |
| 4 | 30.0 | 99.2 | 75.141 | 213.096 | 1.758 |

## 3. Interoperabilitas dengan implementasi EDHOC

Primitif cipher-suite EDHOC divalidasi silang terhadap implementasi independen (pyca/cryptography, backend OpenSSL).

Lolos 9/9 pemeriksaan.

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
| 4 | message_1 | 1223 | 5 | 2 | 1 | no |
| 4 | message_2 | 1135 | 5 | 2 | 1 | no |
| 4 | message_3 | 20 | 1 | 1 | 1 | no |
Pesan yang memerlukan fragmentasi terdapat pada method 4 (profil PQC XWING), karena ML-KEM-768 menambah ~1–1.2 KB per pesan.

