# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication

_Dibuat otomatis oleh benchmark/analyze.py pada 2026-10-29T11:39:00._

Method matrix:

| Method | Initiator | Responder | Profil kripto |
| --- | --- | --- | --- |
| 0 | SIG (Ed25519) | SIG (Ed25519) | Ed25519 |
| 1 | SIG (Ed25519) | MAC (static-DH X25519) | Ed25519 + X25519 |
| 2 | MAC (static-DH X25519) | SIG (Ed25519) | X25519 + Ed25519 |
| 3 | MAC (static-DH X25519) | MAC (static-DH X25519) | X25519 |
| 4 | SIGMA (ML-DSA-44) | SIGMA (ML-DSA-44) | XWING (X25519 + ML-KEM-768) + ML-DSA-44 (PQC) |
| 5 | EAP-TLS Classic (mutual, Ed25519) | EAP-TLS Classic (mutual, Ed25519) | X25519 ECDHE + Ed25519 (classical TLS) |
| 6 | EAP-TLS Hybrid PQC (X25519MLKEM768 + ML-DSA-44) | EAP-TLS Hybrid PQC (X25519MLKEM768 + ML-DSA-44) | X25519MLKEM768 hybrid KEM + ML-DSA-44 (PQC) |

> **Catatan metodologi:** `analysis.md` (dokumen ini) adalah pandangan primitif/komputasi murni, independen terhadap transport, untuk SEMUA method 0-6 secara konsisten (section 1a/1b/4 di bawah memakai model/komputasi, bukan byte yang benar-benar diobservasi di kabel, untuk method manapun) — ini pilihan desain dokumen ini, bukan keterbatasan. Method 6 (EAP-TLS Hybrid PQC) SEKARANG JUGA diukur end-to-end secara live melalui EAP-over-RADIUS nyata (liboqs + oqs-provider terpasang, tls-config ML-DSA-44 + grup hybrid X25519MLKEM768 dipakai oleh `rlm_eap_tls`) — lihat `analisys2.md` untuk angka live-nya (section 1c/2), yang membandingkannya langsung dengan method 4 (SIGMA-XWING PQC) dan method 5 (EAP-TLS Classic).

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
| Keygen_X25519 | libsodium | 3000 | 25535.0 | 20908.0 | 37063.0 | 119769.0 | 29916.4 |
| ScalarMult_X25519 | libsodium | 3000 | 25163.6 | 21986.0 | 38243.0 | 96128.0 | 19026.1 |
| Keygen_Ed25519 | libsodium | 3000 | 10730.4 | 9453.0 | 9865.0 | 24795.0 | 17311.9 |
| Signature_Ed25519 | libsodium | 3000 | 11069.9 | 9660.0 | 10270.0 | 57661.0 | 10090.7 |
| Verify_Ed25519 | libsodium | 3000 | 29438.8 | 26193.0 | 31224.0 | 112777.0 | 20344.7 |
| SHA256 | libsodium | 3000 | 299.6 | 262.0 | 275.0 | 277.0 | 1233.2 |
| HKDF_SHA256 | libsodium | 3000 | 1455.6 | 1107.0 | 1147.0 | 1936.0 | 5021.7 |
| AES128GCM | mbedTLS | 3000 | 226.0 | 225.0 | 229.0 | 230.0 | 20.7 |
| Keygen_MLKEM768 | PQClean | 3000 | 32440.5 | 28845.0 | 33769.0 | 121631.0 | 24175.8 |
| Encaps_MLKEM768 | PQClean | 3000 | 33775.5 | 30744.0 | 34407.0 | 120757.0 | 19317.3 |
| Decaps_MLKEM768 | PQClean | 3000 | 41870.0 | 38544.0 | 44115.0 | 127021.0 | 21982.2 |
| Keygen_MLDSA44 | PQClean | 3000 | 56853.6 | 49436.0 | 99271.0 | 188883.0 | 41449.2 |
| Signature_MLDSA44 | PQClean | 3000 | 223240.5 | 161314.0 | 524059.0 | 1017444.0 | 212971.3 |
| Verify_MLDSA44 | PQClean | 3000 | 59596.1 | 53955.0 | 77449.0 | 182822.0 | 28309.9 |
| Keygen_RSA2048 | pyca/cryptography(OpenSSL) | 30 | 120316211.1 | 97294573.5 | 216257887.7 | 261913624.5 | 58562015.0 |
| Signature_RSA2048 | pyca/cryptography(OpenSSL) | 500 | 413753.9 | 366106.5 | 631892.9 | 965104.2 | 124882.5 |
| Verify_RSA2048 | pyca/cryptography(OpenSSL) | 500 | 22266.8 | 20089.0 | 27313.6 | 88074.0 | 12917.6 |

## 1b. Breakdown komputasi per method (Keygen, Scalar mult, Encaps, Decaps, Signature, Verify)

Kontribusi waktu komputasi tiap operasi dalam satu handshake (initiator = UE, responder = DN-AAA). Untuk EAP-TLS (method 5/6), Verify = 2 per pihak: CertificateVerify + tanda tangan CA pada sertifikat peer (rantai root CA -> end-entity, tanpa intermediate). EDHOC (method 0-4) tidak memakai sertifikat. Method 4: Keygen = 3 per pihak (X25519 ephemeral di dalam encapsulation X-Wing + pasangan kunci rotasi X25519/ML-KEM-768 untuk EAD3/EAD4), semuanya dihitung di dalam handshake.

| Method | Role | Operation | Primitive | Count | Compute (ns) |
| --- | --- | --- | --- | --- | --- |
| 0 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 0 | initiator | ScalarMult | X25519 | 1 | 25163.6 |
| 0 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 0 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 0 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 11069.9 |
| 0 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 29438.8 |
| 0 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 0 | responder | ScalarMult | X25519 | 1 | 25163.6 |
| 0 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 0 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 0 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11069.9 |
| 0 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 29438.8 |
| 1 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 1 | initiator | ScalarMult | X25519 | 2 | 50327.3 |
| 1 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 1 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 1 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 11069.9 |
| 1 | initiator | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 1 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 1 | responder | ScalarMult | X25519 | 2 | 50327.3 |
| 1 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 1 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 1 | responder | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 1 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 29438.8 |
| 2 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 2 | initiator | ScalarMult | X25519 | 2 | 50327.3 |
| 2 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 2 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 2 | initiator | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 2 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 29438.8 |
| 2 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 2 | responder | ScalarMult | X25519 | 2 | 50327.3 |
| 2 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 2 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 2 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11069.9 |
| 2 | responder | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 3 | initiator | ScalarMult | X25519 | 3 | 75490.8 |
| 3 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 3 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 3 | initiator | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | initiator | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 3 | responder | ScalarMult | X25519 | 3 | 75490.8 |
| 3 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 3 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 3 | responder | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | responder | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 4 | initiator | Keygen | X25519/ML-KEM-768 | 3 | 83510.4 |
| 4 | initiator | ScalarMult | X25519 | 2 | 50327.3 |
| 4 | initiator | Encaps | ML-KEM-768 | 1 | 33775.5 |
| 4 | initiator | Decaps | ML-KEM-768 | 1 | 41870.0 |
| 4 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 223240.5 |
| 4 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 59596.1 |
| 4 | responder | Keygen | X25519/ML-KEM-768 | 3 | 83510.4 |
| 4 | responder | ScalarMult | X25519 | 2 | 50327.3 |
| 4 | responder | Encaps | ML-KEM-768 | 1 | 33775.5 |
| 4 | responder | Decaps | ML-KEM-768 | 1 | 41870.0 |
| 4 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 223240.5 |
| 4 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 59596.1 |
| 5 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 5 | initiator | ScalarMult | X25519 | 1 | 25163.6 |
| 5 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 5 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 5 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 11069.9 |
| 5 | initiator | Verify | Ed25519/ML-DSA-44 | 2 | 58877.6 |
| 5 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 5 | responder | ScalarMult | X25519 | 1 | 25163.6 |
| 5 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11069.9 |
| 5 | responder | Verify | Ed25519/ML-DSA-44 | 2 | 58877.6 |
| 6 | initiator | Keygen | X25519/ML-KEM-768 | 2 | 57975.5 |
| 6 | initiator | ScalarMult | X25519 | 1 | 25163.6 |
| 6 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 6 | initiator | Decaps | ML-KEM-768 | 1 | 41870.0 |
| 6 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 223240.5 |
| 6 | initiator | Verify | Ed25519/ML-DSA-44 | 2 | 119192.2 |
| 6 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 6 | responder | ScalarMult | X25519 | 1 | 25163.6 |
| 6 | responder | Encaps | ML-KEM-768 | 1 | 33775.5 |
| 6 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 6 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 223240.5 |
| 6 | responder | Verify | Ed25519/ML-DSA-44 | 2 | 119192.2 |

### Total komputasi handshake per method

| Method | Profil | Initiator (us) | Responder (us) | Total (us) |
| --- | --- | --- | --- | --- |
| 0 | SIG/SIG Ed25519 | 91.207 | 91.207 | 182.415 |
| 1 | SIG-Ed25519 / MAC-X25519 | 86.932 | 105.301 | 192.233 |
| 2 | MAC-X25519 / SIG-Ed25519 | 105.301 | 86.932 | 192.233 |
| 3 | MAC/MAC static-DH X25519 | 101.026 | 101.026 | 202.052 |
| 4 | SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768) | 492.320 | 492.320 | 984.640 |
| 5 | EAP-TLS Classic (X25519 ECDHE + Ed25519, mutual) | 120.646 | 120.646 | 241.292 |
| 6 | EAP-TLS Hybrid PQC (X25519MLKEM768 hybrid KEM, ML-DSA-44 cert) | 467.442 | 426.907 | 894.349 |

- Termurah secara komputasi: **method 0** (SIG/SIG Ed25519, 182.415 us).
- Termahal secara komputasi: **method 4** (SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768), 984.640 us).

> **Peringatan baca:** urutan termurah/termahal di atas HANYA waktu komputasi kripto murni (µs) — TIDAK termasuk round-trip jaringan RADIUS/fragmentasi EAP. Urutan itu BUKAN urutan kecepatan handshake end-to-end nyata. Untuk urutan yang sebenarnya dialami pengguna (termasuk RTT), lihat `analisys2.md` section 1c — di sana method 6 (EAP-TLS Hybrid PQC) adalah yang paling lambat secara live, bukan method 4, justru karena jumlah round-trip fragmentasi EAP-nya yang jauh lebih banyak, sesuatu yang tidak tertangkap oleh tabel compute murni ini.

### Operasi kriptografi per method (Initiator/Responder)

| Method | X25519 KeyGen | X25519 DH | ML-KEM KeyGen | Encaps | Decaps | Sign | Verify |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 1/1 | 1/1 | - | - | - | 1/1 | 1/1 |
| 1 | 1/1 | 2/2 | - | - | - | 1/0 | 0/1 |
| 2 | 1/1 | 2/2 | - | - | - | 0/1 | 1/0 |
| 3 | 1/1 | 3/3 | - | - | - | - | - |
| 4 | 2/2 | 2/2 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| 5 | 1/1 | 1/1 | - | - | - | 1/1 | 2/2 |
| 6 | 1/1 | 1/1 | 1/0 | 0/1 | 1/0 | 1/1 | 2/2 |

### Komputasi per fungsi (kedua pihak, ms)

Key exchange: share X25519 ephemeral, DH ephemeral, operasi KEM. Authentication: tanda tangan transcript dan verifikasinya, atau static DH. Certificate check: tanda tangan CA pada sertifikat peer. Key rotation: pasangan kunci X-Wing one-time berikutnya.

| Method | Key exchange | Authentication | Certificate check | Key rotation | Total |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.101 | 0.081 | - | - | 0.182 |
| 1 | 0.101 | 0.091 | - | - | 0.192 |
| 2 | 0.101 | 0.091 | - | - | 0.192 |
| 3 | 0.101 | 0.101 | - | - | 0.202 |
| 4 | 0.303 | 0.566 | - | 0.116 | 0.985 |
| 5 | 0.101 | 0.081 | 0.059 | - | 0.241 |
| 6 | 0.209 | 0.566 | 0.119 | - | 0.894 |

### Kebijakan precompute yang sama untuk kedua protokol

| Aturan (sama untuk kedua sisi) | Proposal (ms) | EAP-TLS Hybrid (ms) |
| --- | --- | --- |
| Semua keygen di dalam handshake | 0.985 | 0.894 |
| Hanya "kunci berikutnya" di muka (kunci rotasi proposal <-> key share client TLS) | 0.869 | 0.836 |
| Semua keygen yang tidak bergantung sesi di muka (termasuk share X25519 ephemeral) | 0.818 | 0.811 |

Dengan aturan yang sama, komputasi kedua protokol hampir sama; perbedaannya ada di transport.

## 2. Performa pada jaringan lossy (simulasi 2-round-trip, semua method)

Handshake 2-round-trip (message_1→message_2, message_3→message_4/ack) gaya EAP dengan retransmisi, di atas socket UDP nyata; ukuran payload per method sesuai `edhoc_sizes.py` (method 0-4 model dari elemen kripto, method 5-6 byte nyata hasil observasi live), loss diemulasi di level aplikasi. Mencakup method 0-6.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 4.734 | 9.438 | 0.0 |
| 0 | 1.0 | 100.0 | 5.882 | 12.318 | 0.025 |
| 0 | 5.0 | 100.0 | 14.991 | 54.405 | 0.217 |
| 0 | 10.0 | 100.0 | 24.408 | 88.711 | 0.458 |
| 0 | 20.0 | 100.0 | 49.984 | 147.857 | 1.008 |
| 0 | 30.0 | 98.3 | 92.935 | 261.683 | 2.125 |
| 1 | 0.0 | 100.0 | 3.635 | 4.899 | 0.0 |
| 1 | 1.0 | 100.0 | 5.869 | 11.381 | 0.017 |
| 1 | 5.0 | 100.0 | 14.848 | 54.332 | 0.217 |
| 1 | 10.0 | 100.0 | 22.587 | 89.863 | 0.4 |
| 1 | 20.0 | 99.2 | 44.025 | 134.038 | 0.983 |
| 1 | 30.0 | 97.5 | 92.913 | 255.791 | 2.192 |
| 2 | 0.0 | 100.0 | 4.055 | 7.645 | 0.0 |
| 2 | 1.0 | 100.0 | 6.696 | 13.481 | 0.033 |
| 2 | 5.0 | 100.0 | 13.243 | 51.966 | 0.175 |
| 2 | 10.0 | 100.0 | 25.636 | 93.37 | 0.467 |
| 2 | 20.0 | 100.0 | 62.391 | 177.804 | 1.325 |
| 2 | 30.0 | 96.7 | 91.936 | 226.199 | 2.233 |
| 3 | 0.0 | 100.0 | 4.953 | 11.294 | 0.0 |
| 3 | 1.0 | 100.0 | 7.191 | 19.819 | 0.042 |
| 3 | 5.0 | 100.0 | 17.149 | 86.103 | 0.283 |
| 3 | 10.0 | 100.0 | 24.871 | 92.61 | 0.467 |
| 3 | 20.0 | 100.0 | 50.879 | 140.767 | 1.083 |
| 3 | 30.0 | 99.2 | 92.859 | 250.958 | 2.017 |
| 4 | 0.0 | 100.0 | 6.323 | 12.843 | 0.0 |
| 4 | 1.0 | 100.0 | 6.345 | 14.353 | 0.025 |
| 4 | 5.0 | 100.0 | 14.796 | 51.779 | 0.242 |
| 4 | 10.0 | 100.0 | 27.498 | 102.028 | 0.517 |
| 4 | 20.0 | 100.0 | 54.395 | 138.873 | 1.133 |
| 4 | 30.0 | 99.2 | 81.021 | 232.531 | 1.775 |
| 5 | 0.0 | 100.0 | 4.81 | 9.619 | 0.0 |
| 5 | 1.0 | 100.0 | 8.048 | 49.024 | 0.067 |
| 5 | 5.0 | 100.0 | 13.962 | 49.667 | 0.192 |
| 5 | 10.0 | 100.0 | 18.159 | 85.97 | 0.325 |
| 5 | 20.0 | 98.3 | 59.973 | 181.839 | 1.358 |
| 5 | 30.0 | 100.0 | 94.884 | 260.719 | 2.042 |
| 6 | 0.0 | 100.0 | 4.851 | 10.573 | 0.0 |
| 6 | 1.0 | 100.0 | 6.632 | 14.946 | 0.025 |
| 6 | 5.0 | 100.0 | 15.213 | 50.582 | 0.267 |
| 6 | 10.0 | 100.0 | 26.667 | 98.462 | 0.508 |
| 6 | 20.0 | 100.0 | 50.846 | 168.616 | 1.042 |
| 6 | 30.0 | 95.8 | 89.13 | 208.975 | 2.192 |
> **Keterbatasan penting:** skrip ini SELALU 2 round-trip jaringan berapa pun ukuran pesannya — TIDAK memodelkan fragmentasi EAP (RFC 3579/5216), sehingga TIDAK menangkap efek amplifikasi paparan-loss dari pesan besar yang sebenarnya terpecah jadi banyak fragmen/round-trip (tiap fragmen = satu kesempatan tambahan kena loss). Efek itu justru yang paling penting untuk method 4/6 (pesan besar, banyak fragmen) — lihat perbedaannya sendiri: method 6 di sini terlihat *tangguh* (95.8% sukses di loss 30%) padahal live sungguhan lewat RADIUS (`analisys2.md` section 2, dengan fragmentasi EAP nyata dan 28 round-trip) cuma ~79% di loss yang sama. Bagian ini berguna sebagai pembanding "loss resilience pada ukuran payload asli, RTT tetap" — bukan pengganti section 2 di `analisys2.md` yang memasukkan efek fragmentasi nyata.

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

Ukuran pesan method 0-4 dihitung dari elemen kripto nyata (model, `edhoc_sizes.py`); method 5-6 memakai byte yang **benar-benar diobservasi** dari handshake live (`rsa_bench.py` / `compute_tls_hybrid.py`, sama-sama bersumber dari `e2e-handshake.csv`). Fragmentasi EAP (RFC 3579, atribut 253 B) dan IP (MTU 1500) diturunkan darinya untuk semua method. Lihat `analisys2.md` section 4 untuk tabel yang sama persis, sepenuhnya diobservasi langsung dari handshake live method 0-6.

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
| 4 | message_1 | 2361 | 10 | 3 | 2 | yes |
| 4 | message_2 | 6098 | 25 | 6 | 5 | yes |
| 4 | message_3 | 3751 | 15 | 4 | 3 | yes |
| 4 | message_4 | 9 | 1 | 1 | 1 | no |
| 5 | message_1 | 289 | 2 | 1 | 1 | no |
| 5 | message_2 | 1148 | 5 | 2 | 1 | no |
| 5 | message_3 | 990 | 4 | 1 | 1 | no |
| 5 | message_4 | 51 | 1 | 1 | 1 | no |
| 6 | message_1 | 1589 | 7 | 2 | 2 | yes |
| 6 | message_2 | 12600 | 50 | 13 | 9 | yes |
| 6 | message_3 | 10983 | 44 | 11 | 8 | yes |
| 6 | message_4 | 23 | 1 | 1 | 1 | no |
Fragmentasi berat (banyak fragmen EAP) terjadi pada method 4, 6 — profil PQC (XWING/ML-KEM-768 hybrid key establishment dan/atau sertifikat ML-DSA-44), karena elemen KEM/tanda-tangan PQC menambah ~1.1-2.4 KB per elemen. Method 6's baris di sini memakai byte yang **benar-benar diobservasi** dari handshake live (bukan model — `edhoc_sizes.py`, sama seperti method 5), karena model murni sebelumnya meleset cukup jauh (~2.5x lebih kecil dari yang sebenarnya, akibat framing X.509 penuh yang sulit dimodelkan tanpa observasi langsung).

Fragmentasi ringan (2 fragmen EAP maksimum) terjadi pada method 5 — ini **bukan** soal PQC: method 5 memakai Ed25519 (bukan ML-KEM/ML-DSA sama sekali), fragmentasinya semata karena framing TLS record + X.509 (rantai sertifikat CA+server) sedikit lebih besar dari CBOR EDHOC yang sangat ringkas.
