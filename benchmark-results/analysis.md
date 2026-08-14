# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication

_Dibuat otomatis oleh benchmark/analyze.py pada 2026-08-14T15:26:06._

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
| Keygen_RSA2048 | pyca/cryptography(OpenSSL) | 30 | 107049255.0 | 102318402.0 | 189754320.6 | 202904756.9 | 44155227.4 |
| Signature_RSA2048 | pyca/cryptography(OpenSSL) | 500 | 387713.9 | 350887.0 | 503803.9 | 959024.5 | 219517.6 |
| Verify_RSA2048 | pyca/cryptography(OpenSSL) | 500 | 25334.4 | 20013.5 | 29807.4 | 144692.5 | 34113.2 |

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
| 5 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 11225.8 |
| 5 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 29693.1 |
| 5 | responder | Keygen | X25519/ML-KEM-768 | 1 | 24004.0 |
| 5 | responder | ScalarMult | X25519 | 1 | 24888.8 |
| 5 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11225.8 |
| 5 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 29693.1 |
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
| 5 | EAP-TLS Classic (X25519 ECDHE + Ed25519, mutual) | 89.812 | 89.812 | 179.623 |
| 6 | EAP-TLS Hybrid PQC (X25519MLKEM768 hybrid KEM, ML-DSA-44 cert) | 431.165 | 388.404 | 819.569 |

- Termurah secara komputasi: **method 3** (MAC/MAC static-DH X25519, 147.563 us).
- Termahal secara komputasi: **method 4** (SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768), 1258.778 us).

> **Peringatan baca:** urutan termurah/termahal di atas HANYA waktu komputasi kripto murni (µs) — TIDAK termasuk round-trip jaringan RADIUS/fragmentasi EAP. Urutan itu BUKAN urutan kecepatan handshake end-to-end nyata. Untuk urutan yang sebenarnya dialami pengguna (termasuk RTT), lihat `analisys2.md` section 1c — di sana method 6 (EAP-TLS Hybrid PQC) adalah yang paling lambat secara live, bukan method 4, justru karena jumlah round-trip fragmentasi EAP-nya yang jauh lebih banyak, sesuatu yang tidak tertangkap oleh tabel compute murni ini.

## 2. Performa pada jaringan lossy (simulasi 2-round-trip, semua method)

Handshake 2-round-trip (message_1→message_2, message_3→message_4/ack) gaya EAP dengan retransmisi, di atas socket UDP nyata; ukuran payload per method sesuai `edhoc_sizes.py` (method 0-4 model dari elemen kripto, method 5-6 byte nyata hasil observasi live), loss diemulasi di level aplikasi. Mencakup method 0-6.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 5.068 | 11.875 | 0.0 |
| 0 | 1.0 | 100.0 | 5.864 | 10.351 | 0.025 |
| 0 | 5.0 | 100.0 | 14.355 | 50.744 | 0.217 |
| 0 | 10.0 | 100.0 | 25.917 | 91.533 | 0.458 |
| 0 | 20.0 | 100.0 | 47.156 | 140.43 | 1.008 |
| 0 | 30.0 | 98.3 | 92.072 | 258.892 | 2.125 |
| 1 | 0.0 | 100.0 | 5.218 | 12.081 | 0.0 |
| 1 | 1.0 | 100.0 | 5.599 | 16.834 | 0.017 |
| 1 | 5.0 | 100.0 | 14.079 | 50.027 | 0.217 |
| 1 | 10.0 | 100.0 | 21.687 | 86.94 | 0.4 |
| 1 | 20.0 | 99.2 | 44.511 | 142.304 | 0.983 |
| 1 | 30.0 | 97.5 | 92.241 | 256.042 | 2.192 |
| 2 | 0.0 | 100.0 | 4.681 | 9.439 | 0.0 |
| 2 | 1.0 | 100.0 | 6.557 | 16.932 | 0.033 |
| 2 | 5.0 | 100.0 | 12.999 | 53.362 | 0.175 |
| 2 | 10.0 | 100.0 | 24.664 | 95.008 | 0.467 |
| 2 | 20.0 | 100.0 | 61.774 | 171.128 | 1.325 |
| 2 | 30.0 | 96.7 | 94.146 | 251.174 | 2.233 |
| 3 | 0.0 | 100.0 | 4.598 | 10.97 | 0.0 |
| 3 | 1.0 | 100.0 | 7.035 | 22.476 | 0.042 |
| 3 | 5.0 | 100.0 | 17.037 | 87.962 | 0.283 |
| 3 | 10.0 | 100.0 | 24.665 | 91.563 | 0.467 |
| 3 | 20.0 | 100.0 | 52.204 | 141.411 | 1.083 |
| 3 | 30.0 | 99.2 | 88.895 | 256.922 | 2.008 |
| 4 | 0.0 | 100.0 | 5.308 | 12.405 | 0.0 |
| 4 | 1.0 | 100.0 | 6.127 | 14.637 | 0.025 |
| 4 | 5.0 | 100.0 | 17.075 | 54.879 | 0.242 |
| 4 | 10.0 | 100.0 | 27.632 | 90.612 | 0.517 |
| 4 | 20.0 | 100.0 | 54.089 | 143.11 | 1.133 |
| 4 | 30.0 | 99.2 | 78.363 | 218.752 | 1.775 |
| 5 | 0.0 | 100.0 | 5.4 | 13.303 | 0.0 |
| 5 | 1.0 | 100.0 | 8.036 | 47.055 | 0.067 |
| 5 | 5.0 | 100.0 | 13.636 | 53.66 | 0.192 |
| 5 | 10.0 | 100.0 | 19.669 | 84.213 | 0.325 |
| 5 | 20.0 | 98.3 | 57.221 | 167.188 | 1.358 |
| 5 | 30.0 | 100.0 | 92.548 | 260.383 | 2.042 |
| 6 | 0.0 | 100.0 | 4.316 | 8.206 | 0.0 |
| 6 | 1.0 | 100.0 | 6.371 | 19.428 | 0.025 |
| 6 | 5.0 | 100.0 | 16.138 | 56.452 | 0.267 |
| 6 | 10.0 | 100.0 | 25.86 | 93.673 | 0.508 |
| 6 | 20.0 | 100.0 | 48.996 | 169.59 | 1.042 |
| 6 | 30.0 | 95.8 | 89.576 | 217.891 | 2.192 |
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
| 4 | message_1 | 2355 | 10 | 3 | 2 | yes |
| 4 | message_2 | 5998 | 24 | 6 | 5 | yes |
| 4 | message_3 | 4967 | 20 | 5 | 4 | yes |
| 4 | message_4 | 1227 | 5 | 2 | 1 | no |
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
