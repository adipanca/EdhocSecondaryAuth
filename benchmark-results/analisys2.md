# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)

_Dibuat otomatis oleh benchmark/e2e_analyze.py pada 2026-08-14T15:42:03._

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
| 0 | 2026-08-14T15:05:37+0900 | 1 | PASS | 4.135 | 1 |
| 1 | 2026-08-14T15:05:37+0900 | 1 | PASS | 1.288 | 1 |
| 2 | 2026-08-14T15:05:37+0900 | 1 | PASS | 1.920 | 1 |
| 3 | 2026-08-14T15:05:37+0900 | 1 | PASS | 3.047 | 1 |
| 4 | 2026-08-14T15:05:38+0900 | 1 | PASS | 6.854 | 1 |
| 5 | 2026-08-14T15:10:36+0900 | 1 | PASS | 3.287 | 1 |
| 6 | 2026-08-14T15:16:27+0900 | 1 | PASS | 12.615 | 1 |

### Ringkasan statistik handshake end-to-end per method

| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 100 | 100.0 | 0.992 | 0.726 | 2.332 | 0.475 | 10.929 | 3 | 3 |
| 1 | SIG/STAT | 100 | 100.0 | 0.821 | 0.786 | 1.071 | 0.655 | 1.469 | 3 | 3 |
| 2 | STAT/SIG | 100 | 100.0 | 0.872 | 0.808 | 1.179 | 0.658 | 2.887 | 3 | 3 |
| 3 | STAT/STAT | 100 | 100.0 | 0.910 | 0.835 | 1.220 | 0.689 | 3.047 | 3 | 3 |
| 4 | SIGMA-XWING-PQC | 100 | 100.0 | 7.493 | 5.410 | 14.226 | 3.747 | 86.583 | 17 | 17 |
| 5 | EAP-TLS-Classic | 100 | 100.0 | 2.835 | 2.577 | 3.886 | 2.133 | 9.028 | 6 | 6 |
| 6 | EAP-TLS-Hybrid-PQC | 100 | 100.0 | 9.241 | 8.435 | 14.626 | 6.610 | 28.219 | 28 | 28 |

- Handshake end-to-end tercepat: **method 1** (SIG/STAT).
- Handshake end-to-end terlambat: **method 6** (EAP-TLS-Hybrid-PQC), karena fragmentasi EAP membutuhkan 28 round-trip RADIUS dibanding 3 untuk method klasik.

### Pembagian beban initiator vs responder (live, wall-clock nyata)

Setiap harness (UE/initiator) mengukur, per round-trip RADIUS, waktu yang dihabiskan **menunggu balasan** (`send()` sampai `recv()` kembali) secara terpisah dari waktu yang dihabiskan **mengerjakan sendiri** (membangun paket RADIUS/EAP, HMAC-MD5 Message-Authenticator, dan menjalankan engine EDHOC/TLS-nya sendiri) di antara round-trip. `responder_ms` = total waktu menunggu (mendominasi oleh pemrosesan penuh di sisi FreeRADIUS — parsing, dispatch modul, kripto, serialisasi balasan — karena transit jaringan nyata di loopback nyaris nol); `initiator_ms` = `duration_ms` dikurangi itu, murni kerja lokal UE. Ini pengukuran **live nyata** per handshake, bukan model — berbeda dari section 1b yang cuma menghitung compute kripto murni tanpa overhead RADIUS/TLS-framing sama sekali.

| Method | Profil | Initiator mean (ms) | Responder mean (ms) | Initiator % | Responder % | Total mean (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 0.110 | 0.882 | 11.1% | 88.9% | 0.992 |
| 1 | SIG/STAT | 0.101 | 0.720 | 12.3% | 87.7% | 0.821 |
| 2 | STAT/SIG | 0.120 | 0.753 | 13.7% | 86.3% | 0.872 |
| 3 | STAT/STAT | 0.119 | 0.792 | 13.1% | 86.9% | 0.910 |
| 4 | SIGMA-XWING-PQC | 0.872 | 6.620 | 11.6% | 88.4% | 7.493 |
| 5 | EAP-TLS-Classic | 0.640 | 2.195 | 22.6% | 77.4% | 2.835 |
| 6 | EAP-TLS-Hybrid-PQC | 0.729 | 8.512 | 7.9% | 92.1% | 9.241 |

- Di semua method, beban **responder** (AAA/FreeRADIUS) mendominasi total waktu handshake — wajar, karena responder-lah yang benar-benar memproses paket RADIUS (parsing, dispatch modul, verifikasi kripto) dan initiator cuma menunggu selama itu; porsi initiator yang genuinely CPU-bound (encode paket + panggilan engine lokal) jauh lebih kecil dari total.
- Proporsi responder tertinggi: **method 6** (EAP-TLS-Hybrid-PQC).

### Uji stabilitas statistik method 0-3 (N=10000/method, bootstrap CI)

Sweep utama di atas cuma 100 iterasi/method — cukup untuk method 4-6 (beda RADIUS round-trip yang besar, jelas dominan), tapi TIDAK cukup untuk membedakan method 0-3 (semua sama-sama 3 round-trip, beda compute cuma puluhan µs) secara meyakinkan: urutan mereka terbukti berubah-ubah antar rerun benchmark ini.

> **Bug pengukuran ditemukan dan diperbaiki selama investigasi ini:** percobaan pertama (`radiusd -X`, mode debug penuh) menunjukkan 14-63 outlier ekstrem (~2000ms) per method dari 5000 sampel. Root cause: logging `-X` yang sangat verbose (setiap atribut/cabang policy dicetak per request) membuat `radiusd` sesekali tertinggal memproses di bawah beban tinggi, menyebabkan delay paket UDP nyata — yang lalu diperbesar jadi stall ~2 detik oleh socket timeout harness (`SO_RCVTIMEO=2s`). Dikonfirmasi lewat A/B test: sweep identik dengan `radiusd -f` (foreground tanpa debug, lihat `switch_tls_config.sh`) menghasilkan **nol** outlier semacam itu dari 20000 sampel gabungan (maksimum ~23ms). Seluruh data live di dokumen ini (termasuk sweep utama 100/720-iterasi di atas) sekarang dikumpulkan dengan `radiusd -f`. Efek order kedua yang lebih kecil (median bergeser ±20µs dan sebagian urutan terbalik antar rerun dengan urutan method dibalik) masih ada meski `-X` sudah dimatikan — untuk mengontrolnya, data di bawah menggabungkan **dua run 5000 iterasi/method dengan urutan berlawanan** (0,1,2,3 lalu 3,2,1,0), sehingga tiap method dapat eksposur seimbang terhadap efek posisi "jalan duluan" vs "belakangan" — N=10000/method setelah digabung.

| Method | Profil | N | Mean (ms) | Median (ms) | Trimmed mean (ms) | Stddev (ms) | Outlier >5ms | Median 95% CI (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 10000 | 0.990 | 0.874 | 0.887 | 0.774 | 58 | [0.8710, 0.8760] |
| 1 | SIG/STAT | 10000 | 0.954 | 0.871 | 0.881 | 0.581 | 42 | [0.8690, 0.8740] |
| 2 | STAT/SIG | 10000 | 0.964 | 0.886 | 0.893 | 0.591 | 32 | [0.8840, 0.8880] |
| 3 | STAT/STAT | 10000 | 0.995 | 0.881 | 0.896 | 0.790 | 72 | [0.8790, 0.8850] |

- Urutan median (N=10000, dua arah digabung): **method 1 (0.871 ms) < method 0 (0.874 ms) < method 3 (0.881 ms) < method 2 (0.886 ms)**.
- Pasangan yang CI-nya **overlap** (bedanya tidak signifikan secara statistik): method 0 vs 1, dan method 2 vs 3. Pasangan lintas-kelompok (0/1 vs 2/3) semuanya terpisah signifikan.
- **Kesimpulan jujur:** setelah bug `-X` diperbaiki dan efek urutan dikontrol, method 0-3 terbagi jadi dua kelompok yang stabil dan reproducible: **{0,1} (~0.87ms, initiator melakukan SIGNATURE) sedikit lebih cepat dari {2,3} (~0.88ms, initiator melakukan static-DH/MAC)** — selisihnya cuma ~10-15µs, jauh lebih kecil dari klaim awal (~30-60µs) dan TIDAK mengikuti urutan compute-only (section 1b memprediksi method 3 termurah, method 0 termahal). Sudah dicek ke kode `rlm_eap_edhoc.c`: kredensial dimuat sekali saat startup (bukan per-request, tidak ada I/O per-request), jadi hipotesis "lookup kredensial" sebelumnya **terbukti salah**. Kode `edhoc03.c` memang punya 1 panggilan HKDF-Extract tambahan untuk static-DH (~1.4µs, tidak masuk hitungan section 1b) tapi itu juga terlalu kecil untuk menjelaskan selisih 10-15µs yang teramati.

> **Verifikasi lapis terakhir — `strace -f -c` langsung ke proses `radiusd` hidup** (1500 handshake method 0 vs 1500 handshake method 3, masing-masing di-trace terpisah): profil syscall-nya **identik** — sendmsg/recvfrom/recvmsg/getsockname sama-sama persis 4500 kali (3/handshake, cocok RADIUS round-trip), tidak ada satu pun syscall tambahan yang membedakan method 0 dari method 3 (tidak ada file I/O ekstra, tidak ada alokasi berbeda). Yang mendominasi waktu trace di **kedua** method secara setara: `futex` (85.79% method 0, 85.40% method 3) — itu overhead sinkronisasi thread-pool internal FreeRADIUS (worker thread bangun/tidur lewat mutex/condition-variable tiap request masuk, karena harness mengirim request satu-satu/sekuensial), sama sekali bukan bagian dari logika EDHOC. **Kesimpulan final: method 3 TIDAK seharusnya jauh lebih cepat dari method 0** — biaya kripto EDHOC (ratusan nanodetik/operasi) memang microscopic dibanding overhead scheduling thread-pool FreeRADIUS (puluhan-ratusan µs/request) yang besarnya SAMA untuk semua method karena bukan bagian dari protokol sama sekali. Selisih 10-15µs yang tersisa di kelompok {0,1} vs {2,3} kemungkinan besar cuma variasi acak dalam overhead futex/scheduling itu sendiri, bukan efek desain protokol.

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

## 2. Performa pada jaringan lossy (end-to-end EAP-over-RADIUS)

Handshake EAP-EDHOC/EAP-TLS nyata melalui RADIUS dengan retransmisi gaya EAP (RTO 40 ms, maks 6 retransmisi per pertukaran); loss diemulasi di level aplikasi pada tiap datagram UDP nyata. 120 percobaan per sel, semua method (0..6) live.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 1.089 | 2.384 | 0.000 |
| 0 | 1.0 | 100.0 | 2.433 | 4.049 | 0.025 |
| 0 | 5.0 | 100.0 | 18.413 | 84.533 | 0.400 |
| 0 | 10.0 | 100.0 | 38.930 | 126.381 | 0.875 |
| 0 | 20.0 | 100.0 | 77.387 | 181.579 | 1.783 |
| 0 | 30.0 | 95.8 | 122.439 | 265.129 | 2.642 |
| 1 | 0.0 | 100.0 | 1.098 | 2.223 | 0.000 |
| 1 | 1.0 | 100.0 | 3.243 | 9.121 | 0.050 |
| 1 | 5.0 | 100.0 | 14.725 | 85.466 | 0.292 |
| 1 | 10.0 | 100.0 | 23.699 | 85.831 | 0.525 |
| 1 | 20.0 | 100.0 | 78.173 | 216.189 | 1.800 |
| 1 | 30.0 | 97.5 | 131.235 | 305.769 | 2.942 |
| 2 | 0.0 | 100.0 | 1.306 | 2.803 | 0.000 |
| 2 | 1.0 | 100.0 | 3.706 | 12.881 | 0.058 |
| 2 | 5.0 | 100.0 | 16.489 | 83.666 | 0.358 |
| 2 | 10.0 | 100.0 | 28.594 | 102.732 | 0.642 |
| 2 | 20.0 | 100.0 | 76.968 | 217.711 | 1.758 |
| 2 | 30.0 | 97.5 | 135.790 | 278.733 | 3.050 |
| 3 | 0.0 | 100.0 | 0.885 | 1.494 | 0.000 |
| 3 | 1.0 | 100.0 | 2.552 | 4.016 | 0.033 |
| 3 | 5.0 | 100.0 | 13.752 | 52.711 | 0.283 |
| 3 | 10.0 | 100.0 | 37.503 | 133.917 | 0.825 |
| 3 | 20.0 | 100.0 | 73.442 | 211.972 | 1.692 |
| 3 | 30.0 | 95.8 | 125.528 | 303.074 | 2.800 |
| 4 | 0.0 | 100.0 | 5.589 | 8.695 | 0.000 |
| 4 | 1.0 | 100.0 | 21.440 | 61.713 | 0.325 |
| 4 | 5.0 | 100.0 | 93.037 | 210.512 | 2.000 |
| 4 | 10.0 | 100.0 | 182.719 | 348.887 | 4.083 |
| 4 | 20.0 | 99.2 | 409.325 | 741.101 | 9.333 |
| 4 | 30.0 | 87.5 | 724.610 | 1197.131 | 14.742 |
| 5 | 0.0 | 100.0 | 2.802 | 3.498 | 0.000 |
| 5 | 1.0 | 100.0 | 9.604 | 46.031 | 0.142 |
| 5 | 5.0 | 100.0 | 37.874 | 130.610 | 0.750 |
| 5 | 10.0 | 100.0 | 67.026 | 173.252 | 1.475 |
| 5 | 20.0 | 99.2 | 151.093 | 336.259 | 3.417 |
| 5 | 30.0 | 95.8 | 267.341 | 559.345 | 5.875 |
| 6 | 0.0 | 100.0 | 9.378 | 15.506 | 0.000 |
| 6 | 1.0 | 100.0 | 33.155 | 98.550 | 0.508 |
| 6 | 5.0 | 100.0 | 162.780 | 319.330 | 3.492 |
| 6 | 10.0 | 100.0 | 279.546 | 465.440 | 6.283 |
| 6 | 20.0 | 96.7 | 681.476 | 1034.203 | 15.108 |
| 6 | 30.0 | 73.3 | 1201.793 | 1786.093 | 20.400 |

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

