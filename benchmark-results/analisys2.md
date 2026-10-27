# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)

_Dibuat otomatis oleh benchmark/e2e_analyze.py pada 2026-10-27T22:36:46._

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
| 0 | 2026-10-27T22:35:44+0900 | 1 | PASS | 1.864 | 1 |
| 1 | 2026-10-27T22:35:44+0900 | 1 | PASS | 1.626 | 1 |
| 2 | 2026-10-27T22:35:44+0900 | 1 | PASS | 1.674 | 1 |
| 3 | 2026-10-27T22:35:44+0900 | 1 | PASS | 1.753 | 1 |
| 4 | 2026-10-27T22:35:44+0900 | 1 | PASS | 6.459 | 1 |
| 5 | 2026-10-27T22:35:45+0900 | 1 | PASS | 3.642 | 1 |
| 6 | 2026-10-27T22:35:52+0900 | 1 | PASS | 9.237 | 1 |

### Ringkasan statistik handshake end-to-end per method

| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 100 | 100.0 | 1.000 | 0.976 | 1.276 | 0.758 | 1.864 | 3 | 3 |
| 1 | SIG/STAT | 100 | 100.0 | 1.016 | 0.958 | 1.465 | 0.840 | 2.030 | 3 | 3 |
| 2 | STAT/SIG | 100 | 100.0 | 0.981 | 0.953 | 1.146 | 0.835 | 1.674 | 3 | 3 |
| 3 | STAT/STAT | 100 | 100.0 | 1.158 | 1.099 | 1.462 | 0.881 | 1.808 | 3 | 3 |
| 4 | SIGMA-XWING-PQC | 100 | 100.0 | 5.570 | 5.704 | 6.863 | 3.973 | 7.483 | 14 | 14 |
| 5 | EAP-TLS-Classic | 100 | 100.0 | 3.147 | 3.132 | 3.467 | 2.816 | 3.930 | 6 | 6 |
| 6 | EAP-TLS-Hybrid-PQC | 100 | 100.0 | 9.319 | 9.306 | 10.449 | 7.606 | 12.395 | 28 | 28 |

- Handshake end-to-end tercepat: **method 2** (STAT/SIG).
- Handshake end-to-end terlambat: **method 6** (EAP-TLS-Hybrid-PQC), karena fragmentasi EAP membutuhkan 28 round-trip RADIUS dibanding 3 untuk method klasik.

### Pembagian beban initiator vs responder (live, wall-clock nyata)

Setiap harness (UE/initiator) mengukur, per round-trip RADIUS, waktu yang dihabiskan **menunggu balasan** (`send()` sampai `recv()` kembali) secara terpisah dari waktu yang dihabiskan **mengerjakan sendiri** (membangun paket RADIUS/EAP, HMAC-MD5 Message-Authenticator, dan menjalankan engine EDHOC/TLS-nya sendiri) di antara round-trip. `responder_ms` = total waktu menunggu (mendominasi oleh pemrosesan penuh di sisi FreeRADIUS — parsing, dispatch modul, kripto, serialisasi balasan — karena transit jaringan nyata di loopback nyaris nol); `initiator_ms` = `duration_ms` dikurangi itu, murni kerja lokal UE. Ini pengukuran **live nyata** per handshake, bukan model — berbeda dari section 1b yang cuma menghitung compute kripto murni tanpa overhead RADIUS/TLS-framing sama sekali.

| Method | Profil | Initiator mean (ms) | Responder mean (ms) | Initiator % | Responder % | Total mean (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 0.136 | 0.864 | 13.6% | 86.4% | 1.000 |
| 1 | SIG/STAT | 0.120 | 0.896 | 11.8% | 88.2% | 1.016 |
| 2 | STAT/SIG | 0.136 | 0.846 | 13.8% | 86.2% | 0.981 |
| 3 | STAT/STAT | 0.126 | 1.032 | 10.8% | 89.2% | 1.158 |
| 4 | SIGMA-XWING-PQC | 0.649 | 4.921 | 11.6% | 88.4% | 5.570 |
| 5 | EAP-TLS-Classic | 0.695 | 2.452 | 22.1% | 77.9% | 3.147 |
| 6 | EAP-TLS-Hybrid-PQC | 0.809 | 8.510 | 8.7% | 91.3% | 9.319 |

- Di semua method, beban **responder** (AAA/FreeRADIUS) mendominasi total waktu handshake — wajar, karena responder-lah yang benar-benar memproses paket RADIUS (parsing, dispatch modul, verifikasi kripto) dan initiator cuma menunggu selama itu; porsi initiator yang genuinely CPU-bound (encode paket + panggilan engine lokal) jauh lebih kecil dari total.
- Proporsi responder tertinggi: **method 6** (EAP-TLS-Hybrid-PQC).

### Uji stabilitas statistik method 0-3 (N=10000/method, bootstrap CI)

Sweep utama di atas cuma 100 iterasi/method — cukup untuk method 4-6 (beda RADIUS round-trip yang besar, jelas dominan), tapi TIDAK cukup untuk membedakan method 0-3 (semua sama-sama 3 round-trip, beda compute cuma puluhan µs) secara meyakinkan: urutan mereka terbukti berubah-ubah antar rerun benchmark ini.

> **Bug pengukuran ditemukan dan diperbaiki selama investigasi ini:** percobaan pertama (`radiusd -X`, mode debug penuh) menunjukkan 14-63 outlier ekstrem (~2000ms) per method dari 5000 sampel. Root cause: logging `-X` yang sangat verbose (setiap atribut/cabang policy dicetak per request) membuat `radiusd` sesekali tertinggal memproses di bawah beban tinggi, menyebabkan delay paket UDP nyata — yang lalu diperbesar jadi stall ~2 detik oleh socket timeout harness (`SO_RCVTIMEO=2s`). Dikonfirmasi lewat A/B test: sweep identik dengan `radiusd -f` (foreground tanpa debug, lihat `switch_tls_config.sh`) menghasilkan **nol** outlier semacam itu dari 20000 sampel gabungan (maksimum ~23ms). Seluruh data live di dokumen ini (termasuk sweep utama 100/720-iterasi di atas) sekarang dikumpulkan dengan `radiusd -f`. Efek order kedua yang lebih kecil (median bergeser ±20µs dan sebagian urutan terbalik antar rerun dengan urutan method dibalik) masih ada meski `-X` sudah dimatikan — untuk mengontrolnya, data di bawah menggabungkan **dua run 5000 iterasi/method dengan urutan berlawanan** (0,1,2,3 lalu 3,2,1,0), sehingga tiap method dapat eksposur seimbang terhadap efek posisi "jalan duluan" vs "belakangan" — N=10000/method setelah digabung.

| Method | Profil | N | Mean (ms) | Median (ms) | Trimmed mean (ms) | Stddev (ms) | Outlier >5ms | Median 95% CI (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 10000 | 1.550 | 1.021 | 1.149 | 2.417 | 350 | [1.0160, 1.0260] |
| 1 | SIG/STAT | 10000 | 1.615 | 1.039 | 1.187 | 2.489 | 385 | [1.0350, 1.0430] |
| 2 | STAT/SIG | 10000 | 1.517 | 1.032 | 1.152 | 2.324 | 325 | [1.0270, 1.0370] |
| 3 | STAT/STAT | 10000 | 1.565 | 1.028 | 1.138 | 2.587 | 335 | [1.0230, 1.0310] |

- Urutan median (N=10000, dua arah digabung): **method 0 (1.021 ms) < method 3 (1.028 ms) < method 2 (1.032 ms) < method 1 (1.039 ms)**.
- Pasangan yang CI-nya **overlap** (bedanya tidak signifikan secara statistik): method 0 vs 3, method 1 vs 2, method 2 vs 3. Terpisah signifikan: method 0 vs 1, method 0 vs 2, method 1 vs 3.
- **Kesimpulan jujur:** setelah bug `-X` diperbaiki dan efek urutan dikontrol, selisih median tercepat-terlambat method 0-3 hanya **18 µs**. Urutannya TIDAK mengikuti urutan compute-only section 1b secara konsisten antar rerun. Sudah dicek ke kode `rlm_eap_edhoc.c`: kredensial dimuat sekali saat startup (bukan per-request, tidak ada I/O per-request), jadi hipotesis "lookup kredensial" **terbukti salah**. Kode `edhoc03.c` punya 1 panggilan HKDF-Extract tambahan untuk static-DH (~1.4µs, tidak masuk hitungan section 1b), terlalu kecil untuk menjelaskan selisih yang teramati.

> **Verifikasi lapis terakhir — `strace -f -c` langsung ke proses `radiusd` hidup** (1500 handshake method 0 vs 1500 handshake method 3, masing-masing di-trace terpisah): profil syscall-nya **identik** — sendmsg/recvfrom/recvmsg/getsockname sama-sama persis 4500 kali (3/handshake, cocok RADIUS round-trip), tidak ada satu pun syscall tambahan yang membedakan method 0 dari method 3 (tidak ada file I/O ekstra, tidak ada alokasi berbeda). Yang mendominasi waktu trace di **kedua** method secara setara: `futex` (85.79% method 0, 85.40% method 3) — itu overhead sinkronisasi thread-pool internal FreeRADIUS (worker thread bangun/tidur lewat mutex/condition-variable tiap request masuk, karena harness mengirim request satu-satu/sekuensial), sama sekali bukan bagian dari logika EDHOC. **Kesimpulan final: method 3 TIDAK seharusnya jauh lebih cepat dari method 0** — biaya kripto EDHOC (ratusan nanodetik/operasi) memang microscopic dibanding overhead scheduling thread-pool FreeRADIUS (puluhan-ratusan µs/request) yang besarnya SAMA untuk semua method karena bukan bagian dari protokol sama sekali. Selisih puluhan µs yang tersisa antar method 0-3 kemungkinan besar cuma variasi acak dalam overhead futex/scheduling itu sendiri, bukan efek desain protokol.

### Ablation biaya penyimpanan kunci method 4 (durable vs tmpfs)

Run yang sama dengan direktori kunci (`/usr/local/etc/edhoc`: `edhoc_db/` DN-AAA dan `ue/` UE) di disk VM (A, durable) dan di tmpfs (B), tempat `fsync`/`fdatasync` praktis gratis. Selisih A - B adalah biaya penyimpanan yang terukur. Sumber B: `e2e-handshake-tmpfs.csv`, `e2e-lossy-tmpfs.csv`.

| Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) | Initiator mean (ms) | Responder mean (ms) | UE commit mean (ms, di luar handshake) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A durable (disk VM) | 100 | 5.570 | 5.704 | 6.863 | 0.649 | 4.921 | 0.573 |
| B tmpfs | 100 | 8.465 | 5.614 | 28.923 | 0.830 | 7.635 | 0.091 |
| **A - B (biaya penyimpanan)** | | **-2.895** | **0.090** | -22.059 | -0.182 | -2.714 | 0.482 |

- Mean/p95 B lebih tinggi dari A karena outlier di run B (bukan biaya penyimpanan negatif); bandingkan median. Selisih median berada di dalam noise run-ke-run VM.
- Penyimpanan: record dua-slot praalokasi (`rec.bin` DN-AAA, `ue.rec` UE). Flush per handshake (`strace -c -f -e trace=fsync,fdatasync`, 20 handshake): DN-AAA 1 `fdatasync` (slot non-aktif ditulis sebelum Message4, write-ahead; penghapusan grace key lama ikut flush yang sama); UE 1 `fdatasync` setelah EAP-Success, di luar `duration_ms` (kolom `ue_commit_ms`). Jumlah panggilan sama di tmpfs; hanya biayanya yang hilang.

> Bagian 1a dan 1b berikut adalah pengukuran primitif/komputasi yang **identik** dengan `analysis.md` (independen terhadap transport), disertakan agar kedua dokumen memiliki kolom yang sama persis.

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

Kontribusi waktu komputasi tiap operasi dalam satu handshake (initiator = UE, responder = DN-AAA).

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
| 1 | initiator | ScalarMult | X25519 | 1 | 25163.6 |
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
| 2 | responder | ScalarMult | X25519 | 1 | 25163.6 |
| 2 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 2 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 2 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11069.9 |
| 2 | responder | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | initiator | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 3 | initiator | ScalarMult | X25519 | 2 | 50327.3 |
| 3 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 3 | initiator | Decaps | ML-KEM-768 | 0 | 0.0 |
| 3 | initiator | Signature | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | initiator | Verify | Ed25519/ML-DSA-44 | 0 | 0.0 |
| 3 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 3 | responder | ScalarMult | X25519 | 2 | 50327.3 |
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
| 5 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 29438.8 |
| 5 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 5 | responder | ScalarMult | X25519 | 1 | 25163.6 |
| 5 | responder | Encaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 5 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 11069.9 |
| 5 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 29438.8 |
| 6 | initiator | Keygen | X25519/ML-KEM-768 | 2 | 57975.5 |
| 6 | initiator | ScalarMult | X25519 | 1 | 25163.6 |
| 6 | initiator | Encaps | ML-KEM-768 | 0 | 0.0 |
| 6 | initiator | Decaps | ML-KEM-768 | 1 | 41870.0 |
| 6 | initiator | Signature | Ed25519/ML-DSA-44 | 1 | 223240.5 |
| 6 | initiator | Verify | Ed25519/ML-DSA-44 | 1 | 59596.1 |
| 6 | responder | Keygen | X25519/ML-KEM-768 | 1 | 25535.0 |
| 6 | responder | ScalarMult | X25519 | 1 | 25163.6 |
| 6 | responder | Encaps | ML-KEM-768 | 1 | 33775.5 |
| 6 | responder | Decaps | ML-KEM-768 | 0 | 0.0 |
| 6 | responder | Signature | Ed25519/ML-DSA-44 | 1 | 223240.5 |
| 6 | responder | Verify | Ed25519/ML-DSA-44 | 1 | 59596.1 |

### Total komputasi handshake per method

| Method | Profil | Initiator (us) | Responder (us) | Total (us) |
| --- | --- | --- | --- | --- |
| 0 | SIG/SIG Ed25519 | 91.207 | 91.207 | 182.415 |
| 1 | SIG-Ed25519 / MAC-X25519 | 61.769 | 105.301 | 167.070 |
| 2 | MAC-X25519 / SIG-Ed25519 | 105.301 | 61.769 | 167.070 |
| 3 | MAC/MAC static-DH X25519 | 75.862 | 75.862 | 151.725 |
| 4 | SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768) | 492.320 | 492.320 | 984.640 |
| 5 | EAP-TLS Classic (X25519 ECDHE + Ed25519, mutual) | 91.207 | 91.207 | 182.415 |
| 6 | EAP-TLS Hybrid PQC (X25519MLKEM768 hybrid KEM, ML-DSA-44 cert) | 407.846 | 367.311 | 775.156 |

- Termurah secara komputasi: **method 3** (MAC/MAC static-DH X25519, 151.725 us).
- Termahal secara komputasi: **method 4** (SIGMA XWING+ML-DSA-44 (X25519+ML-KEM-768), 984.640 us).

> **Peringatan baca:** urutan termurah/termahal di atas HANYA waktu komputasi kripto murni (µs) — TIDAK termasuk round-trip jaringan RADIUS/fragmentasi EAP. Urutan itu BUKAN urutan kecepatan handshake end-to-end nyata. Untuk urutan yang sebenarnya dialami pengguna (termasuk RTT), lihat `analisys2.md` section 1c — di sana method 6 (EAP-TLS Hybrid PQC) adalah yang paling lambat secara live, bukan method 4, justru karena jumlah round-trip fragmentasi EAP-nya yang jauh lebih banyak, sesuatu yang tidak tertangkap oleh tabel compute murni ini.

## 2. Performa pada jaringan lossy (end-to-end EAP-over-RADIUS)

Handshake EAP-EDHOC/EAP-TLS nyata melalui RADIUS dengan retransmisi gaya EAP (RTO 40 ms, maks 6 retransmisi per pertukaran); loss diemulasi di level aplikasi pada tiap datagram UDP nyata. 120 percobaan per sel, semua method (0..6) live.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 2.064 | 6.316 | 0.000 |
| 0 | 1.0 | 100.0 | 5.356 | 41.855 | 0.067 |
| 0 | 5.0 | 100.0 | 12.713 | 55.341 | 0.258 |
| 0 | 10.0 | 100.0 | 34.913 | 122.702 | 0.783 |
| 0 | 20.0 | 99.2 | 70.557 | 209.538 | 1.650 |
| 0 | 30.0 | 98.3 | 127.186 | 327.815 | 2.900 |
| 1 | 0.0 | 100.0 | 2.096 | 7.918 | 0.000 |
| 1 | 1.0 | 100.0 | 5.128 | 43.300 | 0.083 |
| 1 | 5.0 | 100.0 | 16.290 | 56.331 | 0.308 |
| 1 | 10.0 | 100.0 | 28.141 | 97.092 | 0.608 |
| 1 | 20.0 | 100.0 | 83.340 | 266.673 | 1.875 |
| 1 | 30.0 | 96.7 | 117.627 | 292.633 | 2.583 |
| 2 | 0.0 | 100.0 | 0.930 | 1.139 | 0.000 |
| 2 | 1.0 | 100.0 | 4.592 | 43.800 | 0.075 |
| 2 | 5.0 | 100.0 | 13.859 | 51.091 | 0.292 |
| 2 | 10.0 | 100.0 | 32.440 | 91.760 | 0.717 |
| 2 | 20.0 | 100.0 | 74.431 | 178.439 | 1.700 |
| 2 | 30.0 | 95.8 | 131.816 | 301.342 | 2.892 |
| 3 | 0.0 | 100.0 | 0.979 | 1.347 | 0.000 |
| 3 | 1.0 | 100.0 | 3.014 | 1.731 | 0.042 |
| 3 | 5.0 | 100.0 | 11.655 | 46.238 | 0.242 |
| 3 | 10.0 | 100.0 | 39.300 | 143.073 | 0.850 |
| 3 | 20.0 | 100.0 | 84.974 | 207.739 | 1.950 |
| 3 | 30.0 | 99.2 | 126.992 | 343.712 | 2.842 |
| 4 | 0.0 | 100.0 | 5.930 | 7.532 | 0.000 |
| 4 | 1.0 | 100.0 | 22.409 | 91.479 | 0.308 |
| 4 | 5.0 | 100.0 | 72.580 | 179.805 | 1.417 |
| 4 | 10.0 | 100.0 | 152.067 | 292.188 | 3.408 |
| 4 | 20.0 | 99.2 | 307.062 | 583.033 | 7.042 |
| 4 | 30.0 | 88.3 | 575.309 | 918.962 | 11.500 |
| 5 | 0.0 | 100.0 | 2.949 | 3.370 | 0.000 |
| 5 | 1.0 | 100.0 | 8.591 | 48.795 | 0.117 |
| 5 | 5.0 | 100.0 | 34.487 | 138.507 | 0.650 |
| 5 | 10.0 | 100.0 | 60.281 | 154.720 | 1.267 |
| 5 | 20.0 | 99.2 | 152.724 | 356.405 | 3.442 |
| 5 | 30.0 | 99.2 | 264.651 | 486.733 | 5.775 |
| 6 | 0.0 | 100.0 | 8.712 | 12.948 | 0.000 |
| 6 | 1.0 | 100.0 | 34.975 | 108.068 | 0.483 |
| 6 | 5.0 | 100.0 | 152.428 | 305.216 | 3.267 |
| 6 | 10.0 | 100.0 | 286.959 | 500.314 | 6.300 |
| 6 | 20.0 | 97.5 | 678.298 | 1087.493 | 15.208 |
| 6 | 30.0 | 85.0 | 1326.051 | 2000.269 | 24.058 |

### Validasi model analitis loss

Model: satu RADIUS round-trip berhasil dengan peluang p = (1 - L)^2 (request dan reply sama-sama harus lolos), pertukaran gagal permanen setelah 7 percobaan (1 + 6 retransmisi), sehingga sukses handshake = (1 - (1 - p)^7)^n_RT dan retransmisi per handshake sukses ~ n_RT (1 - p) / p, masing-masing menambah RTO 40 ms. n_RT = jumlah RADIUS round-trip terukur tanpa loss. Interval sukses = Wilson 95%. Retx terukur dihitung di antara handshake yang sukses agar sebanding dengan model; kolom terakhir = rata-rata semua percobaan (seperti tabel di atas).

| Method | n_RT | Loss % | Sukses terukur % | Wilson 95% CI % | Sukses model % | Retx terukur (sukses) | Retx model | Mean terukur (ms) | Model retx x RTO (ms) | Retx (semua) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 12.7 | 13 | 0.3 |
| 0 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.8 | 0.7 | 34.9 | 28 | 0.8 |
| 0 | 3 | 20 | 99.2 | [95.4, 99.9] | 99.8 | 1.7 | 1.7 | 70.6 | 67 | 1.6 |
| 0 | 3 | 30 | 98.3 | [94.1, 99.5] | 97.3 | 2.9 | 3.1 | 127.2 | 125 | 2.9 |
| 1 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 16.3 | 13 | 0.3 |
| 1 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.6 | 0.7 | 28.1 | 28 | 0.6 |
| 1 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.9 | 1.7 | 83.3 | 67 | 1.9 |
| 1 | 3 | 30 | 96.7 | [91.7, 98.7] | 97.3 | 2.7 | 3.1 | 117.6 | 125 | 2.6 |
| 2 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 13.9 | 13 | 0.3 |
| 2 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.7 | 0.7 | 32.4 | 28 | 0.7 |
| 2 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.7 | 1.7 | 74.4 | 67 | 1.7 |
| 2 | 3 | 30 | 95.8 | [90.6, 98.2] | 97.3 | 3.0 | 3.1 | 131.8 | 125 | 2.9 |
| 3 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.2 | 0.3 | 11.7 | 13 | 0.2 |
| 3 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.8 | 0.7 | 39.3 | 28 | 0.8 |
| 3 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.9 | 1.7 | 85.0 | 67 | 1.9 |
| 3 | 3 | 30 | 99.2 | [95.4, 99.9] | 97.3 | 2.9 | 3.1 | 127.0 | 125 | 2.8 |
| 4 | 14 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 1.4 | 1.5 | 72.6 | 60 | 1.4 |
| 4 | 14 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 3.4 | 3.3 | 152.1 | 131 | 3.4 |
| 4 | 14 | 20 | 99.2 | [95.4, 99.9] | 98.9 | 7.1 | 7.9 | 307.1 | 315 | 7.0 |
| 4 | 14 | 30 | 88.3 | [81.4, 92.9] | 88.1 | 13.0 | 14.6 | 575.3 | 583 | 11.5 |
| 5 | 6 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.7 | 0.6 | 34.5 | 26 | 0.7 |
| 5 | 6 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 1.3 | 1.4 | 60.3 | 56 | 1.3 |
| 5 | 6 | 20 | 99.2 | [95.4, 99.9] | 99.5 | 3.5 | 3.4 | 152.7 | 135 | 3.4 |
| 5 | 6 | 30 | 99.2 | [95.4, 99.9] | 94.7 | 5.8 | 6.2 | 264.7 | 250 | 5.8 |
| 6 | 28 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 3.3 | 3.0 | 152.4 | 121 | 3.3 |
| 6 | 28 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 6.3 | 6.6 | 287.0 | 263 | 6.3 |
| 6 | 28 | 20 | 97.5 | [92.9, 99.1] | 97.8 | 15.6 | 15.7 | 678.3 | 630 | 15.2 |
| 6 | 28 | 30 | 85.0 | [77.5, 90.3] | 77.7 | 28.3 | 29.1 | 1326.1 | 1166 | 24.1 |

- Model mengabaikan biaya tanpa-loss (T_loopback) dan jitter, sehingga cocok terutama pada loss tinggi, saat retransmisi mendominasi waktu.

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
| 4 | message_1 | 1141 | 5 | 2 | 1 | no | observasi nyata |
| 4 | message_2 | 4880 | 20 | 5 | 4 | yes | observasi nyata |
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

