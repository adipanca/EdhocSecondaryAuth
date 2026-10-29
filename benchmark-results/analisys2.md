# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)

_Dibuat otomatis oleh benchmark/e2e_analyze.py pada 2026-10-29T10:53:23._

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

Jalur live EAP-over-RADIUS (harness UE initiator -> FreeRADIUS `rlm_eap_edhoc` untuk method 0..4, `rlm_eap_tls` untuk method 5 dan 6). 200 iterasi per method, tanpa loss (gabungan semua run di `e2e-handshake.csv`, kolom `label`; tiap run didahului 20 handshake pemanasan yang dibuang). Method 5 dan 6 diukur berurutan (lihat catatan metodologi di atas), tetapi keduanya live.

Baris perwakilan (satu handshake sukses per method), kolom identik dengan `analysis.md` bagian 1c (`duration_ms` menggantikan `duration_sec`; nilai adalah durasi pertukaran EAP-EDHOC saja, bukan seluruh registrasi 5G):

| Method | timestamp | iteration | status | duration_ms | pdu_success_count |
| --- | --- | --- | --- | --- | --- |
| 0 | 2026-10-29T10:50:00+0900 | 1 | PASS | 1.993 | 1 |
| 1 | 2026-10-29T10:50:00+0900 | 1 | PASS | 2.368 | 1 |
| 2 | 2026-10-29T10:50:00+0900 | 1 | PASS | 1.951 | 1 |
| 3 | 2026-10-29T10:50:00+0900 | 1 | PASS | 1.836 | 1 |
| 4 | 2026-10-29T10:50:01+0900 | 1 | PASS | 8.498 | 1 |
| 5 | 2026-10-29T10:50:02+0900 | 1 | PASS | 4.151 | 1 |
| 6 | 2026-10-29T10:50:08+0900 | 1 | PASS | 12.222 | 1 |

### Ringkasan statistik handshake end-to-end per method

| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 200 | 100.0 | 0.962 | 0.920 | 1.211 | 0.732 | 1.993 | 3 | 3 |
| 1 | SIG/STAT | 200 | 100.0 | 0.994 | 0.925 | 1.329 | 0.751 | 2.368 | 3 | 3 |
| 2 | STAT/SIG | 200 | 100.0 | 1.002 | 0.957 | 1.336 | 0.802 | 2.277 | 3 | 3 |
| 3 | STAT/STAT | 200 | 100.0 | 0.999 | 0.976 | 1.254 | 0.824 | 1.872 | 3 | 3 |
| 4 | SIGMA-XWING-PQC | 200 | 100.0 | 7.171 | 6.992 | 9.130 | 5.932 | 13.092 | 15 | 15 |
| 5 | EAP-TLS-Classic | 200 | 100.0 | 3.112 | 3.072 | 3.606 | 2.584 | 4.586 | 6 | 6 |
| 6 | EAP-TLS-Hybrid-PQC | 200 | 100.0 | 11.822 | 10.022 | 20.853 | 6.973 | 41.950 | 28 | 28 |

- Handshake end-to-end tercepat: **method 0** (SIG/SIG).
- Handshake end-to-end terlambat: **method 6** (EAP-TLS-Hybrid-PQC), karena fragmentasi EAP membutuhkan 28 round-trip RADIUS dibanding 3 untuk method klasik.

### Pembagian beban initiator vs responder (live, wall-clock nyata)

Setiap harness (UE/initiator) mengukur, per round-trip RADIUS, waktu yang dihabiskan **menunggu balasan** (`send()` sampai `recv()` kembali) secara terpisah dari waktu yang dihabiskan **mengerjakan sendiri** (membangun paket RADIUS/EAP, HMAC-MD5 Message-Authenticator, dan menjalankan engine EDHOC/TLS-nya sendiri) di antara round-trip. `responder_ms` = total waktu menunggu (mendominasi oleh pemrosesan penuh di sisi FreeRADIUS — parsing, dispatch modul, kripto, serialisasi balasan — karena transit jaringan nyata di loopback nyaris nol); `initiator_ms` = `duration_ms` dikurangi itu, murni kerja lokal UE. Ini pengukuran **live nyata** per handshake, bukan model — berbeda dari section 1b yang cuma menghitung compute kripto murni tanpa overhead RADIUS/TLS-framing sama sekali.

| Method | Profil | Initiator mean (ms) | Responder mean (ms) | Initiator % | Responder % | Total mean (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 0.130 | 0.832 | 13.5% | 86.5% | 0.962 |
| 1 | SIG/STAT | 0.116 | 0.878 | 11.6% | 88.4% | 0.994 |
| 2 | STAT/SIG | 0.134 | 0.868 | 13.4% | 86.6% | 1.002 |
| 3 | STAT/STAT | 0.126 | 0.873 | 12.6% | 87.4% | 0.999 |
| 4 | SIGMA-XWING-PQC | 1.289 | 5.881 | 18.0% | 82.0% | 7.171 |
| 5 | EAP-TLS-Classic | 0.595 | 2.517 | 19.1% | 80.9% | 3.112 |
| 6 | EAP-TLS-Hybrid-PQC | 0.963 | 10.859 | 8.1% | 91.9% | 11.822 |

- Di semua method, beban **responder** (AAA/FreeRADIUS) mendominasi total waktu handshake — wajar, karena responder-lah yang benar-benar memproses paket RADIUS (parsing, dispatch modul, verifikasi kripto) dan initiator cuma menunggu selama itu; porsi initiator yang genuinely CPU-bound (encode paket + panggilan engine lokal) jauh lebih kecil dari total.
- Proporsi responder tertinggi: **method 6** (EAP-TLS-Hybrid-PQC).

### Uji stabilitas statistik method 0-3 (N=10000/method, bootstrap CI)

Sweep utama di atas cuma 100-200 iterasi/method — cukup untuk method 4-6 (beda RADIUS round-trip yang besar, jelas dominan), tapi TIDAK cukup untuk membedakan method 0-3 (semua sama-sama 3 round-trip, beda compute cuma puluhan µs) secara meyakinkan: urutan mereka terbukti berubah-ubah antar rerun benchmark ini.

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

`benchmark/storage_ablation.sh`: direktori kunci (`/usr/local/etc/edhoc`: `edhoc_db/` DN-AAA dan `ue/` UE) di disk VM (durable) dan di tmpfs, tempat `fdatasync` praktis gratis, dalam ronde bergantian (record di-provision ulang dan radiusd di-restart tiap ronde, 20 handshake pemanasan dibuang). Selisih median durable - tmpfs adalah biaya penyimpanan yang terukur; bootstrap 95% CI (4000 resample, seed 1).

| Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) | Responder mean (ms) | UE commit mean (ms, di luar handshake) |
| --- | --- | --- | --- | --- | --- | --- |
| durable | 600 | 7.171 | 6.841 | 9.515 | 5.847 | 0.702 |
| tmpfs | 600 | 5.888 | 5.701 | 7.580 | 5.161 | 0.045 |

- Biaya penyimpanan (selisih median durable - tmpfs): **1.140 ms**, 95% CI [1.061, 1.244] ms.
- Penyimpanan (protokol v3): record dua-slot praalokasi (`rec.bin` DN-AAA, `ue.rec` UE). Di jalur kritis ada dua `fdatasync`: UE menulis slot NEXT sebelum Message3 dan DN-AAA menulis record baru sebelum Message4 (write-ahead). Di luar jalur kritis ada dua lagi: DN-AAA menolkan slot dengan sk_B lama setelah Message4 (worker thread) dan UE menolkan sk_A lama saat promosi setelah Message4 (kolom `ue_commit_ms`). Waktu per panggilan: `storage-strace.txt` (`strace -c -w`, wall-clock, termasuk overhead tracing).

### Komputasi method 4 in-process: sebelum vs sesudah (X-Wing standar, kunci rotasi precompute)

`benchmark/m4_inproc_compare.sh`: handshake method 4 tanpa transport dan tanpa penyimpanan, waktu pemrosesan pesan per pihak, beberapa ronde diselang-seling. `before` = core edhoc4 sebelum perubahan X-Wing (combiner SHA-256 non-standar, decapsulation menghitung ulang pk_X); `inline_rotation_keygen` = core saat ini (X-Wing sesuai draft-connolly-cfrg-xwing-kem-09), kunci rotasi dibuat di dalam handshake: **default dan angka utama**; `precomputed_rotation` = core saat ini dengan pool opsional (kunci rotasi dibuat di luar handshake, ablation). Nilai = rata-rata dari mean/median tiap ronde.

| Varian | Ronde | N/ronde | Initiator mean (us) | Initiator median (us) | Responder mean (us) | Responder median (us) | Total mean (us) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| before | 5 | 2000 | 609.4 | 537.8 | 605.3 | 537.9 | 1214.7 |
| inline_rotation_keygen | 5 | 2000 | 578.2 | 508.7 | 582.3 | 511.7 | 1160.4 |
| precomputed_rotation | 5 | 2000 | 532.7 | 464.1 | 537.2 | 465.4 | 1069.9 |

- Default (rotasi inline): 1160.4 us, 54.3 us lebih rendah dari `before` berkat perubahan X-Wing (terutama decapsulation tanpa hitung ulang pk_X).
- Pool opsional: 1069.9 us, 90.6 us lebih rendah dari default karena kunci rotasi dibuat di luar handshake.
- Angka in-process lebih besar dari model primitif (`handshake-compute.csv`) karena mencakup HKDF, AEAD, hash transcript, dan serialisasi.

### Ablation live: kunci rotasi precompute (pool) vs dibuat di dalam handshake

`benchmark/pool_ablation.sh`: method 4 loss-free, ronde bergantian `pool_on` / `pool_off` (UE dan DN-AAA sama-sama), radiusd di-restart tiap ronde, 20 handshake pemanasan dibuang. Selisih median dengan bootstrap 95% CI (4000 resample, seed 1).

| Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) |
| --- | --- | --- | --- | --- |
| pool_on | 800 | 7.447 | 6.016 | 14.717 |
| pool_off | 800 | 7.453 | 6.139 | 13.674 |

- Selisih median (off - on): **0.123 ms**, 95% CI [-0.027, 0.222] ms. Biaya yang dipindah keluar handshake kira-kira dua kali X-Wing KeyGen (UE dan DN-AAA); di VM ini besarnya setara dengan noise run-ke-run.

### Biaya transport per RADIUS round-trip (pasangan hybrid)

(E2E mean - komputasi model - biaya penyimpanan) / n_RT. Penyimpanan = selisih median durable - tmpfs (hanya method 4; EAP-TLS tidak menyimpan kunci).

| Method | E2E mean (ms) | Komputasi (ms) | Penyimpanan (ms) | n_RT | Per round-trip (ms) |
| --- | --- | --- | --- | --- | --- |
| 4 | 7.171 | 0.985 | 1.140 | 15 | 0.336 |
| 6 | 11.822 | 0.894 | 0.000 | 28 | 0.390 |

### Uji pemulihan method 4 (protokol v3, tanpa grace key)

150 handshake pada loss 20% lalu 30 handshake tanpa loss, tanpa re-provisioning. `used_next` = run dimulai di slot NEXT (sesi sebelumnya berhenti setelah UE menulis NEXT); tanpa fallback berarti DN-AAA sudah commit (Message4 / EAP-Success hilang) dan sesi ini memulihkannya; dengan fallback berarti Message3 tidak sampai, NEXT ditolak, dan UE mengulang dengan CUR.

| Seri | N | PASS | used_next | pulih tanpa fallback (Message4 hilang) | fallback (Message3 hilang) | gagal |
| --- | --- | --- | --- | --- | --- | --- |
| loss 20% | 150 | 147 | 1 | 0 | 1 | 3 |
| setelahnya, loss 0% | 30 | 30 | 0 | 0 | 0 | 0 |

- Desync: **0** (run tanpa loss yang gagal setelah seri lossy); re-provisioning: **0** (seri tidak pernah menulis ulang kunci).
- Run yang gagal pada loss 20% adalah run yang kehabisan retransmisi; sesi berikutnya memulihkan state lewat NEXT atau fallback.

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

## 2. Performa pada jaringan lossy (end-to-end EAP-over-RADIUS)

Handshake EAP-EDHOC/EAP-TLS nyata melalui RADIUS dengan retransmisi gaya EAP (RTO 40 ms, maks 6 retransmisi per pertukaran); loss diemulasi di level aplikasi pada tiap datagram UDP nyata. 120 percobaan per sel, semua method (0..6) live.

| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- |
| 0 | 0.0 | 100.0 | 1.257 | 1.928 | 0.000 |
| 0 | 1.0 | 100.0 | 4.609 | 41.771 | 0.075 |
| 0 | 5.0 | 100.0 | 13.582 | 84.251 | 0.292 |
| 0 | 10.0 | 100.0 | 33.331 | 130.271 | 0.725 |
| 0 | 20.0 | 100.0 | 60.346 | 169.762 | 1.383 |
| 0 | 30.0 | 97.5 | 116.980 | 333.239 | 2.600 |
| 1 | 0.0 | 100.0 | 1.018 | 1.641 | 0.000 |
| 1 | 1.0 | 100.0 | 3.858 | 41.590 | 0.067 |
| 1 | 5.0 | 100.0 | 16.327 | 83.368 | 0.350 |
| 1 | 10.0 | 100.0 | 24.111 | 88.060 | 0.542 |
| 1 | 20.0 | 100.0 | 63.155 | 174.766 | 1.442 |
| 1 | 30.0 | 99.2 | 126.867 | 307.286 | 2.858 |
| 2 | 0.0 | 100.0 | 0.791 | 1.278 | 0.000 |
| 2 | 1.0 | 100.0 | 2.058 | 2.355 | 0.025 |
| 2 | 5.0 | 100.0 | 14.542 | 51.743 | 0.300 |
| 2 | 10.0 | 100.0 | 38.622 | 115.412 | 0.858 |
| 2 | 20.0 | 100.0 | 61.288 | 173.563 | 1.392 |
| 2 | 30.0 | 98.3 | 155.891 | 368.926 | 3.383 |
| 3 | 0.0 | 100.0 | 1.269 | 2.328 | 0.000 |
| 3 | 1.0 | 100.0 | 3.480 | 6.258 | 0.042 |
| 3 | 5.0 | 100.0 | 15.364 | 83.527 | 0.317 |
| 3 | 10.0 | 100.0 | 36.369 | 132.239 | 0.775 |
| 3 | 20.0 | 99.2 | 78.625 | 223.736 | 1.750 |
| 3 | 30.0 | 97.5 | 110.606 | 290.842 | 2.475 |
| 4 | 0.0 | 100.0 | 7.706 | 11.372 | 0.000 |
| 4 | 1.0 | 100.0 | 22.023 | 57.964 | 0.325 |
| 4 | 5.0 | 100.0 | 76.252 | 160.028 | 1.542 |
| 4 | 10.0 | 100.0 | 159.589 | 320.523 | 3.417 |
| 4 | 20.0 | 99.2 | 369.511 | 619.949 | 7.967 |
| 4 | 30.0 | 89.2 | 729.830 | 1178.884 | 13.275 |
| 5 | 0.0 | 100.0 | 2.987 | 3.529 | 0.000 |
| 5 | 1.0 | 100.0 | 8.650 | 50.108 | 0.108 |
| 5 | 5.0 | 100.0 | 33.199 | 119.543 | 0.567 |
| 5 | 10.0 | 100.0 | 69.050 | 214.784 | 1.325 |
| 5 | 20.0 | 100.0 | 177.638 | 422.801 | 3.533 |
| 5 | 30.0 | 92.5 | 299.157 | 612.957 | 5.467 |
| 6 | 0.0 | 100.0 | 9.183 | 10.623 | 0.000 |
| 6 | 1.0 | 100.0 | 37.864 | 116.659 | 0.575 |
| 6 | 5.0 | 100.0 | 145.947 | 313.390 | 2.867 |
| 6 | 10.0 | 100.0 | 347.604 | 644.825 | 6.733 |
| 6 | 20.0 | 99.2 | 779.842 | 1226.894 | 15.758 |
| 6 | 30.0 | 76.7 | 1295.381 | 1793.425 | 20.025 |

### Validasi model analitis loss

Model: satu RADIUS round-trip berhasil dengan peluang p = (1 - L)^2 (request dan reply sama-sama harus lolos), pertukaran gagal permanen setelah 7 percobaan (1 + 6 retransmisi), sehingga sukses handshake = (1 - (1 - p)^7)^n_RT dan retransmisi per handshake sukses ~ n_RT (1 - p) / p, masing-masing menambah RTO 40 ms. n_RT = jumlah RADIUS round-trip terukur tanpa loss. Interval sukses = Wilson 95%. Retx terukur dihitung di antara handshake yang sukses agar sebanding dengan model; kolom terakhir = rata-rata semua percobaan (seperti tabel di atas).

| Method | n_RT | Loss % | Sukses terukur % | Wilson 95% CI % | Sukses model % | Retx terukur (sukses) | Retx model | Mean terukur (ms) | Model retx x RTO (ms) | Retx (semua) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 13.6 | 13 | 0.3 |
| 0 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.7 | 0.7 | 33.3 | 28 | 0.7 |
| 0 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.4 | 1.7 | 60.3 | 67 | 1.4 |
| 0 | 3 | 30 | 97.5 | [92.9, 99.1] | 97.3 | 2.7 | 3.1 | 117.0 | 125 | 2.6 |
| 1 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 16.3 | 13 | 0.3 |
| 1 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.5 | 0.7 | 24.1 | 28 | 0.5 |
| 1 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.4 | 1.7 | 63.2 | 67 | 1.4 |
| 1 | 3 | 30 | 99.2 | [95.4, 99.9] | 97.3 | 2.9 | 3.1 | 126.9 | 125 | 2.9 |
| 2 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 14.5 | 13 | 0.3 |
| 2 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.9 | 0.7 | 38.6 | 28 | 0.9 |
| 2 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.4 | 1.7 | 61.3 | 67 | 1.4 |
| 2 | 3 | 30 | 98.3 | [94.1, 99.5] | 97.3 | 3.4 | 3.1 | 155.9 | 125 | 3.4 |
| 3 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 15.4 | 13 | 0.3 |
| 3 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.8 | 0.7 | 36.4 | 28 | 0.8 |
| 3 | 3 | 20 | 99.2 | [95.4, 99.9] | 99.8 | 1.8 | 1.7 | 78.6 | 67 | 1.8 |
| 3 | 3 | 30 | 97.5 | [92.9, 99.1] | 97.3 | 2.5 | 3.1 | 110.6 | 125 | 2.5 |
| 4 | 15 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 1.5 | 1.6 | 76.3 | 65 | 1.5 |
| 4 | 15 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 3.4 | 3.5 | 159.6 | 141 | 3.4 |
| 4 | 15 | 20 | 99.2 | [95.4, 99.9] | 98.8 | 8.0 | 8.4 | 369.5 | 337 | 8.0 |
| 4 | 15 | 30 | 89.2 | [82.3, 93.6] | 87.4 | 14.9 | 15.6 | 729.8 | 624 | 13.3 |
| 5 | 6 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.6 | 0.6 | 33.2 | 26 | 0.6 |
| 5 | 6 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 1.3 | 1.4 | 69.1 | 56 | 1.3 |
| 5 | 6 | 20 | 100.0 | [96.9, 100.0] | 99.5 | 3.5 | 3.4 | 177.6 | 135 | 3.5 |
| 5 | 6 | 30 | 92.5 | [86.4, 96.0] | 94.7 | 5.9 | 6.2 | 299.2 | 250 | 5.5 |
| 6 | 28 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 2.9 | 3.0 | 145.9 | 121 | 2.9 |
| 6 | 28 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 6.7 | 6.6 | 347.6 | 263 | 6.7 |
| 6 | 28 | 20 | 99.2 | [95.4, 99.9] | 97.8 | 15.9 | 15.7 | 779.8 | 630 | 15.8 |
| 6 | 28 | 30 | 76.7 | [68.3, 83.3] | 77.7 | 26.1 | 29.1 | 1295.4 | 1166 | 20.0 |

- Model mengabaikan biaya tanpa-loss (T_loopback) dan jitter, sehingga cocok terutama pada loss tinggi, saat retransmisi mendominasi waktu.

### Uji signifikansi sukses: proposal (method 4) vs EAP-TLS Hybrid PQC (method 6)

Per tingkat loss: sukses/percobaan, Wilson 95%, dan uji eksak Fisher dua sisi (`scipy.stats.fisher_exact`) pada tabel 2x2 sukses/gagal.

| Loss % | Method 4 sukses | Wilson 95% % | Method 6 sukses | Wilson 95% % | Fisher p (dua sisi) |
| --- | --- | --- | --- | --- | --- |
| 0 | 120/120 (100.0%) | [96.9, 100.0] | 120/120 (100.0%) | [96.9, 100.0] | 1.000 |
| 1 | 120/120 (100.0%) | [96.9, 100.0] | 120/120 (100.0%) | [96.9, 100.0] | 1.000 |
| 5 | 120/120 (100.0%) | [96.9, 100.0] | 120/120 (100.0%) | [96.9, 100.0] | 1.000 |
| 10 | 120/120 (100.0%) | [96.9, 100.0] | 120/120 (100.0%) | [96.9, 100.0] | 1.000 |
| 20 | 119/120 (99.2%) | [95.4, 99.9] | 119/120 (99.2%) | [95.4, 99.9] | 1.000 |
| 30 | 107/120 (89.2%) | [82.3, 93.6] | 92/120 (76.7%) | [68.3, 83.3] | 0.016 |

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
| 4 | message_1 | 2358 | 10 | 3 | 2 | yes | observasi nyata |
| 4 | message_2 | 6114 | 25 | 7 | 5 | yes | observasi nyata |
| 4 | message_3 | 3759 | 15 | 4 | 3 | yes | observasi nyata |
| 4 | message_4 | 16 | 1 | 1 | 1 | no | observasi nyata |
| 5 | message_1 | 289 | 2 | 1 | 1 | no | observasi nyata |
| 5 | message_2 | 1148 | 5 | 2 | 1 | no | observasi nyata |
| 5 | message_3 | 990 | 4 | 1 | 1 | no | observasi nyata |
| 5 | message_4 | 51 | 1 | 1 | 1 | no | observasi nyata |
| 6 | message_1 | 1589 | 7 | 2 | 2 | yes | observasi nyata |
| 6 | message_2 | 12600 | 50 | 13 | 9 | yes | observasi nyata |
| 6 | message_3 | 10983 | 44 | 11 | 8 | yes | observasi nyata |
| 6 | message_4 | 23 | 1 | 1 | 1 | no | observasi nyata |

Pesan yang memerlukan fragmentasi pada method 4 (SIGMA XWING PQC) dan method 6 (EAP-TLS Hybrid PQC) — keduanya observasi nyata: XWING/hybrid-KEM (X25519+ML-KEM-768) menambah ~1.1-1.2 KB per elemen KEM dan tanda tangan ML-DSA-44 menambah ~2.4 KB per pesan, sehingga keduanya memerlukan banyak round-trip fragmentasi EAP sedangkan method 0, 1, 2, 3 dan 5 (klasik) selalu muat dalam sedikit fragmen.

