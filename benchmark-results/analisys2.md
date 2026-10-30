# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)

_Dibuat otomatis oleh benchmark/e2e_analyze.py pada 2026-10-30T16:32:21._

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
| 0 | 2026-10-29T11:35:43+0900 | 1 | PASS | 1.664 | 1 |
| 1 | 2026-10-29T11:35:43+0900 | 1 | PASS | 1.808 | 1 |
| 2 | 2026-10-29T11:35:43+0900 | 1 | PASS | 2.716 | 1 |
| 3 | 2026-10-29T11:35:43+0900 | 1 | PASS | 2.116 | 1 |
| 4 | 2026-10-29T11:35:43+0900 | 1 | PASS | 7.803 | 1 |
| 5 | 2026-10-29T11:35:44+0900 | 1 | PASS | 4.127 | 1 |
| 6 | 2026-10-29T11:35:51+0900 | 1 | PASS | 9.009 | 1 |

### Ringkasan statistik handshake end-to-end per method

| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 200 | 100.0 | 1.161 | 0.972 | 1.851 | 0.795 | 10.618 | 3 | 3 |
| 1 | SIG/STAT | 200 | 100.0 | 1.277 | 0.989 | 2.344 | 0.674 | 14.312 | 3 | 3 |
| 2 | STAT/SIG | 200 | 100.0 | 0.996 | 0.954 | 1.378 | 0.635 | 3.103 | 3 | 3 |
| 3 | STAT/STAT | 200 | 100.0 | 1.130 | 1.017 | 1.477 | 0.770 | 11.269 | 3 | 3 |
| 4 | SIGMA-XWING-PQC | 200 | 100.0 | 7.159 | 6.582 | 11.939 | 5.640 | 16.138 | 15 | 15 |
| 5 | EAP-TLS-Classic | 200 | 100.0 | 3.483 | 3.101 | 5.474 | 2.555 | 9.481 | 6 | 6 |
| 6 | EAP-TLS-Hybrid-PQC | 200 | 100.0 | 8.771 | 8.620 | 10.010 | 7.574 | 13.904 | 28 | 28 |

- Handshake end-to-end tercepat: **method 2** (STAT/SIG).
- Handshake end-to-end terlambat: **method 6** (EAP-TLS-Hybrid-PQC), karena fragmentasi EAP membutuhkan 28 round-trip RADIUS dibanding 3 untuk method klasik.

### Pembagian beban initiator vs responder (live, wall-clock nyata)

Setiap harness (UE/initiator) mengukur, per round-trip RADIUS, waktu yang dihabiskan **menunggu balasan** (`send()` sampai `recv()` kembali) secara terpisah dari waktu yang dihabiskan **mengerjakan sendiri** (membangun paket RADIUS/EAP, HMAC-MD5 Message-Authenticator, dan menjalankan engine EDHOC/TLS-nya sendiri) di antara round-trip. `responder_ms` = total waktu menunggu (mendominasi oleh pemrosesan penuh di sisi FreeRADIUS — parsing, dispatch modul, kripto, serialisasi balasan — karena transit jaringan nyata di loopback nyaris nol); `initiator_ms` = `duration_ms` dikurangi itu, murni kerja lokal UE. Ini pengukuran **live nyata** per handshake, bukan model — berbeda dari section 1b yang cuma menghitung compute kripto murni tanpa overhead RADIUS/TLS-framing sama sekali.

| Method | Profil | Initiator mean (ms) | Responder mean (ms) | Initiator % | Responder % | Total mean (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 0.134 | 1.027 | 11.5% | 88.5% | 1.161 |
| 1 | SIG/STAT | 0.132 | 1.145 | 10.3% | 89.7% | 1.277 |
| 2 | STAT/SIG | 0.141 | 0.855 | 14.2% | 85.8% | 0.996 |
| 3 | STAT/STAT | 0.131 | 0.999 | 11.6% | 88.4% | 1.130 |
| 4 | SIGMA-XWING-PQC | 1.295 | 5.863 | 18.1% | 81.9% | 7.159 |
| 5 | EAP-TLS-Classic | 0.639 | 2.845 | 18.3% | 81.7% | 3.483 |
| 6 | EAP-TLS-Hybrid-PQC | 0.676 | 8.094 | 7.7% | 92.3% | 8.771 |

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
| durable | 600 | 7.550 | 6.688 | 11.740 | 6.140 | 0.770 |
| tmpfs | 600 | 5.787 | 5.527 | 7.635 | 5.064 | 0.044 |

- Biaya penyimpanan (selisih median durable - tmpfs): **1.161 ms**, 95% CI [1.063, 1.285] ms.
- Penyimpanan (protokol v3): record dua-slot praalokasi (`rec.bin` DN-AAA, `ue.rec` UE). Di jalur kritis ada dua `fdatasync`: UE menulis slot NEXT sebelum Message3 dan DN-AAA menulis record baru sebelum Message4 (write-ahead). Di luar jalur kritis ada dua lagi: DN-AAA menolkan slot dengan sk_B lama setelah Message4 (worker thread) dan UE menolkan sk_A lama saat promosi setelah Message4 (kolom `ue_commit_ms`). Waktu per panggilan: `storage-strace.txt` (`strace -c -w`, wall-clock, termasuk overhead tracing).

### Biaya per flush di jalur kritis (UE dan DN-AAA dipisah)

`benchmark/storage_ablation.sh R 100 flush`: empat konfigurasi dalam satu sesi VM, urutan dirotasi tiap ronde, record di-provision ulang dan radiusd di-restart tiap run, 20 handshake pemanasan dibuang. `ue_tmpfs` = direktori UE (`ue/`) di tmpfs, DN-AAA (`edhoc_db/`) di disk, sehingga yang tersisa hanya flush commit DN-AAA sebelum Message4; `dn_tmpfs` = kebalikannya, yang tersisa hanya flush NEXT UE sebelum Message3. Median dengan bootstrap 95% CI (4000 resample, seed 1). Seri ini terpisah dari tabel durable/tmpfs di atas (yang dipakai untuk angka 1.161 ms dan tabel transport).

| Konfigurasi | UE | DN-AAA | N (PASS/total) | Mean (ms) | Median (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| durable | disk | disk | 600/600 | 7.229 | 6.592 | [6.502, 6.658] |
| ue_tmpfs | tmpfs | disk | 600/600 | 6.447 | 6.017 | [5.942, 6.083] |
| dn_tmpfs | disk | tmpfs | 600/600 | 6.598 | 6.081 | [6.025, 6.159] |
| tmpfs | tmpfs | tmpfs | 600/600 | 5.610 | 5.231 | [5.189, 5.304] |

| Biaya | Selisih median | Nilai (ms) | 95% CI (ms) |
| --- | --- | --- | --- |
| Flush UE (NEXT sebelum Message3) | durable - ue_tmpfs | 0.575 | [0.473, 0.677] |
| Flush UE, tanpa flush DN-AAA | dn_tmpfs - tmpfs | 0.850 | [0.749, 0.936] |
| Flush DN-AAA (commit sebelum Message4) | durable - dn_tmpfs | 0.511 | [0.394, 0.603] |
| Flush DN-AAA, tanpa flush UE | ue_tmpfs - tmpfs | 0.786 | [0.682, 0.856] |
| Kedua flush | durable - tmpfs | 1.361 | [1.250, 1.438] |

- Tiap flush diukur dua kali (dengan dan tanpa flush pihak lain). Satu flush saja: UE 0.850 ms, DN-AAA 0.786 ms (jumlah 1.636 ms); kedua flush bersama: 1.361 ms. Biayanya tidak aditif: flush kedua menambah lebih sedikit dari flush pertama (UE dan DN-AAA di disk VM yang sama).
- Selisih durable - tmpfs pada seri ini (1.361 ms) berbeda dari seri dua-konfigurasi di atas karena diukur di sesi VM lain; perbandingan per flush hanya memakai seri ini.

### Komputasi method 4 in-process: sebelum vs sesudah (X-Wing standar, kunci rotasi precompute)

`benchmark/m4_inproc_compare.sh`: handshake method 4 tanpa transport dan tanpa penyimpanan, waktu pemrosesan pesan per pihak, beberapa ronde diselang-seling. `before` = core edhoc4 sebelum perubahan X-Wing (combiner SHA-256 non-standar, decapsulation menghitung ulang pk_X); `inline_rotation_keygen` = core saat ini (X-Wing sesuai draft-connolly-cfrg-xwing-kem-09), kunci rotasi dibuat di dalam handshake: **default dan angka utama**; `precomputed_rotation` = core saat ini dengan pool opsional (kunci rotasi dibuat di luar handshake, ablation). Nilai = rata-rata dari mean/median tiap ronde.

| Varian | Ronde | N/ronde | Initiator mean (us) | Initiator median (us) | Responder mean (us) | Responder median (us) | Total mean (us) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| before | 5 | 2000 | 589.9 | 523.1 | 586.2 | 517.3 | 1176.1 |
| inline_rotation_keygen | 5 | 2000 | 564.4 | 501.5 | 566.3 | 501.4 | 1130.8 |
| precomputed_rotation | 5 | 2000 | 509.7 | 452.8 | 509.8 | 454.2 | 1019.6 |

- Default (rotasi inline): 1130.8 us, 45.3 us lebih rendah dari `before` berkat perubahan X-Wing (terutama decapsulation tanpa hitung ulang pk_X).
- Pool opsional: 1019.6 us, 111.2 us lebih rendah dari default karena kunci rotasi dibuat di luar handshake.
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
| 4 | 7.159 | 0.985 | 1.161 | 15 | 0.334 |
| 6 | 8.771 | 0.894 | 0.000 | 28 | 0.281 |

### Uji pemulihan method 4 (protokol v3, tanpa grace key)

150 handshake pada loss 20% lalu 30 handshake tanpa loss, tanpa re-provisioning. `used_next` = run dimulai di slot NEXT (sesi sebelumnya berhenti setelah UE menulis NEXT); tanpa fallback berarti DN-AAA sudah commit (Message4 / EAP-Success hilang) dan sesi ini memulihkannya; dengan fallback berarti Message3 tidak sampai, NEXT ditolak, dan UE mengulang dengan CUR.

| Seri | N | PASS | used_next | pulih tanpa fallback (Message4 hilang) | fallback (Message3 hilang) | gagal |
| --- | --- | --- | --- | --- | --- | --- |
| loss 20% | 150 | 149 | 0 | 0 | 0 | 1 |
| setelahnya, loss 0% | 30 | 30 | 0 | 0 | 0 | 0 |

- Desync: **0** (run tanpa loss yang gagal setelah seri lossy); re-provisioning: **0** (seri tidak pernah menulis ulang kunci).
- Run yang gagal pada loss 20% adalah run yang kehabisan retransmisi; sesi berikutnya memulihkan state lewat NEXT atau fallback.

### Uji pemulihan dengan loss paksa (Message3 / Message4 di-drop)

`benchmark/recovery_forced.sh`: provisioning sekali di awal, lalu tiap kasus berulang kali: satu sesi dengan loss deterministik (`e2e_radius_bench --drop-msg3-once` / `--drop-msg4-once`, semua salinan pesan itu hilang; status DROP) diikuti satu sesi normal (sesi pemulihan), tanpa loss lain dan tanpa re-provisioning. Di akhir 10 sesi normal untuk cek desync. `EAP-Failure` = Access-Reject pada percobaan pertama sesi pemulihan.

| Kasus | N | Sesi drop | Pemulihan PASS | used_next | EAP-Failure | fallback | Mean pemulihan (ms) | Median pemulihan (ms) | RADIUS RT (median) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 di-drop (tidak sampai ke DN-AAA) | 20 | 20 | 20 | 20 | 20 | 20 | 1011.496 | 1010.368 | 19 |
| Message4 di-drop (DN-AAA sudah commit) | 20 | 20 | 20 | 20 | 0 | 0 | 8.238 | 7.010 | 15 |
| Message3 di-drop, `reject_delay = 0` | 20 | 20 | 20 | 20 | 20 | 20 | 9.697 | 8.636 | 19 |
| Setelahnya, sesi normal | 10 | 0 | 10 | 0 | 0 | 0 | 7.200 | 6.469 | 15 |

- Desync: **0** (sesi pemulihan atau sesi sesudahnya yang gagal); re-provisioning: **0** (record hanya di-provision sekali sebelum kasus pertama).
- Message3 di-drop: sesi pemulihan mulai di NEXT, DN-AAA (belum commit) menolak Message1 dengan EAP-Failure, UE mengulang dengan CUR dan menyimpan NEXT baru; waktunya mencakup kedua percobaan. Message4 di-drop: DN-AAA sudah commit, jadi sesi di NEXT langsung sukses tanpa fallback.
- Waktu pemulihan Message3 di-drop didominasi `reject_delay = 1` FreeRADIUS (default; setiap Access-Reject ditahan 1 s, kebijakan server, bukan protokol): median 1010.368 ms. Dengan `reject_delay = 0` (radiusd.conf diubah sementara lalu dikembalikan): median 8.636 ms, yaitu percobaan di NEXT sampai EAP-Failure ditambah satu sesi penuh di CUR.

### Load VM selama seri (vmstat, sampel 5 s)

| Sampel | r (run queue) mean | us % | sy % | id % mean | id % min | wa % |
| --- | --- | --- | --- | --- | --- | --- |
| 188 | 2.2 | 0.4 | 0.6 | 98.6 | 91 | 0.0 |

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
| 0 | 0.0 | 100.0 | 0.977 | 1.173 | 0.000 |
| 0 | 1.0 | 100.0 | 5.645 | 43.705 | 0.083 |
| 0 | 5.0 | 100.0 | 19.411 | 91.083 | 0.350 |
| 0 | 10.0 | 100.0 | 38.790 | 157.819 | 0.708 |
| 0 | 20.0 | 99.2 | 81.712 | 239.408 | 1.533 |
| 0 | 30.0 | 97.5 | 161.029 | 383.435 | 3.058 |
| 1 | 0.0 | 100.0 | 0.809 | 1.076 | 0.000 |
| 1 | 1.0 | 100.0 | 1.536 | 1.217 | 0.017 |
| 1 | 5.0 | 100.0 | 19.427 | 108.565 | 0.325 |
| 1 | 10.0 | 100.0 | 23.844 | 94.903 | 0.483 |
| 1 | 20.0 | 100.0 | 68.790 | 191.953 | 1.450 |
| 1 | 30.0 | 96.7 | 165.228 | 390.800 | 3.225 |
| 2 | 0.0 | 100.0 | 0.532 | 0.961 | 0.000 |
| 2 | 1.0 | 100.0 | 3.539 | 41.316 | 0.058 |
| 2 | 5.0 | 100.0 | 15.262 | 90.071 | 0.275 |
| 2 | 10.0 | 100.0 | 37.770 | 107.100 | 0.817 |
| 2 | 20.0 | 100.0 | 74.363 | 213.275 | 1.642 |
| 2 | 30.0 | 98.3 | 148.250 | 374.694 | 2.925 |
| 3 | 0.0 | 100.0 | 0.851 | 1.210 | 0.000 |
| 3 | 1.0 | 100.0 | 3.945 | 41.869 | 0.067 |
| 3 | 5.0 | 100.0 | 11.244 | 59.387 | 0.233 |
| 3 | 10.0 | 100.0 | 37.823 | 95.199 | 0.825 |
| 3 | 20.0 | 100.0 | 80.548 | 229.709 | 1.708 |
| 3 | 30.0 | 96.7 | 143.578 | 391.016 | 3.125 |
| 4 | 0.0 | 100.0 | 5.953 | 6.908 | 0.000 |
| 4 | 1.0 | 100.0 | 21.153 | 57.563 | 0.292 |
| 4 | 5.0 | 100.0 | 80.910 | 174.216 | 1.558 |
| 4 | 10.0 | 100.0 | 161.970 | 358.491 | 3.267 |
| 4 | 20.0 | 98.3 | 412.602 | 731.976 | 8.292 |
| 4 | 30.0 | 93.3 | 712.643 | 1062.735 | 13.358 |
| 5 | 0.0 | 100.0 | 3.091 | 3.485 | 0.000 |
| 5 | 1.0 | 100.0 | 8.010 | 45.306 | 0.092 |
| 5 | 5.0 | 100.0 | 30.474 | 129.948 | 0.592 |
| 5 | 10.0 | 100.0 | 76.256 | 218.478 | 1.492 |
| 5 | 20.0 | 100.0 | 160.511 | 401.762 | 3.292 |
| 5 | 30.0 | 96.7 | 297.577 | 524.193 | 6.075 |
| 6 | 0.0 | 100.0 | 8.975 | 10.332 | 0.000 |
| 6 | 1.0 | 100.0 | 41.569 | 129.487 | 0.625 |
| 6 | 5.0 | 100.0 | 155.856 | 324.408 | 3.033 |
| 6 | 10.0 | 100.0 | 329.046 | 541.296 | 6.600 |
| 6 | 20.0 | 99.2 | 782.599 | 1223.036 | 15.642 |
| 6 | 30.0 | 79.2 | 1356.487 | 2033.476 | 21.750 |

### Validasi model analitis loss

Model: satu RADIUS round-trip berhasil dengan peluang p = (1 - L)^2 (request dan reply sama-sama harus lolos), pertukaran gagal permanen setelah 7 percobaan (1 + 6 retransmisi), sehingga sukses handshake = (1 - (1 - p)^7)^n_RT dan retransmisi per handshake sukses ~ n_RT (1 - p) / p, masing-masing menambah RTO 40 ms. n_RT = jumlah RADIUS round-trip terukur tanpa loss. Interval sukses = Wilson 95%. Retx terukur dihitung di antara handshake yang sukses agar sebanding dengan model; kolom terakhir = rata-rata semua percobaan (seperti tabel di atas).

| Method | n_RT | Loss % | Sukses terukur % | Wilson 95% CI % | Sukses model % | Retx terukur (sukses) | Retx model | Mean terukur (ms) | Model retx x RTO (ms) | Retx (semua) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 19.4 | 13 | 0.3 |
| 0 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.7 | 0.7 | 38.8 | 28 | 0.7 |
| 0 | 3 | 20 | 99.2 | [95.4, 99.9] | 99.8 | 1.5 | 1.7 | 81.7 | 67 | 1.5 |
| 0 | 3 | 30 | 97.5 | [92.9, 99.1] | 97.3 | 3.1 | 3.1 | 161.0 | 125 | 3.1 |
| 1 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 19.4 | 13 | 0.3 |
| 1 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.5 | 0.7 | 23.8 | 28 | 0.5 |
| 1 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.4 | 1.7 | 68.8 | 67 | 1.4 |
| 1 | 3 | 30 | 96.7 | [91.7, 98.7] | 97.3 | 3.3 | 3.1 | 165.2 | 125 | 3.2 |
| 2 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.3 | 0.3 | 15.3 | 13 | 0.3 |
| 2 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.8 | 0.7 | 37.8 | 28 | 0.8 |
| 2 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.6 | 1.7 | 74.4 | 67 | 1.6 |
| 2 | 3 | 30 | 98.3 | [94.1, 99.5] | 97.3 | 3.0 | 3.1 | 148.2 | 125 | 2.9 |
| 3 | 3 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.2 | 0.3 | 11.2 | 13 | 0.2 |
| 3 | 3 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 0.8 | 0.7 | 37.8 | 28 | 0.8 |
| 3 | 3 | 20 | 100.0 | [96.9, 100.0] | 99.8 | 1.7 | 1.7 | 80.5 | 67 | 1.7 |
| 3 | 3 | 30 | 96.7 | [91.7, 98.7] | 97.3 | 3.2 | 3.1 | 143.6 | 125 | 3.1 |
| 4 | 15 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 1.6 | 1.6 | 80.9 | 65 | 1.6 |
| 4 | 15 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 3.3 | 3.5 | 162.0 | 141 | 3.3 |
| 4 | 15 | 20 | 98.3 | [94.1, 99.5] | 98.8 | 8.4 | 8.4 | 412.6 | 337 | 8.3 |
| 4 | 15 | 30 | 93.3 | [87.4, 96.6] | 87.4 | 14.3 | 15.6 | 712.6 | 624 | 13.4 |
| 5 | 6 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 0.6 | 0.6 | 30.5 | 26 | 0.6 |
| 5 | 6 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 1.5 | 1.4 | 76.3 | 56 | 1.5 |
| 5 | 6 | 20 | 100.0 | [96.9, 100.0] | 99.5 | 3.3 | 3.4 | 160.5 | 135 | 3.3 |
| 5 | 6 | 30 | 96.7 | [91.7, 98.7] | 94.7 | 6.3 | 6.2 | 297.6 | 250 | 6.1 |
| 6 | 28 | 5 | 100.0 | [96.9, 100.0] | 100.0 | 3.0 | 3.0 | 155.9 | 121 | 3.0 |
| 6 | 28 | 10 | 100.0 | [96.9, 100.0] | 100.0 | 6.6 | 6.6 | 329.0 | 263 | 6.6 |
| 6 | 28 | 20 | 99.2 | [95.4, 99.9] | 97.8 | 15.8 | 15.7 | 782.6 | 630 | 15.6 |
| 6 | 28 | 30 | 79.2 | [71.1, 85.5] | 77.7 | 27.5 | 29.1 | 1356.5 | 1166 | 21.8 |

- Model mengabaikan biaya tanpa-loss (T_loopback) dan jitter, sehingga cocok terutama pada loss tinggi, saat retransmisi mendominasi waktu.

### Uji signifikansi sukses: proposal (method 4) vs EAP-TLS Hybrid PQC (method 6)

Per tingkat loss: sukses/percobaan, Wilson 95%, dan uji eksak Fisher dua sisi (`scipy.stats.fisher_exact`) pada tabel 2x2 sukses/gagal.

| Loss % | Method 4 sukses | Wilson 95% % | Method 6 sukses | Wilson 95% % | Fisher p (dua sisi) |
| --- | --- | --- | --- | --- | --- |
| 0 | 120/120 (100.0%) | [96.9, 100.0] | 120/120 (100.0%) | [96.9, 100.0] | 1.000 |
| 1 | 120/120 (100.0%) | [96.9, 100.0] | 120/120 (100.0%) | [96.9, 100.0] | 1.000 |
| 5 | 120/120 (100.0%) | [96.9, 100.0] | 120/120 (100.0%) | [96.9, 100.0] | 1.000 |
| 10 | 120/120 (100.0%) | [96.9, 100.0] | 120/120 (100.0%) | [96.9, 100.0] | 1.000 |
| 20 | 118/120 (98.3%) | [94.1, 99.5] | 119/120 (99.2%) | [95.4, 99.9] | 1.000 |
| 30 | 112/120 (93.3%) | [87.4, 96.6] | 95/120 (79.2%) | [71.1, 85.5] | 0.002 |

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
| 4 | message_2 | 6097 | 25 | 7 | 5 | yes | observasi nyata |
| 4 | message_3 | 3756 | 15 | 4 | 3 | yes | observasi nyata |
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

### Model ukuran method 4 vs live

`edhoc_sizes.py` memodelkan format kawat `edhoc4.c` byte demi byte (field digabung mentah tanpa CBOR, tag AES-128-GCM 16 B, item EAD = label 1 B + Npk) dan fragmenter EAP-EDHOC yang sama dengan `transport.cpp`/harness (payload maksimum 1000 B: fragmen pertama 997 B data, berikutnya 999 B). `mtu_fragmentation.py` berhenti dengan error jika model berbeda dari live.

| Pesan | Model (B) | Live (B) | Fragmen EAP model | Fragmen EAP live |
| --- | --- | --- | --- | --- |
| message_1 | 2358 | 2358 | 3 | 3 |
| message_2 | 6097 | 6097 | 7 | 7 |
| message_3 | 3756 | 3756 | 4 | 4 |
| message_4 | 16 | 16 | 1 | 1 |
| **Total** | **12227** | **12227** | **15** | **15** |

- Satu fragmen EAP = satu round-trip RADIUS, jadi n_RT method 4 = **15**. Model sama dengan live.

## 5. Full 5G core path (UE → gNB → AMF → SMF → UPF → FreeRADIUS)

`benchmark/fullstack_bench.sh` (log: `fullstack_analyze.py`): method 4 protokol final v3 lewat UERANSIM (nr-ue, nr-gnb) + Open5GS (AMF, SMF, UPF dengan relay RADIUS) + FreeRADIUS `radiusd -f`, satu VM. Tiap proses menulis `[E4T] <tag> t_us=...` (CLOCK_MONOTONIC, µs, `E4_TIMING=1`). Konfigurasi A = secondary authentication aktif; B = `OPEN5GS_SEC_AUTH=0` (PDU session tanpa EAP-EDHOC). Seri A1 B1 A2 B2 A3 B3, tiap seri stack di-restart, 5 sesi pemanasan dibuang lalu 100 sesi (nr-cli `ps-establish`, tunggu hasil atau 5 s, `ps-release`, jeda 200 ms). Record UE dan DN-AAA di-provision sekali di awal. Median dengan bootstrap 95% CI (4000 resample, seed 1).

- Di SMF ini secondary authentication **dimulai setelah** PDU Session Establishment Accept (timer 100 ms setelah N2 PDU Session Resource Setup Response), bukan sebelum Accept. Karena itu `t_pdu_ms` (Request → Accept) tidak memuat EAP-EDHOC; waktu sampai sesi terautentikasi adalah `t_ready_ms` (Request → Authentication Result dengan EAP-Success; untuk B = Accept).
- `t_secauth_ms` = Authentication Command pertama → Authentication Result di UE; `t_radius_ms` = jumlah Access-Request → balasan di relay UPF (FreeRADIUS + loopback); `t_core_ms` = selisihnya (UE, gNB, AMF, SMF, relay SMF↔UPF); `t_smf_relay_ms` = jumlah waktu panggilan relay di SMF (SMF↔UPF + `t_radius_ms`).
- UERANSIM tidak punya EAP-TLS peer, jadi EAP-TLS tidak diukur lewat full stack (perbandingan EAP-TLS tetap dari harness, bagian 1c dan 2).

| Konfigurasi | Sesi | PASS | Gagal | msk_match | rotated |
| --- | --- | --- | --- | --- | --- |
| A | 300 | 300 | 0 | 100.0% | 100.0% |
| B | 300 | 300 | 0 | n/a | n/a |

| Metrik | Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| `t_pdu_ms` | A | 300 | 193.506 | 193.445 | 205.524 | [192.566, 194.224] |
| `t_pdu_ms` | B | 300 | 189.237 | 191.127 | 203.367 | [190.331, 192.089] |
| `t_ready_ms` | A | 300 | 433.705 | 398.221 | 645.524 | [386.620, 410.984] |
| `t_ready_ms` | B | 300 | 189.237 | 191.127 | 203.367 | [190.310, 191.964] |
| `t_secauth_ms` | A | 300 | 102.802 | 73.373 | 262.023 | [70.953, 76.568] |
| `t_radius_ms` | A | 300 | 13.275 | 9.249 | 34.137 | [7.887, 10.910] |
| `t_core_ms` | A | 300 | 89.528 | 64.489 | 236.364 | [61.927, 67.451] |
| `t_acc_to_auth_ms` | A | 300 | 137.397 | 121.944 | 198.471 | [111.865, 133.551] |
| `t_smf_relay_ms` | A | 300 | 25.972 | 17.992 | 66.309 | [14.950, 22.365] |
| `ue_store_next_ms` | A | 300 | 0.890 | 0.701 | 1.669 | [0.687, 0.731] |
| `ue_promote_ms` | A | 300 | 0.816 | 0.603 | 1.961 | [0.585, 0.629] |
| `aaa_commit_ms` | A | 300 | 0.880 | 0.665 | 1.915 | [0.653, 0.679] |

- Selisih median `t_pdu_ms` A − B (Request → Accept): **2.318 ms**, 95% CI [1.084, 3.488] ms.
- Selisih median `t_ready_ms` A − B (Request → sesi siap): **207.094 ms**, 95% CI [195.574, 219.377] ms.
- `t_pdu_ms` A ≈ B: tidak ada pesan EAP-EDHOC antara Request dan Accept (semua sesi A: Command pertama datang 102.6 ms atau lebih setelah Accept), jadi selisih `t_pdu_ms` bukan biaya secondary authentication. Biayanya ada di `t_ready_ms`: selisih A − B = jeda Accept → Command pertama (median 121.9 ms, termasuk timer 100 ms SMF dan setup N2/N3) + `t_secauth_ms` (median 73.4 ms).

Median per seri (ms):

| Seri | N | `t_pdu_ms` | `t_ready_ms` | `t_secauth_ms` | `t_radius_ms` | `t_core_ms` |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | 100 | 193.413 | 447.529 | 101.146 | 14.960 | 82.891 |
| A2 | 100 | 192.032 | 380.019 | 69.665 | 7.254 | 61.829 |
| A3 | 100 | 194.260 | 383.793 | 67.992 | 7.575 | 58.219 |
| B1 | 100 | 190.667 | 190.667 | - | - | - |
| B2 | 100 | 191.396 | 191.396 | - | - | - |
| B3 | 100 | 191.151 | 191.151 | - | - | - |

- Antar seri A, median `t_secauth_ms` berkisar 68.0–101.1 ms (seri pertama setelah provisioning paling lambat); B stabil. Angka gabungan memakai ketiga seri.

| Sumber | Message1 | Message2 | Message3 | Message4 | Ronde NAS | RADIUS RT | Sesi |
| --- | --- | --- | --- | --- | --- | --- | --- |
| full stack | 2358 | 6097 | 3756 | 16 | 14 | 15 | 300 |
| harness (e2e-handshake.csv) | 2358 | 6097 | 3756 | 16 | - | 15 | 200 |

- RADIUS RT full stack = harness: EAP-Response/Identity dikirim SMF sendiri (dari SUPI) tanpa ronde NAS, sehingga ronde NAS = RADIUS RT − 1.

| Pengukuran | Mean (ms) | Median (ms) | Per RADIUS RT, median (ms) |
| --- | --- | --- | --- |
| harness: handshake E2E (`duration_ms`) | 7.159 | 6.582 | 0.439 |
| harness: menunggu RADIUS (`responder_ms`) | 5.863 | 5.348 | 0.356 |
| full stack: `t_radius_ms` | 13.275 | 9.249 | 0.617 |
| full stack: `t_secauth_ms` | 102.802 | 73.373 | 4.891 |

- `t_radius_ms` mengukur bagian yang sama dengan `responder_ms` harness (Access-Request → balasan, FreeRADIUS + DN-AAA), bukan `duration_ms`: `duration_ms` juga memuat kriptografi dan flush UE. Selisih median `t_radius_ms` − `responder_ms` = 3.902 ms (0.260 ms per RT). Kemungkinan penyebab (tidak diukur terpisah): relay UPF membuat socket UDP baru per Access-Request dan menghitung MD5/HMAC sendiri, dan di full stack radiusd berbagi CPU dengan 13 proses lain (NF Open5GS, gNB, UE).
- Bagian terbesar `t_secauth_ms` adalah `t_core_ms` (UE ↔ gNB ↔ AMF ↔ SMF, 14 ronde NAS lewat NGAP/SBI): biaya transport 5G core per ronde, bukan kriptografi EDHOC.

### Uji pemulihan lewat full stack (`E4_DROP_ONCE` di relay UPF)

Relay UPF membuang sekali Access-Request berisi fragmen pertama Message3 (tidak sampai ke DN-AAA) atau Access-Challenge berisi Message4 (DN-AAA sudah commit); SMF lalu timeout (2 s) dan mengirim Authentication Result tanpa EAP. Sesi berikutnya diulang sampai EAP-Success (maks. 3); UERANSIM tidak mengulang sendiri, jadi setelah EAP-Failure + fallback diperlukan satu PDU session lagi di CUR.

| Kasus | N | Drop di UPF | Sesi drop tanpa EAP | used_next | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) | Sesi terakhir median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 dibuang | 10 | 10 | 10 | 10 | 10 | 10 | 2 | 10 | 10 | 2091.5 / 2063.0 | 434.0 |
| Message4 dibuang | 10 | 10 | 10 | 10 | 0 | 0 | 1 | 10 | 10 | 362.4 / 361.8 | 361.8 |

- Sesi normal sesudahnya: 10/10 sukses. Desync: **0**; re-provisioning: **0** (record di-provision sekali sebelum seri pertama).
- Waktu pulih = PDU Session Establishment Request sesi pemulihan pertama → EAP-Success sesi terakhir. Pada Message3 dibuang waktunya memuat `reject_delay = 1` FreeRADIUS (Access-Reject ditahan 1 s) dan satu PDU session tambahan.

## 6. Full 5G core path, standard order (secondary authentication di dalam establishment)

Step 19: SMF menjalankan secondary authentication sebagai **langkah 6 TS 23.502 4.3.2.2.1**, setelah CreateSMContext Response dan data UDM, sebelum asosiasi SM policy (PCF), pemilihan UPF dan PFCP. SMF mengirim EAP-Request/Identity dalam PDU SESSION AUTHENTICATION COMMAND (PTI 0); UE menjawab dengan identitas khusus DN (`ue.yaml` `secondaryAuth.identity` = `ue1@edhoc.internet`, bukan SUPI); EAP-Success dibawa di PDU SESSION ESTABLISHMENT ACCEPT, EAP-Failure di REJECT #29 (TS 24.501 6.3.1.1, 6.4.1.4.1); timeout/error relay = REJECT #29 tanpa EAP. Relay: socket UDP persisten SMF→UPF dan UPF→FreeRADIUS, RADIUS Identifier per request dengan pencocokan Identifier + Response Authenticator, dan relay SMF **non-blocking** (socket di pollset Open5GS, balasan sebagai event, timeout `ogs_timer` 2,5 s; UPF menunggu FreeRADIUS 2 s). Konfigurasi dan prosedur pengukuran sama dengan bagian 5 (seri A1 B1 C1 A2 B2 C2 A3 B3 C3).

- `t_pdu_ms` = Establishment Request → Accept, sekarang **mencakup** secondary authentication; `t_secauth_ms` = Command pertama → Accept; `t_req_to_auth_ms` = Request → Command pertama (CreateSMContext, UDM). Uraian relay per sesi: `t_hop_smf_upf_ms` = Σ(smf_relay_tx→rx) − Σ(upf_req_rx→upf_resp_tx), `t_relay_proc_ms` = Σ(upf_req_rx→upf_resp_tx) − Σ(upf_rad_tx→rx) (build/verify RADIUS di relay), `t_aaa_ms` = Σ(upf_rad_tx→rx) (FreeRADIUS + loopback, = `t_radius_ms`).
- T3580 (TS 24.501 6.3.1.2.1): UE yang menerima Authentication Command hanya menghentikan T3396/T3584/T3585; T3580 tetap berjalan (16 s) dan berhenti saat Accept/Reject. Secondary authentication selesai jauh di bawah 16 s, jadi tidak ada Establishment Request yang dikirim ulang di tengah EAP.

| Konfigurasi | Sesi | PASS | Gagal | msk_match | rotated |
| --- | --- | --- | --- | --- | --- |
| A | 300 | 300 | 0 | 100.0% | 100.0% |
| B | 300 | 300 | 0 | n/a | n/a |

| Metrik | Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| `t_pdu_ms` | A | 300 | 275.731 | 270.529 | 323.493 | [267.905, 272.647] |
| `t_pdu_ms` | B | 300 | 191.316 | 192.201 | 205.677 | [191.343, 192.868] |
| `t_secauth_ms` | A | 300 | 90.161 | 84.233 | 132.715 | [82.134, 86.071] |
| `t_req_to_auth_ms` | A | 300 | 185.571 | 186.998 | 197.714 | [186.209, 187.596] |
| `t_radius_ms` | A | 300 | 6.646 | 5.956 | 10.182 | [5.823, 6.077] |
| `t_core_ms` | A | 300 | 83.515 | 78.219 | 123.254 | [76.297, 80.041] |
| `t_smf_relay_ms` | A | 300 | 12.337 | 11.146 | 19.210 | [10.899, 11.450] |
| `t_hop_smf_upf_ms` | A | 300 | 3.796 | 3.429 | 6.454 | [3.351, 3.521] |
| `t_relay_proc_ms` | A | 300 | 1.895 | 1.523 | 3.908 | [1.445, 1.565] |
| `t_aaa_ms` | A | 300 | 6.646 | 5.956 | 10.182 | [5.830, 6.077] |
| `ue_store_next_ms` | A | 300 | 1.762 | 1.138 | 3.327 | [0.887, 1.599] |
| `ue_promote_ms` | A | 300 | 0.687 | 0.575 | 1.241 | [0.557, 0.588] |
| `aaa_commit_ms` | A | 300 | 0.799 | 0.644 | 1.320 | [0.631, 0.660] |

- **Biaya secondary authentication di dalam establishment**: selisih median `t_pdu_ms` A − B = **78.328 ms**, 95% CI [75.472, 80.853] ms (median `t_secauth_ms` 84.233 ms).
- `t_secauth_ms` berakhir di Accept, jadi juga memuat langkah setelah Access-Accept (PCF, pemilihan UPF, PFCP, N1N2 Accept) yang di B juga ada; karena itu selisih A − B sedikit lebih kecil dari `t_secauth_ms` (di capture: Access-Accept → Accept ≈ 5 ms).

Median per seri (ms):

| Seri | N | `t_pdu_ms` | `t_secauth_ms` | `t_radius_ms` | `t_core_ms` | `t_hop_smf_upf_ms` | `t_relay_proc_ms` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | 100 | 272.536 | 88.434 | 6.351 | 80.857 | 3.618 | 1.524 |
| A2 | 100 | 270.137 | 82.962 | 5.943 | 77.490 | 3.478 | 1.583 |
| A3 | 100 | 269.369 | 82.363 | 5.693 | 76.913 | 3.327 | 1.410 |
| B1 | 100 | 191.957 | - | - | - | - | - |
| B2 | 100 | 192.060 | - | - | - | - | - |
| B3 | 100 | 192.630 | - | - | - | - | - |

### Uraian waktu relay SMF → UPF → DN-AAA (per sesi, A)

| Bagian | Mean (ms) | Median (ms) | Median per RT (ms) | Porsi dari mean total |
| --- | --- | --- | --- | --- |
| SMF ↔ UPF (hop, dua arah) | 3.796 | 3.429 | 0.229 | 30.8% |
| relay UPF (build/verify RADIUS) | 1.895 | 1.523 | 0.102 | 15.4% |
| FreeRADIUS + loopback (`t_aaa_ms`) | 6.646 | 5.956 | 0.397 | 53.9% |
| **Total SMF relay** (`t_smf_relay_ms`) | 12.337 | 11.146 | 0.743 | 100% |

### Konfigurasi C: harness langsung ke radiusd saat full stack menyala tetapi diam

| Pengukuran | N | `duration_ms` mean / median | `responder_ms` mean / median | `responder_ms` per RT, median |
| --- | --- | --- | --- | --- |
| harness, VM diam (e2e-handshake.csv, bagian 1c) | 200 | 7.159 / 6.582 | 5.863 / 5.348 | 0.356 |
| C: harness, full stack diam | 300 | 6.643 / 6.364 | 5.392 / 5.154 | 0.344 |
| A: `t_aaa_ms` (relay UPF → FreeRADIUS) | 300 | - | 6.646 / 5.956 | 0.397 |

- Berbagi CPU dengan stack yang diam: `responder_ms` median 5.348 → 5.154 ms (-0.194 ms). Sisa selisih ke `t_aaa_ms` (+0.802 ms) muncul saat stack aktif (UE, gNB, AMF, SMF bekerja di antara round-trip) dan dari klien RADIUS relay; `t_relay_proc_ms` dan `t_hop_smf_upf_ms` di tabel di atas berada di luar `t_aaa_ms`.

| Sumber | Message1 | Message2 | Message3 | Message4 | Ronde NAS | RADIUS RT | Sesi |
| --- | --- | --- | --- | --- | --- | --- | --- |
| full stack v2 | 2358 | 6097 | 3756 | 16 | 15 | 15 | 300 |
| harness | 2358 | 6097 | 3756 | 16 | - | 15 | 200 |

- Sekarang UE sendiri yang menjawab EAP-Request/Identity, jadi ronde NAS = RADIUS RT (di bagian 5 ronde Identity tidak lewat NAS).

### Uji pemulihan (v2)

Relay UPF membuang sekali Message3 atau Message4; SMF timeout (2,5 s) lalu mengirim REJECT #29 tanpa EAP (UE tidak fallback). Sesi berikutnya diulang sampai Accept dengan EAP-Success (maks. 3).

| Kasus | N | Drop di UPF | Sesi drop: Reject #29 tanpa EAP | used_next | Sesi pemulihan pertama | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 dibuang | 10 | 10 | 10 | 10 | failure 10 | 10 | 10 | 2 | 10 | 10 | 1452.4 / 1438.3 |
| Message4 dibuang | 10 | 10 | 10 | 10 | success 10 | 0 | 0 | 1 | 10 | 10 | 135.9 / 112.5 |

- Sesi normal sesudahnya: 10/10 sukses. Desync: **0**; re-provisioning: **0**.
- `failure` = REJECT #29 berisi EAP-Failure (DN-AAA belum commit, NEXT ditolak), lalu fallback ke CUR dan PDU session berikutnya sukses. Waktu pulih Message3 memuat `reject_delay = 1` FreeRADIUS.

### Urutan pesan dari capture (`fullstack-v2-sample.pcap`)

```
# Message order from fullstack-v2-sample.pcap (tshark, NAS NEA0 null deciphering); repeated EAP-EDHOC rounds are collapsed.
# t [s]   interface  message
   0.3197  NAS        PDU SESSION ESTABLISHMENT REQUEST
   0.3201  SBI        POST /nsmf-pdusession/v1/sm-contexts
   0.3209  SBI        GET /nudm-sdm/v2/imsi-999700000000001/sm-data
   0.3213  SBI        GET /nudr-dr/v1/subscription-data/imsi-999700000000001/99970/provisioned-data/sm-data
   0.3229  SBI        POST /nudm-sdm/v2/imsi-999700000000001/sdm-subscriptions
   0.3239  SBI        POST /namf-comm/v1/ue-contexts/imsi-999700000000001/n1-n2-messages
   0.3246  NAS        PDU SESSION AUTHENTICATION COMMAND [EAP-Request/Identity]
   0.3259  NAS        PDU SESSION AUTHENTICATION COMPLETE [EAP-Response/Identity]
   0.3261  SBI        POST /nsmf-pdusession/v1/sm-contexts/1/modify
   0.3269  RADIUS     Access-Request id=1 [EAP-Response/Identity]
   0.3311  ...        EAP-EDHOC rounds: 28 NAS Command/Complete, 28 RADIUS Access-Request/Challenge (+ SBI N1N2 / UpdateSMContext)
   0.5178  RADIUS     Access-Accept id=15 [EAP-Success]
   0.5180  SBI        POST /npcf-smpolicycontrol/v1/sm-policies
   0.5186  SBI        GET /nudr-dr/v1/policy-data/ues/imsi-999700000000001/sm-data
   0.5203  SBI        POST /nbsf-management/v1/pcfBindings
   0.5226  SBI        POST /namf-comm/v1/ue-contexts/imsi-999700000000001/n1-n2-messages
   0.5230  NAS        PDU SESSION ESTABLISHMENT ACCEPT [EAP-Success]
   0.5253  SBI        POST /nsmf-pdusession/v1/sm-contexts/1/modify
   0.5264  SBI        PUT /nudm-uecm/v1/imsi-999700000000001/registrations/smf-registrations/1
   0.7314  NAS        PDU SESSION RELEASE REQUEST (cause #36)
   0.7317  SBI        POST /nsmf-pdusession/v1/sm-contexts/1/modify
   0.7324  SBI        POST /npcf-smpolicycontrol/v1/sm-policies/1/delete
   0.7328  SBI        DELETE /nbsf-management/v1/pcfBindings/1
   0.7344  NAS        PDU SESSION RELEASE COMMAND (cause #36)
   0.9386  NAS        PDU SESSION RELEASE COMPLETE
   0.9395  SBI        POST /nsmf-pdusession/v1/sm-contexts/1/modify
   0.9407  SBI        DELETE /nudm-sdm/v2/imsi-999700000000001/sdm-subscriptions/e697d8fa-d427-41f1-9f65-f7eed9e4671c
   0.9418  SBI        DELETE /nudm-uecm/v1/imsi-999700000000001/registrations/smf-registrations/1
   0.9421  SBI        DELETE /nudr-dr/v1/subscription-data/imsi-999700000000001/context-data/smf-registrations/1
   0.9431  SBI        POST /namf-callback/v1/imsi-999700000000001/sm-context-status/1
   1.1466  NAS        PDU SESSION ESTABLISHMENT REQUEST
   1.1474  SBI        POST /nsmf-pdusession/v1/sm-contexts
   1.1481  SBI        GET /nudm-sdm/v2/imsi-999700000000001/sm-data
   1.1486  SBI        GET /nudr-dr/v1/subscription-data/imsi-999700000000001/99970/provisioned-data/sm-data
   1.1511  SBI        POST /nudm-sdm/v2/imsi-999700000000001/sdm-subscriptions
   1.1519  SBI        POST /namf-comm/v1/ue-contexts/imsi-999700000000001/n1-n2-messages
   1.1526  NAS        PDU SESSION AUTHENTICATION COMMAND [EAP-Request/Identity]
   1.1543  NAS        PDU SESSION AUTHENTICATION COMPLETE [EAP-Response/Identity]
   1.1544  SBI        POST /nsmf-pdusession/v1/sm-contexts/2/modify
   1.1549  RADIUS     Access-Request id=16 [EAP-Response/Identity]
   1.1553  ...        EAP-EDHOC rounds: 20 NAS Command/Complete, 19 RADIUS Access-Request/Challenge (+ SBI N1N2 / UpdateSMContext)
   3.7607  NAS        PDU SESSION ESTABLISHMENT REJECT (cause #29)
   4.0889  NAS        PDU SESSION ESTABLISHMENT REQUEST
   4.0895  SBI        POST /nsmf-pdusession/v1/sm-contexts
   4.0902  SBI        GET /nudm-sdm/v2/imsi-999700000000001/sm-data
   4.0906  SBI        GET /nudr-dr/v1/subscription-data/imsi-999700000000001/99970/provisioned-data/sm-data
   4.0924  SBI        POST /nudm-sdm/v2/imsi-999700000000001/sdm-subscriptions
   4.0932  SBI        POST /namf-comm/v1/ue-contexts/imsi-999700000000001/n1-n2-messages
   4.0936  NAS        PDU SESSION AUTHENTICATION COMMAND [EAP-Request/Identity]
   4.0950  NAS        PDU SESSION AUTHENTICATION COMPLETE [EAP-Response/Identity]
   4.0951  SBI        POST /nsmf-pdusession/v1/sm-contexts/3/modify
   4.0958  RADIUS     Access-Request id=26 [EAP-Response/Identity]
   4.0960  ...        EAP-EDHOC rounds: 6 NAS Command/Complete, 6 RADIUS Access-Request/Challenge (+ SBI N1N2 / UpdateSMContext)
   5.1303  RADIUS     Access-Reject id=29 [EAP-Failure]
   5.1318  SBI        POST /namf-comm/v1/ue-contexts/imsi-999700000000001/n1-n2-messages
   5.1327  NAS        PDU SESSION ESTABLISHMENT REJECT (cause #29) [EAP-Failure]
   5.4207  NAS        PDU SESSION ESTABLISHMENT REQUEST
   5.4212  SBI        POST /nsmf-pdusession/v1/sm-contexts
   5.4219  SBI        GET /nudm-sdm/v2/imsi-999700000000001/sm-data
   5.4222  SBI        GET /nudr-dr/v1/subscription-data/imsi-999700000000001/99970/provisioned-data/sm-data
   5.4235  SBI        POST /nudm-sdm/v2/imsi-999700000000001/sdm-subscriptions
   5.4242  SBI        POST /namf-comm/v1/ue-contexts/imsi-999700000000001/n1-n2-messages
   5.4249  NAS        PDU SESSION AUTHENTICATION COMMAND [EAP-Request/Identity]
   5.4260  NAS        PDU SESSION AUTHENTICATION COMPLETE [EAP-Response/Identity]
   5.4262  SBI        POST /nsmf-pdusession/v1/sm-contexts/4/modify
   5.4270  RADIUS     Access-Request id=30 [EAP-Response/Identity]
   5.4272  ...        EAP-EDHOC rounds: 28 NAS Command/Complete, 28 RADIUS Access-Request/Challenge (+ SBI N1N2 / UpdateSMContext)
   5.5053  RADIUS     Access-Accept id=44 [EAP-Success]
   5.5057  SBI        POST /npcf-smpolicycontrol/v1/sm-policies
   5.5061  SBI        GET /nudr-dr/v1/policy-data/ues/imsi-999700000000001/sm-data
   5.5074  SBI        POST /nbsf-management/v1/pcfBindings
   5.5095  SBI        POST /namf-comm/v1/ue-contexts/imsi-999700000000001/n1-n2-messages
   5.5099  NAS        PDU SESSION ESTABLISHMENT ACCEPT [EAP-Success]
   5.5112  SBI        POST /nsmf-pdusession/v1/sm-contexts/4/modify
   5.5120  SBI        PUT /nudm-uecm/v1/imsi-999700000000001/registrations/smf-registrations/1
   5.7144  NAS        PDU SESSION RELEASE REQUEST (cause #36)
   5.7148  SBI        POST /nsmf-pdusession/v1/sm-contexts/4/modify
   5.7156  SBI        POST /npcf-smpolicycontrol/v1/sm-policies/2/delete
   5.7160  SBI        DELETE /nbsf-management/v1/pcfBindings/2
   5.7178  NAS        PDU SESSION RELEASE COMMAND (cause #36)
   5.9228  NAS        PDU SESSION RELEASE COMPLETE
   5.9234  SBI        POST /nsmf-pdusession/v1/sm-contexts/4/modify
   5.9241  SBI        DELETE /nudm-sdm/v2/imsi-999700000000001/sdm-subscriptions/e9a21ec0-d427-41f1-9f65-f7eed9e4671c
   5.9263  SBI        DELETE /nudm-uecm/v1/imsi-999700000000001/registrations/smf-registrations/1
   5.9267  SBI        DELETE /nudr-dr/v1/subscription-data/imsi-999700000000001/context-data/smf-registrations/1
   5.9293  SBI        POST /namf-callback/v1/imsi-999700000000001/sm-context-status/1
```

### Perbandingan dengan step 17 (secondary auth setelah Accept, relay blocking)

| Metrik (median, ms) | Step 17 | Step 19 |
| --- | --- | --- |
| PDU session siap (A): `t_ready_ms` / `t_pdu_ms` | 398.221 | 270.529 |
| Tanpa secondary auth (B): `t_pdu_ms` | 191.127 | 192.201 |
| `t_secauth_ms` | 73.373 | 84.233 |
| `t_radius_ms` | 9.249 | 5.956 |
| `t_core_ms` | 64.489 | 78.219 |
| `t_smf_relay_ms` | 17.992 | 11.146 |
| Biaya secondary auth (A − B) | 207.094 | 78.328 |

- Step 17 mengukur sampai Authentication Result setelah Accept (termasuk timer 100 ms SMF); step 19 mengukur sampai Accept yang membawa EAP-Success, tanpa timer, dengan secondary authentication sebelum PCF/UPF/PFCP.
- `t_radius_ms` dan `t_smf_relay_ms` turun karena socket persisten dan relay SMF non-blocking. `t_core_ms` naik: ada satu ronde NAS tambahan (EAP-Request/Identity ke UE, di step 17 dibuat SMF sendiri), dan definisi `t_secauth_ms` sekarang berakhir di Accept (termasuk PCF/UPF/PFCP), bukan di Authentication Result.

### Pengukuran ulang setelah perbaikan jeda UERANSIM (step 20, opsional)

Tag tambahan di gNB (`gnb_ngap_tx`, `gnb_ngap_dl_rx`, `gnb_ngap_setup_rx`, `gnb_dl_nas_tx`) dan UE (`ue_nas_tx`) menunjukkan bahwa jeda ~160 ms pada sesi kedua dan seterusnya bukan di UE sebelum request keluar: request sampai ke gNB ~20 ms kemudian, lalu NGAP-nya tertahan di SCTP gNB sampai SACK tertunda dari AMF datang (Nagle SCTP; UERANSIM tidak memasang `SCTP_NODELAY`, Open5GS memasangnya). Sesi pertama tidak punya data yang belum di-ACK, jadi langsung terkirim (~30 ms). Sisa ~20 ms adalah task RLS UE yang masih di-pause oleh `nr-cli` (polling 20 ms). Perbaikan: `SCTP_NODELAY` di soket SCTP UERANSIM dan RLS ikut berjalan selama `ps-establish`; alur NAS tidak berubah. Seri A1 B1 A2 B2 A3 B3 diukur ulang (3 × 100, 5 pemanasan dibuang); angka step 19 di atas dan di paper tetap.

| Metrik | Konf. | Step 19 median (ms) | Ulang: N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `t_pdu_ms` | A | 270.529 | 300 | 141.094 | 114.352 | 208.911 | [111.453, 116.600] |
| `t_pdu_ms` | B | 192.201 | 300 | 23.262 | 20.962 | 37.100 | [20.807, 21.363] |
| `t_req_to_auth_ms` | A | 186.998 | 300 | 26.136 | 21.154 | 32.491 | [20.919, 21.620] |
| `t_secauth_ms` | A | 84.233 | 300 | 114.958 | 89.970 | 183.862 | [87.951, 92.514] |
| `t_core_ms` | A | 78.219 | 300 | 106.935 | 82.701 | 166.954 | [81.858, 85.078] |
| `t_hop_smf_upf_ms` | A | 3.429 | 300 | 4.633 | 3.580 | 8.535 | [3.466, 3.706] |
| `t_relay_proc_ms` | A | 1.523 | 300 | 2.322 | 1.645 | 5.657 | [1.550, 1.740] |
| `t_aaa_ms` | A | 5.956 | 300 | 8.023 | 6.476 | 14.391 | [6.341, 6.765] |

- `t_pdu_ms` A − B setelah perbaikan: **93.389 ms**, 95% CI [90.426, 95.579] ms (step 19: 78.328 ms). Sesi A PASS 300/300, B PASS 300/300.
- A − B ≈ `t_req_to_auth_ms`(A) + `t_secauth_ms` − `t_pdu_ms`(B). Di step 19 jeda SCTP tidak persis sama di kedua konfigurasi: A 187.0 ms sampai Command pertama, B 192.2 ms sampai Accept; setelah perbaikan 21.2 vs 21.0 ms. `t_secauth_ms` juga naik +5.7 ms karena VM lebih sibuk pada pengukuran ulang (lihat vmstat di folder log). Jadi biaya secondary authentication di dalam establishment berada di kisaran 78–93 ms, didominasi transport 5G core per ronde NAS.

#### Uji pemulihan setelah perbaikan SCTP (step 21)

Relay UPF membuang sekali Message3 atau Message4; SMF timeout (2,5 s) lalu mengirim REJECT #29 tanpa EAP (UE tidak fallback). Sesi berikutnya diulang sampai Accept dengan EAP-Success (maks. 3).

| Kasus | N | Drop di UPF | Sesi drop: Reject #29 tanpa EAP | used_next | Sesi pemulihan pertama | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 dibuang | 10 | 10 | 10 | 10 | failure 10 | 10 | 10 | 2 | 10 | 10 | 1442.6 / 1420.0 |
| Message4 dibuang | 10 | 10 | 10 | 10 | success 10 | 0 | 0 | 1 | 10 | 10 | 149.7 / 125.1 |

- Sesi normal sesudahnya: 10/10 sukses. Desync: **0**; re-provisioning: **0**.
- `failure` = REJECT #29 berisi EAP-Failure (DN-AAA belum commit, NEXT ditolak), lalu fallback ke CUR dan PDU session berikutnya sukses. Waktu pulih Message3 memuat `reject_delay = 1` FreeRADIUS.

- Median waktu pulih step 19 → step 21: Message3 1438.3 → 1420.0 ms, Message4 112.5 → 125.1 ms. Hampir sama: sesi pemulihan didahului sesi yang berakhir dengan Reject setelah timeout 2,5 s, jadi SCTP gNB tidak punya data yang belum di-ACK dan jeda Nagle tidak muncul di step 19 pun.

