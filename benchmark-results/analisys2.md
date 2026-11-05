# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)

_Dibuat otomatis oleh benchmark/e2e_analyze.py pada 2026-11-04T19:31:49._

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
| 4 | 2026-11-04T19:11:07+0900 | 1 | PASS | 6.979 | 1 |
| 5 | 2026-10-29T11:35:44+0900 | 1 | PASS | 4.127 | 1 |
| 6 | 2026-11-04T19:11:13+0900 | 1 | PASS | 12.608 | 1 |

### Ringkasan statistik handshake end-to-end per method

| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | SIG/SIG | 200 | 100.0 | 1.161 | 0.972 | 1.851 | 0.795 | 10.618 | 3 | 3 |
| 1 | SIG/STAT | 200 | 100.0 | 1.277 | 0.989 | 2.344 | 0.674 | 14.312 | 3 | 3 |
| 2 | STAT/SIG | 200 | 100.0 | 0.996 | 0.954 | 1.378 | 0.635 | 3.103 | 3 | 3 |
| 3 | STAT/STAT | 200 | 100.0 | 1.130 | 1.017 | 1.477 | 0.770 | 11.269 | 3 | 3 |
| 4 | SIGMA-XWING-PQC | 200 | 100.0 | 6.383 | 6.284 | 7.758 | 4.963 | 11.283 | 15 | 15 |
| 5 | EAP-TLS-Classic | 200 | 100.0 | 3.483 | 3.101 | 5.474 | 2.555 | 9.481 | 6 | 6 |
| 6 | EAP-TLS-Hybrid-PQC | 200 | 100.0 | 8.273 | 7.847 | 10.436 | 5.530 | 28.005 | 28 | 28 |

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
| 4 | SIGMA-XWING-PQC | 1.223 | 5.160 | 19.2% | 80.8% | 6.383 |
| 5 | EAP-TLS-Classic | 0.639 | 2.845 | 18.3% | 81.7% | 3.483 |
| 6 | EAP-TLS-Hybrid-PQC | 0.684 | 7.589 | 8.3% | 91.7% | 8.273 |

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
| 4 | 6.383 | 0.985 | 1.161 | 15 | 0.283 |
| 6 | 8.273 | 0.894 | 0.000 | 28 | 0.264 |

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
| 4 | message_1 | 2390 | 10 | 3 | 2 | yes | observasi nyata |
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
| message_1 | 2390 | 2390 | 3 | 3 |
| message_2 | 6097 | 6097 | 7 | 7 |
| message_3 | 3756 | 3756 | 4 | 4 |
| message_4 | 16 | 16 | 1 | 1 |
| **Total** | **12259** | **12259** | **15** | **15** |

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
| harness (e2e-handshake.csv) | 2390 | 6097 | 3756 | 16 | - | 15 | 200 |

- RADIUS RT full stack = harness: EAP-Response/Identity dikirim SMF sendiri (dari SUPI) tanpa ronde NAS, sehingga ronde NAS = RADIUS RT − 1.

| Pengukuran | Mean (ms) | Median (ms) | Per RADIUS RT, median (ms) |
| --- | --- | --- | --- |
| harness: handshake E2E (`duration_ms`) | 6.383 | 6.284 | 0.419 |
| harness: menunggu RADIUS (`responder_ms`) | 5.160 | 5.080 | 0.339 |
| full stack: `t_radius_ms` | 13.275 | 9.249 | 0.617 |
| full stack: `t_secauth_ms` | 102.802 | 73.373 | 4.891 |

- `t_radius_ms` mengukur bagian yang sama dengan `responder_ms` harness (Access-Request → balasan, FreeRADIUS + DN-AAA), bukan `duration_ms`: `duration_ms` juga memuat kriptografi dan flush UE. Selisih median `t_radius_ms` − `responder_ms` = 4.169 ms (0.278 ms per RT). Kemungkinan penyebab (tidak diukur terpisah): relay UPF membuat socket UDP baru per Access-Request dan menghitung MD5/HMAC sendiri, dan di full stack radiusd berbagi CPU dengan 13 proses lain (NF Open5GS, gNB, UE).
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
| harness, VM diam (e2e-handshake.csv, bagian 1c) | 200 | 6.383 / 6.284 | 5.160 / 5.080 | 0.339 |
| C: harness, full stack diam | 300 | 6.643 / 6.364 | 5.392 / 5.154 | 0.344 |
| A: `t_aaa_ms` (relay UPF → FreeRADIUS) | 300 | - | 6.646 / 5.956 | 0.397 |

- Berbagi CPU dengan stack yang diam: `responder_ms` median 5.080 → 5.154 ms (+0.074 ms). Sisa selisih ke `t_aaa_ms` (+0.802 ms) muncul saat stack aktif (UE, gNB, AMF, SMF bekerja di antara round-trip) dan dari klien RADIUS relay; `t_relay_proc_ms` dan `t_hop_smf_upf_ms` di tabel di atas berada di luar `t_aaa_ms`.

| Sumber | Message1 | Message2 | Message3 | Message4 | Ronde NAS | RADIUS RT | Sesi |
| --- | --- | --- | --- | --- | --- | --- | --- |
| full stack v2 | 2358 | 6097 | 3756 | 16 | 15 | 15 | 300 |
| harness | 2390 | 6097 | 3756 | 16 | - | 15 | 200 |

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

## 7. Protokol v4: KeyID_B = H(pk_B) di Message1, identitas EAP anonim

Bagian ini adalah hasil step 26, dengan indeks KeyID di disk (`e2e-handshake-v4a.csv`); bagian 7b memakai indeks di memori.

Message1 = KeyID_B ‖ ct_B ‖ AEAD(K_1, AAD_1, PT1) dengan KeyID_B = SHA-256(pk_B), AAD_1 = KeyID_B ‖ ct_B, TH_1 = SHA-256(pk_B ‖ ct_B), PT1 tidak berubah dari v3. DN-AAA mencari record lewat indeks `<db>/kid/<hex(KeyID_B)>` (tanpa operasi KEM jika KeyID tidak dikenal), lalu memeriksa KeyID_B = SHA-256(pk_B record) (waktu-konstan) sebelum Decaps; KeyID_B atau ct_B yang diubah gagal di AEAD. Identitas EAP luar = NAI anonim `@edhoc.internet` (RFC 7542 §2.4) dan tidak memilih apa pun. Rotasi, write-ahead, aturan fallback dan kriptografi tidak berubah. Commit DN-AAA sekarang juga menulis entri indeks (file sementara + rename + fsync direktori) sebelum Message4.

| Pesan | v3 (B) | v4 model (B) | v4 live (B) | Fragmen EAP v4 (model / live) |
| --- | --- | --- | --- | --- |
| Message1 | 2358 | 2390 | 2390 | 3 / 3 |
| Message2 | 6097 | 6097 | 6097 | 7 / 7 |
| Message3 | 3756 | 3756 | 3756 | 4 / 4 |
| Message4 | 16 | 16 | 16 | 1 / 1 |
| **Total** | **12227** | **12259** | **12259** | **15 / 15** |

- RADIUS round-trip: v3 15, v4 15. Message1 bertambah 32 B tetapi tetap 3 fragmen EAP (997 + 999 + 394 B), jadi jumlah fragmen dan round-trip tidak berubah. Karena itu uji loss (bagian 2) **tidak diulang**: peluang kehilangan per round-trip dan jumlah round-trip sama dengan v3.

### Harness E2E loss-free: proposal vs EAP-TLS Hybrid PQC (sesi pengukuran yang sama)

`benchmark/v4_harness.sh`: 2 run × (20 pemanasan dibuang + 100), bergantian method 4 dan 6, radiusd di-restart tiap run (prosedur yang sama dengan seri step 12). Baris method 4 dan 6 di `e2e-handshake.csv` diganti; file lama disimpan sebagai `e2e-handshake-v3.csv`. Median dengan bootstrap 95% CI.

| Method | Versi | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| Proposal (method 4) | v3 (step 12) | 200 | 7.159 | 6.582 | 11.939 | [6.506, 6.672] |
| Proposal (method 4) | v4 | 200 | 8.573 | 8.242 | 10.927 | [8.100, 8.397] |
| EAP-TLS Hybrid PQC | v3 (step 12) | 200 | 8.771 | 8.620 | 10.010 | [8.454, 8.712] |
| EAP-TLS Hybrid PQC | v4 | 200 | 8.392 | 8.087 | 9.641 | [7.964, 8.204] |

- v4, selisih median EAP-TLS Hybrid PQC − proposal: **-0.155 ms**, 95% CI [-0.348, 0.002]: tidak berbeda signifikan (CI memuat 0). Rasio median 0.98×.
- Kenaikan method 4 dari v3 ke v4 (median): E2E 6.582 → 8.242 ms; `responder_ms` 5.348 → 6.995 ms; `initiator_ms` 1.204 → 1.192 ms. Jadi kenaikan ada di sisi DN-AAA, bukan di ukuran pesan (32 B) atau UE. `storage-strace-v4.txt`: flush DN-AAA per handshake naik dari 2 (`storage-strace.txt`) menjadi 5: tulis slot, `fdatasync` file sementara indeks dan `fsync` direktori indeks saat commit (di jalur kritis), lalu nol slot dan `fsync` direktori saat erase (di luar jalur kritis). Flush UE per panggilan tidak naik.

### Full stack v4 (identitas `@edhoc.internet`)

Prosedur sama dengan step 20 (A/B 3 × 100, 5 pemanasan dibuang, perbaikan SCTP aktif). File: `fullstack-handshake-v4.csv`, `fullstack-harness-shared-v4.csv`, `fullstack-recovery-v4.csv`.

- A: PASS 300/300, msk_match 300/300, rotated 300/300; B: PASS 300/300; identitas `@edhoc.internet`.

| Metrik | Konf. | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| `t_pdu_ms` | A | 300 | 107.724 | 99.370 | 156.689 | [97.916, 101.019] |
| `t_pdu_ms` | B | 300 | 22.715 | 21.430 | 34.755 | [21.113, 21.688] |
| `t_secauth_ms` | A | 300 | 85.054 | 77.084 | 133.943 | [76.005, 79.100] |
| `t_core_ms` | A | 300 | 77.775 | 69.773 | 126.931 | [68.820, 71.583] |
| `t_hop_smf_upf_ms` | A | 300 | 2.696 | 2.664 | 3.589 | [2.623, 2.714] |
| `t_relay_proc_ms` | A | 300 | 0.841 | 0.770 | 1.360 | [0.758, 0.793] |
| `t_aaa_ms` | A | 300 | 7.279 | 7.133 | 9.043 | [7.013, 7.318] |
| `ue_store_next_ms` | A | 300 | 2.384 | 2.844 | 3.189 | [2.817, 2.862] |
| `aaa_commit_ms` | A | 300 | 2.896 | 2.814 | 3.569 | [2.788, 2.840] |

- `t_pdu_ms` A − B: **77.940 ms**, 95% CI [76.386, 79.544] ms.
- Ukuran / ronde (full stack): [('2390', '6097', '3756', '16', '15', '15')] (Message1..4 B, ronde NAS, RADIUS RT).
- `aaa_commit_ms` sekarang memuat tulis slot dan entri indeks (bagian 6: slot saja). `ue_store_next_ms` juga lebih tinggi daripada di bagian 6 walaupun kode UE tidak berubah dan flush UE di harness tidak naik; penyebabnya di full stack belum diurai.

#### Uji pemulihan v4

Relay UPF membuang sekali Message3 atau Message4; SMF timeout (2,5 s) lalu mengirim REJECT #29 tanpa EAP (UE tidak fallback). Sesi berikutnya diulang sampai Accept dengan EAP-Success (maks. 3).

| Kasus | N | Drop di UPF | Sesi drop: Reject #29 tanpa EAP | used_next | Sesi pemulihan pertama | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 dibuang | 10 | 10 | 10 | 10 | failure 10 | 10 | 10 | 2 | 10 | 10 | 1477.0 / 1467.9 |
| Message4 dibuang | 10 | 10 | 10 | 10 | success 10 | 0 | 0 | 1 | 10 | 10 | 123.4 / 117.1 |

- Sesi normal sesudahnya: 10/10 sukses. Desync: **0**; re-provisioning: **0**.
- `failure` = REJECT #29 berisi EAP-Failure (DN-AAA belum commit, NEXT ditolak), lalu fallback ke CUR dan PDU session berikutnya sukses. Waktu pulih Message3 memuat `reject_delay = 1` FreeRADIUS.

### Identitas di RADIUS dan EAP (v4)

```
# v4 identity check: logs-fullstack-v4-20261104-182330
RADIUS User-Name values in capture.pcap      : ['@edhoc.internet']
EAP-Response/Identity values (all)           : ['@edhoc.internet']
EAP-Response/Identity in NAS (UE -> SMF)     : ['@edhoc.internet']
SUPI (imsi-999700000000001)                  in the 177 RADIUS/relay packets: absent
old DN identity (ue1@edhoc.internet)         in the 177 RADIUS/relay packets: absent
SUPI (imsi-999700000000001)                  in aaa-e4t.txt / radiusd.log: absent
old DN identity (ue1@edhoc.internet)         in aaa-e4t.txt / radiusd.log: absent
RESULT: PASS (only the anonymous NAI appears)
```

## 7b. v4 dengan indeks di memori

Step 27: indeks `<db>/kid/` di disk diganti tabel hash di memori (KeyID_B → record, slot) di dalam instance `rlm_eap_edhoc`, dibangun ulang dari slot record saat start. Slot adalah satu-satunya sumber kebenaran. Commit = tulis slot + satu `fdatasync`, lalu entri tabel. Lookup tetap membaca slot dan memeriksa KeyID_B = SHA-256(pk_B). KeyID tidak dikenal ditolak dari memori, tanpa akses disk dan tanpa Decaps. Format pesan dan kriptografi sama dengan bagian 7.

### Flush per handshake (`strace -c -w`, 20 handshake)

| Versi | UE `fdatasync` | DN-AAA `fdatasync` | DN-AAA `fsync` | DN-AAA `rename` | µs/call UE; DN `fdatasync` |
| --- | --- | --- | --- | --- | --- |
| v3 (step 12) | 2 | 2 | 0 | 0 | 798; 741 |
| v4a, indeks di disk (step 26) | 2 | 3 | 2 | 0 | 673; 903 |
| v4b, indeks di memori | 2 | 2 | 0 | 0 | 688; 758 |

- Di jalur kritis v4b: UE 1 (NEXT sebelum Message3) dan DN-AAA 1 (commit sebelum Message4), sama dengan v3. Sisanya di luar jalur kritis: promosi UE dan erase DN-AAA. Di v4a, indeks menambah dua flush di jalur kritis DN-AAA.

### Harness E2E loss-free (`v4_harness.sh`, sesi yang sama per versi, kernel `7.0.0-38-generic`)

| Method | Versi | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| Proposal (method 4) | v3 (step 12) | 200 | 7.159 | 6.582 | 11.939 | [6.506, 6.672] |
| Proposal (method 4) | v4a (step 26) | 200 | 8.573 | 8.242 | 10.927 | [8.100, 8.397] |
| Proposal (method 4) | v4b | 200 | 6.383 | 6.284 | 7.758 | [6.206, 6.357] |
| EAP-TLS Hybrid PQC | v3 (step 12) | 200 | 8.771 | 8.620 | 10.010 | [8.457, 8.710] |
| EAP-TLS Hybrid PQC | v4a (step 26) | 200 | 8.392 | 8.087 | 9.641 | [7.967, 8.217] |
| EAP-TLS Hybrid PQC | v4b | 200 | 8.273 | 7.847 | 10.436 | [7.760, 7.956] |

- v3 (step 12): selisih median EAP-TLS Hybrid PQC − proposal **2.038 ms**, 95% CI [1.859, 2.157]: proposal lebih cepat.
- v4a (step 26): selisih median EAP-TLS Hybrid PQC − proposal **-0.155 ms**, 95% CI [-0.351, 0.005]: tidak berbeda signifikan (CI memuat 0).
- v4b: selisih median EAP-TLS Hybrid PQC − proposal **1.563 ms**, 95% CI [1.436, 1.707]: proposal lebih cepat.

### Ablasi storage per flush (6 ronde bergantian × 100, `storage_ablation.sh 6 100 flush`)

| Konfigurasi | UE | DN-AAA | N | Mean (ms) | Median (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| durable | disk | disk | 600 | 6.189 | 6.098 | [6.064, 6.130] |
| ue_tmpfs | tmpfs | disk | 600 | 5.693 | 5.608 | [5.579, 5.644] |
| dn_tmpfs | disk | tmpfs | 600 | 5.573 | 5.530 | [5.489, 5.564] |
| tmpfs | tmpfs | tmpfs | 600 | 5.072 | 5.000 | [4.963, 5.051] |

| Biaya | Selisih median | Nilai (ms) | 95% CI (ms) |
| --- | --- | --- | --- |
| Flush UE saja | dn_tmpfs − tmpfs | 0.531 | [0.470, 0.584] |
| Flush DN-AAA saja | ue_tmpfs − tmpfs | 0.609 | [0.550, 0.666] |
| Flush UE, di atas flush DN-AAA | durable − ue_tmpfs | 0.489 | [0.442, 0.535] |
| Flush DN-AAA, di atas flush UE | durable − dn_tmpfs | 0.567 | [0.523, 0.617] |
| Kedua flush | durable − tmpfs | 1.098 | [1.043, 1.152] |

### Full stack v4b (A/B 3 × 100, identitas `@edhoc.internet`)

- A: PASS 300/300, msk_match 300/300, rotated 300/300; B: PASS 300/300.

| Metrik | Konf. | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| `t_pdu_ms` | A | 300 | 101.132 | 96.770 | 135.383 | [95.455, 97.991] |
| `t_pdu_ms` | B | 300 | 22.939 | 20.899 | 38.204 | [20.640, 21.393] |
| `t_secauth_ms` | A | 300 | 79.464 | 74.740 | 112.026 | [73.439, 75.593] |
| `t_core_ms` | A | 300 | 74.395 | 69.391 | 106.629 | [68.454, 70.489] |
| `t_hop_smf_upf_ms` | A | 300 | 2.763 | 2.713 | 3.700 | [2.671, 2.752] |
| `t_relay_proc_ms` | A | 300 | 0.865 | 0.786 | 1.403 | [0.758, 0.823] |
| `t_aaa_ms` | A | 300 | 5.069 | 4.962 | 6.843 | [4.873, 5.056] |
| `ue_store_next_ms` | A | 300 | 2.432 | 2.842 | 3.630 | [2.820, 2.865] |
| `ue_promote_ms` | A | 300 | 0.589 | 0.532 | 0.788 | [0.523, 0.548] |
| `aaa_commit_ms` | A | 300 | 0.620 | 0.583 | 0.764 | [0.576, 0.589] |

- `t_pdu_ms` A − B: **75.871 ms**, 95% CI [74.374, 77.119] ms.
- Ukuran / ronde: [('2390', '6097', '3756', '16', '15', '15')] (Message1..4 B, ronde NAS, RADIUS RT).

#### Uji pemulihan v4b

Relay UPF membuang sekali Message3 atau Message4; SMF timeout (2,5 s) lalu mengirim REJECT #29 tanpa EAP (UE tidak fallback). Sesi berikutnya diulang sampai Accept dengan EAP-Success (maks. 3).

| Kasus | N | Drop di UPF | Sesi drop: Reject #29 tanpa EAP | used_next | Sesi pemulihan pertama | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 dibuang | 10 | 10 | 10 | 10 | failure 10 | 10 | 10 | 2 | 10 | 10 | 1458.2 / 1455.2 |
| Message4 dibuang | 10 | 10 | 10 | 10 | success 10 | 0 | 0 | 1 | 10 | 10 | 102.4 / 100.6 |

- Sesi normal sesudahnya: 10/10 sukses. Desync: **0**; re-provisioning: **0**.
- `failure` = REJECT #29 berisi EAP-Failure (DN-AAA belum commit, NEXT ditolak), lalu fallback ke CUR dan PDU session berikutnya sukses. Waktu pulih Message3 memuat `reject_delay = 1` FreeRADIUS.

### `ue_store_next_ms` di full stack

Median 2,84 ms di full stack v4 dan v4b, padahal 0,70 ms di step 17 dan 1,14–1,37 ms di step 19–20. **Bukan flush tambahan dan bukan indeks KeyID:** nilainya sama sebelum dan sesudah indeks dipindah ke memori, sedangkan `aaa_commit_ms` turun dari 2,81 ke 0,58 ms.

- **Jalur tulis tidak berubah.** `strace -f -T -P ue.rec` pada `nr-ue` (25 sesi): tiap NEXT adalah satu `pwrite64` 12.288 B dan satu `fdatasync`, pada file record yang sama. Tidak ada flush yang bisa dihapus.
- **Waktunya ada di dalam `fdatasync`, dan bimodal:** NEXT lambat (> 1,5 ms) di 21 dari 30 flush, promosi pada file yang sama di 0 dari 30.
- **Bukan MongoDB:** tidak ada satu pun flush NEXT yang bertumpang-tindih dengan flush `mongod` (0 dari 30, jam yang sama).
- **Penyebab: flush pertama setelah disk menganggur.** Di trace, NEXT didahului jeda median 675 ms sejak flush terakhir (flush 2,91 ms), promosi hanya 37 ms (flush 0,61 ms). `benchmark/fsync_idle_probe.py`, tanpa protokol sama sekali, menunjukkan hal yang sama pada disk ini: median 0,60–0,68 ms setelah jeda 0–5 ms, 1,03 ms setelah 100 ms, 2,10 ms setelah 200 ms, 3,00 ms setelah 500 ms (`v4b-fsync-idle-probe.txt`).
- **Mengapa harness tidak terkena:** handshake harness berurutan tanpa jeda, jadi flush UE tetap sekitar 0,69 ms per panggilan (`storage-strace-v4b.txt`). Full stack memberi jeda antar-sesi (release + 200 ms).

Jadi 2,84 ms adalah biaya disk VM setelah menganggur akibat pola sesi benchmark, bukan biaya protokol. Perbedaan dengan step 17 dan 19–20 belum diuji langsung: di step 17 secondary auth berjalan setelah Accept, sehingga ada flush lain tepat sebelumnya (cocok dengan penjelasan ini, tetapi tidak diukur); step 19–20 berjalan di sesi VM lain.

### Waktu bangun ulang indeks

```
edhoc4_dbtest (DBTEST_KEEP10K=1) / edhoc4_keygen --scan, 10000 synthetic records (313 MB), one valid slot each:
page cache warm  : 10000 records, 10000 KeyIDs, 455.6 ms (dbtest), 452.4 ms (--scan)
page cache cold  : 10000 records, 10000 KeyIDs, 6595.8 ms (--scan, after sync + drop_caches)
```

## 7c. Unlinkability v4 (bounded)

Step 29: dua model baru di `symmetry-rev/proverif/`, primitif sama dengan `edhoc_m4v4_*.pv`. `edhoc_m4v4_unlink.pv` tetap ada dan ditandai superseded. Kernel `7.0.0-38-generic`. Batas tiap proses: `systemd-run --user --scope -p MemoryMax=10G -p MemorySwapMax=0`, `timeout 7200` (varian opsi solver: 1800 s), ditambah watchdog `MemAvailable` < 3 GB yang tidak pernah terpicu. VM tidak macet di semua percobaan.

**Hasil: kerahasiaan Npk_A dan Npk_B terbukti. Unlinkability NOT CONCLUDED: tidak ada bukti dan tidak ada serangan, jadi model ini tidak mendukung klaim unlinkability.**

| Model / percobaan | Waktu | Peak memory | Hasil |
|---|---|---|---|
| edhoc_m4v4_nextkey.pv | 0:00.12 | 22 MB | not attacker(s_NpkA[]) is true.; not attacker(s_NpkB[]) is true. |
| edhoc_m4v4_unlink_bounded.pv (duplikat dihapus) | 1:54.41 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| 3c.1 `reconstructTrace = false` | 1:57.24 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| 3c.2 transcript diratakan | 1:56.05 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| 3c.1 + 3c.2 | 1:56.09 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| 3c.3 run 2 berhenti setelah `let PT22` | 0:55.03 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| 3c.1 + 3c.2 + 3c.3 | 0:47.62 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| tambahan: `redundancyElim = no` | 1:55.93 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| tambahan: `simplifyProcess = false` | 1:55.66 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| tambahan: `selFun = Term` | 1:12.27 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| tambahan: `redundantHypElim = false` | 1:55.76 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |
| tambahan: `redundancyElim = no` + `simplifyProcess = false` | 1:56.68 | 9.99 GiB | NOT CONCLUDED (oom-kill di MemoryMax=10G) |

- **Penyebab berhenti:** journal systemd mencatat `oom-kill` pada scope ProVerif untuk `unlink_bounded` dan semua variannya. Tidak ada trace, jadi penilaian serangan nyata atau false attack (langkah 3b) tidak berlaku.
- **Percobaan 3c:** tidak ada yang berhasil, termasuk klaim yang lebih sempit (3c.3). Baris "tambahan" di luar daftar step: hanya opsi solver, model protokol tidak diubah.
- **Letak ledakan memori:** saturasi berhenti di biprocess pertama (`let moved downwards`) pada sekitar 800–1200 clause, sebelum ada keputusan. Model yang sama tanpa `choice` selesai dalam kurang dari 600 MB (di bawah), jadi biaya itu muncul pada terjemahan biprocess. Clause mana yang meledak belum diperiksa.

**Perbaikan pada file terlampir (langkah 3a).** Kedua file berhenti dengan `identifier H already defined` (baris 63), karena blok `Hash, HKDF, AEAD` tertulis dua kali. Blok kedua (10 baris) dihapus; isinya sama dengan blok pertama, dan protokol, AAD, TH_1 serta pemeriksaan KeyID_B tidak berubah. Log error asli: `results/step29-attempts/*.a0-duplicate-decl.log`.

**Cek keterjangkauan (tambahan, bukan hasil baru).** Salinan model dengan event di akhir run, `choice` diganti satu sisi. Tujuannya memastikan hasil secrecy tidak vacuous dan run 2 memang bisa selesai.

| Model | Waktu | Peak memory | Hasil |
|---|---|---|---|
| `reach_nextkey.pv` | 0.21 s | 27 MB | DN mengirim Message2 dan UE selesai: terjangkau; kedua secrecy tetap true |
| `reach_unlink_left.pv` | 51.62 s | 583 MB | run 1 dan run 2 selesai: terjangkau |
| `reach_unlink_right.pv` | 51.33 s | 528 MB | run 1 dan run 2 selesai: terjangkau |

**Cakupan `edhoc_m4v4_nextkey.pv`.** Satu run UE dan satu sesi DN-AAA, tanpa replikasi. `pk_A` dan `pk_B` awal tidak dikirim ke penyerang, sesuai rancangan kunci satu kali yang tidak dipublikasikan. Hasil ini adalah kerahasiaan simbolik dari kunci berikutnya, bukan unlinkability.

**Lint.** `lint.py` memberi OK untuk `nextkey`. Untuk `unlink_bounded`, 14 temuannya semua terkait `choice[...]`, yang tidak dikenali linter; salinan tanpa `choice` hanya memberi temuan untuk nama event `Run1Done`/`Run2Done` yang ditambahkan untuk cek ini.

Berkas: `results/edhoc_m4v4_{nextkey,unlink_bounded}.{log,time}`, `results/step29-attempts/` (varian `.pv`, log, waktu), `results/SUMMARY_v4.txt` (dijalankan ulang `run_all_v4.sh`; hasil model lama tidak berubah).

## 8. Varian AD Message1: v4 (Prof. You), v4s (Dr. Shin), v4t

Step 30. Ketiga varian ada dalam satu build; `edhoc_variant` di blok `edhoc` config radiusd (default `v4`), `secondaryAuth.edhocVariant` atau `EDHOC_VARIANT` di `nr-ue`. `v4s+chk` hanya berbeda di DN-AAA. Paper tidak diubah.

**Ringkasan.** Biaya dan keamanan terhadap penyerang luar praktis sama di keempat varian. Semua query lama ProVerif memberi hasil yang sama, dan T1–T6 ditolak atau diterima dengan cara yang sama. Biaya v4s dan v4s+chk adalah +34 B pada Message1, tanpa tambahan fragmen atau RT. Komputasi Message1 v4s lebih rendah sekitar 3,5 µs di UE dan 6,1 µs di DN-AAA karena tidak menghitung H(pk_B), jauh di bawah derau harness. Satu-satunya perbedaan fungsional adalah T7: pada v4s, UE yang menyimpang boleh mengisi KeyID_B lain di PT1 dan handshake tetap selesai (20/20), jadi salinan itu tidak berfungsi tanpa pemeriksaan `v4s+chk` (ditolak 20/20). Secara simbolik, integritas header pada v4s datang dari TH_1 = H(KeyID_B, ct_B) yang masuk ke K_1, bukan dari salinan di PT1.

### Jawaban §0: AD Message2–4 di implementasi

- AD = **`TH_x` mentah (32 B)**, bukan kosong dan bukan `Enc_structure`: `aead_seal()` memanggil `gcm_seal(key, nonce, th, 32, ...)` dan `aead_open()` memanggil `gcm_open(key, nonce, th, 32, ...)` di `edhoc4/edhoc4.c` (pada saat cek, baris 173 dan 187).
- Sesuai §0.2, AD Message1 v4s mengikuti konvensi itu: **AD = TH_1**. Akibatnya v4s dan v4t memakai panggilan AEAD yang sama; bedanya hanya salinan KeyID_B di PT1 dan pemeriksaan KeyID_B = H(pk_B). "Tanpa AAD" di v4s berarti tanpa AAD_1 = (KeyID_B, ct_B), bukan AD kosong.
- Di model ProVerif, AEAD Message2 ditulis `AEAD_enc` tanpa AD karena TH_x sudah masuk ke kuncinya. v4s dimodelkan dengan cara yang sama, sesuai langkah 3.1.

### Penyesuaian terhadap step file

- **Dicocokkan dengan `Symmetry_Journal_Shin.drawio` halaman 1** (coretan dan teks merah di markup; tersimpan di `symmetry-rev/paper/drawio/`). Sesuai dengan v4s: AAD_1 dicoret di UE dan DN-AAA, `Verify KeyID_B = H(pk_B)` dicoret, TH_1 = H(KeyID_B, ct_B), KeyID_B ditambahkan di posisi ke-3 Plaintext1, `Check ID_CRED_I` tetap, dan tidak ada perbandingan KeyID_B dalam dengan header.
- **Satu coretan di luar Message1:** baris `Store NEXT = (Nsk_A, Npk_A, Npk_B = EAD_2)` di kotak Message2 UE. Step file menyatakan NEXT write-ahead tidak berubah, jadi write-ahead tetap ada di semua varian. Baris itu juga tidak ada di halaman 1 `Symmetry_Journal.drawio`; maksud coretannya perlu dikonfirmasi ke Dr. Shin.
- Di diagram, urutan PT1 adalah `..., KeyID_B, ID_CRED_I, C_I, EAD_1`; implementasi v4 sudah memakai urutan C_I lalu ID_CRED_I, dan v4s mengikutinya. Ukurannya sama.
- Tabel step menulis cek v4t "sama dengan v4s", sedangkan bagian DN-AAA menulis pemeriksaan KeyID_B = H(pk_B) "tetap ada". Yang diikuti bagian DN-AAA.
- PT1 v4s memakai profil biner yang sudah ada: `method ‖ 0x58 0x20 KeyID_B ‖ C_I ‖ ID_CRED_I ‖ EAD_1`. Implementasi v4 tidak membawa Suites_I di PT1, jadi di sini juga tidak; urutan C_I dan ID_CRED_I mengikuti v4. TH_1 v4s dan v4t memakai CBOR sequence `bstr(KeyID_B) bstr(ct_B)` seperti diminta.
- Di v4s, pemeriksaan KeyID terhadap slot record di `edhoc4_db_handle_msg1` juga dilewati, bukan hanya di inti protokol.

### Ukuran (live vs model)

| Varian | Message1–4 live (B) | Total (B) | Model (B) | Live = model | Fragmen EAP | RT |
|---|---|---|---|---|---|---|
| v4 | 2390/6097/3756/16 | 12259 | 2390/6097/3756/16 | cocok | 3/7/4/1 | 15 |
| v4s | 2424/6097/3756/16 | 12293 | 2424/6097/3756/16 | cocok | 3/7/4/1 | 15 |
| v4s+chk | 2424/6097/3756/16 | 12293 | 2424/6097/3756/16 | cocok | 3/7/4/1 | 15 |
| v4t | 2390/6097/3756/16 | 12259 | 2390/6097/3756/16 | cocok | 3/7/4/1 | 15 |

### Harness E2E loss-free (2 run × 100, bergantian dalam satu sesi)

| Varian | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) | Selisih median vs v4 (ms) [95% CI] |
|---|---|---|---|---|---|---|
| v4 | 200 | 6.863 | 6.530 | 7.515 | [6.471, 6.631] | — |
| v4s | 200 | 6.921 | 6.816 | 7.886 | [6.739, 6.907] | +0.285 [+0.160, +0.400] |
| v4s+chk | 200 | 6.695 | 6.544 | 7.621 | [6.452, 6.668] | +0.013 [-0.133, +0.143] |
| v4t | 200 | 6.492 | 6.381 | 7.534 | [6.314, 6.460] | -0.149 [-0.272, -0.054] |
| EAP-TLS Hybrid PQC | 200 | 8.758 | 8.745 | 9.991 | [8.614, 8.838] | +2.215 [+2.037, +2.313] |

Selisih di tabel ini **tidak boleh dibaca sebagai biaya protokol**. v4s dan v4s+chk hanya berbeda satu perbandingan 32 B, tetapi mediannya berbeda 0,272 ms, dan CI v4s serta v4t tidak mencakup 0 dengan arah berlawanan, padahal komputasi Message1 hanya berbeda beberapa µs. Tiap varian memakai radiusd dan record baru dengan urutan tetap dalam tiap run, jadi selisih sebesar ini mencerminkan derau antarsesi dan urutan. Selisih EAP-TLS Hybrid PQC (+2,2 ms) jauh di atas derau itu.

### Komputasi Message1 (10.000 iterasi per varian, bergantian per iterasi, dalam proses)

| Varian | Message1 (B) | UE median (µs) | UE p95 (µs) | DN-AAA median (µs) | DN-AAA p95 (µs) | UE vs v4 (µs) | DN-AAA vs v4 (µs) |
|---|---|---|---|---|---|---|---|
| v4 | 2390 | 142.3 | 194.9 | 74.7 | 117.9 | +0.0 | +0.0 |
| v4s | 2424 | 138.8 | 190.9 | 68.6 | 90.1 | -3.5 | -6.1 |
| v4s+chk | 2424 | 139.0 | 191.5 | 68.7 | 89.3 | -3.3 | -6.0 |
| v4t | 2390 | 138.6 | 192.5 | 70.9 | 90.7 | -3.7 | -3.8 |

### Full stack v4s (A/B 1 × 100, `@edhoc.internet`, tanpa uji pemulihan)

- A: PASS 100/100, msk_match 100/100, rotated 100/100; B: PASS 100/100.
- Ukuran / ronde: [('2424', '6097', '3756', '16', '15', '15')] (Message1..4 B, ronde NAS, RADIUS RT).

| Metrik | Konf. | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
|---|---|---|---|---|---|---|
| `t_pdu_ms` | A | 100 | 96.609 | 96.361 | 114.729 | [94.414, 97.904] |
| `t_pdu_ms` | B | 100 | 20.925 | 20.501 | 32.594 | [19.656, 21.293] |
| `t_secauth_ms` | A | 100 | 77.590 | 76.961 | 91.867 | [75.169, 78.909] |
| `t_aaa_ms` | A | 100 | 5.813 | 5.730 | 7.968 | [5.491, 6.054] |

- `t_pdu_ms` A − B: **75.859 ms**, 95% CI [73.761, 77.942] ms.
- `uname -r`: 7.0.0-38-generic

Yang diukur di sini hanya v4s. Selisih A − B v4b di bagian 7b (75,871 ms) berasal dari sesi dan N yang berbeda.

### ProVerif per varian

Sumber: `symmetry-rev/proverif/results/SUMMARY_v4_variants.txt` (`run_all_variants.sh`, MemoryMax=10G, 3600 s per query; model unlink tidak dijalankan). Semua query selesai; tidak ada NOT CONCLUDED.

Model di `variants/` menambah pemeriksaan ID_CRED_I terhadap record, yang ada di implementasi tetapi tidak ada di `edhoc_m4v4_*.pv` (`claimedI` bebas). File `edhoc_m4v4_*.pv` lama tidak berubah.

| Kelompok query | v4 | v4s | v4s+chk | v4t |
|---|---|---|---|---|
| classical, quantum: sanity false; Q2–Q4, Q5, Q5b, Q6–Q9 true | sesuai | sesuai | sesuai | sesuai |
| KCI: semua true | sesuai | sesuai | sesuai | sesuai |
| PCS: sanity false; Q2–Q4, Q10, Q11 true | sesuai | sesuai | sesuai | sesuai |
| fs_noerase (kontrol negatif): Q5, Q5b, Q6–Q9 false | sesuai | sesuai | sesuai | sesuai |
| recovery: sanity false; Q5, Q7–Q9 true | sesuai | sesuai | sesuai | sesuai |
| nextkey: `s_NpkA`, `s_NpkB` true | sesuai | sesuai | sesuai | sesuai |
| **Integritas header** (classical, quantum, fs_noerase, recovery) | true | true | true | true |
| Integritas header, DN **tanpa** cek ID_CRED_I (`noid`) | false | false | false | false |
| T7 `DN_acc_inner ==> h = p`, UE jujur | n/a | true | true | n/a |
| T7, UE menyimpang (`t7`: penyerang tahu ID_CRED_I) | n/a | **false** | true | n/a |

- **`noid` false di semua varian:** `pk_B` publik di model ini, jadi tanpa cek ID_CRED_I siapa pun bisa membuat Message1 yang diterima DN. Integritas header bergantung pada kerahasiaan ID_CRED_I dan pemeriksaannya, di semua varian. AAD_1 tidak mengubah hasil ini.
- Query integritas header bersifat non-injective, jadi replay ke sesi DN lain tidak dicakup (lihat T6).
- Ini model simbolik dengan AEAD dan hash ideal. Perbedaan antara AD = TH_1 dan AD = AAD_1 pada tingkat komputasional tidak diuji di sini.

### Uji manipulasi T1–T7 (harness, 20 kali per sel)

| test | manipulation | variant | result at the UE | DN-AAA step | DN-AAA median ms | Decaps run |
|---|---|---|---|---|---|---|
| T1 | KeyID_B header: 1 bit | v4 | eap-failure 20/20 | lookup | 0.002 | no |
| T1 | KeyID_B header: 1 bit | v4s | eap-failure 20/20 | lookup | 0.002 | no |
| T1 | KeyID_B header: 1 bit | v4s+chk | eap-failure 20/20 | lookup | 0.002 | no |
| T1 | KeyID_B header: 1 bit | v4t | eap-failure 20/20 | lookup | 0.002 | no |
| T2 | KeyID_B header: of another UE | v4 | eap-failure 20/20 | AEAD tag | 0.161 | yes |
| T2 | KeyID_B header: of another UE | v4s | eap-failure 20/20 | AEAD tag | 0.176 | yes |
| T2 | KeyID_B header: of another UE | v4s+chk | eap-failure 20/20 | AEAD tag | 0.174 | yes |
| T2 | KeyID_B header: of another UE | v4t | eap-failure 20/20 | AEAD tag | 0.160 | yes |
| T3 | ct_B: 1 bit | v4 | eap-failure 20/20 | AEAD tag | 0.178 | yes |
| T3 | ct_B: 1 bit | v4s | eap-failure 20/20 | AEAD tag | 0.164 | yes |
| T3 | ct_B: 1 bit | v4s+chk | eap-failure 20/20 | AEAD tag | 0.172 | yes |
| T3 | ct_B: 1 bit | v4t | eap-failure 20/20 | AEAD tag | 0.154 | yes |
| T4 | AEAD ciphertext: 1 bit | v4 | eap-failure 20/20 | AEAD tag | 0.158 | yes |
| T4 | AEAD ciphertext: 1 bit | v4s | eap-failure 20/20 | AEAD tag | 0.148 | yes |
| T4 | AEAD ciphertext: 1 bit | v4s+chk | eap-failure 20/20 | AEAD tag | 0.147 | yes |
| T4 | AEAD ciphertext: 1 bit | v4t | eap-failure 20/20 | AEAD tag | 0.169 | yes |
| T5 | old Message1 replayed | v4 | eap-failure 20/20 | lookup | 0.001 | no |
| T5 | old Message1 replayed | v4s | eap-failure 20/20 | lookup | 0.001 | no |
| T5 | old Message1 replayed | v4s+chk | eap-failure 20/20 | lookup | 0.001 | no |
| T5 | old Message1 replayed | v4t | eap-failure 20/20 | lookup | 0.001 | no |
| T6 | current Message1 in a second EAP session | v4 | session 1: success 20/20; replay session: challenge 20/20 | accepted (replay); accepted (session 1) | 0.504 | yes |
| T6 | current Message1 in a second EAP session | v4s | session 1: success 20/20; replay session: challenge 20/20 | accepted (replay); accepted (session 1) | 0.540 | yes |
| T6 | current Message1 in a second EAP session | v4s+chk | session 1: success 20/20; replay session: challenge 20/20 | accepted (replay); accepted (session 1) | 0.492 | yes |
| T6 | current Message1 in a second EAP session | v4t | session 1: success 20/20; replay session: challenge 20/20 | accepted (replay); accepted (session 1) | 0.561 | yes |
| T7 | KeyID_B in PT1 != header | v4s | success 20/20 | accepted | 0.562 | yes |
| T7 | KeyID_B in PT1 != header | v4s+chk | eap-failure 20/20 | inner KeyID check | 0.149 | yes |

- **T1, T5:** ditolak dari indeks memori tanpa Decaps, di semua varian.
- **T2–T4:** ditolak di AEAD setelah Decaps, di semua varian. Waktu tolak sama besarnya.
- **T6:** sama di semua varian. DN-AAA menerima Message1 yang sama di sesi EAP kedua, menjalankan Decaps, dan membalas Message2 (biaya sekitar 0,5 ms termasuk tanda tangan). Sesi asli tetap sukses 20/20. Sesi replay hanya dihentikan oleh harness di titik itu, jadi uji ini tidak menunjukkan apakah sesi itu bisa berlanjut; penyerang tidak punya sk_A untuk membuka Message2.
- **T7:** v4s **lolos** 20/20 dan handshake selesai; v4s+chk ditolak 20/20 di cek KeyID dalam. Pelakunya di sini UE yang memegang kuncinya sendiri, bukan penyerang di jaringan.
- **Belum diuji:** pada v4, pemeriksaan KeyID_B = H(pk_B) melindungi dari entri indeks yang tidak konsisten sebelum Decaps (`edhoc4_dbtest`). Skenario itu tidak ada di T1–T7 dan tidak diuji pada v4s.

Berkas: `benchmark-results/{e2e-handshake-variants,m1-compute-variants,fullstack-handshake-v2-variants,fullstack-harness-shared-variants,tamper-variants}.csv`, `tamper-variants-raw/`, `logs-fullstack-v2-20261105-224207/`; skrip `benchmark/{variants_harness.sh,variants_analyze.py,tamper_tests.sh,tamper_analyze.py,m1_compute_bench.c}`.

## 9. Final v5

Step 31. v5 = protokol Dr. Shin + cek KeyID dalam (`v4s+chk` di bagian 8), sekarang default. TH_1 = H(KeyID_B, ct_B); AEAD Message1 dengan AD = TH_1; KeyID_B juga di Plaintext1; DN-AAA mengambil record dari indeks memori, memeriksa ID_CRED_I dan KeyID_B di Plaintext1 = header. Write-ahead NEXT tetap ada. Kernel `7.0.0-38-generic`. Paper tidak diubah.

### Hasil test

| Test | Hasil |
|---|---|
| `edhoc4_xwing_kat` | PASS (3 vektor X-Wing) |
| `edhoc4_selftest` | PASS (default v5, dan 4 varian) |
| `edhoc03_selftest` | PASS |
| `edhoc4_dbtest` | PASS |

`edhoc4_dbtest` disesuaikan: vektor Message1 sekarang 2424 B. Dua kasus memakai pemeriksaan KeyID_B = H(pk_B) yang tidak ada di v5, jadi dijalankan pada varian v4. Untuk v5 ditambah kasus entri indeks palsu: Decaps berjalan, lalu `E4_ERR_AEAD`, dan entri itu **tidak** dihapus. Di v4 penolakan terjadi sebelum Decaps dan entri dihapus. Indeks dibangun dari slot saat start, jadi entri seperti ini tidak muncul dalam operasi normal.

T1–T7 pada v5 (`tamper_tests.sh 20 v5 v5`), 20 kali per baris:

| test | manipulation | variant | result at the UE | DN-AAA step | DN-AAA median ms | Decaps run |
|---|---|---|---|---|---|---|
| T1 | KeyID_B header: 1 bit | v5 | eap-failure 20/20 | lookup | 0.002 | no |
| T2 | KeyID_B header: of another UE | v5 | eap-failure 20/20 | AEAD tag | 0.154 | yes |
| T3 | ct_B: 1 bit | v5 | eap-failure 20/20 | AEAD tag | 0.193 | yes |
| T4 | AEAD ciphertext: 1 bit | v5 | eap-failure 20/20 | AEAD tag | 0.149 | yes |
| T5 | old Message1 replayed | v5 | eap-failure 20/20 | lookup | 0.001 | no |
| T6 | current Message1 in a second EAP session | v5 | session 1: success 20/20; replay session: challenge 20/20 | accepted (replay); accepted (session 1) | 0.522 | yes |
| T7 | KeyID_B in PT1 != header | v5 | eap-failure 20/20 | inner KeyID check | 0.153 | yes |

### SUMMARY_v5 (ProVerif)

Sumber: `symmetry-rev/proverif/results/SUMMARY_v5.txt` (`run_all_v5.sh`, MemoryMax=10G, 3600 s per query). Tidak ada NOT CONCLUDED.

```
Proverif 2.05. Cryptographic protocol verifier, by Bruno Blanchet, Vincent Cheval, and Marc Sylvestre
Final v5 models (gen_m4v4.py --variant v5), one ProVerif process per query, MemoryMax=10G / 3600s
==================================================================
edhoc_m4v5_classical.pv
  query     time  peakmem  result
  q1       0.79s    200MB  not event(UE_finish(W0,a,b)) is false.
  q2       0.72s    205MB  not event(DN_finish(W0,a,b)) is false.
  q3       0.64s    181MB  not event(UE_send_M1(W0,m)) is false.
  q4       1.72s    535MB  inj-event(UE_recv_M2(W0,x,t,a,b)) ==> inj-event(DN_send_M2(W0,x,t,a,b)) is true.
  q5       2.20s    650MB  inj-event(DN_recv_M3(W0,x,t,a,b)) ==> inj-event(UE_send_M3(W0,x,t,a,b)) is true.
  q6       3.40s   1109MB  inj-event(UE_recv_M4(W0,x,t,a,b)) ==> inj-event(DN_send_M4(W0,x,t,a,b)) is true.
  q7       0.64s    180MB  not attacker_p1(ID_CREDI[]) is true.
  q8       0.63s    180MB  not attacker_p1(ID_CREDR[]) is true.
  q9       0.63s    180MB  not attacker_p1(app_data_UE[]) is true.
  q10      0.67s    180MB  not attacker_p1(app_data_DN[]) is true.
  q11      0.67s    180MB  not attacker_p1(MSK_test[]) is true.
  q12      0.67s    180MB  not attacker_p1(EMSK_test[]) is true.
  q13      0.75s    178MB  event(DN_acc_M1(W0,kid,ct)) ==> event(UE_send_M1hdr(W0,kid,ct)) is true.
  q14      0.71s    181MB  event(DN_acc_inner(W0,h,p)) ==> h = p is true.
==================================================================
edhoc_m4v5_quantum.pv
  query     time  peakmem  result
  q1       0.73s    193MB  not event(UE_finish(W0,a,b)) is false.
  q2       0.73s    201MB  not event(DN_finish(W0,a,b)) is false.
  q3       0.69s    180MB  not event(UE_send_M1(W0,m)) is false.
  q4       1.76s    526MB  inj-event(UE_recv_M2(W0,x,t,a,b)) ==> inj-event(DN_send_M2(W0,x,t,a,b)) is true.
  q5       2.16s    650MB  inj-event(DN_recv_M3(W0,x,t,a,b)) ==> inj-event(UE_send_M3(W0,x,t,a,b)) is true.
  q6       3.37s   1089MB  inj-event(UE_recv_M4(W0,x,t,a,b)) ==> inj-event(DN_send_M4(W0,x,t,a,b)) is true.
  q7       0.65s    182MB  not attacker_p1(ID_CREDI[]) is true.
  q8       0.70s    182MB  not attacker_p1(ID_CREDR[]) is true.
  q9       0.67s    182MB  not attacker_p1(app_data_UE[]) is true.
  q10      0.64s    182MB  not attacker_p1(app_data_DN[]) is true.
  q11      0.66s    182MB  not attacker_p1(MSK_test[]) is true.
  q12      0.66s    182MB  not attacker_p1(EMSK_test[]) is true.
  q13      0.64s    178MB  event(DN_acc_M1(W0,kid,ct_2)) ==> event(UE_send_M1hdr(W0,kid,ct_2)) is true.
  q14      0.58s    181MB  event(DN_acc_inner(W0,h,p_2)) ==> h = p_2 is true.
==================================================================
edhoc_m4v5_kci.pv
  query     time  peakmem  result
  q1       2.53s    381MB  inj-event(UE_recv_M2(W1,x,t,a,b)) ==> inj-event(DN_send_M2(W1,x,t,a,b)) is true.
  q2       3.78s    627MB  inj-event(UE_recv_M4(W1,x,t,a,b)) ==> inj-event(DN_send_M4(W1,x,t,a,b)) is true.
  q3       2.39s    392MB  inj-event(DN_recv_M3(W2,x,t,a,b)) ==> inj-event(UE_send_M3(W2,x,t,a,b)) is true.
==================================================================
edhoc_m4v5_pcs.pv
  query     time  peakmem  result
  q1       0.27s    101MB  not event(UE_finish(W2,a,b)) is false.
  q2       0.37s    116MB  inj-event(UE_recv_M2(W2,x,t,a,b)) ==> inj-event(DN_send_M2(W2,x,t,a,b)) is true.
  q3       0.47s    134MB  inj-event(DN_recv_M3(W2,x,t,a,b)) ==> inj-event(UE_send_M3(W2,x,t,a,b)) is true.
  q4       0.66s    207MB  inj-event(UE_recv_M4(W2,x,t,a,b)) ==> inj-event(DN_send_M4(W2,x,t,a,b)) is true.
  q5       0.22s     73MB  not attacker(MSK_test2[]) is true.
  q6       0.23s     73MB  not attacker(EMSK_test2[]) is true.
==================================================================
edhoc_m4v5_fs_noerase.pv
  query     time  peakmem  result
  q1       0.42s     70MB  not event(UE_finish(W0,a,b)) is false.
  q2       0.43s     79MB  not event(DN_finish(W0,a,b)) is false.
  q3       0.38s     64MB  not event(UE_send_M1(W0,m)) is false.
  q4       0.37s     68MB  not attacker_p1(ID_CREDI[]) is false.
  q5       0.38s     68MB  not attacker_p1(ID_CREDR[]) is false.
  q6       0.56s     76MB  not attacker_p1(app_data_UE[]) is false.
  q7       0.41s     73MB  not attacker_p1(app_data_DN[]) is false.
  q8       0.45s     77MB  not attacker_p1(MSK_test[]) is false.
  q9       0.41s     73MB  not attacker_p1(EMSK_test[]) is false.
  q10      0.39s     64MB  event(DN_acc_M1(W0,kid,ct)) ==> event(UE_send_M1hdr(W0,kid,ct)) is true.
  q11      0.37s     63MB  event(DN_acc_inner(W0,h,p)) ==> h = p is true.
==================================================================
edhoc_m4v5_recovery.pv
  query     time  peakmem  result
  q1       1.41s    303MB  not event(UE_finish(W0,a,b)) is false.
  q2       1.45s    308MB  not event(DN_finish(W0,a,b)) is false.
  q3       1.39s    297MB  not event(UE_send_M1(W0,m)) is false.
  q4       1.36s    286MB  not attacker_p1(ID_CREDI[]) is true.
  q5       1.36s    286MB  not attacker_p1(app_data_DN[]) is true.
  q6       1.38s    284MB  not attacker_p1(MSK_test[]) is true.
  q7       1.26s    284MB  not attacker_p1(EMSK_test[]) is true.
  q8       2.56s    333MB  event(DN_acc_M1(W0,kid,ct)) ==> event(UE_send_M1hdr(W0,kid,ct)) is true.
  q9       1.39s    283MB  event(DN_acc_inner(W0,h,p)) ==> h = p is true.
==================================================================
edhoc_m4v5_nextkey.pv
  query     time  peakmem  result
  q1       0.69s     18MB  not attacker(s_NpkA[]) is true.
  q2       0.42s     18MB  not attacker(s_NpkB[]) is true.
==================================================================
edhoc_m4v5_noid_classical.pv
  query     time  peakmem  result
  q1       0.69s    205MB  event(DN_acc_M1(W0,kid,ct)) ==> event(UE_send_M1hdr(W0,kid,ct)) is false.
==================================================================
edhoc_m4v5_t7_classical.pv
  query     time  peakmem  result
  q1       0.73s    190MB  event(DN_acc_inner(W0,h,p)) ==> h = p is true.
DONE
```

Model unlinkability tidak dijalankan untuk v5; status terakhir tetap NOT CONCLUDED untuk v4 (bagian 7c), jadi tidak ada klaim unlinkability.

### Harness E2E (v5 dan EAP-TLS Hybrid PQC, satu sesi, 2 run × 100)

| Method | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) | UE lokal mean (ms) | Tunggu balasan mean (ms) |
|---|---|---|---|---|---|---|---|
| Proposal v5 | 200 | 6.545 | 6.438 | 7.399 | [6.392, 6.524] | 1.220 | 5.325 |
| EAP-TLS Hybrid PQC | 200 | 8.992 | 8.936 | 10.309 | [8.857, 9.021] | 0.672 | 8.320 |

- Selisih median EAP-TLS Hybrid PQC − v5: **2.498 ms**, 95% CI [2.392, 2.597]; mean 2.447 ms.
- Sebagai pembanding saja, v4b di `e2e-handshake-v4b.csv`: median 6.284 ms, sesi lain. Selisih antarsesi bukan biaya protokol (bagian 8).

### Ablasi storage (`storage_ablation.sh 6 100 flush`, 4 konfigurasi, 6 ronde × 100)

| Konfigurasi | UE | DN-AAA | N | Mean (ms) | Median (ms) | 95% CI median (ms) |
|---|---|---|---|---|---|---|
| durable | disk | disk | 600 | 6.546 | 6.466 | [6.418, 6.499] |
| ue_tmpfs | tmpfs | disk | 600 | 6.078 | 5.987 | [5.953, 6.034] |
| dn_tmpfs | disk | tmpfs | 600 | 5.910 | 5.812 | [5.771, 5.863] |
| tmpfs | tmpfs | tmpfs | 600 | 5.521 | 5.404 | [5.365, 5.450] |

| Biaya | Selisih median | Nilai (ms) | 95% CI (ms) |
|---|---|---|---|
| Flush UE saja | dn_tmpfs − tmpfs | 0.408 | [0.349, 0.474] |
| Flush DN-AAA saja | ue_tmpfs − tmpfs | 0.583 | [0.522, 0.638] |
| Flush UE, di atas flush DN-AAA | durable − ue_tmpfs | 0.479 | [0.412, 0.527] |
| Flush DN-AAA, di atas flush UE | durable − dn_tmpfs | 0.654 | [0.584, 0.704] |
| Kedua flush | durable − tmpfs | 1.062 | [0.997, 1.112] |

### Full stack v5 (A/B 3 × 100, `@edhoc.internet`)

- A: PASS 299/300, msk_match 299/299, rotated 299/299; B: PASS 300/300.
- **Satu sesi gagal di A (seri 3, iterasi 77), status timeout**, tidak ikut statistik. Log UE: `No response from RRC from UAC checks, considering access attempt is barred`, jadi UERANSIM menahan permintaan sebelum NAS dikirim dan belum ada Message1. Permintaan dikirim ulang saat T3580 habis (16 s) dan handshake-nya selesai normal; sesi berikutnya sukses. Ini perilaku simulator, bukan protokol. Di v4b tidak muncul (300/300).
- Ukuran / ronde: [('2424', '6097', '3756', '16', '15', '15')] (Message1..4 B, ronde NAS, RADIUS RT).

| Segmen (Tabel 6) | Kolom | N | Median (ms) | 95% CI | Mean (ms) | p95 (ms) |
|---|---|---|---|---|---|---|
| Added to PDU session establishment (A − B) | `t_pdu_ms` | 299 | 78.7 | [76.6, 80.0] | 79.9 | -- |
| Secondary authentication at the UE | `t_secauth_ms` | 299 | 77.1 | [76.3, 78.1] | 79.1 | 99.0 |
| 5G core transport (UE, gNB, AMF, SMF) | `t_core_ms` | 299 | 71.5 | [70.7, 72.9] | 73.7 | 90.5 |
| SMF ↔ UPF relay hop | `t_hop_smf_upf_ms` | 299 | 2.8 | [2.7, 2.8] | 2.8 | 3.8 |
| RADIUS processing in the UPF relay | `t_relay_proc_ms` | 299 | 0.9 | [0.8, 0.9] | 0.9 | 1.6 |
| DN-AAA (FreeRADIUS, from the UPF relay) | `t_aaa_ms` | 299 | 5.4 | [5.3, 5.5] | 5.5 | 7.4 |
| UE write of NEXT (before Message3) | `ue_store_next_ms` | 299 | 2.85 | [2.82, 2.87] | 2.29 | 3.56 |
| DN-AAA commit (before Message4) | `aaa_commit_ms` | 299 | 0.64 | [0.64, 0.65] | 0.69 | 0.92 |
| UE promotion (after Message4) | `ue_promote_ms` | 299 | 0.57 | [0.56, 0.59] | 0.67 | 1.21 |

#### Uji pemulihan v5

Relay UPF membuang sekali Message3 atau Message4; SMF timeout (2,5 s) lalu mengirim REJECT #29 tanpa EAP (UE tidak fallback). Sesi berikutnya diulang sampai Accept dengan EAP-Success (maks. 3).

| Kasus | N | Drop di UPF | Sesi drop: Reject #29 tanpa EAP | used_next | Sesi pemulihan pertama | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 dibuang | 10 | 10 | 10 | 10 | failure 10 | 10 | 10 | 2 | 10 | 10 | 1426.6 / 1426.4 |
| Message4 dibuang | 10 | 10 | 10 | 10 | success 10 | 0 | 0 | 1 | 10 | 10 | 104.2 / 93.3 |

- Sesi normal sesudahnya: 10/10 sukses. Desync: **0**; re-provisioning: **0**.
- `failure` = REJECT #29 berisi EAP-Failure (DN-AAA belum commit, NEXT ditolak), lalu fallback ke CUR dan PDU session berikutnya sukses. Waktu pulih Message3 memuat `reject_delay = 1` FreeRADIUS.

- Cek identitas (`v5-identity-check.txt`): RESULT: PASS (only the anonymous NAI appears)

### Ukuran (live dan model)

| Method | Message1–4 live (B) | Total (B) | Model (B) | Live = model | Dikirim UE (M1+M3) | Dikirim DN-AAA (M2+M4) | Fragmen EAP | Fragmen IP (model) | RT |
|---|---|---|---|---|---|---|---|---|---|
| Proposal v5 | 2424/6097/3756/16 | 12293 | 2424/6097/3756/16 | cocok | 6180 | 6113 | 3/7/4/1 (total 15) | 2/5/3/1 (total 11) | 15 |
| EAP-TLS Hybrid PQC | 1589/12600/10983/23 | 25195 | 1589/12600/10983/23 | cocok | 12572 | 12623 | 2/13/11/1 (total 27) | 2/9/8/1 (total 20) | 28 |

### Komputasi per fungsi

Harness yang sama dengan Figure 7 kiri: `crypto_bench` mengukur primitif lalu mengalikannya dengan jumlah operasi per peran; EAP-TLS Hybrid dengan `compute_tls_hybrid.py`, dari primitif yang sama.

| Method | Initiator (µs) | Responder (µs) | Total (µs) |
|---|---|---|---|
| Proposal v5 | 462.475 | 462.475 | 924.950 |
| EAP-TLS Hybrid PQC | 441.958 | 404.503 | 846.461 |

| Operasi method 4 (per peran, sama di kedua peran) | Jumlah | Waktu (µs) |
|---|---|---|
| Keygen (X25519/ML-KEM-768) | 3 | 72.859 |
| ScalarMult (X25519) | 2 | 46.731 |
| Encaps (ML-KEM-768) | 1 | 32.291 |
| Decaps (ML-KEM-768) | 1 | 40.139 |
| Signature (Ed25519/ML-DSA-44) | 1 | 213.689 |
| Verify (Ed25519/ML-DSA-44) | 1 | 56.766 |

- **Batas model ini:** hanya menghitung primitif, jadi jumlah operasinya sama di v4 dan v5. Beda hash dan AEAD Message1 tidak terlihat di sini; beda angka dengan v4b (492,320 µs) berasal dari pengukuran primitif sesi lain, EAP-TLS Hybrid juga bergeser (467,442 → 441.958 µs). Selisih v5 yang sebenarnya untuk Message1 ada di `m1-compute-variants.csv` (bagian 8).
- Pembanding yang menjalankan handshake v5 sungguhan dalam proses (`m4_inproc_bench`, N=2000, tanpa storage): initiator median 496.3 µs, responder median 491.9 µs.

### Tabel ringkas angka untuk paper

Semua nilai dibaca dari file sumber oleh `benchmark/v5_analyze.py`.

| Angka | Nilai | Sumber | Kolom |
|---|---|---|---|
| T1: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; lookup; 0.002; no | `tamper-v5.csv` | semua |
| T2: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; AEAD tag; 0.154; yes | `tamper-v5.csv` | semua |
| T3: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; AEAD tag; 0.193; yes | `tamper-v5.csv` | semua |
| T4: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; AEAD tag; 0.149; yes | `tamper-v5.csv` | semua |
| T5: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; lookup; 0.001; no | `tamper-v5.csv` | semua |
| T6: hasil; DN-AAA; median ms; Decaps | session 1: success 20/20; replay session: challenge 20/20; accepted (replay); accepted (session 1); 0.522; yes | `tamper-v5.csv` | semua |
| T7: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; inner KeyID check; 0.153; yes | `tamper-v5.csv` | semua |
| ProVerif v5: jumlah query, NOT CONCLUDED | 70, 0 | `symmetry-rev/proverif/results/SUMMARY_v5.txt` | result |
| Proposal v5: mean (ms) | 6.545 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 4 |
| Proposal v5: median (ms) | 6.438 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 4 |
| Proposal v5: p95 (ms) | 7.399 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 4 |
| Proposal v5: 95% CI median (ms) | [6.392, 6.524] | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 4 |
| Proposal v5: UE lokal, Figure 7 kanan (ms) | 1.220 | `e2e-handshake-v5-m4m6.csv` | initiator_ms, method 4 |
| Proposal v5: tunggu balasan, Figure 7 kanan (ms) | 5.325 | `e2e-handshake-v5-m4m6.csv` | responder_ms, method 4 |
| EAP-TLS Hybrid PQC: mean (ms) | 8.992 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: median (ms) | 8.936 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: p95 (ms) | 10.309 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: 95% CI median (ms) | [8.857, 9.021] | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: UE lokal, Figure 7 kanan (ms) | 0.672 | `e2e-handshake-v5-m4m6.csv` | initiator_ms, method 6 |
| EAP-TLS Hybrid PQC: tunggu balasan, Figure 7 kanan (ms) | 8.320 | `e2e-handshake-v5-m4m6.csv` | responder_ms, method 6 |
| EAP-TLS Hybrid PQC − v5: selisih median (ms) | 2.498 | `e2e-handshake-v5-m4m6.csv` | duration_ms |
| EAP-TLS Hybrid PQC − v5: 95% CI (ms) | [2.392, 2.597] | `e2e-handshake-v5-m4m6.csv` | duration_ms |
| Storage, Flush UE saja (ms) | 0.408 [0.349, 0.474] | `e2e-storage-flush-v5.csv` | duration_ms, dn_tmpfs − tmpfs |
| Storage, Flush DN-AAA saja (ms) | 0.583 [0.522, 0.638] | `e2e-storage-flush-v5.csv` | duration_ms, ue_tmpfs − tmpfs |
| Storage, Flush UE, di atas flush DN-AAA (ms) | 0.479 [0.412, 0.527] | `e2e-storage-flush-v5.csv` | duration_ms, durable − ue_tmpfs |
| Storage, Flush DN-AAA, di atas flush UE (ms) | 0.654 [0.584, 0.704] | `e2e-storage-flush-v5.csv` | duration_ms, durable − dn_tmpfs |
| Storage, Kedua flush (ms) | 1.062 [0.997, 1.112] | `e2e-storage-flush-v5.csv` | duration_ms, durable − tmpfs |
| Tabel 6, Added: median [CI] / mean (ms) | 78.7 [76.6, 80.0] / 79.9 | `fullstack-handshake-v5.csv` | t_pdu_ms, A − B |
| Tabel 6, Secondary authentication at the UE: median [CI] / mean / p95 (ms) | 77.1 [76.3, 78.1] / 79.1 / 99.0 | `fullstack-handshake-v5.csv` | t_secauth_ms, A |
| Tabel 6, 5G core transport (UE, gNB, AMF, SMF): median [CI] / mean / p95 (ms) | 71.5 [70.7, 72.9] / 73.7 / 90.5 | `fullstack-handshake-v5.csv` | t_core_ms, A |
| Tabel 6, SMF ↔ UPF relay hop: median [CI] / mean / p95 (ms) | 2.8 [2.7, 2.8] / 2.8 / 3.8 | `fullstack-handshake-v5.csv` | t_hop_smf_upf_ms, A |
| Tabel 6, RADIUS processing in the UPF relay: median [CI] / mean / p95 (ms) | 0.9 [0.8, 0.9] / 0.9 / 1.6 | `fullstack-handshake-v5.csv` | t_relay_proc_ms, A |
| Tabel 6, DN-AAA (FreeRADIUS, from the UPF relay): median [CI] / mean / p95 (ms) | 5.4 [5.3, 5.5] / 5.5 / 7.4 | `fullstack-handshake-v5.csv` | t_aaa_ms, A |
| Tabel 6, UE write of NEXT (before Message3): median [CI] / mean / p95 (ms) | 2.85 [2.82, 2.87] / 2.29 / 3.56 | `fullstack-handshake-v5.csv` | ue_store_next_ms, A |
| Tabel 6, DN-AAA commit (before Message4): median [CI] / mean / p95 (ms) | 0.64 [0.64, 0.65] / 0.69 / 0.92 | `fullstack-handshake-v5.csv` | aaa_commit_ms, A |
| Tabel 6, UE promotion (after Message4): median [CI] / mean / p95 (ms) | 0.57 [0.56, 0.59] / 0.67 / 1.21 | `fullstack-handshake-v5.csv` | ue_promote_ms, A |
| Pemulihan, Message3 dibuang: median / mean (ms) | 1426.4 / 1426.6 | `fullstack-recovery-v5.csv` | t_recovery_ms |
| Pemulihan, Message4 dibuang: median / mean (ms) | 93.3 / 104.2 | `fullstack-recovery-v5.csv` | t_recovery_ms |
| Pemulihan: desync, re-provisioning | 0, 0 | `fullstack-recovery-v5.csv` | recovered |
| Proposal v5: Message1–4 (B) | 2424/6097/3756/16 | `e2e-handshake-v5-m4m6.csv` | msg1..4_bytes |
| Proposal v5: total (B) | 12293 | `e2e-handshake-v5-m4m6.csv` | msg1..4_bytes |
| Proposal v5: dikirim UE, Message1+3 (B) | 6180 | `e2e-handshake-v5-m4m6.csv` | msg1_bytes + msg3_bytes |
| Proposal v5: dikirim DN-AAA/server, Message2+4 (B) | 6113 | `e2e-handshake-v5-m4m6.csv` | msg2_bytes + msg4_bytes |
| Proposal v5: fragmen EAP | 3/7/4/1 | `e2e-handshake-v5-m4m6.csv` | msg1..4_frags |
| Proposal v5: RT | 15 | `e2e-handshake-v5-m4m6.csv` | radius_round_trips |
| EAP-TLS Hybrid PQC: Message1–4 (B) | 1589/12600/10983/23 | `e2e-handshake-v5-m4m6.csv` | msg1..4_bytes |
| EAP-TLS Hybrid PQC: total (B) | 25195 | `e2e-handshake-v5-m4m6.csv` | msg1..4_bytes |
| EAP-TLS Hybrid PQC: dikirim UE, Message1+3 (B) | 12572 | `e2e-handshake-v5-m4m6.csv` | msg1_bytes + msg3_bytes |
| EAP-TLS Hybrid PQC: dikirim DN-AAA/server, Message2+4 (B) | 12623 | `e2e-handshake-v5-m4m6.csv` | msg2_bytes + msg4_bytes |
| EAP-TLS Hybrid PQC: fragmen EAP | 2/13/11/1 | `e2e-handshake-v5-m4m6.csv` | msg1..4_frags |
| EAP-TLS Hybrid PQC: RT | 28 | `e2e-handshake-v5-m4m6.csv` | radius_round_trips |
| Proposal v5: komputasi initiator / responder, Figure 7 kiri (µs) | 462.475 / 462.475 | `compute-v5/handshake-compute.csv` | initiator_compute_us, responder_compute_us |
| EAP-TLS Hybrid PQC: komputasi initiator / responder, Figure 7 kiri (µs) | 441.958 / 404.503 | `compute-v5/handshake-compute.csv` | initiator_compute_us, responder_compute_us |
| Proposal v5: handshake dalam proses, initiator / responder median (µs) | 496.3 / 491.9 | `m4-inprocess-compute-v5.csv` | initiator_median_us, responder_median_us |
