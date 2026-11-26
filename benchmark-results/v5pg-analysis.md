
## 10. Pra-generasi X-Wing KeyGen (v5-pregen)

Step 32. KeyGen kunci berikutnya dikeluarkan dari jalur kritis handshake sebagai pilihan implementasi; protokol, pesan, ukuran, dan model ProVerif tidak berubah (model tidak dijalankan ulang, dicatat di README ProVerif). Hanya proposal (v5) yang berubah. Kernel `7.0.0-38-generic`. Paper tidak diubah.

### Desain pool dan alasan keamanannya

- **Apa yang dipindah:** hanya KeyGen kunci berikutnya (Nsk_A/Npk_A di UE untuk EAD_1, Nsk_B/Npk_B di DN-AAA untuk EAD_2). Kunci ini tidak bergantung pada isi run, hanya acak segar yang dipakai sekali, jadi membuatnya lebih awal tidak mengubah pesan, ukuran, maupun model ProVerif (`new` di model sudah berarti kunci segar sekali pakai).
- **Opsi:** `xwing_next_keygen = pregen | inline` (radiusd, default `pregen`; UE `secondaryAuth.xwingNextKeygen` atau env `EDHOC_NEXT_KEYGEN`, default `pregen`); `xwing_pool_size` di DN-AAA (default 64, 0..1024). Proses yang tidak mengonfigurasi pool (tool, test) memakai inline.
- **Hanya di memori:** kunci pool belum berarti apa-apa bagi protokol sampai masuk NEXT (UE) atau commit (DN-AAA), jadi pool tidak ditulis ke disk dan dibuat ulang setiap start. Jalur durable tidak berubah: satu `fdatasync` per pihak.
- **Memori terkunci:** area pool di-`mlock` (`sodium_mlock`); status tercatat di log start (`locked memory`).
- **Sekali pakai:** kunci yang diambil disalin ke ctx lalu slot pool di-zeroize; tidak pernah dikembalikan. Run yang gagal menghapus ctx (termasuk Nsk) dan run berikutnya mengambil kunci baru.
- **Zeroize:** saat diambil, saat ctx dihapus, saat pool dikosongkan atau dikonfigurasi ulang, dan saat proses keluar (`atexit`, juga `mod_detach` di radiusd). Kunci pool tidak pernah ditulis ke log; log hanya berisi penghitung.
- **Ukuran:** UE satu kunci (satu sesi pada satu waktu); DN-AAA satu pool global, dilindungi mutex karena FreeRADIUS multithread. Kunci acak tidak terikat pada UE, jadi satu pool global aman.
- **Isi ulang:** thread `e4-keypool` (nice 19) membuat kunci tanpa memegang mutex dan hanya mengunci untuk push. UE: dibangunkan setelah Message1 dibangun (berjalan selama UE menunggu Message2) dan setelah promosi Message4. Spesifikasi step hanya menyebut "setelah promosi"; pemicu setelah Message1 ditambahkan karena run yang tidak sampai promosi (Message3/4 hilang, EAP-Failure) meninggalkan pool kosong untuk run berikutnya (lihat percobaan pertama full stack). DN-AAA: setelah commit, atau saat pengambilan membuat pool di bawah setengah.
- **Pool kosong:** fallback ke KeyGen inline (hasil tetap benar) dan `pool_miss` bertambah. UE mencatat `pool_miss` di baris `[E4T] ue_msg1`, DN-AAA di `[E4T] aaa_commit` dan di baris penutup radius.log.
- **Mode lama:** `inline` menjalankan kode yang sama dengan v5 step 31; transkrip identik byte per byte di bawah RNG deterministik (`edhoc4/inline_identity.sh`).
- **Tidak berubah:** write-ahead NEXT, commit, erase, recovery, indeks KeyID di memori; Message1–4 tetap 2424/6097/3756/16 B, 15 RT. EAP-TLS Classic/Hybrid dan EDHOC methods 0–3 tidak disentuh.

### Hasil test

| Test | Hasil |
|---|---|
| `edhoc4_xwing_kat` | PASS (3 vektor X-Wing) |
| `edhoc4_selftest` | PASS |
| `edhoc03_selftest` | PASS |
| `edhoc4_dbtest` | PASS |
| `edhoc4_pooltest` (dalam proses) | PASS, rincian di bawah |
| `edhoc4/inline_identity.sh` (inline vs 284e9402) | PASS (inline transcripts identical to 284e9402) |
| Test live `pool_tests.sh` | lihat tabel berikut |
| T1–T7 dengan pregen (`tamper_tests.sh 20 v5 v5pg`) | lihat tabel berikut |

`edhoc4_pooltest 1000 100` (`pooltest-v5pg.txt`; satu proses memegang kedua pihak, jadi UE dan DN-AAA berbagi satu pool):

```
1. 1000 sequential handshakes (pregen, pool 64): failed=0 dup Npk_A=0 dup Npk_B=0 dup across both=0 pool_miss=0
  [seq] mode=pregen size=64 n=64 locked=1 taken=2000 pool_miss=0 inline=0 refilled=2000 refill_cpu_per_key_us=57.9
2. Message2 dropped: run1 ok to Message2=1, Nsk_A zero in wiped ctx=1, taken pool slots zero=1, retry ok=1, retry Npk_A new=1
3. 100 parallel handshakes (pool 64, both parties take from it): failed=0 keys taken twice=0 taken=112 pool_miss=88
4. pool size 0: handshake ok=1, pool_miss +2 (fallback inline KeyGen)
5. restart: before ok=1, pool wiped=1, rebuilt n=4, after ok=1, new keys=1
6. inline: handshake ok=1, taken +0, inline KeyGen +2, pool size=0
pooltest: PASS
```

Kernel `7.0.0-38-generic`. Sumber: `benchmark/pool_tests.sh`, mentah di `benchmark-results/pool-tests-v5pg/`.
UE = `e2e_radius_bench` (pool satu kunci, diisi sebelum jam mulai); DN-AAA = radiusd dengan `xwing_pool_size` 64 kecuali disebut lain.
Penghitung DN-AAA dari baris yang ditulis `rlm_eap_edhoc` saat radiusd berhenti.

| Test | UE: sukses | UE: pool_miss | DN-AAA: mode, ukuran | DN-AAA: diambil / pool_miss / inline | Keunikan dan catatan | Hasil |
|---|---|---|---|---|---|---|
| 1000 handshake berurutan, pregen | 1000/1000 | 0 | pregen, 64 | 1000 / 0 / 0 | Npk_A 1000/1000 unik, Npk_B 1000/1000 unik, tidak ada Npk_A = Npk_B | PASS |
| Message2 dibuang, lalu run baru | 1/2 | 0 | pregen, 64 | 2 / 0 / 0 | run ulang memakai Npk_A baru; Nsk_A = 0 di ctx yang dihapus (UE); Message2 tidak pernah diproses, jadi tidak ada Npk_B | PASS |
| 100 UE paralel × 5 run, pregen 64 | 500/500 | 0 | pregen, 64 | 501 / 0 / 0 | 1000 kunci (Npk_A dan Npk_B), dipakai dua kali: 0; level pool terendah saat commit: 39 | PASS |
| `xwing_pool_size = 0` | 5/5 | 0 | pregen, 0 | 0 / 5 / 0 | setiap pengambilan jatuh ke KeyGen inline (5 pool_miss = jumlah run) | PASS |
| Restart radiusd | 3/3 sebelum, 3/3 sesudah | 0 | pregen, 64 | 3 / 0 / 0 (sesudah) | pool dibuat ulang saat start: 64 kunci dalam 3.9 ms | PASS |
| Mode inline (UE dan DN-AAA) | 5/5 | 0 | inline, 0 | 0 / 0 / 5 | ukuran Message1–4: 2424/6097/3756/16 B; pool tidak dipakai | PASS |

### Beban background DN-AAA (100 UE paralel)

| Ukuran | Nilai |
|---|---|
| Durasi uji (s) | 8.76 |
| CPU radiusd selama uji (s) | 20.68 |
| CPU thread isi ulang `e4-keypool` selama uji (s) | 0.23 |
| Porsi thread isi ulang dari CPU radiusd | 1.1 % |
| Kunci dibuat thread isi ulang | 501 |
| CPU per kunci, thread isi ulang (µs) | 264.4 |
| Pool pernah habis (pool_miss) | 0 |
| Level pool terendah saat commit | 39 dari 64 |

CPU per kunci di thread isi ulang lebih tinggi di bawah beban paralel (264.4 µs) daripada pada uji berurutan (89.6 µs). Penyebabnya tidak diukur terpisah; thread itu berjalan dengan nice 19 bersama thread radiusd lain. CPU ini dipakai di luar pemrosesan pesan, tetapi tetap memakai core yang sama dengan radiusd.

**Semua test: PASS**

T1–T7 pada v5 dengan `xwing_next_keygen = pregen` (20 kali per baris):

| test | manipulation | variant | result at the UE | DN-AAA step | DN-AAA median ms | Decaps run |
|---|---|---|---|---|---|---|
| T1 | KeyID_B header: 1 bit | v5 | eap-failure 20/20 | lookup | 0.002 | no |
| T2 | KeyID_B header: of another UE | v5 | eap-failure 20/20 | AEAD tag | 0.160 | yes |
| T3 | ct_B: 1 bit | v5 | eap-failure 20/20 | AEAD tag | 0.151 | yes |
| T4 | AEAD ciphertext: 1 bit | v5 | eap-failure 20/20 | AEAD tag | 0.153 | yes |
| T5 | old Message1 replayed | v5 | eap-failure 20/20 | lookup | 0.001 | no |
| T6 | current Message1 in a second EAP session | v5 | session 1: success 20/20; replay session: challenge 20/20 | accepted (replay); accepted (session 1) | 0.427 | yes |
| T7 | KeyID_B in PT1 != header | v5 | eap-failure 20/20 | inner KeyID check | 0.151 | yes |

### Harness E2E (v5-pregen, v5-inline, EAP-TLS Hybrid PQC; satu sesi, 2 run × (20 + 100), bergantian)

| Metode | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) | UE lokal mean / median (ms) | Tunggu balasan mean / median (ms) |
|---|---|---|---|---|---|---|---|
| v5-pregen | 200 | 8.518 | 6.916 | 15.926 | [6.610, 7.221] | 1.447 / 1.252 | 7.071 / 5.639 |
| v5-inline | 200 | 7.842 | 7.293 | 11.264 | [7.209, 7.470] | 1.444 / 1.340 | 6.398 / 5.942 |
| EAP-TLS Hybrid PQC | 200 | 11.328 | 9.998 | 18.073 | [9.784, 10.345] | 0.867 / 0.806 | 10.461 / 9.210 |

- Selisih median v5-pregen − v5-inline: **-0.377 ms**, 95% CI [-0.715, -0.063]; selisih mean 0.676 ms.
- Selisih median EAP-TLS Hybrid PQC − v5-pregen: **3.082 ms**, 95% CI [2.706, 3.530]; selisih mean 2.810 ms.
- UE lokal (median): inline − pregen = 0.087 ms; KeyGen UE yang dipindah ≈ 0,05 ms (bagian komputasi).
- **Percobaan pertama** (skrip yang sama, 10:38, `e2e-handshake-v5pg-attempt1.csv`): median pregen / inline / TLS = 6.967 / 7.159 / 10.877 ms; pregen − inline -0.192 [-0.354, -0.003], TLS − pregen 3.909 [3.547, 4.309]. Saya menjalankan ulang karena seluruh sesi lebih lambat dari step 31 (v5 6.438, TLS 8.936 ms), termasuk EAP-TLS yang tidak berubah, dengan outlier sampai puluhan ms. Percobaan kedua (tabel di atas) sama berisiknya; guest idle (vmstat: idle 98–100 %, steal 0), jadi sumbernya di host VM. Kedua percobaan disimpan.
- **Bacaan:** efek pregen yang diharapkan di jalur kritis ≈ 2 × 0,05 ms (satu KeyGen di UE, satu di DN-AAA). Itu jauh di bawah kebisingan sesi ini, jadi harness E2E tidak bisa memisahkannya; yang terlihat jelas hanya di pengukuran komputasi.

### Komputasi per fungsi

Harness Figure 7 kiri (`crypto_bench` + `compute_tls_hybrid.py`, satu sesi primitif baru di `compute-v5pg/`): v5-inline = method 4 seperti dihitung `crypto_bench` (KeyGen kunci berikutnya di dalam handshake); v5-pregen = v5-inline dikurangi satu X-Wing KeyGen per peran (Keygen_MLKEM768 + Keygen_X25519, mean, sama seperti model). `compute_v5pg.py`.

| Bar | Initiator (µs) | Responder (µs) | Total (µs) |
|---|---|---|---|
| v5-inline | 484.917 | 484.917 | 969.834 |
| v5-pregen | 430.501 | 430.501 | 861.002 |
| KeyGen yang dipindah (per peran) | 54.416 | 54.416 | 108.832 |
| EAP-TLS Hybrid PQC | 465.472 | 427.426 | 892.898 |

- X-Wing KeyGen per peran dari primitif yang sama: mean 54.416 µs, median 49.081 µs (Keygen_MLKEM768 + Keygen_X25519).

Handshake v5 sungguhan dalam proses (`m4_inproc_bench`, 3 ronde × 2000 per mode, bergantian, tanpa storage; pregen: pool 64 diisi penuh di antara handshake, di luar jam). Nilai = rata-rata median per ronde.

| Mode | Initiator median (µs) | Responder median (µs) | Total mean (µs) | pool_miss per ronde |
|---|---|---|---|---|
| v5-inline | 517.3 | 515.4 | 1134.8 | -- |
| v5-pregen | 459.7 | 459.8 | 1017.3 | 0, 0, 0 |

- Selisih inline − pregen: initiator 57.6 µs, responder 55.6 µs, sesuai satu X-Wing KeyGen per pihak.
- Biaya isi ulang per kunci (satu X-Wing KeyGen ke pool, di luar handshake): median 51.5 µs, mean 57.3 µs (dalam proses).
- Di radiusd live, CPU thread isi ulang (nice 19) per kunci: 89.6 µs pada 1000 handshake berurutan (1000 kunci), 264.4 µs saat 100 UE paralel (501 kunci). Ini waktu CPU thread itu, diukur dengan `CLOCK_THREAD_CPUTIME_ID`.

### Full stack v5-pregen (A/B 3 × 100, `@edhoc.internet`, nr-ue dan radiusd pregen)

- A: PASS 300/300, msk_match 300/300, rotated 300/300; B: PASS 300/300.
- pool_miss: UE maks 0 dari 379 baris `ue_msg1` (penghitung kumulatif per proses nr-ue); DN-AAA maks 0 dari 672 baris `aaa_commit`, level pool terendah saat commit 62.
- **Percobaan pertama full stack** (`fullstack-*-v5pg-attempt1.csv`, `logs-fullstack-v5pg-*-attempt1/`): A 300/300, B 300/300, tetapi pool_miss UE = 20 di uji pemulihan dan 1 di capture sampel (0 di seri A). Penyebab: UE hanya mengisi ulang setelah promosi, jadi run yang tidak sampai promosi meninggalkan pool kosong dan run berikutnya memakai KeyGen inline (hasil tetap benar). Setelah UE juga mengisi ulang setelah Message1, seluruh full stack dijalankan ulang; angka di atas dan di bawah berasal dari run ulang itu.
- Ukuran / ronde: [('2424', '6097', '3756', '16', '15', '15')] (Message1..4 B, ronde NAS, RADIUS RT).

| Segmen (Tabel 6) | Kolom | N | Median (ms) | 95% CI | Mean (ms) | p95 (ms) |
|---|---|---|---|---|---|---|
| Added to PDU session establishment (A − B) | `t_pdu_ms` | 300 | 85.2 | [83.3, 87.7] | 93.7 | -- |
| Secondary authentication at the UE | `t_secauth_ms` | 300 | 85.1 | [83.5, 86.9] | 95.8 | 151.6 |
| 5G core transport (UE, gNB, AMF, SMF) | `t_core_ms` | 300 | 78.2 | [76.6, 80.2] | 88.0 | 142.0 |
| SMF ↔ UPF relay hop | `t_hop_smf_upf_ms` | 300 | 3.3 | [3.3, 3.4] | 4.2 | 9.1 |
| RADIUS processing in the UPF relay | `t_relay_proc_ms` | 300 | 1.0 | [0.9, 1.0] | 1.3 | 3.0 |
| DN-AAA (FreeRADIUS, from the UPF relay) | `t_aaa_ms` | 300 | 6.6 | [6.4, 6.9] | 7.8 | 13.9 |
| UE write of NEXT (before Message3) | `ue_store_next_ms` | 300 | 1.16 | [0.95, 1.68] | 1.85 | 3.65 |
| DN-AAA commit (before Message4) | `aaa_commit_ms` | 300 | 0.71 | [0.69, 0.72] | 0.95 | 1.93 |
| UE promotion (after Message4) | `ue_promote_ms` | 300 | 0.64 | [0.62, 0.65] | 0.92 | 2.32 |

- DN-AAA (`t_aaa_ms`) pregen − v5 step 31: 1.25 ms [1.01, 1.52], sesi berbeda.

#### Uji pemulihan v5-pregen

Relay UPF membuang sekali Message3 atau Message4; SMF timeout (2,5 s) lalu mengirim REJECT #29 tanpa EAP (UE tidak fallback). Sesi berikutnya diulang sampai Accept dengan EAP-Success (maks. 3).

| Kasus | N | Drop di UPF | Sesi drop: Reject #29 tanpa EAP | used_next | Sesi pemulihan pertama | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 dibuang | 10 | 10 | 10 | 10 | failure 10 | 10 | 10 | 2 | 10 | 10 | 1424.3 / 1424.9 |
| Message4 dibuang | 10 | 10 | 10 | 10 | success 10 | 0 | 0 | 1 | 10 | 10 | 104.7 / 101.6 |

- Sesi normal sesudahnya: 10/10 sukses. Desync: **0**; re-provisioning: **0**.
- `failure` = REJECT #29 berisi EAP-Failure (DN-AAA belum commit, NEXT ditolak), lalu fallback ke CUR dan PDU session berikutnya sukses. Waktu pulih Message3 memuat `reject_delay = 1` FreeRADIUS.

- Cek identitas (`v5pg-identity-check.txt`): RESULT: PASS (only the anonymous NAI appears)

### Ukuran (tidak berubah)

| Mode | Message1–4 (B), RT, semua run |
|---|---|
| v5-pregen | 2424/6097/3756/16, RT 15 |
| v5-inline | 2424/6097/3756/16, RT 15 |

### Beban background DN-AAA dan `pool_miss`

| Ukuran | Nilai |
|---|---|
| Durasi uji (s) | 8.76 |
| CPU radiusd selama uji (s) | 20.68 |
| CPU thread isi ulang `e4-keypool` selama uji (s) | 0.23 |
| Porsi thread isi ulang dari CPU radiusd | 1.1 % |
| Kunci dibuat thread isi ulang | 501 |
| CPU per kunci, thread isi ulang (µs) | 264.4 |
| Pool pernah habis (pool_miss) | 0 |
| Level pool terendah saat commit | 39 dari 64 |

CPU per kunci di thread isi ulang lebih tinggi di bawah beban paralel (264.4 µs) daripada pada uji berurutan (89.6 µs). Penyebabnya tidak diukur terpisah; thread itu berjalan dengan nice 19 bersama thread radiusd lain. CPU ini dipakai di luar pemrosesan pesan, tetapi tetap memakai core yang sama dengan radiusd.

### Tabel ringkas angka untuk paper (v5-pregen)

Semua nilai dibaca dari file sumber oleh `benchmark/v5pg_analyze.py`.

| Angka | Nilai | Sumber | Kolom |
|---|---|---|---|
| Test pool: 1000 handshake berurutan, Npk_A / Npk_B unik, pool_miss UE / DN-AAA | 1000/1000, 1000/1000, 0 / 0 | `pool-tests-v5pg/seq.keys, seq.ue, seq.pool` | fingerprint Npk_A, Npk_B; pool_miss |
| Test pool: 100 UE paralel × 5, kunci dipakai dua kali, pool_miss DN-AAA | 0, 0 | `pool-tests-v5pg/par-*.keys, par.pool` | fingerprint; pool_miss |
| v5-pregen: mean / median / p95 (ms) | 8.518 / 6.916 / 15.926 | `e2e-handshake-v5pg.csv` | duration_ms, method 4, label pregen-run* |
| v5-pregen: 95% CI median (ms) | [6.610, 7.221] | `e2e-handshake-v5pg.csv` | duration_ms, method 4, label pregen-run* |
| v5-pregen: UE lokal mean (ms) | 1.447 | `e2e-handshake-v5pg.csv` | initiator_ms, method 4, label pregen-run* |
| v5-pregen: tunggu balasan mean (ms) | 7.071 | `e2e-handshake-v5pg.csv` | responder_ms, method 4, label pregen-run* |
| v5-inline: mean / median / p95 (ms) | 7.842 / 7.293 / 11.264 | `e2e-handshake-v5pg.csv` | duration_ms, method 4, label inline-run* |
| v5-inline: 95% CI median (ms) | [7.209, 7.470] | `e2e-handshake-v5pg.csv` | duration_ms, method 4, label inline-run* |
| v5-inline: UE lokal mean (ms) | 1.444 | `e2e-handshake-v5pg.csv` | initiator_ms, method 4, label inline-run* |
| v5-inline: tunggu balasan mean (ms) | 6.398 | `e2e-handshake-v5pg.csv` | responder_ms, method 4, label inline-run* |
| EAP-TLS Hybrid PQC: mean / median / p95 (ms) | 11.328 / 9.998 / 18.073 | `e2e-handshake-v5pg.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: 95% CI median (ms) | [9.784, 10.345] | `e2e-handshake-v5pg.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: UE lokal mean (ms) | 0.867 | `e2e-handshake-v5pg.csv` | initiator_ms, method 6 |
| EAP-TLS Hybrid PQC: tunggu balasan mean (ms) | 10.461 | `e2e-handshake-v5pg.csv` | responder_ms, method 6 |
| v5-pregen − v5-inline: selisih median [95% CI] (ms) | -0.377 [-0.715, -0.063] | `e2e-handshake-v5pg.csv` | duration_ms |
| EAP-TLS Hybrid PQC − v5-pregen: selisih median [95% CI] (ms) | 3.082 [2.706, 3.530] | `e2e-handshake-v5pg.csv` | duration_ms |
| Figure 7 kiri, v5-inline: initiator / responder (µs) | 484.917 / 484.917 | `compute-v5pg/handshake-compute-v5pg.csv` | initiator_compute_us, responder_compute_us |
| Figure 7 kiri, v5-pregen: initiator / responder (µs) | 430.501 / 430.501 | `compute-v5pg/handshake-compute-v5pg.csv` | initiator_compute_us, responder_compute_us |
| Figure 7 kiri, KeyGen yang dipindah (per peran): initiator / responder (µs) | 54.416 / 54.416 | `compute-v5pg/handshake-compute-v5pg.csv` | initiator_compute_us, responder_compute_us |
| Figure 7 kiri, EAP-TLS Hybrid PQC: initiator / responder (µs) | 465.472 / 427.426 | `compute-v5pg/handshake-compute-v5pg.csv` | initiator_compute_us, responder_compute_us |
| KeyGen yang dipindah per pihak, median primitif (µs) | 49.081 | `compute-v5pg/crypto-primitives.csv` | median_ns, Keygen_MLKEM768 + Keygen_X25519 |
| Dalam proses, v5-inline: initiator / responder median (µs) | 517.3 / 515.4 | `m4-inprocess-compute-v5pg.csv` | initiator_median_us, responder_median_us, label inline-r* |
| Dalam proses, v5-pregen: initiator / responder median (µs) | 459.7 / 459.8 | `m4-inprocess-compute-v5pg.csv` | initiator_median_us, responder_median_us, label pregen-r* |
| Dalam proses, inline − pregen: initiator / responder (µs) | 57.6 / 55.6 | `m4-inprocess-compute-v5pg.csv` | initiator_median_us, responder_median_us |
| Isi ulang per kunci, dalam proses: median / mean (µs) | 51.5 / 57.3 | `m4-inprocess-compute-v5pg.csv` | refill_median_us_per_key, refill_mean_us_per_key |
| Isi ulang per kunci, thread radiusd live: berurutan / 100 UE paralel (µs CPU) | 89.6 / 264.4 | `pool-tests-v5pg/seq.pool, par.pool` | refill CPU us/key |
| Full stack: sukses A / B | 300/300, 300/300 | `fullstack-handshake-v5pg.csv` | status |
| Full stack: pool_miss UE / DN-AAA | 0 / 0 | `logs-fullstack-v5pg-20261126-105441/{*/ue.log, aaa-e4t.txt}` | pool_miss di [E4T] ue_msg1 / aaa_commit |
| Tabel 6 (pregen), Added: median [CI] / mean (ms) | 85.2 [83.3, 87.7] / 93.7 | `fullstack-handshake-v5pg.csv` | t_pdu_ms, A − B |
| Tabel 6 (pregen), Secondary authentication at the UE: median [CI] / mean / p95 (ms) | 85.1 [83.5, 86.9] / 95.8 / 151.6 | `fullstack-handshake-v5pg.csv` | t_secauth_ms, A |
| Tabel 6 (pregen), 5G core transport (UE, gNB, AMF, SMF): median [CI] / mean / p95 (ms) | 78.2 [76.6, 80.2] / 88.0 / 142.0 | `fullstack-handshake-v5pg.csv` | t_core_ms, A |
| Tabel 6 (pregen), SMF ↔ UPF relay hop: median [CI] / mean / p95 (ms) | 3.3 [3.3, 3.4] / 4.2 / 9.1 | `fullstack-handshake-v5pg.csv` | t_hop_smf_upf_ms, A |
| Tabel 6 (pregen), RADIUS processing in the UPF relay: median [CI] / mean / p95 (ms) | 1.0 [0.9, 1.0] / 1.3 / 3.0 | `fullstack-handshake-v5pg.csv` | t_relay_proc_ms, A |
| Tabel 6 (pregen), DN-AAA (FreeRADIUS, from the UPF relay): median [CI] / mean / p95 (ms) | 6.6 [6.4, 6.9] / 7.8 / 13.9 | `fullstack-handshake-v5pg.csv` | t_aaa_ms, A |
| Tabel 6 (pregen), UE write of NEXT (before Message3): median [CI] / mean / p95 (ms) | 1.16 [0.95, 1.68] / 1.85 / 3.65 | `fullstack-handshake-v5pg.csv` | ue_store_next_ms, A |
| Tabel 6 (pregen), DN-AAA commit (before Message4): median [CI] / mean / p95 (ms) | 0.71 [0.69, 0.72] / 0.95 / 1.93 | `fullstack-handshake-v5pg.csv` | aaa_commit_ms, A |
| Tabel 6 (pregen), UE promotion (after Message4): median [CI] / mean / p95 (ms) | 0.64 [0.62, 0.65] / 0.92 / 2.32 | `fullstack-handshake-v5pg.csv` | ue_promote_ms, A |
| Pemulihan (pregen), Message3 dibuang: median / mean (ms) | 1424.9 / 1424.3 | `fullstack-recovery-v5pg.csv` | t_recovery_ms |
| Pemulihan (pregen), Message4 dibuang: median / mean (ms) | 101.6 / 104.7 | `fullstack-recovery-v5pg.csv` | t_recovery_ms |
| Pemulihan (pregen): desync, re-provisioning | 0, 0 | `fullstack-recovery-v5pg.csv` | recovered |
| Ukuran v5-pregen dan v5-inline: Message1–4 (B), RT | 2424/6097/3756/16, 15 (sama dengan v5) | `e2e-handshake-v5pg.csv` | msg1..4_bytes, radius_round_trips |
| Beban background DN-AAA, 100 UE paralel: CPU thread isi ulang / porsi dari radiusd; pool_miss | 0.23 s / 1.1 %; 0 | `pool-tests-v5pg/par.cpu, par.pool` | refill_thread_cpu_ticks, radiusd_cpu_ticks; pool_miss |
