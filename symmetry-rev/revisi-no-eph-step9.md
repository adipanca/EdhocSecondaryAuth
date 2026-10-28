# revisi-no-eph-step9.md: rotasi ikut dihitung, tabel operasi per method, uji ulang

## Tujuan

1. Pembuatan kunci rotasi (Nsk/Npk) **dihitung di dalam handshake** untuk proposal, di model komputasi maupun di run live. Precompute dan pool tetap ada, tapi hanya sebagai opsi dan ablation.
2. Op count Method 1–3 dikoreksi. Model lama kurang satu DH per autentikasi static-DH: DH itu dihitung di sisi pemilik kunci statis, tetapi lawannya juga melakukan satu DH dengan kunci ephemeral-nya. Kode `edhoc03.c` sudah benar:
   - G_RX: `crypto_scalarmult` di responder (baris 336) **dan** di initiator (baris 432);
   - G_IY: di initiator (baris 470) **dan** di responder (baris 545).
   Yang salah hanya model di `crypto_bench.c`.
3. Semua pengukuran live diulang dalam satu sesi VM yang sama untuk ketujuh method.
4. Paper sudah saya siapkan di `Symmetry_EAP-EDHOC_overleaf_step9-draft.zip`: dua tabel baru, teks dengan rotasi inline, dan klaim perbandingan yang lebih hati-hati. Claude Code hanya perlu memperbarui angka yang berasal dari uji ulang.

## 1. Model komputasi

**Jangan** jalankan ulang micro-benchmark primitif. `crypto-primitives.csv` dan Tabel 5 di paper tetap. Buat ulang breakdown dari CSV yang ada, dengan cara yang sama seperti `compute_tls_hybrid.py`: tambahkan opsi `--from-csv` di `crypto_bench.c` atau skrip Python kecil.

Op count per pihak, ditulis Initiator / Responder:

| Method | X25519 keygen | X25519 DH | ML-KEM keygen | Encaps | Decaps | Sign | Verify |
|---|---|---|---|---|---|---|---|
| 0 SIG/SIG | 1/1 | 1/1 | – | – | – | 1/1 | 1/1 |
| 1 SIG/STAT | 1/1 | **2/2** | – | – | – | 1/0 | 0/1 |
| 2 STAT/SIG | 1/1 | **2/2** | – | – | – | 0/1 | 1/0 |
| 3 STAT/STAT | 1/1 | **3/3** | – | – | – | 0/0 | 0/0 |
| 4 Proposal | **2/2** (1 eph. di Encaps + 1 rotasi) | 2/2 | **1/1** (rotasi) | 1/1 | 1/1 | 1/1 | 1/1 |
| 5 EAP-TLS Classic | 1/1 | 1/1 | – | – | – | 1/1 | 2/2 |
| 6 EAP-TLS Hybrid | 1/1 | 1/1 | 1/0 | 0/1 | 1/0 | 1/1 | 2/2 |

Hasil `handshake-compute.csv` yang diharapkan (µs):

| Method | Initiator | Responder | Total |
|---|---:|---:|---:|
| 0 | 91.207 | 91.207 | 182.415 |
| 1 | 86.932 | 105.301 | 192.233 |
| 2 | 105.301 | 86.932 | 192.233 |
| 3 | 101.026 | 101.026 | 202.052 |
| 4 | 492.320 | 492.320 | 984.640 |
| 5 | 120.646 | 120.646 | 241.292 |
| 6 | 467.442 | 426.907 | 894.349 |

Kalau hasilnya berbeda, jangan diubah agar cocok. Laporkan selisihnya.

## 2. Implementasi: rotasi inline sebagai default

- UE membuat (Nsk_A, Npk_A) saat menyusun Message3.
- DN-AAA membuat (Nsk_B, Npk_B) setelah Message3 terverifikasi, sebelum commit dan sebelum Message4.
- Pool dan precompute UE setelah commit tetap ada, tapi opt-in dan **default off**, misalnya env `EDHOC4_ROTATION_POOL=1` atau opsi modul `rotation_pool = no`.
- Di semua run utama, log harus menunjukkan `ead3_keys_inline` sama dengan jumlah handshake.
- `edhoc4_selftest`, `edhoc4_dbtest`, `edhoc4_xwing_kat`, dan `edhoc03_selftest` harus tetap lolos. Build ulang UERANSIM dan modul FreeRADIUS.

## 3. Uji ulang

Semua langkah dijalankan di sesi VM yang sama dan dengan default inline:

1. `m4_inproc_compare.sh`, 5 × 2000 handshake. Angka utama adalah inline; perkiraan saya sekitar 1.12 ms.
2. E2E: 2 run × 100 handshake × 7 method, masing-masing dengan 20 warm-up. Gabungkan jadi N=200 per method seperti sebelumnya.
3. Loss: 0, 1, 5, 10, 20, dan 30%, 120 percobaan per sel, ketujuh method.
4. `storage_ablation.sh` (6 ronde bergantian durable vs tmpfs) dengan rotasi inline.
5. `rtt_projection.py`.
6. Untuk setiap tingkat loss, pasangan hybrid (method 4 vs 6): Wilson 95% untuk kedua method dan uji eksak Fisher dua sisi (`scipy.stats.fisher_exact`).
7. Data `pool_ablation` lama boleh tetap dipakai sebagai ablation. Paper menyebutnya sebagai "optional deployment optimisation".

## 4. Notebook dan gambar

Pakai `EAP_Edhoc_Secondary_Authentication_v2.ipynb` dari lampiran. `compute_initiator` dan `compute_responder` di dalamnya sudah berisi angka baru. Lalu:

- isi `e2e_initiator`, `e2e_responder`, dan data loss dengan hasil uji ulang;
- buat ulang `img_handshake_computation_grouped.png`, keempat gambar `img_combined_*`, dan `img_D_baseline_comparison.png`;
- perbaiki judul `img_A2_compute_breakdown.png` yang terpotong di kanan (perpendek judul atau pakai `bbox_inches='tight'`).

## 5. Paper

Salin `manuscript.tex` dan gambar dari zip lampiran ke `symmetry-rev/paper/`.

**Sudah final, jangan diubah:**
- Tabel 6 (operasi per method) dan Tabel 7 (komputasi per fungsi);
- teks komputasi 0.985 / 0.492 / 0.894 / 0.241 / 0.182–0.202, "4.9–5.4×", dan "3.7×";
- penjelasan selisih 0.094 + 0.116 − 0.119 ms.

**Angka yang harus diperbarui dari uji ulang:**

1. §Performance: in-process "$1.119$~ms" dan "$0.048$~ms".
2. Paragraf live:
   - jumlah iterasi;
   - mean dan median proposal;
   - rentang mean dan median Method 0–3;
   - mean dan median EAP-TLS Classic dan Hybrid;
   - commit UE "0.605 ms";
   - storage ablation "5.789 / 5.107 / 0.68 [0.56, 0.77]".
3. Tabel RTT (`tab:rtt-projection`) dan kalimat "ratio grows from 1.7 … to 2.0 … (146 vs 290 ms)".
4. Paragraf pasangan classic/hybrid:
   - median classic dan rasio "2.9–3.1×";
   - mean dan median hybrid;
   - "about 0.3 ms per round-trip": hitung (E2E − compute − storage) / n_RT untuk method 4 dan 6, lalu tulis nilainya;
   - "0.68 ms".
5. Paragraf loss: semua angka sukses, mean, retransmisi, Wilson, Fisher, perbandingan dengan model, dan angka di 1% dan 5%.
6. Bootstrap: "6.8% of the handshake" dan "6.116 ms".
7. Discussion: "about 16% of the … handshake" (0.985 / E2E proposal).
8. Conclusion: mean proposal dan mean EAP-TLS Hybrid.
9. Threats (3): jumlah iterasi.

**Aturan:**
- Jangan menambah klaim baru.
- Jika data baru bertentangan dengan suatu kalimat, tulis ulang kalimat itu agar sesuai data, lalu laporkan. Contohnya "lower mean latency of the hybrid pair at every loss level", "degrades less in our emulation", atau "significant but modest".

## 6. Dokumen analisis

- `analysis.md` 1b: tabel op count dan tabel komputasi per fungsi di atas.
- `analisys2.md`: hasil uji ulang beserta p-value Fisher.

## Commit (terpisah)

1. `bench: correct static-DH op counts for methods 1-3; count rotation keygen in method 4`
2. `edhoc4: generate rotation keys inside the handshake by default (pool opt-in)`
3. `bench: re-run in-process, e2e, loss and storage with inline rotation`
4. `paper/notebook: per-method operation tables, measured comparison wording, re-run numbers`

## Laporan balik

Kirimkan:
- tabel angka baru (E2E mean/median 7 method, loss 20/30%, Fisher p, in-process, storage);
- daftar kalimat paper yang harus diubah karena data;
- status test.