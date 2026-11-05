# revisi-no-eph-step31.md: versi final v5 (protokol Dr. Shin + cek KeyID dalam) dan angka paper

## Keputusan

Versi final adalah protokol Dr. Shin, yaitu varian **`v4s+chk`** dari step 30, yang sekarang disebut **v5**:
- `TH_1 = H(KeyID_B ‖ ct_B)`;
- tidak ada AAD_1 terpisah. AEAD Message1 memakai AD = TH_1, mengikuti konvensi implementasi untuk Message2–4 (AD = TH_x);
- `Plaintext1 = (Method, Suites_I, KeyID_B, ID_CRED_I, C_I, EAD_1)`;
- DN-AAA:
  - mengambil record dengan KeyID_B dari indeks memori, tanpa pemeriksaan terpisah KeyID_B = H(pk_B);
  - memeriksa ID_CRED_I cocok dengan record;
  - memeriksa **KeyID_B di Plaintext1 = KeyID_B di header**.
- Write-ahead NEXT di UE **tetap ada**. Dr. Shin mencoret baris itu hanya di diagram, sedangkan Algorithm 5 dan implementasi tetap memakainya.

Diagram referensi: `Symmetry_Journal.drawio` halaman 1, "Final v5" (terlampir). Halaman v4 dan v3 tetap ada di file yang sama.

## 1. Jadikan v5 default

1. `edhoc_variant` default = `v5`, sebagai alias dari `v4s+chk`. Varian lain tetap tersedia untuk reproduksi step 30.
2. Konfigurasi radiusd dan UE di testbed diubah ke `v5`.
3. Jalankan `selftest`, `dbtest`, `xwing_kat`, `edhoc03_selftest`, dan T1–T7 untuk `v5`. Semuanya harus PASS, dan T7 harus ditolak.

## 2. ProVerif v5 (model utama paper)

1. Dari `gen_m4v4.py --variant v4s_chk`, hasilkan file dengan nama final `edhoc_m4v5_{classical,quantum,kci,pcs,fs_noerase,recovery,nextkey}.pv`.
   - Pemeriksaan ID_CRED_I di DN sudah termasuk, sama seperti model varian step 30.
   - Tambahkan juga query integritas header dan query T7.
2. Jalankan dengan batas memori seperti step 30. Simpan hasilnya di `results/SUMMARY_v5.txt`, dengan format sama seperti `SUMMARY_v4.txt`.
3. Perbarui `run_all_v5.sh` dan README ProVerif. File v4 tetap disimpan.

## 3. Pengukuran ulang untuk paper (kernel sama, catat `uname -r`)

Semua file baru diberi akhiran `-v5`. File lama tidak diubah.

1. **Harness E2E:** v5 dan EAP-TLS Hybrid PQC, bergantian dalam satu sesi, 2 run × (20 pemanasan dibuang + 100).
   - Ganti baris method 4 dan 6 di `e2e-handshake.csv`, lalu simpan versi sebelumnya sebagai `e2e-handshake-v4b.csv`.
   - Laporkan mean, median, p95, CI median, dan selisih median beserta CI.
2. **Ablasi storage:** `storage_ablation.sh`, 4 konfigurasi, 6 ronde × 100. Laporkan median dan bootstrap CI untuk UE, DN-AAA, dan dua flush.
3. **Full stack:** A/B 3 × 100 dan pemulihan 10 + 10, dengan prosedur step 27. File: `fullstack-handshake-v5.csv` dan `fullstack-recovery-v5.csv`. Isi tabel yang sama dengan Tabel 6 paper:
   - added, UE secondary authentication, 5G core transport, relay hop, relay RADIUS, DN-AAA;
   - UE write NEXT, DN commit, UE promotion;
   - median, CI, mean, p95.
4. **Ukuran:** Message1–4, total, byte yang dikirim UE dan DN-AAA, fragmen, dan RT, dari live dan model.
5. **Komputasi per fungsi** (initiator dan responder, per peran), dengan harness yang dipakai untuk Figure 7. Laporkan nilai init/resp untuk v5.
6. **Bootstrapping EMSK** tidak perlu diulang.

## 4. Gambar paper (dari notebook repo)

1. Perbarui data v5 di notebook `EAP_Edhoc_Secondary_Authentication_v2.ipynb`:
   - cell Figure 7, `handshake_computation_grouped`: proposal init/resp dan EAP-TLS Hybrid, dari §3.1 dan §3.5;
   - cell `communication_breakdown_methods`: ukuran v5;
   - cell `D_baseline_comparison`: nilai handshake v5.
2. Render ulang ke `symmetry-rev/paper/`:
   - `img_handshake_computation_grouped.png`;
   - `img_communication_breakdown_methods.png`;
   - `img_D_baseline_comparison.png`.
3. Ekspor diagram halaman 1 ("Final v5") menjadi `img_SecondaryAuth2_v5.png` dengan lebar 4300 px. Versi yang sudah diekspor terlampir dan boleh langsung dipakai.

## 5. Output

Bagian baru di `analisys2.md`, "9. Final v5", berisi:
- hasil test;
- SUMMARY_v5;
- harness;
- ablasi storage;
- full stack dan pemulihan;
- ukuran;
- komputasi per fungsi.

Tambahkan juga **satu tabel ringkas berisi semua angka yang akan masuk paper**, dengan sumber file dan kolom untuk setiap angka.

**Jangan ubah paper.**

## Commit

1. `edhoc: make v5 (Shin revision + inner KeyID check) the default`
2. `proverif: v5 models and SUMMARY_v5`
3. `bench: v5 harness, storage ablation, full stack, recovery, sizes, per-function compute`
4. `notebook: v5 figures`

## Laporan balik

- tabel ringkas angka paper;
- hasil test dan ProVerif v5;
- tiga gambar baru, termasuk path-nya;
- hash commit.