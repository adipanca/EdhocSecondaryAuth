# revisi-no-eph-step27.md: indeks KeyID di memori (tanpa flush di jalur kritis) dan pengukuran ulang v4

## Hasil cek step 26

**Sudah sesuai:**
- Message1 v4: KeyID_B ‖ ct_B ‖ AEAD(K_1, AAD_1, PT1), dengan TH_1 = H(pk_B ‖ ct_B).
- Ukuran 2.390 / 6.097 / 3.756 / 16 B, total 12.259 B, 15 fragmen dan 15 RT. Model ukuran sama dengan live.
- Identitas `@edhoc.internet` saja; SUPI dan `ue1@…` tidak muncul di RADIUS maupun EAP.
- Full stack: 300/300 sukses. Pemulihan 10 + 10, tanpa desync.
- ProVerif v4 sesuai harapan; `fs_noerase` satu sesi selesai dalam 0,5 detik.
- Model `unlink`: NOT CONCLUDED (memori habis). Tidak akan diklaim di paper.

**Masalah:**
- **E2E proposal naik** dari 6,582 menjadi 8,242 ms (median). Sekarang setara dengan EAP-TLS Hybrid (8,087 ms; selisih tidak signifikan).
- **Penyebab:** `storage-strace-v4.txt` menunjukkan flush DN-AAA per handshake naik dari 2 menjadi 5. Tiga di antaranya berada di jalur kritis sebelum Message4: fdatasync slot, fdatasync file indeks sementara, dan fsync direktori indeks.
- **Indeks tidak perlu durable.** Slot record adalah satu-satunya sumber kebenaran, dan indeks bisa dibangun ulang dari slot kapan saja.

## 1. Indeks KeyID di memori (`edhoc4_db.c/.h`, `rlm_eap_edhoc.c`)

1. **Hapus indeks berbasis file** `<root>/kid/`, termasuk tulis file sementara, `rename`, dan `fsync` direktori. Tambahkan langkah migrasi yang menghapus folder `kid/` lama.
2. **Indeks di memori:** tabel hash `KeyID_B (32 B) → (record_id, slot)` di dalam instance `rlm_eap_edhoc`, dilindungi mutex (FreeRADIUS multithread).
3. **Bangun ulang saat start** (`mod_instantiate`):
   - pindai semua `<root>/<record_id>/`;
   - untuk setiap slot yang valid, hitung SHA-256(pk_B) lalu masukkan ke tabel. Setelah crash di antara commit dan erase_old, kedua slot masuk ke tabel;
   - catat jumlah record dan lama pemindaian di log.
4. **`commit`:** tulis slot baru + **satu** `fdatasync` (sama seperti v3), lalu tambahkan entri SHA-256(Npk_B) ke tabel memori. Tidak ada penulisan indeks ke disk.
5. **`erase_old`:** nolkan slot lama (dengan `fsync` seperti sekarang, di luar jalur kritis), lalu hapus entri SHA-256(pk_B lama) dari tabel.
6. **Lookup:** cari KeyID_B di tabel, lalu baca slot dan **tetap** cek KeyID_B = SHA-256(pk_B) dengan perbandingan waktu-konstan.
   - KeyID tidak ditemukan → EAP-Failure **tanpa** pemindaian disk, untuk mencegah DoS lewat KeyID acak, dan tanpa Decaps.
7. **Sisi UE tidak berubah.**

**Target:** flush di jalur kritis per handshake kembali seperti v3, yaitu **UE 1 (NEXT) dan DN-AAA 1 (commit)**. Buktikan dengan `strace -f -e trace=fsync,fdatasync,rename` → `storage-strace-v4b.txt`.

## 2. Selidiki `ue_store_next_ms` di full stack

- Di full stack v4, nilainya 2,84 ms (median), padahal di step 19/20 sekitar 1,1–1,4 ms. Kode UE tidak berubah.
- Cek dengan `strace` pada `nr-ue` saat menulis NEXT: jumlah dan jenis flush, dan apakah file record UE sekarang ditulis lewat jalur berbeda.
- Laporkan penyebabnya. Jika ada flush yang tidak perlu, hapus. Jika tidak, tulis penjelasannya di `analisys2.md`.

## 3. Test (wajib PASS)

| Test | Harapan |
|---|---|
| Restart radiusd setelah commit, sebelum erase_old | kedua KeyID ditemukan setelah start; Message1 berikutnya membersihkan yang lama |
| Restart radiusd setelah erase_old | hanya KeyID baru yang ditemukan; KeyID lama → EAP-Failure tanpa Decaps |
| `kill -9` radiusd di tengah commit (sebelum dan sesudah fdatasync) | setelah restart, UE pulih lewat NEXT atau fallback; 0 desync |
| 1.000 KeyID acak | semuanya EAP-Failure, tanpa Decaps dan tanpa pemindaian disk |
| 100 UE anonim, bergantian dan paralel | 0 record tertukar |
| Waktu bangun ulang untuk 10.000 record sintetis | laporkan dalam ms |
| `selftest`, `dbtest`, `xwing_kat`, `edhoc03_selftest` | PASS |

## 4. Pengukuran ulang (kernel sama dengan step 26, catat `uname -r`)

1. **Harness:** method 4 dan EAP-TLS Hybrid PQC dalam sesi yang sama, 2 run × (20 pemanasan dibuang + 100), bergantian (`v4_harness.sh`). Ganti baris method 4 dan 6 di `e2e-handshake.csv`; simpan hasil step 26 sebagai `e2e-handshake-v4a.csv`. Laporkan mean, median, p95, CI median, dan selisih median dengan CI.
2. **Ablasi storage per flush:** `storage_ablation.sh` dengan 4 konfigurasi seperti step 13 (durable/durable, tmpfs/tmpfs, dan dua campuran), 6 ronde bergantian × 100. Laporkan median dan bootstrap 95% CI.
3. **Full stack:** A/B 3 × 100 dan pemulihan 10 + 10, dengan prosedur yang sama seperti step 26. File diberi akhiran `-v4b`; simpan file step 26 apa adanya.
4. **Uji loss tidak perlu diulang**, karena jumlah RT tetap 15.

## 5. Output

Bagian baru di `analisys2.md`, "7b. v4 dengan indeks di memori", berisi:
- strace sebelum dan sesudah perbaikan;
- tabel harness (v3, v4a, v4b);
- tabel ablasi storage;
- tabel full stack dan pemulihan v4b;
- penjelasan `ue_store_next_ms`;
- waktu bangun ulang indeks.

## Commit

1. `db: in-memory KeyID index rebuilt from record slots at start-up, no index flush on the critical path`
2. `tests: index rebuild after restart/crash, random KeyIDs, 100 anonymous UEs`
3. `bench: v4b harness, per-flush storage ablation, full stack and recovery`

## Laporan balik

Kirimkan:
- jumlah flush per handshake (UE dan DN-AAA) sebelum dan sesudah perbaikan;
- tabel harness v4b (proposal vs EAP-TLS Hybrid);
- ablasi storage;
- full stack dan pemulihan;
- penjelasan `ue_store_next_ms`;
- hasil test;
- hash commit.