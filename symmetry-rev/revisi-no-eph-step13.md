# revisi-no-eph-step13.md: perapian akhir setelah step 12

## Hasil pengecekan step 12

**Sudah sesuai dengan protokol final:**
- **Kode:** pseudonim sudah hilang dari kode. EAD_2 = Npk_B, PT3 = (MAC_3, VK_I, σ_I), dan record dipilih dari identitas EAP.
- **Fallback:** hanya terjadi pada EAP-Failure eksplisit, dan NEXT tetap disimpan.
- **Test:** saya build ulang dan jalankan `edhoc4_xwing_kat`, `edhoc4_selftest`, `edhoc4_dbtest` (termasuk EAP-Failure palsu dan timeout), serta `edhoc03_selftest`. Semua PASS.
- **ProVerif v3** tanpa pseudonim: semua hasil sesuai harapan.
- **Angka benchmark** di `analisys2.md` cocok dengan CSV. Saya sudah menghitung ulang E2E, loss, Wilson, Fisher (p = 0.0023 di loss 30%), storage, dan in-process.

**Yang masih perlu dirapikan ada di bawah.** Jangan mengulang benchmark utama dan jangan mengubah `manuscript.tex`.

## 1. Diagram final belum masuk repo

`symmetry-rev/figure/Symmetry_Journal.drawio` di repo masih versi step 11: halaman "v3: rotation keys in EAD_1/EAD_2, **pseudonym**, no grace key".

- Timpa dengan `Symmetry_Journal.drawio` terlampir (halaman pertama: "Final v3 (Npk_A in EAD_1, Npk_B in EAD_2)").
- Salin `img_SecondaryAuth2_v3.png` terlampir ke `symmetry-rev/paper/`.
- Jangan mengedit atau mengekspor ulang.

## 2. Komentar yang masih menyebut P_next

- `rlm_eap_edhoc.c:468`: "commit: (P_next, Nsk_B, Npk_B, Npk_A)" → "(Nsk_B, Npk_B, Npk_A)".
- `UERANSIM/src/ue/nas/sm/transport.cpp:337`: "NEXT = (Nsk_A, Npk_B, P_next)" → "(Nsk_A, Npk_A, Npk_B)".

## 3. Model ukuran pesan tidak sama dengan pengukuran live

`benchmark-results/mtu-fragmentation.csv` (dari `edhoc_sizes.py`) untuk method 4 berbeda dari `e2e-handshake.csv`:

| | Model (`edhoc_sizes.py`) | Live |
|---|---|---|
| Message1 | 2.361 B, 3 fragmen EAP | 2.358 B, 3 |
| Message2 | 6.098 B, **6** | 6.097 B, **7** |
| Message3 | 3.751 B, 4 | 3.756 B, 4 |
| Message4 | **9 B** | **16 B** |
| Total fragmen / RT | **14** | **15** |

- Samakan model dengan format pesan yang sebenarnya, termasuk ukuran fragmen pertama dan berikutnya seperti di `transport.cpp`.
- Byte dan jumlah fragmen harus sama dengan live, yaitu **15 fragmen dan 15 RT**.
- Render ulang `img_communication_breakdown_methods.png`.
- Jika selisihnya disengaja (misalnya model tidak menghitung header), jelaskan di `analisys2.md`, dan pakai angka **live** di gambar.

## 4. Uji pemulihan live yang benar-benar memicu jalur pemulihan

Di uji pemulihan step 12 (150 handshake di loss 20%), `used_next` = 0 dan `fallback` = 0. Jadi jalur pemulihan **tidak pernah terpicu** di stack live; satu-satunya run yang gagal berhenti sebelum Message3. Jalur itu sejauh ini baru teruji di `edhoc4_dbtest`.

Tambahkan uji drop deterministik di `e2e_radius_bench.c`, misalnya opsi `--drop-msg3-once` / `--drop-msg4-once`. Setiap kasus 20 kali, masing-masing diikuti 1 sesi normal:

| Kasus | Yang diharapkan pada sesi berikutnya |
|---|---|
| Message3 di-drop (tidak sampai ke DN-AAA) | `used_next=1`, EAP-Failure, `fallback=1`, lalu sukses dengan CUR |
| Message4 di-drop (DN-AAA sudah commit) | `used_next=1`, `fallback=0`, sukses |

Laporkan juga desync (harus 0), re-provisioning (harus 0), dan waktu sesi pemulihan (mean/median). Simpan hasilnya di `e2e-recovery-forced.csv` dan tambahkan bagiannya di `analisys2.md`.

## 5. Pisahkan biaya dua flush di jalur kritis

Biaya penyimpanan naik dari 0,46 ms (satu flush) menjadi **1,16 ms** karena sekarang ada dua flush: write-ahead NEXT di UE sebelum Message3 dan commit DN-AAA sebelum Message4. Untuk paper perlu angka per flush.

- Jalankan `storage_ablation.sh` dengan dua konfigurasi tambahan, 6 ronde bergantian, masing-masing 100 handshake:
  - UE di tmpfs + DN-AAA durable;
  - UE durable + DN-AAA di tmpfs.
- Laporkan median dan interval bootstrap 95% untuk keempat konfigurasi (durable/durable, tmpfs/tmpfs, dan dua campuran) di `analisys2.md`.

## Commit

1. `figure: approved final v3 diagram`
2. `cleanup: drop stale P_next comments`
3. `bench: message-size model matches live sizes and fragments`
4. `bench: forced message_3 / message_4 drop recovery test`
5. `bench: per-flush storage ablation`

## Laporan balik

Kirimkan:
- tabel ukuran dan fragmen (model = live);
- hasil uji drop paksa;
- tabel storage empat konfigurasi;
- konfirmasi bahwa diagram dan PNG sudah di repo.