# revisi-no-eph-step29.md: unlinkability v4 dengan model sesi terbatas

## Latar belakang

- `edhoc_m4v4_unlink.pv` (step 26) gagal: allocation failure, 4,1 GB dalam 24 detik.
- Penyebabnya bentuk model, bukan protokol:
  - `! DN(...)` direplikasi tanpa batas;
  - lookup lewat tabel `get`/`insert`, yang pada diff-equivalence membuat percabangan mahal;
  - Ed25519, quantum oracle, dan konstanta TLS yang tidak dipakai ikut dimuat.
- Step ini menambah dua model baru. Primitifnya sama persis dengan `edhoc_m4v4_*.pv`.

| File | Isi | Hasil yang diharapkan |
|---|---|---|
| `edhoc_m4v4_unlink_bounded.pv` | Diff-equivalence. **Kiri:** UE1 dua kali, run kedua memakai kunci hasil rotasi run pertama. **Kanan:** UE1 lalu UE2 yang berbeda. Tepat dua sesi DN-AAA, tanpa tabel. | `Observational equivalence is true` |
| `edhoc_m4v4_nextkey.pv` | Kerahasiaan Npk_A (EAD_1) dan Npk_B (EAD_2). KeyID_B run berikutnya = H(Npk_B), jadi tidak bisa dihitung penyerang dari run sebelumnya. | `not attacker(s_NpkA[]) is true` dan `not attacker(s_NpkB[]) is true` |

**Cara kerja model terbatas:**
- DN1 menangani run 1 dengan record UE1.
- Setelah commit, DN1 mengirim record barunya `(Nsk_B, Npk_A)` ke DN2 lewat channel privat `st`. Channel ini menggantikan database/tabel.
- DN2 memakai `choice[record dari DN1, record UE2]` dan **tetap** memeriksa `KeyID_B = H(pk_B)`.
- Message1 tetap memakai AAD `(KeyID_B, ct_B)` dan `TH_1 = H(pk_B, ct_B)`.

## 1. Tambahkan file

- Salin `edhoc_m4v4_unlink_bounded.pv` dan `edhoc_m4v4_nextkey.pv` (terlampir) ke `symmetry-rev/proverif/`.
- File lama `edhoc_m4v4_unlink.pv` jangan dihapus. Tambahkan komentar di kepalanya: "superseded by edhoc_m4v4_unlink_bounded.pv (allocation failure, see SUMMARY_v4.txt)".
- Jalankan `lint.py` pada kedua file kalau linter itu berlaku untuk model v4.

## 2. Jalankan dengan batas memori (wajib, supaya VM tidak macet)

```
cd symmetry-rev/proverif
uname -r; free -g
for f in edhoc_m4v4_nextkey edhoc_m4v4_unlink_bounded; do
  /usr/bin/time -v systemd-run --user --scope -p MemoryMax=10G -p MemorySwapMax=0 \
    timeout 7200 proverif $f.pv > results/$f.log 2> results/$f.time
  echo "$f exit=$?"; tail -5 results/$f.log
done
```

- Kalau `systemd-run --user` tidak tersedia, pakai `( ulimit -v 10000000; timeout 7200 proverif $f.pv )`.
- Jangan menaikkan `MemoryMax` di atas 12G, karena VM hanya punya 16 GB.
- Pantau dari terminal lain dengan `watch -n 5 'ps -o rss,etime,cmd -C proverif'`.

## 3. Kalau `unlink_bounded` gagal

Jalankan langkah berikut berurutan. Setiap percobaan dicatat apa adanya.

**a. Error sintaks atau tipe.** Perbaiki seminimal mungkin. Jangan mengubah protokol, AAD, TH_1, maupun pemeriksaan KeyID_B.

**b. `cannot be proved` dengan trace.**
- Simpan trace-nya.
- Periksa apakah serangannya nyata (KeyID_B, panjang pesan, atau field terbuka berbeda antara kiri dan kanan) atau *false attack* akibat diff-equivalence (perbedaan cabang `if`/`let` di DN2).
- Laporkan langkah trace yang membedakan kiri dan kanan.

**c. Memori habis lagi.** Coba satu per satu, lalu laporkan percobaan mana yang berhasil:
1. Tambahkan `set reconstructTrace = false.` di awal file.
2. Hapus `TH_1`/`TH_2` bersarang dari transcript: ganti `H(Message1)` di TH_2 dengan `H((kidB, ctB, encP1))`. Bentuknya setara karena Message1 memang tuple ini. Lakukan identik di UE dan DN.
3. Hilangkan run kedua dari Message3–4. Run 2 dihentikan setelah UE menerima Message2, yaitu `0` setelah `let PT22 = …`. Dengan begitu yang diuji adalah Message1–2 run kedua, tempat KeyID_B dan ct_A muncul.

   Ini klaim yang lebih sempit, jadi tulis jelas di laporan.

## 4. Output

Bagian baru di `analisys2.md`, "7c. Unlinkability v4 (bounded)", berisi:
- tabel: file, waktu, peak memory (`Maximum resident set size`), dan hasil;
- untuk `cannot be proved`: ringkasan trace dan penilaian apakah serangan nyata atau false attack;
- percobaan dari langkah 3c yang dipakai, kalau ada.

Tambahkan juga dua model baru ke `results/SUMMARY_v4.txt` dan `run_all_v4.sh`.

## Commit

`proverif: bounded unlinkability model and next-key secrecy for v4`

## Laporan balik

- hasil kedua model, beserta waktu dan memori;
- trace, kalau ada;
- `uname -r`;
- hash commit.

Teks paper (Section 5, footnote Tabel 8, Threats to validity) akan saya sesuaikan setelah hasilnya ada. Jangan ubah paper di step ini.