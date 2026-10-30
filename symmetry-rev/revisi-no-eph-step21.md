# revisi-no-eph-step21.md: paper memakai hasil setelah perbaikan SCTP, dan uji pemulihan diulang

Hasil step 20 sudah saya cek. Angka di `fullstack-handshake-v2-ue-fix.csv` cocok setelah saya hitung ulang, termasuk A − B = 93,4 ms [90,4; 95,6].

## 1. Salin paper

1. Dari `Symmetry_EAP-EDHOC_overleaf.zip` terlampir, salin `manuscript.tex` ke `symmetry-rev/paper/`.
2. Timpa juga `manuscript.pdf` dan `manuscript_tracked_changes.pdf` dengan file terlampir.
3. Jangan mengubah isi teks.

Yang berubah di paper:
- **Tabel 9 dan teks "Full 5G Core Path"** sekarang memakai hasil setelah perbaikan SCTP (`-ue-fix`): +93,4 ms terhadap establishment (21 ms tanpa vs 114 ms dengan secondary auth), transport 5G core 82,7 ms, hop SMF–UPF 3,6 ms, relay 1,6 ms, DN-AAA 6,5 ms.
- **Kalimat soal jeda di UE dihapus.** Bagian testbed sekarang menjelaskan `SCTP_NODELAY` di NGAP UERANSIM dan efeknya sebelum diperbaiki (sekitar 160 ms per sesi setelah sesi pertama).
- **Waktu pemulihan (ms) dikeluarkan dari paper** sampai bagian 2 selesai, karena angka step 19 masih memuat jeda SCTP. Hasil kualitatifnya (pulih, tanpa desync, tanpa re-provisioning) tetap ada.

## 2. Ulangi uji pemulihan dengan perbaikan SCTP

`fullstack-recovery-v2-ue-fix.csv` hanya berisi 10 baris `after`, tanpa kasus `msg3` dan `msg4`. Uji pemulihan belum dijalankan ulang setelah perbaikan.

1. Jalankan 10 + 10 drop dengan `E4_DROP_ONCE=msg3|msg4`, dengan prosedur yang sama seperti step 19.
2. Tulis ulang `fullstack-recovery-v2-ue-fix.csv` dengan kolom yang sama seperti `fullstack-recovery-v2.csv`.
3. Perbarui tabel pemulihan di `analisys2.md`.
4. Hasil yang diharapkan sama dengan step 19: Message3 → Reject #29 + EAP-Failure → fallback → sukses; Message4 → NEXT langsung sukses; desync 0; re-provisioning 0.

Commit: `bench: full-stack recovery re-run after the SCTP_NODELAY fix`

## Laporan balik

Kirimkan:
- tabel pemulihan: N, pulih, EAP-Failure, fallback, sesi sampai pulih, serta waktu pulih mean/median;
- hash commit.

Waktu pemulihannya akan saya masukkan kembali ke paper.