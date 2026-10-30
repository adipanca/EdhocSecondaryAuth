# revisi-no-eph-step20.md: paper dengan hasil full stack v2 (step 19)

Hasil step 19 sudah saya cek terhadap CSV, log mentah, capture dan kode. Semua angka di `analisys2.md` cocok.

## Langkah

1. Dari `Symmetry_EAP-EDHOC_overleaf.zip` terlampir, salin `manuscript.tex` dan `egbib.bib` (entri baru TS 24.501) ke `symmetry-rev/paper/`.
2. Jangan mengubah isi teks.

## Perubahan di paper

- **Subbab "Full 5G Core Path":**
  - menjelaskan urutan sesuai TS 23.502 langkah 6, identitas khusus DN, EAP-Success di Accept, dan Reject #29 dengan EAP-Failure;
  - Tabel 9 diganti dengan angka v2. Biaya terhadap establishment 78,3 ms; uraian per bagian: transport 5G core 78,2 ms, hop SMF–UPF 3,4 ms, relay 1,5 ms, DN-AAA 6,0 ms;
  - hasil uji pemulihan v2.
- **Testbed:** relay SMF disebut non-blocking dengan socket persisten.
- **Kesimpulan dan threats to validity (1)** disesuaikan.

## Opsional (tidak mengubah hasil di paper)

**Masalah:** di UERANSIM, sesi pertama setelah start mendapat balasan pertama sekitar 30 ms setelah Establishment Request. Sesi-sesi berikutnya baru mendapat balasan setelah sekitar 185 ms. Menurut capture, bagian di 5G core hanya sekitar 5 ms, jadi jeda ini terjadi di dalam UE sebelum request keluar. Penyebab yang paling mungkin adalah jeda RRC/UAC dari perbaikan `cmd_handler.cpp` di step 17.

**Yang bisa dilakukan:**
- telusuri jeda ini dengan tag `E4T` di gNB (`gnb_ul_nas_rx`);
- jika bisa diperbaiki tanpa mengubah alur NAS, ukur ulang A dan B.

Selisih A − B tidak terpengaruh, karena jeda yang sama muncul di kedua konfigurasi. Paper sudah menjelaskan hal ini.

Commit: `paper: full 5G core path in standard order (step 19 results)`