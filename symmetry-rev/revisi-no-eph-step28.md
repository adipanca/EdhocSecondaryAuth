# revisi-no-eph-step28.md: paper final (v4b) dan sumber draw.io masuk ke repo

## Hasil cek step 27

Semua sesuai. Sudah dihitung ulang dari CSV:

- **Flush di jalur kritis** kembali seperti v3: UE 1 dan DN-AAA 1 (`storage-strace-v4b.txt`).
- **Harness** (sesi yang sama):
  - proposal: 6,383 ms (median 6,284);
  - EAP-TLS Hybrid PQC: 8,273 ms (median 7,847);
  - selisih median 1,563 ms, CI [1,436; 1,707].
- **Ablasi storage:** dua flush 1,10 ms, CI [1,04; 1,15]. UE 0,53 ms, DN-AAA 0,61 ms.
- **Full stack:** A − B = 75,9 ms, CI [74,4; 77,1]. 300/300 PASS.
- **Pemulihan:** 1,46 s (Message3) dan 101 ms (Message4). 0 desync.
- **`ue_store_next_ms` 2,84 ms:** flush pertama setelah disk menganggur. Ini biaya disk VM, bukan biaya protokol, dan sekarang dijelaskan dalam satu kalimat di paper.

## 1. Salin paper final

Isi zip `Symmetry_EAP-EDHOC_final_v4b.zip` disalin ke `symmetry-rev/paper/`. Timpa file yang sudah ada:

- `manuscript.tex`, `egbib.bib`, `manuscript.pdf`;
- semua `img_*.png`, termasuk:
  - `img_SecondaryAuth2_v4.png`;
  - `img_handshake_computation_grouped.png` (angka v4b);
  - `img_communication_breakdown_methods.png`;
- folder `Definitions/`;
- folder `drawio/` → `symmetry-rev/paper/drawio/`, berisi:
  - `Symmetry_Journal.drawio`, dengan halaman 1 = Final v4;
  - `testbed_architecture.drawio`;
  - `testbed_architecture_paper.drawio`;
  - `EAP-TLS_and_KeyGen_comparison.drawio`.

Jangan commit file `.aux`, `.log`, `.out`, `.blg`, maupun `diff_tc*`.

## 2. Cek build

```
cd symmetry-rev/paper
pdflatex manuscript && bibtex manuscript && pdflatex manuscript && pdflatex manuscript
```

**Harapan:**
- 23 halaman;
- tidak ada `!` error, overfull box, atau referensi undefined.

## 3. Cek konsistensi angka (grep harus kosong)

```
grep -n -E '7\.159|8\.771|6\.582|8\.620|\$93\$~ms|5\.8\\%' manuscript.tex
```

## 4. README

Di `symmetry-rev/paper/README.md` (buat jika belum ada), tambahkan:

- Gambar protokol ada di `drawio/Symmetry_Journal.drawio`, halaman "Final v4". Ekspor PNG dengan scale 2 menjadi `img_SecondaryAuth2_v4.png`.
- Angka E2E dan full stack berasal dari:
  - `e2e-handshake.csv` (method 4 dan 6 = v4b);
  - `fullstack-handshake-v4b.csv`;
  - `fullstack-recovery-v4b.csv`;
  - `e2e-storage-flush-v4b.csv`.
- Uji loss memakai handshake v3, dengan jumlah RT yang sama (15).

## Commit

`paper: final v4b manuscript, figures, and draw.io sources`

## Laporan balik

- hash commit;
- jumlah halaman;
- hasil grep di langkah 3.