# revisi-no-eph-step4.md — Satu perbaikan ProVerif (branch `symmetry-no-eph`)

**Masalah.** Pada commit `c2e39cea`, kelima model di-generate ulang dengan `gen_v3.py`. Akibatnya dua perbaikan yang sebelumnya ada di file `.pv` (versi yang benar-benar diverifikasi, lihat `proverif/results/split_v2/*_kci_*.pv` dan `*_pcs_*.pv`) **hilang**:
- `edhoc_m4v2_kci.pv`: `| QXW` (oracle kuantum) tidak ada lagi di proses main.
- `edhoc_m4v2_pcs.pv`: `out(c, ID_CREDR);` tidak ada lagi.

Dampaknya:
- `SUMMARY_v2.txt` masih melaporkan hasil versi lama (yang lebih kuat), sehingga file `.pv` di repo **tidak sama** dengan file yang diverifikasi.
- Tabel paper memberi ● (classical **dan** quantum) untuk KCI pada proposal. Klaim itu hanya didukung model KCI yang memuat `QXW`.

**Perbaikan** (file terlampir):
- `gen_v3.py`: KCI kembali memuat `| QXW`, PCS kembali memuat `out(c, ID_CREDR)`.
- `edhoc_m4v2_kci.pv` dan `edhoc_m4v2_pcs.pv` hasil generate ulang.
  - Isinya identik (di luar komentar dan pemenggalan baris) dengan versi yang diverifikasi di `77a29b07`.
  - Classical, quantum, dan fs_noerase **tidak berubah**.

```bash
cp gen_v3.py symmetry-rev/proverif/
cp edhoc_m4v2_kci.pv edhoc_m4v2_pcs.pv proverif/
cp edhoc_m4v2_kci.pv edhoc_m4v2_pcs.pv symmetry-rev/proverif/
python3 symmetry-rev/proverif/gen_v3.py proverif/edhoc_m4_hybrid_classical.pv /tmp/regen \
  && for f in /tmp/regen/*.pv; do cmp "$f" "proverif/$(basename "$f")"; done   # harus diam (identik)
# jalankan ulang hanya kci dan pcs (per query, seperti sebelumnya); harapannya kci 3/3 true, pcs 6/6 as expected
```

Lalu:
- Perbarui `SUMMARY_v2.txt` (di `proverif/results/` dan `symmetry-rev/proverif/results/`).
- Ubah baris `_kci` di README menjadi: "... Same structure as `edhoc_m4_hybrid_kci.pv`, plus the quantum oracle `QXW`."

Commit: `proverif: restore quantum oracle in KCI and public ID_CRED_R in PCS`.
