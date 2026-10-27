# revisi-no-eph-step2.md — Lanjutan untuk Claude Code (branch `symmetry-no-eph`)

Langkah 1 (`revisi-no-eph.md`) sudah dijalankan dan di-push. File ini hanya berisi pekerjaan yang tersisa: **ProVerif ulang dengan model baru** dan **benchmark E2E live**. Setelah itu notebook dan paper bisa difinalkan.

## 0. Ringkasan hasil run pertama (sudah dipakai di paper)

| Item | Hasil | Dipakai di |
|---|---|---|
| `handshake-compute.csv` | method 4: 492.320 / 492.320 µs (total 984.640 µs); method 0–3: 151.7–182.4 µs; EAP-TLS Classic 182.4 µs, Hybrid 775.2 µs | paper (tabel primitif, §Computation, §Discussion), notebook `compute_*` |
| `crypto-primitives.csv` | run baru, misalnya ML-DSA sign 0.223 ms | tabel primitif paper |
| `lossy-network.csv` | simulasi, semua method | notebook `sim_*` |
| `mtu-fragmentation.csv` | model: 14 fragmen EAP, 10 IP untuk method 4 | belum dipakai; angka final dari observasi live (langkah 2) |
| ProVerif v2 | Q3/Q4 classical + semua quantum/KCI/PCS **out of memory** | diganti model baru (langkah 1) |

## 1. ProVerif — ganti model v2 dengan versi compact

**Penyebab OOM.** Model v2 pertama memodelkan X25519 dengan teori persamaan DH (`exp(exp(g,x),y)`) plus hash combiner eksplisit. Header `edhoc_m4_hybrid_classical.pv` sudah mencatat bahwa cara ini membuat term membengkak dan ProVerif kehabisan memori. Jadi ini masalah pemodelan, bukan protokolnya.

**Model baru** memakai abstraksi X-Wing yang **persis sama** dengan `edhoc_m4_hybrid_*.pv`:
- term: `xwpk`, `xw_ct`, `xw_ss`, `xw_decaps`, `mlkem_dec`, `x25519_dec`;
- oracle kuantum: `QXW`;
- deklarasi disalin verbatim dari model lama. Satu-satunya perubahan: `ID_CREDR` dijadikan private (untuk Q5b).

Struktur KCI dan PCS juga sama dengan model `m4_hybrid` yang dulu selesai.

```bash
# salin 5 file .pv baru + gen_v3.py + lint.py + README dari paket ke DUA lokasi
cp paket/proverif/edhoc_m4v2_*.pv proverif/
cp paket/proverif/edhoc_m4v2_*.pv paket/proverif/README.md symmetry-rev/proverif/
cp paket/proverif/gen_v3.py paket/proverif/lint.py symmetry-rev/proverif/
python3 symmetry-rev/proverif/lint.py proverif     # harus OK untuk kelima file m4v2

cd proverif
# jalankan dengan cara split per-query yang sudah Anda pakai (results/split_v2/),
# atau seluruh file sekaligus:
TIMEOUT=3600 ./run_all_v2.sh
```

Hasil yang diharapkan:

| File | Harapan |
|---|---|
| `edhoc_m4v2_classical.pv` | Q0/Q1 false (reachable); Q2, Q3, Q4 **true**; Q5, Q5b, Q6–Q9 true |
| `edhoc_m4v2_quantum.pv` | sama dengan classical |
| `edhoc_m4v2_kci.pv` | 3/3 true |
| `edhoc_m4v2_pcs.pv` | sanity false; Q2–Q4 (W2), Q10, Q11 true |
| `edhoc_m4v2_fs_noerase.pv` | Q5, Q5b, Q6–Q9 **false** (kontrol negatif); Q2–Q4 true |

Aturan pelaporan:
- Jika sebuah query masih OOM, catat sebagai "not concluded". **Jangan** catat sebagai false.
- Laporkan angka memori dan waktu per query.
- Jika hasil berbeda dari harapan, kirim potongan trace serangan dari output ProVerif (bagian "A trace has been found").

Setelah selesai:
- Salin `results/SUMMARY_v2.txt` ke `symmetry-rev/proverif/results/`.
- Isi tabel verifikasi paper (baris ~427, ~486, ~510): hapus `\pend{...}` di sana dan cocokkan status R1–R9.

## 2. Benchmark E2E live (belum pernah dijalankan untuk protokol baru)

`e2e-handshake.csv`, `e2e-lossy.csv`, `analisys2.md`, dan `analisys3.md` masih dari 14 Agustus.

```bash
cd benchmark
sudo ./setup_no_eph.sh                # pasang modul baru, provisioning ulang record per-UE, restart radiusd (config classic)
./run_e2e_benchmarks.sh               # method 0-4; TIMING_ITERS=100, LOSSY_ITERS=120
./switch_tls_config.sh classic  && (restart radiusd) && jalankan bagian EAP-TLS Classic
./switch_tls_config.sh hybrid   && (restart radiusd) && jalankan bagian EAP-TLS Hybrid
python3 e2e_analyze.py ../benchmark-results     # perbarui analisys2.md / analisys3.md
cd ../bootstrap && python3 bootstrap_bench.py && python3 analyze_bootstrap.py
```

- **Method 0–3 wajib diulang**, karena AEAD-nya kini AES-128-GCM.
- Cek `/tmp/radiusd.log` setelah run lossy: harus ada kasus "grace key" (Message4 hilang lalu sesi berikutnya sukses lewat `prev/`), dan **tidak boleh ada desync permanen**.
- Laporkan:
  - ukuran pesan teramati (harus 1141 / 4880 / 4975 / 1232 B);
  - jumlah fragmen EAP dan IP teramati per pesan, serta jumlah round-trip RADIUS method 4.

## 3. Isi notebook dan paper dari hasil langkah 2

Notebook `symmetry-rev/notebook/EAP_Edhoc_Secondary_Authentication_v2.ipynb`.

Sudah terisi dari run pertama:
- `compute_initiator` / `compute_responder` (semua method);
- `sim_mean`, `sim_p95`, `sim_retx`, `sim_success` (semua method);
- `MSG1..MSG4` (ukuran kawat).

Masih `TODO(no-eph)`:
- `e2e_initiator`, `e2e_responder` (**semua** method, dari bagian "Pembagian beban initiator vs responder" di analisys2.md);
- `total_eap_frags`, `total_ip_frags` (method 4, dari tabel observasi live analisys2.md §4);
- `e2e_mean`, `e2e_p95`, `e2e_retx`, `e2e_success` (semua method);
- `EDHOC_HANDSHAKE_MEAN_MS` di cell bootstrap.

Jalankan notebook, lalu salin PNG berikut ke folder paper (nama tetap):
- `img_handshake_computation_grouped.png`
- `img_communication_breakdown_methods.png`
- `img_combined_*.png`
- `img_A2_compute_breakdown.png`
- `img_D_baseline_comparison.png`

Juga perbarui `img_A1_primitive_mean.png`, karena tabel primitif berubah.

Paper `symmetry-rev/paper/manuscript.tex` — isi semua `\pend{...}` yang tersisa:

| Baris | Isi |
|---|---|
| ~567 | mean e2e method 4, angka method 0–3 / EAP-TLS bila berubah, round-trip RADIUS method 4 |
| ~571 | round-trip method 4 |
| ~574 | success / latensi / retransmisi method 4 pada loss 20 % dan 30 % (e2e) |
| ~598 | mean handshake di baseline bootstrapping |
| ~622 | porsi fragmentasi / round-trip |
| ~635 | mean e2e (Conclusion) |

Setelah itu:
- hapus macro `\pend`;
- kompilasi (`pdflatex`, `bibtex`, `pdflatex` ×2);
- buat tracked changes: `latexdiff --math-markup=0 old.tex manuscript.tex > diff.tex`.

## 4. Commit

Satu commit per langkah, di branch `symmetry-no-eph`:
1. `proverif: compact X-Wing model for m4v2 (fix OOM)`
2. `bench: e2e live re-run after no-eph + AES-128-GCM`
3. `paper/notebook: fill e2e + ProVerif results`

Jangan commit binary hasil build (`*.o`, `*.a`, `*.so`, `crypto_bench`, `e2e_radius_bench`, `edhoc4_*` executables) dan jangan commit `opam-2.6.1-x86_64-linux`. Tambahkan semuanya ke `.gitignore`. Commit terakhir branch ini memuat file-file tersebut, termasuk binary opam 9 MB.
