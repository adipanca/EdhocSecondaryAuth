# revisi-no-eph-step8.md: perbandingan komputasi yang adil dan uji signifikansi loss

Saya sudah memeriksa commit 1a0d1d7, 22a84ee, dan 7afe741. Hasilnya:

- Angka di paper cocok dengan CSV (E2E, ablation, loss, compute).
- Test vector X-Wing juga saya cek ulang dengan implementasi independen (kyber-py + pyca/cryptography + hashlib). Ketiga vektor cocok untuk pk, ct, dan ss.

Hanya tiga hal yang perlu diperbaiki di paper. Semuanya sudah ada di `manuscript.tex` dalam zip Overleaf terlampir.

## 1. Klaim "the proposal now computes less than EAP-TLS Hybrid PQC"

Klaim ini memakai dua aturan berbeda untuk dua protokol:
- pembuatan kunci rotasi proposal dikeluarkan dari handshake;
- pembuatan key share EAP-TLS tetap dihitung di dalam handshake.

Padahal key share client TLS sama-sama tidak bergantung pada sesi, jadi bisa juga dibuat di muka. Kalau aturannya disamakan, proposal tidak pernah lebih murah:

| Aturan (sama untuk kedua sisi) | Proposal | EAP-TLS Hybrid |
|---|---:|---:|
| Semua keygen di dalam handshake | 0.985 ms | 0.894 ms |
| Hanya "kunci berikutnya" yang dibuat di muka (kunci rotasi proposal ↔ key share client TLS) | 0.869 ms | 0.836 ms |
| Semua keygen yang tidak bergantung sesi dibuat di muka (termasuk share X25519 ephemeral) | 0.818 ms | 0.811 ms |

Rincian perhitungannya:
- Proposal: 868.689 − 2×25.535 = 817.62 µs.
- EAP-TLS: 894.349 − 57.976 − 25.535 = 810.84 µs.

Teks baru di paper:
- §Performance: menyebut kedua titik ekstrem (0.985 vs 0.894 dan 0.818 vs 0.811) dan menyimpulkan "compute about the same, differ in transport".
- Hybrid pair: "the two compute about the same ($0.869$ vs.\ $0.894$~ms as implemented, $0.818$ vs.\ $0.811$~ms with every session-independent key generation precomputed on both sides) …".

## 2. Sukses di loss 30%: "barely distinguishable" diganti

Hasilnya 108/120 (proposal) vs 94/120 (EAP-TLS Hybrid). Uji eksak Fisher dua sisi memberi p = 0.021, dan uji z dua proporsi p = 0.013. Jadi bedanya signifikan.

Teks baru: "the difference between the two success rates is significant but modest (Fisher's exact test, $p=0.02$)".

## 3. Dua perbaikan lokal yang hilang lagi

- Gambar loss di Figure 8 dan 9 kembali ke `width=0.75\linewidth`. Tanpa ini ada overfull vbox di halaman 18 dan 19.
- Baris `% TODO (authors): …` dihapus.

## Langkah

1. Salin `manuscript.tex` dari zip ke `symmetry-rev/paper/`. Gambar tidak berubah.
2. Tambahkan tabel di atas ke `benchmark-results/analysis.md` bagian 1b, di bawah tabel komputasi, dengan judul "Kebijakan precompute yang sama untuk kedua protokol".
3. Opsional: di `benchmark/e2e_analyze.py` bagian loss, tambahkan uji eksak Fisher untuk proposal vs EAP-TLS Hybrid di tiap tingkat loss (`scipy.stats.fisher_exact`), lalu laporkan p-value-nya di `analisys2.md`.
4. Compile di Overleaf. Hasil lokal saya: 26 halaman, 0 error, 0 overfull.

Commit: `paper: same precompute rule for both protocols in the compute comparison; Fisher test for loss success`