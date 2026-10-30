# revisi-no-eph-step22.md: waktu pemulihan masuk ke paper

Hasil step 21 sudah saya cek. `fullstack-recovery-v2-ue-fix.csv` cocok:

| Kasus | Pulih | Median waktu pulih |
|---|---|---|
| Message3 di-drop | 10/10, dengan EAP-Failure dan fallback | 1.420 ms |
| Message4 di-drop | 10/10 | 125 ms |

Hasil lain: msk_match 20/20, desync 0, re-provisioning 0.

`manuscript.tex` di repo (`f66cd04`) sama persis dengan versi saya sebelum perubahan ini.

## Langkah

1. Dari zip terlampir, salin `manuscript.tex` ke `symmetry-rev/paper/`.
2. Timpa `manuscript.pdf` dan `manuscript_tracked_changes.pdf` dengan file terlampir.
3. Jangan mengubah isi teks.

## Perubahan

Hanya satu kalimat di subbab "Full 5G Core Path" yang berubah: kalimat itu sekarang memuat median waktu pemulihan, yaitu 1,42 s setelah Message3 hilang (termasuk `reject_delay` 1 s) dan 125 ms setelah Message4 hilang.

Commit: `paper: full-stack recovery times after the SCTP_NODELAY fix`