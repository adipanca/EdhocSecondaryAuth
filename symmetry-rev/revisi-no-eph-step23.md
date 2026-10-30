# revisi-no-eph-step23.md: perapian akhir

Step 22 sudah saya cek: `manuscript.tex` dan `manuscript.pdf` di repo (`bc80a5cd`) sama persis dengan versi saya, dan semua gambar yang dirujuk paper ada di repo.

Ada dua hal kecil yang belum sesuai dengan implementasi akhir.

## Perubahan

1. **Preliminaries (Section 3.1):** kalimat "secondary authentication ... runs only after the PDU session is established" diganti menjadi "runs during PDU session establishment, before the session is accepted". Sumbernya TS 33.501 dan TS 23.502.
2. **Diagram arsitektur (versi paper dan versi lengkap):**
   - nr-gnb sekarang diberi tanda "modified" (SCTP_NODELAY);
   - AMF hanya meneruskan Authentication Command;
   - SMF: secondary auth di dalam establishment, EAP-Success di Accept, EAP-Failure di Reject #29, relay non-blocking;
   - UPF: socket persisten;
   - UE: identitas EAP khusus DN.

## Langkah

1. Dari zip terlampir, salin `manuscript.tex` dan `img_testbed_architecture.png` ke `symmetry-rev/paper/`.
2. Salin `testbed_architecture.drawio`, `testbed_architecture.png` dan `testbed_architecture_paper.drawio` ke `symmetry-rev/figure/`.
3. Timpa `manuscript.pdf` dan `manuscript_tracked_changes.pdf` dengan file terlampir.
4. Jangan mengubah isi teks.

Commit: `paper/figure: secondary auth during establishment in preliminaries, final architecture labels`