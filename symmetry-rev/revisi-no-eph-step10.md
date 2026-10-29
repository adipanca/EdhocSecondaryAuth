# revisi-no-eph-step10.md: sinkronkan tiga kalimat di paper

Hasil step 8 dan 9 (commit 63c3142) sudah saya cek, dan semuanya cocok dengan CSV:
- `handshake-compute.csv`;
- E2E mean dan median ketujuh method;
- loss (sukses, mean, retransmisi, Wilson, Fisher p = 0.0018);
- storage ablation;
- in-process (1.090 / 1.144 / 0.988);
- tabel RTT, rasio classic 2.8–2.9×, 7.2%, dan 17%.

Klaim "lower mean latency at every loss level" dan "gap widens" juga masih sesuai data.

Saya hanya merapikan tiga kalimat. Hasilnya ada di `manuscript.tex` dalam zip terlampir.

1. **fdatasync vs biaya penyimpanan.** Sebelumnya paper menyebut satu fdatasync 0.7–0.8 ms, tetapi biaya terukurnya 0.46 ms "essentially the one flush". Kedua angka itu tampak bertentangan. Padahal `strace -w` sendiri juga mencatat 0.10–0.11 ms per panggilan di tmpfs (`storage-strace.txt`), jadi sebagian angka itu adalah overhead tracing. Teks baru:
   - "With `strace -w`, one `fdatasync` takes 0.69–0.76 ms of wall-clock time on the virtual disk of our VM and 0.10–0.11 ms on `tmpfs`, most of which is tracing overhead."
   - "… durable storage costs 0.46 ms (…), of the same order as the one flush on the DN-AAA's critical path."
2. **Pool ablation dari sesi lain.** Angka 6.139 vs 6.016 ms berasal dari sesi sebelumnya, sedangkan seri utama sekarang 5.8 ms. Teks baru menyebut hal itu dan menambahkan angka in-process dari sesi ini: "it lowers the in-process computation from 1.090 to 0.988 ms, and in an earlier session 8 alternating rounds of 100 handshakes showed that it lowered the live median …".

## Langkah

1. Salin `manuscript.tex` dari zip ke `symmetry-rev/paper/`. Gambar tidak berubah.
2. Compile di Overleaf. Hasil lokal saya: 27 halaman, 0 error, 0 overfull, 0 undefined.

Commit: `paper: clarify fdatasync tracing overhead and the session of the pool ablation`