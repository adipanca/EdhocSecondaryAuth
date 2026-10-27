# revisi-no-eph-step3.md — Perbaikan setelah review (branch `symmetry-no-eph`)

Kode, ProVerif, notebook, dan gambar sudah konsisten. File ini hanya berisi tiga perbaikan agar klaim di paper berbasis pengukuran, bukan estimasi.

## 1. ProVerif: ganti fs_noerase dengan versi ringan

`symmetry-rev/proverif/edhoc_m4v2_fs_noerase.pv` versi ringan (lampiran, tanpa Q2–Q4) menggantikan versi yang ada, di `proverif/` dan `symmetry-rev/proverif/`.
- Q2–Q4 dibuang karena kunci tambahan baru bocor di phase 1, setelah semua event autentikasi phase 0. Hasilnya pasti sama dengan model classical.
- Jalankan, lalu perbarui `SUMMARY_v2.txt`. Harapan: q1–q3 false (reachable) dan Q5, Q5b, Q6–Q9 false.

Di paper (§Formal verification), hapus kalimat:

> "(The authentication queries Q2--Q4 of the negative control did not terminate … key-rotation models.)"

Ganti dengan:

> "The negative control queries only secrecy: its extra keys leak in phase 1, after every authentication event, so its Q2--Q4 coincide with those of the classical model."

## 2. Ukur biaya penyimpanan kunci (ablation), jangan diestimasi

Paper sekarang menulis "roughly 7 ms" (estimasi) dan "without the estimated 7 ms … it would be the faster of the two" (klaim yang belum diukur). Ukur langsung dengan dua konfigurasi pada **mesin yang idle**: tidak ada ProVerif atau proses berat lain yang berjalan. Run sebelumnya kemungkinan berjalan bersamaan dengan ProVerif; method 0–3 punya outlier sampai 30 ms.

```bash
# A. durable (seperti sekarang): edhoc_db dan direktori UE di disk VM
sudo benchmark/setup_no_eph.sh
LABEL=durable ./run_e2e_benchmarks.sh            # TIMING_ITERS=100, method 0-4 + EAP-TLS

# B. storage tanpa biaya flush: direktori kunci yang sama di tmpfs
sudo mount -t tmpfs -o size=64m,mode=0755 tmpfs /usr/local/etc/edhoc
sudo benchmark/setup_no_eph.sh                   # provisioning ulang ke tmpfs
LABEL=tmpfs ./run_e2e_benchmarks.sh              # cukup method 4 (timing + lossy)
sudo umount /usr/local/etc/edhoc && sudo benchmark/setup_no_eph.sh
```

Catatan:
- `fsync`/`fdatasync` di tmpfs praktis gratis. Selisih A − B adalah biaya penyimpanan yang **terukur**.
- Juga catat jumlah flush per handshake di sisi UE dan DN-AAA, misalnya dengan `strace -c -f -e trace=fsync,fdatasync -p <radiusd pid>` selama 20 handshake.

Laporkan untuk method 4 di A dan B: mean, median, p95, initiator_ms, responder_ms.

Opsi tambahan (boleh dikerjakan, sebutkan di paper bila dipakai):
- **UE:** `commit_creds()` saat ini dipanggil sebelum ACK terakhir, sehingga masuk ke waktu handshake. Pindahkan ke **setelah EAP-Success**. Ini aman: UE baru membutuhkan kunci baru pada sesi berikutnya, dan jika commit gagal, grace key DN-AAA menyinkronkan ulang.
- **DN-AAA:** urutan sekarang sudah benar dan wajib dipertahankan. Record baru di-`fsync` **sebelum** Message4 dikirim (write-ahead); jika tidak, crash bisa menyebabkan desync permanen. Penghapusan `prev/` (overwrite + `fdatasync`) di jalur Message1 bisa dipindah keluar dari jalur request, misalnya ke thread atau handler setelah reply.
- Satukan `server.creds` + `ue.pub` dalam satu file record, sehingga satu fsync menggantikan dua.

## 3. Update paper dengan angka terukur

- **§Performance (baris "Two costs drive the gap"):** ganti "roughly 7 ms / about 1.2–1.5 ms per flush" dengan selisih A − B terukur dan jumlah flush dari strace.
- **Kalimat** "without the estimated 7 ms of storage flushes it would be the faster of the two": tulis ulang berdasarkan B. Jika B < 10.066 ms, klaim ini boleh tetap dengan angka B. Jika tidak, hapus.
- **Discussion (baris ~775) dan Conclusion:** samakan angka penyimpanan.
- **Jika E2E diulang pada mesin idle:** perbarui semua angka E2E (method 0–6, loss), notebook (`e2e_*`, `EDHOC_HANDSHAKE_MEAN_MS`), dan regenerate PNG.
- Hapus komentar sisa di baris 68: `% Values that must be re-measured on the testbed for the revised protocol.`
- Samakan pembulatan method 3: teks 0.956 ms, gambar 0.957 ms.

Commit: `bench: storage ablation (durable vs tmpfs)` lalu `paper: measured storage cost, light fs_noerase`.