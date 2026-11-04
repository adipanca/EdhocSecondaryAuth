Median 2,84 ms di full stack v4 dan v4b, padahal 0,70 ms di step 17 dan 1,14–1,37 ms di step 19–20. **Bukan flush tambahan dan bukan indeks KeyID:** nilainya sama sebelum dan sesudah indeks dipindah ke memori, sedangkan `aaa_commit_ms` turun dari 2,81 ke 0,58 ms.

- **Jalur tulis tidak berubah.** `strace -f -T -P ue.rec` pada `nr-ue` (25 sesi): tiap NEXT adalah satu `pwrite64` 12.288 B dan satu `fdatasync`, pada file record yang sama. Tidak ada flush yang bisa dihapus.
- **Waktunya ada di dalam `fdatasync`, dan bimodal:** NEXT lambat (> 1,5 ms) di 21 dari 30 flush, promosi pada file yang sama di 0 dari 30.
- **Bukan MongoDB:** tidak ada satu pun flush NEXT yang bertumpang-tindih dengan flush `mongod` (0 dari 30, jam yang sama).
- **Penyebab: flush pertama setelah disk menganggur.** Di trace, NEXT didahului jeda median 675 ms sejak flush terakhir (flush 2,91 ms), promosi hanya 37 ms (flush 0,61 ms). `benchmark/fsync_idle_probe.py`, tanpa protokol sama sekali, menunjukkan hal yang sama pada disk ini: median 0,60–0,68 ms setelah jeda 0–5 ms, 1,03 ms setelah 100 ms, 2,10 ms setelah 200 ms, 3,00 ms setelah 500 ms (`v4b-fsync-idle-probe.txt`).
- **Mengapa harness tidak terkena:** handshake harness berurutan tanpa jeda, jadi flush UE tetap sekitar 0,69 ms per panggilan (`storage-strace-v4b.txt`). Full stack memberi jeda antar-sesi (release + 200 ms).

Jadi 2,84 ms adalah biaya disk VM setelah menganggur akibat pola sesi benchmark, bukan biaya protokol. Perbedaan dengan step 17 dan 19–20 belum diuji langsung: di step 17 secondary auth berjalan setelah Accept, sehingga ada flush lain tepat sebelumnya (cocok dengan penjelasan ini, tetapi tidak diukur); step 19–20 berjalan di sesi VM lain.
