# revisi-no-eph-step6.md — Optimasi penyimpanan kunci (branch `symmetry-no-eph`)

**Tujuan:** memangkas biaya penyimpanan kunci 7,9 ms tanpa mengurangi keamanan (forward secrecy tetap berbasis rotasi + penghapusan) dan tanpa mengubah protokol, pesan, atau model ProVerif.

## 0. Kondisi sekarang (commit `6e9efa32`)

| Pihak | Yang terjadi per handshake | Di jalur waktu handshake? |
|---|---|---|
| UE (`e2e_radius_bench.c` `commit_creds`, UERANSIM) | tulis `ue.creds` dan `server.pub`, masing-masing tmp + `fsync` + rename → **2 `fsync`** | **Ya**: dipanggil sebelum ACK terakhir |
| DN-AAA (`edhoc4_db_commit`) | record aktif dipindah ke `prev/`, `server.creds` + `ue.pub` baru via tmp + `fsync` + rename → **2 `fsync`** | Ya (sebelum Message4, wajib) |
| DN-AAA (`handle_one` di Message1) | `wipe_prev`: overwrite + **2 `fdatasync`** | **Ya**, di jalur Message1 |

Hasil ukur: 13,223 ms (disk), 5,314 ms (tmpfs), jadi penyimpanan menambah 7,9 ms. Optimasi opsional dari step 3 belum diterapkan.

## 1. Desain tercepat yang tetap aman: record dua-slot, satu flush

Prinsip: per handshake cukup **satu** `fdatasync` di DN-AAA (wajib, write-ahead sebelum Message4) dan **nol** di jalur handshake UE.

### 1.1 Format file record (DN-AAA dan UE sama)

Satu file per record, ukuran tetap, dialokasikan sekali saat provisioning (`posix_fallocate`), berisi dua slot:

```
header (32 B): magic "E4R2", version=1, slot_size
slot[0], slot[1] (masing-masing):
    u64  seq            // naik setiap commit
    u32  len
    u8   payload[...]   // DN-AAA: edhoc4_creds(server) || pk_A
                        // UE:     edhoc4_creds(ue)     || pk_B
    u8   tag[32]        // HMAC-SHA256(k_rec, seq||len||payload) atau SHA-256
```

- DN-AAA: `edhoc_db/<identity>/rec.bin`. File `ue.vk` dan `id_cred` tetap terpisah karena tidak berotasi.
- UE: `ue.rec`, menggantikan `ue.creds` dan `server.pub`.

Aturan baca:
- Muat kedua slot dan cek tag-nya.
- **Aktif** = slot valid dengan `seq` tertinggi; **prev (grace key)** = slot valid lainnya.
- Slot yang rusak (torn write) diabaikan, sehingga crash di tengah penulisan selalu menyisakan slot lama yang utuh.

### 1.2 DN-AAA (`edhoc4_db.c`)

- **Commit** (setelah Message3 valid, sebelum Message4):
  1. Tulis state baru (Nsk_B, Npk_B, Npk_A) ke slot **non-aktif** dengan `seq = seq_aktif + 1` lewat `pwrite`.
  2. **Satu `fdatasync(fd)`.** Tidak ada `rename`, `mkdir`, atau fsync direktori, karena file sudah dialokasikan dan ukurannya tidak berubah.
  3. Slot lama otomatis menjadi prev (grace key). Slot "prev sebelumnya" tertimpa oleh tulisan ini, jadi penghapusannya terjadi di dalam flush yang sama.
- **Message1, UE terbukti sudah berotasi** (dekripsi berhasil dengan slot aktif):
  - Timpa slot prev dengan nol (`pwrite`) **tanpa `fdatasync`**.
  - Data ini ikut ter-flush oleh `fdatasync` commit di akhir sesi yang sama, karena berada di file yang sama.
  - Hasilnya: 2 `fdatasync` hilang dari jalur Message1.
- **Message1 hanya berhasil dengan slot prev** (Message4 sebelumnya hilang):
  - Salin isi prev ke slot non-prev dengan `seq` lebih tinggi, lalu `fdatasync`.
  - Ini jalur langka, jadi biaya flush di sini tidak masalah.
- `flock` tetap dipakai.
- Hapus `prev/`, `server.creds`, dan `ue.pub` lama. Sediakan migrasi satu kali di `keygen`/`setup_no_eph.sh`.

### 1.3 UE (`e2e_radius_bench.c`, UERANSIM `transport.cpp`)

- Pindahkan `commit_creds()` / `edhoc4_commit` + simpan ke **setelah EAP-Success diterima**, bukan sebelum ACK terakhir.
  - Aman: UE baru butuh kunci baru di sesi berikutnya.
  - Jika UE crash sebelum commit, UE tetap memakai kunci lama, dan grace key (prev) di DN-AAA menerimanya.
- UE juga memakai record dua-slot dengan **satu `fdatasync`**.
- Di benchmark, catat `ue_commit_ms` terpisah sebagai kolom baru di CSV. **`duration_ms` berhenti saat EAP-Success diterima**, konsisten dengan EAP-TLS yang selesai di EAP-Success.

### 1.4 Keamanan (tidak berubah)

- Pesan, key schedule, dan model ProVerif tidak berubah, karena model mengabstraksi rotasi yang selesai.
- Forward secrecy: kunci lama ditimpa di file yang sama dan ter-flush di commit berikutnya. Jeda tunda FS tetap "satu sesi", sama seperti kebijakan grace key yang sudah tertulis di paper.
- Write-ahead DN-AAA tetap dipertahankan: record baru durable sebelum Message4 dikirim. Ini tidak boleh dihilangkan, karena tanpanya crash bisa menyebabkan desync permanen.
- Catatan jujur untuk paper: overwrite di SSD/FTL tidak menjamin penghapusan fisik. Batasan ini sama dengan implementasi sekarang.

## 2. Pengujian

1. `edhoc4_dbtest` / `selftest`:
   - 2 UE × 5 sesi;
   - simulasi Message4 hilang (grace path);
   - simulasi torn write (rusakkan tag slot terbaru → harus jatuh ke slot lama);
   - pastikan slot prev berisi nol setelah sesi berikutnya.
2. `strace -c -f -e trace=fsync,fdatasync`, 20 handshake. Target:
   - DN-AAA **1 `fdatasync`** per handshake (sebelumnya 2 `fsync` + 2 `fdatasync`);
   - UE 1 `fdatasync`, **di luar** `duration_ms`.
3. Benchmark di mesin idle (`sudo ./setup_no_eph.sh` lalu `./run_e2e_benchmarks.sh`):
   - method 0–6 durable;
   - method 4 tmpfs, sebagai pembanding batas bawah.
   - Simpan sebagai `e2e-handshake.csv` dan `e2e-handshake-tmpfs.csv`, plus lossy.
4. Estimasi sebelum diukur (**jangan dikutip, ukur dulu**): sekitar 5,3 ms + 1 flush (~1,3 ms di VM) ≈ 6,5–7 ms, di bawah EAP-TLS Hybrid PQC (9,696 ms).

## 3. Update paper dan notebook setelah diukur

- §Performance "Two costs drive the gap": angka baru, jumlah flush (DN-AAA 1 `fdatasync`, write-ahead; UE di luar jalur), dan nilai durable vs tmpfs.
- Kalimat perbandingan dengan EAP-TLS Hybrid PQC: jika durable < 9,696 ms, tulis bahwa proposal lebih cepat bahkan di loopback. Hitung ulang titik impas RTT: `(T_prop − T_tls) / (28 − 14)`. Jika hasilnya negatif, tulis "faster at every RTT".
- Tabel RTT (`tab:rtt-projection`), Discussion, Conclusion, abstract (jika menyebut storage), notebook (`e2e_*`, `EDHOC_HANDSHAKE_MEAN_MS`), lalu regenerate PNG.
- Tambahkan satu kalimat desain di §Handshake/Implementation: *"Each party keeps its record in a preallocated two-slot file; a commit writes the inactive slot and issues a single fdatasync, so the previous slot serves as the grace key and is overwritten by the next commit."*

Commit:
- `edhoc4: two-slot key record, one flush per commit; UE commit after EAP-Success`
- `bench: e2e re-run with two-slot storage`
- `paper/notebook: storage-optimised results`