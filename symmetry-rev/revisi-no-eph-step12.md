# revisi-no-eph-step12.md: samakan implementasi dengan protokol final (tanpa pseudonim)

Protokol final adalah halaman **"Final v3 (Npk_A in EAD_1, Npk_B in EAD_2)"** di `Symmetry_Journal.drawio`, yang dikirim bersama dokumen ini.

## Hasil pengecekan step 10 dan 11

- **Step 10:** sesuai. Kedua kalimat ("tracing overhead" dan "earlier session") sudah ada di `manuscript.tex`.
- **Step 11, bagian yang sudah sesuai dan dipertahankan:**
  - EAD_1 = Npk_A, dibuat sebelum Message1;
  - keygen DN-AAA sebelum Message2;
  - MAC_2 dan σ_R mencakup EAD_2;
  - Message3 tanpa EAD_3;
  - Message4 = AEAD(K_4, kosong);
  - tanpa grace key;
  - write-ahead NEXT di UE sebelum Message3;
  - commit DN-AAA sebelum Message4, lalu slot lama dinolkan.
- **Step 11, bagian yang tidak sesuai dengan protokol final:**
  1. **Pseudonim.** P_next di EAD_2, identitas EAP berupa NAI pseudonim, indeks pseudonim di DN-AAA, record versi 2 dengan pseudonim, `E4_ERR_PSEUDO`, dan NAI di UERANSIM. Protokol final **tidak memakai pseudonim**.
  2. **PT3 masih membawa ID_CRED_I.** Protokol final: **Plaintext3 = (MAC_3, VK_I, σ_I)**. ID_CRED_I sudah dikirim di PT1.
  3. **`Symmetry_Journal.drawio` diubah oleh Claude Code.** Ganti dengan file terlampir.
  4. **Model ProVerif v3 masih memuat pseudonim** (`P_test`, parameter `p` di event).

## 1. `edhoc4`

1. **EAD_2 = Npk_B saja.**
   - `E4_EAD2_LEN = 1 + E4_XWING_PK`.
   - Hapus `E4_EAD_PSEUDONYM`, `E4_PSEUDO_LEN`, `ctx->pnext`, dan parameter pseudonim di `ead2_build`.
   - Pengecekan parse EAD_2 menyesuaikan.
2. **PT3 = MAC_3 ‖ VK_I ‖ σ_I.**
   - `E4_PT3_LEN = E4_MAC_LEN + E4_MLDSA_PK + E4_MLDSA_SIG`.
   - Di `edhoc4_r_handle_msg3`, pakai `ctx->peer_id_cred` dari PT1 untuk MAC_3 dan σ_I. Perbandingan `id_i` dengan PT3 dihapus.
   - TH_4 = H(TH_3 ‖ PT3) tetap sama.
3. **Fungsi pseudonim dihapus:** `edhoc4_pseudo_to_nai`, `edhoc4_nai_to_pseudo`, dan `E4_ERR_PSEUDO`.

## 2. Record dan DN-AAA

1. **Payload record kembali menjadi `creds ‖ peer pk`** (tanpa pseudonim). Naikkan nomor versi format menjadi 3 agar record versi 2 ditolak dengan jelas. Tetap dua-slot.
2. **Pemilihan record per-UE kembali memakai identitas EAP** (RADIUS User-Name), yaitu `<db>/<identity>/rec.bin`, seperti step 6–9.
   - Hapus indeks pseudonim.
   - Identitas yang tidak dikenal ditolak dengan EAP-Failure.
   - (pk_A, VK_I) = Lookup(ID_CRED_I) setelah PT1 dibuka tetap berlaku, dan hasilnya harus cocok dengan record.
3. **Commit tetap seperti step 11:**
   - tulis slot tidak aktif (Nsk_B, Npk_B, pk_A := Npk_A, VK_I) + `fdatasync` sebelum Message4;
   - setelah Message4 dikirim, nolkan slot lama + `fdatasync` di luar jalur kritis.
4. **EMSK** diekspor dengan nama identitas EAP seperti sebelum step 11.

## 3. UE

1. **NEXT** = (Nsk_A, Npk_A, Npk_B), tanpa P_next. Identitas EAP tetap identitas yang dikonfigurasi.
2. **Aturan fallback.** Tanpa pseudonim, DN-AAA yang belum commit akan gagal membuka PT1 (AEAD) dan mengirim EAP-Failure.
   - Jika NEXT ada, sesi dimulai dengan NEXT.
   - Fallback ke CUR **hanya** jika UE menerima **EAP-Failure eksplisit** setelah Message1 dan sebelum Message2 terverifikasi. **Timeout tidak memicu fallback**, karena bisa jadi DN-AAA sudah commit dan pesannya hilang.
   - **NEXT jangan dihapus saat fallback.** NEXT baru boleh dibuang jika:
     - sesi dengan CUR selesai (Message4 terverifikasi), yang berarti DN-AAA tidak pernah commit NEXT; NEXT lama diganti NEXT baru dari sesi itu; atau
     - NEXT dipromosikan setelah sesi dengan NEXT sukses.
   - Jika NEXT dan CUR sama-sama ditolak, simpan keduanya, catat error, dan coba lagi di sesi berikutnya. EAP-Failure tidak terautentikasi, jadi Failure palsu hanya boleh menunda, tidak boleh menghapus kunci.
3. Write-ahead NEXT sebelum Message3, dan promosi setelah Message4 terverifikasi, tetap seperti step 11.

## 4. ProVerif

- Perbarui `gen_m4v3.py`:
  - EAD_2 hanya `npkB`;
  - PT3 tanpa ID_CRED_I;
  - event tanpa parameter pseudonim;
  - query `attacker(P_test)` dihapus.
- Generate ulang keenam model `edhoc_m4v3_*.pv` dan jalankan `run_all_v3.sh`.
- Hasil yang diharapkan sama dengan `SUMMARY_v3.txt` tanpa query P_test:
  - **classical, quantum:** reachability false, agreement M2/M3/M4 true, kerahasiaan ID_CRED_I, ID_CRED_R, app_data, MSK, dan EMSK true;
  - **kci, pcs:** true;
  - **fs_noerase:** kerahasiaan **false** (kontrol negatif);
  - **recovery:** true.
- Perbarui `README.md` dan `SUMMARY_v3.txt`. Jika ada hasil yang menyimpang, berhenti dan laporkan.

## 5. Test

1. **Selftest:** 2 UE × 5 run. MSK/EMSK sama di kedua sisi, setelah commit hanya ada satu sk_B, dan setelah promosi sk_A lama sudah terhapus.
2. **Injeksi kegagalan.** Di semua kasus berikut **tidak boleh ada re-provisioning**:

| Kasus | Hasil yang diharapkan di sesi berikutnya |
|---|---|
| Message3 di-drop | percobaan NEXT ditolak (EAP-Failure) → fallback ke CUR → sukses; NEXT lama diganti |
| Message4 di-drop | NEXT sukses |
| EAP-Success di-drop | normal (UE sudah commit setelah Message4) |
| UE crash setelah Message3 | NEXT sukses, atau fallback jika DN-AAA belum commit |
| DN-AAA crash setelah commit, sebelum Message4 | NEXT sukses |
| **Baru:** EAP-Failure palsu setelah Message1 padahal DN-AAA sudah commit | UE fallback ke CUR → ditolak → NEXT tetap disimpan → sesi berikutnya dengan NEXT sukses |
| **Baru:** timeout setelah Message1 | tidak ada fallback; percobaan berikutnya tetap memakai NEXT |

3. `edhoc4_xwing_kat`, `edhoc4_dbtest`, `edhoc4_selftest`, dan `edhoc03_selftest` harus PASS. Build ulang UERANSIM dan FreeRADIUS.

## 6. Benchmark

Dijalankan dalam satu sesi VM untuk ketujuh method, dengan skrip yang sama seperti step 11 (`run_series.sh`):

1. **Ukuran.** Perkiraan: Message1 2.358 B, Message2 sekitar 6.097 B (pseudonim 17 B dihapus), Message3 sekitar 3.756 B (ID_CRED_I 3 B dihapus), Message4 16 B, total 15 RT. Laporkan angka aktualnya.
2. **Model komputasi:** harus tetap 984.640 µs untuk method 4.
3. **In-process** (5 × 2000), **E2E** (2 run × 100 + 20 warm-up), **loss** (0–30%, 120 percobaan, Wilson dan Fisher), dan **storage ablation** (6 ronde bergantian).
4. **Uji pemulihan:** 150 handshake di loss 20%, ditambah 30 handshake sesudahnya. Hitung:
   - fallback (karena EAP-Failure eksplisit);
   - sesi yang pulih;
   - desync (harus 0);
   - re-provisioning (harus 0).
5. `rtt_projection.py`.

Catatan: di step 11, E2E proposal 7,171 ms dan EAP-TLS Hybrid 11,822 ms, keduanya naik dibanding sesi sebelumnya (5,836 / 9,734 ms). Laporkan bersama load VM, supaya jelas berapa yang berasal dari variasi VM dan berapa dari flush UE yang sekarang ada di jalur kritis.

## 7. Gambar, notebook, paper

- **Salin `Symmetry_Journal.drawio` terlampir** ke `symmetry-rev/figure/` (timpa versi step 11), dan **`img_SecondaryAuth2_v3.png`** ke `symmetry-rev/paper/`. **Jangan** mengedit atau mengekspor ulang drawio.
- Perbarui notebook dengan hasil §6, lalu render ulang gambar seperti di step 11 (`render_figures.py`).
- **Jangan ubah `manuscript.tex`.** Saya yang akan menulis teks paper dan memperbarui deck dari laporan.

## Commit (terpisah)

1. `edhoc4: final v3 protocol without pseudonym; PT3 = (MAC_3, VK_I, sigma_I)`
2. `dn-aaa/ue: record by EAP identity; fallback only on explicit EAP-Failure, NEXT kept`
3. `proverif: m4v3 models without pseudonym`
4. `test: failure-injection incl. forged EAP-Failure and timeout`
5. `bench: re-run all methods with the final v3 protocol`
6. `figure/notebook: approved v3 diagram and re-rendered plots`

## Laporan balik

Kirimkan:
- tabel ProVerif;
- ukuran pesan, fragmen, dan n_RT;
- E2E mean/median ketujuh method;
- loss 20/30% beserta Fisher;
- in-process;
- storage;
- hasil uji pemulihan;
- status semua test;
- daftar hal yang menyimpang dari dokumen ini.