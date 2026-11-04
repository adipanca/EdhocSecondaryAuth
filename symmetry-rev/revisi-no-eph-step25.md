# revisi-no-eph-step25.md: lookup record lewat H(pk_B) (saran Dr. Shin) dan identitas EAP anonim

## Latar belakang

DN-AAA sekarang memilih record per UE dari identitas EAP (`ue1@edhoc.internet`). Identitas itu terkirim terbuka dan sama di setiap sesi, sehingga semua sesi milik satu UE bisa dikaitkan.

Dr. Shin menyarankan agar Message1 membawa H(pk_B). DN-AAA lalu mencari record lewat H(pk_B), dan identitas EAP bisa dibuat anonim. Karena pk_B dirotasi setiap run yang berhasil, H(pk_B) juga selalu baru.

**Protokol ini kita sebut v4.** Yang tidak berubah: rotasi lewat EAD_1/EAD_2, Message4 kosong, urutan penulisan (write-ahead NEXT, commit sebelum Message4), aturan fallback, dan kriptografi.

## 0. Perubahan protokol (v3 → v4)

Saya memakai notasi KID_B untuk H(pk_B).

```
KID_B      = SHA-256(pk_B)                         (32 B, hash suite EDHOC)
Plaintext1 = (Method, Suites_I, ID_CRED_I, C_I, EAD_1, KID_B)
Message1   = (KID_B, ct_B, AEAD.Enc(K_1, Plaintext1))
TH_1       = H(ct_B)                               (tidak berubah)
TH_2       = H(H(Message1), ct_A)                  (H(Message1) sekarang mencakup KID_B)
```

**DN-AAA:**
1. Ambil KID_B dari bagian terbuka Message1.
2. Cari record dengan KID_B. Jika tidak ditemukan, kirim EAP-Failure **tanpa operasi KEM**.
3. Decaps ct_B dengan sk_B dari record itu, lalu buka Plaintext1.
4. **Wajib** cek, dengan perbandingan waktu-konstan:
   - Plaintext1.KID_B == KID_B terbuka;
   - KID_B == SHA-256(pk_B record).
   Jika tidak cocok, tolak.
5. `Lookup(ID_CRED_I)` tetap dicocokkan dengan record, seperti sekarang.

**Ukuran:** Message1 bertambah 64 B, dari 2.358 menjadi sekitar **2.422 B**. Laporkan jumlah fragmen EAP yang terukur; seharusnya tetap 3.

## 1. Library `edhoc4/`

1. Tambahkan `E4_KID_LEN 32` dan helper `edhoc4_kid(const uint8_t pk[E4_XWING_PK], uint8_t kid[32])`.
2. **`edhoc4_i_make_msg1`:**
   - layout menjadi `KID_B[32] ‖ ct_B[1120] ‖ AEAD(K1, PT1)`;
   - `PT1 = method ‖ C_I ‖ ID_CRED_I ‖ EAD_1 ‖ KID_B`, sehingga `E4_PT1_LEN` bertambah 32;
   - KID_B dihitung dari `peer_kem_pk` yang sedang dipakai UE (pk_B dari CUR, atau Npk_B dari NEXT).
3. **Fungsi baru `edhoc4_r_peek_kid(const uint8_t *in, size_t in_len, uint8_t kid[32])`:** mengambil KID_B terbuka **sebelum** record dipilih, tanpa operasi kripto.
4. **`edhoc4_r_handle_msg1`:**
   - parsing layout baru;
   - cek kedua kesamaan KID_B di atas dengan `sodium_memcmp`;
   - kode error baru `E4_ERR_KID`.
5. Perbarui komentar layout dan `edhoc_sizes.py` (model ukuran) agar sama dengan layout live.

## 2. Record DN-AAA: indeks KID (`edhoc4_db.c/.h`)

1. **Folder record diberi nama ID record internal** (misalnya `ue1`), bukan identitas EAP. Folder ini **tidak** ditentukan oleh pesan dari jaringan.
2. **Indeks baru `<root>/kid/<hex(KID_B)>`:** file kecil berisi nama folder record, ditulis lewat file sementara + `rename` + `fsync` direktori.
3. **API:**
   - ganti `edhoc4_db_handle_msg1(root, identity, …)` menjadi `edhoc4_db_handle_msg1(root, …)`. Fungsi ini mengambil KID_B dengan `edhoc4_r_peek_kid`, membaca indeks, membuka record, lalu memilih **slot yang SHA-256(pk_B)-nya sama dengan KID_B**;
   - indeks hanya petunjuk: jika folder atau slotnya tidak cocok, perlakukan sebagai KID tidak dikenal (`E4_ERR_PEER`) dan hapus entri basi itu.
4. **`edhoc4_db_commit`:**
   1. tulis slot baru + `fdatasync` (seperti sekarang);
   2. **setelah itu** buat entri indeks untuk SHA-256(Npk_B);
   3. keduanya harus selesai sebelum Message4.
5. **`edhoc4_db_erase_old`:** nolkan slot lama, lalu hapus entri indeks SHA-256(pk_B lama).
6. **Crash di antara commit dan erase:** kedua slot dan kedua entri indeks tetap valid. Message1 berikutnya membersihkan yang lebih tua, seperti sekarang.
7. **Semua operasi indeks** di bawah `flock(<root>/kid/.lock)`, ditambah lock record yang sudah ada.
8. **`keygen.c` / `provision`:**
   - buat entri indeks untuk pk_B awal;
   - tambahkan skrip migrasi untuk record lama: ganti nama folder dari identitas ke ID internal, lalu buat entri indeksnya.

**Sisi UE tidak berubah:** `ue.rec` dengan CUR/NEXT. Fallback tetap hanya pada EAP-Failure eksplisit, dan NEXT tetap disimpan.

## 3. FreeRADIUS `rlm_eap_edhoc`

1. **Method 4 tidak lagi memakai `handler->identity` / User-Name untuk memilih record.** Hapus kode itu dan komentar "EAP identity selects the record".
2. **Identitas EAP luar** hanya dicek bentuknya: NAI anonim `@edhoc.internet` atau `anonymous@edhoc.internet` (RFC 7542 §2.4). Pakai realm untuk routing jika perlu.
3. **Ekspor EMSK** (`edhoc_export_emsk`): ganti nama file dari `<identity>.emsk.hex` menjadi `<record_id>.emsk.hex`. Sesuaikan `bootstrap/aaa_keyexport.py` dan skrip bootstrap.
4. **Method 0–3 tidak berubah** dan tetap memakai mekanismenya sekarang.

## 4. UE dan harness

1. **UERANSIM:** `config/open5gs-ue.yaml` → `secondaryAuth.identity: '@edhoc.internet'`. Kode EAP identity tidak perlu berubah.
2. **`e2e_radius_bench`:** method 4 mengirim identitas anonim yang sama.
3. **Pastikan identitas khusus DN dan SUPI tidak muncul** di RADIUS User-Name maupun di EAP-Response/Identity. Cek dengan `grep` di log dan capture.

## 5. Test

Tambahkan ke `selftest` / `dbtest`. Semua harus PASS:

| Test | Harapan |
|---|---|
| KID_B terbuka ≠ KID_B di Plaintext1 | ditolak (`E4_ERR_KID`) |
| KID_B ≠ SHA-256(pk_B) record (indeks diarahkan ke record lain) | ditolak |
| KID_B tidak dikenal | `E4_ERR_PEER`, tanpa Decaps |
| Run normal | entri indeks Npk_B dibuat saat commit; entri pk_B lama hilang setelah erase_old |
| Message3 hilang | UE di NEXT mengirim H(Npk_B), tidak dikenal → EAP-Failure → fallback CUR dengan H(pk_B) lama → sukses |
| Message4 hilang | H(Npk_B) sudah ada di indeks → sukses |
| Crash di antara commit dan erase_old | kedua KID ditemukan; Message1 berikutnya membersihkan yang lama |
| EAP-Failure palsu atau timeout | perilaku sama seperti step 12 (NEXT tetap) |
| 100 UE, semua dengan identitas `@edhoc.internet`, dijalankan bergantian dan paralel | semua memilih record yang benar, 0 tertukar |

Jalankan juga `edhoc4_xwing_kat` dan `edhoc03_selftest`.

## 6. ProVerif (`symmetry-rev/proverif/`)

1. **`gen_m4v4.py`** dari `gen_m4v3.py`. Buat versi v4 untuk keenam model: `classical`, `quantum`, `kci`, `pcs`, `fs_noerase`, `recovery`.
   - **UE:** `let kidB = H(pk2b(pkB)) in`, PT1 ditambah `kidB`, dan `Message1 = (kidB, ctB, AEAD_enc(K1, PT1))`.
   - **DN:** jangan lagi menerima (sk_B, pk_A) sebagai argumen proses. Ambil dari tabel:
     ```
     table recs(bitstring, kemsk, exponent, xpk).
     ... in(c, (kidB:bitstring, ctB:bitstring, encP1:bitstring));
         get recs(=kidB, B_pq, B_x, pkA) in ...
         ... let (=M_4, =SuitesI, claimedI, =CI, EAD1, =kidB) = AEAD_dec(K1, encP1) in
     ```
   - **Proses utama:** setelah membuat pasangan kunci per run, lakukan `insert recs(H(pk2b(pkB)), B_pq, B_x, pkA)`.
   - **`pcs` dan `recovery`:** entri tabel untuk kunci berikutnya dibuat saat commit DN, sama seperti alur implementasi.
2. **Query Q1–Q11 tetap.** Hasil yang diharapkan sama dengan v3, termasuk negative control: Q5–Q9 gagal di `fs_noerase`.
3. **Query baru, opsional tetapi diinginkan:** model `edhoc_m4v4_unlink.pv` dengan `choice[]` (diff-equivalence). Skenario kiri: dua run berturut-turut dari **UE yang sama**, dengan run kedua memakai kunci hasil rotasi. Skenario kanan: dua run dari **dua UE berbeda**. Identitas luar anonim di kedua skenario.
   - Jika ProVerif membuktikan ekuivalensi, laporkan sebagai bukti *unlinkability* antar run yang berhasil.
   - Jika ProVerif tidak bisa membuktikan (false attack sering muncul pada diff-equivalence), laporkan apa adanya dan **jangan** klaim properti itu.
4. **`run_all_v4.sh`** menjalankan semua model dan menyimpan output ke `results/v4/`. Ringkasannya ditulis di `SUMMARY_v4`.

## 7. Pengukuran ulang

Message1 berubah, jadi angka yang memakai ukuran pesan harus diukur ulang:
1. **Harness RADIUS:** method 4 **dan** EAP-TLS Hybrid PQC dalam **sesi pengukuran yang sama**, 200 handshake loss-free. Perbarui `e2e-handshake.csv`; file lama disimpan dengan akhiran `-v3`.
2. **Ukuran dan fragmentasi:** `mtu-fragmentation.csv` dan gambar `img_communication_breakdown_methods.png`. Model ukuran harus sama dengan live.
3. **Full stack:** A/B 3 × 100 dan pemulihan 10 + 10, dengan prosedur yang sama seperti step 20–21, dan identitas `@edhoc.internet`. File baru diberi akhiran `-v4`.
4. **Uji loss:** cukup jalankan ulang hanya jika jumlah fragmen atau round-trip berubah. Jika tetap 15 RT, tulis alasannya di `analisys2.md` dan jangan ulangi.

## Commit

1. `edhoc4: KID_B = H(pk_B) in message_1 and plaintext_1 (v4)`
2. `db: KID index for DN-AAA records, record directories by internal id`
3. `freeradius: select method-4 record by KID, anonymous outer identity, EMSK export by record id`
4. `ue/bench: anonymous NAI @edhoc.internet`
5. `tests: KID mismatch, unknown KID, index across commit/erase/crash, 100 anonymous UEs`
6. `proverif: v4 models with KID table lookup, unlinkability model`
7. `bench: v4 sizes, harness E2E, full stack and recovery`

## Laporan balik

Kirimkan:
- ukuran Message1–4, jumlah fragmen dan RT;
- hasil semua test;
- ringkasan ProVerif v4 (Q1–Q11 di keenam model, ditambah hasil unlinkability);
- E2E harness (mean/median, proposal vs EAP-TLS Hybrid);
- tabel full stack dan pemulihan;
- bukti bahwa SUPI dan identitas DN tidak muncul di RADIUS dan EAP (hasil grep log/capture);
- hash commit.

Diagram protokol dan paper akan saya perbarui setelah hasil ini masuk.