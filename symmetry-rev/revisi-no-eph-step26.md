# revisi-no-eph-step26.md: protokol v4, KeyID_B = H(pk_B) terbuka dan terikat sebagai AAD (Dr. Shin + Prof. You)

**Step ini menggantikan step 25.** Bagian step 25 yang sudah selesai boleh dipakai lagi; yang berubah hanya format Message1, TH_1, dan model ProVerif. Bagian 7 menjelaskan apa yang tetap dan apa yang perlu diubah.

Diagram acuan: halaman pertama `Symmetry_Journal.drawio` terlampir, "Final v4 (KeyID_B = H(pk_B) in Message1, AAD-bound)".

Yang **tidak** berubah: rotasi lewat EAD_1/EAD_2, Message4 kosong, urutan tulis (write-ahead NEXT, commit sebelum Message4), aturan fallback, Message2–4, dan semua kriptografi lainnya.

## 0. Spesifikasi v4 (usulan Prof. You)

```
UE
  (ss_B, ct_B) = X-WING.Encaps(pk_B)
  KeyID_B      = SHA-256(pk_B)                           (32 B)
  Plaintext1   = (Method, Suites_I, ID_CRED_I, C_I, EAD_1)  (TIDAK berubah dari v3)
  TH_1         = SHA-256(pk_B ‖ ct_B)                    (sebelumnya SHA-256(ct_B))
  PRK_1e       = HKDF-Extract(TH_1, ss_B);  K_1 = HKDF-Expand(PRK_1e, TH_1)
  AAD_1        = KeyID_B ‖ ct_B                           (panjang tetap, 32 + 1120 B)
  Message1     = KeyID_B ‖ ct_B ‖ AEAD.Enc(K_1, AAD_1, Plaintext1)

DN-AAA
  1. ambil KeyID_B (32 B pertama), lalu Lookup(KeyID_B) → (sk_B, pk_B, pk_A, VK_I)
     tidak ditemukan → EAP-Failure, TANPA Decaps
  2. Verify KeyID_B == SHA-256(pk_B)   (sodium_memcmp)
  3. ss_B = Decaps(ct_B, sk_B); TH_1 = SHA-256(pk_B ‖ ct_B); K_1
  4. Plaintext1 = AEAD.Dec(K_1, AAD_1 = KeyID_B ‖ ct_B, …)   gagal → tolak
  5. Verify ID_CRED_I cocok dengan record
TH_2 = H(H(Message1), ct_A)   (tidak berubah; H(Message1) kini mencakup KeyID_B)
```

**Ukuran:** Message1 bertambah tepat **32 B**, dari 2.358 menjadi **2.390 B**. Laporkan jumlah fragmen yang terukur; seharusnya tetap 3.

## 1. Library `edhoc4/`

1. Tambahkan konstanta `E4_KEYID_LEN 32` dan helper `edhoc4_keyid(pk, out)` (SHA-256 dari pk).
2. **AEAD dengan AAD eksplisit:** tambahkan `aead_seal_aad(prk, th, aad, aad_len, pt, …)` dan `aead_open_aad(…)`. Kunci dan nonce tetap diturunkan dari (PRK, TH), seperti `derive_k`. Hanya **Message1** yang memakai AAD_1. Message2 dan Message3 tetap memakai `aead_seal`/`aead_open` yang sekarang (AAD = TH).
3. **`edhoc4_i_make_msg1`:**
   - `TH_1 = SHA-256(peer_kem_pk ‖ ct_B)`;
   - `AAD_1 = KeyID_B ‖ ct_B`;
   - layout `KeyID_B[32] ‖ ct_B[1120] ‖ AEAD`;
   - `E4_PT1_LEN` **tidak berubah**;
   - `h_msg1` dihitung dari seluruh Message1 yang baru.
4. **`edhoc4_r_peek_keyid(in, in_len, out)`:** mengambil KeyID_B tanpa operasi kripto.
5. **`edhoc4_r_handle_msg1`:**
   - langkah 2–4 dari spesifikasi di atas;
   - kode error baru `E4_ERR_KEYID` untuk KeyID_B ≠ SHA-256(pk_B);
   - kegagalan AEAD tetap `E4_ERR_AEAD`.
6. Perbarui komentar layout di kode dan `edhoc_sizes.py`.

## 2. Record DN-AAA dan indeks KeyID (sama dengan step 25 §2)

- Folder record diberi nama ID internal, bukan identitas EAP.
- Indeks `<root>/kid/<hex(KeyID_B)>` berisi nama folder record. Ditulis lewat file sementara + `rename` + `fsync` direktori, di bawah `flock`.
- `edhoc4_db_handle_msg1(root, …)` tanpa parameter identity:
  - pilih record lewat indeks, lalu slot yang SHA-256(pk_B)-nya sama dengan KeyID_B;
  - entri indeks yang basi dihapus dan diperlakukan sebagai "tidak dikenal".
- **`commit`:** tulis slot baru + `fdatasync`, **lalu** tambahkan entri SHA-256(Npk_B), semuanya sebelum Message4.
- **`erase_old`:** nolkan slot lama, lalu hapus entri SHA-256(pk_B lama).
- **`keygen`/`provision`:** buat entri untuk pk_B awal. Tambahkan skrip migrasi untuk record lama.

## 3. FreeRADIUS, UE dan harness (sama dengan step 25 §3–4)

- **`rlm_eap_edhoc` method 4:** record tidak lagi dipilih dari `handler->identity` atau User-Name. Identitas luar hanya dicek bentuknya, `@edhoc.internet` atau `anonymous@edhoc.internet` (RFC 7542 §2.4).
- **Ekspor EMSK:** `<record_id>.emsk.hex`. Sesuaikan `bootstrap/aaa_keyexport.py`.
- **UERANSIM:** `secondaryAuth.identity: '@edhoc.internet'`. `e2e_radius_bench` method 4 memakai identitas yang sama.
- **Method 0–3:** tidak berubah.

## 4. Test (wajib PASS)

| Test | Harapan |
|---|---|
| KeyID_B diubah 1 bit (masih menunjuk record yang sama lewat indeks palsu) | `E4_ERR_KEYID` |
| ct_B diubah 1 bit | `E4_ERR_AEAD` (AAD + TH_1) |
| KeyID_B dan ct_B ditukar dengan milik sesi lain | ditolak |
| Ciphertext1 diubah | `E4_ERR_AEAD` |
| KeyID_B tidak dikenal | `E4_ERR_PEER`, tanpa Decaps (cek dengan counter atau log) |
| Run normal | entri Npk_B dibuat saat commit; entri pk_B lama hilang setelah erase_old |
| Message3 hilang | UE di NEXT mengirim H(Npk_B), tidak dikenal → EAP-Failure → fallback CUR → sukses |
| Message4 hilang | H(Npk_B) ada di indeks → sukses |
| Crash di antara commit dan erase_old | kedua KeyID ditemukan; Message1 berikutnya membersihkan yang lama |
| EAP-Failure palsu atau timeout | NEXT tetap disimpan (seperti step 12) |
| 100 UE, semua `@edhoc.internet`, bergantian dan paralel | 0 record tertukar |
| Vektor uji Message1 | layout dan ukuran 2.390 B sama dengan `edhoc_sizes.py` |

Jalankan juga `edhoc4_xwing_kat` dan `edhoc03_selftest`.

## 5. ProVerif v4 (`gen_m4v4.py`, termasuk perbaikan model yang berat)

1. **AEAD dengan AAD**, khusus Message1:
   ```
   fun AEAD_enc_aad(key, bitstring, bitstring): bitstring.
   reduc forall k:key, a:bitstring, m:bitstring;
         AEAD_dec_aad(k, a, AEAD_enc_aad(k, a, m)) = m.
   ```
   AEAD untuk Message2–4 tetap seperti v3.
2. **UE:**
   ```
   let kidB = H(xpk2b(pkB)) in
   let TH1  = H((xpk2b(pkB), ctB)) in
   let K1   = expands(extract(TH1, ssB), TH1) in
   let PT1  = (M_4, SuitesI, ID_CREDI, CI, EAD1) in
   let Message1 = (kidB, ctB, AEAD_enc_aad(K1, (kidB, ctB), PT1)) in
   ```
3. **DN** mengambil kunci dari tabel, tidak lagi dari argumen proses:
   ```
   table recs(bitstring, kemsk, exponent, xpk).
   in(c, (kidB:bitstring, ctB:bitstring, encP1:bitstring));
   get recs(=kidB, B_pq, B_x, pkA) in
   let pkB = xwpk(B_pq, B_x) in
   if kidB = H(xpk2b(pkB)) then
   let ssB = xw_decaps(B_pq, B_x, ctB) in
   let TH1 = H((xpk2b(pkB), ctB)) in
   ...
   let (=M_4, =SuitesI, claimedI:bitstring, =CI, EAD1:bitstring)
       = AEAD_dec_aad(K1, (kidB, ctB), encP1) in
   ```
   - **Proses utama:** `insert recs(H(xpk2b(pkB)), B_pq, B_x, pkA)` setelah membuat pasangan kunci.
   - **`pcs`/`recovery`:** entri untuk kunci berikutnya dibuat saat commit DN.
4. **Model yang dibuat:** `classical`, `quantum`, `kci`, `pcs`, `recovery` tetap dengan replikasi `!` dan tabel.
5. **`fs_noerase` (sebelumnya > 40 menit):**
   - pakai **satu sesi tanpa `!`**, dengan satu entri tabel. Model ini negative control, dan satu sesi sudah cukup untuk menunjukkan serangan FS jika kunci tidak dihapus;
   - tambahkan `set traceDisplay = none.`;
   - **jangan** `set reconstructTrace = false.`, karena hasilnya harus tetap "is false", bukan "cannot be proved";
   - tulis alasan pemakaian satu sesi di header model dan di README.
6. **Jalankan satu proses per query**: `run_all_v4.sh` meniru `run_all_v3.sh` (`JOBS=3 MEM_KB=4500000 TIMEOUT=3600`). Query yang melewati batas waktu dilaporkan "NOT CONCLUDED", jangan "false".
7. **Hasil yang diharapkan sama dengan v3:**
   - Q1–Q11 di `classical`, `quantum`, `kci`, `pcs` dan `recovery` sesuai v3;
   - di `fs_noerase`, Q1–Q3 false (reachability) dan Q5–Q9 false (serangan FS).
   - Jika `pcs` atau `recovery` jauh lebih lambat dari v3 (lebih dari 10 menit per query), berhenti dan laporkan waktu per query, jangan dipaksa.
8. **Opsional:** `edhoc_m4v4_unlink.pv` (diff-equivalence, dua run dari UE yang sama vs dua UE berbeda), dengan `TIMEOUT=3600`. Laporkan apa adanya dan jangan klaim jika tidak terbukti.
9. **Output:** `results/v4/` dan `results/SUMMARY_v4.txt`, dengan waktu dan memori puncak per query.

## 6. Pengukuran ulang

1. **Harness RADIUS:** method 4 dan EAP-TLS Hybrid PQC dalam sesi pengukuran yang sama, 200 handshake loss-free. Perbarui `e2e-handshake.csv`; file lama disimpan dengan akhiran `-v3`.
2. **Ukuran dan fragmentasi:** `mtu-fragmentation.csv` dan `img_communication_breakdown_methods.png`. Model ukuran harus sama dengan live.
3. **Full stack:** A/B 3 × 100 dan pemulihan 10 + 10, prosedur sama seperti step 20–21, identitas `@edhoc.internet`. File baru diberi akhiran `-v4`.
4. **Uji loss:** ulangi hanya jika jumlah fragmen atau RT berubah. Jika tetap 15 RT, tulis alasannya di `analisys2.md`.
5. **Bukti identitas:** grep log dan capture menunjukkan tidak ada SUPI dan tidak ada `ue1@…` di User-Name maupun EAP-Response/Identity.

## 7. Jika step 25 sudah sebagian dikerjakan

| Bagian step 25 | Status di step 26 |
|---|---|
| Indeks KID, folder record berdasarkan ID internal, migrasi | **tetap**; nama boleh tetap `kid/` |
| FreeRADIUS tanpa lookup identitas, ekspor EMSK per record | **tetap** |
| Identitas anonim di UE dan harness | **tetap** |
| `edhoc4_r_peek_kid` | **tetap**, ganti nama ke `peek_keyid` (opsional) |
| KID_B di dalam Plaintext1 dan cek "dalam = luar" | **hapus** |
| TH_1 = H(ct_B), AEAD Message1 tanpa AAD_1 | **ganti** ke TH_1 = H(pk_B ‖ ct_B) dan AAD_1 |
| Model ProVerif v4 versi step 25 | **ganti** sesuai bagian 5 |

## 8. Diagram

Salin `Symmetry_Journal.drawio` terlampir ke `symmetry-rev/figure/`. Halaman pertamanya adalah v4. Salin juga `img_SecondaryAuth2_v4.png` ke `symmetry-rev/figure/`. Jangan masukkan ke paper dulu; paper akan saya perbarui setelah hasil masuk.

## Commit

1. `edhoc4: v4 message_1 — KeyID_B in clear, AAD_1 = KeyID_B || ct_B, TH_1 = H(pk_B, ct_B)`
2. `db: KeyID index for DN-AAA records, record directories by internal id`
3. `freeradius/ue/bench: record by KeyID, anonymous NAI @edhoc.internet, EMSK export by record id`
4. `tests: KeyID/ct_B/ciphertext tampering, unknown KeyID, index across commit/erase/crash, 100 anonymous UEs`
5. `proverif: v4 models with AAD-bound KeyID and table lookup; single-session fs_noerase`
6. `bench: v4 sizes, harness E2E, full stack and recovery`
7. `figure: protocol diagram v4`

## Laporan balik

Kirimkan:
- ukuran Message1–4, jumlah fragmen dan RT;
- hasil semua test;
- `SUMMARY_v4` lengkap dengan waktu per query, termasuk unlink jika dijalankan;
- E2E harness (mean/median, proposal vs EAP-TLS Hybrid);
- tabel full stack dan pemulihan;
- bukti identitas anonim;
- hash commit.