# revisi-no-eph-step30.md: varian protokol Dr. Shin (tanpa AAD) dibandingkan dengan v4 (AAD)

## Tujuan

Dr. Shin mengirim revisi protokol: `Symmetry_Journal_Shin.drawio`, halaman 1. Step ini mengimplementasikan revisi itu **sebagai varian**, tanpa mengganti v4. Kedua varian lalu dibandingkan dari tiga sisi: performa, keamanan (ProVerif), dan bukti empiris (uji manipulasi pesan).

Tiga varian dijalankan berdampingan dalam satu build, dipilih lewat konfigurasi (`edhoc_variant = v4 | v4s | v4t`). Default tetap `v4`.

| Varian | Asal | TH_1 | AEAD Message1 | Plaintext1 | Cek di DN-AAA |
|---|---|---|---|---|---|
| **v4** (sekarang) | Prof. You | `H(pk_B ‖ ct_B)` | `AEAD.Enc(K_1, AAD_1 = (KeyID_B, ct_B), PT1)` | `(Method, Suites_I, ID_CRED_I, C_I, EAD_1)` | KeyID_B = H(pk_B); ID_CRED_I cocok dengan record |
| **v4s** | Dr. Shin | `H(KeyID_B ‖ ct_B)` | `AEAD.Enc(K_1, PT1)`, **tanpa AAD** | `(Method, Suites_I, **KeyID_B**, ID_CRED_I, C_I, EAD_1)` | Record diambil dengan KeyID_B, **tanpa** verifikasi KeyID_B = H(pk_B); ID_CRED_I cocok dengan record |
| **v4t** (opsional, jalan tengah) | RFC 9528 §5.4 (AD = TH) | `H(KeyID_B ‖ ct_B)` | `AEAD.Enc(K_1, AD = TH_1, PT1)` | sama dengan v4 | sama dengan v4s |

**Catatan v4s:**
- Di diagram Dr. Shin, DN-AAA tidak membandingkan KeyID_B di dalam Plaintext1 dengan KeyID_B di header.
- Implementasikan dua sub-mode:
  - `v4s` persis seperti diagram, tanpa pemeriksaan tersebut;
  - `v4s+chk`, yang menambah pemeriksaan `KeyID_B(PT1) == KeyID_B(header)`. Kalau berbeda, kirim EAP-Failure.
- Pemeriksaan ini usulan kita, bukan bagian dari diagram beliau, jadi laporkan keduanya terpisah.

**Tidak berubah di semua varian:**
- Message2–4;
- `TH_2 = H(H(Message1), ct_A)`, di mana Message1 adalah byte yang diterima apa adanya;
- rotasi EAD_1/EAD_2, NEXT write-ahead, indeks KeyID di memori, dan NAI anonim.

## 0. Cek awal (laporkan sebelum mengubah kode)

1. AD apa yang **sebenarnya** dipakai implementasi untuk AEAD Message2, Message3, dan Message4? Pilihannya: kosong, `Enc_structure("Encrypt0", h'', TH_x)` seperti RFC 9528, atau yang lain. Tulis nama fungsi dan barisnya. Ini menentukan apakah "tanpa AAD" di v4s berarti AD kosong atau AD = Enc_structure tanpa external_aad.
2. Untuk v4s, AD Message1 dibuat **sama** dengan konvensi Message2 di implementasi. Jangan memakai aturan baru.

## 1. Implementasi

### UE (`nr-ue`, modul EAP-EDHOC)

**v4s:**
- `KeyID_B = SHA-256(pk_B)`, sama seperti v4.
- `PT1 = CBOR(Method, Suites_I, KeyID_B (bstr 32), ID_CRED_I, C_I, EAD_1)`.
- `TH_1 = SHA-256(KeyID_B ‖ ct_B)`. Gunakan encoding yang sama persis di UE dan DN-AAA: CBOR sequence `bstr(KeyID_B) bstr(ct_B)`.
- `K_1 = HKDF-Expand(HKDF-Extract(TH_1, ss_B), TH_1)`.
- `Message1 = (KeyID_B, ct_B, AEAD(K_1, AD sesuai §0, PT1))`.

**v4t:** seperti v4, tetapi `TH_1 = SHA-256(KeyID_B ‖ ct_B)` dan AD AEAD Message1 = TH_1. Kalau implementasi memakai Enc_structure, isi external_aad dengan TH_1.

### DN-AAA (`rlm_eap_edhoc`)

**v4s:**
1. Parse header, lalu ambil record dari indeks memori dengan KeyID_B.
   - KeyID_B tidak ditemukan → EAP-Failure tanpa Decaps, sama seperti v4.
   - Pemeriksaan `KeyID_B = SHA-256(pk_B)` **dilewati**, sesuai diagram.
2. Decaps, lalu hitung `TH_1 = SHA-256(KeyID_B ‖ ct_B)` dan K_1.
3. AEAD.Dec dengan AD sesuai §0. Parse PT1 dengan KeyID_B di posisi ke-3.
4. Cek ID_CRED_I cocok dengan record.
5. Khusus `v4s+chk`: cek KeyID_B di PT1 sama dengan KeyID_B di header.

**v4t:** seperti v4, tetapi TH_1 dan AD diganti seperti di sisi UE. Pemeriksaan KeyID_B = H(pk_B) tetap ada.

### Lain-lain

- Model ukuran (`size_model`) diperbarui per varian.
- Untuk v4s, Message1 diperkirakan +34 B (2.390 → sekitar 2.424 B). Laporkan ukuran live, jumlah fragmen, dan RT.

## 2. Uji manipulasi pesan (bukti empiris)

Semua uji dijalankan untuk v4, v4s, v4s+chk, dan v4t, masing-masing 20 kali, dengan modifikasi dilakukan di relay UPF atau di harness. Catat:
- hasil akhir (EAP-Failure, atau sukses kalau ada yang lolos);
- **di langkah mana** DN-AAA menolak: lookup, verifikasi KeyID, Decaps, AEAD tag, parse, cek ID_CRED, atau cek KeyID dalam;
- waktu DN-AAA sampai menolak, dalam ms;
- apakah Decaps dijalankan.

| # | Manipulasi | Harapan |
|---|---|---|
| T1 | Flip 1 bit di KeyID_B header (jadi KeyID tak dikenal) | gagal di lookup, tanpa Decaps |
| T2 | KeyID_B header diganti KeyID_B **sah milik UE lain** | gagal (v4: AEAD/verifikasi; v4s: Decaps/AEAD) |
| T3 | Flip 1 bit di ct_B | gagal di AEAD tag |
| T4 | Flip 1 bit di ciphertext AEAD | gagal di AEAD tag |
| T5 | Replay Message1 dari run lama (KeyID lama sudah dihapus) | gagal di lookup |
| T6 | Replay Message1 run yang sedang berjalan ke sesi EAP lain | laporkan apa adanya (sama untuk semua varian?) |
| T7 | (v4s, v4s+chk) UE uji sengaja mengisi KeyID_B di PT1 ≠ header, dengan header benar | **v4s: laporkan apakah lolos**; v4s+chk: gagal di cek KeyID dalam |

T7 menunjukkan apakah salinan KeyID_B di Plaintext1 berfungsi tanpa pemeriksaan tambahan.

## 3. ProVerif

1. Tambahkan flag varian ke `gen_m4v4.py`: `--variant v4|v4s|v4s_chk|v4t`. Hasilkan untuk setiap varian:
   - `edhoc_m4<var>_{classical,quantum,kci,pcs,fs_noerase,recovery,nextkey}.pv`;
   - query sama dengan v4 (Q1–Q12, KCI, PCS, FS, recovery, nextkey).
   - Pada v4s, hapus `if kidB = H(xpk2b(pkB))` dan gunakan `AEAD_enc` tanpa AAD untuk Message1.
2. **Query baru (semua varian): integritas header Message1.** Tambahkan event `UE_send_M1hdr(W0, kid, ct)` di UE dan `DN_acc_M1(W0, kid, ct)` di DN-AAA setelah AEAD.Dec berhasil, lalu query:
   ```
   query kid:bitstring, ct:bitstring; event(DN_acc_M1(W0, kid, ct)) ==> event(UE_send_M1hdr(W0, kid, ct)).
   ```
   Query ini non-injective, karena replay ke sesi DN lain memang mungkin dalam model.
3. Untuk v4s, tambahkan juga query T7: apakah DN bisa menerima Message1 dengan KeyID di PT1 ≠ header. Gunakan event `DN_acc_inner(W0, kid_hdr, kid_pt)`, query `event(DN_acc_inner(W0, h, p)) ==> h = p`.
4. Jalankan dengan batas memori, sama seperti step 29: `systemd-run --user --scope -p MemoryMax=10G -p MemorySwapMax=0 timeout 3600 proverif …`. Jangan menjalankan model unlink.
5. Simpan hasil di `results/SUMMARY_v4_variants.txt`, dengan format tabel yang sama seperti `SUMMARY_v4.txt`.

## 4. Pengukuran performa (kernel sama, catat `uname -r`)

1. **Harness:**
   - v4, v4s, v4s+chk, v4t, dan EAP-TLS Hybrid PQC, bergantian dalam satu sesi;
   - 2 run × (20 pemanasan dibuang + 100);
   - laporkan mean, median, p95, CI median, dan selisih median tiap varian dengan v4 (beserta CI).
2. **Komputasi Message1 saja** (UE build Message1 dan DN-AAA proses Message1), 10.000 iterasi per varian: median dalam µs.
3. **Ukuran:** Message1–4, total, jumlah fragmen, dan RT per varian (live dan model).
4. **Full stack (singkat):** v4s A/B 1 × 100 dengan prosedur step 27. Cukup untuk menunjukkan v4s bekerja di 5G core. Tidak perlu uji pemulihan ulang.

File baru diberi akhiran `-variants`. File lama tidak diubah.

## 5. Output

Bagian baru di `analisys2.md`, "8. Varian AD Message1: v4 (Prof. You), v4s (Dr. Shin), v4t", berisi:
- jawaban §0 (AD Message2–4 di implementasi);
- tabel ukuran;
- tabel harness;
- tabel komputasi Message1;
- tabel ProVerif per varian, termasuk query integritas header dan T7;
- tabel uji manipulasi T1–T7;
- ringkasan satu paragraf: perbedaan keamanan dan biaya antarvarian.

Simpan juga `Symmetry_Journal_Shin.drawio` (terlampir) di `symmetry-rev/paper/drawio/` sebagai referensi.

**Jangan ubah paper** di step ini.

## Commit

1. `edhoc: Message1 AD variants v4s (no AAD, KeyID_B in PT1, TH_1 = H(KeyID_B, ct_B)) and v4t (AD = TH_1)`
2. `tests: Message1 tamper tests T1-T7 for all variants`
3. `proverif: variant models and Message1 header-integrity query`
4. `bench: variant harness, Message1 compute, sizes, v4s full stack`

## Laporan balik

- jawaban §0;
- ukuran per varian;
- harness dan selisih terhadap v4;
- hasil ProVerif per varian;
- tabel T1–T7;
- hash commit.