# revisi-no-eph-step11-protokol.md: kunci rotasi di EAD_1/EAD_2, pseudonim, sinkronisasi

Revisi ini menindaklanjuti balasan Dr. Shin. Kerjakan bagian ProVerif (A4) dulu dan pastikan semua hasilnya sesuai harapan sebelum mulai implementasi (`revisi-no-eph-step11-implementasi.md`).

## A0. Ringkasan keputusan

| Poin Dr. Shin | Keputusan |
|---|---|
| FS hanya dari rotasi dan penghapusan kunci | Tetap. Tidak ada share ephemeral X25519. Sinkronisasi dibahas di subbagian tersendiri. |
| Message4 hilang | Npk_A dipindah ke **EAD_1**, Npk_B ke **EAD_2**. DN-AAA tidak lagi menyimpan grace key. |
| ct_A di Message2, PRK_4e3m = PRK_3e2m | Tetap, tidak diubah. |
| Jeda satu sesi pada PCS | Itu memang definisi PCS, jadi bukan keterbatasan. |
| ID_CRED_I di Message1 | Sudah dilindungi AEAD(K_1) dari ss_B. Selain itu, identitas EAP luar diganti **pseudonim sekali pakai** (lihat A3). |

**Catatan:** Message4 **tidak** dihapus. Di draft-ietf-emu-eap-edhoc-12 §3.1, message_4 "is mandatory and acts as a protected success indication". Setelah revisi ini, Message4 hanya berisi AEAD dengan EAD_4 kosong.

## A1. Alur pesan baru

**Message1 (UE → DN-AAA)**
1. Identitas EAP-Response/Identity (= RADIUS User-Name) diisi P_cur, yaitu NAI pseudonim (A3).
2. UE membuat `(Nsk_A, Npk_A) ← X-Wing.KeyGen()`. Sebelumnya langkah ini terjadi sebelum Message3.
3. `(ct_B, ss_B) ← X-Wing.Encaps(pk_B)`, lalu `PRK_1e = Extract(H(ct_B), ss_B)` → K_1.
4. `PT1 = (METHOD, SUITES_I, C_I, ID_CRED_I, EAD_1 = Npk_A)`.
5. `Message1 = ct_B ‖ AEAD(K_1, PT1)`.

**Message2 (DN-AAA → UE)**
1. DN-AAA mencari record berdasarkan P_cur, lalu melakukan decaps dan membuka PT1. Pseudonim yang tidak dikenal langsung ditolak.
2. `(Nsk_B, Npk_B) ← X-Wing.KeyGen()` dan `P_next ← random(16 B)`.
3. `(ct_A, ss_A) ← Encaps(pk_A)`; `TH_2 = H(H(message_1) ‖ ct_A ‖ C_R)` (tidak berubah); `PRK_2e`, `PRK_3e2m` tetap seperti sekarang.
4. `EAD_2 = (Npk_B, P_next)`.
5. MAC_2 dihitung dengan `context_2 = ⟨C_R, ID_CRED_R, TH_2, CRED_R, EAD_2⟩`. **EAD_2 wajib masuk ke MAC_2 dan σ_R**; saat ini kode memanggil `compute_mac(..., NULL, 0)`.
6. `PT2 = (C_R, ID_CRED_R, EAD_2, σ_R)` dan `Message2 = ct_A ‖ AEAD(K_2, PT2)`.
7. Belum ada yang ditulis ke disk. Nsk_B, Npk_A, dan P_next disimpan di memori sesi saja.

**Message3 (UE → DN-AAA)**
1. UE melakukan decaps ct_A, lalu memverifikasi MAC_2 dan σ_R. Keduanya mencakup EAD_2, jadi Npk_B dan P_next ikut terautentikasi.
2. **Write-ahead di UE:** tulis slot NEXT = (Nsk_A, Npk_A, Npk_B, P_next) dengan satu `fdatasync` **sebelum** Message3 dikirim.
3. `TH_3 = H(TH_2 ‖ PT2)` (tidak berubah) sudah mencakup EAD_2. MAC_3 dan σ_I dihitung tanpa EAD_3.
4. `PT3 = (σ_I)` dan `Message3 = AEAD(K_3, PT3)`.

**Message4 (DN-AAA → UE, wajib)**
1. DN-AAA memverifikasi MAC_3 dan σ_I.
2. **Commit write-ahead:** record baru = (P_next, Nsk_B, Npk_B, pk_A := Npk_A, VK_I), lalu satu `fdatasync`. Indeks P_cur dihapus. **Tidak ada grace key**: slot lama yang berisi sk_B lama di-nol-kan setelah Message4 terkirim, di luar jalur kritis.
3. `Message4 = AEAD(K_4, EAD_4 = kosong)`. Setelah itu ekspor MSK dan EMSK, lalu kirim EAP-Success.

**Setelah UE memverifikasi Message4:** UE mempromosikan NEXT menjadi CUR (P_cur := P_next, sk_A := Nsk_A, pk_B := Npk_B) dan menghapus sk_A lama. Langkah ini boleh lazy, di luar jalur kritis: kalau UE crash sebelumnya, NEXT tetap ada dan akan dicoba lebih dulu di sesi berikut.

Key schedule (PRK_1e, PRK_2e, PRK_3e2m, PRK_4e3m = PRK_3e2m, PRK_out) **tidak berubah**.

## A2. Aturan sinkronisasi dan pemulihan

**State UE:** slot CUR (P_cur, sk_A, pk_B) dan slot NEXT yang opsional (P_next, Nsk_A, Npk_B).

**Awal sesi:** jika NEXT valid, UE memakai NEXT. Jika DN-AAA menolak pseudonimnya ("unknown identity", sebelum Message2), UE membuang NEXT dan mengulang sekali dengan CUR.

| Pesan yang hilang / kejadian | DN-AAA | UE | Sesi berikutnya |
|---|---|---|---|
| Message1 atau Message2 | tidak berubah | NEXT belum ditulis | pakai CUR, normal |
| Message3 | tidak berubah (P_cur) | NEXT sudah ditulis | coba NEXT → ditolak → ulang dengan CUR (1 fallback) |
| Message4 atau EAP-Success | sudah commit (P_next) | NEXT ada, CUR masih ada | coba NEXT → sukses → hapus sk_A lama |
| UE crash setelah Message3 | commit atau belum | NEXT durable | sama seperti dua baris di atas |
| DN-AAA crash setelah commit | sudah commit | – | sama seperti "Message4 hilang" |

**Argumen FS (untuk ditulis di paper):**
- Kunci sesi butuh ss_A **dan** ss_B. Karena DN-AAA selalu menghapus sk_B lama saat commit, sesi yang sudah diterima DN-AAA tetap punya FS walaupun UE masih menyimpan sk_A lama sampai sesi sukses berikutnya.
- Sesi yang tidak pernah diterima DN-AAA (Message3 hilang) tidak menghasilkan kunci yang dipakai.
- Satu-satunya yang terbuka kalau sk_A lama yang masih disimpan bocor adalah isi Message2 sesi itu: P_next, Npk_B, dan ID_CRED_R. Ini masalah privasi, bukan kerahasiaan kunci.

## A3. Pseudonim untuk identitas EAP

**Alasan:**
- draft-ietf-emu-eap-edhoc-12 §3.1.5: peer "MUST NOT send its username (or any other permanent identifiers) in cleartext in the Identity Response".
- Saat ini DN-AAA memilih record per-UE dari User-Name. Jadi walaupun ID_CRED_I terlindungi AEAD, identitas luar tetap membocorkan siapa UE-nya.

**Desain:**
- `P` = 16 byte acak, ditulis sebagai NAI `p<32 hex>@<realm DN>`. Realm tetap dipakai untuk routing RADIUS.
- P_0 di-provision bersama kunci awal. P_next yang baru dibuat setiap sesi dan dikirim di EAD_2: rahasia karena berada di bawah K_2, dan terautentikasi oleh σ_R.
- Tiap P dipakai sekali. Dua sesi hanya bisa dikaitkan saat terjadi fallback (UE mengulang dengan P_cur).
- Pseudonim yang tidak dikenal ditolak sebelum DN-AAA melakukan operasi KEM apa pun. Pseudonim juga berfungsi sebagai penanda state kunci, jadi tidak perlu trial decryption.

## A4. ProVerif

Buat `symmetry-rev/proverif/edhoc_m4v3_*.pv` dari model v2 dengan perubahan berikut:

1. PT1 membawa `npkA`, PT2 membawa `(npkB, pnext)`. MAC_2 dan σ_R mencakup EAD_2; TH_3 mencakup PT2. PT3 tanpa EAD. Message4 = AEAD(K_4, kosong).
2. UE baru "accept" dan "commit" setelah Message4 terverifikasi. DN-AAA commit setelah Message3 terverifikasi.
3. Event autentikasi (begin/end) menyertakan `(npkA, npkB, pnext)`, supaya agreement juga mencakup kunci baru dan pseudonim.
4. Lima model: `classical`, `quantum` (QXW di fase 0 dan 1), `kci` (dengan QXW), `pcs` (out ID_CREDR), dan `fs_noerase` (kedua pihak tidak menghapus; kontrol negatif, harus **false**).
5. **Model baru `edhoc_m4v3_recovery.pv`:**
   - Situasi yang dimodelkan: DN-AAA menghapus sk_B lama saat commit, tetapi UE **menyimpan** sk_A lama (Message4 hilang).
   - Di fase 1, bocorkan seluruh state UE (sk_A lama dan Nsk_A), state DN-AAA (Nsk_B), dan kedua kunci ML-DSA.
   - Query kerahasiaan kunci sesi diharapkan **true**.
6. Query tambahan:
   - `attacker(pnext)` di fase 0 diharapkan **true** (pnext rahasia);
   - kerahasiaan ID_CRED_I (identity concealment) diharapkan tetap **true** kecuali jika sk_B saat ini bocor, seperti sebelumnya.

Hasil yang diharapkan: R1–R9 sama dengan v2 (semua lolos), `recovery` FS **true**, `fs_noerase` FS **false**. Laporkan tabel query, hasil, dan waktu jalan. Jika ada hasil yang berbeda dari harapan, berhenti dan laporkan tanpa mengubah desain.

## A5. Konteks untuk paper

Bagian ini **jangan dikerjakan** oleh Claude Code; saya yang akan menyiapkannya setelah hasil masuk. Isinya:
- FS dan PCS dari rotasi, ditambah subbagian baru "Key synchronization and recovery" (A2).
- Jeda satu sesi pada PCS ditulis sebagai definisi PCS, bukan keterbatasan.
- Anonimitas: ID_CRED_I dilindungi AEAD, ditambah pseudonim sekali pakai. Istilah "SIGMA-style gate" diganti menjadi "detached-signature gate", karena alurnya bukan lagi SIGMA.
- Pembuatan kunci 2× dibanding EAP-TLS Hybrid dibahas eksplisit.

# revisi-no-eph-step11-implementasi.md: implementasi EAD_1/EAD_2, pseudonim, tanpa grace key

**Prasyarat:**
- `revisi-no-eph-step11-protokol.md` sudah dibaca;
- ProVerif A4 sudah lolos dengan hasil sesuai harapan.

Spesifikasi alur, state, dan aturan pemulihan ada di A1–A3 dokumen protokol. Dokumen ini hanya berisi langkah implementasi.

## B1. `edhoc4` (library)

1. **Waktu pembuatan kunci:**
   - UE membuat (Nsk_A, Npk_A) di awal pembuatan Message1.
   - DN-AAA membuat (Nsk_B, Npk_B) saat memproses Message1, sebelum Message2.
   - Pool tetap opt-in (`EDHOC4_ROTATION_POOL`) dan default off.
2. **EAD:**
   - EAD_1 = Npk_A di PT1. Pakai label EAD yang sekarang dipakai untuk kunci rotasi.
   - EAD_2 = dua item, yaitu Npk_B dan P_next. Untuk P_next, tambahkan label baru di rentang yang sama, misalnya label rotasi + 1.
   - PT3 tanpa EAD_3. PT4 kosong (hanya tag AEAD).
3. **MAC_2 dan σ_R harus mencakup EAD_2.** Ganti `compute_mac(prk3e2m, th2, id_cred, NULL, 0, mac2)` agar memakai EAD_2, dan pastikan `sig_message` memakai MAC_2 yang baru. TH_2 dan TH_3 tidak berubah, karena H(message_1) sudah mengikat PT1 dan TH_3 = H(TH_2 ‖ PT2).
4. **Tidak ada lagi grace key.** Hapus logika `used_prev` / "grace key: prev slot".
5. **Ukuran:** perbarui konstanta ukuran pesan dan buffer, karena Message1 dan Message2 masing-masing bertambah sekitar 1.216 B + 16 B.

## B2. DN-AAA (`edhoc4_db` + `rlm_eap_edhoc`)

1. **Record berbasis ID internal** `<db>/<uid>/rec.bin`. Format dua-slot tetap dipakai untuk atomisitas. Setiap slot berisi: P, sk_B, pk_B, pk_A, VK_I, dan versi.
2. **Indeks pseudonim:**
   - Map P → uid ada di memori (hash map + mutex) dan dibangun ulang saat start dengan memindai `rec.bin`.
   - Lookup memakai identitas EAP (User-Name).
   - **Pseudonim yang tidak dikenal langsung ditolak** dengan EAP-Failure dan log `unknown pseudonym`, sebelum operasi KEM apa pun.
3. **Commit** dilakukan setelah σ_I dan MAC_3 terverifikasi:
   1. tulis slot tidak aktif (P_next, Nsk_B, Npk_B, Npk_A, VK_I), lalu `fdatasync` di jalur kritis;
   2. perbarui indeks: P_next masuk, P_cur dihapus;
   3. kirim Message4;
   4. **nolkan slot lama** yang berisi sk_B lama, lalu `fdatasync` di luar jalur kritis (setelah Message4 dikirim).
4. Ekspor EMSK (`<emsk_dir>/...`) memakai uid, bukan identitas EAP.

## B3. UE (UERANSIM + sisi UE `edhoc4`)

1. **`ue.rec` dua-slot:** slot CUR dan slot NEXT, masing-masing dengan flag valid.
2. **Identitas EAP** = pseudonim NAI dari slot yang sedang dipakai.
3. **Awal sesi:**
   - jika NEXT valid, pakai NEXT;
   - jika DN-AAA menolak sebelum Message2, invalidasi NEXT dan **ulang sekali** dengan CUR;
   - log `fallback=1`.
4. **Sebelum mengirim Message3:** tulis NEXT = (Nsk_A, Npk_A, Npk_B, P_next) + `fdatasync` di jalur kritis.
5. **Setelah Message4 terverifikasi** (bukan setelah EAP-Success): promosikan NEXT menjadi CUR, lalu nolkan slot CUR lama (sk_A lama) + `fdatasync`. Langkah ini di luar jalur kritis.
6. **Provisioning** (`edhoc4_keygen`, `provision`): buat P_0 untuk UE dan indeksnya di DN-AAA.

## B4. Test

1. **Selftest:** 2 UE × 5 run. Periksa bahwa:
   - MSK/EMSK sama di kedua sisi;
   - pseudonim berubah di setiap run dan tidak pernah berulang;
   - setelah commit, DN-AAA hanya menyimpan satu sk_B (slot lama berisi nol);
   - setelah promosi, UE tidak lagi menyimpan sk_A lama.
2. **Injeksi kegagalan** (unit test). Kasusnya:
   - Message3 di-drop;
   - Message4 di-drop;
   - EAP-Success di-drop;
   - UE dimatikan setelah mengirim Message3;
   - DN-AAA dimatikan setelah commit dan sebelum Message4.

   Di semua kasus, sesi berikutnya harus selesai **tanpa re-provisioning**, dengan paling banyak 1 fallback, dan DN-AAA tidak pernah memegang dua sk_B setelah slot lama dinolkan.
3. `edhoc4_xwing_kat`, `edhoc4_dbtest` (diperbarui), dan `edhoc03_selftest` harus tetap PASS. Build ulang UERANSIM dan modul FreeRADIUS.

## B5. Benchmark

Semua langkah dijalankan dalam satu sesi VM untuk ketujuh method:

1. **Ukuran:** byte Message1–4, jumlah fragmen EAP, dan n_RT untuk method 4. Bandingkan dengan sebelumnya (1.141 / 4.880 / 4.975 / 1.232 B, 14 RT).
2. **Model komputasi:** jumlah operasi tidak berubah, jadi `handshake-compute.csv` harus tetap 984.640 µs untuk method 4. Kalau berubah, laporkan.
3. **In-process:** `m4_inproc_compare.sh` (5 × 2000).
4. **E2E:** 2 run × 100, masing-masing dengan 20 warm-up, untuk ketujuh method.
5. **Loss:** 0–30%, 120 percobaan per sel, ketujuh method, ditambah Wilson dan Fisher untuk pasangan hybrid.
6. **Storage ablation:** durable vs tmpfs dalam 6 ronde bergantian. Sekarang ada dua flush di jalur kritis (UE sebelum Message3 dan DN-AAA sebelum Message4), jadi laporkan biayanya.
7. **Uji pemulihan** (menggantikan uji grace key): 150 handshake di loss 20%. Hitung:
   - jumlah fallback;
   - jumlah sesi dengan Message4 hilang yang pulih di sesi berikutnya;
   - desync (harus 0);
   - re-provisioning (harus 0).
8. `rtt_projection.py`.

## B6. Gambar dan notebook

- Perbarui notebook dengan hasil B5, lalu render ulang `img_communication_breakdown_methods.png`, `img_handshake_computation_grouped.png`, keempat `img_combined_*`, dan `img_D_baseline_comparison.png`.
- **Diagram protokol** `symmetry-rev/figure/Symmetry_Journal.drawio`:
  - pindahkan Npk_A ke Message1 (EAD_1) dan Npk_B + P_next ke Message2 (EAD_2);
  - kosongkan EAD_3 dan EAD_4;
  - pindahkan KeyGen ke sebelum Message1 (UE) dan sebelum Message2 (DN-AAA);
  - tambahkan write-ahead UE sebelum Message3 dan identitas EAP = pseudonim.

  Ekspor ke `img_SecondaryAuth2_v2.png` kalau drawio CLI tersedia. Kalau tidak, laporkan agar diekspor manual.
- **Jangan ubah `manuscript.tex`.** Saya yang akan menyiapkan teks paper dan deck dari laporan.

## Commit (terpisah)

1. `proverif: m4v3 models (EAD_1/EAD_2 rotation keys, pseudonym, recovery FS)`
2. `edhoc4: rotation keys in EAD_1/EAD_2, empty Message4, no grace key`
3. `dn-aaa/ue: one-time pseudonymous EAP identity, NEXT slot with fallback`
4. `test: failure-injection and recovery tests`
5. `bench: re-run all methods with the EAD_1/EAD_2 protocol`
6. `figure/notebook: updated protocol diagram and plots`

## Laporan balik

Kirimkan:
- tabel hasil ProVerif;
- ukuran pesan, fragmen, dan n_RT;
- E2E mean/median ketujuh method;
- loss 20/30% beserta Fisher;
- in-process;
- biaya storage (dua flush);
- hasil uji pemulihan;
- status semua test;
- daftar hal yang menyimpang dari spesifikasi.