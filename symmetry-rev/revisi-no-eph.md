# revisi-no-eph.md — Instruksi untuk Claude Code

**Tugas:** terapkan protokol revisi Symmetry (EAP-EDHOC method 4 **tanpa ephemeral X-Wing**, tanpa `kid`) ke repo `EdhocSecondaryAuth` (basis commit `5eb75075`), jalankan ulang semua benchmark, lalu laporkan angka baru untuk notebook grafik dan paper.

**Acuan protokol:** halaman "Revised: no ephemeral X-Wing" di `figure/Symmetry_Journal.drawio`, yaitu versi yang dikirim ke Dr. Shin. Jangan menambah field apa pun ke pesan EDHOC. Secara khusus, **tidak ada `kid_B`**.

---

## 0. Isi paket ini

| Path | Isi |
|---|---|
| `implementation/edhoc4/` | `edhoc4.c`, `edhoc4.h`, `selftest.c` versi baru (sudah lulus selftest) |
| `implementation/edhoc4_v2.patch` | diff `edhoc4/` terhadap `5eb75075` (protokol baru + AEAD AES-128-GCM untuk method 0–4) |
| `implementation/aead_link_v2.patch` | tambah `-lmbedcrypto` di FreeRADIUS (`all.mk`), UERANSIM (`CMakeLists.txt`), `benchmark/Makefile` |
| `implementation/benchmark_v2.patch` | diff `benchmark/crypto_bench.c` + `benchmark/edhoc_sizes.py` |
| `proverif/` | 5 model `edhoc_m4v2_*.pv` + `run_all_v2.sh` + README |
| `notebook/EAP_Edhoc_Secondary_Authentication_v2.ipynb` | notebook grafik; nilai yang sudah pasti sudah diganti, sisanya ditandai `TODO(no-eph)` |
| `paper/` | `manuscript.tex`/`.pdf`, `manuscript_tracked_changes.pdf`, `img_SecondaryAuth2_v2.png` |
| `figure/` | drawio Anda + halaman "Final v2 (no ephemeral X-Wing, clean)" + PNG |

---

## 1. Protokol yang harus diimplementasikan

```
UE (sk_A, pk_A, skSig_I, VK_I)                 DN-AAA (sk_B, pk_B, skSig_R, VK_R)
(ss_B, ct_B) = XWing.Encaps(pk_B)
PT1  = (Method, Suites_I, ID_CRED_I, C_I, EAD_1)
TH_1 = H(ct_B)
PRK_1e = Extract(TH_1, ss_B);  K_1 = Expand(PRK_1e, TH_1)
Message1 = (ct_B, AEAD(K_1, PT1))  ------------>
                                   ss_B = Decaps(ct_B, sk_B); dekripsi PT1
                                   (pk_A, VK_I) = Lookup(ID_CRED_I)
                                   (ss_A, ct_A) = Encaps(pk_A)
                                   TH_2 = H(H(Message1), ct_A)
                                   PRK_2e = Extract(TH_2, ss_A); K_2 = Expand(PRK_2e, TH_2)
                                   PRK_3e2m = Extract(PRK_2e, ss_B)
                                   MAC_2, σ_R = Sign(skSig_R, TH_2‖ID_CRED_R‖MAC_2)
                 <------------  Message2 = (ct_A, AEAD(K_2, C_R, ID_CRED_R, VK_R, EAD_2, MAC_2, σ_R))
ss_A = Decaps(ct_A, sk_A); PRK_2e, PRK_3e2m sama
PRK_4e3m = PRK_3e2m
EAD_3 = Npk_A;  MAC_3;  σ_I
Message3 = AEAD(K_3, EAD_3, MAC_3, VK_I, σ_I) --------->
                                   verifikasi; MSK/EMSK; commit (Nsk_B, Npk_A), hapus sk_B lama
                 <------------  Message4 = AEAD(K_4, EAD_4 = Npk_B)   (dalam EAP-Success)
commit (Nsk_A, Npk_B), hapus sk_A lama
```

**Pemilihan record per UE di DN-AAA (tanpa kid).** pk_B sekarang berbeda untuk setiap UE dan dirotasi setiap sesi. DN-AAA memilih record UE dari **EAP identity / RADIUS User-Name**, yang tiba di Access-Request *sebelum* Message1. Dengan begitu tidak ada byte tambahan di Message1. Jika identity tidak dikenal, fallback-nya adalah *trial decapsulation*: coba Decaps + AEAD-Dec PT1 dengan setiap record yang ada.

---

## 2. Langkah 1 — terapkan patch `edhoc4`

```bash
cd EdhocSecondaryAuth
git checkout -b symmetry-no-eph 5eb75075
sudo apt-get install -y libmbedtls-dev          # AES-128-GCM (mbedTLS 2.28, Ubuntu 24.04)
git apply /path/paket/implementation/edhoc4_v2.patch
git apply /path/paket/implementation/aead_link_v2.patch
cd edhoc4 && make clean && make && ./edhoc4_selftest && ./edhoc03_selftest
```

Output yang benar (ukuran harus persis sama):

```
message_1 : 1141 bytes
message_2 : 4880 bytes
message_3 : 4975 bytes
message_4 : 1232 bytes
total     : 12228 bytes
UE 01 run 1: MSK/EMSK MATCH ... (2 UE x 3 run)
stale pre-rotation key of UE 01: rejected (AEAD auth failure)
RESULT: PASS
# edhoc03_selftest: method 0-3 PASS, ALL PASS
```

**AEAD diganti ke AES-128-GCM (mbedTLS)**, sesuai teks paper. Sebelumnya kode memakai ChaCha20-Poly1305 (libsodium).
- Berlaku untuk `edhoc4.c` (method 4) **dan** `edhoc03.c` (method 0–3), agar semua metode EAP-EDHOC yang dibandingkan memakai AEAD yang sama.
- Kunci AEAD diturunkan 16 B (`E4_AEAD_KEY`/`E3_AEAD_KEY` = 16), nonce 12 B, tag 16 B, AAD = TH_x.
- Implementasinya `mbedtls_gcm_crypt_and_tag` / `mbedtls_gcm_auth_decrypt`. Jika dekripsi gagal, plaintext di-zeroize.
- Ukuran pesan **tidak berubah**, karena tag tetap 16 B.
- Model komputasi juga tidak berubah: `crypto_bench` memang sudah memakai AES128GCM.
- **Format pesan di kawat berubah** (ciphertext beda). Karena itu UE (UERANSIM), FreeRADIUS, dan `e2e_radius_bench` harus di-rebuild bersamaan dengan `libedhoc4.a` baru. File kredensial lama tetap kompatibel.

Ringkasan API baru di `edhoc4.h`. Nama fungsi handshake lama **tidak berubah**.

```c
#define E4_METHOD   0x04
#define E4_ERR_PEER (-9)
typedef int (*edhoc4_lookup_fn)(const uint8_t id_cred[E4_ID_CRED],
                                uint8_t pk_a[E4_XWING_PK], uint8_t vk_i[E4_MLDSA_PK], void *arg);
void edhoc4_set_lookup(edhoc4_ctx *ctx, edhoc4_lookup_fn fn, void *arg); /* responder */
int  edhoc4_commit(edhoc4_ctx *ctx, edhoc4_creds *creds, uint8_t peer_pk[E4_XWING_PK]);
void edhoc4_ctx_wipe(edhoc4_ctx *ctx);
```

- `edhoc4_commit` memasang (Nsk, Npk) milik sendiri dan Npk peer, menghapus sk lama (`sodium_memzero`), lalu menghapus seluruh state sesi.
- **Ekspor MSK/EMSK sebelum memanggil `edhoc4_commit`.**

---

## 3. Langkah 2 — integrasi (wajib, agar FS benar-benar berlaku)

Di kode lama, NpkA/NpkB memang dipertukarkan, tetapi **tidak pernah disimpan**: setiap sesi memuat ulang file kredensial yang sama. Tanpa rotasi yang disimpan, kunci statis dipakai ulang dan forward secrecy hilang. Tambahkan persistensi di tiga tempat berikut.

### 3.1 Helper simpan atomik (dipakai semua pihak)

Tambahkan di `edhoc4.c` / `edhoc4.h`:

```c
/* tulis ke path.tmp -> fsync -> rename(path.tmp, path) */
int edhoc4_creds_save_atomic(const char *path, const edhoc4_creds *c);
int edhoc4_pub_save_atomic_raw(const char *path, const uint8_t pk[E4_XWING_PK]);
```

Catatan: `edhoc4_pub_save` saat ini menerima `edhoc4_creds*`, jadi buat varian yang menerima pk mentah untuk menyimpan Npk peer.

### 3.2 UE — `UERANSIM/src/ue/nas/sm/transport.cpp`

Di cabang `m_edhocRound == 2`, setelah `edhoc4_i_handle_msg4` mengembalikan `E4_OK`:

1. ekspor MSK/EMSK seperti sekarang;
2. `edhoc4_commit(&m_edhocCtx, &m_edhocCreds, m_edhocPeerPub)`;
3. simpan secara atomik ke `EDHOC_UE_CREDS` dan `EDHOC_SRV_PUB`;
4. reset flag cache provisioning (`ensureEdhocProvisioned`) agar sesi berikutnya memakai kunci baru.

Pastikan EAP identity yang dikirim UE adalah identity yang dipakai DN-AAA untuk memilih record (lihat 3.3).

### 3.3 DN-AAA — `freeradius-v3/.../rlm_eap_edhoc/rlm_eap_edhoc.c`

1. **Database per UE.** Ganti `inst->server` + `inst->ue_pub` tunggal dengan direktori, misalnya `edhoc_db/<eap_identity>/`, yang berisi:
   - `server.creds` (sk_B/pk_B khusus UE + kunci ML-DSA DN-AAA; ML-DSA sama untuk semua UE);
   - `ue.pub` (pk_A);
   - `ue.vk` (VK_I);
   - `id_cred` (ID_CRED_I);
   - `prev/` (record sebelumnya, lihat poin 4).
2. **Pilih record.** Di handler Message1, baca `User-Name` dari request (`request->username` atau `fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, …)`). Muat record identity itu, lalu:
   ```c
   edhoc4_init_responder(&sess->ctx, &rec->server, rec->ue_pub);
   edhoc4_set_lookup(&sess->ctx, lookup_fn, rec); /* cek ID_CRED_I == rec->id_cred, isi pk_A & VK_I */
   rc = edhoc4_r_handle_msg1(...);
   ```
   - Jika gagal dengan `E4_ERR_AEAD`, coba `prev/` (lihat poin 4).
   - Jika identity tidak dikenal, lakukan trial decapsulation pada semua record.
   - Pengecekan panjang `msg_len == 1+E3_X_PK+E3_CONN_ID && msg[0] <= 3` untuk method 0–3 tetap aman: Message1 baru 1141 B, sehingga tidak bentrok.
3. **Commit.** Setelah `edhoc4_r_handle_msg3` sukses:
   - ekspor MSK ke `MS-MPPE-*` dan EMSK ke `aaa_keyexport`;
   - pindahkan record aktif ke `prev/`;
   - `edhoc4_commit(&sess->ctx, &rec->server, rec->ue_pub)`;
   - simpan record baru secara atomik.

   Gunakan lock per record (`flock`), karena FreeRADIUS multi-thread.
4. **Kebijakan bila Message4 hilang.** EAP-Success tidak diretransmisi, sehingga ini akan terjadi di uji packet loss. Implementasikan kebijakan *grace key* berikut:
   - Jika Message1 berikutnya hanya bisa didekripsi dengan `prev/`, UE belum berotasi. Pakai `prev/`, buang record "baru", dan jalankan sesi dengan `prev/`.
   - Begitu Message1 berhasil dengan record aktif, hapus `prev/` (`sodium_memzero` + unlink).
   - Konsekuensinya: forward secrecy sesi terakhir tertunda satu sesi. Ini sudah tertulis di paper (Discussion).

### 3.4 Benchmark client — `benchmark/e2e_radius_bench.c`

`load_creds()` memuat `ue.creds`/`server.pub` di setiap handshake. Setelah `edhoc4_i_handle_msg4` sukses di method 4:
- panggil `edhoc4_commit`;
- simpan atomik ke `$CREDDIR/ue.creds` dan `$CREDDIR/server.pub`.

Ini membuat setiap iterasi benar-benar memakai kunci one-time dan ikut mengukur biaya rotasi. Pastikan `g_identity` ("edhoc-ue") cocok dengan nama direktori record di DN-AAA. Bila Message4 hilang di uji lossy, jangan commit: kebijakan grace key di DN-AAA akan menyinkronkan sesi berikutnya.

### 3.5 Provisioning — `edhoc4/keygen.c`, `provision`

Buat satu record per UE:
- X-Wing DN-AAA khusus UE (sk_B, pk_B);
- X-Wing UE (sk_A, pk_A);
- ML-DSA UE (VK_I);
- ID_CRED_I.

Kunci ML-DSA DN-AAA tetap satu. Tulis ke `edhoc_db/<identity>/` (sisi DN-AAA) dan `ue.creds` + `server.pub` (sisi UE). Sebelum setiap rangkaian benchmark, jalankan provisioning ulang agar mulai dari state bersih.

---

## 4. Langkah 3 — patch benchmark

```bash
git apply /path/paket/implementation/benchmark_v2.patch
```

- `crypto_bench.c`: op count method 4 (urutan `{x25519_keygen, x25519_dh, ed_sign, ed_verify, mlkem_keygen, encaps, decaps, mldsa_sign, mldsa_verify}`) berubah dari `{3,3,0,0,2,1,2,1,1}` / `{3,3,0,0,1,2,1,1,1}` menjadi **`{2,2,0,0,1,1,1,1,1}` untuk kedua peran**.
- `edhoc_sizes.py`: model method 4 tanpa `pk_X`, `ct_A` di bagian terbuka Message2, dan `ID_CRED_I` di PT1. Model CBOR memberi 1139/4878/4967/1227 (total 12211). Ukuran di kawat dari selftest/e2e adalah **1141/4880/4975/1232 (12228)**. Untuk paper dan notebook, **pakai angka kawat**.

---

## 5. Langkah 4 — jalankan ulang

```bash
# a) primitif + komputasi + ukuran + fragmentasi
cd benchmark && make && ./run_all_benchmarks.sh          # CRYPTO_ITERS=3000

# b) end-to-end (radiusd harus jalan dengan modul baru)
echo admin | sudo -S /usr/local/sbin/radiusd -f > /tmp/radiusd.log 2>&1 &
./run_e2e_benchmarks.sh                                   # TIMING_ITERS=100, LOSSY_ITERS=120, RTO 40, MAX_RETX 6
python3 e2e_analyze.py ../benchmark-results

# c) bootstrapping, hanya baseline D (EDHOC_HANDSHAKE_MEAN_MS baru)
cd ../bootstrap && python3 bootstrap_bench.py && python3 analyze_bootstrap.py
```

- **Jalankan ulang method 0–4 semuanya**: method 0–3 kini juga memakai AES-128-GCM. EAP-TLS tidak berubah, tetapi sebaiknya ikut diulang dalam sesi yang sama agar kondisi mesinnya sama.
- Setelah itu perbarui juga angka method 0–3 di notebook (`e2e_initiator/e2e_responder[0..3]`, `sim_*`/`e2e_*` key 0–3) dan di paper (misalnya "$0.821$--$0.992$~ms for methods 0--3"), jika berubah.
- Jangan lupa `switch_tls_config.sh` untuk bagian EAP-TLS.

---

## 6. Angka yang sudah pasti vs yang harus diukur

| Besaran (method 4) | Lama | Baru | Status |
|---|---:|---:|---|
| MSG1 / MSG2 / MSG3 / MSG4 (B) | 2354 / 6000 / 4975 / 1232 | **1141 / 4880 / 4975 / 1232** | pasti (selftest) |
| Total (B) | 14561 | **12228** | pasti |
| UE → DN / DN → UE (B) | 7329 / 7232 | **6116 / 6112** | pasti |
| Komputasi inisiator (ms) | 0.650770 | **0.519587** | dari model primitif; cek dengan `crypto_bench` |
| Komputasi responder (ms) | 0.608008 | **0.519587** | idem |
| Total komputasi (ms) | 1.259 | **1.039** | idem |
| Fragmen EAP / IP | 17 / 11 | estimasi model: 14 / 10 | **ukur** (`mtu-fragmentation.csv` / e2e) |
| RADIUS round-trips | — | ? | **ukur** |
| e2e initiator / responder (ms) | 0.872 / 6.620 | ? | **ukur** |
| e2e mean (`EDHOC_HANDSHAKE_MEAN_MS`) | 7.492 | ? | **ukur** |
| Loss 0–30 %: mean, p95, retx, success | — | ? | **ukur** (sim + e2e) |

Jika `crypto_bench` di testbed memberi primitif yang sedikit berbeda, pakai angka dari run baru dan perbarui paper, termasuk paragraf "1.039 ms / 0.520 ms each" dan "6–7×".

---

## 7. Update notebook (`notebook/…_v2.ipynb`)

Sudah diganti:
- `compute_initiator[4] = 0.519587`;
- `compute_responder[4] = 0.519587`;
- `MSG1[1] = 1141`;
- `MSG2[1] = 4880`.

Catatan: di `methods_c2`, index 1 adalah EAP-EDHOC Hybrid. MSG3/MSG4 tetap.

Masih `TODO(no-eph)`, isi dari hasil Langkah 4:
- `e2e_initiator[4]`, `e2e_responder[4]`;
- `total_eap_frags[4]`, `total_ip_frags[4]`;
- `sim_mean/sim_p95/sim_retx/sim_success[4]`;
- `e2e_mean/e2e_p95/e2e_retx/e2e_success[4]`;
- cell bootstrap: `EDHOC_HANDSHAKE_MEAN_MS`.

Periksa juga komentar teks di cell 0 yang menyebut angka lama, misalnya round-trip proposal.

---

## 8. Update paper (`paper/manuscript.tex`)

Semua nilai yang belum ada ditandai `\pend{…}` (teks merah). Isi lalu hapus:

| Baris | Isi |
|---|---|
| ~427, ~486, ~510 | hasil ProVerif `edhoc_m4v2_*.pv` (Langkah 9) |
| ~567 | mean e2e method 4, jumlah RADIUS round-trips |
| ~571 | round-trips (perbandingan dengan EAP-TLS Hybrid 28) |
| ~574 | success / latensi / retransmisi pada loss 20 % dan 30 % |
| ~598 | mean handshake di baseline bootstrapping |
| ~622 | porsi fragmentasi/round-trip |
| ~635 (Conclusion) | mean e2e |

Setelah selesai, hapus definisi macro `\pend` (sekitar baris 69) dan regenerate PNG grafik dari notebook. Nama file gambar tidak berubah.

---

## 9. ProVerif

```bash
cd proverif && ./run_all_v2.sh      # ProVerif 2.05
```

Hasil yang diharapkan:
- `classical` / `quantum`: Q0/Q1 false (reachable), lainnya true.
- `kci`: semua true.
- `pcs`: sanity false, Q2–Q4 (W2), Q10, Q11 true.
- `fs_noerase` (kontrol negatif): **Q5, Q8, Q9 false**.

Salin `results/SUMMARY.txt` ke tabel verifikasi paper.

---

## 10. Checklist verifikasi

- [ ] `edhoc4_selftest` PASS dengan 1141/4880/4975/1232; `edhoc03_selftest` ALL PASS.
- [ ] `grep -rn chacha20 edhoc4/` kosong; `ldd` FreeRADIUS module / `nr-ue` / `e2e_radius_bench` memuat `libmbedcrypto`.
- [ ] `grep -rn "eph_sk\|eph_pk\|ss_e\|kid" edhoc4/ freeradius-v3/src/modules/rlm_eap/types/rlm_eap_edhoc/ UERANSIM/src/ue/nas/sm/` kosong untuk method 4.
- [ ] Wireshark/tcpdump: Message1 = ct_B (1120 B) + ciphertext, tanpa pk_X dan tanpa kid.
- [ ] Setelah 2 sesi berturut-turut, isi `ue.creds` dan `edhoc_db/<id>/server.creds` berubah (`sha256sum`), dan sesi ke-3 tetap sukses.
- [ ] Uji kunci basi: kembalikan `ue.creds` lama → DN-AAA menolak setelah `prev/` terhapus.
- [ ] Uji Message4 hilang: drop EAP-Success sekali → sesi berikutnya sukses lewat `prev/`.
- [ ] `crypto_bench` method 4: initiator ≈ responder.
- [ ] Tabel 6 terisi, notebook dijalankan ulang, `\pend` habis, paper dikompilasi tanpa error.

## 11. Catatan terbuka

- **AEAD.** Sudah diganti ke AES-128-GCM (mbedTLS) di kode, sesuai paper bagian setup eksperimen; teks paper tidak perlu diubah. Karena method 0–3 ikut berganti AEAD, **ukur ulang juga e2e method 0–3** dalam run yang sama. Selisihnya kecil, tetapi angka lama diukur dengan ChaCha20-Poly1305.
- **Biaya rotasi.** Benchmark sekarang ikut mengukur penulisan file atomik (fsync) di UE dan DN-AAA. Sebutkan ini di bagian setup eksperimen.
