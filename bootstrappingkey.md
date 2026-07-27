# Key Bootstrapping ke Aplikasi (dari EMSK) — Rencana Implementasi & Pengukuran

Dokumen ini mencakup dua bagian:
1. Prompt implementasi siap pakai untuk dikembangkan di atas Open5GS, FreeRADIUS, dan UERANSIM.
2. Rencana pengukuran (metrik) untuk fase Key Bootstrapping, disusun paralel dengan metodologi benchmark EAP-EDHOC yang sudah ada.

---

## 1. Prompt Implementasi

Prompt berikut bisa langsung ditempel ke Claude Code (atau dev assistant lain) yang sudah memiliki akses ke codebase Open5GS, FreeRADIUS, dan UERANSIM.

```
Konteks: Saya sudah mengimplementasikan EAP-EDHOC dengan otentikasi ML-DSA-44
sebagai metode secondary authentication di 5G core, berjalan di atas Open5GS
(SMF sebagai RADIUS client / EAP passthrough), FreeRADIUS (sebagai DN-AAA /
EAP server), dan UERANSIM (sebagai UE / EAP supplicant). Handshake ini sudah
menghasilkan EMSK yang identik di sisi UE dan di sisi FreeRADIUS setelah
Message4 selesai diproses.

Tugas: Implementasikan fase lanjutan Key Bootstrapping ke Aplikasi dari EMSK
tersebut, dengan komponen berikut:

1. Modul derivasi USRK/DSRK (RFC 5295)
   - Buat fungsi derive_usrk(EMSK, key_label, key_length) dan
     derive_dsrk(USRK, domain_label, key_length) menggunakan HKDF (atau KDF
     sesuai RFC 5295 §3.2) yang identik di kedua sisi (client library untuk
     UERANSIM, dan modul C/Python untuk FreeRADIUS).
   - Definisikan format key_label dan domain_label secara eksplisit
     (mis. "usrk@example.org,ekeylabel=EAP-EDHOC" untuk USRK,
     "dsrk@app-domain.example.org" untuk DSRK per-aplikasi).
   - Sediakan instrumentasi (timestamp start/end) di sekitar setiap
     pemanggilan KDF agar bisa diukur terpisah dari HKDF EDHOC utama.

2. Modul key transport AAA -> Application Server (AS)
   - Implementasikan channel transport (bisa mulai dari yang sederhana: mTLS
     antar container/service, atau REST endpoint internal dengan token
     pre-shared) yang membawa DSRK + ID_CREDI (atau identifier UE yang sudah
     dianonimkan) dari FreeRADIUS ke AS.
   - Catat: ini bukan protokol keamanan baru — nyatakan secara eksplisit di
     kode/README bahwa keamanannya bersandar pada asumsi trust-domain
     (co-located, mTLS, atau jaringan tertutup), sama seperti model ERP di
     RFC 6696.
   - Tambahkan logging timestamp: t_key_ready_at_AAA, t_key_sent,
     t_key_received_at_AS.

3. Application Server (AS) tiruan
   - Buat service ringan (mis. pakai libcoap atau aiocoap di Python) yang
     menjalankan OSCORE, menerima DSRK/USRK dari langkah 2, lalu menunggu
     koneksi dari UE.
   - Implementasikan derive_oscore_master_secret(DSRK) dan
     derive_oscore_master_salt(DSRK) sesuai OSCORE spec (RFC 8613 §3.2),
     dengan instrumentasi waktu yang sama.

4. Sisi UE (UERANSIM / supplicant)
   - Setelah EAP sukses dan EMSK tersedia, panggil urutan derivasi yang sama
     (USRK -> DSRK -> OSCORE Master Secret/Salt) secara lokal.
   - Setelah itu, lakukan first-contact ke AS (CoAP request pertama dengan
     OSCORE) dan catat sukses/gagalnya.

5. Verifikasi korespondensi kunci (hanya untuk keperluan pengujian, bukan
   produksi)
   - Tambahkan mode debug yang mengekspos hash dari DSRK/OSCORE Master
     Secret di kedua sisi (UE dan AS) supaya bisa diverifikasi keduanya
     identik selama pengujian, tanpa mengekspos kunci asli di log produksi.

6. Logging terstruktur untuk benchmarking
   - Semua timestamp di atas ditulis ke satu file log terstruktur
     (JSON/CSV) per sesi, dengan field:
     session_id, t_emsk_ready, t_usrk_derived, t_dsrk_derived,
     t_key_sent_aaa, t_key_received_as, t_oscore_secret_derived_ue,
     t_oscore_secret_derived_as, t_first_oscore_success, result(success/fail)

Tolong mulai dengan struktur modul/file yang diperlukan di masing-masing
repo (Open5GS/FreeRADIUS/UERANSIM/AS baru), sebelum menulis implementasi
detailnya.
```

---

## 2. Rencana Pengukuran Fase Key Bootstrapping

Struktur paralel dengan benchmark EAP-EDHOC yang sudah ada (success rate heatmap, retransmission vs packet loss, handshake latency vs packet loss, computation time per method, communication breakdown, percentile latency per packet loss, primitive cryptography time), ditambah metrik baru yang spesifik untuk fase ini.

### A. Metrik Latensi

| Metrik | Definisi | Kenapa Penting |
|---|---|---|
| **Key derivation time (USRK/DSRK)** | Waktu `derive_usrk` + `derive_dsrk` di sisi UE dan di sisi AAA, diukur terpisah | Overhead KDF murni — masuk kategori *primitive cryptography time*, bisa dibandingkan langsung dengan waktu X-Wing/ML-DSA yang sudah diukur |
| **Key transport latency (AAA → AS)** | `t_key_received_at_AS - t_key_sent` | Komponen baru yang tidak ada di fase EDHOC — perlu breakdown sendiri karena melibatkan network hop tambahan |
| **OSCORE derivation time** | Waktu derive Master Secret/Salt di UE & di AS | Overhead tambahan sebelum sesi aplikasi bisa mulai |
| **End-to-end bootstrap latency** | `t_first_oscore_success - t_emsk_ready` | **Metrik utama** — membuktikan klaim "tanpa login tambahan" secara kuantitatif: berapa lama dari EAP selesai sampai sesi aplikasi aktif |
| **Percentile latency (p50/p95/p99) vs packet loss** | Sama seperti benchmark existing, diterapkan ke leg AAA↔AS dan UE↔AS | Leg jaringan baru bisa punya karakteristik loss/delay berbeda dari leg UE↔SMF↔AAA |

### B. Metrik Keandalan (Reliability)

- **Success rate bootstrap end-to-end** vs packet loss/jitter pada tiap leg (AAA→AS dan UE→AS terpisah) — heatmap yang sama seperti benchmark success rate, tapi untuk fase ini.
- **Mean retransmission vs packet loss** untuk request key-transport (AAA→AS) dan first-contact OSCORE (UE→AS) — paralel dengan benchmark retransmission yang sudah ada.
- **Key consistency rate** — dari N sesi percobaan, persentase di mana hash `DSRK`/OSCORE Master Secret UE == AS (idealnya 100%, tapi wajib dilaporkan sebagai bukti correctness, bukan diasumsikan).

### C. Metrik Beban Sistem (Skalabilitas)

- **Throughput AAA server** — berapa key-bootstrap/detik yang bisa diproses FreeRADIUS di bawah beban CPU tertentu (overhead KDF di atas overhead ML-DSA yang sudah ada).
- **Throughput AS** — berapa sesi OSCORE baru/detik yang bisa di-handle AS.
- **Storage overhead per sesi** — byte state yang harus disimpan AAA (DSRK per UE per domain) dan AS (OSCORE context per UE) — relevan untuk skenario multi-aplikasi per UE.

### D. Metrik Perbandingan (Baseline)

- **Bootstrap latency ini vs estimasi waktu login manual/OAuth flow** (mis. authorization code grant: redirect + login form + token exchange) — sebagai angka literatur pembanding untuk memperkuat klaim UX "tanpa login manual".
- **Overhead relatif fase bootstrapping vs total waktu EAP-EDHOC** (persentase) — menjawab pertanyaan reviewer: apakah fase tambahan ini menambah beban signifikan terhadap total onboarding time.

### E. Yang Dilaporkan sebagai Batasan (bukan Metrik Performa)

- Keamanan channel AAA→AS — ini asumsi arsitektur (trust-domain), bukan sesuatu yang diverifikasi kriptografis dalam eksperimen. Taruh di bagian *threats to validity*, jangan dicampur dengan metrik performa.
- Perilaku saat re-authentication/handover (status DSRK lama di AS) — kalau belum diimplementasikan, sebutkan sebagai future work, jangan diukur seolah-olah sudah ditangani.

---

## 3. Langkah Berikutnya (opsional)

- Susun tabel desain eksperimen: variabel independen (packet loss %, jumlah sesi konkuren) vs variabel dependen (metrik-metrik di atas) untuk bagian *Evaluation Methodology* paper.
- Perluas diagram draw.io fase bootstrapping untuk menandai titik implementasi di masing-masing komponen (Open5GS, FreeRADIUS, UERANSIM, AS).