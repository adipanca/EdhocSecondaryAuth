# Key Bootstrapping ke Aplikasi (dari EMSK)

Implementasi fase lanjutan setelah EAP-EDHOC secondary authentication: mem-
*bootstrap* kunci aplikasi langsung dari **EMSK** yang dihasilkan handshake
EAP-EDHOC (method 4, SIGMA XWING PQC), tanpa login tambahan di sisi aplikasi.

Spesifikasi lengkap: [`../bootstrappingkey.md`](../bootstrappingkey.md).

## Arsitektur

```
 EAP-EDHOC (sudah ada)                    fase Key Bootstrapping (folder ini)
 ─────────────────────                    ──────────────────────────────────
 UE  ── EAP ─► SMF ── RADIUS ─► FreeRADIUS
  │  (handshake XWING+ML-DSA)     │
  ▼                               ▼
 EMSK (identik) ───────────────► EMSK
  │                               │  derive_usrk (RFC 5295)
  │                               │  derive_dsrk (RFC 5295)
  │                               ▼
  │                          [AAA] ── DSRK/HTTP(token) ─► [AS]
  │ derive_usrk/dsrk                                       │ OSCORE master
  │ OSCORE master secret/salt                              │ secret/salt
  ▼                                                        ▼
 [UE] ───────── OSCORE first contact (CoAP-lite/UDP) ─► [AS]
        kontak pertama terlindungi = bukti kunci cocok
```

Rantai derivasi (identik di UE, AAA, dan AS — sumber tunggal `keyschedule.py`):

```
EMSK --RFC5295 §3.2--> USRK --RFC5295--> DSRK
DSRK --> OSCORE Master Secret / Master Salt
(Master Secret, Master Salt) --RFC8613 §3.2.1--> Sender/Recipient Key + Common IV
```

## Komponen

| File | Peran (bootstrappingkey.md) |
| --- | --- |
| `keyschedule.py` | §1.1 Modul derivasi USRK/DSRK (RFC 5295) + OSCORE (RFC 8613). Sumber kebenaran tunggal. |
| `oscore_lite.py` | Proteksi kontak pertama: OSCORE key schedule + nonce (RFC 8613 §5.2) + AES-CCM-16-64-128. |
| `aaa_keyexport.py` | §1.2 Sisi AAA/FreeRADIUS: EMSK → USRK → DSRK, transport DSRK ke AS (HTTP + bearer token). |
| `app_server.py` | §1.3 Application Server tiruan: penerima kunci (AAA→AS) + server OSCORE (UE→AS). |
| `ue_client.py` | §1.4 Sisi UE/UERANSIM: derivasi sama + kontak pertama OSCORE. |
| `verify_session.py` | §1.5 Verifikasi korespondensi kunci (fingerprint UE == AS) + rekap record sesi. |
| `botlog.py` | §1.6 Logging terstruktur JSON-Lines + record per sesi. |
| `bootstrap.c` / `bootstrap.h` / `selftest.c` | Modul **C** paritas untuk di-link ke `rlm_eap_edhoc` (FreeRADIUS) & UERANSIM. |
| `bootstrap_interop.py` | Cross-check C vs Python (byte-for-byte identik). |
| `bootstrap_bench.py` | Harness pengukuran (paralel metodologi `benchmark/`). |
| `analyze_bootstrap.py` | Menghasilkan `../benchmark-results/analisys3.md`. |
| `run_bootstrap_demo.sh` | Demo end-to-end multi-proses (socket nyata). |

## Menjalankan demo (aplikasi sederhana, end-to-end)

```bash
cd bootstrap
./run_bootstrap_demo.sh
```

Skrip akan: sintesis EMSK bersama (stand-in output EAP-EDHOC) → jalankan AS →
AAA derive & kirim DSRK → UE derive & kontak pertama OSCORE → cetak record sesi
`§1.6` dan cek konsistensi kunci. Contoh keluaran:

```
[AS] OSCORE first contact OK for demo-...: 'GET /bootstrap/hello (first contact)'
[UE] OSCORE first contact OK for demo-...: '2.05 Content: bootstrap OK, welcome UE'
Key consistency check: UE fp == AS fp -> MATCH (keys identical)
```

### Menghubungkan ke EAP-EDHOC nyata

Demo mensintesis satu EMSK acak lalu memberikannya ke sisi AAA **dan** UE —
persis yang dijamin handshake EAP-EDHOC yang sukses (EMSK identik di kedua sisi,
lihat `derive_prk_out_and_msk` di `../edhoc4/edhoc4.c`). Untuk memakai handshake
nyata, dump `sess->ctx.emsk` (FreeRADIUS) / `ctx->emsk` (UE) ke `emsk.hex` pada
build debug, lalu:

```bash
python3 app_server.py --jsonlog run.jsonl --expect 1 &
python3 aaa_keyexport.py --emsk-file emsk.hex --session-id S1 --jsonlog run.jsonl
python3 ue_client.py     --emsk-file emsk.hex --session-id S1 --jsonlog run.jsonl
python3 verify_session.py run.jsonl S1
```

## Modul C untuk integrasi (FreeRADIUS / UERANSIM)

`bootstrap.c` memakai libsodium HMAC-SHA256/SHA-256 — dependensi yang sama dengan
`libedhoc4.a` — dan menghasilkan kunci **byte-for-byte identik** dengan
`keyschedule.py` (dibuktikan `bootstrap_interop.py`).

```bash
make                 # libbootstrap.a + bootstrap_selftest (butuh header libsodium)
make interop         # assert paritas C vs Python
./bootstrap_selftest # fingerprint USRK/DSRK/OSCORE + cek korespondensi konteks
```

Pemakaian dari kode responder/inititator (setelah handshake selesai):

```c
#include "bootstrap.h"
uint8_t usrk[BK_USRK_LEN], dsrk[BK_DSRK_LEN];
bk_oscore_ctx octx;
bk_derive_usrk(ctx.emsk, BK_EMSK_LEN, BK_USRK_KEY_LABEL, usrk, sizeof usrk);
bk_derive_dsrk(usrk, sizeof usrk, BK_DSRK_DOMAIN_LABEL, dsrk, sizeof dsrk);
bk_oscore_ctx_from_dsrk(dsrk, sizeof dsrk, /*sender*/1, /*recipient*/0, &octx);
```

## Pengukuran & analisis

```bash
python3 bootstrap_bench.py            # tulis CSV ke ../benchmark-results/
python3 analyze_bootstrap.py          # tulis ../benchmark-results/analisys3.md
```

CSV: `bootstrap-primitives.csv`, `bootstrap-latency.csv`, `bootstrap-lossy.csv`,
`bootstrap-e2e-lossy.csv`, `bootstrap-consistency.csv`. Dokumen `analisys3.md`
mengikuti rencana metrik `bootstrappingkey.md §2` (A latensi, B keandalan,
C skalabilitas, D baseline, E batasan) dan paralel dengan `analysis.md` /
`analisys2.md`.

## Model keamanan (penting)

Ini **bukan protokol keamanan baru**. Keamanan hop **AAA→AS** bersandar pada
asumsi *trust-domain* (co-located / mTLS / jaringan tertutup + token pre-shared),
model yang sama dengan ERP pada RFC 6696. `oscore_lite.py` memakai key schedule
OSCORE nyata (RFC 8613 §3.2.1/§5.2) + AES-CCM-16-64-128, tetapi bukan encoding
CoAP/opsi OSCORE penuh — cukup untuk membuktikan kesepakatan kunci. Batasan
lengkap ada di bagian **E** `analisys3.md`.
