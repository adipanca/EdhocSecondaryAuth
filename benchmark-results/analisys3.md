# Analisis Hasil Pengukuran Key Bootstrapping ke Aplikasi (dari EMSK)

_Dibuat otomatis oleh bootstrap/analyze_bootstrap.py pada 2026-07-28T04:57:40._

Dokumen ini adalah kelanjutan dari `analysis.md` (microbench EAP-EDHOC) dan `analisys2.md` (end-to-end EAP-over-RADIUS). Fokusnya adalah fase **Key Bootstrapping ke Aplikasi**: turunan USRK/DSRK (RFC 5295) dari EMSK hasil handshake EAP-EDHOC, transport DSRK dari AAA ke Application Server (AS), derivasi konteks OSCORE (RFC 8613), dan kontak pertama UE↔AS. Kolom dibuat sebisa mungkin paralel dengan kedua dokumen sebelumnya agar overhead fase ini dapat dibandingkan langsung dengan handshake utama.

Rantai kunci yang diukur:

```
EMSK --USRK(RFC5295)--> USRK --DSRK(RFC5295)--> DSRK
DSRK --> OSCORE Master Secret/Salt --> (RFC8613 §3.2.1) Sender/Recipient Key + Common IV
```

## A1. Waktu derivasi primitif (Key derivation time)

Latensi per operasi derivasi kunci fase bootstrapping (pengukuran nyata HKDF-SHA256 / AES-CCM via pustaka cryptography). Ini kategori *primitive cryptography time* — dapat dibandingkan langsung dengan tabel 1a `analysis.md` (X-Wing/ML-DSA).

| Operation | Iter | Mean (ns) | Median (ns) | p95 (ns) | p99 (ns) | Stddev (ns) |
| --- | --- | --- | --- | --- | --- | --- |
| Derive_USRK_RFC5295 | 5000 | 2498.8 | 2375.0 | 2833.0 | 4459.3 | 1768.8 |
| Derive_DSRK_RFC5295 | 5000 | 2416.3 | 2375.0 | 2459.0 | 2708.0 | 1106.2 |
| Derive_OSCORE_MasterSecret | 5000 | 1170.8 | 1167.0 | 1209.0 | 1250.0 | 184.7 |
| Derive_OSCORE_MasterSalt | 5000 | 1171.1 | 1167.0 | 1209.0 | 1209.0 | 170.2 |
| Derive_OSCORE_Context_RFC8613 | 5000 | 6485.1 | 6375.0 | 6625.0 | 8336.1 | 1162.6 |
| OSCORE_Protect_AESCCM | 5000 | 7920.5 | 7833.0 | 8083.0 | 10333.0 | 625.9 |
| OSCORE_Unprotect_AESCCM | 5000 | 6938.3 | 6876.0 | 7000.0 | 7334.4 | 469.6 |

## A2. Breakdown latensi per komponen (loss 0)

Rata-rata dari 2000 sesi tanpa loss. Waktu derivasi murni (kompute) dilaporkan dalam mikrodetik; leg jaringan dilaporkan terpisah di §A3/§B karena melibatkan hop tambahan.

| Komponen | Mean (µs) | p95 (µs) |
| --- | --- | --- |
| USRK+DSRK derivation (UE) | 4.802 | 4.875 |
| USRK+DSRK derivation (AAA) | 5.160 | 5.209 |
| OSCORE context derivation (UE) | 8.698 | 8.791 |
| OSCORE context derivation (AS) | 9.066 | 9.542 |

- **End-to-end bootstrap latency** (t_first_oscore_success − t_emsk_ready), jalur kritis, loss 0: **mean 0.4142 ms**, p95 0.4150 ms.

## A3. Percentile latency end-to-end vs packet loss

Latensi bootstrap end-to-end (kedua leg baru terkena loss yang sama) dengan retransmisi gaya EAP (RTO 40 ms, maks 6). Paralel dengan tabel *percentile latency per packet loss* pada benchmark utama.

| Loss % | Trials | Success % | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 0.0 | 2000 | 100.0 | 0.4139 | 0.4138 | 0.414 | 0.4185 |
| 1.0 | 2000 | 100.0 | 1.0144 | 0.4139 | 0.4158 | 40.4137 |
| 5.0 | 2000 | 100.0 | 4.494 | 0.4139 | 40.4138 | 40.4142 |
| 10.0 | 2000 | 100.0 | 8.9541 | 0.4139 | 40.4141 | 80.4139 |
| 20.0 | 2000 | 100.0 | 20.2742 | 0.4141 | 80.414 | 120.4141 |
| 30.0 | 2000 | 100.0 | 35.0343 | 40.4138 | 120.4141 | 200.414 |

## B1. Keandalan per-leg vs packet loss (success rate & retransmisi)

Dua leg jaringan **baru** yang diperkenalkan fase ini diukur terpisah: `AAA→AS` (transport DSRK) dan `UE→AS` (kontak pertama OSCORE). Paralel dengan *success rate heatmap* dan *retransmission vs packet loss*.

| Leg | Loss % | Trials | Success % | Mean (ms) | p95 (ms) | p99 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AAA->AS | 0.0 | 2000 | 100.0 | 0.2 | 0.2 | 0.2 | 0 |
| UE->AS | 0.0 | 2000 | 100.0 | 0.2 | 0.2 | 0.2 | 0 |
| AAA->AS | 1.0 | 2000 | 100.0 | 0.5 | 0.2 | 0.2 | 0.0075 |
| UE->AS | 1.0 | 2000 | 100.0 | 0.5 | 0.2 | 0.2 | 0.0075 |
| AAA->AS | 5.0 | 2000 | 100.0 | 1.94 | 0.2 | 40.2 | 0.0435 |
| UE->AS | 5.0 | 2000 | 100.0 | 2.54 | 40.2 | 40.2 | 0.0585 |
| AAA->AS | 10.0 | 2000 | 100.0 | 4.5 | 40.2 | 40.2 | 0.1075 |
| UE->AS | 10.0 | 2000 | 100.0 | 4.44 | 40.2 | 80.2 | 0.106 |
| AAA->AS | 20.0 | 2000 | 100.0 | 10.02 | 40.2 | 80.2 | 0.2455 |
| UE->AS | 20.0 | 2000 | 100.0 | 10.24 | 40.2 | 80.2 | 0.251 |
| AAA->AS | 30.0 | 2000 | 100.0 | 18.5 | 80.2 | 120.2 | 0.4575 |
| UE->AS | 30.0 | 2000 | 100.0 | 16.52 | 80.2 | 120.2 | 0.408 |

## B2. Key consistency rate

Persentase sesi di mana fingerprint OSCORE Master Secret sisi UE == sisi AS (bukti *correctness* derivasi identik, bukan asumsi).

| Sesi | Konsisten | Rate % |
| --- | --- | --- |
| 12000 | 12000 | 100.0 |

- Konsistensi kunci: **12000/12000 (100.0%)** — semua sesi menghasilkan konteks OSCORE identik di UE dan AS.

## C. Beban sistem & skalabilitas

Throughput derivasi (single-core, batas atas hanya-kompute, mengabaikan I/O):

| Komponen | Derivasi/sesi | Waktu/ sesi (µs) | Throughput (sesi/detik/core) |
| --- | --- | --- | --- |
| AAA (USRK+DSRK) | 1 | 4.915 | 203,455 |
| AS (OSCORE master secret/salt + context) | 1 | 8.827 | 113,289 |

> Overhead KDF fase bootstrapping ini berada di orde puluhan µs, jauh di bawah biaya ML-DSA-44 sign (~238 µs) pada handshake EAP-EDHOC method 4, sehingga tidak menggeser bottleneck komputasi AAA.

Storage overhead state per sesi (relevan untuk skenario multi-aplikasi per UE):

| Sisi | State per UE per domain | Ukuran |
| --- | --- | --- |
| AAA | DSRK per UE per domain | 64 B |
| AS | OSCORE context (master secret/salt + sender/recipient key + IV) | 71 B |

## D. Perbandingan baseline (klaim UX 'tanpa login tambahan')

- **Bootstrap latency (fase ini)**: ~0.4142 ms (loss 0, jalur kritis).
- **Login manual/OAuth 2.0 (referensi literatur)**: ~2–10 detik untuk *authorization code grant* dengan input kredensial manusia + redirect (angka literatur/estimasi, bukan pengukuran di testbed ini).
- Selisih orde besaran: bootstrap otomatis ini **~4,828× lebih cepat** dari batas bawah estimasi login manual — mendukung klaim onboarding aplikasi tanpa langkah login tambahan.
- **Overhead relatif terhadap handshake EAP-EDHOC method 4** (mean end-to-end 6.971 ms, dari `analisys2.md`): fase bootstrapping menambah ~0.4142 ms (≈ **5.94%** dari waktu handshake utama) — kontribusi kecil terhadap total onboarding.

## E. Batasan & threats to validity

Bagian ini **bukan** metrik performa, melainkan batasan arsitektur/eksperimen:

1. **Keamanan channel AAA→AS adalah asumsi trust-domain**, bukan sesuatu yang diverifikasi kriptografis di sini. Transport DSRK memakai token pre-shared (bearer) dan bergantung pada co-location / mTLS / jaringan tertutup — model yang sama dengan ERP (RFC 6696). Ini bukan protokol keamanan baru.
2. **Emulasi loss** dilakukan di level aplikasi pada kedua leg baru (konsisten dengan metodologi `lossy_bench.py`/`e2e-lossy`), bukan via netem kernel; angka absolut latensi jaringan bersifat nominal (base RTT localhost), yang di-*stress* adalah pola retransmisi terhadap loss.
3. **Re-authentication / handover**: status DSRK lama di AS setelah re-auth belum ditangani; dicatat sebagai *future work*, tidak diukur seolah sudah selesai.
4. **OSCORE-lite**: proteksi kontak pertama memakai key schedule OSCORE nyata (RFC 8613 §3.2.1) + nonce (§5.2) + AES-CCM-16-64-128, tetapi bukan encoding CoAP/opsi OSCORE penuh; cukup untuk membuktikan kesepakatan kunci, belum interop dengan stack OSCORE pihak ketiga.
