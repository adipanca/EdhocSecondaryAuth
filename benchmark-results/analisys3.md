# Analisis Hasil Pengukuran Key Bootstrapping ke Aplikasi (dari EMSK)

_Dibuat otomatis oleh bootstrap/analyze_bootstrap.py pada 2026-10-27T17:49:26._

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
| Derive_USRK_RFC5295 | 3000 | 2658.3 | 2359.0 | 2459.0 | 4019.1 | 5787.8 |
| Derive_DSRK_RFC5295 | 3000 | 2483.6 | 2363.0 | 2437.0 | 2591.1 | 2563.7 |
| Derive_OSCORE_MasterSecret | 3000 | 1281.9 | 1152.0 | 1196.0 | 1361.2 | 2990.7 |
| Derive_OSCORE_MasterSalt | 3000 | 1219.1 | 1140.0 | 1182.0 | 1366.2 | 1890.8 |
| Derive_OSCORE_Context_RFC8613 | 3000 | 6916.8 | 6324.0 | 6508.1 | 25031.2 | 5552.4 |
| OSCORE_Protect_AESCCM | 3000 | 7584.3 | 7104.0 | 7694.0 | 15908.7 | 5005.2 |
| OSCORE_Unprotect_AESCCM | 3000 | 7367.8 | 6401.0 | 7340.6 | 29213.5 | 9041.3 |

## A2. Breakdown latensi per komponen (loss 0)

Rata-rata dari 1000 sesi tanpa loss. Waktu derivasi murni (kompute) dilaporkan dalam mikrodetik; leg jaringan dilaporkan terpisah di §A3/§B karena melibatkan hop tambahan.

| Komponen | Mean (µs) | p95 (µs) |
| --- | --- | --- |
| USRK+DSRK derivation (UE) | 5.540 | 5.825 |
| USRK+DSRK derivation (AAA) | 6.944 | 8.696 |
| OSCORE context derivation (UE) | 9.831 | 9.820 |
| OSCORE context derivation (AS) | 11.388 | 13.269 |

- **End-to-end bootstrap latency** (t_first_oscore_success − t_emsk_ready), jalur kritis, loss 0: **mean 0.4183 ms**, p95 0.4253 ms.

## A3. Percentile latency end-to-end vs packet loss

Latensi bootstrap end-to-end (kedua leg baru terkena loss yang sama) dengan retransmisi gaya EAP (RTO 40 ms, maks 6). Paralel dengan tabel *percentile latency per packet loss* pada benchmark utama.

| Loss % | Trials | Success % | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 0.0 | 1000 | 100.0 | 0.4176 | 0.4158 | 0.4243 | 0.4668 |
| 1.0 | 1000 | 100.0 | 1.0578 | 0.4158 | 0.4266 | 40.4157 |
| 5.0 | 1000 | 100.0 | 4.578 | 0.4157 | 40.4157 | 80.4154 |
| 10.0 | 1000 | 100.0 | 8.8981 | 0.4158 | 40.4164 | 80.4157 |
| 20.0 | 1000 | 100.0 | 19.6177 | 0.416 | 80.4159 | 120.4157 |
| 30.0 | 1000 | 100.0 | 34.1776 | 40.4153 | 120.4157 | 160.4166 |

## B1. Keandalan per-leg vs packet loss (success rate & retransmisi)

Dua leg jaringan **baru** yang diperkenalkan fase ini diukur terpisah: `AAA→AS` (transport DSRK) dan `UE→AS` (kontak pertama OSCORE). Paralel dengan *success rate heatmap* dan *retransmission vs packet loss*.

| Leg | Loss % | Trials | Success % | Mean (ms) | p95 (ms) | p99 (ms) | Mean retx |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AAA->AS | 0.0 | 1000 | 100.0 | 0.2 | 0.2 | 0.2 | 0 |
| UE->AS | 0.0 | 1000 | 100.0 | 0.2 | 0.2 | 0.2 | 0 |
| AAA->AS | 1.0 | 1000 | 100.0 | 0.48 | 0.2 | 0.2 | 0.007 |
| UE->AS | 1.0 | 1000 | 100.0 | 0.56 | 0.2 | 0.2 | 0.009 |
| AAA->AS | 5.0 | 1000 | 100.0 | 2.56 | 40.2 | 40.2 | 0.059 |
| UE->AS | 5.0 | 1000 | 100.0 | 2.0 | 0.2 | 40.2 | 0.045 |
| AAA->AS | 10.0 | 1000 | 100.0 | 4.44 | 40.2 | 40.2 | 0.106 |
| UE->AS | 10.0 | 1000 | 100.0 | 4.44 | 40.2 | 80.2 | 0.106 |
| AAA->AS | 20.0 | 1000 | 100.0 | 9.96 | 40.2 | 80.2 | 0.244 |
| UE->AS | 20.0 | 1000 | 100.0 | 9.64 | 40.2 | 80.2 | 0.236 |
| AAA->AS | 30.0 | 1000 | 100.0 | 17.04 | 80.2 | 120.2 | 0.421 |
| UE->AS | 30.0 | 1000 | 100.0 | 17.12 | 80.2 | 160.2 | 0.423 |

## B2. Key consistency rate

Persentase sesi di mana fingerprint OSCORE Master Secret sisi UE == sisi AS (bukti *correctness* derivasi identik, bukan asumsi).

| Sesi | Konsisten | Rate % |
| --- | --- | --- |
| 6000 | 6000 | 100.0 |

- Konsistensi kunci: **6000/6000 (100.0%)** — semua sesi menghasilkan konteks OSCORE identik di UE dan AS.

## C. Beban sistem & skalabilitas

Throughput derivasi (single-core, batas atas hanya-kompute, mengabaikan I/O):

| Komponen | Derivasi/sesi | Waktu/ sesi (µs) | Throughput (sesi/detik/core) |
| --- | --- | --- | --- |
| AAA (USRK+DSRK) | 1 | 5.142 | 194,481 |
| AS (OSCORE master secret/salt + context) | 1 | 9.418 | 106,182 |

> Overhead KDF fase bootstrapping ini berada di orde puluhan µs, jauh di bawah biaya ML-DSA-44 sign (~238 µs) pada handshake EAP-EDHOC method 4, sehingga tidak menggeser bottleneck komputasi AAA.

Storage overhead state per sesi (relevan untuk skenario multi-aplikasi per UE):

| Sisi | State per UE per domain | Ukuran |
| --- | --- | --- |
| AAA | DSRK per UE per domain | 64 B |
| AS | OSCORE context (master secret/salt + sender/recipient key + IV) | 71 B |

## D. Perbandingan baseline (klaim UX 'tanpa login tambahan')

- **Bootstrap latency (fase ini)**: ~0.4183 ms (loss 0, jalur kritis).
- **Login manual/OAuth 2.0 (referensi literatur)**: ~2–10 detik untuk *authorization code grant* dengan input kredensial manusia + redirect (angka literatur/estimasi, bukan pengukuran di testbed ini).
- Selisih orde besaran: bootstrap otomatis ini **~4,781× lebih cepat** dari batas bawah estimasi login manual — mendukung klaim onboarding aplikasi tanpa langkah login tambahan.
- **Overhead relatif terhadap handshake EAP-EDHOC method 4** (mean end-to-end 14.733 ms, dari `analisys2.md`): fase bootstrapping menambah ~0.4183 ms (≈ **2.84%** dari waktu handshake utama) — kontribusi kecil terhadap total onboarding.

## E. Batasan & threats to validity

Bagian ini **bukan** metrik performa, melainkan batasan arsitektur/eksperimen:

1. **Keamanan channel AAA→AS adalah asumsi trust-domain**, bukan sesuatu yang diverifikasi kriptografis di sini. Transport DSRK memakai token pre-shared (bearer) dan bergantung pada co-location / mTLS / jaringan tertutup — model yang sama dengan ERP (RFC 6696). Ini bukan protokol keamanan baru.
2. **Emulasi loss** dilakukan di level aplikasi pada kedua leg baru (konsisten dengan metodologi `lossy_bench.py`/`e2e-lossy`), bukan via netem kernel; angka absolut latensi jaringan bersifat nominal (base RTT localhost), yang di-*stress* adalah pola retransmisi terhadap loss.
3. **Re-authentication / handover**: status DSRK lama di AS setelah re-auth belum ditangani; dicatat sebagai *future work*, tidak diukur seolah sudah selesai.
4. **OSCORE-lite**: proteksi kontak pertama memakai key schedule OSCORE nyata (RFC 8613 §3.2.1) + nonce (§5.2) + AES-CCM-16-64-128, tetapi bukan encoding CoAP/opsi OSCORE penuh; cukup untuk membuktikan kesepakatan kunci, belum interop dengan stack OSCORE pihak ketiga.
