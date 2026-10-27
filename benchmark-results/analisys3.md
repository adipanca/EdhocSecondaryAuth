# Analisis Hasil Pengukuran Key Bootstrapping ke Aplikasi (dari EMSK)

_Dibuat otomatis oleh bootstrap/analyze_bootstrap.py pada 2026-10-27T17:27:02._

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
| Derive_USRK_RFC5295 | 3000 | 2527.1 | 2341.0 | 2448.0 | 3989.0 | 3219.5 |
| Derive_DSRK_RFC5295 | 3000 | 2575.0 | 2370.0 | 2509.0 | 3925.3 | 3069.3 |
| Derive_OSCORE_MasterSecret | 3000 | 1257.0 | 1146.0 | 1213.0 | 1985.1 | 2352.3 |
| Derive_OSCORE_MasterSalt | 3000 | 1222.6 | 1146.0 | 1186.0 | 1299.1 | 2072.1 |
| Derive_OSCORE_Context_RFC8613 | 3000 | 7465.3 | 6337.0 | 6645.6 | 34743.9 | 18294.5 |
| OSCORE_Protect_AESCCM | 3000 | 8484.0 | 7368.0 | 8573.2 | 20277.1 | 13726.1 |
| OSCORE_Unprotect_AESCCM | 3000 | 7614.4 | 6656.0 | 7326.2 | 18149.4 | 17649.0 |

## A2. Breakdown latensi per komponen (loss 0)

Rata-rata dari 1000 sesi tanpa loss. Waktu derivasi murni (kompute) dilaporkan dalam mikrodetik; leg jaringan dilaporkan terpisah di §A3/§B karena melibatkan hop tambahan.

| Komponen | Mean (µs) | p95 (µs) |
| --- | --- | --- |
| USRK+DSRK derivation (UE) | 5.661 | 5.653 |
| USRK+DSRK derivation (AAA) | 7.281 | 10.052 |
| OSCORE context derivation (UE) | 10.079 | 9.935 |
| OSCORE context derivation (AS) | 11.441 | 13.323 |

- **End-to-end bootstrap latency** (t_first_oscore_success − t_emsk_ready), jalur kritis, loss 0: **mean 0.4187 ms**, p95 0.4256 ms.

## A3. Percentile latency end-to-end vs packet loss

Latensi bootstrap end-to-end (kedua leg baru terkena loss yang sama) dengan retransmisi gaya EAP (RTO 40 ms, maks 6). Paralel dengan tabel *percentile latency per packet loss* pada benchmark utama.

| Loss % | Trials | Success % | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| 0.0 | 1000 | 100.0 | 0.4184 | 0.4158 | 0.4254 | 0.5013 |
| 1.0 | 1000 | 100.0 | 1.0578 | 0.4158 | 0.4262 | 40.4158 |
| 5.0 | 1000 | 100.0 | 4.5773 | 0.4157 | 40.4157 | 80.4153 |
| 10.0 | 1000 | 100.0 | 8.8972 | 0.4158 | 40.4163 | 80.4158 |
| 20.0 | 1000 | 100.0 | 19.6176 | 0.4161 | 80.4159 | 120.4159 |
| 30.0 | 1000 | 100.0 | 34.1775 | 40.4153 | 120.4158 | 160.4163 |

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
| AAA (USRK+DSRK) | 1 | 5.102 | 195,998 |
| AS (OSCORE master secret/salt + context) | 1 | 9.945 | 100,554 |

> Overhead KDF fase bootstrapping ini berada di orde puluhan µs, jauh di bawah biaya ML-DSA-44 sign (~238 µs) pada handshake EAP-EDHOC method 4, sehingga tidak menggeser bottleneck komputasi AAA.

Storage overhead state per sesi (relevan untuk skenario multi-aplikasi per UE):

| Sisi | State per UE per domain | Ukuran |
| --- | --- | --- |
| AAA | DSRK per UE per domain | 64 B |
| AS | OSCORE context (master secret/salt + sender/recipient key + IV) | 71 B |

## D. Perbandingan baseline (klaim UX 'tanpa login tambahan')

- **Bootstrap latency (fase ini)**: ~0.4187 ms (loss 0, jalur kritis).
- **Login manual/OAuth 2.0 (referensi literatur)**: ~2–10 detik untuk *authorization code grant* dengan input kredensial manusia + redirect (angka literatur/estimasi, bukan pengukuran di testbed ini).
- Selisih orde besaran: bootstrap otomatis ini **~4,776× lebih cepat** dari batas bawah estimasi login manual — mendukung klaim onboarding aplikasi tanpa langkah login tambahan.
- **Overhead relatif terhadap handshake EAP-EDHOC method 4** (mean end-to-end 19.383 ms, dari `analisys2.md`): fase bootstrapping menambah ~0.4187 ms (≈ **2.16%** dari waktu handshake utama) — kontribusi kecil terhadap total onboarding.

## E. Batasan & threats to validity

Bagian ini **bukan** metrik performa, melainkan batasan arsitektur/eksperimen:

1. **Keamanan channel AAA→AS adalah asumsi trust-domain**, bukan sesuatu yang diverifikasi kriptografis di sini. Transport DSRK memakai token pre-shared (bearer) dan bergantung pada co-location / mTLS / jaringan tertutup — model yang sama dengan ERP (RFC 6696). Ini bukan protokol keamanan baru.
2. **Emulasi loss** dilakukan di level aplikasi pada kedua leg baru (konsisten dengan metodologi `lossy_bench.py`/`e2e-lossy`), bukan via netem kernel; angka absolut latensi jaringan bersifat nominal (base RTT localhost), yang di-*stress* adalah pola retransmisi terhadap loss.
3. **Re-authentication / handover**: status DSRK lama di AS setelah re-auth belum ditangani; dicatat sebagai *future work*, tidak diukur seolah sudah selesai.
4. **OSCORE-lite**: proteksi kontak pertama memakai key schedule OSCORE nyata (RFC 8613 §3.2.1) + nonce (§5.2) + AES-CCM-16-64-128, tetapi bukan encoding CoAP/opsi OSCORE penuh; cukup untuk membuktikan kesepakatan kunci, belum interop dengan stack OSCORE pihak ketiga.
