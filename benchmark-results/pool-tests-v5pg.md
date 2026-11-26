# Test pool kunci berikutnya (live, v5-pregen)

Kernel `7.0.0-38-generic`. Sumber: `benchmark/pool_tests.sh`, mentah di `benchmark-results/pool-tests-v5pg/`.
UE = `e2e_radius_bench` (pool satu kunci, diisi sebelum jam mulai); DN-AAA = radiusd dengan `xwing_pool_size` 64 kecuali disebut lain.
Penghitung DN-AAA dari baris yang ditulis `rlm_eap_edhoc` saat radiusd berhenti.

| Test | UE: sukses | UE: pool_miss | DN-AAA: mode, ukuran | DN-AAA: diambil / pool_miss / inline | Keunikan dan catatan | Hasil |
|---|---|---|---|---|---|---|
| 1000 handshake berurutan, pregen | 1000/1000 | 0 | pregen, 64 | 1000 / 0 / 0 | Npk_A 1000/1000 unik, Npk_B 1000/1000 unik, tidak ada Npk_A = Npk_B | PASS |
| Message2 dibuang, lalu run baru | 1/2 | 0 | pregen, 64 | 2 / 0 / 0 | run ulang memakai Npk_A baru; Nsk_A = 0 di ctx yang dihapus (UE); Message2 tidak pernah diproses, jadi tidak ada Npk_B | PASS |
| 100 UE paralel × 5 run, pregen 64 | 500/500 | 0 | pregen, 64 | 501 / 0 / 0 | 1000 kunci (Npk_A dan Npk_B), dipakai dua kali: 0; level pool terendah saat commit: 39 | PASS |
| `xwing_pool_size = 0` | 5/5 | 0 | pregen, 0 | 0 / 5 / 0 | setiap pengambilan jatuh ke KeyGen inline (5 pool_miss = jumlah run) | PASS |
| Restart radiusd | 3/3 sebelum, 3/3 sesudah | 0 | pregen, 64 | 3 / 0 / 0 (sesudah) | pool dibuat ulang saat start: 64 kunci dalam 3.9 ms | PASS |
| Mode inline (UE dan DN-AAA) | 5/5 | 0 | inline, 0 | 0 / 0 / 5 | ukuran Message1–4: 2424/6097/3756/16 B; pool tidak dipakai | PASS |

### Beban background DN-AAA (100 UE paralel)

| Ukuran | Nilai |
|---|---|
| Durasi uji (s) | 8.76 |
| CPU radiusd selama uji (s) | 20.68 |
| CPU thread isi ulang `e4-keypool` selama uji (s) | 0.23 |
| Porsi thread isi ulang dari CPU radiusd | 1.1 % |
| Kunci dibuat thread isi ulang | 501 |
| CPU per kunci, thread isi ulang (µs) | 264.4 |
| Pool pernah habis (pool_miss) | 0 |
| Level pool terendah saat commit | 39 dari 64 |

CPU per kunci di thread isi ulang lebih tinggi di bawah beban paralel (264.4 µs) daripada pada uji berurutan (89.6 µs). Penyebabnya tidak diukur terpisah; thread itu berjalan dengan nice 19 bersama thread radiusd lain. CPU ini dipakai di luar pemrosesan pesan, tetapi tetap memakai core yang sama dengan radiusd.

**Semua test: PASS**
