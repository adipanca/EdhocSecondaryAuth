# revisi-no-eph-step17.md: full-stack 5G core dengan protokol final v3

## Latar belakang

Semua angka waktu di paper (E2E, loss, recovery, storage) berasal dari `e2e_radius_bench`. Program ini menjadi EAP peer dan RADIUS client sekaligus, lalu langsung bicara ke FreeRADIUS. UERANSIM, AMF, SMF dan UPF tidak ikut terukur.

Log full-stack terakhir (`logs-live-20260722-*`) masih memakai protokol sebelum v3.

Tujuan step ini:
1. Membuktikan bahwa protokol final v3 berjalan lewat jalur penuh UE → gNB → AMF → SMF → UPF → FreeRADIUS.
2. Mengukur waktunya, dan memisahkan bagian 5G core dari bagian RADIUS/DN-AAA.

**Jangan mengubah protokol, format pesan atau kriptografi.** Yang boleh ditambahkan hanya log waktu dan skrip.

## 0. Build ulang dari HEAD branch `symmetry-no-eph`

1. Build `make -C edhoc4`, lalu UERANSIM, Open5GS (`build-ws`) dan FreeRADIUS (`rlm_eap_edhoc`). Semuanya harus memakai `libedhoc4.a` yang sama dengan `e2e_radius_bench`.
2. Jalankan `edhoc4_xwing_kat`, `edhoc4_selftest` dan `edhoc4_dbtest`. Semua harus PASS.
3. Provision ulang satu UE (IMSI yang dipakai `ue.yaml`) dengan record method 4 baru di UE dan di DN-AAA.

## 1. Instrumentasi waktu

Gunakan `clock_gettime(CLOCK_MONOTONIC)` dengan resolusi mikrodetik. Semua proses berjalan di VM yang sama, jadi stempel waktu antar-proses bisa dibandingkan langsung.

Format log satu baris:
`[E4T] <tag> t_us=<...> sess=<psi> len=<bytes>`

Lokasi tag:

| Proses | File | Tag |
|---|---|---|
| nr-ue | `src/ue/nas/sm/establishment.cpp` | `ue_pdu_req` saat PDU Session Establishment Request dikirim; `ue_pdu_acc` saat Accept diterima |
| nr-ue | `src/ue/nas/sm/transport.cpp` | `ue_cmd_rx` setiap Authentication Command diterima; `ue_cmpl_tx` setiap Complete dikirim (`len` = panjang EAP); `ue_store_next` (durasi tulis NEXT, µs); `ue_promote` (durasi promosi); `ue_result_rx` saat Authentication Result (EAP-Success) diterima |
| SMF | `src/smf/gsm-sm.c` | `smf_relay_begin` / `smf_relay_end` di sekitar setiap panggilan `smf_eap_relay_exchange` |
| UPF | `src/upf/eap-relay.c` | `upf_rad_tx` / `upf_rad_rx` di sekitar setiap Access-Request → Access-Challenge/Accept/Reject |
| FreeRADIUS | `rlm_eap_edhoc.c` | `aaa_commit` (durasi commit record, µs) |

**Cek kunci:**
- Di nr-ue dan `rlm_eap_edhoc`, log 8 byte pertama SHA-256(MSK) dengan tag `msk_tag`.
- Kunci tidak boleh dicetak.
- Aktifkan lewat variabel lingkungan `E4_TIMING=1`. Defaultnya mati.

## 2. Mode tanpa secondary authentication (baseline)

Tambahkan `OPEN5GS_SEC_AUTH=0` di SMF. Dengan mode ini, PDU session langsung diterima tanpa secondary auth. Jika toggle seperti ini sudah ada, pakai yang ada.

Mode ini dipakai untuk mengukur waktu PDU session tanpa EAP-EDHOC.

## 3. Skrip `benchmark/fullstack_bench.sh`

1. Jalankan `run_live_stack.sh`, `radiusd -f` (bukan `-X`), `nr-gnb`, lalu `nr-ue`.
2. Setiap iterasi:
   - `nr-cli <imsi> -e "ps-establish IPv4 --sst 1 --dnn <dnn>"`;
   - tunggu `ue_pdu_acc` atau timeout 5 s;
   - `ps-release <psi>`;
   - jeda 200 ms.
3. Lima iterasi pertama adalah warm-up dan dibuang.
4. **Konfigurasi A (secondary auth aktif):** 3 seri × 100 handshake.
5. **Konfigurasi B (`OPEN5GS_SEC_AUTH=0`):** 3 seri × 100 PDU session. Jalankan seri A dan B bergantian: A1, B1, A2, B2, A3, B3.
6. Simpan semua log di `benchmark-results/logs-fullstack-<timestamp>/`.

## 4. Uji pemulihan lewat full stack (smoke test)

Tambahkan opsi `E4_DROP_ONCE=msg3|msg4` di UPF relay. Opsi ini membuang satu kali Access-Request yang berisi Message3, atau Access-Challenge yang berisi Message4.

Jalankan 10 kali untuk setiap kasus, masing-masing diikuti 1 sesi normal. Yang diharapkan sama seperti step 13:

| Kasus | Sesi berikutnya |
|---|---|
| Message3 dibuang | mulai dengan NEXT → EAP-Failure → fallback ke CUR → sukses |
| Message4 dibuang | NEXT langsung sukses |

Hitung desync (harus 0) dan re-provisioning (harus 0). Simpan hasilnya di `fullstack-recovery.csv`.

## 5. Output

**`benchmark-results/fullstack-handshake.csv`**, satu baris per iterasi, dengan kolom:
- `config` (A/B), `series`, `iter`, `status`;
- `t_pdu_ms`: `ue_pdu_req` → `ue_pdu_acc`;
- `t_secauth_ms`: `ue_cmd_rx` pertama → `ue_result_rx`;
- `t_radius_ms`: jumlah semua `upf_rad_tx` → `upf_rad_rx`;
- `t_core_ms` = `t_secauth_ms` − `t_radius_ms`, yaitu UE + gNB + AMF + SMF + relay;
- `n_nas_rounds` (jumlah Command/Complete) dan `n_radius_rt`;
- `len_m1`, `len_m2`, `len_m3`, `len_m4`;
- `ue_store_next_ms`, `ue_promote_ms`, `aaa_commit_ms`;
- `msk_match` (tag UE = tag AAA), `rotated` (record UE dan DN-AAA berubah setelah sesi).

**Bagian baru di `analisys2.md` ("Full 5G core path")** berisi:
- mean, median, p95 dan bootstrap 95% CI untuk `t_pdu_ms` A dan B, `t_secauth_ms`, `t_radius_ms` dan `t_core_ms`;
- selisih `t_pdu_ms`(A) − `t_pdu_ms`(B), yaitu biaya secondary auth di dalam PDU session establishment;
- perbandingan `t_radius_ms` dengan E2E harness step 12–13 (7,159 ms mean, 6,582 ms median). Jelaskan selisihnya;
- jumlah sukses/gagal, `msk_match` (harus 100%) dan `rotated` (harus 100%);
- ukuran pesan dan jumlah ronde, yang harus sama dengan live harness: 2.358 / 6.097 / 3.756 / 16 B dan 15 RT. Jika berbeda, jelaskan;
- hasil uji pemulihan.

Catatan: UERANSIM tidak punya EAP-TLS peer, jadi EAP-TLS tidak diukur lewat full stack. Tulis ini di analisis, dan jangan menambahkan implementasi EAP-TLS ke UERANSIM.

## 6. Diagram arsitektur

Salin `testbed_architecture.drawio` dan `testbed_architecture.png` terlampir ke `symmetry-rev/figure/`.

## Commit

1. `instrument: E4_TIMING timestamps in nr-ue, SMF, UPF relay, rlm_eap_edhoc`
2. `smf: OPEN5GS_SEC_AUTH=0 baseline toggle`
3. `bench: full-stack 5G core benchmark and recovery smoke test`
4. `results: fullstack-handshake.csv, fullstack-recovery.csv, analisys2 full-stack section`
5. `figure: testbed architecture`

## Laporan balik

Kirimkan:
- tabel ringkasan dari bagian 5;
- hasil uji pemulihan;
- path folder log;
- hash commit.