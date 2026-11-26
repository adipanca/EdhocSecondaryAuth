### Tabel ringkas angka untuk paper (v5-pregen)

Semua nilai dibaca dari file sumber oleh `benchmark/v5pg_analyze.py`.

| Angka | Nilai | Sumber | Kolom |
|---|---|---|---|
| Test pool: 1000 handshake berurutan, Npk_A / Npk_B unik, pool_miss UE / DN-AAA | 1000/1000, 1000/1000, 0 / 0 | `pool-tests-v5pg/seq.keys, seq.ue, seq.pool` | fingerprint Npk_A, Npk_B; pool_miss |
| Test pool: 100 UE paralel × 5, kunci dipakai dua kali, pool_miss DN-AAA | 0, 0 | `pool-tests-v5pg/par-*.keys, par.pool` | fingerprint; pool_miss |
| v5-pregen: mean / median / p95 (ms) | 8.518 / 6.916 / 15.926 | `e2e-handshake-v5pg.csv` | duration_ms, method 4, label pregen-run* |
| v5-pregen: 95% CI median (ms) | [6.610, 7.221] | `e2e-handshake-v5pg.csv` | duration_ms, method 4, label pregen-run* |
| v5-pregen: UE lokal mean (ms) | 1.447 | `e2e-handshake-v5pg.csv` | initiator_ms, method 4, label pregen-run* |
| v5-pregen: tunggu balasan mean (ms) | 7.071 | `e2e-handshake-v5pg.csv` | responder_ms, method 4, label pregen-run* |
| v5-inline: mean / median / p95 (ms) | 7.842 / 7.293 / 11.264 | `e2e-handshake-v5pg.csv` | duration_ms, method 4, label inline-run* |
| v5-inline: 95% CI median (ms) | [7.209, 7.470] | `e2e-handshake-v5pg.csv` | duration_ms, method 4, label inline-run* |
| v5-inline: UE lokal mean (ms) | 1.444 | `e2e-handshake-v5pg.csv` | initiator_ms, method 4, label inline-run* |
| v5-inline: tunggu balasan mean (ms) | 6.398 | `e2e-handshake-v5pg.csv` | responder_ms, method 4, label inline-run* |
| EAP-TLS Hybrid PQC: mean / median / p95 (ms) | 11.328 / 9.998 / 18.073 | `e2e-handshake-v5pg.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: 95% CI median (ms) | [9.784, 10.345] | `e2e-handshake-v5pg.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: UE lokal mean (ms) | 0.867 | `e2e-handshake-v5pg.csv` | initiator_ms, method 6 |
| EAP-TLS Hybrid PQC: tunggu balasan mean (ms) | 10.461 | `e2e-handshake-v5pg.csv` | responder_ms, method 6 |
| v5-pregen − v5-inline: selisih median [95% CI] (ms) | -0.377 [-0.715, -0.063] | `e2e-handshake-v5pg.csv` | duration_ms |
| EAP-TLS Hybrid PQC − v5-pregen: selisih median [95% CI] (ms) | 3.082 [2.706, 3.530] | `e2e-handshake-v5pg.csv` | duration_ms |
| Figure 7 kiri, v5-inline: initiator / responder (µs) | 484.917 / 484.917 | `compute-v5pg/handshake-compute-v5pg.csv` | initiator_compute_us, responder_compute_us |
| Figure 7 kiri, v5-pregen: initiator / responder (µs) | 430.501 / 430.501 | `compute-v5pg/handshake-compute-v5pg.csv` | initiator_compute_us, responder_compute_us |
| Figure 7 kiri, KeyGen yang dipindah (per peran): initiator / responder (µs) | 54.416 / 54.416 | `compute-v5pg/handshake-compute-v5pg.csv` | initiator_compute_us, responder_compute_us |
| Figure 7 kiri, EAP-TLS Hybrid PQC: initiator / responder (µs) | 465.472 / 427.426 | `compute-v5pg/handshake-compute-v5pg.csv` | initiator_compute_us, responder_compute_us |
| KeyGen yang dipindah per pihak, median primitif (µs) | 49.081 | `compute-v5pg/crypto-primitives.csv` | median_ns, Keygen_MLKEM768 + Keygen_X25519 |
| Dalam proses, v5-inline: initiator / responder median (µs) | 517.3 / 515.4 | `m4-inprocess-compute-v5pg.csv` | initiator_median_us, responder_median_us, label inline-r* |
| Dalam proses, v5-pregen: initiator / responder median (µs) | 459.7 / 459.8 | `m4-inprocess-compute-v5pg.csv` | initiator_median_us, responder_median_us, label pregen-r* |
| Dalam proses, inline − pregen: initiator / responder (µs) | 57.6 / 55.6 | `m4-inprocess-compute-v5pg.csv` | initiator_median_us, responder_median_us |
| Isi ulang per kunci, dalam proses: median / mean (µs) | 51.5 / 57.3 | `m4-inprocess-compute-v5pg.csv` | refill_median_us_per_key, refill_mean_us_per_key |
| Isi ulang per kunci, thread radiusd live: berurutan / 100 UE paralel (µs CPU) | 89.6 / 264.4 | `pool-tests-v5pg/seq.pool, par.pool` | refill CPU us/key |
| Full stack: sukses A / B | 300/300, 300/300 | `fullstack-handshake-v5pg.csv` | status |
| Full stack: pool_miss UE / DN-AAA | 0 / 0 | `logs-fullstack-v5pg-20261126-105441/{*/ue.log, aaa-e4t.txt}` | pool_miss di [E4T] ue_msg1 / aaa_commit |
| Tabel 6 (pregen), Added: median [CI] / mean (ms) | 85.2 [83.3, 87.7] / 93.7 | `fullstack-handshake-v5pg.csv` | t_pdu_ms, A − B |
| Tabel 6 (pregen), Secondary authentication at the UE: median [CI] / mean / p95 (ms) | 85.1 [83.5, 86.9] / 95.8 / 151.6 | `fullstack-handshake-v5pg.csv` | t_secauth_ms, A |
| Tabel 6 (pregen), 5G core transport (UE, gNB, AMF, SMF): median [CI] / mean / p95 (ms) | 78.2 [76.6, 80.2] / 88.0 / 142.0 | `fullstack-handshake-v5pg.csv` | t_core_ms, A |
| Tabel 6 (pregen), SMF ↔ UPF relay hop: median [CI] / mean / p95 (ms) | 3.3 [3.3, 3.4] / 4.2 / 9.1 | `fullstack-handshake-v5pg.csv` | t_hop_smf_upf_ms, A |
| Tabel 6 (pregen), RADIUS processing in the UPF relay: median [CI] / mean / p95 (ms) | 1.0 [0.9, 1.0] / 1.3 / 3.0 | `fullstack-handshake-v5pg.csv` | t_relay_proc_ms, A |
| Tabel 6 (pregen), DN-AAA (FreeRADIUS, from the UPF relay): median [CI] / mean / p95 (ms) | 6.6 [6.4, 6.9] / 7.8 / 13.9 | `fullstack-handshake-v5pg.csv` | t_aaa_ms, A |
| Tabel 6 (pregen), UE write of NEXT (before Message3): median [CI] / mean / p95 (ms) | 1.16 [0.95, 1.68] / 1.85 / 3.65 | `fullstack-handshake-v5pg.csv` | ue_store_next_ms, A |
| Tabel 6 (pregen), DN-AAA commit (before Message4): median [CI] / mean / p95 (ms) | 0.71 [0.69, 0.72] / 0.95 / 1.93 | `fullstack-handshake-v5pg.csv` | aaa_commit_ms, A |
| Tabel 6 (pregen), UE promotion (after Message4): median [CI] / mean / p95 (ms) | 0.64 [0.62, 0.65] / 0.92 / 2.32 | `fullstack-handshake-v5pg.csv` | ue_promote_ms, A |
| Pemulihan (pregen), Message3 dibuang: median / mean (ms) | 1424.9 / 1424.3 | `fullstack-recovery-v5pg.csv` | t_recovery_ms |
| Pemulihan (pregen), Message4 dibuang: median / mean (ms) | 101.6 / 104.7 | `fullstack-recovery-v5pg.csv` | t_recovery_ms |
| Pemulihan (pregen): desync, re-provisioning | 0, 0 | `fullstack-recovery-v5pg.csv` | recovered |
| Ukuran v5-pregen dan v5-inline: Message1–4 (B), RT | 2424/6097/3756/16, 15 (sama dengan v5) | `e2e-handshake-v5pg.csv` | msg1..4_bytes, radius_round_trips |
| Beban background DN-AAA, 100 UE paralel: CPU thread isi ulang / porsi dari radiusd; pool_miss | 0.23 s / 1.1 %; 0 | `pool-tests-v5pg/par.cpu, par.pool` | refill_thread_cpu_ticks, radiusd_cpu_ticks; pool_miss |
