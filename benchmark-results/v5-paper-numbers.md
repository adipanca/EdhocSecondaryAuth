### Tabel ringkas angka untuk paper

Semua nilai dibaca dari file sumber oleh `benchmark/v5_analyze.py`.

| Angka | Nilai | Sumber | Kolom |
|---|---|---|---|
| T1: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; lookup; 0.002; no | `tamper-v5.csv` | semua |
| T2: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; AEAD tag; 0.154; yes | `tamper-v5.csv` | semua |
| T3: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; AEAD tag; 0.193; yes | `tamper-v5.csv` | semua |
| T4: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; AEAD tag; 0.149; yes | `tamper-v5.csv` | semua |
| T5: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; lookup; 0.001; no | `tamper-v5.csv` | semua |
| T6: hasil; DN-AAA; median ms; Decaps | session 1: success 20/20; replay session: challenge 20/20; accepted (replay); accepted (session 1); 0.522; yes | `tamper-v5.csv` | semua |
| T7: hasil; DN-AAA; median ms; Decaps | eap-failure 20/20; inner KeyID check; 0.153; yes | `tamper-v5.csv` | semua |
| ProVerif v5: jumlah query, NOT CONCLUDED | 70, 0 | `symmetry-rev/proverif/results/SUMMARY_v5.txt` | result |
| Proposal v5: mean (ms) | 6.545 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 4 |
| Proposal v5: median (ms) | 6.438 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 4 |
| Proposal v5: p95 (ms) | 7.399 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 4 |
| Proposal v5: 95% CI median (ms) | [6.392, 6.524] | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 4 |
| Proposal v5: UE lokal, Figure 7 kanan (ms) | 1.220 | `e2e-handshake-v5-m4m6.csv` | initiator_ms, method 4 |
| Proposal v5: tunggu balasan, Figure 7 kanan (ms) | 5.325 | `e2e-handshake-v5-m4m6.csv` | responder_ms, method 4 |
| EAP-TLS Hybrid PQC: mean (ms) | 8.992 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: median (ms) | 8.936 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: p95 (ms) | 10.309 | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: 95% CI median (ms) | [8.857, 9.021] | `e2e-handshake-v5-m4m6.csv` | duration_ms, method 6 |
| EAP-TLS Hybrid PQC: UE lokal, Figure 7 kanan (ms) | 0.672 | `e2e-handshake-v5-m4m6.csv` | initiator_ms, method 6 |
| EAP-TLS Hybrid PQC: tunggu balasan, Figure 7 kanan (ms) | 8.320 | `e2e-handshake-v5-m4m6.csv` | responder_ms, method 6 |
| EAP-TLS Hybrid PQC − v5: selisih median (ms) | 2.498 | `e2e-handshake-v5-m4m6.csv` | duration_ms |
| EAP-TLS Hybrid PQC − v5: 95% CI (ms) | [2.392, 2.597] | `e2e-handshake-v5-m4m6.csv` | duration_ms |
| Storage, Flush UE saja (ms) | 0.408 [0.349, 0.474] | `e2e-storage-flush-v5.csv` | duration_ms, dn_tmpfs − tmpfs |
| Storage, Flush DN-AAA saja (ms) | 0.583 [0.522, 0.638] | `e2e-storage-flush-v5.csv` | duration_ms, ue_tmpfs − tmpfs |
| Storage, Flush UE, di atas flush DN-AAA (ms) | 0.479 [0.412, 0.527] | `e2e-storage-flush-v5.csv` | duration_ms, durable − ue_tmpfs |
| Storage, Flush DN-AAA, di atas flush UE (ms) | 0.654 [0.584, 0.704] | `e2e-storage-flush-v5.csv` | duration_ms, durable − dn_tmpfs |
| Storage, Kedua flush (ms) | 1.062 [0.997, 1.112] | `e2e-storage-flush-v5.csv` | duration_ms, durable − tmpfs |
| Tabel 6, Added: median [CI] / mean (ms) | 78.7 [76.6, 80.0] / 79.9 | `fullstack-handshake-v5.csv` | t_pdu_ms, A − B |
| Tabel 6, Secondary authentication at the UE: median [CI] / mean / p95 (ms) | 77.1 [76.3, 78.1] / 79.1 / 99.0 | `fullstack-handshake-v5.csv` | t_secauth_ms, A |
| Tabel 6, 5G core transport (UE, gNB, AMF, SMF): median [CI] / mean / p95 (ms) | 71.5 [70.7, 72.9] / 73.7 / 90.5 | `fullstack-handshake-v5.csv` | t_core_ms, A |
| Tabel 6, SMF ↔ UPF relay hop: median [CI] / mean / p95 (ms) | 2.8 [2.7, 2.8] / 2.8 / 3.8 | `fullstack-handshake-v5.csv` | t_hop_smf_upf_ms, A |
| Tabel 6, RADIUS processing in the UPF relay: median [CI] / mean / p95 (ms) | 0.9 [0.8, 0.9] / 0.9 / 1.6 | `fullstack-handshake-v5.csv` | t_relay_proc_ms, A |
| Tabel 6, DN-AAA (FreeRADIUS, from the UPF relay): median [CI] / mean / p95 (ms) | 5.4 [5.3, 5.5] / 5.5 / 7.4 | `fullstack-handshake-v5.csv` | t_aaa_ms, A |
| Tabel 6, UE write of NEXT (before Message3): median [CI] / mean / p95 (ms) | 2.85 [2.82, 2.87] / 2.29 / 3.56 | `fullstack-handshake-v5.csv` | ue_store_next_ms, A |
| Tabel 6, DN-AAA commit (before Message4): median [CI] / mean / p95 (ms) | 0.64 [0.64, 0.65] / 0.69 / 0.92 | `fullstack-handshake-v5.csv` | aaa_commit_ms, A |
| Tabel 6, UE promotion (after Message4): median [CI] / mean / p95 (ms) | 0.57 [0.56, 0.59] / 0.67 / 1.21 | `fullstack-handshake-v5.csv` | ue_promote_ms, A |
| Pemulihan, Message3 dibuang: median / mean (ms) | 1426.4 / 1426.6 | `fullstack-recovery-v5.csv` | t_recovery_ms |
| Pemulihan, Message4 dibuang: median / mean (ms) | 93.3 / 104.2 | `fullstack-recovery-v5.csv` | t_recovery_ms |
| Pemulihan: desync, re-provisioning | 0, 0 | `fullstack-recovery-v5.csv` | recovered |
| Proposal v5: Message1–4 (B) | 2424/6097/3756/16 | `e2e-handshake-v5-m4m6.csv` | msg1..4_bytes |
| Proposal v5: total (B) | 12293 | `e2e-handshake-v5-m4m6.csv` | msg1..4_bytes |
| Proposal v5: dikirim UE, Message1+3 (B) | 6180 | `e2e-handshake-v5-m4m6.csv` | msg1_bytes + msg3_bytes |
| Proposal v5: dikirim DN-AAA/server, Message2+4 (B) | 6113 | `e2e-handshake-v5-m4m6.csv` | msg2_bytes + msg4_bytes |
| Proposal v5: fragmen EAP | 3/7/4/1 | `e2e-handshake-v5-m4m6.csv` | msg1..4_frags |
| Proposal v5: RT | 15 | `e2e-handshake-v5-m4m6.csv` | radius_round_trips |
| EAP-TLS Hybrid PQC: Message1–4 (B) | 1589/12600/10983/23 | `e2e-handshake-v5-m4m6.csv` | msg1..4_bytes |
| EAP-TLS Hybrid PQC: total (B) | 25195 | `e2e-handshake-v5-m4m6.csv` | msg1..4_bytes |
| EAP-TLS Hybrid PQC: dikirim UE, Message1+3 (B) | 12572 | `e2e-handshake-v5-m4m6.csv` | msg1_bytes + msg3_bytes |
| EAP-TLS Hybrid PQC: dikirim DN-AAA/server, Message2+4 (B) | 12623 | `e2e-handshake-v5-m4m6.csv` | msg2_bytes + msg4_bytes |
| EAP-TLS Hybrid PQC: fragmen EAP | 2/13/11/1 | `e2e-handshake-v5-m4m6.csv` | msg1..4_frags |
| EAP-TLS Hybrid PQC: RT | 28 | `e2e-handshake-v5-m4m6.csv` | radius_round_trips |
| Proposal v5: komputasi initiator / responder, Figure 7 kiri (µs) | 462.475 / 462.475 | `compute-v5/handshake-compute.csv` | initiator_compute_us, responder_compute_us |
| EAP-TLS Hybrid PQC: komputasi initiator / responder, Figure 7 kiri (µs) | 441.958 / 404.503 | `compute-v5/handshake-compute.csv` | initiator_compute_us, responder_compute_us |
| Proposal v5: handshake dalam proses, initiator / responder median (µs) | 496.3 / 491.9 | `m4-inprocess-compute-v5.csv` | initiator_median_us, responder_median_us |
