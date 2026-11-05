
## 9. Final v5

Step 31. v5 = protokol Dr. Shin + cek KeyID dalam (`v4s+chk` di bagian 8), sekarang default. TH_1 = H(KeyID_B, ct_B); AEAD Message1 dengan AD = TH_1; KeyID_B juga di Plaintext1; DN-AAA mengambil record dari indeks memori, memeriksa ID_CRED_I dan KeyID_B di Plaintext1 = header. Write-ahead NEXT tetap ada. Kernel `7.0.0-38-generic`. Paper tidak diubah.

### Hasil test

| Test | Hasil |
|---|---|
| `edhoc4_xwing_kat` | PASS (3 vektor X-Wing) |
| `edhoc4_selftest` | PASS (default v5, dan 4 varian) |
| `edhoc03_selftest` | PASS |
| `edhoc4_dbtest` | PASS |

`edhoc4_dbtest` disesuaikan: vektor Message1 sekarang 2424 B. Dua kasus memakai pemeriksaan KeyID_B = H(pk_B) yang tidak ada di v5, jadi dijalankan pada varian v4. Untuk v5 ditambah kasus entri indeks palsu: Decaps berjalan, lalu `E4_ERR_AEAD`, dan entri itu **tidak** dihapus. Di v4 penolakan terjadi sebelum Decaps dan entri dihapus. Indeks dibangun dari slot saat start, jadi entri seperti ini tidak muncul dalam operasi normal.

T1–T7 pada v5 (`tamper_tests.sh 20 v5 v5`), 20 kali per baris:

| test | manipulation | variant | result at the UE | DN-AAA step | DN-AAA median ms | Decaps run |
|---|---|---|---|---|---|---|
| T1 | KeyID_B header: 1 bit | v5 | eap-failure 20/20 | lookup | 0.002 | no |
| T2 | KeyID_B header: of another UE | v5 | eap-failure 20/20 | AEAD tag | 0.154 | yes |
| T3 | ct_B: 1 bit | v5 | eap-failure 20/20 | AEAD tag | 0.193 | yes |
| T4 | AEAD ciphertext: 1 bit | v5 | eap-failure 20/20 | AEAD tag | 0.149 | yes |
| T5 | old Message1 replayed | v5 | eap-failure 20/20 | lookup | 0.001 | no |
| T6 | current Message1 in a second EAP session | v5 | session 1: success 20/20; replay session: challenge 20/20 | accepted (replay); accepted (session 1) | 0.522 | yes |
| T7 | KeyID_B in PT1 != header | v5 | eap-failure 20/20 | inner KeyID check | 0.153 | yes |

### SUMMARY_v5 (ProVerif)

Sumber: `symmetry-rev/proverif/results/SUMMARY_v5.txt` (`run_all_v5.sh`, MemoryMax=10G, 3600 s per query). Tidak ada NOT CONCLUDED.

```
Proverif 2.05. Cryptographic protocol verifier, by Bruno Blanchet, Vincent Cheval, and Marc Sylvestre
Final v5 models (gen_m4v4.py --variant v5), one ProVerif process per query, MemoryMax=10G / 3600s
==================================================================
edhoc_m4v5_classical.pv
  query     time  peakmem  result
  q1       0.79s    200MB  not event(UE_finish(W0,a,b)) is false.
  q2       0.72s    205MB  not event(DN_finish(W0,a,b)) is false.
  q3       0.64s    181MB  not event(UE_send_M1(W0,m)) is false.
  q4       1.72s    535MB  inj-event(UE_recv_M2(W0,x,t,a,b)) ==> inj-event(DN_send_M2(W0,x,t,a,b)) is true.
  q5       2.20s    650MB  inj-event(DN_recv_M3(W0,x,t,a,b)) ==> inj-event(UE_send_M3(W0,x,t,a,b)) is true.
  q6       3.40s   1109MB  inj-event(UE_recv_M4(W0,x,t,a,b)) ==> inj-event(DN_send_M4(W0,x,t,a,b)) is true.
  q7       0.64s    180MB  not attacker_p1(ID_CREDI[]) is true.
  q8       0.63s    180MB  not attacker_p1(ID_CREDR[]) is true.
  q9       0.63s    180MB  not attacker_p1(app_data_UE[]) is true.
  q10      0.67s    180MB  not attacker_p1(app_data_DN[]) is true.
  q11      0.67s    180MB  not attacker_p1(MSK_test[]) is true.
  q12      0.67s    180MB  not attacker_p1(EMSK_test[]) is true.
  q13      0.75s    178MB  event(DN_acc_M1(W0,kid,ct)) ==> event(UE_send_M1hdr(W0,kid,ct)) is true.
  q14      0.71s    181MB  event(DN_acc_inner(W0,h,p)) ==> h = p is true.
==================================================================
edhoc_m4v5_quantum.pv
  query     time  peakmem  result
  q1       0.73s    193MB  not event(UE_finish(W0,a,b)) is false.
  q2       0.73s    201MB  not event(DN_finish(W0,a,b)) is false.
  q3       0.69s    180MB  not event(UE_send_M1(W0,m)) is false.
  q4       1.76s    526MB  inj-event(UE_recv_M2(W0,x,t,a,b)) ==> inj-event(DN_send_M2(W0,x,t,a,b)) is true.
  q5       2.16s    650MB  inj-event(DN_recv_M3(W0,x,t,a,b)) ==> inj-event(UE_send_M3(W0,x,t,a,b)) is true.
  q6       3.37s   1089MB  inj-event(UE_recv_M4(W0,x,t,a,b)) ==> inj-event(DN_send_M4(W0,x,t,a,b)) is true.
  q7       0.65s    182MB  not attacker_p1(ID_CREDI[]) is true.
  q8       0.70s    182MB  not attacker_p1(ID_CREDR[]) is true.
  q9       0.67s    182MB  not attacker_p1(app_data_UE[]) is true.
  q10      0.64s    182MB  not attacker_p1(app_data_DN[]) is true.
  q11      0.66s    182MB  not attacker_p1(MSK_test[]) is true.
  q12      0.66s    182MB  not attacker_p1(EMSK_test[]) is true.
  q13      0.64s    178MB  event(DN_acc_M1(W0,kid,ct_2)) ==> event(UE_send_M1hdr(W0,kid,ct_2)) is true.
  q14      0.58s    181MB  event(DN_acc_inner(W0,h,p_2)) ==> h = p_2 is true.
==================================================================
edhoc_m4v5_kci.pv
  query     time  peakmem  result
  q1       2.53s    381MB  inj-event(UE_recv_M2(W1,x,t,a,b)) ==> inj-event(DN_send_M2(W1,x,t,a,b)) is true.
  q2       3.78s    627MB  inj-event(UE_recv_M4(W1,x,t,a,b)) ==> inj-event(DN_send_M4(W1,x,t,a,b)) is true.
  q3       2.39s    392MB  inj-event(DN_recv_M3(W2,x,t,a,b)) ==> inj-event(UE_send_M3(W2,x,t,a,b)) is true.
==================================================================
edhoc_m4v5_pcs.pv
  query     time  peakmem  result
  q1       0.27s    101MB  not event(UE_finish(W2,a,b)) is false.
  q2       0.37s    116MB  inj-event(UE_recv_M2(W2,x,t,a,b)) ==> inj-event(DN_send_M2(W2,x,t,a,b)) is true.
  q3       0.47s    134MB  inj-event(DN_recv_M3(W2,x,t,a,b)) ==> inj-event(UE_send_M3(W2,x,t,a,b)) is true.
  q4       0.66s    207MB  inj-event(UE_recv_M4(W2,x,t,a,b)) ==> inj-event(DN_send_M4(W2,x,t,a,b)) is true.
  q5       0.22s     73MB  not attacker(MSK_test2[]) is true.
  q6       0.23s     73MB  not attacker(EMSK_test2[]) is true.
==================================================================
edhoc_m4v5_fs_noerase.pv
  query     time  peakmem  result
  q1       0.42s     70MB  not event(UE_finish(W0,a,b)) is false.
  q2       0.43s     79MB  not event(DN_finish(W0,a,b)) is false.
  q3       0.38s     64MB  not event(UE_send_M1(W0,m)) is false.
  q4       0.37s     68MB  not attacker_p1(ID_CREDI[]) is false.
  q5       0.38s     68MB  not attacker_p1(ID_CREDR[]) is false.
  q6       0.56s     76MB  not attacker_p1(app_data_UE[]) is false.
  q7       0.41s     73MB  not attacker_p1(app_data_DN[]) is false.
  q8       0.45s     77MB  not attacker_p1(MSK_test[]) is false.
  q9       0.41s     73MB  not attacker_p1(EMSK_test[]) is false.
  q10      0.39s     64MB  event(DN_acc_M1(W0,kid,ct)) ==> event(UE_send_M1hdr(W0,kid,ct)) is true.
  q11      0.37s     63MB  event(DN_acc_inner(W0,h,p)) ==> h = p is true.
==================================================================
edhoc_m4v5_recovery.pv
  query     time  peakmem  result
  q1       1.41s    303MB  not event(UE_finish(W0,a,b)) is false.
  q2       1.45s    308MB  not event(DN_finish(W0,a,b)) is false.
  q3       1.39s    297MB  not event(UE_send_M1(W0,m)) is false.
  q4       1.36s    286MB  not attacker_p1(ID_CREDI[]) is true.
  q5       1.36s    286MB  not attacker_p1(app_data_DN[]) is true.
  q6       1.38s    284MB  not attacker_p1(MSK_test[]) is true.
  q7       1.26s    284MB  not attacker_p1(EMSK_test[]) is true.
  q8       2.56s    333MB  event(DN_acc_M1(W0,kid,ct)) ==> event(UE_send_M1hdr(W0,kid,ct)) is true.
  q9       1.39s    283MB  event(DN_acc_inner(W0,h,p)) ==> h = p is true.
==================================================================
edhoc_m4v5_nextkey.pv
  query     time  peakmem  result
  q1       0.69s     18MB  not attacker(s_NpkA[]) is true.
  q2       0.42s     18MB  not attacker(s_NpkB[]) is true.
==================================================================
edhoc_m4v5_noid_classical.pv
  query     time  peakmem  result
  q1       0.69s    205MB  event(DN_acc_M1(W0,kid,ct)) ==> event(UE_send_M1hdr(W0,kid,ct)) is false.
==================================================================
edhoc_m4v5_t7_classical.pv
  query     time  peakmem  result
  q1       0.73s    190MB  event(DN_acc_inner(W0,h,p)) ==> h = p is true.
DONE
```

Model unlinkability tidak dijalankan untuk v5; status terakhir tetap NOT CONCLUDED untuk v4 (bagian 7c), jadi tidak ada klaim unlinkability.

### Harness E2E (v5 dan EAP-TLS Hybrid PQC, satu sesi, 2 run × 100)

| Method | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) | UE lokal mean (ms) | Tunggu balasan mean (ms) |
|---|---|---|---|---|---|---|---|
| Proposal v5 | 200 | 6.545 | 6.438 | 7.399 | [6.392, 6.524] | 1.220 | 5.325 |
| EAP-TLS Hybrid PQC | 200 | 8.992 | 8.936 | 10.309 | [8.857, 9.021] | 0.672 | 8.320 |

- Selisih median EAP-TLS Hybrid PQC − v5: **2.498 ms**, 95% CI [2.392, 2.597]; mean 2.447 ms.
- Sebagai pembanding saja, v4b di `e2e-handshake-v4b.csv`: median 6.284 ms, sesi lain. Selisih antarsesi bukan biaya protokol (bagian 8).

### Ablasi storage (`storage_ablation.sh 6 100 flush`, 4 konfigurasi, 6 ronde × 100)

| Konfigurasi | UE | DN-AAA | N | Mean (ms) | Median (ms) | 95% CI median (ms) |
|---|---|---|---|---|---|---|
| durable | disk | disk | 600 | 6.546 | 6.466 | [6.418, 6.499] |
| ue_tmpfs | tmpfs | disk | 600 | 6.078 | 5.987 | [5.953, 6.034] |
| dn_tmpfs | disk | tmpfs | 600 | 5.910 | 5.812 | [5.771, 5.863] |
| tmpfs | tmpfs | tmpfs | 600 | 5.521 | 5.404 | [5.365, 5.450] |

| Biaya | Selisih median | Nilai (ms) | 95% CI (ms) |
|---|---|---|---|
| Flush UE saja | dn_tmpfs − tmpfs | 0.408 | [0.349, 0.474] |
| Flush DN-AAA saja | ue_tmpfs − tmpfs | 0.583 | [0.522, 0.638] |
| Flush UE, di atas flush DN-AAA | durable − ue_tmpfs | 0.479 | [0.412, 0.527] |
| Flush DN-AAA, di atas flush UE | durable − dn_tmpfs | 0.654 | [0.584, 0.704] |
| Kedua flush | durable − tmpfs | 1.062 | [0.997, 1.112] |

### Full stack v5 (A/B 3 × 100, `@edhoc.internet`)

- A: PASS 299/300, msk_match 299/299, rotated 299/299; B: PASS 300/300.
- **Satu sesi gagal di A (seri 3, iterasi 77), status timeout**, tidak ikut statistik. Log UE: `No response from RRC from UAC checks, considering access attempt is barred`, jadi UERANSIM menahan permintaan sebelum NAS dikirim dan belum ada Message1. Permintaan dikirim ulang saat T3580 habis (16 s) dan handshake-nya selesai normal; sesi berikutnya sukses. Ini perilaku simulator, bukan protokol. Di v4b tidak muncul (300/300).
- Ukuran / ronde: [('2424', '6097', '3756', '16', '15', '15')] (Message1..4 B, ronde NAS, RADIUS RT).

| Segmen (Tabel 6) | Kolom | N | Median (ms) | 95% CI | Mean (ms) | p95 (ms) |
|---|---|---|---|---|---|---|
| Added to PDU session establishment (A − B) | `t_pdu_ms` | 299 | 78.7 | [76.6, 80.0] | 79.9 | -- |
| Secondary authentication at the UE | `t_secauth_ms` | 299 | 77.1 | [76.3, 78.1] | 79.1 | 99.0 |
| 5G core transport (UE, gNB, AMF, SMF) | `t_core_ms` | 299 | 71.5 | [70.7, 72.9] | 73.7 | 90.5 |
| SMF ↔ UPF relay hop | `t_hop_smf_upf_ms` | 299 | 2.8 | [2.7, 2.8] | 2.8 | 3.8 |
| RADIUS processing in the UPF relay | `t_relay_proc_ms` | 299 | 0.9 | [0.8, 0.9] | 0.9 | 1.6 |
| DN-AAA (FreeRADIUS, from the UPF relay) | `t_aaa_ms` | 299 | 5.4 | [5.3, 5.5] | 5.5 | 7.4 |
| UE write of NEXT (before Message3) | `ue_store_next_ms` | 299 | 2.85 | [2.82, 2.87] | 2.29 | 3.56 |
| DN-AAA commit (before Message4) | `aaa_commit_ms` | 299 | 0.64 | [0.64, 0.65] | 0.69 | 0.92 |
| UE promotion (after Message4) | `ue_promote_ms` | 299 | 0.57 | [0.56, 0.59] | 0.67 | 1.21 |

#### Uji pemulihan v5

Relay UPF membuang sekali Message3 atau Message4; SMF timeout (2,5 s) lalu mengirim REJECT #29 tanpa EAP (UE tidak fallback). Sesi berikutnya diulang sampai Accept dengan EAP-Success (maks. 3).

| Kasus | N | Drop di UPF | Sesi drop: Reject #29 tanpa EAP | used_next | Sesi pemulihan pertama | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Message3 dibuang | 10 | 10 | 10 | 10 | failure 10 | 10 | 10 | 2 | 10 | 10 | 1426.6 / 1426.4 |
| Message4 dibuang | 10 | 10 | 10 | 10 | success 10 | 0 | 0 | 1 | 10 | 10 | 104.2 / 93.3 |

- Sesi normal sesudahnya: 10/10 sukses. Desync: **0**; re-provisioning: **0**.
- `failure` = REJECT #29 berisi EAP-Failure (DN-AAA belum commit, NEXT ditolak), lalu fallback ke CUR dan PDU session berikutnya sukses. Waktu pulih Message3 memuat `reject_delay = 1` FreeRADIUS.

- Cek identitas (`v5-identity-check.txt`): RESULT: PASS (only the anonymous NAI appears)

### Ukuran (live dan model)

| Method | Message1–4 live (B) | Total (B) | Model (B) | Live = model | Dikirim UE (M1+M3) | Dikirim DN-AAA (M2+M4) | Fragmen EAP | Fragmen IP (model) | RT |
|---|---|---|---|---|---|---|---|---|---|
| Proposal v5 | 2424/6097/3756/16 | 12293 | 2424/6097/3756/16 | cocok | 6180 | 6113 | 3/7/4/1 (total 15) | 2/5/3/1 (total 11) | 15 |
| EAP-TLS Hybrid PQC | 1589/12600/10983/23 | 25195 | 1589/12600/10983/23 | cocok | 12572 | 12623 | 2/13/11/1 (total 27) | 2/9/8/1 (total 20) | 28 |

### Komputasi per fungsi

Harness yang sama dengan Figure 7 kiri: `crypto_bench` mengukur primitif lalu mengalikannya dengan jumlah operasi per peran; EAP-TLS Hybrid dengan `compute_tls_hybrid.py`, dari primitif yang sama.

| Method | Initiator (µs) | Responder (µs) | Total (µs) |
|---|---|---|---|
| Proposal v5 | 462.475 | 462.475 | 924.950 |
| EAP-TLS Hybrid PQC | 441.958 | 404.503 | 846.461 |

| Operasi method 4 (per peran, sama di kedua peran) | Jumlah | Waktu (µs) |
|---|---|---|
| Keygen (X25519/ML-KEM-768) | 3 | 72.859 |
| ScalarMult (X25519) | 2 | 46.731 |
| Encaps (ML-KEM-768) | 1 | 32.291 |
| Decaps (ML-KEM-768) | 1 | 40.139 |
| Signature (Ed25519/ML-DSA-44) | 1 | 213.689 |
| Verify (Ed25519/ML-DSA-44) | 1 | 56.766 |

- **Batas model ini:** hanya menghitung primitif, jadi jumlah operasinya sama di v4 dan v5. Beda hash dan AEAD Message1 tidak terlihat di sini; beda angka dengan v4b (492,320 µs) berasal dari pengukuran primitif sesi lain, EAP-TLS Hybrid juga bergeser (467,442 → 441.958 µs). Selisih v5 yang sebenarnya untuk Message1 ada di `m1-compute-variants.csv` (bagian 8).
- Pembanding yang menjalankan handshake v5 sungguhan dalam proses (`m4_inproc_bench`, N=2000, tanpa storage): initiator median 496.3 µs, responder median 491.9 µs.

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
