### Ukuran (live vs model)

| Varian | Message1–4 live (B) | Total (B) | Model (B) | Live = model | Fragmen EAP | RT |
|---|---|---|---|---|---|---|
| v4 | 2390/6097/3756/16 | 12259 | 2390/6097/3756/16 | cocok | 3/7/4/1 | 15 |
| v4s | 2424/6097/3756/16 | 12293 | 2424/6097/3756/16 | cocok | 3/7/4/1 | 15 |
| v4s+chk | 2424/6097/3756/16 | 12293 | 2424/6097/3756/16 | cocok | 3/7/4/1 | 15 |
| v4t | 2390/6097/3756/16 | 12259 | 2390/6097/3756/16 | cocok | 3/7/4/1 | 15 |

### Harness E2E loss-free (2 run × 100, bergantian dalam satu sesi)

| Varian | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) | Selisih median vs v4 (ms) [95% CI] |
|---|---|---|---|---|---|---|
| v4 | 200 | 6.863 | 6.530 | 7.515 | [6.471, 6.631] | — |
| v4s | 200 | 6.921 | 6.816 | 7.886 | [6.739, 6.907] | +0.285 [+0.160, +0.400] |
| v4s+chk | 200 | 6.695 | 6.544 | 7.621 | [6.452, 6.668] | +0.013 [-0.133, +0.143] |
| v4t | 200 | 6.492 | 6.381 | 7.534 | [6.314, 6.460] | -0.149 [-0.272, -0.054] |
| EAP-TLS Hybrid PQC | 200 | 8.758 | 8.745 | 9.991 | [8.614, 8.838] | +2.215 [+2.037, +2.313] |

### Komputasi Message1 (10.000 iterasi per varian, bergantian per iterasi, dalam proses)

| Varian | Message1 (B) | UE median (µs) | UE p95 (µs) | DN-AAA median (µs) | DN-AAA p95 (µs) | UE vs v4 (µs) | DN-AAA vs v4 (µs) |
|---|---|---|---|---|---|---|---|
| v4 | 2390 | 142.3 | 194.9 | 74.7 | 117.9 | +0.0 | +0.0 |
| v4s | 2424 | 138.8 | 190.9 | 68.6 | 90.1 | -3.5 | -6.1 |
| v4s+chk | 2424 | 139.0 | 191.5 | 68.7 | 89.3 | -3.3 | -6.0 |
| v4t | 2390 | 138.6 | 192.5 | 70.9 | 90.7 | -3.7 | -3.8 |

### Full stack v4s (A/B 1 × 100, `@edhoc.internet`, tanpa uji pemulihan)

- A: PASS 100/100, msk_match 100/100, rotated 100/100; B: PASS 100/100.
- Ukuran / ronde: [('2424', '6097', '3756', '16', '15', '15')] (Message1..4 B, ronde NAS, RADIUS RT).

| Metrik | Konf. | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |
|---|---|---|---|---|---|---|
| `t_pdu_ms` | A | 100 | 96.609 | 96.361 | 114.729 | [94.414, 97.904] |
| `t_pdu_ms` | B | 100 | 20.925 | 20.501 | 32.594 | [19.656, 21.293] |
| `t_secauth_ms` | A | 100 | 77.590 | 76.961 | 91.867 | [75.169, 78.909] |
| `t_aaa_ms` | A | 100 | 5.813 | 5.730 | 7.968 | [5.491, 6.054] |

- `t_pdu_ms` A − B: **75.859 ms**, 95% CI [73.761, 77.942] ms.
- `uname -r`: 7.0.0-38-generic
