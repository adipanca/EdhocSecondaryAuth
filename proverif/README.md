# ProVerif models

Symbolic (Dolev–Yao) models for the paper *"Role-Symmetric EAP-EDHOC with Hybrid Post-Quantum Cryptography for 5G Secondary Authentication and Application-Server Access"*. All models target **ProVerif 2.05**.

```bash
./run_all.sh                 # runs every model, writes results/<model>.txt and results/SUMMARY.txt
proverif edhoc_m0_classical.pv   # run a single model
```

## Files

| Variant (Table 4 column) | Classical | Quantum | KCI | Other |
|---|---|---|---|---|
| EAP-EDHOC Method 0 (SIG-SIG) | `edhoc_m0_classical.pv` | `edhoc_m0_quantum.pv` | `edhoc_m0_kci.pv` | |
| EAP-EDHOC Method 1 (SIG-STAT) | `edhoc_m1_classical.pv` | `edhoc_m1_quantum.pv` | `edhoc_m1_kci.pv` | |
| EAP-EDHOC Method 2 (STAT-SIG) | `edhoc_m2_classical.pv` | `edhoc_m2_quantum.pv` | `edhoc_m2_kci.pv` | |
| EAP-EDHOC Method 3 (STAT-STAT) | `edhoc_m3_classical.pv` | `edhoc_m3_quantum.pv` | `edhoc_m3_kci.pv` | |
| EAP-EDHOC Hybrid PQC (proposed) | `edhoc_m4_hybrid_classical.pv` | `edhoc_m4_hybrid_quantum.pv` | `edhoc_m4_hybrid_kci.pv` | `edhoc_m4_hybrid_pcs.pv`, `edhoc_m4_hybrid_base.pv` |
| EAP-TLS Classic | `eaptls_classic_classical.pv` | `eaptls_classic_quantum.pv` | `eaptls_classic_kci.pv` | |
| EAP-TLS Hybrid PQC | `eaptls_hybrid_classical.pv` | `eaptls_hybrid_quantum.pv` | `eaptls_hybrid_kci.pv` | |

`edhoc_m4_hybrid_base.pv` is the model whose output appears in the paper's verification-summary figure (Q1–Q9). It abstracts X-Wing as one opaque IND-CCA KEM. The `edhoc_m4_hybrid_*` files keep X-Wing's two halves visible: a key pair is (ML-KEM-768 key `k`, X25519 scalar `x`) with `pk = xwpk(k, x)`, and `ss = xw_ss(pk, s, e)` needs both the ML-KEM coins `s` and the X25519 ephemeral `e`. Decapsulation needs both secret halves; each half alone (`mlkem_dec`, `x25519_dec`) opens only its own component. The quantum oracle recovers `x` and `e` but never `k` or `s`. An earlier version spelled X25519 out with a DH equational theory and a 5-input combiner hash. Its transcript terms grew exponentially (single clauses of several hundred KB), and ProVerif used up all RAM.

## Settings

- **classical**: Active Dolev–Yao attacker. Honest sessions run in phase 0. In phase 1 the attacker learns **all long-term keys of both parties** (static DH/KEM keys and signing keys), which tests forward secrecy and identity concealment.
- **quantum**: The classical setting plus a *quantum oracle* that is available in every phase. The oracle returns the discrete log of any X25519 group element (`qdlog`) and the Ed25519 signing key for any Ed25519 public key (`qed`). This models Shor's algorithm against an attacker that is active during the run and that also stores traffic to decrypt it later (harvest-now, decrypt-later). There is **no** oracle for ML-KEM-768 or ML-DSA-44, so a hybrid secret stays secure as long as its ML-KEM part does.
- **kci**: Two independent worlds:
  - In W1 the UE's long-term keys are given to the attacker from the start. The test checks that the DN is still authenticated **to the UE**.
  - In W2 the DN's long-term keys are leaked, and the test checks that the UE is still authenticated **to the DN**.

  This is the standard Key-Compromise Impersonation definition.
- **pcs** (proposed protocol only): Both parties rotate their static X-Wing keys through EAD3/EAD4. The **old** static X-Wing keys are revealed, and a second epoch (W2) runs under the rotated keys. Signing keys are not compromised. The model checks only epoch W2. It does not re-run epoch 1; instead it relies on `edhoc_m4_hybrid_classical.pv`, where Q3/Q4 authenticate the rotated public keys carried in EAD3/EAD4. Each W2 session therefore starts from an authentic, fresh rotated key pair per party. The attacker holds the old keys from the start and also sees the rotated public keys, which is stronger than the real protocol. A version that ran both epochs in one process did not finish within 20 minutes.

## Queries

| Query | Meaning | Paper requirement |
|---|---|---|
| `event(UE_finish/DN_finish)`, Q1 `event(UE_send_M1)` | sanity: honest runs complete (expected `is false`) | — |
| Q2 `inj-event(UE_recv_M2) ==> inj-event(DN_send_M2)` | DN authenticated to UE | R1 |
| Q3 `inj-event(DN_recv_M3) ==> inj-event(UE_send_M3)` | UE authenticated to DN | R1 |
| Q4 `inj-event(UE_recv_M4) ==> inj-event(DN_send_M4)` | key confirmation (4-message variants only) | R1 |
| Q5 `attacker(ID_CREDI)` | identity concealment | R2 |
| Q6, Q7 `attacker(app_data_UE/DN)` | confidentiality | R3 |
| Q8, Q9 `attacker(MSK_test/EMSK_test)` | secure key exchange; forward secrecy (phase-1 leak) | R4, R5 |
| Q10, Q11 `attacker(MSK_test2/EMSK_test2)` in `*_pcs.pv` | post-compromise security | R6 |
| Q2–Q4 (messages are parsed through `AEAD_dec`) | AEAD protection | R7 |
| Q8, Q9 in `*_quantum.pv` | quantum resilience | R8 |
| all queries in `*_kci.pv` | KCI resistance | R9 |

## How Table 4 statuses are derived

- ● **fully secure**: the property holds in `*_classical.pv` **and** in `*_quantum.pv`.
- ◐ **partial**: the property holds in `*_classical.pv` but not in `*_quantum.pv`.
- ○ **not secure**: the property fails in `*_classical.pv`.

Some rows need a special rule:
- **R8 (quantum resilience)**: ● if Q8 and Q9 hold in `*_quantum.pv`, otherwise ○.
- **R9 (KCI)**: ● if every `*_kci.pv` query holds **and** Q2/Q3 hold in `*_quantum.pv`. ◐ if only the `*_kci.pv` queries hold.
- **R6 (post-compromise security)**: only the proposed protocol defines a static-key rotation step, so only it has a PCS model. The baselines are marked ○ because their specifications contain no rotation mechanism. That mark comes from the specification, not from a ProVerif run, and the paper's table note should say so.

If a ProVerif result differs from the current Table 4, the table must be updated to match the result.

## Notes

- `cannot be proved` means ProVerif could neither prove nor refute a query. It is not a proof. Report it as such, or refine the model.
- `run_all.sh` first runs every model with a 10-minute limit (`QUICK_TIMEOUT`). A model that takes longer is deferred and rerun at the end one query at a time, each with a 1-hour limit (`TIMEOUT`), so slow models do not hold up the others. Each run is also capped at 50% of RAM (`MEM_LIMIT_MB`). Without the cap, a model that blows up can trigger systemd-oomd, which kills the whole desktop session (VS Code included), not only ProVerif.
