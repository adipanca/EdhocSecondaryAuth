# ProVerif models — revised protocol (method 4 v2, no ephemeral X-Wing)

These models replace the `edhoc_m4_hybrid_*` files for the **revised** proposed protocol. The baseline models (`edhoc_m0`–`m3`, `eaptls_*`) do not change.

**What changed in the protocol**
- **Message1:** the UE's ephemeral X-Wing key pair (sk_X, pk_X) is removed, so Message1 = (ct_B, AEAD(K_1, Plaintext1)).
- **Message2:** ct_A moves into the clear part of Message2, in the place of ct_e. The new key schedule is:
  - PRK_2e = Extract(TH_2, ss_A)
  - PRK_3e2m = Extract(PRK_2e, ss_B)
  - PRK_4e3m = PRK_3e2m
- **Forward secrecy:** the static X-Wing keys are now one-time keys. They are rotated every run (EAD_3 / EAD_4) and the old secret key is erased.

All files target **ProVerif 2.05**. Run them with:

```bash
./run_all_v2.sh              # writes results/<model>.txt and results/SUMMARY.txt
```

## Files

| File | Setting | Expected result |
|---|---|---|
| `edhoc_m4v2_classical.pv` | Each run uses a one-time static key pair per party. In phase 1 the attacker gets the **post-run state** (the rotated X-Wing keys) and both ML-DSA signing keys. | Q0/Q1 false (reachable); Q2–Q4 true; Q5, Q5b, Q6–Q9 true |
| `edhoc_m4v2_quantum.pv` | Same as classical, plus the X25519 discrete-log oracle in every phase. | Same as classical |
| `edhoc_m4v2_kci.pv` | W1: the UE's long-term keys leak from the start. W2: the DN's long-term keys leak from the start. Same structure as `edhoc_m4_hybrid_kci.pv`, plus the quantum oracle `QXW`. | All queries true |
| `edhoc_m4v2_pcs.pv` | The old one-time keys of both parties are known from the start; every run uses a fresh rotated key pair per party. Same abstraction as `edhoc_m4_hybrid_pcs.pv` (epoch 1 is covered by Q3/Q4/Q8/Q9 of `_classical`). | Sanity query false (reachable); Q2–Q4 (W2), Q10, Q11 true |
| `edhoc_m4v2_fs_noerase.pv` | **Negative control.** Same as classical, but the old one-time keys are **not** erased and also leak in phase 1. | **Q5, Q5b, Q6–Q9 false.** Secrecy only: Q2–Q4 are omitted |

The negative control shows two things:
- Forward secrecy and the concealment of ID_CRED_I depend on erasing the old key.
- The models are not trivially secure.

If `edhoc_m4v2_fs_noerase.pv` reports Q8/Q9 **true**, the attacker is not receiving the leaked keys and the model has a mistake.

## Queries

| Query | Meaning | Requirement |
|---|---|---|
| Q0 `event(UE_finish/DN_finish)`, Q1 `event(UE_send_M1)` | Sanity: honest runs complete (expected `is false`) | — |
| Q2 / Q3 / Q4 | DN authenticated to UE / UE authenticated to DN / key confirmation | R1, R7 |
| Q5 `attacker(ID_CREDI)` | Initiator identity concealment | R2 |
| Q5b `attacker(ID_CREDR)` | Responder identity concealment. **New:** Message2 is now encrypted under ss_A, not under an ephemeral secret | R2 |
| Q6, Q7 | Confidentiality of application data | R3 |
| Q8, Q9 | Secrecy of MSK/EMSK, including after the phase-1 leak (forward secrecy through rotation) | R4, R5 |
| Q10, Q11 (`_pcs`) | Secrecy in the epoch after compromise | R6 |
| Q8, Q9 in `_quantum` | Quantum resilience | R8 |
| `_kci` | KCI resistance | R9 |

## Modelling notes

0. **X-Wing abstraction (changed in this version).** X-Wing is modelled exactly as in the repo's `edhoc_m4_hybrid_*.pv`: compact terms `xwpk(k, x)`, `xw_ct(pk, s, e)`, `xw_ss(pk, s, e)`, with `xw_decaps` needing both secret halves, `mlkem_dec` / `x25519_dec` opening one half each, and the quantum oracle `QXW` (`q_xpk`, `q_xct`) recovering only the X25519 half.
   - The first v2 files spelled X25519 out with a DH equational theory (`exp(exp(g,x),y)`) and an explicit combiner hash. ProVerif ran out of memory on Q3/Q4 (classical) and on every query of `_quantum`, `_kci` and `_pcs`.
   - Those failures came from the term blow-up of that theory, as already noted in the header of `edhoc_m4_hybrid_classical.pv`. They say nothing about the protocol.
   - With the compact abstraction the v2 models have the same size as the old `m4_hybrid` models, which all finished.

1. **One-time keys.** In `_classical`, `_quantum` and `_fs_noerase`, every replicated run draws a fresh static key pair for each party. Its public part is given to the attacker.
   - This abstracts the rotation: the key used in run *n* is the key announced in run *n−1*. The announcement is authenticated by MAC_3/σ_I and MAC_4, which the `_pcs` model checks separately.
   - The model does **not** cover a failed rotation (lost Message4). In that case the old key stays in use and forward secrecy for that run depends on the recovery policy.
2. **ID_CRED_R is a private name**, so that Q5b can be asked.
   - In `_kci` and `_pcs` it is given to the attacker at the start. Otherwise authentication could hold only because the attacker cannot guess the responder's identity.
   - R1 should therefore be read from Q2–Q4 in `_kci` and `_pcs`. Q2–Q4 in `_classical` are a weaker check.
3. **Behaviour that is expected and therefore not queried.** If the **current** one-time keys of **both** parties leak **before** a run, a passive attacker can read that run, because no ephemeral secret is left. Security returns from the next run, because the rotated secret keys are generated locally and never sent. This one-run delay in PCS is the cost of removing the ephemeral X-Wing key pair, and the paper states it.
4. **Generator.** `python3 gen_v3.py ../../proverif/edhoc_m4_hybrid_classical.pv <dir>` regenerates the five files into `<dir>`. Its declarations are copied verbatim from `edhoc_m4_hybrid_classical.pv`; the only change is that ID_CRED_R is a private name. `python3 lint.py <dir>` checks parentheses, identifier scoping and arities. The checker is not a substitute for running ProVerif.

## Results (ProVerif 2.05, one process per query)

Full table with time and peak memory per query: `results/SUMMARY_v2.txt`.

| File | Result | Slowest query |
|---|---|---|
| `_classical` | 12/12 as expected | Q4: 7.1 s, 2.0 GB |
| `_quantum` | 12/12 as expected | Q4: 6.7 s, 2.0 GB |
| `_kci` | 3/3 true | 4.8 s, 0.9 GB |
| `_pcs` | 6/6 as expected | 0.9 s, 0.3 GB |
| `_fs_noerase` | 9/9 as expected: Q0/Q1 false (reachable); **Q5, Q5b, Q6–Q9 false** as the negative control requires | 3.6 s, 0.5 GB per query |

The negative control queries only secrecy. Its extra keys leak in phase 1, after every phase-0 authentication event, so its Q2–Q4 coincide with those of `_classical`. An earlier version that kept Q2–Q4 did not terminate (stopped after ~36 min / out of memory at 4.5 GB).

## How the paper table changes

| R | Previous protocol | Revised protocol | Source |
|---|:-:|:-:|---|
| R2 | ○ | ● if the old keys are erased (Q5 true in `_classical`, false in `_fs_noerase`) | Q5, Q5b |
| R5 | ● (ephemeral X-Wing) | ● **conditional on erasure** | Q8, Q9 + negative control |
| others | ● | ● | unchanged |
