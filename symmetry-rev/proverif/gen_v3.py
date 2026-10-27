#!/usr/bin/env python3
"""ProVerif models for the revised protocol (method 4 v2, no ephemeral X-Wing),
written with the SAME compact X-Wing abstraction as the repo's
edhoc_m4_hybrid_*.pv (xwpk / xw_ct / xw_ss / xw_decaps), not with a DH
equational theory (which made ProVerif run out of memory).

usage: gen_v3.py <path/to/edhoc_m4_hybrid_classical.pv> <outdir>
"""
import os, re, sys

SRC, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
old = open(SRC).read()
pre = old[old.index("(* ---------------- Channel, types"):old.index("(* ============================ QUERIES")]

# ID_CRED_R becomes a private name so that Q5b can query its secrecy
pre2 = pre.replace("const SuitesI, CI, CR, ID_CREDR, EAD2,", "const SuitesI, CI, CR, EAD2,")
pre2 = pre2.replace("free ID_CREDI : bitstring [private].",
                    "free ID_CREDI : bitstring [private].\nfree ID_CREDR : bitstring [private].")
assert pre2 != pre and "free ID_CREDR" in pre2
for need in ("fun xwpk(kemsk, exponent) : xpk.", "xw_decaps(k, x, xw_ct(xwpk(k, x), s, e))",
             "let QXW =", "MSK_test2", "fun xpk2b(xpk) : bitstring [data, typeConverter]."):
    assert need in pre2, need

TITLE = ("Revised proposed EAP-EDHOC hybrid PQC (X-Wing = ML-KEM-768 + X25519, ML-DSA-44 SIGMA gate),\n"
         " *           no ephemeral X-Wing: ct_B in Message1, ct_A in Message2, one-time static keys")

def header(fname, setting, expect):
    return f"""(* =====================================================================
 * {fname}
 * Variant : {TITLE}
 * Setting : {setting}
 * Model   : symbolic (Dolev-Yao), ProVerif 2.05. X-Wing uses the same compact
 *           abstraction as edhoc_m4_hybrid_*.pv (no DH equational theory).
 * Part of : EdhocSecondaryAuth -- ProVerif models for
 *           "Role-Symmetric EAP-EDHOC with Hybrid Post-Quantum Cryptography
 *            for 5G Secondary Authentication and Application-Server Access"
 * Expected: {expect}
 * ===================================================================== *)

"""

def ue_body(w, A_pq, A_x, pkB, v, tail):
    return f"""  new sB{v}:bitstring; new eB{v}:exponent;
  let ctB{v} = xw_ct({pkB}, sB{v}, eB{v}) in
  let ssB{v} = xw_ss({pkB}, sB{v}, eB{v}) in
  let PT1{v} = (M_4, SuitesI, ID_CREDI, CI) in
  let TH1{v} = H(ctB{v}) in
  let K1{v} = expands(extract(TH1{v}, ssB{v}), TH1{v}) in
  let Message1{v} = (ctB{v}, AEAD_enc(K1{v}, PT1{v})) in
  event UE_send_M1({w}, Message1{v});
  out(c, Message1{v});
  in(c, (ctA{v}:bitstring, encP2{v}:bitstring));
  let ssA{v} = xw_decaps({A_pq}, {A_x}, ctA{v}) in
  let TH2{v} = H((H(Message1{v}), ctA{v}, CR)) in
  let PRK2e{v} = extract(TH2{v}, ssA{v}) in
  let K2{v} = expands(PRK2e{v}, (lbl_K2, TH2{v})) in
  let PT2{v} = AEAD_dec(K2{v}, encP2{v}) in
  let (=CR, =ID_CREDR, =pkSigR, =EAD2, MAC2{v}:bitstring, sigR{v}:bitstring) = PT2{v} in
  let PRK3e2m{v} = extract(PRK2e{v}, ssB{v}) in
  let MAC2chk{v} = expands(PRK3e2m{v}, (lbl_MAC2, TH2{v}, ID_CREDR, EAD2, Len2)) in
  let v2{v} = mdverify(pkSigR, sigR{v}) in
  if MAC2{v} = MAC2chk{v} then
  if v2{v} = (TH2{v}, ID_CREDR, MAC2{v}) then
  event UE_recv_M2({w}, MAC2{v}, TH2{v});
  let TH3{v} = H((TH2{v}, PT2{v})) in
  let PRK4e3m{v} = PRK3e2m{v} in
  new NA_pq{v}:kemsk; new NA_x{v}:exponent;
  let EAD3{v} = xpk2b(xwpk(NA_pq{v}, NA_x{v})) in
  let MAC3{v} = expands(PRK4e3m{v}, (lbl_MAC3, TH3{v}, ID_CREDI, EAD3{v}, Len3)) in
  let sigI{v} = mdsign((TH3{v}, ID_CREDI, MAC3{v}), skSigI) in
  let K3{v} = expands(PRK3e2m{v}, (lbl_K3, TH3{v})) in
  let PT3{v} = (EAD3{v}, MAC3{v}, pkSigI, sigI{v}) in
  let Message3{v} = AEAD_enc(K3{v}, PT3{v}) in
  let TH4{v} = H((TH3{v}, PT3{v})) in
  event UE_send_M3({w}, MAC3{v}, TH3{v});
  out(c, Message3{v});
  in(c, Message4{v}:bitstring);
  let K4{v} = expands(PRK4e3m{v}, (lbl_K4, TH4{v})) in
  let xpk2b(NpkB{v}:xpk) = AEAD_dec(K4{v}, Message4{v}) in
  event UE_recv_M4({w}, Message4{v}, TH4{v});
  let PRKout{v} = expands(PRK4e3m{v}, (lbl_out, TH4{v})) in
  let MSK{v} = expands(PRKout{v}, lbl_MSK) in
  let EMSK{v} = expands(PRKout{v}, lbl_EMSK) in
{tail}"""

def dn_body(w, B_pq, B_x, pkA, v, tail):
    return f"""  in(c, Message1{v}:bitstring);
  let (ctB{v}:bitstring, encP1{v}:bitstring) = Message1{v} in
  (* (sk_B, pk_B): per-UE record selected from the EAP identity (process argument) *)
  let ssB{v} = xw_decaps({B_pq}, {B_x}, ctB{v}) in
  let TH1{v} = H(ctB{v}) in
  let K1{v} = expands(extract(TH1{v}, ssB{v}), TH1{v}) in
  let (=M_4, =SuitesI, claimedI{v}:bitstring, =CI) = AEAD_dec(K1{v}, encP1{v}) in
  (* (pk_A, VK_I) = Lookup(ID_CRED_I): the per-UE record (process argument) *)
  new sA{v}:bitstring; new eA{v}:exponent;
  let ctA{v} = xw_ct({pkA}, sA{v}, eA{v}) in
  let ssA{v} = xw_ss({pkA}, sA{v}, eA{v}) in
  let TH2{v} = H((H(Message1{v}), ctA{v}, CR)) in
  let PRK2e{v} = extract(TH2{v}, ssA{v}) in
  let K2{v} = expands(PRK2e{v}, (lbl_K2, TH2{v})) in
  let PRK3e2m{v} = extract(PRK2e{v}, ssB{v}) in
  let MAC2{v} = expands(PRK3e2m{v}, (lbl_MAC2, TH2{v}, ID_CREDR, EAD2, Len2)) in
  let sigR{v} = mdsign((TH2{v}, ID_CREDR, MAC2{v}), skSigR) in
  let PT2{v} = (CR, ID_CREDR, pkSigR, EAD2, MAC2{v}, sigR{v}) in
  let TH3{v} = H((TH2{v}, PT2{v})) in
  event DN_send_M2({w}, MAC2{v}, TH2{v});
  out(c, (ctA{v}, AEAD_enc(K2{v}, PT2{v})));
  in(c, Message3{v}:bitstring);
  let K3{v} = expands(PRK3e2m{v}, (lbl_K3, TH3{v})) in
  let PT3{v} = AEAD_dec(K3{v}, Message3{v}) in
  let (EAD3r{v}:bitstring, MAC3r{v}:bitstring, =pkSigI, sigIr{v}:bitstring) = PT3{v} in
  let TH4{v} = H((TH3{v}, PT3{v})) in
  let PRK4e3m{v} = PRK3e2m{v} in
  let MAC3chk{v} = expands(PRK4e3m{v}, (lbl_MAC3, TH3{v}, claimedI{v}, EAD3r{v}, Len3)) in
  let v3{v} = mdverify(pkSigI, sigIr{v}) in
  if MAC3r{v} = MAC3chk{v} then
  if v3{v} = (TH3{v}, claimedI{v}, MAC3r{v}) then
  event DN_recv_M3({w}, MAC3r{v}, TH3{v});
  let xpk2b(NpkA{v}:xpk) = EAD3r{v} in
  new NB_pq{v}:kemsk; new NB_x{v}:exponent;
  let K4{v} = expands(PRK4e3m{v}, (lbl_K4, TH4{v})) in
  let Message4{v} = AEAD_enc(K4{v}, xpk2b(xwpk(NB_pq{v}, NB_x{v}))) in
  event DN_send_M4({w}, Message4{v}, TH4{v});
  out(c, Message4{v});
  let PRKout{v} = expands(PRK4e3m{v}, (lbl_out, TH4{v})) in
  let MSK{v} = expands(PRKout{v}, lbl_MSK) in
  let EMSK{v} = expands(PRKout{v}, lbl_EMSK) in
{tail}"""

def procs(ue_tail, dn_tail):
    return ("let UE(w:bitstring, A_pq:kemsk, A_x:exponent, pkB:xpk,\n"
            "       skSigI:mdsk, pkSigI:mdpk, pkSigR:mdpk) =\n"
            + ue_body("w", "A_pq", "A_x", "pkB", "", ue_tail) + ".\n\n"
            "let DN(w:bitstring, B_pq:kemsk, B_x:exponent, pkA:xpk,\n"
            "       skSigR:mdsk, pkSigR:mdpk, pkSigI:mdpk) =\n"
            + dn_body("w", "B_pq", "B_x", "pkA", "", dn_tail) + ".\n")

UE_T = ("  event UE_finish(w, MSK, EMSK);\n"
        "  out(c, AEAD_enc(MSK, app_data_UE));\n"
        "  out(c, AEAD_enc(MSK, MSK_test))")
DN_T = ("  event DN_finish(w, MSK, EMSK);\n"
        "  out(c, AEAD_enc(MSK, app_data_DN));\n"
        "  out(c, AEAD_enc(EMSK, EMSK_test))")
# After a run the device keeps ONLY the rotated key (old sk erased): the state
# leaked in phase 1 is the next key pair.
UE_T_ERASE = UE_T + ";\n  (* post-run state: rotated key only (old sk erased) *)\n  phase 1; out(c, NA_pq); out(c, NA_x)"
DN_T_ERASE = DN_T + ";\n  (* post-run state: rotated key only (old sk erased) *)\n  phase 1; out(c, NB_pq); out(c, NB_x)"
# Negative control: the used one-time key is NOT erased and leaks too.
UE_T_KEEP = UE_T_ERASE + "; out(c, A_pq); out(c, A_x)"
DN_T_KEEP = DN_T_ERASE + "; out(c, B_pq); out(c, B_x)"

def auth(w, which=("Q2", "Q3", "Q4")):
    q = {"Q2": f"query x:bitstring, t:bitstring; inj-event(UE_recv_M2({w}, x, t)) ==> inj-event(DN_send_M2({w}, x, t)).   (* Q2: DN authenticated to UE *)\n",
         "Q3": f"query x:bitstring, t:bitstring; inj-event(DN_recv_M3({w}, x, t)) ==> inj-event(UE_send_M3({w}, x, t)).   (* Q3: UE authenticated to DN *)\n",
         "Q4": f"query x:bitstring, t:bitstring; inj-event(UE_recv_M4({w}, x, t)) ==> inj-event(DN_send_M4({w}, x, t)).   (* Q4: key confirmation by DN *)\n"}
    return "".join(q[k] for k in which)

SANITY = ("(* Q0: honest runs complete (sanity check; expected 'is false') *)\n"
          "query a:bitstring, b:bitstring; event(UE_finish(W0, a, b)).\n"
          "query a:bitstring, b:bitstring; event(DN_finish(W0, a, b)).\n"
          "(* Q1 *)\nquery m:bitstring; event(UE_send_M1(W0, m)).\n")
SECRECY = (
           "query attacker(ID_CREDI).        (* Q5: identity concealment (initiator) *)\n"
           "query attacker(ID_CREDR).        (* Q5b: identity concealment (responder) *)\n"
           "query attacker(app_data_UE).     (* Q6: confidentiality *)\n"
           "query attacker(app_data_DN).     (* Q7: confidentiality *)\n"
           "query attacker(MSK_test).        (* Q8: MSK secrecy + FS through rotation *)\n"
           "query attacker(EMSK_test).       (* Q9: EMSK secrecy + FS through rotation *)\n")
QUERIES = SANITY + auth("W0") + SECRECY
# the negative control leaks its extra keys in phase 1, after every phase-0
# authentication event, so Q2-Q4 coincide with the classical model: secrecy only
QUERIES_NOERASE = SANITY + SECRECY

def one_time_main(quantum):
    oracle = "\n    | QXW | (phase 1; QXW)" if quantum else ""
    return f"""process
  new skSigI:mdsk; new skSigR:mdsk;
  let pkSigI = mdpub(skSigI) in let pkSigR = mdpub(skSigR) in
  out(c, (pkSigI, pkSigR));
  (
      ( ! (* one run = one one-time static X-Wing key pair per party *)
          new A_pq:kemsk; new A_x:exponent; new B_pq:kemsk; new B_x:exponent;
          let pkA = xwpk(A_pq, A_x) in
          let pkB = xwpk(B_pq, B_x) in
          out(c, (pkA, pkB));
          (   UE(W0, A_pq, A_x, pkB, skSigI, pkSigI, pkSigR)
            | DN(W0, B_pq, B_x, pkA, skSigR, pkSigR, pkSigI) ) )
    | ( phase 1; out(c, skSigI); out(c, skSigR) ){oracle}
  )
"""

def write(fname, setting, expect, queries, body, main):
    text = (header(fname, setting, expect) + pre2 +
            "(* ============================ QUERIES ============================ *)\n" + queries +
            "\n(* ============================ PROCESSES ========================== *)\n" + body +
            "\n(* ============================== MAIN ============================= *)\n" + main)
    open(os.path.join(OUT, fname), "w").write(text)
    return fname

files = []
files.append(write("edhoc_m4v2_classical.pv",
    "classical Dolev-Yao; one-time static X-Wing keys per run; phase 1 leaks the post-run\n"
    " *           state (rotated X-Wing keys) and both ML-DSA signing keys (FS through rotation)",
    "Q0/Q1 false (reachable); Q2-Q4 true; Q5, Q5b, Q6-Q9 true",
    QUERIES, procs(UE_T_ERASE, DN_T_ERASE), one_time_main(False)))
files.append(write("edhoc_m4v2_quantum.pv",
    "as edhoc_m4v2_classical + quantum oracle (X25519 half of X-Wing) in all phases",
    "as in the classical setting (the ML-KEM-768 half keeps every secret)",
    QUERIES, procs(UE_T_ERASE, DN_T_ERASE), one_time_main(True)))
files.append(write("edhoc_m4v2_fs_noerase.pv",
    "NEGATIVE CONTROL: as edhoc_m4v2_classical, but the used one-time X-Wing keys are\n"
    " *           NOT erased and leak in phase 1",
    "Q0/Q1 false (reachable); Q5, Q5b, Q6-Q9 FALSE (FS and identity concealment rely\n"
    " *           on erasure); Q2-Q4 omitted (identical to edhoc_m4v2_classical)",
    QUERIES_NOERASE, procs(UE_T_KEEP, DN_T_KEEP), one_time_main(False)))

# ---- KCI (same structure as edhoc_m4_hybrid_kci.pv)
def keys(s):
    return (f"  new A_pq{s}:kemsk; new A_x{s}:exponent; new skSigI{s}:mdsk;\n"
            f"  new B_pq{s}:kemsk; new B_x{s}:exponent; new skSigR{s}:mdsk;\n"
            f"  let pkA{s} = xwpk(A_pq{s}, A_x{s}) in\n"
            f"  let pkB{s} = xwpk(B_pq{s}, B_x{s}) in\n"
            f"  let pkSigI{s} = mdpub(skSigI{s}) in let pkSigR{s} = mdpub(skSigR{s}) in\n"
            f"  out(c, (pkA{s}, pkB{s}, pkSigI{s}, pkSigR{s}));\n")
kci_q = ("(* World W1: UE's long-term keys are known to the attacker from the start.\n"
         " * KCI resistance for the UE requires that the DN is still authenticated to it. *)\n"
         + auth("W1", ("Q2", "Q4")) +
         "(* World W2: DN's long-term keys are known to the attacker from the start.\n"
         " * KCI resistance for the DN requires that the UE is still authenticated to it. *)\n"
         + auth("W2", ("Q3",)))
kci_main = ("process\n" + keys("1") + keys("2") +
            "  out(c, ID_CREDR);   (* responder identity public here so authentication is not vacuous *)\n"
            "  out(c, A_pq1); out(c, A_x1); out(c, skSigI1);\n"
            "  out(c, B_pq2); out(c, B_x2); out(c, skSigR2);\n"
            "  (\n      ( ! UE(W1, A_pq1, A_x1, pkB1, skSigI1, pkSigI1, pkSigR1) )\n"
            "    | ( ! DN(W1, B_pq1, B_x1, pkA1, skSigR1, pkSigR1, pkSigI1) )\n"
            "    | ( ! UE(W2, A_pq2, A_x2, pkB2, skSigI2, pkSigI2, pkSigR2) )\n"
            "    | ( ! DN(W2, B_pq2, B_x2, pkA2, skSigR2, pkSigR2, pkSigI2) )\n"
            "    | QXW   (* quantum oracle: KCI must hold against a quantum adversary too *)\n  )\n")
files.append(write("edhoc_m4v2_kci.pv",
    "Key-Compromise Impersonation: victim's long-term keys leaked from the start (W1: UE, W2: DN),\n"
    " *           quantum oracle (X25519 half of X-Wing) available",
    "all queries true", kci_q, procs(UE_T, DN_T), kci_main))

# ---- PCS (same abstraction as edhoc_m4_hybrid_pcs.pv)
pcs_ue_t = "  event UE_finish(w, MSK, EMSK);\n  out(c, AEAD_enc(MSK, MSK_test2))"
pcs_dn_t = "  event DN_finish(w, MSK, EMSK);\n  out(c, AEAD_enc(EMSK, EMSK_test2))"
pcs_q = ("(* Epoch W2 runs under the keys rotated through EAD3/EAD4; the OLD one-time\n"
         " * X-Wing keys of both parties are known to the attacker. Signing keys are\n"
         " * not compromised. *)\n"
         "query a:bitstring, b:bitstring; event(UE_finish(W2, a, b)).   (* sanity: epoch 2 reachable *)\n"
         + auth("W2") +
         "query attacker(MSK_test2).       (* Q10 *)\n"
         "query attacker(EMSK_test2).      (* Q11 *)\n")
pcs_main = """process
  new A_pq:kemsk; new A_x:exponent; new skSigI:mdsk;
  new B_pq:kemsk; new B_x:exponent; new skSigR:mdsk;
  let pkSigI = mdpub(skSigI) in let pkSigR = mdpub(skSigR) in
  out(c, (xwpk(A_pq, A_x), xwpk(B_pq, B_x), pkSigI, pkSigR));
  out(c, ID_CREDR);   (* responder identity public here so authentication is not vacuous *)
  (* compromise: the OLD one-time X-Wing keys of both parties *)
  out(c, (A_pq, A_x, B_pq, B_x));
  (* each epoch-1 run hands one fresh rotated key pair to each party *)
  ! (
    new NA_pq:kemsk; new NA_x:exponent; new NB_pq:kemsk; new NB_x:exponent;
    let NpkA = xwpk(NA_pq, NA_x) in
    let NpkB = xwpk(NB_pq, NB_x) in
    out(c, (NpkA, NpkB));
      UE(W2, NA_pq, NA_x, NpkB, skSigI, pkSigI, pkSigR)
    | DN(W2, NB_pq, NB_x, NpkA, skSigR, pkSigR, pkSigI)
  )
"""
files.append(write("edhoc_m4v2_pcs.pv",
    "post-compromise security: old one-time X-Wing keys known to the attacker; runs under\n"
    " *           rotated keys. Abstraction: as edhoc_m4_hybrid_pcs.pv (epoch 1 is covered by\n"
    " *           Q3/Q4/Q8/Q9 of edhoc_m4v2_classical.pv, which authenticate and protect EAD3/EAD4)",
    "sanity query false (reachable); Q2-Q4 (W2), Q10, Q11 true", pcs_q, procs(pcs_ue_t, pcs_dn_t), pcs_main))
print("\n".join(files))
