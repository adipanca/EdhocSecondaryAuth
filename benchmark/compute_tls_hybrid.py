#!/usr/bin/env python3
"""
compute_tls_hybrid.py — method 6 "EAP-TLS Hybrid PQC" compute-breakdown
model, feeding benchmark-results/analysis.md's sections 1a/1b/4.

Method 6 IS live end-to-end elsewhere in this benchmark suite: liboqs +
oqs-provider are installed under pqc-tls/, and benchmark/eap_tls_hybrid_bench.c
drives a real mutual-TLS-1.3 handshake (X25519MLKEM768 hybrid KEM group,
ML-DSA-44 certs) against the live FreeRADIUS rlm_eap_tls responder — see
benchmark-results/e2e-handshake.csv / e2e-lossy.csv and analisys2.md's
section 1c/2 for those live numbers.

This script's job is narrower and complementary: `analysis.md` (unlike
analisys2.md) is intentionally a pure primitive/compute view, independent of
transport, for EVERY method 0-6 alike (methods 0-4 also only ever appear
there via computed/modeled breakdowns, not observed wire bytes) — so method
6's rows here are derived the same way, from the SAME real,
independently-measured primitive numbers already in crypto-primitives.csv
(the exact measurements method 4 uses), combined with a realistic TLS 1.3
handshake framing model, for apples-to-apples consistency with the rest of
that document. No new benchmark is run by this script; it is a compute-only
companion to the live method-6 measurement, not a substitute for it.

Model (mutual TLS 1.3, 1-RTT):
  - Key establishment: hybrid KEM group X25519 + ML-KEM-768, combined exactly
    like the X-Wing construction already used for method 4. Client holds the
    ML-KEM-768 keypair and decapsulates; server encapsulates to it — this
    matches real draft hybrid-KEM TLS groups such as X25519MLKEM768.
  - Client authentication: mutual TLS, CertificateVerify signature scheme =
    ML-DSA-44 on both sides (same PQC signature as method 4, for an
    apples-to-apples comparison).

Per-side operation counts (see task spec / final report for the exact
mapping):
  initiator (UE)  : Keygen(X25519)x1 + Keygen(ML-KEM-768)x1, ScalarMult x1,
                     Decaps(ML-KEM-768)x1, Encaps x0,
                     Signature(ML-DSA-44)x1, Verify(ML-DSA-44)x1.
  responder (AAA) : Keygen(X25519)x1 (no ML-KEM keypair — it encapsulates to
                     the client's), ScalarMult x1, Encaps(ML-KEM-768)x1,
                     Decaps x0, Signature(ML-DSA-44)x1, Verify(ML-DSA-44)x1.

Outputs (append method=6 rows to, creating the files if missing):
  benchmark-results/crypto-breakdown.csv
  benchmark-results/handshake-compute.csv
  benchmark-results/mtu-fragmentation.csv

This script never touches e2e-handshake.csv / e2e-lossy.csv — method 6's rows
there come from the live benchmark/eap_tls_hybrid_bench.c harness instead
(see benchmark/run_e2e_benchmarks.sh and analisys2.md's methodology note).
"""
import csv
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.abspath(os.path.join(HERE, "..", "benchmark-results")) \
    if len(sys.argv) < 2 else os.path.abspath(sys.argv[1])

PRIM_CSV = os.path.join(RESULTS, "crypto-primitives.csv")
BREAKDOWN_CSV = os.path.join(RESULTS, "crypto-breakdown.csv")
COMPUTE_CSV = os.path.join(RESULTS, "handshake-compute.csv")
MTU_CSV = os.path.join(RESULTS, "mtu-fragmentation.csv")

METHOD = 6
PROFILE = "EAP-TLS Hybrid PQC (X25519MLKEM768 hybrid KEM, ML-DSA-44 cert)"

# ---------------------------------------------------------------------
# 1. Load real primitive means (same source method 4 uses)
# ---------------------------------------------------------------------
def load_means(path):
    means = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            means[row["operation"]] = float(row["mean_ns"])
    return means


def opcount_row(role, op, cnt, prim, ns):
    return {
        "method": METHOD, "profile": PROFILE, "role": role,
        "operation": op, "primitive": prim, "op_count": cnt,
        "compute_ns": round(ns, 1),
    }


def build_breakdown_rows(means):
    """Mirror crypto_bench.c's write_breakdown_rows()/role_total() exactly:
    one row per (Keygen, ScalarMult, Encaps, Decaps, Signature, Verify),
    ALWAYS emitted even when op_count is 0 (method 0..3 already do this for
    e.g. Encaps/Decaps=0 in crypto-breakdown.csv — matched here, not
    omitted)."""
    kx = means["Keygen_X25519"]
    sx = means["ScalarMult_X25519"]
    kk = means["Keygen_MLKEM768"]
    ek = means["Encaps_MLKEM768"]
    dk = means["Decaps_MLKEM768"]
    sd = means["Signature_MLDSA44"]
    vd = means["Verify_MLDSA44"]

    # (x25519_keygen, x25519_dh, mlkem_keygen, mlkem_encaps, mlkem_decaps, mldsa_sign, mldsa_verify)
    initiator = dict(x25519_keygen=1, x25519_dh=1, mlkem_keygen=1, mlkem_encaps=0,
                      mlkem_decaps=1, mldsa_sign=1, mldsa_verify=1)
    responder = dict(x25519_keygen=1, x25519_dh=1, mlkem_keygen=0, mlkem_encaps=1,
                      mlkem_decaps=0, mldsa_sign=1, mldsa_verify=1)

    def role_rows(role, o):
        keygen_cnt = o["x25519_keygen"] + o["mlkem_keygen"]
        keygen_ns = o["x25519_keygen"] * kx + o["mlkem_keygen"] * kk
        rows = [
            opcount_row(role, "Keygen", keygen_cnt, "X25519/ML-KEM-768", keygen_ns),
            opcount_row(role, "ScalarMult", o["x25519_dh"], "X25519", o["x25519_dh"] * sx),
            opcount_row(role, "Encaps", o["mlkem_encaps"], "ML-KEM-768", o["mlkem_encaps"] * ek),
            opcount_row(role, "Decaps", o["mlkem_decaps"], "ML-KEM-768", o["mlkem_decaps"] * dk),
            opcount_row(role, "Signature", o["mldsa_sign"], "Ed25519/ML-DSA-44", o["mldsa_sign"] * sd),
            opcount_row(role, "Verify", o["mldsa_verify"], "Ed25519/ML-DSA-44", o["mldsa_verify"] * vd),
        ]
        total_ns = keygen_ns + o["x25519_dh"] * sx + o["mlkem_encaps"] * ek \
            + o["mlkem_decaps"] * dk + o["mldsa_sign"] * sd + o["mldsa_verify"] * vd
        return rows, total_ns

    ini_rows, ini_ns = role_rows("initiator", initiator)
    res_rows, res_ns = role_rows("responder", responder)
    return ini_rows + res_rows, ini_ns, res_ns


# ---------------------------------------------------------------------
# 2. Realistic (computed, not byte-perfect) TLS 1.3 message-size model
# ---------------------------------------------------------------------
# Real component sizes (bytes), same values already validated in section 3
# (interoperability) and used by method 4's edhoc_sizes.py:
X25519_PK = 32
MLKEM768_EK = 1184     # encapsulation (public) key
MLKEM768_CT = 1088     # ciphertext
MLDSA44_PK = 1312      # ML-DSA-44 verification key
MLDSA44_SIG = 2420     # ML-DSA-44 signature

# TLS 1.3 record/handshake framing overhead — small round numbers (comment
# documents each), not meant to be byte-perfect (RFC 8446 framing plus a
# generic AEAD tag/padding budget), only realistic:
REC_HDR = 5            # TLS record header (type+version+length)
HS_HDR = 4             # handshake message header (type + 3-byte length) per sub-message
CH_OVERHEAD = 25        # ClientHello core fields + key_share/ext headers, rounded
SH_OVERHEAD = 45        # ServerHello core fields + selected key_share ext headers, rounded
EE_SIZE = 25            # EncryptedExtensions (minimal extension set), rounded
CERT_OVERHEAD = 15      # Certificate message framing (request-context + list/entry lengths)
CV_OVERHEAD = 9         # CertificateVerify framing (sig-scheme id + length fields)
FIN_SIZE = 36           # Finished (transcript HMAC, rounded)
FINAL_ACK = 50          # bare post-handshake EAP-Request/TLS ack before EAP-Success
                        # (mirrors method 5's live-observed message_4 = 51 B)


def flight(*parts):
    return sum(parts)


def _build_mtu_rows_modeled_unused():
    """Original from-scratch TLS-framing size model, kept for documentation
    only -- superseded by build_mtu_rows() below once method 6 went live:
    this model undercounted by ~2.5x (e.g. message_2 5027 modeled vs 12600
    really observed) because full X.509 DER framing (cert chain, ASN.1
    structure overhead) is harder to get right from first principles than
    just reusing the real observed bytes now that they're available."""
    # message_1 (UE->AAA): ClientHello carrying X25519 + ML-KEM-768 pubkeys
    # in the hybrid key_share.
    m1 = flight(REC_HDR, HS_HDR, CH_OVERHEAD, X25519_PK, MLKEM768_EK)

    # message_2 (AAA->UE): ServerHello (X25519 share + ML-KEM-768 ciphertext
    # in key_share) + EncryptedExtensions + Certificate(ML-DSA-44 pubkey) +
    # CertificateVerify(ML-DSA-44 sig) + Finished. Same crypto payload as
    # method 4's message_2/message_3 combined, just TLS-framed instead of
    # EDHOC/CBOR-framed.
    sh = flight(REC_HDR, HS_HDR, SH_OVERHEAD, X25519_PK, MLKEM768_CT)
    ee = flight(REC_HDR, HS_HDR, EE_SIZE)
    cert_srv = flight(REC_HDR, HS_HDR, CERT_OVERHEAD, MLDSA44_PK)
    cv_srv = flight(REC_HDR, HS_HDR, CV_OVERHEAD, MLDSA44_SIG)
    fin_srv = flight(REC_HDR, HS_HDR, FIN_SIZE)
    m2 = sh + ee + cert_srv + cv_srv + fin_srv

    # message_3 (UE->AAA): Client Certificate(ML-DSA-44 pubkey) +
    # CertificateVerify(ML-DSA-44 sig) + Finished (mutual-TLS client auth).
    cert_cli = flight(REC_HDR, HS_HDR, CERT_OVERHEAD, MLDSA44_PK)
    cv_cli = flight(REC_HDR, HS_HDR, CV_OVERHEAD, MLDSA44_SIG)
    fin_cli = flight(REC_HDR, HS_HDR, FIN_SIZE)
    m3 = cert_cli + cv_cli + fin_cli

    # message_4 (AAA->UE): final bare ack before EAP-Success.
    m4 = FINAL_ACK

    return {"message_1": m1, "message_2": m2, "message_3": m3, "message_4": m4}


# Real byte sizes actually observed on the wire in the live method-6 handshake
# (benchmark-results/e2e-handshake.csv, constant across iterations), used
# instead of the modeled sizes above for accuracy -- see
# _build_mtu_rows_modeled_unused()'s docstring for why.
def build_mtu_rows():
    return {"message_1": 1589, "message_2": 12600, "message_3": 10983, "message_4": 23}


EAP_ATTR = 253
EAP_FRAG_SIZE = 1020   # matches TLS_FRAG_MAX in eap_tls_bench.c
IP_MTU = 1500
IP_HDR = 20
UDP_HDR = 8
IP_PAYLOAD = IP_MTU - IP_HDR


def ip_fragments(nbytes):
    total = nbytes + UDP_HDR
    if total <= IP_PAYLOAD:
        return 1
    return math.ceil(total / (IP_PAYLOAD - (IP_PAYLOAD % 8)))


# ---------------------------------------------------------------------
# CSV append helpers (write header only if file didn't already exist)
# ---------------------------------------------------------------------
def append_rows(path, header, rows):
    existed = os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if not existed:
            w.writerow(header)
        for r in rows:
            w.writerow(r)


def strip_existing_method(path, method_str):
    """Idempotency: drop any pre-existing method==6 rows before appending,
    so re-running this script doesn't duplicate rows."""
    if not os.path.exists(path):
        return
    with open(path, newline="") as f:
        rows = list(csv.reader(f))
    if not rows:
        return
    header, body = rows[0], rows[1:]
    kept = [r for r in body if not (r and r[0] == method_str)]
    if len(kept) != len(body):
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(kept)


def main():
    means = load_means(PRIM_CSV)

    # ---- crypto-breakdown.csv ----
    breakdown_rows, ini_ns, res_ns = build_breakdown_rows(means)
    strip_existing_method(BREAKDOWN_CSV, "6")
    append_rows(BREAKDOWN_CSV,
                ["method", "profile", "role", "operation", "primitive", "op_count", "compute_ns"],
                [[r["method"], r["profile"], r["role"], r["operation"], r["primitive"],
                  r["op_count"], f"{r['compute_ns']:.1f}"] for r in breakdown_rows])

    # ---- handshake-compute.csv ----
    ini_us = ini_ns / 1000.0
    res_us = res_ns / 1000.0
    strip_existing_method(COMPUTE_CSV, "6")
    append_rows(COMPUTE_CSV,
                ["method", "profile", "initiator_compute_us", "responder_compute_us", "total_compute_us"],
                [[METHOD, PROFILE, f"{ini_us:.3f}", f"{res_us:.3f}", f"{ini_us + res_us:.3f}"]])

    # ---- mtu-fragmentation.csv (computed sizes, analysis.md's flavor) ----
    sizes = build_mtu_rows()
    mtu_rows = []
    for msg, sz in sizes.items():
        eap_attrs = math.ceil(sz / EAP_ATTR)
        eap_frags = math.ceil(sz / EAP_FRAG_SIZE)
        ipd = sz + UDP_HDR + IP_HDR
        ipf = ip_fragments(sz)
        exceeds = "yes" if (sz + UDP_HDR + IP_HDR) > IP_MTU else "no"
        mtu_rows.append([METHOD, PROFILE, msg, sz, eap_attrs, eap_frags, ipd, ipf, exceeds])
    strip_existing_method(MTU_CSV, "6")
    append_rows(MTU_CSV,
                ["method", "profile", "message", "size_bytes", "eap_message_attrs",
                 "eap_fragments", "ip_datagram_bytes", "ip_fragments", "exceeds_mtu"],
                mtu_rows)

    print(f"[compute_tls_hybrid] method 6 initiator={ini_us:.3f}us responder={res_us:.3f}us "
          f"total={ini_us + res_us:.3f}us")
    print(f"[compute_tls_hybrid] message sizes: {sizes}")
    print(f"[compute_tls_hybrid] appended rows to:\n  {BREAKDOWN_CSV}\n  {COMPUTE_CSV}\n  {MTU_CSV}")


if __name__ == "__main__":
    main()
