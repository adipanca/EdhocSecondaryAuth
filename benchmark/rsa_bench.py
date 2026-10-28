#!/usr/bin/env python3
"""
rsa_bench.py — method 5 (EAP-TLS Classic) crypto compute breakdown.

Method 5 switched its live certificates (raddb/certs/{ca,server,client}.pem)
from RSA-2048 to Ed25519, so that the "classical" comparison against EDHOC
(methods 0..3, which are Ed25519 + X25519 throughout) is apples-to-apples:
same signature algorithm, same DH group, and the only remaining variable is
protocol framing (TLS record layer + X.509 vs EDHOC's CBOR) and transport
(RFC 5216 EAP-TLS fragmentation vs EDHOC-over-EAP fragmentation) — exactly
the axis this benchmark suite is trying to isolate. See the live
e2e-handshake.csv / analisys2.md section 1c for the real Ed25519 handshake
numbers; this script only derives the matching 1a/1b compute-breakdown view.

Per-side operation model (method 0's SIG/SIG shape plus certificate
validation — one keygen, one scalar-mult, one sign, two verifies per side,
all Ed25519/X25519):
  initiator (UE)  : Keygen(X25519)x1, ScalarMult(X25519)x1,
                     Signature(Ed25519)x1 [CertificateVerify],
                     Verify(Ed25519)x2   [server's CertificateVerify +
                                          CA signature on server cert]
  responder (AAA) : Keygen(X25519)x1, ScalarMult(X25519)x1,
                     Signature(Ed25519)x1 [ServerKeyExchange/CertVerify signature],
                     Verify(Ed25519)x2   [client's CertificateVerify +
                                          CA signature on client cert]
The certificate chain is root CA (trusted, not verified) -> end-entity, so
certificate validation adds exactly one verify per side. EDHOC methods 0..3
use raw public keys and do not verify a certificate.

No new primitive measurement is needed for this model: Keygen_X25519,
ScalarMult_X25519, Signature_Ed25519 and Verify_Ed25519 are already real,
independently-measured rows in crypto-primitives.csv (the same ones methods
0..3 use) — this script just reuses them.

RSA-2048 keygen/sign/verify is still measured here too, for real (via
pyca/cryptography, OpenSSL backend), and still appended to
crypto-primitives.csv (section 1a) — kept as reference/comparison data for
anyone curious what a legacy-RSA classic-TLS deployment would have cost
instead, but it no longer feeds method 5's breakdown rows.
"""
import csv
import math
import os
import statistics
import sys
import time

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.abspath(os.path.join(HERE, "..", "benchmark-results")) \
    if len(sys.argv) < 2 else os.path.abspath(sys.argv[1])

PRIM_CSV = os.path.join(RESULTS, "crypto-primitives.csv")
BREAKDOWN_CSV = os.path.join(RESULTS, "crypto-breakdown.csv")
COMPUTE_CSV = os.path.join(RESULTS, "handshake-compute.csv")
MTU_CSV = os.path.join(RESULTS, "mtu-fragmentation.csv")

METHOD = 5
PROFILE = "EAP-TLS Classic (X25519 ECDHE + Ed25519, mutual)"

# message_1..4 byte sizes as actually observed from the live Ed25519 handshake
# (benchmark-results/e2e-handshake.csv, method 5, constant across iterations
# since there is no variable-length data in this exchange) -- reused here
# rather than modeled/estimated, same spirit as analysis.md's other computed
# rows but grounded in the real live measurement instead of a guess.
LIVE_MSG_BYTES = {"message_1": 289, "message_2": 1148, "message_3": 990, "message_4": 51}
EAP_ATTR = 253
IP_MTU = 1500
IP_HDR = 20
UDP_HDR = 8
ITERS = 500   # RSA-2048 sign/verify is ~1-2 orders of magnitude slower than
              # the EC/PQC primitives above; 500 iters is already representative.


def timed_ns(fn, iters):
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    return samples


def pct(values, p):
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def stat_row(name, lib, samples):
    return {
        "operation": name, "library": lib, "iterations": len(samples),
        "mean_ns": statistics.mean(samples), "median_ns": statistics.median(samples),
        "p95_ns": pct(samples, 95), "p99_ns": pct(samples, 99),
        "stddev_ns": statistics.pstdev(samples),
        "min_ns": min(samples), "max_ns": max(samples),
    }


def main():
    msg = b"\xa5" * 64   # representative transcript-hash-sized message, same
                          # pattern crypto_bench.c uses (memset 0xA5/0x7E bufs)

    # ---- real RSA-2048 keygen/sign/verify measurement (OpenSSL backend) ----
    # Reference/comparison data only (section 1a) -- method 5 no longer uses
    # RSA certs, see module docstring.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    sig = key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    def op_keygen():
        rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def op_sign():
        key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                   salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    def op_verify():
        pub.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    # RSA keygen is slow (~tens of ms); a smaller iteration count keeps this fast.
    keygen_samples = timed_ns(op_keygen, 30)
    sign_samples = timed_ns(op_sign, ITERS)
    verify_samples = timed_ns(op_verify, ITERS)

    rsa_rows = [
        stat_row("Keygen_RSA2048", "pyca/cryptography(OpenSSL)", keygen_samples),
        stat_row("Signature_RSA2048", "pyca/cryptography(OpenSSL)", sign_samples),
        stat_row("Verify_RSA2048", "pyca/cryptography(OpenSSL)", verify_samples),
    ]

    NEW_OPS = {"Keygen_RSA2048", "Signature_RSA2048", "Verify_RSA2048"}
    header = ["operation", "library", "iterations", "mean_ns", "median_ns",
              "p95_ns", "p99_ns", "stddev_ns", "min_ns", "max_ns"]
    STAT_COLS = {"mean_ns", "median_ns", "p95_ns", "p99_ns", "stddev_ns"}

    def fmt_row(r):
        return [f"{r[h]:.1f}" if h in STAT_COLS else str(r[h]) for h in header]

    # idempotency: drop any prior RSA2048 rows, keep everything else as-is;
    # also pull the real, already-measured Ed25519/X25519 means method 5's
    # breakdown now uses.
    prior = []
    kx = sx = ed_sign = ed_verify = None
    if os.path.exists(PRIM_CSV):
        with open(PRIM_CSV, newline="") as f:
            for r in csv.DictReader(f):
                if r["operation"] == "Keygen_X25519":
                    kx = float(r["mean_ns"])
                if r["operation"] == "ScalarMult_X25519":
                    sx = float(r["mean_ns"])
                if r["operation"] == "Signature_Ed25519":
                    ed_sign = float(r["mean_ns"])
                if r["operation"] == "Verify_Ed25519":
                    ed_verify = float(r["mean_ns"])
                if r["operation"] not in NEW_OPS:
                    prior.append(r)
    if None in (kx, sx, ed_sign, ed_verify):
        sys.exit("rsa_bench.py: crypto-primitives.csv missing Keygen_X25519/"
                 "ScalarMult_X25519/Signature_Ed25519/Verify_Ed25519 — run "
                 "crypto_bench first")

    with open(PRIM_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in prior:
            w.writerow([r[h] for h in header])
        for r in rsa_rows:
            w.writerow(fmt_row(r))

    def role_rows(role):
        rows_out = [
            (METHOD, PROFILE, role, "Keygen", "X25519/ML-KEM-768", 1, kx),
            (METHOD, PROFILE, role, "ScalarMult", "X25519", 1, sx),
            (METHOD, PROFILE, role, "Encaps", "ML-KEM-768", 0, 0.0),
            (METHOD, PROFILE, role, "Decaps", "ML-KEM-768", 0, 0.0),
            (METHOD, PROFILE, role, "Signature", "Ed25519/ML-DSA-44", 1, ed_sign),
            # CertificateVerify + peer certificate signature
            (METHOD, PROFILE, role, "Verify", "Ed25519/ML-DSA-44", 2, 2 * ed_verify),
        ]
        total_ns = kx + sx + ed_sign + 2 * ed_verify
        return rows_out, total_ns

    ini_rows, ini_ns = role_rows("initiator")
    res_rows, res_ns = role_rows("responder")

    # ---- append to crypto-breakdown.csv (idempotent on method==5) ----
    bd_existed = os.path.exists(BREAKDOWN_CSV)
    bd_prior = []
    if bd_existed:
        with open(BREAKDOWN_CSV, newline="") as f:
            bd_prior = [r for r in csv.reader(f)]
    bd_header = bd_prior[0] if bd_prior else \
        ["method", "profile", "role", "operation", "primitive", "op_count", "compute_ns"]
    bd_body = [r for r in bd_prior[1:] if not (r and r[0] == str(METHOD))] if bd_prior else []
    with open(BREAKDOWN_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(bd_header)
        w.writerows(bd_body)
        for m, p, role, op, prim, cnt, ns in ini_rows + res_rows:
            w.writerow([m, p, role, op, prim, cnt, f"{ns:.1f}"])

    # ---- append to handshake-compute.csv (idempotent on method==5) ----
    hc_existed = os.path.exists(COMPUTE_CSV)
    hc_prior = []
    if hc_existed:
        with open(COMPUTE_CSV, newline="") as f:
            hc_prior = [r for r in csv.reader(f)]
    hc_header = hc_prior[0] if hc_prior else \
        ["method", "profile", "initiator_compute_us", "responder_compute_us", "total_compute_us"]
    hc_body = [r for r in hc_prior[1:] if not (r and r[0] == str(METHOD))] if hc_prior else []
    ini_us, res_us = ini_ns / 1000.0, res_ns / 1000.0
    with open(COMPUTE_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(hc_header)
        w.writerows(hc_body)
        w.writerow([METHOD, PROFILE, f"{ini_us:.3f}", f"{res_us:.3f}", f"{ini_us + res_us:.3f}"])

    # ---- mtu-fragmentation.csv (method 5 row, using the real observed live
    # byte sizes rather than a modeled estimate -- see LIVE_MSG_BYTES) ----
    mtu_existed = os.path.exists(MTU_CSV)
    mtu_prior = []
    if mtu_existed:
        with open(MTU_CSV, newline="") as f:
            mtu_prior = [r for r in csv.reader(f)]
    mtu_header = mtu_prior[0] if mtu_prior else \
        ["method", "profile", "message", "size_bytes", "eap_message_attrs",
         "eap_fragments", "ip_datagram_bytes", "ip_fragments", "exceeds_mtu"]
    mtu_body = [r for r in mtu_prior[1:] if not (r and r[0] == str(METHOD))] if mtu_prior else []
    EAP_FRAG_SIZE = 1020  # matches TLS_FRAG_MAX in eap_tls_bench.c

    def ip_fragments(nbytes):
        total = nbytes + UDP_HDR
        payload = IP_MTU - IP_HDR
        if total <= payload:
            return 1
        return math.ceil(total / (payload - (payload % 8)))

    with open(MTU_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(mtu_header)
        w.writerows(mtu_body)
        for msg, sz in LIVE_MSG_BYTES.items():
            eap_attrs = math.ceil(sz / EAP_ATTR) if sz else 0
            eap_frags = math.ceil(sz / EAP_FRAG_SIZE) if sz else 0
            ipd = sz + UDP_HDR + IP_HDR
            ipf = ip_fragments(sz)
            exceeds = "yes" if ipd > IP_MTU else "no"
            w.writerow([METHOD, PROFILE, msg, sz, eap_attrs, eap_frags, ipd, ipf, exceeds])

    sign_mean = statistics.mean(sign_samples)
    verify_mean = statistics.mean(verify_samples)
    keygen_mean = statistics.mean(keygen_samples)
    print(f"[rsa_bench] (reference only, not used by method 5) RSA-2048 sign "
          f"mean={sign_mean/1000:.1f}us verify mean={verify_mean/1000:.1f}us "
          f"keygen mean={keygen_mean/1e6:.2f}ms")
    print(f"[rsa_bench] method 5 (Ed25519) initiator={ini_us:.3f}us "
          f"responder={res_us:.3f}us total={ini_us+res_us:.3f}us")


if __name__ == "__main__":
    main()
