#!/usr/bin/env python3
"""
rsa_bench.py — method 5 (EAP-TLS Classic) crypto compute breakdown.

Unlike method 6, method 5 is fully live (see eap_tls_bench.c), so its 1b
compute-breakdown numbers are backed by a REAL micro-benchmark here too —
not a computed/simulated model. crypto_bench.c (C, libsodium/mbedTLS/PQClean)
already measures every primitive methods 0..4 need; the one primitive it
does not cover is RSA-2048 sign/verify, which classic mutual EAP-TLS needs
for its ECDHE-RSA key exchange (ServerKeyExchange signature) and mutual
client-certificate authentication (CertificateVerify). This script measures
that primitive for real via pyca/cryptography (OpenSSL backend — the same
library already used for cross-implementation checks in section 3 /
interop_check.py), appends it to crypto-primitives.csv, and derives method 5
rows for crypto-breakdown.csv / handshake-compute.csv the same way
crypto_bench.c derives methods 0..4 (reusing the already-measured
Keygen_X25519 / ScalarMult_X25519 rows for the ECDHE half).

Per-side operation model (mirrors method 0's SIG/SIG shape — one keygen, one
scalar-mult, one sign, one verify per side — with RSA-2048 in place of
Ed25519, matching the real live handshake observed in section 1c/e2e-*.csv:
X25519 ECDHE key_share both directions, plus a signature exchanged in each
direction — server's ServerKeyExchange, client's mutual-TLS CertificateVerify):
  initiator (UE)  : Keygen(X25519)x1, ScalarMult(X25519)x1,
                     Signature(RSA-2048)x1 [CertificateVerify],
                     Verify(RSA-2048)x1   [verifies server's signature]
  responder (AAA) : Keygen(X25519)x1, ScalarMult(X25519)x1,
                     Signature(RSA-2048)x1 [ServerKeyExchange signature],
                     Verify(RSA-2048)x1   [verifies client's CertificateVerify]

RSA-2048 keygen is measured too (for completeness of crypto-primitives.csv)
but not counted in the handshake breakdown (op_count=0, same pattern used
for e.g. Encaps/Decaps=0 rows on methods 0..3): both peers' RSA keypairs are
pre-provisioned certificates (raddb/certs/), not generated per-handshake.
"""
import csv
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

METHOD = 5
PROFILE = "EAP-TLS Classic (X25519 ECDHE + RSA-2048, mutual)"
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

    rows = [
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

    # idempotency: drop any prior RSA2048 rows, keep everything else as-is
    prior = []
    kx = sx = None
    if os.path.exists(PRIM_CSV):
        with open(PRIM_CSV, newline="") as f:
            for r in csv.DictReader(f):
                if r["operation"] == "Keygen_X25519":
                    kx = float(r["mean_ns"])
                if r["operation"] == "ScalarMult_X25519":
                    sx = float(r["mean_ns"])
                if r["operation"] not in NEW_OPS:
                    prior.append(r)
    if kx is None or sx is None:
        sys.exit("rsa_bench.py: crypto-primitives.csv missing Keygen_X25519/"
                 "ScalarMult_X25519 — run crypto_bench first")

    with open(PRIM_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in prior:
            w.writerow([r[h] for h in header])
        for r in rows:
            w.writerow(fmt_row(r))

    sign_mean = statistics.mean(sign_samples)
    verify_mean = statistics.mean(verify_samples)

    def role_rows(role):
        keygen_ns = kx  # x25519_keygen=1, mlkem_keygen=0
        rows_out = [
            (METHOD, PROFILE, role, "Keygen", "X25519/ML-KEM-768", 1, keygen_ns),
            (METHOD, PROFILE, role, "ScalarMult", "X25519", 1, sx),
            (METHOD, PROFILE, role, "Encaps", "ML-KEM-768", 0, 0.0),
            (METHOD, PROFILE, role, "Decaps", "ML-KEM-768", 0, 0.0),
            (METHOD, PROFILE, role, "Signature", "Ed25519/ML-DSA-44/RSA-2048", 1, sign_mean),
            (METHOD, PROFILE, role, "Verify", "Ed25519/ML-DSA-44/RSA-2048", 1, verify_mean),
        ]
        total_ns = keygen_ns + sx + sign_mean + verify_mean
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

    keygen_mean = statistics.mean(keygen_samples)
    print(f"[rsa_bench] RSA-2048 sign mean={sign_mean/1000:.1f}us verify mean={verify_mean/1000:.1f}us "
          f"keygen mean={keygen_mean/1e6:.2f}ms")
    print(f"[rsa_bench] method 5 initiator={ini_us:.3f}us responder={res_us:.3f}us total={ini_us+res_us:.3f}us")


if __name__ == "__main__":
    main()
