#!/usr/bin/env python3
"""compute_v5pg.py — Figure 7 left model for v5-pregen.

From compute-v5pg/ (crypto_bench + compute_tls_hybrid.py, one primitive
session) writes compute-v5pg/handshake-compute-v5pg.csv with one row per
bar: v5-inline (method 4 as crypto_bench counts it, the next KeyGen inside
the handshake), v5-pregen (minus one X-Wing KeyGen per role), the moved
KeyGen itself, and EAP-TLS Hybrid PQC (method 6, unchanged). X-Wing KeyGen
= Keygen_MLKEM768 + Keygen_X25519 (crypto_bench.c), means as in the model;
the medians of the same primitives are given as well.
"""
import csv
import os

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "benchmark-results", "compute-v5pg")


def main():
    prim = {r["operation"]: r for r in csv.DictReader(open(os.path.join(D, "crypto-primitives.csv")))}
    comp = {r["method"]: r for r in csv.DictReader(open(os.path.join(D, "handshake-compute.csv")))}
    kg_mean = (float(prim["Keygen_MLKEM768"]["mean_ns"]) + float(prim["Keygen_X25519"]["mean_ns"])) / 1e3
    kg_med = (float(prim["Keygen_MLKEM768"]["median_ns"]) + float(prim["Keygen_X25519"]["median_ns"])) / 1e3
    i4, r4 = float(comp["4"]["initiator_compute_us"]), float(comp["4"]["responder_compute_us"])
    i6, r6 = float(comp["6"]["initiator_compute_us"]), float(comp["6"]["responder_compute_us"])
    rows = [("v5-inline", i4, r4, "KeyGen of the next key pair inside the handshake"),
            ("v5-pregen", i4 - kg_mean, r4 - kg_mean, "next key pair taken from the pool"),
            ("keygen-moved", kg_mean, kg_mean, f"X-Wing KeyGen per role, mean of the primitives (median {kg_med:.3f} us)"),
            ("eap-tls-hybrid", i6, r6, "method 6, unchanged")]
    with open(os.path.join(D, "handshake-compute-v5pg.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["bar", "initiator_compute_us", "responder_compute_us", "total_compute_us", "note"])
        for b, i, r, n in rows:
            w.writerow([b, f"{i:.3f}", f"{r:.3f}", f"{i + r:.3f}", n])
    for b, i, r, n in rows:
        print(f"[compute_v5pg] {b}: initiator {i:.3f} us, responder {r:.3f} us")


if __name__ == "__main__":
    main()
