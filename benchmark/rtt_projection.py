#!/usr/bin/env python3
"""
rtt_projection.py — loss-free handshake time projected to a non-zero
SMF--DN-AAA round-trip time, T(RTT) = T_loopback + n_RT * RTT (ms).

T_loopback is the measured loss-free mean from e2e-handshake.csv; for
methods 0-3 it is the median of the pooled 10,000-handshake runs in
e2e-handshake-highn.csv (their 100-200-run means are dominated by outliers).
Prints the LaTeX rows of the paper's tab:rtt-projection and the ratios
quoted in the text.
"""
import csv
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.abspath(os.path.join(HERE, "..", "benchmark-results")) if len(sys.argv) < 2 else sys.argv[1]
RTTS = [0, 1, 5, 10, 20]


def rows(name):
    with open(os.path.join(R, name), newline="") as f:
        return [r for r in csv.DictReader(f) if r["status"] == "PASS"]


hs = rows("e2e-handshake.csv")
hn = rows("e2e-handshake-highn.csv")
n_rt = {m: int(next(r for r in hs if int(r["method"]) == m)["radius_round_trips"]) for m in range(7)}
mean = {m: statistics.mean(float(r["duration_ms"]) for r in hs if int(r["method"]) == m) for m in range(7)}
t03 = statistics.median(float(r["duration_ms"]) for r in hn)

table = [("EAP-EDHOC Methods 0--3 (median)", n_rt[0], t03),
         ("EAP-TLS Classic", n_rt[5], mean[5]),
         ("Proposal (durable key storage)", n_rt[4], mean[4]),
         ("EAP-TLS Hybrid PQC", n_rt[6], mean[6])]
for name, n, t in table:
    print(f"{name:<31} & {n:<2} & " + " & ".join(f"{t + n * x:.1f}" for x in RTTS) + r" \\")
p, h = mean[4], mean[6]
be = (p - h) / (n_rt[6] - n_rt[4])
print(f"% breakeven RTT {be:.3f} ms; ratio hybrid/proposal at 0 ms {h / p:.2f}, "
      f"at 10 ms {(h + 10 * n_rt[6]) / (p + 10 * n_rt[4]):.2f} "
      f"({p + 10 * n_rt[4]:.1f} vs {h + 10 * n_rt[6]:.1f} ms)")
