#!/usr/bin/env python3
"""
merge_v4_handshake.py — protocol v4 changes message_1 of method 4 only, so
the loss-free harness series is re-measured for method 4 and, in the same
session, EAP-TLS Hybrid PQC (method 6) (v4_harness.sh). This keeps the old
benchmark-results/e2e-handshake.csv as e2e-handshake-v3.csv (once) and
writes e2e-handshake.csv with the rows of methods 4 and 6 replaced by
e2e-handshake-v4-m4m6.csv; methods 0-3 and 5 are unchanged.
"""
import csv
import os
import shutil

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "benchmark-results")
cur, old, new = (os.path.join(R, n) for n in
                 ("e2e-handshake.csv", "e2e-handshake-v3.csv", "e2e-handshake-v4-m4m6.csv"))
if not os.path.exists(old):
    shutil.copyfile(cur, old)
with open(old, newline="") as f:
    rd = csv.DictReader(f)
    cols = rd.fieldnames
    keep = [r for r in rd if r["method"] not in ("4", "6")]
with open(new, newline="") as f:
    fresh = list(csv.DictReader(f))
assert {r["method"] for r in fresh} == {"4", "6"}, "expected methods 4 and 6"
rows = sorted(keep + fresh, key=lambda r: (int(r["method"]), r["label"], int(r["iteration"])))
with open(cur, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
print(f"e2e-handshake.csv: {len(keep)} rows kept (methods 0-3, 5), {len(fresh)} new (4, 6); old -> e2e-handshake-v3.csv")
