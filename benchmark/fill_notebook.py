#!/usr/bin/env python3
"""
fill_notebook.py — write the live results of benchmark-results/ into the
data cells of symmetry-rev/notebook/EAP_Edhoc_Secondary_Authentication_v2.ipynb
(same definitions as e2e_analyze.py), so no number is typed by hand:

  e2e_initiator / e2e_responder   loss-free means (responder = total - initiator)
  e2e_mean / e2e_p95 / e2e_retx / e2e_success   lossy series (mean/p95 over
                                  PASS runs, retransmissions and success over
                                  all trials)
  MSG1..MSG4                      observed message sizes (chart 2 order)
  total_eap_frags / total_ip_frags  observed EAP fragments, IP fragments at MTU 1500
  compute_initiator / compute_responder  handshake-compute.csv
  EDHOC_HANDSHAKE_MEAN_MS         loss-free mean of method 4

usage: fill_notebook.py [notebook]
"""
import csv
import json
import os
import re
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
R = os.path.join(ROOT, "benchmark-results")
NB = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "symmetry-rev/notebook/EAP_Edhoc_Secondary_Authentication_v2.ipynb")
LOSS = [0.0, 1.0, 5.0, 10.0, 20.0, 30.0]
MTU = 1500
# chart 2 order: methods_c2 in the notebook
C2_ORDER = [6, 4, 5, 0, 2, 1, 3]


def rows(name):
    with open(os.path.join(R, name), newline="") as f:
        return list(csv.DictReader(f))


def pct(values, p):
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


hs = [r for r in rows("e2e-handshake.csv") if r["status"] == "PASS"]
by_m = {m: [r for r in hs if int(r["method"]) == m] for m in range(7)}
init = [statistics.mean(float(r["initiator_ms"]) for r in by_m[m]) for m in range(7)]
tot = [statistics.mean(float(r["duration_ms"]) for r in by_m[m]) for m in range(7)]
resp = [round(t, 3) - round(i, 3) for t, i in zip(tot, init)]

lossy = rows("e2e-lossy.csv")
e2e = {k: {} for k in ("mean", "p95", "retx", "success")}
for m in range(7):
    for k in e2e:
        e2e[k][m] = []
    for l in LOSS:
        rr = [r for r in lossy if int(r["method"]) == m and float(r["loss_pct"]) == l]
        d = [float(r["duration_ms"]) for r in rr if r["status"] == "PASS"]
        e2e["mean"][m].append(statistics.mean(d) if d else 0.0)
        e2e["p95"][m].append(pct(d, 95) if d else 0.0)
        e2e["retx"][m].append(statistics.mean(int(r["retransmits"]) for r in rr))
        e2e["success"][m].append(100.0 * len(d) / len(rr))

first = {m: by_m[m][0] for m in range(7)}
msg = {i: [int(first[m][f"msg{i}_bytes"]) for m in C2_ORDER] for i in range(1, 5)}
eap_frags = [sum(int(first[m][f"msg{i}_frags"]) for i in range(1, 5)) for m in range(7)]
ip_frags = [sum((int(first[m][f"msg{i}_bytes"]) + MTU - 1) // MTU for i in range(1, 5)) for m in range(7)]

comp = {int(r["method"]): r for r in rows("handshake-compute.csv")}
c_ini = [float(comp[m]["initiator_compute_us"]) / 1000 for m in range(7)]
c_res = [float(comp[m]["responder_compute_us"]) / 1000 for m in range(7)]


def lst(v, f="{:.3f}"):
    return "[" + ", ".join(f.format(x) for x in v) + "]"


def dct(d, f):
    return "{\n" + "".join(f"    {m}: [" + ", ".join(f.format(x) for x in d[m]) + "],\n" for m in range(7)) + "}"


nb = json.load(open(NB))
cells = [c for c in nb["cells"] if c["cell_type"] == "code"]
subs = [
    (0, r"compute_initiator = \[[^\]]*\]", "compute_initiator = " + lst(c_ini, "{:.6f}")),
    (0, r"compute_responder = \[[^\]]*\]", "compute_responder = " + lst(c_res, "{:.6f}")),
    (0, r"e2e_initiator = \[[^\]]*\]", "e2e_initiator = " + lst(init)),
    (0, r"e2e_responder = \[[^\]]*\]", "e2e_responder = " + lst(resp)),
    (0, r"MSG1 = \[[^\]]*\]", "MSG1 = " + lst(msg[1], "{}")),
    (0, r"MSG2 = \[[^\]]*\]", "MSG2 = " + lst(msg[2], "{}")),
    (0, r"MSG3 = \[[^\]]*\]", "MSG3 = " + lst(msg[3], "{}")),
    (0, r"MSG4 = \[[^\]]*\]", "MSG4 = " + lst(msg[4], "{}")),
    (0, r"total_eap_frags = \[[^\]]*\]", "total_eap_frags = " + lst(eap_frags, "{}")),
    (0, r"total_ip_frags = \[[^\]]*\]", "total_ip_frags = " + lst(ip_frags, "{}")),
    (0, r"e2e_mean = \{[^}]*\}", "e2e_mean = " + dct(e2e["mean"], "{:.3f}")),
    (0, r"e2e_p95 = \{[^}]*\}", "e2e_p95 = " + dct(e2e["p95"], "{:.3f}")),
    (0, r"e2e_retx = \{[^}]*\}", "e2e_retx = " + dct(e2e["retx"], "{:.3f}")),
    (0, r"e2e_success = \{[^}]*\}", "e2e_success = " + dct(e2e["success"], "{:.1f}")),
    (2, r"EDHOC_HANDSHAKE_MEAN_MS = [0-9.]+", f"EDHOC_HANDSHAKE_MEAN_MS = {tot[4]:.3f}"),
]
for ci, pat, rep in subs:
    src = "".join(cells[ci]["source"])
    new, n = re.subn(pat, lambda _m: rep, src, count=1)
    if n != 1:
        sys.exit(f"pattern not found in code cell {ci}: {pat}")
    lines = new.split("\n")
    cells[ci]["source"] = [l + "\n" for l in lines[:-1]] + ([lines[-1]] if lines[-1] else [])
with open(NB, "w") as f:
    f.write(json.dumps(nb, indent=1, ensure_ascii=False))   # same layout as the file
print(f"filled {NB}: m4 mean {tot[4]:.3f} ms, EAP frags {eap_frags}, IP frags {ip_frags}")
