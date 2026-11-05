#!/usr/bin/env python3
"""
variants_analyze.py — tables of the Message1 variants (step 30), from
e2e-handshake-variants.csv, m1-compute-variants.csv and
fullstack-*-variants.csv. Writes benchmark-results/variants-analysis.md.
Median CI and difference CI: bootstrap, 4000 resamples, seed 1.
"""
import csv
import os
import random
import statistics
import subprocess

import edhoc_sizes

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(HERE, "..", "benchmark-results")
VARIANTS = ["v4", "v4s", "v4s+chk", "v4t"]
rng = random.Random(1)


def rows(name):
    with open(os.path.join(R, name), newline="") as f:
        return list(csv.DictReader(f))


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(p * (len(s) - 1) + 0.5))]


def boot(a):
    return [statistics.median(rng.choices(a, k=len(a))) for _ in range(4000)]


def ci(b):
    return pct(b, 0.025), pct(b, 0.975)


def table(hdr, body):
    return ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)] + ["| " + " | ".join(r) + " |" for r in body]


def main():
    L = []
    hs = rows("e2e-handshake-variants.csv")
    by = {v: [r for r in hs if r["label"].endswith("-" + v) and r["method"] == "4"] for v in VARIANTS}
    tls = [r for r in hs if r["label"].endswith("-tls")]
    for k, s in by.items():
        assert s and all(r["status"] == "PASS" for r in s), k
    assert tls and all(r["status"] == "PASS" for r in tls)

    L += ["### Ukuran (live vs model)", ""]
    body = []
    for v in VARIANTS:
        r = by[v][0]
        live = [int(r[f"msg{i}_bytes"]) for i in range(1, 5)]
        m = edhoc_sizes._message_sizes_sigma_xwing(v)
        model = [m[f"message_{i}"] for i in range(1, 5)]
        frags = "/".join(r[f"msg{i}_frags"] for i in range(1, 5))
        assert {x["radius_round_trips"] for x in by[v]} == {r["radius_round_trips"]}
        body.append([v, "/".join(map(str, live)), str(sum(live)), "/".join(map(str, model)),
                     "cocok" if live == model else "BEDA", frags, r["radius_round_trips"]])
    L += table(["Varian", "Message1–4 live (B)", "Total (B)", "Model (B)", "Live = model", "Fragmen EAP", "RT"], body) + [""]

    L += ["### Harness E2E loss-free (2 run × 100, bergantian dalam satu sesi)", ""]
    base = [float(r["duration_ms"]) for r in by["v4"]]
    bb = boot(base)
    body = []
    series = [(v, by[v]) for v in VARIANTS] + [("EAP-TLS Hybrid PQC", tls)]
    for name, s in series:
        d = [float(r["duration_ms"]) for r in s]
        b = boot(d)
        lo, hi = ci(b)
        if name == "v4":
            diff = "—"
        else:
            dd = [x - y for x, y in zip(b, bb)]
            dl, dh = ci(dd)
            diff = f"{statistics.median(d) - statistics.median(base):+.3f} [{dl:+.3f}, {dh:+.3f}]"
        body.append([name, str(len(d)), f"{statistics.mean(d):.3f}", f"{statistics.median(d):.3f}",
                     f"{pct(d, 0.95):.3f}", f"[{lo:.3f}, {hi:.3f}]", diff])
    L += table(["Varian", "N", "Mean (ms)", "Median (ms)", "p95 (ms)", "95% CI median (ms)",
                "Selisih median vs v4 (ms) [95% CI]"], body) + [""]

    L += ["### Komputasi Message1 (10.000 iterasi per varian, bergantian per iterasi, dalam proses)", ""]
    m1 = {r["variant"]: r for r in rows("m1-compute-variants.csv")}
    body = []
    for v in VARIANTS:
        r = m1[v]
        body.append([v, r["msg1_bytes"], r["ue_median_us"], r["ue_p95_us"], r["dn_median_us"], r["dn_p95_us"],
                     f"{float(r['ue_median_us']) - float(m1['v4']['ue_median_us']):+.1f}",
                     f"{float(r['dn_median_us']) - float(m1['v4']['dn_median_us']):+.1f}"])
    L += table(["Varian", "Message1 (B)", "UE median (µs)", "UE p95 (µs)", "DN-AAA median (µs)", "DN-AAA p95 (µs)",
                "UE vs v4 (µs)", "DN-AAA vs v4 (µs)"], body) + [""]

    L += ["### Full stack v4s (A/B 1 × 100, `@edhoc.internet`, tanpa uji pemulihan)", ""]
    fs = rows("fullstack-handshake-v2-variants.csv")
    A = [r for r in fs if r["config"] == "A"]
    B = [r for r in fs if r["config"] == "B"]
    ok = lambda s, k, v="1": sum(r[k] == v for r in s)
    L.append(f"- A: PASS {ok(A, 'status', 'PASS')}/{len(A)}, msk_match {ok(A, 'msk_match')}/{len(A)}, "
             f"rotated {ok(A, 'rotated')}/{len(A)}; B: PASS {ok(B, 'status', 'PASS')}/{len(B)}.")
    L.append("- Ukuran / ronde: " + str(sorted({(r["len_m1"], r["len_m2"], r["len_m3"], r["len_m4"], r["n_nas_rounds"],
                                                  r["n_radius_rt"]) for r in A})) + " (Message1..4 B, ronde NAS, RADIUS RT).")
    L.append("")
    body = []
    for m, s, c in (("t_pdu_ms", A, "A"), ("t_pdu_ms", B, "B"), ("t_secauth_ms", A, "A"), ("t_aaa_ms", A, "A")):
        d = [float(r[m]) for r in s if r[m] != ""]
        lo, hi = ci(boot(d))
        body.append([f"`{m}`", c, str(len(d)), f"{statistics.mean(d):.3f}", f"{statistics.median(d):.3f}",
                     f"{pct(d, 0.95):.3f}", f"[{lo:.3f}, {hi:.3f}]"])
    L += table(["Metrik", "Konf.", "N", "Mean (ms)", "Median (ms)", "p95 (ms)", "95% CI median (ms)"], body) + [""]
    a, b = [[float(r["t_pdu_ms"]) for r in s] for s in (A, B)]
    dl, dh = ci([x - y for x, y in zip(boot(a), boot(b))])
    L.append(f"- `t_pdu_ms` A − B: **{statistics.median(a) - statistics.median(b):.3f} ms**, 95% CI [{dl:.3f}, {dh:.3f}] ms.")
    L.append("- `uname -r`: " + subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip())
    with open(os.path.join(R, "variants-analysis.md"), "w") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
