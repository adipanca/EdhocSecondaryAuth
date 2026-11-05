#!/usr/bin/env python3
"""
tamper_analyze.py — table of the message_1 tamper tests T1-T7, from the UE
results and the [E4T] aaa_msg1 lines of the DN-AAA (tamper_tests.sh):
final result at the UE, DN-AAA step that refused, time to refuse, Decaps run.

  tamper_analyze.py     writes benchmark-results/tamper-variants.csv and .md

T5 alternates a completed run (not counted) and the replay of its message_1.
T6 has two sessions per iteration: the first one continues, the second
replays its message_1; both are reported.
"""
import csv
import os
import re
import statistics

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(HERE, "..", "benchmark-results")
RAW = os.path.join(R, "tamper-variants-raw")
VARIANTS = ["v4", "v4s", "v4s+chk", "v4t"]
LINE = re.compile(r"aaa_msg1 .*dur_us=(\d+) rc=(-?\d+) decaps=(\d+)")
DESC = {1: "KeyID_B header: 1 bit", 2: "KeyID_B header: of another UE", 3: "ct_B: 1 bit",
        4: "AEAD ciphertext: 1 bit", 5: "old Message1 replayed", 6: "current Message1 in a second EAP session",
        7: "KeyID_B in PT1 != header"}


def step(rc, decaps):
    if rc == 0:
        return "accepted"
    if rc == -9:
        return "lookup" if decaps == 0 else "ID_CRED check"
    return {-10: "KeyID verification", -5: "AEAD tag", -3: "parse", -11: "inner KeyID check", -4: "Decaps"}.get(rc, f"rc={rc}")


def load(variant, test):
    with open(os.path.join(RAW, f"{variant}-T{test}.e4t")) as f:
        rows = [LINE.search(l) for l in f]
    return [(int(m[1]), int(m[2]), int(m[3])) for m in rows if m]


def summarize(rows):
    steps = sorted({step(rc, d) for _, rc, d in rows})
    durs = [u / 1000 for u, _, _ in rows]
    dec = sorted({d for _, _, d in rows})
    return " / ".join(steps), statistics.median(durs), "yes" if dec == [1] else "no" if dec == [0] else f"{dec}"


def main():
    ue = {}
    with open(os.path.join(RAW, "ue.csv")) as f:
        for v, t, _, res, _, _, rep in csv.reader(f):
            ue.setdefault((v, int(t[1:])), []).append((res, rep))
    out = []
    for t in range(1, 8):
        for v in VARIANTS:
            if (v, t) not in ue:
                continue
            res = ue[(v, t)]
            rows = load(v, t)
            n = len(res)
            count = lambda k, i=0: sum(r[i] == k for r in res)
            final = ", ".join(f"{k} {count(k)}/{n}" for k in sorted({r[0] for r in res}))
            if t == 5:
                rows = rows[1::2]
            if t == 6:
                first, second = rows[0::2], rows[1::2]
                s1, d1, c1 = summarize(first)
                s2, d2, c2 = summarize(second)
                reps = ", ".join(f"{k} {count(k, 1)}/{n}" for k in sorted({r[1] for r in res}))
                out.append([f"T{t}", DESC[t], v, f"session 1: {final}; replay session: {reps}",
                            f"{s2} (replay); {s1} (session 1)", f"{d2:.3f}", c2])
                continue
            s, d, c = summarize(rows)
            out.append([f"T{t}", DESC[t], v, final, s, f"{d:.3f}", c])
    hdr = ["test", "manipulation", "variant", "result at the UE", "DN-AAA step", "DN-AAA median ms", "Decaps run"]
    with open(os.path.join(R, "tamper-variants.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(hdr)
        w.writerows(out)
    with open(os.path.join(R, "tamper-variants.md"), "w") as f:
        f.write("| " + " | ".join(hdr) + " |\n|" + "---|" * len(hdr) + "\n")
        for r in out:
            f.write("| " + " | ".join(r) + " |\n")
    print(open(os.path.join(R, "tamper-variants.md")).read())


if __name__ == "__main__":
    main()
