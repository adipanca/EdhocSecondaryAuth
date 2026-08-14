#!/usr/bin/env python3
"""
stability_0_3.py — high-N statistical stability check for methods 0..3.

Section 1c's 100-iter/method live sweep showed methods 0..3 (all identical
RADIUS/EAP round-trip count = 3, no fragmentation) swapping rank order
between reruns of this benchmark suite -- e.g. one run had 2 < 1 < 3 < 0,
another had 1 < 0 < 3 < 2. Since their real compute-cost difference is only
tens of microseconds (handshake-compute.csv: 147.6-179.6 us total), far
below the millisecond-scale wall-clock noise floor, this script asks: does a
MUCH larger sample (5000 iterations/method instead of 100) resolve a real,
statistically stable ranking, or does it stay noise?

Reads benchmark-results/e2e-handshake-highn.csv (produced separately, e.g.:
  for m in 0 1 2 3; do
    ./e2e_radius_bench --method $m --iters 5000 --loss 0 \
      --csv ../benchmark-results/e2e-handshake-highn.csv --label highn
  done

Uses the MEDIAN (not mean) as the primary central-tendency estimator because
the raw samples contain rare, extreme outliers (up to ~2s among 5000
samples/method -- almost certainly transient system hiccups: GC-like pauses,
scheduler contention, or a dropped-and-recovered UDP datagram even at
loss=0, not a per-method property) that would otherwise dominate a plain
mean. A bootstrap 95% CI is computed on the median (resampling-based, no
normality assumption) so pairwise method comparisons are statistically
honest: if two methods' CIs overlap, their difference is NOT
distinguishable from noise at this sample size.

Writes benchmark-results/stability-0-3.csv.
"""
import csv
import os
import random
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.abspath(os.path.join(HERE, "..", "benchmark-results")) \
    if len(sys.argv) < 2 else os.path.abspath(sys.argv[1])
IN_CSV = os.path.join(RESULTS, "e2e-handshake-highn.csv")
OUT_CSV = os.path.join(RESULTS, "stability-0-3.csv")

METHOD_NAMES = {0: "SIG/SIG", 1: "SIG/STAT", 2: "STAT/SIG", 3: "STAT/STAT"}
OUTLIER_MS = 5.0     # >5ms is ~5-10x the typical 0.6-1.1ms baseline for 0..3
BOOTSTRAP_N = 5000
random.seed(42)       # reproducible bootstrap


def bootstrap_median_ci(samples, n_resample=BOOTSTRAP_N, alpha=0.05):
    meds = []
    n = len(samples)
    for _ in range(n_resample):
        resample = [samples[random.randrange(n)] for _ in range(n)]
        meds.append(statistics.median(resample))
    meds.sort()
    lo = meds[int((alpha / 2) * n_resample)]
    hi = meds[int((1 - alpha / 2) * n_resample) - 1]
    return lo, hi


def trimmed_mean(samples, frac=0.05):
    s = sorted(samples)
    k = int(len(s) * frac)
    core = s[k: len(s) - k] if k > 0 else s
    return statistics.mean(core)


def main():
    by_method = {}
    with open(IN_CSV, newline="") as f:
        for r in csv.DictReader(f):
            if r["status"] != "PASS":
                continue
            by_method.setdefault(int(r["method"]), []).append(float(r["duration_ms"]))

    rows = []
    print(f"{'Method':<8}{'N':<7}{'Mean':<9}{'Median':<9}{'TrimMean':<10}"
          f"{'Stddev':<9}{'Outliers>5ms':<13}{'Median 95% CI'}")
    results = {}
    for m in sorted(by_method):
        samples = by_method[m]
        n = len(samples)
        mean_ms = statistics.mean(samples)
        median_ms = statistics.median(samples)
        tmean_ms = trimmed_mean(samples)
        stddev_ms = statistics.stdev(samples)
        outliers = sum(1 for s in samples if s > OUTLIER_MS)
        ci_lo, ci_hi = bootstrap_median_ci(samples)
        results[m] = (median_ms, ci_lo, ci_hi)
        rows.append([m, METHOD_NAMES[m], n, f"{mean_ms:.4f}", f"{median_ms:.4f}",
                     f"{tmean_ms:.4f}", f"{stddev_ms:.4f}", outliers,
                     f"{ci_lo:.4f}", f"{ci_hi:.4f}"])
        print(f"{m:<8}{n:<7}{mean_ms:<9.3f}{median_ms:<9.3f}{tmean_ms:<10.3f}"
              f"{stddev_ms:<9.3f}{outliers:<13}[{ci_lo:.4f}, {ci_hi:.4f}] ms")

    with open(OUT_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "profile", "n", "mean_ms", "median_ms",
                    "trimmed_mean_ms", "stddev_ms", "outliers_gt_5ms",
                    "median_ci95_low_ms", "median_ci95_high_ms"])
        w.writerows(rows)

    # pairwise overlap check on the median CIs
    print("\nPairwise median-CI overlap (ranking dianggap TIDAK signifikan kalau overlap):")
    ms = sorted(results)
    any_distinct = False
    for i in range(len(ms)):
        for j in range(i + 1, len(ms)):
            a, b = ms[i], ms[j]
            _, alo, ahi = results[a]
            _, blo, bhi = results[b]
            overlap = not (ahi < blo or bhi < alo)
            if not overlap:
                any_distinct = True
            print(f"  method {a} vs method {b}: "
                  f"{'OVERLAP (tidak signifikan)' if overlap else 'TERPISAH (signifikan)'}")
    print(f"\n[stability_0_3] wrote {OUT_CSV}")
    print(f"[stability_0_3] ada pasangan method yang signifikan berbeda: {any_distinct}")


if __name__ == "__main__":
    main()
