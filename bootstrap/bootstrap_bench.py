#!/usr/bin/env python3
"""
bootstrap_bench.py — measurement harness for the Key Bootstrapping phase.

Parallels the existing EAP-EDHOC benchmark methodology (benchmark/lossy_bench.py
+ crypto_bench.c): real cryptographic derivations timed with perf_counter, and
application-level packet-loss emulation with EAP-style retransmission on the two
NEW network legs introduced by this phase:

    leg AAA->AS  : DSRK key transport (HTTP hop)
    leg UE->AS   : first OSCORE contact (CoAP-lite UDP)

Produces the CSVs consumed by analyze_bootstrap.py -> analisys3.md:

    bootstrap-primitives.csv   per-derivation primitive latency (ns)
    bootstrap-latency.csv      per-session breakdown at loss 0
    bootstrap-lossy.csv        per-leg success/latency/retx vs packet loss
    bootstrap-e2e-lossy.csv    end-to-end bootstrap latency percentiles vs loss
    bootstrap-consistency.csv  key-consistency rate (UE vs AS master secret)

Usage: bootstrap_bench.py [results_dir] [--iters N] [--loss-iters N]
"""
from __future__ import annotations

import argparse
import os
import random
import statistics
import time
import gc

from keyschedule import (derive_usrk, derive_dsrk, derive_oscore_master_secret,
                         derive_oscore_master_salt, oscore_context_from_dsrk,
                         derive_oscore_context, fingerprint)
from oscore_lite import protect, unprotect

UE_ID = b"\x01"
AS_ID = b"\x00"
LOSS_RATES = [0.0, 1.0, 5.0, 10.0, 20.0, 30.0]


# ------------------------------------------------------------------ #
# primitive timing                                                   #
# ------------------------------------------------------------------ #
def pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def bench_primitive(name, fn, iters):
    for _ in range(min(50, iters)):
        fn()
    gc_was_enabled = gc.isenabled()
    gc.disable()
    samples = []
    try:
        for _ in range(iters):
            t0 = time.perf_counter_ns()
            fn()
            samples.append(time.perf_counter_ns() - t0)
    finally:
        if gc_was_enabled:
            gc.enable()
    return {
        "operation": name,
        "iterations": iters,
        "mean_ns": round(statistics.mean(samples), 1),
        "median_ns": round(statistics.median(samples), 1),
        "p95_ns": round(pct(samples, 95), 1),
        "p99_ns": round(pct(samples, 99), 1),
        "stddev_ns": round(statistics.pstdev(samples), 1),
    }


def primitive_table(iters):
    emsk = os.urandom(64)
    usrk = derive_usrk(emsk)
    dsrk = derive_dsrk(usrk)
    ms = derive_oscore_master_secret(dsrk)
    salt = derive_oscore_master_salt(dsrk)
    ctx = oscore_context_from_dsrk(dsrk, UE_ID, AS_ID)
    ctx_as = oscore_context_from_dsrk(dsrk, AS_ID, UE_ID)
    payload = b"GET /bootstrap/hello (first contact)"
    msg = protect(ctx, payload, 1)

    rows = [
        bench_primitive("Derive_USRK_RFC5295", lambda: derive_usrk(emsk), iters),
        bench_primitive("Derive_DSRK_RFC5295", lambda: derive_dsrk(usrk), iters),
        bench_primitive("Derive_OSCORE_MasterSecret",
                        lambda: derive_oscore_master_secret(dsrk), iters),
        bench_primitive("Derive_OSCORE_MasterSalt",
                        lambda: derive_oscore_master_salt(dsrk), iters),
        bench_primitive("Derive_OSCORE_Context_RFC8613",
                        lambda: derive_oscore_context(ms, salt, UE_ID, AS_ID), iters),
        bench_primitive("OSCORE_Protect_AESCCM",
                        lambda: protect(ctx, payload, 1), iters),
        bench_primitive("OSCORE_Unprotect_AESCCM",
                        lambda: unprotect(ctx_as, msg), iters),
    ]
    return rows


# ------------------------------------------------------------------ #
# per-session end-to-end model                                        #
# ------------------------------------------------------------------ #
def _leg(loss, rto_ms, max_retx, base_rtt_ms, rng):
    """Emulate one request/response leg with EAP-style retransmission.

    Returns (success, latency_ms, retransmits). Each dropped datagram costs one
    RTO and one retransmit; a leg fails only if all (max_retx+1) tries drop.
    """
    retx = 0
    latency = 0.0
    for attempt in range(max_retx + 1):
        if rng.random() >= loss / 100.0:
            return True, latency + base_rtt_ms, retx
        latency += rto_ms
        retx += 1
    return False, latency, retx


def run_session(emsk, loss_aaa, loss_ue, rto_ms, max_retx, base_rtt_ms, rng):
    # ---- AAA side: real USRK/DSRK derivation (timed) ----
    t0 = time.perf_counter_ns()
    usrk_a = derive_usrk(emsk)
    dsrk_a = derive_dsrk(usrk_a)
    usrk_dsrk_ns_aaa = time.perf_counter_ns() - t0

    # ---- AAA->AS key transport leg (emulated loss) ----
    ok_tx, transport_ms, retx_tx = _leg(loss_aaa, rto_ms, max_retx, base_rtt_ms, rng)

    # ---- AS side: real OSCORE context derivation (timed) ----
    t0 = time.perf_counter_ns()
    ctx_as = oscore_context_from_dsrk(dsrk_a, AS_ID, UE_ID)
    oscore_ns_as = time.perf_counter_ns() - t0

    # ---- UE side: real derivation (timed) ----
    t0 = time.perf_counter_ns()
    usrk_u = derive_usrk(emsk)
    dsrk_u = derive_dsrk(usrk_u)
    usrk_dsrk_ns_ue = time.perf_counter_ns() - t0
    t0 = time.perf_counter_ns()
    ctx_ue = oscore_context_from_dsrk(dsrk_u, UE_ID, AS_ID)
    oscore_ns_ue = time.perf_counter_ns() - t0

    # ---- key consistency (real crypto check) ----
    consistent = (fingerprint(ctx_ue.master_secret) ==
                  fingerprint(ctx_as.master_secret) and
                  ctx_ue.sender_key == ctx_as.recipient_key)

    # ---- UE->AS first OSCORE contact leg (emulated loss + real AEAD) ----
    firstcontact_ms = 0.0
    retx_fc = 0
    ok_fc = False
    if ok_tx:
        ok_fc, firstcontact_ms, retx_fc = _leg(loss_ue, rto_ms, max_retx,
                                               base_rtt_ms, rng)
        if ok_fc:
            # real protected round-trip so the AEAD cost is included/verified
            req = protect(ctx_ue, b"GET /bootstrap/hello", 1)
            got = unprotect(ctx_as, req)
            rep = protect(ctx_as, b"2.05 Content OK", 1)
            unprotect(ctx_ue, rep)
            ok_fc = ok_fc and (got == b"GET /bootstrap/hello")

    # ---- critical-path end-to-end latency ----
    ns_to_ms = 1e-6
    aaa_path_ms = usrk_dsrk_ns_aaa * ns_to_ms + transport_ms + oscore_ns_as * ns_to_ms
    ue_ready_ms = usrk_dsrk_ns_ue * ns_to_ms + oscore_ns_ue * ns_to_ms
    e2e_ms = max(aaa_path_ms, ue_ready_ms) + firstcontact_ms

    result = "success" if (ok_tx and ok_fc and consistent) else "fail"
    return {
        "usrk_dsrk_ns_aaa": usrk_dsrk_ns_aaa,
        "usrk_dsrk_ns_ue": usrk_dsrk_ns_ue,
        "oscore_ns_as": oscore_ns_as,
        "oscore_ns_ue": oscore_ns_ue,
        "transport_ms": round(transport_ms, 4),
        "firstcontact_ms": round(firstcontact_ms, 4),
        "e2e_ms": round(e2e_ms, 4),
        "retx_tx": retx_tx,
        "retx_fc": retx_fc,
        "ok_tx": ok_tx,
        "ok_fc": ok_fc,
        "consistent": consistent,
        "result": result,
    }


# ------------------------------------------------------------------ #
# CSV writers                                                         #
# ------------------------------------------------------------------ #
def write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        f.write(",".join(header) + "\n")
        for r in rows:
            f.write(",".join(str(r.get(h, "")) for h in header) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Key Bootstrapping benchmark")
    ap.add_argument("results_dir", nargs="?",
                    default=os.path.join(os.path.dirname(__file__), "..",
                                         "benchmark-results"))
    ap.add_argument("--iters", type=int, default=3000, help="primitive iters/op")
    ap.add_argument("--loss-iters", type=int, default=1000, help="sessions/cell")
    ap.add_argument("--rto-ms", type=float, default=40.0)
    ap.add_argument("--max-retx", type=int, default=6)
    ap.add_argument("--base-rtt-ms", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()

    rd = os.path.abspath(args.results_dir)
    os.makedirs(rd, exist_ok=True)
    rng = random.Random(args.seed)

    print(f"[bootstrap_bench] results -> {rd}")

    # ---- 1. primitives ----
    print(f"[1/4] primitive derivation latency ({args.iters} iters/op)")
    prim = primitive_table(args.iters)
    write_csv(os.path.join(rd, "bootstrap-primitives.csv"),
              ["operation", "iterations", "mean_ns", "median_ns", "p95_ns",
               "p99_ns", "stddev_ns"], prim)
    for r in prim:
        print(f"      {r['operation']:<32} mean={r['mean_ns']:>10.1f} ns")

    # ---- 2. per-session breakdown at loss 0 ----
    print(f"[2/4] per-session breakdown at loss 0 ({args.loss_iters} sessions)")
    latency_rows = []
    for i in range(args.loss_iters):
        emsk = os.urandom(64)
        s = run_session(emsk, 0.0, 0.0, args.rto_ms, args.max_retx,
                        args.base_rtt_ms, rng)
        latency_rows.append({
            "session": i + 1,
            "usrk_dsrk_ns_ue": s["usrk_dsrk_ns_ue"],
            "usrk_dsrk_ns_aaa": s["usrk_dsrk_ns_aaa"],
            "oscore_ns_ue": s["oscore_ns_ue"],
            "oscore_ns_as": s["oscore_ns_as"],
            "transport_ms": s["transport_ms"],
            "firstcontact_ms": s["firstcontact_ms"],
            "e2e_ms": s["e2e_ms"],
            "consistent": int(s["consistent"]),
        })
    write_csv(os.path.join(rd, "bootstrap-latency.csv"),
              ["session", "usrk_dsrk_ns_ue", "usrk_dsrk_ns_aaa", "oscore_ns_ue",
               "oscore_ns_as", "transport_ms", "firstcontact_ms", "e2e_ms",
               "consistent"], latency_rows)

    # ---- 3. per-leg lossy + e2e lossy ----
    print(f"[3/4] per-leg loss sweep ({args.loss_iters} sessions/cell)")
    leg_rows = []
    e2e_rows = []
    consistency_total = 0
    consistency_ok = 0
    for loss in LOSS_RATES:
        tx_ms, tx_ok, tx_retx = [], 0, []
        fc_ms, fc_ok, fc_retx = [], 0, []
        e2e_ms_all, e2e_ok = [], 0
        for _ in range(args.loss_iters):
            emsk = os.urandom(64)
            # apply the same loss independently to each new leg
            s = run_session(emsk, loss, loss, args.rto_ms, args.max_retx,
                            args.base_rtt_ms, rng)
            consistency_total += 1
            consistency_ok += int(s["consistent"])
            tx_retx.append(s["retx_tx"])
            if s["ok_tx"]:
                tx_ok += 1
                tx_ms.append(s["transport_ms"])
            fc_retx.append(s["retx_fc"])
            if s["ok_fc"]:
                fc_ok += 1
                fc_ms.append(s["firstcontact_ms"])
            if s["result"] == "success":
                e2e_ok += 1
                e2e_ms_all.append(s["e2e_ms"])
        n = args.loss_iters
        leg_rows.append({
            "leg": "AAA->AS", "loss_pct": loss, "trials": n,
            "success_pct": round(100.0 * tx_ok / n, 1),
            "mean_ms": round(statistics.mean(tx_ms), 4) if tx_ms else 0.0,
            "p95_ms": round(pct(tx_ms, 95), 4) if tx_ms else 0.0,
            "p99_ms": round(pct(tx_ms, 99), 4) if tx_ms else 0.0,
            "mean_retx": round(statistics.mean(tx_retx), 4),
        })
        leg_rows.append({
            "leg": "UE->AS", "loss_pct": loss, "trials": n,
            "success_pct": round(100.0 * fc_ok / n, 1),
            "mean_ms": round(statistics.mean(fc_ms), 4) if fc_ms else 0.0,
            "p95_ms": round(pct(fc_ms, 95), 4) if fc_ms else 0.0,
            "p99_ms": round(pct(fc_ms, 99), 4) if fc_ms else 0.0,
            "mean_retx": round(statistics.mean(fc_retx), 4),
        })
        e2e_rows.append({
            "loss_pct": loss, "trials": n,
            "success_pct": round(100.0 * e2e_ok / n, 1),
            "mean_e2e_ms": round(statistics.mean(e2e_ms_all), 4) if e2e_ms_all else 0.0,
            "p50_e2e_ms": round(pct(e2e_ms_all, 50), 4) if e2e_ms_all else 0.0,
            "p95_e2e_ms": round(pct(e2e_ms_all, 95), 4) if e2e_ms_all else 0.0,
            "p99_e2e_ms": round(pct(e2e_ms_all, 99), 4) if e2e_ms_all else 0.0,
        })
    write_csv(os.path.join(rd, "bootstrap-lossy.csv"),
              ["leg", "loss_pct", "trials", "success_pct", "mean_ms", "p95_ms",
               "p99_ms", "mean_retx"], leg_rows)
    write_csv(os.path.join(rd, "bootstrap-e2e-lossy.csv"),
              ["loss_pct", "trials", "success_pct", "mean_e2e_ms", "p50_e2e_ms",
               "p95_e2e_ms", "p99_e2e_ms"], e2e_rows)

    # ---- 4. key consistency ----
    print("[4/4] key consistency across all sessions")
    write_csv(os.path.join(rd, "bootstrap-consistency.csv"),
              ["sessions", "consistent", "rate_pct"],
              [{"sessions": consistency_total, "consistent": consistency_ok,
                "rate_pct": round(100.0 * consistency_ok / consistency_total, 2)}])

    print(f"[bootstrap_bench] done. consistency {consistency_ok}/{consistency_total}")


if __name__ == "__main__":
    main()
