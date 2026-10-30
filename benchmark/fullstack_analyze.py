#!/usr/bin/env python3
"""
fullstack_analyze.py — turn the [E4T] logs of benchmark/fullstack_bench.sh
into benchmark-results/fullstack-handshake.csv and fullstack-recovery.csv.

  fullstack_analyze.py <logs-fullstack-dir>          step 17 (auth after Accept)
  fullstack_analyze.py <logs-fullstack-v2-dir> v2    secondary auth inside
      establishment -> fullstack-handshake-v2.csv, fullstack-recovery-v2.csv,
      fullstack-harness-shared.csv (configuration C)
  fullstack_analyze.py <dir> v2 <suffix>             same, file names with
      <suffix> before ".csv" (a re-measurement next to the step-19 files)

v2 columns (A): t_pdu_ms = Request -> Accept (includes the secondary
authentication), t_secauth_ms = first Command -> Accept, t_req_to_auth_ms =
Request -> first Command (CreateSMContext, UDM), and the relay split
  t_hop_smf_upf_ms  sum(smf_relay_tx -> rx) - sum(upf_req_rx -> upf_resp_tx)
  t_relay_proc_ms   sum(upf_req_rx -> upf_resp_tx) - sum(upf_rad_tx -> rx)
  t_aaa_ms          sum(upf_rad_tx -> upf_rad_rx) (FreeRADIUS + loopback,
                    = t_radius_ms)
  id_identity       DN-specific EAP identity (ue.yaml secondaryAuth.identity)

Every process prints "[E4T] <tag> t_us=<CLOCK_MONOTONIC us> ..." (same host,
same clock). A session owns the events from its "start" mark up to the next
session's "start" mark (fullstack_driver.py writes the marks).

fullstack-handshake.csv, one row per measured session (warm-up dropped):
  t_pdu_ms      ue_pdu_req -> ue_pdu_acc
  t_secauth_ms  first ue_cmd_rx -> ue_result_rx                       (A)
  t_radius_ms   sum of upf_rad_tx -> upf_rad_rx                       (A)
  t_core_ms     t_secauth_ms - t_radius_ms: UE + gNB + AMF + SMF + relay
  t_ready_ms    ue_pdu_req -> ue_result_rx (A) / ue_pdu_acc (B): PDU
                session usable; in this SMF the secondary authentication
                starts after the Accept (100 ms timer after the N2 setup)
  t_acc_to_auth_ms  ue_pdu_acc -> first ue_cmd_rx                     (A)
  t_smf_relay_ms    sum of smf_relay_begin -> smf_relay_end            (A)
  n_nas_rounds  Authentication Commands received by the UE
  n_radius_rt   Access-Requests sent by the UPF relay
  len_m1..m4    EDHOC message sizes seen by the UE
  ue_store_next_ms, ue_promote_ms, aaa_commit_ms
  msk_match     SHA-256(MSK)[0:8] of UE == DN-AAA
  rotated       ue.rec and rec.bin both changed by the session
"""
import csv
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.abspath(os.path.join(HERE, "..", "benchmark-results"))
LINE = re.compile(r"\[E4T\] (\S+) t_us=(\d+) sess=(\d+) len=(\d+)(.*)")


def events(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, errors="replace") as f:
        for ln in f:
            m = LINE.search(ln)
            if m:
                kv = dict(x.split("=", 1) for x in m.group(5).split() if "=" in x)
                out.append((int(m.group(2)), m.group(1), int(m.group(4)), kv))
    out.sort(key=lambda e: e[0])
    return out


def marks(path):
    starts, ends = [], {}
    with open(path) as f:
        for ln in f:
            p = ln.split()
            key = (p[1], p[2], p[3], p[4])
            if p[0] == "start":
                starts.append((int(p[5]), key))
            else:
                ends[key] = (int(p[5]), p[6], int(p[7]), int(p[8]))
    return starts, ends


def window(evs, t0, t1):
    return [e for e in evs if t0 <= e[0] < t1]


def first(evs, tag):
    return next((e for e in evs if e[1] == tag), None)


def dur(evs, a, b):
    """sum of a -> b pairs (each a with the next b)"""
    tot, t_a = 0, None
    for t, tag, _, _ in evs:
        if tag == a:
            t_a = t
        elif tag == b and t_a is not None:
            tot += t - t_a
            t_a = None
    return tot


def sessions(d, aaa):
    """yield (key, end, merged events) for every session of series dir d"""
    starts, ends = marks(os.path.join(d, "marks.txt"))
    ue = events(os.path.join(d, "ue.log"))
    smf = events(os.path.join(d, "smfd.log"))
    upf = events(os.path.join(d, "upfd.log"))
    for i, (t0, key) in enumerate(starts):
        t1 = starts[i + 1][0] if i + 1 < len(starts) else t0 + 30_000_000
        yield key, ends.get(key), {
            "ue": window(ue, t0, t1), "smf": window(smf, t0, t1),
            "upf": window(upf, t0, t1), "aaa": window(aaa, t0, t1)}


def ms(us):
    return f"{us / 1000:.3f}"


def row_v2(key, end, ev, identity):
    kind, config, series, it = key
    ue, upf, smf, aaa = ev["ue"], ev["upf"], ev["smf"], ev["aaa"]
    req, acc = first(ue, "ue_pdu_req"), first(ue, "ue_pdu_acc")
    cmd = first(ue, "ue_cmd_rx")
    outcome = end[1] if end else "missing"
    r = {"config": config, "series": series, "iter": it, "status": "PASS" if outcome == "success" else "FAIL",
         "outcome": outcome}
    r["t_pdu_ms"] = ms(acc[0] - req[0]) if req and acc else ""
    r["t_ready_ms"] = r["t_pdu_ms"]
    if config == "A":
        t_sec = acc[0] - cmd[0] if cmd and acc else None
        t_rad = dur(upf, "upf_rad_tx", "upf_rad_rx")
        t_upf = dur(upf, "upf_req_rx", "upf_resp_tx")
        t_smf = dur(smf, "smf_relay_tx", "smf_relay_rx")
        r["t_secauth_ms"] = ms(t_sec) if t_sec is not None else ""
        r["t_radius_ms"] = ms(t_rad)
        r["t_core_ms"] = ms(t_sec - t_rad) if t_sec is not None else ""
        r["t_req_to_auth_ms"] = ms(cmd[0] - req[0]) if req and cmd else ""
        r["t_smf_relay_ms"] = ms(t_smf)
        r["t_hop_smf_upf_ms"] = ms(t_smf - t_upf)
        r["t_relay_proc_ms"] = ms(t_upf - t_rad)
        r["t_aaa_ms"] = ms(t_rad)
        r["id_identity"] = identity
        r["n_nas_rounds"] = sum(1 for e in ue if e[1] == "ue_cmd_rx")
        r["n_radius_rt"] = sum(1 for e in upf if e[1] == "upf_rad_tx")
        for n in range(1, 5):
            m = first(ue, f"ue_msg{n}")
            r[f"len_m{n}"] = m[2] if m else ""
        sn, pr, cm = first(ue, "ue_store_next"), first(ue, "ue_promote"), first(aaa, "aaa_commit")
        r["ue_store_next_ms"] = ms(int(sn[3]["dur_us"])) if sn else ""
        r["ue_promote_ms"] = ms(int(pr[3]["dur_us"])) if pr else ""
        r["aaa_commit_ms"] = ms(int(cm[3]["dur_us"])) if cm else ""
        mu, ma = first(ue, "msk_tag"), first(aaa, "msk_tag")
        r["msk_match"] = int(bool(mu and ma and mu[3].get("tag") == ma[3].get("tag")))
        r["rotated"] = int(bool(end and end[2] and end[3]))
    return r


def row(key, end, ev):
    kind, config, series, it = key
    ue, upf, smf, aaa = ev["ue"], ev["upf"], ev["smf"], ev["aaa"]
    req, acc = first(ue, "ue_pdu_req"), first(ue, "ue_pdu_acc")
    cmd, res = first(ue, "ue_cmd_rx"), first(ue, "ue_result_rx")
    outcome = end[1] if end else "missing"
    r = {"config": config, "series": series, "iter": it, "status": "PASS" if outcome == "success" else "FAIL",
         "outcome": outcome}
    r["t_pdu_ms"] = ms(acc[0] - req[0]) if req and acc else ""
    lens = {n: first(ue, f"ue_msg{n}") for n in range(1, 5)}
    if config == "A":
        t_sec = res[0] - cmd[0] if cmd and res else None
        t_rad = dur(upf, "upf_rad_tx", "upf_rad_rx")
        r["t_secauth_ms"] = ms(t_sec) if t_sec is not None else ""
        r["t_radius_ms"] = ms(t_rad)
        r["t_core_ms"] = ms(t_sec - t_rad) if t_sec is not None else ""
        r["t_ready_ms"] = ms(res[0] - req[0]) if req and res else ""
        r["t_acc_to_auth_ms"] = ms(cmd[0] - acc[0]) if acc and cmd else ""
        r["t_smf_relay_ms"] = ms(dur(smf, "smf_relay_begin", "smf_relay_end"))
        r["n_nas_rounds"] = sum(1 for e in ue if e[1] == "ue_cmd_rx")
        r["n_radius_rt"] = sum(1 for e in upf if e[1] == "upf_rad_tx")
        for n in range(1, 5):
            r[f"len_m{n}"] = lens[n][2] if lens[n] else ""
        sn, pr, cm = first(ue, "ue_store_next"), first(ue, "ue_promote"), first(aaa, "aaa_commit")
        r["ue_store_next_ms"] = ms(int(sn[3]["dur_us"])) if sn else ""
        r["ue_promote_ms"] = ms(int(pr[3]["dur_us"])) if pr else ""
        r["aaa_commit_ms"] = ms(int(cm[3]["dur_us"])) if cm else ""
        mu, ma = first(ue, "msk_tag"), first(aaa, "msk_tag")
        r["msk_match"] = int(bool(mu and ma and mu[3].get("tag") == ma[3].get("tag")))
        r["rotated"] = int(bool(end and end[2] and end[3]))
    else:
        r["t_ready_ms"] = r["t_pdu_ms"]
    return r


COLS = ["config", "series", "iter", "status", "outcome", "t_pdu_ms", "t_secauth_ms", "t_radius_ms",
        "t_core_ms", "t_ready_ms", "t_acc_to_auth_ms", "t_smf_relay_ms", "n_nas_rounds", "n_radius_rt",
        "len_m1", "len_m2", "len_m3", "len_m4", "ue_store_next_ms", "ue_promote_ms", "aaa_commit_ms",
        "msk_match", "rotated"]

COLS_V2 = COLS[:10] + ["t_req_to_auth_ms"] + COLS[10:] + [
    "t_hop_smf_upf_ms", "t_relay_proc_ms", "t_aaa_ms", "id_identity"]

RCOLS = ["case", "iter", "drop_outcome", "drop_upf", "used_next", "eap_failure", "fallback",
         "sessions_to_recover", "recovered", "t_recovery_ms", "t_last_session_ms", "msk_match"]


def main():
    d = os.path.abspath(sys.argv[1])
    v2 = len(sys.argv) > 2 and sys.argv[2] == "v2"
    sfx = sys.argv[3] if v2 and len(sys.argv) > 3 else ""
    aaa = events(os.path.join(d, "aaa-e4t.txt"))
    identity = ""
    if os.path.exists(os.path.join(d, "ue.yaml")):
        m = re.search(r"^secondaryAuth:\s*\n\s+identity:\s*'?([^'\n]+)'?", open(os.path.join(d, "ue.yaml")).read(), re.M)
        identity = m.group(1).strip() if m else ""
    rows = []
    for s in sorted(os.listdir(d)):
        sd = os.path.join(d, s)
        if not (os.path.isdir(sd) and re.fullmatch(r"[AB]\d+", s)):
            continue
        for key, end, ev in sessions(sd, aaa):
            if key[0] == "run":
                rows.append(row_v2(key, end, ev, identity) if v2 else row(key, end, ev))
    rows.sort(key=lambda r: (r["config"], int(r["series"]), int(r["iter"])))
    hs_name = f"fullstack-handshake-v2{sfx}.csv" if v2 else "fullstack-handshake.csv"
    with open(os.path.join(RESULTS, hs_name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS_V2 if v2 else COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # recovery: drop session, then recover_<case> sessions until success
    rec, after = [], []
    rd = os.path.join(d, "R")
    if os.path.isdir(rd):
        groups = {}
        for key, end, ev in sessions(rd, aaa):
            kind, _, k, it = key
            if kind == "after":
                after.append((end, ev))
                continue
            case = kind.split("_", 1)[1]
            groups.setdefault((case, int(it)), []).append((kind, int(k), end, ev))
        for (case, it), ss in sorted(groups.items()):
            drop = [s for s in ss if s[0].startswith("drop_")][0]
            recs = sorted((s for s in ss if s[0].startswith("recover_")), key=lambda s: s[1])
            first_ev = recs[0][3]["ue"] if recs else []
            load = first(first_ev, "ue_load")
            ok = recs and recs[-1][2] and recs[-1][2][1] == "success"
            req = first(first_ev, "ue_pdu_req")
            # v2: the session ends with the Accept (EAP-Success inside)
            res = first(recs[-1][3]["ue"], "ue_pdu_acc" if v2 else "ue_result_rx") if recs else None
            lreq = first(recs[-1][3]["ue"], "ue_pdu_req") if recs else None
            mu = first(recs[-1][3]["ue"], "msk_tag") if recs else None
            ma = first(recs[-1][3]["aaa"], "msk_tag") if recs else None
            rec.append({
                "case": case, "iter": it,
                "drop_outcome": drop[2][1] if drop[2] else "missing",
                "drop_upf": int(any(e[1] == "upf_drop" for e in drop[3]["upf"])),
                "used_next": int(bool(load and load[3].get("next") == "1")),
                "eap_failure": sum(1 for s in recs if s[2] and s[2][1] == "failure"),
                "fallback": sum(1 for s in recs for e in s[3]["ue"] if e[1] == "ue_fallback"),
                "sessions_to_recover": len(recs),
                "recovered": int(bool(ok)),
                "t_recovery_ms": ms(res[0] - req[0]) if ok and req and res else "",
                "t_last_session_ms": ms(res[0] - lreq[0]) if ok and lreq and res else "",
                "msk_match": int(bool(mu and ma and mu[3].get("tag") == ma[3].get("tag"))),
                "first_recovery_outcome": recs[0][2][1] if recs and recs[0][2] else "",
            })
        rc_name = f"fullstack-recovery-v2{sfx}.csv" if v2 else "fullstack-recovery.csv"
        with open(os.path.join(RESULTS, rc_name), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=RCOLS + (["first_recovery_outcome"] if v2 else []),
                               extrasaction="ignore")
            w.writeheader()
            w.writerows(rec)
            # trailing normal sessions (desync check)
            for i, (end, ev) in enumerate(after, 1):
                w.writerow({"case": "after", "iter": i,
                            "recovered": int(bool(end and end[1] == "success")),
                            "sessions_to_recover": 1})
    if v2:
        # configuration C: e2e_radius_bench straight to radiusd, stack idle
        hrows = []
        for name in sorted(os.listdir(d)):
            if re.fullmatch(r"harness-C\d+\.csv", name):
                with open(os.path.join(d, name), newline="") as f:
                    hrows += list(csv.DictReader(f))
        if hrows:
            with open(os.path.join(RESULTS, f"fullstack-harness-shared{sfx}.csv"), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(hrows[0].keys()))
                w.writeheader()
                w.writerows(hrows)
        print(f"{len(hrows)} harness rows -> fullstack-harness-shared{sfx}.csv")
    print(f"{len(rows)} sessions -> {hs_name}; {len(rec)} recovery cases "
          f"+ {len(after)} after ({os.path.basename(d)})")


if __name__ == "__main__":
    main()
