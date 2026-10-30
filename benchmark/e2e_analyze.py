#!/usr/bin/env python3
"""
e2e_analyze.py — aggregate the real EAP-over-RADIUS harness CSVs into
benchmark-results/analisys2.md.

analisys2.md is the end-to-end counterpart of analysis.md: it reuses the SAME
table columns so every EDHOC method (0..4) can be compared side by side between
the two experiments (analysis.md = microbench / non end-to-end, analisys2.md =
live EAP-over-RADIUS end-to-end against FreeRADIUS rlm_eap_edhoc).

Method-independent sections (crypto primitives, per-method compute breakdown,
interoperability) are carried over verbatim from analysis.md because they are
identical measurements in both experiments.

Inputs  : benchmark-results/e2e-handshake.csv, benchmark-results/e2e-lossy.csv
Carried : benchmark-results/analysis.md (sections 1a, 1b, 3)
Output  : benchmark-results/analisys2.md
"""
import csv
import os
import random
import statistics

try:
    from scipy.stats import fisher_exact
except ImportError:  # the loss table is still written, without p-values
    fisher_exact = None
from collections import defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.abspath(os.path.join(HERE, "..", "benchmark-results"))
HS_CSV = os.path.join(RESULTS, "e2e-handshake.csv")
LOSS_CSV = os.path.join(RESULTS, "e2e-lossy.csv")
ANALYSIS = os.path.join(RESULTS, "analysis.md")
OUT = os.path.join(RESULTS, "analisys2.md")

METHOD_NAMES = {
    0: "SIG/SIG",
    1: "SIG/STAT",
    2: "STAT/SIG",
    3: "STAT/STAT",
    4: "SIGMA-XWING-PQC",
    5: "EAP-TLS-Classic",
    6: "EAP-TLS-Hybrid-PQC",
}
EAP_ATTR = 253      # RFC 3579 EAP-Message attribute payload
MTU = 1500          # IP MTU


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


def wilson(k, n, z=1.959964):
    """Wilson score interval for k successes out of n trials."""
    if n == 0:
        return 0.0, 0.0
    ph = k / n
    den = 1 + z * z / n
    mid = (ph + z * z / (2 * n)) / den
    half = z * ((ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5) / den
    return mid - half, mid + half


def load_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def eap_attrs(nbytes):
    # EDHOC message is wrapped in 1000 B EAP fragments; each fragment is then
    # carried in ceil(frag/253) EAP-Message attributes. Count over all frags.
    return None  # computed per-message below with observed fragment count


def carry_section(analysis_text, start_header, end_headers):
    """Extract a markdown section [start_header .. next end header) verbatim."""
    lines = analysis_text.splitlines()
    out = []
    grabbing = False
    for ln in lines:
        if ln.strip() == start_header:
            grabbing = True
            out.append(ln)
            continue
        if grabbing:
            if any(ln.strip().startswith(h) for h in end_headers):
                break
            out.append(ln)
    return "\n".join(out).rstrip()


def full_5g_core_section(L, by_m):
    """## 5: method 4 through UERANSIM + Open5GS + UPF relay + FreeRADIUS
    (fullstack-handshake.csv / fullstack-recovery.csv, fullstack_analyze.py)."""
    hs_path = os.path.join(RESULTS, "fullstack-handshake.csv")
    if not os.path.exists(hs_path):
        return
    rows = load_rows(hs_path)
    rng = random.Random(1)

    def vals(cfg, k, series=None):
        return [float(r[k]) for r in rows if r["config"] == cfg and r["status"] == "PASS" and r[k]
                and (series is None or r["series"] == series)]

    def ci_med(a):
        bs = sorted(statistics.median(rng.choices(a, k=len(a))) for _ in range(4000))
        return bs[100], bs[3899]

    def ci_diff(a, b):
        bs = sorted(statistics.median(rng.choices(a, k=len(a))) -
                    statistics.median(rng.choices(b, k=len(b))) for _ in range(4000))
        return statistics.median(a) - statistics.median(b), bs[100], bs[3899]

    L.append("## 5. Full 5G core path (UE → gNB → AMF → SMF → UPF → FreeRADIUS)")
    L.append("")
    L.append("`benchmark/fullstack_bench.sh` (log: `fullstack_analyze.py`): method 4 protokol final v3 "
             "lewat UERANSIM (nr-ue, nr-gnb) + Open5GS (AMF, SMF, UPF dengan relay RADIUS) + "
             "FreeRADIUS `radiusd -f`, satu VM. Tiap proses menulis `[E4T] <tag> t_us=...` "
             "(CLOCK_MONOTONIC, µs, `E4_TIMING=1`). Konfigurasi A = secondary authentication "
             "aktif; B = `OPEN5GS_SEC_AUTH=0` (PDU session tanpa EAP-EDHOC). Seri A1 B1 A2 B2 A3 "
             "B3, tiap seri stack di-restart, 5 sesi pemanasan dibuang lalu 100 sesi (nr-cli "
             "`ps-establish`, tunggu hasil atau 5 s, `ps-release`, jeda 200 ms). Record UE dan "
             "DN-AAA di-provision sekali di awal. Median dengan bootstrap 95% CI (4000 resample, seed 1).")
    L.append("")
    L.append("- Di SMF ini secondary authentication **dimulai setelah** PDU Session Establishment "
             "Accept (timer 100 ms setelah N2 PDU Session Resource Setup Response), bukan sebelum "
             "Accept. Karena itu `t_pdu_ms` (Request → Accept) tidak memuat EAP-EDHOC; waktu sampai "
             "sesi terautentikasi adalah `t_ready_ms` (Request → Authentication Result dengan "
             "EAP-Success; untuk B = Accept).")
    L.append("- `t_secauth_ms` = Authentication Command pertama → Authentication Result di UE; "
             "`t_radius_ms` = jumlah Access-Request → balasan di relay UPF (FreeRADIUS + loopback); "
             "`t_core_ms` = selisihnya (UE, gNB, AMF, SMF, relay SMF↔UPF); `t_smf_relay_ms` = jumlah "
             "waktu panggilan relay di SMF (SMF↔UPF + `t_radius_ms`).")
    L.append("- UERANSIM tidak punya EAP-TLS peer, jadi EAP-TLS tidak diukur lewat full stack "
             "(perbandingan EAP-TLS tetap dari harness, bagian 1c dan 2).")
    L.append("")

    L.append("| Konfigurasi | Sesi | PASS | Gagal | msk_match | rotated |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for cfg in ("A", "B"):
        rr = [r for r in rows if r["config"] == cfg]
        ok = [r for r in rr if r["status"] == "PASS"]
        fails = {}
        for r in rr:
            if r["status"] != "PASS":
                fails[r["outcome"]] = fails.get(r["outcome"], 0) + 1
        fs = ", ".join(f"{k} {v}" for k, v in sorted(fails.items())) or "0"
        if cfg == "A" and ok:
            mm = f"{100 * sum(int(r['msk_match']) for r in ok) / len(ok):.1f}%"
            ro = f"{100 * sum(int(r['rotated']) for r in ok) / len(ok):.1f}%"
        else:
            mm = ro = "n/a"
        L.append(f"| {cfg} | {len(rr)} | {len(ok)} | {fs} | {mm} | {ro} |")
    L.append("")

    metrics = [("A", "t_pdu_ms"), ("B", "t_pdu_ms"), ("A", "t_ready_ms"), ("B", "t_ready_ms"),
               ("A", "t_secauth_ms"), ("A", "t_radius_ms"), ("A", "t_core_ms"),
               ("A", "t_acc_to_auth_ms"), ("A", "t_smf_relay_ms"), ("A", "ue_store_next_ms"),
               ("A", "ue_promote_ms"), ("A", "aaa_commit_ms")]
    L.append("| Metrik | Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for cfg, k in metrics:
        v = vals(cfg, k)
        if not v:
            continue
        lo, hi = ci_med(v)
        L.append(f"| `{k}` | {cfg} | {len(v)} | {statistics.mean(v):.3f} | {statistics.median(v):.3f} | "
                 f"{pct(v, 95):.3f} | [{lo:.3f}, {hi:.3f}] |")
    L.append("")
    for k, name in (("t_pdu_ms", "Request → Accept"), ("t_ready_ms", "Request → sesi siap")):
        a, b = vals("A", k), vals("B", k)
        if a and b:
            d, lo, hi = ci_diff(a, b)
            L.append(f"- Selisih median `{k}` A − B ({name}): **{d:.3f} ms**, 95% CI [{lo:.3f}, {hi:.3f}] ms.")
    acc = vals("A", "t_acc_to_auth_ms")
    if acc and vals("A", "t_secauth_ms"):
        L.append(f"- `t_pdu_ms` A ≈ B: tidak ada pesan EAP-EDHOC antara Request dan Accept (semua sesi A: "
                 f"Command pertama datang {min(acc):.1f} ms atau lebih setelah Accept), jadi selisih "
                 "`t_pdu_ms` bukan biaya secondary authentication. Biayanya ada di `t_ready_ms`: "
                 f"selisih A − B = jeda Accept → Command pertama (median {statistics.median(acc):.1f} ms, "
                 "termasuk timer 100 ms SMF dan setup N2/N3) + `t_secauth_ms` (median "
                 f"{statistics.median(vals('A', 't_secauth_ms')):.1f} ms).")
    L.append("")

    L.append("Median per seri (ms):")
    L.append("")
    L.append("| Seri | N | `t_pdu_ms` | `t_ready_ms` | `t_secauth_ms` | `t_radius_ms` | `t_core_ms` |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for cfg in ("A", "B"):
        for s in sorted({r["series"] for r in rows if r["config"] == cfg}, key=int):
            cells = []
            for k in ("t_pdu_ms", "t_ready_ms", "t_secauth_ms", "t_radius_ms", "t_core_ms"):
                v = vals(cfg, k, s)
                cells.append(f"{statistics.median(v):.3f}" if v else "-")
            L.append(f"| {cfg}{s} | {len(vals(cfg, 't_ready_ms', s))} | " + " | ".join(cells) + " |")
    L.append("")

    # sizes and rounds against the live harness
    okA = [r for r in rows if r["config"] == "A" and r["status"] == "PASS"]
    shapes = {}
    for r in okA:
        key = (r["len_m1"], r["len_m2"], r["len_m3"], r["len_m4"], r["n_nas_rounds"], r["n_radius_rt"])
        shapes[key] = shapes.get(key, 0) + 1
    h4 = [r for r in by_m.get(4, []) if r["status"] == "PASS"]
    sm = {s_: statistics.median(vals("A", "t_secauth_ms", s_)) for s_ in
          sorted({r["series"] for r in rows if r["config"] == "A"}, key=int) if vals("A", "t_secauth_ms", s_)}
    if len(sm) > 1:
        L.append(f"- Antar seri A, median `t_secauth_ms` berkisar {min(sm.values()):.1f}–{max(sm.values()):.1f} ms "
                 "(seri pertama setelah provisioning paling lambat); B stabil. Angka gabungan memakai "
                 "ketiga seri.")
        L.append("")
    L.append("| Sumber | Message1 | Message2 | Message3 | Message4 | Ronde NAS | RADIUS RT | Sesi |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, n in sorted(shapes.items(), key=lambda kv: -kv[1]):
        L.append(f"| full stack | {key[0]} | {key[1]} | {key[2]} | {key[3]} | {key[4]} | {key[5]} | {n} |")
    if h4:
        r = h4[0]
        L.append(f"| harness (e2e-handshake.csv) | {r['msg1_bytes']} | {r['msg2_bytes']} | {r['msg3_bytes']} | "
                 f"{r['msg4_bytes']} | - | {r['radius_round_trips']} | {len(h4)} |")
    L.append("")
    L.append("- RADIUS RT full stack = harness: EAP-Response/Identity dikirim SMF sendiri (dari SUPI) "
             "tanpa ronde NAS, sehingga ronde NAS = RADIUS RT − 1.")
    L.append("")

    if h4:
        hd = [float(r["duration_ms"]) for r in h4]
        hr = [float(r["responder_ms"]) for r in h4]
        rad = vals("A", "t_radius_ms")
        sec = vals("A", "t_secauth_ms")
        n_rt = int(h4[0]["radius_round_trips"])
        L.append("| Pengukuran | Mean (ms) | Median (ms) | Per RADIUS RT, median (ms) |")
        L.append("| --- | --- | --- | --- |")
        L.append(f"| harness: handshake E2E (`duration_ms`) | {statistics.mean(hd):.3f} | "
                 f"{statistics.median(hd):.3f} | {statistics.median(hd) / n_rt:.3f} |")
        L.append(f"| harness: menunggu RADIUS (`responder_ms`) | {statistics.mean(hr):.3f} | "
                 f"{statistics.median(hr):.3f} | {statistics.median(hr) / n_rt:.3f} |")
        if rad:
            L.append(f"| full stack: `t_radius_ms` | {statistics.mean(rad):.3f} | {statistics.median(rad):.3f} | "
                     f"{statistics.median(rad) / n_rt:.3f} |")
        if sec:
            L.append(f"| full stack: `t_secauth_ms` | {statistics.mean(sec):.3f} | {statistics.median(sec):.3f} | "
                     f"{statistics.median(sec) / n_rt:.3f} |")
        L.append("")
        if rad:
            L.append(f"- `t_radius_ms` mengukur bagian yang sama dengan `responder_ms` harness (Access-Request "
                     f"→ balasan, FreeRADIUS + DN-AAA), bukan `duration_ms`: `duration_ms` juga memuat "
                     f"kriptografi dan flush UE. Selisih median `t_radius_ms` − `responder_ms` = "
                     f"{statistics.median(rad) - statistics.median(hr):.3f} ms "
                     f"({(statistics.median(rad) - statistics.median(hr)) / n_rt:.3f} ms per RT). Kemungkinan "
                     "penyebab (tidak diukur terpisah): relay UPF membuat socket UDP baru per Access-Request "
                     "dan menghitung MD5/HMAC sendiri, dan di full stack radiusd berbagi CPU dengan 13 "
                     "proses lain (NF Open5GS, gNB, UE).")
            L.append(f"- Bagian terbesar `t_secauth_ms` adalah `t_core_ms` (UE ↔ gNB ↔ AMF ↔ SMF, "
                     f"{n_rt - 1} ronde NAS lewat NGAP/SBI): biaya transport 5G core per ronde, bukan "
                     "kriptografi EDHOC.")
            L.append("")

    rec_path = os.path.join(RESULTS, "fullstack-recovery.csv")
    if os.path.exists(rec_path):
        rr = load_rows(rec_path)
        L.append("### Uji pemulihan lewat full stack (`E4_DROP_ONCE` di relay UPF)")
        L.append("")
        L.append("Relay UPF membuang sekali Access-Request berisi fragmen pertama Message3 (tidak "
                 "sampai ke DN-AAA) atau Access-Challenge berisi Message4 (DN-AAA sudah commit); SMF "
                 "lalu timeout (2 s) dan mengirim Authentication Result tanpa EAP. Sesi berikutnya "
                 "diulang sampai EAP-Success (maks. 3); UERANSIM tidak mengulang sendiri, jadi setelah "
                 "EAP-Failure + fallback diperlukan satu PDU session lagi di CUR.")
        L.append("")
        L.append("| Kasus | N | Drop di UPF | Sesi drop tanpa EAP | used_next | EAP-Failure | fallback | "
                 "Sesi sampai pulih (median) | Pulih | msk_match | Waktu pulih mean / median (ms) | "
                 "Sesi terakhir median (ms) |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        desync = 0
        for case, name in (("msg3", "Message3 dibuang"), ("msg4", "Message4 dibuang")):
            c = [r for r in rr if r["case"] == case]
            if not c:
                continue
            cnt = lambda f: sum(1 for r in c if f(r))
            t = [float(r["t_recovery_ms"]) for r in c if r["t_recovery_ms"]]
            tl = [float(r["t_last_session_ms"]) for r in c if r["t_last_session_ms"]]
            desync += cnt(lambda r: r["recovered"] != "1")
            L.append(f"| {name} | {len(c)} | {cnt(lambda r: r['drop_upf'] == '1')} | "
                     f"{cnt(lambda r: r['drop_outcome'] == 'noeap')} | {cnt(lambda r: r['used_next'] == '1')} | "
                     f"{sum(int(r['eap_failure']) for r in c)} | {sum(int(r['fallback']) for r in c)} | "
                     f"{statistics.median(int(r['sessions_to_recover']) for r in c):.0f} | "
                     f"{cnt(lambda r: r['recovered'] == '1')} | {cnt(lambda r: r['msk_match'] == '1')} | "
                     + (f"{statistics.mean(t):.1f} / {statistics.median(t):.1f}" if t else "-") + " | "
                     + (f"{statistics.median(tl):.1f}" if tl else "-") + " |")
        after = [r for r in rr if r["case"] == "after"]
        desync += sum(1 for r in after if r["recovered"] != "1")
        L.append("")
        L.append(f"- Sesi normal sesudahnya: {sum(1 for r in after if r['recovered'] == '1')}/{len(after)} sukses. "
                 f"Desync: **{desync}**; re-provisioning: **0** (record di-provision sekali sebelum seri pertama).")
        L.append("- Waktu pulih = PDU Session Establishment Request sesi pemulihan pertama → EAP-Success "
                 "sesi terakhir. Pada Message3 dibuang waktunya memuat `reject_delay = 1` FreeRADIUS "
                 "(Access-Reject ditahan 1 s) dan satu PDU session tambahan.")
        L.append("")


def full_5g_core_v2_section(L, by_m):
    """## 6: secondary authentication inside PDU session establishment
    (step 19: fullstack-handshake-v2.csv, fullstack-harness-shared.csv,
    fullstack-recovery-v2.csv, fullstack-v2-sequence.txt)."""
    hs_path = os.path.join(RESULTS, "fullstack-handshake-v2.csv")
    if not os.path.exists(hs_path):
        return
    rows = load_rows(hs_path)
    rng = random.Random(1)

    def vals(cfg, k, series=None, src=None):
        return [float(r[k]) for r in (src or rows) if r["config"] == cfg and r["status"] == "PASS"
                and r.get(k) and (series is None or r["series"] == series)]

    def ci_med(a):
        bs = sorted(statistics.median(rng.choices(a, k=len(a))) for _ in range(4000))
        return bs[100], bs[3899]

    def ci_diff(a, b):
        bs = sorted(statistics.median(rng.choices(a, k=len(a))) -
                    statistics.median(rng.choices(b, k=len(b))) for _ in range(4000))
        return statistics.median(a) - statistics.median(b), bs[100], bs[3899]

    def stat_row(name, cfg, v):
        lo, hi = ci_med(v)
        return (f"| {name} | {cfg} | {len(v)} | {statistics.mean(v):.3f} | {statistics.median(v):.3f} | "
                f"{pct(v, 95):.3f} | [{lo:.3f}, {hi:.3f}] |")

    okA = [r for r in rows if r["config"] == "A" and r["status"] == "PASS"]
    ident = okA[0]["id_identity"] if okA else ""
    L.append("## 6. Full 5G core path, standard order (secondary authentication di dalam establishment)")
    L.append("")
    L.append("Step 19: SMF menjalankan secondary authentication sebagai **langkah 6 TS 23.502 "
             "4.3.2.2.1**, setelah CreateSMContext Response dan data UDM, sebelum asosiasi SM policy "
             "(PCF), pemilihan UPF dan PFCP. SMF mengirim EAP-Request/Identity dalam PDU SESSION "
             "AUTHENTICATION COMMAND (PTI 0); UE menjawab dengan identitas khusus DN "
             f"(`ue.yaml` `secondaryAuth.identity` = `{ident}`, bukan SUPI); EAP-Success dibawa di PDU "
             "SESSION ESTABLISHMENT ACCEPT, EAP-Failure di REJECT #29 (TS 24.501 6.3.1.1, 6.4.1.4.1); "
             "timeout/error relay = REJECT #29 tanpa EAP. Relay: socket UDP persisten SMF→UPF dan "
             "UPF→FreeRADIUS, RADIUS Identifier per request dengan pencocokan Identifier + Response "
             "Authenticator, dan relay SMF **non-blocking** (socket di pollset Open5GS, balasan sebagai "
             "event, timeout `ogs_timer` 2,5 s; UPF menunggu FreeRADIUS 2 s). Konfigurasi dan "
             "prosedur pengukuran sama dengan bagian 5 (seri A1 B1 C1 A2 B2 C2 A3 B3 C3).")
    L.append("")
    L.append("- `t_pdu_ms` = Establishment Request → Accept, sekarang **mencakup** secondary "
             "authentication; `t_secauth_ms` = Command pertama → Accept; `t_req_to_auth_ms` = Request → "
             "Command pertama (CreateSMContext, UDM). Uraian relay per sesi: `t_hop_smf_upf_ms` = "
             "Σ(smf_relay_tx→rx) − Σ(upf_req_rx→upf_resp_tx), `t_relay_proc_ms` = Σ(upf_req_rx→"
             "upf_resp_tx) − Σ(upf_rad_tx→rx) (build/verify RADIUS di relay), `t_aaa_ms` = "
             "Σ(upf_rad_tx→rx) (FreeRADIUS + loopback, = `t_radius_ms`).")
    L.append("- T3580 (TS 24.501 6.3.1.2.1): UE yang menerima Authentication Command hanya "
             "menghentikan T3396/T3584/T3585; T3580 tetap berjalan (16 s) dan berhenti saat "
             "Accept/Reject. Secondary authentication selesai jauh di bawah 16 s, jadi tidak ada "
             "Establishment Request yang dikirim ulang di tengah EAP.")
    L.append("")

    L.append("| Konfigurasi | Sesi | PASS | Gagal | msk_match | rotated |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for cfg in ("A", "B"):
        rr = [r for r in rows if r["config"] == cfg]
        ok = [r for r in rr if r["status"] == "PASS"]
        fails = {}
        for r in rr:
            if r["status"] != "PASS":
                fails[r["outcome"]] = fails.get(r["outcome"], 0) + 1
        fs = ", ".join(f"{k} {v}" for k, v in sorted(fails.items())) or "0"
        if cfg == "A" and ok:
            mm = f"{100 * sum(int(r['msk_match']) for r in ok) / len(ok):.1f}%"
            ro = f"{100 * sum(int(r['rotated']) for r in ok) / len(ok):.1f}%"
        else:
            mm = ro = "n/a"
        L.append(f"| {cfg} | {len(rr)} | {len(ok)} | {fs} | {mm} | {ro} |")
    L.append("")

    L.append("| Metrik | Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) | 95% CI median (ms) |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for cfg, k in (("A", "t_pdu_ms"), ("B", "t_pdu_ms"), ("A", "t_secauth_ms"), ("A", "t_req_to_auth_ms"),
                   ("A", "t_radius_ms"), ("A", "t_core_ms"), ("A", "t_smf_relay_ms"),
                   ("A", "t_hop_smf_upf_ms"), ("A", "t_relay_proc_ms"), ("A", "t_aaa_ms"),
                   ("A", "ue_store_next_ms"), ("A", "ue_promote_ms"), ("A", "aaa_commit_ms")):
        v = vals(cfg, k)
        if v:
            L.append(stat_row(f"`{k}`", cfg, v))
    L.append("")
    a, b = vals("A", "t_pdu_ms"), vals("B", "t_pdu_ms")
    if a and b:
        d, lo, hi = ci_diff(a, b)
        L.append(f"- **Biaya secondary authentication di dalam establishment**: selisih median `t_pdu_ms` "
                 f"A − B = **{d:.3f} ms**, 95% CI [{lo:.3f}, {hi:.3f}] ms (median `t_secauth_ms` "
                 f"{statistics.median(vals('A', 't_secauth_ms')):.3f} ms).")
        L.append("- `t_secauth_ms` berakhir di Accept, jadi juga memuat langkah setelah Access-Accept "
                 "(PCF, pemilihan UPF, PFCP, N1N2 Accept) yang di B juga ada; karena itu selisih A − B "
                 "sedikit lebih kecil dari `t_secauth_ms` (di capture: Access-Accept → Accept ≈ 5 ms).")
        L.append("")

    L.append("Median per seri (ms):")
    L.append("")
    L.append("| Seri | N | `t_pdu_ms` | `t_secauth_ms` | `t_radius_ms` | `t_core_ms` | `t_hop_smf_upf_ms` | `t_relay_proc_ms` |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for cfg in ("A", "B"):
        for s in sorted({r["series"] for r in rows if r["config"] == cfg}, key=int):
            cells = []
            for k in ("t_pdu_ms", "t_secauth_ms", "t_radius_ms", "t_core_ms", "t_hop_smf_upf_ms",
                      "t_relay_proc_ms"):
                v = vals(cfg, k, s)
                cells.append(f"{statistics.median(v):.3f}" if v else "-")
            L.append(f"| {cfg}{s} | {len(vals(cfg, 't_pdu_ms', s))} | " + " | ".join(cells) + " |")
    L.append("")

    # relay breakdown
    parts = [("SMF ↔ UPF (hop, dua arah)", "t_hop_smf_upf_ms"),
             ("relay UPF (build/verify RADIUS)", "t_relay_proc_ms"),
             ("FreeRADIUS + loopback (`t_aaa_ms`)", "t_aaa_ms")]
    tot = vals("A", "t_smf_relay_ms")
    n_rt = statistics.median(float(r["n_radius_rt"]) for r in okA) if okA else 0
    if tot and n_rt:
        L.append("### Uraian waktu relay SMF → UPF → DN-AAA (per sesi, A)")
        L.append("")
        L.append("| Bagian | Mean (ms) | Median (ms) | Median per RT (ms) | Porsi dari mean total |")
        L.append("| --- | --- | --- | --- | --- |")
        for name, k in parts:
            v = vals("A", k)
            L.append(f"| {name} | {statistics.mean(v):.3f} | {statistics.median(v):.3f} | "
                     f"{statistics.median(v) / n_rt:.3f} | {100 * statistics.mean(v) / statistics.mean(tot):.1f}% |")
        L.append(f"| **Total SMF relay** (`t_smf_relay_ms`) | {statistics.mean(tot):.3f} | "
                 f"{statistics.median(tot):.3f} | {statistics.median(tot) / n_rt:.3f} | 100% |")
        L.append("")

    # configuration C against the idle harness
    hr_path = os.path.join(RESULTS, "fullstack-harness-shared.csv")
    h4 = [r for r in by_m.get(4, []) if r["status"] == "PASS"]
    if os.path.exists(hr_path) and h4:
        cr = [r for r in load_rows(hr_path) if r["status"] == "PASS"]
        L.append("### Konfigurasi C: harness langsung ke radiusd saat full stack menyala tetapi diam")
        L.append("")
        L.append("| Pengukuran | N | `duration_ms` mean / median | `responder_ms` mean / median | "
                 "`responder_ms` per RT, median |")
        L.append("| --- | --- | --- | --- | --- |")
        for name, src in (("harness, VM diam (e2e-handshake.csv, bagian 1c)", h4),
                          ("C: harness, full stack diam", cr)):
            d_ = [float(r["duration_ms"]) for r in src]
            r_ = [float(r["responder_ms"]) for r in src]
            nrt = int(src[0]["radius_round_trips"])
            L.append(f"| {name} | {len(src)} | {statistics.mean(d_):.3f} / {statistics.median(d_):.3f} | "
                     f"{statistics.mean(r_):.3f} / {statistics.median(r_):.3f} | "
                     f"{statistics.median(r_) / nrt:.3f} |")
        aaa = vals("A", "t_aaa_ms")
        if aaa:
            L.append(f"| A: `t_aaa_ms` (relay UPF → FreeRADIUS) | {len(aaa)} | - | "
                     f"{statistics.mean(aaa):.3f} / {statistics.median(aaa):.3f} | "
                     f"{statistics.median(aaa) / n_rt:.3f} |")
        L.append("")
        r_idle = statistics.median(float(r["responder_ms"]) for r in h4)
        r_c = statistics.median(float(r["responder_ms"]) for r in cr) if cr else None
        if r_c is not None and aaa:
            L.append(f"- Berbagi CPU dengan stack yang diam: `responder_ms` median {r_idle:.3f} → "
                     f"{r_c:.3f} ms ({r_c - r_idle:+.3f} ms). Sisa selisih ke `t_aaa_ms` "
                     f"({statistics.median(aaa) - r_c:+.3f} ms) muncul saat stack aktif (UE, gNB, AMF, SMF "
                     "bekerja di antara round-trip) dan dari klien RADIUS relay; `t_relay_proc_ms` dan "
                     "`t_hop_smf_upf_ms` di tabel di atas berada di luar `t_aaa_ms`.")
            L.append("")

    # sizes and rounds
    shapes = {}
    for r in okA:
        key = (r["len_m1"], r["len_m2"], r["len_m3"], r["len_m4"], r["n_nas_rounds"], r["n_radius_rt"])
        shapes[key] = shapes.get(key, 0) + 1
    L.append("| Sumber | Message1 | Message2 | Message3 | Message4 | Ronde NAS | RADIUS RT | Sesi |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, n in sorted(shapes.items(), key=lambda kv: -kv[1]):
        L.append(f"| full stack v2 | {key[0]} | {key[1]} | {key[2]} | {key[3]} | {key[4]} | {key[5]} | {n} |")
    if h4:
        r = h4[0]
        L.append(f"| harness | {r['msg1_bytes']} | {r['msg2_bytes']} | {r['msg3_bytes']} | {r['msg4_bytes']} | "
                 f"- | {r['radius_round_trips']} | {len(h4)} |")
    L.append("")
    L.append("- Sekarang UE sendiri yang menjawab EAP-Request/Identity, jadi ronde NAS = RADIUS RT "
             "(di bagian 5 ronde Identity tidak lewat NAS).")
    L.append("")

    # recovery
    rec_path = os.path.join(RESULTS, "fullstack-recovery-v2.csv")
    if os.path.exists(rec_path):
        rr = load_rows(rec_path)
        L.append("### Uji pemulihan (v2)")
        L.append("")
        L.append("Relay UPF membuang sekali Message3 atau Message4; SMF timeout (2,5 s) lalu mengirim "
                 "REJECT #29 tanpa EAP (UE tidak fallback). Sesi berikutnya diulang sampai Accept "
                 "dengan EAP-Success (maks. 3).")
        L.append("")
        L.append("| Kasus | N | Drop di UPF | Sesi drop: Reject #29 tanpa EAP | used_next | Sesi pemulihan "
                 "pertama | EAP-Failure | fallback | Sesi sampai pulih (median) | Pulih | msk_match | "
                 "Waktu pulih mean / median (ms) |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        desync = 0
        for case, name in (("msg3", "Message3 dibuang"), ("msg4", "Message4 dibuang")):
            c = [r for r in rr if r["case"] == case]
            if not c:
                continue
            cnt = lambda f: sum(1 for r in c if f(r))
            t = [float(r["t_recovery_ms"]) for r in c if r["t_recovery_ms"]]
            firsts = {}
            for r in c:
                firsts[r["first_recovery_outcome"]] = firsts.get(r["first_recovery_outcome"], 0) + 1
            fo = ", ".join(f"{k} {v}" for k, v in sorted(firsts.items()))
            desync += cnt(lambda r: r["recovered"] != "1")
            L.append(f"| {name} | {len(c)} | {cnt(lambda r: r['drop_upf'] == '1')} | "
                     f"{cnt(lambda r: r['drop_outcome'] == 'noeap')} | {cnt(lambda r: r['used_next'] == '1')} | "
                     f"{fo} | {sum(int(r['eap_failure']) for r in c)} | {sum(int(r['fallback']) for r in c)} | "
                     f"{statistics.median(int(r['sessions_to_recover']) for r in c):.0f} | "
                     f"{cnt(lambda r: r['recovered'] == '1')} | {cnt(lambda r: r['msk_match'] == '1')} | "
                     + (f"{statistics.mean(t):.1f} / {statistics.median(t):.1f}" if t else "-") + " |")
        after = [r for r in rr if r["case"] == "after"]
        desync += sum(1 for r in after if r["recovered"] != "1")
        L.append("")
        L.append(f"- Sesi normal sesudahnya: {sum(1 for r in after if r['recovered'] == '1')}/{len(after)} sukses. "
                 f"Desync: **{desync}**; re-provisioning: **0**.")
        L.append("- `failure` = REJECT #29 berisi EAP-Failure (DN-AAA belum commit, NEXT ditolak), lalu "
                 "fallback ke CUR dan PDU session berikutnya sukses. Waktu pulih Message3 memuat "
                 "`reject_delay = 1` FreeRADIUS.")
        L.append("")

    seq_path = os.path.join(RESULTS, "fullstack-v2-sequence.txt")
    if os.path.exists(seq_path):
        L.append("### Urutan pesan dari capture (`fullstack-v2-sample.pcap`)")
        L.append("")
        L.append("```")
        L.extend(open(seq_path).read().rstrip("\n").split("\n"))
        L.append("```")
        L.append("")

    # against step 17
    old = os.path.join(RESULTS, "fullstack-handshake.csv")
    if os.path.exists(old):
        o = load_rows(old)
        L.append("### Perbandingan dengan step 17 (secondary auth setelah Accept, relay blocking)")
        L.append("")
        L.append("| Metrik (median, ms) | Step 17 | Step 19 |")
        L.append("| --- | --- | --- |")
        pairs = [("PDU session siap (A): `t_ready_ms` / `t_pdu_ms`", vals("A", "t_ready_ms", src=o), vals("A", "t_pdu_ms")),
                 ("Tanpa secondary auth (B): `t_pdu_ms`", vals("B", "t_pdu_ms", src=o), vals("B", "t_pdu_ms")),
                 ("`t_secauth_ms`", vals("A", "t_secauth_ms", src=o), vals("A", "t_secauth_ms")),
                 ("`t_radius_ms`", vals("A", "t_radius_ms", src=o), vals("A", "t_radius_ms")),
                 ("`t_core_ms`", vals("A", "t_core_ms", src=o), vals("A", "t_core_ms")),
                 ("`t_smf_relay_ms`", vals("A", "t_smf_relay_ms", src=o), vals("A", "t_smf_relay_ms"))]
        for name, x, y in pairs:
            if x and y:
                L.append(f"| {name} | {statistics.median(x):.3f} | {statistics.median(y):.3f} |")
        a17, b17 = vals("A", "t_ready_ms", src=o), vals("B", "t_pdu_ms", src=o)
        if a17 and b17 and a and b:
            L.append(f"| Biaya secondary auth (A − B) | {statistics.median(a17) - statistics.median(b17):.3f} | "
                     f"{statistics.median(a) - statistics.median(b):.3f} |")
        L.append("")
        L.append("- Step 17 mengukur sampai Authentication Result setelah Accept (termasuk timer 100 ms "
                 "SMF); step 19 mengukur sampai Accept yang membawa EAP-Success, tanpa timer, dengan "
                 "secondary authentication sebelum PCF/UPF/PFCP.")
        L.append("- `t_radius_ms` dan `t_smf_relay_ms` turun karena socket persisten dan relay SMF "
                 "non-blocking. `t_core_ms` naik: ada satu ronde NAS tambahan (EAP-Request/Identity ke UE, "
                 "di step 17 dibuat SMF sendiri), dan definisi `t_secauth_ms` sekarang berakhir di Accept "
                 "(termasuk PCF/UPF/PFCP), bukan di Authentication Result.")
        L.append("")


def main():
    hs = load_rows(HS_CSV)
    ls = load_rows(LOSS_CSV)
    analysis_text = open(ANALYSIS).read()

    # ---- per-method handshake aggregation (loss 0) ----
    by_m = defaultdict(list)
    for r in hs:
        by_m[int(r["method"])].append(r)

    # ---- per (method, loss) lossy aggregation ----
    by_ml = defaultdict(list)
    for r in ls:
        by_ml[(int(r["method"]), float(r["loss_pct"]))].append(r)

    now = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S")
    L = []
    L.append("# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication (End-to-End)")
    L.append("")
    L.append(f"_Dibuat otomatis oleh benchmark/e2e_analyze.py pada {now}._")
    L.append("")
    L.append("Dokumen ini adalah pasangan **end-to-end** dari `analysis.md`. Setiap angka "
             "diperoleh dari handshake EAP-EDHOC **nyata** yang berjalan di atas transport "
             "EAP-over-RADIUS (RFC 2865/3579) menuju responder FreeRADIUS `rlm_eap_edhoc` "
             "yang hidup di `127.0.0.1:1812`. Tidak ada estimasi/proyeksi: kolom setiap tabel "
             "dibuat **identik** dengan `analysis.md` agar perbedaan tiap method dapat "
             "dibandingkan langsung antara kedua percobaan.")
    L.append("")
    L.append("Setiap method 0..4 diimplementasikan penuh dan interoperable: method 0..3 "
             "(klasik: Ed25519 SIG / static-DH X25519 MAC, core `edhoc03`) dan method 4 "
             "(SIGMA XWING PQC, core `edhoc4`). Method 0..3 memakai 3 pesan (tanpa message_4), "
             "method 4 memakai 4 pesan dengan fragmentasi EAP. Method 5 (EAP-TLS Classic) "
             "menjalankan handshake mutual-TLS **nyata** (RFC 5216) melalui OpenSSL "
             "(`benchmark/eap_tls_bench.c`) melawan `rlm_eap_tls` yang hidup, dengan negosiasi "
             "EAP-Nak dari `edhoc` (default_eap_type) ke tipe TLS (13). Method 6 (EAP-TLS "
             "Hybrid PQC) menjalankan handshake mutual-TLS 1.3 **nyata** juga (grup KEM hybrid "
             "X25519MLKEM768 + sertifikat ML-DSA-44, via `benchmark/eap_tls_hybrid_bench.c` "
             "dan `oqs-provider`) melawan `rlm_eap_tls` yang sama — lihat catatan metodologi "
             "di bawah untuk cara pengukurannya.")
    L.append("")

    # ---- Method matrix (identical to analysis.md, plus methods 5 & 6) ----
    L.append("Method matrix:")
    L.append("")
    L.append("| Method | Initiator | Responder | Profil kripto |")
    L.append("| --- | --- | --- | --- |")
    L.append("| 0 | SIG (Ed25519) | SIG (Ed25519) | Ed25519 |")
    L.append("| 1 | SIG (Ed25519) | MAC (static-DH X25519) | Ed25519 + X25519 |")
    L.append("| 2 | MAC (static-DH X25519) | SIG (Ed25519) | X25519 + Ed25519 |")
    L.append("| 3 | MAC (static-DH X25519) | MAC (static-DH X25519) | X25519 |")
    L.append("| 4 | SIGMA (ML-DSA-44) | SIGMA (ML-DSA-44) | XWING (X25519 + ML-KEM-768) + ML-DSA-44 (PQC) |")
    L.append("| 5 | EAP-TLS Classic (mutual, Ed25519) | EAP-TLS Classic (mutual, Ed25519) | X25519 ECDHE + Ed25519 (classical TLS) |")
    L.append("| 6 | EAP-TLS Hybrid PQC (mutual, ML-DSA-44) | EAP-TLS Hybrid PQC (mutual, ML-DSA-44) | X25519MLKEM768 hybrid KEM + ML-DSA-44 (PQC) |")
    L.append("")
    L.append("> **Catatan metodologi — bagaimana method 5 dan method 6 diukur:** Method "
             "**0-6 seluruhnya** diukur end-to-end secara **live** di atas EAP-over-RADIUS "
             "nyata terhadap `rlm_eap_tls`/`rlm_eap_edhoc` yang hidup. Method 5 memakai "
             "sertifikat **Ed25519** (bukan RSA-2048) supaya perbandingan dengan EDHOC klasik "
             "(method 0-3, yang semuanya Ed25519 + X25519) apples-to-apples: algoritma tanda "
             "tangan dan grup DH-nya identik, sehingga selisih yang tersisa murni berasal dari "
             "framing protokol (TLS record + X.509 vs CBOR EDHOC) dan transport (fragmentasi "
             "EAP RFC 5216 vs EDHOC-over-EAP), bukan dari pilihan algoritma kripto. (Sertifikat "
             "RSA-2048 asli masih tersimpan di `raddb/certs/rsa2048-backup/` kalau diperlukan "
             "sebagai referensi.) Method 5 (klasik, Ed25519) dan method 6 (hybrid-PQC, "
             "ML-DSA-44 + grup KEM X25519MLKEM768) memakai "
             "`rlm_eap_tls` yang SAMA, tetapi satu instance `tls {}` hanya bisa memegang satu "
             "pasangan sertifikat/grup pada satu waktu — jadi keduanya diukur **berurutan, "
             "bukan bersamaan**: `benchmark/switch_tls_config.sh classic|hybrid` menukar "
             "`tls-config` yang dipakai lalu me-restart radiusd (untuk method 6, ditambah "
             "variabel lingkungan `OPENSSL_CONF`/`OPENSSL_MODULES` yang mengaktifkan "
             "`oqs-provider`, lihat `pqc-tls/openssl-hybrid.cnf`). Method 6 memerlukan OpenSSL "
             ">= 3.2 untuk sertifikat/tanda tangan ML-DSA-44 di TLS1.3 (`oqs-provider` belum "
             "mendukung ini di versi OpenSSL yang lebih lama); lingkungan ini memakai OpenSSL "
             "3.0.13 secara default, sehingga sebuah build OpenSSL 3.2.6 privat "
             "(`pqc-tls/openssl32/`) dipakai lewat `LD_LIBRARY_PATH` khusus untuk radiusd dan "
             "harness method 6 saja — `rlm_eap_tls`/radiusd sendiri tidak diubah kodenya untuk "
             "ini (hanya linking runtime-nya), kecuali satu pengecekan versi OpenSSL di "
             "`src/main/version.c` yang direlaksasi agar tidak menolak kombinasi minor-version "
             "3.0/3.2 ini (OpenSSL menjamin stabilitas ABI/API di seluruh seri 3.x). Setiap "
             "handshake method 6 diverifikasi (bukan cuma diasumsikan) benar-benar memakai grup "
             "`X25519MLKEM768` dan sertifikat `mldsa44` lewat `SSL_get0_group_name()`/"
             "`EVP_PKEY_get0_type_name()` — kalau sampai jatuh diam-diam ke classical, harness "
             "menandainya FAIL, bukan PASS.")
    L.append("")

    # ---- 1c. Handshake end-to-end per method (identical column set to analysis.md 1c) ----
    L.append("## 1c. Handshake secondary authentication P2P (end-to-end EAP-over-RADIUS)")
    L.append("")
    n_iter = len(by_m[0]) if by_m else 0
    L.append(f"Jalur live EAP-over-RADIUS (harness UE initiator -> FreeRADIUS `rlm_eap_edhoc` "
             f"untuk method 0..4, `rlm_eap_tls` untuk method 5 dan 6). {n_iter} iterasi per "
             f"method, tanpa loss (gabungan semua run di `e2e-handshake.csv`, kolom `label`; "
             f"tiap run didahului 20 handshake pemanasan yang dibuang). Method 5 dan 6 diukur "
             f"berurutan (lihat catatan metodologi di atas), tetapi keduanya live.")
    L.append("")
    L.append("Baris perwakilan (satu handshake sukses per method), kolom identik dengan "
             "`analysis.md` bagian 1c (`duration_ms` menggantikan `duration_sec`; nilai adalah "
             "durasi pertukaran EAP-EDHOC saja, bukan seluruh registrasi 5G):")
    L.append("")
    L.append("| Method | timestamp | iteration | status | duration_ms | pdu_success_count |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for m in sorted(by_m):
        rows = by_m[m]
        sample = next((r for r in rows if r["status"] == "PASS"), rows[0])
        L.append(f"| {m} | {sample['timestamp']} | {sample['iteration']} | "
                 f"{sample['status']} | {sample['duration_ms']} | 1 |")
    L.append("")
    L.append("### Ringkasan statistik handshake end-to-end per method")
    L.append("")
    L.append("| Method | Profil | Iterasi | Sukses % | Mean (ms) | Median (ms) | p95 (ms) | Min (ms) | Max (ms) | RADIUS round-trips | EAP round-trips |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for m in sorted(by_m):
        rows = by_m[m]
        durs = [float(r["duration_ms"]) for r in rows if r["status"] == "PASS"]
        npass = len(durs)
        rt = int(rows[0]["radius_round_trips"])
        ert = int(rows[0]["eap_round_trips"])
        L.append(f"| {m} | {METHOD_NAMES[m]} | {len(rows)} | "
                 f"{100.0*npass/len(rows):.1f} | {statistics.mean(durs):.3f} | "
                 f"{statistics.median(durs):.3f} | {pct(durs,95):.3f} | {min(durs):.3f} | "
                 f"{max(durs):.3f} | {rt} | {ert} |")
    L.append("")
    cheapest = min(by_m, key=lambda m: statistics.mean([float(r["duration_ms"]) for r in by_m[m] if r["status"]=="PASS"]))
    dearest = max(by_m, key=lambda m: statistics.mean([float(r["duration_ms"]) for r in by_m[m] if r["status"]=="PASS"]))
    L.append(f"- Handshake end-to-end tercepat: **method {cheapest}** ({METHOD_NAMES[cheapest]}).")
    L.append(f"- Handshake end-to-end terlambat: **method {dearest}** ({METHOD_NAMES[dearest]}), "
             f"karena fragmentasi EAP membutuhkan {int(by_m[dearest][0]['radius_round_trips'])} "
             f"round-trip RADIUS dibanding {int(by_m[cheapest][0]['radius_round_trips'])} untuk method klasik.")
    L.append("")

    # ---- 1c-2. Initiator vs responder wall-clock split (live, real) ----
    L.append("### Pembagian beban initiator vs responder (live, wall-clock nyata)")
    L.append("")
    L.append("Setiap harness (UE/initiator) mengukur, per round-trip RADIUS, waktu yang "
             "dihabiskan **menunggu balasan** (`send()` sampai `recv()` kembali) secara "
             "terpisah dari waktu yang dihabiskan **mengerjakan sendiri** (membangun paket "
             "RADIUS/EAP, HMAC-MD5 Message-Authenticator, dan menjalankan engine "
             "EDHOC/TLS-nya sendiri) di antara round-trip. `responder_ms` = total waktu "
             "menunggu (mendominasi oleh pemrosesan penuh di sisi FreeRADIUS — parsing, "
             "dispatch modul, kripto, serialisasi balasan — karena transit jaringan nyata "
             "di loopback nyaris nol); `initiator_ms` = `duration_ms` dikurangi itu, murni "
             "kerja lokal UE. Ini pengukuran **live nyata** per handshake, bukan model — "
             "berbeda dari section 1b yang cuma menghitung compute kripto murni tanpa "
             "overhead RADIUS/TLS-framing sama sekali.")
    L.append("")
    L.append("| Method | Profil | Initiator mean (ms) | Responder mean (ms) | Initiator % | Responder % | Total mean (ms) |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for m in sorted(by_m):
        rows = [r for r in by_m[m] if r["status"] == "PASS"]
        ini = statistics.mean([float(r["initiator_ms"]) for r in rows])
        res = statistics.mean([float(r["responder_ms"]) for r in rows])
        tot = ini + res
        L.append(f"| {m} | {METHOD_NAMES[m]} | {ini:.3f} | {res:.3f} | "
                 f"{100.0*ini/tot:.1f}% | {100.0*res/tot:.1f}% | {tot:.3f} |")
    L.append("")
    heaviest_responder_pct = max(
        by_m, key=lambda m: statistics.mean([float(r["responder_ms"]) for r in by_m[m] if r["status"] == "PASS"])
        / statistics.mean([float(r["duration_ms"]) for r in by_m[m] if r["status"] == "PASS"]))
    L.append(f"- Di semua method, beban **responder** (AAA/FreeRADIUS) mendominasi total "
             f"waktu handshake — wajar, karena responder-lah yang benar-benar memproses "
             f"paket RADIUS (parsing, dispatch modul, verifikasi kripto) dan initiator "
             f"cuma menunggu selama itu; porsi initiator yang genuinely CPU-bound (encode "
             f"paket + panggilan engine lokal) jauh lebih kecil dari total.")
    L.append(f"- Proporsi responder tertinggi: **method {heaviest_responder_pct}** "
             f"({METHOD_NAMES[heaviest_responder_pct]}).")
    L.append("")

    # ---- 1c-3. High-N statistical stability check for methods 0..3 ----
    stab_path = os.path.join(RESULTS, "stability-0-3.csv")
    if os.path.exists(stab_path):
        stab_rows = load_rows(stab_path)
        L.append("### Uji stabilitas statistik method 0-3 (N=10000/method, bootstrap CI)")
        L.append("")
        L.append("Sweep utama di atas cuma 100-200 iterasi/method — cukup untuk method 4-6 "
                 "(beda RADIUS round-trip yang besar, jelas dominan), tapi TIDAK cukup "
                 "untuk membedakan method 0-3 (semua sama-sama 3 round-trip, beda compute "
                 "cuma puluhan µs) secara meyakinkan: urutan mereka terbukti berubah-ubah "
                 "antar rerun benchmark ini.")
        L.append("")
        L.append("> **Bug pengukuran ditemukan dan diperbaiki selama investigasi ini:** "
                 "percobaan pertama (`radiusd -X`, mode debug penuh) menunjukkan 14-63 "
                 "outlier ekstrem (~2000ms) per method dari 5000 sampel. Root cause: logging "
                 "`-X` yang sangat verbose (setiap atribut/cabang policy dicetak per request) "
                 "membuat `radiusd` sesekali tertinggal memproses di bawah beban tinggi, "
                 "menyebabkan delay paket UDP nyata — yang lalu diperbesar jadi stall ~2 detik "
                 "oleh socket timeout harness (`SO_RCVTIMEO=2s`). Dikonfirmasi lewat A/B test: "
                 "sweep identik dengan `radiusd -f` (foreground tanpa debug, lihat "
                 "`switch_tls_config.sh`) menghasilkan **nol** outlier semacam itu dari 20000 "
                 "sampel gabungan (maksimum ~23ms). Seluruh data live di dokumen ini (termasuk "
                 "sweep utama 100/720-iterasi di atas) sekarang dikumpulkan dengan `radiusd -f`. "
                 "Efek order kedua yang lebih kecil (median bergeser ±20µs dan sebagian urutan "
                 "terbalik antar rerun dengan urutan method dibalik) masih ada meski `-X` sudah "
                 "dimatikan — untuk mengontrolnya, data di bawah menggabungkan **dua run 5000 "
                 "iterasi/method dengan urutan berlawanan** (0,1,2,3 lalu 3,2,1,0), sehingga tiap "
                 "method dapat eksposur seimbang terhadap efek posisi \"jalan duluan\" vs "
                 "\"belakangan\" — N=10000/method setelah digabung.")
        L.append("")
        L.append("| Method | Profil | N | Mean (ms) | Median (ms) | Trimmed mean (ms) | Stddev (ms) | Outlier >5ms | Median 95% CI (ms) |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in sorted(stab_rows, key=lambda r: int(r["method"])):
            L.append(f"| {r['method']} | {r['profile']} | {r['n']} | {float(r['mean_ms']):.3f} | "
                     f"{float(r['median_ms']):.3f} | {float(r['trimmed_mean_ms']):.3f} | "
                     f"{float(r['stddev_ms']):.3f} | {r['outliers_gt_5ms']} | "
                     f"[{float(r['median_ci95_low_ms']):.4f}, {float(r['median_ci95_high_ms']):.4f}] |")
        L.append("")
        by_med = sorted(stab_rows, key=lambda r: float(r["median_ms"]))
        order_str = " < ".join(f"method {r['method']} ({float(r['median_ms']):.3f} ms)" for r in by_med)
        L.append(f"- Urutan median (N=10000, dua arah digabung): **{order_str}**.")
        ci = {int(r["method"]): (float(r["median_ci95_low_ms"]), float(r["median_ci95_high_ms"]))
              for r in stab_rows}
        pairs = [(a, b) for a in sorted(ci) for b in sorted(ci) if a < b]
        overlap = [f"method {a} vs {b}" for a, b in pairs if ci[a][0] <= ci[b][1] and ci[b][0] <= ci[a][1]]
        separate = [f"method {a} vs {b}" for a, b in pairs if not (ci[a][0] <= ci[b][1] and ci[b][0] <= ci[a][1])]
        L.append("- Pasangan yang CI-nya **overlap** (bedanya tidak signifikan secara statistik): "
                 + (", ".join(overlap) if overlap else "tidak ada") + ". Terpisah signifikan: "
                 + (", ".join(separate) if separate else "tidak ada") + ".")
        spread_us = (float(by_med[-1]["median_ms"]) - float(by_med[0]["median_ms"])) * 1000
        L.append(f"- **Kesimpulan jujur:** setelah bug `-X` diperbaiki dan efek urutan dikontrol, "
                 f"selisih median tercepat-terlambat method 0-3 hanya **{spread_us:.0f} µs**. "
                 "Urutannya TIDAK mengikuti urutan compute-only section 1b secara konsisten antar "
                 "rerun. Sudah dicek ke kode `rlm_eap_edhoc.c`: kredensial dimuat sekali saat "
                 "startup (bukan per-request, tidak ada I/O per-request), jadi hipotesis "
                 "\"lookup kredensial\" **terbukti salah**. Kode `edhoc03.c` punya 1 panggilan "
                 "HKDF-Extract tambahan untuk static-DH (~1.4µs, tidak masuk hitungan section 1b), "
                 "terlalu kecil untuk menjelaskan selisih yang teramati.")
        L.append("")
        L.append("> **Verifikasi lapis terakhir — `strace -f -c` langsung ke proses `radiusd` "
                 "hidup** (1500 handshake method 0 vs 1500 handshake method 3, masing-masing "
                 "di-trace terpisah): profil syscall-nya **identik** — sendmsg/recvfrom/"
                 "recvmsg/getsockname sama-sama persis 4500 kali (3/handshake, cocok RADIUS "
                 "round-trip), tidak ada satu pun syscall tambahan yang membedakan method 0 "
                 "dari method 3 (tidak ada file I/O ekstra, tidak ada alokasi berbeda). Yang "
                 "mendominasi waktu trace di **kedua** method secara setara: `futex` (85.79% "
                 "method 0, 85.40% method 3) — itu overhead sinkronisasi thread-pool internal "
                 "FreeRADIUS (worker thread bangun/tidur lewat mutex/condition-variable tiap "
                 "request masuk, karena harness mengirim request satu-satu/sekuensial), sama "
                 "sekali bukan bagian dari logika EDHOC. **Kesimpulan final: method 3 TIDAK "
                 "seharusnya jauh lebih cepat dari method 0** — biaya kripto EDHOC (ratusan "
                 "nanodetik/operasi) memang microscopic dibanding overhead scheduling "
                 "thread-pool FreeRADIUS (puluhan-ratusan µs/request) yang besarnya SAMA untuk "
                 "semua method karena bukan bagian dari protokol sama sekali. Selisih puluhan µs "
                 "yang tersisa antar method 0-3 kemungkinan besar cuma variasi acak "
                 "dalam overhead futex/scheduling itu sendiri, bukan efek desain protokol.")
        L.append("")

    # ---- 1c-4. Storage ablation for method 4: durable disk vs tmpfs ----
    stor_path = os.path.join(RESULTS, "e2e-storage-ablation.csv")
    if os.path.exists(stor_path):
        L.append("### Ablation biaya penyimpanan kunci method 4 (durable vs tmpfs)")
        L.append("")
        L.append("`benchmark/storage_ablation.sh`: direktori kunci (`/usr/local/etc/edhoc`: `edhoc_db/` "
                 "DN-AAA dan `ue/` UE) di disk VM (durable) dan di tmpfs, tempat `fdatasync` praktis "
                 "gratis, dalam ronde bergantian (record di-provision ulang dan radiusd di-restart tiap "
                 "ronde, 20 handshake pemanasan dibuang). Selisih median durable - tmpfs adalah biaya "
                 "penyimpanan yang terukur; bootstrap 95% CI (4000 resample, seed 1).")
        L.append("")
        L.append("| Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) | Responder mean (ms) | UE commit mean (ms, di luar handshake) |")
        L.append("| --- | --- | --- | --- | --- | --- | --- |")
        sr = {}
        for r in load_rows(stor_path):
            if r["status"] == "PASS":
                sr.setdefault(r["label"], []).append(r)
        for lab in ["durable", "tmpfs"]:
            ok = sr.get(lab, [])
            if not ok:
                continue
            d = [float(r["duration_ms"]) for r in ok]
            L.append(f"| {lab} | {len(ok)} | {statistics.mean(d):.3f} | {statistics.median(d):.3f} | "
                     f"{pct(d, 95):.3f} | {statistics.mean(float(r['responder_ms']) for r in ok):.3f} | "
                     f"{statistics.mean(float(r.get('ue_commit_ms') or 0) for r in ok):.3f} |")
        if sr.get("durable") and sr.get("tmpfs"):
            a_ = [float(r["duration_ms"]) for r in sr["durable"]]
            b_ = [float(r["duration_ms"]) for r in sr["tmpfs"]]
            rng = random.Random(1)
            bs = sorted(statistics.median(rng.choices(a_, k=len(a_))) -
                        statistics.median(rng.choices(b_, k=len(b_))) for _ in range(4000))
            L.append("")
            L.append(f"- Biaya penyimpanan (selisih median durable - tmpfs): "
                     f"**{statistics.median(a_) - statistics.median(b_):.3f} ms**, 95% CI "
                     f"[{bs[100]:.3f}, {bs[3899]:.3f}] ms.")
        L.append("- Penyimpanan (protokol v3): record dua-slot praalokasi (`rec.bin` DN-AAA, "
                 "`ue.rec` UE). Di jalur kritis ada dua `fdatasync`: UE menulis slot NEXT sebelum "
                 "Message3 dan DN-AAA menulis record baru sebelum Message4 (write-ahead). Di luar "
                 "jalur kritis ada dua lagi: DN-AAA menolkan slot dengan sk_B lama setelah Message4 "
                 "(worker thread) dan UE menolkan sk_A lama saat promosi setelah Message4 (kolom "
                 "`ue_commit_ms`). Waktu per panggilan: `storage-strace.txt` (`strace -c -w`, "
                 "wall-clock, termasuk overhead tracing).")
        L.append("")

    # ---- 1c-4b. Per-flush split: UE / DN-AAA on tmpfs separately ----
    flush_path = os.path.join(RESULTS, "e2e-storage-flush.csv")
    if os.path.exists(flush_path):
        fl = {}
        for r in load_rows(flush_path):
            if r["status"] == "PASS":
                fl.setdefault(r["label"], []).append(float(r["duration_ms"]))
        ntot = {}
        for r in load_rows(flush_path):
            ntot[r["label"]] = ntot.get(r["label"], 0) + 1
        rng = random.Random(1)
        def boot_med(a):
            bs = sorted(statistics.median(rng.choices(a, k=len(a))) for _ in range(4000))
            return bs[100], bs[3899]
        def boot_diff(a, b):
            bs = sorted(statistics.median(rng.choices(a, k=len(a))) -
                        statistics.median(rng.choices(b, k=len(b))) for _ in range(4000))
            return statistics.median(a) - statistics.median(b), bs[100], bs[3899]
        L.append("### Biaya per flush di jalur kritis (UE dan DN-AAA dipisah)")
        L.append("")
        L.append("`benchmark/storage_ablation.sh R 100 flush`: empat konfigurasi dalam satu sesi VM, "
                 "urutan dirotasi tiap ronde, record di-provision ulang dan radiusd di-restart tiap "
                 "run, 20 handshake pemanasan dibuang. `ue_tmpfs` = direktori UE (`ue/`) di tmpfs, "
                 "DN-AAA (`edhoc_db/`) di disk, sehingga yang tersisa hanya flush commit DN-AAA "
                 "sebelum Message4; `dn_tmpfs` = kebalikannya, yang tersisa hanya flush NEXT UE "
                 "sebelum Message3. Median dengan bootstrap 95% CI (4000 resample, seed 1). Seri "
                 "ini terpisah dari tabel durable/tmpfs di atas (yang dipakai untuk angka 1.161 ms "
                 "dan tabel transport).")
        L.append("")
        L.append("| Konfigurasi | UE | DN-AAA | N (PASS/total) | Mean (ms) | Median (ms) | 95% CI median (ms) |")
        L.append("| --- | --- | --- | --- | --- | --- | --- |")
        where = {"durable": ("disk", "disk"), "tmpfs": ("tmpfs", "tmpfs"),
                 "ue_tmpfs": ("tmpfs", "disk"), "dn_tmpfs": ("disk", "tmpfs")}
        for lab in ("durable", "ue_tmpfs", "dn_tmpfs", "tmpfs"):
            d = fl.get(lab, [])
            if not d:
                continue
            lo, hi = boot_med(d)
            L.append(f"| {lab} | {where[lab][0]} | {where[lab][1]} | {len(d)}/{ntot[lab]} | "
                     f"{statistics.mean(d):.3f} | {statistics.median(d):.3f} | [{lo:.3f}, {hi:.3f}] |")
        L.append("")
        if all(fl.get(k) for k in ("durable", "tmpfs", "ue_tmpfs", "dn_tmpfs")):
            rows_ = [
                ("Flush UE (NEXT sebelum Message3)", "durable - ue_tmpfs", fl["durable"], fl["ue_tmpfs"]),
                ("Flush UE, tanpa flush DN-AAA", "dn_tmpfs - tmpfs", fl["dn_tmpfs"], fl["tmpfs"]),
                ("Flush DN-AAA (commit sebelum Message4)", "durable - dn_tmpfs", fl["durable"], fl["dn_tmpfs"]),
                ("Flush DN-AAA, tanpa flush UE", "ue_tmpfs - tmpfs", fl["ue_tmpfs"], fl["tmpfs"]),
                ("Kedua flush", "durable - tmpfs", fl["durable"], fl["tmpfs"]),
            ]
            L.append("| Biaya | Selisih median | Nilai (ms) | 95% CI (ms) |")
            L.append("| --- | --- | --- | --- |")
            for name, expr, a_, b_ in rows_:
                v, lo, hi = boot_diff(a_, b_)
                L.append(f"| {name} | {expr} | {v:.3f} | [{lo:.3f}, {hi:.3f}] |")
            L.append("")
            med = {k: statistics.median(v) for k, v in fl.items()}
            alone = (med["dn_tmpfs"] - med["tmpfs"]) + (med["ue_tmpfs"] - med["tmpfs"])
            both_ = med["durable"] - med["tmpfs"]
            L.append("- Tiap flush diukur dua kali (dengan dan tanpa flush pihak lain). Satu flush "
                     f"saja: UE {med['dn_tmpfs'] - med['tmpfs']:.3f} ms, DN-AAA "
                     f"{med['ue_tmpfs'] - med['tmpfs']:.3f} ms (jumlah {alone:.3f} ms); kedua flush "
                     f"bersama: {both_:.3f} ms. Biayanya "
                     f"{'tidak aditif: flush kedua menambah lebih sedikit dari flush pertama (UE dan DN-AAA di disk VM yang sama)' if alone - both_ > 0.1 else 'kira-kira aditif'}.")
            L.append(f"- Selisih durable - tmpfs pada seri ini ({both_:.3f} ms) berbeda dari seri "
                     "dua-konfigurasi di atas karena diukur di sesi VM lain; perbandingan per flush "
                     "hanya memakai seri ini.")
            L.append("")

    # ---- 1c-5. Method 4: precomputed rotation key / X-Wing per spec ----
    inproc_path = os.path.join(RESULTS, "m4-inprocess-compute.csv")
    pool_path = os.path.join(RESULTS, "e2e-pool-ablation.csv")
    if os.path.exists(inproc_path):
        L.append("### Komputasi method 4 in-process: sebelum vs sesudah (X-Wing standar, kunci rotasi precompute)")
        L.append("")
        L.append("`benchmark/m4_inproc_compare.sh`: handshake method 4 tanpa transport dan tanpa "
                 "penyimpanan, waktu pemrosesan pesan per pihak, beberapa ronde diselang-seling. "
                 "`before` = core edhoc4 sebelum perubahan X-Wing (combiner SHA-256 non-standar, "
                 "decapsulation menghitung ulang pk_X); `inline_rotation_keygen` = core saat ini "
                 "(X-Wing sesuai draft-connolly-cfrg-xwing-kem-09), kunci rotasi dibuat di dalam "
                 "handshake: **default dan angka utama**; `precomputed_rotation` = core saat ini "
                 "dengan pool opsional (kunci rotasi dibuat di luar handshake, ablation). "
                 "Nilai = rata-rata dari mean/median tiap ronde.")
        L.append("")
        L.append("| Varian | Ronde | N/ronde | Initiator mean (us) | Initiator median (us) | Responder mean (us) | Responder median (us) | Total mean (us) |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        groups = {}
        for r in load_rows(inproc_path):
            groups.setdefault(r["label"], []).append(r)
        cols = ["initiator_mean_us", "initiator_median_us", "responder_mean_us",
                "responder_median_us", "total_mean_us"]
        tot = {}
        for lab in ["before", "inline_rotation_keygen", "precomputed_rotation"]:
            g = groups.get(lab, [])
            if not g:
                continue
            vals = [statistics.mean(float(r[c]) for r in g) for c in cols]
            tot[lab] = vals[-1]
            L.append(f"| {lab} | {len(g)} | {g[0]['iters']} | " + " | ".join(f"{v:.1f}" for v in vals) + " |")
        L.append("")
        if "before" in tot and "inline_rotation_keygen" in tot:
            L.append(f"- Default (rotasi inline): {tot['inline_rotation_keygen']:.1f} us, "
                     f"{tot['before'] - tot['inline_rotation_keygen']:.1f} us lebih rendah dari `before` "
                     "berkat perubahan X-Wing (terutama decapsulation tanpa hitung ulang pk_X).")
            if "precomputed_rotation" in tot:
                L.append(f"- Pool opsional: {tot['precomputed_rotation']:.1f} us, "
                         f"{tot['inline_rotation_keygen'] - tot['precomputed_rotation']:.1f} us lebih rendah "
                         "dari default karena kunci rotasi dibuat di luar handshake.")
            L.append("- Angka in-process lebih besar dari model primitif (`handshake-compute.csv`) karena "
                     "mencakup HKDF, AEAD, hash transcript, dan serialisasi.")
            L.append("")
    if os.path.exists(pool_path):
        L.append("### Ablation live: kunci rotasi precompute (pool) vs dibuat di dalam handshake")
        L.append("")
        L.append("`benchmark/pool_ablation.sh`: method 4 loss-free, ronde bergantian `pool_on` / "
                 "`pool_off` (UE dan DN-AAA sama-sama), radiusd di-restart tiap ronde, 20 handshake "
                 "pemanasan dibuang. Selisih median dengan bootstrap 95% CI (4000 resample, seed 1).")
        L.append("")
        pr = {}
        for r in load_rows(pool_path):
            if r["status"] == "PASS":
                pr.setdefault(r["label"], []).append(float(r["duration_ms"]))
        L.append("| Konfigurasi | N | Mean (ms) | Median (ms) | p95 (ms) |")
        L.append("| --- | --- | --- | --- | --- |")
        for lab in ["pool_on", "pool_off"]:
            d = pr.get(lab, [])
            if d:
                L.append(f"| {lab} | {len(d)} | {statistics.mean(d):.3f} | {statistics.median(d):.3f} | {pct(d, 95):.3f} |")
        if pr.get("pool_on") and pr.get("pool_off"):
            rng = random.Random(1)
            a_, b_ = pr["pool_off"], pr["pool_on"]
            bs = sorted(statistics.median(rng.choices(a_, k=len(a_))) -
                        statistics.median(rng.choices(b_, k=len(b_))) for _ in range(4000))
            L.append("")
            L.append(f"- Selisih median (off - on): **{statistics.median(a_) - statistics.median(b_):.3f} ms**, "
                     f"95% CI [{bs[100]:.3f}, {bs[3899]:.3f}] ms. Biaya yang dipindah keluar handshake "
                     "kira-kira dua kali X-Wing KeyGen (UE dan DN-AAA); di VM ini besarnya setara "
                     "dengan noise run-ke-run.")
        L.append("")

    # ---- 1c-6. Transport cost per RADIUS round-trip, hybrid pair ----
    comp_path = os.path.join(RESULTS, "handshake-compute.csv")
    if os.path.exists(comp_path) and os.path.exists(stor_path):
        comp = {int(r["method"]): float(r["total_compute_us"]) / 1000 for r in load_rows(comp_path)}
        sd = {}
        for r in load_rows(stor_path):
            if r["status"] == "PASS":
                sd.setdefault(r["label"], []).append(float(r["duration_ms"]))
        storage = (statistics.median(sd["durable"]) - statistics.median(sd["tmpfs"])
                   if sd.get("durable") and sd.get("tmpfs") else 0.0)
        L.append("### Biaya transport per RADIUS round-trip (pasangan hybrid)")
        L.append("")
        L.append("(E2E mean - komputasi model - biaya penyimpanan) / n_RT. Penyimpanan = selisih "
                 "median durable - tmpfs (hanya method 4; EAP-TLS tidak menyimpan kunci).")
        L.append("")
        L.append("| Method | E2E mean (ms) | Komputasi (ms) | Penyimpanan (ms) | n_RT | Per round-trip (ms) |")
        L.append("| --- | --- | --- | --- | --- | --- |")
        for m in (4, 6):
            ok = [r for r in by_m.get(m, []) if r["status"] == "PASS"]
            if not ok or m not in comp:
                continue
            e2e = statistics.mean(float(r["duration_ms"]) for r in ok)
            st_ = storage if m == 4 else 0.0
            n_rt = int(ok[0]["radius_round_trips"])
            L.append(f"| {m} | {e2e:.3f} | {comp[m]:.3f} | {st_:.3f} | {n_rt} | {(e2e - comp[m] - st_) / n_rt:.3f} |")
        L.append("")

    # ---- 1c-7. Recovery test (method 4, protocol v3) ----
    rec_path = os.path.join(RESULTS, "e2e-recovery.csv")
    if os.path.exists(rec_path):
        rr = load_rows(rec_path)
        lossy_ = [r for r in rr if r["label"] == "recovery-loss20"]
        after = [r for r in rr if r["label"] == "recovery-after"]
        def cnt(rows, f):
            return sum(1 for r in rows if f(r))
        L.append("### Uji pemulihan method 4 (protokol v3, tanpa grace key)")
        L.append("")
        L.append("150 handshake pada loss 20% lalu 30 handshake tanpa loss, tanpa re-provisioning. "
                 "`used_next` = run dimulai di slot NEXT (sesi sebelumnya berhenti setelah UE menulis "
                 "NEXT); tanpa fallback berarti DN-AAA sudah commit (Message4 / EAP-Success hilang) "
                 "dan sesi ini memulihkannya; dengan fallback berarti Message3 tidak sampai, NEXT "
                 "ditolak, dan UE mengulang dengan CUR.")
        L.append("")
        L.append("| Seri | N | PASS | used_next | pulih tanpa fallback (Message4 hilang) | fallback (Message3 hilang) | gagal |")
        L.append("| --- | --- | --- | --- | --- | --- | --- |")
        for name, rows in (("loss 20%", lossy_), ("setelahnya, loss 0%", after)):
            L.append(f"| {name} | {len(rows)} | {cnt(rows, lambda r: r['status'] == 'PASS')} | "
                     f"{cnt(rows, lambda r: r.get('used_next') == '1')} | "
                     f"{cnt(rows, lambda r: r.get('used_next') == '1' and r.get('fallback') == '0' and r['status'] == 'PASS')} | "
                     f"{cnt(rows, lambda r: r.get('fallback') == '1')} | "
                     f"{cnt(rows, lambda r: r['status'] != 'PASS')} |")
        L.append("")
        desync = cnt(after, lambda r: r["status"] != "PASS")
        L.append(f"- Desync: **{desync}** (run tanpa loss yang gagal setelah seri lossy); "
                 "re-provisioning: **0** (seri tidak pernah menulis ulang kunci).")
        L.append("- Run yang gagal pada loss 20% adalah run yang kehabisan retransmisi; sesi "
                 "berikutnya memulihkan state lewat NEXT atau fallback.")
        L.append("")

    # ---- 1c-7b. Forced message_3 / message_4 loss (method 4, protocol v3) ----
    frc_path = os.path.join(RESULTS, "e2e-recovery-forced.csv")
    if os.path.exists(frc_path):
        fr = load_rows(frc_path)
        def cnt(rows, f):
            return sum(1 for r in rows if f(r))
        L.append("### Uji pemulihan dengan loss paksa (Message3 / Message4 di-drop)")
        L.append("")
        L.append("`benchmark/recovery_forced.sh`: provisioning sekali di awal, lalu tiap kasus "
                 "berulang kali: satu sesi dengan loss deterministik (`e2e_radius_bench "
                 "--drop-msg3-once` / `--drop-msg4-once`, semua salinan pesan itu hilang; status "
                 "DROP) diikuti satu sesi normal (sesi pemulihan), tanpa loss lain dan tanpa "
                 "re-provisioning. Di akhir 10 sesi normal untuk cek desync. `EAP-Failure` = "
                 "Access-Reject pada percobaan pertama sesi pemulihan.")
        L.append("")
        L.append("| Kasus | N | Sesi drop | Pemulihan PASS | used_next | EAP-Failure | fallback | "
                 "Mean pemulihan (ms) | Median pemulihan (ms) | RADIUS RT (median) |")
        L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        fails = 0
        for lab, name in (("drop_msg3", "Message3 di-drop (tidak sampai ke DN-AAA)"),
                          ("drop_msg4", "Message4 di-drop (DN-AAA sudah commit)"),
                          ("drop_msg3_rd0", "Message3 di-drop, `reject_delay = 0`")):
            drops = [r for r in fr if r["label"] == lab and r["iteration"] == "1"]
            recs = [r for r in fr if r["label"] == lab and r["iteration"] == "2"]
            if not recs:
                continue
            ok = [r for r in recs if r["status"] == "PASS"]
            fails += len(recs) - len(ok)
            d = [float(r["duration_ms"]) for r in ok] or [0.0]
            L.append(f"| {name} | {len(recs)} | {cnt(drops, lambda r: r['status'] == 'DROP')} | "
                     f"{len(ok)} | {cnt(recs, lambda r: r['used_next'] == '1')} | "
                     f"{cnt(recs, lambda r: int(r['access_reject']) > 0)} | "
                     f"{cnt(recs, lambda r: r['fallback'] == '1')} | "
                     f"{statistics.mean(d):.3f} | {statistics.median(d):.3f} | "
                     f"{statistics.median(int(r['radius_round_trips']) for r in recs):.0f} |")
        after = [r for r in fr if r["label"] == "after"]
        if after:
            d = [float(r["duration_ms"]) for r in after if r["status"] == "PASS"] or [0.0]
            L.append(f"| Setelahnya, sesi normal | {len(after)} | 0 | "
                     f"{cnt(after, lambda r: r['status'] == 'PASS')} | "
                     f"{cnt(after, lambda r: r['used_next'] == '1')} | "
                     f"{cnt(after, lambda r: int(r['access_reject']) > 0)} | "
                     f"{cnt(after, lambda r: r['fallback'] == '1')} | "
                     f"{statistics.mean(d):.3f} | {statistics.median(d):.3f} | "
                     f"{statistics.median(int(r['radius_round_trips']) for r in after):.0f} |")
        L.append("")
        desync = fails + cnt(after, lambda r: r["status"] != "PASS")
        L.append(f"- Desync: **{desync}** (sesi pemulihan atau sesi sesudahnya yang gagal); "
                 "re-provisioning: **0** (record hanya di-provision sekali sebelum kasus pertama).")
        L.append("- Message3 di-drop: sesi pemulihan mulai di NEXT, DN-AAA (belum commit) menolak "
                 "Message1 dengan EAP-Failure, UE mengulang dengan CUR dan menyimpan NEXT baru; "
                 "waktunya mencakup kedua percobaan. Message4 di-drop: DN-AAA sudah commit, jadi "
                 "sesi di NEXT langsung sukses tanpa fallback.")
        rd = {lab: [float(r["duration_ms"]) for r in fr if r["label"] == lab
                    and r["iteration"] == "2" and r["status"] == "PASS"]
              for lab in ("drop_msg3", "drop_msg3_rd0")}
        if rd["drop_msg3"] and rd["drop_msg3_rd0"]:
            L.append(f"- Waktu pemulihan Message3 di-drop didominasi `reject_delay = 1` FreeRADIUS "
                     f"(default; setiap Access-Reject ditahan 1 s, kebijakan server, bukan protokol): "
                     f"median {statistics.median(rd['drop_msg3']):.3f} ms. Dengan `reject_delay = 0` "
                     f"(radiusd.conf diubah sementara lalu dikembalikan): median "
                     f"{statistics.median(rd['drop_msg3_rd0']):.3f} ms, yaitu percobaan di NEXT "
                     "sampai EAP-Failure ditambah satu sesi penuh di CUR.")
        L.append("")

    # ---- 1c-8. VM load during the series (vmstat every 5 s) ----
    vm_path = os.path.join(RESULTS, "series-vmstat.txt")
    if os.path.exists(vm_path):
        smp = []
        with open(vm_path) as f:
            hdr = None
            for line in f:
                t = line.split()
                if "us" in t and "id" in t:
                    hdr = t
                elif hdr and t and t[0].isdigit():
                    smp.append({k: float(v) for k, v in zip(hdr, t[:len(hdr)]) if k in ("r", "us", "sy", "id", "wa")})
        if smp:
            L.append("### Load VM selama seri (vmstat, sampel 5 s)")
            L.append("")
            L.append("| Sampel | r (run queue) mean | us % | sy % | id % mean | id % min | wa % |")
            L.append("| --- | --- | --- | --- | --- | --- | --- |")
            m = lambda k: statistics.mean(x[k] for x in smp)
            L.append(f"| {len(smp)} | {m('r'):.1f} | {m('us'):.1f} | {m('sy'):.1f} | {m('id'):.1f} | "
                     f"{min(x['id'] for x in smp):.0f} | {m('wa'):.1f} |")
            L.append("")

    # ---- carry 1a and 1b from analysis.md (method-independent) ----
    sec1a = carry_section(analysis_text, "## 1a. Breakdown komputasi primitif kriptografi",
                          ["## "])
    sec1b = carry_section(analysis_text, "## 1b. Breakdown komputasi per method (Keygen, Scalar mult, Encaps, Decaps, Signature, Verify)",
                          ["## "])
    L.append("> Bagian 1a dan 1b berikut adalah pengukuran primitif/komputasi yang "
             "**identik** dengan `analysis.md` (independen terhadap transport), disertakan "
             "agar kedua dokumen memiliki kolom yang sama persis.")
    L.append("")
    L.append(sec1a)
    L.append("")
    L.append(sec1b)
    L.append("")

    # ---- 2. Lossy network end-to-end (identical columns to analysis.md 2) ----
    L.append("## 2. Performa pada jaringan lossy (end-to-end EAP-over-RADIUS)")
    L.append("")
    trials = len(by_ml[(0, 0.0)]) if (0, 0.0) in by_ml else 0
    L.append(f"Handshake EAP-EDHOC/EAP-TLS nyata melalui RADIUS dengan retransmisi gaya EAP "
             f"(RTO 40 ms, maks 6 retransmisi per pertukaran); loss diemulasi di level "
             f"aplikasi pada tiap datagram UDP nyata. {trials} percobaan per sel, semua "
             f"method (0..6) live.")
    L.append("")
    L.append("| Method | Loss % | Success % | Mean (ms) | p95 (ms) | Mean retx |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for m in sorted(METHOD_NAMES):
        for loss in [0.0, 1.0, 5.0, 10.0, 20.0, 30.0]:
            rows = by_ml.get((m, loss))
            if not rows:
                continue
            durs = [float(r["duration_ms"]) for r in rows if r["status"] == "PASS"]
            npass = len(durs)
            retx = [int(r["retransmits"]) for r in rows]
            succ = 100.0 * npass / len(rows)
            mean_ms = statistics.mean(durs) if durs else 0.0
            p95_ms = pct(durs, 95) if durs else 0.0
            L.append(f"| {m} | {loss:.1f} | {succ:.1f} | {mean_ms:.3f} | "
                     f"{p95_ms:.3f} | {statistics.mean(retx):.3f} |")
    L.append("")

    # ---- analytic loss model vs measurement, with Wilson CIs ----
    RTO_MS, ATTEMPTS = 40.0, 7
    L.append("### Validasi model analitis loss")
    L.append("")
    L.append("Model: satu RADIUS round-trip berhasil dengan peluang p = (1 - L)^2 "
             "(request dan reply sama-sama harus lolos), pertukaran gagal permanen setelah "
             f"{ATTEMPTS} percobaan (1 + 6 retransmisi), sehingga sukses handshake = "
             "(1 - (1 - p)^7)^n_RT dan retransmisi per handshake sukses ~ n_RT (1 - p) / p, "
             f"masing-masing menambah RTO {RTO_MS:.0f} ms. n_RT = jumlah RADIUS round-trip "
             "terukur tanpa loss. Interval sukses = Wilson 95%. Retx terukur dihitung di antara "
             "handshake yang sukses agar sebanding dengan model; kolom terakhir = rata-rata "
             "semua percobaan (seperti tabel di atas).")
    L.append("")
    L.append("| Method | n_RT | Loss % | Sukses terukur % | Wilson 95% CI % | Sukses model % | "
             "Retx terukur (sukses) | Retx model | Mean terukur (ms) | Model retx x RTO (ms) | Retx (semua) |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for m in sorted(METHOD_NAMES):
        ok0 = [r for r in by_m.get(m, []) if r["status"] == "PASS"]
        if not ok0:
            continue
        n_rt = int(ok0[0]["radius_round_trips"])
        for loss in [5.0, 10.0, 20.0, 30.0]:
            rows = by_ml.get((m, loss))
            if not rows:
                continue
            ok = [r for r in rows if r["status"] == "PASS"]
            n, k = len(rows), len(ok)
            lo, hi = wilson(k, n)
            p = (1 - loss / 100) ** 2
            succ_model = (1 - (1 - p) ** ATTEMPTS) ** n_rt
            retx_model = n_rt * (1 - p) / p
            retx_ok = statistics.mean(int(r["retransmits"]) for r in ok) if ok else 0.0
            mean_ok = statistics.mean(float(r["duration_ms"]) for r in ok) if ok else 0.0
            L.append(f"| {m} | {n_rt} | {loss:.0f} | {100*k/n:.1f} | [{100*lo:.1f}, {100*hi:.1f}] | "
                     f"{100*succ_model:.1f} | {retx_ok:.1f} | {retx_model:.1f} | {mean_ok:.1f} | "
                     f"{retx_model*RTO_MS:.0f} | {statistics.mean(int(r['retransmits']) for r in rows):.1f} |")
    L.append("")
    L.append("- Model mengabaikan biaya tanpa-loss (T_loopback) dan jitter, sehingga cocok "
             "terutama pada loss tinggi, saat retransmisi mendominasi waktu.")
    L.append("")

    # ---- hybrid pair: proposal (4) vs EAP-TLS Hybrid PQC (6), success rates ----
    L.append("### Uji signifikansi sukses: proposal (method 4) vs EAP-TLS Hybrid PQC (method 6)")
    L.append("")
    L.append("Per tingkat loss: sukses/percobaan, Wilson 95%, dan uji eksak Fisher dua sisi "
             "(`scipy.stats.fisher_exact`) pada tabel 2x2 sukses/gagal.")
    L.append("")
    L.append("| Loss % | Method 4 sukses | Wilson 95% % | Method 6 sukses | Wilson 95% % | Fisher p (dua sisi) |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for loss in [0.0, 1.0, 5.0, 10.0, 20.0, 30.0]:
        a = by_ml.get((4, loss)); b = by_ml.get((6, loss))
        if not a or not b:
            continue
        ka = sum(r["status"] == "PASS" for r in a); kb = sum(r["status"] == "PASS" for r in b)
        wa, wb = wilson(ka, len(a)), wilson(kb, len(b))
        pv = fisher_exact([[ka, len(a) - ka], [kb, len(b) - kb]])[1] if fisher_exact else float("nan")
        L.append(f"| {loss:.0f} | {ka}/{len(a)} ({100*ka/len(a):.1f}%) | [{100*wa[0]:.1f}, {100*wa[1]:.1f}] | "
                 f"{kb}/{len(b)} ({100*kb/len(b):.1f}%) | [{100*wb[0]:.1f}, {100*wb[1]:.1f}] | {pv:.3f} |")
    L.append("")

    # ---- carry 3 (interop) from analysis.md ----
    sec3 = carry_section(analysis_text, "## 3. Interoperabilitas dengan implementasi EDHOC",
                         ["## "])
    L.append("> Bagian 3 (interoperabilitas primitif) identik dengan `analysis.md`.")
    L.append("")
    L.append(sec3)
    L.append("")

    # ---- 4. Fragmentation observed end-to-end (identical columns to analysis.md 4) ----
    L.append("## 4. Pengaruh ukuran paket terhadap MTU dan fragmentasi")
    L.append("")
    L.append("Ukuran pesan dan jumlah fragmen EAP untuk method 0..6 di bawah ini adalah "
             "**hasil observasi langsung** dari byte yang benar-benar dikirim/diterima harness "
             "(bukan perkiraan) — termasuk method 6, yang sekarang live sama seperti method "
             "lainnya. `EAP frags` = fragmen EDHOC/TLS yang teramati; `EAP attrs` = atribut "
             "EAP-Message 253 B (RFC 3579); `IP frags` dan `>MTU` diturunkan dari byte teramati "
             "pada MTU 1500.")
    L.append("")
    L.append("| Method | Pesan | Bytes | EAP attrs | EAP frags | IP frags | >MTU | Sumber |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for m in sorted(by_m):
        r = by_m[m][0]
        msgs = [("message_1", int(r["msg1_bytes"]), int(r["msg1_frags"])),
                ("message_2", int(r["msg2_bytes"]), int(r["msg2_frags"])),
                ("message_3", int(r["msg3_bytes"]), int(r["msg3_frags"])),
                ("message_4", int(r["msg4_bytes"]), int(r["msg4_frags"]))]
        for name, nbytes, frags in msgs:
            if nbytes == 0 and frags == 0:
                continue  # method 0..3 have no message_4
            # EAP-Message 253 B attributes across the observed frags:
            wire = nbytes + frags  # +1 flag byte per fragment
            attrs = (wire + EAP_ATTR - 1) // EAP_ATTR
            ipf = (nbytes + MTU - 1) // MTU
            over = "yes" if nbytes > MTU else "no"
            L.append(f"| {m} | {name} | {nbytes} | {attrs} | {frags} | {ipf} | {over} | observasi nyata |")

    L.append("")
    L.append("Pesan yang memerlukan fragmentasi pada method 4 (SIGMA XWING PQC) dan method 6 "
             "(EAP-TLS Hybrid PQC) — keduanya observasi nyata: XWING/hybrid-KEM "
             "(X25519+ML-KEM-768) menambah ~1.1-1.2 KB per elemen KEM dan tanda tangan "
             "ML-DSA-44 menambah ~2.4 KB per pesan, sehingga keduanya memerlukan banyak "
             "round-trip fragmentasi EAP sedangkan method 0, 1, 2, 3 dan 5 (klasik) selalu "
             "muat dalam sedikit fragmen.")
    L.append("")

    # ---- method 4: size model (edhoc_sizes.py, mtu-fragmentation.csv) vs live ----
    from edhoc_sizes import edhoc4_eap_fragments, message_sizes
    model4 = message_sizes(4)
    r4 = by_m[4][0]
    L.append("### Model ukuran method 4 vs live")
    L.append("")
    L.append("`edhoc_sizes.py` memodelkan format kawat `edhoc4.c` byte demi byte (field "
             "digabung mentah tanpa CBOR, tag AES-128-GCM 16 B, item EAD = label 1 B + Npk) "
             "dan fragmenter EAP-EDHOC yang sama dengan `transport.cpp`/harness (payload "
             "maksimum 1000 B: fragmen pertama 997 B data, berikutnya 999 B). "
             "`mtu_fragmentation.py` berhenti dengan error jika model berbeda dari live.")
    L.append("")
    L.append("| Pesan | Model (B) | Live (B) | Fragmen EAP model | Fragmen EAP live |")
    L.append("| --- | --- | --- | --- | --- |")
    tm = tl = fm = fl = 0
    for i in range(1, 5):
        mb = model4[f"message_{i}"]
        lb, lf = int(r4[f"msg{i}_bytes"]), int(r4[f"msg{i}_frags"])
        mf = edhoc4_eap_fragments(mb)
        tm, tl, fm, fl = tm + mb, tl + lb, fm + mf, fl + lf
        L.append(f"| message_{i} | {mb} | {lb} | {mf} | {lf} |")
    L.append(f"| **Total** | **{tm}** | **{tl}** | **{fm}** | **{fl}** |")
    L.append("")
    L.append(f"- Satu fragmen EAP = satu round-trip RADIUS, jadi n_RT method 4 = **{fl}**. "
             f"Model {'sama dengan' if (tm, fm) == (tl, fl) else 'BERBEDA dari'} live.")
    L.append("")

    full_5g_core_section(L, by_m)
    full_5g_core_v2_section(L, by_m)

    with open(OUT, "w") as f:
        f.write("\n".join(L) + "\n")
    print(f"wrote {OUT} ({len(L)} lines)")


if __name__ == "__main__":
    main()
