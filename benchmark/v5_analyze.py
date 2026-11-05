#!/usr/bin/env python3
"""
v5_analyze.py — section "9. Final v5" of analisys2.md and the table of every
number that goes into the paper, from the -v5 result files.
Writes benchmark-results/v5-analysis.md and v5-paper-numbers.md.
Median CI and difference CI: bootstrap, 4000 resamples, seed 1.
"""
import csv
import os
import statistics

import e2e_analyze as ea
import edhoc_sizes
import mtu_fragmentation as mtu

R = ea.RESULTS
rng = ea.random.Random(1)


def load(name):
    with open(os.path.join(R, name), newline="") as f:
        return list(csv.DictReader(f))


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(p * (len(s) - 1) + 0.5))]


def ci_med(a):
    bs = sorted(statistics.median(rng.choices(a, k=len(a))) for _ in range(4000))
    return bs[100], bs[3899]


def ci_diff(a, b):
    bs = sorted(statistics.median(rng.choices(a, k=len(a))) - statistics.median(rng.choices(b, k=len(b)))
                for _ in range(4000))
    return statistics.median(a) - statistics.median(b), bs[100], bs[3899]


def table(hdr, body):
    return ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)] + ["| " + " | ".join(map(str, r)) + " |" for r in body]


N = []   # the paper numbers: item, value, source file, column


def num(item, value, source, column):
    N.append([item, value, f"`{source}`", column])


def harness(L):
    src = "e2e-handshake-v5-m4m6.csv"
    rows = load(src)
    d = {m: [r for r in rows if r["method"] == m and r["status"] == "PASS"] for m in "46"}
    v = {m: [float(r["duration_ms"]) for r in d[m]] for m in "46"}
    L += ["### Harness E2E (v5 dan EAP-TLS Hybrid PQC, satu sesi, 2 run × 100)", ""]
    body = []
    for m, name in (("4", "Proposal v5"), ("6", "EAP-TLS Hybrid PQC")):
        lo, hi = ci_med(v[m])
        ini, res = [statistics.mean(float(r[k]) for r in d[m]) for k in ("initiator_ms", "responder_ms")]
        body.append([name, len(v[m]), f"{statistics.mean(v[m]):.3f}", f"{statistics.median(v[m]):.3f}", f"{pct(v[m], .95):.3f}",
                     f"[{lo:.3f}, {hi:.3f}]", f"{ini:.3f}", f"{res:.3f}"])
        for it, val, col in ((f"{name}: mean (ms)", f"{statistics.mean(v[m]):.3f}", "duration_ms"),
                             (f"{name}: median (ms)", f"{statistics.median(v[m]):.3f}", "duration_ms"),
                             (f"{name}: p95 (ms)", f"{pct(v[m], .95):.3f}", "duration_ms"),
                             (f"{name}: 95% CI median (ms)", f"[{lo:.3f}, {hi:.3f}]", "duration_ms"),
                             (f"{name}: UE lokal, Figure 7 kanan (ms)", f"{ini:.3f}", "initiator_ms"),
                             (f"{name}: tunggu balasan, Figure 7 kanan (ms)", f"{res:.3f}", "responder_ms")):
            num(it, val, src, f"{col}, method {m}")
    L += table(["Method", "N", "Mean (ms)", "Median (ms)", "p95 (ms)", "95% CI median (ms)", "UE lokal mean (ms)",
                "Tunggu balasan mean (ms)"], body) + [""]
    x, lo, hi = ci_diff(v["6"], v["4"])
    L.append(f"- Selisih median EAP-TLS Hybrid PQC − v5: **{x:.3f} ms**, 95% CI [{lo:.3f}, {hi:.3f}]; "
             f"mean {statistics.mean(v['6']) - statistics.mean(v['4']):.3f} ms.")
    num("EAP-TLS Hybrid PQC − v5: selisih median (ms)", f"{x:.3f}", src, "duration_ms")
    num("EAP-TLS Hybrid PQC − v5: 95% CI (ms)", f"[{lo:.3f}, {hi:.3f}]", src, "duration_ms")
    old = [float(r["duration_ms"]) for r in load("e2e-handshake-v4b.csv") if r["method"] == "4" and r["status"] == "PASS"]
    L.append(f"- Sebagai pembanding saja, v4b di `e2e-handshake-v4b.csv`: median {statistics.median(old):.3f} ms, sesi lain. "
             "Selisih antarsesi bukan biaya protokol (bagian 8).")
    L.append("")


def storage(L):
    src = "e2e-storage-flush-v5.csv"
    fl = {}
    for r in load(src):
        if r["status"] == "PASS":
            fl.setdefault(r["label"], []).append(float(r["duration_ms"]))
    where = {"durable": ("disk", "disk"), "tmpfs": ("tmpfs", "tmpfs"), "ue_tmpfs": ("tmpfs", "disk"), "dn_tmpfs": ("disk", "tmpfs")}
    L += ["### Ablasi storage (`storage_ablation.sh 6 100 flush`, 4 konfigurasi, 6 ronde × 100)", ""]
    body = []
    for lab in ("durable", "ue_tmpfs", "dn_tmpfs", "tmpfs"):
        lo, hi = ci_med(fl[lab])
        body.append([lab, *where[lab], len(fl[lab]), f"{statistics.mean(fl[lab]):.3f}", f"{statistics.median(fl[lab]):.3f}", f"[{lo:.3f}, {hi:.3f}]"])
    L += table(["Konfigurasi", "UE", "DN-AAA", "N", "Mean (ms)", "Median (ms)", "95% CI median (ms)"], body) + [""]
    body = []
    for name, e, a, b in (("Flush UE saja", "dn_tmpfs − tmpfs", "dn_tmpfs", "tmpfs"),
                          ("Flush DN-AAA saja", "ue_tmpfs − tmpfs", "ue_tmpfs", "tmpfs"),
                          ("Flush UE, di atas flush DN-AAA", "durable − ue_tmpfs", "durable", "ue_tmpfs"),
                          ("Flush DN-AAA, di atas flush UE", "durable − dn_tmpfs", "durable", "dn_tmpfs"),
                          ("Kedua flush", "durable − tmpfs", "durable", "tmpfs")):
        x, lo, hi = ci_diff(fl[a], fl[b])
        body.append([name, e, f"{x:.3f}", f"[{lo:.3f}, {hi:.3f}]"])
        num(f"Storage, {name} (ms)", f"{x:.3f} [{lo:.3f}, {hi:.3f}]", src, f"duration_ms, {e}")
    L += table(["Biaya", "Selisih median", "Nilai (ms)", "95% CI (ms)"], body) + [""]


def fullstack(L):
    src = "fullstack-handshake-v5.csv"
    rows = load(src)
    A = [r for r in rows if r["config"] == "A"]
    B = [r for r in rows if r["config"] == "B"]
    okA, okB = [[r for r in s if r["status"] == "PASS"] for s in (A, B)]
    vals = lambda s, k: [float(r[k]) for r in s if r.get(k)]
    L += ["### Full stack v5 (A/B 3 × 100, `@edhoc.internet`)", ""]
    L.append(f"- A: PASS {len(okA)}/{len(A)}, msk_match {sum(int(r['msk_match']) for r in okA)}/{len(okA)}, "
             f"rotated {sum(int(r['rotated']) for r in okA)}/{len(okA)}; B: PASS {len(okB)}/{len(B)}.")
    L.append("- **Satu sesi gagal di A (seri 3, iterasi 77), status timeout**, tidak ikut statistik. Log UE: `No response from RRC "
             "from UAC checks, considering access attempt is barred`, jadi UERANSIM menahan permintaan sebelum NAS dikirim dan "
             "belum ada Message1. Permintaan dikirim ulang saat T3580 habis (16 s) dan handshake-nya selesai normal; sesi "
             "berikutnya sukses. Ini perilaku simulator, bukan protokol. Di v4b tidak muncul (300/300).")
    shapes = {(r["len_m1"], r["len_m2"], r["len_m3"], r["len_m4"], r["n_nas_rounds"], r["n_radius_rt"]) for r in okA}
    L.append(f"- Ukuran / ronde: {sorted(shapes)} (Message1..4 B, ronde NAS, RADIUS RT).")
    L.append("")
    a, b = vals(okA, "t_pdu_ms"), vals(okB, "t_pdu_ms")
    x, lo, hi = ci_diff(a, b)
    body = [["Added to PDU session establishment (A − B)", "`t_pdu_ms`", len(a), f"{x:.1f}", f"[{lo:.1f}, {hi:.1f}]",
             f"{statistics.mean(a) - statistics.mean(b):.1f}", "--"]]
    num("Tabel 6, Added: median [CI] / mean (ms)", f"{x:.1f} [{lo:.1f}, {hi:.1f}] / {statistics.mean(a) - statistics.mean(b):.1f}", src, "t_pdu_ms, A − B")
    seg = (("Secondary authentication at the UE", "t_secauth_ms", 1), ("5G core transport (UE, gNB, AMF, SMF)", "t_core_ms", 1),
           ("SMF ↔ UPF relay hop", "t_hop_smf_upf_ms", 1), ("RADIUS processing in the UPF relay", "t_relay_proc_ms", 1),
           ("DN-AAA (FreeRADIUS, from the UPF relay)", "t_aaa_ms", 1), ("UE write of NEXT (before Message3)", "ue_store_next_ms", 2),
           ("DN-AAA commit (before Message4)", "aaa_commit_ms", 2), ("UE promotion (after Message4)", "ue_promote_ms", 2))
    for name, k, dp in seg:
        v = vals(okA, k)
        lo, hi = ci_med(v)
        f = lambda z: f"{z:.{dp}f}"
        body.append([name, f"`{k}`", len(v), f(statistics.median(v)), f"[{f(lo)}, {f(hi)}]", f(statistics.mean(v)), f(pct(v, .95))])
        num(f"Tabel 6, {name}: median [CI] / mean / p95 (ms)", f"{f(statistics.median(v))} [{f(lo)}, {f(hi)}] / {f(statistics.mean(v))} / {f(pct(v, .95))}", src, f"{k}, A")
    L += table(["Segmen (Tabel 6)", "Kolom", "N", "Median (ms)", "95% CI", "Mean (ms)", "p95 (ms)"], body) + [""]
    rec = os.path.join(R, "fullstack-recovery-v5.csv")
    ea.recovery_v2_table(L, rec, "#### Uji pemulihan v5")
    rr = load("fullstack-recovery-v5.csv")
    for case, name in (("msg3", "Message3 dibuang"), ("msg4", "Message4 dibuang")):
        t = [float(r["t_recovery_ms"]) for r in rr if r["case"] == case and r["t_recovery_ms"]]
        num(f"Pemulihan, {name}: median / mean (ms)", f"{statistics.median(t):.1f} / {statistics.mean(t):.1f}", "fullstack-recovery-v5.csv", "t_recovery_ms")
    bad = sum(1 for r in rr if r["recovered"] != "1")
    num("Pemulihan: desync, re-provisioning", f"{bad}, 0", "fullstack-recovery-v5.csv", "recovered")
    idc = open(os.path.join(R, "v5-identity-check.txt")).read().strip().split("\n")[-1]
    L += [f"- Cek identitas (`v5-identity-check.txt`): {idc}", ""]


def sizes(L):
    src = "e2e-handshake-v5-m4m6.csv"
    rows = load(src)
    body = []
    for m, name, model in (("4", "Proposal v5", edhoc_sizes.message_sizes(4)), ("6", "EAP-TLS Hybrid PQC", edhoc_sizes.message_sizes(6))):
        r = next(x for x in rows if x["method"] == m)
        live = [int(r[f"msg{i}_bytes"]) for i in range(1, 5)]
        mod = [model[f"message_{i}"] for i in range(1, 5)]
        fr = [int(r[f"msg{i}_frags"]) for i in range(1, 5)]
        ip = [mtu.ip_fragments(s) for s in live]
        body.append([name, "/".join(map(str, live)), sum(live), "/".join(map(str, mod)), "cocok" if live == mod else "BEDA",
                     live[0] + live[2], live[1] + live[3], "/".join(map(str, fr)) + f" (total {sum(fr)})",
                     "/".join(map(str, ip)) + f" (total {sum(ip)})", r["radius_round_trips"]])
        num(f"{name}: Message1–4 (B)", "/".join(map(str, live)), src, "msg1..4_bytes")
        num(f"{name}: total (B)", sum(live), src, "msg1..4_bytes")
        num(f"{name}: dikirim UE, Message1+3 (B)", live[0] + live[2], src, "msg1_bytes + msg3_bytes")
        num(f"{name}: dikirim DN-AAA/server, Message2+4 (B)", live[1] + live[3], src, "msg2_bytes + msg4_bytes")
        num(f"{name}: fragmen EAP", "/".join(map(str, fr)), src, "msg1..4_frags")
        num(f"{name}: RT", r["radius_round_trips"], src, "radius_round_trips")
    L += ["### Ukuran (live dan model)", ""]
    L += table(["Method", "Message1–4 live (B)", "Total (B)", "Model (B)", "Live = model", "Dikirim UE (M1+M3)", "Dikirim DN-AAA (M2+M4)",
                "Fragmen EAP", "Fragmen IP (model)", "RT"], body) + [""]


def compute(L):
    src = "compute-v5/handshake-compute.csv"
    c = {r["method"]: r for r in load(src)}
    L += ["### Komputasi per fungsi", ""]
    L.append("Harness yang sama dengan Figure 7 kiri: `crypto_bench` mengukur primitif lalu mengalikannya dengan jumlah operasi per peran; EAP-TLS Hybrid dengan `compute_tls_hybrid.py`, dari primitif yang sama.")
    L.append("")
    body = []
    for m, name in (("4", "Proposal v5"), ("6", "EAP-TLS Hybrid PQC")):
        i, r = float(c[m]["initiator_compute_us"]), float(c[m]["responder_compute_us"])
        body.append([name, f"{i:.3f}", f"{r:.3f}", f"{i + r:.3f}"])
        num(f"{name}: komputasi initiator / responder, Figure 7 kiri (µs)", f"{i:.3f} / {r:.3f}", src, "initiator_compute_us, responder_compute_us")
    L += table(["Method", "Initiator (µs)", "Responder (µs)", "Total (µs)"], body) + [""]
    L.append("| Operasi method 4 (per peran, sama di kedua peran) | Jumlah | Waktu (µs) |\n|---|---|---|")
    for r in load("compute-v5/crypto-breakdown.csv"):
        if r["method"] == "4" and r["role"] == "initiator":
            L.append(f"| {r['operation']} ({r['primitive']}) | {r['op_count']} | {float(r['compute_ns']) / 1000:.3f} |")
    L.append("")
    p = load("m4-inprocess-compute-v5.csv")[-1]
    L.append(f"- **Batas model ini:** hanya menghitung primitif, jadi jumlah operasinya sama di v4 dan v5. Beda hash dan AEAD Message1 tidak terlihat di sini; beda angka dengan v4b (492,320 µs) berasal dari pengukuran primitif sesi lain, EAP-TLS Hybrid juga bergeser (467,442 → {float(c['6']['initiator_compute_us']):.3f} µs). Selisih v5 yang sebenarnya untuk Message1 ada di `m1-compute-variants.csv` (bagian 8).")
    L.append(f"- Pembanding yang menjalankan handshake v5 sungguhan dalam proses (`m4_inproc_bench`, N={p['iters']}, tanpa storage): initiator median {p['initiator_median_us']} µs, responder median {p['responder_median_us']} µs.")
    L.append("")
    num("Proposal v5: handshake dalam proses, initiator / responder median (µs)", f"{p['initiator_median_us']} / {p['responder_median_us']}", "m4-inprocess-compute-v5.csv", "initiator_median_us, responder_median_us")


def tests(L):
    L += ["### Hasil test", ""]
    L += table(["Test", "Hasil"], [["`edhoc4_xwing_kat`", "PASS (3 vektor X-Wing)"], ["`edhoc4_selftest`", "PASS (default v5, dan 4 varian)"],
                                   ["`edhoc03_selftest`", "PASS"], ["`edhoc4_dbtest`", "PASS"]]) + [""]
    L.append("`edhoc4_dbtest` disesuaikan: vektor Message1 sekarang 2424 B. Dua kasus memakai pemeriksaan KeyID_B = H(pk_B) yang tidak ada di v5, jadi dijalankan pada varian v4. Untuk v5 ditambah kasus entri indeks palsu: Decaps berjalan, lalu `E4_ERR_AEAD`, dan entri itu **tidak** dihapus. Di v4 penolakan terjadi sebelum Decaps dan entri dihapus. Indeks dibangun dari slot saat start, jadi entri seperti ini tidak muncul dalam operasi normal.")
    L.append("")
    L += ["T1–T7 pada v5 (`tamper_tests.sh 20 v5 v5`), 20 kali per baris:", ""]
    L += open(os.path.join(R, "tamper-v5.md")).read().strip().split("\n") + [""]
    for r in load("tamper-v5.csv"):
        num(f"{r['test']}: hasil; DN-AAA; median ms; Decaps", f"{r['result at the UE']}; {r['DN-AAA step']}; {r['DN-AAA median ms']}; {r['Decaps run']}", "tamper-v5.csv", "semua")


def proverif(L):
    path = os.path.join(R, "..", "symmetry-rev/proverif/results/SUMMARY_v5.txt")
    text = open(path).read()
    L += ["### SUMMARY_v5 (ProVerif)", "", "Sumber: `symmetry-rev/proverif/results/SUMMARY_v5.txt` (`run_all_v5.sh`, MemoryMax=10G, 3600 s per query). Tidak ada NOT CONCLUDED.", "", "```"]
    L += text.rstrip("\n").split("\n") + ["```", ""]
    n = sum(1 for l in text.split("\n") if l.startswith("  q"))
    assert "NOT CONCLUDED" not in text
    num("ProVerif v5: jumlah query, NOT CONCLUDED", f"{n}, 0", "symmetry-rev/proverif/results/SUMMARY_v5.txt", "result")
    L.append("Model unlinkability tidak dijalankan untuk v5; status terakhir tetap NOT CONCLUDED untuk v4 (bagian 7c), jadi tidak ada klaim unlinkability.")
    L.append("")


def main():
    L = ["", "## 9. Final v5", "",
         "Step 31. v5 = protokol Dr. Shin + cek KeyID dalam (`v4s+chk` di bagian 8), sekarang default. TH_1 = H(KeyID_B, ct_B); AEAD Message1 dengan AD = TH_1; KeyID_B juga di Plaintext1; DN-AAA mengambil record dari indeks memori, memeriksa ID_CRED_I dan KeyID_B di Plaintext1 = header. Write-ahead NEXT tetap ada. Kernel `" + os.uname().release + "`. Paper tidak diubah.", ""]
    tests(L)
    proverif(L)
    harness(L)
    storage(L)
    fullstack(L)
    sizes(L)
    compute(L)
    P = ["### Tabel ringkas angka untuk paper", "", "Semua nilai dibaca dari file sumber oleh `benchmark/v5_analyze.py`.", ""]
    P += table(["Angka", "Nilai", "Sumber", "Kolom"], N)
    L += P + [""]
    with open(os.path.join(R, "v5-analysis.md"), "w") as f:
        f.write("\n".join(L))
    with open(os.path.join(R, "v5-paper-numbers.md"), "w") as f:
        f.write("\n".join(P) + "\n")
    print("\n".join(P))


if __name__ == "__main__":
    main()
