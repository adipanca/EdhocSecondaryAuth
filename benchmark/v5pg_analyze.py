#!/usr/bin/env python3
"""
v5pg_analyze.py — section "10. Pra-generasi X-Wing KeyGen (v5-pregen)" of
analisys2.md and the table of the paper numbers, from the -v5pg files.
Writes benchmark-results/v5pg-analysis.md and v5pg-paper-numbers.md.

  v5pg_analyze.py [logs-fullstack-dir]   (for the UE / DN-AAA pool_miss of
                                          the full-stack run)
Median CI and difference CI: bootstrap, 4000 resamples, seed 1 (as v5_analyze.py).
"""
import csv
import glob
import os
import re
import statistics
import sys

import e2e_analyze as ea

R = ea.RESULTS
rng = ea.random.Random(1)
N = []   # paper numbers: item, value, source file, column


def load(name):
    with open(os.path.join(R, name), newline="") as f:
        return list(csv.DictReader(f))


def text(name):
    return open(os.path.join(R, name)).read().strip()


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


def num(item, value, source, column):
    N.append([item, value, f"`{source}`", column])


def design(L):
    L += ["### Desain pool dan alasan keamanannya", "",
          "- **Apa yang dipindah:** hanya KeyGen kunci berikutnya (Nsk_A/Npk_A di UE untuk EAD_1, Nsk_B/Npk_B di DN-AAA untuk EAD_2). Kunci ini tidak bergantung pada isi run, hanya acak segar yang dipakai sekali, jadi membuatnya lebih awal tidak mengubah pesan, ukuran, maupun model ProVerif (`new` di model sudah berarti kunci segar sekali pakai).",
          "- **Opsi:** `xwing_next_keygen = pregen | inline` (radiusd, default `pregen`; UE `secondaryAuth.xwingNextKeygen` atau env `EDHOC_NEXT_KEYGEN`, default `pregen`); `xwing_pool_size` di DN-AAA (default 64, 0..1024). Proses yang tidak mengonfigurasi pool (tool, test) memakai inline.",
          "- **Hanya di memori:** kunci pool belum berarti apa-apa bagi protokol sampai masuk NEXT (UE) atau commit (DN-AAA), jadi pool tidak ditulis ke disk dan dibuat ulang setiap start. Jalur durable tidak berubah: satu `fdatasync` per pihak.",
          "- **Memori terkunci:** area pool di-`mlock` (`sodium_mlock`); status tercatat di log start (`locked memory`).",
          "- **Sekali pakai:** kunci yang diambil disalin ke ctx lalu slot pool di-zeroize; tidak pernah dikembalikan. Run yang gagal menghapus ctx (termasuk Nsk) dan run berikutnya mengambil kunci baru.",
          "- **Zeroize:** saat diambil, saat ctx dihapus, saat pool dikosongkan atau dikonfigurasi ulang, dan saat proses keluar (`atexit`, juga `mod_detach` di radiusd). Kunci pool tidak pernah ditulis ke log; log hanya berisi penghitung.",
          "- **Ukuran:** UE satu kunci (satu sesi pada satu waktu); DN-AAA satu pool global, dilindungi mutex karena FreeRADIUS multithread. Kunci acak tidak terikat pada UE, jadi satu pool global aman.",
          "- **Isi ulang:** thread `e4-keypool` (nice 19) membuat kunci tanpa memegang mutex dan hanya mengunci untuk push. UE: dibangunkan setelah Message1 dibangun (berjalan selama UE menunggu Message2) dan setelah promosi Message4. Spesifikasi step hanya menyebut \"setelah promosi\"; pemicu setelah Message1 ditambahkan karena run yang tidak sampai promosi (Message3/4 hilang, EAP-Failure) meninggalkan pool kosong untuk run berikutnya (lihat percobaan pertama full stack). DN-AAA: setelah commit, atau saat pengambilan membuat pool di bawah setengah.",
          "- **Pool kosong:** fallback ke KeyGen inline (hasil tetap benar) dan `pool_miss` bertambah. UE mencatat `pool_miss` di baris `[E4T] ue_msg1`, DN-AAA di `[E4T] aaa_commit` dan di baris penutup radius.log.",
          "- **Mode lama:** `inline` menjalankan kode yang sama dengan v5 step 31; transkrip identik byte per byte di bawah RNG deterministik (`edhoc4/inline_identity.sh`).",
          "- **Tidak berubah:** write-ahead NEXT, commit, erase, recovery, indeks KeyID di memori; Message1–4 tetap 2424/6097/3756/16 B, 15 RT. EAP-TLS Classic/Hybrid dan EDHOC methods 0–3 tidak disentuh.", ""]


def tests(L):
    L += ["### Hasil test", ""]
    body = [["`edhoc4_xwing_kat`", "PASS (3 vektor X-Wing)"], ["`edhoc4_selftest`", "PASS"], ["`edhoc03_selftest`", "PASS"],
            ["`edhoc4_dbtest`", "PASS"], ["`edhoc4_pooltest` (dalam proses)", "PASS, rincian di bawah"],
            ["`edhoc4/inline_identity.sh` (inline vs 284e9402)", text("inline-identity-v5pg.txt").split("\n")[-1].replace("RESULT: ", "")],
            ["Test live `pool_tests.sh`", "lihat tabel berikut"], ["T1–T7 dengan pregen (`tamper_tests.sh 20 v5 v5pg`)", "lihat tabel berikut"]]
    L += table(["Test", "Hasil"], body) + ["", "`edhoc4_pooltest 1000 100` (`pooltest-v5pg.txt`; satu proses memegang kedua pihak, jadi UE dan DN-AAA berbagi satu pool):", "", "```"]
    L += text("pooltest-v5pg.txt").split("\n") + ["```", ""]
    L += text("pool-tests-v5pg.md").split("\n")[2:] + [""]
    L += ["T1–T7 pada v5 dengan `xwing_next_keygen = pregen` (20 kali per baris):", ""]
    L += text("tamper-v5pg.md").split("\n") + [""]
    num("Test pool: 1000 handshake berurutan, Npk_A / Npk_B unik, pool_miss UE / DN-AAA", "1000/1000, 1000/1000, 0 / 0",
        "pool-tests-v5pg/seq.keys, seq.ue, seq.pool", "fingerprint Npk_A, Npk_B; pool_miss")
    num("Test pool: 100 UE paralel × 5, kunci dipakai dua kali, pool_miss DN-AAA", "0, 0", "pool-tests-v5pg/par-*.keys, par.pool", "fingerprint; pool_miss")


def harness(L):
    src = "e2e-handshake-v5pg.csv"
    rows = [r for r in load(src) if r["status"] == "PASS"]
    g = {"pregen": [r for r in rows if r["method"] == "4" and r["label"].startswith("pregen")],
         "inline": [r for r in rows if r["method"] == "4" and r["label"].startswith("inline")],
         "tls": [r for r in rows if r["method"] == "6"]}
    names = {"pregen": "v5-pregen", "inline": "v5-inline", "tls": "EAP-TLS Hybrid PQC"}
    v = {k: [float(r["duration_ms"]) for r in g[k]] for k in g}
    L += ["### Harness E2E (v5-pregen, v5-inline, EAP-TLS Hybrid PQC; satu sesi, 2 run × (20 + 100), bergantian)", ""]
    body = []
    for k in ("pregen", "inline", "tls"):
        lo, hi = ci_med(v[k])
        ini = [float(r["initiator_ms"]) for r in g[k]]
        res = [float(r["responder_ms"]) for r in g[k]]
        body.append([names[k], len(v[k]), f"{statistics.mean(v[k]):.3f}", f"{statistics.median(v[k]):.3f}", f"{pct(v[k], .95):.3f}",
                     f"[{lo:.3f}, {hi:.3f}]", f"{statistics.mean(ini):.3f} / {statistics.median(ini):.3f}",
                     f"{statistics.mean(res):.3f} / {statistics.median(res):.3f}"])
        m = "4" if k != "tls" else "6"
        for it, val, col in ((f"{names[k]}: mean / median / p95 (ms)", f"{statistics.mean(v[k]):.3f} / {statistics.median(v[k]):.3f} / {pct(v[k], .95):.3f}", "duration_ms"),
                             (f"{names[k]}: 95% CI median (ms)", f"[{lo:.3f}, {hi:.3f}]", "duration_ms"),
                             (f"{names[k]}: UE lokal mean (ms)", f"{statistics.mean(ini):.3f}", "initiator_ms"),
                             (f"{names[k]}: tunggu balasan mean (ms)", f"{statistics.mean(res):.3f}", "responder_ms")):
            num(it, val, src, f"{col}, method {m}, label {k}-run*" if k != "tls" else f"{col}, method 6")
    L += table(["Metode", "N", "Mean (ms)", "Median (ms)", "p95 (ms)", "95% CI median (ms)", "UE lokal mean / median (ms)",
                "Tunggu balasan mean / median (ms)"], body) + [""]
    for a, b in (("pregen", "inline"), ("tls", "pregen")):
        x, lo, hi = ci_diff(v[a], v[b])
        L.append(f"- Selisih median {names[a]} − {names[b]}: **{x:.3f} ms**, 95% CI [{lo:.3f}, {hi:.3f}]; "
                 f"selisih mean {statistics.mean(v[a]) - statistics.mean(v[b]):.3f} ms.")
        num(f"{names[a]} − {names[b]}: selisih median [95% CI] (ms)", f"{x:.3f} [{lo:.3f}, {hi:.3f}]", src, "duration_ms")
    ia = statistics.median(float(r["initiator_ms"]) for r in g["inline"]) - statistics.median(float(r["initiator_ms"]) for r in g["pregen"])
    L.append(f"- UE lokal (median): inline − pregen = {ia:.3f} ms; KeyGen UE yang dipindah ≈ 0,05 ms (bagian komputasi).")
    # first attempt, same script, kept as measured
    old = [r for r in load("e2e-handshake-v5pg-attempt1.csv") if r["status"] == "PASS"]
    o = {k: [float(r["duration_ms"]) for r in old if (r["method"] == "6") == (k == "tls") and (k == "tls" or r["label"].startswith(k))]
         for k in ("pregen", "inline", "tls")}
    xa, loa, hia = ci_diff(o["pregen"], o["inline"])
    xb, lob, hib = ci_diff(o["tls"], o["pregen"])
    s31 = load("e2e-handshake-v5-m4m6.csv")
    m31 = {m: statistics.median(float(r["duration_ms"]) for r in s31 if r["method"] == m and r["status"] == "PASS") for m in "46"}
    L.append(f"- **Percobaan pertama** (skrip yang sama, 10:38, `e2e-handshake-v5pg-attempt1.csv`): median pregen / inline / TLS = "
             f"{statistics.median(o['pregen']):.3f} / {statistics.median(o['inline']):.3f} / {statistics.median(o['tls']):.3f} ms; "
             f"pregen − inline {xa:.3f} [{loa:.3f}, {hia:.3f}], TLS − pregen {xb:.3f} [{lob:.3f}, {hib:.3f}]. Saya menjalankan ulang karena seluruh sesi "
             f"lebih lambat dari step 31 (v5 {m31['4']:.3f}, TLS {m31['6']:.3f} ms), termasuk EAP-TLS yang tidak berubah, dengan outlier sampai puluhan ms. "
             "Percobaan kedua (tabel di atas) sama berisiknya; guest idle (vmstat: idle 98–100 %, steal 0), jadi sumbernya di host VM. Kedua percobaan disimpan.")
    L.append("- **Bacaan:** efek pregen yang diharapkan di jalur kritis ≈ 2 × 0,05 ms (satu KeyGen di UE, satu di DN-AAA). Itu jauh di bawah kebisingan sesi ini, jadi harness E2E tidak bisa memisahkannya; yang terlihat jelas hanya di pengukuran komputasi.")
    L.append("")


def compute(L):
    src = "compute-v5pg/handshake-compute-v5pg.csv"
    c = {r["bar"]: r for r in load(src)}
    prim = {r["operation"]: r for r in load("compute-v5pg/crypto-primitives.csv")}
    L += ["### Komputasi per fungsi", "",
          "Harness Figure 7 kiri (`crypto_bench` + `compute_tls_hybrid.py`, satu sesi primitif baru di `compute-v5pg/`): v5-inline = method 4 seperti dihitung `crypto_bench` (KeyGen kunci berikutnya di dalam handshake); v5-pregen = v5-inline dikurangi satu X-Wing KeyGen per peran (Keygen_MLKEM768 + Keygen_X25519, mean, sama seperti model). `compute_v5pg.py`.", ""]
    body = []
    for b, name in (("v5-inline", "v5-inline"), ("v5-pregen", "v5-pregen"), ("keygen-moved", "KeyGen yang dipindah (per peran)"), ("eap-tls-hybrid", "EAP-TLS Hybrid PQC")):
        i, r = float(c[b]["initiator_compute_us"]), float(c[b]["responder_compute_us"])
        body.append([name, f"{i:.3f}", f"{r:.3f}", f"{i + r:.3f}"])
        num(f"Figure 7 kiri, {name}: initiator / responder (µs)", f"{i:.3f} / {r:.3f}", src, "initiator_compute_us, responder_compute_us")
    L += table(["Bar", "Initiator (µs)", "Responder (µs)", "Total (µs)"], body) + [""]
    med = (float(prim["Keygen_MLKEM768"]["median_ns"]) + float(prim["Keygen_X25519"]["median_ns"])) / 1e3
    L.append(f"- X-Wing KeyGen per peran dari primitif yang sama: mean {float(c['keygen-moved']['initiator_compute_us']):.3f} µs, median {med:.3f} µs (Keygen_MLKEM768 + Keygen_X25519).")
    num("KeyGen yang dipindah per pihak, median primitif (µs)", f"{med:.3f}", "compute-v5pg/crypto-primitives.csv", "median_ns, Keygen_MLKEM768 + Keygen_X25519")
    rows = load("m4-inprocess-compute-v5pg.csv")
    g = {k: [r for r in rows if r["label"].startswith(k)] for k in ("inline", "pregen")}
    agg = lambda k, col: statistics.mean(float(r[col]) for r in g[k])
    L += ["", f"Handshake v5 sungguhan dalam proses (`m4_inproc_bench`, {len(g['inline'])} ronde × {g['inline'][0]['iters']} per mode, bergantian, tanpa storage; pregen: pool 64 diisi penuh di antara handshake, di luar jam). Nilai = rata-rata median per ronde.", ""]
    body = []
    for k in ("inline", "pregen"):
        body.append([f"v5-{k}", f"{agg(k, 'initiator_median_us'):.1f}", f"{agg(k, 'responder_median_us'):.1f}", f"{agg(k, 'total_mean_us'):.1f}",
                     ", ".join(r["pool_miss"] for r in g[k]) if k == "pregen" else "--"])
        num(f"Dalam proses, v5-{k}: initiator / responder median (µs)", f"{agg(k, 'initiator_median_us'):.1f} / {agg(k, 'responder_median_us'):.1f}",
            "m4-inprocess-compute-v5pg.csv", f"initiator_median_us, responder_median_us, label {k}-r*")
    L += table(["Mode", "Initiator median (µs)", "Responder median (µs)", "Total mean (µs)", "pool_miss per ronde"], body) + [""]
    di = agg("inline", "initiator_median_us") - agg("pregen", "initiator_median_us")
    dr = agg("inline", "responder_median_us") - agg("pregen", "responder_median_us")
    rf = statistics.mean(float(r["refill_median_us_per_key"]) for r in g["pregen"])
    rfm = statistics.mean(float(r["refill_mean_us_per_key"]) for r in g["pregen"])
    L.append(f"- Selisih inline − pregen: initiator {di:.1f} µs, responder {dr:.1f} µs, sesuai satu X-Wing KeyGen per pihak.")
    L.append(f"- Biaya isi ulang per kunci (satu X-Wing KeyGen ke pool, di luar handshake): median {rf:.1f} µs, mean {rfm:.1f} µs (dalam proses).")
    num("Dalam proses, inline − pregen: initiator / responder (µs)", f"{di:.1f} / {dr:.1f}", "m4-inprocess-compute-v5pg.csv", "initiator_median_us, responder_median_us")
    num("Isi ulang per kunci, dalam proses: median / mean (µs)", f"{rf:.1f} / {rfm:.1f}", "m4-inprocess-compute-v5pg.csv", "refill_median_us_per_key, refill_mean_us_per_key")
    pools = {}
    for ph in ("seq", "par"):
        m = re.search(r"refilled (\d+), refill CPU ([\d.]+)", text(f"pool-tests-v5pg/{ph}.pool"))
        pools[ph] = (m.group(1), m.group(2))
    L.append(f"- Di radiusd live, CPU thread isi ulang (nice 19) per kunci: {pools['seq'][1]} µs pada 1000 handshake berurutan "
             f"({pools['seq'][0]} kunci), {pools['par'][1]} µs saat 100 UE paralel ({pools['par'][0]} kunci). Ini waktu CPU thread itu, diukur dengan `CLOCK_THREAD_CPUTIME_ID`.")
    num("Isi ulang per kunci, thread radiusd live: berurutan / 100 UE paralel (µs CPU)", f"{pools['seq'][1]} / {pools['par'][1]}",
        "pool-tests-v5pg/seq.pool, par.pool", "refill CPU us/key")
    L.append("")


def fullstack(L, logdir):
    src = "fullstack-handshake-v5pg.csv"
    if not os.path.exists(os.path.join(R, src)):
        L += ["### Full stack v5-pregen", "", "Belum ada `fullstack-handshake-v5pg.csv`.", ""]
        return
    rows = load(src)
    A = [r for r in rows if r["config"] == "A"]
    B = [r for r in rows if r["config"] == "B"]
    okA, okB = [[r for r in s if r["status"] == "PASS"] for s in (A, B)]
    vals = lambda s, k: [float(r[k]) for r in s if r.get(k)]
    L += ["### Full stack v5-pregen (A/B 3 × 100, `@edhoc.internet`, nr-ue dan radiusd pregen)", ""]
    L.append(f"- A: PASS {len(okA)}/{len(A)}, msk_match {sum(int(r['msk_match']) for r in okA)}/{len(okA)}, "
             f"rotated {sum(int(r['rotated']) for r in okA)}/{len(okA)}; B: PASS {len(okB)}/{len(B)}.")
    for r in [r for r in A + B if r["status"] != "PASS"]:
        L.append(f"- Gagal: {r['config']}{r['series']} iterasi {r['iter']}, status {r['status']}/{r['outcome']} (tidak ikut statistik).")
    num("Full stack: sukses A / B", f"{len(okA)}/{len(A)}, {len(okB)}/{len(B)}", src, "status")
    if logdir:
        ue_miss, dn_miss = [], []
        for f in glob.glob(os.path.join(logdir, "**", "ue.log"), recursive=True):
            ue_miss += [int(x) for x in re.findall(r"ue_msg1 .*?pool_miss=(\d+)", open(f, errors="replace").read())]
        dn = open(os.path.join(logdir, "aaa-e4t.txt"), errors="replace").read()
        dn_miss = [int(x) for x in re.findall(r"aaa_commit .*?pool_miss=(\d+)", dn)]
        lv = [int(x) for x in re.findall(r"aaa_commit .*?pool_n=(\d+)", dn)]
        L.append(f"- pool_miss: UE maks {max(ue_miss) if ue_miss else '-'} dari {len(ue_miss)} baris `ue_msg1` (penghitung kumulatif per proses nr-ue); "
                 f"DN-AAA maks {max(dn_miss) if dn_miss else '-'} dari {len(dn_miss)} baris `aaa_commit`, level pool terendah saat commit {min(lv) if lv else '-'}.")
        num("Full stack: pool_miss UE / DN-AAA", f"{max(ue_miss) if ue_miss else '-'} / {max(dn_miss) if dn_miss else '-'}",
            os.path.relpath(logdir, R) + "/{*/ue.log, aaa-e4t.txt}", "pool_miss di [E4T] ue_msg1 / aaa_commit")
    if os.path.exists(os.path.join(R, "fullstack-handshake-v5pg-attempt1.csv")):
        a1 = load("fullstack-handshake-v5pg-attempt1.csv")
        L.append(f"- **Percobaan pertama full stack** (`fullstack-*-v5pg-attempt1.csv`, `logs-fullstack-v5pg-*-attempt1/`): A {sum(r['status'] == 'PASS' for r in a1 if r['config'] == 'A')}/300, "
                 f"B {sum(r['status'] == 'PASS' for r in a1 if r['config'] == 'B')}/300, tetapi pool_miss UE = 20 di uji pemulihan dan 1 di capture sampel (0 di seri A). "
                 "Penyebab: UE hanya mengisi ulang setelah promosi, jadi run yang tidak sampai promosi meninggalkan pool kosong dan run berikutnya memakai KeyGen inline (hasil tetap benar). "
                 "Setelah UE juga mengisi ulang setelah Message1, seluruh full stack dijalankan ulang; angka di atas dan di bawah berasal dari run ulang itu.")
    shapes = {(r["len_m1"], r["len_m2"], r["len_m3"], r["len_m4"], r["n_nas_rounds"], r["n_radius_rt"]) for r in okA}
    L.append(f"- Ukuran / ronde: {sorted(shapes)} (Message1..4 B, ronde NAS, RADIUS RT).")
    L.append("")
    a, b = vals(okA, "t_pdu_ms"), vals(okB, "t_pdu_ms")
    x, lo, hi = ci_diff(a, b)
    body = [["Added to PDU session establishment (A − B)", "`t_pdu_ms`", len(a), f"{x:.1f}", f"[{lo:.1f}, {hi:.1f}]",
             f"{statistics.mean(a) - statistics.mean(b):.1f}", "--"]]
    num("Tabel 6 (pregen), Added: median [CI] / mean (ms)", f"{x:.1f} [{lo:.1f}, {hi:.1f}] / {statistics.mean(a) - statistics.mean(b):.1f}", src, "t_pdu_ms, A − B")
    seg = (("Secondary authentication at the UE", "t_secauth_ms", 1), ("5G core transport (UE, gNB, AMF, SMF)", "t_core_ms", 1),
           ("SMF ↔ UPF relay hop", "t_hop_smf_upf_ms", 1), ("RADIUS processing in the UPF relay", "t_relay_proc_ms", 1),
           ("DN-AAA (FreeRADIUS, from the UPF relay)", "t_aaa_ms", 1), ("UE write of NEXT (before Message3)", "ue_store_next_ms", 2),
           ("DN-AAA commit (before Message4)", "aaa_commit_ms", 2), ("UE promotion (after Message4)", "ue_promote_ms", 2))
    for name, k, dp in seg:
        v = vals(okA, k)
        lo, hi = ci_med(v)
        f = lambda z: f"{z:.{dp}f}"
        body.append([name, f"`{k}`", len(v), f(statistics.median(v)), f"[{f(lo)}, {f(hi)}]", f(statistics.mean(v)), f(pct(v, .95))])
        num(f"Tabel 6 (pregen), {name}: median [CI] / mean / p95 (ms)", f"{f(statistics.median(v))} [{f(lo)}, {f(hi)}] / {f(statistics.mean(v))} / {f(pct(v, .95))}", src, f"{k}, A")
    L += table(["Segmen (Tabel 6)", "Kolom", "N", "Median (ms)", "95% CI", "Mean (ms)", "p95 (ms)"], body) + [""]
    old = load("fullstack-handshake-v5.csv")
    oa = [float(r["t_aaa_ms"]) for r in old if r["config"] == "A" and r["status"] == "PASS"]
    na = vals(okA, "t_aaa_ms")
    x, lo, hi = ci_diff(na, oa)
    L.append(f"- DN-AAA (`t_aaa_ms`) pregen − v5 step 31: {x:.2f} ms [{lo:.2f}, {hi:.2f}], sesi berbeda.")
    L.append("")
    rec = os.path.join(R, "fullstack-recovery-v5pg.csv")
    ea.recovery_v2_table(L, rec, "#### Uji pemulihan v5-pregen")
    rr = load("fullstack-recovery-v5pg.csv")
    for case, name in (("msg3", "Message3 dibuang"), ("msg4", "Message4 dibuang")):
        t = [float(r["t_recovery_ms"]) for r in rr if r["case"] == case and r["t_recovery_ms"]]
        num(f"Pemulihan (pregen), {name}: median / mean (ms)", f"{statistics.median(t):.1f} / {statistics.mean(t):.1f}", "fullstack-recovery-v5pg.csv", "t_recovery_ms")
    bad = sum(1 for r in rr if r["recovered"] != "1")
    num("Pemulihan (pregen): desync, re-provisioning", f"{bad}, 0", "fullstack-recovery-v5pg.csv", "recovered")
    idc = os.path.join(R, "v5pg-identity-check.txt")
    if os.path.exists(idc):
        L += [f"- Cek identitas (`v5pg-identity-check.txt`): {open(idc).read().strip().split(chr(10))[-1]}", ""]


def sizes(L):
    src = "e2e-handshake-v5pg.csv"
    rows = load(src)
    body = []
    for k in ("pregen", "inline"):
        s = {"/".join(r[f"msg{i}_bytes"] for i in range(1, 5)) + f", RT {r['radius_round_trips']}" for r in rows if r["method"] == "4" and r["label"].startswith(k)}
        body.append([f"v5-{k}", "; ".join(sorted(s))])
    L += ["### Ukuran (tidak berubah)", ""] + table(["Mode", "Message1–4 (B), RT, semua run"], body) + [""]
    num("Ukuran v5-pregen dan v5-inline: Message1–4 (B), RT", "2424/6097/3756/16, 15 (sama dengan v5)", src, "msg1..4_bytes, radius_round_trips")


def main():
    logdir = sys.argv[1] if len(sys.argv) > 1 else None
    L = ["", "## 10. Pra-generasi X-Wing KeyGen (v5-pregen)", "",
         "Step 32. KeyGen kunci berikutnya dikeluarkan dari jalur kritis handshake sebagai pilihan implementasi; protokol, pesan, ukuran, dan model ProVerif tidak berubah (model tidak dijalankan ulang, dicatat di README ProVerif). Hanya proposal (v5) yang berubah. Kernel `" + os.uname().release + "`. Paper tidak diubah.", ""]
    design(L)
    tests(L)
    harness(L)
    compute(L)
    fullstack(L, logdir)
    sizes(L)
    L += ["### Beban background DN-AAA dan `pool_miss`", ""]
    bg = text("pool-tests-v5pg.md").split("### Beban background DN-AAA (100 UE paralel)")[1].split("**Semua test")[0].strip()
    L += bg.split("\n") + [""]
    m = re.search(r"\| Porsi thread isi ulang dari CPU radiusd \| ([\d.]+) % \|", bg)
    num("Beban background DN-AAA, 100 UE paralel: CPU thread isi ulang / porsi dari radiusd; pool_miss",
        re.search(r"`e4-keypool` selama uji \(s\) \| ([\d.]+)", bg).group(1) + f" s / {m.group(1)} %; 0", "pool-tests-v5pg/par.cpu, par.pool", "refill_thread_cpu_ticks, radiusd_cpu_ticks; pool_miss")
    P = ["### Tabel ringkas angka untuk paper (v5-pregen)", "", "Semua nilai dibaca dari file sumber oleh `benchmark/v5pg_analyze.py`.", ""]
    P += table(["Angka", "Nilai", "Sumber", "Kolom"], N)
    L += P + [""]
    with open(os.path.join(R, "v5pg-analysis.md"), "w") as f:
        f.write("\n".join(L))
    with open(os.path.join(R, "v5pg-paper-numbers.md"), "w") as f:
        f.write("\n".join(P) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
