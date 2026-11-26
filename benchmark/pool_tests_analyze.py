#!/usr/bin/env python3
"""pool_tests_analyze.py — summary of benchmark/pool_tests.sh.

Reads benchmark-results/pool-tests-v5pg/ and writes pool-tests-v5pg.md next
to it: per test the UE result, the DN-AAA pool counters (shutdown line of
rlm_eap_edhoc), key uniqueness from the --dump-keys files, the lowest pool
level seen at a commit, and the refill thread CPU in the parallel test.
"""
import glob
import os
import re
import sys

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "benchmark-results")
D = os.path.join(R, "pool-tests-v5pg")


def read(name):
    p = os.path.join(D, name)
    return open(p).read().strip() if os.path.exists(p) else ""


def keys(paths):
    rows = []
    for p in paths:
        for line in open(p):
            run, ok, dropped, fa, fb, wiped = line.strip().split(",")
            rows.append(dict(ok=int(ok), dropped=int(dropped), fa=fa, fb=fb, wiped=int(wiped)))
    return rows


def pool(name):
    """counters of the DN-AAA shutdown line"""
    s = read(name + ".pool")
    m = re.search(r"\((\w+), size (\d+)\): taken (\d+), pool_miss (\d+), inline (\d+), refilled (\d+), refill CPU ([\d.]+)", s)
    if not m:
        return None
    k = ("mode", "size", "taken", "miss", "inline", "refilled", "cpu_us")
    return dict(zip(k, m.groups()))


def ue(name):
    s = read(name + ".ue").splitlines()
    s = [l for l in s if l.startswith("==")]
    m = re.search(r"(\d+)/(\d+) PASS.*next_keygen=(\w+) pool_taken=(\d+) pool_miss=(\d+) inline=(\d+)", s[-1]) if s else None
    return dict(zip(("pass", "n", "mode", "taken", "miss", "inline"), m.groups())) if m else None


def min_level(name):
    lv = [int(x) for x in re.findall(r"pool_n=(\d+)", read(name + ".e4t"))]
    return min(lv) if lv else None


def uniq(rows, field):
    v = [r[field] for r in rows if r[field]]
    return len(v), len(set(v))


def main():
    L = ["# Test pool kunci berikutnya (live, v5-pregen)", "",
         f"Kernel `{read('uname.txt')}`. Sumber: `benchmark/pool_tests.sh`, mentah di `benchmark-results/pool-tests-v5pg/`.",
         "UE = `e2e_radius_bench` (pool satu kunci, diisi sebelum jam mulai); DN-AAA = radiusd dengan `xwing_pool_size` 64 kecuali disebut lain.",
         "Penghitung DN-AAA dari baris yang ditulis `rlm_eap_edhoc` saat radiusd berhenti.", "",
         "| Test | UE: sukses | UE: pool_miss | DN-AAA: mode, ukuran | DN-AAA: diambil / pool_miss / inline | Keunikan dan catatan | Hasil |",
         "|---|---|---|---|---|---|---|"]
    ok_all = True

    def row(test, name, note, ok):
        nonlocal ok_all
        u, p = ue(name), pool(name)
        ok_all &= ok
        L.append(f"| {test} | {u['pass']}/{u['n']} | {u['miss']} | {p['mode']}, {p['size']} | "
                 f"{p['taken']} / {p['miss']} / {p['inline']} | {note} | {'PASS' if ok else 'FAIL'} |")
        return u, p

    s = keys([os.path.join(D, "seq.keys")])
    na, ua = uniq(s, "fa")
    nb, ub = uniq(s, "fb")
    both = [r["fa"] for r in s] + [r["fb"] for r in s]
    u, p = ue("seq"), pool("seq")
    ok = u["pass"] == u["n"] and na == ua and nb == ub and len(set(both)) == len(both) and u["miss"] == "0" and p["miss"] == "0"
    row(f"{u['n']} handshake berurutan, pregen", "seq",
        f"Npk_A {ua}/{na} unik, Npk_B {ub}/{nb} unik, tidak ada Npk_A = Npk_B", ok)

    d = keys([os.path.join(D, "drop2.keys")])
    ok = (len(d) == 2 and d[0]["dropped"] == 1 and d[1]["ok"] == 1 and d[0]["fa"] != d[1]["fa"]
          and all(r["wiped"] for r in d) and d[0]["fb"] == "")
    row("Message2 dibuang, lalu run baru", "drop2",
        "run ulang memakai Npk_A baru; Nsk_A = 0 di ctx yang dihapus (UE); Message2 tidak pernah diproses, jadi tidak ada Npk_B", ok)

    par = keys(sorted(glob.glob(os.path.join(D, "par-ue*.keys"))))
    allk = [r["fa"] for r in par] + [r["fb"] for r in par if r["fb"]]
    dup = len(allk) - len(set(allk))
    ues = [ue(os.path.basename(f)[:-3]) for f in sorted(glob.glob(os.path.join(D, "par-ue*.ue")))]
    n_ok = sum(int(x["pass"]) for x in ues)
    n_all = sum(int(x["n"]) for x in ues)
    ue_miss = sum(int(x["miss"]) for x in ues)
    p = pool("par")
    lvl = min_level("par")
    cpu = dict(kv.split("=") for kv in read("par.cpu").split())
    ok = n_ok == n_all and dup == 0
    L.append(f"| {len(ues)} UE paralel × {n_all // max(len(ues), 1)} run, pregen 64 | {n_ok}/{n_all} | {ue_miss} | {p['mode']}, {p['size']} | "
             f"{p['taken']} / {p['miss']} / {p['inline']} | {len(allk)} kunci (Npk_A dan Npk_B), dipakai dua kali: {dup}; "
             f"level pool terendah saat commit: {lvl} | {'PASS' if ok else 'FAIL'} |")
    ok_all &= ok

    u, p = ue("size0"), pool("size0")
    row("`xwing_pool_size = 0`", "size0", f"setiap pengambilan jatuh ke KeyGen inline ({p['miss']} pool_miss = jumlah run)",
        u["pass"] == u["n"] and p["miss"] == u["n"] and p["taken"] == "0")

    u1, p1 = ue("restart-1"), pool("restart-1")
    u2, p2 = ue("restart-2"), pool("restart-2")
    st = read("restart-2.start")
    m = re.search(r"pool (\d+) key\(s\) ready in ([\d.]+) ms", st)
    ok = u1["pass"] == u1["n"] and u2["pass"] == u2["n"] and m and m.group(1) == "64"
    ok_all &= bool(ok)
    L.append(f"| Restart radiusd | {u1['pass']}/{u1['n']} sebelum, {u2['pass']}/{u2['n']} sesudah | {int(u1['miss']) + int(u2['miss'])} | "
             f"{p2['mode']}, {p2['size']} | {p2['taken']} / {p2['miss']} / {p2['inline']} (sesudah) | "
             f"pool dibuat ulang saat start: {m.group(1)} kunci dalam {m.group(2)} ms | {'PASS' if ok else 'FAIL'} |")

    u, p = ue("inline"), pool("inline")
    sizes = set()
    for line in open(os.path.join(D, "inline.csv")):
        f = line.split(",")
        if f[0] == "inline":
            sizes.add("/".join(f[15:19]))
    row("Mode inline (UE dan DN-AAA)", "inline", f"ukuran Message1–4: {', '.join(sorted(sizes))} B; pool tidak dipakai",
        u["pass"] == u["n"] and p["taken"] == "0" and p["inline"] == u["n"] and sizes == {"2424/6097/3756/16"})

    tck = int(cpu["clk_tck"])
    L += ["", "### Beban background DN-AAA (100 UE paralel)", "",
          "| Ukuran | Nilai |", "|---|---|",
          f"| Durasi uji (s) | {float(cpu['wall_s']):.2f} |",
          f"| CPU radiusd selama uji (s) | {int(cpu['radiusd_cpu_ticks']) / tck:.2f} |",
          f"| CPU thread isi ulang `e4-keypool` selama uji (s) | {int(cpu['refill_thread_cpu_ticks']) / tck:.2f} |",
          f"| Porsi thread isi ulang dari CPU radiusd | {100 * int(cpu['refill_thread_cpu_ticks']) / max(int(cpu['radiusd_cpu_ticks']), 1):.1f} % |",
          f"| Kunci dibuat thread isi ulang | {p['refilled'] if (p := pool('par')) else '-'} |",
          f"| CPU per kunci, thread isi ulang (µs) | {p['cpu_us']} |",
          f"| Pool pernah habis (pool_miss) | {p['miss']} |",
          f"| Level pool terendah saat commit | {lvl} dari 64 |", "",
          f"CPU per kunci di thread isi ulang lebih tinggi di bawah beban paralel ({p['cpu_us']} µs) daripada pada uji berurutan ({pool('seq')['cpu_us']} µs). Penyebabnya tidak diukur terpisah; thread itu berjalan dengan nice 19 bersama thread radiusd lain. CPU ini dipakai di luar pemrosesan pesan, tetapi tetap memakai core yang sama dengan radiusd.",
          "", f"**Semua test: {'PASS' if ok_all else 'FAIL'}**", ""]
    open(os.path.join(R, "pool-tests-v5pg.md"), "w").write("\n".join(L))
    print("\n".join(L))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
