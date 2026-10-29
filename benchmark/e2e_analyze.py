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

    with open(OUT, "w") as f:
        f.write("\n".join(L) + "\n")
    print(f"wrote {OUT} ({len(L)} lines)")


if __name__ == "__main__":
    main()
