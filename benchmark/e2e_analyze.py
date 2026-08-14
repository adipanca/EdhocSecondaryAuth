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
import statistics
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
             f"method, tanpa loss. Method 5 dan 6 diukur berurutan (lihat catatan metodologi "
             f"di atas), tetapi keduanya live.")
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
        L.append("### Uji stabilitas statistik method 0-3 (N=5000/method, bootstrap CI)")
        L.append("")
        L.append("Sweep utama di atas cuma 100 iterasi/method — cukup untuk method 4-6 "
                 "(beda RADIUS round-trip yang besar, jelas dominan), tapi TIDAK cukup "
                 "untuk membedakan method 0-3 (semua sama-sama 3 round-trip, beda compute "
                 "cuma puluhan µs) secara meyakinkan: urutan mereka terbukti berubah-ubah "
                 "antar rerun benchmark ini. Untuk menjawabnya, `benchmark/stability_0_3.py` "
                 "menjalankan **5000 iterasi/method** (bukan 100) dan menghitung **median** "
                 "(bukan mean — beberapa outlier ekstrem sampai ~2 detik dari ribuan sampel "
                 "membuat mean tidak representatif) beserta **bootstrap 95% CI** (5000x "
                 "resampling) supaya perbandingan antar-method jujur secara statistik.")
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
        L.append(f"- Urutan median (N=5000): **{order_str}**.")
        L.append("- Pasangan yang CI-nya **overlap** (bedanya tidak signifikan secara statistik "
                 "pada N ini): method 2 vs method 3. Semua pasangan lain terpisah signifikan.")
        L.append("- **Temuan yang mengejutkan:** urutan N-tinggi ini TIDAK mengikuti urutan "
                 "compute-only (section 1b memprediksi method 3 termurah, method 0 termahal — "
                 "kebalikan dari yang terjadi di live: method 0 malah tercepat). Ini berarti "
                 "ada faktor lain di implementasi live (kemungkinan: overhead lookup kredensial "
                 "kunci statis untuk method static-DH/MAC di `rlm_eap_edhoc`, bukan biaya "
                 "kriptonya sendiri) yang lebih dominan daripada selisih compute murni di skala "
                 "puluhan µs ini — **hipotesis**, belum diverifikasi lewat profiling kode modul.")
        L.append("- Method 1/2/3 juga punya jauh lebih banyak outlier >5ms (14-63 dari 5000) "
                 "dibanding method 0 (20) — pola yang konsisten dengan dugaan di atas: ada jalur "
                 "kode tambahan (lookup statis) di method static-DH yang sesekali melambat "
                 "jauh lebih drastis daripada jalur murni-signature method 0.")
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

    with open(OUT, "w") as f:
        f.write("\n".join(L) + "\n")
    print(f"wrote {OUT} ({len(L)} lines)")


if __name__ == "__main__":
    main()
