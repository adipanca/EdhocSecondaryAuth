#!/usr/bin/env python3
"""
analyze.py — Point 5: generate the measurement analysis report.

Reads every CSV produced by the benchmark suite from the results directory and
writes a consolidated Markdown report (analysis.md) with per-method comparison
tables and interpretation. Missing inputs are skipped gracefully so the report
can be regenerated at any time.

Usage: analyze.py <results_dir>
"""
import csv
import os
import sys
from datetime import datetime


def read_csv(path):
    if not os.path.exists(path):
        return None
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def md_table(rows, cols, headers=None):
    headers = headers or cols
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |")
    return "\n".join(out)


def section_primitives(rd):
    rows = read_csv(os.path.join(rd, "crypto-primitives.csv"))
    if not rows:
        return None
    body = md_table(
        rows,
        ["operation", "library", "iterations", "mean_ns", "median_ns",
         "p95_ns", "p99_ns", "stddev_ns"],
        ["Operation", "Lib", "Iter", "Mean (ns)", "Median (ns)",
         "p95 (ns)", "p99 (ns)", "Stddev (ns)"])
    return ("## 1a. Breakdown komputasi primitif kriptografi\n\n"
            "Latensi per operasi primitif (pengukuran nyata, libsodium + "
            "mbedTLS + PQClean).\n\n"
            + body + "\n")


def section_breakdown(rd):
    rows = read_csv(os.path.join(rd, "crypto-breakdown.csv"))
    comp = read_csv(os.path.join(rd, "handshake-compute.csv"))
    if not rows:
        return None
    # rows/comp are appended by different scripts at different times (0..4 by
    # crypto_bench.c, 5 by rsa_bench.py, 6 by compute_tls_hybrid.py), so file
    # order isn't numeric method order -- sort for a readable table (stable
    # sort preserves each method's own initiator/responder row order).
    rows = sorted(rows, key=lambda r: int(r["method"]))
    if comp:
        comp = sorted(comp, key=lambda r: int(r["method"]))
    parts = ["## 1b. Breakdown komputasi per method (Keygen, Scalar mult, "
             "Encaps, Decaps, Signature, Verify)\n",
             "Kontribusi waktu komputasi tiap operasi dalam satu handshake "
             "(initiator = UE, responder = DN-AAA). Untuk EAP-TLS (method "
             "5/6), Verify = 2 per pihak: CertificateVerify + tanda tangan CA "
             "pada sertifikat peer (rantai root CA -> end-entity, tanpa "
             "intermediate). EDHOC (method 0-4) tidak memakai sertifikat. "
             "Method 4: Keygen = 3 per pihak (X25519 ephemeral di dalam "
             "encapsulation X-Wing + pasangan kunci rotasi X25519/ML-KEM-768 "
             "untuk EAD3/EAD4), semuanya dihitung di dalam handshake.\n",
             md_table(rows,
                      ["method", "role", "operation", "primitive",
                       "op_count", "compute_ns"],
                      ["Method", "Role", "Operation", "Primitive",
                       "Count", "Compute (ns)"])]
    if comp:
        parts += ["\n### Total komputasi handshake per method\n",
                  md_table(comp,
                           ["method", "profile", "initiator_compute_us",
                            "responder_compute_us", "total_compute_us"],
                           ["Method", "Profil", "Initiator (us)",
                            "Responder (us)", "Total (us)"])]
        # cheapest / most expensive
        try:
            srt = sorted(comp, key=lambda r: float(r["total_compute_us"]))
            parts.append(
                f"\n- Termurah secara komputasi: **method {srt[0]['method']}** "
                f"({srt[0]['profile']}, {srt[0]['total_compute_us']} us).")
            parts.append(
                f"- Termahal secara komputasi: **method {srt[-1]['method']}** "
                f"({srt[-1]['profile']}, {srt[-1]['total_compute_us']} us).")
            parts.append(
                "\n> **Peringatan baca:** urutan termurah/termahal di atas HANYA "
                "waktu komputasi kripto murni (µs) — TIDAK termasuk round-trip "
                "jaringan RADIUS/fragmentasi EAP. Urutan itu BUKAN urutan "
                "kecepatan handshake end-to-end nyata. Untuk urutan yang "
                "sebenarnya dialami pengguna (termasuk RTT), lihat "
                "`analisys2.md` section 1c — di sana method 6 (EAP-TLS Hybrid "
                "PQC) adalah yang paling lambat secara live, bukan method 4, "
                "justru karena jumlah round-trip fragmentasi EAP-nya yang jauh "
                "lebih banyak, sesuatu yang tidak tertangkap oleh tabel compute "
                "murni ini.")
        except (ValueError, KeyError):
            pass
    extra = op_tables(rd)
    if extra:
        parts.append(extra)
    return "\n".join(parts) + "\n"


# Operations per handshake, (initiator, responder), as in the paper's
# tab:opcount. sig/ver are Ed25519 at the classical level and ML-DSA-44 at
# the hybrid level; EAP-TLS verify = CertificateVerify + peer certificate.
# Each X25519 key pair is ephemeral; static-DH authentication costs one DH
# on each side (edhoc03.c). Method 4: one X25519 key pair is the ephemeral
# share inside Encaps, the other plus the ML-KEM key pair is the rotation key.
OPS = {
    0: dict(xk=(1, 1), dh=(1, 1), sdh=(0, 0), kk=(0, 0), enc=(0, 0), dec=(0, 0), sig=(1, 1), ver=(1, 1), cert=(0, 0), rot=(0, 0), pq=False),
    1: dict(xk=(1, 1), dh=(1, 1), sdh=(1, 1), kk=(0, 0), enc=(0, 0), dec=(0, 0), sig=(1, 0), ver=(0, 1), cert=(0, 0), rot=(0, 0), pq=False),
    2: dict(xk=(1, 1), dh=(1, 1), sdh=(1, 1), kk=(0, 0), enc=(0, 0), dec=(0, 0), sig=(0, 1), ver=(1, 0), cert=(0, 0), rot=(0, 0), pq=False),
    3: dict(xk=(1, 1), dh=(1, 1), sdh=(2, 2), kk=(0, 0), enc=(0, 0), dec=(0, 0), sig=(0, 0), ver=(0, 0), cert=(0, 0), rot=(0, 0), pq=False),
    4: dict(xk=(1, 1), dh=(2, 2), sdh=(0, 0), kk=(0, 0), enc=(1, 1), dec=(1, 1), sig=(1, 1), ver=(1, 1), cert=(0, 0), rot=(1, 1), pq=True),
    5: dict(xk=(1, 1), dh=(1, 1), sdh=(0, 0), kk=(0, 0), enc=(0, 0), dec=(0, 0), sig=(1, 1), ver=(1, 1), cert=(1, 1), rot=(0, 0), pq=False),
    6: dict(xk=(1, 1), dh=(1, 1), sdh=(0, 0), kk=(1, 0), enc=(0, 1), dec=(1, 0), sig=(1, 1), ver=(1, 1), cert=(1, 1), rot=(0, 0), pq=True),
}


def op_tables(rd):
    prim = {r["operation"]: float(r["mean_ns"]) / 1e6
            for r in read_csv(os.path.join(rd, "crypto-primitives.csv"))}
    try:
        xk, dh, kk = prim["Keygen_X25519"], prim["ScalarMult_X25519"], prim["Keygen_MLKEM768"]
        enc, dec = prim["Encaps_MLKEM768"], prim["Decaps_MLKEM768"]
    except KeyError:
        return None
    out = ["\n### Operasi kriptografi per method (Initiator/Responder)\n",
           "| Method | X25519 KeyGen | X25519 DH | ML-KEM KeyGen | Encaps | Decaps | Sign | Verify |",
           "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    groups = {}
    for m, o in OPS.items():
        sg = prim["Signature_MLDSA44" if o["pq"] else "Signature_Ed25519"]
        vf = prim["Verify_MLDSA44" if o["pq"] else "Verify_Ed25519"]
        f = lambda k: "/".join(str(v) for v in o[k]) if any(o[k]) else "-"
        pair = lambda *ks: "/".join(str(sum(o[k][i] for k in ks)) for i in range(2)) \
            if any(sum(o[k][i] for k in ks) for i in range(2)) else "-"
        out.append(f"| {m} | {pair('xk', 'rot')} | {pair('dh', 'sdh')} | {pair('kk', 'rot')} | "
                   f"{f('enc')} | {f('dec')} | {f('sig')} | {pair('ver', 'cert')} |")
        t = lambda k: sum(o[k])
        groups[m] = (t("xk") * xk + t("dh") * dh + t("kk") * kk + t("enc") * enc + t("dec") * dec,
                     t("sig") * sg + t("ver") * vf + t("sdh") * dh,
                     t("cert") * vf,
                     t("rot") * (xk + kk))
    out += ["\n### Komputasi per fungsi (kedua pihak, ms)\n",
            "Key exchange: share X25519 ephemeral, DH ephemeral, operasi KEM. "
            "Authentication: tanda tangan transcript dan verifikasinya, atau static DH. "
            "Certificate check: tanda tangan CA pada sertifikat peer. "
            "Key rotation: pasangan kunci X-Wing one-time berikutnya.\n",
            "| Method | Key exchange | Authentication | Certificate check | Key rotation | Total |",
            "| --- | --- | --- | --- | --- | --- |"]
    for m, g in groups.items():
        out.append(f"| {m} | " + " | ".join(f"{v:.3f}" if v else "-" for v in g)
                   + f" | {sum(g):.3f} |")
    # same precompute rule for both hybrid protocols
    p4, p6 = sum(groups[4]), sum(groups[6])
    out += ["\n### Kebijakan precompute yang sama untuk kedua protokol\n",
            "| Aturan (sama untuk kedua sisi) | Proposal (ms) | EAP-TLS Hybrid (ms) |",
            "| --- | --- | --- |",
            f"| Semua keygen di dalam handshake | {p4:.3f} | {p6:.3f} |",
            f"| Hanya \"kunci berikutnya\" di muka (kunci rotasi proposal <-> key share client TLS) "
            f"| {p4 - 2 * (xk + kk):.3f} | {p6 - (xk + kk):.3f} |",
            f"| Semua keygen yang tidak bergantung sesi di muka (termasuk share X25519 ephemeral) "
            f"| {p4 - 2 * (xk + kk) - 2 * xk:.3f} | {p6 - (xk + kk) - xk:.3f} |",
            "\nDengan aturan yang sama, komputasi kedua protokol hampir sama; "
            "perbedaannya ada di transport."]
    return "\n".join(out)


def section_lossy(rd):
    rows = read_csv(os.path.join(rd, "lossy-network.csv"))
    if not rows:
        return None
    rows = sorted(rows, key=lambda r: (int(r["method"]), float(r["loss_pct"])))
    body = md_table(
        rows,
        ["method", "loss_pct", "success_rate_pct", "mean_handshake_ms",
         "p95_handshake_ms", "mean_retransmits"],
        ["Method", "Loss %", "Success %", "Mean (ms)", "p95 (ms)", "Mean retx"])
    return ("## 2. Performa pada jaringan lossy (simulasi 2-round-trip, semua method)\n\n"
            "Handshake 2-round-trip (message_1→message_2, message_3→message_4/ack) "
            "gaya EAP dengan retransmisi, di atas socket UDP nyata; ukuran payload "
            "per method sesuai `edhoc_sizes.py` (method 0-4 model dari elemen kripto, "
            "method 5-6 byte nyata hasil observasi live), loss diemulasi di level "
            "aplikasi. Mencakup method 0-6.\n\n"
            + body +
            "\n> **Keterbatasan penting:** skrip ini SELALU 2 round-trip jaringan "
            "berapa pun ukuran pesannya — TIDAK memodelkan fragmentasi EAP (RFC "
            "3579/5216), sehingga TIDAK menangkap efek amplifikasi paparan-loss dari "
            "pesan besar yang sebenarnya terpecah jadi banyak fragmen/round-trip "
            "(tiap fragmen = satu kesempatan tambahan kena loss). Efek itu justru "
            "yang paling penting untuk method 4/6 (pesan besar, banyak fragmen) — "
            "lihat perbedaannya sendiri: method 6 di sini terlihat *tangguh* (95.8% "
            "sukses di loss 30%) padahal live sungguhan lewat RADIUS (`analisys2.md` "
            "section 2, dengan fragmentasi EAP nyata dan 28 round-trip) cuma ~79% di "
            "loss yang sama. Bagian ini berguna sebagai pembanding \"loss resilience "
            "pada ukuran payload asli, RTT tetap\" — bukan pengganti section 2 di "
            "`analisys2.md` yang memasukkan efek fragmentasi nyata.\n")


def section_interop(rd):
    rows = read_csv(os.path.join(rd, "interop.csv"))
    if not rows:
        return None
    body = md_table(rows, ["check", "result", "detail"],
                    ["Pemeriksaan", "Hasil", "Detail"])
    n_pass = sum(1 for r in rows if r.get("result") == "PASS")
    return ("## 3. Interoperabilitas dengan implementasi EDHOC\n\n"
            "Primitif cipher-suite EDHOC divalidasi silang terhadap "
            "implementasi independen (pyca/cryptography, backend OpenSSL).\n\n"
            f"Lolos {n_pass}/{len(rows)} pemeriksaan.\n\n" + body + "\n")


_MSG_ORDER = {"message_1": 1, "message_2": 2, "message_3": 3, "message_4": 4}


def section_mtu(rd):
    rows = read_csv(os.path.join(rd, "mtu-fragmentation.csv"))
    if not rows:
        return None
    rows = sorted(rows, key=lambda r: (int(r["method"]),
                                       _MSG_ORDER.get(r["message"], 9)))
    body = md_table(
        rows,
        ["method", "message", "size_bytes", "eap_message_attrs",
         "eap_fragments", "ip_fragments", "exceeds_mtu"],
        ["Method", "Pesan", "Bytes", "EAP attrs", "EAP frags",
         "IP frags", ">MTU"])
    # Split fragmenting methods into "heavy" (multi-fragment, PQC-driven: 4, 6)
    # vs "light" (fragments once or twice at most, nothing to do with PQC: 5,
    # whose Ed25519 certs are just slightly bigger than raw EDHOC's CBOR) so
    # the explanation doesn't misattribute method 5's mild fragmentation to
    # XWING/ML-DSA elements it doesn't even use.
    by_method_max_frag = {}
    for r in rows:
        m = r["method"]
        by_method_max_frag[m] = max(by_method_max_frag.get(m, 1), int(r["eap_fragments"]))
    heavy = sorted((m for m, f in by_method_max_frag.items() if f >= 3), key=int)
    light = sorted((m for m, f in by_method_max_frag.items() if 1 < f < 3), key=int)
    note = ""
    if heavy:
        note += (f"\nFragmentasi berat (banyak fragmen EAP) terjadi pada method "
                 f"{', '.join(heavy)} — profil PQC (XWING/ML-KEM-768 hybrid key "
                 f"establishment dan/atau sertifikat ML-DSA-44), karena elemen "
                 f"KEM/tanda-tangan PQC menambah ~1.1-2.4 KB per elemen. Method 6's "
                 f"baris di sini memakai byte yang **benar-benar diobservasi** dari "
                 f"handshake live (bukan model — `edhoc_sizes.py`, sama seperti "
                 f"method 5), karena model murni sebelumnya meleset cukup jauh "
                 f"(~2.5x lebih kecil dari yang sebenarnya, akibat framing X.509 "
                 f"penuh yang sulit dimodelkan tanpa observasi langsung).\n")
    if light:
        note += (f"\nFragmentasi ringan (2 fragmen EAP maksimum) terjadi pada method "
                 f"{', '.join(light)} — ini **bukan** soal PQC: method 5 memakai "
                 f"Ed25519 (bukan ML-KEM/ML-DSA sama sekali), fragmentasinya semata "
                 f"karena framing TLS record + X.509 (rantai sertifikat CA+server) "
                 f"sedikit lebih besar dari CBOR EDHOC yang sangat ringkas.\n")
    return ("## 4. Pengaruh ukuran paket terhadap MTU dan fragmentasi\n\n"
            "Ukuran pesan method 0-4 dihitung dari elemen kripto nyata (model, "
            "`edhoc_sizes.py`); method 5-6 memakai byte yang **benar-benar "
            "diobservasi** dari handshake live (`rsa_bench.py` / "
            "`compute_tls_hybrid.py`, sama-sama bersumber dari "
            "`e2e-handshake.csv`). Fragmentasi EAP (RFC 3579, atribut 253 B) "
            "dan IP (MTU 1500) diturunkan darinya untuk semua method. Lihat "
            "`analisys2.md` section 4 untuk tabel yang sama persis, sepenuhnya "
            "diobservasi langsung dari handshake live method 0-6.\n\n"
            + body + note)


def section_e2e(rd):
    rows = read_csv(os.path.join(rd, "benchmark.csv"))
    if not rows:
        return None
    body = md_table(rows[-10:],
                    list(rows[0].keys()),
                    list(rows[0].keys()))
    passes = sum(1 for r in rows if r.get("status") == "PASS")
    return ("## 1c. Handshake secondary authentication P2P (end-to-end 5G)\n\n"
            f"Jalur live 5G (UERANSIM UE -> AMF -> SMF -> UPF -> FreeRADIUS). "
            f"PASS {passes}/{len(rows)} iterasi.\n\n"
            "10 baris terakhir:\n\n" + body + "\n")


def main():
    rd = sys.argv[1] if len(sys.argv) > 1 else "."
    out = os.path.join(rd, "analysis.md")

    header = (f"# Analisis Hasil Pengukuran EAP-EDHOC Secondary Authentication\n\n"
              f"_Dibuat otomatis oleh benchmark/analyze.py pada "
              f"{datetime.now().isoformat(timespec='seconds')}._\n\n"
              "Method matrix:\n\n"
              "| Method | Initiator | Responder | Profil kripto |\n"
              "| --- | --- | --- | --- |\n"
              "| 0 | SIG (Ed25519) | SIG (Ed25519) | Ed25519 |\n"
              "| 1 | SIG (Ed25519) | MAC (static-DH X25519) | Ed25519 + X25519 |\n"
              "| 2 | MAC (static-DH X25519) | SIG (Ed25519) | X25519 + Ed25519 |\n"
              "| 3 | MAC (static-DH X25519) | MAC (static-DH X25519) | X25519 |\n"
              "| 4 | SIGMA (ML-DSA-44) | SIGMA (ML-DSA-44) | XWING (X25519 + ML-KEM-768) + ML-DSA-44 (PQC) |\n"
              "| 5 | EAP-TLS Classic (mutual, Ed25519) | EAP-TLS Classic (mutual, Ed25519) | X25519 ECDHE + Ed25519 (classical TLS) |\n"
              "| 6 | EAP-TLS Hybrid PQC (X25519MLKEM768 + ML-DSA-44) | EAP-TLS Hybrid PQC (X25519MLKEM768 + ML-DSA-44) | X25519MLKEM768 hybrid KEM + ML-DSA-44 (PQC) |\n\n"
              "> **Catatan metodologi:** `analysis.md` (dokumen ini) adalah pandangan "
              "primitif/komputasi murni, independen terhadap transport, untuk SEMUA method "
              "0-6 secara konsisten (section 1a/1b/4 di bawah memakai model/komputasi, bukan "
              "byte yang benar-benar diobservasi di kabel, untuk method manapun) — ini "
              "pilihan desain dokumen ini, bukan keterbatasan. Method 6 (EAP-TLS Hybrid PQC) "
              "SEKARANG JUGA diukur end-to-end secara live melalui EAP-over-RADIUS nyata "
              "(liboqs + oqs-provider terpasang, tls-config ML-DSA-44 + grup hybrid "
              "X25519MLKEM768 dipakai oleh `rlm_eap_tls`) — lihat `analisys2.md` untuk angka "
              "live-nya (section 1c/2), yang membandingkannya langsung dengan method 4 "
              "(SIGMA-XWING PQC) dan method 5 (EAP-TLS Classic).\n")

    sections = [
        header,
        section_e2e(rd),
        section_primitives(rd),
        section_breakdown(rd),
        section_lossy(rd),
        section_interop(rd),
        section_mtu(rd),
    ]
    body = "\n".join(s for s in sections if s)

    with open(out, "w") as f:
        f.write(body)
    print(f"[analyze] wrote {out}")


if __name__ == "__main__":
    main()
