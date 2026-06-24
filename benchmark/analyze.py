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
    parts = ["## 1b. Breakdown komputasi per method (Keygen, Scalar mult, "
             "Encaps, Decaps, Signature, Verify)\n",
             "Kontribusi waktu komputasi tiap operasi dalam satu handshake "
             "(initiator = UE, responder = DN-AAA).\n",
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
        except (ValueError, KeyError):
            pass
    return "\n".join(parts) + "\n"


def section_lossy(rd):
    rows = read_csv(os.path.join(rd, "lossy-network.csv"))
    if not rows:
        return None
    body = md_table(
        rows,
        ["method", "loss_pct", "success_rate_pct", "mean_handshake_ms",
         "p95_handshake_ms", "mean_retransmits"],
        ["Method", "Loss %", "Success %", "Mean (ms)", "p95 (ms)", "Mean retx"])
    return ("## 2. Performa pada jaringan lossy\n\n"
            "Handshake 3-pesan EDHOC dengan retransmisi gaya EAP; loss "
            "diemulasi di level aplikasi pada socket UDP nyata.\n\n"
            + body + "\n")


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


def section_mtu(rd):
    rows = read_csv(os.path.join(rd, "mtu-fragmentation.csv"))
    if not rows:
        return None
    body = md_table(
        rows,
        ["method", "message", "size_bytes", "eap_message_attrs",
         "eap_fragments", "ip_fragments", "exceeds_mtu"],
        ["Method", "Pesan", "Bytes", "EAP attrs", "EAP frags",
         "IP frags", ">MTU"])
    frag = [r for r in rows if int(r["eap_fragments"]) > 1 or r["exceeds_mtu"] == "yes"]
    note = ""
    if frag:
        methods = sorted({r["method"] for r in frag})
        note = (f"\nPesan yang memerlukan fragmentasi terdapat pada "
                f"method {', '.join(methods)} (profil PQC XWING), karena "
                f"ML-KEM-768 menambah ~1–1.2 KB per pesan.\n")
    return ("## 4. Pengaruh ukuran paket terhadap MTU dan fragmentasi\n\n"
            "Ukuran pesan dihitung dari elemen kripto nyata; fragmentasi EAP "
            "(RFC 3579, atribut 253 B) dan IP (MTU 1500) diturunkan darinya.\n\n"
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
              "| 4 | MAC (static-XWING) | MAC (static-XWING) | X25519 + ML-KEM-768 (PQC) |\n")

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
