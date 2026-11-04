#!/usr/bin/env python3
"""
v4_identity_check.py — protocol v4: the SUPI and the old DN-specific
identity must not appear in RADIUS (User-Name, EAP-Message) nor in any
EAP-Response/Identity. Checks the sample capture and the logs of a
full-stack run (fullstack_bench.sh) and writes a short report.

  v4_identity_check.py <logs-fullstack-dir> <out.txt>
"""
import os
import subprocess
import sys

SUPI_DIGITS = "999700000000001"
NEEDLES = {"SUPI (imsi-999700000000001)": [b"imsi-" + SUPI_DIGITS.encode(), SUPI_DIGITS.encode()],
           "old DN identity (ue1@edhoc.internet)": [b"ue1@edhoc.internet"]}


def tshark(pcap, filt, fields):
    cmd = ["tshark", "-r", pcap, "-o", "nas-5gs.null_decipher:TRUE", "-Y", filt, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.split("\n")


def raw_frames(pcap, filt):
    """raw bytes of each matching frame"""
    out = subprocess.run(["tshark", "-r", pcap, "-Y", filt, "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True, check=True).stdout.split()
    data = subprocess.run(["tshark", "-r", pcap, "-Y", filt, "-T", "fields", "-e", "data.data",
                           "-e", "udp.payload"], capture_output=True, text=True, check=True).stdout
    return len(out), bytes.fromhex("".join(c for c in data if c in "0123456789abcdefABCDEF"))


def main():
    d, out = sys.argv[1], sys.argv[2]
    pcap = os.path.join(d, "capture.pcap")
    lines = [f"# v4 identity check: {os.path.basename(d)}"]

    users = sorted({u for u in tshark(pcap, "radius", ["radius.User_Name"]) if u})
    eap_ids = sorted({u for u in tshark(pcap, "eap.type == 1 && eap.code == 2", ["eap.identity"]) if u})
    nas_ids = sorted({u for u in tshark(pcap, "nas-5gs && eap.type == 1 && eap.code == 2", ["eap.identity"]) if u})
    lines.append(f"RADIUS User-Name values in capture.pcap      : {users}")
    lines.append(f"EAP-Response/Identity values (all)           : {eap_ids}")
    lines.append(f"EAP-Response/Identity in NAS (UE -> SMF)     : {nas_ids}")

    n_rad, rad = raw_frames(pcap, "udp.port == 1812 || udp.port == 3870")
    for name, needles in NEEDLES.items():
        hit = any(n in rad for n in needles)
        lines.append(f"{name:<44} in the {n_rad} RADIUS/relay packets: {'FOUND' if hit else 'absent'}")

    # DN-AAA logs of the run (the UPF/SMF logs also carry the SUPI for PFCP and
    # SBI, which is not RADIUS)
    for name, needles in NEEDLES.items():
        hits = []
        for root, _, files in os.walk(d):
            for f in files:
                if f in ("aaa-e4t.txt", "radiusd.log"):
                    with open(os.path.join(root, f), "rb") as fh:
                        if any(n in fh.read() for n in needles):
                            hits.append(os.path.relpath(os.path.join(root, f), d))
        lines.append(f"{name:<44} in aaa-e4t.txt / radiusd.log: "
                     + (", ".join(sorted(hits)) if hits else "absent"))
    ok = (users and all(u in ("@edhoc.internet", "anonymous@edhoc.internet") for u in users + eap_ids)
          and not any("FOUND" in l for l in lines)
          and all(l.endswith("absent") for l in lines if "in aaa-e4t" in l))
    lines.append(f"RESULT: {'PASS' if ok else 'FAIL'} (only the anonymous NAI appears)")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
