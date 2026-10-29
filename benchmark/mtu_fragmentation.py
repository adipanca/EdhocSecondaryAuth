#!/usr/bin/env python3
"""
mtu_fragmentation.py — Point 4: effect of packet size on MTU and fragmentation.

For each EDHOC method and message it computes:
  - EAP fragmentation : EAP-Message RADIUS attributes carry <=253 bytes each
                        (RFC 3579 §3.1) -> number of EAP-Message attributes.
  - EAP packets       : EAP fragmentation -> number of EAP request/response
                        round trips needed to ship one message: the live
                        EAP-EDHOC fragmenter (997/999 bytes) for method 4,
                        a typical 1020-byte fragment size otherwise.
  - IP fragmentation  : whether the UDP/IP datagram (message + UDP/IP headers)
                        exceeds the link MTU (default 1500) and into how many
                        IP fragments it splits.

Writes <outdir>/mtu-fragmentation.csv. If <outdir>/e2e-handshake.csv exists,
the method-4 sizes and EAP fragments are checked against the live run.
"""
import csv
import math
import os
import sys

from edhoc_sizes import METHODS, PROFILE, edhoc4_eap_fragments, message_sizes

IP_MTU = 1500
IP_HDR = 20
UDP_HDR = 8
IP_PAYLOAD = IP_MTU - IP_HDR              # usable per IP fragment
RADIUS_EAP_ATTR = 253                     # RFC 3579 EAP-Message attribute limit
EAP_FRAG_SIZE = 1020                      # typical EAP-EDHOC fragment MTU


def ip_fragments(datagram_payload: int) -> int:
    total = datagram_payload + UDP_HDR
    # first fragment carries IP_PAYLOAD bytes (incl. UDP header), rest IP_PAYLOAD
    if total <= IP_PAYLOAD:
        return 1
    # IP fragment payload must be multiple of 8; approximate by ceil
    return math.ceil(total / (IP_PAYLOAD - (IP_PAYLOAD % 8)))


def eap_fragments(method: int, sz: int) -> int:
    if method == 4:
        return edhoc4_eap_fragments(sz)
    return math.ceil(sz / EAP_FRAG_SIZE)


def check_live(outdir: str) -> None:
    """Method 4: model sizes and EAP fragments must equal the live run."""
    live = os.path.join(outdir, "e2e-handshake.csv")
    if not os.path.exists(live):
        return
    with open(live, newline="") as f:
        row = next((r for r in csv.DictReader(f)
                    if r["method"] == "4" and r["status"] == "PASS"), None)
    if row is None:
        return
    model = message_sizes(4)
    bad = []
    for i in range(1, 5):
        sz = model[f"message_{i}"]
        got = (int(row[f"msg{i}_bytes"]), int(row[f"msg{i}_frags"]))
        if (sz, eap_fragments(4, sz)) != got:
            bad.append(f"message_{i}: model {sz} B/{eap_fragments(4, sz)} live {got[0]} B/{got[1]}")
    if bad:
        sys.exit("[mtu_fragmentation] method 4 model != live: " + "; ".join(bad))
    print(f"[mtu_fragmentation] method 4 model == live: "
          f"{sum(model.values())} B, {sum(eap_fragments(4, v) for v in model.values())} EAP fragments")


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "mtu-fragmentation.csv")

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "method", "profile", "message", "size_bytes",
            "eap_message_attrs", "eap_fragments", "ip_datagram_bytes",
            "ip_fragments", "exceeds_mtu",
        ])
        for m in METHODS:
            sizes = message_sizes(m)
            for msg, sz in sizes.items():
                eap_attrs = math.ceil(sz / RADIUS_EAP_ATTR)
                eap_frags = eap_fragments(m, sz)
                ipd = sz + UDP_HDR + IP_HDR
                ipf = ip_fragments(sz)
                exceeds = "yes" if (sz + UDP_HDR + IP_HDR) > IP_MTU else "no"
                w.writerow([m, PROFILE[m], msg, sz, eap_attrs, eap_frags,
                            ipd, ipf, exceeds])

    print(f"[mtu_fragmentation] wrote {path}")

    # human-readable summary to stdout
    print(f"{'method':6} {'message':10} {'bytes':6} {'EAP-attrs':9} "
          f"{'EAP-frags':9} {'IP-frags':8} {'>MTU':5}")
    for m in METHODS:
        for msg, sz in message_sizes(m).items():
            print(f"{m:<6} {msg:<10} {sz:<6} "
                  f"{math.ceil(sz/RADIUS_EAP_ATTR):<9} "
                  f"{eap_fragments(m, sz):<9} "
                  f"{ip_fragments(sz):<8} "
                  f"{'yes' if (sz+UDP_HDR+IP_HDR)>IP_MTU else 'no':<5}")
    check_live(outdir)


if __name__ == "__main__":
    main()
