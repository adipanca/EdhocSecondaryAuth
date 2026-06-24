#!/usr/bin/env python3
"""
mtu_fragmentation.py — Point 4: effect of packet size on MTU and fragmentation.

For each EDHOC method and message it computes:
  - EAP fragmentation : EAP-Message RADIUS attributes carry <=253 bytes each
                        (RFC 3579 §3.1) -> number of EAP-Message attributes.
  - EAP packets       : EAP-EDHOC fragmentation with a typical 1020-byte
                        EAP fragment size -> number of EAP request/response
                        round trips needed to ship one EDHOC message.
  - IP fragmentation  : whether the UDP/IP datagram (message + UDP/IP headers)
                        exceeds the link MTU (default 1500) and into how many
                        IP fragments it splits.

Writes <outdir>/mtu-fragmentation.csv
"""
import csv
import math
import os
import sys

from edhoc_sizes import METHODS, PROFILE, message_sizes

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
                eap_frags = math.ceil(sz / EAP_FRAG_SIZE)
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
                  f"{math.ceil(sz/EAP_FRAG_SIZE):<9} "
                  f"{ip_fragments(sz):<8} "
                  f"{'yes' if (sz+UDP_HDR+IP_HDR)>IP_MTU else 'no':<5}")


if __name__ == "__main__":
    main()
