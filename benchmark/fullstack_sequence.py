#!/usr/bin/env python3
"""
fullstack_sequence.py — message order of the sample capture of
fullstack_bench.sh (one successful session, one session whose message_3 is
dropped in the UPF relay, and its recovery), from tshark:

  NGAP/NAS-5GS (SCTP, NAS NEA0 so the 5GSM messages are readable),
  SBI HTTP/2 (tcp 7777, via the SCP), RADIUS (udp 1812).

  fullstack_sequence.py <capture.pcap> <out.txt>

NAS messages are listed from NGAP over SCTP only (the same N1 container also rides in
the SBI N1N2MessageTransfer / UpdateSMContext), an SBI request that passes
the SCP (two hops) once, NRF heartbeats (PATCH nnrf-nfm) are left out, and
consecutive EAP-EDHOC rounds (Command/Complete and Access-Request/
Challenge) are collapsed into one line with their count.
"""
import subprocess
import sys

SM = {0xc1: "PDU SESSION ESTABLISHMENT REQUEST", 0xc2: "PDU SESSION ESTABLISHMENT ACCEPT",
      0xc3: "PDU SESSION ESTABLISHMENT REJECT", 0xc5: "PDU SESSION AUTHENTICATION COMMAND",
      0xc6: "PDU SESSION AUTHENTICATION COMPLETE", 0xc7: "PDU SESSION AUTHENTICATION RESULT",
      0xd1: "PDU SESSION RELEASE REQUEST", 0xd3: "PDU SESSION RELEASE COMMAND",
      0xd4: "PDU SESSION RELEASE COMPLETE", 0xd6: "5GSM STATUS"}
EAP_CODE = {"1": "Request", "2": "Response", "3": "Success", "4": "Failure"}
EAP_TYPE = {"1": "Identity", "56": "EDHOC"}
RAD = {"1": "Access-Request", "2": "Access-Accept", "3": "Access-Reject", "11": "Access-Challenge"}
FIELDS = ["frame.time_relative", "frame.protocols", "nas-5gs.sm.message_type", "nas-5gs.sm.5gsm_cause",
          "eap.code", "eap.type", "radius.code", "radius.id", "http2.headers.method",
          "http2.headers.path", "http2.headers.status"]


def first(v):
    return v.split(",")[0] if v else ""


def label(f):
    t, protos, smt, cause, ecode, etype, rcode, rid, meth, path, status = f
    if smt and "sctp" not in protos.split(":"):
        smt = ""                 # N1 container inside SBI: shown via NGAP
    if smt:
        out = []
        for m in smt.split(","):
            name = SM.get(int(m, 16) if m.startswith("0x") else int(m), f"5GSM {m}")
            out.append(name)
        s = " + ".join(out)
        if cause:
            s += f" (cause #{first(cause)})"
        if ecode:
            s += f" [EAP-{EAP_CODE.get(first(ecode), first(ecode))}"
            if etype:
                s += f"/{EAP_TYPE.get(first(etype), first(etype))}"
            s += "]"
        return "NAS", s
    if rcode:
        s = f"{RAD.get(first(rcode), rcode)} id={first(rid)}"
        if ecode:
            s += f" [EAP-{EAP_CODE.get(first(ecode), first(ecode))}"
            if etype:
                s += f"/{EAP_TYPE.get(first(etype), first(etype))}"
            s += "]"
        return "RADIUS", s
    if meth and path:
        if first(meth) == "PATCH" and first(path).startswith("/nnrf-nfm/"):
            return None, None    # NRF heartbeat
        return "SBI", f"{first(meth)} {first(path).split('?')[0]}"
    if status:
        return "SBI", f"HTTP {first(status)}"
    return None, None


def main():
    pcap, out = sys.argv[1], sys.argv[2]
    cmd = ["tshark", "-r", pcap, "-o", "nas-5gs.null_decipher:TRUE", "-d", "tcp.port==7777,http2",
           "-Y", "nas-5gs.sm.message_type || radius || http2.headers.method", "-T", "fields",
           "-E", "separator=\t"] + sum((["-e", f] for f in FIELDS), [])
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    events = []
    for ln in res.stdout.splitlines():
        f = (ln.split("\t") + [""] * len(FIELDS))[:len(FIELDS)]
        kind, s = label(f)
        if not kind:
            continue
        t = float(f[0])
        # the same SBI request on both SCP hops
        if kind == "SBI" and any(k == kind and x == s and t - t0 < 0.005 for t0, k, x in events[-4:]):
            continue
        events.append((t, kind, s))

    lines = ["# Message order from fullstack-v2-sample.pcap (tshark, NAS NEA0 null "
             "deciphering); repeated EAP-EDHOC rounds are collapsed.",
             "# t [s]   interface  message"]
    i = 0
    while i < len(events):
        t, kind, s = events[i]
        edhoc = ("EAP-Request/EDHOC" in s or "EAP-Response/EDHOC" in s or
                 ("Access-" in s and ("Challenge" in s or "Request" in s) and "Identity" not in s))
        if edhoc:
            j, n_nas, n_rad = i, 0, 0
            while j < len(events):
                s2 = events[j][2]
                e2 = ("EAP-Request/EDHOC" in s2 or "EAP-Response/EDHOC" in s2 or
                      ("Access-" in s2 and ("Challenge" in s2 or "Request" in s2)
                       and "Identity" not in s2))
                if not (e2 or events[j][1] == "SBI"):
                    break
                n_nas += events[j][1] == "NAS"
                n_rad += events[j][1] == "RADIUS"
                j += 1
            lines.append(f"{t:9.4f}  ...        EAP-EDHOC rounds: {n_nas} NAS Command/Complete, "
                         f"{n_rad} RADIUS Access-Request/Challenge (+ SBI N1N2 / UpdateSMContext)")
            i = j
            continue
        lines.append(f"{t:9.4f}  {kind:<9}  {s}")
        i += 1
    with open(out, "w") as fo:
        fo.write("\n".join(lines) + "\n")
    print(f"wrote {out} ({len(lines) - 2} lines from {len(events)} messages)")


if __name__ == "__main__":
    main()
