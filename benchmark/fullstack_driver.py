#!/usr/bin/env python3
"""
fullstack_driver.py — drive PDU sessions of the live 5G stack (UERANSIM nr-ue
+ Open5GS + UPF EAP relay + FreeRADIUS) through nr-cli, for
benchmark/fullstack_bench.sh. It only starts sessions, waits for their
outcome in the nr-ue [E4T] log and releases them; all timing comes from the
[E4T] lines of the processes (fullstack_analyze.py).

  fullstack_driver.py bench    <ue.log> <marks> <config A|B> <series> <n> <warmup>
  fullstack_driver.py recovery <ue.log> <marks> <drop-file> <n>

marks: one line per session, written before it starts and after it ends:
  start <kind> <config> <series> <iter> <t_us>
  end   <kind> <config> <series> <iter> <t_us> <outcome> <ue_rec_changed> <dn_rec_changed>
outcome: success (A: EAP-Success; B: Accept), failure (EAP-Failure), noeap
(Result without EAP, i.e. relay timeout), timeout (nothing within 5 s).
"""
import hashlib
import os
import re
import subprocess
import sys
import time

CLI = "/home/admin-vb/EdhocSecondaryAuth/UERANSIM/build/nr-cli"
IMSI = os.environ.get("FS_IMSI", "imsi-999700000000001")
DNN = os.environ.get("FS_DNN", "internet")
UE_REC = f"/usr/local/etc/edhoc/ue/{IMSI}/ue.rec"
DN_REC = f"/usr/local/etc/edhoc/edhoc_db/{IMSI}/rec.bin"
WAIT_S = 5.0
LINE = re.compile(r"\[E4T\] (\S+) t_us=(\d+) sess=(\d+) len=(\d+)(.*)")


def now_us():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000


def digest(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


class UeLog:
    """Follows the nr-ue log; returns [E4T] events after a given offset."""

    def __init__(self, path):
        self.path = path
        self.pos = os.path.getsize(path)

    def wait(self, want, timeout):
        """Wait for the first event whose tag is in `want`; return (tag, extra)."""
        end = time.monotonic() + timeout
        buf = ""
        while time.monotonic() < end:
            with open(self.path, errors="replace") as f:
                f.seek(self.pos)
                chunk = f.read()
                self.pos = f.tell()
            buf += chunk
            lines = buf.split("\n")
            buf = lines.pop()
            for ln in lines:
                m = LINE.search(ln)
                if m and m.group(1) in want:
                    self.pos -= len(buf.encode())
                    return m.group(1), m.group(5)
            time.sleep(0.002)
        return None, ""


def cli(cmd):
    subprocess.run([CLI, IMSI, "-e", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)


def session(log, marks, kind, config, series, it):
    """One PDU session: establish, wait for the outcome, release, 200 ms gap."""
    ue0, dn0 = digest(UE_REC), digest(DN_REC)
    marks.write(f"start {kind} {config} {series} {it} {now_us()}\n")
    marks.flush()
    cli(f"ps-establish IPv4 --sst 1 --dnn {DNN}")
    if config == "B":
        tag, _ = log.wait({"ue_pdu_acc", "ue_pdu_rej"}, WAIT_S)
        outcome = "success" if tag == "ue_pdu_acc" else ("failure" if tag else "timeout")
    else:
        # secondary auth runs after the Accept; its Result ends the session
        tag, extra = log.wait({"ue_result_rx", "ue_pdu_rej"}, WAIT_S)
        if tag == "ue_result_rx":
            code = re.search(r"code=(\d+)", extra)
            code = int(code.group(1)) if code else -1
            outcome = {3: "success", 4: "failure", 0: "noeap"}.get(code, "other")
        else:
            outcome = "failure" if tag else "timeout"
    t_end = now_us()
    time.sleep(0.02)   # promotion after the closing ACK
    ue1, dn1 = digest(UE_REC), digest(DN_REC)
    marks.write(f"end {kind} {config} {series} {it} {t_end} {outcome} "
                f"{int(ue0 != ue1)} {int(dn0 != dn1)}\n")
    marks.flush()
    cli("ps-release 1")
    log.wait({"ue_pdu_rel"}, 2.0)   # release finished on the UE
    log.wait({"__never__"}, 0.2)    # 200 ms gap, keeps following the log
    if outcome == "timeout":
        # a request UERANSIM did not send (UAC "barred") is retransmitted on
        # T3580 (16 s) and then runs a full session: let it finish, release
        # everything, so the next session starts clean
        log.wait({"__never__"}, 18.0)
        cli("ps-release-all")
        log.wait({"__never__"}, 1.0)
    return outcome


def bench(ue_log, marks_path, config, series, n, warmup):
    log = UeLog(ue_log)
    with open(marks_path, "a") as marks:
        for i in range(1, warmup + n + 1):
            kind = "warmup" if i <= warmup else "run"
            out = session(log, marks, kind, config, series, i)
            if i % 20 == 0 or out != "success":
                print(f"  {config}{series} iter {i}: {out}", flush=True)


def recovery(ue_log, marks_path, drop_file, n):
    log = UeLog(ue_log)
    with open(marks_path, "a") as marks:
        for case in ("msg3", "msg4"):
            for i in range(1, n + 1):
                with open(drop_file, "w") as f:
                    f.write(case + "\n")
                out = session(log, marks, f"drop_{case}", "A", 0, i)
                # recovery: up to 3 sessions until EAP-Success (a fallback
                # needs a second one; UERANSIM does not retry by itself)
                for k in range(1, 4):
                    out2 = session(log, marks, f"recover_{case}", "A", k, i)
                    if out2 == "success":
                        break
                print(f"  {case} {i}: drop session {out}, recovered after {k} session(s): {out2}", flush=True)
        for i in range(1, 11):
            session(log, marks, "after", "A", 0, i)


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "bench":
        bench(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7]))
    elif mode == "recovery":
        recovery(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]))
    else:
        sys.exit(__doc__)
