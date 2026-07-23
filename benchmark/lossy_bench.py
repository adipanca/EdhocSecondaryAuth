#!/usr/bin/env python3
"""
lossy_bench.py — Point 2: secondary-authentication handshake performance on a
lossy network.

Runs the 3-message EDHOC handshake (message_1/2/3, sized per method via
edhoc_sizes) over a real localhost UDP socket pair with EAP-style reliable
retransmission, while emulating packet loss at the application layer. Loss is
applied only to the benchmark's own packets, so it never disturbs the 5G core
loopback traffic (mongodb / Open5GS NFs).

For each method x loss-rate it reports handshake completion time, retransmit
count and success rate.

Writes <outdir>/lossy-network.csv
"""
import csv
import os
import random
import socket
import statistics
import sys
import threading
import time

from edhoc_sizes import METHODS, PROFILE, message_sizes

LOSS_RATES = [0.0, 0.01, 0.05, 0.10, 0.20, 0.30]
TRIALS = int(os.environ.get("LOSSY_TRIALS", "120"))
RTO = float(os.environ.get("LOSSY_RTO_MS", "40")) / 1000.0
MAX_RETX = int(os.environ.get("LOSSY_MAX_RETX", "6"))
PROC_DELAY = float(os.environ.get("LOSSY_PROC_MS", "1")) / 1000.0  # responder compute


def run_responder(sock: socket.socket, sizes: dict, loss: float, stop: threading.Event):
    """Echo responder: msg1 -> msg2, msg3 -> ack. Drops replies with prob=loss."""
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if not data:
            continue
        tag = data[:1]
        time.sleep(PROC_DELAY)
        if tag == b"\x01":                      # received message_1
            reply = b"\x02" + b"\x00" * (sizes["message_2"] - 1)
        elif tag == b"\x03":                    # received message_3
            # EAP-Success = message_4 when the method defines one (method 4
            # carries EAD4=NpkB), otherwise a short EAP-Success.
            m4len = sizes.get("message_4", 4)
            reply = b"\x04" + b"\x00" * (m4len - 1)
        else:
            continue
        if random.random() >= loss:             # emulate downstream loss
            sock.sendto(reply, addr)


def send_reliable(sock, dst, payload, expect_tag, loss):
    """Send `payload`, retransmit until a reply with `expect_tag` arrives."""
    retx = 0
    sock.settimeout(RTO)
    for attempt in range(MAX_RETX + 1):
        if random.random() >= loss:             # emulate upstream loss
            sock.sendto(payload, dst)
        try:
            while True:
                data, _ = sock.recvfrom(65535)
                if data[:1] == expect_tag:
                    return True, retx
        except socket.timeout:
            retx += 1
            continue
    return False, retx


def one_handshake(cli, dst, sizes, loss):
    m1 = b"\x01" + b"\x00" * (sizes["message_1"] - 1)
    m3 = b"\x03" + b"\x00" * (sizes["message_3"] - 1)

    t0 = time.perf_counter()
    ok, r1 = send_reliable(cli, dst, m1, b"\x02", loss)   # msg1 -> msg2
    if not ok:
        return False, (time.perf_counter() - t0) * 1000.0, r1
    ok, r2 = send_reliable(cli, dst, m3, b"\x04", loss)   # msg3 -> success
    dt = (time.perf_counter() - t0) * 1000.0
    return ok, dt, r1 + r2


def bench_method_loss(method, loss):
    sizes = message_sizes(method)

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv_addr = srv.getsockname()

    stop = threading.Event()
    th = threading.Thread(target=run_responder, args=(srv, sizes, loss, stop), daemon=True)
    th.start()

    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.bind(("127.0.0.1", 0))

    times, retx_list, ok_count = [], [], 0
    for _ in range(TRIALS):
        ok, dt, retx = one_handshake(cli, srv_addr, sizes, loss)
        retx_list.append(retx)
        if ok:
            ok_count += 1
            times.append(dt)

    stop.set()
    th.join(timeout=1.0)
    srv.close()
    cli.close()

    succ_rate = 100.0 * ok_count / TRIALS
    if times:
        times.sort()
        mean_ms = statistics.fmean(times)
        median_ms = statistics.median(times)
        p95_ms = times[min(len(times) - 1, int(len(times) * 0.95))]
    else:
        mean_ms = median_ms = p95_ms = 0.0
    mean_retx = statistics.fmean(retx_list) if retx_list else 0.0
    return succ_rate, mean_ms, median_ms, p95_ms, mean_retx


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "lossy-network.csv")

    random.seed(1234)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "profile", "loss_pct", "trials",
                    "success_rate_pct", "mean_handshake_ms",
                    "median_handshake_ms", "p95_handshake_ms", "mean_retransmits"])
        for m in METHODS:
            for loss in LOSS_RATES:
                sr, mean_ms, med_ms, p95_ms, mretx = bench_method_loss(m, loss)
                w.writerow([m, PROFILE[m], round(loss * 100, 1), TRIALS,
                            round(sr, 1), round(mean_ms, 3), round(med_ms, 3),
                            round(p95_ms, 3), round(mretx, 3)])
                print(f"method {m} loss={loss*100:4.1f}%  "
                      f"success={sr:5.1f}%  mean={mean_ms:7.3f} ms  "
                      f"retx={mretx:.2f}")

    print(f"[lossy_bench] wrote {path}")


if __name__ == "__main__":
    main()
