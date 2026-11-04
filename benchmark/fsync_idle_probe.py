#!/usr/bin/env python3
"""
fsync_idle_probe.py — does one pwrite + fdatasync on this disk cost more after
the disk was idle? No protocol involved: a 12288-byte overwrite (the size of a
key-record slot), then a pause, 60 times per gap, gaps alternating.

  fsync_idle_probe.py <file on the disk under test>
"""
import os
import statistics
import sys
import time

path = sys.argv[1]
GAPS_MS = (0, 2, 5, 10, 20, 50, 100, 200, 500)
fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
os.pwrite(fd, b"\0" * 16384, 0)
os.fdatasync(fd)
res = {g: [] for g in GAPS_MS}
for _ in range(60):
    for g in GAPS_MS:
        time.sleep(g / 1000)
        data = os.urandom(12288)
        t0 = time.perf_counter()
        os.pwrite(fd, data, 0)
        os.fdatasync(fd)
        res[g].append((time.perf_counter() - t0) * 1e3)
os.close(fd)
os.unlink(path)
print("idle gap before the flush | n | median ms | p10 ms | p90 ms")
for g in GAPS_MS:
    v = sorted(res[g])
    print(f"{g:>5} ms | {len(v)} | {statistics.median(v):.3f} | {v[len(v) // 10]:.3f} | {v[9 * len(v) // 10]:.3f}")
