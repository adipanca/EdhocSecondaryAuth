#!/usr/bin/env python3
"""
verify_session.py — collapse a bootstrap JSON-Lines log into the spec record.

Reads the JSON-Lines produced by botlog.SessionLog and prints, for a given
session_id, the single flat record required by bootstrappingkey.md §1.6, plus a
correctness check that the UE-side and AS-side OSCORE Master Secret fingerprints
match (Key consistency, §2.B).

Usage: python3 verify_session.py <run.jsonl> <session_id>
"""
import json
import sys

from botlog import SESSION_FIELDS


def main():
    if len(sys.argv) != 3:
        print("usage: verify_session.py <run.jsonl> <session_id>", file=sys.stderr)
        sys.exit(2)
    path, sid = sys.argv[1], sys.argv[2]
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("session_id") == sid:
                events.append(rec)

    by_event = {}
    for e in events:
        by_event[e["event"]] = e

    flat = {k: "" for k in SESSION_FIELDS}
    flat["session_id"] = sid
    for f in SESSION_FIELDS:
        if f in by_event:
            flat[f] = by_event[f]["t_iso"]

    ue_ms = by_event.get("t_oscore_secret_derived_ue", {}).get("master_secret_fp")
    as_ms = by_event.get("t_oscore_secret_derived_as", {}).get("master_secret_fp")
    consistent = bool(ue_ms) and ue_ms == as_ms
    ue_ok = "t_first_oscore_success" in by_event
    flat["result"] = "success" if (consistent and ue_ok) else "fail"

    print("Per-session record (bootstrappingkey.md §1.6):")
    print(json.dumps(flat, indent=2))
    print()
    print("Key consistency check (UE OSCORE master-secret fp == AS fp):")
    print(f"  UE fp: {ue_ms}")
    print(f"  AS fp: {as_ms}")
    print(f"  -> {'MATCH (keys identical)' if consistent else 'MISMATCH'}")
    sys.exit(0 if flat["result"] == "success" else 1)


if __name__ == "__main__":
    main()
