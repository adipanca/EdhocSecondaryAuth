#!/usr/bin/env python3
"""
botlog.py — structured per-session logging for the bootstrapping phase.

Writes one JSON object per event as a JSON-Lines stream, and can collapse all
events of a session into the single flat record required by bootstrappingkey.md
§1.6:

    session_id, t_emsk_ready, t_usrk_derived, t_dsrk_derived,
    t_key_sent_aaa, t_key_received_as, t_oscore_secret_derived_ue,
    t_oscore_secret_derived_as, t_first_oscore_success, result

Timestamps are wall-clock ISO-8601 (for humans) plus a monotonic millisecond
counter (for latency math that is immune to clock steps).
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

# The exact per-session fields mandated by the spec (§1.6).
SESSION_FIELDS = [
    "session_id",
    "t_emsk_ready",
    "t_usrk_derived",
    "t_dsrk_derived",
    "t_key_sent_aaa",
    "t_key_received_as",
    "t_oscore_secret_derived_ue",
    "t_oscore_secret_derived_as",
    "t_first_oscore_success",
    "result",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")


def now_ms() -> float:
    return time.monotonic() * 1000.0


class SessionLog:
    """Accumulates timestamped events for one bootstrap session."""

    def __init__(self, session_id: str, path: str | None = None):
        self.session_id = session_id
        self.path = path
        self.events: list[dict] = []
        self.marks: dict[str, float] = {}

    def mark(self, event: str, **extra) -> None:
        rec = {
            "session_id": self.session_id,
            "event": event,
            "t_iso": now_iso(),
            "t_ms": now_ms(),
        }
        rec.update(extra)
        self.marks[event] = rec["t_ms"]
        self.events.append(rec)
        if self.path:
            with open(self.path, "a") as f:
                f.write(json.dumps(rec) + "\n")

    def elapsed_ms(self, start: str, end: str) -> float | None:
        if start in self.marks and end in self.marks:
            return self.marks[end] - self.marks[start]
        return None

    def flat_record(self, result: str) -> dict:
        """Collapse to the spec's per-session record (event -> ISO timestamp)."""
        by_event = {e["event"]: e["t_iso"] for e in self.events}
        rec = {f: "" for f in SESSION_FIELDS}
        rec["session_id"] = self.session_id
        rec["result"] = result
        for f in SESSION_FIELDS:
            if f in by_event:
                rec[f] = by_event[f]
        return rec


def append_csv(path: str, header: list[str], row: dict) -> None:
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        if new:
            f.write(",".join(header) + "\n")
        f.write(",".join(str(row.get(h, "")) for h in header) + "\n")
