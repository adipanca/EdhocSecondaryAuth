#!/usr/bin/env python3
"""
ue_client.py — UE (UERANSIM / EAP supplicant) side of Key Bootstrapping.

Runs the steps from bootstrappingkey.md §1.4 on the UE:

  * Takes the EMSK that the EAP-EDHOC handshake produced locally on the UE side,
    derives the SAME USRK -> DSRK -> OSCORE Master Secret/Salt chain, then
  * makes first contact with the Application Server over OSCORE (CoAP-lite UDP).

A successful protected round-trip proves — cryptographically — that the UE and
the AS bootstrapped identical keys straight from the EAP EMSK, with no extra
application login (the central claim of bootstrappingkey.md).

Usage:
    python3 ue_client.py --emsk-file emsk.hex --session-id S1 \
        --as-host 127.0.0.1 --coap-port 5683 [--jsonlog run.jsonl]
"""
from __future__ import annotations

import argparse
import socket
import sys

from keyschedule import (derive_usrk, derive_dsrk, oscore_context_from_dsrk,
                         fingerprint)
from oscore_lite import protect, unprotect
import botlog

# UE is OSCORE sender 0x01; the AS is sender 0x00 (UE recipient 0x00).
UE_SENDER_ID = b"\x01"
AS_SENDER_ID = b"\x00"


def read_emsk(path: str | None, hex_str: str | None) -> bytes:
    if hex_str:
        return bytes.fromhex(hex_str.strip())
    with open(path) as f:
        return bytes.fromhex(f.read().strip())


def first_contact(emsk: bytes, session_id: str, as_host: str, coap_port: int,
                  slog: botlog.SessionLog, timeout: float = 5.0) -> dict:
    usrk = derive_usrk(emsk)
    slog.mark("t_usrk_derived", role="UE", usrk_fp=fingerprint(usrk))
    dsrk = derive_dsrk(usrk)
    slog.mark("t_dsrk_derived", role="UE", dsrk_fp=fingerprint(dsrk))
    ctx = oscore_context_from_dsrk(dsrk, UE_SENDER_ID, AS_SENDER_ID)
    slog.mark("t_oscore_secret_derived_ue", role="UE",
              master_secret_fp=fingerprint(ctx.master_secret))

    request = protect(ctx, b"GET /bootstrap/hello (first contact)", partial_iv=1)
    datagram = bytes([len(session_id)]) + session_id.encode() + request

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(datagram, (as_host, coap_port))
    try:
        reply, _ = sock.recvfrom(65535)
    except socket.timeout:
        sock.close()
        raise TimeoutError("no OSCORE reply from AS")
    sock.close()

    if reply[:1] == b"\x00":  # AS-side plaintext error frame
        raise ValueError(f"AS rejected first contact: {reply[1:].decode(errors='replace')}")

    plaintext = unprotect(ctx, reply)
    slog.mark("t_first_oscore_success", role="UE",
              reply=plaintext.decode(errors="replace"))
    print(f"[UE] OSCORE first contact OK for {session_id}: "
          f"{plaintext.decode(errors='replace')!r} "
          f"(ms_fp={fingerprint(ctx.master_secret)})")
    return {"master_secret_fp": fingerprint(ctx.master_secret)}


def main():
    ap = argparse.ArgumentParser(description="UE Key Bootstrapping first contact")
    ap.add_argument("--emsk-file")
    ap.add_argument("--emsk-hex")
    ap.add_argument("--session-id", required=True)
    ap.add_argument("--as-host", default="127.0.0.1")
    ap.add_argument("--coap-port", type=int, default=5683)
    ap.add_argument("--jsonlog", default=None)
    args = ap.parse_args()

    if not args.emsk_file and not args.emsk_hex:
        ap.error("one of --emsk-file / --emsk-hex is required")

    emsk = read_emsk(args.emsk_file, args.emsk_hex)
    slog = botlog.SessionLog(args.session_id, args.jsonlog)
    slog.mark("t_emsk_ready", role="UE", emsk_fp=fingerprint(emsk))
    try:
        first_contact(emsk, args.session_id, args.as_host, args.coap_port, slog)
    except Exception as exc:
        print(f"[UE] first contact failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
