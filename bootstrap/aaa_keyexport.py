#!/usr/bin/env python3
"""
aaa_keyexport.py — AAA (FreeRADIUS/DN-AAA) side of Key Bootstrapping.

Runs the steps from bootstrappingkey.md §1.1 + §1.2 on the server side:

  * Takes the EMSK that the EAP-EDHOC handshake produced on the FreeRADIUS side
    (rlm_eap_edhoc's ``sess->ctx.emsk``), derives USRK -> DSRK (RFC 5295), and
  * transports the DSRK + ID_CREDI to the Application Server over a pre-shared
    bearer-token HTTP hop (trust-domain assumption; see README.md).

The EMSK is provided as a hex file so this tool can be driven both by the live
FreeRADIUS module (which can dump ``emsk`` in a debug/test build) and by the
benchmark harness.

Usage:
    python3 aaa_keyexport.py --emsk-file emsk.hex --session-id S1 \
        --id-credi ue-0001 --as-url http://127.0.0.1:8686/oscore/session \
        --token bootstrap-shared-token [--jsonlog run.jsonl]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request

from keyschedule import derive_usrk, derive_dsrk, fingerprint
import botlog


def read_emsk(path: str | None, hex_str: str | None) -> bytes:
    if hex_str:
        return bytes.fromhex(hex_str.strip())
    with open(path) as f:
        return bytes.fromhex(f.read().strip())


def export_key(emsk: bytes, session_id: str, id_credi: str, as_url: str,
               token: str, slog: botlog.SessionLog, timeout: float = 5.0) -> dict:
    slog.mark("t_emsk_ready", role="AAA", emsk_fp=fingerprint(emsk))
    usrk = derive_usrk(emsk)
    slog.mark("t_usrk_derived", role="AAA", usrk_fp=fingerprint(usrk))
    dsrk = derive_dsrk(usrk)
    slog.mark("t_dsrk_derived", role="AAA", dsrk_fp=fingerprint(dsrk))

    body = json.dumps({
        "session_id": session_id,
        "id_credi": id_credi,
        "dsrk": dsrk.hex(),
    }).encode()
    req = urllib.request.Request(
        as_url, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"})
    slog.mark("t_key_sent_aaa", role="AAA", dsrk_fp=fingerprint(dsrk))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        result = json.loads(resp.read())
    print(f"[AAA] exported DSRK for session {session_id} "
          f"(dsrk_fp={fingerprint(dsrk)}); AS ack: {result}")
    return {"dsrk_fp": fingerprint(dsrk),
            "as_master_secret_fp": result.get("master_secret_fp")}


def main():
    ap = argparse.ArgumentParser(description="AAA key export (USRK/DSRK -> AS)")
    ap.add_argument("--emsk-file")
    ap.add_argument("--emsk-hex")
    ap.add_argument("--session-id", required=True)
    ap.add_argument("--id-credi", default="ue-0001")
    ap.add_argument("--as-url", default="http://127.0.0.1:8686/oscore/session")
    ap.add_argument("--token", default="bootstrap-shared-token")
    ap.add_argument("--jsonlog", default=None)
    args = ap.parse_args()

    if not args.emsk_file and not args.emsk_hex:
        ap.error("one of --emsk-file / --emsk-hex is required")

    emsk = read_emsk(args.emsk_file, args.emsk_hex)
    slog = botlog.SessionLog(args.session_id, args.jsonlog)
    try:
        export_key(emsk, args.session_id, args.id_credi, args.as_url,
                   args.token, slog)
    except Exception as exc:
        print(f"[AAA] key export failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
