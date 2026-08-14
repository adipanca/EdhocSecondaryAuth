#!/usr/bin/env python3
"""
app_server.py — mock Application Server (AS) for the Key Bootstrapping demo.

Implements the AS role from bootstrappingkey.md §1.3:

  1. Key-transport receiver (AAA -> AS)
     A tiny HTTP endpoint (POST /oscore/session) protected by a pre-shared
     bearer token. It receives {session_id, id_credi, dsrk} from the AAA
     server. NOTE: this hop is NOT a new security protocol — its confidentiality
     rests on the trust-domain assumption (co-located / mTLS / closed network),
     the same model as ERP in RFC 6696. See README.md.

  2. OSCORE first-contact server (UE -> AS)
     A CoAP-lite UDP endpoint. When the UE makes first contact it derives the
     OSCORE Master Secret/Salt from the same DSRK, and this server derives the
     matching context and verifies the protected request — proving the keys
     match, with no additional application login.

Usage:
    python3 app_server.py --http-port 8686 --coap-port 5683 --token secret123 \
                          [--jsonlog run.jsonl] [--expect 1]
"""
from __future__ import annotations

import argparse
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from keyschedule import oscore_context_from_dsrk, fingerprint
from oscore_lite import protect, unprotect
import botlog

# AS is OSCORE sender 0x00; the UE is sender 0x01 (AS recipient 0x01).
AS_SENDER_ID = b"\x00"
UE_SENDER_ID = b"\x01"


class SessionStore:
    """Thread-safe map of session_id -> derived OSCORE context + metadata."""

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}

    def put(self, session_id: str, info: dict) -> None:
        with self._lock:
            self._data[session_id] = info

    def get(self, session_id: str) -> dict | None:
        with self._lock:
            return self._data.get(session_id)


def _make_http_handler(store: SessionStore, token: str, jsonlog: str | None):
    class KeyTransportHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):  # silence default logging
            pass

        def _deny(self, code: int, msg: str):
            self.send_response(code)
            self.end_headers()
            self.wfile.write(msg.encode())

        def do_POST(self):
            if self.path != "/oscore/session":
                return self._deny(404, "not found")
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {token}":
                return self._deny(401, "bad token")
            length = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(length))
                session_id = body["session_id"]
                id_credi = body["id_credi"]
                dsrk = bytes.fromhex(body["dsrk"])
            except (ValueError, KeyError) as exc:
                return self._deny(400, f"bad body: {exc}")

            slog = botlog.SessionLog(session_id, jsonlog)
            slog.mark("t_key_received_as", role="AS", id_credi=id_credi)
            # AS derives the OSCORE context (AS is sender 0x00, recipient = UE).
            ctx = oscore_context_from_dsrk(dsrk, AS_SENDER_ID, UE_SENDER_ID)
            slog.mark("t_oscore_secret_derived_as", role="AS",
                      master_secret_fp=fingerprint(ctx.master_secret))
            store.put(session_id, {
                "ctx": ctx, "id_credi": id_credi, "dsrk_fp": fingerprint(dsrk),
                "master_secret_fp": fingerprint(ctx.master_secret),
            })
            resp = json.dumps({
                "status": "stored",
                "session_id": session_id,
                "master_secret_fp": fingerprint(ctx.master_secret),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            print(f"[AS] key received for session {session_id} "
                  f"(id_credi={id_credi}, ms_fp={fingerprint(ctx.master_secret)})")

    return KeyTransportHandler


def _coap_server(store: SessionStore, port: int, jsonlog: str | None,
                 expect: int, stop: threading.Event):
    """UDP CoAP-lite OSCORE first-contact server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.5)
    print(f"[AS] OSCORE first-contact server on udp/127.0.0.1:{port}")
    served = 0
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(65535)
        except socket.timeout:
            continue
        # datagram = 1 byte session_id_len | session_id | oscore-lite message
        try:
            sid_len = data[0]
            session_id = data[1:1 + sid_len].decode()
            oscore_msg = data[1 + sid_len:]
        except (IndexError, UnicodeDecodeError):
            continue
        info = store.get(session_id)
        if not info:
            print(f"[AS] first contact for unknown session {session_id!r}")
            continue
        ctx = info["ctx"]
        slog = botlog.SessionLog(session_id, jsonlog)
        try:
            request = unprotect(ctx, oscore_msg)
        except Exception as exc:  # InvalidTag / ValueError
            print(f"[AS] OSCORE verify FAILED for {session_id}: {exc}")
            reply = json.dumps({"session_id": session_id, "result": "fail",
                                "error": str(exc)}).encode()
            sock.sendto(b"\x00" + reply, peer)
            continue
        slog.mark("t_first_oscore_success", role="AS",
                  request=request.decode(errors="replace"))
        print(f"[AS] OSCORE first contact OK for {session_id}: "
              f"{request.decode(errors='replace')!r}")
        # Protected application reply.
        resp = protect(ctx, b"2.05 Content: bootstrap OK, welcome UE", partial_iv=1)
        sock.sendto(resp, peer)
        served += 1
        if expect and served >= expect:
            stop.set()
    sock.close()


def main():
    ap = argparse.ArgumentParser(description="Mock Application Server (AS)")
    ap.add_argument("--http-port", type=int, default=8686)
    ap.add_argument("--coap-port", type=int, default=5683)
    ap.add_argument("--token", default="bootstrap-shared-token")
    ap.add_argument("--jsonlog", default=None)
    ap.add_argument("--expect", type=int, default=0,
                    help="exit after N successful OSCORE contacts (0 = run forever)")
    args = ap.parse_args()

    store = SessionStore()
    stop = threading.Event()

    handler = _make_http_handler(store, args.token, args.jsonlog)
    httpd = ThreadingHTTPServer(("127.0.0.1", args.http_port), handler)
    http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    http_thread.start()
    print(f"[AS] key-transport (AAA->AS) endpoint on "
          f"http://127.0.0.1:{args.http_port}/oscore/session")

    try:
        _coap_server(store, args.coap_port, args.jsonlog, args.expect, stop)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    print("[AS] shutting down")


if __name__ == "__main__":
    main()
