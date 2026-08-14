#!/usr/bin/env bash
#
# run_bootstrap_demo.sh — end-to-end, multi-process Key Bootstrapping demo.
#
# Wires the four roles from bootstrappingkey.md together over REAL sockets:
#
#   EAP-EDHOC (already done) --EMSK--> [AAA] --DSRK/HTTP--> [AS]
#                                         \                    ^
#                                          `--(same EMSK)-->[UE]--OSCORE/UDP--'
#
# The EMSK is taken as the shared secret that the EAP-EDHOC handshake already
# produced identically on the UE and FreeRADIUS sides. For a standalone demo we
# synthesize one random 64-byte EMSK and hand the SAME bytes to both the AAA and
# UE roles (that is exactly what a real successful EAP-EDHOC run guarantees).
#
# To drive it from a real handshake instead, dump rlm_eap_edhoc's sess->ctx.emsk
# (and the UE ctx->emsk) to emsk.hex and pass --emsk-file, skipping step 0.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

HTTP_PORT="${HTTP_PORT:-8686}"
COAP_PORT="${COAP_PORT:-5683}"
TOKEN="${TOKEN:-bootstrap-shared-token}"
SESSION_ID="${SESSION_ID:-demo-$(date +%s)}"
ID_CREDI="${ID_CREDI:-ue-0001}"
WORK="$(mktemp -d)"
EMSK_FILE="$WORK/emsk.hex"
JSONLOG="$WORK/run.jsonl"

cleanup() {
  [[ -n "${AS_PID:-}" ]] && kill "$AS_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== [0] Synthesize shared EMSK (stand-in for EAP-EDHOC output) =="
python3 -c "import os,sys; sys.stdout.write(os.urandom(64).hex())" > "$EMSK_FILE"
echo "   EMSK written to $EMSK_FILE"

echo
echo "== [1] Start Application Server (AS): HTTP key-receiver + OSCORE server =="
python3 app_server.py --http-port "$HTTP_PORT" --coap-port "$COAP_PORT" \
    --token "$TOKEN" --jsonlog "$JSONLOG" --expect 1 &
AS_PID=$!
# Wait until the AS HTTP port is accepting connections.
for _ in $(seq 1 50); do
  if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$HTTP_PORT))==0 else 1)" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

echo
echo "== [2] AAA derives USRK/DSRK and transports DSRK to AS =="
python3 aaa_keyexport.py --emsk-file "$EMSK_FILE" --session-id "$SESSION_ID" \
    --id-credi "$ID_CREDI" \
    --as-url "http://127.0.0.1:$HTTP_PORT/oscore/session" \
    --token "$TOKEN" --jsonlog "$JSONLOG"

echo
echo "== [3] UE derives the same chain and makes OSCORE first contact =="
python3 ue_client.py --emsk-file "$EMSK_FILE" --session-id "$SESSION_ID" \
    --as-host 127.0.0.1 --coap-port "$COAP_PORT" --jsonlog "$JSONLOG"

wait "$AS_PID" 2>/dev/null || true
AS_PID=""

echo
echo "== [4] Collapse structured log + verify key consistency =="
python3 verify_session.py "$JSONLOG" "$SESSION_ID"
