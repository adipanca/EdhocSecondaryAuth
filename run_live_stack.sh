#!/usr/bin/env bash
# Launch the full Open5GS 5GC live stack from freshly-built build-ws binaries,
# plus the UPF EAP relay, using install-ws configs. Logs to a timestamped dir.
set -uo pipefail

ROOT="/home/admin-vb/EdhocSecondaryAuth"
O5G="$ROOT/open5gs"
BIN="$O5G/build-ws"
CFG="$O5G/install-ws/etc/open5gs"
TS="$(date +%Y%m%d-%H%M%S)"
LOGDIR="$ROOT/benchmark-results/logs-live-$TS"
mkdir -p "$LOGDIR"
echo "$LOGDIR" > "$ROOT/.last_live_logdir"

export OPEN5GS_EAP_RELAY_ADDR=127.0.0.1
export OPEN5GS_EAP_RELAY_PORT=3870
export OPEN5GS_RADIUS_SERVER=127.0.0.1
export OPEN5GS_RADIUS_PORT=1812
export OPEN5GS_RADIUS_SECRET=testing123

start_nf() {
  local name="$1"; local path="$2"; local cfg="$3"
  nohup "$path" -c "$cfg" > "$LOGDIR/$name.log" 2>&1 &
  echo "  started $name (pid $!)"
}

echo "[live] launching NFs -> $LOGDIR"
start_nf nrfd  "$BIN/src/nrf/open5gs-nrfd"   "$CFG/nrf.yaml"
sleep 1
start_nf scpd  "$BIN/src/scp/open5gs-scpd"   "$CFG/scp.yaml"
sleep 1
start_nf udrd  "$BIN/src/udr/open5gs-udrd"   "$CFG/udr.yaml"
start_nf udmd  "$BIN/src/udm/open5gs-udmd"   "$CFG/udm.yaml"
start_nf ausfd "$BIN/src/ausf/open5gs-ausfd" "$CFG/ausf.yaml"
start_nf nssfd "$BIN/src/nssf/open5gs-nssfd" "$CFG/nssf.yaml"
start_nf bsfd  "$BIN/src/bsf/open5gs-bsfd"   "$CFG/bsf.yaml"
start_nf pcfd  "$BIN/src/pcf/open5gs-pcfd"   "$CFG/pcf.yaml"
sleep 1
start_nf upfd  "$BIN/src/upf/open5gs-upfd"   "$CFG/upf.yaml"
start_nf smfd  "$BIN/src/smf/open5gs-smfd"   "$CFG/smf.yaml"
sleep 1
start_nf amfd  "$BIN/src/amf/open5gs-amfd"   "$CFG/amf.yaml"
sleep 2
echo "[live] NFs up. LOGDIR=$LOGDIR"
