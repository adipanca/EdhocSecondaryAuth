#!/usr/bin/env bash
#
# fullstack_bench.sh — EAP-EDHOC method 4 (final v3) through the full 5G
# path UE -> gNB -> AMF -> SMF -> UPF relay -> FreeRADIUS (UERANSIM +
# Open5GS), timed with the E4_TIMING=1 [E4T] lines of every process.
#
#   sudo benchmark/fullstack_bench.sh [N=100] [SERIES=3] [RECOVERY_N=10]
#
#   A  secondary authentication on (EAP-EDHOC), B  OPEN5GS_SEC_AUTH=0;
#   series A1 B1 A2 B2 A3 B3, each 5 warm-up + N PDU sessions
#   (nr-cli ps-establish, wait for the outcome or 5 s, ps-release, 200 ms);
#   then the recovery smoke test: E4_DROP_ONCE drops message_3 / message_4
#   once in the UPF relay, RECOVERY_N times each, each followed by normal
#   sessions until EAP-Success, then 10 normal sessions.
#
# The method-4 records of the UE (SUPI) are provisioned once at the start
# (setup_no_eph.sh), never between series. Logs: benchmark-results/
# logs-fullstack-<timestamp>/<series>/ (NFs, gnb.log, ue.log, marks.txt)
# and aaa-e4t.txt (FreeRADIUS). Then run fullstack_analyze.py <logdir>.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
N="${1:-100}"; SERIES="${2:-3}"; RN="${3:-10}"
IMSI="${FS_IMSI:-imsi-999700000000001}"
U="$ROOT/UERANSIM"
OUT="$ROOT/benchmark-results/logs-fullstack-$(date +%Y%m%d-%H%M%S)"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
mkdir -p "$OUT"
: > "$OUT/aaa-e4t.txt"; chmod 0666 "$OUT/aaa-e4t.txt"   # radiusd may run as its own user

export E4_TIMING=1
export E4_TIMING_FILE="$OUT/aaa-e4t.txt"     # rlm_eap_edhoc (radiusd -f)
export EDHOC_UE_REC="/usr/local/etc/edhoc/ue/$IMSI/ue.rec"
DROP="$OUT/drop-once"

# UE config without initial sessions: every PDU session comes from nr-cli
sed '/^sessions:/,/^$/d' "$U/config/open5gs-ue.yaml" > "$OUT/ue.yaml"

stop_stack() {
  pkill -x nr-ue; pkill -x nr-gnb
  pkill -f 'open5gs-[a-z]+d'
  for _ in $(seq 25); do pgrep -f 'open5gs-[a-z]+d|nr-ue|nr-gnb' >/dev/null || break; sleep 0.2; done
  # the UPF relay thread blocks in recvfrom() and never joins on SIGTERM
  pkill -9 -f 'open5gs-[a-z]+d|nr-ue|nr-gnb'
  for _ in $(seq 25); do pgrep -f 'open5gs-[a-z]+d|nr-ue|nr-gnb' >/dev/null || break; sleep 0.2; done
  rm -rf /tmp/UERANSIM.*
}
# $1 = series dir, $2 = OPEN5GS_SEC_AUTH value
start_stack() {
  local d="$1"
  mkdir -p "$d"
  OPEN5GS_SEC_AUTH="$2" E4_DROP_ONCE="file:$DROP" LIVE_LOGDIR="$d" "$ROOT/run_live_stack.sh" >/dev/null
  sleep 2
  (cd "$U" && nohup build/nr-gnb -c config/open5gs-gnb.yaml > "$d/gnb.log" 2>&1 &)
  sleep 2
  (cd "$U" && nohup build/nr-ue -c "$OUT/ue.yaml" > "$d/ue.log" 2>&1 &)
  for _ in $(seq 100); do grep -q "MM-REGISTERED/NORMAL-SERVICE" "$d/ue.log" 2>/dev/null && { sleep 1; return 0; }; sleep 0.2; done
  echo "UE did not register, see $d" >&2; return 1
}

echo "== provision $IMSI, restart radiusd (E4_TIMING)"
stop_stack
"$HERE/setup_no_eph.sh" "$IMSI" | tail -1
uptime | tee "$OUT/uptime.txt"
vmstat -t -n 5 > "$OUT/vmstat.txt" & VMSTAT=$!
trap 'kill $VMSTAT 2>/dev/null; stop_stack' EXIT

for s in $(seq "$SERIES"); do
  for cfg in A B; do
    d="$OUT/$cfg$s"; sa=1; [[ $cfg == B ]] && sa=0
    echo "== series $cfg$s (OPEN5GS_SEC_AUTH=$sa) $(cut -d' ' -f1-3 /proc/loadavg)"
    stop_stack; start_stack "$d" "$sa" || exit 1
    python3 "$HERE/fullstack_driver.py" bench "$d/ue.log" "$d/marks.txt" "$cfg" "$s" "$N" 5
  done
done

echo "== recovery smoke test ($RN x message_3, $RN x message_4)"
d="$OUT/R"
stop_stack; start_stack "$d" 1 || exit 1
python3 "$HERE/fullstack_driver.py" recovery "$d/ue.log" "$d/marks.txt" "$DROP" "$RN"

stop_stack
cp /tmp/radiusd-classic.log "$OUT/radiusd.log" 2>/dev/null
chown -R "${SUDO_USER:-root}" "$OUT"
echo "logs: $OUT"
