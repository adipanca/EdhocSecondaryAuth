#!/usr/bin/env bash
#
# fullstack_bench.sh — EAP-EDHOC method 4 (final v3) through the full 5G
# path UE -> gNB -> AMF -> SMF -> UPF relay -> FreeRADIUS (UERANSIM +
# Open5GS), timed with the E4_TIMING=1 [E4T] lines of every process.
# Secondary authentication runs inside PDU session establishment (TS 23.502
# 4.3.2.2.1 step 6): the session ends with the ESTABLISHMENT ACCEPT carrying
# the EAP-Success, or a REJECT #29.
#
#   sudo benchmark/fullstack_bench.sh [N=100] [SERIES=3] [RECOVERY_N=10]
#
#   A  secondary authentication on (smf.yaml secondary_auth for the DNN),
#   B  OPEN5GS_SEC_AUTH=0,
#   C  e2e_radius_bench method 4 straight to radiusd while the stack is up
#      but idle (shared CPU, no relay);
#   series A1 B1 C1 A2 B2 C2 A3 B3 C3, each 5 warm-up + N sessions
#   (A/B: nr-cli ps-establish, wait for Accept/Reject or 5 s, ps-release,
#   200 ms); then the recovery test (E4_DROP_ONCE drops message_3 /
#   message_4 once in the UPF relay, RECOVERY_N times each, each followed by
#   sessions until EAP-Success, then 10 normal sessions), then a sample
#   capture on lo (one session, one message_3 drop and its recovery).
#
# The method-4 records of the DN-specific identity (ue.yaml
# secondaryAuth.identity) are provisioned once at the start
# (setup_no_eph.sh), never between series. Logs: benchmark-results/
# logs-fullstack-v2-<timestamp>/<series>/ (NFs, gnb.log, ue.log, marks.txt),
# aaa-e4t.txt (FreeRADIUS), harness-C*.csv, capture.pcap.
# Then run fullstack_analyze.py <logdir> v2.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
N="${1:-100}"; SERIES="${2:-3}"; RN="${3:-10}"
U="$ROOT/UERANSIM"
OWNER="${SUDO_USER:-$(id -un)}"
IDENT="$(sed -n "/^secondaryAuth:/,/^[^ ]/s/^ *identity: *'\{0,1\}\([^']*\)'\{0,1\} *$/\1/p" "$U/config/open5gs-ue.yaml")"
[[ -n "$IDENT" ]] || { echo "no secondaryAuth.identity in open5gs-ue.yaml" >&2; exit 1; }
OUT="$ROOT/benchmark-results/logs-fullstack-v2-$(date +%Y%m%d-%H%M%S)"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
mkdir -p "$OUT"; chown "$OWNER" "$OUT"     # harness-C*.csv are written as $OWNER
: > "$OUT/aaa-e4t.txt"; chmod 0666 "$OUT/aaa-e4t.txt"   # radiusd may run as its own user

export E4_TIMING=1
export E4_TIMING_FILE="$OUT/aaa-e4t.txt"     # rlm_eap_edhoc (radiusd -f)
export EDHOC_UE_REC="/usr/local/etc/edhoc/ue/$IDENT/ue.rec"
export FS_ID="$IDENT"
DROP="$OUT/drop-once"

# UE config without initial sessions: every PDU session comes from nr-cli
sed '/^sessions:/,/^$/d' "$U/config/open5gs-ue.yaml" > "$OUT/ue.yaml"

stop_stack() {
  pkill -x nr-ue; pkill -x nr-gnb
  pkill -f 'open5gs-[a-z]+d'
  for _ in $(seq 25); do pgrep -f 'open5gs-[a-z]+d|nr-ue|nr-gnb' >/dev/null || break; sleep 0.2; done
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
# configuration C: harness straight to radiusd, stack idle
harness() {
  local csv="$OUT/harness-C$1.csv"
  sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 --ue-dir /usr/local/etc/edhoc/ue/edhoc-ue \
    --rto-ms 40 --max-retx 6 --loss 0 --iters 5 --csv /dev/null --label warmup | tail -1
  sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 --ue-dir /usr/local/etc/edhoc/ue/edhoc-ue \
    --rto-ms 40 --max-retx 6 --loss 0 --iters "$N" --csv "$csv" --label "C$1" | tail -1
}

echo "== provision $IDENT (and edhoc-ue for C), restart radiusd (E4_TIMING)"
stop_stack
"$HERE/setup_no_eph.sh" "$IDENT" | tail -1
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
  echo "== series C$s (harness, stack idle) $(cut -d' ' -f1-3 /proc/loadavg)"
  sleep 2
  harness "$s"
done

echo "== recovery test ($RN x message_3, $RN x message_4)"
d="$OUT/R"
stop_stack; start_stack "$d" 1 || exit 1
python3 "$HERE/fullstack_driver.py" recovery "$d/ue.log" "$d/marks.txt" "$DROP" "$RN"

echo "== sample capture"
d="$OUT/P"
stop_stack; start_stack "$d" 1 || exit 1
# -G 40 -W 1: tcpdump stops by itself after 40 s (the AppArmor profile of
# tcpdump may refuse signals from the calling shell)
tcpdump -i lo -s 0 -U -G 40 -W 1 -w "$OUT/capture.pcap" \
  'sctp or udp port 1812 or udp port 3870 or tcp port 7777' > "$d/tcpdump.log" 2>&1 & TCPD=$!
sleep 1
python3 "$HERE/fullstack_driver.py" capture "$d/ue.log" "$d/marks.txt" "$DROP"
wait $TCPD 2>/dev/null

stop_stack
cp /tmp/radiusd-classic.log "$OUT/radiusd.log" 2>/dev/null
chown -R "$OWNER" "$OUT"
echo "logs: $OUT"
