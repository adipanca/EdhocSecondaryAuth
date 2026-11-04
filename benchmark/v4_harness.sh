#!/usr/bin/env bash
#
# v4_harness.sh — loss-free harness E2E of method 4 (protocol v4: KeyID_B in
# message_1, anonymous identity) and EAP-TLS Hybrid PQC (method 6) in the
# same measurement session, as in run_series.sh stage 4: 2 runs x (20
# discarded + 100), alternating, radiusd restarted per run.
#
#   sudo benchmark/v4_harness.sh            (benchmarks run as $SUDO_USER)
#
# Writes benchmark-results/e2e-handshake-v4-m4m6.csv (labels
# handshake-run1/2); merge_v4_handshake.py puts these rows into
# e2e-handshake.csv (methods 4 and 6) and keeps the old file as
# e2e-handshake-v3.csv.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/benchmark-results/e2e-handshake-v4-m4m6.csv"
OWNER="${SUDO_USER:-$(id -un)}"
UE=/usr/local/etc/edhoc/ue/edhoc-ue
RTO=40; MR=6; T=100
PQ="$ROOT/pqc-tls"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

as_user() { sudo -u "$OWNER" "$@"; }
edhoc() { as_user "$HERE/e2e_radius_bench" --ue-dir "$UE" --rto-ms $RTO --max-retx $MR "$@" | tail -1; }
tls6()  { (cd "$HERE" && as_user env OPENSSL_CONF="$PQ/openssl-hybrid.cnf" \
             OPENSSL_MODULES="$PQ/oqs-provider-install/lib" \
             LD_LIBRARY_PATH="$PQ/openssl32-install/lib64:$PQ/liboqs-install/lib" \
             ./eap_tls_hybrid_bench --method 6 --rto-ms $RTO --max-retx $MR "$@" | tail -1); }
stamp() { echo "== $(date +%T) $* (load $(cut -d' ' -f1-3 /proc/loadavg))"; }

rm -f "$OUT"
vmstat -t -n 5 > "$ROOT/benchmark-results/v4-harness-vmstat.txt" & VMSTAT=$!
trap 'kill $VMSTAT 2>/dev/null' EXIT
for r in 1 2; do
  stamp "run $r: method 4"
  "$HERE/setup_no_eph.sh" | tail -1; sleep 15
  edhoc --method 4 --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  edhoc --method 4 --iters $T --loss 0 --csv "$OUT" --label handshake-run$r
  stamp "run $r: method 6"
  "$HERE/switch_tls_config.sh" hybrid | tail -1; sleep 5
  tls6 --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  tls6 --iters $T --loss 0 --csv "$OUT" --label handshake-run$r
  "$HERE/switch_tls_config.sh" classic | tail -1
done
chown "$OWNER" "$OUT" "$ROOT/benchmark-results/v4-harness-vmstat.txt"
stamp "done: $OUT"
