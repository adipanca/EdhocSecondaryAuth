#!/usr/bin/env bash
#
# run_e2e_benchmarks.sh — drive the real EAP-over-RADIUS harness for every
# EDHOC method (0..4) against a live FreeRADIUS rlm_eap_edhoc responder and
# collect the per-method end-to-end CSVs consumed by e2e_analyze.py.
#
# Produces (under $OUTDIR, default ../benchmark-results):
#   e2e-handshake.csv   per-iteration handshake timing / round-trips / frags (loss 0)
#   e2e-lossy.csv       per-iteration results across method x loss-rate
#
# radiusd must already be running, e.g.:
#   echo admin | sudo -S /usr/local/sbin/radiusd -X > /tmp/radiusd.log 2>&1 &
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/e2e_radius_bench"
OUTDIR="${OUTDIR:-$HERE/../benchmark-results}"
TIMING_ITERS="${TIMING_ITERS:-100}"
LOSSY_ITERS="${LOSSY_ITERS:-120}"
RTO_MS="${RTO_MS:-40}"
MAX_RETX="${MAX_RETX:-6}"
LOSS_RATES=(0 1 5 10 20 30)
METHODS=(0 1 2 3 4)

mkdir -p "$OUTDIR"
HS_CSV="$OUTDIR/e2e-handshake.csv"
LOSS_CSV="$OUTDIR/e2e-lossy.csv"
rm -f "$HS_CSV" "$LOSS_CSV"

echo "== handshake timing (loss 0, $TIMING_ITERS iters/method) =="
for m in "${METHODS[@]}"; do
    "$BIN" --method "$m" --iters "$TIMING_ITERS" --loss 0 \
           --rto-ms "$RTO_MS" --max-retx "$MAX_RETX" \
           --csv "$HS_CSV" --label handshake | tail -1 || true
done

echo "== lossy network (method x loss, $LOSSY_ITERS iters/cell) =="
for m in "${METHODS[@]}"; do
    for l in "${LOSS_RATES[@]}"; do
        "$BIN" --method "$m" --iters "$LOSSY_ITERS" --loss "$l" \
               --rto-ms "$RTO_MS" --max-retx "$MAX_RETX" \
               --csv "$LOSS_CSV" --label lossy | tail -1 || true
    done
done

echo "CSVs written to:"
echo "  $HS_CSV"
echo "  $LOSS_CSV"
