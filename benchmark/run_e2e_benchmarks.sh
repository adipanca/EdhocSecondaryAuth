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
TLS_BIN="$HERE/eap_tls_bench"
TLS_HYBRID_BIN="$HERE/eap_tls_hybrid_bench"
PQC_ROOT="$(cd "$HERE/../pqc-tls" 2>/dev/null && pwd)"
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

# ---------------------------------------------------------------------
# Method 5 = EAP-TLS Classic — same methodology, separate live harness
# (real mutual-TLS EAP-over-RADIUS via OpenSSL against rlm_eap_tls).
# Certs are read from ./certs/{ca,client}.pem (see eap_tls_bench.c header).
#
# IMPORTANT: radiusd must be running with the CLASSICAL tls-config for this
# (tls = tls-common) -- `benchmark/switch_tls_config.sh classic` (see below
# for method 6's counterpart). Run this block BEFORE the method-6 block, or
# re-run `switch_tls_config.sh classic` + restart radiusd afterwards if you
# need to re-run method 5 after method 6.
# ---------------------------------------------------------------------
if [[ -x "$TLS_BIN" ]]; then
    echo "== method 5 (EAP-TLS Classic) handshake timing (loss 0, $TIMING_ITERS iters) =="
    ( cd "$HERE" && "$TLS_BIN" --method 5 --iters "$TIMING_ITERS" --loss 0 \
             --rto-ms "$RTO_MS" --max-retx "$MAX_RETX" \
             --csv "$HS_CSV" --label handshake | tail -1 ) || true

    echo "== method 5 (EAP-TLS Classic) lossy network ($LOSSY_ITERS iters/cell) =="
    for l in "${LOSS_RATES[@]}"; do
        ( cd "$HERE" && "$TLS_BIN" --method 5 --iters "$LOSSY_ITERS" --loss "$l" \
                 --rto-ms "$RTO_MS" --max-retx "$MAX_RETX" \
                 --csv "$LOSS_CSV" --label lossy | tail -1 ) || true
    done
else
    echo "== method 5 (EAP-TLS Classic) skipped: $TLS_BIN not built (run 'make eap_tls_bench') =="
fi

# ---------------------------------------------------------------------
# Method 6 = EAP-TLS Hybrid PQC — X25519MLKEM768 hybrid-KEM TLS1.3 group +
# mutual ML-DSA-44 certs, genuinely live against rlm_eap_tls (same
# RADIUS/EAP/UDP harness plumbing as method 5, see
# benchmark/eap_tls_hybrid_bench.c header comment for the full story: needs
# liboqs+oqs-provider (pqc-tls/) and a private OpenSSL 3.2.6 build, both
# built from source by this task).
#
# IMPORTANT: radiusd must be running with the HYBRID tls-config AND the
# oqs-provider env vars (OPENSSL_CONF/OPENSSL_MODULES) --
# `sudo benchmark/switch_tls_config.sh hybrid` sets both up and restarts
# radiusd. A single rlm_eap_tls instance only holds one cert/group posture
# at a time, so methods 5 and 6 are measured sequentially, not
# concurrently -- run switch_tls_config.sh classic|hybrid to switch between
# them (see benchmark/switch_tls_config.sh header comment).
# ---------------------------------------------------------------------
if [[ -x "$TLS_HYBRID_BIN" && -n "$PQC_ROOT" ]]; then
    export OPENSSL_CONF="$PQC_ROOT/openssl-hybrid.cnf"
    export OPENSSL_MODULES="$PQC_ROOT/oqs-provider-install/lib"
    export LD_LIBRARY_PATH="$PQC_ROOT/openssl32-install/lib64:$PQC_ROOT/liboqs-install/lib:${LD_LIBRARY_PATH:-}"

    echo "== method 6 (EAP-TLS Hybrid PQC) handshake timing (loss 0, $TIMING_ITERS iters) =="
    ( cd "$HERE" && "$TLS_HYBRID_BIN" --method 6 --iters "$TIMING_ITERS" --loss 0 \
             --rto-ms "$RTO_MS" --max-retx "$MAX_RETX" \
             --csv "$HS_CSV" --label handshake | tail -1 ) || true

    echo "== method 6 (EAP-TLS Hybrid PQC) lossy network ($LOSSY_ITERS iters/cell) =="
    for l in "${LOSS_RATES[@]}"; do
        ( cd "$HERE" && "$TLS_HYBRID_BIN" --method 6 --iters "$LOSSY_ITERS" --loss "$l" \
                 --rto-ms "$RTO_MS" --max-retx "$MAX_RETX" \
                 --csv "$LOSS_CSV" --label lossy | tail -1 ) || true
    done
else
    echo "== method 6 (EAP-TLS Hybrid PQC) skipped: $TLS_HYBRID_BIN or $HERE/../pqc-tls not built (run 'make eap_tls_hybrid_bench') =="
fi

echo "CSVs written to:"
echo "  $HS_CSV"
echo "  $LOSS_CSV"
