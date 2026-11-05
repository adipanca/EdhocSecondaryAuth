#!/usr/bin/env bash
#
# v5_harness.sh — loss-free harness E2E of method 4 (final protocol v5) and
# EAP-TLS Hybrid PQC (method 6) in the same measurement session, as in
# v4_harness.sh: 2 runs x (20 discarded + 100), alternating, radiusd restarted
# per run.
#
#   sudo benchmark/v5_harness.sh            (benchmarks run as $SUDO_USER)
#
# Writes benchmark-results/e2e-handshake-v5-m4m6.csv (labels
# handshake-run1/2); merge_v5_handshake.py puts these rows into
# e2e-handshake.csv (methods 4 and 6) and keeps the old file as
# e2e-handshake-v4b.csv.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/benchmark-results/e2e-handshake-v5-m4m6.csv"
OWNER="${SUDO_USER:-$(id -un)}"
UE=/usr/local/etc/edhoc/ue/edhoc-ue
RTO=40; MR=6; T=100
PQ="$ROOT/pqc-tls"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

as_user() { sudo -u "$OWNER" "$@"; }
edhoc() { as_user "$HERE/e2e_radius_bench" --variant v5 --ue-dir "$UE" --rto-ms $RTO --max-retx $MR "$@" | tail -1; }
tls6()  { (cd "$HERE" && as_user env OPENSSL_CONF="$PQ/openssl-hybrid.cnf" \
             OPENSSL_MODULES="$PQ/oqs-provider-install/lib" \
             LD_LIBRARY_PATH="$PQ/openssl32-install/lib64:$PQ/liboqs-install/lib" \
             ./eap_tls_hybrid_bench --method 6 --rto-ms $RTO --max-retx $MR "$@" | tail -1); }
stamp() { echo "== $(date +%T) $* (load $(cut -d' ' -f1-3 /proc/loadavg))"; }

rm -f "$OUT"
uname -r
"$HERE/set_edhoc_variant.sh" v5
for r in 1 2; do
  stamp "run $r: method 4 (v5)"
  "$HERE/setup_no_eph.sh" | tail -1; sleep 15
  edhoc --method 4 --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  edhoc --method 4 --iters $T --loss 0 --csv "$OUT" --label handshake-run$r
  stamp "run $r: method 6"
  "$HERE/switch_tls_config.sh" hybrid | tail -1; sleep 5
  tls6 --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  tls6 --iters $T --loss 0 --csv "$OUT" --label handshake-run$r
  "$HERE/switch_tls_config.sh" classic | tail -1
done
chown "$OWNER" "$OUT"
stamp "done: $OUT"
