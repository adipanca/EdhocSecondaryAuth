#!/usr/bin/env bash
#
# variants_harness.sh — loss-free harness E2E of the Message1 variants (v4, v4s,
# v4s+chk, v4t) and EAP-TLS Hybrid PQC (method 6), taking turns in one session,
# as in v4_harness.sh: 2 runs x (20 discarded + 100). radiusd restarted and the
# records provisioned anew per variant.
#
#   sudo benchmark/variants_harness.sh           (benchmarks run as $SUDO_USER)
#
# Writes benchmark-results/e2e-handshake-variants.csv, labels
# handshake-run<r>-<variant> and handshake-run<r>-tls; ends on edhoc_variant v5.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/benchmark-results/e2e-handshake-variants.csv"
OWNER="${SUDO_USER:-$(id -un)}"
UE=/usr/local/etc/edhoc/ue/edhoc-ue
RTO=40; MR=6; T=100
PQ="$ROOT/pqc-tls"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

as_user() { sudo -u "$OWNER" "$@"; }
edhoc() { as_user "$HERE/e2e_radius_bench" --method 4 --ue-dir "$UE" --rto-ms $RTO --max-retx $MR "$@" | tail -1; }
tls6()  { (cd "$HERE" && as_user env OPENSSL_CONF="$PQ/openssl-hybrid.cnf" \
             OPENSSL_MODULES="$PQ/oqs-provider-install/lib" \
             LD_LIBRARY_PATH="$PQ/openssl32-install/lib64:$PQ/liboqs-install/lib" \
             ./eap_tls_hybrid_bench --method 6 --rto-ms $RTO --max-retx $MR "$@" | tail -1); }
stamp() { echo "== $(date +%T) $* (load $(cut -d' ' -f1-3 /proc/loadavg))"; }

rm -f "$OUT"
uname -r
for r in 1 2; do
  for v in v4 v4s v4s+chk v4t; do
    stamp "run $r: $v"
    "$HERE/set_edhoc_variant.sh" "$v"
    "$HERE/setup_no_eph.sh" | tail -1; sleep 15
    edhoc --variant "$v" --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
    edhoc --variant "$v" --iters $T --loss 0 --csv "$OUT" --label "handshake-run$r-$v"
  done
  stamp "run $r: method 6"
  "$HERE/switch_tls_config.sh" hybrid | tail -1; sleep 5
  tls6 --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  tls6 --iters $T --loss 0 --csv "$OUT" --label "handshake-run$r-tls"
  "$HERE/switch_tls_config.sh" classic | tail -1
done
"$HERE/set_edhoc_variant.sh" v5
"$HERE/setup_no_eph.sh" | tail -1
chown "$OWNER" "$OUT"
stamp "done: $OUT"
