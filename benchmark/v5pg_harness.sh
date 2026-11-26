#!/usr/bin/env bash
#
# v5pg_harness.sh — loss-free harness E2E of v5 with the next X-Wing key pair
# pre-generated (pregen) or generated in the handshake (inline), and of
# EAP-TLS Hybrid PQC (method 6, unchanged), in one measurement session:
# 2 runs x (20 discarded + 100) per method, radiusd restarted for each
# method (xwing_next_keygen is read at start). The order of pregen and
# inline alternates between the runs.
#
#   sudo benchmark/v5pg_harness.sh            (benchmarks run as $SUDO_USER)
#
# Writes benchmark-results/e2e-handshake-v5pg.csv: method 4 rows labelled
# pregen-run<r> / inline-run<r>, method 6 rows tls-run<r>. Ends on pregen 64.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/benchmark-results/e2e-handshake-v5pg.csv"
OWNER="${SUDO_USER:-$(id -un)}"
UE=/usr/local/etc/edhoc/ue/edhoc-ue
RLOG=/usr/local/var/log/radius/radius.log
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

# one method-4 block: DN-AAA and UE in the same mode, fresh records
m4() {
  local mode=$1 r=$2
  stamp "run $r: v5-$mode"
  if [[ $mode == pregen ]]; then "$HERE/set_next_keygen.sh" pregen 64; else "$HERE/set_next_keygen.sh" inline; fi
  "$HERE/setup_no_eph.sh" | tail -1; sleep 15
  edhoc --next-keygen "$mode" --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  edhoc --next-keygen "$mode" --iters $T --loss 0 --csv "$OUT" --label "$mode-run$r"
  "$HERE/switch_tls_config.sh" stop >/dev/null; sleep 1
  echo "   DN-AAA: $(grep 'next-key pool' "$RLOG" | tail -1 | sed 's/.*rlm_eap_edhoc: //')"
}

rm -f "$OUT"
uname -r
"$HERE/set_edhoc_variant.sh" v5
for r in 1 2; do
  if [[ $r == 1 ]]; then m4 pregen $r; m4 inline $r; else m4 inline $r; m4 pregen $r; fi
  stamp "run $r: method 6"
  "$HERE/switch_tls_config.sh" hybrid | tail -1; sleep 5
  tls6 --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  tls6 --iters $T --loss 0 --csv "$OUT" --label tls-run$r
  "$HERE/switch_tls_config.sh" classic | tail -1
done
"$HERE/set_next_keygen.sh" pregen 64
"$HERE/setup_no_eph.sh" | tail -1
chown "$OWNER" "$OUT"
stamp "done: $OUT"
