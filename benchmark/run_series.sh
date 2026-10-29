#!/usr/bin/env bash
#
# run_series.sh — the full live benchmark series for all seven methods, in
# one VM session, as used for the paper:
#
#   1. in-process method-4 computation (m4_inproc_compare.sh, 5 x 2000)
#   2. loss-free (100) and lossy (0-30 %, 120 per cell) series, methods 0-6
#   3. flush count and wall-clock flush time, method 4 (strace -c -w)
#   4. loss-free series with warm-up: 2 runs x (20 discarded + 100), 0-6
#   5. storage ablation, durable vs tmpfs (storage_ablation.sh, 6 x 100)
#   6. recovery test, method 4: 150 handshakes at 20 % loss, then 30 at 0 %
#
#   sudo benchmark/run_series.sh        (benchmarks run as $SUDO_USER)
#
# Writes into benchmark-results/: e2e-handshake.csv, e2e-lossy.csv,
# storage-strace.txt, e2e-storage-ablation.csv, e2e-recovery.csv and
# m4-inprocess-compute.csv.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/benchmark-results"
OWNER="${SUDO_USER:-$(id -un)}"
UE=/usr/local/etc/edhoc/ue/edhoc-ue
RTO=40; MR=6; T=100; L=120
PQ="$ROOT/pqc-tls"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

as_user() { sudo -u "$OWNER" "$@"; }
edhoc() { as_user "$HERE/e2e_radius_bench" --ue-dir "$UE" --rto-ms $RTO --max-retx $MR "$@" | tail -1; }
tls5()  { (cd "$HERE" && as_user ./eap_tls_bench --method 5 --rto-ms $RTO --max-retx $MR "$@" | tail -1); }
tls6()  { (cd "$HERE" && as_user env OPENSSL_CONF="$PQ/openssl-hybrid.cnf" \
             OPENSSL_MODULES="$PQ/oqs-provider-install/lib" \
             LD_LIBRARY_PATH="$PQ/openssl32-install/lib64:$PQ/liboqs-install/lib" \
             ./eap_tls_hybrid_bench --method 6 --rto-ms $RTO --max-retx $MR "$@" | tail -1); }
classic() { "$HERE/switch_tls_config.sh" classic | tail -1; }
hybrid()  { "$HERE/switch_tls_config.sh" hybrid | tail -1; }
setup()   { "$HERE/setup_no_eph.sh" | tail -1; }
stamp()   { echo "== $(date +%T) $*"; }

stamp "1. in-process"
as_user "$HERE/m4_inproc_compare.sh" 5 2000 | tail -1

stamp "2. loss-free + lossy, methods 0-6"
setup
HS="$OUT/e2e-handshake.csv"; LS="$OUT/e2e-lossy.csv"; rm -f "$HS" "$LS"
for m in 0 1 2 3 4; do edhoc --method $m --iters $T --loss 0 --csv "$HS" --label handshake; done
for m in 0 1 2 3 4; do for l in 0 1 5 10 20 30; do
  edhoc --method $m --iters $L --loss $l --csv "$LS" --label lossy; done; done
tls5 --iters $T --loss 0 --csv "$HS" --label handshake
for l in 0 1 5 10 20 30; do tls5 --iters $L --loss $l --csv "$LS" --label lossy; done
hybrid; sleep 5
tls6 --iters $T --loss 0 --csv "$HS" --label handshake
for l in 0 1 5 10 20 30; do tls6 --iters $L --loss $l --csv "$LS" --label lossy; done
classic

stamp "3. flushes (strace -c -w), method 4"
TMP="$(as_user mktemp -d)"
setup; sleep 3
edhoc --method 4 --iters 5 --loss 0 --csv /dev/null --label warmup >/dev/null
strace -c -w -f -e trace=fsync,fdatasync -o "$TMP/dn.txt" -p "$(pgrep -x radiusd)" & SP=$!
sleep 1
as_user strace -c -w -f -e trace=fsync,fdatasync -o "$TMP/ue.txt" "$HERE/e2e_radius_bench" \
  --method 4 --iters 20 --loss 0 --ue-dir "$UE" --csv /dev/null --label strace | tail -1
sleep 2; kill -INT $SP; wait $SP 2>/dev/null
{ echo "# strace -c -w -f -e trace=fsync,fdatasync (wall-clock time per call), 20 method-4 handshakes, protocol v3, $(date +%F)"
  echo "## ue durable"; grep -v '^$' "$TMP/ue.txt"
  echo "## dn durable"; grep -v '^$' "$TMP/dn.txt"; } > "$OUT/storage-strace.txt"
chown "$OWNER" "$OUT/storage-strace.txt"; rm -rf "$TMP"
grep "fdatasync$" "$OUT/storage-strace.txt"

stamp "4. loss-free with warm-up, 2 runs"
rm -f "$HS"
for r in 1 2; do
  setup; sleep 15
  for m in 0 1 2 3 4; do
    edhoc --method $m --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
    edhoc --method $m --iters $T --loss 0 --csv "$HS" --label handshake-run$r
  done
  tls5 --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  tls5 --iters $T --loss 0 --csv "$HS" --label handshake-run$r
  hybrid; sleep 5
  tls6 --iters 20 --loss 0 --csv /dev/null --label warmup >/dev/null
  tls6 --iters $T --loss 0 --csv "$HS" --label handshake-run$r
  classic
done

stamp "5. storage ablation"
"$HERE/storage_ablation.sh" 6 100 | tail -1

stamp "6. recovery test"
RC="$OUT/e2e-recovery.csv"; rm -f "$RC"
setup; sleep 3
edhoc --method 4 --iters 150 --loss 20 --csv "$RC" --label recovery-loss20
edhoc --method 4 --iters 30 --loss 0 --csv "$RC" --label recovery-after
chown "$OWNER" "$OUT"/*.csv
stamp "SERIES DONE"
