#!/usr/bin/env bash
#
# compute_v5pg.sh — per-function computation of v5 with the next X-Wing key
# pair pre-generated (pregen) and generated in the handshake (inline):
#   1. crypto_bench + compute_tls_hybrid.py into compute-v5pg/ (the Figure 7
#      left harness: primitives x op counts per role; method 4 = inline)
#   2. compute_v5pg.py: v5-pregen = v5-inline minus one X-Wing KeyGen per
#      role (Keygen_MLKEM768 + Keygen_X25519), same primitives
#   3. m4_inproc_bench, real handshakes in process, inline and pregen
#      alternating, ROUNDS x ITERS -> m4-inprocess-compute-v5pg.csv
#
#   benchmark/compute_v5pg.sh [rounds=3] [iters=2000]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
R="$HERE/../benchmark-results"
ROUNDS="${1:-3}"; ITERS="${2:-2000}"
make -s -C "$HERE" crypto_bench m4_inproc_bench
uname -r
mkdir -p "$R/compute-v5pg"
"$HERE/crypto_bench" "$R/compute-v5pg" 2000 | tail -2
python3 "$HERE/compute_tls_hybrid.py" "$R/compute-v5pg" | head -1
python3 "$HERE/compute_v5pg.py"
rm -f "$R/m4-inprocess-compute-v5pg.csv"
for r in $(seq 1 "$ROUNDS"); do
  "$HERE/m4_inproc_bench" --iters "$ITERS" --next-keygen inline --csv "$R/m4-inprocess-compute-v5pg.csv" --label "inline-r$r"
  "$HERE/m4_inproc_bench" --iters "$ITERS" --next-keygen pregen --csv "$R/m4-inprocess-compute-v5pg.csv" --label "pregen-r$r"
done
