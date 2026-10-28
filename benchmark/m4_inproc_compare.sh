#!/usr/bin/env bash
#
# m4_inproc_compare.sh — method 4 in-process computation, before vs after
# the X-Wing / rotation-key changes, interleaved over several rounds:
#
#   before                 edhoc4 core of git ref $BEFORE (default f65dfbe):
#                          non-standard SHA-256 combiner, decapsulation
#                          recomputes pk_X, rotation key generated inline
#   inline_rotation_keygen current core with --no-pool
#   precomputed_rotation   current core, next key pair made between handshakes
#
#   benchmark/m4_inproc_compare.sh [rounds] [iters]
#
# Appends to benchmark-results/m4-inprocess-compute.csv (recreated).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ROUNDS="${1:-5}"; ITERS="${2:-2000}"; BEFORE="${BEFORE:-f65dfbe}"
PQ="$ROOT/PQClean"
OUT="$ROOT/benchmark-results/m4-inprocess-compute.csv"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

make -s -C "$ROOT/edhoc4" libedhoc4.a
make -s -C "$HERE" m4_inproc_bench
git -C "$ROOT" show "$BEFORE:edhoc4/edhoc4.c" > "$TMP/edhoc4.c"
git -C "$ROOT" show "$BEFORE:edhoc4/edhoc4.h" > "$TMP/edhoc4.h"
cc -O2 -std=c11 -fPIC -c "$TMP/edhoc4.c" -o "$TMP/edhoc4.o"
cc -O2 -DNO_POOL_API -I"$TMP" -o "$TMP/m4_before" "$HERE/m4_inproc_bench.c" "$TMP/edhoc4.o" \
   "$PQ/crypto_kem/ml-kem-768/clean/libml-kem-768_clean.a" \
   "$PQ/crypto_sign/ml-dsa-44/clean/libml-dsa-44_clean.a" \
   "$PQ/common/fips202.o" "$PQ/common/randombytes.o" -lsodium -lmbedcrypto -lm

rm -f "$OUT"
for r in $(seq 1 "$ROUNDS"); do
  "$TMP/m4_before" --iters "$ITERS" --csv "$OUT" --label before
  "$HERE/m4_inproc_bench" --iters "$ITERS" --no-pool --csv "$OUT" --label inline_rotation_keygen
  "$HERE/m4_inproc_bench" --iters "$ITERS" --csv "$OUT" --label precomputed_rotation
done
echo "wrote $OUT"
