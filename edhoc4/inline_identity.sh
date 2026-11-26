#!/usr/bin/env bash
#
# inline_identity.sh — xwing_next_keygen = inline gives the same handshakes
# as the v5 core before the next-key pool (commit 284e9402, step 31): both
# builds run inline_identity.c under the same deterministic RNG and must
# print identical transcript hashes. A process that never configures the
# pool runs the inline path, the same code as edhoc4_pool_config(inline).
#
#   edhoc4/inline_identity.sh [base-commit]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BASE="${1:-284e9402}"
PQ="$ROOT/PQClean"
LIBS=("$PQ/crypto_kem/ml-kem-768/clean/libml-kem-768_clean.a"
      "$PQ/crypto_sign/ml-dsa-44/clean/libml-dsa-44_clean.a" "$PQ/common/fips202.o")
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/old"
git -C "$ROOT" show "$BASE:edhoc4/edhoc4.c" > "$T/old/edhoc4.c"
git -C "$ROOT" show "$BASE:edhoc4/edhoc4.h" > "$T/old/edhoc4.h"
build() { cc -O2 -std=c11 -I"$1" -o "$2" "$HERE/inline_identity.c" "$1/edhoc4.c" "${LIBS[@]}" -lsodium -lmbedcrypto -lm -pthread; }
build "$T/old" "$T/before"
build "$HERE" "$T/now"
"$T/before" > "$T/before.txt"
"$T/now" > "$T/now.txt"
echo "== $BASE (before the pool)"; cat "$T/before.txt"
echo "== current core, inline (unconfigured process)"; cat "$T/now.txt"
if cmp -s "$T/before.txt" "$T/now.txt"; then
  echo "RESULT: PASS (inline transcripts identical to $BASE)"
else
  echo "RESULT: FAIL (inline transcripts differ from $BASE)"; exit 1
fi
