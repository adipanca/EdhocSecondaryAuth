#!/usr/bin/env bash
#
# run_all_benchmarks.sh — one command to run the full EAP-EDHOC benchmark suite
# and write all results into ../benchmark-results/.
#
# Covers the five required measurements from spesifikasi.md:
#   1. handshake + crypto breakdown (Keygen/ScalarMult/Encaps/Decaps/Sign/Verify)
#   2. lossy-network performance
#   3. interoperability with an independent EDHOC implementation
#   4. packet size vs MTU / fragmentation
#   5. analysis report generation
#
# Optional end-to-end 5G testbed run (UERANSIM->Open5GS->FreeRADIUS) when
# RUN_E2E=1 (needs sudo; uses ../benchmark_secondary_auth.sh).
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$HERE/.." && pwd)"
RESULT_DIR="${RESULT_DIR:-$ROOT_DIR/benchmark-results}"
CRYPTO_ITERS="${CRYPTO_ITERS:-3000}"

mkdir -p "$RESULT_DIR"

echo "=============================================================="
echo " EAP-EDHOC Secondary Authentication — full benchmark suite"
echo " results -> $RESULT_DIR"
echo "=============================================================="

echo
echo "[0/6] Building native micro-benchmarks (libsodium + mbedTLS + PQClean)"
make -C "$HERE" >/dev/null
echo "      ok"

echo
echo "[1/6] Crypto breakdown (Keygen/ScalarMult/Encaps/Decaps/Sign/Verify)"
"$HERE/crypto_bench" "$RESULT_DIR" "$CRYPTO_ITERS"

echo
echo "[2/6] Lossy-network handshake performance"
python3 "$HERE/lossy_bench.py" "$RESULT_DIR" >/dev/null
echo "      wrote $RESULT_DIR/lossy-network.csv"

echo
echo "[3/6] Interoperability with independent EDHOC crypto (OpenSSL)"
python3 "$HERE/interop_check.py" "$RESULT_DIR" || echo "      [warn] some interop checks failed (see interop.csv)"

echo
echo "[4/6] MTU / fragmentation analysis"
python3 "$HERE/mtu_fragmentation.py" "$RESULT_DIR" >/dev/null
echo "      wrote $RESULT_DIR/mtu-fragmentation.csv"

if [[ "${RUN_E2E:-0}" == "1" ]]; then
  echo
  echo "[5/6] End-to-end 5G secondary-authentication testbed"
  ( cd "$ROOT_DIR" && ITERATIONS="${ITERATIONS:-3}" UE_TIMEOUT_SEC="${UE_TIMEOUT_SEC:-80}" \
      ./benchmark_secondary_auth.sh ) || echo "      [warn] e2e run reported issues"
else
  echo
  echo "[5/6] End-to-end 5G testbed skipped (set RUN_E2E=1 to enable)"
fi

echo
echo "[6/6] Generating analysis report"
python3 "$HERE/analyze.py" "$RESULT_DIR"

echo
echo "=============================================================="
echo " Done. Artifacts in $RESULT_DIR:"
ls -1 "$RESULT_DIR"/*.csv "$RESULT_DIR"/analysis.md 2>/dev/null | sed 's/^/   /'
echo "=============================================================="
