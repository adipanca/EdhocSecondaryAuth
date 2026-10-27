#!/usr/bin/env bash
# Run every ProVerif model in this folder and collect the verification summaries.
# Usage:  ./run_all.sh            (requires ProVerif 2.05 on PATH)
#         TIMEOUT=3600 ./run_all.sh
set -u
cd "$(dirname "$0")"
TIMEOUT="${TIMEOUT:-1800}"
mkdir -p results
: > results/SUMMARY_v2.txt
proverif -help 2>&1 | head -1 | tee -a results/SUMMARY_v2.txt
for f in edhoc_m4v2_classical.pv edhoc_m4v2_quantum.pv edhoc_m4v2_kci.pv \
         edhoc_m4v2_pcs.pv edhoc_m4v2_fs_noerase.pv; do
  [ -f "$f" ] || continue
  out="results/${f%.pv}.txt"
  start=$(date +%s)
  timeout "$TIMEOUT" proverif "$f" > "$out" 2>&1
  rc=$?
  secs=$(( $(date +%s) - start ))
  {
    echo "=================================================================="
    echo "$f   (exit $rc, ${secs}s)"
    if [ $rc -eq 124 ]; then echo "  TIMEOUT after ${TIMEOUT}s"; fi
    grep -iE "^Error|error:" "$out" | head -5
    sed -n '/Verification summary/,/^-\{20,\}/p' "$out" | grep -E "Query|cannot be proved"
  } | tee -a results/SUMMARY_v2.txt
done
echo; echo "Full outputs in results/, combined summary in results/SUMMARY_v2.txt"
