#!/usr/bin/env bash
# Run every ProVerif model in this folder and collect the verification summaries.
# Usage:  ./run_all.sh            (requires ProVerif 2.05 on PATH)
#         TIMEOUT=3600 ./run_all.sh
#         QUICK_TIMEOUT=300 ./run_all.sh
#         MEM_LIMIT_MB=8000 ./run_all.sh
#
# Pass 1 runs every model with QUICK_TIMEOUT. A model that runs out of time is
# deferred: once all the others have finished, pass 2 reruns it one query at a
# time, each with the full TIMEOUT. A slow model never holds up the other results.
set -u
cd "$(dirname "$0")"
TIMEOUT="${TIMEOUT:-3600}"
QUICK_TIMEOUT="${QUICK_TIMEOUT:-600}"
# Cap each ProVerif run's memory. A model that grows without bound would
# otherwise exhaust RAM, and systemd-oomd would kill the whole desktop session
# (VS Code, gnome-shell) instead of just ProVerif. Default: 50% of physical RAM.
MEM_LIMIT_MB="${MEM_LIMIT_MB:-$(awk '/^MemTotal:/ {print int($2 / 1024 / 2)}' /proc/meminfo)}"
mkdir -p results
: > results/SUMMARY.txt
proverif -help 2>&1 | head -1 | tee -a results/SUMMARY.txt
echo "Per-model limits: ${QUICK_TIMEOUT}s first pass, ${TIMEOUT}s for deferred models, ${MEM_LIMIT_MB} MB" \
  | tee -a results/SUMMARY.txt

# run_one FILE LIMIT: run one model; exit status is ProVerif's (124 = timeout).
# Its summary block is left in $block for the caller.
run_one() {
  local f="$1" limit="$2" out="results/$(basename "${1%.pv}").txt" start rc secs
  start=$(date +%s)
  ( ulimit -v $(( MEM_LIMIT_MB * 1024 )); exec timeout "$limit" proverif "$f" ) > "$out" 2>&1
  rc=$?
  # ProVerif 2.05 occasionally segfaults at random (seen on edhoc_m4_hybrid_kci;
  # a rerun succeeds), so retry a crash once.
  if [ $rc -eq 139 ]; then
    ( ulimit -v $(( MEM_LIMIT_MB * 1024 )); exec timeout "$limit" proverif "$f" ) > "$out" 2>&1
    rc=$?
  fi
  secs=$(( $(date +%s) - start ))
  block=$(
    echo "=================================================================="
    echo "$f   (exit $rc, ${secs}s)"
    if [ $rc -eq 124 ]; then echo "  TIMEOUT after ${limit}s"; fi
    if grep -qE "Out of memory|allocation failure" "$out"; then echo "  OUT OF MEMORY (limit ${MEM_LIMIT_MB} MB)"; fi
    grep -iE "^Error|error:" "$out" | head -5
    sed -n '/Verification summary/,/^-\{20,\}/p' "$out" | grep -E "Query|cannot be proved"
  )
  return $rc
}

quick=$(( QUICK_TIMEOUT < TIMEOUT ? QUICK_TIMEOUT : TIMEOUT ))
deferred=()
for f in edhoc_m4_hybrid_base.pv edhoc_m*_classical.pv edhoc_m*_quantum.pv edhoc_m*_kci.pv \
         edhoc_m4_hybrid_pcs.pv eaptls_*_classical.pv eaptls_*_quantum.pv eaptls_*_kci.pv; do
  [ -f "$f" ] || continue
  run_one "$f" "$quick"
  if [ $? -eq 124 ] && [ "$quick" -lt "$TIMEOUT" ]; then
    deferred+=("$f")
    echo "$f: slower than ${quick}s, deferred to the end"
  else
    echo "$block" | tee -a results/SUMMARY.txt
  fi
done

# keep_query FILE K: print FILE with every query statement removed except the
# K-th (1-based). A statement runs from "query" to the line ending in "."
# (a trailing comment is ignored).
keep_query() {
  awk -v k="$2" '
    /^query/ { n++; inq = 1 }
    { if (!inq || n == k) print }
    inq && /\.[ \t]*(\(\*.*\*\))?[ \t]*$/ { inq = 0 }
  ' "$1"
}

# Pass 2: a deferred model is run one query at a time. Queries are
# independent, so the results are the same; ProVerif is often much faster
# on a single query (edhoc_m3_quantum: >30 min together, ~20 s per query).
splitdir="results/split"
for f in "${deferred[@]}"; do
  echo "--- deferred model, one query per run (${TIMEOUT}s each) ---" | tee -a results/SUMMARY.txt
  mkdir -p "$splitdir"
  nq=$(grep -c '^query' "$f")
  for k in $(seq 1 "$nq"); do
    part="$splitdir/${f%.pv}_q$k.pv"
    keep_query "$f" "$k" > "$part"
    run_one "$part" "$TIMEOUT"
    echo "$block" | tee -a results/SUMMARY.txt
  done
done
echo; echo "Full outputs in results/, combined summary in results/SUMMARY.txt"
