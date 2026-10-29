#!/usr/bin/env bash
# Run the method-4 v3 ProVerif models, one ProVerif process per query, and
# collect a summary table (query, wall time, peak memory, result).
#
#   ./run_all_v3.sh                 (requires ProVerif 2.05 on PATH)
#   JOBS=3 MEM_KB=4500000 TIMEOUT=3600 ./run_all_v3.sh [model.pv ...]
#
# A query that runs out of memory or time is reported as "NOT CONCLUDED",
# never as false.
set -u
cd "$(dirname "$0")"
JOBS="${JOBS:-3}"; MEM_KB="${MEM_KB:-4500000}"; TIMEOUT="${TIMEOUT:-3600}"
MODELS=("$@")
[ ${#MODELS[@]} -eq 0 ] && MODELS=(edhoc_m4v3_classical.pv edhoc_m4v3_quantum.pv edhoc_m4v3_kci.pv
                                    edhoc_m4v3_pcs.pv edhoc_m4v3_fs_noerase.pv edhoc_m4v3_recovery.pv)
W=results/v3_split; mkdir -p "$W"

# one file per query: keep every non-query line, plus the n-th query only
split_model() {
  local f=$1 b=${1%.pv} n
  n=$(grep -c '^query ' "$f")
  for i in $(seq 1 "$n"); do
    awk -v k="$i" '/^query /{q++; if (q!=k) next} {print}' "$f" > "$W/${b}_q${i}.pv"
  done
}

run_one() {
  local pv=$1 out=${1%.pv}.out
  ( ulimit -v "$MEM_KB"
    /usr/bin/time -f "%e %M" -o "${out}.time" timeout "$TIMEOUT" proverif "$pv" > "$out" 2>&1
    echo $? > "${out}.rc" )
}
export -f run_one; export MEM_KB TIMEOUT

for f in "${MODELS[@]}"; do rm -f "$W/${f%.pv}"_q*; split_model "$f"; done
ls "$W"/*_q*.pv | xargs -P "$JOBS" -I{} bash -c 'run_one {}'

{
  proverif -help 2>&1 | head -1
  echo "Method 4 v3 models (gen_m4v3.py), one ProVerif process per query, cap ${MEM_KB}KB / ${TIMEOUT}s"
  for f in "${MODELS[@]}"; do
    b=${f%.pv}
    echo "=================================================================="
    echo "$f"
    printf "  %-6s %7s %8s  %s\n" query time peakmem result
    n=$(ls "$W/${b}"_q*.pv | wc -l)
    for i in $(seq 1 "$n"); do
      o="$W/${b}_q${i}.out"; read -r t m < "$o.time" 2>/dev/null || { t=?; m=0; }
      rc=$(cat "$o.rc" 2>/dev/null || echo ?)
      r=$(sed -n '/Verification summary/,/^-\{20,\}/p' "$o" | grep -E "^Query" | sed 's/^Query //')
      [ -z "$r" ] && r="NOT CONCLUDED (exit $rc$(grep -m1 -ioE 'out of memory|Fatal error[^.]*' "$o" | sed 's/^/, /'))"
      printf "  q%-5s %6ss %6dMB  %s\n" "$i" "$t" $((m / 1024)) "$r"
    done
  done
  echo DONE
} | tee results/SUMMARY_v3.txt
