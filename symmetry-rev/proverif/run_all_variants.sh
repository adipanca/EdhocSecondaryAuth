#!/usr/bin/env bash
# Run the Message1 variant models (gen_m4v4.py --variant, in variants/), one
# ProVerif process per query, and collect a summary table per model, in the
# format of results/SUMMARY_v4.txt: results/SUMMARY_v4_variants.txt.
#
#   ./run_all_variants.sh            (requires ProVerif 2.05 on PATH)
#
# Every process: MemoryMax=10G, no swap, timeout 3600 s. A watchdog stops
# ProVerif when MemAvailable falls below MIN_AVAIL_KB. A query stopped this way
# is reported as "NOT CONCLUDED", never as false. No unlinkability model here.
set -u
cd "$(dirname "$0")"
JOBS="${JOBS:-3}"; TMO="${TMO:-3600}"; MIN_AVAIL_KB="${MIN_AVAIL_KB:-3000000}"
W=results/v4_variants; rm -rf "$W"; mkdir -p "$W"

run_one() {
  local pv=$1 out=${1%.pv}.out
  /usr/bin/time -f "%e %M" -o "${out}.time" systemd-run --user --scope -q -p MemoryMax=10G -p MemorySwapMax=0 \
    timeout "$TMO" nice -n 5 proverif "$pv" > "$out" 2>&1
  echo $? > "${out}.rc"
}
export -f run_one; export TMO

( while sleep 5; do
    a=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    if [ "$a" -lt "$MIN_AVAIL_KB" ]; then
      echo "$(date +%T) MemAvailable ${a} kB: stopping the oldest proverif" >> "$W/watchdog.log"
      pkill -KILL -o -x proverif
    fi
  done ) & WD=$!
trap 'kill $WD 2>/dev/null' EXIT

MODELS=()
for var in v4 v4s v4s_chk v4t; do
  for k in classical quantum kci pcs fs_noerase recovery nextkey noid_classical t7_classical; do
    [ -f "variants/edhoc_m4${var}_$k.pv" ] && MODELS+=("edhoc_m4${var}_$k.pv")
  done
done
for f in "${MODELS[@]}"; do
  n=$(grep -c '^query ' "variants/$f")
  for i in $(seq 1 "$n"); do
    awk -v k="$i" '/^query /{q++; if (q!=k) next} {print}' "variants/$f" > "$W/${f%.pv}_q${i}.pv"
  done
done
ls "$W"/*_q*.pv | xargs -P "$JOBS" -I{} bash -c 'run_one {}'

{
  proverif -help 2>&1 | head -1
  echo "Message1 variant models (gen_m4v4.py --variant), one ProVerif process per query, MemoryMax=10G / ${TMO}s"
  for f in "${MODELS[@]}"; do
    b=${f%.pv}
    echo "=================================================================="
    echo "$f"
    printf "  %-6s %7s %8s  %s\n" query time peakmem result
    n=$(ls "$W/${b}"_q*.pv | wc -l)
    for i in $(seq 1 "$n"); do
      o="$W/${b}_q${i}.out"; read -r t m < <(tail -1 "$o.time" 2>/dev/null) || { t=?; m=0; }
      rc=$(cat "$o.rc" 2>/dev/null || echo ?)
      r=$(sed -n '/Verification summary/,/^-\{20,\}/p' "$o" | grep -E "^Query" | sed 's/^Query //')
      [ -z "$r" ] && r="NOT CONCLUDED (exit $rc$(grep -m1 -ioE 'out of memory|allocation failure|Fatal error[^.]*|^Error.*' "$o" | sed 's/^/, /'))"
      printf "  q%-5s %6ss %6dMB  %s\n" "$i" "$t" $((m / 1024)) "$r"
    done
  done
  echo DONE
} | tee results/SUMMARY_v4_variants.txt
