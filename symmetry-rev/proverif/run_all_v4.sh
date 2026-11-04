#!/usr/bin/env bash
# Run the method-4 v4 ProVerif models (gen_m4v4.py), one ProVerif process
# per query, plus the unlinkability model (diff-equivalence, one process),
# and collect a summary table (query, wall time, peak memory, result).
#
#   ./run_all_v4.sh                 (requires ProVerif 2.05 on PATH)
#   JOBS=3 MEM_KB=4500000 TIMEOUT=3600 ./run_all_v4.sh [model.pv ...]
#
# A query that runs out of memory or time is reported as "NOT CONCLUDED",
# never as false. To keep the VM alive: every process has a memory cap
# (ulimit -v), a watchdog stops ProVerif when MemAvailable falls below
# MIN_AVAIL_KB, pcs and recovery get PCS_TIMEOUT per query (the step limit
# of 10 minutes), and the unlinkability models run alone, after the others.
# edhoc_m4v4_unlink_bounded.pv runs under its own cap (MemoryMax=BOUNDED_MEM,
# no swap, systemd-run; ulimit -v if that is not available).
set -u
cd "$(dirname "$0")"
JOBS="${JOBS:-3}"; MEM_KB="${MEM_KB:-4500000}"; TIMEOUT="${TIMEOUT:-3600}"
PCS_TIMEOUT="${PCS_TIMEOUT:-600}"; MIN_AVAIL_KB="${MIN_AVAIL_KB:-3000000}"
MODELS=("$@")
[ ${#MODELS[@]} -eq 0 ] && MODELS=(edhoc_m4v4_classical.pv edhoc_m4v4_quantum.pv edhoc_m4v4_kci.pv
                                    edhoc_m4v4_pcs.pv edhoc_m4v4_fs_noerase.pv edhoc_m4v4_recovery.pv
                                    edhoc_m4v4_nextkey.pv)
W=results/v4; mkdir -p "$W"

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
  local tmo=$TIMEOUT
  case "$pv" in *_pcs_q*|*_recovery_q*) tmo=$PCS_TIMEOUT ;; esac
  ( ulimit -v "$MEM_KB"; ulimit -c 0
    /usr/bin/time -f "%e %M" -o "${out}.time" timeout "$tmo" nice -n 5 proverif "$pv" > "$out" 2>&1
    echo $? > "${out}.rc" )
}
export -f run_one; export MEM_KB TIMEOUT PCS_TIMEOUT

BOUNDED_MEM="${BOUNDED_MEM:-10G}"; BOUNDED_TIMEOUT="${BOUNDED_TIMEOUT:-7200}"
run_bounded() {
  local pv=$1 out=${1%.pv}.out
  if systemd-run --user --scope -q true 2>/dev/null; then
    /usr/bin/time -f "%e %M" -o "${out}.time" systemd-run --user --scope -q -p MemoryMax="$BOUNDED_MEM" \
      -p MemorySwapMax=0 timeout "$BOUNDED_TIMEOUT" proverif "$pv" > "$out" 2>&1
  else
    ( ulimit -v 10000000; /usr/bin/time -f "%e %M" -o "${out}.time" timeout "$BOUNDED_TIMEOUT" proverif "$pv" > "$out" 2>&1 )
  fi
  echo $? > "${out}.rc"
}

# watchdog: never let ProVerif take the VM down
( while sleep 5; do
    a=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
    if [ "$a" -lt "$MIN_AVAIL_KB" ]; then
      echo "$(date +%T) MemAvailable ${a} kB: stopping the oldest proverif" >> "$W/watchdog.log"
      pkill -KILL -o -x proverif
    fi
  done ) & WD=$!
trap 'kill $WD 2>/dev/null' EXIT

for f in "${MODELS[@]}"; do rm -f "$W/${f%.pv}"_q*; split_model "$f"; done
UNL=edhoc_m4v4_unlink.pv; UNLB=edhoc_m4v4_unlink_bounded.pv
ls "$W"/*_q*.pv | xargs -P "$JOBS" -I{} bash -c 'run_one {}'
[ -n "${NO_UNLINK:-}" ] || { [ -f "$UNL" ] && cp "$UNL" "$W/" && run_one "$W/$UNL"; }
[ -n "${NO_UNLINK:-}" ] || { [ -f "$UNLB" ] && cp "$UNLB" "$W/" && run_bounded "$W/$UNLB"; }

{
  proverif -help 2>&1 | head -1
  echo "Method 4 v4 models (gen_m4v4.py), one ProVerif process per query, cap ${MEM_KB}KB / ${TIMEOUT}s"
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
      [ -z "$r" ] && r="NOT CONCLUDED (exit $rc$(grep -m1 -ioE 'out of memory|Fatal error[^.]*' "$o" | sed 's/^/, /'))"
      printf "  q%-5s %6ss %6dMB  %s\n" "$i" "$t" $((m / 1024)) "$r"
    done
  done
  for u in "$UNL" "$UNLB"; do
    [ -f "$W/${u%.pv}.out" ] || continue
    o="$W/${u%.pv}.out"; read -r t m < <(tail -1 "$o.time" 2>/dev/null) || { t=?; m=0; }
    echo "=================================================================="
    echo "$u (diff-equivalence: same UE twice on rotated keys ~ two different UEs)"
    r=$(grep -E "^RESULT" "$o" | tail -1)
    [ -z "$r" ] && r="NOT CONCLUDED (exit $(cat "$o.rc" 2>/dev/null)$(grep -m1 -ioE 'allocation failure|out of memory' "$o" | sed 's/^/, /'))"
    printf "  %-6s %6ss %6dMB  %s\n" equiv "$t" $((m / 1024)) "$r"
  done
  echo DONE
} | tee results/SUMMARY_v4.txt
