#!/usr/bin/env bash
#
# pool_tests.sh — live tests of the next-key pool (xwing_next_keygen) against
# radiusd, with e2e_radius_bench as the UE (its own pool of one key):
#
#   seq       N_SEQ handshakes in a row, pregen: Npk_A / Npk_B unique, pool_miss
#   drop2     Message2 lost, then a new run: new Npk_A, Nsk_A wiped
#   par       N_PAR UEs in parallel (own records), pregen 64: no key twice,
#             pool_miss, CPU of the refill thread, lowest pool level
#   size0     xwing_pool_size = 0: inline fallback, handshakes succeed
#   restart   radiusd restarted between two series: pool rebuilt, success
#   inline    xwing_next_keygen = inline: same sizes, no pool use
#
#   sudo benchmark/pool_tests.sh [N_SEQ=1000] [N_PAR=100] [ITERS_PAR=5]
#   then benchmark/pool_tests_analyze.py
#
# Raw output: benchmark-results/pool-tests-v5pg/. The DN-AAA pool counters
# come from the line rlm_eap_edhoc writes at shutdown (radius.log), the pool
# level at each commit from its [E4T] aaa_commit lines. Ends on pregen 64.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
N_SEQ="${1:-1000}"; N_PAR="${2:-100}"; IT_PAR="${3:-5}"
OWNER="${SUDO_USER:-$(id -un)}"
OUT="$ROOT/benchmark-results/pool-tests-v5pg"
UE=/usr/local/etc/edhoc/ue
RLOG=/usr/local/var/log/radius/radius.log
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"; chown "$OWNER" "$OUT"
export E4_TIMING=1

bench() { sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 "$@"; }
# start radiusd (records kept) with its [E4T] lines in $OUT/<phase>.e4t
start() {
  export E4_TIMING_FILE="$OUT/$1.e4t"
  : > "$E4_TIMING_FILE"; chmod 0666 "$E4_TIMING_FILE"
  "$HERE/switch_tls_config.sh" classic | tail -1
  grep "next X-Wing key pair" "$RLOG" | tail -1 > "$OUT/$1.start"
}
# stop radiusd and keep its pool counters
stop() {
  "$HERE/switch_tls_config.sh" stop >/dev/null; sleep 1
  grep "next-key pool" "$RLOG" | tail -1 > "$OUT/$1.pool"
  echo "  DN-AAA: $(sed 's/.*rlm_eap_edhoc: //' "$OUT/$1.pool")"
}
tick() { awk '{print $14 + $15}' "$1" 2>/dev/null || echo 0; }

uname -r | tee "$OUT/uname.txt"
ids=(); for i in $(seq -f "ue%03g" 1 "$N_PAR"); do ids+=("$i"); done
"$HERE/set_next_keygen.sh" pregen 64
"$HERE/setup_no_eph.sh" "${ids[@]}" | tail -1
"$HERE/switch_tls_config.sh" stop >/dev/null

echo "== seq: $N_SEQ handshakes, pregen"
start seq
bench --ue-dir "$UE/edhoc-ue" --iters "$N_SEQ" --rto-ms 40 --max-retx 6 \
  --dump-keys "$OUT/seq.keys" --csv "$OUT/seq.csv" --label seq | tail -1 | tee "$OUT/seq.ue"
stop seq

echo "== drop2: Message2 lost, then a new run"
start drop2
bench --ue-dir "$UE/edhoc-ue" --iters 2 --drop-msg2-once --rto-ms 40 --max-retx 6 \
  --dump-keys "$OUT/drop2.keys" --csv "$OUT/drop2.csv" --label drop2 | tee "$OUT/drop2.ue" | tail -3
stop drop2

echo "== par: $N_PAR UEs in parallel x $IT_PAR runs, pregen 64"
start par
bench --ue-dir "$UE/edhoc-ue" --iters 1 --csv /dev/null >/dev/null   # starts the refill thread
pid=$(pgrep -x radiusd)
tid=$(grep -l '^e4-keypool$' /proc/"$pid"/task/*/comm | head -1 | xargs dirname)
p0=$(tick /proc/"$pid"/stat); r0=$(tick "$tid/stat"); t0=$(date +%s.%N)
for id in "${ids[@]}"; do
  bench --ue-dir "$UE/$id" --iters "$IT_PAR" --rto-ms 1000 --max-retx 6 \
    --dump-keys "$OUT/par-$id.keys" --csv "$OUT/par.csv" --label "$id" > "$OUT/par-$id.ue" 2>&1 &
done
wait
t1=$(date +%s.%N); p1=$(tick /proc/"$pid"/stat); r1=$(tick "$tid/stat")
echo "wall_s=$(echo "$t1 - $t0" | bc) radiusd_cpu_ticks=$((p1 - p0)) refill_thread_cpu_ticks=$((r1 - r0)) clk_tck=$(getconf CLK_TCK)" | tee "$OUT/par.cpu"
grep -h "== method" "$OUT"/par-ue*.ue | awk '{print $5}' | sort | uniq -c
stop par

echo "== size0: xwing_pool_size = 0"
"$HERE/set_next_keygen.sh" pregen 0
start size0
bench --ue-dir "$UE/edhoc-ue" --iters 5 --rto-ms 40 --max-retx 6 --csv "$OUT/size0.csv" --label size0 | tail -1 | tee "$OUT/size0.ue"
stop size0

echo "== restart: pregen 64, radiusd restarted between two series"
"$HERE/set_next_keygen.sh" pregen 64
start restart-1
bench --ue-dir "$UE/edhoc-ue" --iters 3 --rto-ms 40 --max-retx 6 --csv "$OUT/restart.csv" --label before | tail -1 | tee "$OUT/restart-1.ue"
stop restart-1
start restart-2
bench --ue-dir "$UE/edhoc-ue" --iters 3 --rto-ms 40 --max-retx 6 --csv "$OUT/restart.csv" --label after | tail -1 | tee "$OUT/restart-2.ue"
stop restart-2

echo "== inline: xwing_next_keygen = inline (UE and DN-AAA)"
"$HERE/set_next_keygen.sh" inline
start inline
bench --ue-dir "$UE/edhoc-ue" --iters 5 --next-keygen inline --rto-ms 40 --max-retx 6 \
  --csv "$OUT/inline.csv" --label inline | tail -1 | tee "$OUT/inline.ue"
stop inline

"$HERE/set_next_keygen.sh" pregen 64
"$HERE/setup_no_eph.sh" | tail -1
chown -R "$OWNER" "$OUT"
echo "done: $OUT"
