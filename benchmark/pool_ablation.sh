#!/usr/bin/env bash
#
# pool_ablation.sh — live method-4 ablation of the precomputed rotation key:
# "pool_on" (UE and DN-AAA take the EAD3/EAD4 key pair from the opt-in edhoc4
# pool) against "pool_off" (the default: both generate it inside the
# handshake), in alternating
# rounds on the same stack so that drift of the VM affects both alike.
#
#   sudo -E benchmark/pool_ablation.sh [rounds] [iters]
#
# Needs the stack prepared by setup_no_eph.sh. Writes
# benchmark-results/e2e-pool-ablation.csv (recreated).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ROUNDS="${1:-8}"; ITERS="${2:-100}"
UE=/usr/local/etc/edhoc/ue/edhoc-ue; ID=edhoc-ue
OUT="$ROOT/benchmark-results/e2e-pool-ablation.csv"
OWNER="${SUDO_USER:-$(id -un)}"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

bench() {   # $1 = label, rest = extra args; run as the UE owner
  sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 --ue-dir "$UE" --identity "$ID" \
       --rto-ms 40 --max-retx 6 --loss 0 "${@:2}" --label "$1" | tail -1
}
run() {     # $1 = on|off
  local size=0 flag=()
  [[ $1 == on ]] && { size=4; flag=(--pool); }
  EDHOC4_ROTATION_POOL=$size "$HERE/switch_tls_config.sh" classic | tail -1
  sleep 5
  bench "warmup" --iters 20 "${flag[@]}" --csv /dev/null >/dev/null
  bench "pool_$1" --iters "$ITERS" "${flag[@]}" --csv "$OUT"
}

rm -f "$OUT"
for r in $(seq 1 "$ROUNDS"); do
  if (( r % 2 )); then run on; run off; else run off; run on; fi
done
chown "$OWNER" "$OUT"
EDHOC4_ROTATION_POOL=0 "$HERE/switch_tls_config.sh" classic | tail -1
echo "wrote $OUT"
