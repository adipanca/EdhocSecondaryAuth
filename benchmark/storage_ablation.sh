#!/usr/bin/env bash
#
# storage_ablation.sh — live method-4 storage cost: key records on the VM
# disk ("durable") against the same directory on tmpfs ("tmpfs"), in
# alternating rounds so that drift of the VM affects both alike. Each round
# re-provisions the records (setup_no_eph.sh) and restarts radiusd.
#
#   sudo benchmark/storage_ablation.sh [rounds] [iters]
#
# Writes benchmark-results/e2e-storage-ablation.csv (recreated).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ROUNDS="${1:-6}"; ITERS="${2:-100}"
C=/usr/local/etc/edhoc; UE=$C/ue/edhoc-ue; ID=edhoc-ue
OUT="$ROOT/benchmark-results/e2e-storage-ablation.csv"
OWNER="${SUDO_USER:-$(id -un)}"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

BAK="$(mktemp -d)"; cp -a "$C/." "$BAK/"
cleanup() { mountpoint -q "$C" && umount "$C"; rm -rf "$BAK"; }
trap cleanup EXIT

bench() {
  sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 --ue-dir "$UE" --identity "$ID" \
       --rto-ms 40 --max-retx 6 --loss 0 --label "$1" "${@:2}" | tail -1
}
run() {     # $1 = durable|tmpfs
  if [[ $1 == tmpfs ]]; then
    mount -t tmpfs -o size=64m,mode=0755 tmpfs "$C"; cp -a "$BAK/." "$C/"
  fi
  "$HERE/setup_no_eph.sh" >/dev/null
  sleep 5
  bench warmup --iters 20 --csv /dev/null >/dev/null
  bench "$1" --iters "$ITERS" --csv "$OUT"
  if [[ $1 == tmpfs ]]; then pkill -x radiusd || true; sleep 1; umount "$C"; fi
}

rm -f "$OUT"
for r in $(seq 1 "$ROUNDS"); do
  if (( r % 2 )); then run durable; run tmpfs; else run tmpfs; run durable; fi
done
chown "$OWNER" "$OUT"
"$HERE/setup_no_eph.sh" >/dev/null
echo "wrote $OUT"
