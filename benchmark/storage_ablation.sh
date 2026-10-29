#!/usr/bin/env bash
#
# storage_ablation.sh — live method-4 storage cost: key records on the VM
# disk ("durable") against the same directory on tmpfs ("tmpfs"), in
# alternating rounds so that drift of the VM affects both alike. Each round
# re-provisions the records (setup_no_eph.sh) and restarts radiusd.
#
#   sudo benchmark/storage_ablation.sh [rounds] [iters] [both|flush]
#
# both  (default): durable / tmpfs for UE and DN-AAA together
#       -> benchmark-results/e2e-storage-ablation.csv (recreated)
# flush: per-flush split, four configurations rotated every round:
#       durable (UE + DN-AAA on disk), tmpfs (both on tmpfs),
#       ue_tmpfs (UE ue/ on tmpfs, DN-AAA edhoc_db/ on disk) and
#       dn_tmpfs (UE on disk, DN-AAA on tmpfs); on the critical path the UE
#       flushes NEXT before message_3 and the DN-AAA its commit before
#       message_4, so ue_tmpfs keeps only the DN-AAA flush and dn_tmpfs only
#       the UE flush
#       -> benchmark-results/e2e-storage-flush.csv (recreated)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ROUNDS="${1:-6}"; ITERS="${2:-100}"; MODE="${3:-both}"
C=/usr/local/etc/edhoc; UE=$C/ue/edhoc-ue; ID=edhoc-ue
OWNER="${SUDO_USER:-$(id -un)}"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
case "$MODE" in
  both)  OUT="$ROOT/benchmark-results/e2e-storage-ablation.csv"; CONFIGS=(durable tmpfs) ;;
  flush) OUT="$ROOT/benchmark-results/e2e-storage-flush.csv"; CONFIGS=(durable tmpfs ue_tmpfs dn_tmpfs) ;;
  *) echo "mode: both|flush" >&2; exit 2 ;;
esac

BAK="$(mktemp -d)"; cp -a "$C/." "$BAK/"
STAGE="$(mktemp -d)"
umount_all() { local d; for d in "$C/ue" "$C/edhoc_db" "$C"; do mountpoint -q "$d" && umount "$d"; done; return 0; }
cleanup() { umount_all; rm -rf "$BAK" "$STAGE"; }
trap cleanup EXIT

bench() {
  sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 --ue-dir "$UE" --identity "$ID" \
       --rto-ms 40 --max-retx 6 --loss 0 --label "$1" "${@:2}" | tail -1
}
# move the provisioned subdirectory $1 (ue|edhoc_db) onto a tmpfs, same
# owner and mode, then restart radiusd so it opens the records there
sub_tmpfs() {
  local d="$C/$1" own mode
  own="$(stat -c %u:%g "$d")"; mode="$(stat -c %a "$d")"
  rm -rf "$STAGE/$1"; cp -a "$d" "$STAGE/$1"
  mount -t tmpfs -o "size=16m,mode=$mode,uid=${own%:*},gid=${own#*:}" tmpfs "$d"
  cp -a "$STAGE/$1/." "$d/"
  "$HERE/switch_tls_config.sh" classic >/dev/null
}
run() {     # $1 = durable|tmpfs|ue_tmpfs|dn_tmpfs
  if [[ $1 == tmpfs ]]; then
    mount -t tmpfs -o size=64m,mode=0755 tmpfs "$C"; cp -a "$BAK/." "$C/"
  fi
  "$HERE/setup_no_eph.sh" >/dev/null
  case "$1" in
    ue_tmpfs) sub_tmpfs ue ;;
    dn_tmpfs) sub_tmpfs edhoc_db ;;
  esac
  sleep 5
  bench warmup --iters 20 --csv /dev/null >/dev/null
  bench "$1" --iters "$ITERS" --csv "$OUT"
  if [[ $1 != durable ]]; then pkill -x radiusd || true; sleep 1; umount_all; fi
}

rm -f "$OUT"
n=${#CONFIGS[@]}
for r in $(seq 1 "$ROUNDS"); do
  # rotate the order every round so each configuration takes every position
  for k in $(seq 0 $((n - 1))); do run "${CONFIGS[$(( (k + r - 1) % n ))]}"; done
done
chown "$OWNER" "$OUT"
"$HERE/setup_no_eph.sh" >/dev/null
echo "wrote $OUT"
