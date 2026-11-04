#!/usr/bin/env bash
#
# v4_flush_trace.sh — flush count and wall-clock time per call, method 4,
# protocol v4 with the in-memory KeyID index: strace -c -w on radiusd and on
# the harness, 20 handshakes, as stage 3 of run_series.sh. Compare with
# storage-strace.txt (v3) and storage-strace-v4.txt (on-disk index).
#
#   sudo benchmark/v4_flush_trace.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/benchmark-results/storage-strace-v4b.txt"
OWNER="${SUDO_USER:-$(id -un)}"
UE=/usr/local/etc/edhoc/ue/edhoc-ue
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
TMP="$(sudo -u "$OWNER" mktemp -d)"
"$HERE/setup_no_eph.sh" | tail -1; sleep 3
sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 --iters 5 --loss 0 --ue-dir "$UE" --csv /dev/null --label warmup >/dev/null
strace -c -w -f -e trace=fsync,fdatasync,rename -o "$TMP/dn.txt" -p "$(pgrep -x radiusd)" & SP=$!
sleep 1
sudo -u "$OWNER" strace -c -w -f -e trace=fsync,fdatasync,rename -o "$TMP/ue.txt" "$HERE/e2e_radius_bench" \
  --method 4 --iters 20 --loss 0 --ue-dir "$UE" --csv /dev/null --label strace | tail -1
sleep 2; kill -INT $SP; wait $SP 2>/dev/null
{ echo "# strace -c -w -f -e trace=fsync,fdatasync,rename (wall-clock time per call), 20 method-4 handshakes, protocol v4 in-memory index, $(date +%F)"
  echo "## ue durable"; grep -v '^$' "$TMP/ue.txt"
  echo "## dn durable"; grep -v '^$' "$TMP/dn.txt"; } > "$OUT"
chown "$OWNER" "$OUT"; rm -rf "$TMP"
cat "$OUT"
