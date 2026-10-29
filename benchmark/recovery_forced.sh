#!/usr/bin/env bash
#
# recovery_forced.sh — live recovery test of method 4 with deterministic
# losses (protocol v3, no grace key, no re-provisioning between cases):
#
#   drop_msg3  N x (session whose message_3 never reaches the DN-AAA,
#                   then one normal session): expected used_next=1,
#                   EAP-Failure, fallback=1, success on CUR
#   drop_msg4  N x (session whose message_4 is lost after the DN-AAA
#                   committed, then one normal session): expected
#                   used_next=1, fallback=0, success
#   after      10 normal sessions (desync check)
#   drop_msg3_rd0  drop_msg3 again with FreeRADIUS reject_delay = 0
#              (radiusd.conf, default 1 s: every Access-Reject is held 1 s),
#              to separate the cost of the fallback from that server
#              policy; radiusd.conf is restored afterwards
#
#   sudo benchmark/recovery_forced.sh [N=20]     (benchmarks run as $SUDO_USER)
#
# Writes benchmark-results/e2e-recovery-forced.csv: label = case,
# iteration 1 = the injected loss (status DROP), iteration 2 = the
# recovery session.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/benchmark-results/e2e-recovery-forced.csv"
OWNER="${SUDO_USER:-$(id -un)}"
UE=/usr/local/etc/edhoc/ue/edhoc-ue
N="${1:-20}"
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

edhoc() { sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 --ue-dir "$UE" --loss 0 --csv "$OUT" "$@" | tail -1; }

rm -f "$OUT"
"$HERE/setup_no_eph.sh" | tail -1; sleep 3
sudo -u "$OWNER" "$HERE/e2e_radius_bench" --method 4 --ue-dir "$UE" --iters 20 --loss 0 \
  --csv /dev/null --label warmup | tail -1
for i in $(seq "$N"); do edhoc --iters 2 --label drop_msg3 --drop-msg3-once; done
for i in $(seq "$N"); do edhoc --iters 2 --label drop_msg4 --drop-msg4-once; done
edhoc --iters 10 --label after

CONF=/usr/local/etc/raddb/radiusd.conf
cp -p "$CONF" "$CONF.recovery-bak"
trap 'mv -f "$CONF.recovery-bak" "$CONF"; "$HERE/switch_tls_config.sh" classic | tail -1' EXIT
sed -i 's/^\(\s*reject_delay = \)1$/\10/' "$CONF"
grep -q '^\s*reject_delay = 0$' "$CONF" || { echo "reject_delay not found" >&2; exit 1; }
"$HERE/switch_tls_config.sh" classic | tail -1; sleep 3
for i in $(seq "$N"); do edhoc --iters 2 --label drop_msg3_rd0 --drop-msg3-once; done
chown "$OWNER" "$OUT"
echo "wrote $OUT"
