#!/usr/bin/env bash
#
# tamper_tests.sh — message_1 tamper tests T1-T7 against the live radiusd, per
# variant, 20 times each; the harness (e2e_radius_tamper) changes message_1.
# T7 only for v4s and v4s+chk: only they carry KeyID_B in PT1.
#
#   sudo benchmark/tamper_tests.sh [iters=20]     then tamper_analyze.py
#
# Per variant the records are provisioned anew. UE results:
# benchmark-results/tamper-variants-raw/ue.csv; per test the [E4T] aaa_msg1
# lines of the DN-AAA: <variant>-T<n>.e4t. Ends on edhoc_variant v4.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
N="${1:-20}"
OWNER="${SUDO_USER:-$(id -un)}"
OUT="$ROOT/benchmark-results/tamper-variants-raw"
UE=/usr/local/etc/edhoc/ue
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"
export E4_TIMING=1
export E4_TIMING_FILE="$OUT/current.e4t"
: > "$E4_TIMING_FILE"; chmod 0666 "$E4_TIMING_FILE"
chown -R "$OWNER" "$OUT"

for v in v4 v4s v4s+chk v4t; do
  "$HERE/set_edhoc_variant.sh" "$v"
  "$HERE/setup_no_eph.sh" ue2 | tail -1
  sleep 2
  case $v in v4s|v4s+chk) tests="1 2 3 4 5 6 7" ;; *) tests="1 2 3 4 5 6" ;; esac
  for t in $tests; do
    sudo -u "$OWNER" "$HERE/e2e_radius_tamper" --method 4 --variant "$v" --ue-dir "$UE/edhoc-ue" \
      --other-ue-dir "$UE/ue2" --rto-ms 40 --max-retx 6 --tamper "$t" --iters "$N" \
      --csv "$OUT/ue.csv" --label "$v"
    sleep 0.5
    mv "$E4_TIMING_FILE" "$OUT/$v-T$t.e4t"
    : > "$E4_TIMING_FILE"; chmod 0666 "$E4_TIMING_FILE"
    echo "$v T$t: $(grep -c aaa_msg1 "$OUT/$v-T$t.e4t") aaa_msg1 lines"
  done
done
rm -f "$E4_TIMING_FILE"
"$HERE/set_edhoc_variant.sh" v4
"$HERE/setup_no_eph.sh" | tail -1
chown -R "$OWNER" "$OUT"
