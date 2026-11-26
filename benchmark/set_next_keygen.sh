#!/usr/bin/env bash
#
# set_next_keygen.sh — set xwing_next_keygen (pregen | inline) and, for pregen,
# xwing_pool_size in the edhoc block of the installed EAP config. radiusd
# reads them at start; restart it with switch_tls_config.sh or setup_no_eph.sh.
#
#   sudo benchmark/set_next_keygen.sh pregen [pool_size]   (default 64)
#   sudo benchmark/set_next_keygen.sh inline
set -euo pipefail
EAP_CONF=/usr/local/etc/raddb/mods-available/eap
mode="${1:-}"; size="${2:-64}"
case "$mode" in pregen|inline) ;; *) echo "usage: $0 pregen [pool_size] | inline" >&2; exit 2 ;; esac
[[ $size =~ ^[0-9]+$ ]] || { echo "pool size must be a number" >&2; exit 2; }
sed -i '/^\s*xwing_next_keygen\s*=/d; /^\s*xwing_pool_size\s*=/d' "$EAP_CONF"
sed -i "/^\s*edhoc\s*{/a\\		xwing_pool_size = $size" "$EAP_CONF"
sed -i "/^\s*edhoc\s*{/a\\		xwing_next_keygen = \"$mode\"" "$EAP_CONF"
