#!/usr/bin/env bash
#
# set_edhoc_variant.sh — set edhoc_variant (v5, v4, v4s, v4s+chk, v4t) in the edhoc
# block of the installed EAP config. radiusd reads it at start; restart it with
# switch_tls_config.sh or setup_no_eph.sh.
#
#   sudo benchmark/set_edhoc_variant.sh v4s
set -euo pipefail
EAP_CONF=/usr/local/etc/raddb/mods-available/eap
case "${1:-}" in v5|v4|v4s|v4s+chk|v4t) ;; *) echo "usage: $0 v5|v4|v4s|v4s+chk|v4t" >&2; exit 2 ;; esac
sed -i '/^\s*edhoc_variant\s*=/d' "$EAP_CONF"
sed -i "/^\s*edhoc\s*{/a\\		edhoc_variant = \"$1\"" "$EAP_CONF"
