#!/usr/bin/env bash
#
# setup_no_eph.sh — prepare the live stack for EAP-EDHOC method 4 "no-eph"
# (one-time X-Wing keys, per-UE DN-AAA records). Run with sudo before every
# e2e benchmark series so it starts from a clean, non-rotated state:
#
#   sudo benchmark/setup_no_eph.sh [extra-eap-identity ...]
#
#   1. installs the rebuilt rlm_eap_edhoc.so (AES-128-GCM, per-UE records)
#   2. provisions /usr/local/etc/edhoc/edhoc_db/<identity>/ (DN-AAA side) and
#      /usr/local/etc/edhoc/ue/<identity>/ (UE side, owned by $SUDO_USER so
#      e2e_radius_bench can persist the rotated keys)
#   3. restarts radiusd with the classic TLS config (methods 0-5); switch to
#      hybrid with switch_tls_config.sh for method 6
#
# Record id "edhoc-ue" is always provisioned (e2e_radius_bench default
# --ue-dir .../ue/edhoc-ue). Add an id per UERANSIM UE for the live 5G stack
# and point EDHOC_UE_REC at /usr/local/etc/edhoc/ue/<id>/ue.rec.
#
# Protocol v3: the EAP identity is the one-time pseudonym stored in the
# record (P_0 from edhoc4_keygen, then P_next of every session); the DN-AAA
# finds the record through its pseudonym index. Records are two-slot files
# (rec.bin on the DN-AAA, ue.rec on the UE); records of the earlier layout
# are not converted, re-run this script.
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$HERE/.." && pwd)"
CREDDIR="${CREDDIR:-/usr/local/etc/edhoc}"
OWNER="${SUDO_USER:-$(id -un)}"

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

echo "== install rlm_eap_edhoc.so"
install -m 0755 "$ROOT_DIR/freeradius-v3/build/lib/local/.libs/rlm_eap_edhoc.so" /usr/local/lib/rlm_eap_edhoc.so

echo "== provision per-UE records in $CREDDIR"
rm -rf "$CREDDIR/edhoc_db" "$CREDDIR/ue"
"$ROOT_DIR/edhoc4/edhoc4_keygen" "$CREDDIR" edhoc-ue "$@"
chmod 0700 "$CREDDIR/edhoc_db"
chmod 0755 "$CREDDIR/ue"
chown -R "$OWNER" "$CREDDIR/ue"
chmod 0644 "$CREDDIR/server.pub" "$CREDDIR/ue.pub" "$CREDDIR/ue.vk"
chmod 0600 "$CREDDIR/server.creds" "$CREDDIR/ue.creds" "$CREDDIR/ue.rec"

echo "== restart radiusd (classic TLS config, quiet -f)"
"$HERE/switch_tls_config.sh" classic
