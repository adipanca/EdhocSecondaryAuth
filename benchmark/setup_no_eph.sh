#!/usr/bin/env bash
#
# setup_no_eph.sh — prepare the live stack for EAP-EDHOC method 4 "no-eph"
# (one-time X-Wing keys, per-UE DN-AAA records). Run with sudo before every
# e2e benchmark series so it starts from a clean, non-rotated state:
#
#   sudo benchmark/setup_no_eph.sh [extra-record-id ...]
#
#   1. installs the rebuilt rlm_eap_edhoc.so (AES-128-GCM, per-UE records)
#   2. provisions /usr/local/etc/edhoc/edhoc_db/<record_id>/ (DN-AAA side,
#      plus the KeyID index edhoc_db/kid/) and /usr/local/etc/edhoc/ue/
#      <record_id>/ (UE side, owned by $SUDO_USER so e2e_radius_bench can
#      persist the rotated keys)
#   3. restarts radiusd with the classic TLS config (methods 0-5); switch to
#      hybrid with switch_tls_config.sh for method 6
#
# Record "edhoc-ue" is always provisioned (e2e_radius_bench). Add e.g. "ue1"
# for the live 5G stack and point EDHOC_UE_REC at
# /usr/local/etc/edhoc/ue/ue1/ue.rec.
#
# Protocol v4: the DN-AAA finds <db>/<record_id>/rec.bin by KeyID_B =
# SHA-256(pk_B) from message_1 (index <db>/kid/); the outer EAP identity is
# the anonymous NAI @edhoc.internet. Key records are two-slot files (rec.bin
# on the DN-AAA, ue.rec with CUR/NEXT on the UE). Records of earlier formats
# are not converted (see edhoc4/migrate_v4.sh), re-run this script.
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
