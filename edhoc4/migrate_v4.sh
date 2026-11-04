#!/usr/bin/env bash
#
# migrate_v4.sh — move DN-AAA records named by EAP identity (protocol v3)
# to internal record ids, and remove the on-disk KeyID index <db>/kid/ of the
# first v4 build. The DN-AAA rebuilds its in-memory index from the record
# slots at every start.
#
#   migrate_v4.sh <db_root> [<eap_identity>=<record_id> ...]
#   e.g. migrate_v4.sh /usr/local/etc/edhoc/edhoc_db ue1@edhoc.internet=ue1
#
# Stop radiusd first. The UE side (ue.rec) does not change; only its
# directory name may be adapted by the caller.
set -euo pipefail
ROOT="${1:?db_root}"; shift
HERE="$(cd "$(dirname "$0")" && pwd)"
for map in "$@"; do
  old="${map%%=*}"; new="${map#*=}"
  [[ -d "$ROOT/$old" ]] || { echo "no record $ROOT/$old" >&2; exit 1; }
  [[ "$new" != */* && "$new" != .* && -n "$new" ]] || { echo "bad record id $new" >&2; exit 1; }
  [[ -e "$ROOT/$new" ]] && { echo "$ROOT/$new exists" >&2; exit 1; }
  mv "$ROOT/$old" "$ROOT/$new"
  echo "  $old -> $new"
done
rm -rf "$ROOT/kid"
"$HERE/edhoc4_keygen" --scan "$ROOT"
