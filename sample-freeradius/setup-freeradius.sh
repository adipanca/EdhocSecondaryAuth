#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FR_DIR="${1:-$HOME/freeradius-v3}"

if [[ ! -d "$FR_DIR" ]]; then
  git clone --branch release_3_2_6 --depth 1 https://github.com/FreeRADIUS/freeradius-server.git "$FR_DIR"
fi

cp "$ROOT_DIR/authorize" /usr/local/etc/raddb/users
cp "$ROOT_DIR/clients.conf.sample" /usr/local/etc/raddb/clients.conf

if ! grep -q "VALUE[[:space:]]\+EAP-Type[[:space:]]\+EDHOC[[:space:]]\+56" /usr/local/etc/raddb/dictionary; then
  echo "VALUE EAP-Type EDHOC 56" | sudo tee -a /usr/local/etc/raddb/dictionary >/dev/null
fi

if ! grep -q "default_eap_type = edhoc" /usr/local/etc/raddb/mods-available/eap; then
  sudo sed -i 's/default_eap_type = md5/default_eap_type = edhoc/' /usr/local/etc/raddb/mods-available/eap
  cat <<'EOF' | sudo tee -a /usr/local/etc/raddb/mods-available/eap >/dev/null

edhoc {
}
EOF
fi

echo "FreeRADIUS sample setup completed."
