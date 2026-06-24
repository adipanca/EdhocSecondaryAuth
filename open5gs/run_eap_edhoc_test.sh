#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPEN5GS_DIR="$ROOT_DIR/open5gs"
UERANSIM_DIR="$ROOT_DIR/UERANSIM"

log() {
  printf '[eap-edhoc-test] %s\n' "$*"
}

export OPEN5GS_EAP_RELAY_ADDR="${OPEN5GS_EAP_RELAY_ADDR:-127.0.0.1}"
export OPEN5GS_EAP_RELAY_PORT="${OPEN5GS_EAP_RELAY_PORT:-3870}"
export OPEN5GS_RADIUS_SERVER="${OPEN5GS_RADIUS_SERVER:-127.0.0.1}"
export OPEN5GS_RADIUS_PORT="${OPEN5GS_RADIUS_PORT:-1812}"
export OPEN5GS_RADIUS_SECRET="${OPEN5GS_RADIUS_SECRET:-testing123}"

log "Using OPEN5GS_EAP_RELAY_ADDR=$OPEN5GS_EAP_RELAY_ADDR"
log "Using OPEN5GS_EAP_RELAY_PORT=$OPEN5GS_EAP_RELAY_PORT"
log "Using OPEN5GS_RADIUS_SERVER=$OPEN5GS_RADIUS_SERVER"
log "Using OPEN5GS_RADIUS_PORT=$OPEN5GS_RADIUS_PORT"

log "Restarting Open5GS services"
sudo systemctl restart open5gs-upfd
sudo systemctl restart open5gs-smfd
sudo systemctl restart open5gs-amfd
sudo systemctl restart open5gs-ausfd
sudo systemctl restart open5gs-udmd
sudo systemctl restart open5gs-udrd
sudo systemctl restart open5gs-nrfd

log "Hint: start FreeRADIUS in another terminal with 'sudo radiusd -X'"
log "Hint: start gNB and UE in another terminal from $UERANSIM_DIR"

log "Recent UPF log lines"
sudo journalctl -u open5gs-upfd -n 50 --no-pager

log "Recent SMF log lines"
sudo journalctl -u open5gs-smfd -n 50 --no-pager
