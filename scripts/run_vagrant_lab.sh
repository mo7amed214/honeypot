#!/usr/bin/env bash
set -euo pipefail

if ! command -v vagrant >/dev/null 2>&1; then
  echo "vagrant is not installed on this host" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PROFILE="${HONEYPOT_VAGRANT_PROFILE:-laptop1-safe}"
SAFE_NET_PREFIX="${HONEYPOT_SAFE_NET_PREFIX:-192.168.56}"
INTEGRATION_NET_PREFIX="${HONEYPOT_INTEGRATION_NET_PREFIX:-172.30.70}"
ENABLE_INTEGRATION_NIC="${HONEYPOT_ENABLE_INTEGRATION_NIC:-0}"
export VAGRANT_DOTFILE_PATH="${VAGRANT_DOTFILE_PATH:-.vagrant-${PROFILE}}"

if [[ "$ENABLE_INTEGRATION_NIC" == "1" && -x "${ROOT_DIR}/scripts/configure_vbox_hostonly_networks.sh" ]]; then
  "${ROOT_DIR}/scripts/configure_vbox_hostonly_networks.sh"
fi

vagrant up opcua
vagrant up historian
vagrant up ews
vagrant up zeek
vagrant up smb

if [[ "$PROFILE" == "integration" ]]; then
  EWS_HOST="172.30.70.10"
  HISTORIAN_HOST="172.30.70.11"
  OPCUA_HOST="172.30.70.12"
  ZEEK_HOST="172.30.70.13"
  SMB_HOST="172.30.70.14"
else
  EWS_HOST="${SAFE_NET_PREFIX}.5"
  HISTORIAN_HOST="${SAFE_NET_PREFIX}.10"
  OPCUA_HOST="${SAFE_NET_PREFIX}.11"
  ZEEK_HOST="${SAFE_NET_PREFIX}.13"
  SMB_HOST="${SAFE_NET_PREFIX}.7"
fi

echo
echo "Vagrant lab targets (${PROFILE}):"
echo "  EWS:       ssh john@${EWS_HOST}"
echo "  Historian: http://${HISTORIAN_HOST}:5000"
echo "  OPC UA:    opc.tcp://${OPCUA_HOST}:4840"
echo "  Zeek:      ${ZEEK_HOST}"
echo "  SMB:       //${SMB_HOST}/Operations"

if [[ "$PROFILE" != "integration" && "$ENABLE_INTEGRATION_NIC" == "1" ]]; then
  echo
  echo "Integration NIC targets (${INTEGRATION_NET_PREFIX}.x):"
  echo "  EWS:       ssh john@${INTEGRATION_NET_PREFIX}.10"
  echo "  Historian: http://${INTEGRATION_NET_PREFIX}.11:5000"
  echo "  OPC UA:    opc.tcp://${INTEGRATION_NET_PREFIX}.12:4840"
  echo "  Zeek:      ${INTEGRATION_NET_PREFIX}.13"
  echo "  SMB:       //${INTEGRATION_NET_PREFIX}.14/Operations"
fi
