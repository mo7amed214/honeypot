#!/usr/bin/env bash
set -euo pipefail

PROFILE="${HONEYPOT_VAGRANT_PROFILE:-laptop1-safe}"
SAFE_NET_PREFIX="${HONEYPOT_SAFE_NET_PREFIX:-192.168.56}"
INTEGRATION_NET_PREFIX="${HONEYPOT_INTEGRATION_NET_PREFIX:-172.30.70}"
ENABLE_INTEGRATION_NIC="${HONEYPOT_ENABLE_INTEGRATION_NIC:-0}"
export VAGRANT_DOTFILE_PATH="${VAGRANT_DOTFILE_PATH:-.vagrant-${PROFILE}}"
if [[ "$PROFILE" == "integration" ]]; then
  DEFAULT_EWS_HOST="172.30.70.10"
  DEFAULT_HISTORIAN_HOST="172.30.70.11"
  DEFAULT_OPCUA_HOST="172.30.70.12"
  DEFAULT_ZEEK_HOST="172.30.70.13"
  DEFAULT_SMB_HOST="172.30.70.14"
else
  DEFAULT_EWS_HOST="${SAFE_NET_PREFIX}.5"
  DEFAULT_HISTORIAN_HOST="${SAFE_NET_PREFIX}.10"
  DEFAULT_OPCUA_HOST="${SAFE_NET_PREFIX}.11"
  DEFAULT_ZEEK_HOST="${SAFE_NET_PREFIX}.13"
  DEFAULT_SMB_HOST="${SAFE_NET_PREFIX}.7"
fi

EWS_HOST="${EWS_HOST:-$DEFAULT_EWS_HOST}"
HISTORIAN_HOST="${HISTORIAN_HOST:-$DEFAULT_HISTORIAN_HOST}"
OPCUA_HOST="${OPCUA_HOST:-$DEFAULT_OPCUA_HOST}"
ZEEK_HOST="${ZEEK_HOST:-$DEFAULT_ZEEK_HOST}"
SMB_HOST="${SMB_HOST:-$DEFAULT_SMB_HOST}"
TARGET_USER="${LEVEL3_USER:-john}"
TARGET_PASS="${LEVEL3_PASSWORD:-Cisco}"

if ! command -v sshpass >/dev/null 2>&1; then
  echo "sshpass is required for the smoke test" >&2
  exit 1
fi

check_tcp() {
  local host="$1"
  local port="$2"
  echo "[smoke] checking TCP reachability to ${host}:${port}"
  timeout 5 bash -lc "cat < /dev/null > /dev/tcp/${host}/${port}"
}

check_tcp "$EWS_HOST" 22
check_tcp "$HISTORIAN_HOST" 5000
check_tcp "$OPCUA_HOST" 4840
check_tcp "$SMB_HOST" 445
check_tcp "$ZEEK_HOST" 22

echo "[smoke] checking SSH login for ${TARGET_USER}@${EWS_HOST}"
sshpass -p "$TARGET_PASS" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 \
  "${TARGET_USER}@${EWS_HOST}" \
  "hostname && whoami"

echo "[smoke] checking historian HTTP login page"
curl -fsS --max-time 5 "http://${HISTORIAN_HOST}:5000/login" >/dev/null

if command -v smbclient >/dev/null 2>&1; then
  echo "[smoke] checking anonymous SMB share listing"
  smbclient -N -L "//${SMB_HOST}" >/dev/null
fi

if [[ "$PROFILE" != "integration" && "$ENABLE_INTEGRATION_NIC" == "1" ]]; then
  echo "[smoke] checking dual-NIC integration reachability"
  check_tcp "${INTEGRATION_NET_PREFIX}.10" 22
  check_tcp "${INTEGRATION_NET_PREFIX}.11" 5000
  check_tcp "${INTEGRATION_NET_PREFIX}.12" 4840
  check_tcp "${INTEGRATION_NET_PREFIX}.13" 22
  check_tcp "${INTEGRATION_NET_PREFIX}.14" 445
fi

echo "[smoke] OK"
