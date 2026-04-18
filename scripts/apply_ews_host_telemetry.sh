#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EWS_HOST="${EWS_HOST:-192.168.1.5}"
EWS_USER="${EWS_USER:-john}"
EWS_PASSWORD="${EWS_PASSWORD:-Cisco}"
REMOTE_SCRIPT='C:\Users\john\Downloads\enable_ews_host_telemetry.ps1'

command -v sshpass >/dev/null 2>&1 || {
  echo "[ews-telemetry] sshpass is required" >&2
  exit 1
}

sshpass -p "$EWS_PASSWORD" scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$ROOT_DIR/scripts/windows/enable_ews_host_telemetry.ps1" "$EWS_USER@$EWS_HOST:/C:/Users/john/Downloads/enable_ews_host_telemetry.ps1"

sshpass -p "$EWS_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$EWS_USER@$EWS_HOST" "powershell -NoProfile -ExecutionPolicy Bypass -File \"$REMOTE_SCRIPT\""

sshpass -p "$EWS_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$EWS_USER@$EWS_HOST" "powershell -NoProfile -Command \"Write-Output EWS-HOST-TELEMETRY-CHECK\""

echo "[ews-telemetry] applied Windows telemetry settings on $EWS_HOST"
echo "[ews-telemetry] use Wazuh rule 100405 to verify PowerShell script block visibility"
