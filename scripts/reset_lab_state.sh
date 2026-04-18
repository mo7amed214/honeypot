#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EWS_HOST="${EWS_HOST:-192.168.1.5}"
EWS_USER="${EWS_USER:-john}"
EWS_PASSWORD="${EWS_PASSWORD:-Cisco}"

cleanup_local() {
  rm -f /tmp/shift_notes.txt \
        /tmp/ews_access.txt \
        /tmp/shift_notes_demo.txt \
        /tmp/ews_maintenance_access_demo.txt
}

cleanup_remote() {
  if command -v sshpass >/dev/null 2>&1; then
    sshpass -p "$EWS_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$EWS_USER@$EWS_HOST" \
      'cmd /c "taskkill /F /IM arpspoof.exe >nul 2>&1 & del /Q C:\Users\john\Downloads\hist.cookies >nul 2>&1"' >/dev/null 2>&1 || true
  fi
}

cleanup_local
cleanup_remote
echo "[reset] removed local demo temp files"
echo "[reset] attempted EWS cleanup for arpspoof.exe and historian cookie"
echo "[reset] logs were preserved; use scripts/archive_telemetry_bundle.sh before any destructive cleanup"
