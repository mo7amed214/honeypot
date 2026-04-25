#!/usr/bin/env bash
set -euo pipefail

HOST="${EWS_HOST:-172.30.70.10}"
PORT="${EWS_PORT:-22}"
TARGET_USER="${LEVEL3_USER:-john}"
TARGET_PASS="${LEVEL3_PASSWORD:-Cisco}"
export VAGRANT_DOTFILE_PATH="${VAGRANT_DOTFILE_PATH:-.vagrant-integration}"

if ! command -v sshpass >/dev/null 2>&1; then
  echo "sshpass is required for the smoke test" >&2
  exit 1
fi

echo "[smoke] checking TCP reachability to ${HOST}:${PORT}"
timeout 5 bash -lc "cat < /dev/null > /dev/tcp/${HOST}/${PORT}"

echo "[smoke] checking SSH login for ${TARGET_USER}@${HOST}"
sshpass -p "$TARGET_PASS" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 \
  -p "$PORT" \
  "${TARGET_USER}@${HOST}" \
  "hostname && whoami"

echo "[smoke] OK"
