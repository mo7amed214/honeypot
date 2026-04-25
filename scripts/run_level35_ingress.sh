#!/usr/bin/env bash
set -euo pipefail

if ! command -v vagrant >/dev/null 2>&1; then
  echo "vagrant is not installed on this host" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export HONEYPOT_VAGRANT_PROFILE=integration
export HONEYPOT_EWS_MODE="${HONEYPOT_EWS_MODE:-${HONEYPOT_LEVEL35_EWS_MODE:-linux}}"
export LEVEL3_USER="${LEVEL3_USER:-john}"
export LEVEL3_PASSWORD="${LEVEL3_PASSWORD:-Cisco}"
export VAGRANT_DOTFILE_PATH="${VAGRANT_DOTFILE_PATH:-.vagrant-integration}"

vagrant up ews

echo
echo "Level 3.5 ingress contract is up:"
echo "  Host: 172.30.70.10"
echo "  Port: 22"
echo "  User: ${LEVEL3_USER}"
echo "  Mode: ${HONEYPOT_EWS_MODE}"
echo "  Role: Level 3 EWS / operator workstation"
