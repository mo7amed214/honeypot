#!/usr/bin/env bash
set -euo pipefail

EWS_HOST="${EWS_HOST:-192.168.1.5}"
EWS_USER="${EWS_USER:-john}"
EWS_PASSWORD="${EWS_PASSWORD:-Cisco}"
HISTORIAN_URL="${HISTORIAN_URL:-http://192.168.1.10:5000/tags}"
SMB_HOST="${SMB_HOST:-192.168.1.7}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
MAX_SKEW_SECONDS="${MAX_SKEW_SECONDS:-15}"

run_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif [[ "${1:-}" == "docker" ]] && docker info >/dev/null 2>&1; then
    "$@"
  else
    sudo "$@"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[time-sync] missing command: $1" >&2
    exit 1
  }
}

iso_to_epoch() {
  python3 - "$1" <<'PY'
import email.utils
import sys
from datetime import datetime, timezone

value = sys.argv[1].strip()
if not value:
    raise SystemExit(1)

for parser in (
    lambda text: datetime.fromisoformat(text.replace("Z", "+00:00")),
    email.utils.parsedate_to_datetime,
):
    try:
        dt = parser(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        print(int(dt.timestamp()))
        raise SystemExit(0)
    except Exception:
        pass

raise SystemExit(1)
PY
}

report_clock() {
  local name="$1"
  local iso_value="$2"
  local epoch_value skew
  if ! epoch_value="$(iso_to_epoch "$iso_value" 2>/dev/null)"; then
    echo "[time-sync] WARN: could not parse $name time: $iso_value"
    return 1
  fi
  skew="$((epoch_value - LOCAL_EPOCH))"
  printf '[time-sync] %-20s utc=%s skew=%+ss\n' "$name" "$iso_value" "$skew"
  if (( skew > MAX_SKEW_SECONDS || skew < -MAX_SKEW_SECONDS )); then
    BAD_CLOCKS+=("$name:$skew")
  fi
}

require_cmd curl
require_cmd sshpass
require_cmd nmap
require_cmd python3
require_cmd docker

LOCAL_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
LOCAL_EPOCH="$(date -u +%s)"
BAD_CLOCKS=()

printf '[time-sync] %-20s utc=%s skew=%+ss\n' "monitoring_laptop" "$LOCAL_ISO" "0"

EWS_ISO="$(
  sshpass -p "$EWS_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "$EWS_USER@$EWS_HOST" \
    "powershell -NoProfile -Command \"[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')\"" \
    2>/dev/null | tr -d '\r' | tail -n 1 || true
)"
if [[ -n "$EWS_ISO" ]]; then
  report_clock "ews_windows" "$EWS_ISO"
else
  echo "[time-sync] WARN: could not read EWS clock from $EWS_HOST"
fi

HISTORIAN_DATE="$(
  curl -skD - -o /dev/null --max-time 5 "$HISTORIAN_URL" 2>/dev/null |
    awk -F': ' 'tolower($1) == "date" {print $2}' | tr -d '\r' | tail -n 1 || true
)"
if [[ -n "$HISTORIAN_DATE" ]]; then
  report_clock "historian_http" "$HISTORIAN_DATE"
else
  echo "[time-sync] WARN: could not read Historian HTTP date from $HISTORIAN_URL"
fi

SMB_DATE="$(nmap -Pn -p445 --script smb2-time "$SMB_HOST" 2>/dev/null | awk '/date:/ {print $2" "$3" "$4" "$5" "$6" "$7}' | tail -n 1)"
if [[ -n "$SMB_DATE" ]]; then
  report_clock "smb_server" "$SMB_DATE"
else
  echo "[time-sync] WARN: could not read SMB server time from $SMB_HOST"
fi

MANAGER_ISO="$(run_root docker exec "$MANAGER_CONTAINER" date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)"
if [[ -n "$MANAGER_ISO" ]]; then
  report_clock "wazuh_manager" "$MANAGER_ISO"
else
  echo "[time-sync] WARN: could not read Wazuh manager container time"
fi

if (( ${#BAD_CLOCKS[@]} > 0 )); then
  echo "[time-sync] FAIL: skew exceeded ${MAX_SKEW_SECONDS}s for ${BAD_CLOCKS[*]}"
  exit 1
fi

echo "[time-sync] PASS: all sampled assets within ${MAX_SKEW_SECONDS}s"
