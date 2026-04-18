#!/usr/bin/env bash
set -euo pipefail

RELAY_LOG="/home/ceo/zeek_feed.log"
SOURCE_LOG="/opt/zeek/spool/zeek/conn.log"
MAX_AGE_SECONDS="${1:-120}"
TAIL_WINDOW_LINES="${TAIL_WINDOW_LINES:-4000}"
UID_MATCH_RETRIES="${UID_MATCH_RETRIES:-5}"
REMOTE_RELAY_ENV="/etc/default/zeek-remote-relay"
ZEEK_SENSOR_MODE="${ZEEK_SENSOR_MODE:-local}"

run_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

fail() {
  echo "[zeek-pipeline] FAIL: $1"
  exit 1
}

if [[ -r "$REMOTE_RELAY_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$REMOTE_RELAY_ENV"
fi

if [[ "$ZEEK_SENSOR_MODE" == "local" && -n "${REMOTE_SENSOR_HOST:-}" ]]; then
  ZEEK_SENSOR_MODE="remote"
fi

build_remote_ssh_cmd() {
  local -n out_ref=$1
  out_ref=(
    ssh
    -p "${REMOTE_SENSOR_PORT:-22}"
    -o LogLevel=ERROR
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=3
  )

  if [[ -n "${REMOTE_SENSOR_KEY:-}" ]]; then
    out_ref+=(-i "$REMOTE_SENSOR_KEY")
  fi
}

run_remote() {
  local remote_cmd="$1"
  local ssh_cmd=()
  build_remote_ssh_cmd ssh_cmd

  if [[ -n "${REMOTE_SENSOR_PASSWORD:-}" ]]; then
    sshpass -p "$REMOTE_SENSOR_PASSWORD" "${ssh_cmd[@]}" \
      "${REMOTE_SENSOR_USER}@${REMOTE_SENSOR_HOST}" "$remote_cmd"
    return
  fi

  "${ssh_cmd[@]}" "${REMOTE_SENSOR_USER}@${REMOTE_SENSOR_HOST}" "$remote_cmd"
}

run_remote_root() {
  local remote_cmd="$1"
  local escaped
  escaped="$(printf '%q' "$remote_cmd")"

  if [[ -n "${REMOTE_SENSOR_PASSWORD:-}" ]]; then
    run_remote "echo $(printf '%q' "$REMOTE_SENSOR_PASSWORD") | sudo -S -p '' bash -lc $escaped"
    return
  fi

  run_remote "sudo bash -lc $escaped"
}

if [[ "$ZEEK_SENSOR_MODE" == "remote" ]]; then
  RELAY_SERVICE="zeek-remote-relay.service"
  SOURCE_LOG="${REMOTE_PRIMARY_SOURCE_LOG:-${REMOTE_SOURCE_LOG:-/opt/zeek/spool/zeek/conn.log}}"

  if ! run_remote_root "/opt/zeek/bin/zeekctl status" 2>/dev/null | grep -Eq 'zeek\s+standalone\s+localhost\s+running'; then
    fail "Remote Zeek is not running"
  fi

  if ! run_remote_root "test -r $SOURCE_LOG"; then
    fail "Remote source log missing or unreadable: $SOURCE_LOG"
  fi
else
  RELAY_SERVICE="zeek-relay.service"

  if ! run_root /opt/zeek/bin/zeekctl status 2>/dev/null | grep -Eq 'zeek\s+standalone\s+localhost\s+running'; then
    fail "Zeek is not running"
  fi

  if ! run_root test -r "$SOURCE_LOG"; then
    fail "Source log missing or unreadable: $SOURCE_LOG"
  fi
fi

if ! systemctl is-active --quiet "$RELAY_SERVICE"; then
  fail "$RELAY_SERVICE is not active"
fi

if [[ ! -f "$RELAY_LOG" ]]; then
  fail "Relay log missing: $RELAY_LOG"
fi

now_ts="$(date +%s)"
relay_ts="$(stat -c %Y "$RELAY_LOG")"
age="$((now_ts - relay_ts))"

if (( age > MAX_AGE_SECONDS )); then
  fail "Relay file stale (${age}s > ${MAX_AGE_SECONDS}s): $RELAY_LOG"
fi

if [[ "$ZEEK_SENSOR_MODE" == "remote" ]]; then
  source_info="$(
    run_remote_root "python3 - '$SOURCE_LOG' <<'PY'
import os
import sys

path = sys.argv[1]
fields = []
last_line = ''

with open(path, 'r', encoding='utf-8', errors='replace') as fh:
    for raw_line in fh:
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('#fields'):
            fields = line.split('\t')[1:]
            continue
        if line.startswith('#'):
            continue
        last_line = line

if not last_line:
    print('\t\t0')
    raise SystemExit(0)

uid = ''
ts = 0.0

if last_line.startswith('{'):
    import json
    obj = json.loads(last_line)
    uid = str(obj.get('uid', ''))
    ts = float(obj.get('ts', 0) or 0)
else:
    values = last_line.split('\t')
    if fields and len(values) == len(fields):
        row = dict(zip(fields, values))
        uid = str(row.get('uid', ''))
        try:
            ts = float(row.get('ts', 0) or 0)
        except Exception:
            ts = 0.0

mtime = int(os.path.getmtime(path))
print(f'{uid}\t{ts}\t{mtime}')
PY"
  )"
else
  source_info="$(
    run_root python3 - "$SOURCE_LOG" <<'PY'
import json
import os
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="replace") as fh:
    lines = [line.strip() for line in fh if line.strip()]

if not lines:
    print("\t\t0")
    raise SystemExit(0)

last = json.loads(lines[-1])
uid = str(last.get("uid", ""))
ts = float(last.get("ts", 0) or 0)
mtime = int(os.path.getmtime(path))
print(f"{uid}\t{ts}\t{mtime}")
PY
  )"
fi

source_uid="$(printf '%s' "$source_info" | awk -F '\t' '{print $1}')"
source_event_ts="$(printf '%s' "$source_info" | awk -F '\t' '{print $2}')"
source_mtime="$(printf '%s' "$source_info" | awk -F '\t' '{print $3}')"

if [[ -z "$source_uid" ]]; then
  fail "Source log has no live conn.log entries yet: $SOURCE_LOG"
fi

source_age="$((now_ts - source_mtime))"
if (( source_age > MAX_AGE_SECONDS )); then
  fail "Source conn.log stale (${source_age}s > ${MAX_AGE_SECONDS}s): $SOURCE_LOG"
fi

uid_found=0
for _ in $(seq 1 "$UID_MATCH_RETRIES"); do
  if python3 - "$RELAY_LOG" "$source_uid" "$TAIL_WINDOW_LINES" <<'PY'
import json
import sys
from collections import deque

path = sys.argv[1]
uid = sys.argv[2]
window = int(sys.argv[3])

buf = deque(maxlen=window)
with open(path, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        line = line.strip()
        if line:
            buf.append(line)

for line in reversed(buf):
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if str(obj.get("uid", "")) == uid:
        raise SystemExit(0)

raise SystemExit(1)
PY
  then
    uid_found=1
    break
  fi

  sleep 1
done

if (( uid_found == 0 )); then
  fail "Latest conn.log uid=$source_uid not found in relay feed tail (last ${TAIL_WINDOW_LINES} lines)"
fi

echo "[zeek-pipeline] OK: zeek=running relay=active source_age=${source_age}s feed_age=${age}s uid=${source_uid} conn_ts=${source_event_ts}"
