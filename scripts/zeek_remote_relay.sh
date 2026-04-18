#!/usr/bin/env bash
set -euo pipefail

REMOTE_SENSOR_HOST="${REMOTE_SENSOR_HOST:?REMOTE_SENSOR_HOST is required}"
REMOTE_SENSOR_USER="${REMOTE_SENSOR_USER:?REMOTE_SENSOR_USER is required}"
REMOTE_SENSOR_PORT="${REMOTE_SENSOR_PORT:-22}"
REMOTE_SOURCE_LOG="${REMOTE_SOURCE_LOG:-/opt/zeek/spool/zeek/conn.log}"
REMOTE_SOURCE_LOGS="${REMOTE_SOURCE_LOGS:-}"
TARGET_LOG="${TARGET_LOG:-/home/ceo/zeek_feed.log}"
REMOTE_SENSOR_KEY="${REMOTE_SENSOR_KEY:-}"
REMOTE_SENSOR_PASSWORD="${REMOTE_SENSOR_PASSWORD:-}"
REMOTE_USE_SUDO="${REMOTE_USE_SUDO:-1}"

touch "$TARGET_LOG"

ssh_cmd=(
  ssh
  -p "$REMOTE_SENSOR_PORT"
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=3
)

if [[ -n "$REMOTE_SENSOR_KEY" ]]; then
  ssh_cmd+=(-i "$REMOTE_SENSOR_KEY")
fi

source_logs=()
if [[ -n "$REMOTE_SOURCE_LOGS" ]]; then
  # shellcheck disable=SC2206
  source_logs=($REMOTE_SOURCE_LOGS)
else
  source_logs=("$REMOTE_SOURCE_LOG")
fi

prepare_cmd=""
quoted_logs=""
for log_path in "${source_logs[@]}"; do
  prepare_cmd+="if [ ! -e $(printf '%q' "$log_path") ]; then : > $(printf '%q' "$log_path"); fi; "
  quoted_logs+=" $(printf '%q' "$log_path")"
done

remote_cmd="${prepare_cmd}exec stdbuf -oL tail -n0 -F${quoted_logs} 2>/dev/null | sed -u '/^==>/d;/^<==$/d;/^tail:/d;/^$/d'"
escaped_remote_cmd="$(printf '%q' "$remote_cmd")"

echo "[zeek-remote-relay] relaying ${REMOTE_SENSOR_USER}@${REMOTE_SENSOR_HOST}:${source_logs[*]} -> ${TARGET_LOG}"

if [[ -n "$REMOTE_SENSOR_PASSWORD" ]]; then
  if ! command -v sshpass >/dev/null 2>&1; then
    echo "[zeek-remote-relay] sshpass is required when REMOTE_SENSOR_PASSWORD is set" >&2
    exit 1
  fi
  if [[ "$REMOTE_USE_SUDO" == "1" ]]; then
    exec sshpass -p "$REMOTE_SENSOR_PASSWORD" "${ssh_cmd[@]}" \
      "${REMOTE_SENSOR_USER}@${REMOTE_SENSOR_HOST}" \
      "echo $(printf '%q' "$REMOTE_SENSOR_PASSWORD") | sudo -S -p '' bash -lc $escaped_remote_cmd" >> "$TARGET_LOG"
  fi
  exec sshpass -p "$REMOTE_SENSOR_PASSWORD" "${ssh_cmd[@]}" \
    "${REMOTE_SENSOR_USER}@${REMOTE_SENSOR_HOST}" "$remote_cmd" >> "$TARGET_LOG"
fi

if [[ "$REMOTE_USE_SUDO" == "1" ]]; then
  exec "${ssh_cmd[@]}" "${REMOTE_SENSOR_USER}@${REMOTE_SENSOR_HOST}" \
    "sudo bash -lc $escaped_remote_cmd" >> "$TARGET_LOG"
fi

exec "${ssh_cmd[@]}" "${REMOTE_SENSOR_USER}@${REMOTE_SENSOR_HOST}" "$remote_cmd" >> "$TARGET_LOG"
