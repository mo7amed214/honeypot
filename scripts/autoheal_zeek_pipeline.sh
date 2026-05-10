#!/usr/bin/env bash
set -euo pipefail

MAX_AGE_SECONDS="${MAX_AGE_SECONDS:-180}"
CHECK_SCRIPT="/home/ceo/honeypot/scripts/check_zeek_pipeline.sh"
LOG_TAG="[zeek-watchdog]"
REMOTE_RELAY_ENV="/etc/default/zeek-remote-relay"
ZEEK_SENSOR_MODE="${ZEEK_SENSOR_MODE:-local}"

log() {
  echo "$LOG_TAG $*"
}

run_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif [[ "${1:-}" == "docker" ]] && docker info >/dev/null 2>&1; then
    "$@"
  else
    sudo "$@"
  fi
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

ensure_zeek_running() {
  if [[ "$ZEEK_SENSOR_MODE" == "remote" ]]; then
    if run_remote_root "/opt/zeek/bin/zeekctl status" 2>/dev/null | grep -Eq 'zeek\s+standalone\s+localhost\s+running'; then
      return 0
    fi

    log "remote Zeek not running, attempting deploy"
    run_remote_root "/opt/zeek/bin/zeekctl deploy" >/dev/null
    return
  fi

  if run_root /opt/zeek/bin/zeekctl status 2>/dev/null | grep -Eq 'zeek\s+standalone\s+localhost\s+running'; then
    return 0
  fi

  log "Zeek not running, attempting deploy"
  run_root /opt/zeek/bin/zeekctl deploy >/dev/null
}

ensure_relay_running() {
  local relay_service="zeek-relay.service"
  if [[ "$ZEEK_SENSOR_MODE" == "remote" ]]; then
    relay_service="zeek-remote-relay.service"
  fi

  if systemctl is-active --quiet "$relay_service"; then
    return 0
  fi

  log "$relay_service inactive, restarting"
  run_root systemctl restart "$relay_service"
}

main() {
  ensure_zeek_running
  ensure_relay_running

  if bash "$CHECK_SCRIPT" "$MAX_AGE_SECONDS" >/dev/null 2>&1; then
    log "pipeline healthy"
    return 0
  fi

  log "pipeline check failed, trying staged recovery"

  if [[ "$ZEEK_SENSOR_MODE" == "remote" ]]; then
    run_root systemctl restart zeek-remote-relay.service
  else
    run_root systemctl restart zeek-relay.service
  fi
  sleep 3

  if bash "$CHECK_SCRIPT" "$MAX_AGE_SECONDS" >/dev/null 2>&1; then
    log "recovered after relay restart"
    return 0
  fi

  if [[ "$ZEEK_SENSOR_MODE" == "remote" ]]; then
    run_remote_root "/opt/zeek/bin/zeekctl deploy" >/dev/null
    run_root systemctl restart zeek-remote-relay.service
  else
    run_root /opt/zeek/bin/zeekctl deploy >/dev/null
    run_root systemctl restart zeek-relay.service
  fi
  sleep 5

  if bash "$CHECK_SCRIPT" "$MAX_AGE_SECONDS" >/dev/null 2>&1; then
    log "recovered after zeek deploy + relay restart"
    return 0
  fi

  log "recovery failed; manual intervention required"
  bash "$CHECK_SCRIPT" "$MAX_AGE_SECONDS"
}

main "$@"
