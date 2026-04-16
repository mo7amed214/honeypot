#!/usr/bin/env bash
set -euo pipefail

MAX_AGE_SECONDS="${MAX_AGE_SECONDS:-180}"
CHECK_SCRIPT="/home/ceo/honeypot/scripts/check_zeek_pipeline.sh"
LOG_TAG="[zeek-watchdog]"

log() {
  echo "$LOG_TAG $*"
}

run_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

ensure_zeek_running() {
  if run_root /opt/zeek/bin/zeekctl status 2>/dev/null | grep -Eq 'zeek\s+standalone\s+localhost\s+running'; then
    return 0
  fi

  log "Zeek not running, attempting deploy"
  run_root /opt/zeek/bin/zeekctl deploy >/dev/null
}

ensure_relay_running() {
  if systemctl is-active --quiet zeek-relay.service; then
    return 0
  fi

  log "zeek-relay.service inactive, restarting"
  run_root systemctl restart zeek-relay.service
}

main() {
  ensure_zeek_running
  ensure_relay_running

  if "$CHECK_SCRIPT" "$MAX_AGE_SECONDS" >/dev/null 2>&1; then
    log "pipeline healthy"
    return 0
  fi

  log "pipeline check failed, trying staged recovery"

  # Stage 1: restart relay first (fast and low impact).
  run_root systemctl restart zeek-relay.service
  sleep 3
  if "$CHECK_SCRIPT" "$MAX_AGE_SECONDS" >/dev/null 2>&1; then
    log "recovered after relay restart"
    return 0
  fi

  # Stage 2: redeploy Zeek and restart relay.
  run_root /opt/zeek/bin/zeekctl deploy >/dev/null
  run_root systemctl restart zeek-relay.service
  sleep 5

  if "$CHECK_SCRIPT" "$MAX_AGE_SECONDS" >/dev/null 2>&1; then
    log "recovered after zeek deploy + relay restart"
    return 0
  fi

  log "recovery failed; manual intervention required"
  "$CHECK_SCRIPT" "$MAX_AGE_SECONDS"
}

main "$@"
