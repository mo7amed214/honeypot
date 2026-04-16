#!/usr/bin/env bash
set -euo pipefail

RELAY_LOG="/home/ceo/zeek_feed.log"
MAX_AGE_SECONDS="${1:-120}"

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

if ! run_root /opt/zeek/bin/zeekctl status 2>/dev/null | grep -Eq 'zeek\s+standalone\s+localhost\s+running'; then
  fail "Zeek is not running"
fi

if ! systemctl is-active --quiet zeek-relay.service; then
  fail "zeek-relay.service is not active"
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

echo "[zeek-pipeline] OK: zeek=running relay=active feed_age=${age}s"
