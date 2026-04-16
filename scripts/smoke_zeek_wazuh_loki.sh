#!/usr/bin/env bash
set -euo pipefail

UID_TAG="SMOKE100302_$(date +%s)"
FEED_LOG="/home/ceo/zeek_feed.log"
MANAGER_CONTAINER="single-node-wazuh.manager-1"
LOKI_URL="http://localhost:3100/loki/api/v1/query_range"
TIMEOUT_SECONDS="${1:-25}"

log() {
  echo "[smoke] $*"
}

fail() {
  echo "[smoke] FAIL: $*" >&2
  exit 1
}

inject_test_event() {
  printf '{"ts":%.6f,"uid":"%s","id.orig_h":"192.168.1.6","id.orig_p":54545,"id.resp_h":"192.168.1.9","id.resp_p":445,"proto":"tcp","conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,"history":"ShADadfF","orig_pkts":12,"orig_ip_bytes":980,"resp_pkts":10,"resp_ip_bytes":860,"ip_proto":6}\n' "$(date +%s.%N)" "$UID_TAG" >> "$FEED_LOG"
  log "injected uid=$UID_TAG into $FEED_LOG"
}

wait_wazuh_alert() {
  local i
  for i in $(seq 1 "$TIMEOUT_SECONDS"); do
    if docker exec "$MANAGER_CONTAINER" bash -lc "tail -n 8000 /var/ossec/logs/alerts/alerts.json | grep -q '$UID_TAG'"; then
      log "wazuh manager saw uid=$UID_TAG"
      return 0
    fi
    sleep 1
  done
  fail "uid=$UID_TAG not found in manager alerts within ${TIMEOUT_SECONDS}s"
}

wait_loki_alert() {
  local i start_ns end_ns out
  for i in $(seq 1 "$TIMEOUT_SECONDS"); do
    start_ns="$(date -u -d '10 minutes ago' +%s%N)"
    end_ns="$(date -u +%s%N)"
    out="$(curl -sG "$LOKI_URL" \
      --data-urlencode "query={job=\"wazuh\"} |= \"$UID_TAG\"" \
      --data-urlencode "start=$start_ns" \
      --data-urlencode "end=$end_ns" \
      --data-urlencode 'limit=5')"

    if echo "$out" | grep -q "$UID_TAG"; then
      log "loki saw uid=$UID_TAG"
      return 0
    fi

    sleep 1
  done
  fail "uid=$UID_TAG not found in loki within ${TIMEOUT_SECONDS}s"
}

main() {
  [[ -f "$FEED_LOG" ]] || fail "missing feed log: $FEED_LOG"
  inject_test_event
  wait_wazuh_alert
  wait_loki_alert
  log "PASS: zeek_feed -> wazuh -> loki"
}

main "$@"
