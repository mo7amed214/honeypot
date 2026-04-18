#!/usr/bin/env bash
set -euo pipefail

SOURCE_EVENT_LOG="${SOURCE_EVENT_LOG:-/home/ceo/honeypot/services/historian/logs/events.jsonl}"
SOURCE_INGEST_LOG="${SOURCE_INGEST_LOG:-/home/ceo/honeypot/services/historian/logs/ingest.jsonl}"
TARGET_DIR="${TARGET_DIR:-/var/lib/docker/volumes/single-node_wazuh_logs/_data/historian}"

mkdir -p "$(dirname "$SOURCE_EVENT_LOG")" "$(dirname "$SOURCE_INGEST_LOG")" "$TARGET_DIR"
touch "$SOURCE_EVENT_LOG" "$SOURCE_INGEST_LOG"

target_event_log="$TARGET_DIR/events.jsonl"
target_ingest_log="$TARGET_DIR/ingest.jsonl"
touch "$target_event_log" "$target_ingest_log"

echo "[historian-wazuh-relay] relaying $SOURCE_EVENT_LOG -> $target_event_log"
echo "[historian-wazuh-relay] relaying $SOURCE_INGEST_LOG -> $target_ingest_log"

cleanup() {
  jobs -p | xargs -r kill >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

stdbuf -oL tail -n0 -F "$SOURCE_EVENT_LOG" >> "$target_event_log" &
pid_events=$!
stdbuf -oL tail -n0 -F "$SOURCE_INGEST_LOG" >> "$target_ingest_log" &
pid_ingest=$!

wait -n "$pid_events" "$pid_ingest"
