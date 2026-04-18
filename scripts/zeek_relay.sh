#!/usr/bin/env bash
set -euo pipefail

SOURCE_LOG="/opt/zeek/spool/zeek/conn.log"
TARGET_LOG="/home/ceo/zeek_feed.log"

touch "$TARGET_LOG"

while [[ ! -r "$SOURCE_LOG" ]]; do
  echo "[zeek-relay] waiting for source log: $SOURCE_LOG" >&2
  sleep 2
done

echo "[zeek-relay] relaying $SOURCE_LOG -> $TARGET_LOG"
exec stdbuf -oL tail -n0 -F "$SOURCE_LOG" >> "$TARGET_LOG"
