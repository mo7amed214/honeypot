#!/usr/bin/env bash
set -euo pipefail

SOURCE_LOG="/opt/zeek/spool/zeek/conn.log"
TARGET_LOG="/home/ceo/zeek_feed.log"

if [[ ! -r "$SOURCE_LOG" ]]; then
  echo "[zeek-relay] source not readable: $SOURCE_LOG" >&2
  exit 1
fi

touch "$TARGET_LOG"

echo "[zeek-relay] relaying $SOURCE_LOG -> $TARGET_LOG"
exec stdbuf -oL tail -n0 -F "$SOURCE_LOG" >> "$TARGET_LOG"
