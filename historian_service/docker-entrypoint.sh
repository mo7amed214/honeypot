#!/bin/sh
set -eu

DB_PATH="${DB_PATH:-historian.db}"
EVENT_LOG_PATH="${EVENT_LOG_PATH:-/var/log/historian/events.jsonl}"

DB_DIR="$(dirname "$DB_PATH")"
LOG_DIR="$(dirname "$EVENT_LOG_PATH")"

if [ "$DB_DIR" != "." ]; then
  mkdir -p "$DB_DIR"
fi
if [ "$LOG_DIR" != "." ]; then
  mkdir -p "$LOG_DIR"
fi

if [ ! -f "$DB_PATH" ]; then
  echo "[startup] database missing at $DB_PATH, initializing"
else
  echo "[startup] database found at $DB_PATH, reconciling canonical schema"
fi

python init_db.py

exec uvicorn main:app --host 0.0.0.0 --port 5000
