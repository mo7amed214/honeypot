#!/bin/sh
set -eu

DB_PATH="${DB_PATH:-historian.db}"
EVENT_LOG_PATH="${EVENT_LOG_PATH:-/var/log/historian/events.jsonl}"
RUN_DB_RECONCILE="${RUN_DB_RECONCILE:-0}"

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
  if ! python init_db.py; then
    echo "[startup] WARN: init_db failed during first init; continuing with existing database state"
  fi
else
  if [ "$RUN_DB_RECONCILE" = "1" ]; then
    echo "[startup] database found at $DB_PATH, reconciling canonical schema"
    if ! python init_db.py; then
      echo "[startup] WARN: init_db failed (likely transient DB lock); continuing with existing database"
    fi
  else
    echo "[startup] database found at $DB_PATH, skipping reconcile (RUN_DB_RECONCILE=0)"
  fi
fi

exec uvicorn main:app --host 0.0.0.0 --port 5000
