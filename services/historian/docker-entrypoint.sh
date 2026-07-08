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

schema_ready() {
  python -c "
import sqlite3, sys
try:
    conn = sqlite3.connect('$DB_PATH', timeout=2)
    row = conn.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='tag_metadata'\").fetchone()
    sys.exit(0 if row else 1)
except sqlite3.Error:
    sys.exit(1)
"
}

if [ ! -f "$DB_PATH" ] || ! schema_ready; then
  # A sibling container (e.g. historian-ingest) sharing this DB volume may have
  # already created the file with only its own table, so file-existence alone
  # can't be trusted here - check for the tag_metadata table explicitly.
  echo "[startup] database missing or schema incomplete at $DB_PATH, initializing"
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
