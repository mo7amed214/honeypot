#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPCUA_DIR="$ROOT_DIR/services/opcua/opcua_server"
HISTORIAN_COMPOSE="$ROOT_DIR/compose/docker-compose.historian.yml"

is_opcua_up() {
  ss -ltn | grep -q ':4840 '
}

start_opcua_if_needed() {
  if is_opcua_up; then
    echo "[startup] OPC UA server already listening on :4840"
    return
  fi

  echo "[startup] OPC UA server not detected, starting host server..."
  (
    cd "$OPCUA_DIR"
    nohup ./run.sh > "$ROOT_DIR/services/opcua/opcua_server/opcua_server.log" 2>&1 &
  )

  for i in {1..20}; do
    if is_opcua_up; then
      echo "[startup] OPC UA server is up"
      return
    fi
    sleep 1
  done

  echo "[startup] ERROR: OPC UA server did not start on :4840"
  echo "[startup] Check log: $ROOT_DIR/services/opcua/opcua_server/opcua_server.log"
  exit 1
}

start_stack() {
  echo "[startup] Starting historian services..."
  docker compose -f "$HISTORIAN_COMPOSE" up -d
  docker compose -f "$HISTORIAN_COMPOSE" ps
}

start_opcua_if_needed
start_stack

echo "[startup] Ready. Historian ingest should now have live OPC UA data."
