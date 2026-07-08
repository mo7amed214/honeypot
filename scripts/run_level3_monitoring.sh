#!/usr/bin/env bash
set -euo pipefail

# Starts the docker-compose.level3.yml monitoring profile (grafana, loki,
# promtail, smb, zeek, soc-publisher) and points zeek at the actual ot-net
# bridge interface, resolved via the Docker API rather than guessed from
# inside the container - that guess is unreliable once more than one
# docker-compose project/bridge network exists on the same host (e.g. this
# stack running alongside the Wazuh compose project).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/compose/docker-compose.level3.yml"

docker compose -f "$COMPOSE_FILE" --profile monitoring up -d --build

net_id="$(docker network inspect ot-net --format '{{.Id}}' 2>/dev/null | cut -c1-12)"
if [[ -n "$net_id" ]]; then
  export ZEEK_IFACE="br-$net_id"
  echo "[level3] zeek will capture on $ZEEK_IFACE (ot-net bridge)"
  docker compose -f "$COMPOSE_FILE" --profile monitoring up -d zeek
else
  echo "[level3] WARN: could not resolve ot-net bridge id; zeek will fall back to its own heuristic"
fi

docker compose -f "$COMPOSE_FILE" --profile monitoring ps
