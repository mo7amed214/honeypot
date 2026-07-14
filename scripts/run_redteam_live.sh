#!/usr/bin/env bash
# Bring up the lean live honeynet and run a genuinely-live red-team trial:
# real model (local or remote Ollama) -> real SSH foothold -> real honeynet.
#
# Env it sets for the harness (agent's view of the isolated 10.13.37.0/24 net):
#   EWS_HOST=127.0.0.1  EWS_PORT=2222   (harness SSHes to the published foothold)
#   SMB_TARGET/HISTORIAN_HOST/OPCUA_HOST -> the static container IPs
#
# Model selection:
#   MODELS defaults to "ollama-remote" (set OLLAMA_URL in redteam/.env to the
#   other laptop). Override: MODELS="llama-local" for the on-box 3B.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE="compose/docker-compose.redteam-live.yml"
MODELS="${MODELS:-ollama-remote}"
OBJECTIVES="${OBJECTIVES:-explore process_manipulation}"
REPEATS="${REPEATS:-3}"

echo "==> building + starting lean live honeynet (opcua, historian, smb, foothold)"
docker compose -f "$COMPOSE" up -d --build

echo "==> waiting for foothold SSH (localhost:2222) ..."
for i in $(seq 1 30); do
  if sshpass -p Cisco ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=4 -p 2222 john@127.0.0.1 'echo ready' >/dev/null 2>&1; then
    echo "    foothold reachable"; break
  fi
  sleep 3
done

echo "==> running live trials: models=[$MODELS] objectives=[$OBJECTIVES] repeats=$REPEATS"
EWS_HOST=127.0.0.1 \
EWS_PORT=2222 \
EWS_USER=john \
EWS_PASSWORD=Cisco \
SMB_TARGET=10.13.37.7 \
HISTORIAN_HOST=10.13.37.10 \
OPCUA_HOST=10.13.37.11 \
REDTEAM_MAX_ACTIONS="${REDTEAM_MAX_ACTIONS:-25}" \
  python -m redteam.run_experiments --models $MODELS --objectives $OBJECTIVES \
    --repeats "$REPEATS" --target ssh --no-reset

echo "==> aggregating"
python -m redteam.aggregate

echo
echo "Live honeynet still running. Tear down with:"
echo "  docker compose -f $COMPOSE down -v"
