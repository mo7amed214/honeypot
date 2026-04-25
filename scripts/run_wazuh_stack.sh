#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/compose/docker-compose.wazuh.yml"
CERT_DIR="$ROOT_DIR/monitoring/wazuh/runtime/config/wazuh_indexer_ssl_certs"
PROJECT_NAME="${WAZUH_COMPOSE_PROJECT:-single-node}"
AGENT_CIDR="${WAZUH_AGENT_CIDR:-192.168.1.0/24}"
CONFIGURE_FIREWALL="${WAZUH_CONFIGURE_FIREWALL:-1}"

ensure_iptables_rule() {
  if command -v iptables >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    local chain="$1"
    shift
    sudo iptables -C "$chain" "$@" 2>/dev/null || sudo iptables -I "$chain" 1 "$@"
  fi
}

mkdir -p "$CERT_DIR"

if [[ ! -s "$CERT_DIR/root-ca.pem" || ! -s "$CERT_DIR/wazuh.manager.pem" ]]; then
  echo "[wazuh] generating local Wazuh certificates"
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" --profile certs run --rm wazuh-certs-generator
fi

echo "[wazuh] starting manager, indexer, and dashboard"
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d wazuh.indexer wazuh.manager wazuh.dashboard

if [[ "$CONFIGURE_FIREWALL" == "1" ]]; then
  echo "[wazuh] allowing agents from $AGENT_CIDR to reach Wazuh ports"
  ensure_iptables_rule INPUT -p tcp -s "$AGENT_CIDR" -m multiport --dports 1514,1515,55000 -j ACCEPT
  ensure_iptables_rule INPUT -p udp -s "$AGENT_CIDR" --dport 514 -j ACCEPT
  ensure_iptables_rule DOCKER-USER -s "$AGENT_CIDR" -j ACCEPT
  ensure_iptables_rule FORWARD -s "$AGENT_CIDR" -j ACCEPT
  ensure_iptables_rule FORWARD -d "$AGENT_CIDR" -j ACCEPT
else
  echo "[wazuh] firewall rule installation skipped because WAZUH_CONFIGURE_FIREWALL=$CONFIGURE_FIREWALL"
fi

echo "[wazuh] status"
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" ps
