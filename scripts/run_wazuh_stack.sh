#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/compose/docker-compose.wazuh.yml"
CERT_DIR="$ROOT_DIR/monitoring/wazuh/runtime/config/wazuh_indexer_ssl_certs"
PROJECT_NAME="${WAZUH_COMPOSE_PROJECT:-single-node}"
AGENT_CIDR="${WAZUH_AGENT_CIDR:-192.168.1.0/24}"
CONFIGURE_FIREWALL="${WAZUH_CONFIGURE_FIREWALL:-1}"
LAB_NIC="${LAB_NIC:-enx00e04c257e28}"
OPCUA_ALIAS_IP="${OPCUA_ALIAS_IP:-192.168.1.11}"

ensure_iptables_rule() {
  local chain="$1"
  shift

  if command -v iptables >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo iptables -C "$chain" "$@" 2>/dev/null || sudo iptables -I "$chain" 1 "$@"
    return 0
  fi

  local check_args insert_args
  check_args="$(printf '%q ' "$chain" "$@")"
  insert_args="$(printf '%q ' "$chain" 1 "$@")"
  docker run --rm --privileged --net=host alpine:3.20 sh -lc \
    "apk add --no-cache iptables >/dev/null && \
     iptables -C ${check_args} 2>/dev/null || iptables -I ${insert_args}"
}

ensure_ip_alias() {
  local dev="$1" addr="$2"
  ip addr show "$dev" 2>/dev/null | grep -q "$addr" && return 0
  if sudo -n true 2>/dev/null; then
    sudo ip addr add "$addr/24" dev "$dev" 2>/dev/null || true
  else
    docker run --rm --privileged --net=host ubuntu:22.04 \
      ip addr add "$addr/24" dev "$dev" 2>/dev/null || true
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
  # Explicit OPC UA port 4840 rule — needed because the OPC UA server runs as a Docker
  # container behind an IP alias (OPCUA_ALIAS_IP) on the lab NIC. Docker's DNAT handles
  # the PREROUTING, but DOCKER-USER needs an explicit ACCEPT so external hosts can reach
  # it when iptables-nft and iptables-legacy coexist and the AGENT_CIDR rule lands in
  # the wrong backend.
  ensure_iptables_rule DOCKER-USER -i "$LAB_NIC" -p tcp --dport 4840 -j ACCEPT
  # Return path: container SYN-ACK back out to physical NIC must be allowed.
  ensure_iptables_rule DOCKER-USER -o "$LAB_NIC" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  echo "[wazuh] ensuring OPC UA IP alias $OPCUA_ALIAS_IP on $LAB_NIC"
  ensure_ip_alias "$LAB_NIC" "$OPCUA_ALIAS_IP"
else
  echo "[wazuh] firewall rule installation skipped because WAZUH_CONFIGURE_FIREWALL=$CONFIGURE_FIREWALL"
fi

echo "[wazuh] status"
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" ps
