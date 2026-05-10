#!/usr/bin/env bash
# Provision the EWS VM: install Docker Engine and bring up all Level 3 containers.
set -euo pipefail

LEVEL3_USER="${1:-john}"
ENABLE_INTEGRATION_NIC="${HONEYPOT_ENABLE_INTEGRATION_NIC:-0}"
INTEGRATION_IP="${HONEYPOT_INTEGRATION_IP:-}"
OT_CORE_L3_IP="${HONEYPOT_OT_CORE_L3_IP:-172.30.70.1}"
DECOY_SUBNET="${HONEYPOT_DECOY_SUBNET:-172.30.40.0/24}"

export DEBIAN_FRONTEND=noninteractive

configure_dns() {
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/90-honeypot-dns.conf <<'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=9.9.9.9 1.0.0.1
DNSStubListener=yes
EOF
  systemctl restart systemd-resolved 2>/dev/null || true

  mkdir -p /etc/docker
  if [[ ! -s /etc/docker/daemon.json ]]; then
    cat > /etc/docker/daemon.json <<'EOF'
{
  "dns": ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
}
EOF
  fi
}

configure_dns

# Install Docker Engine (official get.docker.com script handles Ubuntu 22.04)
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi

configure_dns
systemctl restart docker 2>/dev/null || true

# Allow the honeypot user to run docker without sudo
usermod -aG docker "${LEVEL3_USER}"

# If a second NIC exists for the integration plane, configure its static IP via
# netplan. Vagrant adds the NIC but doesn't configure it inside the guest when
# using Ubuntu 22.04 with a custom provision script.
if [[ "$ENABLE_INTEGRATION_NIC" == "1" && -n "$INTEGRATION_IP" ]]; then
  INTEGRATION_IFACE="$(ip -o -4 addr show | awk -v ip="${INTEGRATION_IP}" '$4 ~ "^" ip "/" {print $2; exit}')"
  if [[ -z "$INTEGRATION_IFACE" ]]; then
    INTEGRATION_IFACE="$(ip -o link show | awk -F': ' '$2 ~ /^(eth|enp|ens)/ {print $2}' | tail -n1)"
  fi
  if [[ -n "$INTEGRATION_IFACE" ]]; then
    cat > /etc/netplan/60-integration.yaml <<EOF
network:
  version: 2
  ethernets:
    ${INTEGRATION_IFACE}:
      addresses: [${INTEGRATION_IP}/24]
      routes:
        - to: ${DECOY_SUBNET}
          via: ${OT_CORE_L3_IP}
EOF
    chmod 0600 /etc/netplan/60-integration.yaml
    netplan apply 2>/dev/null || true
    ip route replace "${DECOY_SUBNET}" via "${OT_CORE_L3_IP}" dev "${INTEGRATION_IFACE}" || true
  fi
fi

# Create Zeek log dir so the bind-mount in docker-compose doesn't fail
mkdir -p /var/log/zeek

# Compose expects this shared network to exist before startup.
docker network create l2_l3_integration 2>/dev/null || true

# Pull images and build services in the background so vagrant up returns quickly.
# The containers start automatically on boot via restart: unless-stopped.
docker compose \
  -f /opt/honeypot/compose/docker-compose.level3.yml \
  --profile monitoring \
  up -d --build
