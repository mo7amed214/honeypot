#!/usr/bin/env bash
set -euo pipefail

USERNAME="${1:-john}"
PASSWORD="${LEVEL3_PASSWORD:-Cisco}"
TARGET_IP="${HONEYPOT_EWS_SERVICE_IP:-172.30.70.10}"

EWS_INTEGRATION_IP="${HONEYPOT_EWS_SERVICE_IP:-172.30.70.10}"
OT_CORE_L3_IP="${HONEYPOT_OT_CORE_L3_IP:-172.30.70.1}"
DECOY_SUBNET="${HONEYPOT_DECOY_SUBNET:-172.30.40.0/24}"
EWS_IFACE="${HONEYPOT_EWS_INTEGRATION_IFACE:-eth1}"
HOSTNAME="level3-ews"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  openssh-server \
  sudo

hostnamectl set-hostname "$HOSTNAME"

mkdir -p /var/run/sshd
systemctl enable ssh

if ! id -u "$USERNAME" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USERNAME"
fi

echo "${USERNAME}:${PASSWORD}" | chpasswd
usermod -aG sudo "$USERNAME"

cat >"/etc/sudoers.d/90-${USERNAME}" <<EOF
${USERNAME} ALL=(ALL) NOPASSWD:ALL
EOF
chmod 0440 "/etc/sudoers.d/90-${USERNAME}"

if grep -qE '^#?PasswordAuthentication' /etc/ssh/sshd_config; then
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
else
  echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
fi

if grep -qE '^#?PubkeyAuthentication' /etc/ssh/sshd_config; then
  sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
else
  echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config
fi

cat >/etc/motd <<EOF
Level 3 ingress workstation
Role: Engineering workstation / operator pivot host
Contract: ssh ${USERNAME}@${TARGET_IP}
EOF

cat >"/home/${USERNAME}/LEVEL3_CONTRACT.txt" <<EOF
This VM represents the Level 3 engineering workstation ingress surface.
Fixed login: ${USERNAME} / ${PASSWORD}
Stable SSH target: ${TARGET_IP}:22
EOF
chown "${USERNAME}:${USERNAME}" "/home/${USERNAME}/LEVEL3_CONTRACT.txt"

cat >/etc/netplan/70-level3-ingress-routes.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    ${EWS_IFACE}:
      dhcp4: false
      addresses:
        - ${EWS_INTEGRATION_IP}/24
      routes:
        - to: ${DECOY_SUBNET}
          via: ${OT_CORE_L3_IP}
EOF
chmod 0600 /etc/netplan/70-level3-ingress-routes.yaml

netplan generate
netplan apply

TEST_DECOY_IP="${HONEYPOT_TEST_DECOY_IP:-172.30.40.31}"

route_ready=0
for _ in $(seq 1 15); do
  if ip route get "${TEST_DECOY_IP}" | grep -q "via ${OT_CORE_L3_IP} dev ${EWS_IFACE}"; then
    route_ready=1
    break
  fi
  sleep 1
done

if [ "${route_ready}" -ne 1 ]; then
  echo "ERROR: EWS return route to ${DECOY_SUBNET} was not installed correctly"
  echo "Expected: ${TEST_DECOY_IP} via ${OT_CORE_L3_IP} dev ${EWS_IFACE}"
  echo
  ip route
  echo
  ip route get "${TEST_DECOY_IP}" || true
  exit 1
fi

systemctl restart ssh

# ── Docker Engine ────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
usermod -aG docker "$USERNAME"

# ── Shared integration bridge ────────────────────────────────────────────────
docker network create l2_l3_integration 2>/dev/null || true

# ── Level 2 (PERA) containers ───────────────────────────────────────────────
# cd to PERA root so relative build contexts (./physics, ./blue_team/ingest)
# resolve correctly in both the main and overlay compose files.
mkdir -p /var/log/pera
cd /opt/pera
docker compose \
  -f docker-compose.yml \
  -f blue_team/docker-compose.blueteam.yml \
  up -d --build

# ── Level 3 containers ───────────────────────────────────────────────────────
# SCADA_L2_URL tells the OPC-UA server (C binary) to defer the 4 PERA-mapped
# nodes, and activates the pera_bridge sidecar that writes those values from
# PERA into the OPC-UA node store every 2 s.
# Monitoring profile is intentionally omitted: PERA's blue team stack
# (bt_grafana, bt_aiis, influxdb) is the SOC console for this integration.
# Level 3 grafana/loki/promtail/zeek would conflict on ports 3000/3100.
mkdir -p /var/log/zeek
cd /opt/honeypot
export SCADA_L2_URL="http://level2_scada:8080"
docker compose \
  -f compose/docker-compose.level3.yml \
  up -d --build
