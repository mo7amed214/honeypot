#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

SERVICE_IP="$(ip -o -4 addr show | awk '$4 !~ /^10\\.0\\.2\\./ && $2 != "lo" { sub(/\\/.*/, "", $4); print $4; exit }')"
if [[ -z "${SERVICE_IP}" ]]; then
  SERVICE_IP="172.30.70.11"
fi
BASE_PREFIX="${SERVICE_IP%.*}"
OPCUA_IP="${BASE_PREFIX}.11"

apt-get update
apt-get install -y \
  docker-compose \
  docker.io

systemctl enable --now docker
usermod -aG docker john || true

mkdir -p /opt/honeypot/services/historian/logs

cat >/etc/systemd/system/honeypot-historian.service <<'EOF'
[Unit]
Description=Honeypot historian stack
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/honeypot
Environment=OPCUA_URL=opc.tcp://${OPCUA_IP}:4840
Environment=SERVER_BASE=http://${SERVICE_IP}:5000
Environment=HISTORIAN_USERNAME=john
Environment=HISTORIAN_PASSWORD=Cisco
ExecStart=/usr/bin/docker-compose -f /opt/honeypot/compose/docker-compose.historian.yml up -d
ExecStop=/usr/bin/docker-compose -f /opt/honeypot/compose/docker-compose.historian.yml down

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-historian.service
