#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  build-essential \
  make \
  pkg-config

cat >/etc/systemd/system/honeypot-opcua.service <<'EOF'
[Unit]
Description=Honeypot OPC UA server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/honeypot/services/opcua/opcua_server
ExecStart=/bin/bash -lc 'if [ -x /opt/honeypot/services/opcua/opcua_server/server ]; then exec /opt/honeypot/services/opcua/opcua_server/server; elif [ -x /opt/honeypot/services/opcua/opcua_server/opcua_server ]; then exec /opt/honeypot/services/opcua/opcua_server/opcua_server; else exec /usr/bin/make -C /opt/honeypot/services/opcua/opcua_server run; fi'
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-opcua.service
