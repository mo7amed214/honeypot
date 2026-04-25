#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

SAFE_NET_PREFIX="${HONEYPOT_SAFE_NET_PREFIX:-192.168.56}"
PROFILE="${HONEYPOT_VAGRANT_PROFILE:-laptop1-safe}"

if [[ "$PROFILE" == "integration" ]]; then
  TARGET_IP="172.30.70.10"
else
  TARGET_IP="${SAFE_NET_PREFIX}.5"
fi

apt-get update
apt-get install -y \
  curl \
  netcat-openbsd \
  smbclient

cat >/etc/motd <<'EOF'
Level 3 ingress workstation
Role: Engineering workstation / operator pivot host
EOF

echo "Contract: ssh john@${TARGET_IP}" >> /etc/motd

cat >/home/john/LEVEL3_CONTRACT.txt <<'EOF'
This VM represents the Level 3 engineering workstation ingress surface.
Fixed login: john / Cisco
EOF

echo "Stable SSH target: ${TARGET_IP}:22" >> /home/john/LEVEL3_CONTRACT.txt

chown john:john /home/john/LEVEL3_CONTRACT.txt
