#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  curl \
  debconf-utils \
  gnupg \
  tcpdump

if [[ ! -f /etc/apt/trusted.gpg.d/security_zeek.gpg ]]; then
  curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor \
    | tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null
fi

cat >/etc/apt/sources.list.d/security:zeek.list <<'EOF'
deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /
EOF

apt-get update

# Zeek pulls in postfix on Ubuntu; preseed it so provisioning never blocks
# on an interactive mail configuration prompt.
debconf-set-selections <<'EOF'
postfix postfix/mailname string zeek.local
postfix postfix/main_mailer_type select Local only
EOF

apt-get install -y \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  postfix

apt-get install -y \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  zeek-6.0

CAPTURE_IFACE="$(ip -o -4 addr show | awk '$4 !~ /^10\.0\.2\./ && $2 != "lo" {print $2; exit}')"
if [[ -z "${CAPTURE_IFACE}" ]]; then
  CAPTURE_IFACE="$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}')"
fi

mkdir -p /opt/zeek/logs/current

cat >/etc/default/honeypot-zeek <<EOF
CAPTURE_IFACE=${CAPTURE_IFACE}
EOF

cat >/etc/systemd/system/honeypot-zeek.service <<'EOF'
[Unit]
Description=Honeypot Zeek sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/default/honeypot-zeek
WorkingDirectory=/opt/zeek/logs/current
ExecStart=/bin/bash -lc 'exec /opt/zeek/bin/zeek -C -i "${CAPTURE_IFACE}" /opt/honeypot/monitoring/zeek/discovery_scan_detect.zeek /opt/honeypot/monitoring/zeek/opcua_write_detect.zeek /opt/honeypot/monitoring/zeek/arp_mitm_detect.zeek'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-zeek.service
