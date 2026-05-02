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

netplan generate
netplan apply


systemctl restart ssh
