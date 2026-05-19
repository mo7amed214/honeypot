#!/usr/bin/env bash
set -euo pipefail

USERNAME="${1:-john}"
PASSWORD="${LEVEL3_PASSWORD:-Cisco}"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  git \
  gnupg \
  iproute2 \
  jq \
  net-tools \
  nmap \
  openssh-server \
  python3 \
  python3-pip \
  python3-venv \
  rsync \
  smbclient \
  sshpass \
  sudo \
  unzip

mkdir -p /var/run/sshd
systemctl enable ssh

if ! id -u "$USERNAME" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$USERNAME"
fi

echo "${USERNAME}:${PASSWORD}" | chpasswd

# EWS operator: no sudo, no docker socket access.
# Purdue Level 3 EWS user is a plant engineer — not a sysadmin.
# Docker/compose infrastructure must remain opaque to this account.
gpasswd -d "$USERNAME" sudo 2>/dev/null || true
rm -f "/etc/sudoers.d/90-${USERNAME}"

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

if grep -qE '^#?KbdInteractiveAuthentication' /etc/ssh/sshd_config; then
  sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
fi

systemctl restart ssh
