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
  openssh-server \
  python3 \
  python3-pip \
  python3-venv \
  rsync \
  sshpass \
  sudo \
  unzip

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

if grep -qE '^#?KbdInteractiveAuthentication' /etc/ssh/sshd_config; then
  sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
fi

systemctl restart ssh
