#!/usr/bin/env bash
# Provision the EWS VM: install Docker Engine and bring up all Level 3 containers.
set -euo pipefail

LEVEL3_USER="${1:-john}"

export DEBIAN_FRONTEND=noninteractive

# Install Docker Engine (official get.docker.com script handles Ubuntu 22.04)
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi

# Allow the honeypot user to run docker without sudo
usermod -aG docker "${LEVEL3_USER}"

# Pull images and build services in the background so vagrant up returns quickly.
# The containers start automatically on boot via restart: unless-stopped.
docker compose \
  -f /opt/honeypot/compose/docker-compose.level3.yml \
  up -d --build
