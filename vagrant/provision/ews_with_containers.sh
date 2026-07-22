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
  resolvectl dns eth0 1.1.1.1 8.8.8.8 9.9.9.9 2>/dev/null || true
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true

  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<'EOF'
{
  "dns": ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
}
EOF
}

configure_dns

# Install Docker Engine (official get.docker.com script handles Ubuntu 22.04)
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi

configure_dns
systemctl restart docker 2>/dev/null || true

# Do NOT add EWS user to the docker group.
# Docker socket access would expose all container internals (networks, envs,
# compose configs) across Purdue levels — a direct Purdue boundary violation.
# All container management is root-only.

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

# Safety: ensure the vagrant synced folders are actually mounted. After a
# boot-timeout/re-provision, vagrant can skip the mount step, leaving
# /opt/honeypot empty and the compose files unreachable. Re-mount via vboxsf.
if [[ ! -f /opt/honeypot/compose/docker-compose.level3.yml ]]; then
  modprobe vboxsf 2>/dev/null || true
  mkdir -p /opt/honeypot /opt/pera
  # Match the Vagrantfile synced_folder options exactly (root:root, dmode=750,
  # fmode=640). vboxsf ignores chmod, so these mount options are the ONLY thing
  # keeping the EWS operator (john) blind to compose files / cross-level source.
  # A bare `mount -t vboxsf` defaults to 0777 and silently breaks the deception.
  MNT_OPTS="uid=0,gid=0,dmode=750,fmode=640"
  mountpoint -q /opt/honeypot || mount -t vboxsf -o "$MNT_OPTS" opt_honeypot /opt/honeypot 2>/dev/null || true
  mountpoint -q /opt/pera     || mount -t vboxsf -o "$MNT_OPTS" opt_pera     /opt/pera     2>/dev/null || true
fi

# Create Zeek log dir so the bind-mount in docker-compose doesn't fail
mkdir -p /var/log/zeek

# The Level 3 compose file uses this as an external bridge for the PERA bridge
# container. Recreate it on rebuilt EWS guests before docker compose starts.
if ! docker network inspect l2_l3_integration >/dev/null 2>&1; then
  docker network create l2_l3_integration >/dev/null
fi

# Drop a demo attack script into the operator's home if the PERA checkout ships
# one. The old stealth_sabotage.py path no longer exists in the current L0-2
# repo; search for a real attack script instead (falls back gracefully).
ATTACK_SRC="$(find /opt/pera -maxdepth 3 -type f -name 'attack_path_3_bms_thermal_kill.py' 2>/dev/null | head -1)"
[[ -z "$ATTACK_SRC" ]] && ATTACK_SRC="$(find /opt/pera /opt/honeypot -maxdepth 4 -type f -name 'stealth_sabotage.py' 2>/dev/null | head -1)"
if [[ -n "$ATTACK_SRC" && -f "$ATTACK_SRC" ]]; then
  dest="/home/${LEVEL3_USER}/$(basename "$ATTACK_SRC")"
  cp "$ATTACK_SRC" "$dest"
  chown "${LEVEL3_USER}:${LEVEL3_USER}" "$dest"
  chmod +x "$dest"
fi

# If the Level 0-2 (PERA) checkout is mounted with its integration override,
# bring the Level 2 physics/PLC/SCADA stack up first and point Level 3's OPC-UA
# bridge at it (SCADA_L2_URL). Without a PERA checkout, SCADA_L2_URL stays empty
# and Level 3 comes up standalone exactly as before — nothing breaks.
SCADA_L2_URL=""
L3_PROFILES=(--profile monitoring)
if [[ -f /opt/pera/docker-compose.yml && -f /opt/pera/docker-compose.integration.yml ]]; then
  echo "[ews] PERA Level 0-2 detected — bringing up Level 2 stack for the L2<->L3 bridge"
  ( cd /opt/pera && docker compose -f docker-compose.yml -f docker-compose.integration.yml up -d --build )
  SCADA_L2_URL="http://scada_mtu:8080"
  L3_PROFILES+=(--profile integration)
fi

# Pull images and build services. Containers restart on boot via
# restart: unless-stopped. The integration profile adds the opcua-pera-bridge.
SCADA_L2_URL="$SCADA_L2_URL" docker compose \
  -f /opt/honeypot/compose/docker-compose.level3.yml \
  "${L3_PROFILES[@]}" \
  up -d --build

# Lock down infrastructure directories from the EWS operator account.
# john is a plant engineer — compose files, PERA source, and ML code
# are root-owned infrastructure, not operator tools.
chmod 700 /opt/honeypot 2>/dev/null || true
chmod 700 /opt/pera 2>/dev/null || true
chown -R root:root /opt/honeypot /opt/pera 2>/dev/null || true
