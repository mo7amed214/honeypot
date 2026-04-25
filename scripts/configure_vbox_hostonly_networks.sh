#!/usr/bin/env bash
set -euo pipefail

if ! command -v VBoxManage >/dev/null 2>&1; then
  echo "VBoxManage is not installed on this host" >&2
  exit 1
fi

PROFILE="${HONEYPOT_VAGRANT_PROFILE:-laptop1-safe}"
SAFE_NET_PREFIX="${HONEYPOT_SAFE_NET_PREFIX:-192.168.56}"
INTEGRATION_NET_PREFIX="${HONEYPOT_INTEGRATION_NET_PREFIX:-172.30.70}"
SERVICE_IF="${HONEYPOT_SERVICE_HOSTONLY_IF:-vboxnet0}"
INTEGRATION_IF="${HONEYPOT_INTEGRATION_HOSTONLY_IF:-vboxnet1}"

ensure_hostonly_if() {
  local ifname="$1"
  while ! VBoxManage list hostonlyifs | grep -q "^Name:[[:space:]]*${ifname}\$"; do
    VBoxManage hostonlyif create >/dev/null
  done
}

ensure_dhcp_server() {
  local network_name="$1"
  local server_ip="$2"
  local lower_ip="$3"
  local upper_ip="$4"
  local netmask="$5"

  if VBoxManage list dhcpservers | grep -q "^NetworkName:[[:space:]]*${network_name}\$"; then
    VBoxManage dhcpserver modify \
      --network="${network_name}" \
      --server-ip="${server_ip}" \
      --lower-ip="${lower_ip}" \
      --upper-ip="${upper_ip}" \
      --netmask="${netmask}" \
      --enable
  else
    VBoxManage dhcpserver add \
      --network="${network_name}" \
      --server-ip="${server_ip}" \
      --lower-ip="${lower_ip}" \
      --upper-ip="${upper_ip}" \
      --netmask="${netmask}" \
      --enable
  fi
}

if [[ "${PROFILE}" == "laptop1-safe" ]]; then
  ensure_hostonly_if "${SERVICE_IF}"
  VBoxManage hostonlyif ipconfig "${SERVICE_IF}" \
    --ip "${SAFE_NET_PREFIX}.1" \
    --netmask "255.255.255.0"
  ensure_dhcp_server \
    "HostInterfaceNetworking-${SERVICE_IF}" \
    "${SAFE_NET_PREFIX}.2" \
    "${SAFE_NET_PREFIX}.5" \
    "${SAFE_NET_PREFIX}.5" \
    "255.255.255.0"
fi

ensure_hostonly_if "${INTEGRATION_IF}"
VBoxManage hostonlyif ipconfig "${INTEGRATION_IF}" \
  --ip "${INTEGRATION_NET_PREFIX}.1" \
  --netmask "255.255.255.0"
ensure_dhcp_server \
  "HostInterfaceNetworking-${INTEGRATION_IF}" \
  "${INTEGRATION_NET_PREFIX}.2" \
  "${INTEGRATION_NET_PREFIX}.10" \
  "${INTEGRATION_NET_PREFIX}.10" \
  "255.255.255.0"

echo "Configured VirtualBox host-only networks:"
echo "  ${SERVICE_IF}: ${SAFE_NET_PREFIX}.0/24 (safe profile service plane)"
echo "  ${INTEGRATION_IF}: ${INTEGRATION_NET_PREFIX}.0/24 (integration plane)"
