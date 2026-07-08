#!/bin/sh
set -eu

# Interface selection, in priority order:
#   1. ZEEK_IFACE, if the operator set it explicitly.
#   2. The docker-compose bridge interface (br-*), so the containerized
#      profile (network_mode: host) sees inter-container traffic on ot-net.
#      Read from /proc/net/dev rather than `ip` - some zeek image tags don't
#      ship iproute2, which previously made this detection silently no-op.
#   3. The bare-metal heuristic (first non-loopback, non-docker interface),
#      for a physical-NIC lab deployment where zeek runs on its own host.
#   4. eth0, as a last-resort default.

iface="${ZEEK_IFACE:-}"

if [ -z "$iface" ]; then
  iface=$(awk -F: 'NR>2 { gsub(/ /,"",$1); if ($1 ~ /^br-/) { print $1; exit } }' /proc/net/dev 2>/dev/null || true)
fi

if [ -z "$iface" ] && command -v ip >/dev/null 2>&1; then
  iface=$(ip -o -4 addr show |
    awk '$4 !~ /^10[.]0[.]2[.]/ && $2 != "lo" && $2 !~ /^(docker|br-|veth)/ { sub(/\/.*/, "", $4); print $2; exit }')
fi

iface="${iface:-eth0}"

mkdir -p /opt/zeek/spool/zeek
cd /opt/zeek/spool/zeek

echo "[zeek] capturing on interface: $iface"

exec zeek -C -i "$iface" \
  /opt/zeek/share/zeek/site/discovery_scan_detect.zeek \
  /opt/zeek/share/zeek/site/opcua_write_detect.zeek \
  /opt/zeek/share/zeek/site/arp_mitm_detect.zeek
