#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y samba

install -d -m 0755 /srv/samba/Operations /srv/samba/Backups /srv/samba/Docs
cp -a /opt/honeypot/services/smb/bait_files/. /srv/samba/
chown -R nobody:nogroup /srv/samba
chmod -R 0755 /srv/samba

install -d -m 0755 /etc/samba
cp /opt/honeypot/services/smb/config/smb.conf /etc/samba/smb.conf

systemctl enable smbd nmbd
systemctl restart smbd nmbd
