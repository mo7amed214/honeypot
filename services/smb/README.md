# SMB Honey Share

This directory defines the reproducible SMB server content for the thesis lab.
The share tree in `bait_files/` was imported from the live SMB VM so the repo
matches the real architecture more closely.

The Vagrant-managed SMB VM exposes:

- default safe-profile host: `192.168.1.7`
- shares:
  - `Operations`
  - `Backups`
  - `Docs`
- access: anonymous (`guest ok`)

The live SMB VM currently uses:

- Ubuntu 24.04.4
- Samba standalone server
- guest-readable shares rooted at `/srv/samba`
- VirtualBox shape: 2048 MB RAM, 1 vCPU, bridged service NIC plus NAT

This matches the real architecture better than the original minimal placeholder
share.
