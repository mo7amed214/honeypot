# Vagrant Lab

This directory makes the Level 3 lab reproducible with Vagrant.

The repo now supports three profiles:

- `laptop1-safe` (default) — keeps the real VM names, roles, and last-octet
  addressing pattern, but remaps them onto a safe Vagrant-managed host-only
  subnet (`192.168.56.x` by default) instead of blindly touching your live LAN.
- `laptop1-bridge` — near-live replay of the laptop1 topology using bridged
  networking on `Realtek Gaming GbE Family Controller`.
- `integration` — the clean `172.30.70.x` contract for Level 3.5 integration.

You can also add a second integration-facing NIC to the non-integration
profiles by exporting:

```bash
export HONEYPOT_ENABLE_INTEGRATION_NIC=1
```

That keeps the normal service/data plane on the profile subnet and adds a
second host-only integration plane on `172.30.70.x` by default.

When the integration NIC is enabled, the repo now also configures the
VirtualBox host-only DHCP pools automatically through:

- `scripts/configure_vbox_hostonly_networks.sh`

That matters most for the Windows EWS path: the host-only DHCP pools are pinned
so a fresh EWS NIC identity can pick up:

- `192.168.56.5` on the safe-profile service plane
- `172.30.70.10` on the integration plane

Current reproducible nodes in the laptop1-safe profile:

- `ews` at `192.168.56.5` — `EWS-WIN11`, Level 3 ingress / operator workstation
- `smb` at `192.168.56.7` — Ubuntu Samba host with `Operations`, `Backups`, and `Docs`
- `historian` at `192.168.56.10` — historian web + ingest
- `opcua` at `192.168.56.11` — `opcuaserver` / `opuca vm`
- `zeek` at `192.168.56.13` — Zeek sensor VM

The last octets deliberately match the live lab. If you want a different safe
subnet, set:

```bash
export HONEYPOT_SAFE_NET_PREFIX=192.168.57
```

Default credentials on the Vagrant-managed Linux guests:

- user: `john`
- password: `Cisco`

## Important note about EWS

The live EWS is a real Windows 11 Enterprise Evaluation VM.
This repo supports two EWS modes:

- default `linux` mode for quick bring-up
- `windows` mode for architecture-matched reproduction when you provide a Windows base box

The Linux fallback preserves the contract:

- reachable SSH target
- fixed credentials
- stable IP
- same role in the Level 3 model

For a Windows-accurate EWS run, package/register the real EWS VM first as
documented in [windows_ews_box.md](windows_ews_box.md), then set:

```bash
export HONEYPOT_EWS_MODE=windows
export HONEYPOT_EWS_BOX=honeypot/ews-win11-local
export HONEYPOT_EWS_WINRM_USER=vagrant
export HONEYPOT_EWS_WINRM_PASSWORD=vagrant
```

Then `vagrant up ews`.

The repo now includes:

- `scripts/windows/package_ews_vagrant_box.ps1` to package the real Windows VM
- `bash scripts/register_ews_windows_box.sh` to register it on Linux
- `vagrant/windows_ews_box.md` with the workflow

## Quick start

```bash
bash scripts/run_vagrant_lab.sh
```

That brings up the default `laptop1-safe` profile.

To switch profiles:

```bash
export HONEYPOT_VAGRANT_PROFILE=laptop1-bridge
```

or:

```bash
export HONEYPOT_VAGRANT_PROFILE=integration
```

Then run `bash scripts/run_vagrant_lab.sh`.

To run a dual-NIC lab where the normal subnet and the integration subnet exist
at the same time:

```bash
export HONEYPOT_VAGRANT_PROFILE=laptop1-safe
export HONEYPOT_ENABLE_INTEGRATION_NIC=1
```

or, on a stronger reproduction host that can tolerate bridged replay:

```bash
export HONEYPOT_VAGRANT_PROFILE=laptop1-bridge
export HONEYPOT_ENABLE_INTEGRATION_NIC=1
```

The integration NIC uses this fixed mapping:

- `ews` -> `172.30.70.10`
- `historian` -> `172.30.70.11`
- `opcua` -> `172.30.70.12`
- `zeek` -> `172.30.70.13`
- `smb` -> `172.30.70.14`

If you want a different integration subnet:

```bash
export HONEYPOT_INTEGRATION_NET_PREFIX=172.30.71
```

The real laptop1 VirtualBox layout observed from the host was:

- `EWS-WIN11` — Windows 11, 8256 MB RAM, 3 CPUs, bridged
- `smb` — Ubuntu, 2048 MB RAM, dual-NIC (bridged + NAT)
- `Historian` — Ubuntu, 2048 MB RAM, dual-NIC (bridged + NAT)
- `opuca vm` — Ubuntu, 2496 MB RAM, 2 CPUs, bridged
- `Zeek` — Ubuntu, 2048 MB RAM, 2 CPUs, bridged

The Vagrant profile preserves those names, CPU/RAM sizes, primary service
roles, and last-octet mapping. The intentional safety deviation is that
`laptop1-safe` uses a host-only data plane so you do not accidentally trample
the live lab.

With `HONEYPOT_ENABLE_INTEGRATION_NIC=1`, the repo can now represent the
architecture as two coherent planes at once:

- primary service/data plane
- secondary integration plane

For the Windows EWS on lighter hosts, the safe profile intentionally supports
smaller defaults than the real laptop1 VM:

- `HONEYPOT_EWS_WINDOWS_SAFE_MEMORY` defaults to `4096`
- `HONEYPOT_EWS_WINDOWS_SAFE_CPUS` defaults to `2`

Example:

```bash
export HONEYPOT_EWS_WINDOWS_SAFE_MEMORY=4096
export HONEYPOT_EWS_WINDOWS_SAFE_CPUS=2
```

The Linux-side safe-profile VMs are also reduced for weaker laptops:

- `HONEYPOT_SAFE_SMB_MEMORY=1024`
- `HONEYPOT_SAFE_HISTORIAN_MEMORY=1536`
- `HONEYPOT_SAFE_OPCUA_MEMORY=1536`
- `HONEYPOT_SAFE_ZEEK_MEMORY=1536`
- all safe-profile Linux guests default to `1` vCPU

If your laptop is still tight on RAM, export even smaller values before `vagrant up`.

## Integration profile

If you only want the Level 3.5 ingress contract, use:

```bash
export HONEYPOT_VAGRANT_PROFILE=integration
```

That brings up:

- `ews` at `172.30.70.10`
- `historian` at `172.30.70.11`
- `opcua` at `172.30.70.12`
- `zeek` at `172.30.70.13`
- `smb` at `172.30.70.14`

## Smoke test

```bash
bash scripts/smoke_vagrant_lab.sh
```

This verifies the profile-appropriate ingress host and service ports, including
the fixed `john / Cisco` login.

## Zeek relay note

The Zeek VM logs to:

- `/opt/zeek/logs/current/conn.log`

To relay that feed back into the monitoring laptop, point the existing relay at:

```bash
REMOTE_SENSOR_HOST=192.168.56.13 \
REMOTE_SENSOR_USER=john \
REMOTE_SENSOR_PASSWORD=Cisco \
REMOTE_SOURCE_LOG=/opt/zeek/logs/current/conn.log \
bash scripts/zeek_remote_relay.sh
```

## Architecture note

For the thesis-level host roles and data flow, see
[docs/thesis_honeypot_architecture.md](../docs/thesis_honeypot_architecture.md).
