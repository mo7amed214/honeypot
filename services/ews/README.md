# EWS Role

The live EWS in the thesis lab is currently:

- hostname: `EWS-WIN11`
- OS: Windows 11 Enterprise Evaluation
- primary access: SSH on port 22
- login used in the lab: `john / Cisco`
- observed LAN IP: `192.168.1.5`
- observed VirtualBox shape: 8256 MB RAM, 3 vCPUs, bridged NIC on `Realtek Gaming GbE Family Controller`

Observed software and telemetry on the live EWS:

- OpenSSH Server
- Sysmon
- Wazuh agent
- Python launcher (`py.exe`)
- attacker-tool staging under `C:\Users\john\Downloads`

Observed operator/download artifacts on the live EWS:

- `arpspoof.exe`
- `enable_ews_host_telemetry.ps1`
- `nmap-7.99-setup.exe`
- `python-3.11.9-amd64.exe`
- `wazuh-agent-4.14.4-1.msi`
- `Sysmon.zip`

The Vagrant scaffold now supports:

- a `laptop1-safe` profile that keeps the real hostname and IP on a safe Vagrant network
- a `laptop1-bridge` profile for near-live bridged replay
- a Linux ingress fallback for quick bring-up when a Windows base box is not available
- an optional Windows EWS mode when you provide a Windows base box

That split exists because the real EWS is Windows, but shipping a ready-made
Windows base image inside this repo is not practical.
