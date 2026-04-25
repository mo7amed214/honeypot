# Thesis Honeypot Architecture

This document describes the thesis honeypot as a set of cooperating hosts and
planes rather than as a single app stack.

## High-level layout

There are two main planes:

1. Monitoring plane
2. Level 3 OT interaction plane

The monitoring plane lives on the demo laptop and aggregates evidence.
The OT plane contains the hosts that the attacker touches during the storyline.

## Monitoring plane

The monitoring plane is the analyst side of the thesis:

- Grafana for SOC dashboards and analyst views
- Loki for log aggregation
- Promtail for log shipping into Loki
- Wazuh for host and application alerting
- Streamlit for controlled demo execution
- LSTM session-correlation pipeline for analyst-facing session summaries
- Historian API proxy for local dashboard access to historian-backed telemetry

This plane is what the SOC analyst sees.

## Level 3 OT plane

Current live lab inventory observed from the actual VMs and the VirtualBox host:

- `192.168.1.5` `EWS-WIN11` — Windows 11 Enterprise Evaluation
- `192.168.1.7` `smb` — Ubuntu 24.04.4 with Samba guest shares
- `192.168.1.10` `historian` — Ubuntu 24.04.4 with Dockerized historian
- `192.168.1.11` `opcuaserver` — Ubuntu 24.04.4 running the open62541 server
- `192.168.1.13` `zeek` — Ubuntu 24.04.4 running Zeek

The actual VirtualBox inventory on laptop1 also showed:

- registered VMs: `EWS-WIN11`, `smb`, `Historian`, `opuca vm`, `Zeek`
- an additional dormant `OPCUA server` VM entry
- host-only adapter space centered on `192.168.1.0/24`
- the live service VMs primarily attached to `Realtek Gaming GbE Family Controller`

### EWS VM

- Role: Level 3 ingress host / operator workstation
- Purpose: first stable pivot target for attacker access and integration
- Live host: `EWS-WIN11` on `192.168.1.5`
- Evidence produced:
  - SSH or host login activity
  - command execution
  - PowerShell / script execution
  - staged tool execution

The live EWS currently runs:

- OpenSSH Server
- Sysmon
- Wazuh agent
- Python launcher
- staged operator/tool artifacts in `C:\Users\john\Downloads`

Observed VirtualBox shape on laptop1:

- 8256 MB RAM
- 3 vCPUs
- Windows 11 guest type with EFI and TPM 2.0
- primary service NIC bridged to `Realtek Gaming GbE Family Controller`

The repo now supports both:

- a Linux ingress fallback
- an optional Windows Vagrant EWS mode for closer reproduction

### SMB VM

- Role: honey file share / maintenance repository
- Purpose: expose lure files and credential-adjacent artifacts
- Live host: `smb` on `192.168.1.7`
- Shares:
  - `Operations`
  - `Backups`
  - `Docs`
- Evidence produced:
  - SMB connection events
  - SMB share or file access detections

This is the initial collection and credential-discovery step in the attack
storyline.

Observed VirtualBox shape on laptop1:

- 2048 MB RAM
- 1 vCPU
- bridged service NIC
- second NAT adapter

### Historian VM

- Role: process data web application and ingest point
- Purpose: expose process history and store OPC UA-derived telemetry
- Live host: `historian` on `192.168.1.10`
- Evidence produced:
  - historian web access
  - authentication events
  - ingest anomalies
  - application-side process impact clues

This host bridges IT-style web access and OT process awareness.

Observed VirtualBox shape on laptop1:

- 2048 MB RAM
- 1 vCPU
- bridged service NIC
- second NAT adapter

### OPC UA VM

- Role: physics-aware process simulation / tag server
- Purpose: expose the live industrial tags that the historian ingests
- Live host: `opcuaserver` on `192.168.1.11`
- Evidence produced:
  - OPC UA network path visibility
  - write-like activity
  - critical write-like behavior when abuse looks sustained or sensitive

This is the OT target where manipulation becomes meaningful.

Observed VirtualBox shape on laptop1:

- 2496 MB RAM
- 2 vCPUs
- single bridged service NIC
- promiscuous policy `AllowNetwork`

### Zeek VM

- Role: east-west network sensor
- Purpose: observe VM-to-VM traffic that the monitoring laptop cannot always
  see directly
- Live host: `zeek` on `192.168.1.13`
- Evidence produced:
  - historian web connections
  - SMB traffic
  - OPC UA path telemetry
  - discovery or scan behavior
  - write-like OT detections

This VM is what makes the network story honest when traffic stays inside the
virtual lab.

Observed VirtualBox shape on laptop1:

- 2048 MB RAM
- 2 vCPUs
- single bridged service NIC
- promiscuous policy `AllowAll`

## Reproducibility model in the repo

The repo now keeps two ideas separate on purpose:

1. live architecture truth
2. reproducible bring-up profiles

The live architecture truth is the laptop1 layout above.
The reproducible bring-up profiles are:

- `laptop1-safe`
  - uses the real VM names and keeps the last-octet mapping
  - remaps them onto a safe host-only subnet such as `192.168.56.x`
  - avoids blindly reusing the live LAN on a reproduction laptop
- `laptop1-bridge`
  - aims closer to the live VirtualBox bridging behavior
  - meant for a dedicated reproduction host, not a casual laptop
- `integration`
  - exposes the cleaner `172.30.70.x` surface for Level 3.5 integration work

The repo also now supports a dual-NIC model for non-integration profiles:

- NIC 1 stays on the normal service/data plane
- NIC 2 exposes the fixed integration plane on `172.30.70.x`

That means the same reproduced VM can participate in both:

- the thesis lab subnet
- the Level 3.5 integration subnet

without forcing you to abandon the original architecture.

This split is intentional.
It lets the thesis repo represent the real architecture without forcing the
live network assumptions on every new machine.

## Attack story across the architecture

The thesis storyline is:

1. discover reachable services
2. browse the SMB share
3. recover maintenance-style access hints
4. validate access to the EWS
5. access the historian web portal
6. probe the OPC UA path
7. optionally place a man-in-the-middle position
8. perform write-like or telemetry-affecting activity

Each step is meant to leave evidence in more than one place:

- host evidence from Wazuh
- application evidence from historian logs
- network evidence from Zeek
- correlated session interpretation from the ML pipeline

## Why this architecture matters

The thesis is not only showing isolated detections.
It is showing a modular honeypot where:

- each VM represents a believable asset role
- each asset emits a different evidence type
- the monitoring plane correlates those signals into a session-level story

That is what makes the final analyst dashboard, replay pipeline, and ML layer
useful together.
