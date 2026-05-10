# ICS Honeypot (thesis demo)

This repo contains a small ICS honeypot + SOC demo stack:

- Historian service (web UI + OPC UA ingest)
- Optional standalone OPC UA server
- Monitoring plane (Grafana + Loki + Promtail) to visualize detections (e.g., Zeek/Wazuh)

## Repository layout

- `compose/` — Docker Compose entrypoints (historian-only, monitoring-only, legacy fullstack)
- `services/` — application services (e.g., historian, opcua)
- `monitoring/` — monitoring + detection configs (Promtail/Loki, Wazuh rules, Zeek, Sysmon)
- `demos/` — Streamlit demos used for the presentation
- `scripts/` — helper scripts
- `docs/` — schema and operations notes for replay, labeling, and capture workflows
  - `docs/lab_hardening.md` — operational guardrails for isolation, retention, and reset hygiene
  - `docs/telemetry_persistence_and_dashboards.md` — dashboard datasource wiring and host-backed persistence

## Quick start (from repo root)

### Wazuh runtime

```bash
bash scripts/run_wazuh_stack.sh
```

This starts the reproducible Wazuh Manager/Indexer/Dashboard stack from this
repo and generates local certificates if they are missing. It also opens the
manager ports for lab agents from `192.168.1.0/24` by default. Override that
with `WAZUH_AGENT_CIDR`, or set `WAZUH_CONFIGURE_FIREWALL=0` if you want to
manage firewall rules yourself.

### Monitoring plane (Grafana/Loki/Promtail/Streamlit)

```bash
bash scripts/run_monitoring_stack.sh
```

The helper starts Loki, Promtail, Grafana, the historian API proxy, imports both
Grafana dashboards, and starts Streamlit. Promtail auto-discovers the
`single-node_wazuh_logs` Docker volume when Wazuh is running.

To import the PERA Blue Team InfluxDB dashboard into this Grafana too, set
`IMPORT_PERA_BLUE_TEAM_DASHBOARD=1` and point `PERA_INFLUX_URL` at the PERA
InfluxDB endpoint before running the helper.

### Historian plane (web + ingest)

```bash
docker compose -f compose/docker-compose.historian.yml up -d
```

Or, to also start the local OPC UA server (if not already listening on port 4840):

```bash
bash scripts/run_historian_stack.sh
```

### Demos (Streamlit)

```bash
pip install -r demos/requirements.txt
bash scripts/run_streamlit_demo.sh
```

Default ports:

- Grafana: `http://localhost:3000`
- Loki: `http://localhost:3100`
- Historian web: `http://localhost:5000`
- Streamlit demo: `http://localhost:8501`

## Reproducible VM lab (Vagrant)

This repo now includes a Vagrant scaffold for a reproducible Level 3 lab.

Default profile: `laptop1-safe`

- `ews` at `192.168.56.5`
- `smb` at `192.168.56.7`
- `historian` at `192.168.56.10`
- `opcua` at `192.168.56.11`
- `zeek` at `192.168.56.13`

Additional profiles:

- `laptop1-bridge` for a near-live bridged replay of the real VirtualBox layout
- `integration` for the clean `172.30.70.x` Level 3.5 contract

Bring the lab up with:

```bash
bash scripts/run_vagrant_lab.sh
```

To switch profiles:

```bash
export HONEYPOT_VAGRANT_PROFILE=integration
```

Smoke test the Level 3 ingress contract with:

```bash
bash scripts/smoke_vagrant_lab.sh
```

Default lab credentials on the Vagrant-managed guests:

- username: `john`
- password: `Cisco`

More detail is in [vagrant/README.md](vagrant/README.md).
For a real Windows EWS instead of the Linux fallback, see
[vagrant/windows_ews_box.md](vagrant/windows_ews_box.md).
The Windows box is too large for normal git history; install it from a release,
Git LFS object, shared artifact, or the Windows laptop with
`bash scripts/install_ews_windows_box.sh`.
The thesis host-by-host architecture is documented in
[docs/thesis_honeypot_architecture.md](docs/thesis_honeypot_architecture.md).

## Minimal Level 3.5 integration surface

If you only need the first Level 3 pivot target for integration, use the
minimal ingress contract instead of the full lab:

```bash
bash scripts/run_level35_ingress.sh
bash scripts/smoke_level35_ingress.sh
```

That provides:

- host: `172.30.70.10`
- port: `22`
- login: `john / Cisco`
- role: Level 3 `EWS` / operator workstation

More detail is in [integrations/level35/README.md](integrations/level35/README.md).

## Operations helpers

- `bash scripts/check_zeek_pipeline.sh` — validate Zeek live capture and relay propagation
- `bash scripts/smoke_zeek_wazuh_loki.sh` — inject labeled smoke marker and verify Loki/Wazuh flow
- `docs/zeek_virtualbox_east_west.md` — recommended Zeek placement when VMs live on a different VirtualBox host
- `bash scripts/check_lab_time_sync.sh` — compare UTC time across the monitoring host and reachable lab assets
- `bash scripts/replay_attack_scenario.sh` — run a labeled live replay and write a ground-truth manifest
- `bash scripts/validate_honeypot_readiness.sh` — run a full replay plus alert verification for host, app, and OT coverage
- `bash scripts/demo_green_check.sh` — short pass/fail check for Zeek, Wazuh, and Loki demo readiness
- `bash scripts/archive_telemetry_bundle.sh <scenario-id>` — snapshot Zeek, Wazuh, and historian logs into an archive
- `bash scripts/capture_benign_baseline.sh <duration-seconds> [scenario-id]` — collect a benign capture window and archive it
- `bash scripts/reset_lab_state.sh` — clean up non-destructive demo residue and stop MITM tooling
- `bash scripts/apply_ews_host_telemetry.sh` — enable EWS PowerShell logging and Wazuh collection for script blocks
