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

## Quick start (from repo root)

### Monitoring plane (Grafana/Loki/Promtail)

```bash
docker compose -f compose/docker-compose.monitoring.yml up -d
```

Promtail is configured to read Wazuh alerts from:

- `/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts`

If your Wazuh setup differs, update the bind mount in [compose/docker-compose.monitoring.yml](compose/docker-compose.monitoring.yml).

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
