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
