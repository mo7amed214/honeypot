# Compose files

Run these from the repository root.

- `docker-compose.level3.yml` — the main integrated stack: OPC UA server (built
  from `open62541`), historian web + ingest, SMB honey share, and an optional
  `monitoring` profile (Grafana, Loki, Promtail, Zeek, SOC publisher)
- `docker-compose.monitoring.yml` — Grafana + Loki + Promtail only (standalone)
- `docker-compose.wazuh.yml` — reproducible Wazuh Manager/Indexer/Dashboard runtime
- `docker-compose.historian.yml` — historian web + OPC UA ingest only
- `docker-compose.legacy.fullstack.yml` — legacy combined stack kept for compatibility
- `docker-compose.ml.yml` — LSTM inference/training sidecar services

Examples:

```bash
# Core OT loop (OPC UA + historian)
docker compose -f compose/docker-compose.level3.yml up -d opcua historian-web historian-ingest

# Everything, including monitoring
docker compose -f compose/docker-compose.level3.yml --profile monitoring up -d

docker compose -f compose/docker-compose.monitoring.yml up -d
docker compose -f compose/docker-compose.historian.yml up -d
```

Use the script for Wazuh so local certificates are generated before startup:

```bash
bash scripts/run_wazuh_stack.sh
```
