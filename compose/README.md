# Compose files

Run these from the repository root.

- `docker-compose.monitoring.yml` — Grafana + Loki + Promtail only (standalone)
- `docker-compose.wazuh.yml` — reproducible Wazuh Manager/Indexer/Dashboard runtime
- `docker-compose.historian.yml` — historian web + OPC UA ingest only
- `docker-compose.legacy.fullstack.yml` — legacy combined stack kept for compatibility
- `docker-compose.ml.yml` — LSTM inference/training sidecar services

Examples:

```bash
docker compose -f compose/docker-compose.monitoring.yml up -d
docker compose -f compose/docker-compose.historian.yml up -d
```

Use the script for Wazuh so local certificates are generated before startup:

```bash
bash scripts/run_wazuh_stack.sh
```
