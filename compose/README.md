# Compose files

Run these from the repository root.

- `docker-compose.monitoring.yml` — Grafana + Loki + Promtail only (standalone)
- `docker-compose.historian.yml` — historian web + OPC UA ingest only
- `docker-compose.legacy.fullstack.yml` — legacy combined stack kept for compatibility

Examples:

```bash
docker compose -f compose/docker-compose.monitoring.yml up -d
docker compose -f compose/docker-compose.historian.yml up -d
```
