# Historian service

This folder is the Docker build context for the historian web app and OPC UA ingest worker.

## Run (Docker)

From repo root:

```bash
docker compose -f compose/docker-compose.historian.yml up -d
```

## Configuration

- Environment variables are defined in the compose file with defaults.
- An example env file is provided as `.env.example`.

Runtime outputs (local-only):

- `logs/*.jsonl`
- `*.db`
