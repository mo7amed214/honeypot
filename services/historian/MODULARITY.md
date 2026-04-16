# Modularity Guide

This stack supports modular expansion for additional historian instances and multiple EWS-style sources.

## What changed

- Removed fixed container names to avoid naming collisions.
- Parameterized ports and service identity via environment variables.
- Added optional `multi` profile with a second historian + ingest pair.
- Updated Promtail EWS matching to support multiple EWS naming patterns.

## Quick start (single historian)

1. Copy environment template:

   cp .env.example .env

2. Start the stack:

   docker compose up -d

## Add a second historian (modular scale-out)

1. Ensure `.env` contains values for the second historian (`HISTORIAN2_*`, `OPCUA_URL_2`).
2. Start with multi profile:

   docker compose --profile multi up -d

3. Access second historian at `http://localhost:${HISTORIAN2_WEB_PORT}` (default 5001).

## Add more EWS sources

- Promtail maps EWS activity when `agent_name` contains `ews` or `engineering` (case-insensitive).
- To add stricter naming conventions, extend matcher blocks in `promtail-config.yml`.

## Notes

- Existing dashboard queries can remain unchanged for shared labels (`job=wazuh`, `source=wazuh`).
- For per-instance visualization, add panel filters by `agent_name` or custom labels.
