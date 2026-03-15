# OT Honeypot Docker Stack

## Services
- `opcua_server`: realistic assembly-line OPC UA source.
- `mitm_proxy`: attacker-in-the-middle TCP proxy between historian ingest and OPC UA server.
- `historian_init`: seeds/initializes SQLite DB once.
- `historian_web`: FastAPI portal/API.
- `historian_ingest`: OPC UA client that writes telemetry + `security_events`.

## Run
```powershell
cd C:\ot_honeypot
docker compose up --build -d
```

Open portal: `http://localhost:5000/login`

## View MITM abnormalities
- Historian anomaly API:
  - `http://localhost:5000/api/security-events?limit=50`
- Standard history APIs/pages will also show quality changes (`Good`, `Uncertain`, `Bad`).

## Simulate attack intensity
Edit `mitm_proxy` env vars in `docker-compose.yml` and restart that service:
- `BASE_DELAY_MS`: fixed latency to all traffic.
- `JITTER_MS`: random latency variance.
- `DROP_RATE`: probability (0.0-1.0) to drop traffic chunks.
- `DISCONNECT_RATE`: probability (0.0-1.0) to force session drops.

Example aggressive attack:
- `BASE_DELAY_MS=180`
- `JITTER_MS=220`
- `DROP_RATE=0.08`
- `DISCONNECT_RATE=0.05`

Apply changes:
```powershell
docker compose up -d --build mitm_proxy historian_ingest
```

## Why Docker changes behavior
- `localhost` inside one container is **not** another container. Services communicate by Compose name (`opcua_server`, `mitm_proxy`).
- Without a volume, SQLite data disappears when containers are recreated. This stack uses `historian_data`.
- Startup order matters. `historian_ingest` depends on `mitm_proxy`; reconnect logic handles transient unavailability.

## Teardown
```powershell
docker compose down
```

Delete containers + volume data:
```powershell
docker compose down -v
```
