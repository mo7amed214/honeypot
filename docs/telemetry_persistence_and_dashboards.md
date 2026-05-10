# Telemetry Persistence and Dashboard Wiring

## Current telemetry shape

The repo now has two useful dashboard families, but they are backed by different data stores:

- The `honeypot` SOC dashboard uses Loki data from Promtail labels over Wazuh alerts and ML JSONL outputs.
- The `honeypot` OPC UA telemetry dashboard uses the historian API through the Grafana Infinity datasource.
- The `PERA-integration-ready-` Blue Team dashboard uses InfluxDB Flux queries over `physics`, `divergence`, `mitre_event`, `integrity`, and `aiis` measurements.

That means the PERA dashboard can be displayed in the same Grafana instance, but it still needs an InfluxDB datasource with matching data. Importing only the JSON gives you the dashboard layout, not the telemetry behind it.

## Import the PERA Blue Team dashboard

Start your Grafana/Loki stack first:

```bash
cd honeypot
bash scripts/run_monitoring_stack.sh
```

If the PERA Blue Team InfluxDB is reachable on the host at port `8086`, import the dashboard into the same Grafana:

```bash
python3 scripts/import_pera_blue_team_dashboard.py \
  --influx-url http://host.docker.internal:8086 \
  --influx-token bt-supersecret-token-change-me \
  --influx-org thesis \
  --influx-bucket honeypot
```

Or let the monitoring launcher import it automatically:

```bash
IMPORT_PERA_BLUE_TEAM_DASHBOARD=1 \
PERA_INFLUX_URL=http://host.docker.internal:8086 \
bash scripts/run_monitoring_stack.sh
```

Use `http://bt_influxdb:8086` instead of `host.docker.internal` only when Grafana and the PERA InfluxDB container are attached to the same Docker network.

If you are running the PERA Blue Team stack, persist its InfluxDB evidence store too:

```bash
cd ../PERA-integration-ready-
mkdir -p persistent/influxdb persistent/influxdb-config persistent/grafana

export PERA_INFLUX_DATA_PATH="$PWD/persistent/influxdb"
export PERA_INFLUX_CONFIG_PATH="$PWD/persistent/influxdb-config"
export PERA_GRAFANA_DATA_PATH="$PWD/persistent/grafana"

docker compose -f docker-compose.yml -f blue_team/docker-compose.blueteam.yml up -d
```

## Persistence model

Docker named volumes already survive container restarts, host reboots, and normal VM poweroff/crash. They do not survive `docker volume rm`, some reset workflows, or `vagrant destroy`.

For collection runs that must survive a VM rebuild, bind the stateful stores into a shared host/repo path before starting the stacks:

```bash
cd honeypot
mkdir -p persistent/historian persistent/grafana persistent/loki persistent/promtail

export HISTORIAN_DATA_PATH="$PWD/persistent/historian"
export GRAFANA_DATA_PATH="$PWD/persistent/grafana"
export LOKI_DATA_PATH="$PWD/persistent/loki"
export PROMTAIL_POSITIONS_PATH="$PWD/persistent/promtail"

bash scripts/run_historian_stack.sh
bash scripts/run_monitoring_stack.sh
```

State then lands in:

- `persistent/historian`: SQLite historian database and seed sentinel
- `persistent/grafana`: Grafana database, imported dashboards, datasource config
- `persistent/loki`: Loki chunks and index
- `persistent/promtail`: Promtail read positions

If the PERA stack is used, its `persistent/influxdb` directory is the long-lived store for `physics`, `divergence`, `mitre_event`, `integrity`, and `aiis`.

Historian event logs are already bind-mounted at `services/historian/logs`, and ML outputs are already under `monitoring/ml`, so those are naturally visible in the repo.

## Collection guidance for tomorrow

Keep the stores separate on purpose:

- Use SQLite historian data for physical process values and OPC UA history.
- Use Loki for security evidence, Wazuh alerts, Zeek-derived detections, and ML/session summaries.
- Use InfluxDB only for the PERA physics/intelligence dashboard unless you also wire the PERA ingest into your run.

The current telemetry is not uselessly redundant. The overlap is intentional: the same incident should be visible as process movement, network/security detection, and analyst/session summary. The weak point is when a dashboard expects one store but the run only populates another. Before collecting, run the smoke checks, keep a single `session_id` for the run, and archive the bundle afterward:

```bash
bash scripts/check_zeek_pipeline.sh
bash scripts/smoke_zeek_wazuh_loki.sh
bash scripts/archive_telemetry_bundle.sh tomorrow-run-01
```
