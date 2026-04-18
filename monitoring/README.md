# Monitoring

This folder holds monitoring/detection configuration used by the demo environment.

- `loki/` — Loki config
- `promtail/` — Promtail config (tails Wazuh alerts and forwards to Loki)
- `wazuh/` — custom Wazuh rules used by the demo
- `zeek/` — Zeek scripts/rules used by the pipeline
- `sysmon/` — Sysmon configuration artifacts
- `systemd/` — systemd unit files used for pipeline watchdog/relays

Promtail now also carries small normalized labels for downstream filtering:

- `telemetry_origin`
- `ground_truth_label`
- `scenario_family`
- `dataset_split`
- `session_id`

Notes:

- The Compose monitoring stack is in [compose/docker-compose.monitoring.yml](../compose/docker-compose.monitoring.yml).
- Wazuh Manager/Indexer/Dashboard are not started by this repo’s monitoring compose; the stack expects Wazuh alerts to already exist on the host (Promtail bind-mount).
