# Telemetry Schema

This project keeps raw telemetry in source-specific logs and adds a small set of normalized metadata for replay, analyst correlation, and future ML work.

## Core normalized fields

- `session_id`: operator/demo session identifier
- `scenario_id`: stable identifier for a replay or labeled capture window
- `scenario_family`: broad scenario grouping such as `ics_honeypot_demo` or `pipeline_smoke`
- `scenario_step`: step slug inside the scenario
- `ground_truth_label`: high-level label such as `attack`, `benign`, or `test`
- `dataset_split`: collection bucket such as `attack_labeled`, `baseline_capture`, or `synthetic_smoke`
- `telemetry_origin`: `live_sensor`, `synthetic`, or `synthetic_smoke`
- `attack_label`: behavior class such as `recon`, `collection`, `lateral_movement`, `execution`, or `impact`
- `attack_stage`: normalized analyst-facing stage label
- `asset_class`: normalized target class such as `ews`, `historian`, `smb`, or `opcua`
- `mitre_technique`: ATT&CK for ICS mapping used for the step
- `source_asset`: source side of the action
- `target_asset`: target side of the action
- `event_kind`: high-level source bucket such as `demo_marker`, `application_marker`, or `smoke_marker`

## Raw telemetry sources

- Zeek relay feed: `/home/ceo/zeek_feed.log`
- Zeek live logs: `/opt/zeek/spool/zeek/*.log`
- Wazuh alerts: `/var/ossec/logs/alerts/alerts.json` inside the manager
- Historian application logs:
  - `services/historian/logs/events.jsonl`
  - `services/historian/logs/ingest.jsonl`

## Labeling guidance

- Live sensor events should default to `telemetry_origin=live_sensor`
- Synthetic demo markers should always include `telemetry_origin=synthetic`
- Smoke-test markers should always include `telemetry_origin=synthetic_smoke`
- Ground truth for live replay windows should be stored in companion manifests under `artifacts/scenario-runs/`
- Long-running benign captures should be stored under `artifacts/baselines/`

## Query guidance

For Grafana/Loki:

- use `session_id` for short demo windows
- use `scenario_family` for grouped analysis
- use `telemetry_origin` to exclude synthetic markers from live-only views
- use `ground_truth_label` and `dataset_split` to build training and validation slices later
