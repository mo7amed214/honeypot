# Data Readiness

This repo now includes the minimum operational pieces needed before a sequence model is worth training.

## Priorities implemented here

- consistent replay and marker metadata
- explicit synthetic versus live separation
- stricter Zeek relay validation against `conn.log`
- repeatable attack replay manifest generation
- one-command readiness validation for host, app, OT, and relay detections
- benign capture window tooling
- telemetry bundle archiving
- partial lab reset workflow
- EWS PowerShell logging and Wazuh collection enablement script
- time-skew audit helpers for the monitoring laptop and reachable lab assets

## What still needs time, not just code

- multi-day benign baseline capture
- Level 3.5 telemetry once that integration is ready
- repeated variants of the same scenario with different timing and operator behavior
- final train/validation/test curation from archived bundles and manifests

## Recommended workflow

1. Enable EWS host telemetry with `scripts/apply_ews_host_telemetry.sh`
2. Verify the pipeline with `scripts/check_zeek_pipeline.sh` and `scripts/smoke_zeek_wazuh_loki.sh`
3. Audit clock drift with `scripts/check_lab_time_sync.sh`
4. Run a labeled replay with `scripts/replay_attack_scenario.sh`
5. Validate the end-to-end chain with `scripts/validate_honeypot_readiness.sh`
6. Archive the resulting logs with `scripts/archive_telemetry_bundle.sh`
7. Capture benign windows with `scripts/capture_benign_baseline.sh`
8. Reset the lab with `scripts/reset_lab_state.sh`

See `docs/telemetry_persistence_and_dashboards.md` before long collection runs
for the Grafana/Influx/Loki wiring and the host-backed persistence options.
