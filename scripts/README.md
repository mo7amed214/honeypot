# Scripts

Helper scripts intended to be run from the repository root.

- `run_historian_stack.sh` — starts the local OPC UA server (if needed) and brings up historian compose
- `run_streamlit_demo.sh` — runs the Streamlit demo on port 8501
- `check_zeek_pipeline.sh` / `run_*zeek*` — pipeline utilities used by the demo environment
- `smoke_zeek_wazuh_loki.sh` — injects a labeled smoke marker and verifies Wazuh/Loki ingestion
- `zeek_remote_relay.sh` — tails a remote Zeek sensor `conn.log` over SSH and appends it into the local feed for Wazuh/Loki
- `check_lab_time_sync.sh` — compares UTC time across the monitoring host and reachable lab assets
- `replay_attack_scenario.sh` — executes a labeled live scenario and writes a ground-truth manifest
- `validate_honeypot_readiness.sh` — executes a replay, validates Wazuh/Loki detections, and archives the result
- `demo_green_check.sh` — short pass/fail check for the Zeek, Wazuh, and Loki demo path
- `archive_telemetry_bundle.sh` — captures Zeek, Wazuh, historian, and service state into an archive
- `capture_benign_baseline.sh` — records a benign capture window and archives the resulting telemetry
- `reset_lab_state.sh` — non-destructive cleanup for temp files and EWS MITM residue
- `apply_ews_host_telemetry.sh` — applies EWS PowerShell logging and Wazuh eventchannel collection
- `generate_ml_session_corpus.sh` — attempts a fully live labeled ML corpus build from the running lab
- `generate_curated_ml_profiles.py` — writes curated labeled session manifests when you need broader ML coverage without depending on live network stability
- `run_ml_pipeline.sh` — trains the LSTM, publishes ML summaries, restarts Promtail, and refreshes the Grafana ML row
