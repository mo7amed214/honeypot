# Lab Hardening

These guardrails keep the honeypot useful for research and safe to operate.

## Network isolation

- keep the honeypot assets on a dedicated lab segment or switch
- block direct routing from the honeypot segment to production networks
- restrict egress so compromised assets cannot freely reach the internet
- document the intended monitoring interface and keep Zeek pinned to that interface

## Access control

- rotate lab credentials on a schedule even if they are intentionally weak for bait
- separate operator credentials from planted credentials used in the demo story
- limit SSH and RDP access to the monitoring host and approved jump paths only

## Time and integrity

- run a repeatable clock audit with `scripts/check_lab_time_sync.sh`
- keep NTP enabled on Windows, Linux, and any appliance-like services that support it
- archive telemetry before resets so labels and timestamps remain reproducible

## Recovery and rollback

- treat `scripts/reset_lab_state.sh` as non-destructive cleanup only
- keep VM or device snapshots for the EWS and adjacent assets
- validate the environment with `scripts/validate_honeypot_readiness.sh` before a demo or capture run

## Telemetry quality

- keep synthetic markers clearly labeled with `telemetry_origin=synthetic`
- store live replay manifests under `artifacts/scenario-runs/`
- store benign windows separately under `artifacts/baselines/`
- preserve raw Zeek, Wazuh, and historian logs in archived bundles for later re-labeling
