# Level 3 Honeynet Session Dataset — Schema

Each line in `*.jsonl` is one attacker/benign **event** within a session.
Events sharing a `session_id` form one session (the unit of classification).

| Field | Type | Description |
|---|---|---|
| session_id | str | Groups events into one session |
| scenario_family | str | Scenario template the session was drawn from |
| ground_truth_label | str | `attack` or a `benign_*` label |
| dataset_split | str | Provenance tag (curated / replay / detection) |
| telemetry_origin | str | How the event was produced |
| session_intent | str | Session-level intent (e.g. ot_impact, collection) |
| session_danger_label | str | Session-level danger (low/medium/high/critical) |
| scenario_step | str | Step name within the session |
| attack_label | str | Per-event stage label |
| attack_stage | str | Per-event kill-chain stage |
| asset_class | str | Target asset (ews/smb/historian/opcua/network) |
| mitre_technique | str | MITRE ATT&CK for ICS technique id |
| source_asset | str | Acting asset |
| target_asset | str | Targeted asset |
| event_kind | str | Event type hint |
| start_ts_epoch | float | Session-relative start time (seconds) |
| end_ts_epoch | float | Session-relative end time (seconds) |
| exit_code | int | Command exit code (0 = success) |
| command | str | Sanitised command text |
