# Session LSTM

This directory contains the LSTM-based session-correlation pipeline for the
honeypot's labeled session data.

What it does:

- reads replay manifests from `artifacts/scenario-runs/*/ground_truth.jsonl`
- groups records into correlated sessions
- expands each session into progressive prefixes so the model can learn attack
  buildup
- trains a small LSTM to predict:
  - `danger_label` as `low`, `medium`, `high`, or `critical`
  - `dominant_stage` for the correlated session
  - `session_intent` for the correlated session
- publishes analyst-facing session summaries into `monitoring/ml/*.jsonl`
- feeds those summaries into Loki and Grafana

Important note:

- the session corpus can mix `live_sensor` captures with `curated_profile`
  sessions when the lab network is unstable
- the published dashboard view uses a hybrid session-intent layer:
  - the LSTM provides the base prediction
  - a small deterministic path refinement cleans up obvious SOC-facing edge
    cases like `opcua_write -> ot_impact`

Asset IP mapping (portability across lab profiles):

- `session_builder.py` and `session_detection.py` classify events by asset
  using a default 192.168.1.x mapping (the original lab subnet).
- To run against a different bring-up profile (e.g. `laptop1-safe` on
  192.168.56.x, or `integration` on 172.30.70.x), override without editing
  code:
  - `LEVEL3_IP_TO_ASSET='{"192.168.56.5": "ews", ...}'` (used by `session_builder.py`)
  - `LEVEL3_ASSET_IPS='{"ews": ["192.168.56.5"], ...}'` (used by `session_detection.py`)
  - Both are JSON, merged on top of the defaults, so you only need to specify
    the entries that differ.

Quick start:

```bash
bash scripts/train_lstm_session_model.sh
```

That will build the ML container and train the model on the local artifacts.

To regenerate the broader curated session corpus before training:

```bash
python3 scripts/generate_curated_ml_profiles.py
```

To run the full ML publish flow and refresh Grafana:

```bash
bash scripts/run_ml_pipeline.sh
```

Outputs:

- `ml/runs/latest/metrics.json`
- `ml/runs/latest/model.pt`
- `ml/runs/latest/sessions.jsonl`
- `ml/runs/latest/predictions.json`
- `ml/runs/latest/eval_predictions.json`
- `monitoring/ml/model_summary.jsonl`
- `monitoring/ml/correlated_sessions.jsonl`

Inference on one replay manifest:

```bash
docker compose -f compose/docker-compose.ml.yml run --rm lstm-session-model \
  python ml/lstm_session/infer.py \
  --model-path ml/runs/latest/model.pt \
  --session-file artifacts/scenario-runs/final-sleep-check-20260417T014959Z/ground_truth.jsonl
```
