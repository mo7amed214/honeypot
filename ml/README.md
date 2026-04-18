# Session LSTM

This directory contains a first-pass LSTM pipeline for the honeypot's labeled
session data.

What it does:

- reads replay manifests from `artifacts/scenario-runs/*/ground_truth.jsonl`
- groups records into correlated sessions
- expands each session into progressive prefixes so the model can learn attack
  buildup
- trains a small LSTM to predict:
  - `danger_score` from `0.0` to `1.0`
  - `danger_label` as `low`, `medium`, `high`, or `critical`
  - `dominant_stage` for the correlated session

Important note:

- the current dataset is still small
- this model is a baseline for pipeline validation and feature plumbing, not a
  final thesis-quality result yet

Quick start:

```bash
bash scripts/train_lstm_session_model.sh
```

That will build the ML container and train the model on the local artifacts.

Outputs:

- `ml/runs/latest/metrics.json`
- `ml/runs/latest/model.pt`
- `ml/runs/latest/sessions.jsonl`
- `ml/runs/latest/predictions.json`

Inference on one replay manifest:

```bash
docker compose -f compose/docker-compose.ml.yml run --rm lstm-session-model \
  python ml/lstm_session/infer.py \
  --model-path ml/runs/latest/model.pt \
  --session-file artifacts/scenario-runs/final-sleep-check-20260417T014959Z/ground_truth.jsonl
```
