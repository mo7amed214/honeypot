#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"
if [[ "${GENERATE_ML_CORPUS:-0}" == "1" ]]; then
  bash scripts/generate_ml_session_corpus.sh
fi
bash scripts/train_lstm_session_model.sh "$@"
python3 -m ml.lstm_session.publish_results --run-dir ml/runs/latest --output-dir monitoring/ml
docker compose -f compose/docker-compose.monitoring.yml up -d promtail >/dev/null
python3 scripts/apply_ml_dashboard.py
