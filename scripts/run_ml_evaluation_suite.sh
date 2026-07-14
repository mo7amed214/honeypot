#!/usr/bin/env bash
# One-command driver for the full ML evaluation suite reported in the paper:
# corpus -> headline model (+k-fold) -> ablation -> baselines -> robustness ->
# public dataset. Each stage writes its report under ml/runs/ or dataset/.
#
# Runs inside the ML image (compose/docker-compose.ml.yml) so the host needs
# only Docker. Seed is fixed for reproducibility; override with SEED=... .
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
SEED="${SEED:-1337}"
ML="docker compose -f compose/docker-compose.ml.yml run --rm -T lstm-session-runtime"

echo "==> [1/6] generate curated corpus"
python ml/lstm_session/generate_curated_sessions.py

echo "==> [2/6] build + ensure ML image"
docker compose -f compose/docker-compose.ml.yml build lstm-session-runtime >/dev/null

echo "==> [3/6] headline model + 5-fold CV"
$ML python -m ml.lstm_session.train --scenario-root artifacts/scenario-runs \
    --output-dir ml/runs/latest --kfold 5 --seed "$SEED"

echo "==> [4/6] ablation sweep"
$ML python -m ml.lstm_session.ablation --scenario-root artifacts/scenario-runs \
    --out ml/runs/ablation --kfold 0 --seed "$SEED"

echo "==> [5/6] strong baselines + robustness"
$ML python -m ml.lstm_session.baselines --scenario-root artifacts/scenario-runs \
    --out ml/runs/baselines --seed "$SEED"
$ML python -m ml.lstm_session.robustness --model ml/runs/latest/model.pt \
    --scenario-root artifacts/scenario-runs --out ml/runs/robustness --seed "$SEED"

echo "==> [6/6] public dataset + datasheet"
python scripts/build_public_dataset.py

echo
echo "Done. Reports:"
echo "  ml/runs/latest/metrics.json            (headline + k-fold)"
echo "  ml/runs/ablation/ablation/ablation_report.md"
echo "  ml/runs/baselines/baselines_report.md"
echo "  ml/runs/robustness/robustness_report.md"
echo "  dataset/DATASHEET.md + stats.json"
