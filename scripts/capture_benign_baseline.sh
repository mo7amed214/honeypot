#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION_SECONDS="${1:-900}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SCENARIO_ID="${2:-baseline-$STAMP}"
OUT_DIR="$ROOT_DIR/artifacts/baselines/$SCENARIO_ID"
mkdir -p "$OUT_DIR"

python3 - "$OUT_DIR/manifest.json" "$SCENARIO_ID" "$DURATION_SECONDS" <<'PY'
import json
import sys
import time

manifest = {
    "scenario_id": sys.argv[2],
    "scenario_family": "benign_baseline_capture",
    "ground_truth_label": "benign",
    "dataset_split": "baseline_capture",
    "telemetry_origin": "live_sensor",
    "capture_start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "planned_duration_seconds": int(sys.argv[3]),
}

with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2)
PY

echo "[baseline] collecting benign window for ${DURATION_SECONDS}s"
sleep "$DURATION_SECONDS"
bash "$ROOT_DIR/scripts/archive_telemetry_bundle.sh" "$SCENARIO_ID" > "$OUT_DIR/archive.log" 2>&1
echo "[baseline] archived telemetry for $SCENARIO_ID"
