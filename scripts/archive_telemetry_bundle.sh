#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="$ROOT_DIR/artifacts/telemetry-bundles"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SCENARIO_ID="${1:-${SCENARIO_ID:-bundle-$STAMP}}"
BUNDLE_DIR="$ARTIFACT_ROOT/$SCENARIO_ID"
ZEEK_LOG_DIR="/opt/zeek/spool/zeek"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
ALERT_TAIL_LINES="${ALERT_TAIL_LINES:-40000}"

run_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif [[ "${1:-}" == "docker" ]] && docker info >/dev/null 2>&1; then
    "$@"
  else
    sudo "$@"
  fi
}

copy_root_file() {
  local src="$1"
  local dst="$2"
  if run_root test -f "$src"; then
    run_root python3 - "$src" "$dst" <<'PY'
import pathlib
import shutil
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
dst.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(src, dst)
PY
  fi
}

mkdir -p "$BUNDLE_DIR"/{zeek,wazuh,historian,system}

if [[ -f /home/ceo/zeek_feed.log ]]; then
  cp /home/ceo/zeek_feed.log "$BUNDLE_DIR/zeek/zeek_feed.log"
fi

if [[ -f /home/ceo/zeek_feed.synthetic.log ]]; then
  cp /home/ceo/zeek_feed.synthetic.log "$BUNDLE_DIR/zeek/zeek_feed.synthetic.log"
fi

for name in conn.log ssh.log http.log smb_mapping.log smb_files.log opcua_write.log reporter.log; do
  copy_root_file "$ZEEK_LOG_DIR/$name" "$BUNDLE_DIR/zeek/$name"
done

if docker ps --format '{{.Names}}' | grep -qx "$MANAGER_CONTAINER"; then
  docker exec "$MANAGER_CONTAINER" bash -lc "tail -n $ALERT_TAIL_LINES /var/ossec/logs/alerts/alerts.json" > "$BUNDLE_DIR/wazuh/alerts.json" || true
fi

if [[ -f /home/ceo/wazuh_alerts.synthetic.json ]]; then
  cp /home/ceo/wazuh_alerts.synthetic.json "$BUNDLE_DIR/wazuh/alerts.synthetic.json"
fi

if [[ -f "$ROOT_DIR/services/historian/logs/events.jsonl" ]]; then
  cp "$ROOT_DIR/services/historian/logs/events.jsonl" "$BUNDLE_DIR/historian/events.jsonl"
fi

if [[ -f "$ROOT_DIR/services/historian/logs/ingest.jsonl" ]]; then
  cp "$ROOT_DIR/services/historian/logs/ingest.jsonl" "$BUNDLE_DIR/historian/ingest.jsonl"
fi

if [[ -f "$ROOT_DIR/artifacts/scenario-runs/$SCENARIO_ID/ground_truth.jsonl" ]]; then
  mkdir -p "$BUNDLE_DIR/ground_truth"
  cp "$ROOT_DIR/artifacts/scenario-runs/$SCENARIO_ID/ground_truth.jsonl" "$BUNDLE_DIR/ground_truth/ground_truth.jsonl"
fi

if [[ -f "$ROOT_DIR/artifacts/baselines/$SCENARIO_ID/manifest.json" ]]; then
  mkdir -p "$BUNDLE_DIR/ground_truth"
  cp "$ROOT_DIR/artifacts/baselines/$SCENARIO_ID/manifest.json" "$BUNDLE_DIR/ground_truth/baseline_manifest.json"
fi

docker compose -f "$ROOT_DIR/compose/docker-compose.monitoring.yml" ps > "$BUNDLE_DIR/system/monitoring-compose-ps.txt" 2>&1 || true
docker compose -f "$ROOT_DIR/compose/docker-compose.historian.yml" ps > "$BUNDLE_DIR/system/historian-compose-ps.txt" 2>&1 || true
run_root /opt/zeek/bin/zeekctl status > "$BUNDLE_DIR/system/zeekctl-status.txt" 2>&1 || true
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$BUNDLE_DIR/system/captured_at_utc.txt"

python3 - "$BUNDLE_DIR/zeek/zeek_feed.log" "$BUNDLE_DIR/zeek/zeek_feed.observed.jsonl" <<'PY'
import json
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])

if not src.exists():
    raise SystemExit(0)

with src.open("r", encoding="utf-8", errors="ignore") as fin, dst.open("w", encoding="utf-8") as fout:
    for line in fin:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("telemetry_origin") == "synthetic":
            continue
        fout.write(json.dumps(obj, ensure_ascii=True, separators=(",", ":")) + "\n")
PY

python3 - "$BUNDLE_DIR/wazuh/alerts.json" "$BUNDLE_DIR/wazuh/alerts.observed.json" <<'PY'
import json
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])

if not src.exists():
    raise SystemExit(0)

with src.open("r", encoding="utf-8", errors="ignore") as fin, dst.open("w", encoding="utf-8") as fout:
    for line in fin:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("data", {}).get("telemetry_origin") == "synthetic":
            continue
        fout.write(json.dumps(obj, ensure_ascii=True, separators=(",", ":")) + "\n")
PY

python3 - "$BUNDLE_DIR/system/manifest.json" "$SCENARIO_ID" <<'PY'
import json
import os
import platform
import socket
import sys
import time

manifest = {
    "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "scenario_id": sys.argv[2],
    "host": socket.gethostname(),
    "platform": platform.platform(),
    "bundle_type": "telemetry_bundle",
}

with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2)
PY

tar -C "$ARTIFACT_ROOT" -czf "$BUNDLE_DIR.tar.gz" "$SCENARIO_ID"
echo "[bundle] wrote $BUNDLE_DIR"
echo "[bundle] archived $BUNDLE_DIR.tar.gz"
