#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="$ROOT_DIR/artifacts/scenario-runs"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SCENARIO_ID="${1:-replay-$STAMP}"
OUT_DIR="$ARTIFACT_ROOT/$SCENARIO_ID"
MANIFEST="$OUT_DIR/ground_truth.jsonl"
mkdir -p "$OUT_DIR"

EWS_HOST="${EWS_HOST:-192.168.1.5}"
EWS_USER="${EWS_USER:-john}"
EWS_PASSWORD="${EWS_PASSWORD:-Cisco}"
SMB_TARGET="${SMB_TARGET:-192.168.1.7}"
HISTORIAN_HOST="${HISTORIAN_HOST:-192.168.1.10}"
OPCUA_HOST="${OPCUA_HOST:-192.168.1.11}"
OPCUA_PORT="${OPCUA_PORT:-4840}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[replay] missing command: $1" >&2
    exit 1
  }
}

record_step() {
  local step_name="$1"
  local attack_label="$2"
  local attack_stage="$3"
  local asset_class="$4"
  local mitre_technique="$5"
  local start_ts="$6"
  local end_ts="$7"
  local exit_code="$8"
  local command_text="$9"
  local output_file="${10}"
  python3 - "$MANIFEST" "$SCENARIO_ID" "$step_name" "$attack_label" "$attack_stage" "$asset_class" "$mitre_technique" "$start_ts" "$end_ts" "$exit_code" "$command_text" "$output_file" <<'PY'
import json
import sys

record = {
    "scenario_id": sys.argv[2],
    "session_id": sys.argv[2],
    "scenario_family": "ics_honeypot_replay",
    "ground_truth_label": "attack",
    "dataset_split": "attack_labeled",
    "telemetry_origin": "live_sensor",
    "scenario_step": sys.argv[3],
    "attack_label": sys.argv[4],
    "attack_stage": sys.argv[5],
    "asset_class": sys.argv[6],
    "mitre_technique": sys.argv[7],
    "source_asset": "monitoring_laptop",
    "target_asset": sys.argv[6],
    "event_kind": "live_replay_action",
    "start_ts_epoch": float(sys.argv[8]),
    "end_ts_epoch": float(sys.argv[9]),
    "exit_code": int(sys.argv[10]),
    "command": sys.argv[11],
    "output_file": sys.argv[12],
}
with open(sys.argv[1], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, ensure_ascii=True) + "\n")
PY
}

run_step() {
  local step_name="$1"
  local attack_label="$2"
  local attack_stage="$3"
  local asset_class="$4"
  local mitre_technique="$5"
  local command_text="$6"
  local output_file="$7"

  local start_ts end_ts rc
  start_ts="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
  if bash -lc "$command_text" >"$output_file" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  end_ts="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
  record_step "$step_name" "$attack_label" "$attack_stage" "$asset_class" "$mitre_technique" "$start_ts" "$end_ts" "$rc" "$command_text" "$output_file"
  echo "[replay] $step_name exit=$rc output=$output_file"
}

require_cmd sshpass
require_cmd smbclient
require_cmd curl
require_cmd python3

run_step \
  "step_4_ews_access_ssh" \
  "lateral_movement" \
  "host_activity" \
  "ews" \
  "T0866" \
  "sshpass -p '$EWS_PASSWORD' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $EWS_USER@$EWS_HOST \"hostname && whoami && powershell -NoProfile -Command \\\"Write-Output REPLAY-$SCENARIO_ID\\\"\"" \
  "$OUT_DIR/step_4_ews_access_ssh.txt"

run_step \
  "step_3_anonymous_smb_browse" \
  "collection" \
  "smb_access" \
  "smb" \
  "T0811" \
  "smbclient //$SMB_TARGET/Operations -N -m SMB3 -c 'ls; get ews_maintenance_access.txt $OUT_DIR/ews_maintenance_access.txt'" \
  "$OUT_DIR/step_3_anonymous_smb_browse.txt"

run_step \
  "step_5_historian_access" \
  "collection" \
  "historian_web" \
  "historian" \
  "T0802" \
  "curl -s http://$HISTORIAN_HOST:5000/tags" \
  "$OUT_DIR/step_5_historian_access.txt"

run_step \
  "step_6_opcua_probe" \
  "recon" \
  "opcua_path" \
  "opcua" \
  "T0861" \
  "python3 -c \"import socket; socket.create_connection(('${OPCUA_HOST}', ${OPCUA_PORT}), timeout=3).close(); print('opcua tcp probe ok')\"" \
  "$OUT_DIR/step_6_opcua_probe.txt"

echo "[replay] manifest written to $MANIFEST"
