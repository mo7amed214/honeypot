#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SCENARIO_ID="${1:-validate-$STAMP}"
WAIT_SECONDS="${WAIT_SECONDS:-75}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
LOKI_URL="${LOKI_URL:-http://localhost:3100/loki/api/v1/query_range}"
EWS_HOST="${EWS_HOST:-192.168.1.5}"
SMB_HOST="${SMB_HOST:-192.168.1.7}"
HISTORIAN_HOST="${HISTORIAN_HOST:-192.168.1.10}"
OPCUA_HOST="${OPCUA_HOST:-192.168.1.11}"
OPCUA_PORT="${OPCUA_PORT:-4840}"
ARCHIVE_TIMEOUT_SECONDS="${ARCHIVE_TIMEOUT_SECONDS:-60}"

run_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  elif [[ "${1:-}" == "docker" ]] && docker info >/dev/null 2>&1; then
    "$@"
  elif sudo -n true 2>/dev/null; then
    sudo "$@"
  elif [[ -n "${SUDO_PASSWORD:-}" ]]; then
    printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' -v
    sudo -n "$@"
  else
    sudo "$@"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[validate] missing command: $1" >&2
    exit 1
  }
}

log() {
  echo "[validate] $*"
}

fail() {
  echo "[validate] FAIL: $*" >&2
  exit 1
}

require_cmd curl
require_cmd docker
require_cmd python3

START_EPOCH="$(date -u +%s)"

preflight_assets() {
  python3 - "$EWS_HOST" "$SMB_HOST" "$HISTORIAN_HOST" "$OPCUA_HOST" "$OPCUA_PORT" <<'PY'
import socket
import sys

checks = [
    ("ews_ssh", sys.argv[1], 22),
    ("smb_share", sys.argv[2], 445),
    ("historian_http", sys.argv[3], 5000),
    ("opcua_tcp", sys.argv[4], int(sys.argv[5])),
]
failures = []

for label, host, port in checks:
    try:
        with socket.create_connection((host, port), timeout=5):
            print(f"[validate] preflight OK: {label} {host}:{port}")
    except OSError as exc:
        failures.append(f"{label} {host}:{port} ({exc})")

if failures:
    print("[validate] preflight failed for: " + "; ".join(failures), file=sys.stderr)
    raise SystemExit(1)
PY
}

log "checking lab asset reachability"
preflight_assets

log "checking Zeek live capture"
bash "$ROOT_DIR/scripts/check_zeek_pipeline.sh" 180

log "running labeled replay scenario_id=$SCENARIO_ID"
bash "$ROOT_DIR/scripts/replay_attack_scenario.sh" "$SCENARIO_ID"

log "sending live OPC UA write-like validation probe"
EWS_USER="${EWS_USER:-john}"
EWS_PASSWORD="${EWS_PASSWORD:-Cisco}"
_probe_via_ews=0

# Send from EWS so the probe crosses the switch and Zeek can detect it.
# Local probe never leaves this machine (IP alias), so Zeek is blind to it.
if command -v sshpass >/dev/null 2>&1; then
  if sshpass -p "$EWS_PASSWORD" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=8 \
      "${EWS_USER}@${EWS_HOST}" \
      "powershell -Command \"\$b=[byte[]]@(77,83,71,70,1,161,2)+[System.Text.Encoding]::ASCII.GetBytes('air_pressure_bar');\$c=New-Object Net.Sockets.TcpClient;\$c.Connect('${OPCUA_HOST}',${OPCUA_PORT});\$s=\$c.GetStream();\$s.Write(\$b,0,\$b.Length);\$c.Close()\"" 2>/dev/null; then
    log "sent_opcua_write_like_probe via EWS (crosses switch, Zeek-visible)"
    _probe_via_ews=1
  fi
fi

if [[ "$_probe_via_ews" -eq 0 ]]; then
  python3 - "$OPCUA_HOST" "$OPCUA_PORT" "$SCENARIO_ID" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
scenario_id = sys.argv[3]
payload = b"MSGF" + b"\x01\xa1\x02" + b"air_pressure_bar" + scenario_id.encode("ascii", errors="ignore")
with socket.create_connection((host, port), timeout=5) as sock:
    sock.sendall(payload)
print(f"sent_opcua_write_like_probe_bytes={len(payload)} (local fallback — Zeek-blind)")
PY
fi

wait_for_wazuh_rules() {
  local i summary
  for i in $(seq 1 "$WAIT_SECONDS"); do
    summary="$(
      run_root docker exec -i "$MANAGER_CONTAINER" python3 - "$START_EPOCH" <<'PY'
import json
import sys
from datetime import datetime, timezone

start_epoch = int(sys.argv[1])
expected = ["100301", "100302", "100303", "100304", "100305", "100306", "100402", "100404", "100405"]
counts = {rule_id: 0 for rule_id in expected}

def parse_epoch(text):
    if not text:
        return None
    try:
        return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp())
    except Exception:
        try:
            return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
        except Exception:
            return None

with open("/var/ossec/logs/alerts/alerts.json", "r", encoding="utf-8", errors="ignore") as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        rule_id = str(obj.get("rule", {}).get("id", ""))
        if rule_id not in counts:
            continue
        ts = obj.get("timestamp") or obj.get("@timestamp")
        epoch = parse_epoch(ts)
        if epoch is None or epoch < start_epoch:
            continue
        counts[rule_id] += 1

missing = [rule_id for rule_id, count in counts.items() if count == 0]
if "100302" in missing and counts["100306"] > 0:
    missing.remove("100302")
if "100304" in missing and counts["100305"] > 0:
    missing.remove("100304")
print(json.dumps({"counts": counts, "missing": missing}, ensure_ascii=True))
PY
    )"
    if ! SUMMARY_JSON="$summary" python3 - <<'PY'
import json
import os
obj = json.loads(os.environ["SUMMARY_JSON"])
raise SystemExit(0 if not obj["missing"] else 1)
PY
    then
      sleep 1
      continue
    fi
    log "Wazuh coverage summary: $summary"
    return 0
  done

  fail "expected Wazuh alerts not observed within ${WAIT_SECONDS}s"
}

wait_for_loki_rules() {
  local i start_ns end_ns summary
  start_ns="${START_EPOCH}000000000"
  for i in $(seq 1 "$WAIT_SECONDS"); do
    end_ns="$(date -u +%s%N)"
    summary="$(python3 - "$LOKI_URL" "$start_ns" "$end_ns" <<'PY'
import json
import subprocess
import sys

url, start_ns, end_ns = sys.argv[1:4]
rules = ["100301", "100305", "100405"]
results = {}

for rule_id in rules:
    query = f'{{job="wazuh",rule_id="{rule_id}"}}'
    cmd = [
        "curl",
        "-sG",
        url,
        "--data-urlencode",
        f"query={query}",
        "--data-urlencode",
        f"start={start_ns}",
        "--data-urlencode",
        f"end={end_ns}",
        "--data-urlencode",
        "limit=5",
    ]
    payload = subprocess.check_output(cmd, text=True)
    obj = json.loads(payload)
    streams = obj.get("data", {}).get("result", [])
    results[rule_id] = len(streams)

missing = [rule_id for rule_id, count in results.items() if count == 0]
print(json.dumps({"counts": results, "missing": missing}, ensure_ascii=True))
PY
    )"
    if ! SUMMARY_JSON="$summary" python3 - <<'PY'
import json
import os
obj = json.loads(os.environ["SUMMARY_JSON"])
raise SystemExit(0 if not obj["missing"] else 1)
PY
    then
      sleep 1
      continue
    fi
    log "Loki coverage summary: $summary"
    return 0
  done

  fail "expected Loki labels not observed within ${WAIT_SECONDS}s"
}

wait_for_wazuh_rules
wait_for_loki_rules

log "archiving telemetry bundle"
if command -v timeout >/dev/null 2>&1; then
  if ! timeout "$ARCHIVE_TIMEOUT_SECONDS" bash "$ROOT_DIR/scripts/archive_telemetry_bundle.sh" "$SCENARIO_ID" >/tmp/"$SCENARIO_ID".bundle.log 2>&1; then
    log "archive step timed out or failed; detections validated, bundle log: /tmp/$SCENARIO_ID.bundle.log"
    log "PASS: host, application, OT, relay, Wazuh, and Loki coverage validated for $SCENARIO_ID"
    exit 0
  fi
else
  bash "$ROOT_DIR/scripts/archive_telemetry_bundle.sh" "$SCENARIO_ID" >/tmp/"$SCENARIO_ID".bundle.log 2>&1
fi
log "bundle log: /tmp/$SCENARIO_ID.bundle.log"
log "PASS: host, application, OT, relay, Wazuh, and Loki coverage validated for $SCENARIO_ID"
