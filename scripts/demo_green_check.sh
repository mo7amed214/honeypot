#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOOKBACK_MINUTES="${LOOKBACK_MINUTES:-10}"
LOKI_URL="${LOKI_URL:-http://localhost:3100/loki/api/v1/query_range}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-single-node-wazuh.manager-1}"

log() {
  echo "[green-check] $*"
}

fail() {
  echo "[green-check] FAIL: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

require_cmd docker
require_cmd python3
require_cmd curl

log "checking zeek pipeline"
bash "$ROOT_DIR/scripts/check_zeek_pipeline.sh" 180

start_epoch="$(date -u -d "${LOOKBACK_MINUTES} minutes ago" +%s)"
wazuh_summary="$(
  docker exec -i "$MANAGER_CONTAINER" python3 - "$start_epoch" <<'PY'
import json
import sys
from datetime import datetime

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

SUMMARY_JSON="$wazuh_summary" python3 - <<'PY'
import json
import os
import sys
obj = json.loads(os.environ["SUMMARY_JSON"])
if obj["missing"]:
    print("[green-check] missing Wazuh rules: " + ",".join(obj["missing"]))
    sys.exit(1)
print("[green-check] Wazuh counts: " + json.dumps(obj["counts"], ensure_ascii=True))
PY

start_ns="$(date -u -d "${LOOKBACK_MINUTES} minutes ago" +%s%N)"
end_ns="$(date -u +%s%N)"
loki_summary="$(
  python3 - "$LOKI_URL" "$start_ns" "$end_ns" <<'PY'
import json
import subprocess
import sys

url, start_ns, end_ns = sys.argv[1:4]
rules = ["100301", "100302", "100304", "100305", "100306", "100405"]
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
        "limit=1",
    ]
    payload = subprocess.check_output(cmd, text=True)
    obj = json.loads(payload)
    results[rule_id] = len(obj.get("data", {}).get("result", []))

missing = [rule_id for rule_id, count in results.items() if count == 0]
if "100302" in missing and results.get("100306", 0) > 0:
    missing.remove("100302")
if "100306" in missing and results.get("100302", 0) > 0:
    missing.remove("100306")
if "100304" in missing and results["100305"] > 0:
    missing.remove("100304")
print(json.dumps({"counts": results, "missing": missing}, ensure_ascii=True))
PY
)"

SUMMARY_JSON="$loki_summary" python3 - <<'PY'
import json
import os
import sys
obj = json.loads(os.environ["SUMMARY_JSON"])
if obj["missing"]:
    print("[green-check] missing Loki rules: " + ",".join(obj["missing"]))
    sys.exit(1)
print("[green-check] Loki streams: " + json.dumps(obj["counts"], ensure_ascii=True))
PY

log "PASS: demo path is green"
