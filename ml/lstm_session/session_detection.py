"""
Live session detection — polls Loki for new telemetry and assembles attacker sessions.

Continuously queries the Loki log aggregation endpoint for Wazuh alerts, Zeek
detections, and historian application events.  Incoming log lines are grouped by
session ID, normalised to the common event schema, and written to per-session
JSONL files that the ML inference pipeline consumes.

Environment variables:
  LIVE_LOKI_QUERY_URL   Loki base URL (default: http://host.docker.internal:3100)

Typical invocation (inside the monitoring Docker network):
  python -m ml.lstm_session.session_detection
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


LOKI_QUERY_URL = os.environ.get("LIVE_LOKI_QUERY_URL", "http://host.docker.internal:3100")

DEFAULT_ASSET_IPS: Dict[str, set[str]] = {
    "monitoring_laptop": {"192.168.1.9"},
    "workstation": {"192.168.1.9"},
    "ews": {"192.168.1.5"},
    "historian": {"192.168.1.10"},
    "opcua": {"192.168.1.11"},
    "opcua_server": {"192.168.1.11"},
    "historian_opcua": {"192.168.1.10", "192.168.1.11"},
    "smb": {"192.168.1.7"},
    "level3_subnet": {"192.168.1.5", "192.168.1.7", "192.168.1.10", "192.168.1.11"},
}


def _load_asset_ips() -> Dict[str, set[str]]:
    """Merge in a LEVEL3_ASSET_IPS JSON override (asset -> list of IPs) for
    non-default lab subnets (e.g. laptop1-safe, laptop1-bridge, integration)."""
    merged = {asset: set(ips) for asset, ips in DEFAULT_ASSET_IPS.items()}
    override = os.environ.get("LEVEL3_ASSET_IPS")
    if override:
        for asset, ips in json.loads(override).items():
            merged[asset] = set(ips)
    return merged


ASSET_IPS: Dict[str, set[str]] = _load_asset_ips()

RULE_TO_EVIDENCE = {
    "100301": "historian_web",
    "100302": "smb_access",
    "100303": "opcua_path",
    "100304": "write_like",
    "100305": "critical_write",
    "100306": "smb_access",
    "100307": "discovery",
    "100308": "critical_write",
    "100402": "host_access",
    "100404": "host_command",
    "100405": "host_scriptblock",
    "100406": "staged_tool",
    "100209": "process_anomaly",
}

RULE_TO_STAGE = {
    "100301": "historian_web",
    "100302": "smb_access",
    "100303": "opcua_path",
    "100304": "opcua_write",
    "100305": "opcua_write",
    "100306": "smb_access",
    "100307": "discovery",
    "100308": "opcua_write",
    "100402": "host_activity",
    "100404": "host_command",
    "100405": "host_scriptblock",
    "100406": "process_anomaly",
    "100209": "process_anomaly",
}

RULE_TO_ASSET = {
    "100301": "historian",
    "100302": "smb",
    "100303": "opcua",
    "100304": "opcua",
    "100305": "opcua",
    "100306": "smb",
    "100307": "level3",
    "100308": "opcua",
    "100402": "ews",
    "100404": "ews",
    "100405": "ews",
    "100406": "ews",
    "100209": "historian",
}

STAGE_TO_RULES = {
    "discovery": {"100307"},
    "credential_access": {"100402"},
    "host_activity": {"100402", "100404", "100405"},
    "host_command": {"100404", "100405", "100406"},
    "host_scriptblock": {"100405"},
    "smb_access": {"100302", "100306"},
    "historian_web": {"100301"},
    "opcua_path": {"100303"},
    "opcua_write": {"100303", "100304", "100305", "100308", "100209", "100406"},
    "process_anomaly": {"100209", "100406"},
}

STAGE_BUFFERS = {
    "discovery": (10, 120),
    "credential_access": (10, 60),
    "host_activity": (10, 90),
    "host_command": (10, 120),
    "host_scriptblock": (10, 120),
    "smb_access": (10, 180),
    "historian_web": (10, 180),
    "opcua_path": (10, 90),
    "opcua_write": (15, 240),
    "process_anomaly": (15, 240),
}

SUMMARY_KEYS = {
    "historian_web": "observed_historian_web_count",
    "smb_access": "observed_smb_access_count",
    "opcua_path": "observed_opcua_path_count",
    "write_like": "observed_write_like_count",
    "critical_write": "observed_critical_write_count",
    "process_anomaly": "observed_process_anomaly_count",
    "host_access": "observed_host_access_count",
    "host_command": "observed_host_command_count",
    "host_scriptblock": "observed_host_scriptblock_count",
    "staged_tool": "observed_staged_tool_count",
    "discovery": "observed_discovery_count",
}


def parse_loki_timestamp(value: str) -> float:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).timestamp()
        except ValueError:
            continue
    return 0.0


def load_manifest_rows(session_file: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for raw_line in session_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        rows.append(row)
    rows.sort(key=lambda row: float(row.get("start_ts_epoch", 0.0)))
    return rows


def nested_get(data: Dict[str, Any], *path: str) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def step_rule_ids(row: Dict[str, Any]) -> set[str]:
    stage = str(row.get("attack_stage", ""))
    rules = set(STAGE_TO_RULES.get(stage, set()))
    if row.get("scenario_step") == "step_4_ews_access":
        rules.update({"100402", "100404", "100405"})
    return rules


def step_window(row: Dict[str, Any]) -> Tuple[float, float]:
    stage = str(row.get("attack_stage", ""))
    before, after = STAGE_BUFFERS.get(stage, (10, 90))
    start = float(row.get("start_ts_epoch", 0.0)) - before
    end = float(row.get("end_ts_epoch", row.get("start_ts_epoch", 0.0))) + after
    return start, end


def query_loki_raw(rule_ids: Iterable[str], start_ts: float, end_ts: float) -> List[Dict[str, Any]]:
    rule_list = sorted({rule_id for rule_id in rule_ids if rule_id})
    if not rule_list:
        return []
    query = '{job="wazuh",source="wazuh",rule_id=~"%s"}' % "|".join(rule_list)
    params = {
        "query": query,
        "limit": "500",
        "direction": "forward",
        "start": str(int(start_ts * 1_000_000_000)),
        "end": str(int(end_ts * 1_000_000_000)),
    }
    url = f"{LOKI_QUERY_URL.rstrip('/')}/loki/api/v1/query_range?{urllib.parse.urlencode(params)}"
    payload = json.loads(urllib.request.urlopen(url, timeout=30).read().decode())
    rows: List[Dict[str, Any]] = []
    for stream in payload.get("data", {}).get("result", []):
        for _, line in stream.get("values", []):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def network_event_matches(alert: Dict[str, Any], row: Dict[str, Any]) -> bool:
    data = alert.get("data", {})
    conn_id = data.get("id", {}) if isinstance(data.get("id"), dict) else {}
    orig_h = conn_id.get("orig_h") or data.get("id_orig_h")
    resp_h = conn_id.get("resp_h") or data.get("id_resp_h")
    source_ips = ASSET_IPS.get(str(row.get("source_asset", "")), set())
    target_ips = ASSET_IPS.get(str(row.get("target_asset", "")), set())
    if source_ips and orig_h not in source_ips:
        return False
    if target_ips and resp_h not in target_ips:
        return False
    return True


def host_event_matches(alert: Dict[str, Any], row: Dict[str, Any]) -> bool:
    agent_name = str(nested_get(alert, "agent", "name") or "")
    if str(row.get("target_asset")) == "ews" or str(row.get("source_asset")) == "ews":
        return agent_name == "EWS-WIN11"
    return True


def historian_anomaly_matches(alert: Dict[str, Any], row: Dict[str, Any]) -> bool:
    data = alert.get("data", {})
    return str(data.get("event_type", "")) == "ingest_anomaly" and str(data.get("status", "")) == "high"


def alert_matches_step(alert: Dict[str, Any], row: Dict[str, Any]) -> bool:
    rule_id = str(nested_get(alert, "rule", "id") or "")
    if rule_id not in step_rule_ids(row):
        return False
    if rule_id in {"100301", "100302", "100303", "100304", "100305", "100306", "100307", "100308"}:
        return network_event_matches(alert, row)
    if rule_id in {"100402", "100404", "100405", "100406"}:
        return host_event_matches(alert, row)
    if rule_id == "100209":
        return historian_anomaly_matches(alert, row)
    return True


def event_row_from_alert(alert: Dict[str, Any], row: Dict[str, Any], manifest_path: Path) -> Dict[str, Any]:
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    conn_id = data.get("id", {}) if isinstance(data.get("id"), dict) else {}
    command_line = nested_get(data, "win", "eventdata", "commandLine")
    script_text = nested_get(data, "win", "eventdata", "scriptBlockText")
    win_eventdata_targetUserName = nested_get(data, "win", "eventdata", "targetUserName")
    rule_id = str(rule.get("id", ""))
    rule_level = int(rule.get("level", 0) or 0)
    evidence_key = RULE_TO_EVIDENCE.get(rule_id, "other")
    alert_ts_raw = str(alert.get("timestamp", ""))
    alert_epoch = parse_loki_timestamp(alert_ts_raw)
    alert_ts = datetime.fromtimestamp(alert_epoch, UTC).isoformat() if alert_epoch else alert_ts_raw
    return {
        "ts": alert_ts,
        "source": "ml",
        "kind": "session_detection_event",
        "session_id": str(row.get("session_id", "")),
        "scenario_id": str(row.get("scenario_id", "")),
        "source_manifest": str(manifest_path),
        "detection_uid": str(alert.get("id", "")),
        "alert_timestamp": alert_ts,
        "alert_epoch": round(alert_epoch, 6),
        "matched_step": str(row.get("scenario_step", "")),
        "source_asset": str(row.get("source_asset", "")),
        "target_asset": str(row.get("target_asset", "")),
        "event_kind": str(row.get("event_kind", "")),
        "rule_id": rule_id,
        "rule_description": str(rule.get("description", "")),
        "rule_level": rule_level,
        "evidence_key": evidence_key,
        "attack_stage": RULE_TO_STAGE.get(rule_id, evidence_key),
        "asset_class": RULE_TO_ASSET.get(rule_id, str(row.get("asset_class", "other"))),
        "agent_name": str(nested_get(alert, "agent", "name") or ""),
        "data_uid": str(data.get("uid", "")),
        "data_id_orig_h": str(conn_id.get("orig_h") or data.get("id_orig_h") or ""),
        "data_id_resp_h": str(conn_id.get("resp_h") or data.get("id_resp_h") or ""),
        "data_id_resp_p": str(conn_id.get("resp_p") or data.get("id_resp_p") or ""),
        "data_service": str(data.get("service", "")),
        "data_tag": str(data.get("tag", "")),
        "data_confidence": str(data.get("confidence", "")),
        "data_route": str(data.get("route", "")),
        "data_event_type": str(data.get("event_type", "")),
        "data_command_line": str(command_line or ""),
        "data_script_content": str(script_text or ""),
        "data_win_eventdata_targetUserName": str(win_eventdata_targetUserName or ""),
        "summary_text": str(rule.get("description", "")),
    }


def build_session_detection_rows(session_file: Path) -> List[Dict[str, Any]]:
    rows = load_manifest_rows(session_file)
    if not rows:
        return []

    session_id = str(rows[-1].get("session_id", ""))
    manifest_path = session_file
    latest_stage = str(rows[-1].get("attack_stage", ""))
    retry_attempts = 4 if latest_stage in {"opcua_write", "process_anomaly", "opcua_path"} else 1
    retry_sleep_seconds = 4
    required_rules = {"100305", "100304"} if latest_stage == "opcua_write" else {"100303"} if latest_stage == "opcua_path" else set()

    matched: Dict[str, Dict[str, Any]] = {}
    for attempt in range(retry_attempts):
        matched.clear()
        for row in rows:
            rule_ids = step_rule_ids(row)
            if not rule_ids:
                continue
            start_ts, end_ts = step_window(row)
            for alert in query_loki_raw(rule_ids, start_ts, end_ts):
                if not alert_matches_step(alert, row):
                    continue
                detection_uid = str(alert.get("id", ""))
                event_row = event_row_from_alert(alert, row, manifest_path)
                previous = matched.get(detection_uid)
                if previous is None or event_row["alert_epoch"] < previous["alert_epoch"]:
                    matched[detection_uid] = event_row
        seen_rules = {row["rule_id"] for row in matched.values()}
        if not required_rules or (seen_rules & required_rules):
            break
        if attempt < retry_attempts - 1:
            time.sleep(retry_sleep_seconds)

    detection_rows = sorted(matched.values(), key=lambda item: float(item.get("alert_epoch", 0.0)))
    evidence_counter = Counter(row["evidence_key"] for row in detection_rows)
    rule_counter = Counter(row["rule_id"] for row in detection_rows)
    asset_classes = sorted({row["asset_class"] for row in detection_rows if row.get("asset_class")})

    primary_rule_id = ""
    primary_rule_description = ""
    primary_rule_level = 0
    if rule_counter:
        primary_rule_id = sorted(rule_counter.items(), key=lambda item: (-item[1], item[0]))[0][0]
        for row in detection_rows:
            if row["rule_id"] == primary_rule_id:
                primary_rule_description = row["rule_description"]
                primary_rule_level = int(row["rule_level"])
                break

    high_risk = sorted(detection_rows, key=lambda item: (-int(item["rule_level"]), item["rule_id"]))
    top_high_risk_rule_id = high_risk[0]["rule_id"] if high_risk else ""
    top_high_risk_rule_description = high_risk[0]["rule_description"] if high_risk else ""
    top_high_risk_rule_level = int(high_risk[0]["rule_level"]) if high_risk else 0

    summary_ts = detection_rows[-1]["ts"] if detection_rows else datetime.fromtimestamp(float(rows[-1].get("end_ts_epoch", rows[-1].get("start_ts_epoch", 0.0))), UTC).isoformat()
    summary_row: Dict[str, Any] = {
        "ts": summary_ts,
        "source": "ml",
        "kind": "session_detection_summary",
        "session_id": session_id,
        "scenario_id": str(rows[-1].get("scenario_id", "")),
        "source_manifest": str(manifest_path),
        "asset_classes_hit": len(asset_classes),
        "asset_classes": asset_classes,
        "observed_detection_count": len(detection_rows),
        "primary_rule_id": primary_rule_id,
        "primary_rule_description": primary_rule_description,
        "primary_rule_level": primary_rule_level,
        "primary_rule_id_numeric": int(primary_rule_id) if primary_rule_id.isdigit() else 0,
        "top_high_risk_rule_id": top_high_risk_rule_id,
        "top_high_risk_rule_description": top_high_risk_rule_description,
        "top_high_risk_rule_level": top_high_risk_rule_level,
        "top_high_risk_rule_id_numeric": int(top_high_risk_rule_id) if top_high_risk_rule_id.isdigit() else 0,
        "summary_text": (
            f"{len(detection_rows)} correlated live detections observed across "
            f"{len(asset_classes)} asset classes for session {session_id}."
            if detection_rows
            else f"No correlated live detections observed yet for session {session_id}."
        ),
    }
    for evidence_key, field_name in SUMMARY_KEYS.items():
        if evidence_key == "write_like":
            count = evidence_counter.get("write_like", 0) + evidence_counter.get("critical_write", 0)
        else:
            count = evidence_counter.get(evidence_key, 0)
        summary_row[field_name] = int(count)

    return [*detection_rows, summary_row]
