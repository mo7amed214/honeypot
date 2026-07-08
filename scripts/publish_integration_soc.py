#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


LOOKBACK_SECONDS = int(os.environ.get("INTEGRATION_SOC_LOOKBACK_SECONDS", "7200"))
POLL_SECONDS = float(os.environ.get("INTEGRATION_SOC_POLL_SECONDS", "15"))
RUN_ONCE = os.environ.get("INTEGRATION_SOC_ONCE", "0") == "1"
SESSION_ID = os.environ.get("INTEGRATION_SOC_SESSION_ID", "INTEGRATION-LIVE")

ALERTS_PATH = Path(os.environ.get("INTEGRATION_SOC_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json"))
ML_DIR = Path(os.environ.get("INTEGRATION_SOC_ML_DIR", "/var/log/honeypot-ml"))
HIST_DIR = Path(os.environ.get("INTEGRATION_SOC_HIST_DIR", "/var/log/historian"))
ZEEK_DIR = Path(os.environ.get("INTEGRATION_SOC_ZEEK_DIR", "/var/log/zeek/current"))
AUTH_LOG = Path(os.environ.get("INTEGRATION_SOC_AUTH_LOG", "/var/log/auth.log"))
STATE_PATH = Path(os.environ.get("INTEGRATION_SOC_STATE_PATH", "/tmp/integration_soc_state.json"))
DOCKER_BIN = os.environ.get("INTEGRATION_SOC_DOCKER_BIN", "docker")
SMB_CONTAINER = os.environ.get("INTEGRATION_SOC_SMB_CONTAINER", "compose-smb-1")
OPCUA_CONTAINER = os.environ.get("INTEGRATION_SOC_OPCUA_CONTAINER", "compose-opcua-1")

AGENT_NAME = os.environ.get("INTEGRATION_SOC_AGENT_NAME", socket.gethostname())
MANAGER_NAME = os.environ.get("INTEGRATION_SOC_MANAGER_NAME", "integration.soc")

RULES: Dict[str, Dict[str, Any]] = {
    "100301": {
        "level": 8,
        "description": "Zeek historian web connection observed.",
        "evidence_key": "historian_web",
        "attack_stage": "historian_web",
        "asset_class": "historian",
        "event_kind": "http_session",
        "source_asset": "workstation",
        "target_asset": "historian",
    },
    "100302": {
        "level": 8,
        "description": "Zeek SMB connection observed.",
        "evidence_key": "smb_access",
        "attack_stage": "smb_access",
        "asset_class": "smb",
        "event_kind": "smb_session",
        "source_asset": "workstation",
        "target_asset": "smb",
    },
    "100303": {
        "level": 7,
        "description": "Zeek OPC UA connection observed.",
        "evidence_key": "opcua_path",
        "attack_stage": "opcua_path",
        "asset_class": "opcua",
        "event_kind": "tcp_probe",
        "source_asset": "workstation",
        "target_asset": "opcua",
    },
    "100304": {
        "level": 10,
        "description": "100304A Zeek OPC UA write-like payload pattern detected.",
        "evidence_key": "write_like",
        "attack_stage": "opcua_write",
        "asset_class": "opcua",
        "event_kind": "write_like",
        "source_asset": "workstation",
        "target_asset": "opcua",
    },
    "100305": {
        "level": 13,
        "description": "100304A critical OPC UA write-like activity observed from sensitive tag or sustained EWS write session.",
        "evidence_key": "critical_write",
        "attack_stage": "opcua_write",
        "asset_class": "opcua",
        "event_kind": "critical_write",
        "source_asset": "workstation",
        "target_asset": "opcua",
    },
    "100307": {
        "level": 9,
        "description": "Zeek rapid discovery scan observed against Level 3 services.",
        "evidence_key": "discovery",
        "attack_stage": "discovery",
        "asset_class": "level3",
        "event_kind": "discovery_scan",
        "source_asset": "workstation",
        "target_asset": "level3_subnet",
    },
    "100308": {
        "level": 13,
        "description": "ARP cache poisoning detected — MAC changed for a known asset IP (T0830 MitM on OPC UA path).",
        "evidence_key": "critical_write",
        "attack_stage": "opcua_write",
        "asset_class": "opcua",
        "event_kind": "arp_mitm",
        "source_asset": "workstation",
        "target_asset": "historian_opcua",
    },
    "100209": {
        "level": 10,
        "description": "Historian high-severity ingest anomaly detected.",
        "evidence_key": "process_anomaly",
        "attack_stage": "process_anomaly",
        "asset_class": "historian",
        "event_kind": "ingest_anomaly",
        "source_asset": "historian",
        "target_asset": "opcua",
    },
    "100402": {
        "level": 8,
        "description": "SSH session initiated on EWS endpoint.",
        "evidence_key": "host_access",
        "attack_stage": "host_activity",
        "asset_class": "ews",
        "event_kind": "ssh_session",
        "source_asset": "level35_jump_host",
        "target_asset": "ews",
    },
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

STAGE_PRIORITY = {
    "process_anomaly": 6,
    "opcua_write": 5,
    "opcua_path": 4,
    "historian_web": 3,
    "smb_access": 3,
    "host_activity": 3,
    "discovery": 2,
}

AUTH_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from (?P<src_ip>[0-9.]+)"
)
SMBSTATUS_RE = re.compile(
    r"^(?P<service>\S+)\s+(?P<pid>\d+)\s+(?P<machine>\S+)\s+(?P<connected>.+)$"
)
OPCUA_CONN_RE = re.compile(
    r"^\[(?P<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) \(UTC[+-]\d{4}\)\].*Connection (?P<connection>\d+) \| New connection over TCP from (?P<src_ip>[0-9.]+)"
)


def now_epoch() -> float:
    return time.time()


def iso_from_epoch(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def load_state() -> Dict[str, Any]:
    if not STATE_PATH.exists():
        return {"seen_alert_keys": [], "last_ml_fingerprint": ""}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"seen_alert_keys": [], "last_ml_fingerprint": ""}


def save_state(state: Dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=True, indent=2), encoding="utf-8")


def append_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")


def decode_separator(raw: str) -> str:
    token = raw.split(" ", 1)[1].strip()
    try:
        return bytes(token, "utf-8").decode("unicode_escape")
    except Exception:
        return "\t"


def read_zeek_log(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    rows: List[Dict[str, Any]] = []
    fields: List[str] = []
    separator = "\t"

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.rstrip("\n")
        if not line:
            continue
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            continue
        if line.startswith("#separator "):
            separator = decode_separator(line)
            continue
        if line.startswith("#fields"):
            fields = line.split(separator)[1:]
            continue
        if line.startswith("#"):
            continue
        if not fields:
            continue
        values = line.split(separator)
        if len(values) != len(fields):
            continue
        rows.append(dict(zip(fields, values)))
    return rows


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def parse_alert_epoch(value: str) -> float:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.000+0000").replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0


def read_persisted_transient_alert_events(cutoff: float) -> List[Dict[str, Any]]:
    if not ALERTS_PATH.exists():
        return []

    events: List[Dict[str, Any]] = []
    for row in read_jsonl(ALERTS_PATH):
        rule_id = str((row.get("rule") or {}).get("id", ""))
        if rule_id not in {"100302", "100303", "100304", "100305", "100307"}:
            continue

        data = row.get("data") or {}
        if str(data.get("session_id", "")) != SESSION_ID:
            continue

        ts_epoch = parse_alert_epoch(str(row.get("timestamp", "")))
        if ts_epoch < cutoff:
            continue

        conn = data.get("id") or {}
        events.append(
            {
                "rule_id": rule_id,
                "ts_epoch": ts_epoch,
                "data": {
                    "uid": str(data.get("uid", data.get("detection_id", ""))),
                    "id.orig_h": str(conn.get("orig_h", data.get("id_orig_h", ""))),
                    "id.orig_p": str(conn.get("orig_p", data.get("id_orig_p", ""))),
                    "id.resp_h": str(conn.get("resp_h", data.get("id_resp_h", ""))),
                    "id.resp_p": str(conn.get("resp_p", data.get("id_resp_p", ""))),
                    "proto": str(data.get("proto", "tcp")),
                    "service": str(data.get("service", "")),
                    "src_ip": str(data.get("src_ip", conn.get("orig_h", data.get("id_orig_h", "")))),
                    "matched_tag": str(data.get("tag", "")),
                    "critical_target": str(data.get("critical_target", "")),
                    "confidence": str(data.get("confidence", "")),
                    "detection_id": str(data.get("detection_id", "")),
                },
            }
        )
    return events


def parse_auth_epoch(match: re.Match[str]) -> float:
    current = datetime.now(timezone.utc)
    stamp = f"{current.year} {match.group('month')} {match.group('day')} {match.group('clock')}"
    parsed = datetime.strptime(stamp, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def parse_smb_connected_epoch(raw: str) -> float:
    try:
        return datetime.strptime(raw, "%a %b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return now_epoch()


def parse_opcua_log_epoch(raw: str) -> float:
    return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()


def read_command_output(args: List[str], timeout: float = 10.0) -> str:
    try:
        proc = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return ""
    output = (proc.stdout or "") + (proc.stderr or "")
    return output.strip()


def read_live_smb_events(cutoff: float) -> List[Dict[str, Any]]:
    if not Path(DOCKER_BIN).exists() and not shutil.which(DOCKER_BIN):
        return []

    output = read_command_output([DOCKER_BIN, "exec", SMB_CONTAINER, "smbstatus", "-S"])
    events: List[Dict[str, Any]] = []
    for line in output.splitlines():
        match = SMBSTATUS_RE.match(line.strip())
        if not match:
            continue
        ts_epoch = parse_smb_connected_epoch(match.group("connected"))
        if ts_epoch < cutoff:
            continue
        src_ip = match.group("machine")
        service = match.group("service")
        pid = match.group("pid")
        events.append(
            {
                "rule_id": "100302",
                "ts_epoch": ts_epoch,
                "data": {
                    "uid": f"smb:{service}:{pid}:{int(ts_epoch)}",
                    "id.orig_h": src_ip,
                    "id.orig_p": "",
                    "id.resp_h": "127.0.0.1",
                    "id.resp_p": "445",
                    "proto": "tcp",
                    "service": service,
                    "src_ip": src_ip,
                },
            }
        )
    return events


def read_recent_opcua_connection_events(cutoff: float) -> List[Dict[str, Any]]:
    if not Path(DOCKER_BIN).exists() and not shutil.which(DOCKER_BIN):
        return []

    since = iso_from_epoch(cutoff)
    output = read_command_output([DOCKER_BIN, "logs", "--since", since, OPCUA_CONTAINER], timeout=15.0)
    events: List[Dict[str, Any]] = []
    for line in output.splitlines():
        match = OPCUA_CONN_RE.match(line.strip())
        if not match:
            continue
        ts_epoch = parse_opcua_log_epoch(match.group("stamp"))
        if ts_epoch < cutoff:
            continue
        src_ip = match.group("src_ip")
        conn_id = match.group("connection")
        events.append(
            {
                "rule_id": "100303",
                "ts_epoch": ts_epoch,
                "data": {
                    "uid": f"opcua:{conn_id}:{int(ts_epoch)}",
                    "id.orig_h": src_ip,
                    "id.orig_p": "",
                    "id.resp_h": "127.0.0.1",
                    "id.resp_p": "4840",
                    "proto": "tcp",
                    "src_ip": src_ip,
                    "service": "opcua",
                },
            }
        )
    return events


def read_recent_auth_events(cutoff: float) -> List[Dict[str, Any]]:
    if not AUTH_LOG.is_file():
        # .exists() alone isn't enough: a bind mount of a host path that
        # doesn't exist yet gets silently created as an empty directory
        # rather than a file, which .exists() can't tell apart.
        return []
    events: List[Dict[str, Any]] = []
    for raw_line in AUTH_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        match = AUTH_RE.match(raw_line)
        if not match:
            continue
        event_epoch = parse_auth_epoch(match)
        if event_epoch < cutoff:
            continue
        events.append(
            {
                "ts_epoch": event_epoch,
                "src_ip": match.group("src_ip"),
                "username": match.group("user"),
                "raw": raw_line,
            }
        )
    return events


def normalize_recent_events(cutoff: float) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for row in read_zeek_log(ZEEK_DIR / "conn.log"):
        ts_epoch = safe_float(row.get("ts"))
        if ts_epoch < cutoff:
            continue
        resp_p = str(row.get("id.resp_p", ""))
        if resp_p == "5000/tcp" or resp_p == "5000":
            rule_id = "100301"
        elif resp_p == "445/tcp" or resp_p == "445":
            rule_id = "100302"
        elif resp_p == "4840/tcp" or resp_p == "4840":
            rule_id = "100303"
        else:
            continue
        events.append({"rule_id": rule_id, "ts_epoch": ts_epoch, "data": row})

    for row in read_zeek_log(ZEEK_DIR / "discovery_scan.log"):
        ts_epoch = safe_float(row.get("ts"))
        if ts_epoch < cutoff:
            continue
        events.append({"rule_id": "100307", "ts_epoch": ts_epoch, "data": row})

    for row in read_zeek_log(ZEEK_DIR / "opcua_write.log"):
        ts_epoch = safe_float(row.get("ts"))
        if ts_epoch < cutoff:
            continue
        events.append({"rule_id": "100304", "ts_epoch": ts_epoch, "data": row})
        if str(row.get("critical_target", "")).lower() == "true" and str(row.get("confidence", "")).lower() == "high":
            events.append({"rule_id": "100305", "ts_epoch": ts_epoch, "data": row})

    for row in read_zeek_log(ZEEK_DIR / "arp_mitm.log"):
        ts_epoch = safe_float(row.get("ts"))
        if ts_epoch < cutoff:
            continue
        events.append({"rule_id": "100308", "ts_epoch": ts_epoch, "data": row})

    for row in read_jsonl(HIST_DIR / "events.jsonl"):
        event_epoch = safe_float(datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp()) if row.get("timestamp") else 0.0
        if event_epoch < cutoff:
            continue
        if row.get("event_type") in {
            "login_attempt",
            "basic_auth_capture",
            "pi_probe",
            "decoy_probe",
            "portal_visit",
            "portal_history_query",
            "history_query",
            "grafana_latest",
            "grafana_history",
            "list_tags",
        }:
            events.append({"rule_id": "100301", "ts_epoch": event_epoch, "data": row})

    for row in read_jsonl(HIST_DIR / "ingest.jsonl"):
        event_epoch = safe_float(datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp()) if row.get("timestamp") else 0.0
        if event_epoch < cutoff:
            continue
        if row.get("event_type") == "ingest_anomaly" and str(row.get("status", "")).lower() == "high":
            events.append({"rule_id": "100209", "ts_epoch": event_epoch, "data": row})

    for row in read_recent_auth_events(cutoff):
        events.append({"rule_id": "100402", "ts_epoch": row["ts_epoch"], "data": row})

    events.extend(read_live_smb_events(cutoff))
    events.extend(read_recent_opcua_connection_events(cutoff))
    events.extend(read_persisted_transient_alert_events(cutoff))

    events.sort(key=lambda item: (item["ts_epoch"], item["rule_id"]))
    return collapse_event_bursts(events)


def collapse_event_bursts(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    collapsed: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, int]] = set()

    for event in events:
        data = event["data"]
        discriminator = "|".join(
            [
                str(data.get("uid", "")),
                str(data.get("detection_id", "")),
                str(data.get("id.orig_h", data.get("id_orig_h", ""))),
                str(data.get("id.resp_h", data.get("id_resp_h", ""))),
                str(data.get("id.resp_p", data.get("id_resp_p", ""))),
                str(data.get("tag", data.get("matched_tag", ""))),
                str(data.get("route", "")),
                str(data.get("src_ip", "")),
            ]
        )
        burst_bucket = int(event["ts_epoch"] // 30)
        signature = (event["rule_id"], discriminator, burst_bucket)
        if signature in seen:
            continue
        seen.add(signature)
        collapsed.append(event)
    return collapsed


def alert_key(event: Dict[str, Any]) -> str:
    rule_id = event["rule_id"]
    data = event["data"]
    key_parts = [rule_id, f"{event['ts_epoch']:.6f}"]
    for field in ("uid", "detection_id", "tag", "route", "src_ip", "username", "raw"):
        value = data.get(field) if isinstance(data, dict) else None
        if value:
            key_parts.append(str(value))
    if isinstance(data, dict):
        if data.get("id.orig_h") or data.get("id.resp_h"):
            key_parts.extend([str(data.get("id.orig_h", "")), str(data.get("id.resp_h", "")), str(data.get("id.resp_p", ""))])
    return "|".join(key_parts)


def build_alert(event: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = event["rule_id"]
    rule = RULES[rule_id]
    data = event["data"]
    ts_iso = datetime.fromtimestamp(event["ts_epoch"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    payload: Dict[str, Any] = {
        "timestamp": ts_iso,
        "rule": {
            "level": rule["level"],
            "description": rule["description"],
            "id": rule_id,
            "firedtimes": 1,
            "mail": False,
            "groups": ["integration", "level3", "observed"],
        },
        "agent": {"id": "L3", "name": AGENT_NAME, "ip": "127.0.0.1"},
        "manager": {"name": MANAGER_NAME},
        "id": f"{int(event['ts_epoch'])}.{abs(hash(alert_key(event))) % 1000000}",
        "decoder": {"name": "json"},
        "data": {
            "session_id": SESSION_ID,
            "telemetry_origin": "integration_live",
            "ground_truth_label": "observed",
            "scenario_family": "integration_mode",
            "dataset_split": "observed",
        },
    }

    if rule_id in {"100301", "100302", "100303"}:
        payload["data"].update(
            {
                "ts": f"{safe_float(data.get('ts')):.6f}",
                "uid": str(data.get("uid", "")),
                "id": {
                    "orig_h": str(data.get("id.orig_h", "")),
                    "orig_p": str(data.get("id.orig_p", "")),
                    "resp_h": str(data.get("id.resp_h", "")),
                    "resp_p": str(data.get("id.resp_p", "")),
                },
                "proto": str(data.get("proto", "tcp")),
                "duration": str(data.get("duration", "")),
                "orig_bytes": str(data.get("orig_bytes", "")),
                "resp_bytes": str(data.get("resp_bytes", "")),
            }
        )
    elif rule_id in {"100304", "100305"}:
        payload["data"].update(
            {
                "ts": f"{safe_float(data.get('ts')):.6f}",
                "uid": str(data.get("uid", "")),
                "id_orig_h": str(data.get("id_orig_h", "")),
                "id_orig_p": str(data.get("id_orig_p", "")),
                "id_resp_h": str(data.get("id_resp_h", "")),
                "id_resp_p": str(data.get("id_resp_p", "")),
                "detection_id": str(data.get("detection_id", "100304A")),
                "service": str(data.get("service", "opcua.write_like")),
                "tag": str(data.get("matched_tag", "")),
                "critical_target": str(data.get("critical_target", "")),
                "confidence": str(data.get("confidence", "")),
            }
        )
    elif rule_id == "100307":
        payload["data"].update(
            {
                "ts": f"{safe_float(data.get('ts')):.6f}",
                "src_h": str(data.get("src_h", "")),
                "detection_id": str(data.get("detection_id", "100307A")),
                "service": str(data.get("service", "network.discovery_scan")),
                "confidence": str(data.get("confidence", "")),
            }
        )
    elif rule_id == "100308":
        payload["data"].update(
            {
                "ts": f"{safe_float(data.get('ts')):.6f}",
                "orig_ip": str(data.get("orig_ip", "")),
                "detection_id": str(data.get("detection_id", "100308A")),
                "service": str(data.get("service", "network.arp_mitm")),
                "confidence": str(data.get("confidence", "")),
            }
        )
    elif rule_id == "100209":
        payload["data"].update(
            {
                "service": str(data.get("service", "historian_ingest")),
                "event_type": str(data.get("event_type", "ingest_anomaly")),
                "route": str(data.get("route", "opcua_ingest")),
                "tag": str(data.get("tag", "")),
                "status": str(data.get("status", "")),
            }
        )
    elif rule_id == "100402":
        payload["agent"]["name"] = "EWS-LINUX"
        payload["data"].update(
            {
                "event_id": "4624",
                "src_ip": str(data.get("src_ip", "")),
                "targetUserName": str(data.get("username", "")),
                "processName": "/usr/sbin/sshd",
            }
        )
    return payload


def dedupe_in_order(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def dominant_stage(events: List[Dict[str, Any]]) -> str:
    stages = dedupe_in_order(RULES[event["rule_id"]]["attack_stage"] for event in events)
    if not stages:
        return "benign_access"
    return max(stages, key=lambda stage: (STAGE_PRIORITY.get(stage, 0), stages.index(stage)))


def danger_from_rules(rule_ids: set[str]) -> Tuple[float, str]:
    if rule_ids & {"100305", "100308", "100209"}:
        return 0.93, "critical"
    if rule_ids & {"100304"}:
        return 0.88, "high"
    if "100303" in rule_ids and rule_ids & {"100301", "100302", "100402"}:
        return 0.74, "high"
    if rule_ids & {"100301", "100302", "100402", "100307"}:
        return 0.56, "medium"
    return 0.22, "low"


def intent_from_rules(rule_ids: set[str]) -> str:
    if rule_ids & {"100305", "100308", "100209", "100304"}:
        return "ot_impact"
    if "100303" in rule_ids:
        return "ot_recon"
    if rule_ids & {"100301", "100302"}:
        return "collection"
    if "100402" in rule_ids:
        return "credential_access"
    return "benign_operations"


def priority_from_label(label: str) -> str:
    return {"critical": "P1", "high": "P2", "medium": "P3"}.get(label, "P4")


def summarize_session(intent: str, label: str, event_count: int, stage_path: str, asset_path: str) -> str:
    return f"{intent} session with {label} severity across {event_count} events. Path={stage_path} assets={asset_path}."


def build_ml_rows(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not events:
        return []

    latest_epoch = events[-1]["ts_epoch"]
    ts = iso_from_epoch(latest_epoch)
    rule_ids = {event["rule_id"] for event in events}
    stage_path_items = dedupe_in_order(RULES[event["rule_id"]]["attack_stage"] for event in events)
    asset_path_items = dedupe_in_order(RULES[event["rule_id"]]["asset_class"] for event in events)
    stage_path = ">".join(stage_path_items)
    asset_path = ">".join(asset_path_items)
    dom_stage = dominant_stage(events)
    danger_score, danger_label = danger_from_rules(rule_ids)
    intent = intent_from_rules(rule_ids)
    priority = priority_from_label(danger_label)
    summary_text = summarize_session(intent, danger_label, len(events), stage_path, asset_path)

    detection_rows: List[Dict[str, Any]] = []
    counts = Counter()

    for event in events:
        rule_id = event["rule_id"]
        rule = RULES[rule_id]
        data = event["data"]
        counts[rule["evidence_key"]] += 1
        data_uid = str(data.get("uid", data.get("detection_id", "")))
        detection_rows.append(
            {
                "ts": iso_from_epoch(event["ts_epoch"]),
                "source": "ml",
                "kind": "session_detection_event",
                "session_id": SESSION_ID,
                "scenario_id": SESSION_ID,
                "source_manifest": "integration_live",
                "detection_uid": f"{rule_id}:{data_uid or int(event['ts_epoch'])}",
                "alert_timestamp": iso_from_epoch(event["ts_epoch"]),
                "alert_epoch": round(event["ts_epoch"], 6),
                "matched_step": f"observed_{rule['attack_stage']}",
                "source_asset": rule["source_asset"],
                "target_asset": rule["target_asset"],
                "event_kind": rule["event_kind"],
                "rule_id": rule_id,
                "rule_description": rule["description"],
                "rule_level": rule["level"],
                "evidence_key": rule["evidence_key"],
                "attack_stage": rule["attack_stage"],
                "asset_class": rule["asset_class"],
                "agent_name": "EWS-LINUX" if rule_id == "100402" else AGENT_NAME,
                "data_uid": data_uid,
                "data_id_orig_h": str(data.get("id.orig_h", data.get("id_orig_h", ""))),
                "data_id_resp_h": str(data.get("id.resp_h", data.get("id_resp_h", ""))),
                "data_id_resp_p": str(data.get("id.resp_p", data.get("id_resp_p", ""))),
                "data_service": str(data.get("service", "")),
                "data_tag": str(data.get("tag", data.get("matched_tag", ""))),
                "data_confidence": str(data.get("confidence", "")),
                "data_route": str(data.get("route", "")),
                "data_event_type": str(data.get("event_type", "")),
                "data_command_line": str(data.get("raw", "")) if rule_id == "100402" else "",
                "data_script_content": "",
                "summary_text": rule["description"],
            }
        )

    primary_event = Counter(event["rule_id"] for event in events).most_common(1)[0][0]
    top_risk = max(events, key=lambda item: RULES[item["rule_id"]]["level"])["rule_id"]
    detection_summary = {
        "ts": ts,
        "source": "ml",
        "kind": "session_detection_summary",
        "session_id": SESSION_ID,
        "scenario_id": SESSION_ID,
        "source_manifest": "integration_live",
        "asset_classes_hit": len(asset_path_items),
        "asset_classes": asset_path_items,
        "observed_detection_count": len(events),
        "primary_rule_id": primary_event,
        "primary_rule_description": RULES[primary_event]["description"],
        "primary_rule_level": RULES[primary_event]["level"],
        "primary_rule_id_numeric": safe_int(primary_event),
        "top_high_risk_rule_id": top_risk,
        "top_high_risk_rule_description": RULES[top_risk]["description"],
        "top_high_risk_rule_level": RULES[top_risk]["level"],
        "top_high_risk_rule_id_numeric": safe_int(top_risk),
        "summary_text": f"{len(events)} correlated live detections observed across {len(asset_path_items)} asset classes for session {SESSION_ID}.",
    }
    for evidence_key, summary_key in SUMMARY_KEYS.items():
        detection_summary[summary_key] = counts.get(evidence_key, 0)

    progression = {
        "ts": ts,
        "source": "ml",
        "kind": "session_progression",
        "model_name": "integration_soc_overlay",
        "session_id": SESSION_ID,
        "event_count": len(events),
        "total_event_count": len(events),
        "is_full_session": True,
        "stage_path": stage_path,
        "asset_path": asset_path,
        "predicted_danger_score": danger_score,
        "predicted_danger_label": danger_label,
        "predicted_dominant_stage": dom_stage,
        "predicted_session_intent": intent,
        "predicted_session_intent_hybrid": intent,
        "predicted_priority": priority,
        "summary_text": summary_text,
    }

    correlated = {
        "ts": ts,
        "source": "ml",
        "kind": "correlated_session_summary",
        "model_name": "integration_soc_overlay",
        "session_id": SESSION_ID,
        "session_rank": 0,
        "event_count": len(events),
        "total_event_count": len(events),
        "is_full_session": True,
        "stage_path": stage_path,
        "asset_path": asset_path,
        "predicted_danger_score": danger_score,
        "predicted_danger_label": danger_label,
        "predicted_dominant_stage": dom_stage,
        "predicted_session_intent": intent,
        "predicted_session_intent_hybrid": intent,
        "predicted_priority": priority,
        "summary_text": summary_text,
    }

    return detection_rows + [detection_summary, progression, correlated]


def cleanup_old_snapshots(prefix: str, keep: int = 8) -> None:
    files = sorted(ML_DIR.glob(f"{prefix}_*.jsonl"))
    for path in files[:-keep]:
        try:
            path.unlink()
        except OSError:
            pass


def main() -> None:
    state = load_state()
    seen_alert_keys = set(state.get("seen_alert_keys", []))
    last_ml_fingerprint = str(state.get("last_ml_fingerprint", ""))

    while True:
        cutoff = now_epoch() - LOOKBACK_SECONDS
        events = normalize_recent_events(cutoff)

        new_alerts: List[Dict[str, Any]] = []
        for event in events:
            key = alert_key(event)
            if key in seen_alert_keys:
                continue
            new_alerts.append(build_alert(event))
            seen_alert_keys.add(key)

        if new_alerts:
            append_jsonl(ALERTS_PATH, new_alerts)

        ml_rows = build_ml_rows(events)
        fingerprint = hashlib.sha1(json.dumps(ml_rows, sort_keys=True).encode("utf-8")).hexdigest() if ml_rows else ""
        if ml_rows and fingerprint != last_ml_fingerprint:
            run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            latest_path = ML_DIR / "integration_live_latest.json"
            stamped_path = ML_DIR / f"integration_live_{run_stamp}.jsonl"
            write_jsonl(stamped_path, ml_rows)
            latest_path.write_text(json.dumps(ml_rows, ensure_ascii=True, indent=2), encoding="utf-8")
            cleanup_old_snapshots("integration_live")
            last_ml_fingerprint = fingerprint

        state["seen_alert_keys"] = list(seen_alert_keys)[-5000:]
        state["last_ml_fingerprint"] = last_ml_fingerprint
        save_state(state)

        if RUN_ONCE:
            return
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
