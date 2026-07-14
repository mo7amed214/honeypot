"""Experiment 4 - detection coverage.

For a completed trial, cross-reference each recorded agent action against the
alerts the honeynet's own sensors produced during the trial window, and report
what fraction of adversary actions were caught, broken down by asset class.

Alert sources (all already produced by the running stack):
  * Wazuh alerts JSON  (INTEGRATION_SOC_ALERTS_PATH or the wazuh volume)
  * Zeek current logs  (conn.log, discovery_scan.log, opcua_write.log,
                        arp_mitm.log)

An action counts as "detected" if at least one alert falls within its
[start_ts, end_ts] window (with a small grace margin) and plausibly matches its
asset/technique. This mirrors Table 5.5 in the thesis, now generated
automatically for an unscripted attacker.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


GRACE_SEC = 5.0


def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not os.path.isfile(path):
        return rows
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _read_zeek_tsv_ts(path: str) -> List[float]:
    """Extract the `ts` (epoch) column from a TSV-format Zeek log.

    Zeek writes tab-separated logs with #-prefixed headers; the #fields line
    names the columns. We locate the `ts` column and pull its value from each
    data row. (Zeek can be configured for JSON, but the default is TSV, which is
    what the detection scripts emit here.)"""
    epochs: List[float] = []
    if not os.path.isfile(path):
        return epochs
    ts_idx = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                if "ts" in fields:
                    ts_idx = fields.index("ts")
                continue
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) > ts_idx:
                try:
                    epochs.append(float(parts[ts_idx]))
                except ValueError:
                    continue
    return epochs


def _alert_epochs(alerts_path: str, zeek_dir: str) -> List[float]:
    """Collect alert timestamps (epoch seconds) from Wazuh + Zeek detections.

    Only actual *detection* logs count as alerts (discovery_scan / opcua_write /
    arp_mitm / notice) - conn.log is raw traffic, not a detection, so including
    it would make every connection trivially "covered"."""
    epochs: List[float] = []
    for row in _read_jsonl(alerts_path):
        ts = row.get("timestamp") or row.get("alert_timestamp")
        e = _parse_ts(ts)
        if e is not None:
            epochs.append(e)
    for name in ("discovery_scan.log", "opcua_write.log", "arp_mitm.log", "notice.log"):
        p = os.path.join(zeek_dir, name)
        # try JSON first (some deployments log JSON), then TSV (Zeek default)
        json_rows = _read_jsonl(p)
        if json_rows:
            for row in json_rows:
                ts = row.get("ts")
                e = float(ts) if isinstance(ts, (int, float)) else _parse_ts(ts)
                if e is not None:
                    epochs.append(e)
        else:
            epochs.extend(_read_zeek_tsv_ts(p))
    return sorted(epochs)


def _parse_ts(ts: Any) -> Optional[float]:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(s.split("+")[0].split("Z")[0], fmt.split("%z")[0].strip()))
        except (ValueError, OverflowError):
            continue
    return None


@dataclass
class CoverageResult:
    trial_id: str
    total_actions: int
    detected_actions: int
    coverage_ratio: float
    per_asset: Dict[str, Dict[str, int]]


def compute_coverage(trial_dir: str,
                     alerts_path: Optional[str] = None,
                     zeek_dir: Optional[str] = None) -> CoverageResult:
    manifest = _read_jsonl(os.path.join(trial_dir, "ground_truth.jsonl"))
    trial = {}
    tp = os.path.join(trial_dir, "trial.json")
    if os.path.isfile(tp):
        with open(tp, encoding="utf-8") as fh:
            trial = json.load(fh)

    alerts_path = alerts_path or os.environ.get(
        "INTEGRATION_SOC_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
    zeek_dir = zeek_dir or os.environ.get(
        "INTEGRATION_SOC_ZEEK_DIR", "/var/log/zeek/current")
    alert_epochs = _alert_epochs(alerts_path, zeek_dir)

    per_asset: Dict[str, Dict[str, int]] = {}
    detected = 0
    for row in manifest:
        asset = row.get("asset_class", "unknown")
        start = float(row.get("start_ts_epoch", 0.0))
        end = float(row.get("end_ts_epoch", start)) + GRACE_SEC
        is_detected = any(start - GRACE_SEC <= e <= end for e in alert_epochs)
        bucket = per_asset.setdefault(asset, {"actions": 0, "detected": 0})
        bucket["actions"] += 1
        if is_detected:
            bucket["detected"] += 1
            detected += 1

    total = len(manifest)
    return CoverageResult(
        trial_id=trial.get("trial_id", os.path.basename(trial_dir)),
        total_actions=total,
        detected_actions=detected,
        coverage_ratio=round(detected / total, 4) if total else 0.0,
        per_asset=per_asset,
    )
