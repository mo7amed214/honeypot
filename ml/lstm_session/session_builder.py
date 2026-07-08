"""
Session builder — assembles raw telemetry events into labelled training examples.

Reads ground-truth manifests (artifacts/scenario-runs/*/ground_truth.jsonl) and
live detection session files, groups records by session ID, maps rule IDs to
attack-stage labels, and expands each full session into N progressive prefix
examples so the model learns attack build-up across partial sessions.

Key exports used by train.py and infer.py:
  - build_all_vocabs()       : builds categorical-field vocabularies from corpus
  - build_examples()         : manifest → list of labelled session examples
  - encode_examples()        : maps categorical fields to integer indices
  - grouped_split()          : stratified train/val/test split by session intent
  - DANGER_LABEL_TO_SCORE    : canonical danger-label → numeric score mapping
"""

from __future__ import annotations

import json
import math
import os
import random
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

SEED = 7

STAGE_RISK = {
    "benign_access": 0.14,
    "benign_host_check": 0.18,
    "benign_historian_review": 0.20,
    "benign_smb_review": 0.16,
    "monitoring_api": 0.16,
    "network_healthcheck": 0.18,
    "discovery": 0.28,
    "credential_access": 0.46,
    "host_activity": 0.50,
    "host_command": 0.62,
    "host_scriptblock": 0.70,
    "smb_access": 0.58,
    "historian_web": 0.74,
    "opcua_path": 0.78,
    "opcua_write": 0.95,
    "process_anomaly": 0.90,
}

BENIGN_STAGES = {
    "benign_access",
    "benign_host_check",
    "benign_historian_review",
    "benign_smb_review",
    "monitoring_api",
    "network_healthcheck",
}

DANGER_LABEL_TO_SCORE = {
    "low": 0.20,
    "medium": 0.50,
    "high": 0.78,
    "critical": 0.95,
}

INTENT_CANONICAL = {
    "operator_review": "benign_operations",
    "process_monitoring": "benign_operations",
    "maintenance_check": "benign_operations",
    "ot_healthcheck": "benign_operations",
    "credential_access": "credential_access",
    "credential_reuse": "credential_access",
    "host_recon": "host_recon",
    "collection": "collection",
    "multi_stage_collection": "collection",
    "ot_recon": "ot_recon",
    "discovery_scan": "discovery_scan",
    "ot_impact": "ot_impact",
}

DEFAULT_DETECTION_IP_TO_ASSET = {
    "192.168.1.5": "ews",
    "192.168.1.7": "smb",
    "192.168.1.9": "monitoring_laptop",
    "192.168.1.10": "historian",
    "192.168.1.11": "opcua",
}


def _load_ip_to_asset() -> Dict[str, str]:
    """Merge in a LEVEL3_IP_TO_ASSET JSON override for non-default lab subnets
    (e.g. the laptop1-safe 192.168.56.x or integration 172.30.70.x profiles)."""
    override = os.environ.get("LEVEL3_IP_TO_ASSET")
    if not override:
        return dict(DEFAULT_DETECTION_IP_TO_ASSET)
    return {**DEFAULT_DETECTION_IP_TO_ASSET, **json.loads(override)}


DETECTION_IP_TO_ASSET = _load_ip_to_asset()


def iter_ground_truth_files(scenario_root: Path) -> Iterable[Path]:
    yield from sorted(scenario_root.glob("*/ground_truth.jsonl"))


def iter_detection_session_files(detection_root: Path) -> Iterable[Path]:
    yield from sorted(detection_root.glob("streamlit_live_session_*.jsonl"))


def load_manifest(path: Path) -> List[Dict]:
    rows: List[Dict] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def load_jsonl_rows(path: Path) -> List[Dict]:
    rows: List[Dict] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def normalize_event(raw: Dict, first_ts: float) -> Dict:
    start_ts = float(raw.get("start_ts_epoch", 0.0) or 0.0)
    end_ts = float(raw.get("end_ts_epoch", start_ts) or start_ts)
    duration = max(0.0, end_ts - start_ts)
    return {
        "scenario_step": raw.get("scenario_step", "unknown"),
        "attack_label": raw.get("attack_label", "unknown"),
        "attack_stage": raw.get("attack_stage", "unknown"),
        "asset_class": raw.get("asset_class", "unknown"),
        "source_asset": raw.get("source_asset", "unknown"),
        "target_asset": raw.get("target_asset", "unknown"),
        "event_kind": raw.get("event_kind", "unknown"),
        "rule_id": raw.get("rule_id", "none"),
        "agent_name": raw.get("agent_name", "none"),
        "ground_truth_label": raw.get("ground_truth_label", "unknown"),
        "dataset_split": raw.get("dataset_split", "unknown"),
        "telemetry_origin": raw.get("telemetry_origin", "unknown"),
        "mitre_technique": raw.get("mitre_technique", "unknown"),
        "scenario_family": raw.get("scenario_family", "unknown"),
        "session_intent": raw.get("session_intent", "unknown"),
        "session_danger_label": raw.get("session_danger_label", ""),
        "session_summary": raw.get("session_summary", ""),
        "exit_code": int(raw.get("exit_code", 1)),
        "success": 1.0 if int(raw.get("exit_code", 1)) == 0 else 0.0,
        "duration_sec": duration,
        "time_delta_sec": max(0.0, start_ts - first_ts),
        "rule_level": float(raw.get("rule_level", 0.0) or 0.0),
        "repeat_count": int(raw.get("repeat_count", 1) or 1),
    }


def infer_detection_assets(raw: Dict) -> Tuple[str, str]:
    source_ip = str(raw.get("data_id_orig_h", "") or "")
    target_ip = str(raw.get("data_id_resp_h", "") or "")
    source_asset = DETECTION_IP_TO_ASSET.get(source_ip, "")
    target_asset = DETECTION_IP_TO_ASSET.get(target_ip, "")
    agent_name = str(raw.get("agent_name", "") or "")
    asset_class = str(raw.get("asset_class", "unknown") or "unknown")

    if agent_name == "EWS-WIN11":
        source_asset = source_asset or "ews"
        target_asset = target_asset or "ews"

    if not source_asset:
        source_asset = str(raw.get("source_asset", "") or "")
    if not target_asset:
        target_asset = str(raw.get("target_asset", "") or "")
    if not target_asset or target_asset == "unknown":
        target_asset = asset_class

    return source_asset or "unknown", target_asset or "unknown"


def normalize_detection_event(raw: Dict, first_ts: float, meta: Dict[str, str]) -> Dict:
    event_ts = float(raw.get("alert_epoch", 0.0) or 0.0)
    rule_id = str(raw.get("rule_id", "none") or "none")
    evidence_key = str(raw.get("evidence_key", raw.get("attack_stage", "unknown")) or "unknown")
    service_hint = (
        str(raw.get("data_event_type", "") or "")
        or str(raw.get("data_service", "") or "")
        or str(raw.get("data_route", "") or "")
        or str(raw.get("data_tag", "") or "")
        or evidence_key
    )
    source_asset, target_asset = infer_detection_assets(raw)
    return {
        "scenario_step": f"det_rule_{rule_id}",
        "attack_label": evidence_key,
        "attack_stage": raw.get("attack_stage", "unknown"),
        "asset_class": raw.get("asset_class", "unknown"),
        "source_asset": source_asset,
        "target_asset": target_asset,
        "event_kind": service_hint,
        "rule_id": rule_id,
        "agent_name": str(raw.get("agent_name", "none") or "none"),
        "ground_truth_label": meta.get("ground_truth_label", "unknown"),
        "dataset_split": meta.get("dataset_split", "ml_live_detection"),
        "telemetry_origin": meta.get("telemetry_origin", "live_detection"),
        "mitre_technique": meta.get("mitre_technique", "unknown"),
        "scenario_family": meta.get("scenario_family", "live_detection"),
        "session_intent": meta.get("session_intent", "unknown"),
        "session_danger_label": meta.get("session_danger_label", ""),
        "session_summary": meta.get("session_summary", ""),
        "exit_code": 0,
        "success": 1.0,
        "duration_sec": 0.0,
        "time_delta_sec": max(0.0, event_ts - first_ts),
        "rule_level": float(raw.get("rule_level", 0.0) or 0.0),
        "repeat_count": int(raw.get("repeat_count", 1) or 1),
    }


def collapse_detection_bursts(events: List[Dict], max_gap_sec: float = 30.0) -> List[Dict]:
    if not events:
        return []

    def signature(event: Dict) -> Tuple[str, ...]:
        return (
            str(event.get("rule_id", "")),
            str(event.get("attack_stage", "")),
            str(event.get("asset_class", "")),
            str(event.get("source_asset", "")),
            str(event.get("target_asset", "")),
            str(event.get("event_kind", "")),
            str(event.get("agent_name", "")),
        )

    collapsed: List[Dict] = []
    current = dict(events[0])
    burst_start = float(current.get("time_delta_sec", 0.0) or 0.0)
    repeat_count = 1

    for event in events[1:]:
        same_signature = signature(event) == signature(current)
        gap = float(event.get("time_delta_sec", 0.0) or 0.0) - float(current.get("time_delta_sec", 0.0) or 0.0)
        if same_signature and gap <= max_gap_sec:
            repeat_count += 1
            current["duration_sec"] = max(0.0, float(event.get("time_delta_sec", 0.0) or 0.0) - burst_start)
            current["rule_level"] = max(float(current.get("rule_level", 0.0) or 0.0), float(event.get("rule_level", 0.0) or 0.0))
            current["repeat_count"] = repeat_count
            continue

        current["repeat_count"] = repeat_count
        collapsed.append(current)
        current = dict(event)
        burst_start = float(current.get("time_delta_sec", 0.0) or 0.0)
        repeat_count = 1

    current["repeat_count"] = repeat_count
    collapsed.append(current)
    return collapsed


def annotated_session_label(events: List[Dict]) -> str:
    explicit = [event["session_danger_label"] for event in events if event.get("session_danger_label")]
    return explicit[-1] if explicit else ""


def annotated_session_intent(events: List[Dict]) -> str:
    intents = [event["session_intent"] for event in events if event.get("session_intent") not in {"", "unknown"}]
    return INTENT_CANONICAL.get(intents[-1], intents[-1]) if intents else ""


def derived_danger_score_from_events(events: List[Dict]) -> float:
    if not events:
        return 0.0

    stages = {event["attack_stage"] for event in events}
    max_stage = max(STAGE_RISK.get(event["attack_stage"], 0.35) for event in events)
    progress_bonus = min(0.12, 0.04 * max(0, len(events) - 1))
    success_bonus = min(0.06, 0.06 * (sum(event["success"] for event in events) / len(events)))
    combo_bonus = 0.0
    if "host_command" in stages or "host_scriptblock" in stages:
        combo_bonus += 0.02
    if "smb_access" in stages and "host_activity" in stages:
        combo_bonus += 0.03
    if "historian_web" in stages and ("host_activity" in stages or "smb_access" in stages):
        combo_bonus += 0.04
    if "opcua_path" in stages and "historian_web" in stages:
        combo_bonus += 0.03
    if "credential_access" in stages and "discovery" in stages:
        combo_bonus += 0.02
    score = min(0.99, max_stage * 0.78 + progress_bonus + success_bonus + combo_bonus)
    if "opcua_write" in stages or "process_anomaly" in stages:
        score = max(score, 0.92)
    elif "opcua_path" in stages and ("historian_web" in stages or "smb_access" in stages):
        score = max(score, 0.74)
    else:
        score = min(score, 0.79)
    return round(score, 4)


def danger_label_from_score(score: float) -> str:
    if score < 0.30:
        return "low"
    if score < 0.55:
        return "medium"
    if score < 0.80:
        return "high"
    return "critical"


def danger_score_from_events(events: List[Dict], is_full_session: bool) -> float:
    return derived_danger_score_from_events(events)


def danger_label_from_events(events: List[Dict], score: float, is_full_session: bool) -> str:
    return danger_label_from_score(score)


def dominant_stage_from_events(events: List[Dict]) -> str:
    return max(events, key=lambda event: STAGE_RISK.get(event["attack_stage"], 0.35))["attack_stage"]


def derived_session_intent_from_events(events: List[Dict]) -> str:
    stage_path = {event["attack_stage"] for event in events}
    if stage_path.issubset(BENIGN_STAGES):
        return "benign_operations"
    if "opcua_write" in stage_path or "process_anomaly" in stage_path:
        return "ot_impact"
    if "opcua_path" in stage_path:
        return "ot_recon"
    if "historian_web" in stage_path or "smb_access" in stage_path:
        return "collection"
    if "host_command" in stage_path or "host_scriptblock" in stage_path:
        return "host_recon"
    if "credential_access" in stage_path:
        return "credential_access"
    if "host_activity" in stage_path:
        return "credential_access"
    if "discovery" in stage_path:
        return "discovery_scan"
    return "host_recon"


def session_intent_from_events(events: List[Dict], is_full_session: bool) -> str:
    return derived_session_intent_from_events(events)


def session_summary_from_events(events: List[Dict]) -> str:
    summaries = [event["session_summary"] for event in events if event.get("session_summary")]
    return summaries[-1] if summaries else ""


def manifest_meta_from_rows(rows: List[Dict], telemetry_origin: str, dataset_split: str) -> Dict[str, str]:
    if not rows:
        return {
            "ground_truth_label": "unknown",
            "dataset_split": dataset_split,
            "telemetry_origin": telemetry_origin,
            "mitre_technique": "unknown",
            "scenario_family": "unknown",
            "session_intent": "unknown",
            "session_danger_label": "",
            "session_summary": "",
        }
    return {
        "ground_truth_label": str(rows[-1].get("ground_truth_label", "unknown")),
        "dataset_split": str(rows[-1].get("dataset_split", dataset_split)),
        "telemetry_origin": telemetry_origin,
        "mitre_technique": str(rows[-1].get("mitre_technique", "unknown")),
        "scenario_family": str(rows[-1].get("scenario_family", rows[0].get("scenario_id", "unknown"))),
        "session_intent": str(rows[-1].get("session_intent", "unknown")),
        "session_danger_label": str(rows[-1].get("session_danger_label", "")),
        "session_summary": str(rows[-1].get("session_summary", "")),
    }


def build_examples_for_manifest(manifest_path: Path, expand_prefixes: bool = True) -> List[Dict]:
    examples: List[Dict] = []
    rows = sorted(load_manifest(manifest_path), key=lambda row: float(row.get("start_ts_epoch", 0.0) or 0.0))
    if not rows:
        return examples

    session_id = rows[0].get("session_id", manifest_path.parent.name)
    base_scenario_id = rows[0].get("scenario_id", manifest_path.parent.name)
    first_ts = float(rows[0].get("start_ts_epoch", 0.0) or 0.0)
    normalized = [normalize_event(row, first_ts) for row in rows]

    prefixes = range(1, len(normalized) + 1) if expand_prefixes else [len(normalized)]
    for prefix_len in prefixes:
        prefix_events = normalized[:prefix_len]
        attack_labels = sorted({event["attack_label"] for event in prefix_events})
        ground_truth_labels = sorted({event["ground_truth_label"] for event in prefix_events})
        dataset_splits = sorted({event["dataset_split"] for event in prefix_events})
        telemetry_origins = sorted({event["telemetry_origin"] for event in prefix_events})
        is_full_session = prefix_len == len(normalized)
        danger_score = danger_score_from_events(prefix_events, is_full_session)
        session_intent = session_intent_from_events(prefix_events, is_full_session)
        examples.append(
            {
                "example_id": f"{session_id}-prefix-{prefix_len}",
                "session_id": session_id,
                "base_session_id": base_scenario_id,
                "source_manifest": str(manifest_path),
                "event_count": prefix_len,
                "total_event_count": len(normalized),
                "is_full_session": is_full_session,
                "stage_path": ">".join(event["attack_stage"] for event in prefix_events),
                "asset_path": ">".join(event["asset_class"] for event in prefix_events),
                "attack_labels_present": attack_labels,
                "ground_truth_labels_present": ground_truth_labels,
                "ground_truth_label": ground_truth_labels[-1] if ground_truth_labels else "unknown",
                "dataset_split": dataset_splits[-1] if dataset_splits else "unknown",
                "telemetry_origin": telemetry_origins[-1] if telemetry_origins else "unknown",
                "annotated_session_intent": annotated_session_intent(prefix_events),
                "annotated_session_danger_label": annotated_session_label(prefix_events),
                "session_intent": session_intent,
                "session_summary": session_summary_from_events(prefix_events),
                "events": prefix_events,
                "danger_score": danger_score,
                "danger_label": danger_label_from_events(prefix_events, danger_score, is_full_session),
                "dominant_stage": dominant_stage_from_events(prefix_events),
            }
        )
    return examples


def build_examples_for_detection_file(
    detection_file: Path,
    expand_prefixes: bool = True,
    manifest_cache: Dict[Path, List[Dict]] | None = None,
) -> List[Dict]:
    rows = [
        row for row in load_jsonl_rows(detection_file)
        if row.get("kind") == "session_detection_event"
    ]
    rows.sort(key=lambda row: float(row.get("alert_epoch", 0.0) or 0.0))
    if not rows:
        return []

    session_id = str(rows[0].get("session_id", detection_file.stem))
    base_session_id = str(rows[0].get("scenario_id", session_id))
    manifest_path = Path(str(rows[0].get("source_manifest", "")))
    manifest_rows: List[Dict] = []
    if manifest_path and manifest_path.exists():
        if manifest_cache is not None and manifest_path in manifest_cache:
            manifest_rows = manifest_cache[manifest_path]
        else:
            manifest_rows = load_manifest(manifest_path)
            if manifest_cache is not None:
                manifest_cache[manifest_path] = manifest_rows

    meta = manifest_meta_from_rows(manifest_rows, telemetry_origin="live_detection", dataset_split="ml_live_detection")
    first_ts = float(rows[0].get("alert_epoch", 0.0) or 0.0)
    normalized = collapse_detection_bursts([normalize_detection_event(row, first_ts, meta) for row in rows])

    examples: List[Dict] = []
    prefixes = range(1, len(normalized) + 1) if expand_prefixes else [len(normalized)]
    for prefix_len in prefixes:
        prefix_events = normalized[:prefix_len]
        attack_labels = sorted({event["attack_label"] for event in prefix_events})
        ground_truth_labels = sorted({event["ground_truth_label"] for event in prefix_events})
        dataset_splits = sorted({event["dataset_split"] for event in prefix_events})
        telemetry_origins = sorted({event["telemetry_origin"] for event in prefix_events})
        is_full_session = prefix_len == len(normalized)
        danger_score = danger_score_from_events(prefix_events, is_full_session)
        session_intent = session_intent_from_events(prefix_events, is_full_session)
        examples.append(
            {
                "example_id": f"{session_id}-detect-prefix-{prefix_len}",
                "session_id": session_id,
                "base_session_id": base_session_id,
                "source_manifest": str(manifest_path) if manifest_path else str(detection_file),
                "source_detection_file": str(detection_file),
                "event_count": prefix_len,
                "total_event_count": len(normalized),
                "is_full_session": is_full_session,
                "stage_path": ">".join(event["attack_stage"] for event in prefix_events),
                "asset_path": ">".join(event["asset_class"] for event in prefix_events),
                "attack_labels_present": attack_labels,
                "ground_truth_labels_present": ground_truth_labels,
                "ground_truth_label": ground_truth_labels[-1] if ground_truth_labels else meta["ground_truth_label"],
                "dataset_split": dataset_splits[-1] if dataset_splits else meta["dataset_split"],
                "telemetry_origin": telemetry_origins[-1] if telemetry_origins else meta["telemetry_origin"],
                "annotated_session_intent": meta.get("session_intent", "unknown"),
                "annotated_session_danger_label": meta.get("session_danger_label", ""),
                "session_intent": session_intent,
                "session_summary": meta.get("session_summary", ""),
                "events": prefix_events,
                "danger_score": danger_score,
                "danger_label": danger_label_from_events(prefix_events, danger_score, is_full_session),
                "dominant_stage": dominant_stage_from_events(prefix_events),
            }
        )
    return examples


def latest_detection_files_by_session(detection_root: Path) -> Dict[str, Path]:
    latest: Dict[str, Tuple[float, Path]] = {}
    for detection_file in iter_detection_session_files(detection_root):
        rows = load_jsonl_rows(detection_file)
        session_rows = [row for row in rows if row.get("kind") == "session_detection_event"]
        if not session_rows:
            continue
        session_id = str(session_rows[0].get("session_id", detection_file.stem))
        score = max(float(row.get("alert_epoch", 0.0) or 0.0) for row in session_rows)
        previous = latest.get(session_id)
        if previous is None or score >= previous[0]:
            latest[session_id] = (score, detection_file)
    return {session_id: item[1] for session_id, item in latest.items()}


def build_examples(
    scenario_root: Path,
    expand_prefixes: bool = True,
    detection_root: Path | None = None,
    prefer_detection_views: bool = True,
) -> List[Dict]:
    examples: List[Dict] = []
    manifest_cache: Dict[Path, List[Dict]] = {}
    detection_sessions: Dict[str, Path] = {}

    if prefer_detection_views and detection_root is not None and detection_root.exists():
        detection_sessions = latest_detection_files_by_session(detection_root)
        for detection_file in detection_sessions.values():
            examples.extend(
                build_examples_for_detection_file(
                    detection_file,
                    expand_prefixes=False,
                    manifest_cache=manifest_cache,
                )
            )

    for manifest_path in iter_ground_truth_files(scenario_root):
        examples.extend(build_examples_for_manifest(manifest_path, expand_prefixes=expand_prefixes))

    return examples


def build_event_vocab(examples: List[Dict], field: str) -> Dict[str, int]:
    values = sorted(
        {
            event.get(field, "unknown")
            for example in examples
            for event in example["events"]
        }
    )
    vocab = {"<pad>": 0, "<unk>": 1}
    for value in values:
        if value not in vocab:
            vocab[value] = len(vocab)
    return vocab


def build_example_vocab(examples: List[Dict], field: str) -> Dict[str, int]:
    values = sorted({example.get(field, "unknown") for example in examples})
    vocab = {"<pad>": 0, "<unk>": 1}
    for value in values:
        if value not in vocab:
            vocab[value] = len(vocab)
    return vocab


def build_all_vocabs(examples: List[Dict]) -> Dict[str, Dict[str, int]]:
    event_fields = [
        "asset_class",
        "source_asset",
        "target_asset",
        "event_kind",
        "rule_id",
        "agent_name",
    ]
    example_fields = [
        "danger_label",
        "dominant_stage",
        "session_intent",
    ]
    vocabs = {field: build_event_vocab(examples, field) for field in event_fields}
    vocabs.update({field: build_example_vocab(examples, field) for field in example_fields})
    return vocabs


def encode_event(event: Dict, vocabs: Dict[str, Dict[str, int]]) -> Dict:
    def lookup(field: str) -> int:
        vocab = vocabs[field]
        return vocab.get(event.get(field, "unknown"), vocab["<unk>"])

    return {
        "asset_class": lookup("asset_class"),
        "source_asset": lookup("source_asset"),
        "target_asset": lookup("target_asset"),
        "event_kind": lookup("event_kind"),
        "rule_id": lookup("rule_id"),
        "agent_name": lookup("agent_name"),
        "numeric": [
            math.log1p(event["duration_sec"]),
            math.log1p(event["time_delta_sec"]),
            float(event["success"]),
            float(event.get("rule_level", 0.0)) / 13.0,
            math.log1p(int(event.get("repeat_count", 1) or 1)),
        ],
    }


def encode_examples(examples: List[Dict], vocabs: Dict[str, Dict[str, int]]) -> List[Dict]:
    encoded: List[Dict] = []
    for example in examples:
        encoded.append(
            {
                **example,
                "encoded_events": [encode_event(event, vocabs) for event in example["events"]],
                "danger_score_target": float(example["danger_score"]),
                "danger_label_target": vocabs["danger_label"][example["danger_label"]],
                "dominant_stage_target": vocabs["dominant_stage"][example["dominant_stage"]],
                "session_intent_target": vocabs["session_intent"][example["session_intent"]],
            }
        )
    return encoded


def grouped_split(examples: List[Dict]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    sessions: Dict[str, Dict] = {}
    for example in examples:
        if not example["is_full_session"]:
            continue
        sessions[example["base_session_id"]] = example

    base_ids = sorted(sessions)
    if len(base_ids) <= 2:
        return examples, examples, []

    rng = random.Random(SEED)

    def split_ids(items: List[str]) -> Tuple[set[str], set[str], set[str]]:
        count = len(items)
        if count == 0:
            return set(), set(), set()
        if count == 1:
            return {items[0]}, set(), set()
        if count == 2:
            return {items[0]}, {items[1]}, set()

        train_cut = max(1, int(round(count * 0.6)))
        val_cut = max(1, int(round(count * 0.2)))
        if train_cut + val_cut >= count:
            val_cut = 1
            train_cut = count - 1 - val_cut
        if train_cut <= 0:
            train_cut = 1
        train = set(items[:train_cut])
        val = set(items[train_cut:train_cut + val_cut])
        test = set(items[train_cut + val_cut:])
        if not test and len(items) >= 3:
            moved = next(iter(val))
            val.remove(moved)
            test.add(moved)
        return train, val, test

    intent_buckets: Dict[str, List[str]] = {}
    for session_id in base_ids:
        intent = sessions[session_id]["session_intent"]
        intent_buckets.setdefault(intent, []).append(session_id)

    train_ids: set[str] = set()
    val_ids: set[str] = set()
    test_ids: set[str] = set()
    for session_ids in intent_buckets.values():
        rng.shuffle(session_ids)
        train_part, val_part, test_part = split_ids(session_ids)
        train_ids |= train_part
        val_ids |= val_part
        test_ids |= test_part

    train = [example for example in examples if example["base_session_id"] in train_ids]
    val = [example for example in examples if example["base_session_id"] in val_ids]
    test = [example for example in examples if example["base_session_id"] in test_ids]
    return train, val, test
