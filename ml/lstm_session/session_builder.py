from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

STAGE_RISK = {
    "discovery": 0.20,
    "host_activity": 0.45,
    "host_command": 0.62,
    "host_scriptblock": 0.68,
    "smb_access": 0.52,
    "historian_web": 0.70,
    "opcua_path": 0.78,
    "opcua_write": 0.95,
    "process_anomaly": 0.90,
}


def iter_ground_truth_files(scenario_root: Path) -> Iterable[Path]:
    yield from sorted(scenario_root.glob("*/ground_truth.jsonl"))


def load_manifest(path: Path) -> List[Dict]:
    rows: List[Dict] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
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
        "exit_code": int(raw.get("exit_code", 1)),
        "success": 1.0 if int(raw.get("exit_code", 1)) == 0 else 0.0,
        "duration_sec": duration,
        "time_delta_sec": max(0.0, start_ts - first_ts),
    }


def danger_score_from_events(events: List[Dict]) -> float:
    if not events:
        return 0.0
    max_stage = max(STAGE_RISK.get(event["attack_stage"], 0.35) for event in events)
    progress_bonus = min(0.18, 0.06 * max(0, len(events) - 1))
    success_bonus = min(0.10, 0.10 * (sum(event["success"] for event in events) / len(events)))
    score = min(0.99, max_stage * 0.82 + progress_bonus + success_bonus)
    return round(score, 4)


def danger_label_from_score(score: float) -> str:
    if score < 0.30:
        return "low"
    if score < 0.55:
        return "medium"
    if score < 0.80:
        return "high"
    return "critical"


def dominant_stage_from_events(events: List[Dict]) -> str:
    return max(events, key=lambda event: STAGE_RISK.get(event["attack_stage"], 0.35))["attack_stage"]


def build_examples(scenario_root: Path, expand_prefixes: bool = True) -> List[Dict]:
    examples: List[Dict] = []

    for manifest_path in iter_ground_truth_files(scenario_root):
        rows = sorted(load_manifest(manifest_path), key=lambda row: float(row.get("start_ts_epoch", 0.0) or 0.0))
        if not rows:
            continue

        session_id = rows[0].get("session_id", manifest_path.parent.name)
        base_scenario_id = rows[0].get("scenario_id", manifest_path.parent.name)
        first_ts = float(rows[0].get("start_ts_epoch", 0.0) or 0.0)
        normalized = [normalize_event(row, first_ts) for row in rows]

        prefixes = range(1, len(normalized) + 1) if expand_prefixes else [len(normalized)]
        for prefix_len in prefixes:
            prefix_events = normalized[:prefix_len]
            danger_score = danger_score_from_events(prefix_events)
            example = {
                "example_id": f"{session_id}-prefix-{prefix_len}",
                "session_id": session_id,
                "base_session_id": base_scenario_id,
                "source_manifest": str(manifest_path),
                "event_count": prefix_len,
                "events": prefix_events,
                "danger_score": danger_score,
                "danger_label": danger_label_from_score(danger_score),
                "dominant_stage": dominant_stage_from_events(prefix_events),
            }
            examples.append(example)

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
        "attack_stage",
        "asset_class",
        "attack_label",
        "source_asset",
        "target_asset",
        "event_kind",
    ]
    example_fields = [
        "danger_label",
        "dominant_stage",
    ]
    vocabs = {field: build_event_vocab(examples, field) for field in event_fields}
    vocabs.update({field: build_example_vocab(examples, field) for field in example_fields})
    return vocabs


def encode_event(event: Dict, vocabs: Dict[str, Dict[str, int]]) -> Dict:
    def lookup(field: str) -> int:
        vocab = vocabs[field]
        return vocab.get(event.get(field, "unknown"), vocab["<unk>"])

    return {
        "attack_stage": lookup("attack_stage"),
        "asset_class": lookup("asset_class"),
        "attack_label": lookup("attack_label"),
        "source_asset": lookup("source_asset"),
        "target_asset": lookup("target_asset"),
        "event_kind": lookup("event_kind"),
        "numeric": [
            math.log1p(event["duration_sec"]),
            math.log1p(event["time_delta_sec"]),
            float(event["success"]),
        ],
    }


def encode_examples(examples: List[Dict], vocabs: Dict[str, Dict[str, int]]) -> List[Dict]:
    encoded: List[Dict] = []
    for example in examples:
        encoded.append(
            {
                **example,
                "encoded_events": [encode_event(event, vocabs) for event in example["events"]],
                "danger_target": float(example["danger_score"]),
                "dominant_stage_target": vocabs["dominant_stage"][example["dominant_stage"]],
            }
        )
    return encoded


def grouped_split(examples: List[Dict]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    base_ids = sorted({example["base_session_id"] for example in examples})
    if len(base_ids) <= 2:
        return examples, examples, []

    if len(base_ids) == 3:
        train_ids = set(base_ids[:2])
        val_ids = {base_ids[2]}
        test_ids = set()
    elif len(base_ids) == 4:
        train_ids = set(base_ids[:2])
        val_ids = {base_ids[2]}
        test_ids = {base_ids[3]}
    else:
        train_ids = set(base_ids[:-2])
        val_ids = {base_ids[-2]}
        test_ids = {base_ids[-1]}

    train = [example for example in examples if example["base_session_id"] in train_ids]
    val = [example for example in examples if example["base_session_id"] in val_ids]
    test = [example for example in examples if example["base_session_id"] in test_ids]
    return train, val, test
