from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from ml.lstm_session.session_builder import build_all_vocabs, encode_examples, load_manifest, normalize_event
from ml.lstm_session.train import SessionLSTM, collate_batch


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run session danger inference with the trained LSTM.")
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--session-file", required=True, help="Path to one ground_truth.jsonl file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    checkpoint = torch.load(args.model_path, map_location="cpu")
    vocabs = checkpoint["vocabs"]

    manifest_rows = load_manifest(Path(args.session_file))
    if not manifest_rows:
        raise SystemExit(f"No rows found in {args.session_file}")

    first_ts = float(manifest_rows[0].get("start_ts_epoch", 0.0) or 0.0)
    normalized = [normalize_event(row, first_ts) for row in sorted(manifest_rows, key=lambda row: float(row.get("start_ts_epoch", 0.0) or 0.0))]
    example = {
        "example_id": Path(args.session_file).stem,
        "session_id": manifest_rows[0].get("session_id", Path(args.session_file).stem),
        "base_session_id": manifest_rows[0].get("scenario_id", Path(args.session_file).stem),
        "source_manifest": str(Path(args.session_file)),
        "event_count": len(normalized),
        "total_event_count": len(normalized),
        "is_full_session": True,
        "stage_path": ">".join(event["attack_stage"] for event in normalized),
        "asset_path": ">".join(event["asset_class"] for event in normalized),
        "ground_truth_label": manifest_rows[0].get("ground_truth_label", "unknown"),
        "dataset_split": manifest_rows[0].get("dataset_split", "unknown"),
        "telemetry_origin": manifest_rows[0].get("telemetry_origin", "unknown"),
        "attack_labels_present": sorted({row.get("attack_label", "unknown") for row in manifest_rows}),
        "session_intent": manifest_rows[0].get("session_intent", "unknown"),
        "session_summary": manifest_rows[0].get("session_summary", ""),
        "events": normalized,
        "danger_score": 0.20,
        "danger_label": "low",
        "dominant_stage": normalized[-1]["attack_stage"],
        "session_intent": manifest_rows[0].get("session_intent", "host_recon"),
        "session_summary": manifest_rows[0].get("session_summary", ""),
    }
    encoded = encode_examples([example], vocabs)
    batch = collate_batch(encoded)

    model = SessionLSTM(vocabs=vocabs, hidden_size=int(checkpoint["config"]["hidden_size"]))
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    with torch.no_grad():
        danger_logits, stage_logits, intent_logits = model(batch)
    danger_label_reverse = {index: value for value, index in vocabs["danger_label"].items()}
    dominant_stage_reverse = {index: value for value, index in vocabs["dominant_stage"].items()}
    session_intent_reverse = {index: value for value, index in vocabs["session_intent"].items()}
    score_lookup = {"low": 0.20, "medium": 0.50, "high": 0.78, "critical": 0.95}
    danger_probs = torch.softmax(danger_logits, dim=-1)[0]
    danger_id = int(danger_logits.argmax(dim=-1)[0].item())
    stage_id = int(stage_logits.argmax(dim=-1)[0].item())
    intent_id = int(intent_logits.argmax(dim=-1)[0].item())
    score = 0.0
    for class_index, class_label in danger_label_reverse.items():
        score += float(danger_probs[class_index].item()) * score_lookup.get(class_label, 0.35)

    print(
        json.dumps(
            {
                "session_id": example["session_id"],
                "predicted_danger_score": round(score, 4),
                "predicted_danger_label": danger_label_reverse[danger_id],
                "predicted_dominant_stage": dominant_stage_reverse[stage_id],
                "predicted_session_intent": session_intent_reverse[intent_id],
                "event_count": len(normalized),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
