from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from ml.lstm_session.session_builder import (
    build_examples_for_detection_file,
    build_examples_for_manifest,
    encode_examples,
    load_jsonl_rows,
)
from ml.lstm_session.train import SessionLSTM, collate_batch


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run session danger inference with the trained LSTM.")
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--session-file", required=True, help="Path to a ground_truth.jsonl or streamlit_live_session_*.jsonl file")
    return parser.parse_args()


def load_one_example(session_file: Path) -> tuple[dict, str]:
    rows = load_jsonl_rows(session_file)
    detection_rows = [row for row in rows if row.get("kind") == "session_detection_event"]
    if detection_rows:
        examples = build_examples_for_detection_file(session_file, expand_prefixes=False)
        if not examples:
            raise SystemExit(f"No detection-backed examples built from {session_file}")
        return examples[-1], "detection"

    examples = build_examples_for_manifest(session_file, expand_prefixes=False)
    if not examples:
        raise SystemExit(f"No manifest-backed examples built from {session_file}")
    return examples[-1], "manifest"


def main() -> None:
    args = parse_args()
    checkpoint = torch.load(args.model_path, map_location="cpu")
    vocabs = checkpoint["vocabs"]

    session_file = Path(args.session_file)
    example, input_mode = load_one_example(session_file)
    encoded = encode_examples([example], vocabs)
    batch = collate_batch(encoded)

    model = SessionLSTM(
        vocabs=vocabs,
        hidden_size=int(checkpoint["config"]["hidden_size"]),
        num_layers=int(checkpoint["config"].get("num_layers", 2)),
        bidirectional=bool(checkpoint["config"].get("bidirectional", False)),
    )
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
                "input_mode": input_mode,
                "session_id": example["session_id"],
                "predicted_danger_score": round(score, 4),
                "predicted_danger_label": danger_label_reverse[danger_id],
                "predicted_dominant_stage": dominant_stage_reverse[stage_id],
                "predicted_session_intent": session_intent_reverse[intent_id],
                "event_count": int(example["event_count"]),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
