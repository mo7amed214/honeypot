from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch

from ml.lstm_session.session_builder import build_all_vocabs, encode_examples, load_manifest, normalize_event
from ml.lstm_session.train import SessionDataset, SessionLSTM, collate_batch, danger_label_from_score


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
        "events": normalized,
        "danger_score": 0.0,
        "danger_label": "unknown",
        "dominant_stage": normalized[-1]["attack_stage"],
    }
    encoded = encode_examples([example], vocabs)
    batch = collate_batch(encoded)

    model = SessionLSTM(vocabs=vocabs, hidden_size=int(checkpoint["config"]["hidden_size"]))
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    with torch.no_grad():
        danger_score, stage_logits = model(batch)
    dominant_stage_reverse = {index: value for value, index in vocabs["dominant_stage"].items()}
    stage_id = int(stage_logits.argmax(dim=-1)[0].item())
    score = float(danger_score[0].item())

    print(
        json.dumps(
            {
                "session_id": example["session_id"],
                "predicted_danger_score": round(score, 4),
                "predicted_danger_label": danger_label_from_score(score),
                "predicted_dominant_stage": dominant_stage_reverse[stage_id],
                "event_count": len(normalized),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
