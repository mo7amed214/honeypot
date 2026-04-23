from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import torch
from torch.utils.data import DataLoader

from ml.lstm_session.publish_results import hybrid_danger, hybrid_session_intent, priority_from_label, summarize_session
from ml.lstm_session.session_detection import build_session_detection_rows, load_manifest_rows
from ml.lstm_session.session_builder import build_examples_for_manifest, encode_examples
from ml.lstm_session.train import SessionDataset, SessionLSTM, collate_batch, predict_examples


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish one live Streamlit session into ML JSONL streams.")
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--session-file", required=True)
    parser.add_argument("--output-dir", default="monitoring/ml")
    parser.add_argument("--model-name", default="session_lstm")
    return parser.parse_args()


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True) + "\n")


def main() -> None:
    args = parse_args()
    model_path = Path(args.model_path)
    session_file = Path(args.session_file)
    output_dir = Path(args.output_dir)

    checkpoint = torch.load(model_path, map_location="cpu")
    vocabs = checkpoint["vocabs"]
    hidden_size = int(checkpoint["config"]["hidden_size"])

    examples = build_examples_for_manifest(session_file, expand_prefixes=True)
    if not examples:
        raise SystemExit(f"No examples built from {session_file}")

    encoded = encode_examples(examples, vocabs)
    loader = DataLoader(SessionDataset(encoded), batch_size=len(encoded), shuffle=False, collate_fn=collate_batch)
    model = SessionLSTM(vocabs=vocabs, hidden_size=hidden_size)
    model.load_state_dict(checkpoint["model_state"])

    danger_label_reverse = {index: value for value, index in vocabs["danger_label"].items()}
    dominant_stage_reverse = {index: value for value, index in vocabs["dominant_stage"].items()}
    session_intent_reverse = {index: value for value, index in vocabs["session_intent"].items()}
    predictions = predict_examples(model, loader, danger_label_reverse, dominant_stage_reverse, session_intent_reverse)
    predictions.sort(key=lambda row: int(row.get("event_count", 0)))

    now = datetime.now(UTC).isoformat()
    run_stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    manifest_rows = load_manifest_rows(session_file)
    latest_event_epoch = max((float(row.get("end_ts_epoch", row.get("start_ts_epoch", 0.0))) for row in manifest_rows), default=datetime.now(UTC).timestamp())
    session_ts = datetime.fromtimestamp(latest_event_epoch, UTC).isoformat()
    session_id = predictions[-1]["session_id"]

    rows: list[dict] = []
    for row in predictions:
        hybrid_intent = hybrid_session_intent(row)
        hybrid_score, hybrid_label = hybrid_danger(row)
        rows.append(
            {
                **row,
                "ts": session_ts,
                "source": "ml",
                "kind": "session_prediction" if row.get("is_full_session") else "session_progression",
                "model_name": args.model_name,
                "predicted_danger_score_model": row.get("predicted_danger_score"),
                "predicted_danger_label_model": row.get("predicted_danger_label"),
                "predicted_priority_model": priority_from_label(row.get("predicted_danger_label", "low")),
                "predicted_danger_score": hybrid_score,
                "predicted_danger_label": hybrid_label,
                "predicted_priority": priority_from_label(hybrid_label),
                "predicted_session_intent_hybrid": hybrid_intent,
                "summary_text": summarize_session({**row, "predicted_session_intent_hybrid": hybrid_intent, "predicted_danger_label": hybrid_label}),
            }
        )

    latest = predictions[-1]
    hybrid_intent = hybrid_session_intent(latest)
    hybrid_score, hybrid_label = hybrid_danger(latest)
    summary_row = {
        **latest,
        "ts": session_ts,
        "source": "ml",
        "kind": "correlated_session_summary",
        "model_name": args.model_name,
        "session_rank": 0,
        "predicted_danger_score_model": latest.get("predicted_danger_score"),
        "predicted_danger_label_model": latest.get("predicted_danger_label"),
        "predicted_priority_model": priority_from_label(latest.get("predicted_danger_label", "low")),
        "predicted_danger_score": hybrid_score,
        "predicted_danger_label": hybrid_label,
        "predicted_priority": priority_from_label(hybrid_label),
        "predicted_session_intent_hybrid": hybrid_intent,
        "summary_text": summarize_session({**latest, "predicted_session_intent_hybrid": hybrid_intent, "predicted_danger_label": hybrid_label}),
    }
    rows.append(summary_row)
    rows.extend(build_session_detection_rows(session_file))

    out_path = output_dir / f"streamlit_live_session_{session_id}_{run_stamp}.jsonl"
    write_jsonl(out_path, rows)
    print(json.dumps({"published": True, "session_id": session_id, "output_file": str(out_path)}, indent=2))


if __name__ == "__main__":
    main()
