from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean
from collections import Counter
from typing import Dict, List, Sequence, Tuple

import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset

from ml.lstm_session.session_builder import (
    DANGER_LABEL_TO_SCORE,
    build_all_vocabs,
    build_examples,
    encode_examples,
    grouped_split,
)


SEED = 7
torch.manual_seed(SEED)
random.seed(SEED)


class SessionDataset(Dataset):
    def __init__(self, examples: Sequence[Dict]):
        self.examples = list(examples)

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, index: int) -> Dict:
        return self.examples[index]


def collate_batch(batch: Sequence[Dict]) -> Dict[str, torch.Tensor]:
    max_len = max(len(example["encoded_events"]) for example in batch)
    batch_size = len(batch)

    def alloc_long() -> torch.Tensor:
        return torch.zeros((batch_size, max_len), dtype=torch.long)

    scenario_step = alloc_long()
    stage = alloc_long()
    asset = alloc_long()
    source = alloc_long()
    target = alloc_long()
    event_kind = alloc_long()
    numeric = torch.zeros((batch_size, max_len, 3), dtype=torch.float32)
    lengths = torch.zeros(batch_size, dtype=torch.long)
    danger_score = torch.zeros(batch_size, dtype=torch.float32)
    danger_label = torch.zeros(batch_size, dtype=torch.long)
    dominant = torch.zeros(batch_size, dtype=torch.long)
    intent = torch.zeros(batch_size, dtype=torch.long)

    metadata = []
    for i, example in enumerate(batch):
        encoded_events = example["encoded_events"]
        lengths[i] = len(encoded_events)
        danger_score[i] = float(example["danger_score_target"])
        danger_label[i] = int(example["danger_label_target"])
        dominant[i] = int(example["dominant_stage_target"])
        intent[i] = int(example["session_intent_target"])
        metadata.append(
            {
                "example_id": example["example_id"],
                "session_id": example["session_id"],
                "base_session_id": example["base_session_id"],
                "source_manifest": example["source_manifest"],
                "event_count": example["event_count"],
                "total_event_count": example["total_event_count"],
                "is_full_session": example["is_full_session"],
                "stage_path": example["stage_path"],
                "asset_path": example["asset_path"],
                "danger_label": example["danger_label"],
                "danger_score_target": example["danger_score_target"],
                "dominant_stage": example["dominant_stage"],
                "session_intent": example["session_intent"],
                "session_summary": example["session_summary"],
                "ground_truth_label": example["ground_truth_label"],
                "dataset_split": example["dataset_split"],
                "telemetry_origin": example["telemetry_origin"],
                "attack_labels_present": example["attack_labels_present"],
            }
        )
        for j, event in enumerate(encoded_events):
            scenario_step[i, j] = event["scenario_step"]
            stage[i, j] = event["attack_stage"]
            asset[i, j] = event["asset_class"]
            source[i, j] = event["source_asset"]
            target[i, j] = event["target_asset"]
            event_kind[i, j] = event["event_kind"]
            numeric[i, j] = torch.tensor(event["numeric"], dtype=torch.float32)

    return {
        "scenario_step": scenario_step,
        "attack_stage": stage,
        "asset_class": asset,
        "source_asset": source,
        "target_asset": target,
        "event_kind": event_kind,
        "numeric": numeric,
        "lengths": lengths,
        "danger_score": danger_score,
        "danger_label": danger_label,
        "dominant_stage": dominant,
        "session_intent": intent,
        "metadata": metadata,
    }


class SessionLSTM(nn.Module):
    def __init__(self, vocabs: Dict[str, Dict[str, int]], hidden_size: int = 48):
        super().__init__()
        self.scenario_step_emb = nn.Embedding(len(vocabs["scenario_step"]), 10, padding_idx=0)
        self.attack_stage_emb = nn.Embedding(len(vocabs["attack_stage"]), 8, padding_idx=0)
        self.asset_class_emb = nn.Embedding(len(vocabs["asset_class"]), 6, padding_idx=0)
        self.source_asset_emb = nn.Embedding(len(vocabs["source_asset"]), 4, padding_idx=0)
        self.target_asset_emb = nn.Embedding(len(vocabs["target_asset"]), 4, padding_idx=0)
        self.event_kind_emb = nn.Embedding(len(vocabs["event_kind"]), 4, padding_idx=0)

        input_size = 10 + 8 + 6 + 4 + 4 + 4 + 3
        self.lstm = nn.LSTM(input_size=input_size, hidden_size=hidden_size, batch_first=True)
        self.dropout = nn.Dropout(0.15)
        self.danger_head = nn.Linear(hidden_size, len(vocabs["danger_label"]))
        self.stage_head = nn.Linear(hidden_size, len(vocabs["dominant_stage"]))
        self.intent_head = nn.Linear(hidden_size, len(vocabs["session_intent"]))

    def forward(self, batch: Dict[str, torch.Tensor]) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        features = torch.cat(
            [
                self.scenario_step_emb(batch["scenario_step"]),
                self.attack_stage_emb(batch["attack_stage"]),
                self.asset_class_emb(batch["asset_class"]),
                self.source_asset_emb(batch["source_asset"]),
                self.target_asset_emb(batch["target_asset"]),
                self.event_kind_emb(batch["event_kind"]),
                batch["numeric"],
            ],
            dim=-1,
        )

        packed = nn.utils.rnn.pack_padded_sequence(
            features,
            batch["lengths"].cpu(),
            batch_first=True,
            enforce_sorted=False,
        )
        _, (hidden, _) = self.lstm(packed)
        final_hidden = self.dropout(hidden[-1])
        danger_logits = self.danger_head(final_hidden)
        dominant_stage = self.stage_head(final_hidden)
        session_intent = self.intent_head(final_hidden)
        return danger_logits, dominant_stage, session_intent


def danger_label_from_score(score: float) -> str:
    if score < 0.30:
        return "low"
    if score < 0.55:
        return "medium"
    if score < 0.80:
        return "high"
    return "critical"


def compute_class_weight_tensor(values: Sequence[int], vocab_size: int) -> torch.Tensor:
    counts = Counter(values)
    weights = []
    for index in range(vocab_size):
        if index == 0:
            weights.append(0.0)
            continue
        count = counts.get(index, 0)
        weights.append(0.0 if count == 0 else 1.0 / count)
    tensor = torch.tensor(weights, dtype=torch.float32)
    non_zero = tensor[tensor > 0]
    if len(non_zero) > 0:
        tensor[tensor > 0] = tensor[tensor > 0] * (len(non_zero) / float(non_zero.sum()))
    return tensor


def run_epoch(
    model: SessionLSTM,
    loader: DataLoader,
    optimizer: torch.optim.Optimizer | None,
    danger_weights: torch.Tensor,
    stage_weights: torch.Tensor,
    intent_weights: torch.Tensor,
) -> Tuple[float, float, float, float]:
    ce_danger = nn.CrossEntropyLoss(weight=danger_weights)
    ce_stage = nn.CrossEntropyLoss(weight=stage_weights)
    ce_intent = nn.CrossEntropyLoss(weight=intent_weights)
    total_loss = 0.0
    total_danger_correct = 0
    total_stage_correct = 0
    total_intent_correct = 0
    total_items = 0

    training = optimizer is not None
    model.train(training)

    for batch in loader:
        danger_logits, stage_logits, intent_logits = model(batch)
        loss = (
            ce_danger(danger_logits, batch["danger_label"])
            + 0.25 * ce_stage(stage_logits, batch["dominant_stage"])
            + 0.30 * ce_intent(intent_logits, batch["session_intent"])
        )

        if training:
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        total_loss += float(loss.item()) * len(batch["danger_label"])
        total_danger_correct += int((danger_logits.argmax(dim=-1) == batch["danger_label"]).sum().item())
        total_stage_correct += int((stage_logits.argmax(dim=-1) == batch["dominant_stage"]).sum().item())
        total_intent_correct += int((intent_logits.argmax(dim=-1) == batch["session_intent"]).sum().item())
        total_items += len(batch["danger_label"])

    if total_items == 0:
        return 0.0, 0.0, 0.0, 0.0

    return (
        total_loss / total_items,
        total_danger_correct / total_items,
        total_stage_correct / total_items,
        total_intent_correct / total_items,
    )


def predict_examples(
    model: SessionLSTM,
    loader: DataLoader,
    danger_label_reverse: Dict[int, str],
    dominant_stage_reverse: Dict[int, str],
    session_intent_reverse: Dict[int, str],
) -> List[Dict]:
    predictions: List[Dict] = []
    model.eval()
    score_lookup = {label: score for label, score in DANGER_LABEL_TO_SCORE.items()}
    with torch.no_grad():
        for batch in loader:
            danger_logits, stage_logits, intent_logits = model(batch)
            danger_probs = torch.softmax(danger_logits, dim=-1)
            danger_pred = danger_logits.argmax(dim=-1).tolist()
            stage_pred = stage_logits.argmax(dim=-1).tolist()
            intent_pred = intent_logits.argmax(dim=-1).tolist()
            for idx, meta in enumerate(batch["metadata"]):
                label = danger_label_reverse[int(danger_pred[idx])]
                score = 0.0
                for class_index, class_label in danger_label_reverse.items():
                    score += float(danger_probs[idx, class_index].item()) * score_lookup.get(class_label, 0.35)
                predictions.append(
                    {
                        **meta,
                        "predicted_danger_score": round(score, 4),
                        "predicted_danger_label": label,
                        "predicted_dominant_stage": dominant_stage_reverse[int(stage_pred[idx])],
                        "predicted_session_intent": session_intent_reverse[int(intent_pred[idx])],
                    }
                )
    return predictions


def build_split_lookup(
    train_examples: Sequence[Dict],
    val_examples: Sequence[Dict],
    test_examples: Sequence[Dict],
) -> Dict[str, str]:
    lookup: Dict[str, str] = {}
    for split_name, examples in (
        ("train", train_examples),
        ("validation", val_examples),
        ("test", test_examples),
    ):
        for example in examples:
            lookup[example["example_id"]] = split_name
    return lookup


def annotate_predictions(predictions: Sequence[Dict], split_lookup: Dict[str, str]) -> List[Dict]:
    annotated: List[Dict] = []
    for prediction in predictions:
        annotated.append(
            {
                **prediction,
                "split": split_lookup.get(prediction["example_id"], "unknown"),
            }
        )
    return annotated


def summarize_eval_predictions(predictions: Sequence[Dict]) -> Dict[str, float]:
    if not predictions:
        return {
            "eval_examples": 0,
            "eval_danger_label_accuracy": 0.0,
            "eval_stage_accuracy": 0.0,
            "eval_intent_accuracy": 0.0,
            "eval_danger_mae": 0.0,
        }

    danger_label_hits = [
        1.0 if row["predicted_danger_label"] == row["danger_label"] else 0.0
        for row in predictions
    ]
    stage_hits = [
        1.0 if row["predicted_dominant_stage"] == row["dominant_stage"] else 0.0
        for row in predictions
    ]
    intent_hits = [
        1.0 if row["predicted_session_intent"] == row["session_intent"] else 0.0
        for row in predictions
    ]
    danger_errors = [
        abs(float(row["predicted_danger_score"]) - float(row["danger_score_target"]))
        for row in predictions
    ]
    return {
        "eval_examples": len(predictions),
        "eval_danger_label_accuracy": round(mean(danger_label_hits), 4),
        "eval_stage_accuracy": round(mean(stage_hits), 4),
        "eval_intent_accuracy": round(mean(intent_hits), 4),
        "eval_danger_mae": round(mean(danger_errors), 4),
    }


@dataclass
class TrainSummary:
    total_examples: int
    unique_base_sessions: int
    full_session_examples: int
    unique_stage_paths: int
    unique_session_intents: int
    live_full_sessions: int
    curated_full_sessions: int
    benign_full_sessions: int
    attack_full_sessions: int
    train_examples: int
    val_examples: int
    test_examples: int
    epochs: int
    train_loss: float
    val_loss: float
    train_danger_accuracy: float
    val_danger_accuracy: float
    train_stage_accuracy: float
    val_stage_accuracy: float
    train_intent_accuracy: float
    val_intent_accuracy: float
    eval_examples: int
    eval_danger_label_accuracy: float
    eval_stage_accuracy: float
    eval_intent_accuracy: float
    eval_danger_mae: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a small LSTM on correlated honeypot sessions.")
    parser.add_argument("--scenario-root", default="artifacts/scenario-runs")
    parser.add_argument("--output-dir", default="ml/runs/latest")
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--hidden-size", type=int, default=48)
    parser.add_argument("--learning-rate", type=float, default=0.005)
    parser.add_argument("--no-prefix-expansion", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    scenario_root = Path(args.scenario_root)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    examples = build_examples(scenario_root, expand_prefixes=not args.no_prefix_expansion)
    if not examples:
        raise SystemExit(f"No training examples found under {scenario_root}")

    vocabs = build_all_vocabs(examples)
    encoded_examples = encode_examples(examples, vocabs)
    train_examples, val_examples, test_examples = grouped_split(encoded_examples)

    train_loader = DataLoader(SessionDataset(train_examples), batch_size=args.batch_size, shuffle=True, collate_fn=collate_batch)
    val_loader = DataLoader(SessionDataset(val_examples), batch_size=args.batch_size, shuffle=False, collate_fn=collate_batch)
    test_loader = DataLoader(SessionDataset(test_examples), batch_size=args.batch_size, shuffle=False, collate_fn=collate_batch) if test_examples else None

    danger_weights = compute_class_weight_tensor(
        [example["danger_label_target"] for example in train_examples],
        len(vocabs["danger_label"]),
    )
    stage_weights = compute_class_weight_tensor(
        [example["dominant_stage_target"] for example in train_examples],
        len(vocabs["dominant_stage"]),
    )
    intent_weights = compute_class_weight_tensor(
        [example["session_intent_target"] for example in train_examples],
        len(vocabs["session_intent"]),
    )

    model = SessionLSTM(vocabs=vocabs, hidden_size=args.hidden_size)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)

    best_state = None
    best_val_loss = float("inf")
    last_train = (0.0, 0.0, 0.0, 0.0)
    last_val = (0.0, 0.0, 0.0, 0.0)

    for _epoch in range(args.epochs):
        last_train = run_epoch(model, train_loader, optimizer, danger_weights, stage_weights, intent_weights)
        last_val = run_epoch(model, val_loader, None, danger_weights, stage_weights, intent_weights)
        if last_val[0] < best_val_loss:
            best_val_loss = last_val[0]
            best_state = {key: value.cpu() for key, value in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)

    danger_label_reverse = {index: value for value, index in vocabs["danger_label"].items()}
    dominant_stage_reverse = {index: value for value, index in vocabs["dominant_stage"].items()}
    session_intent_reverse = {index: value for value, index in vocabs["session_intent"].items()}
    split_lookup = build_split_lookup(train_examples, val_examples, test_examples)

    evaluation_predictions = predict_examples(model, val_loader, danger_label_reverse, dominant_stage_reverse, session_intent_reverse)
    if test_loader is not None:
        evaluation_predictions.extend(predict_examples(model, test_loader, danger_label_reverse, dominant_stage_reverse, session_intent_reverse))

    all_loader = DataLoader(SessionDataset(encoded_examples), batch_size=args.batch_size, shuffle=False, collate_fn=collate_batch)
    all_predictions = annotate_predictions(
        predict_examples(model, all_loader, danger_label_reverse, dominant_stage_reverse, session_intent_reverse),
        split_lookup,
    )
    eval_predictions = annotate_predictions(evaluation_predictions, split_lookup)
    eval_summary = summarize_eval_predictions(eval_predictions)

    full_sessions = [example for example in encoded_examples if example["is_full_session"]]
    summary = TrainSummary(
        total_examples=len(encoded_examples),
        unique_base_sessions=len({example["base_session_id"] for example in encoded_examples}),
        full_session_examples=len(full_sessions),
        unique_stage_paths=len({example["stage_path"] for example in full_sessions}),
        unique_session_intents=len({example["session_intent"] for example in full_sessions}),
        live_full_sessions=sum(
            1
            for example in full_sessions
            if example["telemetry_origin"] == "live_sensor"
        ),
        curated_full_sessions=sum(
            1
            for example in full_sessions
            if example["telemetry_origin"] != "live_sensor"
        ),
        benign_full_sessions=sum(
            1
            for example in full_sessions
            if example["ground_truth_label"] == "benign"
        ),
        attack_full_sessions=sum(
            1
            for example in full_sessions
            if example["ground_truth_label"] != "benign"
        ),
        train_examples=len(train_examples),
        val_examples=len(val_examples),
        test_examples=len(test_examples),
        epochs=args.epochs,
        train_loss=round(last_train[0], 6),
        val_loss=round(last_val[0], 6),
        train_danger_accuracy=round(last_train[1], 4),
        val_danger_accuracy=round(last_val[1], 4),
        train_stage_accuracy=round(last_train[2], 4),
        val_stage_accuracy=round(last_val[2], 4),
        train_intent_accuracy=round(last_train[3], 4),
        val_intent_accuracy=round(last_val[3], 4),
        eval_examples=eval_summary["eval_examples"],
        eval_danger_label_accuracy=eval_summary["eval_danger_label_accuracy"],
        eval_stage_accuracy=eval_summary["eval_stage_accuracy"],
        eval_intent_accuracy=eval_summary["eval_intent_accuracy"],
        eval_danger_mae=eval_summary["eval_danger_mae"],
    )

    checkpoint = {
        "model_state": model.state_dict(),
        "vocabs": vocabs,
        "config": {
            "hidden_size": args.hidden_size,
            "numeric_features": ["log_duration_sec", "log_time_delta_sec", "success"],
        },
    }
    torch.save(checkpoint, output_dir / "model.pt")

    with (output_dir / "metrics.json").open("w", encoding="utf-8") as fh:
        json.dump(asdict(summary), fh, indent=2)
    with (output_dir / "sessions.jsonl").open("w", encoding="utf-8") as fh:
        for example in encoded_examples:
            serializable = {key: value for key, value in example.items() if key != "encoded_events"}
            fh.write(json.dumps(serializable, ensure_ascii=True) + "\n")
    with (output_dir / "predictions.json").open("w", encoding="utf-8") as fh:
        json.dump(all_predictions, fh, indent=2)
    with (output_dir / "eval_predictions.json").open("w", encoding="utf-8") as fh:
        json.dump(eval_predictions, fh, indent=2)

    print(json.dumps(asdict(summary), indent=2))


if __name__ == "__main__":
    main()
