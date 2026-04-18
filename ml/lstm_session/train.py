from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset

from ml.lstm_session.session_builder import (
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

    stage = alloc_long()
    asset = alloc_long()
    label = alloc_long()
    source = alloc_long()
    target = alloc_long()
    event_kind = alloc_long()
    numeric = torch.zeros((batch_size, max_len, 3), dtype=torch.float32)
    lengths = torch.zeros(batch_size, dtype=torch.long)
    danger = torch.zeros(batch_size, dtype=torch.float32)
    dominant = torch.zeros(batch_size, dtype=torch.long)

    metadata = []
    for i, example in enumerate(batch):
        encoded_events = example["encoded_events"]
        lengths[i] = len(encoded_events)
        danger[i] = float(example["danger_target"])
        dominant[i] = int(example["dominant_stage_target"])
        metadata.append(
            {
                "example_id": example["example_id"],
                "session_id": example["session_id"],
                "danger_label": example["danger_label"],
                "dominant_stage": example["dominant_stage"],
            }
        )
        for j, event in enumerate(encoded_events):
            stage[i, j] = event["attack_stage"]
            asset[i, j] = event["asset_class"]
            label[i, j] = event["attack_label"]
            source[i, j] = event["source_asset"]
            target[i, j] = event["target_asset"]
            event_kind[i, j] = event["event_kind"]
            numeric[i, j] = torch.tensor(event["numeric"], dtype=torch.float32)

    return {
        "attack_stage": stage,
        "asset_class": asset,
        "attack_label": label,
        "source_asset": source,
        "target_asset": target,
        "event_kind": event_kind,
        "numeric": numeric,
        "lengths": lengths,
        "danger": danger,
        "dominant_stage": dominant,
        "metadata": metadata,
    }


class SessionLSTM(nn.Module):
    def __init__(self, vocabs: Dict[str, Dict[str, int]], hidden_size: int = 48):
        super().__init__()
        self.attack_stage_emb = nn.Embedding(len(vocabs["attack_stage"]), 8, padding_idx=0)
        self.asset_class_emb = nn.Embedding(len(vocabs["asset_class"]), 6, padding_idx=0)
        self.attack_label_emb = nn.Embedding(len(vocabs["attack_label"]), 6, padding_idx=0)
        self.source_asset_emb = nn.Embedding(len(vocabs["source_asset"]), 4, padding_idx=0)
        self.target_asset_emb = nn.Embedding(len(vocabs["target_asset"]), 4, padding_idx=0)
        self.event_kind_emb = nn.Embedding(len(vocabs["event_kind"]), 4, padding_idx=0)

        input_size = 8 + 6 + 6 + 4 + 4 + 4 + 3
        self.lstm = nn.LSTM(input_size=input_size, hidden_size=hidden_size, batch_first=True)
        self.dropout = nn.Dropout(0.15)
        self.danger_head = nn.Linear(hidden_size, 1)
        self.stage_head = nn.Linear(hidden_size, len(vocabs["dominant_stage"]))

    def forward(self, batch: Dict[str, torch.Tensor]) -> Tuple[torch.Tensor, torch.Tensor]:
        features = torch.cat(
            [
                self.attack_stage_emb(batch["attack_stage"]),
                self.asset_class_emb(batch["asset_class"]),
                self.attack_label_emb(batch["attack_label"]),
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
        danger_score = torch.sigmoid(self.danger_head(final_hidden)).squeeze(-1)
        dominant_stage = self.stage_head(final_hidden)
        return danger_score, dominant_stage


def danger_label_from_score(score: float) -> str:
    if score < 0.30:
        return "low"
    if score < 0.55:
        return "medium"
    if score < 0.80:
        return "high"
    return "critical"


def run_epoch(
    model: SessionLSTM,
    loader: DataLoader,
    optimizer: torch.optim.Optimizer | None,
) -> Tuple[float, float]:
    mse = nn.MSELoss()
    ce = nn.CrossEntropyLoss()
    total_loss = 0.0
    total_stage_correct = 0
    total_items = 0

    training = optimizer is not None
    model.train(training)

    for batch in loader:
        danger_pred, stage_logits = model(batch)
        loss = mse(danger_pred, batch["danger"]) + 0.35 * ce(stage_logits, batch["dominant_stage"])

        if training:
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        total_loss += float(loss.item()) * len(batch["danger"])
        total_stage_correct += int((stage_logits.argmax(dim=-1) == batch["dominant_stage"]).sum().item())
        total_items += len(batch["danger"])

    if total_items == 0:
        return 0.0, 0.0

    return total_loss / total_items, total_stage_correct / total_items


def predict_examples(model: SessionLSTM, loader: DataLoader, dominant_stage_reverse: Dict[int, str]) -> List[Dict]:
    predictions: List[Dict] = []
    model.eval()
    with torch.no_grad():
        for batch in loader:
            danger_pred, stage_logits = model(batch)
            stage_pred = stage_logits.argmax(dim=-1).tolist()
            for idx, meta in enumerate(batch["metadata"]):
                score = float(danger_pred[idx].item())
                predictions.append(
                    {
                        **meta,
                        "predicted_danger_score": round(score, 4),
                        "predicted_danger_label": danger_label_from_score(score),
                        "predicted_dominant_stage": dominant_stage_reverse[int(stage_pred[idx])],
                    }
                )
    return predictions


@dataclass
class TrainSummary:
    train_examples: int
    val_examples: int
    test_examples: int
    epochs: int
    train_loss: float
    val_loss: float
    train_stage_accuracy: float
    val_stage_accuracy: float


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

    model = SessionLSTM(vocabs=vocabs, hidden_size=args.hidden_size)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)

    best_state = None
    best_val_loss = float("inf")
    last_train = (0.0, 0.0)
    last_val = (0.0, 0.0)

    for _epoch in range(args.epochs):
        last_train = run_epoch(model, train_loader, optimizer)
        last_val = run_epoch(model, val_loader, None)
        if last_val[0] < best_val_loss:
            best_val_loss = last_val[0]
            best_state = {key: value.cpu() for key, value in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)

    dominant_stage_reverse = {index: value for value, index in vocabs["dominant_stage"].items()}
    predictions = predict_examples(model, val_loader, dominant_stage_reverse)
    if test_loader is not None:
        predictions.extend(predict_examples(model, test_loader, dominant_stage_reverse))

    summary = TrainSummary(
        train_examples=len(train_examples),
        val_examples=len(val_examples),
        test_examples=len(test_examples),
        epochs=args.epochs,
        train_loss=round(last_train[0], 6),
        val_loss=round(last_val[0], 6),
        train_stage_accuracy=round(last_train[1], 4),
        val_stage_accuracy=round(last_val[1], 4),
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
        json.dump(predictions, fh, indent=2)

    print(json.dumps(asdict(summary), indent=2))


if __name__ == "__main__":
    main()
