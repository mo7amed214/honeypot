from __future__ import annotations

import argparse
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean, stdev
from collections import Counter
from typing import Dict, List, Optional, Sequence, Tuple

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

# Maximum rule level in the system (used by RuleBasedBaseline normalization)
MAX_RULE_LEVEL = 13.0

# Threshold table for rule-level → danger label (rule-based baseline)
_RULE_LEVEL_DANGER = [(11.0, "critical"), (9.0, "high"), (7.0, "medium"), (0.0, "low")]
_RULE_LEVEL_STAGE  = [
    (13.0, "opcua_write"),
    (11.0, "process_anomaly"),
    (10.0, "opcua_write"),
    (9.0,  "discovery"),
    (8.0,  "smb_access"),
    (7.0,  "host_command"),
    (0.0,  "benign_access"),
]
_DANGER_INTENT = {
    "critical": "ot_impact",
    "high":     "collection",
    "medium":   "discovery_scan",
    "low":      "benign_operations",
}


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

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

    asset      = alloc_long()
    source     = alloc_long()
    target     = alloc_long()
    event_kind = alloc_long()
    rule_id    = alloc_long()
    agent_name = alloc_long()
    numeric    = torch.zeros((batch_size, max_len, 5), dtype=torch.float32)
    lengths    = torch.zeros(batch_size, dtype=torch.long)
    danger_score  = torch.zeros(batch_size, dtype=torch.float32)
    danger_label  = torch.zeros(batch_size, dtype=torch.long)
    dominant      = torch.zeros(batch_size, dtype=torch.long)
    intent        = torch.zeros(batch_size, dtype=torch.long)

    metadata = []
    for i, example in enumerate(batch):
        encoded_events = example["encoded_events"]
        lengths[i]     = len(encoded_events)
        danger_score[i] = float(example["danger_score_target"])
        danger_label[i] = int(example["danger_label_target"])
        dominant[i]    = int(example["dominant_stage_target"])
        intent[i]      = int(example["session_intent_target"])
        metadata.append(
            {
                "example_id":          example["example_id"],
                "session_id":          example["session_id"],
                "base_session_id":     example["base_session_id"],
                "source_manifest":     example["source_manifest"],
                "event_count":         example["event_count"],
                "total_event_count":   example["total_event_count"],
                "is_full_session":     example["is_full_session"],
                "stage_path":          example["stage_path"],
                "asset_path":          example["asset_path"],
                "danger_label":        example["danger_label"],
                "danger_score_target": example["danger_score_target"],
                "dominant_stage":      example["dominant_stage"],
                "session_intent":      example["session_intent"],
                "session_summary":     example["session_summary"],
                "ground_truth_label":  example["ground_truth_label"],
                "dataset_split":       example["dataset_split"],
                "telemetry_origin":    example["telemetry_origin"],
                "attack_labels_present": example["attack_labels_present"],
            }
        )
        for j, event in enumerate(encoded_events):
            asset[i, j]      = event["asset_class"]
            source[i, j]     = event["source_asset"]
            target[i, j]     = event["target_asset"]
            event_kind[i, j] = event["event_kind"]
            rule_id[i, j]    = event["rule_id"]
            agent_name[i, j] = event["agent_name"]
            numeric[i, j]    = torch.tensor(event["numeric"], dtype=torch.float32)

    return {
        "asset_class":    asset,
        "source_asset":   source,
        "target_asset":   target,
        "event_kind":     event_kind,
        "rule_id":        rule_id,
        "agent_name":     agent_name,
        "numeric":        numeric,
        "lengths":        lengths,
        "danger_score":   danger_score,
        "danger_label":   danger_label,
        "dominant_stage": dominant,
        "session_intent": intent,
        "metadata":       metadata,
    }


# ---------------------------------------------------------------------------
# Model: self-attention over LSTM hidden states
# ---------------------------------------------------------------------------

class SelfAttention(nn.Module):
    """Scalar attention over LSTM output sequence → weighted context vector."""

    def __init__(self, hidden_size: int) -> None:
        super().__init__()
        self.query = nn.Linear(hidden_size, 1, bias=False)

    def forward(self, outputs: torch.Tensor, padding_mask: torch.Tensor) -> torch.Tensor:
        # outputs:      (B, T, H)
        # padding_mask: (B, T) — True for padded (invalid) positions
        scores  = self.query(outputs)                                    # (B, T, 1)
        scores  = scores.masked_fill(padding_mask.unsqueeze(-1), -1e9)
        weights = torch.softmax(scores, dim=1)                           # (B, T, 1)
        return (weights * outputs).sum(dim=1)                            # (B, H)


class SessionAttentionLSTM(nn.Module):
    """
    Bidirectional 2-layer LSTM with additive self-attention pooling.
    Three classification heads: danger (4), dominant stage (N), session intent (M).
    """

    def __init__(
        self,
        vocabs: Dict[str, Dict[str, int]],
        hidden_size: int = 64,
        num_layers: int = 2,
        bidirectional: bool = True,
    ) -> None:
        super().__init__()
        self.asset_class_emb  = nn.Embedding(len(vocabs["asset_class"]),  6, padding_idx=0)
        self.source_asset_emb = nn.Embedding(len(vocabs["source_asset"]), 4, padding_idx=0)
        self.target_asset_emb = nn.Embedding(len(vocabs["target_asset"]), 4, padding_idx=0)
        self.event_kind_emb   = nn.Embedding(len(vocabs["event_kind"]),   4, padding_idx=0)
        self.rule_id_emb      = nn.Embedding(len(vocabs["rule_id"]),      8, padding_idx=0)
        self.agent_name_emb   = nn.Embedding(len(vocabs["agent_name"]),   4, padding_idx=0)

        # 6+4+4+4+8+4 = 30 categorical dims + 5 numeric = 35 input dims
        input_size   = 6 + 4 + 4 + 4 + 8 + 4 + 5
        context_size = hidden_size * 2 if bidirectional else hidden_size

        lstm_dropout = 0.15 if num_layers > 1 else 0.0
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=lstm_dropout,
            bidirectional=bidirectional,
        )
        self.attention   = SelfAttention(context_size)
        self.dropout     = nn.Dropout(0.25)
        self.danger_head = nn.Linear(context_size, len(vocabs["danger_label"]))
        self.stage_head  = nn.Linear(context_size, len(vocabs["dominant_stage"]))
        self.intent_head = nn.Linear(context_size, len(vocabs["session_intent"]))

    def forward(
        self, batch: Dict[str, torch.Tensor]
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        features = torch.cat(
            [
                self.asset_class_emb(batch["asset_class"]),
                self.source_asset_emb(batch["source_asset"]),
                self.target_asset_emb(batch["target_asset"]),
                self.event_kind_emb(batch["event_kind"]),
                self.rule_id_emb(batch["rule_id"]),
                self.agent_name_emb(batch["agent_name"]),
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
        outputs_packed, _ = self.lstm(packed)
        outputs, _ = nn.utils.rnn.pad_packed_sequence(outputs_packed, batch_first=True)

        # Padding mask: True where position >= actual sequence length
        seq_len = outputs.shape[1]
        padding_mask = (
            torch.arange(seq_len, device=outputs.device).unsqueeze(0)
            >= batch["lengths"].to(outputs.device).unsqueeze(1)
        )

        context       = self.attention(outputs, padding_mask)
        context       = self.dropout(context)
        danger_logits = self.danger_head(context)
        stage_logits  = self.stage_head(context)
        intent_logits = self.intent_head(context)
        return danger_logits, stage_logits, intent_logits


# Keep original name as alias so old checkpoint-loading code still resolves
SessionLSTM = SessionAttentionLSTM


# ---------------------------------------------------------------------------
# Baselines (observable-evidence-only, same constraint as LSTM)
# ---------------------------------------------------------------------------

class MajorityClassBaseline:
    """Predicts the training-set majority class for every example."""

    def __init__(self) -> None:
        self.danger_pred = "low"
        self.stage_pred  = "benign_access"
        self.intent_pred = "benign_operations"

    def fit(self, examples: Sequence[Dict]) -> None:
        if not examples:
            return
        self.danger_pred = Counter(e["danger_label"] for e in examples).most_common(1)[0][0]
        self.stage_pred  = Counter(e["dominant_stage"] for e in examples).most_common(1)[0][0]
        self.intent_pred = Counter(e["session_intent"] for e in examples).most_common(1)[0][0]

    def evaluate(self, examples: Sequence[Dict]) -> Dict[str, float]:
        n = len(examples)
        if not n:
            return {"danger": 0.0, "stage": 0.0, "intent": 0.0}
        return {
            "danger": sum(e["danger_label"] == self.danger_pred for e in examples) / n,
            "stage":  sum(e["dominant_stage"] == self.stage_pred for e in examples) / n,
            "intent": sum(e["session_intent"] == self.intent_pred for e in examples) / n,
        }


class RuleBasedBaseline:
    """
    Single-feature heuristic: classify by maximum Wazuh rule level in the session.
    Uses only observable numeric[3] = rule_level / 13 and matches the LSTM input constraint.
    """

    def evaluate(self, examples: Sequence[Dict]) -> Dict[str, float]:
        n = len(examples)
        if not n:
            return {"danger": 0.0, "stage": 0.0, "intent": 0.0}
        danger_hits = stage_hits = intent_hits = 0
        for ex in examples:
            events    = ex.get("encoded_events", [])
            max_level = max(
                (float(ev["numeric"][3]) * MAX_RULE_LEVEL for ev in events), default=0.0
            )

            danger_pred = "low"
            for threshold, label in _RULE_LEVEL_DANGER:
                if max_level >= threshold:
                    danger_pred = label
                    break

            stage_pred = "benign_access"
            for threshold, label in _RULE_LEVEL_STAGE:
                if max_level >= threshold:
                    stage_pred = label
                    break

            intent_pred = _DANGER_INTENT[danger_pred]

            if ex["danger_label"]   == danger_pred: danger_hits += 1
            if ex["dominant_stage"] == stage_pred:  stage_hits  += 1
            if ex["session_intent"] == intent_pred: intent_hits += 1

        return {
            "danger": danger_hits / n,
            "stage":  stage_hits  / n,
            "intent": intent_hits / n,
        }


# ---------------------------------------------------------------------------
# Training helpers
# ---------------------------------------------------------------------------

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
    model: SessionAttentionLSTM,
    loader: DataLoader,
    optimizer: Optional[torch.optim.Optimizer],
    danger_weights: torch.Tensor,
    stage_weights: torch.Tensor,
    intent_weights: torch.Tensor,
    stage_loss_weight: float,
    intent_loss_weight: float,
    grad_clip: float = 1.0,
    label_smoothing: float = 0.0,
) -> Tuple[float, float, float, float]:
    training  = optimizer is not None
    smoothing = label_smoothing if training else 0.0
    ce_danger = nn.CrossEntropyLoss(weight=danger_weights, label_smoothing=smoothing)
    ce_stage  = nn.CrossEntropyLoss(weight=stage_weights,  label_smoothing=smoothing)
    ce_intent = nn.CrossEntropyLoss(weight=intent_weights, label_smoothing=smoothing)

    total_loss = total_danger_correct = total_stage_correct = total_intent_correct = 0
    total_items = 0

    model.train(training)

    for batch in loader:
        danger_logits, stage_logits, intent_logits = model(batch)
        loss = (
            ce_danger(danger_logits, batch["danger_label"])
            + stage_loss_weight  * ce_stage(stage_logits,  batch["dominant_stage"])
            + intent_loss_weight * ce_intent(intent_logits, batch["session_intent"])
        )

        if training:
            optimizer.zero_grad()
            loss.backward()
            if grad_clip > 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), grad_clip)
            optimizer.step()

        total_loss          += float(loss.item()) * len(batch["danger_label"])
        total_danger_correct += int((danger_logits.argmax(dim=-1) == batch["danger_label"]).sum())
        total_stage_correct  += int((stage_logits.argmax(dim=-1) == batch["dominant_stage"]).sum())
        total_intent_correct += int((intent_logits.argmax(dim=-1) == batch["session_intent"]).sum())
        total_items          += len(batch["danger_label"])

    if total_items == 0:
        return 0.0, 0.0, 0.0, 0.0

    return (
        total_loss          / total_items,
        total_danger_correct / total_items,
        total_stage_correct  / total_items,
        total_intent_correct / total_items,
    )


# ---------------------------------------------------------------------------
# Stratified group k-fold
# ---------------------------------------------------------------------------

def stratified_group_kfold(
    examples: List[Dict],
    k: int = 5,
    seed: int = SEED,
) -> List[Tuple[List[Dict], List[Dict]]]:
    """
    Groups examples by base_session_id so prefix-expanded examples stay together.
    Stratifies group assignment by session_intent of the full session.
    Returns list of (train_examples, val_examples) per fold.
    """
    # Determine each group's canonical intent (prefer full-session entry)
    group_intent: Dict[str, str] = {}
    for ex in examples:
        gid = ex["base_session_id"]
        if ex.get("is_full_session") or gid not in group_intent:
            group_intent[gid] = ex["session_intent"]

    # Bucket groups by intent, shuffle within each bucket
    buckets: Dict[str, List[str]] = {}
    for gid, intent in group_intent.items():
        buckets.setdefault(intent, []).append(gid)
    rng = random.Random(seed)
    for lst in buckets.values():
        rng.shuffle(lst)

    # Interleave across intent buckets (round-robin) → assign fold by position
    ordered: List[str] = []
    lists = list(buckets.values())
    while any(lists):
        for lst in lists:
            if lst:
                ordered.append(lst.pop(0))
    group_to_fold = {gid: i % k for i, gid in enumerate(ordered)}

    splits: List[Tuple[List[Dict], List[Dict]]] = []
    for fold in range(k):
        train_ex = [ex for ex in examples if group_to_fold.get(ex["base_session_id"], 0) != fold]
        val_ex   = [ex for ex in examples if group_to_fold.get(ex["base_session_id"], 0) == fold]
        splits.append((train_ex, val_ex))
    return splits


def run_kfold(
    encoded_examples: List[Dict],
    vocabs: Dict,
    args: argparse.Namespace,
    k: int = 5,
) -> Dict[str, float]:
    """Train k independent models (one per fold) and return mean ± std accuracies."""
    folds = stratified_group_kfold(encoded_examples, k=k)
    fold_danger: List[float] = []
    fold_stage:  List[float] = []
    fold_intent: List[float] = []

    kfold_epochs = min(args.epochs, 50)

    for fold_idx, (train_ex, val_ex) in enumerate(folds):
        if not train_ex or not val_ex:
            continue

        d_w = compute_class_weight_tensor(
            [ex["danger_label_target"] for ex in train_ex], len(vocabs["danger_label"])
        )
        s_w = compute_class_weight_tensor(
            [ex["dominant_stage_target"] for ex in train_ex], len(vocabs["dominant_stage"])
        )
        i_w = compute_class_weight_tensor(
            [ex["session_intent_target"] for ex in train_ex], len(vocabs["session_intent"])
        )

        fold_model = SessionAttentionLSTM(
            vocabs=vocabs,
            hidden_size=args.hidden_size,
            num_layers=args.num_layers,
            bidirectional=args.bidirectional,
        )
        fold_opt  = torch.optim.Adam(fold_model.parameters(), lr=args.learning_rate)
        fold_sched = torch.optim.lr_scheduler.ReduceLROnPlateau(
            fold_opt, mode="min", patience=6, factor=0.5, min_lr=1e-5
        )

        tr_loader  = DataLoader(SessionDataset(train_ex), batch_size=args.batch_size, shuffle=True,  collate_fn=collate_batch)
        val_loader = DataLoader(SessionDataset(val_ex),   batch_size=args.batch_size, shuffle=False, collate_fn=collate_batch)

        best_val  = float("inf")
        best_acc  = (0.0, 0.0, 0.0)
        no_improve = 0

        for _ in range(kfold_epochs):
            run_epoch(fold_model, tr_loader, fold_opt, d_w, s_w, i_w,
                      args.stage_loss_weight, args.intent_loss_weight,
                      label_smoothing=args.label_smoothing)
            v_loss, v_d, v_s, v_i = run_epoch(
                fold_model, val_loader, None, d_w, s_w, i_w,
                args.stage_loss_weight, args.intent_loss_weight,
            )
            fold_sched.step(v_loss)
            if v_loss < best_val:
                best_val   = v_loss
                best_acc   = (v_d, v_s, v_i)
                no_improve = 0
            else:
                no_improve += 1
                if no_improve >= args.patience:
                    break

        fold_danger.append(best_acc[0])
        fold_stage.append(best_acc[1])
        fold_intent.append(best_acc[2])
        print(
            f"  [k-fold] fold {fold_idx + 1}/{k}: "
            f"danger={best_acc[0]:.4f} stage={best_acc[1]:.4f} intent={best_acc[2]:.4f}"
        )

    def _safe_std(vals: List[float]) -> float:
        return round(stdev(vals), 4) if len(vals) > 1 else 0.0

    return {
        "kfold_folds":              k,
        "kfold_mean_danger_accuracy": round(mean(fold_danger), 4) if fold_danger else 0.0,
        "kfold_std_danger_accuracy":  _safe_std(fold_danger),
        "kfold_mean_stage_accuracy":  round(mean(fold_stage), 4)  if fold_stage  else 0.0,
        "kfold_std_stage_accuracy":   _safe_std(fold_stage),
        "kfold_mean_intent_accuracy": round(mean(fold_intent), 4) if fold_intent else 0.0,
        "kfold_std_intent_accuracy":  _safe_std(fold_intent),
    }


# ---------------------------------------------------------------------------
# Inference / evaluation helpers
# ---------------------------------------------------------------------------

def predict_examples(
    model: SessionAttentionLSTM,
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
            danger_probs  = torch.softmax(danger_logits, dim=-1)
            danger_pred   = danger_logits.argmax(dim=-1).tolist()
            stage_pred    = stage_logits.argmax(dim=-1).tolist()
            intent_pred   = intent_logits.argmax(dim=-1).tolist()
            for idx, meta in enumerate(batch["metadata"]):
                label = danger_label_reverse[int(danger_pred[idx])]
                score = sum(
                    float(danger_probs[idx, ci]) * score_lookup.get(cl, 0.35)
                    for ci, cl in danger_label_reverse.items()
                )
                predictions.append(
                    {
                        **meta,
                        "predicted_danger_score":    round(score, 4),
                        "predicted_danger_label":    label,
                        "predicted_dominant_stage":  dominant_stage_reverse[int(stage_pred[idx])],
                        "predicted_session_intent":  session_intent_reverse[int(intent_pred[idx])],
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
    return [{**p, "split": split_lookup.get(p["example_id"], "unknown")} for p in predictions]


def summarize_eval_predictions(predictions: Sequence[Dict]) -> Dict[str, float]:
    if not predictions:
        return {
            "eval_examples": 0,
            "eval_danger_label_accuracy": 0.0,
            "eval_stage_accuracy": 0.0,
            "eval_intent_accuracy": 0.0,
            "eval_danger_mae": 0.0,
        }

    danger_hits = [1.0 if r["predicted_danger_label"] == r["danger_label"]   else 0.0 for r in predictions]
    stage_hits  = [1.0 if r["predicted_dominant_stage"] == r["dominant_stage"] else 0.0 for r in predictions]
    intent_hits = [1.0 if r["predicted_session_intent"] == r["session_intent"]  else 0.0 for r in predictions]
    mae_vals    = [abs(float(r["predicted_danger_score"]) - float(r["danger_score_target"])) for r in predictions]

    return {
        "eval_examples":              len(predictions),
        "eval_danger_label_accuracy": round(mean(danger_hits), 4),
        "eval_stage_accuracy":        round(mean(stage_hits),  4),
        "eval_intent_accuracy":       round(mean(intent_hits), 4),
        "eval_danger_mae":            round(mean(mae_vals),    4),
    }


# ---------------------------------------------------------------------------
# Summary dataclass
# ---------------------------------------------------------------------------

@dataclass
class TrainSummary:
    # Dataset statistics
    total_examples:         int
    unique_base_sessions:   int
    full_session_examples:  int
    unique_stage_paths:     int
    unique_session_intents: int
    live_full_sessions:     int
    curated_full_sessions:  int
    benign_full_sessions:   int
    attack_full_sessions:   int
    # Feature configuration
    input_feature_mode:       str
    input_event_fields:       List[str]
    excluded_semantic_fields: List[str]
    # Model configuration
    model_class:   str
    hidden_size:   int
    num_layers:    int
    attention:     bool
    bidirectional: bool
    # Split sizes
    train_examples: int
    val_examples:   int
    test_examples:  int
    # Final epoch metrics (best-val checkpoint)
    epochs:                int
    best_epoch:            int
    train_loss:            float
    val_loss:              float
    train_danger_accuracy: float
    val_danger_accuracy:   float
    train_stage_accuracy:  float
    val_stage_accuracy:    float
    train_intent_accuracy: float
    val_intent_accuracy:   float
    # Held-out evaluation
    eval_examples:              int
    eval_danger_label_accuracy: float
    eval_stage_accuracy:        float
    eval_intent_accuracy:       float
    eval_danger_mae:            float
    # Baselines (observable-evidence-only)
    baseline_majority_danger_accuracy: float
    baseline_majority_stage_accuracy:  float
    baseline_majority_intent_accuracy: float
    baseline_rulebased_danger_accuracy: float
    baseline_rulebased_stage_accuracy:  float
    baseline_rulebased_intent_accuracy: float
    # k-fold cross-validation
    kfold_folds:              int
    kfold_mean_danger_accuracy: float
    kfold_std_danger_accuracy:  float
    kfold_mean_stage_accuracy:  float
    kfold_std_stage_accuracy:   float
    kfold_mean_intent_accuracy: float
    kfold_std_intent_accuracy:  float
    # Readiness
    readiness_verdict: str


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train SessionAttentionLSTM on correlated honeypot sessions.")
    parser.add_argument("--scenario-root",   default="artifacts/scenario-runs")
    parser.add_argument("--detection-root",  default="monitoring/ml")
    parser.add_argument("--output-dir",      default="ml/runs/latest")
    parser.add_argument("--epochs",          type=int,   default=90)
    parser.add_argument("--patience",        type=int,   default=15)
    parser.add_argument("--batch-size",      type=int,   default=8)
    parser.add_argument("--hidden-size",     type=int,   default=64)
    parser.add_argument("--num-layers",      type=int,   default=2)
    parser.add_argument("--learning-rate",   type=float, default=0.005)
    parser.add_argument("--stage-loss-weight",  type=float, default=0.25)
    parser.add_argument("--intent-loss-weight", type=float, default=0.30)
    parser.add_argument("--label-smoothing",    type=float, default=0.05)
    parser.add_argument("--bidirectional",   action="store_true", default=True)
    parser.add_argument("--no-bidirectional", dest="bidirectional", action="store_false")
    parser.add_argument("--kfold",           type=int,   default=5,
                        help="Number of CV folds (0 = skip).")
    parser.add_argument("--no-prefix-expansion", action="store_true")
    parser.add_argument("--manifest-only",   action="store_true")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    scenario_root = Path(args.scenario_root)
    detection_root = Path(args.detection_root)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Load & encode data ──────────────────────────────────────────────────
    examples = build_examples(
        scenario_root,
        expand_prefixes=not args.no_prefix_expansion,
        detection_root=detection_root,
        prefer_detection_views=not args.manifest_only,
    )
    if not examples:
        raise SystemExit(f"No training examples found under {scenario_root}")

    vocabs           = build_all_vocabs(examples)
    encoded_examples = encode_examples(examples, vocabs)
    train_examples, val_examples, test_examples = grouped_split(encoded_examples)

    train_loader = DataLoader(SessionDataset(train_examples), batch_size=args.batch_size, shuffle=True,  collate_fn=collate_batch)
    val_loader   = DataLoader(SessionDataset(val_examples),   batch_size=args.batch_size, shuffle=False, collate_fn=collate_batch)
    test_loader  = (
        DataLoader(SessionDataset(test_examples), batch_size=args.batch_size, shuffle=False, collate_fn=collate_batch)
        if test_examples else None
    )

    danger_weights = compute_class_weight_tensor(
        [ex["danger_label_target"]   for ex in train_examples], len(vocabs["danger_label"])
    )
    stage_weights  = compute_class_weight_tensor(
        [ex["dominant_stage_target"] for ex in train_examples], len(vocabs["dominant_stage"])
    )
    intent_weights = compute_class_weight_tensor(
        [ex["session_intent_target"] for ex in train_examples], len(vocabs["session_intent"])
    )

    # ── Build model ─────────────────────────────────────────────────────────
    model     = SessionAttentionLSTM(vocabs=vocabs, hidden_size=args.hidden_size, num_layers=args.num_layers, bidirectional=args.bidirectional)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", patience=8, factor=0.5, min_lr=5e-6
    )

    best_state    = None
    best_val_loss = float("inf")
    best_epoch    = 0
    last_train    = (0.0, 0.0, 0.0, 0.0)
    last_val      = (0.0, 0.0, 0.0, 0.0)
    no_improve    = 0

    print(f"Training SessionAttentionLSTM: hidden={args.hidden_size} layers={args.num_layers} "
          f"examples={len(encoded_examples)} train/val/test={len(train_examples)}/{len(val_examples)}/{len(test_examples)}")

    for epoch in range(args.epochs):
        last_train = run_epoch(
            model, train_loader, optimizer,
            danger_weights, stage_weights, intent_weights,
            args.stage_loss_weight, args.intent_loss_weight,
            label_smoothing=args.label_smoothing,
        )
        last_val = run_epoch(
            model, val_loader, None,
            danger_weights, stage_weights, intent_weights,
            args.stage_loss_weight, args.intent_loss_weight,
        )
        scheduler.step(last_val[0])

        if last_val[0] < best_val_loss:
            best_val_loss = last_val[0]
            best_epoch    = epoch + 1
            best_state    = {k: v.cpu() for k, v in model.state_dict().items()}
            no_improve    = 0
        else:
            no_improve += 1
            if no_improve >= args.patience:
                print(f"  Early stopping at epoch {epoch + 1}")
                break

        if (epoch + 1) % 10 == 0:
            print(
                f"  epoch {epoch + 1:3d}: "
                f"train_loss={last_train[0]:.4f} val_loss={last_val[0]:.4f} "
                f"val_danger={last_val[1]:.4f} val_intent={last_val[3]:.4f}"
            )

    if best_state is not None:
        model.load_state_dict(best_state)

    # ── Inference ───────────────────────────────────────────────────────────
    danger_label_reverse  = {idx: lbl for lbl, idx in vocabs["danger_label"].items()}
    dominant_stage_reverse = {idx: lbl for lbl, idx in vocabs["dominant_stage"].items()}
    session_intent_reverse = {idx: lbl for lbl, idx in vocabs["session_intent"].items()}
    split_lookup = build_split_lookup(train_examples, val_examples, test_examples)

    eval_preds = predict_examples(model, val_loader, danger_label_reverse, dominant_stage_reverse, session_intent_reverse)
    if test_loader is not None:
        eval_preds.extend(
            predict_examples(model, test_loader, danger_label_reverse, dominant_stage_reverse, session_intent_reverse)
        )

    all_loader   = DataLoader(SessionDataset(encoded_examples), batch_size=args.batch_size, shuffle=False, collate_fn=collate_batch)
    all_preds    = annotate_predictions(
        predict_examples(model, all_loader, danger_label_reverse, dominant_stage_reverse, session_intent_reverse),
        split_lookup,
    )
    eval_preds   = annotate_predictions(eval_preds, split_lookup)
    eval_summary = summarize_eval_predictions(eval_preds)

    # ── Baselines (eval set) ─────────────────────────────────────────────────
    print("\nEvaluating baselines on held-out set …")
    majority = MajorityClassBaseline()
    majority.fit(train_examples)
    maj_metrics = majority.evaluate(val_examples + test_examples)

    rule_based  = RuleBasedBaseline()
    rb_metrics  = rule_based.evaluate(val_examples + test_examples)

    print(
        f"  MajorityClass: danger={maj_metrics['danger']:.4f} "
        f"stage={maj_metrics['stage']:.4f} intent={maj_metrics['intent']:.4f}"
    )
    print(
        f"  RuleBased:     danger={rb_metrics['danger']:.4f} "
        f"stage={rb_metrics['stage']:.4f} intent={rb_metrics['intent']:.4f}"
    )
    print(
        f"  SessionLSTM:   danger={eval_summary['eval_danger_label_accuracy']:.4f} "
        f"stage={eval_summary['eval_stage_accuracy']:.4f} intent={eval_summary['eval_intent_accuracy']:.4f}"
    )

    # ── k-fold cross-validation ─────────────────────────────────────────────
    kfold_metrics: Dict[str, float] = {
        "kfold_folds": 0,
        "kfold_mean_danger_accuracy": 0.0, "kfold_std_danger_accuracy": 0.0,
        "kfold_mean_stage_accuracy":  0.0, "kfold_std_stage_accuracy":  0.0,
        "kfold_mean_intent_accuracy": 0.0, "kfold_std_intent_accuracy": 0.0,
    }
    if args.kfold > 1:
        print(f"\nRunning {args.kfold}-fold cross-validation …")
        kfold_metrics = run_kfold(encoded_examples, vocabs, args, k=args.kfold)
        print(
            f"  k-fold danger: {kfold_metrics['kfold_mean_danger_accuracy']:.4f} "
            f"± {kfold_metrics['kfold_std_danger_accuracy']:.4f}"
        )

    # ── Readiness verdict ────────────────────────────────────────────────────
    full_sessions    = [ex for ex in encoded_examples if ex["is_full_session"]]
    live_full        = sum(1 for ex in full_sessions if str(ex["telemetry_origin"]).startswith("live_"))
    curated_full     = sum(1 for ex in full_sessions if not str(ex["telemetry_origin"]).startswith("live_"))
    unique_paths_cnt = len({ex["stage_path"] for ex in full_sessions})
    unique_intents   = len({ex["session_intent"] for ex in full_sessions})
    benign_full      = sum(1 for ex in full_sessions if ex["ground_truth_label"] == "benign")

    model_beats_baselines = (
        eval_summary["eval_danger_label_accuracy"] > rb_metrics["danger"] + 0.03
        and eval_summary["eval_intent_accuracy"]   > maj_metrics["intent"] + 0.05
    )
    sufficient_data = (
        len(full_sessions) >= 20
        and unique_paths_cnt >= 8
        and benign_full >= 6
        and unique_intents >= 6
        and eval_summary["eval_examples"] >= 12
        and live_full >= 5
    )
    readiness = (
        "soc_analyst_ready"
        if sufficient_data and model_beats_baselines
        else "baseline_only"
    )

    # ── Summary ───────────────────────────────────────────────────────────────
    input_event_fields       = ["asset_class", "source_asset", "target_asset", "event_kind", "rule_id", "agent_name", "numeric"]
    excluded_semantic_fields = ["scenario_step", "attack_stage"]

    summary = TrainSummary(
        total_examples=len(encoded_examples),
        unique_base_sessions=len({ex["base_session_id"] for ex in encoded_examples}),
        full_session_examples=len(full_sessions),
        unique_stage_paths=unique_paths_cnt,
        unique_session_intents=unique_intents,
        live_full_sessions=live_full,
        curated_full_sessions=curated_full,
        benign_full_sessions=benign_full,
        attack_full_sessions=sum(1 for ex in full_sessions if ex["ground_truth_label"] != "benign"),
        input_feature_mode="observable_evidence_only",
        input_event_fields=input_event_fields,
        excluded_semantic_fields=excluded_semantic_fields,
        model_class="SessionAttentionLSTM",
        hidden_size=args.hidden_size,
        num_layers=args.num_layers,
        attention=True,
        bidirectional=args.bidirectional,
        train_examples=len(train_examples),
        val_examples=len(val_examples),
        test_examples=len(test_examples),
        epochs=args.epochs,
        best_epoch=best_epoch,
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
        baseline_majority_danger_accuracy=round(maj_metrics["danger"], 4),
        baseline_majority_stage_accuracy=round(maj_metrics["stage"],  4),
        baseline_majority_intent_accuracy=round(maj_metrics["intent"], 4),
        baseline_rulebased_danger_accuracy=round(rb_metrics["danger"], 4),
        baseline_rulebased_stage_accuracy=round(rb_metrics["stage"],  4),
        baseline_rulebased_intent_accuracy=round(rb_metrics["intent"], 4),
        kfold_folds=int(kfold_metrics["kfold_folds"]),
        kfold_mean_danger_accuracy=kfold_metrics["kfold_mean_danger_accuracy"],
        kfold_std_danger_accuracy=kfold_metrics["kfold_std_danger_accuracy"],
        kfold_mean_stage_accuracy=kfold_metrics["kfold_mean_stage_accuracy"],
        kfold_std_stage_accuracy=kfold_metrics["kfold_std_stage_accuracy"],
        kfold_mean_intent_accuracy=kfold_metrics["kfold_mean_intent_accuracy"],
        kfold_std_intent_accuracy=kfold_metrics["kfold_std_intent_accuracy"],
        readiness_verdict=readiness,
    )

    # ── Checkpoint ───────────────────────────────────────────────────────────
    checkpoint = {
        "model_state": model.state_dict(),
        "vocabs": vocabs,
        "config": {
            "hidden_size": args.hidden_size,
            "num_layers":  args.num_layers,
            "attention":      True,
            "bidirectional":  args.bidirectional,
            "label_smoothing": args.label_smoothing,
            "input_feature_mode": "observable_evidence_only",
            "input_event_fields": input_event_fields,
            "excluded_semantic_fields": excluded_semantic_fields,
            "numeric_features": [
                "log_duration_sec", "log_time_delta_sec", "success",
                "rule_level_norm", "log_repeat_count",
            ],
            "detection_root":      str(detection_root),
            "manifest_only":       bool(args.manifest_only),
            "stage_loss_weight":   args.stage_loss_weight,
            "intent_loss_weight":  args.intent_loss_weight,
        },
    }
    torch.save(checkpoint, output_dir / "model.pt")

    # ── Write outputs ────────────────────────────────────────────────────────
    with (output_dir / "metrics.json").open("w", encoding="utf-8") as fh:
        json.dump(asdict(summary), fh, indent=2)
    with (output_dir / "sessions.jsonl").open("w", encoding="utf-8") as fh:
        for ex in encoded_examples:
            fh.write(json.dumps({k: v for k, v in ex.items() if k != "encoded_events"}) + "\n")
    with (output_dir / "predictions.json").open("w", encoding="utf-8") as fh:
        json.dump(all_preds, fh, indent=2)
    with (output_dir / "eval_predictions.json").open("w", encoding="utf-8") as fh:
        json.dump(eval_preds, fh, indent=2)

    print("\n" + json.dumps(asdict(summary), indent=2))


if __name__ == "__main__":
    main()
