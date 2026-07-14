"""Robustness tests for the trained SessionAttentionLSTM.

Loads a trained checkpoint and re-evaluates it on the held-out test split under
controlled perturbations, to answer "how brittle is the session classifier?":

  * clean           - no perturbation (reference)
  * drop-20%        - randomly drop 20% of events per session (missed detections)
  * shuffle         - randomise event order (tests order sensitivity)
  * truncate-70%    - keep only the first 70% of each session (early prediction)
  * benign-noise    - inject benign events into attack sessions (evasion by noise)

Reports danger-label accuracy under each condition. A model that degrades
gracefully under dropped/reordered/truncated input is more deployable; the
early-prediction column also substantiates the thesis's "critical verdict from
a partial session" claim.

Runs inside the ML image. Usage:
    python -m ml.lstm_session.robustness --model ml/runs/latest/model.pt \
        --scenario-root artifacts/scenario-runs --out ml/runs/robustness
"""

from __future__ import annotations

import argparse
import copy
import json
import random
from pathlib import Path
from typing import Dict, List

import torch

from ml.lstm_session.session_builder import build_examples, grouped_split, encode_examples
from ml.lstm_session.train import SessionAttentionLSTM, collate_batch

REPO_ROOT = Path(__file__).resolve().parents[2]


def _predict_danger(model, examples, vocabs) -> float:
    """Return danger-label accuracy of the model over the given examples."""
    if not examples:
        return 0.0
    danger_reverse = {i: v for v, i in vocabs["danger_label"].items()}
    encoded = encode_examples(examples, vocabs)
    hits = 0
    total = 0
    # evaluate one at a time to keep memory tiny on constrained machines
    for ex_enc, ex_raw in zip(encoded, examples):
        batch = collate_batch([ex_enc])
        with torch.no_grad():
            danger_logits, _, _ = model(batch)
        pred = danger_reverse[int(danger_logits.argmax(dim=-1)[0].item())]
        gold = str(ex_raw.get("danger_label", "unknown"))
        hits += 1 if pred == gold else 0
        total += 1
    return round(hits / total, 4) if total else 0.0


# -- perturbations ----------------------------------------------------------
def perturb_drop(examples, rng, frac=0.2):
    out = []
    for ex in examples:
        ev = ex.get("events", [])
        if len(ev) <= 2:
            out.append(ex); continue
        keep = [e for e in ev if rng.random() > frac] or ev[:1]
        new = copy.deepcopy(ex); new["events"] = keep; new["event_count"] = len(keep)
        out.append(new)
    return out


def perturb_shuffle(examples, rng):
    out = []
    for ex in examples:
        new = copy.deepcopy(ex)
        ev = list(new.get("events", []))
        rng.shuffle(ev)
        new["events"] = ev
        out.append(new)
    return out


def perturb_truncate(examples, frac=0.7):
    out = []
    for ex in examples:
        ev = ex.get("events", [])
        k = max(1, int(len(ev) * frac))
        new = copy.deepcopy(ex); new["events"] = ev[:k]; new["event_count"] = k
        out.append(new)
    return out


def perturb_benign_noise(examples, rng, n_inject=2):
    """Insert benign-looking events at random positions in attack sessions."""
    benign_event = {"asset_class": "network", "attack_stage": "benign",
                    "attack_label": "benign", "mitre_technique": "T0000",
                    "event_kind": "healthcheck", "source_asset": "monitoring_laptop",
                    "target_asset": "network", "rule_id": "none", "agent_name": "none",
                    "rule_level": 0.0, "exit_code": 0, "success": 1.0, "repeat_count": 1,
                    "duration_sec": 0.5, "time_delta_sec": 1.0}
    out = []
    for ex in examples:
        new = copy.deepcopy(ex)
        ev = list(new.get("events", []))
        for _ in range(n_inject):
            ev.insert(rng.randrange(len(ev) + 1), dict(benign_event))
        new["events"] = ev; new["event_count"] = len(ev)
        out.append(new)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Robustness tests for SessionAttentionLSTM.")
    ap.add_argument("--model", default="ml/runs/latest/model.pt")
    ap.add_argument("--scenario-root", default="artifacts/scenario-runs")
    ap.add_argument("--detection-root", default="monitoring/ml")
    ap.add_argument("--out", default="ml/runs/robustness")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    ckpt = torch.load(REPO_ROOT / args.model, map_location="cpu")
    vocabs = ckpt["vocabs"]
    cfg = ckpt["config"]
    model = SessionAttentionLSTM(
        vocabs=vocabs, hidden_size=int(cfg["hidden_size"]),
        num_layers=int(cfg.get("num_layers", 2)),
        bidirectional=bool(cfg.get("bidirectional", True)),
        attention=bool(cfg.get("attention", True)),
    )
    model.load_state_dict(ckpt["model_state"])
    model.eval()

    examples = build_examples(Path(args.scenario_root), expand_prefixes=True,
                              detection_root=Path(args.detection_root))
    _, _, test_ex = grouped_split(examples)
    # only full sessions for a clean robustness reference
    full_test = [e for e in test_ex if e.get("is_full_session")] or test_ex

    conditions = {
        "clean":        full_test,
        "drop-20%":     perturb_drop(full_test, rng, 0.2),
        "shuffle":      perturb_shuffle(full_test, rng),
        "truncate-70%": perturb_truncate(full_test, 0.7),
        "benign-noise": perturb_benign_noise(full_test, rng, 2),
    }
    results = {name: _predict_danger(model, exs, vocabs) for name, exs in conditions.items()}
    for name, acc in results.items():
        print(f"[robustness] {name:14s} danger_acc={acc}")

    out_dir = REPO_ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = ["### Robustness under input perturbation (danger accuracy)",
             "", "| Condition | Danger accuracy | Δ vs clean |", "|---|---|---|"]
    clean = results.get("clean", 0.0)
    for name, acc in results.items():
        d = acc - clean
        lines.append(f"| {name} | {acc} | {'+' if d >= 0 else ''}{d:.4f} |")
    report = "\n".join(lines)
    (out_dir / "robustness_report.md").write_text(report, encoding="utf-8")
    (out_dir / "robustness.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\n" + report)


if __name__ == "__main__":
    main()
