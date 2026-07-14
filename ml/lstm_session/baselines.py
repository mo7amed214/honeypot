"""Strong non-sequential baselines for the session-classification task.

The thesis already reports two trivial baselines (majority-class and a
rule-based single-feature classifier). A reviewer will rightly ask whether the
attention-LSTM beats *learned* baselines too, not just trivial ones. This
module trains classical ML classifiers on **aggregated, order-free** session
features (bag-of-techniques / stages / assets + simple counts) using the SAME
grouped train/test split as train.py, so the comparison is fair.

The argument: if the sequential attention-LSTM beats these order-free learners,
the gain is attributable to sequential/contextual modelling, not just to the
features being informative. Output is a baseline-comparison table.

Runs inside the ML image (needs scikit-learn; see requirements.txt).
Usage:
    python -m ml.lstm_session.baselines --scenario-root artifacts/scenario-runs \
        --out ml/runs/baselines
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

from ml.lstm_session.session_builder import build_examples, grouped_split

REPO_ROOT = Path(__file__).resolve().parents[2]


def _session_features(example: Dict, vocab: Dict[str, List[str]]) -> np.ndarray:
    events = example.get("events", [])
    feats: List[float] = []
    # bag-of-X counts for the categorical vocabularies
    for field in ("asset_class", "attack_stage", "mitre_technique", "event_kind"):
        counts = Counter(str(e.get(field, "unknown")) for e in events)
        for token in vocab[field]:
            feats.append(float(counts.get(token, 0)))
    # simple session-level scalars
    rule_levels = [float(e.get("rule_level", 0) or 0) for e in events]
    feats.append(float(len(events)))                                   # length
    feats.append(max(rule_levels) if rule_levels else 0.0)             # peak severity
    feats.append(sum(rule_levels) / len(rule_levels) if rule_levels else 0.0)
    feats.append(float(len({e.get("mitre_technique") for e in events})))  # unique techniques
    feats.append(float(len({e.get("asset_class") for e in events})))      # unique assets
    return np.asarray(feats, dtype=np.float32)


def _build_vocab(examples: List[Dict]) -> Dict[str, List[str]]:
    vocab: Dict[str, set] = {f: set() for f in ("asset_class", "attack_stage",
                                                "mitre_technique", "event_kind")}
    for ex in examples:
        for e in ex.get("events", []):
            for f in vocab:
                vocab[f].add(str(e.get(f, "unknown")))
    return {f: sorted(v) for f, v in vocab.items()}


def _xy(examples: List[Dict], vocab, label_key="danger_label") -> Tuple[np.ndarray, List[str]]:
    X = np.vstack([_session_features(ex, vocab) for ex in examples])
    y = [str(ex.get(label_key, "unknown")) for ex in examples]
    return X, y


def main() -> None:
    ap = argparse.ArgumentParser(description="Classical baselines for session classification.")
    ap.add_argument("--scenario-root", default="artifacts/scenario-runs")
    ap.add_argument("--detection-root", default="monitoring/ml")
    ap.add_argument("--out", default="ml/runs/baselines")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.svm import LinearSVC
    from sklearn.naive_bayes import GaussianNB
    from sklearn.metrics import accuracy_score

    examples = build_examples(Path(args.scenario_root), expand_prefixes=True,
                              detection_root=Path(args.detection_root))
    if not examples:
        raise SystemExit("no examples")
    train_ex, val_ex, test_ex = grouped_split(examples)
    # baselines don't need a val split; fold it into train
    train_ex = train_ex + val_ex
    vocab = _build_vocab(train_ex)

    Xtr, ytr = _xy(train_ex, vocab)
    Xte, yte = _xy(test_ex, vocab)

    models = {
        "LogisticRegression": LogisticRegression(max_iter=2000, random_state=args.seed),
        "RandomForest": RandomForestClassifier(n_estimators=200, random_state=args.seed),
        "LinearSVM": LinearSVC(random_state=args.seed),
        "GaussianNB": GaussianNB(),
    }
    results = {}
    for name, clf in models.items():
        try:
            clf.fit(Xtr, ytr)
            acc = accuracy_score(yte, clf.predict(Xte))
            results[name] = round(float(acc), 4)
            print(f"[baseline] {name:20s} danger_acc={acc:.4f}")
        except Exception as exc:
            results[name] = None
            print(f"[baseline] {name:20s} FAILED: {exc}")

    # pull the LSTM's eval accuracy for side-by-side context, if present
    lstm_acc = None
    metrics_path = REPO_ROOT / "ml" / "runs" / "latest" / "metrics.json"
    if metrics_path.is_file():
        lstm_acc = json.loads(metrics_path.read_text()).get("eval_danger_label_accuracy")

    out_dir = REPO_ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = ["### Baseline comparison — session danger classification",
             "",
             "| Model | Type | Danger accuracy |",
             "|---|---|---|"]
    lines.append(f"| Majority class | trivial | see metrics.json |")
    for name, acc in results.items():
        lines.append(f"| {name} | learned, order-free | {acc if acc is not None else 'failed'} |")
    if lstm_acc is not None:
        lines.append(f"| **SessionAttentionLSTM** | **sequential** | **{lstm_acc}** |")
    lines.append("")
    lines.append("_Order-free learners use bag-of-technique/stage/asset counts + "
                 "session scalars on the same grouped split; the sequential model's "
                 "margin over them isolates the value of sequence modelling._")
    report = "\n".join(lines)
    (out_dir / "baselines_report.md").write_text(report, encoding="utf-8")
    (out_dir / "baselines.json").write_text(
        json.dumps({"baselines": results, "lstm_eval_danger_accuracy": lstm_acc}, indent=2),
        encoding="utf-8")
    print("\n" + report)


if __name__ == "__main__":
    main()
