"""Ablation, baseline and robustness study for the SessionAttentionLSTM.

Runs the training entry point (ml.lstm_session.train) repeatedly with different
architecture / data configurations and collects the resulting metrics into three
paper tables:

  * ablation      - which design choices matter (attention, bidirectionality,
                    depth, width, prefix expansion)
  * seed-robustness - stability of the headline config across random seeds
  * (baselines are already emitted inside metrics.json by train.py:
     MajorityClass and RuleBased; stronger ML baselines live in baselines.py)

Each configuration is a full, independent training run so the numbers are
directly comparable to the headline model. Runs are sequential and CPU-bound;
on a constrained machine keep --kfold 0 for the ablation sweep and reserve
k-fold for the final headline config only.

Usage (inside the ML image, like train):
    python -m ml.lstm_session.ablation --scenario-root artifacts/scenario-runs \
        --out ml/runs/ablation --kfold 0
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]


# (name, extra CLI args) - every run starts from train.py defaults.
ABLATION_CONFIGS: List[tuple[str, List[str]]] = [
    ("headline (attn+bi+2L+h64)", []),
    ("no-attention (mean-pool)",  ["--no-attention"]),
    ("no-bidirectional",          ["--no-bidirectional"]),
    ("1-layer",                   ["--num-layers", "1"]),
    ("3-layer",                   ["--num-layers", "3"]),
    ("narrow-h32",                ["--hidden-size", "32"]),
    ("wide-h128",                 ["--hidden-size", "128"]),
    ("no-prefix-expansion",       ["--no-prefix-expansion"]),
]

METRICS_KEYS = [
    "eval_danger_label_accuracy", "eval_stage_accuracy", "eval_intent_accuracy",
    "val_danger_accuracy", "kfold_mean_danger_accuracy", "kfold_std_danger_accuracy",
    "baseline_rulebased_danger_accuracy", "baseline_majority_danger_accuracy",
]


def _run_training(extra: List[str], out_dir: Path, scenario_root: str,
                  kfold: int, seed: int) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "ml.lstm_session.train",
           "--scenario-root", scenario_root,
           "--output-dir", str(out_dir),
           "--kfold", str(kfold),
           "--seed", str(seed)] + extra
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    metrics_path = out_dir / "metrics.json"
    if proc.returncode != 0 or not metrics_path.exists():
        return {"error": (proc.stderr or proc.stdout)[-400:]}
    with metrics_path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _fmt(v: Any) -> str:
    if isinstance(v, float):
        return f"{v:.4f}"
    return "-" if v is None else str(v)


def run_ablation(scenario_root: str, out_root: Path, kfold: int, seed: int) -> str:
    rows = []
    for name, extra in ABLATION_CONFIGS:
        slug = name.split()[0].replace("(", "").replace(")", "")
        print(f"[ablation] {name} ...", flush=True)
        m = _run_training(extra, out_root / slug, scenario_root, kfold, seed)
        if "error" in m:
            print(f"  FAILED: {m['error'][:120]}")
            rows.append((name, m, True))
        else:
            print(f"  eval danger={m.get('eval_danger_label_accuracy')} "
                  f"stage={m.get('eval_stage_accuracy')} intent={m.get('eval_intent_accuracy')}")
            rows.append((name, m, False))

    lines = ["| Configuration | Danger acc | Stage acc | Intent acc | Δ danger vs headline |",
             "|---|---|---|---|---|"]
    headline = next((m for n, m, err in rows if n.startswith("headline") and not err), {})
    base = headline.get("eval_danger_label_accuracy") or 0.0
    for name, m, err in rows:
        if err:
            lines.append(f"| {name} | _failed_ | - | - | - |")
            continue
        d = m.get("eval_danger_label_accuracy") or 0.0
        delta = d - base
        lines.append(f"| {name} | {_fmt(d)} | {_fmt(m.get('eval_stage_accuracy'))} | "
                     f"{_fmt(m.get('eval_intent_accuracy'))} | "
                     f"{'+' if delta >= 0 else ''}{delta:.4f} |")
    return "\n".join(lines)


def run_seed_robustness(scenario_root: str, out_root: Path, seeds: List[int],
                        kfold: int) -> str:
    accs = []
    for s in seeds:
        print(f"[seed-robustness] seed={s} ...", flush=True)
        m = _run_training([], out_root / f"seed_{s}", scenario_root, kfold, s)
        if "error" not in m:
            accs.append((s, m.get("eval_danger_label_accuracy")))
            print(f"  danger={m.get('eval_danger_label_accuracy')}")
    lines = ["| Seed | Danger acc |", "|---|---|"]
    vals = [a for _, a in accs if a is not None]
    for s, a in accs:
        lines.append(f"| {s} | {_fmt(a)} |")
    if vals:
        mean = sum(vals) / len(vals)
        var = sum((x - mean) ** 2 for x in vals) / len(vals)
        lines.append(f"| **mean±std** | **{mean:.4f} ± {var ** 0.5:.4f}** |")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Ablation + robustness study for SessionAttentionLSTM.")
    p.add_argument("--scenario-root", default="artifacts/scenario-runs")
    p.add_argument("--out", default="ml/runs/ablation")
    p.add_argument("--kfold", type=int, default=0,
                   help="k for CV inside each run (0 = skip; keep 0 for the sweep on small machines).")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--seeds", type=int, nargs="+", default=[1337, 7, 42, 2024, 99],
                   help="seeds for the robustness sweep")
    p.add_argument("--skip-robustness", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    out_root = REPO_ROOT / args.out
    out_root.mkdir(parents=True, exist_ok=True)

    ablation_md = run_ablation(args.scenario_root, out_root / "ablation", args.kfold, args.seed)
    report = [f"### Ablation study (SessionAttentionLSTM)\n\n{ablation_md}\n"]

    if not args.skip_robustness:
        robustness_md = run_seed_robustness(args.scenario_root, out_root / "robustness",
                                            args.seeds, kfold=0)
        report.append(f"### Seed robustness (headline config)\n\n{robustness_md}\n")

    report_text = "\n\n".join(report)
    (out_root / "ablation_report.md").write_text(report_text, encoding="utf-8")
    print("\n" + report_text)
    print(f"\n[ablation] report -> {out_root / 'ablation_report.md'}")


if __name__ == "__main__":
    main()
