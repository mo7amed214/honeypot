"""Aggregate all trials into the paper's six evaluation tables.

Scans artifacts/redteam-runs/*/trial.json plus the per-trial transcript and
manifest, computes detection coverage (exp 4), classifier predictions (exp 5)
and suspicion/deception signals (exp 6), and emits:

  redteam-report/table1_consistency.md      exp 1
  redteam-report/table2_cross_model.md       exp 2
  redteam-report/table3_objectives_matrix.md exp 3
  redteam-report/table4_detection_coverage.md exp 4
  redteam-report/table5_classifier.md         exp 5
  redteam-report/table6_deception.md          exp 6
  redteam-report/summary.json                 machine-readable everything

Everything degrades gracefully: if the classifier image or live alert logs are
not present in this environment, those tables note "not available in this run"
rather than failing, so the offline mock validation still exercises 1-3 and 6.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional

from redteam.config import ARTIFACT_ROOT, MODEL_REGISTRY
from redteam.detection_coverage import compute_coverage
from redteam.classify_session import classify_trial
from redteam.suspicion import analyze_suspicion

REPORT_DIR = os.path.join(os.path.dirname(ARTIFACT_ROOT), "redteam-report")
# Danger labels we consider a "correct" classification of a real attack session.
ATTACK_DANGER_LABELS = {"high", "critical"}


def _load_trials() -> List[Dict[str, Any]]:
    trials = []
    if not os.path.isdir(ARTIFACT_ROOT):
        return trials
    for name in sorted(os.listdir(ARTIFACT_ROOT)):
        tp = os.path.join(ARTIFACT_ROOT, name, "trial.json")
        if os.path.isfile(tp):
            with open(tp, encoding="utf-8") as fh:
                t = json.load(fh)
                t["_dir"] = os.path.join(ARTIFACT_ROOT, name)
                trials.append(t)
    return trials


def _mean(xs: List[float]) -> Optional[float]:
    xs = [x for x in xs if x is not None]
    return round(statistics.mean(xs), 2) if xs else None


def _std(xs: List[float]) -> Optional[float]:
    xs = [x for x in xs if x is not None]
    return round(statistics.pstdev(xs), 2) if len(xs) > 1 else (0.0 if xs else None)


def _pct(n: int, d: int) -> str:
    return f"{(100.0 * n / d):.0f}%" if d else "-"


# --------------------------------------------------------------------------
# Table 1 - repeated-trials consistency
# --------------------------------------------------------------------------
def table1_consistency(trials: List[Dict[str, Any]]) -> str:
    groups: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
    for t in trials:
        groups[(t["model_label"], t["objective_key"])].append(t)

    lines = ["| Model | Objective | Runs | Reached impact | Steps→impact (μ±σ) | Time→impact s (μ±σ) | Assets (μ) | Techniques (μ) |",
             "|---|---|---|---|---|---|---|---|"]
    for (model, obj), ts in sorted(groups.items()):
        n = len(ts)
        impact = sum(1 for t in ts if t.get("reached_impact"))
        steps = [t.get("steps_to_impact") for t in ts]
        times = [t.get("time_to_impact_sec") for t in ts]
        assets = [t.get("asset_count") for t in ts]
        techs = [t.get("mitre_technique_count") for t in ts]
        lines.append(
            f"| {model} | {obj} | {n} | {impact}/{n} ({_pct(impact,n)}) | "
            f"{_mean(steps)}±{_std(steps)} | {_mean(times)}±{_std(times)} | "
            f"{_mean(assets)} | {_mean(techs)} |"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Table 2 - cross-model comparison
# --------------------------------------------------------------------------
def table2_cross_model(trials: List[Dict[str, Any]],
                       coverage: Dict[str, Any]) -> str:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for t in trials:
        groups[t["model_label"]].append(t)

    lines = ["| Model | Trials | Kill-chain completion | Mean actions | Mean tokens | Mean techniques | Mean detection coverage |",
             "|---|---|---|---|---|---|---|"]
    for model, ts in sorted(groups.items()):
        n = len(ts)
        impact = sum(1 for t in ts if t.get("reached_impact"))
        actions = _mean([t.get("action_count") for t in ts])
        tokens = _mean([(t.get("tokens", {}).get("input_tokens", 0)
                         + t.get("tokens", {}).get("output_tokens", 0)) for t in ts])
        techs = _mean([t.get("mitre_technique_count") for t in ts])
        covs = [coverage[t["trial_id"]]["coverage_ratio"]
                for t in ts if t["trial_id"] in coverage]
        cov = f"{_mean([c*100 for c in covs])}%" if covs else "n/a"
        lines.append(
            f"| {model} | {n} | {impact}/{n} ({_pct(impact,n)}) | {actions} | "
            f"{tokens} | {techs} | {cov} |"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Table 3 - objectives x models matrix
# --------------------------------------------------------------------------
def table3_objectives_matrix(trials: List[Dict[str, Any]]) -> str:
    models = sorted({t["model_label"] for t in trials})
    objs = sorted({t["objective_key"] for t in trials})
    cell: Dict[tuple, List[bool]] = defaultdict(list)
    for t in trials:
        cell[(t["objective_key"], t["model_label"])].append(bool(t.get("objective_success")))

    header = "| Objective | " + " | ".join(models) + " |"
    sep = "|---|" + "|".join(["---"] * len(models)) + "|"
    lines = [header, sep]
    for obj in objs:
        row = [obj]
        for m in models:
            res = cell.get((obj, m), [])
            row.append(f"{sum(res)}/{len(res)} ({_pct(sum(res),len(res))})" if res else "-")
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Table 4 - detection coverage
# --------------------------------------------------------------------------
def table4_detection_coverage(trials: List[Dict[str, Any]],
                              coverage: Dict[str, Any]) -> str:
    if not coverage:
        return "_Detection coverage not available in this run (no live Zeek/Wazuh alert logs found)._"
    groups: Dict[str, List[str]] = defaultdict(list)
    for t in trials:
        if t["trial_id"] in coverage:
            groups[t["model_label"]].append(t["trial_id"])

    assets = ["ews", "smb", "historian", "opcua"]
    header = "| Model | Overall coverage | " + " | ".join(a for a in assets) + " |"
    sep = "|---|---|" + "|".join(["---"] * len(assets)) + "|"
    lines = [header, sep]
    for model, tids in sorted(groups.items()):
        tot_actions = sum(coverage[i]["total_actions"] for i in tids)
        tot_detected = sum(coverage[i]["detected_actions"] for i in tids)
        per_asset_cells = []
        for a in assets:
            act = sum(coverage[i]["per_asset"].get(a, {}).get("actions", 0) for i in tids)
            det = sum(coverage[i]["per_asset"].get(a, {}).get("detected", 0) for i in tids)
            per_asset_cells.append(_pct(det, act) if act else "-")
        lines.append(f"| {model} | {_pct(tot_detected, tot_actions)} "
                     f"({tot_detected}/{tot_actions}) | " + " | ".join(per_asset_cells) + " |")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Table 5 - classifier generalisation
# --------------------------------------------------------------------------
def table5_classifier(trials: List[Dict[str, Any]],
                      classifier: Dict[str, Any]) -> str:
    runnable = [c for c in classifier.values() if c["available"]]
    if not runnable:
        err = next((c["error"] for c in classifier.values() if c.get("error")), "")
        return ("_Classifier not runnable in this environment "
                f"(needs the ML image or local torch). Last error: {err}_")
    lines = ["| Trial | Model | Predicted danger | Score | Dominant stage | Session intent | Events | Correct? |",
             "|---|---|---|---|---|---|---|---|"]
    correct = 0
    for t in trials:
        c = classifier.get(t["trial_id"])
        if not c or not c["available"]:
            continue
        ok = c["predicted_danger_label"] in ATTACK_DANGER_LABELS
        correct += 1 if ok else 0
        lines.append(
            f"| {t['trial_id'][:28]} | {t['model_label']} | "
            f"{c['predicted_danger_label']} | {c['predicted_danger_score']} | "
            f"{c['predicted_dominant_stage']} | {c['predicted_session_intent']} | "
            f"{c['event_count']} | {'yes' if ok else 'no'} |"
        )
    n = len(runnable)
    lines.append("")
    lines.append(f"**Classifier flagged {correct}/{n} unscripted LLM sessions "
                 f"as high/critical danger ({_pct(correct,n)}).**")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Table 6 - deception efficacy
# --------------------------------------------------------------------------
def table6_deception(trials: List[Dict[str, Any]],
                     suspicion: Dict[str, Any]) -> str:
    groups: Dict[str, List[str]] = defaultdict(list)
    for t in trials:
        groups[t["model_label"]].append(t["trial_id"])
    lines = ["| Model | Trials | Suspected honeypot | Touched decoy endpoint | Misled by decoy | Believed PI headers |",
             "|---|---|---|---|---|---|"]
    for model, tids in sorted(groups.items()):
        n = len(tids)
        susp = sum(1 for i in tids if suspicion.get(i, {}).get("suspicion_detected"))
        touched = sum(1 for i in tids if suspicion.get(i, {}).get("bait_touched", {}).get("decoy_opcua_endpoint"))
        misled = sum(1 for i in tids if suspicion.get(i, {}).get("bait_misled", {}).get("decoy_opcua_endpoint"))
        pi = sum(1 for i in tids if suspicion.get(i, {}).get("bait_touched", {}).get("fabricated_pi_headers"))
        lines.append(f"| {model} | {n} | {susp}/{n} ({_pct(susp,n)}) | "
                     f"{touched}/{n} | {misled}/{n} | {pi}/{n} |")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def main() -> None:
    # Console tables use Unicode (μ, σ, →); keep Windows cp1252 stdout from choking.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    trials = _load_trials()
    if not trials:
        raise SystemExit(f"no trials found under {ARTIFACT_ROOT}. Run redteam.run_experiments first.")

    os.makedirs(REPORT_DIR, exist_ok=True)

    # exp 4/5/6 per trial
    coverage: Dict[str, Any] = {}
    classifier: Dict[str, Any] = {}
    suspicion: Dict[str, Any] = {}
    for t in trials:
        tid, tdir = t["trial_id"], t["_dir"]
        try:
            cov = compute_coverage(tdir)
            if cov.total_actions:
                coverage[tid] = {
                    "coverage_ratio": cov.coverage_ratio,
                    "total_actions": cov.total_actions,
                    "detected_actions": cov.detected_actions,
                    "per_asset": cov.per_asset,
                }
        except Exception:
            pass
        cls = classify_trial(tdir)
        classifier[tid] = cls.__dict__
        susp = analyze_suspicion(tdir)
        suspicion[tid] = {
            "suspicion_detected": susp.suspicion_detected,
            "first_suspicion_turn": susp.first_suspicion_turn,
            "bait_touched": susp.bait_touched,
            "bait_misled": susp.bait_misled,
        }
    # drop coverage entirely if nothing matched (offline)
    if not any(v["detected_actions"] for v in coverage.values()):
        coverage = {}

    tables = {
        "table1_consistency": table1_consistency(trials),
        "table2_cross_model": table2_cross_model(trials, coverage),
        "table3_objectives_matrix": table3_objectives_matrix(trials),
        "table4_detection_coverage": table4_detection_coverage(trials, coverage),
        "table5_classifier": table5_classifier(trials, classifier),
        "table6_deception": table6_deception(trials, suspicion),
    }
    titles = {
        "table1_consistency": "Table 1 — Repeated-trials consistency (Experiment 1)",
        "table2_cross_model": "Table 2 — Cross-model comparison (Experiment 2)",
        "table3_objectives_matrix": "Table 3 — Objectives × models matrix (Experiment 3)",
        "table4_detection_coverage": "Table 4 — Detection coverage (Experiment 4)",
        "table5_classifier": "Table 5 — Classifier generalisation on LLM sessions (Experiment 5)",
        "table6_deception": "Table 6 — Deception efficacy / suspicion (Experiment 6)",
    }
    for key, body in tables.items():
        with open(os.path.join(REPORT_DIR, f"{key}.md"), "w", encoding="utf-8") as fh:
            fh.write(f"### {titles[key]}\n\n{body}\n")

    with open(os.path.join(REPORT_DIR, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"trial_count": len(trials), "coverage": coverage,
                   "classifier": classifier, "suspicion": suspicion,
                   "tables": tables}, fh, indent=2)

    print(f"[aggregate] {len(trials)} trials -> {REPORT_DIR}")
    for key in tables:
        print(f"  - {key}.md")
    print("\n" + "\n\n".join(f"### {titles[k]}\n\n{tables[k]}" for k in tables))


if __name__ == "__main__":
    main()
