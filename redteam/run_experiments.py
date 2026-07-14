"""Experiment matrix runner.

Runs the models x objectives x repeats grid, optionally resetting lab state
between trials, and writes each trial into artifacts/redteam-runs/. This single
runner produces the raw material for experiments 1-3 (consistency, cross-model,
objectives); experiments 4-6 are computed afterwards by aggregate.py over the
same trials.

Usage examples
--------------
Offline pipeline validation (no keys, no VM):
    python -m redteam.run_experiments --models mock --objectives explore \
        --repeats 3 --target mock --no-reset

One real model, consistency battery:
    ANTHROPIC_API_KEY=... python -m redteam.run_experiments \
        --models claude-opus --objectives explore --repeats 10

Full cross-model / cross-objective grid:
    python -m redteam.run_experiments \
        --models claude-opus gpt gemini llama-local \
        --objectives explore credential_theft process_manipulation \
                     data_exfiltration persistence \
        --repeats 5
"""

from __future__ import annotations

import argparse
import os
import subprocess
import time
from typing import List

from redteam.agent import run_trial
from redteam.config import MODEL_REGISTRY, OBJECTIVES, ARTIFACT_ROOT
from redteam.providers import get_provider

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _reset_lab() -> None:
    script = os.path.join(REPO_ROOT, "scripts", "reset_lab_state.sh")
    if os.path.isfile(script):
        subprocess.run(["bash", script], cwd=REPO_ROOT,
                       capture_output=True, text=True)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run the LLM red-team experiment matrix.")
    p.add_argument("--models", nargs="+", default=["mock"],
                   help=f"model keys: {', '.join(MODEL_REGISTRY)}")
    p.add_argument("--objectives", nargs="+", default=["explore"],
                   help=f"objective keys: {', '.join(OBJECTIVES)}")
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--target", choices=["ssh", "docker", "mock"], default="ssh")
    p.add_argument("--no-reset", action="store_true",
                   help="skip reset_lab_state.sh between trials")
    p.add_argument("--dry-run", action="store_true",
                   help="print the plan and check provider availability only")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    os.makedirs(ARTIFACT_ROOT, exist_ok=True)

    for mk in args.models:
        if mk not in MODEL_REGISTRY:
            raise SystemExit(f"unknown model '{mk}'. known: {', '.join(MODEL_REGISTRY)}")
    for ok in args.objectives:
        if ok not in OBJECTIVES:
            raise SystemExit(f"unknown objective '{ok}'. known: {', '.join(OBJECTIVES)}")

    planned = []
    for mk in args.models:
        spec = MODEL_REGISTRY[mk]
        avail, why = get_provider(spec).available()
        status = "OK" if avail else f"UNAVAILABLE ({why})"
        print(f"[plan] model {mk:14s} -> {status}")
        for ok in args.objectives:
            for r in range(args.repeats):
                planned.append((mk, ok, r, avail))

    print(f"[plan] {len(planned)} trials "
          f"({len(args.models)} models x {len(args.objectives)} objectives "
          f"x {args.repeats} repeats), target={args.target}")
    if args.dry_run:
        return

    completed, skipped = 0, 0
    for mk, ok, r, avail in planned:
        if not avail and MODEL_REGISTRY[mk].provider != "mock":
            skipped += 1
            continue
        spec = MODEL_REGISTRY[mk]
        objective = OBJECTIVES[ok]
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        trial_id = f"{mk}__{ok}__r{r:02d}__{stamp}"

        if not args.no_reset and args.target == "ssh":
            _reset_lab()
        # Let the mock provider know which objective tail to walk.
        os.environ["REDTEAM_MOCK_OBJECTIVE"] = ok

        print(f"[run ] {trial_id} ...", flush=True)
        try:
            summary = run_trial(trial_id, spec, objective, target_kind=args.target)
            print(f"[done] {trial_id}  impact={summary['reached_impact']} "
                  f"assets={summary['asset_count']} "
                  f"techniques={summary['mitre_technique_count']} "
                  f"actions={summary['action_count']}")
            completed += 1
        except Exception as exc:
            print(f"[fail] {trial_id}: {exc}")
            skipped += 1

    print(f"[summary] completed={completed} skipped={skipped} "
          f"-> {ARTIFACT_ROOT}")
    print("[next] python -m redteam.aggregate")


if __name__ == "__main__":
    main()
