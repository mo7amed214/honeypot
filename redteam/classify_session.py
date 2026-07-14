"""Experiment 5 - classifier generalisation on unscripted LLM sessions.

Runs the trained SessionAttentionLSTM (ml/lstm_session/infer.py) on a trial's
ground_truth.jsonl and returns the predicted danger score/label, dominant
stage and session intent. The classifier was trained on the curated + scripted
corpus and never saw these autonomous LLM sessions, so a correct prediction
here is an out-of-distribution generalisation result - the bridge that turns
the k-fold-validated ML pillar into support for the LLM pillar.

Execution reuses the existing ML runtime image (compose/docker-compose.ml.yml)
so no torch install is needed on the host, matching how the rest of the ML
pipeline runs in this repo. If torch happens to be importable locally, it runs
in-process instead.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MODEL = os.environ.get("REDTEAM_MODEL_PATH", "ml/runs/latest/model.pt")


@dataclass
class ClassifierResult:
    trial_id: str
    available: bool
    predicted_danger_label: Optional[str] = None
    predicted_danger_score: Optional[float] = None
    predicted_dominant_stage: Optional[str] = None
    predicted_session_intent: Optional[str] = None
    event_count: Optional[int] = None
    error: str = ""


def _torch_available() -> bool:
    try:
        import torch  # noqa: F401
        return True
    except Exception:
        return False


def _run_local(session_file: str, model_path: str) -> Dict[str, Any]:
    cmd = ["python", "-m", "ml.lstm_session.infer",
           "--model-path", model_path, "--session-file", session_file]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "infer failed")
    return json.loads(proc.stdout)


def _run_docker(session_file: str, model_path: str) -> Dict[str, Any]:
    # session_file is under the repo, which is mounted at /workspace in the image.
    rel = os.path.relpath(session_file, REPO_ROOT).replace("\\", "/")
    inner = ["python", "-m", "ml.lstm_session.infer",
             "--model-path", model_path, "--session-file", rel]
    cmd = ["docker", "compose", "-f", "compose/docker-compose.ml.yml",
           "run", "--rm", "-T", "lstm-session-runtime"] + inner
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "docker infer failed")
    # The compose runner may print its own lines; take the JSON object.
    out = proc.stdout.strip()
    brace = out.find("{")
    if brace == -1:
        raise RuntimeError(f"no JSON in infer output: {out[:200]}")
    return json.loads(out[brace:])


def classify_trial(trial_dir: str, model_path: str = DEFAULT_MODEL,
                   prefer_docker: bool = True) -> ClassifierResult:
    trial_id = os.path.basename(trial_dir.rstrip("/\\"))
    session_file = os.path.join(trial_dir, "ground_truth.jsonl")
    if not os.path.isfile(session_file):
        return ClassifierResult(trial_id, False, error="no ground_truth.jsonl")

    try:
        if _torch_available() and not prefer_docker:
            data = _run_local(session_file, model_path)
        else:
            try:
                data = _run_docker(session_file, model_path)
            except Exception:
                if _torch_available():
                    data = _run_local(session_file, model_path)
                else:
                    raise
    except Exception as exc:  # classifier not runnable in this environment
        return ClassifierResult(trial_id, False, error=str(exc)[:300])

    return ClassifierResult(
        trial_id=trial_id,
        available=True,
        predicted_danger_label=data.get("predicted_danger_label"),
        predicted_danger_score=data.get("predicted_danger_score"),
        predicted_dominant_stage=data.get("predicted_dominant_stage"),
        predicted_session_intent=data.get("predicted_session_intent"),
        event_count=data.get("event_count"),
    )
