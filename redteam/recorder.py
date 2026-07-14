"""Trial recorder.

Writes three artefacts per trial into its own directory:

  ground_truth.jsonl   one record per agent action, in the SAME schema
                       scripts/replay_attack_scenario.sh emits and
                       ml/lstm_session/session_builder.py consumes - so the
                       SessionAttentionLSTM classifier runs on an LLM session
                       with zero glue code (experiment 5).
  transcript.jsonl     the full model<->target exchange (assistant text,
                       rationale, command, raw output, tokens, timing) for
                       suspicion analysis (experiment 6) and the appendix.
  trial.json           per-trial metadata + rolled-up outcome.

Keeping the manifest schema identical to the scripted kill chain is the whole
point: it lets the paper feed a hand-free LLM attack through the exact
detection + ML stack whose reliability is already established elsewhere.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from redteam.config import ARTIFACT_ROOT
from redteam.mitre import classify_action


@dataclass
class ActionRecord:
    index: int
    command: str
    rationale: Optional[str]
    output: str
    exit_code: int
    duration_sec: float
    start_ts_epoch: float
    end_ts_epoch: float
    mitre_technique: str
    attack_stage: str
    attack_label: str
    asset_class: str
    target_ip: str


class TrialRecorder:
    def __init__(self, trial_id: str, model_key: str, model_label: str,
                 objective_key: str) -> None:
        self.trial_id = trial_id
        self.model_key = model_key
        self.model_label = model_label
        self.objective_key = objective_key
        self.dir = os.path.join(ARTIFACT_ROOT, trial_id)
        os.makedirs(self.dir, exist_ok=True)
        self.manifest_path = os.path.join(self.dir, "ground_truth.jsonl")
        self.transcript_path = os.path.join(self.dir, "transcript.jsonl")
        self.trial_path = os.path.join(self.dir, "trial.json")
        self.actions: List[ActionRecord] = []
        self.usage_total = {"input_tokens": 0, "output_tokens": 0}
        self.start_epoch = time.time()
        # truncate any prior run of the same id
        open(self.manifest_path, "w").close()
        open(self.transcript_path, "w").close()

    # -- per-action -------------------------------------------------------
    def record_action(self, index: int, command: str, rationale: Optional[str],
                       output: str, exit_code: int, duration_sec: float,
                       start_ts: float, end_ts: float,
                       output_file: str) -> ActionRecord:
        label = classify_action(command)
        rec = ActionRecord(
            index=index, command=command, rationale=rationale, output=output,
            exit_code=exit_code, duration_sec=duration_sec,
            start_ts_epoch=start_ts, end_ts_epoch=end_ts,
            mitre_technique=label.mitre_technique, attack_stage=label.attack_stage,
            attack_label=label.attack_label, asset_class=label.asset_class,
            target_ip=label.target_ip,
        )
        self.actions.append(rec)
        self._append_manifest(rec, output_file)
        return rec

    def _append_manifest(self, rec: ActionRecord, output_file: str) -> None:
        record = {
            "scenario_id": self.trial_id,
            "session_id": self.trial_id,
            "scenario_family": "ics_honeypot_llm_redteam",
            "ground_truth_label": "attack",
            "dataset_split": "attack_labeled",
            "telemetry_origin": "live_sensor",
            "scenario_step": f"action_{rec.index:04d}",
            "attack_label": rec.attack_label,
            "attack_stage": rec.attack_stage,
            "asset_class": rec.asset_class,
            "source_asset": "redteam_agent",
            "target_asset": rec.asset_class,
            "event_kind": "llm_redteam_action",
            "mitre_technique": rec.mitre_technique,
            "agent_name": self.model_key,
            "start_ts_epoch": rec.start_ts_epoch,
            "end_ts_epoch": rec.end_ts_epoch,
            "exit_code": rec.exit_code,
            "command": rec.command,
            "output_file": output_file,
        }
        with open(self.manifest_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")

    def record_turn(self, index: int, assistant_text: str, command: Optional[str],
                    rationale: Optional[str], output: Optional[str],
                    usage: Dict[str, int], finish: str) -> None:
        self.usage_total["input_tokens"] += usage.get("input_tokens", 0)
        self.usage_total["output_tokens"] += usage.get("output_tokens", 0)
        entry = {
            "index": index,
            "assistant_text": assistant_text,
            "command": command,
            "rationale": rationale,
            "output": output,
            "usage": usage,
            "finish": finish,
            "ts": time.time(),
        }
        with open(self.transcript_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=True) + "\n")

    # -- finalisation -----------------------------------------------------
    def finalize(self, objective_success: bool, reached_impact: bool,
                 stop_reason: str, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
        end_epoch = time.time()
        techniques = sorted({a.mitre_technique for a in self.actions if a.mitre_technique != "T0000"})
        assets = sorted({a.asset_class for a in self.actions if a.asset_class not in ("unknown", "network")})
        summary = {
            "trial_id": self.trial_id,
            "model_key": self.model_key,
            "model_label": self.model_label,
            "objective_key": self.objective_key,
            "action_count": len(self.actions),
            "reached_impact": reached_impact,
            "objective_success": objective_success,
            "stop_reason": stop_reason,
            "assets_touched": assets,
            "asset_count": len(assets),
            "mitre_techniques": techniques,
            "mitre_technique_count": len(techniques),
            "steps_to_impact": self._steps_to_impact(),
            "time_to_impact_sec": self._time_to_impact(),
            "duration_sec": round(end_epoch - self.start_epoch, 2),
            "tokens": self.usage_total,
            "start_epoch": self.start_epoch,
            "end_epoch": end_epoch,
        }
        if extra:
            summary.update(extra)
        with open(self.trial_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        return summary

    def _steps_to_impact(self) -> Optional[int]:
        for a in self.actions:
            if a.attack_stage in ("process_manipulation", "impact"):
                return a.index + 1
        return None

    def _time_to_impact(self) -> Optional[float]:
        for a in self.actions:
            if a.attack_stage in ("process_manipulation", "impact"):
                return round(a.end_ts_epoch - self.start_epoch, 2)
        return None
