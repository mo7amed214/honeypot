#!/usr/bin/env python3
"""
Generate diverse synthetic curated session manifests for ML training.

Writes artifacts/scenario-runs/<session-id>/ground_truth.jsonl for each
generated session.  Run from the repo root:

    python -m ml.lstm_session.generate_curated_sessions

The existing real/live sessions are NOT touched; this only adds new ones.
"""

from __future__ import annotations

import json
import math
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEED = 2025
BASE_TS = 1_778_168_000.0
OUTPUT_ROOT = Path("artifacts/scenario-runs")

# ---------------------------------------------------------------------------
# Stage event blueprints
# ---------------------------------------------------------------------------

STAGE_EVENTS: Dict[str, Dict[str, Any]] = {
    "discovery": dict(
        attack_stage="discovery", attack_label="discovery",
        asset_class="network", source_asset="monitoring_laptop",
        target_asset="level3_subnet", event_kind="nmap_scan",
        rule_id="100307", rule_level=9.0, agent_name="zeek_sensor",
        mitre_technique="T0846", dur=(3.0, 10.0),
    ),
    "smb_access": dict(
        attack_stage="smb_access", attack_label="smb_access",
        asset_class="smb", source_asset="monitoring_laptop", target_asset="smb",
        event_kind="smb_browse", rule_id="100302", rule_level=8.0,
        agent_name="zeek_sensor", mitre_technique="T0811", dur=(1.0, 5.0),
    ),
    "credential_access": dict(
        attack_stage="credential_access", attack_label="credential_access",
        asset_class="smb", source_asset="monitoring_laptop", target_asset="smb",
        event_kind="file_read", rule_id="100306", rule_level=8.0,
        agent_name="zeek_sensor", mitre_technique="T0811", dur=(0.5, 3.0),
    ),
    "host_activity": dict(
        attack_stage="host_activity", attack_label="host_activity",
        asset_class="ews", source_asset="monitoring_laptop", target_asset="ews",
        event_kind="ssh_logon", rule_id="100402", rule_level=8.0,
        agent_name="EWS-WIN11", mitre_technique="T0866", dur=(0.2, 1.5),
    ),
    "host_command": dict(
        attack_stage="host_command", attack_label="host_command",
        asset_class="ews", source_asset="ews", target_asset="ews",
        event_kind="process_create", rule_id="100404", rule_level=6.0,
        agent_name="EWS-WIN11", mitre_technique="T0866", dur=(0.1, 1.0),
    ),
    "host_scriptblock": dict(
        attack_stage="host_scriptblock", attack_label="host_scriptblock",
        asset_class="ews", source_asset="ews", target_asset="ews",
        event_kind="ps_scriptblock", rule_id="100405", rule_level=7.0,
        agent_name="EWS-WIN11", mitre_technique="T0866", dur=(0.5, 3.0),
    ),
    "historian_web": dict(
        attack_stage="historian_web", attack_label="historian_web",
        asset_class="historian", source_asset="ews", target_asset="historian",
        event_kind="http_login", rule_id="100301", rule_level=8.0,
        agent_name="historian_agent", mitre_technique="T0802", dur=(0.5, 3.0),
    ),
    "opcua_path": dict(
        attack_stage="opcua_path", attack_label="opcua_path",
        asset_class="opcua", source_asset="ews", target_asset="opcua",
        event_kind="tcp_connect", rule_id="100303", rule_level=7.0,
        agent_name="zeek_sensor", mitre_technique="T0861", dur=(0.3, 2.0),
    ),
    "arp_mitm": dict(
        attack_stage="arp_mitm", attack_label="arp_mitm",
        asset_class="network", source_asset="ews", target_asset="opcua",
        event_kind="arp_poison", rule_id="100308", rule_level=13.0,
        agent_name="zeek_sensor", mitre_technique="T0830", dur=(20.0, 60.0),
    ),
    "opcua_write": dict(
        attack_stage="opcua_write", attack_label="opcua_write",
        asset_class="opcua", source_asset="ews", target_asset="opcua",
        event_kind="write_request", rule_id="100305", rule_level=13.0,
        agent_name="zeek_sensor", mitre_technique="T0831", dur=(18.0, 30.0),
    ),
    "process_anomaly": dict(
        attack_stage="process_anomaly", attack_label="process_anomaly",
        asset_class="historian", source_asset="opcua", target_asset="historian",
        event_kind="ingest_anomaly", rule_id="100209", rule_level=10.0,
        agent_name="historian_agent", mitre_technique="T0831", dur=(1.0, 4.0),
    ),
    "benign_access": dict(
        attack_stage="benign_access", attack_label="benign_access",
        asset_class="historian", source_asset="monitoring_laptop",
        target_asset="historian", event_kind="http_request",
        rule_id="100201", rule_level=4.0, agent_name="historian_agent",
        mitre_technique="none", dur=(1.0, 8.0),
    ),
    "benign_historian_review": dict(
        attack_stage="benign_historian_review",
        attack_label="benign_historian_review",
        asset_class="historian", source_asset="monitoring_laptop",
        target_asset="historian", event_kind="http_history_query",
        rule_id="100202", rule_level=4.0, agent_name="historian_agent",
        mitre_technique="none", dur=(2.0, 15.0),
    ),
    "benign_smb_review": dict(
        attack_stage="benign_smb_review", attack_label="benign_smb_review",
        asset_class="smb", source_asset="monitoring_laptop", target_asset="smb",
        event_kind="file_read", rule_id="100302", rule_level=8.0,
        agent_name="zeek_sensor", mitre_technique="none", dur=(1.0, 5.0),
    ),
    "monitoring_api": dict(
        attack_stage="monitoring_api", attack_label="monitoring_api",
        asset_class="historian", source_asset="monitoring_laptop",
        target_asset="historian", event_kind="api_query",
        rule_id="100201", rule_level=4.0, agent_name="historian_agent",
        mitre_technique="none", dur=(0.5, 3.0),
    ),
    "network_healthcheck": dict(
        attack_stage="network_healthcheck", attack_label="network_healthcheck",
        asset_class="network", source_asset="monitoring_laptop",
        target_asset="opcua", event_kind="tcp_probe",
        rule_id="100303", rule_level=7.0, agent_name="zeek_sensor",
        mitre_technique="none", dur=(0.1, 1.0),
    ),
    "benign_host_check": dict(
        attack_stage="benign_host_check", attack_label="benign_host_check",
        asset_class="ews", source_asset="monitoring_laptop", target_asset="ews",
        event_kind="rdp_logon", rule_id="100401", rule_level=7.0,
        agent_name="EWS-WIN11", mitre_technique="none", dur=(0.5, 3.0),
    ),
}

# ---------------------------------------------------------------------------
# Scenario definitions: (stage_sequence, ground_truth_label, session_intent)
# Each scenario is a template; we generate N timing variants of each.
# ---------------------------------------------------------------------------

FULL_CHAIN = [
    "discovery", "smb_access", "credential_access", "host_activity",
    "host_command", "historian_web", "opcua_path", "arp_mitm",
    "opcua_write", "process_anomaly",
]

DIRECT_WRITE = [
    "discovery", "smb_access", "credential_access", "host_activity",
    "host_command", "historian_web", "opcua_path",
    "opcua_write", "process_anomaly",
]

SCENARIOS: List[Tuple[str, List[str], str, str, int]] = [
    # (name_prefix, stages, ground_truth_label, session_intent, n_variants)

    # ── Full-chain variants ────────────────────────────────────────────────
    ("gen-full-chain",        FULL_CHAIN,                                "attack", "ot_impact",        8),
    ("gen-direct-write",      DIRECT_WRITE,                              "attack", "ot_impact",        8),
    ("gen-no-arp-write",      FULL_CHAIN[:-3] + ["opcua_write", "process_anomaly"], "attack", "ot_impact", 5),
    ("gen-fast-chain",        FULL_CHAIN,                                "attack", "ot_impact",        5),
    ("gen-slow-chain",        FULL_CHAIN,                                "attack", "ot_impact",        5),

    # ── Partial chains (stops at increasing depth) ─────────────────────────
    ("gen-stop-discovery",    ["discovery"],                             "attack", "discovery_scan",   5),
    ("gen-stop-smb",          ["discovery", "smb_access"],               "attack", "discovery_scan",   5),
    ("gen-stop-cred",         ["discovery", "smb_access", "credential_access"], "attack", "credential_access", 5),
    ("gen-stop-ews",          ["discovery", "smb_access", "credential_access", "host_activity"], "attack", "credential_access", 5),
    ("gen-stop-cmd",          ["discovery", "smb_access", "credential_access", "host_activity", "host_command"], "attack", "host_recon", 5),
    ("gen-stop-hist",         FULL_CHAIN[:6],                            "attack", "collection",       5),
    ("gen-stop-opcua-path",   FULL_CHAIN[:7],                            "attack", "ot_recon",         5),
    ("gen-stop-arp",          FULL_CHAIN[:8],                            "attack", "ot_recon",         5),

    # ── Recon-only ────────────────────────────────────────────────────────
    ("gen-discovery-only",    ["discovery"],                             "attack", "discovery_scan",   6),
    ("gen-multi-discovery",   ["discovery", "discovery"],                "attack", "discovery_scan",   4),
    ("gen-discovery-smb",     ["discovery", "smb_access"],               "attack", "discovery_scan",   5),

    # ── Credential access ─────────────────────────────────────────────────
    ("gen-cred-only",         ["discovery", "smb_access", "credential_access"], "attack", "credential_access", 6),
    ("gen-cred-failed-ews",   ["discovery", "smb_access", "credential_access", "host_activity"], "attack", "credential_access", 4),

    # ── Host recon ────────────────────────────────────────────────────────
    ("gen-ews-recon",         ["discovery", "smb_access", "credential_access", "host_activity", "host_command"], "attack", "host_recon", 6),
    ("gen-ews-scriptblock",   ["discovery", "credential_access", "host_activity", "host_command", "host_scriptblock"], "attack", "host_recon", 5),
    ("gen-host-recon-deep",   ["discovery", "smb_access", "credential_access", "host_activity", "host_command", "host_scriptblock"], "attack", "host_recon", 4),

    # ── Collection ────────────────────────────────────────────────────────
    ("gen-hist-collect",      ["discovery", "smb_access", "credential_access", "host_activity", "host_command", "historian_web"], "attack", "collection", 6),
    ("gen-smb-collect",       ["discovery", "smb_access", "credential_access"], "attack", "collection", 5),
    ("gen-hist-smb-coll",     ["discovery", "smb_access", "credential_access", "historian_web"], "attack", "collection", 5),
    ("gen-multi-hist",        ["discovery", "smb_access", "credential_access", "host_activity", "historian_web", "historian_web"], "attack", "collection", 4),

    # ── OT recon (reaches OPC UA but doesn't write) ───────────────────────
    ("gen-opcua-recon",       FULL_CHAIN[:7],                            "attack", "ot_recon",         6),
    ("gen-opcua-probe-deep",  ["discovery", "smb_access", "credential_access", "host_activity", "host_command", "historian_web", "opcua_path"], "attack", "ot_recon", 5),
    ("gen-arp-no-write",      FULL_CHAIN[:8],                            "attack", "ot_recon",         4),

    # ── OT impact variants ────────────────────────────────────────────────
    ("gen-staged-tool",       ["discovery", "smb_access", "credential_access", "host_activity", "host_command", "host_scriptblock", "historian_web", "opcua_path", "opcua_write", "process_anomaly"], "attack", "ot_impact", 5),
    ("gen-no-hist-write",     ["discovery", "smb_access", "credential_access", "host_activity", "host_command", "opcua_path", "opcua_write", "process_anomaly"], "attack", "ot_impact", 4),
    ("gen-write-multi",       ["discovery", "smb_access", "credential_access", "host_activity", "historian_web", "opcua_path", "arp_mitm", "opcua_write", "opcua_write", "process_anomaly"], "attack", "ot_impact", 4),

    # ── Noisy sessions (benign events mixed into attack) ──────────────────
    ("gen-noisy-full",        ["monitoring_api", "discovery", "smb_access", "credential_access", "host_activity", "historian_web", "opcua_path", "opcua_write", "process_anomaly"], "attack", "ot_impact", 5),
    ("gen-noisy-collect",     ["benign_access", "discovery", "smb_access", "credential_access", "host_activity", "historian_web"], "attack", "collection", 4),
    ("gen-noisy-recon",       ["network_healthcheck", "discovery", "smb_access", "credential_access", "host_activity", "host_command"], "attack", "host_recon", 4),

    # ── Benign sessions ───────────────────────────────────────────────────
    ("gen-benign-monitoring",  ["monitoring_api", "monitoring_api", "monitoring_api"], "benign", "benign_operations", 6),
    ("gen-benign-historian",   ["benign_access", "benign_historian_review", "benign_historian_review"], "benign", "benign_operations", 6),
    ("gen-benign-smb",         ["benign_smb_review"],                    "benign", "benign_operations", 5),
    ("gen-benign-smb-hist",    ["benign_smb_review", "benign_historian_review"], "benign", "benign_operations", 5),
    ("gen-benign-ews-maint",   ["benign_host_check", "benign_host_check"], "benign", "benign_operations", 5),
    ("gen-benign-opcua-hc",    ["network_healthcheck"],                  "benign", "benign_operations", 5),
    ("gen-benign-full-ops",    ["monitoring_api", "benign_historian_review", "benign_smb_review", "network_healthcheck"], "benign", "benign_operations", 6),
    ("gen-benign-long",        ["monitoring_api", "monitoring_api", "benign_historian_review", "monitoring_api", "benign_historian_review", "monitoring_api"], "benign", "benign_operations", 5),
    ("gen-benign-mixed",       ["benign_access", "monitoring_api", "benign_smb_review", "network_healthcheck"], "benign", "benign_operations", 5),

    # ── Confusable benign (looks like attack surface but is legitimate) ────
    # Operator who happens to scan + SMB browse (legitimate network audit)
    ("gen-benign-discovery",   ["discovery", "benign_smb_review"],       "benign", "benign_operations", 4),
    # Operator who uses EWS + historian (same path as attacker but legitimate)
    ("gen-benign-ews-hist",    ["benign_host_check", "benign_historian_review"], "benign", "benign_operations", 4),
    # Operator who checks OPC UA endpoint (healthcheck, not recon)
    ("gen-benign-opcua-full",  ["monitoring_api", "network_healthcheck", "benign_historian_review"], "benign", "benign_operations", 4),
]

# ---------------------------------------------------------------------------
# Timing profiles
# ---------------------------------------------------------------------------

TIMING_PROFILES = {
    "normal":  dict(inter_step_gap=(5.0, 30.0),   jitter=0.15),
    "fast":    dict(inter_step_gap=(0.5, 3.0),    jitter=0.05),
    "slow":    dict(inter_step_gap=(60.0, 300.0), jitter=0.20),
    "manual":  dict(inter_step_gap=(10.0, 90.0),  jitter=0.25),
    "burst":   dict(inter_step_gap=(0.1, 1.0),    jitter=0.10),
}


def pick_timing(name_prefix: str, variant_index: int) -> str:
    if "fast" in name_prefix:
        return "fast"
    if "slow" in name_prefix:
        return "slow"
    profiles = ["normal", "normal", "normal", "fast", "slow", "manual", "burst"]
    return profiles[variant_index % len(profiles)]


# ---------------------------------------------------------------------------
# Core generation helpers
# ---------------------------------------------------------------------------

def make_event(
    rng: random.Random,
    session_id: str,
    stage: str,
    step_index: int,
    current_ts: float,
    ground_truth_label: str,
    session_intent: str,
    session_danger_label: str,
    exit_code: int = 0,
    repeat_count: int = 1,
) -> Tuple[Dict, float]:
    """Build one ground-truth JSONL row and return (row, end_ts)."""
    tmpl = STAGE_EVENTS[stage]
    dur_min, dur_max = tmpl["dur"]
    duration = rng.uniform(dur_min, dur_max)
    end_ts = current_ts + duration

    row = {
        "session_id": session_id,
        "scenario_id": session_id,
        "scenario_step": f"step_{step_index + 1}_{stage}",
        "attack_label": tmpl["attack_label"],
        "attack_stage": tmpl["attack_stage"],
        "asset_class": tmpl["asset_class"],
        "source_asset": tmpl["source_asset"],
        "target_asset": tmpl["target_asset"],
        "event_kind": tmpl["event_kind"],
        "rule_id": tmpl["rule_id"],
        "rule_level": tmpl["rule_level"],
        "agent_name": tmpl["agent_name"],
        "mitre_technique": tmpl["mitre_technique"],
        "ground_truth_label": ground_truth_label,
        "dataset_split": "ml_curated_synthetic",
        "telemetry_origin": "curated_synthetic",
        "scenario_family": "curated_synthetic",
        "session_intent": session_intent,
        "session_danger_label": session_danger_label,
        "session_summary": "",
        "exit_code": exit_code,
        "start_ts_epoch": round(current_ts, 3),
        "end_ts_epoch": round(end_ts, 3),
        "repeat_count": repeat_count,
    }
    return row, end_ts


def danger_label_for_stages(stages: List[str]) -> str:
    stage_set = set(stages)
    if "opcua_write" in stage_set or "process_anomaly" in stage_set:
        return "critical"
    if "opcua_path" in stage_set and (
        "historian_web" in stage_set or "smb_access" in stage_set
    ):
        return "high"
    if any(s in stage_set for s in [
        "historian_web", "host_command", "host_scriptblock",
        "smb_access", "opcua_path", "arp_mitm",
    ]):
        return "high"
    if any(s in stage_set for s in ["host_activity", "credential_access"]):
        return "medium"
    if "discovery" in stage_set:
        return "medium"
    return "low"


def generate_session(
    rng: random.Random,
    name_prefix: str,
    stages: List[str],
    ground_truth_label: str,
    session_intent: str,
    variant_index: int,
    session_counter: int,
) -> Tuple[str, List[Dict]]:
    """Generate all JSONL rows for one session."""
    session_id = f"{name_prefix}-v{variant_index:02d}-{session_counter:04d}"
    timing_profile = pick_timing(name_prefix, variant_index)
    profile = TIMING_PROFILES[timing_profile]

    # Vary base timestamp per session so timing features are diverse
    ts_offset = rng.uniform(0.0, 86400.0 * 7)  # spread over a week
    current_ts = BASE_TS + ts_offset

    session_danger_label = danger_label_for_stages(stages)
    rows: List[Dict] = []

    for step_idx, stage in enumerate(stages):
        # Occasional repeat_count for burst-timing profiles
        repeat = 1
        if timing_profile == "burst" and rng.random() < 0.3:
            repeat = rng.randint(2, 5)

        # Failed exit for specific failed-session scenarios
        exit_code = 0
        if "failed" in name_prefix and step_idx == len(stages) - 1:
            exit_code = 1

        row, end_ts = make_event(
            rng=rng,
            session_id=session_id,
            stage=stage,
            step_index=step_idx,
            current_ts=current_ts,
            ground_truth_label=ground_truth_label,
            session_intent=session_intent,
            session_danger_label=session_danger_label,
            exit_code=exit_code,
            repeat_count=repeat,
        )
        rows.append(row)

        gap_min, gap_max = profile["inter_step_gap"]
        gap = rng.uniform(gap_min, gap_max)
        # Apply per-step jitter
        gap *= rng.uniform(1.0 - profile["jitter"], 1.0 + profile["jitter"])
        current_ts = end_ts + gap

    return session_id, rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    rng = random.Random(SEED)
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    counter = 0
    total_sessions = 0
    skipped = 0

    for name_prefix, stages, gt_label, intent, n_variants in SCENARIOS:
        for variant_idx in range(n_variants):
            session_id, rows = generate_session(
                rng=rng,
                name_prefix=name_prefix,
                stages=stages,
                ground_truth_label=gt_label,
                session_intent=intent,
                variant_index=variant_idx,
                session_counter=counter,
            )
            counter += 1

            out_dir = OUTPUT_ROOT / session_id
            if out_dir.exists():
                skipped += 1
                continue

            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / "ground_truth.jsonl"
            with out_file.open("w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, ensure_ascii=True) + "\n")
            total_sessions += 1

    print(f"Generated {total_sessions} new sessions ({skipped} already existed).")
    print(f"Output root: {OUTPUT_ROOT.resolve()}")


if __name__ == "__main__":
    main()
