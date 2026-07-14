"""Build a sanitised, public-release subset of the Level 3 honeynet session
dataset, plus a datasheet.

Input : artifacts/scenario-runs/*/ground_truth.jsonl   (labelled sessions)
Output: dataset/
          level3_sessions.full.jsonl     all sessions, sanitised, one event/line
          level3_sessions.subset.jsonl   balanced public subset
          DATASHEET.md                    datasheet-for-datasets style doc
          SCHEMA.md                       field-by-field schema
          stats.json                      machine-readable corpus statistics

Sanitisation policy
-------------------
KEEP (already public in the thesis, not sensitive):
  * RFC1918 lab IPs (192.168.1.x) - non-routable, and published in the thesis
  * the synthetic john/Cisco credential - part of the documented deception design
STRIP / NORMALISE (machine-specific, could leak host details):
  * absolute host paths in `output_file` -> repo-relative posix path
  * any C:\\Users\\<name>\\... path -> redacted
  * drop the local `output_file` blob reference entirely from the public rows
    (the raw per-step text outputs are not part of the public release)

The synthetic credential is intentionally retained and is documented in the
datasheet so downstream users understand it is fabricated bait, not a real
secret.
"""

from __future__ import annotations

import json
import os
import re
import random
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = REPO_ROOT / "artifacts" / "scenario-runs"
OUT_DIR = REPO_ROOT / "dataset"

# Fields carried into the public dataset (whitelist - anything else is dropped).
PUBLIC_FIELDS = [
    "session_id", "scenario_family", "ground_truth_label", "dataset_split",
    "telemetry_origin", "session_intent", "session_danger_label",
    "scenario_step", "attack_label", "attack_stage", "asset_class",
    "mitre_technique", "source_asset", "target_asset", "event_kind",
    "start_ts_epoch", "end_ts_epoch", "exit_code", "command",
]

USER_PATH_RE = re.compile(r"[A-Za-z]:\\Users\\[^\\\"]+", re.IGNORECASE)
ABS_REPO_RE = re.compile(r"[A-Za-z]:\\ot_honeypot\\", re.IGNORECASE)


def sanitise_command(cmd: str) -> str:
    if not cmd:
        return cmd
    cmd = USER_PATH_RE.sub("<USER_HOME>", cmd)
    cmd = ABS_REPO_RE.sub("", cmd)
    return cmd


def sanitise_record(raw: dict) -> dict:
    out = {}
    for k in PUBLIC_FIELDS:
        v = raw.get(k)
        if k == "command" and isinstance(v, str):
            v = sanitise_command(v)
        out[k] = v
    # normalise timestamps to session-relative seconds to avoid leaking wall-clock
    return out


def load_sessions() -> list[list[dict]]:
    sessions = []
    if not SCENARIO_ROOT.is_dir():
        return sessions
    for d in sorted(SCENARIO_ROOT.iterdir()):
        mf = d / "ground_truth.jsonl"
        if not mf.is_file():
            continue
        rows = []
        with mf.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        if rows:
            sessions.append(rows)
    return sessions


def rebase_time(rows: list[dict]) -> list[dict]:
    """Convert absolute epochs to session-relative seconds (privacy + tidiness)."""
    starts = [float(r.get("start_ts_epoch", 0) or 0) for r in rows if r.get("start_ts_epoch")]
    t0 = min(starts) if starts else 0.0
    for r in rows:
        for k in ("start_ts_epoch", "end_ts_epoch"):
            if r.get(k) is not None:
                r[k] = round(float(r[k]) - t0, 3)
    return rows


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sessions = load_sessions()
    if not sessions:
        raise SystemExit(f"no sessions under {SCENARIO_ROOT}")

    full_rows = []
    session_meta = []
    for rows in sessions:
        clean = rebase_time([sanitise_record(r) for r in rows])
        full_rows.extend(clean)
        first = rows[0]
        session_meta.append({
            "session_id": first.get("session_id"),
            "label": first.get("ground_truth_label", "unknown"),
            "intent": first.get("session_intent", "unknown"),
            "events": len(rows),
        })

    # write full
    full_path = OUT_DIR / "level3_sessions.full.jsonl"
    with full_path.open("w", encoding="utf-8") as fh:
        for r in full_rows:
            fh.write(json.dumps(r, ensure_ascii=True) + "\n")

    # balanced public subset: all benign + an equal-sized sample of attack sessions
    rng = random.Random(1337)
    benign = [m for m in session_meta if m["label"] != "attack"]
    attack = [m for m in session_meta if m["label"] == "attack"]
    k = min(len(attack), max(len(benign), 20))
    subset_ids = {m["session_id"] for m in benign} | {
        m["session_id"] for m in rng.sample(attack, min(k, len(attack)))
    }
    subset_rows = [r for r in full_rows if r["session_id"] in subset_ids]
    subset_path = OUT_DIR / "level3_sessions.subset.jsonl"
    with subset_path.open("w", encoding="utf-8") as fh:
        for r in subset_rows:
            fh.write(json.dumps(r, ensure_ascii=True) + "\n")

    # stats
    techniques = Counter(r.get("mitre_technique") for r in full_rows if r.get("mitre_technique"))
    intents = Counter(m["intent"] for m in session_meta)
    labels = Counter(m["label"] for m in session_meta)
    stats = {
        "sessions": len(session_meta),
        "events": len(full_rows),
        "attack_sessions": labels.get("attack", 0),
        "benign_sessions": sum(v for k, v in labels.items() if k != "attack"),
        "unique_intents": len(intents),
        "intent_distribution": dict(intents),
        "mitre_techniques": dict(techniques),
        "mitre_technique_count": len(techniques),
        "subset_sessions": len(subset_ids),
        "subset_events": len(subset_rows),
    }
    (OUT_DIR / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")

    _write_schema()
    _write_datasheet(stats)
    print(f"[dataset] {stats['sessions']} sessions / {stats['events']} events "
          f"-> {OUT_DIR}")
    print(f"[dataset] subset: {stats['subset_sessions']} sessions / {stats['subset_events']} events")
    print(f"[dataset] MITRE techniques covered: {stats['mitre_technique_count']}")


def _write_schema() -> None:
    schema = """# Level 3 Honeynet Session Dataset — Schema

Each line in `*.jsonl` is one attacker/benign **event** within a session.
Events sharing a `session_id` form one session (the unit of classification).

| Field | Type | Description |
|---|---|---|
| session_id | str | Groups events into one session |
| scenario_family | str | Scenario template the session was drawn from |
| ground_truth_label | str | `attack` or a `benign_*` label |
| dataset_split | str | Provenance tag (curated / replay / detection) |
| telemetry_origin | str | How the event was produced |
| session_intent | str | Session-level intent (e.g. ot_impact, collection) |
| session_danger_label | str | Session-level danger (low/medium/high/critical) |
| scenario_step | str | Step name within the session |
| attack_label | str | Per-event stage label |
| attack_stage | str | Per-event kill-chain stage |
| asset_class | str | Target asset (ews/smb/historian/opcua/network) |
| mitre_technique | str | MITRE ATT&CK for ICS technique id |
| source_asset | str | Acting asset |
| target_asset | str | Targeted asset |
| event_kind | str | Event type hint |
| start_ts_epoch | float | Session-relative start time (seconds) |
| end_ts_epoch | float | Session-relative end time (seconds) |
| exit_code | int | Command exit code (0 = success) |
| command | str | Sanitised command text |
"""
    (OUT_DIR / "SCHEMA.md").write_text(schema, encoding="utf-8")


def _write_datasheet(stats: dict) -> None:
    ds = f"""# Datasheet — Level 3 Industrial Honeynet Session Dataset

## Motivation
Labelled, session-level attacker datasets for the *upper* (Purdue Level 3)
layer of ICS are scarce; most public ICS security data is packet- or
field-device-level. This dataset captures multi-step attacker and benign
**sessions** against a Level 3 honeynet (engineering workstation, SMB share,
historian, OPC UA server), each event labelled with a kill-chain stage and a
MITRE ATT&CK for ICS technique, to support session-level detection research.

## Composition
- **Sessions:** {stats['sessions']} ({stats['attack_sessions']} attack, {stats['benign_sessions']} benign)
- **Events:** {stats['events']}
- **Distinct session intents:** {stats['unique_intents']}
- **MITRE ATT&CK for ICS techniques covered:** {stats['mitre_technique_count']}
- **Public subset:** {stats['subset_sessions']} sessions / {stats['subset_events']} events (balanced)

## Collection process
Sessions are produced by (a) curated scenario templates with timing/ordering
variation and (b) live sensor replay of an eight-step kill chain aligned to
MITRE ATT&CK for ICS. Labels are recorded as ground truth at generation time,
not inferred after the fact.

## Sanitisation / privacy
- Absolute host paths are removed; `output_file` blobs are not released.
- Lab IP addresses are RFC1918 (non-routable) and are retained, consistent
  with the published thesis topology.
- The `john / Cisco` credential appearing in some commands is **synthetic bait**
  from the honeynet's deception design — it is not a real secret.
- No personal data, no real user accounts, and no real industrial infrastructure
  are represented.

## Recommended uses
Session-level intrusion classification, kill-chain stage prediction, early-warning
/ partial-session prediction, and MITRE-labelled ICS attack analysis.

## Limitations
The dataset is generated in a single-testbed, closed-world setting; absolute
class frequencies reflect scenario design choices, not field base rates. It is
intended for methodology research, not as a representative traffic sample.

## License / citation
Release under CC BY 4.0 (suggested). Cite the accompanying paper.
"""
    (OUT_DIR / "DATASHEET.md").write_text(ds, encoding="utf-8")


if __name__ == "__main__":
    main()
