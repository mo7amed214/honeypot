from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import requests
import streamlit as st

ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT_DIR / "scripts"


@dataclass
class StepAction:
    name: str
    command: str
    timeout: int = 45
    success_hint: str = ""


def build_attack_chain(
    level35_jump_host: str,
    level3_subnet: str,
    smb_target: str,
    ews_target: str,
    historian_target: str,
    opcua_endpoint: str,
    ews_access_method: str,
) -> List[StepAction]:
    ews_access_cmd = (
        f"xfreerdp /v:{ews_target} /u:operator /p:'<password>' /cert:ignore"
        if ews_access_method == "RDP"
        else f"ssh operator@{ews_target}"
    )

    return [
        StepAction(
            "Initial access through Level 3.5 jump host",
            f"ssh student@{level35_jump_host}",
            40,
            "Assumed entry point from your report: compromised jump host/remote path into operations zone.",
        ),
        StepAction(
            "Discovery / enumeration in Level 3 subnet",
            f"nmap -sV {level3_subnet}",
            90,
            "Enumerate SMB, historian web, OPC UA, and other reachable services before lateral action.",
        ),
        StepAction(
            "SMB share discovery and collection",
            f"smbclient -L //{smb_target} -N && smbclient //{smb_target}/ops -N -c 'ls'",
            50,
            "Represents collection from honey artifacts: PLC projects, configs, backups, credential-adjacent docs.",
        ),
        StepAction(
            "Movement toward / compromise of EWS",
            ews_access_cmd,
            70,
            "Pivot from Level 3.5 to EWS (main high-interaction host) using remote service path.",
        ),
        StepAction(
            "Historian access / collection",
            f"curl -s http://{historian_target}:5000/tags | head -n 40",
            35,
            "Show process values/metadata collection behavior against historian-oriented service.",
        ),
        StepAction(
            "Direct OPC UA interaction",
            "python - <<'PY'\nprint('Run your OPC UA browse/read script here (namespace browse, telemetry inspection).')\nPY",
            25,
            f"Use endpoint {opcua_endpoint} for browse/read/write testing from EWS context.",
        ),
        StepAction(
            "ARP-poisoning MITM on OPC UA path (advanced case)",
            "echo 'sudo arpspoof/ettercap command goes here for your isolated lab only'",
            20,
            "Only valid in your flat Layer 2 lab design from the report. Keep this in isolated demo network.",
        ),
        StepAction(
            "Integrity manipulation of historian-facing telemetry",
            "python - <<'PY'\nprint('Run your write-like/tamper action script here to influence historian-ingested values.')\nPY",
            30,
            "Expected SOC correlation: 100304/100305 and possibly 100209 depending on process effect.",
        ),
    ]


def run_shell(command: str, timeout: int = 45) -> Tuple[int, str, str]:
    proc = subprocess.run(
        ["bash", "-lc", command],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ},
    )
    return proc.returncode, proc.stdout, proc.stderr


def fetch_rule_count(loki_base: str, rid: str, lookback: str = "15m") -> float:
    query = (
        f'sum(count_over_time({{job="wazuh",source="wazuh",rule_id="{rid}"}}[{lookback}])) or vector(0)'
    )
    r = requests.get(
        f"{loki_base.rstrip('/')}/loki/api/v1/query",
        params={"query": query},
        timeout=10,
    )
    r.raise_for_status()
    payload = r.json()
    result = payload.get("data", {}).get("result", [])
    if not result:
        return 0.0
    return float(result[0]["value"][1])


def fetch_pipeline_health() -> Dict[str, str]:
    checks = {
        "Zeek relay pipeline": f"{SCRIPTS_DIR}/check_zeek_pipeline.sh 120",
        "Historian stack": "docker compose -f compose/docker-compose.historian.yml ps --status running",
    }
    out: Dict[str, str] = {}
    for label, cmd in checks.items():
        rc, stdout, stderr = run_shell(cmd, timeout=25)
        if rc == 0:
            out[label] = "OK"
        else:
            msg = (stderr.strip() or stdout.strip() or "failed").splitlines()[:1]
            out[label] = f"FAIL: {msg[0] if msg else 'failed'}"
    return out


def main() -> None:
    st.set_page_config(page_title="ICS Honeypot Attack Demo", layout="wide")

    st.title("ICS Honeypot Attack Demo Console")
    st.caption("Guided attacker storyline for thesis defense: recon -> access -> protocol path -> SOC evidence")

    with st.sidebar:
        st.header("Demo Controls")
        loki_base = st.text_input("Loki URL", value="http://localhost:3100")
        grafana_url = st.text_input("Grafana URL", value="http://localhost:3000/d/adx2v2p/soc-honeypot-detection-dashboard")
        wazuh_url = st.text_input("Wazuh URL", value="https://localhost")
        historian_url = st.text_input("Historian URL", value="http://localhost:5000")
        lookback = st.selectbox("Evidence window", ["15m", "1h", "6h", "24h", "7d"], index=0)

        st.markdown("---")
        st.header("Lab Targets")
        level35_jump_host = st.text_input("Level 3.5 jump host", value="192.168.1.20")
        level3_subnet = st.text_input("Level 3 subnet", value="192.168.1.0/24")
        smb_target = st.text_input("SMB target", value="192.168.1.7")
        ews_target = st.text_input("EWS target", value="192.168.1.5")
        historian_target = st.text_input("Historian target", value="192.168.1.10")
        opcua_endpoint = st.text_input("OPC UA endpoint", value="opc.tcp://192.168.1.11:4840")
        ews_access_method = st.selectbox("EWS access method", ["RDP", "SSH"], index=0)

        st.markdown("---")
        st.header("Execution Mode")
        demo_mode = st.radio(
            "Attack execution style",
            ["Live lab", "Narrative/simulated"],
            index=0,
        )

        st.markdown("---")
        st.write("Quick links")
        st.markdown(f"- [Grafana]({grafana_url})")
        st.markdown(f"- [Wazuh]({wazuh_url})")
        st.markdown(f"- [Historian]({historian_url})")

    col_a, col_b = st.columns([1.3, 1])

    with col_a:
        st.subheader("1) Environment and Pipeline")

        st.write("Live Preconditions")
        p1 = st.checkbox("Level 3.5 jump host is up and reachable", value=True)
        p2 = st.checkbox("EWS host is online (RDP or SSH reachable)", value=True)
        p3 = st.checkbox("OPC UA server/VM is online on port 4840", value=True)
        p4 = st.checkbox("Historian stack is running", value=True)
        if demo_mode == "Live lab" and not all([p1, p2, p3, p4]):
            st.warning("Live mode selected, but one or more required components are not ready.")

        if st.button("Start historian stack", use_container_width=True):
            rc, stdout, stderr = run_shell(f"{SCRIPTS_DIR}/run_historian_stack.sh", timeout=90)
            st.code(stdout or "", language="bash")
            if stderr:
                st.code(stderr, language="bash")
            st.success("Stack start completed") if rc == 0 else st.error("Stack start failed")

        if st.button("Run end-to-end smoke (Zeek -> Wazuh -> Loki)", use_container_width=True):
            rc, stdout, stderr = run_shell(f"{SCRIPTS_DIR}/smoke_zeek_wazuh_loki.sh 30", timeout=50)
            st.code(stdout or "", language="bash")
            if stderr:
                st.code(stderr, language="bash")
            st.success("Smoke passed") if rc == 0 else st.error("Smoke failed")

        st.subheader("2) Attacker Storyline Actions")
        steps = build_attack_chain(
            level35_jump_host,
            level3_subnet,
            smb_target,
            ews_target,
            historian_target,
            opcua_endpoint,
            ews_access_method,
        )

        for idx, step in enumerate(steps, start=1):
            with st.expander(f"Step {idx}: {step.name}", expanded=(idx == 1)):
                cmd = st.text_area(
                    f"Command for Step {idx}",
                    value=step.command,
                    key=f"cmd_{idx}",
                    height=95,
                )
                if step.success_hint:
                    st.info(step.success_hint)
                run_key = f"run_{idx}"
                if st.button(f"Run Step {idx}", key=run_key):
                    try:
                        rc, stdout, stderr = run_shell(cmd, timeout=step.timeout)
                        st.write(f"Exit code: {rc}")
                        if stdout:
                            st.code(stdout, language="bash")
                        if stderr:
                            st.code(stderr, language="bash")
                        if rc == 0:
                            st.success("Command completed")
                        else:
                            st.warning("Command returned non-zero exit code")
                    except subprocess.TimeoutExpired:
                        st.error("Command timed out")

        if st.button("Run final detection check (all mapped rules)", use_container_width=True):
            rule_map = ["100301", "100302", "100303", "100304", "100305", "100209"]
            rows = []
            for rid in rule_map:
                try:
                    rows.append({"Rule": rid, "Count": int(fetch_rule_count(loki_base, rid, lookback=lookback))})
                except Exception as exc:
                    rows.append({"Rule": rid, "Count": f"ERR: {exc}"})
            st.dataframe(rows, use_container_width=True, hide_index=True)

        st.subheader("3) MITRE-Mapped Detection Evidence")
        st.write("Use this after each action to show correlated detections by ATT&CK for ICS mapping.")

        if st.button("Refresh evidence counters", use_container_width=True):
            rule_map = [
                ("100301", "T0822/T0886", "Web access path"),
                ("100302", "T0811", "SMB repository access"),
                ("100303", "T0886", "OPC UA path interaction"),
                ("100304", "T0830", "Write-like MITM candidate"),
                ("100305", "T0830", "Critical write indicator"),
                ("100209", "Impact", "Process anomaly"),
            ]
            rows = []
            errors = []
            for rid, mitre, label in rule_map:
                try:
                    count = fetch_rule_count(loki_base, rid, lookback=lookback)
                    rows.append({"Rule": rid, "MITRE": mitre, "Evidence": label, "Count": int(count)})
                except Exception as exc:
                    errors.append(f"{rid}: {exc}")

            if rows:
                st.dataframe(rows, use_container_width=True, hide_index=True)
            if errors:
                st.error("; ".join(errors))

    with col_b:
        st.subheader("Demo Script (What to say)")
        st.markdown(
            """
1. Baseline and environment health are verified.
2. Attacker enters through Level 3.5 remote path and pivots into Level 3.
3. Attacker enumerates services and accesses SMB honey repository artifacts.
4. Attacker moves toward EWS and performs historian/process data collection.
5. Attacker performs direct OPC UA interaction from EWS context.
6. Advanced case: ARP MITM is established on flat Layer 2 path.
7. Integrity manipulation attempt targets historian-facing telemetry.
8. SOC dashboard shows correlated detections mapped to MITRE ATT&CK for ICS.
9. Analyst concludes with attack-path evidence and process impact narrative.
            """.strip()
        )

        st.subheader("Live Health")
        if st.button("Check live health", use_container_width=True):
            status = fetch_pipeline_health()
            for k, v in status.items():
                if v == "OK":
                    st.success(f"{k}: {v}")
                else:
                    st.error(f"{k}: {v}")

        st.subheader("Notes")
        st.info("Use controlled lab targets only. Keep one dashboard tab open during the demo to reduce query pressure.")
        st.success(
            "Live execution needs both EWS and OPC UA nodes online. If either is down, switch to narrative/simulated mode for that stage."
        )


if __name__ == "__main__":
    main()
